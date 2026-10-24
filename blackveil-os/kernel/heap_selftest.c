/* Emulator-only kernel heap tests, selected with bv.test=heap-* (see selftest.c). */
#include <bv/console.h>
#include <bv/errno.h>
#include <bv/mm.h>
#include <bv/panic.h>
#include <bv/selftest.h>
#include <bv/string.h>

void bv_trigger_write(uint64_t addr);
extern char __kernel_start[];

static uint64_t rng = 0x2545F4914F6CDD1Dull;

static uint64_t next_rand(void)
{
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng;
}

static void verify(const char *test)
{
    char why[160];
    if (kheap_verify(why, sizeof why))
        panic("%s: %s", test, why);
}

/* Heap statistics equal apart from the failure counters. */
static bool same_stats(const struct heap_stats *a, const struct heap_stats *b)
{
    struct heap_stats c = *a;
    c.failed_allocs = b->failed_allocs;
    c.rejected_frees = b->rejected_frees;
    return memcmp(&c, b, sizeof c) == 0;
}

static void *must_alloc(size_t size, size_t align)
{
    void *p;
    int rc = kheap_alloc(size, align, &p);
    if (rc)
        panic("heap test: %zu-byte allocation failed: %s", size, bv_strerror(rc));
    return p;
}

static void stress_alignment(void)
{
    static const size_t sizes[] = { 1, 15, 16, 17, 4095, 4097 };
    void *p[22][6];
    for (unsigned a = 0; a < 22; a++)
        for (unsigned s = 0; s < 6; s++) {
            size_t align = (size_t)1 << a;
            p[a][s] = must_alloc(sizes[s], align);
            if ((uintptr_t)p[a][s] % align)
                panic("heap-stress: %p not %zu-byte aligned", p[a][s], align);
            memset(p[a][s], (int)(a * 6 + s), sizes[s]);
        }
    for (unsigned a = 0; a < 22; a++)
        for (unsigned s = 0; s < 6; s++) {
            for (size_t j = 0; j < sizes[s]; j++)
                if (((uint8_t *)p[a][s])[j] != (uint8_t)(a * 6 + s))
                    panic("heap-stress: aligned allocation %u/%u overwritten", a, s);
            if (kheap_free(p[a][s]))
                panic("heap-stress: aligned free failed");
        }
    verify("heap-stress");
    kprintf("[TEST] heap-stress: 132 allocations at every alignment from 1 B to 2 MiB were aligned and intact\n");
}

static void stress_random(void)
{
    enum { SLOTS = 128, OPS = 20000 };
    static uint8_t *ptr[SLOTS];
    static size_t len[SLOTS];
    const struct heap *h = kheap();
    uint64_t requested = h->st.requested, peak = h->st.peak_requested;
    for (int op = 0; op < OPS; op++) {
        unsigned i = next_rand() % SLOTS;
        if (ptr[i]) {
            for (size_t j = 0; j < len[i]; j++)
                if (ptr[i][j] != (uint8_t)i)
                    panic("heap-stress: allocation in slot %u was overwritten", i);
            if (kheap_free(ptr[i]))
                panic("heap-stress: free of slot %u failed", i);
            requested -= len[i];
            ptr[i] = NULL;
        } else {
            uint64_t r = next_rand();
            len[i] = 1 + (r % 8 == 0 ? r % 65536 : r % 2000);
            ptr[i] = must_alloc(len[i], (size_t)1 << ((r >> 24) % 13));
            memset(ptr[i], (int)i, len[i]);
            requested += len[i];
            if (requested > peak)
                peak = requested;
        }
        if (op % 512 == 0 && heap_check(h))
            panic("heap-stress: heap inconsistent after %d operations", op);
    }
    if (h->st.requested != requested || h->st.peak_requested != peak)
        panic("heap-stress: statistics drifted (requested %lu, expected %lu)", (unsigned long)h->st.requested,
              (unsigned long)requested);
    for (unsigned i = 0; i < SLOTS; i++)
        if (ptr[i] && kheap_free(ptr[i]))
            panic("heap-stress: final free failed");
    if (h->st.live || h->st.requested || heap_largest_free(h) != h->st.mapped)
        panic("heap-stress: memory not fully coalesced after freeing everything");
    verify("heap-stress");
    kprintf("[TEST] heap-stress: %d random operations; contents intact, statistics exact, all memory coalesced\n", OPS);
}

static void stress_bad_frees(void)
{
    const struct heap *h = kheap();
    uint8_t *x = must_alloc(64, 16), *y = must_alloc(64, 16), *z = must_alloc(20, 16);
    uint64_t on_stack = 0x5151;
    const struct mem_range *bd;
    mm_boot_data(&bd);
    void *protected_ptrs[] = {
        __kernel_start, &on_stack, phys_to_virt(bd[0].base), phys_to_virt(kernel_vmm()->root),
        (void *)h->base, (void *)h->brk, y + 1, y + 16, y - 16,
    };
    uint64_t before[sizeof protected_ptrs / sizeof protected_ptrs[0]];
    for (size_t i = 0; i < 4; i++)
        before[i] = *(volatile uint64_t *)protected_ptrs[i];
    struct heap_stats s = h->st;
    for (size_t i = 0; i < sizeof protected_ptrs / sizeof protected_ptrs[0]; i++)
        if (kheap_free(protected_ptrs[i]) != -BV_EINVAL)
            panic("heap-stress: free of non-heap pointer %p accepted", protected_ptrs[i]);
    for (size_t i = 0; i < 4; i++)
        if (*(volatile uint64_t *)protected_ptrs[i] != before[i])
            panic("heap-stress: rejected free modified %p", protected_ptrs[i]);
    if (!same_stats(&h->st, &s) || h->st.rejected_frees != s.rejected_frees + 9)
        panic("heap-stress: rejected frees changed the heap");
    kprintf("[TEST] heap-stress: frees of kernel code, stack, boot data, page tables and non-heap pointers refused\n");

    if (kheap_free(y) || kheap_free(y) != -BV_EALREADY || kheap_free(x) || kheap_free(y) != -BV_EINVAL ||
        kheap_free(x) != -BV_EALREADY)
        panic("heap-stress: double free not detected");
    uint8_t saved = z[20];
    z[20] = 0;
    s = h->st;
    if (kheap_free(z) != -BV_EFAULT || !same_stats(&h->st, &s) || heap_check(h) != -BV_EFAULT)
        panic("heap-stress: overrun past a 20-byte allocation not detected");
    z[20] = saved;
    if (kheap_free(z))
        panic("heap-stress: free after repairing the overrun failed");
    verify("heap-stress");
    kprintf("[TEST] heap-stress: double frees and a 1-byte overrun detected without changing the heap\n");

    uint8_t *f = must_alloc(256, 16), *g = must_alloc(64, 16);
    if (kheap_free(f))
        panic("heap-stress: free failed");
    for (size_t i = 16; i < 256; i++)
        if (f[i] != HEAP_POISON)
            panic("heap-stress: freed payload not poisoned at byte %zu", i);
    f[100] = 0;
    s = h->st;
    if (heap_check(h) != -BV_EFAULT || !same_stats(&h->st, &s))
        panic("heap-stress: write after free not detected");
    f[100] = HEAP_POISON;
    if (kheap_free(g))
        panic("heap-stress: free failed");
    verify("heap-stress");
    kprintf("[TEST] heap-stress: freed memory poisoned and a write after free detected\n");
}

void selftest_heap_stress(void)
{
    stress_alignment();
    stress_random();
    stress_bad_frees();
    const struct heap *h = kheap();
    kprintf("[TEST] heap-stress: %lu KiB mapped, peak %lu bytes requested, %lu allocs, %lu frees, %lu rejected\n",
            (unsigned long)(h->st.mapped / 1024), (unsigned long)h->st.peak_requested, (unsigned long)h->st.allocs,
            (unsigned long)h->st.frees, (unsigned long)h->st.rejected_frees);
}

/* Fills all of memory from the heap, chaining blocks through their first word. */
static uint64_t fill(size_t size, void **head)
{
    uint64_t n = 0;
    void *p;
    while (kheap_alloc(size, 16, &p) == 0) {
        *(void **)p = *head;
        *head = p;
        n++;
    }
    return n;
}

static void free_chain(void *head)
{
    while (head) {
        void *next = *(void **)head;
        if (kheap_free(head))
            panic("heap-exhaust: free failed");
        head = next;
    }
}

void selftest_heap_exhaust(void)
{
    const struct heap *h = kheap();
    const struct pmm *st = kframe_stats();
    const struct vmm *v = kernel_vmm();
    void *head = NULL;
    uint64_t big = fill(65536, &head), small = fill(256, &head);

    struct heap_stats s = h->st;
    uint64_t frames = st->free_frames, tables = v->tables, brk = h->brk;
    void *p = (void *)1;
    int rc = kheap_alloc(65536, 16, &p);
    if (rc != -BV_ENOMEM || p || !same_stats(&h->st, &s) || h->brk != brk ||
        frames - st->free_frames != v->tables - tables)
        panic("heap-exhaust: failed allocation changed the heap or leaked frames (rc %d)", rc);
    if (st->free_frames > 4)
        panic("heap-exhaust: out of memory with %lu frames still free", (unsigned long)st->free_frames);
    verify("heap-exhaust");
    kprintf("[TEST] heap-exhaust: %lu x 64 KiB + %lu x 256 B (%lu KiB mapped), then out of memory with %lu frames left\n",
            (unsigned long)big, (unsigned long)small, (unsigned long)(h->st.mapped / 1024),
            (unsigned long)st->free_frames);
    kprintf("[TEST] heap-exhaust: the failed allocation changed nothing and returned every frame it took\n");

    free_chain(head);
    if (h->st.live || h->st.requested || heap_largest_free(h) != h->st.mapped || heap_check(h))
        panic("heap-exhaust: memory not fully returned");
    head = NULL;
    uint64_t mapped = h->st.mapped, again = fill(65536, &head);
    if (again < big || h->st.mapped != mapped)
        panic("heap-exhaust: reuse got %lu blocks (first pass %lu)", (unsigned long)again, (unsigned long)big);
    free_chain(head);
    verify("heap-exhaust");
    kprintf("[TEST] heap-exhaust: freed memory reused for %lu blocks without growing; statistics consistent\n",
            (unsigned long)again);
}

void selftest_heap_nx(void)
{
    uint8_t *p = kmalloc(16);
    if (!p)
        panic("heap-nx: allocation failed");
    p[0] = 0xC3; /* ret */
    kprintf("[TEST] heap-nx: executing heap memory at %p\n", (void *)p);
    ((void (*)(void))p)();
}

void selftest_heap_overrun(void)
{
    uint8_t *p = kmalloc(64);
    if (!p)
        panic("heap-overrun: allocation failed");
    kprintf("[TEST] heap-overrun: writing at the heap end %p\n", (void *)kheap()->brk);
    bv_trigger_write(kheap()->brk);
}
