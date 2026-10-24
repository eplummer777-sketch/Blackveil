/* Kernel heap: the general allocator over its own virtual range, backed page by page with fresh frames. */
#include <bv/console.h>
#include <bv/errno.h>
#include <bv/format.h>
#include <bv/mm.h>
#include <bv/panic.h>

#define FAIL(...)                              \
    do {                                       \
        bv_snprintf(why, why_len, __VA_ARGS__); \
        return -BV_EINVAL;                     \
    } while (0)

extern char __kernel_start[], __kernel_end[];

static struct heap kh;

static void unmap_run(uintptr_t va, uint64_t len)
{
    struct vmm *v = kernel_vmm();
    for (uint64_t off = 0; off < len; off += PAGE_SIZE) {
        uint64_t pa;
        if (vmm_query(v, va + off, &pa, NULL) == 0 && vmm_unmap(v, va + off, PAGE_SIZE) == 0)
            kframe_free(pa);
    }
}

/* All-or-nothing: on failure every page mapped so far is unmapped and its frame returned. */
static int grow(void *ctx, uintptr_t va, size_t len)
{
    (void)ctx;
    for (size_t off = 0; off < len; off += PAGE_SIZE) {
        uint64_t pa;
        int rc = kframe_alloc(&pa);
        if (rc == 0 && (rc = vmm_map(kernel_vmm(), va + off, pa, PAGE_SIZE, VMM_WRITE)) != 0)
            kframe_free(pa);
        if (rc) {
            unmap_run(va, off);
            return rc;
        }
    }
    return 0;
}

static bool overlaps(uint64_t a, uint64_t b, uint64_t base, uint64_t end)
{
    return a < end && base < b;
}

int kheap_verify(char *why, size_t why_len)
{
    if (heap_check(&kh))
        FAIL("heap metadata or statistics inconsistent");
    const struct vmm *v = kernel_vmm();
    const struct pmm *st = kframe_stats();
    const struct mem_range *bd;
    size_t nbd = mm_boot_data(&bd);
    for (uintptr_t va = kh.base; va < kh.brk; va += PAGE_SIZE) {
        uint64_t pa;
        unsigned fl;
        if (vmm_query(v, va, &pa, &fl))
            FAIL("heap page %p is not mapped", (void *)va);
        if (!(fl & VMM_WRITE) || (v->nx && (fl & VMM_EXEC)))
            FAIL("heap page %p is not read/write, no-execute", (void *)va);
        bool bad = pa < MM_LOW_RESERVED || pmm_state_of(st, pa) != PMM_USED ||
                   overlaps(pa, pa + PAGE_SIZE, (uintptr_t)__kernel_start, (uintptr_t)__kernel_end);
        for (size_t i = 0; i < nbd && !bad; i++)
            bad = overlaps(pa, pa + PAGE_SIZE, bd[i].base, bd[i].end);
        if (bad)
            FAIL("heap page %p is backed by protected frame %p", (void *)va, (void *)pa);
    }
    if (vmm_query(v, kh.brk, NULL, NULL) != -BV_ENOENT)
        FAIL("page after the heap end %p is mapped", (void *)kh.brk);
    return 0;
}

static int selfcheck(char *why, size_t why_len)
{
    static const struct {
        size_t size, align;
    } req[] = { { 1, 1 }, { 24, 16 }, { 100, 64 }, { 4096, 4096 }, { 70000, 16 }, { 3000, 1u << 20 } };
    void *p[sizeof req / sizeof req[0]];
    for (size_t i = 0; i < sizeof req / sizeof req[0]; i++) {
        int rc = heap_alloc(&kh, req[i].size, req[i].align, &p[i]);
        if (rc)
            FAIL("heap self-check: %zu-byte allocation failed: %s", req[i].size, bv_strerror(rc));
        if ((uintptr_t)p[i] % req[i].align)
            FAIL("heap self-check: %p is not %zu-byte aligned", p[i], req[i].align);
        for (size_t j = 0; j < req[i].size; j++)
            ((volatile uint8_t *)p[i])[j] = (uint8_t)(i + 1);
    }
    for (size_t i = 0; i < sizeof req / sizeof req[0]; i++)
        for (size_t j = 0; j < req[i].size; j++)
            if (((volatile uint8_t *)p[i])[j] != (uint8_t)(i + 1))
                FAIL("heap self-check: allocation %zu was overwritten", i);
    int rc = kheap_verify(why, why_len);
    if (rc)
        return rc;
    uint64_t mapped = kh.st.mapped;
    if (heap_free(&kh, (void *)__kernel_start) != -BV_EINVAL || heap_free(&kh, (uint8_t *)p[1] + 16) != -BV_EINVAL)
        FAIL("heap self-check: a pointer it never returned was accepted");
    for (size_t i = 0; i < sizeof req / sizeof req[0]; i++)
        if (heap_free(&kh, p[i]))
            FAIL("heap self-check: free of allocation %zu failed", i);
    if (heap_free(&kh, p[5]) == 0)
        FAIL("heap self-check: double free accepted");
    if (kh.st.live || kh.st.requested || heap_largest_free(&kh) != kh.st.mapped || heap_check(&kh))
        FAIL("heap self-check: memory not fully returned");
    kprintf("[ OK ] Heap self-check passed (%lu KiB mapped)\n", (unsigned long)(mapped / 1024));
    return 0;
}

int kheap_init(char *why, size_t why_len)
{
    struct heap_ops ops = { grow, NULL };
    int rc = heap_init(&kh, KHEAP_BASE, KHEAP_SIZE, &ops);
    if (rc)
        FAIL("heap range rejected: %s", bv_strerror(rc));
    if (vmm_query(kernel_vmm(), KHEAP_BASE, NULL, NULL) != -BV_ENOENT)
        FAIL("heap range is already mapped");
    kprintf("[ OK ] Heap: %p - %p, read/write, no-execute, grows on demand\n", (void *)kh.base, (void *)kh.limit);
    return selfcheck(why, why_len);
}

int kheap_alloc(size_t size, size_t align, void **out)
{
    return heap_alloc(&kh, size, align, out);
}

int kheap_free(void *ptr)
{
    return heap_free(&kh, ptr);
}

const struct heap *kheap(void)
{
    return &kh;
}

void *kmalloc(size_t size)
{
    void *p;
    return heap_alloc(&kh, size, HEAP_ALIGN, &p) ? NULL : p;
}

void kfree(void *ptr)
{
    int rc = heap_free(&kh, ptr);
    if (rc)
        panic("kfree(%p): %s", ptr, bv_strerror(rc));
}
