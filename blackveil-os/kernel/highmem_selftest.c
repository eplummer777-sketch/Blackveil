/* Emulator-only test that RAM above 1 GiB is really handed out and usable (bv.test=highmem). */
#include <bv/console.h>
#include <bv/errno.h>
#include <bv/mm.h>
#include <bv/panic.h>
#include <bv/selftest.h>
#include <bv/string.h>

extern char __kernel_start[], __kernel_end[];

#define GIB       (1ull << 30)
#define HM_VA     0xFFFFD00000000000ull /* empty 512 GiB slot: the first mapping needs 3 new tables */
#define PTE_ADDR  0x000FFFFFFFFFF000ull
#define RELEASE   1024                  /* high frames handed back for the table and heap checks */
#define HEAP_TEST (2u << 20)
#define SAMPLES   4096

static uint64_t *taken;

static bool is_taken(uint64_t f)
{
    return (taken[f / 64] >> (f % 64)) & 1;
}

static void verify(void)
{
    char why[160];
    if (vm_verify_protection(why, sizeof why) || kheap_verify(why, sizeof why))
        panic("highmem: %s", why);
}

static uint64_t pattern(uint64_t pa, uint64_t i)
{
    return (pa + i * 8) ^ 0xB1AC7E11F00DCAFEull;
}

/* Writes then re-reads a spread of high frames, so two frames sharing storage would be caught. */
static uint64_t sample_high(const struct pmm *st, uint64_t highest, bool write)
{
    uint64_t high = 0, n = 0;
    for (uint64_t f = GIB / PAGE_SIZE; f < st->nframes; f++)
        high += is_taken(f);
    uint64_t stride = high / SAMPLES + 1, c = 0;
    for (uint64_t f = GIB / PAGE_SIZE; f < st->nframes; f++) {
        if (!is_taken(f) || (c++ % stride && f * PAGE_SIZE != highest))
            continue;
        volatile uint64_t *p = phys_to_virt(f * PAGE_SIZE);
        for (uint64_t i = 0; i < PAGE_SIZE / 8; i++) {
            if (write)
                p[i] = pattern(f * PAGE_SIZE, i);
            else if (p[i] != pattern(f * PAGE_SIZE, i))
                panic("highmem: frame %p lost its data at word %lu", (void *)(f * PAGE_SIZE), (unsigned long)i);
        }
        n++;
    }
    return n;
}

static void release(uint64_t f)
{
    if (kframe_free(f * PAGE_SIZE))
        panic("highmem: could not free %p", (void *)(f * PAGE_SIZE));
    taken[f / 64] &= ~(1ull << (f % 64));
}

void selftest_highmem(void)
{
    struct vmm *v = kernel_vmm();
    const struct pmm *st = kframe_stats();
    uint64_t top = st->nframes * PAGE_SIZE, ks = (uintptr_t)__kernel_start, ke = (uintptr_t)__kernel_end;
    struct mem_range rec = kframe_records();
    if (top <= GIB)
        panic("highmem: no RAM above 1 GiB (top %p)", (void *)top);
    taken = kmalloc((st->nframes + 63) / 64 * 8);
    if (!taken)
        panic("highmem: no heap for the frame list");
    memset(taken, 0, (st->nframes + 63) / 64 * 8);
    verify();

    uint64_t free0 = st->free_frames, res0 = st->reserved_frames, tables0 = v->tables;
    uint64_t n = 0, high = 0, above4 = 0, highest = 0, f;
    while (kframe_alloc(&f) == 0) {
        uint64_t i = f / PAGE_SIZE;
        if (f % PAGE_SIZE || f >= top || f < MM_LOW_RESERVED || (f >= ks && f < ke) ||
            (f >= rec.base && f < rec.end) || pmm_state_of(st, f) != PMM_USED || is_taken(i))
            panic("highmem: bad, reserved or duplicate frame %p", (void *)f);
        taken[i / 64] |= 1ull << (i % 64);
        n++;
        high += f >= GIB;
        above4 += f >= 4 * GIB;
        highest = f > highest ? f : highest;
    }
    if (n != free0 || st->free_frames != 0 || high == 0)
        panic("highmem: drained %lu of %lu frames, %lu above 1 GiB", (unsigned long)n, (unsigned long)free0,
              (unsigned long)high);
    kprintf("[TEST] highmem: allocated all %lu free frames (%lu above 1 GiB, %lu above 4 GiB, highest %p); "
            "none reserved, duplicated or out of range\n",
            (unsigned long)n, (unsigned long)high, (unsigned long)above4, (void *)highest);

    uint64_t s = sample_high(st, highest, true);
    if (sample_high(st, highest, false) != s)
        panic("highmem: sample count changed");
    kprintf("[TEST] highmem: wrote and verified %lu frames above 1 GiB, including %p\n", (unsigned long)s,
            (void *)highest);

    if (kframe_alloc(&f) != -BV_ENOMEM || vmm_map(v, HM_VA, highest, PAGE_SIZE, VMM_WRITE) != -BV_ENOMEM ||
        vmm_query(v, HM_VA, NULL, NULL) != -BV_ENOENT || v->tables != tables0 || st->free_frames != 0)
        panic("highmem: out of memory left state behind");
    kprintf("[TEST] highmem: out of memory refused and the failed mapping rolled back with no change\n");

    /* Only high frames are free from here, so new tables and heap pages must come from above 1 GiB. */
    uint64_t back = 0;
    for (f = st->nframes; f-- > GIB / PAGE_SIZE && back < RELEASE;)
        if (is_taken(f) && f * PAGE_SIZE != highest) {
            release(f);
            back++;
        }
    uint64_t free_a = st->free_frames;
    if (vmm_map(v, HM_VA, highest, PAGE_SIZE, VMM_WRITE) || v->tables != tables0 + 3)
        panic("highmem: mapping a high frame failed");
    uint64_t pdpt = ((volatile uint64_t *)phys_to_virt(v->root))[(HM_VA >> 39) & 511] & PTE_ADDR;
    volatile uint64_t *alias = (volatile uint64_t *)HM_VA, *direct = phys_to_virt(highest);
    alias[7] = 0x48494748AA55ull;
    if (pdpt < GIB || direct[7] != 0x48494748AA55ull || direct[0] != pattern(highest, 0))
        panic("highmem: alias of %p wrong (new table at %p)", (void *)highest, (void *)pdpt);
    verify();
    if (vmm_unmap(v, HM_VA, PAGE_SIZE))
        panic("highmem: unmap failed");
    kprintf("[TEST] highmem: new page tables at %p and above are read-only and pinned; alias of %p works\n",
            (void *)pdpt, (void *)highest);

    uint8_t *buf = kmalloc(HEAP_TEST);
    uint64_t last;
    if (!buf || vmm_query(v, (uintptr_t)buf + HEAP_TEST - 1, &last, NULL) || last < GIB)
        panic("highmem: heap did not grow into high memory");
    for (uint32_t i = 0; i < HEAP_TEST; i += 8)
        *(volatile uint64_t *)(buf + i) = pattern((uintptr_t)buf, i / 8);
    for (uint32_t i = 0; i < HEAP_TEST; i += 8)
        if (*(volatile uint64_t *)(buf + i) != pattern((uintptr_t)buf, i / 8))
            panic("highmem: heap data mismatch at offset %u", i);
    uint64_t pa = last & ~(uint64_t)(PAGE_SIZE - 1);
    uintptr_t page_va = ((uintptr_t)buf + HEAP_TEST - 1) & ~(uintptr_t)(PAGE_SIZE - 1);
    if (*(volatile uint64_t *)phys_to_virt(pa) != *(volatile uint64_t *)page_va ||
        *(volatile uint64_t *)page_va != pattern((uintptr_t)buf, (page_va - (uintptr_t)buf) / 8))
        panic("highmem: heap page and its frame disagree");
    kfree(buf);
    verify();
    kprintf("[TEST] highmem: heap grew into frame %p above 1 GiB; 2 MiB written and verified\n", (void *)pa);

    uint64_t consumed = free_a - st->free_frames, pinned = st->reserved_frames - res0;
    for (f = 0; f < st->nframes; f++)
        if (is_taken(f))
            release(f);
    kfree(taken);
    if (st->free_frames != free0 - consumed || pinned != v->tables - tables0 || kframe_check())
        panic("highmem: counters wrong after release (free %lu want %lu, pinned %lu tables %lu)",
              (unsigned long)st->free_frames, (unsigned long)(free0 - consumed), (unsigned long)pinned,
              (unsigned long)(v->tables - tables0));
    verify();
    kprintf("[TEST] highmem: all frames returned; %lu kept by new tables and the heap; counters and protection "
            "consistent\n",
            (unsigned long)consumed);
}
