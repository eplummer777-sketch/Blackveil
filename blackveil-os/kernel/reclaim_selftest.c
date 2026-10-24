/* Stage 6 self-tests: page-table reclamation in the live kernel address space. */
#include <bv/console.h>
#include <bv/errno.h>
#include <bv/mm.h>
#include <bv/panic.h>
#include <bv/selftest.h>
#include <bv/string.h>

#define RC_VA    0xFFFFE00000000000ull /* empty 512 GiB slot: one page here needs a PDPT, PD and PT */
#define PTE_ADDR 0x000FFFFFFFFFF000ull
#define TWO_MIB  (1ull << 21)
#define GIB      (1ull << 30)
#define CYCLES   10000

extern char __kernel_start[];
uint64_t bv_trigger_read(uint64_t addr);

static void verify(void)
{
    char why[160];
    if (vm_verify_protection(why, sizeof why) || kheap_verify(why, sizeof why))
        panic("reclaim: %s", why);
}

/* The PDPT, PD and PT physical addresses on va's path; 0 from the first absent level on. */
static void path(const struct vmm *v, uint64_t va, uint64_t out[3])
{
    uint64_t t = v->root;
    for (int i = 0; i < 3; i++) {
        uint64_t e = t ? ((volatile uint64_t *)phys_to_virt(t))[(va >> (39 - 9 * i)) & 511] : 0;
        out[i] = t = (e & 1) ? e & PTE_ADDR : 0;
    }
}

static void map_or_die(struct vmm *v, uint64_t va, uint64_t pa, uint64_t len, unsigned flags)
{
    int rc = vmm_map(v, va, pa, len, flags);
    if (rc)
        panic("reclaim: map of %p failed: %s", (void *)va, bv_strerror(rc));
}

static void unmap_or_die(struct vmm *v, uint64_t va, uint64_t len)
{
    int rc = vmm_unmap(v, va, len);
    if (rc)
        panic("reclaim: unmap of %p failed: %s", (void *)va, bv_strerror(rc));
}

/* Takes the three frames just freed by reclamation back from the allocator, or panics. */
static void take_back(const uint64_t t[3], uint64_t g[3])
{
    int hits = 0;
    for (int i = 0; i < 3; i++) {
        if (kframe_alloc(&g[i]))
            panic("reclaim: no frame to reuse");
        for (int j = 0; j < 3; j++)
            hits += g[i] == t[j];
    }
    if (hits != 3)
        panic("reclaim: freed table frames %p %p %p were not handed out again", (void *)t[0], (void *)t[1],
              (void *)t[2]);
}

static void basic(struct vmm *v, const struct pmm *st, uint64_t f)
{
    uint64_t tables0 = v->tables, rsv0 = st->reserved_frames, free0 = st->free_frames, rec0 = v->reclaimed;
    uint64_t t[3], u[3];
    map_or_die(v, RC_VA, f, PAGE_SIZE, VMM_WRITE);
    path(v, RC_VA, t);
    if (v->tables != tables0 + 3 || st->free_frames != free0 - 3)
        panic("reclaim: mapping did not create 3 tables");
    *(volatile uint64_t *)RC_VA = 0x5EC1A1Bull;
    verify();
    unmap_or_die(v, RC_VA, PAGE_SIZE);
    path(v, RC_VA, u);
    bool ok = v->tables == tables0 && v->reclaimed == rec0 + 3 && st->reserved_frames == rsv0 &&
              st->free_frames == free0 && !u[0];
    for (int i = 0; i < 3; i++) {
        unsigned fl = 0;
        ok = ok && t[i] && pmm_state_of(st, t[i]) == PMM_FREE && !vmm_query(v, t[i], NULL, &fl) && (fl & VMM_WRITE);
    }
    if (!ok)
        panic("reclaim: empty tables %p %p %p not returned (tables %lu -> %lu)", (void *)t[0], (void *)t[1],
              (void *)t[2], (unsigned long)tables0, (unsigned long)v->tables);
    verify();
    kprintf("[TEST] reclaim: 3 empty tables (%p, %p, %p) unlinked, flushed, unpinned and freed; their memory is "
            "writable again\n",
            (void *)t[0], (void *)t[1], (void *)t[2]);

    uint64_t g[3];
    take_back(t, g);
    for (int i = 0; i < 3; i++) {
        volatile uint64_t *p = phys_to_virt(g[i]);
        for (unsigned k = 0; k < PAGE_SIZE / 8; k++)
            p[k] = 0xFFFFFFFFFFFFF067ull; /* would read as present, writable entries */
        for (unsigned k = 0; k < PAGE_SIZE / 8; k++)
            if (p[k] != 0xFFFFFFFFFFFFF067ull)
                panic("reclaim: reused frame %p did not hold data", (void *)g[i]);
        kframe_free(g[i]);
    }
    map_or_die(v, RC_VA, f, PAGE_SIZE, 0);
    path(v, RC_VA, u);
    int reused = 0;
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 3; j++)
            reused += u[i] == t[j];
    if (*(volatile uint64_t *)RC_VA != 0x5EC1A1Bull || vmm_query(v, RC_VA + PAGE_SIZE, NULL, NULL) != -BV_ENOENT ||
        vmm_query(v, RC_VA + TWO_MIB, NULL, NULL) != -BV_ENOENT || reused != 3)
        panic("reclaim: reused tables wrong (%d reused)", reused);
    verify();
    unmap_or_die(v, RC_VA, PAGE_SIZE);
    kprintf("[TEST] reclaim: the freed frames were reused for data, then as zeroed tables again; no stale entry "
            "survived\n");
}

static void nested(struct vmm *v, uint64_t f)
{
    uint64_t tables0 = v->tables, t[3];
    map_or_die(v, RC_VA, f, PAGE_SIZE, 0);
    map_or_die(v, RC_VA + TWO_MIB, f, PAGE_SIZE, 0);
    if (v->tables != tables0 + 4)
        panic("reclaim: nested setup made %lu tables", (unsigned long)(v->tables - tables0));
    unmap_or_die(v, RC_VA, PAGE_SIZE);
    path(v, RC_VA + TWO_MIB, t);
    if (v->tables != tables0 + 3 || !t[2] || vmm_query(v, RC_VA + TWO_MIB, NULL, NULL))
        panic("reclaim: a table still in use was reclaimed");
    unmap_or_die(v, RC_VA + TWO_MIB, PAGE_SIZE);
    map_or_die(v, RC_VA + GIB - PAGE_SIZE, f, 2 * PAGE_SIZE, 0);
    if (v->tables != tables0 + 5)
        panic("reclaim: range across 1 GiB made %lu tables", (unsigned long)(v->tables - tables0));
    unmap_or_die(v, RC_VA + GIB - PAGE_SIZE, 2 * PAGE_SIZE);
    if (v->tables != tables0)
        panic("reclaim: nested tables left behind (%lu)", (unsigned long)(v->tables - tables0));
    verify();
    kprintf("[TEST] reclaim: nested tables go lowest level first; a table still in use was kept; a range across "
            "1 GiB returned all 5\n");
}

static void cycles(struct vmm *v, const struct pmm *st, uint64_t f)
{
    uint64_t tables0 = v->tables, free0 = st->free_frames, rsv0 = st->reserved_frames, rec0 = v->reclaimed;
    for (unsigned i = 0; i < CYCLES; i++) {
        uint64_t a = RC_VA + (i % 3) * GIB + (i % 7) * TWO_MIB + (i % 5) * PAGE_SIZE, len = (1 + i % 3) * PAGE_SIZE;
        map_or_die(v, a, f, len, 0);
        unmap_or_die(v, a, len);
    }
    if (v->tables != tables0 || st->free_frames != free0 || st->reserved_frames != rsv0 ||
        v->reclaimed - rec0 != 3ull * CYCLES || kframe_check())
        panic("reclaim: cycles leaked (tables %lu free %lu reserved %lu reclaimed %lu)",
              (unsigned long)(v->tables - tables0), (unsigned long)(free0 - st->free_frames),
              (unsigned long)(st->reserved_frames - rsv0), (unsigned long)(v->reclaimed - rec0));
    verify();
    kprintf("[TEST] reclaim: %u map/unmap cycles reclaimed %lu tables; frame and table counts back to the start\n",
            CYCLES, (unsigned long)(v->reclaimed - rec0));
}

static void refusals(struct vmm *v, const struct pmm *st, uint64_t f)
{
    const struct mem_range *bd;
    size_t nbd = mm_boot_data(&bd);
    uint64_t free0 = st->free_frames, rsv0 = st->reserved_frames, g;
    if (kframe_alloc(&g) || kframe_free(g))
        panic("reclaim: no free frame for the refusal test");
    int rc[] = { kframe_unpin((uintptr_t)__kernel_start), kframe_unpin(kframe_records().base),
                 kframe_unpin(PAGE_SIZE),                  kframe_unpin(nbd ? bd[0].base & PTE_ADDR : 0),
                 kframe_unpin(0xFEE00000ull),              kframe_unpin(f + 8),
                 kframe_unpin(f),                          kframe_unpin(g),
                 kframe_free(v->root) };
    int want[] = { -BV_EPERM, -BV_EPERM, -BV_EPERM, -BV_EPERM, -BV_EPERM, -BV_EPERM, -BV_EINVAL, -BV_EINVAL, -BV_EPERM };
    for (unsigned i = 0; i < sizeof rc / sizeof rc[0]; i++)
        if (rc[i] != want[i])
            panic("reclaim: unpin/free case %u returned %d (want %d)", i, rc[i], want[i]);
    if (st->free_frames != free0 || st->reserved_frames != rsv0)
        panic("reclaim: refused unpins changed the counters");
    verify();
    kprintf("[TEST] reclaim: unpinning boot data, kernel, records, low memory, unusable memory and non-table frames "
            "refused; live tables still cannot be freed\n");
}

/* Drained frames are tracked in a heap bitmap, never written: on a large guest that would commit all of RAM on the host. */
struct drain {
    uint64_t *bits, n, held;
};

static void give_back(struct drain *d, uint64_t n)
{
    for (uint64_t i = 0; i < d->n && n; i++) {
        if (!(d->bits[i / 64] & (1ull << (i % 64))))
            continue;
        if (kframe_free(i * PAGE_SIZE))
            panic("reclaim: drained frame %p could not be freed", (void *)(i * PAGE_SIZE));
        d->bits[i / 64] &= ~(1ull << (i % 64));
        d->held--;
        n--;
    }
    if (n)
        panic("reclaim: %lu drained frames missing", (unsigned long)n);
}

static void take_all(struct drain *d)
{
    uint64_t x;
    while (!kframe_alloc(&x)) {
        d->bits[x / PAGE_SIZE / 64] |= 1ull << (x / PAGE_SIZE % 64);
        d->held++;
    }
}

static void exhaustion(struct vmm *v, const struct pmm *st, uint64_t f)
{
    uint64_t tables0 = v->tables, rsv0 = st->reserved_frames, words = (st->nframes + 63) / 64;
    struct drain d = { kmalloc(words * 8), st->nframes, 0 };
    if (!d.bits)
        panic("reclaim: no heap for the drain bitmap");
    memset(d.bits, 0, words * 8);
    take_all(&d);
    for (unsigned k = 0; k < 3; k++) {
        give_back(&d, k);
        int rc = vmm_map(v, RC_VA, f, PAGE_SIZE, 0);
        if (rc != -BV_ENOMEM || v->tables != tables0 || st->free_frames != k || st->reserved_frames != rsv0 ||
            vmm_query(v, RC_VA, NULL, NULL) != -BV_ENOENT)
            panic("reclaim: map with %u free frames left state behind (rc %d)", k, rc);
        take_all(&d);
    }
    give_back(&d, 3);
    map_or_die(v, RC_VA, f, PAGE_SIZE, 0);
    if (st->free_frames != 0 || v->tables != tables0 + 3)
        panic("reclaim: map with exactly 3 free frames wrong");
    unmap_or_die(v, RC_VA, PAGE_SIZE);
    if (st->free_frames != 3 || v->tables != tables0 || st->reserved_frames != rsv0)
        panic("reclaim: tables reclaimed at exhaustion not returned (%lu free)", (unsigned long)st->free_frames);
    map_or_die(v, RC_VA, f, PAGE_SIZE, 0);
    unmap_or_die(v, RC_VA, PAGE_SIZE);
    give_back(&d, d.held);
    kfree(d.bits);
    verify();
    kprintf("[TEST] reclaim: out of memory with 0, 1 and 2 frames changed nothing; the last 3 frames became tables, "
            "came back on unmap and were reused\n");
}

void selftest_reclaim(void)
{
    struct vmm *v = kernel_vmm();
    const struct pmm *st = kframe_stats();
    uint64_t free0 = st->free_frames, rsv0 = st->reserved_frames, tables0 = v->tables, f;
    if (kframe_alloc(&f))
        panic("reclaim: no data frame");
    basic(v, st, f);
    nested(v, f);
    cycles(v, st, f);
    refusals(v, st, f);
    exhaustion(v, st, f);
    if (kframe_free(f) || st->free_frames != free0 || st->reserved_frames != rsv0 || v->tables != tables0 ||
        kframe_check())
        panic("reclaim: final counters wrong");
    verify();
    kprintf("[TEST] reclaim: all frames returned; %lu tables live as at the start; protection verified\n",
            (unsigned long)v->tables);
}

/* Reclaimed tables are overwritten with forged entries; a stale cached walk would follow them. */
void selftest_reclaim_stale(void)
{
    struct vmm *v = kernel_vmm();
    uint64_t f, d, t[3], g[3];
    if (kframe_alloc(&f) || kframe_alloc(&d))
        panic("reclaim-stale: no frames");
    map_or_die(v, RC_VA, f, PAGE_SIZE, VMM_WRITE);
    *(volatile uint64_t *)RC_VA = 1;
    path(v, RC_VA, t);
    unmap_or_die(v, RC_VA, PAGE_SIZE);
    take_back(t, g);
    for (int i = 0; i < 4; i++) {
        volatile uint64_t *p = phys_to_virt(i < 3 ? g[i] : d);
        for (unsigned k = 0; k < PAGE_SIZE / 8; k++)
            p[k] = d | 3;
    }
    kprintf("[TEST] reclaim-stale: tables %p %p %p reclaimed and overwritten with forged entries; reading %p\n",
            (void *)t[0], (void *)t[1], (void *)t[2], (void *)RC_VA);
    uint64_t got = bv_trigger_read(RC_VA);
    panic("reclaim-stale: stale translation of %p returned %p", (void *)RC_VA, (void *)got);
}
