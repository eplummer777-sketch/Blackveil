/* Host tests for the page-table engine, backed by a fake physical memory. */
#include "check.h"
#include <bv/errno.h>
#include <bv/vmm.h>
#include <stdbool.h>
#include <stdlib.h>

#define NPAGES 64
#define PHYS_BASE 0x200000ull

static uint8_t *mem;
static int used[NPAGES], pinned[NPAGES];
static int allocs, releases, commits, flushes, fail_after = -1, depth, outside_writes;
static int flush_alls, retires, flushed_since_window, retire_errors;
static struct vmm *cur;
static uint64_t last_flush;
static unsigned long long sealed;
static unsigned long long tables_hash(void);

static int f_alloc(void *ctx, uint64_t *phys)
{
    (void)ctx;
    if (fail_after == 0)
        return -BV_ENOMEM;
    for (int i = 0; i < NPAGES; i++) {
        if (!used[i]) {
            used[i] = 1;
            memset(mem + i * 4096, 0xA5, 4096); /* dirty, so missing zeroing shows up */
            *phys = PHYS_BASE + (uint64_t)i * 4096;
            allocs++;
            if (fail_after > 0)
                fail_after--;
            return 0;
        }
    }
    return -BV_ENOMEM;
}

static void f_release(void *ctx, uint64_t phys)
{
    (void)ctx;
    int i = (int)((phys - PHYS_BASE) / 4096);
    CHECK(used[i] && !pinned[i]);
    used[i] = 0;
    releases++;
}

static void f_commit(void *ctx, uint64_t phys)
{
    (void)ctx;
    pinned[(phys - PHYS_BASE) / 4096] = 1;
    commits++;
}

static void *f_virt(void *ctx, uint64_t phys)
{
    (void)ctx;
    if (phys < PHYS_BASE || phys >= PHYS_BASE + NPAGES * 4096ull) {
        printf("  FAIL  virt() of unowned frame %#llx\n", (unsigned long long)phys);
        exit(1);
    }
    return mem + (phys - PHYS_BASE);
}

static void f_flush(void *ctx, uint64_t va)
{
    (void)ctx;
    flushes++;
    last_flush = va;
}

static void f_flush_all(void *ctx)
{
    (void)ctx;
    flush_alls++;
    flushed_since_window = 1;
}

static void find_table(void *arg, uint64_t phys)
{
    uint64_t *want = arg;
    if (phys == want[0])
        want[1] = 1;
}

/* A retired frame must be a pinned, unreachable, empty (bar the chain word) non-root table, flushed. */
static void f_retire(void *ctx, uint64_t phys)
{
    (void)ctx;
    int i = (int)((phys - PHYS_BASE) / 4096);
    uint64_t probe[2] = { phys, 0 };
    vmm_walk_tables(cur, find_table, probe);
    const uint64_t *t = (const uint64_t *)(mem + i * 4096);
    int dirty = 0;
    for (int k = 1; k < 512; k++)
        dirty |= t[k] != 0;
    if (!used[i] || !pinned[i] || phys == cur->root || probe[1] || dirty || depth || !flushed_since_window)
        retire_errors++;
    pinned[i] = 0;
    used[i] = 0;
    retires++;
    sealed = tables_hash();
}

/* Mirrors the kernel policy: no writable mapping of a frame that is a live table. */
static int f_allow(void *ctx, uint64_t pa, unsigned flags)
{
    (void)ctx;
    bool table = pa >= PHYS_BASE && pa < PHYS_BASE + NPAGES * 4096ull && pinned[(pa - PHYS_BASE) / 4096];
    return (flags & VMM_WRITE) && table ? -BV_EPERM : 0;
}

/* Live tables are hashed when the window closes; a different hash when it next opens means a stray write. */
static void f_write_begin(void *ctx)
{
    (void)ctx;
    if (depth++ == 0 && tables_hash() != sealed)
        outside_writes++;
    flushed_since_window = 0;
}

static void f_write_end(void *ctx)
{
    (void)ctx;
    if (--depth == 0)
        sealed = tables_hash();
}

static const struct vmm_ops ops = { f_alloc,  f_release, f_commit,      f_virt,      f_flush, f_flush_all,
                                    f_retire, f_allow,   f_write_begin, f_write_end, NULL };

static void count_table(void *arg, uint64_t phys)
{
    int *seen = arg;
    seen[(phys - PHYS_BASE) / 4096]++;
}

/* Nothing changed a live table outside the write window, and the window is closed. */
static void check_window(void)
{
    CHECK_EQ(depth, 0);
    CHECK_EQ(outside_writes, 0);
    CHECK_EQ(tables_hash(), sealed);
}

static int in_use(void)
{
    int n = 0;
    for (int i = 0; i < NPAGES; i++)
        n += used[i];
    return n;
}

static unsigned long long tables_hash(void)
{
    unsigned long long h = 1469598103934665603ull;
    for (int i = 0; i < NPAGES; i++)
        if (pinned[i])
            for (int j = 0; j < 4096; j++)
                h = (h ^ mem[i * 4096 + j]) * 1099511628211ull;
    return h;
}

static unsigned long long snapshot(void)
{
    return tables_hash() ^ (unsigned long long)in_use();
}

static void reset(struct vmm *v, int nx)
{
    memset(used, 0, sizeof used);
    memset(pinned, 0, sizeof pinned);
    allocs = releases = commits = flushes = 0;
    flush_alls = retires = retire_errors = 0;
    fail_after = -1;
    cur = v;
    depth = outside_writes = 0;
    CHECK_EQ(vmm_init(v, &ops, nx), 0);
    sealed = tables_hash();
}

/* Stage 6: empty tables are unlinked, flushed and retired; live ones never are. */
static void reclamation(struct vmm *v)
{
    uint64_t far = 0xFFFF900000000000ull, pa;

    /* one page in an empty 512 GiB slot: PDPT, PD and PT all come back */
    reset(v, 1);
    unsigned long long s0 = snapshot();
    CHECK_EQ(vmm_map(v, far, 0x5000, 0x1000, VMM_WRITE), 0);
    CHECK_EQ(v->tables, 4);
    CHECK_EQ(vmm_unmap(v, far, 0x1000), 0);
    CHECK_EQ(v->tables, 1);
    CHECK_EQ(v->reclaimed, 3);
    CHECK_EQ(retires, 3);
    CHECK_EQ(flush_alls, 1);
    CHECK_EQ(in_use(), 1);
    CHECK_EQ(snapshot(), s0);
    CHECK_EQ(vmm_query(v, far, NULL, NULL), -BV_ENOENT);

    /* a table still holding one entry is kept */
    CHECK_EQ(vmm_map(v, 0x400000, 0x5000, 0x2000, 0), 0);
    CHECK_EQ(vmm_unmap(v, 0x400000, 0x1000), 0);
    CHECK_EQ(retires, 3);
    CHECK_EQ(flush_alls, 1);
    CHECK_EQ(v->tables, 4);
    CHECK_EQ(vmm_query(v, 0x401000, &pa, NULL), 0);
    CHECK_EQ(pa, 0x6000);
    CHECK_EQ(vmm_unmap(v, 0x401000, 0x1000), 0);
    CHECK_EQ(retires, 6);
    CHECK_EQ(v->tables, 1);

    /* nested: two PTs under one PD; the PD goes only with the last PT, then the PDPT */
    CHECK_EQ(vmm_map(v, 0x400000, 0x5000, 0x1000, 0), 0);
    CHECK_EQ(vmm_map(v, 0x600000, 0x5000, 0x1000, 0), 0);
    CHECK_EQ(v->tables, 5);
    CHECK_EQ(vmm_unmap(v, 0x400000, 0x1000), 0);
    CHECK_EQ(retires, 7);
    CHECK_EQ(v->tables, 4);
    CHECK_EQ(vmm_query(v, 0x600000, NULL, NULL), 0);
    CHECK_EQ(vmm_unmap(v, 0x600000, 0x1000), 0);
    CHECK_EQ(retires, 10);
    CHECK_EQ(v->tables, 1);

    /* one unmap across two 1 GiB regions: PDPT, 2 PD, 2 PT in a single flush */
    int fa = flush_alls;
    CHECK_EQ(vmm_map(v, far + (1ull << 30) - 0x1000, 0x5000, 0x2000, 0), 0);
    CHECK_EQ(v->tables, 6);
    CHECK_EQ(vmm_unmap(v, far + (1ull << 30) - 0x1000, 0x2000), 0);
    CHECK_EQ(v->tables, 1);
    CHECK_EQ(retires, 15);
    CHECK_EQ(flush_alls, fa + 1);

    /* full 2 MiB tables: middle unmap frees nothing, each edge frees its own PT, the last also PD/PDPT */
    CHECK_EQ(vmm_map(v, 0x200000, 0x10000000, 0x400000, 0), 0);
    CHECK_EQ(v->tables, 5);
    CHECK_EQ(vmm_unmap(v, 0x300000, 0x200000), 0);
    CHECK_EQ(v->tables, 5);
    CHECK_EQ(vmm_unmap(v, 0x200000, 0x100000), 0);
    CHECK_EQ(v->tables, 4);
    CHECK_EQ(vmm_query(v, 0x500000, &pa, NULL), 0);
    CHECK_EQ(pa, 0x10300000);
    CHECK_EQ(vmm_unmap(v, 0x500000, 0x100000), 0);
    CHECK_EQ(v->tables, 1);
    CHECK_EQ(in_use(), 1);

    /* failed and invalid unmaps reclaim nothing and change nothing */
    CHECK_EQ(vmm_map(v, far, 0x5000, 0x1000, 0), 0);
    unsigned long long s = snapshot();
    int r = retires;
    CHECK_EQ(vmm_unmap(v, far, 0x2000), -BV_ENOENT);
    CHECK_EQ(vmm_unmap(v, far + 0x800, 0x1000), -BV_EINVAL);
    CHECK_EQ(vmm_unmap(v, far + 0x1000, 0x1000), -BV_ENOENT);
    CHECK_EQ(retires, r);
    CHECK_EQ(snapshot(), s);
    CHECK_EQ(vmm_unmap(v, far, 0x1000), 0);

    /* repeated cycles at shifting addresses: no growth, no leak, no double release */
    uint64_t before = v->reclaimed;
    for (int i = 0; i < 2000; i++) {
        uint64_t a = (i % 3 == 0 ? far : 0x40000000ull) + (uint64_t)(i % 7) * (1ull << 21) + (uint64_t)(i % 5) * 0x1000;
        CHECK_EQ(vmm_map(v, a, 0x5000, 0x1000 * (uint64_t)(1 + i % 3), VMM_WRITE), 0);
        CHECK_EQ(vmm_unmap(v, a, 0x1000 * (uint64_t)(1 + i % 3)), 0);
    }
    CHECK_EQ(v->tables, 1);
    CHECK_EQ(in_use(), 1);
    CHECK_EQ(v->reclaimed - before, 2000 * 3);

    /* exhaustion, full reclamation, then the same frames are reused for the same work */
    int maps = 0, rc;
    uint64_t a = 0;
    while ((rc = vmm_map(v, a, 0x1000, 0x1000, 0)) == 0) {
        maps++;
        a += 1ull << 21;
    }
    CHECK_EQ(rc, -BV_ENOMEM);
    CHECK_EQ(in_use(), NPAGES);
    CHECK_EQ(vmm_query(v, a, NULL, NULL), -BV_ENOENT);
    for (int i = 0; i < maps; i++)
        CHECK_EQ(vmm_unmap(v, (uint64_t)i << 21, 0x1000), 0);
    CHECK_EQ(v->tables, 1);
    CHECK_EQ(in_use(), 1);
    int again = 0;
    for (a = 0; vmm_map(v, a, 0x2000, 0x1000, 0) == 0; a += 1ull << 21)
        again++;
    CHECK_EQ(again, maps);
    CHECK_EQ(vmm_query(v, 0, &pa, NULL), 0);
    CHECK_EQ(pa, 0x2000); /* reused tables were zeroed: no stale entry from the first pass */
    CHECK_EQ((uint64_t)in_use(), v->tables);

    /* out of frames mid-map after reclamation still rolls back exactly */
    for (int i = 0; i < again; i++)
        CHECK_EQ(vmm_unmap(v, (uint64_t)i << 21, 0x1000), 0);
    s = snapshot();
    for (int k = 0; k < 3; k++) {
        fail_after = k;
        CHECK_EQ(vmm_map(v, far, 0x1000, 0x1000, 0), -BV_ENOMEM);
        CHECK_EQ(snapshot(), s);
        CHECK_EQ(v->tables, 1);
    }
    fail_after = -1;

    CHECK_EQ(retire_errors, 0);
    check_window();
}

int main(void)
{
    mem = aligned_alloc(4096, NPAGES * 4096);
    struct vmm v;
    uint64_t pa;
    unsigned fl;

    reset(&v, 1);
    CHECK_EQ(v.tables, 1);
    CHECK_EQ(vmm_query(&v, 0x1000, &pa, &fl), -BV_ENOENT);

    /* map + query + permissions */
    CHECK_EQ(vmm_map(&v, 0x400000, 0x123000, 0x3000, VMM_WRITE), 0);
    CHECK_EQ(v.tables, 4);
    CHECK_EQ(vmm_query(&v, 0x401abc, &pa, &fl), 0);
    CHECK_EQ(pa, 0x124abc);
    CHECK_EQ(fl, VMM_WRITE);
    CHECK_EQ(vmm_map(&v, 0x500000, 0x9000, 0x1000, VMM_EXEC), 0);
    CHECK_EQ(vmm_query(&v, 0x500000, NULL, &fl), 0);
    CHECK_EQ(fl, VMM_EXEC);
    CHECK_EQ(vmm_map(&v, 0x501000, 0x9000, 0x1000, 0), 0);
    CHECK_EQ(vmm_query(&v, 0x501000, NULL, &fl), 0);
    CHECK_EQ(fl, 0);
    CHECK_EQ(v.tables, 4);

    /* W^X and argument validation, none of which may touch the tables */
    unsigned long long s = snapshot();
    CHECK_EQ(vmm_map(&v, 0x600000, 0x1000, 0x1000, VMM_WRITE | VMM_EXEC), -BV_EINVAL);
    CHECK_EQ(vmm_map(&v, 0x600000, 0x1000, 0x1000, 0x80), -BV_EINVAL);
    CHECK_EQ(vmm_map(&v, 0x600800, 0x1000, 0x1000, 0), -BV_EINVAL);
    CHECK_EQ(vmm_map(&v, 0x600000, 0x1800, 0x1000, 0), -BV_EINVAL);
    CHECK_EQ(vmm_map(&v, 0x600000, 0x1000, 0x1800, 0), -BV_EINVAL);
    CHECK_EQ(vmm_map(&v, 0x600000, 0x1000, 0, 0), -BV_EINVAL);
    CHECK_EQ(vmm_map(&v, 0x0000800000000000ull, 0x1000, 0x1000, 0), -BV_EINVAL);
    CHECK_EQ(vmm_map(&v, 0x00007FFFFFFFF000ull, 0x1000, 0x2000, 0), -BV_EINVAL);
    CHECK_EQ(vmm_map(&v, 0xFFFFFFFFFFFFF000ull, 0x1000, 0x2000, 0), -BV_EINVAL);
    CHECK_EQ(vmm_map(&v, 0x600000, 0xFFFFFFFFFFFFF000ull, 0x2000, 0), -BV_EINVAL);
    CHECK_EQ(vmm_protect(&v, 0x400000, 0x1000, VMM_WRITE | VMM_EXEC), -BV_EINVAL);
    CHECK_EQ(snapshot(), s);

    /* overlap anywhere in the range: refused with no partial mapping */
    CHECK_EQ(vmm_map(&v, 0x3FE000, 0x1000, 0x4000, 0), -BV_EBUSY);
    CHECK_EQ(vmm_query(&v, 0x3FE000, NULL, NULL), -BV_ENOENT);
    CHECK_EQ(vmm_query(&v, 0x3FF000, NULL, NULL), -BV_ENOENT);
    CHECK_EQ(snapshot(), s);

    /* out of frames at every possible point: everything handed back, tables unchanged */
    uint64_t far = 0xFFFF900000000000ull; /* needs PDPT + PD + PT */
    for (int k = 0; k < 3; k++) {
        allocs = releases = commits = 0;
        fail_after = k;
        CHECK_EQ(vmm_map(&v, far, 0x1000, 0x1000, VMM_WRITE), -BV_ENOMEM);
        CHECK_EQ(allocs, k);
        CHECK_EQ(releases, k);
        CHECK_EQ(commits, 0);
        CHECK_EQ(vmm_query(&v, far, NULL, NULL), -BV_ENOENT);
        CHECK_EQ(v.tables, 4);
        CHECK_EQ(snapshot(), s);
    }
    fail_after = -1;

    /* a range spanning two 2 MiB and two 1 GiB regions allocates exactly the tables it needs */
    allocs = releases = commits = 0;
    CHECK_EQ(vmm_map(&v, far + (1ull << 30) - 0x1000, 0x40000000, 0x2000, VMM_WRITE), 0);
    CHECK_EQ(commits, 5); /* PDPT, 2 PD, 2 PT */
    CHECK_EQ(releases, 0);
    CHECK_EQ(vmm_query(&v, far + (1ull << 30), &pa, &fl), 0);
    CHECK_EQ(pa, 0x40001000);

    /* unmap: all-or-nothing, flushes each page */
    s = snapshot();
    CHECK_EQ(vmm_unmap(&v, 0x400000, 0x4000), -BV_ENOENT);
    CHECK_EQ(snapshot(), s);
    CHECK_EQ(flushes, 0);
    CHECK_EQ(vmm_unmap(&v, 0x401000, 0x2000), 0);
    CHECK_EQ(flushes, 2);
    CHECK_EQ(last_flush, 0x402000);
    CHECK_EQ(vmm_query(&v, 0x401000, NULL, NULL), -BV_ENOENT);
    CHECK_EQ(vmm_query(&v, 0x400000, NULL, NULL), 0);
    CHECK_EQ(vmm_unmap(&v, 0x401000, 0x1000), -BV_ENOENT);
    CHECK_EQ(vmm_unmap(&v, 0x400800, 0x1000), -BV_EINVAL);
    CHECK_EQ(vmm_map(&v, 0x401000, 0x777000, 0x1000, 0), 0);
    CHECK_EQ(vmm_query(&v, 0x401000, &pa, NULL), 0);
    CHECK_EQ(pa, 0x777000);

    /* protect */
    CHECK_EQ(vmm_protect(&v, 0x400000, 0x1000, 0), 0);
    CHECK_EQ(vmm_query(&v, 0x400000, &pa, &fl), 0);
    CHECK_EQ(fl, 0);
    CHECK_EQ(pa, 0x123000);
    CHECK_EQ(vmm_protect(&v, 0x400000, 0x3000, VMM_WRITE), -BV_ENOENT);
    CHECK_EQ(vmm_query(&v, 0x400000, NULL, &fl), 0);
    CHECK_EQ(fl, 0);

    /* table frames are committed (pinned) and never released */
    for (int i = 0; i < NPAGES; i++)
        if (used[i])
            CHECK(pinned[i]);
    CHECK_EQ((uint64_t)in_use(), v.tables);

    /* the walker visits every live table exactly once and nothing else */
    int seen[NPAGES] = { 0 };
    CHECK_EQ(vmm_walk_tables(&v, count_table, seen), v.tables);
    int walk_ok = 1;
    for (int i = 0; i < NPAGES; i++)
        walk_ok &= seen[i] == pinned[i];
    CHECK(walk_ok);

    /* every table store so far happened inside the write window */
    check_window();

    /* writable aliases of table frames are refused before anything is allocated or written */
    uint64_t tbl = v.root;
    s = snapshot();
    allocs = 0;
    CHECK_EQ(vmm_map(&v, 0x7000000, tbl, 0x1000, VMM_WRITE), -BV_EPERM);
    CHECK_EQ(vmm_map(&v, far + (2ull << 30), tbl - 0x1000, 0x3000, VMM_WRITE), -BV_EPERM);
    CHECK_EQ(allocs, 0);
    CHECK_EQ(snapshot(), s);
    CHECK_EQ(vmm_query(&v, 0x7000000, NULL, NULL), -BV_ENOENT);
    CHECK_EQ(vmm_query(&v, far + (2ull << 30), NULL, NULL), -BV_ENOENT);
    CHECK_EQ(vmm_map(&v, 0x7000000, tbl, 0x1000, 0), 0); /* a read-only view is allowed */
    s = snapshot();
    CHECK_EQ(vmm_protect(&v, 0x7000000, 0x1000, VMM_WRITE), -BV_EPERM);
    CHECK_EQ(vmm_query(&v, 0x7000000, NULL, &fl), 0);
    CHECK_EQ(fl, 0);
    CHECK_EQ(snapshot(), s);
    CHECK_EQ(vmm_map(&v, 0x7001000, 0x5000, 0x1000, VMM_WRITE), 0); /* ordinary frames still map */
    check_window();

    /* the window check notices a store made outside the window */
    mem[v.root - PHYS_BASE + 8] ^= 1;
    f_write_begin(NULL);
    f_write_end(NULL);
    CHECK_EQ(outside_writes, 1);
    mem[v.root - PHYS_BASE + 8] ^= 1;
    outside_writes = 0;
    sealed = tables_hash();

    /* a CPU without NX: no NX bit is ever written, everything reads back executable */
    reset(&v, 0);
    CHECK_EQ(vmm_map(&v, 0x1000, 0x1000, 0x1000, VMM_WRITE), 0);
    CHECK_EQ(vmm_query(&v, 0x1000, NULL, &fl), 0);
    CHECK_EQ(fl, VMM_WRITE | VMM_EXEC);
    CHECK_EQ(vmm_map(&v, 0x2000, 0x1000, 0x1000, VMM_WRITE | VMM_EXEC), -BV_EINVAL);

    /* filling every frame: the failing map gives all frames back */
    reset(&v, 1);
    int before = in_use();
    uint64_t a = 0;
    int rc;
    while ((rc = vmm_map(&v, a, 0x1000, 0x1000, 0)) == 0)
        a += 1ull << 21;
    CHECK_EQ(rc, -BV_ENOMEM);
    CHECK_EQ((uint64_t)in_use(), v.tables);
    CHECK(in_use() > before);
    CHECK_EQ(vmm_query(&v, a, NULL, NULL), -BV_ENOENT);
    CHECK_EQ(vmm_query(&v, a - (1ull << 21), NULL, NULL), 0);
    check_window();

    reclamation(&v);
    free(mem);
    return report("vmm");
}
