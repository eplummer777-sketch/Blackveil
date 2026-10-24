/* Host-side unit tests for the physical frame allocator (mm/pmm.c). */
#include "check.h"
#include <bv/errno.h>
#include <bv/pmm.h>
#include <stdlib.h>

#define WORDS ((1ull << 30) / PAGE_SIZE / 64)

static uint64_t used[WORDS], reserved[WORDS];
static uint8_t seen[(1u << 30) / PAGE_SIZE];
static uint64_t got[(1u << 30) / PAGE_SIZE];
static struct memmap mm;
static uint64_t used_copy[WORDS], reserved_copy[WORDS];
static struct pmm pmm_copy;

static void save(const struct pmm *p)
{
    memcpy(used_copy, used, sizeof used);
    memcpy(reserved_copy, reserved, sizeof reserved);
    pmm_copy = *p;
}

static int unchanged(const struct pmm *p)
{
    return !memcmp(used_copy, used, sizeof used) && !memcmp(reserved_copy, reserved, sizeof reserved) &&
           !memcmp(&pmm_copy, p, sizeof *p);
}

/* Applies one corruption, expects pmm_check to catch it, then undoes it. */
#define CORRUPT(lvalue, expr)                     \
    do {                                          \
        uint64_t keep_ = (lvalue);                \
        (lvalue) = (expr);                        \
        CHECK_EQ(pmm_check(&p), -BV_EFAULT);      \
        (lvalue) = keep_;                         \
        CHECK_EQ(pmm_check(&p), 0);               \
    } while (0)

#define GIB (1ull << 30)

/* The layout QEMU reports for -m 5G: RAM below 3 GiB, the PCI hole, then RAM from 4 GiB to 6 GiB. */
static void mbmap_qemu_5g(struct mbmap *m)
{
    mbmap_add(m, 0x0, 0x9fc00, 1);
    mbmap_add(m, 0x9fc00, 0x400, 2);
    mbmap_add(m, 0xf0000, 0x10000, 2);
    mbmap_add(m, 0x100000, 3 * GIB - 0x120000, 1);
    mbmap_add(m, 3 * GIB - 0x20000, 0x20000, 2);
    mbmap_add(m, 0xfffc0000, 0x40000, 2);
    mbmap_add(m, 4 * GIB, 2 * GIB, 1);
    mbmap_add(m, 0xfd00000000ull, 0x300000000ull, 2);
}

static void high_memory(void)
{
    struct mbmap m = { 0 };
    struct memmap hm;
    struct pmm p;
    uint64_t a;

    mbmap_qemu_5g(&m);
    CHECK_EQ(memmap_parse(m.buf, m.len, 16 * GIB, &hm), 0);
    CHECK_EQ(hm.count, 3);
    CHECK_EQ(hm.usable[2].base, 4 * GIB);
    CHECK_EQ(hm.usable[2].end, 6 * GIB);
    CHECK_EQ(hm.clipped_bytes, 0);
    uint64_t words = pmm_words_for(&hm);
    CHECK_EQ(words, 6 * GIB / PAGE_SIZE / 64);
    uint64_t *u = malloc(words * 8), *r = malloc(words * 8), *uc = malloc(words * 8), *rc = malloc(words * 8);
    uint8_t *seen_hi = calloc(6 * GIB / PAGE_SIZE, 1);
    CHECK_EQ(pmm_init(&p, u, r, words - 1, &hm), -BV_ENOSPC);
    CHECK_EQ(pmm_init(&p, u, r, words, &hm), 0);
    CHECK_EQ(p.nframes, 6 * GIB / PAGE_SIZE);
    uint64_t low_usable = 0x9f + (3 * GIB - 0x120000) / PAGE_SIZE;
    CHECK_EQ(p.usable_frames, low_usable + 2 * GIB / PAGE_SIZE);
    CHECK_EQ(pmm_state_of(&p, 3 * GIB), PMM_RESERVED);
    CHECK_EQ(pmm_state_of(&p, 4 * GIB - PAGE_SIZE), PMM_RESERVED);
    CHECK_EQ(pmm_state_of(&p, 4 * GIB), PMM_FREE);
    CHECK_EQ(pmm_state_of(&p, 6 * GIB - PAGE_SIZE), PMM_FREE);
    CHECK_EQ(pmm_state_of(&p, 6 * GIB), PMM_OUT_OF_RANGE);
    CHECK_EQ(pmm_state_of(&p, UINT64_MAX), PMM_OUT_OF_RANGE);
    CHECK_EQ(pmm_check(&p), 0);

    /* Reservations above 4 GiB, one straddling the end of RAM, and one wrapping the address space. */
    CHECK_EQ(pmm_reserve(&p, 0, 0x100000), 0);
    CHECK_EQ(pmm_reserve(&p, 5 * GIB, 0x1800), 0);
    CHECK_EQ(pmm_state_of(&p, 5 * GIB + PAGE_SIZE), PMM_RESERVED);
    CHECK_EQ(pmm_reserve(&p, 6 * GIB - PAGE_SIZE, GIB), 0);
    CHECK_EQ(pmm_reserve(&p, 7 * GIB, PAGE_SIZE), 0);
    uint64_t res = p.reserved_frames;
    CHECK_EQ(res, 0x9f + 3);
    CHECK_EQ(pmm_reserve(&p, UINT64_MAX - 0xfff, 0x1000), -BV_EINVAL);
    CHECK_EQ(pmm_free(&p, 6 * GIB), -BV_EINVAL);
    CHECK_EQ(pmm_free(&p, UINT64_MAX & ~0xfffull), -BV_EINVAL);
    CHECK_EQ(pmm_free(&p, 1ull << 52), -BV_EINVAL);
    CHECK_EQ(pmm_pin(&p, UINT64_MAX & ~0xfffull), -BV_EINVAL);
    CHECK_EQ(pmm_free(&p, 5 * GIB), -BV_EPERM);
    CHECK_EQ(pmm_free(&p, 4 * GIB), -BV_EALREADY);
    CHECK_EQ(p.reserved_frames, res);
    CHECK_EQ(pmm_check(&p), 0);

    /* Below-limit allocation stays under the limit and fails without change once that memory is gone. */
    uint64_t n = 0, bad = 0;
    CHECK_EQ(pmm_alloc_below(&p, 0, &a), -BV_ENOMEM);
    CHECK_EQ(pmm_alloc_below(&p, 0x100fff, &a), -BV_ENOMEM);
    while (pmm_alloc_below(&p, GIB + 0x800, &a) == 0) {
        bad += a >= GIB || a < 0x100000 || seen_hi[a / PAGE_SIZE]++;
        n++;
    }
    CHECK_EQ(bad, 0);
    CHECK_EQ(n, (GIB - 0x100000) / PAGE_SIZE);
    memcpy(uc, u, words * 8);
    memcpy(rc, r, words * 8);
    struct pmm pc = p;
    CHECK_EQ(pmm_alloc_below(&p, GIB, &a), -BV_ENOMEM);
    CHECK(!memcmp(uc, u, words * 8) && !memcmp(rc, r, words * 8) && !memcmp(&pc, &p, sizeof p));
    CHECK_EQ(pmm_alloc_below(&p, UINT64_MAX, &a), 0);
    CHECK_EQ(a, GIB);
    seen_hi[a / PAGE_SIZE]++;

    /* The rest drains from above 1 GiB and above 4 GiB, never from holes, reserved or missing frames. */
    uint64_t above4 = 0, top = 0;
    while (pmm_alloc(&p, &a) == 0) {
        bad += a % PAGE_SIZE || a >= 6 * GIB || (a >= 3 * GIB - 0x20000 && a < 4 * GIB) ||
               pmm_state_of(&p, a) != PMM_USED || seen_hi[a / PAGE_SIZE]++;
        above4 += a >= 4 * GIB;
        top = a > top ? a : top;
    }
    CHECK_EQ(bad, 0);
    CHECK_EQ(above4, 2 * GIB / PAGE_SIZE - 3);
    CHECK_EQ(top, 6 * GIB - 2 * PAGE_SIZE);
    CHECK_EQ(p.free_frames, 0);
    CHECK_EQ(pmm_check(&p), 0);
    pc = p;
    CHECK_EQ(pmm_alloc(&p, &a), -BV_ENOMEM);
    CHECK(!memcmp(&pc, &p, sizeof p));
    for (uint64_t f = 0; f < p.nframes; f++)
        if (seen_hi[f])
            bad += pmm_free(&p, f * PAGE_SIZE) != 0;
    CHECK_EQ(bad, 0);
    CHECK_EQ(p.free_frames, p.usable_frames - res);
    CHECK_EQ(pmm_check(&p), 0);
    free(u);
    free(r);
    free(uc);
    free(rc);
    free(seen_hi);

    /* Memory-map edge cases around and beyond the limit. */
    struct mbmap e = { 0 };
    mbmap_add(&e, 0x100000, GIB, 1);                       /* crosses 1 GiB */
    mbmap_add(&e, GIB + 0x100000 - 100, 0x2100, 1);         /* unaligned, merges into the first */
    mbmap_add(&e, 15 * GIB, 2 * GIB, 1);                    /* straddles the 16 GiB limit */
    mbmap_add(&e, 20 * GIB, GIB, 1);                        /* wholly above the limit */
    mbmap_add(&e, 0xFFFFFFFFFFFFF000ull, 0x2000, 1);        /* wraps */
    mbmap_add(&e, UINT64_MAX - 10, 11, 1);                  /* ends exactly at 2^64: wraps to 0 */
    mbmap_add(&e, GIB - PAGE_SIZE, 2 * PAGE_SIZE, 2);       /* hole across the 1 GiB boundary */
    CHECK_EQ(memmap_parse(e.buf, e.len, 16 * GIB + 123, &hm), 0);
    CHECK_EQ(hm.skipped_entries, 2);
    CHECK_EQ(hm.count, 3);
    CHECK_EQ(hm.usable[0].base, 0x100000);
    CHECK_EQ(hm.usable[0].end, GIB - PAGE_SIZE);
    CHECK_EQ(hm.usable[1].base, GIB + PAGE_SIZE);
    CHECK_EQ(hm.usable[1].end, GIB + 0x102000);
    CHECK_EQ(hm.usable[2].base, 15 * GIB);
    CHECK_EQ(hm.usable[2].end, 16 * GIB);
    CHECK_EQ(hm.clipped_bytes, GIB + GIB);
    CHECK_EQ(pmm_words_for(&hm), 16 * GIB / PAGE_SIZE / 64);
    struct memmap empty = { 0 };
    CHECK_EQ(pmm_words_for(&empty), 0);

    /* Frame-record placement: lowest fit below the limit, around every in-use range. */
    struct mem_range avoid[] = { { 0, 0x100000 }, { 0x100000, 0x125000 }, { 0x125000, 0x12501f }, { 0x126000, 0x127000 } };
    uint64_t base = 0xdead;
    m.len = 0;
    mbmap_qemu_5g(&m);
    CHECK_EQ(memmap_parse(m.buf, m.len, 16 * GIB, &hm), 0);
    CHECK_EQ(pmm_place(&hm, 0x3000, avoid, 4, GIB, &base), 0);
    CHECK_EQ(base, 0x127000);
    CHECK_EQ(pmm_place(&hm, 0x3000, avoid, 2, GIB, &base), 0);
    CHECK_EQ(base, 0x125000);
    CHECK_EQ(pmm_place(&hm, 0x3000, NULL, 0, GIB, &base), 0);
    CHECK_EQ(base, 0);
    CHECK_EQ(pmm_place(&hm, 2 * GIB, avoid, 4, 4 * GIB, &base), 0);
    CHECK_EQ(base, 0x127000);
    CHECK_EQ(pmm_place(&hm, 2 * GIB, avoid, 4, 7 * GIB, &base), 0);
    CHECK_EQ(base, 0x127000);
    struct mem_range low2[] = { { 0, 2 * GIB } };
    CHECK_EQ(pmm_place(&hm, 2 * GIB, low2, 1, 7 * GIB, &base), 0);
    CHECK_EQ(base, 4 * GIB);
    CHECK_EQ(pmm_place(&hm, 2 * GIB, low2, 1, 6 * GIB - 1, &base), -BV_ENOMEM);
    base = 0xdead;
    CHECK_EQ(pmm_place(&hm, 2 * GIB, avoid, 4, GIB, &base), -BV_ENOMEM);
    CHECK_EQ(pmm_place(&hm, 3 * GIB, avoid, 4, 6 * GIB - 1, &base), -BV_ENOMEM);
    CHECK_EQ(pmm_place(&hm, 0x1000, avoid, 4, 0x100000, &base), -BV_ENOMEM);
    CHECK_EQ(pmm_place(&hm, 0, avoid, 4, GIB, &base), -BV_EINVAL);
    CHECK_EQ(pmm_place(&hm, UINT64_MAX, avoid, 4, UINT64_MAX, &base), -BV_EINVAL);
    CHECK_EQ(pmm_place(&hm, UINT64_MAX - 0x1000, avoid, 4, UINT64_MAX, &base), -BV_ENOMEM);
    struct mem_range all[] = { { 0, 3 * GIB }, { 4 * GIB, UINT64_MAX } };
    CHECK_EQ(pmm_place(&hm, 0x1000, all, 2, UINT64_MAX, &base), -BV_ENOMEM);
    CHECK_EQ(pmm_place(&hm, 0x1000, all, 1, GIB, &base), -BV_ENOMEM);
    CHECK_EQ(pmm_place(&empty, 0x1000, NULL, 0, GIB, &base), -BV_ENOMEM);
    CHECK_EQ(base, 0xdead);
    struct mem_range tail[] = { { 0, 0x9f000 - 0x3000 } };
    CHECK_EQ(pmm_place(&hm, 0x3000, tail, 1, GIB, &base), 0);
    CHECK_EQ(base, 0x9c000);
    CHECK_EQ(pmm_place(&hm, 0x3001, tail, 1, GIB, &base), 0);
    CHECK_EQ(base, 0x100000);
}

int main(void)
{
    struct mbmap m = { 0 };
    struct pmm p;
    uint64_t a, b;

    mbmap_qemu_128m(&m);
    CHECK_EQ(memmap_parse(m.buf, m.len, 1ull << 30, &mm), 0);
    CHECK_EQ(pmm_init(&p, used, reserved, WORDS, &mm), 0);
    CHECK_EQ(p.nframes, 0x7fe0);
    CHECK_EQ(p.usable_frames, 0x9f + 0x7ee0);
    CHECK_EQ(p.free_frames, p.usable_frames);
    CHECK_EQ(pmm_state_of(&p, 0x9e000), PMM_FREE);
    CHECK_EQ(pmm_state_of(&p, 0xa0000), PMM_RESERVED);
    CHECK_EQ(pmm_state_of(&p, 0x7fe0000), PMM_OUT_OF_RANGE);
    CHECK_EQ(pmm_init(&p, used, reserved, 16, &mm), -BV_ENOSPC);
    CHECK_EQ(pmm_init(&p, used, reserved, WORDS, &mm), 0);

    /* Reservations: low memory, then a "kernel" ending mid-page; repeats change nothing. */
    CHECK_EQ(pmm_reserve(&p, 0, 0x100000), 0);
    CHECK_EQ(p.reserved_frames, 0x9f);
    CHECK_EQ(pmm_reserve(&p, 0x100000, 0x10001), 0);
    CHECK_EQ(p.reserved_frames, 0x9f + 17);
    CHECK_EQ(pmm_reserve(&p, 0x100000, 0x10001), 0);
    CHECK_EQ(pmm_reserve(&p, 0, 0), 0);
    CHECK_EQ(pmm_reserve(&p, 0x7000000000ull, 0x1000), 0);
    CHECK_EQ(pmm_reserve(&p, UINT64_MAX - 10, 100), -BV_EINVAL);
    CHECK_EQ(p.reserved_frames, 0x9f + 17);
    CHECK_EQ(p.free_frames, p.usable_frames - p.reserved_frames);
    CHECK_EQ(pmm_state_of(&p, 0x110000), PMM_RESERVED);
    CHECK_EQ(pmm_state_of(&p, 0x111000), PMM_FREE);

    /* First allocation skips every reserved frame. */
    CHECK_EQ(pmm_alloc(&p, &a), 0);
    CHECK_EQ(a, 0x111000);
    CHECK_EQ(pmm_state_of(&p, a), PMM_USED);

    /* Reserving a range that includes an allocated frame fails with no partial effect. */
    uint64_t before = p.free_frames, rsv = p.reserved_frames;
    CHECK_EQ(pmm_reserve(&p, a - 0x1000, 0x3000), -BV_EBUSY);
    CHECK_EQ(p.free_frames, before);
    CHECK_EQ(p.reserved_frames, rsv);
    CHECK_EQ(pmm_state_of(&p, a + 0x1000), PMM_FREE);

    /* Free errors. */
    CHECK_EQ(pmm_free(&p, a + 1), -BV_EINVAL);
    CHECK_EQ(pmm_free(&p, 0x7fe0000), -BV_EINVAL);
    CHECK_EQ(pmm_free(&p, 0x100000), -BV_EPERM);
    CHECK_EQ(pmm_free(&p, 0xa0000), -BV_EPERM);
    CHECK_EQ(pmm_free(&p, a), 0);
    CHECK_EQ(pmm_free(&p, a), -BV_EALREADY);

    /* Drain: every free frame exactly once, never a reserved one, then out of memory. */
    uint64_t start_free = p.free_frames, n = 0;
    int dup = 0, prot = 0;
    while (pmm_alloc(&p, &a) == 0) {
        if (seen[a / PAGE_SIZE]++)
            dup++;
        if (a < 0x111000 || a % PAGE_SIZE || a >= 0x7fe0000)
            prot++;
        got[n++] = a;
    }
    CHECK_EQ(n, start_free);
    CHECK_EQ(dup, 0);
    CHECK_EQ(prot, 0);
    CHECK_EQ(p.free_frames, 0);
    CHECK_EQ(pmm_alloc(&p, &a), -BV_ENOMEM);
    int bad = 0;
    for (uint64_t i = 0; i < n; i++)
        bad += pmm_free(&p, got[i]) != 0;
    CHECK_EQ(bad, 0);
    CHECK_EQ(p.free_frames, start_free);

    /* Freed low frames are found again despite the search hint. */
    CHECK_EQ(pmm_alloc(&p, &a), 0);
    CHECK_EQ(a, 0x111000);

    /* Pinning: only an allocated frame can be pinned, and a pinned frame can never be freed. */
    uint64_t free_before = p.free_frames, rsv_before = p.reserved_frames;
    CHECK_EQ(pmm_pin(&p, a), 0);
    CHECK_EQ(pmm_state_of(&p, a), PMM_RESERVED);
    CHECK_EQ(p.free_frames, free_before);
    CHECK_EQ(p.reserved_frames, rsv_before + 1);
    CHECK_EQ(pmm_free(&p, a), -BV_EPERM);
    CHECK_EQ(pmm_pin(&p, a), -BV_EPERM);
    CHECK_EQ(pmm_pin(&p, a + 0x1000), -BV_EINVAL);
    CHECK_EQ(pmm_pin(&p, a + 8), -BV_EINVAL);
    CHECK_EQ(pmm_pin(&p, p.nframes * PAGE_SIZE), -BV_EINVAL);
    CHECK_EQ(pmm_alloc(&p, &b), 0);
    CHECK(b != a);
    CHECK_EQ(pmm_check(&p), 0);

    /* Consistency check: each kind of metadata corruption is detected. a is pinned, b allocated. */
    uint64_t fa = a / PAGE_SIZE, fb = b / PAGE_SIZE, ff = fb + 1, last = (p.nframes + 63) / 64 - 1;
    CHECK_EQ(pmm_state_of(&p, ff * PAGE_SIZE), PMM_FREE);
    CORRUPT(reserved[ff / 64], reserved[ff / 64] | 1ull << (ff % 64));      /* reserved but not used */
    CORRUPT(used[ff / 64], used[ff / 64] | 1ull << (ff % 64));              /* free frame marked used */
    CORRUPT(used[fb / 64], used[fb / 64] & ~(1ull << (fb % 64)));           /* allocation lost */
    CORRUPT(reserved[fa / 64], reserved[fa / 64] & ~(1ull << (fa % 64)));   /* table frame unpinned */
    CORRUPT(used[last], used[last] & ~(1ull << 63));                        /* frame past the end freed */
    CORRUPT(reserved[last], reserved[last] & ~(1ull << 63));
    CORRUPT(p.free_frames, p.free_frames + 1);
    CORRUPT(p.free_frames, p.usable_frames + 1);
    CORRUPT(p.reserved_frames, p.reserved_frames - 1);
    CORRUPT(p.next_word, last + 1);
    CHECK(p.nframes % 64 != 0); /* the tail-bit cases above are meaningful */

    /* Failed operations leave every bit and counter exactly as it was. */
    save(&p);
    CHECK_EQ(pmm_free(&p, a), -BV_EPERM);
    CHECK_EQ(pmm_free(&p, ff * PAGE_SIZE), -BV_EALREADY);
    CHECK_EQ(pmm_free(&p, b + 8), -BV_EINVAL);
    CHECK_EQ(pmm_free(&p, p.nframes * PAGE_SIZE), -BV_EINVAL);
    CHECK_EQ(pmm_free(&p, 0x100000), -BV_EPERM);
    CHECK_EQ(pmm_pin(&p, a), -BV_EPERM);
    CHECK_EQ(pmm_pin(&p, ff * PAGE_SIZE), -BV_EINVAL);
    CHECK_EQ(pmm_reserve(&p, b - PAGE_SIZE, 3 * PAGE_SIZE), -BV_EBUSY);
    CHECK_EQ(pmm_reserve(&p, UINT64_MAX - 10, 100), -BV_EINVAL);
    CHECK(unchanged(&p));
    n = 0;
    while (pmm_alloc(&p, &a) == 0)
        got[n++] = a;
    save(&p);
    CHECK_EQ(pmm_alloc(&p, &a), -BV_ENOMEM);
    CHECK(unchanged(&p));
    CHECK_EQ(pmm_check(&p), 0);
    bad = 0;
    for (uint64_t i = 0; i < n; i++)
        bad += pmm_free(&p, got[i]) != 0;
    CHECK_EQ(bad, 0);
    CHECK_EQ(pmm_check(&p), 0);

    high_memory();
    return report("pmm");
}
