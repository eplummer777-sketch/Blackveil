/* Host-side unit tests for memory-map validation (mm/memmap.c). */
#include "check.h"
#include <bv/errno.h>
#include <bv/memmap.h>

#define GIB (1ull << 30)

static struct memmap mm;

static int parse(const struct mbmap *m, uint64_t limit)
{
    return memmap_parse(m->buf, m->len, limit, &mm);
}

int main(void)
{
    struct mbmap m = { 0 };

    mbmap_qemu_128m(&m);
    CHECK_EQ(parse(&m, GIB), 0);
    CHECK_EQ(mm.raw_entries, 6);
    CHECK_EQ(mm.count, 2);
    CHECK_EQ(mm.usable[0].base, 0);
    CHECK_EQ(mm.usable[0].end, 0x9f000);
    CHECK_EQ(mm.usable[1].base, 0x100000);
    CHECK_EQ(mm.usable[1].end, 0x7fe0000);
    CHECK_EQ(memmap_usable_bytes(&mm), 0x9f000 + 0x7ee0000);
    CHECK_EQ(mm.clipped_bytes, 0);

    /* Unsorted, overlapping and adjacent usable ranges merge. */
    m = (struct mbmap){ 0 };
    mbmap_add(&m, 0x300000, 0x100000, 1);
    mbmap_add(&m, 0x100000, 0x180000, 1);
    mbmap_add(&m, 0x200000, 0x100000, 1);
    CHECK_EQ(parse(&m, GIB), 0);
    CHECK_EQ(mm.count, 1);
    CHECK_EQ(mm.usable[0].base, 0x100000);
    CHECK_EQ(mm.usable[0].end, 0x400000);

    /* A non-usable range inside usable memory splits it, rounded outward to whole pages. */
    m = (struct mbmap){ 0 };
    mbmap_add(&m, 0x100000, 0x400000, 1);
    mbmap_add(&m, 0x200800, 0x100, 2);
    CHECK_EQ(parse(&m, GIB), 0);
    CHECK_EQ(mm.count, 2);
    CHECK_EQ(mm.usable[0].end, 0x200000);
    CHECK_EQ(mm.usable[1].base, 0x201000);
    CHECK_EQ(mm.usable[1].end, 0x500000);

    /* Reserved listed before usable still wins; unknown types count as reserved. */
    m = (struct mbmap){ 0 };
    mbmap_add(&m, 0x0, 0x2000, 7);
    mbmap_add(&m, 0x0, 0x10000, 1);
    mbmap_add(&m, 0xf000, 0x2000, 3);
    CHECK_EQ(parse(&m, GIB), 0);
    CHECK_EQ(mm.count, 1);
    CHECK_EQ(mm.usable[0].base, 0x2000);
    CHECK_EQ(mm.usable[0].end, 0xf000);

    /* Unaligned usable ranges shrink inward; sub-page ranges disappear. */
    m = (struct mbmap){ 0 };
    mbmap_add(&m, 0x100123, 0x3000, 1);
    mbmap_add(&m, 0x900010, 0xff0, 1);
    CHECK_EQ(parse(&m, GIB), 0);
    CHECK_EQ(mm.count, 1);
    CHECK_EQ(mm.usable[0].base, 0x101000);
    CHECK_EQ(mm.usable[0].end, 0x103000);

    /* Memory at or above the limit is clipped and counted. */
    m = (struct mbmap){ 0 };
    mbmap_add(&m, 0x100000, 0x50000000, 1);
    mbmap_add(&m, 0x100000000ull, 0x40000000, 1);
    CHECK_EQ(parse(&m, GIB), 0);
    CHECK_EQ(mm.count, 1);
    CHECK_EQ(mm.usable[0].end, GIB);
    CHECK_EQ(mm.clipped_bytes, 0x100000 + 0x50000000 - GIB + 0x40000000);

    /* Zero-length and address-wrapping entries are skipped, not trusted. */
    m = (struct mbmap){ 0 };
    mbmap_add(&m, 0x100000, 0, 1);
    mbmap_add(&m, 0xfffffffffffff000ull, 0x2000, 1);
    mbmap_add(&m, 0x200000, 0x1000, 1);
    CHECK_EQ(parse(&m, GIB), 0);
    CHECK_EQ(mm.skipped_entries, 2);
    CHECK_EQ(mm.count, 1);

    /* Larger entry size fields are honoured (the extra bytes are skipped). */
    m = (struct mbmap){ 0 };
    mbmap_add_sized(&m, 28, 0x100000, 0x1000, 1);
    mbmap_add(&m, 0x300000, 0x1000, 1);
    CHECK_EQ(parse(&m, GIB), 0);
    CHECK_EQ(mm.count, 2);

    /* Malformed maps are rejected outright. */
    m = (struct mbmap){ 0 };
    mbmap_add_sized(&m, 12, 0x100000, 0x1000, 1);
    CHECK_EQ(parse(&m, GIB), -BV_EINVAL);
    m = (struct mbmap){ 0 };
    mbmap_add(&m, 0x100000, 0x1000, 1);
    m.len -= 3;
    CHECK_EQ(parse(&m, GIB), -BV_EINVAL);
    CHECK_EQ(memmap_parse(m.buf, 0, GIB, &mm), -BV_EINVAL);
    CHECK_EQ(memmap_parse(NULL, 24, GIB, &mm), -BV_EINVAL);

    /* No usable memory at all. */
    m = (struct mbmap){ 0 };
    mbmap_add(&m, 0x0, 0x100000, 2);
    CHECK_EQ(parse(&m, GIB), -BV_ENOMEM);
    m = (struct mbmap){ 0 };
    mbmap_add(&m, 2 * GIB, 0x100000, 1);
    CHECK_EQ(parse(&m, GIB), -BV_ENOMEM);

    /* Too many entries, and too much fragmentation, are bounded. */
    m = (struct mbmap){ 0 };
    for (int i = 0; i < 2 * MEMMAP_MAX + 1; i++)
        mbmap_add(&m, (uint64_t)i * 0x2000, 0x1000, 2);
    CHECK_EQ(parse(&m, GIB), -BV_ENOSPC);
    m = (struct mbmap){ 0 };
    mbmap_add(&m, 0, 0x1000000, 1);
    for (int i = 1; i <= MEMMAP_MAX; i++)
        mbmap_add(&m, (uint64_t)i * 0x2000, 0x1000, 2);
    CHECK_EQ(parse(&m, GIB), -BV_ENOSPC);

    /* Raw iteration stops cleanly at the end. */
    m = (struct mbmap){ 0 };
    mbmap_add(&m, 0x1000, 0x2000, 1);
    struct mb_mmap_entry e;
    uint32_t off = 0;
    CHECK_EQ(memmap_raw_next(m.buf, m.len, &off, &e), 1);
    CHECK_EQ(e.base, 0x1000);
    CHECK_EQ(e.len, 0x2000);
    CHECK_EQ(e.type, 1);
    CHECK_EQ(memmap_raw_next(m.buf, m.len, &off, &e), 0);

    return report("memmap");
}
