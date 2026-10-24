/* Multiboot v1 memory-map validation and normalization. Pure code, host-tested. */
#include <bv/errno.h>
#include <bv/memmap.h>
#include <stdbool.h>

#define PAGE_MASK ((uint64_t)PAGE_SIZE - 1)

static uint64_t load_le(const uint8_t *p, int bytes)
{
    uint64_t v = 0;
    for (int i = bytes - 1; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

int memmap_raw_next(const void *buf, uint32_t length, uint32_t *offset, struct mb_mmap_entry *e)
{
    const uint8_t *b = buf;
    uint64_t off = *offset;
    if (off >= length)
        return 0;
    if (length - off < 4)
        return -BV_EINVAL;
    uint64_t size = load_le(b + off, 4);
    if (size < 20 || size > length - off - 4)
        return -BV_EINVAL;
    e->base = load_le(b + off + 4, 8);
    e->len = load_le(b + off + 12, 8);
    e->type = (uint32_t)load_le(b + off + 20, 4);
    *offset = (uint32_t)(off + 4 + size);
    return 1;
}

static int add_range(struct mem_range *r, size_t *n, uint64_t base, uint64_t end)
{
    if (base >= end)
        return 0;
    if (*n >= MEMMAP_MAX)
        return -BV_ENOSPC;
    r[(*n)++] = (struct mem_range){ base, end };
    return 0;
}

static void remove_at(struct mem_range *r, size_t *n, size_t i)
{
    for (size_t j = i + 1; j < *n; j++)
        r[j - 1] = r[j];
    (*n)--;
}

static int subtract(struct mem_range *r, size_t *n, uint64_t base, uint64_t end)
{
    for (size_t i = 0; i < *n;) {
        struct mem_range cur = r[i];
        if (end <= cur.base || base >= cur.end) {
            i++;
            continue;
        }
        bool left = cur.base < base, right = cur.end > end;
        if (left && right) {
            r[i].end = base;
            int err = add_range(r, n, end, cur.end);
            if (err)
                return err;
            i++;
        } else if (left) {
            r[i++].end = base;
        } else if (right) {
            r[i++].base = end;
        } else {
            remove_at(r, n, i);
        }
    }
    return 0;
}

static void sort_and_merge(struct mem_range *r, size_t *n)
{
    for (size_t i = 1; i < *n; i++) {
        struct mem_range k = r[i];
        size_t j = i;
        while (j > 0 && r[j - 1].base > k.base) {
            r[j] = r[j - 1];
            j--;
        }
        r[j] = k;
    }
    size_t w = 0;
    for (size_t i = 0; i < *n; i++) {
        if (w > 0 && r[i].base <= r[w - 1].end) {
            if (r[i].end > r[w - 1].end)
                r[w - 1].end = r[i].end;
        } else {
            r[w++] = r[i];
        }
    }
    *n = w;
}

int memmap_parse(const void *buf, uint32_t length, uint64_t limit, struct memmap *out)
{
    struct mem_range holes[MEMMAP_MAX];
    size_t nholes = 0;
    *out = (struct memmap){ 0 };
    limit &= ~PAGE_MASK;
    if (!buf || length == 0)
        return -BV_EINVAL;

    struct mb_mmap_entry e;
    uint32_t off = 0;
    int rc;
    while ((rc = memmap_raw_next(buf, length, &off, &e)) == 1) {
        if (++out->raw_entries > 2 * MEMMAP_MAX)
            return -BV_ENOSPC;
        uint64_t end = e.base + e.len;
        if (e.len == 0 || end < e.base) {
            out->skipped_entries++;
            continue;
        }
        if (e.type == MEM_USABLE) {
            uint64_t b = (e.base + PAGE_MASK) & ~PAGE_MASK, t = end & ~PAGE_MASK;
            if (b < e.base || b >= t)
                continue;
            if (t > limit) {
                uint64_t from = b > limit ? b : limit;
                out->clipped_bytes += t - from;
                t = limit;
            }
            rc = add_range(out->usable, &out->count, b, t);
        } else {
            uint64_t t = (end + PAGE_MASK) & ~PAGE_MASK;
            rc = add_range(holes, &nholes, e.base & ~PAGE_MASK, t < end ? ~PAGE_MASK : t);
        }
        if (rc)
            return rc;
    }
    if (rc < 0)
        return rc;

    sort_and_merge(out->usable, &out->count);
    for (size_t i = 0; i < nholes; i++) {
        rc = subtract(out->usable, &out->count, holes[i].base, holes[i].end);
        if (rc)
            return rc;
    }
    sort_and_merge(out->usable, &out->count);
    return out->count ? 0 : -BV_ENOMEM;
}

uint64_t memmap_usable_bytes(const struct memmap *m)
{
    uint64_t sum = 0;
    for (size_t i = 0; i < m->count; i++)
        sum += m->usable[i].end - m->usable[i].base;
    return sum;
}

const char *memmap_type_name(uint32_t type)
{
    switch (type) {
    case MEM_USABLE: return "usable";
    case MEM_RESERVED: return "reserved";
    case MEM_ACPI: return "ACPI reclaimable";
    case MEM_NVS: return "ACPI NVS";
    case MEM_BAD: return "bad RAM";
    default: return "unknown";
    }
}
