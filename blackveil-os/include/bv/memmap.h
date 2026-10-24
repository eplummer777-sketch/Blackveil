#ifndef BV_MEMMAP_H
#define BV_MEMMAP_H

#include <stddef.h>
#include <stdint.h>

#define PAGE_SIZE  4096u
#define MEMMAP_MAX 64

enum mem_type { MEM_USABLE = 1, MEM_RESERVED = 2, MEM_ACPI = 3, MEM_NVS = 4, MEM_BAD = 5 };

struct mb_mmap_entry {
    uint64_t base;
    uint64_t len;
    uint32_t type;
};

/* Half-open [base, end). */
struct mem_range {
    uint64_t base;
    uint64_t end;
};

struct memmap {
    struct mem_range usable[MEMMAP_MAX]; /* sorted, page-aligned, disjoint, non-adjacent */
    size_t count;
    uint32_t raw_entries;
    uint32_t skipped_entries; /* zero-length or address-wrapping entries */
    uint64_t clipped_bytes;   /* usable bytes at or above the limit, ignored */
};

/*
 * Reads the Multiboot v1 entry at *offset and advances it.
 * Returns 1 when an entry was read, 0 at the end, -BV_EINVAL if malformed.
 */
int memmap_raw_next(const void *buf, uint32_t length, uint32_t *offset, struct mb_mmap_entry *e);

/*
 * Validates and normalizes a Multiboot v1 memory map into page-aligned usable
 * ranges below `limit`. Any range the firmware marks non-usable wins over an
 * overlapping usable one. Rejects malformed maps (-BV_EINVAL), maps with more than
 * MEMMAP_MAX entries or fragments (-BV_ENOSPC), and maps with no usable memory.
 */
int memmap_parse(const void *buf, uint32_t length, uint64_t limit, struct memmap *out);

uint64_t memmap_usable_bytes(const struct memmap *m);
const char *memmap_type_name(uint32_t type);

#endif
