#ifndef BV_PMM_H
#define BV_PMM_H

#include <bv/memmap.h>
#include <stddef.h>
#include <stdint.h>

/* Physical frame allocator: one "used" and one "reserved" bit per 4 KiB frame. */
struct pmm {
    uint64_t *used;
    uint64_t *reserved;
    uint64_t nframes;
    uint64_t usable_frames;
    uint64_t free_frames;
    uint64_t reserved_frames; /* usable frames later withheld by pmm_reserve() */
    uint64_t next_word;       /* search hint */
};

enum pmm_state { PMM_FREE, PMM_USED, PMM_RESERVED, PMM_OUT_OF_RANGE };

/* Frames outside the map's usable ranges start reserved. `words` is the bitmap capacity. */
int pmm_init(struct pmm *p, uint64_t *used, uint64_t *reserved, size_t words, const struct memmap *m);

/* Withholds every frame touching [base, base+len). Fails without changes if any is allocated. */
int pmm_reserve(struct pmm *p, uint64_t base, uint64_t len);

int pmm_alloc(struct pmm *p, uint64_t *phys);

/* Lowest free frame whose whole page lies below `limit`; -BV_ENOMEM (no change) if none. */
int pmm_alloc_below(struct pmm *p, uint64_t limit, uint64_t *phys);

/* Bitmap words needed to cover every frame up to the end of the map's last usable range. */
uint64_t pmm_words_for(const struct memmap *m);

/*
 * Finds the lowest page-aligned base for `bytes` inside one usable range, ending at or below `limit`
 * and overlapping none of `avoid`. -BV_EINVAL for a zero or overflowing size, -BV_ENOMEM if nothing
 * fits; *base is only written on success.
 */
int pmm_place(const struct memmap *m, uint64_t bytes, const struct mem_range *avoid, size_t navoid, uint64_t limit,
              uint64_t *base);

/* -BV_EINVAL: misaligned/out of range, -BV_EPERM: reserved, -BV_EALREADY: double free. */
int pmm_free(struct pmm *p, uint64_t phys);

/* Permanently withholds an allocated frame (e.g. a live page table): later frees get -BV_EPERM. */
int pmm_pin(struct pmm *p, uint64_t phys);

/*
 * Undoes pmm_pin, leaving the frame allocated. The bitmap cannot tell a pin from a boot reservation,
 * so callers must first rule out reserved boot ranges. -BV_EINVAL: not reserved, -BV_EFAULT: counter
 * already zero.
 */
int pmm_unpin(struct pmm *p, uint64_t phys);

/*
 * -BV_EFAULT if the bitmaps disagree with the counters: a reserved frame not marked used, a frame
 * past the end marked free, or free/reserved counts that do not match the bits.
 */
int pmm_check(const struct pmm *p);

enum pmm_state pmm_state_of(const struct pmm *p, uint64_t phys);

#endif
