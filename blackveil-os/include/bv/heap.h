#ifndef BV_HEAP_H
#define BV_HEAP_H

#include <stddef.h>
#include <stdint.h>

/*
 * General-purpose allocator over one contiguous virtual range that grows upward a page
 * run at a time. Pure code, host-tested. Blocks carry a tagged header and footer, so
 * frees of pointers it never returned, double frees and overruns are refused. The tags are
 * integrity checks against stray writes, not secrets: a deliberate forger can recompute them.
 *
 * Every free block and free-list link is validated before the allocator acts on it, and all
 * checks run before anything is changed. Free payloads (after the list links) are filled with
 * HEAP_POISON; the bytes an allocation hands out are checked first, and heap_check() verifies
 * every free block. Writes after free are caught only when they hit poisoned bytes.
 */
#define HEAP_ALIGN       16u
#define HEAP_PAGE        4096u
#define HEAP_GROW_MIN    (16u * HEAP_PAGE)
#define HEAP_MAX_ALIGN   (2u << 20)
#define HEAP_MAX_REQUEST (1ull << 40)
#define HEAP_POISON      0x6Bu

struct heap_ops {
    /* Back [va, va+len) with fresh writable memory; all-or-nothing. */
    int (*grow)(void *ctx, uintptr_t va, size_t len);
    void *ctx;
};

struct heap_stats {
    uint64_t mapped;         /* bytes backed by memory: in_use + free */
    uint64_t in_use;         /* bytes in allocated blocks, metadata included */
    uint64_t free;           /* bytes in free blocks */
    uint64_t requested;      /* bytes callers asked for in live allocations */
    uint64_t peak_requested;
    uint64_t peak_in_use;
    uint64_t live;           /* allocations not yet freed */
    uint64_t allocs, frees;  /* successful calls */
    uint64_t failed_allocs;
    uint64_t rejected_frees; /* invalid, double or corrupted */
};

struct heap {
    uintptr_t base, brk, limit;
    void *free_list; /* address-ordered */
    struct heap_stats st;
    struct heap_ops ops;
};

/* `base` and `len` must be page-aligned; nothing is mapped until the first allocation. */
int heap_init(struct heap *h, uintptr_t base, size_t len, const struct heap_ops *ops);

/*
 * align: power of two up to HEAP_MAX_ALIGN (smaller than 16 is rounded up).
 * -BV_EINVAL: size 0, bad align or NULL out. -BV_ENOMEM: too big or no memory left.
 * -BV_EFAULT: a free block, free-list link or poisoned byte it needed was corrupted.
 * Any failure leaves the heap unchanged and sets *out to NULL.
 */
int heap_alloc(struct heap *h, size_t size, size_t align, void **out);

/*
 * NULL is a no-op. -BV_EINVAL: not a live allocation, -BV_EALREADY: already freed,
 * -BV_EFAULT: block metadata, the bytes after the request, a neighbouring block or a free-list
 * link it would touch was overwritten. Every rejection leaves the heap unchanged.
 */
int heap_free(struct heap *h, void *ptr);

/* Walks every block and the free list; -BV_EFAULT if anything or any statistic disagrees. */
int heap_check(const struct heap *h);
uint64_t heap_largest_free(const struct heap *h);

#endif
