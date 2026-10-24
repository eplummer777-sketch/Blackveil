#ifndef BV_VMM_H
#define BV_VMM_H

#include <stdbool.h>
#include <stdint.h>

/* 4-level x86-64 page tables with 4 KiB leaves. Pure code, host-tested. */
#define VMM_WRITE 1u
#define VMM_EXEC  2u

struct vmm_ops {
    int (*alloc)(void *ctx, uint64_t *phys);  /* any free frame */
    void (*release)(void *ctx, uint64_t phys); /* return a frame that never became a table */
    void (*commit)(void *ctx, uint64_t phys);  /* frame is now a live table */
    void *(*virt)(void *ctx, uint64_t phys);
    void (*flush)(void *ctx, uint64_t va);     /* drop a stale TLB entry */
    void (*flush_all)(void *ctx);              /* drop every cached translation and paging-structure entry */
    void (*retire)(void *ctx, uint64_t phys);  /* a table frame that is unlinked and flushed: unpin and free it */
    int (*allow)(void *ctx, uint64_t pa, unsigned flags); /* veto a mapping of pa, e.g. writable alias */
    void (*write_begin)(void *ctx);            /* every store into a live table is bracketed by these */
    void (*write_end)(void *ctx);
    void *ctx;
};

struct vmm {
    uint64_t root;
    uint64_t tables;    /* live table pages, root included */
    uint64_t reclaimed; /* table pages retired since vmm_init */
    bool nx;         /* CPU honours the no-execute bit */
    struct vmm_ops ops;
};

int vmm_init(struct vmm *v, const struct vmm_ops *ops, bool nx);

/*
 * All four calls are all-or-nothing: every page is validated and every needed table frame
 * obtained before anything changes, so a failure leaves the tables exactly as they were.
 * -BV_EINVAL: misaligned, empty, wrapping or non-canonical range, or WRITE|EXEC together.
 * map/protect also return whatever ops.allow() returns for any target frame (e.g. -BV_EPERM).
 */
int vmm_map(struct vmm *v, uint64_t va, uint64_t pa, uint64_t len, unsigned flags); /* -BV_EBUSY, -BV_ENOMEM */
/*
 * Tables left empty are reclaimed lowest level first (never the root): unlinked inside the write
 * window, then flush_all, then retire. A table still holding any entry is never touched.
 */
int vmm_unmap(struct vmm *v, uint64_t va, uint64_t len);                             /* -BV_ENOENT */
int vmm_protect(struct vmm *v, uint64_t va, uint64_t len, unsigned flags);           /* -BV_ENOENT */
int vmm_query(const struct vmm *v, uint64_t va, uint64_t *pa, unsigned *flags);      /* -BV_ENOENT */

/* Calls fn for every live table frame (root first); returns how many were visited. */
uint64_t vmm_walk_tables(const struct vmm *v, void (*fn)(void *arg, uint64_t phys), void *arg);

#endif
