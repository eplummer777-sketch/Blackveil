/* Page-table engine. Pure code, host-tested. */
#include <bv/errno.h>
#include <bv/memmap.h>
#include <bv/vmm.h>

#define PTE_P    0x1ull
#define PTE_W    0x2ull
#define PTE_PS   0x80ull
#define PTE_NX   (1ull << 63)
#define PTE_ADDR 0x000FFFFFFFFFF000ull

static unsigned idx(uint64_t va, int level)
{
    return (va >> (12 + 9 * level)) & 511;
}

static uint64_t *table(const struct vmm *v, uint64_t phys)
{
    return v->ops.virt(v->ops.ctx, phys);
}

static bool canonical(uint64_t va)
{
    return va < 0x0000800000000000ull || va >= 0xFFFF800000000000ull;
}

static int check_range(uint64_t va, uint64_t len)
{
    if (len == 0 || va % PAGE_SIZE || len % PAGE_SIZE)
        return -BV_EINVAL;
    uint64_t last = va + len - 1;
    if (last < va || !canonical(va) || !canonical(last) || (va >> 63) != (last >> 63))
        return -BV_EINVAL;
    return 0;
}

/* Leaf slot for va, or NULL with *missing = absent level. A large page is a leaf; *missing = its level. */
static uint64_t *lookup(const struct vmm *v, uint64_t va, int *missing, bool *huge)
{
    uint64_t *t = table(v, v->root);
    *huge = false;
    *missing = 0;
    for (int level = 3; level > 0; level--) {
        uint64_t *e = &t[idx(va, level)];
        if (!(*e & PTE_P)) {
            *missing = level;
            return NULL;
        }
        if (*e & PTE_PS) {
            *huge = true;
            *missing = level;
            return e;
        }
        t = table(v, *e & PTE_ADDR);
    }
    return &t[idx(va, 0)];
}

static uint64_t *leaf4k(const struct vmm *v, uint64_t va)
{
    int missing;
    bool huge;
    uint64_t *e = lookup(v, va, &missing, &huge);
    return e && !huge && (*e & PTE_P) ? e : NULL;
}

static uint64_t leaf_bits(const struct vmm *v, unsigned flags)
{
    return PTE_P | ((flags & VMM_WRITE) ? PTE_W : 0) | (!(flags & VMM_EXEC) && v->nx ? PTE_NX : 0);
}

static int check_flags(unsigned flags)
{
    if (flags & ~(VMM_WRITE | VMM_EXEC))
        return -BV_EINVAL;
    return (flags & VMM_WRITE) && (flags & VMM_EXEC) ? -BV_EINVAL : 0;
}

static void zero_page(const struct vmm *v, uint64_t phys)
{
    volatile uint64_t *t = table(v, phys);
    for (unsigned i = 0; i < PAGE_SIZE / 8; i++)
        t[i] = 0;
}

/* Spare frames are chained through their own first word until they become tables. */
static void pool_release(struct vmm *v, uint64_t head)
{
    while (head) {
        uint64_t next = *table(v, head);
        v->ops.release(v->ops.ctx, head);
        head = next;
    }
}

static uint64_t pool_take(struct vmm *v, uint64_t *head)
{
    uint64_t phys = *head;
    *head = *table(v, phys);
    zero_page(v, phys);
    v->ops.commit(v->ops.ctx, phys);
    v->tables++;
    return phys;
}

int vmm_init(struct vmm *v, const struct vmm_ops *ops, bool nx)
{
    *v = (struct vmm){ .nx = nx, .ops = *ops };
    uint64_t root;
    int rc = v->ops.alloc(v->ops.ctx, &root);
    if (rc)
        return rc;
    zero_page(v, root);
    v->ops.commit(v->ops.ctx, root);
    v->root = root;
    v->tables = 1;
    return 0;
}

int vmm_map(struct vmm *v, uint64_t va, uint64_t pa, uint64_t len, unsigned flags)
{
    int rc = check_range(va, len);
    if (!rc)
        rc = check_flags(flags);
    if (!rc && (pa % PAGE_SIZE || pa + len - 1 < pa || ((pa + len - 1) & ~PTE_ADDR & ~0xFFFull)))
        rc = -BV_EINVAL;
    if (rc)
        return rc;

    /* Pass 1: refuse vetoed frames and overlaps, and count the table pages this range still needs. */
    uint64_t need = 0;
    for (uint64_t off = 0; off < len; off += PAGE_SIZE) {
        uint64_t a = va + off;
        rc = v->ops.allow(v->ops.ctx, pa + off, flags);
        if (rc)
            return rc;
        int missing;
        bool huge, first = off == 0;
        uint64_t *e = lookup(v, a, &missing, &huge);
        if (e && (*e & PTE_P))
            return -BV_EBUSY;
        if (huge)
            missing = 0;
        need += missing >= 1 && (first || a % (1ull << 21) == 0);
        need += missing >= 2 && (first || a % (1ull << 30) == 0);
        need += missing >= 3 && (first || a % (1ull << 39) == 0);
    }

    uint64_t pool = 0;
    for (uint64_t i = 0; i < need; i++) {
        uint64_t phys;
        rc = v->ops.alloc(v->ops.ctx, &phys);
        if (rc) {
            pool_release(v, pool);
            return rc;
        }
        *table(v, phys) = pool;
        pool = phys;
    }

    /* Pass 2: cannot fail. */
    uint64_t bits = leaf_bits(v, flags);
    v->ops.write_begin(v->ops.ctx);
    for (uint64_t off = 0; off < len; off += PAGE_SIZE) {
        uint64_t a = va + off, *t = table(v, v->root);
        for (int level = 3; level > 0; level--) {
            uint64_t *e = &t[idx(a, level)];
            if (!(*e & PTE_P))
                *e = pool_take(v, &pool) | PTE_P | PTE_W;
            t = table(v, *e & PTE_ADDR);
        }
        t[idx(a, 0)] = (pa + off) | bits;
    }
    v->ops.write_end(v->ops.ctx);
    pool_release(v, pool);
    return 0;
}

static int check_mapped(const struct vmm *v, uint64_t va, uint64_t len)
{
    int rc = check_range(va, len);
    if (rc)
        return rc;
    for (uint64_t off = 0; off < len; off += PAGE_SIZE)
        if (!leaf4k(v, va + off))
            return -BV_ENOENT;
    return 0;
}

static bool empty(const struct vmm *v, uint64_t phys)
{
    const uint64_t *t = table(v, phys);
    for (unsigned i = 0; i < 512; i++)
        if (t[i])
            return false;
    return true;
}

/*
 * Unlinks the PT, then PD, then PDPT on va's path while each is empty. Unlinked frames are chained
 * through their first word (a page-aligned value, so never a present entry) for retirement.
 */
static void prune(struct vmm *v, uint64_t va, uint64_t *dead)
{
    uint64_t *slot[3], phys[3];
    uint64_t *t = table(v, v->root);
    int levels = 0;
    for (int level = 3; level > 0; level--) {
        uint64_t *e = &t[idx(va, level)];
        if (!(*e & PTE_P) || (*e & PTE_PS))
            break;
        slot[levels] = e;
        phys[levels++] = *e & PTE_ADDR;
        t = table(v, *e & PTE_ADDR);
    }
    while (levels > 0 && empty(v, phys[levels - 1])) {
        levels--;
        *slot[levels] = 0;
        *table(v, phys[levels]) = *dead;
        *dead = phys[levels];
        v->tables--;
        v->reclaimed++;
    }
}

int vmm_unmap(struct vmm *v, uint64_t va, uint64_t len)
{
    int rc = check_mapped(v, va, len);
    if (rc)
        return rc;
    uint64_t dead = 0;
    v->ops.write_begin(v->ops.ctx);
    for (uint64_t off = 0; off < len; off += PAGE_SIZE) {
        *leaf4k(v, va + off) = 0;
        v->ops.flush(v->ops.ctx, va + off);
    }
    /* Each page table is examined once, at its last page inside the range. */
    for (uint64_t off = 0; off < len; off += PAGE_SIZE) {
        uint64_t a = va + off;
        if (off + PAGE_SIZE == len || (a + PAGE_SIZE) % (1ull << 21) == 0)
            prune(v, a, &dead);
    }
    v->ops.write_end(v->ops.ctx);
    if (!dead)
        return 0;
    /* Nothing may reuse a frame the CPU could still reach through a cached upper-level entry. */
    v->ops.flush_all(v->ops.ctx);
    while (dead) {
        uint64_t next = *table(v, dead);
        v->ops.retire(v->ops.ctx, dead);
        dead = next;
    }
    return 0;
}

int vmm_protect(struct vmm *v, uint64_t va, uint64_t len, unsigned flags)
{
    int rc = check_flags(flags);
    if (!rc)
        rc = check_mapped(v, va, len);
    for (uint64_t off = 0; !rc && off < len; off += PAGE_SIZE)
        rc = v->ops.allow(v->ops.ctx, *leaf4k(v, va + off) & PTE_ADDR, flags);
    if (rc)
        return rc;
    uint64_t bits = leaf_bits(v, flags);
    v->ops.write_begin(v->ops.ctx);
    for (uint64_t off = 0; off < len; off += PAGE_SIZE) {
        uint64_t *e = leaf4k(v, va + off);
        *e = (*e & PTE_ADDR) | bits;
        v->ops.flush(v->ops.ctx, va + off);
    }
    v->ops.write_end(v->ops.ctx);
    return 0;
}

static uint64_t walk(const struct vmm *v, uint64_t phys, int level, void (*fn)(void *, uint64_t), void *arg)
{
    fn(arg, phys);
    uint64_t n = 1;
    if (level == 0)
        return n;
    const uint64_t *t = table(v, phys);
    for (unsigned i = 0; i < 512; i++)
        if ((t[i] & PTE_P) && !(t[i] & PTE_PS))
            n += walk(v, t[i] & PTE_ADDR, level - 1, fn, arg);
    return n;
}

uint64_t vmm_walk_tables(const struct vmm *v, void (*fn)(void *arg, uint64_t phys), void *arg)
{
    return walk(v, v->root, 3, fn, arg);
}

int vmm_query(const struct vmm *v, uint64_t va, uint64_t *pa, unsigned *flags)
{
    if (!canonical(va))
        return -BV_EINVAL;
    int missing;
    bool huge;
    uint64_t *e = lookup(v, va, &missing, &huge);
    if (!e || !(*e & PTE_P))
        return -BV_ENOENT;
    uint64_t mask = huge ? (1ull << (12 + 9 * missing)) - 1 : PAGE_SIZE - 1;
    if (pa)
        *pa = (*e & PTE_ADDR & ~mask) | (va & mask);
    if (flags)
        *flags = ((*e & PTE_W) ? VMM_WRITE : 0) | ((*e & PTE_NX) && v->nx ? 0 : VMM_EXEC);
    return 0;
}
