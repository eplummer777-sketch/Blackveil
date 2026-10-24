#include <bv/errno.h>
#include <bv/heap.h>
#include <stdbool.h>

#define USED      1ull
#define HDR       32u
#define FTR       16u
#define MIN_BLOCK 64u /* header + free-list links + footer */
#define GUARD     0x5AFEB10C5AFEB10Cull
#define HMAGIC    0xB1AC4EA9C0DEF00Dull
#define FMAGIC    0x7E11F00DB1AC4EA9ull
#define SLACK     0xBDu
#define POISON_AT (HDR + 16u) /* free-block bytes from here to the footer hold HEAP_POISON */

struct hdr {
    uint64_t size; /* whole block, | USED */
    uint64_t req;
    uint64_t tag;
    uint64_t guard;
};
struct ftr {
    uint64_t size;
    uint64_t tag;
};
struct links {
    struct hdr *next, *prev;
};

static uint64_t htag(const struct hdr *b, uint64_t size, uint64_t req)
{
    return HMAGIC ^ (uintptr_t)b ^ (size * 0x9E3779B97F4A7C15ull) ^ req;
}

static uint64_t ftag(const struct hdr *b, uint64_t size)
{
    return FMAGIC ^ (uintptr_t)b ^ size;
}

static uint64_t bsize(const struct hdr *b)
{
    return b->size & ~USED;
}

static struct ftr *footer(const struct hdr *b)
{
    return (struct ftr *)((uintptr_t)b + bsize(b) - FTR);
}

static struct links *links(struct hdr *b)
{
    return (struct links *)(b + 1);
}

static uint64_t round_up(uint64_t v, uint64_t a)
{
    return (v + a - 1) & ~(a - 1);
}

static bool sane_size(const struct heap *h, uintptr_t at, uint64_t s)
{
    return s >= MIN_BLOCK && s % HEAP_ALIGN == 0 && s <= h->brk - at;
}

static bool header_ok(const struct heap *h, const struct hdr *b)
{
    return b->guard == GUARD && b->tag == htag(b, b->size, b->req) && sane_size(h, (uintptr_t)b, bsize(b)) &&
           ((b->size & USED) ? b->req <= bsize(b) - HDR - FTR : b->req == 0);
}

static bool footer_ok(const struct hdr *b)
{
    const struct ftr *f = footer(b);
    return f->size == b->size && f->tag == ftag(b, b->size);
}

static bool slack_ok(const struct hdr *b)
{
    const uint8_t *p = (const uint8_t *)b + HDR + b->req, *end = (const uint8_t *)footer(b);
    for (; p < end; p++)
        if (*p != SLACK)
            return false;
    return true;
}

static void stamp(struct hdr *b, uint64_t size, uint64_t req)
{
    b->size = size;
    b->req = req;
    b->tag = htag(b, size, req);
    b->guard = GUARD;
    struct ftr *f = footer(b);
    f->size = size;
    f->tag = ftag(b, size);
}

static void link_between(struct heap *h, struct hdr *b, struct hdr *prev, struct hdr *next)
{
    links(b)->prev = prev;
    links(b)->next = next;
    if (prev)
        links(prev)->next = b;
    else
        h->free_list = b;
    if (next)
        links(next)->prev = b;
}

static void list_remove(struct heap *h, struct hdr *b)
{
    struct links *l = links(b);
    if (l->prev)
        links(l->prev)->next = l->next;
    else
        h->free_list = l->next;
    if (l->next)
        links(l->next)->prev = l->prev;
}

static bool poisoned(uintptr_t lo, uintptr_t hi)
{
    for (const volatile uint8_t *p = (const uint8_t *)lo; p < (const uint8_t *)hi; p++)
        if (*p != HEAP_POISON)
            return false;
    return true;
}

static void poison(uintptr_t lo, uintptr_t hi)
{
    for (uint8_t *p = (uint8_t *)lo; p < (uint8_t *)hi; p++)
        *p = HEAP_POISON;
}

/* A free block whose own header, footer and bounds are intact; its links are not followed. */
static bool free_ok(const struct heap *h, const struct hdr *b)
{
    uintptr_t a = (uintptr_t)b;
    return a >= h->base && a < h->brk && a % HEAP_ALIGN == 0 && h->brk - a >= MIN_BLOCK && header_ok(h, b) &&
           !(b->size & USED) && footer_ok(b);
}

/* `b` reached from `prev` in the address-ordered list: back link agrees and the two are not adjacent. */
static bool node_ok(const struct heap *h, struct hdr *b, const struct hdr *prev)
{
    return free_ok(h, b) && links(b)->prev == prev && (!prev || (uintptr_t)prev + bsize(prev) < (uintptr_t)b);
}

/* Before unlinking `b`: both neighbours are intact and point back at it. */
static bool unlink_ok(const struct heap *h, struct hdr *b)
{
    struct hdr *p = links(b)->prev, *n = links(b)->next;
    if (p ? !(free_ok(h, p) && (uintptr_t)p + bsize(p) < (uintptr_t)b && links(p)->next == b) : h->free_list != b)
        return false;
    return !n || (free_ok(h, n) && (uintptr_t)b + bsize(b) < (uintptr_t)n && links(n)->prev == b);
}

/* Where a block of `need` bytes with an `align`-aligned payload fits inside a free block, or 0. */
static uintptr_t place(const struct hdr *b, uint64_t need, uint64_t align)
{
    uintptr_t start = (uintptr_t)b, nb = start;
    if (align > HEAP_ALIGN) {
        uintptr_t p = round_up(start + HDR, align);
        if (p - HDR != start && p - HDR - start < MIN_BLOCK)
            p = round_up(start + HDR + MIN_BLOCK, align);
        nb = p - HDR;
    }
    return nb + need <= start + bsize(b) ? nb : 0;
}

static void *carve(struct heap *h, struct hdr *b, uintptr_t nb, uint64_t need, uint64_t req)
{
    uintptr_t start = (uintptr_t)b, end = start + bsize(b);
    struct hdr *prev = links(b)->prev, *next = links(b)->next;
    list_remove(h, b);
    if (nb > start) {
        stamp(b, nb - start, 0);
        link_between(h, b, prev, next);
        prev = b;
    }
    uint64_t tail = end - (nb + need);
    if (tail >= MIN_BLOCK) {
        struct hdr *t = (struct hdr *)(nb + need);
        stamp(t, tail, 0);
        link_between(h, t, prev, next);
    } else {
        need += tail;
    }
    struct hdr *u = (struct hdr *)nb;
    stamp(u, need | USED, req);
    for (uint8_t *p = (uint8_t *)u + HDR + req; p < (uint8_t *)footer(u); p++)
        *p = SLACK;

    struct heap_stats *s = &h->st;
    s->in_use += need;
    s->free -= need;
    s->requested += req;
    s->live++;
    s->allocs++;
    if (s->in_use > s->peak_in_use)
        s->peak_in_use = s->in_use;
    if (s->requested > s->peak_requested)
        s->peak_requested = s->requested;
    return (uint8_t *)u + HDR;
}

/* Validates `b` (already checked as a list node) and the bytes it would hand out, then carves. */
static int take(struct heap *h, struct hdr *b, uintptr_t nb, uint64_t need, uint64_t req, void **out)
{
    uintptr_t start = (uintptr_t)b, end = start + bsize(b);
    if (end - (nb + need) < MIN_BLOCK)
        need = end - nb;
    uintptr_t lo = nb > start + POISON_AT ? nb : start + POISON_AT;
    uintptr_t hi = nb + need < end - FTR ? nb + need : end - FTR;
    if (!unlink_ok(h, b) || (lo < hi && !poisoned(lo, hi)))
        return -BV_EFAULT;
    *out = carve(h, b, nb, need, req);
    return 0;
}

static struct hdr *tail_free(const struct heap *h)
{
    if (h->brk == h->base)
        return NULL;
    const struct ftr *f = (const struct ftr *)(h->brk - FTR);
    if ((f->size & USED) || !sane_size(h, h->base, f->size))
        return NULL;
    struct hdr *b = (struct hdr *)(h->brk - f->size);
    return header_ok(h, b) && !(b->size & USED) ? b : NULL;
}

/* Maps enough fresh memory that the free block ending at brk fits the request. `last` is the
 * validated last free-list node; nothing is changed or mapped unless the tail checks out. */
static int grow(struct heap *h, uint64_t need, uint64_t align, struct hdr *last)
{
    struct hdr *t = tail_free(h);
    if (t ? t != last || !poisoned((uintptr_t)t + POISON_AT, h->brk - FTR)
          : last && (uintptr_t)last + bsize(last) >= h->brk)
        return -BV_EFAULT;
    uintptr_t start = t ? (uintptr_t)t : h->brk;
    uint64_t want = need + (align > HEAP_ALIGN ? align + MIN_BLOCK : 0), have = h->brk - start;
    uint64_t room = h->limit - h->brk;
    uint64_t exact = want > have ? round_up(want - have, HEAP_PAGE) : HEAP_PAGE;
    if (exact > room)
        return -BV_ENOMEM;
    uint64_t g = exact >= HEAP_GROW_MIN ? exact : HEAP_GROW_MIN <= room ? HEAP_GROW_MIN : room;
    if (h->ops.grow(h->ops.ctx, h->brk, g) != 0) {
        if (g == exact || h->ops.grow(h->ops.ctx, h->brk, exact) != 0)
            return -BV_ENOMEM;
        g = exact;
    }

    uintptr_t old = h->brk;
    h->brk += g;
    h->st.mapped += g;
    h->st.free += g;
    if (t) {
        poison(old - FTR, h->brk - FTR);
        stamp(t, bsize(t) + g, 0);
    } else {
        poison(old + POISON_AT, h->brk - FTR);
        stamp((struct hdr *)old, g, 0);
        link_between(h, (struct hdr *)old, last, NULL);
    }
    return 0;
}

int heap_init(struct heap *h, uintptr_t base, size_t len, const struct heap_ops *ops)
{
    if (!h || !ops || !ops->grow || base % HEAP_PAGE || len % HEAP_PAGE || len == 0 || base + len < base)
        return -BV_EINVAL;
    *h = (struct heap){ .base = base, .brk = base, .limit = base + len, .ops = *ops };
    return 0;
}

static int fail_alloc(struct heap *h, int rc)
{
    h->st.failed_allocs++;
    return rc;
}

int heap_alloc(struct heap *h, size_t size, size_t align, void **out)
{
    if (!out)
        return fail_alloc(h, -BV_EINVAL);
    *out = NULL;
    if (size == 0 || align == 0 || (align & (align - 1)) || align > HEAP_MAX_ALIGN)
        return fail_alloc(h, -BV_EINVAL);
    if ((uint64_t)size > HEAP_MAX_REQUEST)
        return fail_alloc(h, -BV_ENOMEM);
    if (align < HEAP_ALIGN)
        align = HEAP_ALIGN;
    uint64_t need = round_up(HDR + (uint64_t)size + FTR, HEAP_ALIGN);
    if (need < MIN_BLOCK)
        need = MIN_BLOCK;

    struct hdr *prev = NULL;
    for (struct hdr *b = h->free_list; b; prev = b, b = links(b)->next) {
        if (!node_ok(h, b, prev))
            return fail_alloc(h, -BV_EFAULT);
        uintptr_t nb = place(b, need, align);
        if (nb) {
            int rc = take(h, b, nb, need, size, out);
            return rc ? fail_alloc(h, rc) : 0;
        }
    }
    int rc = grow(h, need, align, prev);
    if (rc)
        return fail_alloc(h, rc);
    struct hdr *t = tail_free(h);
    uintptr_t nb = t ? place(t, need, align) : 0;
    if (!nb || (rc = take(h, t, nb, need, size, out)))
        return fail_alloc(h, nb ? rc : -BV_EFAULT);
    return 0;
}

static int reject(struct heap *h, int rc)
{
    h->st.rejected_frees++;
    return rc;
}

int heap_free(struct heap *h, void *ptr)
{
    if (!ptr)
        return 0;
    uintptr_t p = (uintptr_t)ptr;
    if (p % HEAP_ALIGN || p < h->base + HDR || p >= h->brk)
        return reject(h, -BV_EINVAL);
    struct hdr *b = (struct hdr *)(p - HDR);
    if (!header_ok(h, b))
        return reject(h, -BV_EINVAL);
    if (!(b->size & USED))
        return reject(h, -BV_EALREADY);
    if (!footer_ok(b) || !slack_ok(b))
        return reject(h, -BV_EFAULT);

    uint64_t s = bsize(b);
    uintptr_t start = (uintptr_t)b, end = start + s;
    struct hdr *l = NULL, *r = NULL, *prev = NULL, *next = NULL;
    if (end < h->brk) {
        struct hdr *n = (struct hdr *)end;
        if (!header_ok(h, n) || !footer_ok(n) || (!(n->size & USED) && !unlink_ok(h, n)))
            return reject(h, -BV_EFAULT);
        r = n->size & USED ? NULL : n;
    }
    if (start > h->base) {
        uint64_t ls = ((const struct ftr *)(start - FTR))->size & ~USED;
        struct hdr *n = (struct hdr *)(start - ls);
        if (!sane_size(h, h->base, ls) || ls > start - h->base || !header_ok(h, n) || !footer_ok(n) ||
            (!(n->size & USED) && !unlink_ok(h, n)))
            return reject(h, -BV_EFAULT);
        l = n->size & USED ? NULL : n;
    }
    if (!l && !r) {
        for (next = h->free_list; next && (uintptr_t)next < start; prev = next, next = links(next)->next)
            if (!node_ok(h, next, prev))
                return reject(h, -BV_EFAULT);
        if (next && !node_ok(h, next, prev))
            return reject(h, -BV_EFAULT);
    }

    h->st.in_use -= s;
    h->st.free += s;
    h->st.requested -= b->req;
    h->st.live--;
    h->st.frees++;

    uintptr_t new_end = r ? end + bsize(r) : end;
    if (r) {
        prev = links(r)->prev;
        next = links(r)->next;
        if (l)
            list_remove(h, r);
    }
    poison(l ? start - FTR : start + POISON_AT, r ? end + POISON_AT : end - FTR);
    if (l) {
        stamp(l, new_end - (uintptr_t)l, 0);
    } else {
        stamp(b, new_end - start, 0);
        link_between(h, b, prev, next);
    }
    return 0;
}

int heap_check(const struct heap *h)
{
    uint64_t used = 0, fre = 0, req = 0, live = 0, nfree = 0;
    bool prev_free = false;
    for (uintptr_t a = h->base; a < h->brk;) {
        const struct hdr *b = (const struct hdr *)a;
        if (!header_ok(h, b) || !footer_ok(b))
            return -BV_EFAULT;
        if (!(b->size & USED) && !poisoned(a + POISON_AT, a + bsize(b) - FTR))
            return -BV_EFAULT;
        if (b->size & USED) {
            if (!slack_ok(b))
                return -BV_EFAULT;
            used += bsize(b);
            req += b->req;
            live++;
            prev_free = false;
        } else {
            if (prev_free)
                return -BV_EFAULT;
            fre += bsize(b);
            nfree++;
            prev_free = true;
        }
        a += bsize(b);
    }
    uint64_t n = 0;
    struct hdr *prev = NULL;
    for (struct hdr *b = h->free_list; b; prev = b, b = links(b)->next) {
        if (++n > nfree || !node_ok(h, b, prev))
            return -BV_EFAULT;
    }
    const struct heap_stats *s = &h->st;
    if (n != nfree || used != s->in_use || fre != s->free || req != s->requested || live != s->live ||
        s->mapped != h->brk - h->base || used + fre != s->mapped || s->allocs - s->frees != live)
        return -BV_EFAULT;
    return 0;
}

uint64_t heap_largest_free(const struct heap *h)
{
    uint64_t best = 0;
    for (struct hdr *b = h->free_list; b; b = links(b)->next)
        if (bsize(b) > best)
            best = bsize(b);
    return best;
}
