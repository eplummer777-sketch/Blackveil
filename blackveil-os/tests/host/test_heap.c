#include "check.h"

#include <bv/errno.h>
#include <bv/heap.h>
#include <stdlib.h>

#define ARENA (64u << 20)

static uint8_t *arena;
static uint64_t budget;  /* bytes grow() may still hand out */
static int fail_next;
static unsigned grow_calls;

static int fake_grow(void *ctx, uintptr_t va, size_t len)
{
    struct heap *h = ctx;
    grow_calls++;
    if (va != h->brk || len % HEAP_PAGE || va + len > h->limit) {
        printf("  FAIL  grow called with bad range %#lx+%#zx\n", (unsigned long)va, len);
        failures++;
        return -BV_EINVAL;
    }
    if (fail_next) {
        fail_next = 0;
        return -BV_ENOMEM;
    }
    if (len > budget)
        return -BV_ENOMEM;
    budget -= len;
    memset((void *)va, 0xEE, len); /* fresh memory is never zero */
    return 0;
}

static void setup(struct heap *h, size_t len)
{
    struct heap_ops ops = { fake_grow, h };
    budget = UINT64_MAX;
    fail_next = 0;
    grow_calls = 0;
    CHECK_EQ(heap_init(h, (uintptr_t)arena, len, &ops), 0);
}

static uint64_t hash_mapped(const struct heap *h)
{
    uint64_t x = 1469598103934665603ull;
    for (const uint8_t *p = (const uint8_t *)h->base; p < (const uint8_t *)h->brk; p++)
        x = (x ^ *p) * 1099511628211ull;
    return x;
}

struct snap {
    struct heap h;
    uint64_t hash;
};

static struct snap take(const struct heap *h)
{
    return (struct snap){ *h, hash_mapped(h) };
}

/* Equal apart from the failure counters, which are expected to move. */
static int same(const struct heap *h, struct snap s)
{
    struct heap c = *h;
    c.st.failed_allocs = s.h.st.failed_allocs;
    c.st.rejected_frees = s.h.st.rejected_frees;
    return memcmp(&c, &s.h, sizeof c) == 0 && hash_mapped(h) == s.hash;
}

static void *get(struct heap *h, size_t size, size_t align)
{
    void *p = NULL;
    CHECK_EQ(heap_alloc(h, size, align, &p), 0);
    return p;
}

static void test_init(void)
{
    struct heap h;
    struct heap_ops ops = { fake_grow, &h }, none = { NULL, NULL };
    CHECK_EQ(heap_init(&h, (uintptr_t)arena + 16, ARENA, &ops), -BV_EINVAL);
    CHECK_EQ(heap_init(&h, (uintptr_t)arena, ARENA - 1, &ops), -BV_EINVAL);
    CHECK_EQ(heap_init(&h, (uintptr_t)arena, 0, &ops), -BV_EINVAL);
    CHECK_EQ(heap_init(&h, (uintptr_t)arena, ARENA, &none), -BV_EINVAL);
    CHECK_EQ(heap_init(&h, UINTPTR_MAX & ~(uintptr_t)(HEAP_PAGE - 1), 2 * HEAP_PAGE, &ops), -BV_EINVAL);
    setup(&h, ARENA);
    CHECK_EQ(h.st.mapped, 0);
    CHECK_EQ(heap_check(&h), 0);
    CHECK_EQ(grow_calls, 0);
}

static void test_bad_requests(void)
{
    struct heap h;
    setup(&h, ARENA);
    void *keep = get(&h, 100, 16);
    struct snap s = take(&h);
    static const struct {
        size_t size, align;
        int rc;
    } bad[] = {
        { 0, 16, -BV_EINVAL },
        { 8, 0, -BV_EINVAL },
        { 8, 3, -BV_EINVAL },
        { 8, 24, -BV_EINVAL },
        { 8, HEAP_MAX_ALIGN * 2, -BV_EINVAL },
        { 8, (size_t)1 << 63, -BV_EINVAL },
        { SIZE_MAX, 16, -BV_ENOMEM },
        { SIZE_MAX - 15, 16, -BV_ENOMEM },
        { SIZE_MAX - 47, HEAP_MAX_ALIGN, -BV_ENOMEM },
        { HEAP_MAX_REQUEST + 1, 16, -BV_ENOMEM },
        { HEAP_MAX_REQUEST, 16, -BV_ENOMEM }, /* within the cap, beyond the arena */
        { ARENA, 16, -BV_ENOMEM },
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        void *p = (void *)1;
        CHECK_EQ(heap_alloc(&h, bad[i].size, bad[i].align, &p), bad[i].rc);
        CHECK(p == NULL);
    }
    CHECK_EQ(heap_alloc(&h, 8, 16, NULL), -BV_EINVAL);
    CHECK(same(&h, s));
    CHECK_EQ(h.st.failed_allocs, sizeof bad / sizeof bad[0] + 1);
    CHECK_EQ(heap_check(&h), 0);
    CHECK_EQ(heap_free(&h, keep), 0);
}

static void test_basic_and_stats(void)
{
    struct heap h;
    setup(&h, ARENA);
    uint8_t *p = get(&h, 1, 1);
    CHECK((uintptr_t)p % HEAP_ALIGN == 0);
    CHECK((uintptr_t)p >= h.base && (uintptr_t)p < h.brk);
    CHECK_EQ(h.st.mapped, HEAP_GROW_MIN);
    CHECK_EQ(h.st.requested, 1);
    CHECK_EQ(h.st.live, 1);
    CHECK_EQ(h.st.in_use + h.st.free, h.st.mapped);
    uint8_t *q = get(&h, 1000, 16);
    memset(q, 0x11, 1000);
    *p = 0x22;
    CHECK_EQ(h.st.requested, 1001);
    CHECK_EQ(h.st.peak_requested, 1001);
    CHECK_EQ(heap_check(&h), 0);
    CHECK_EQ(heap_free(&h, q), 0);
    CHECK_EQ(h.st.requested, 1);
    CHECK_EQ(h.st.peak_requested, 1001);
    CHECK_EQ(h.st.allocs, 2);
    CHECK_EQ(h.st.frees, 1);
    uint64_t peak = h.st.peak_in_use;
    CHECK_EQ(heap_free(&h, p), 0);
    CHECK_EQ(h.st.live, 0);
    CHECK_EQ(h.st.in_use, 0);
    CHECK_EQ(h.st.free, h.st.mapped);
    CHECK_EQ(h.st.peak_in_use, peak);
    CHECK_EQ(heap_largest_free(&h), h.st.mapped);
    CHECK_EQ(heap_check(&h), 0);
}

static void test_alignment(void)
{
    struct heap h;
    setup(&h, ARENA);
    static const size_t sizes[] = { 1, 7, 16, 100, 4096, 5000 };
    uint8_t *ptrs[22 * 6];
    size_t lens[22 * 6], n = 0;
    for (size_t align = 1; align <= HEAP_MAX_ALIGN; align <<= 1) {
        for (size_t i = 0; i < 6; i++) {
            uint8_t *p = get(&h, sizes[i], align);
            if (!p)
                continue;
            CHECK((uintptr_t)p % (align < HEAP_ALIGN ? HEAP_ALIGN : align) == 0);
            memset(p, (int)(n & 0xFF), sizes[i]);
            ptrs[n] = p;
            lens[n++] = sizes[i];
        }
    }
    CHECK_EQ(n, 22 * 6);
    CHECK_EQ(heap_check(&h), 0);
    int intact = 1;
    for (size_t i = 0; i < n; i++)
        for (size_t j = 0; j < lens[i]; j++)
            intact &= ptrs[i][j] == (uint8_t)(i & 0xFF);
    CHECK(intact);
    for (size_t i = 0; i < n; i += 2)
        CHECK_EQ(heap_free(&h, ptrs[i]), 0);
    for (size_t i = 1; i < n; i += 2)
        CHECK_EQ(heap_free(&h, ptrs[i]), 0);
    CHECK_EQ(heap_largest_free(&h), h.st.mapped);
    CHECK_EQ(heap_check(&h), 0);
}

static void test_reuse_and_coalesce(void)
{
    struct heap h;
    setup(&h, ARENA);
    void *p = get(&h, 100, 16);
    CHECK_EQ(heap_free(&h, p), 0);
    CHECK(get(&h, 100, 16) == p);
    void *a = get(&h, 200, 16), *b = get(&h, 200, 16), *c = get(&h, 200, 16), *d = get(&h, 200, 16);
    uint64_t mapped = h.st.mapped;
    CHECK_EQ(heap_free(&h, b), 0);
    CHECK_EQ(heap_free(&h, a), 0); /* merges with b */
    CHECK_EQ(heap_free(&h, c), 0); /* merges with a+b */
    CHECK(get(&h, 600, 16) == a);  /* the merged hole is reused */
    CHECK_EQ(h.st.mapped, mapped);
    CHECK_EQ(heap_check(&h), 0);
    CHECK_EQ(heap_free(&h, a), 0);
    CHECK_EQ(heap_free(&h, d), 0);
    CHECK_EQ(heap_free(&h, p), 0);
    CHECK_EQ(heap_largest_free(&h), h.st.mapped);
    CHECK_EQ(heap_check(&h), 0);
}

static void test_fragmentation(void)
{
    struct heap h;
    setup(&h, ARENA);
    void *blk[64];
    for (int i = 0; i < 64; i++) {
        blk[i] = get(&h, 1024, 16);
        memset(blk[i], i, 1024);
    }
    for (int i = 0; i < 64; i += 2)
        CHECK_EQ(heap_free(&h, blk[i]), 0);
    CHECK(heap_largest_free(&h) >= 1024 + 48);
    uint64_t free_before = h.st.free, mapped = h.st.mapped;
    CHECK(free_before >= 32 * 1024);
    uint8_t *big = get(&h, 4096, 16); /* no hole fits; must come from the tail */
    CHECK((uintptr_t)big > (uintptr_t)blk[63]);
    int intact = 1;
    for (int i = 1; i < 64; i += 2)
        for (int j = 0; j < 1024; j++)
            intact &= ((uint8_t *)blk[i])[j] == i;
    CHECK(intact);
    for (int i = 0; i < 64; i += 2)
        blk[i] = get(&h, 1000, 16); /* holes are reused, no growth */
    CHECK_EQ(h.st.mapped, mapped);
    CHECK_EQ(heap_check(&h), 0);
    for (int i = 0; i < 64; i++)
        CHECK_EQ(heap_free(&h, blk[i]), 0);
    CHECK_EQ(heap_free(&h, big), 0);
    CHECK_EQ(heap_largest_free(&h), h.st.mapped);
    CHECK_EQ(heap_check(&h), 0);
}

static void test_invalid_frees(void)
{
    struct heap h;
    setup(&h, ARENA);
    uint8_t *x = get(&h, 64, 16), *y = get(&h, 64, 16), *z = get(&h, 64, 16);
    uint64_t on_stack;
    struct snap s = take(&h);
    CHECK_EQ(heap_free(&h, NULL), 0);
    CHECK_EQ(heap_free(&h, y + 1), -BV_EINVAL);
    CHECK_EQ(heap_free(&h, y + 16), -BV_EINVAL);
    CHECK_EQ(heap_free(&h, y - 16), -BV_EINVAL);
    CHECK_EQ(heap_free(&h, &on_stack), -BV_EINVAL);
    CHECK_EQ(heap_free(&h, (void *)h.base), -BV_EINVAL);
    CHECK_EQ(heap_free(&h, (void *)h.brk), -BV_EINVAL);
    CHECK_EQ(heap_free(&h, (void *)(h.base - 16)), -BV_EINVAL);
    CHECK(same(&h, s));
    CHECK_EQ(h.st.rejected_frees, 7);

    CHECK_EQ(heap_free(&h, y), 0);
    s = take(&h);
    CHECK_EQ(heap_free(&h, y), -BV_EALREADY);
    CHECK(same(&h, s));
    CHECK_EQ(heap_free(&h, x), 0);  /* absorbs y */
    s = take(&h);
    CHECK_EQ(heap_free(&h, y), -BV_EINVAL); /* its header is gone */
    CHECK_EQ(heap_free(&h, x), -BV_EALREADY);
    CHECK(same(&h, s));
    CHECK_EQ(h.st.rejected_frees, 10);
    CHECK_EQ(heap_check(&h), 0);
    CHECK_EQ(heap_free(&h, z), 0);
    CHECK_EQ(heap_free(&h, z), -BV_EINVAL); /* merged into its left neighbour */
    CHECK_EQ(heap_check(&h), 0);
}

static void test_overruns(void)
{
    struct heap h;
    setup(&h, ARENA);
    uint8_t *p = get(&h, 20, 16), *q = get(&h, 32, 16), *r = get(&h, 64, 16);
    uint8_t saved = p[20];
    p[20] = 0;
    struct snap s = take(&h);
    CHECK_EQ(heap_free(&h, p), -BV_EFAULT);
    CHECK(same(&h, s));
    CHECK_EQ(heap_check(&h), -BV_EFAULT);
    p[20] = saved;
    CHECK_EQ(heap_check(&h), 0);

    uint8_t foot[8];
    memcpy(foot, q + 32, 8); /* no slack: the footer starts right after the request */
    memset(q + 32, 0, 8);
    CHECK_EQ(heap_free(&h, q), -BV_EFAULT);
    memcpy(q + 32, foot, 8);

    uint8_t head[8];
    memcpy(head, r - 32, 8); /* the size word of r's header */
    r[-32] ^= 0x40;
    CHECK_EQ(heap_free(&h, r), -BV_EINVAL);
    memcpy(r - 32, head, 8);
    CHECK_EQ(heap_check(&h), 0);
    CHECK_EQ(heap_free(&h, p), 0);
    CHECK_EQ(heap_free(&h, q), 0);
    CHECK_EQ(heap_free(&h, r), 0);
    CHECK_EQ(heap_check(&h), 0);
}

static void test_out_of_memory(void)
{
    struct heap h;
    setup(&h, ARENA);
    void *a = get(&h, 100, 16);
    struct snap s = take(&h);
    budget = 0;
    void *p = (void *)1;
    CHECK_EQ(heap_alloc(&h, HEAP_GROW_MIN, 16, &p), -BV_ENOMEM);
    CHECK(p == NULL);
    CHECK(same(&h, s));
    CHECK_EQ(heap_alloc(&h, 100, HEAP_MAX_ALIGN, &p), -BV_ENOMEM);
    CHECK(same(&h, s));
    CHECK_EQ(heap_alloc(&h, 100, 16, &p), 0); /* still fits without growing */
    CHECK_EQ(heap_free(&h, p), 0);

    struct heap lean; /* in the upper half of the arena, clear of `h` */
    struct heap_ops lean_ops = { fake_grow, &lean };
    CHECK_EQ(heap_init(&lean, (uintptr_t)arena + ARENA / 2, ARENA / 2, &lean_ops), 0);
    budget = 2 * HEAP_PAGE; /* less than the usual growth step */
    CHECK_EQ(heap_alloc(&lean, 5000, 16, &p), 0);
    CHECK_EQ(lean.st.mapped, 2 * HEAP_PAGE);
    CHECK_EQ(heap_alloc(&lean, 4000, 16, &p), -BV_ENOMEM);
    CHECK_EQ(heap_check(&lean), 0);

    budget = UINT64_MAX;
    fail_next = 1;
    s = take(&h);
    CHECK_EQ(heap_alloc(&h, 3 * HEAP_GROW_MIN, 16, &p), -BV_ENOMEM);
    CHECK(same(&h, s));
    CHECK_EQ(heap_alloc(&h, 3 * HEAP_GROW_MIN, 16, &p), 0); /* the tail free block is extended */
    CHECK(h.st.mapped >= 3 * HEAP_GROW_MIN + 48 && h.st.mapped < 4 * HEAP_GROW_MIN);
    CHECK_EQ(heap_check(&h), 0);
    CHECK_EQ(heap_free(&h, p), 0);
    CHECK_EQ(heap_free(&h, a), 0);
    CHECK_EQ(heap_check(&h), 0);
}

static void test_exhaustion_and_limits(void)
{
    struct heap h;
    const size_t len = 1u << 20;
    setup(&h, len);
    void *p = (void *)1;
    CHECK_EQ(heap_alloc(&h, len, 16, &p), -BV_ENOMEM);
    CHECK_EQ(heap_alloc(&h, len - 47, 16, &p), -BV_ENOMEM);
    CHECK_EQ(h.st.mapped, 0);
    CHECK_EQ(heap_alloc(&h, len - 48, 16, &p), 0); /* exactly the whole arena */
    CHECK_EQ(h.st.mapped, len);
    CHECK_EQ(h.st.free, 0);
    CHECK(heap_alloc(&h, 1, 16, &p) == -BV_ENOMEM);
    CHECK_EQ(heap_free(&h, (uint8_t *)h.base + 32), 0);

    void *blk[2048];
    size_t n = 0;
    while (n < 2048 && heap_alloc(&h, 1000, 16, &blk[n]) == 0)
        n++;
    CHECK(n > 900 && n < 2048);
    struct snap s = take(&h);
    CHECK_EQ(heap_alloc(&h, 1000, 16, &p), -BV_ENOMEM);
    CHECK(same(&h, s));
    CHECK_EQ(heap_check(&h), 0);
    for (size_t i = 0; i < n; i++)
        CHECK_EQ(heap_free(&h, blk[i]), 0);
    CHECK_EQ(heap_largest_free(&h), len);
    size_t again = 0;
    while (again < 2048 && heap_alloc(&h, 1000, 16, &blk[again]) == 0)
        again++;
    CHECK_EQ(again, n);
    CHECK_EQ(heap_check(&h), 0);
}

/* Block layout as seen from a payload pointer: 32-byte header before it, list links at its start. */
static uint64_t blk_size(const uint8_t *p)
{
    return *(const uint64_t *)(p - 32) & ~1ull;
}

static uint8_t *footer_of(uint8_t *p)
{
    return p - 32 + blk_size(p) - 16;
}

static void **next_of(uint8_t *p)
{
    return (void **)p;
}

static void **prev_of(uint8_t *p)
{
    return (void **)p + 1;
}

static int all_poison(const uint8_t *lo, const uint8_t *hi)
{
    for (; lo < hi; lo++)
        if (*lo != HEAP_POISON)
            return 0;
    return 1;
}

static void test_free_list_corruption(void)
{
    struct heap h;
    setup(&h, ARENA);
    uint8_t *a = get(&h, 200, 16), *b = get(&h, 200, 16), *c = get(&h, 200, 16), *d = get(&h, 200, 16),
            *e = get(&h, 200, 16);
    CHECK_EQ(heap_free(&h, b), 0);
    CHECK_EQ(heap_free(&h, d), 0);
    CHECK_EQ(heap_check(&h), 0);
    void *p = (void *)1, *saved_next = *next_of(b), *saved_prev = *prev_of(d), *saved_head = h.free_list;
    unsigned calls = grow_calls;

    *next_of(b) = d - 16; /* inside d's header: aligned, in range, not a block */
    struct snap s = take(&h);
    CHECK_EQ(heap_alloc(&h, 1000, 16, &p), -BV_EFAULT); /* b is too small, the walk must stop at the bad link */
    CHECK(p == NULL);
    CHECK_EQ(grow_calls, calls);
    CHECK_EQ(heap_free(&h, a), -BV_EFAULT); /* would merge with b and unlink it */
    CHECK_EQ(heap_free(&h, c), -BV_EFAULT); /* between b and d */
    CHECK(same(&h, s));
    CHECK_EQ(heap_check(&h), -BV_EFAULT);

    *next_of(b) = b - 32; /* a loop back to itself */
    s = take(&h);
    CHECK_EQ(heap_alloc(&h, 1000, 16, &p), -BV_EFAULT);
    CHECK_EQ(heap_check(&h), -BV_EFAULT);
    CHECK(same(&h, s));
    *next_of(b) = saved_next;
    CHECK_EQ(heap_check(&h), 0);

    *prev_of(d) = NULL; /* back link disagrees with b->next */
    s = take(&h);
    CHECK_EQ(heap_alloc(&h, 1000, 16, &p), -BV_EFAULT);
    CHECK_EQ(heap_free(&h, e), -BV_EFAULT); /* would merge with d */
    CHECK_EQ(heap_free(&h, c), -BV_EFAULT);
    CHECK(same(&h, s));
    *prev_of(d) = saved_prev;

    h.free_list = a - 32; /* head points at a used block */
    s = take(&h);
    CHECK_EQ(heap_alloc(&h, 16, 16, &p), -BV_EFAULT);
    CHECK_EQ(heap_check(&h), -BV_EFAULT);
    CHECK(same(&h, s));
    h.free_list = saved_head;

    CHECK_EQ(h.st.failed_allocs, 4);
    CHECK_EQ(h.st.rejected_frees, 4);
    CHECK_EQ(heap_check(&h), 0);
    CHECK_EQ(heap_free(&h, a), 0);
    CHECK_EQ(heap_free(&h, c), 0);
    CHECK_EQ(heap_free(&h, e), 0);
    CHECK_EQ(heap_largest_free(&h), h.st.mapped);
    CHECK_EQ(heap_check(&h), 0);
}

static void test_neighbour_corruption(void)
{
    struct heap h;
    setup(&h, ARENA);
    uint8_t *a = get(&h, 200, 16), *b = get(&h, 200, 16), *c = get(&h, 200, 16), *d = get(&h, 200, 16);
    CHECK_EQ(heap_free(&h, b), 0);
    void *p = (void *)1;

    b[-8] ^= 0x01; /* guard word of the free block b */
    struct snap s = take(&h);
    CHECK_EQ(heap_free(&h, a), -BV_EFAULT);
    CHECK_EQ(heap_free(&h, c), -BV_EFAULT);
    CHECK_EQ(heap_alloc(&h, 200, 16, &p), -BV_EFAULT);
    CHECK(same(&h, s));
    b[-8] ^= 0x01;

    uint8_t *bf = footer_of(b);
    bf[8] ^= 0x01; /* footer tag of b */
    s = take(&h);
    CHECK_EQ(heap_free(&h, a), -BV_EFAULT);
    CHECK_EQ(heap_free(&h, c), -BV_EFAULT);
    CHECK_EQ(heap_alloc(&h, 200, 16, &p), -BV_EFAULT);
    CHECK(same(&h, s));
    bf[8] ^= 0x01;

    c[-32] &= (uint8_t)~1u; /* a used neighbour made to look free */
    s = take(&h);
    CHECK_EQ(heap_free(&h, d), -BV_EFAULT);
    CHECK(same(&h, s));
    c[-32] |= 1u;

    uint8_t *cf = footer_of(c);
    cf[0] ^= 0x10; /* size in the used neighbour's footer */
    s = take(&h);
    CHECK_EQ(heap_free(&h, d), -BV_EFAULT);
    CHECK(same(&h, s));
    cf[0] ^= 0x10;

    /* Copied headers fail: each tag binds the block's own address. */
    memcpy(a + 64, b - 32, 32);
    s = take(&h);
    CHECK_EQ(heap_free(&h, a + 96), -BV_EINVAL);
    CHECK(same(&h, s));
    memcpy(a + 64, c - 32, 32);
    s = take(&h);
    CHECK_EQ(heap_free(&h, a + 96), -BV_EINVAL);
    CHECK(same(&h, s));

    CHECK_EQ(h.st.failed_allocs, 2);
    CHECK_EQ(h.st.rejected_frees, 8);
    CHECK_EQ(heap_check(&h), 0);
    CHECK_EQ(heap_free(&h, c), 0); /* merges with b */
    CHECK(all_poison(c - 48, c)); /* b's footer and c's header are now poison */
    CHECK_EQ(heap_free(&h, a), 0);
    CHECK_EQ(heap_free(&h, d), 0);
    CHECK_EQ(heap_largest_free(&h), h.st.mapped);
    CHECK_EQ(h.st.live, 0);
    CHECK_EQ(h.st.in_use, 0);
    CHECK_EQ(h.st.allocs, h.st.frees);
    CHECK_EQ(heap_check(&h), 0);
}

static void test_poison(void)
{
    struct heap h;
    setup(&h, ARENA);
    uint8_t *a = get(&h, 200, 16), *b = get(&h, 200, 16), *c = get(&h, 200, 16);
    CHECK_EQ(blk_size(b), 256);
    memset(b, 0x11, 200);
    CHECK_EQ(heap_free(&h, b), 0);
    CHECK(all_poison(b + 16, footer_of(b))); /* links stay, payload and slack poisoned */
    CHECK_EQ(heap_check(&h), 0);

    void *p = (void *)1;
    b[100] ^= 0xFF; /* write after free into bytes the next allocation of b hands out */
    CHECK_EQ(heap_check(&h), -BV_EFAULT);
    struct snap s = take(&h);
    CHECK_EQ(heap_alloc(&h, 200, 16, &p), -BV_EFAULT);
    CHECK(p == NULL);
    CHECK(same(&h, s));
    b[100] ^= 0xFF;
    CHECK_EQ(heap_check(&h), 0);
    CHECK(get(&h, 200, 16) == b);
    CHECK_EQ(heap_free(&h, b), 0);

    /* A write the next allocation does not hand out is caught later, by heap_check, not by alloc. */
    b[200] ^= 0xFF;
    uint8_t *small = get(&h, 32, 16);
    CHECK(small == b);
    CHECK_EQ(heap_check(&h), -BV_EFAULT);
    b[200] ^= 0xFF;
    CHECK_EQ(heap_check(&h), 0);
    CHECK_EQ(heap_free(&h, small), 0);

    /* Growth extends the tail block only after checking its poison; nothing is mapped otherwise. */
    uint8_t *tail = c + 256 - 32; /* header of the free block after c */
    CHECK(blk_size(tail + 32) > 1000);
    tail[500] ^= 0xFF;
    unsigned calls = grow_calls;
    s = take(&h);
    CHECK_EQ(heap_alloc(&h, 2 * HEAP_GROW_MIN, 16, &p), -BV_EFAULT);
    CHECK_EQ(grow_calls, calls);
    CHECK(same(&h, s));
    tail[500] ^= 0xFF;
    uint8_t *big = get(&h, 2 * HEAP_GROW_MIN, 16);
    CHECK(big == tail + 32);
    CHECK_EQ(heap_check(&h), 0); /* grown memory (filled 0xEE by the test) was poisoned */
    CHECK_EQ(heap_free(&h, big), 0);
    CHECK(all_poison(tail + 48, (uint8_t *)h.brk - 16));

    CHECK_EQ(h.st.failed_allocs, 2);
    CHECK_EQ(h.st.rejected_frees, 0);
    CHECK_EQ(heap_free(&h, a), 0);
    CHECK_EQ(heap_free(&h, c), 0);
    CHECK_EQ(heap_largest_free(&h), h.st.mapped);
    CHECK_EQ(heap_check(&h), 0);
}

static uint64_t rng = 0x9E3779B97F4A7C15ull;
static uint64_t next_rand(void)
{
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng;
}

static void test_random_stress(void)
{
    struct heap h;
    setup(&h, ARENA);
    enum { SLOTS = 256 };
    uint8_t *ptr[SLOTS] = { 0 };
    size_t len[SLOTS] = { 0 };
    uint64_t requested = 0, peak = 0, bad = 0, checks_failed = 0;
    for (int op = 0; op < 40000; op++) {
        unsigned i = next_rand() % SLOTS;
        if (ptr[i]) {
            for (size_t j = 0; j < len[i]; j++)
                bad += ptr[i][j] != (uint8_t)i;
            if (heap_free(&h, ptr[i]))
                bad++;
            requested -= len[i];
            ptr[i] = NULL;
        } else {
            uint64_t r = next_rand();
            size_t size = 1 + (r % 8 == 0 ? r % 65536 : r % 3000);
            size_t align = (size_t)1 << ((r >> 20) % 13);
            void *p;
            if (heap_alloc(&h, size, align, &p)) {
                bad++;
                continue;
            }
            if ((uintptr_t)p % align)
                bad++;
            memset(p, (int)i, size);
            ptr[i] = p;
            len[i] = size;
            requested += size;
            if (requested > peak)
                peak = requested;
        }
        if (op % 256 == 0 && heap_check(&h))
            checks_failed++;
    }
    CHECK_EQ(bad, 0);
    CHECK_EQ(checks_failed, 0);
    CHECK_EQ(h.st.requested, requested);
    CHECK_EQ(h.st.peak_requested, peak);
    for (unsigned i = 0; i < SLOTS; i++)
        if (ptr[i])
            CHECK_EQ(heap_free(&h, ptr[i]), 0);
    CHECK_EQ(h.st.live, 0);
    CHECK_EQ(h.st.requested, 0);
    CHECK_EQ(h.st.in_use, 0);
    CHECK_EQ(heap_largest_free(&h), h.st.mapped);
    CHECK_EQ(h.st.allocs, h.st.frees);
    CHECK_EQ(h.st.failed_allocs, 0);
    CHECK_EQ(h.st.rejected_frees, 0);
    CHECK_EQ(heap_check(&h), 0);
}

int main(void)
{
    arena = aligned_alloc(HEAP_PAGE, ARENA);
    if (!arena)
        return 2;
    test_init();
    test_bad_requests();
    test_basic_and_stats();
    test_alignment();
    test_reuse_and_coalesce();
    test_fragmentation();
    test_invalid_frees();
    test_overruns();
    test_out_of_memory();
    test_exhaustion_and_limits();
    test_free_list_corruption();
    test_neighbour_corruption();
    test_poison();
    test_random_stress();
    free(arena);
    return report("heap");
}
