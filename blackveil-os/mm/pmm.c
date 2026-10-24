/* Bitmap physical frame allocator. Pure code, host-tested. */
#include <bv/errno.h>
#include <bv/pmm.h>
#include <stdbool.h>

static bool test_bit(const uint64_t *map, uint64_t i)
{
    return (map[i / 64] >> (i % 64)) & 1;
}

static void set_bit(uint64_t *map, uint64_t i)
{
    map[i / 64] |= 1ull << (i % 64);
}

static void clear_bit(uint64_t *map, uint64_t i)
{
    map[i / 64] &= ~(1ull << (i % 64));
}

int pmm_init(struct pmm *p, uint64_t *used, uint64_t *reserved, size_t words, const struct memmap *m)
{
    *p = (struct pmm){ .used = used, .reserved = reserved };
    if (!m->count)
        return -BV_EINVAL;
    uint64_t nframes = m->usable[m->count - 1].end / PAGE_SIZE;
    if (nframes > (uint64_t)words * 64)
        return -BV_ENOSPC;
    for (size_t w = 0; w < words; w++)
        used[w] = reserved[w] = ~0ull;
    for (size_t i = 0; i < m->count; i++) {
        for (uint64_t f = m->usable[i].base / PAGE_SIZE; f < m->usable[i].end / PAGE_SIZE; f++) {
            clear_bit(used, f);
            clear_bit(reserved, f);
        }
        p->usable_frames += (m->usable[i].end - m->usable[i].base) / PAGE_SIZE;
    }
    p->nframes = nframes;
    p->free_frames = p->usable_frames;
    return 0;
}

int pmm_reserve(struct pmm *p, uint64_t base, uint64_t len)
{
    if (len == 0)
        return 0;
    if (base + len < base)
        return -BV_EINVAL;
    uint64_t first = base / PAGE_SIZE;
    uint64_t last = (base + len - 1) / PAGE_SIZE;
    if (last >= p->nframes)
        last = p->nframes ? p->nframes - 1 : 0;
    if (first >= p->nframes)
        return 0;
    for (uint64_t f = first; f <= last; f++)
        if (test_bit(p->used, f) && !test_bit(p->reserved, f))
            return -BV_EBUSY;
    for (uint64_t f = first; f <= last; f++) {
        if (test_bit(p->reserved, f))
            continue;
        set_bit(p->used, f);
        set_bit(p->reserved, f);
        p->free_frames--;
        p->reserved_frames++;
    }
    return 0;
}

int pmm_alloc(struct pmm *p, uint64_t *phys)
{
    uint64_t words = (p->nframes + 63) / 64;
    for (uint64_t n = 0; n < words; n++) {
        uint64_t w = (p->next_word + n) % words;
        if (p->used[w] == ~0ull)
            continue;
        uint64_t f = w * 64 + (uint64_t)__builtin_ctzll(~p->used[w]);
        if (f >= p->nframes)
            continue;
        set_bit(p->used, f);
        p->free_frames--;
        p->next_word = w;
        *phys = f * PAGE_SIZE;
        return 0;
    }
    return -BV_ENOMEM;
}

int pmm_alloc_below(struct pmm *p, uint64_t limit, uint64_t *phys)
{
    uint64_t lim = limit / PAGE_SIZE < p->nframes ? limit / PAGE_SIZE : p->nframes;
    for (uint64_t w = 0; w < (lim + 63) / 64; w++) {
        if (p->used[w] == ~0ull)
            continue;
        uint64_t f = w * 64 + (uint64_t)__builtin_ctzll(~p->used[w]);
        if (f >= lim)
            break;
        set_bit(p->used, f);
        p->free_frames--;
        *phys = f * PAGE_SIZE;
        return 0;
    }
    return -BV_ENOMEM;
}

uint64_t pmm_words_for(const struct memmap *m)
{
    return m->count ? (m->usable[m->count - 1].end / PAGE_SIZE + 63) / 64 : 0;
}

#define PAGE_MASK ((uint64_t)PAGE_SIZE - 1)

int pmm_place(const struct memmap *m, uint64_t bytes, const struct mem_range *avoid, size_t navoid, uint64_t limit,
              uint64_t *base)
{
    if (bytes == 0 || bytes > UINT64_MAX - PAGE_MASK)
        return -BV_EINVAL;
    bytes = (bytes + PAGE_MASK) & ~PAGE_MASK;
    for (size_t i = 0; i < m->count; i++) {
        uint64_t b = (m->usable[i].base + PAGE_MASK) & ~PAGE_MASK, end = m->usable[i].end;
        bool moved = true;
        while (moved) {
            if (b < m->usable[i].base || b > end || end - b < bytes || b > limit || limit - b < bytes)
                break;
            moved = false;
            for (size_t a = 0; a < navoid && !moved; a++) {
                if (avoid[a].base >= b + bytes || avoid[a].end <= b)
                    continue;
                if (avoid[a].end > UINT64_MAX - PAGE_MASK)
                    return -BV_ENOMEM;
                b = (avoid[a].end + PAGE_MASK) & ~PAGE_MASK;
                moved = true;
            }
            if (!moved) {
                *base = b;
                return 0;
            }
        }
    }
    return -BV_ENOMEM;
}

int pmm_free(struct pmm *p, uint64_t phys)
{
    if (phys % PAGE_SIZE || phys / PAGE_SIZE >= p->nframes)
        return -BV_EINVAL;
    uint64_t f = phys / PAGE_SIZE;
    if (test_bit(p->reserved, f))
        return -BV_EPERM;
    if (!test_bit(p->used, f))
        return -BV_EALREADY;
    clear_bit(p->used, f);
    p->free_frames++;
    if (f / 64 < p->next_word)
        p->next_word = f / 64;
    return 0;
}

int pmm_pin(struct pmm *p, uint64_t phys)
{
    if (phys % PAGE_SIZE || phys / PAGE_SIZE >= p->nframes)
        return -BV_EINVAL;
    uint64_t f = phys / PAGE_SIZE;
    if (test_bit(p->reserved, f))
        return -BV_EPERM;
    if (!test_bit(p->used, f))
        return -BV_EINVAL;
    set_bit(p->reserved, f);
    p->reserved_frames++;
    return 0;
}

int pmm_unpin(struct pmm *p, uint64_t phys)
{
    if (phys % PAGE_SIZE || phys / PAGE_SIZE >= p->nframes)
        return -BV_EINVAL;
    uint64_t f = phys / PAGE_SIZE;
    if (!test_bit(p->reserved, f) || !test_bit(p->used, f))
        return -BV_EINVAL;
    if (!p->reserved_frames)
        return -BV_EFAULT;
    clear_bit(p->reserved, f);
    p->reserved_frames--;
    return 0;
}

static uint64_t popcount(uint64_t x)
{
    uint64_t n = 0;
    for (; x; x &= x - 1)
        n++;
    return n;
}

int pmm_check(const struct pmm *p)
{
    uint64_t words = (p->nframes + 63) / 64, used = 0, reserved = 0;
    if (p->free_frames > p->usable_frames || p->usable_frames > p->nframes || (words && p->next_word >= words))
        return -BV_EFAULT;
    for (uint64_t w = 0; w < words; w++) {
        uint64_t u = p->used[w], r = p->reserved[w];
        if (r & ~u)
            return -BV_EFAULT;
        uint64_t tail = w == words - 1 && p->nframes % 64 ? ~0ull << (p->nframes % 64) : 0;
        if ((u & tail) != tail || (r & tail) != tail)
            return -BV_EFAULT;
        used += popcount(u & ~tail);
        reserved += popcount(r & ~tail);
    }
    uint64_t unusable = p->nframes - p->usable_frames;
    if (p->nframes - used != p->free_frames || reserved != p->reserved_frames + unusable)
        return -BV_EFAULT;
    return 0;
}

enum pmm_state pmm_state_of(const struct pmm *p, uint64_t phys)
{
    uint64_t f = phys / PAGE_SIZE;
    if (f >= p->nframes)
        return PMM_OUT_OF_RANGE;
    if (test_bit(p->reserved, f))
        return PMM_RESERVED;
    return test_bit(p->used, f) ? PMM_USED : PMM_FREE;
}
