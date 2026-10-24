/* Kernel memory bring-up: memory map, frame reservations and allocator self-check. */
#include <bv/console.h>
#include <bv/errno.h>
#include <bv/format.h>
#include <bv/io.h>
#include <bv/mm.h>
#include <stdbool.h>

#define MAX_MODULES  64
#define MAX_HELD     (MAX_MODULES + 8)
#define MAX_BOOT_STR 4096

extern char __kernel_start[], __kernel_end[];

static MM_META struct pmm frames;
static MM_META struct mem_range records;
static MM_META uint64_t phys_limit;
static struct memmap map;
static struct mem_range boot_data[MAX_HELD];
static size_t boot_data_count;

/*
 * Memory in use before the allocator exists; all of it is reserved once the bitmaps are placed.
 * Read-only after paging: it is what tells a boot reservation apart from a pinned page table.
 */
static MM_META struct {
    const char *what;
    struct mem_range r;
    bool ro;
} held[MAX_HELD];
static MM_META size_t held_count;

#define FAIL(...)                              \
    do {                                       \
        bv_snprintf(why, why_len, __VA_ARGS__); \
        return -BV_EINVAL;                     \
    } while (0)

static bool boot_mapped(uint64_t base, uint64_t len)
{
    return len <= MM_BOOT_MAPPED && base <= MM_BOOT_MAPPED - len;
}

static uint64_t boot_string_size(uint64_t addr)
{
    const char *s = phys_to_virt(addr);
    uint64_t n = 0;
    while (n < MAX_BOOT_STR && addr + n < MM_BOOT_MAPPED && s[n])
        n++;
    return n + 1;
}

static int hold(const char *what, uint64_t base, uint64_t len, bool ro, char *why, size_t why_len)
{
    if (!boot_mapped(base, len))
        FAIL("%s at %p lies outside mapped memory", what, (void *)base);
    held[held_count].what = what;
    held[held_count].r = (struct mem_range){ base, base + len };
    held[held_count++].ro = ro;
    return 0;
}

static int collect_boot_data(const volatile struct multiboot_info *mb, char *why, size_t why_len)
{
    uint32_t flags = mb->flags;
    int rc = hold("low memory (BIOS, IVT, EBDA, VGA)", 0, MM_LOW_RESERVED, false, why, why_len);
    if (!rc)
        rc = hold("kernel image", (uintptr_t)__kernel_start, (uintptr_t)__kernel_end - (uintptr_t)__kernel_start,
                  false, why, why_len);
    if (!rc)
        rc = hold("Multiboot info", (uintptr_t)mb, sizeof *mb, true, why, why_len);
    if (!rc)
        rc = hold("memory map", mb->mmap_addr, mb->mmap_length, true, why, why_len);
    if (!rc && (flags & MULTIBOOT_INFO_CMDLINE) && boot_mapped(mb->cmdline, 1))
        rc = hold("command line", mb->cmdline, boot_string_size(mb->cmdline), true, why, why_len);
    if (!rc && (flags & MULTIBOOT_INFO_LOADER) && boot_mapped(mb->boot_loader_name, 1))
        rc = hold("loader name", mb->boot_loader_name, boot_string_size(mb->boot_loader_name), true, why, why_len);
    if (rc || !(flags & MULTIBOOT_INFO_MODS) || mb->mods_count == 0)
        return rc;

    uint32_t count = mb->mods_count;
    if (count > MAX_MODULES)
        FAIL("too many boot modules (%u)", count);
    rc = hold("module table", mb->mods_addr, (uint64_t)count * sizeof(struct multiboot_module), true, why, why_len);
    const volatile struct multiboot_module *mods = phys_to_virt(mb->mods_addr);
    for (uint32_t i = 0; !rc && i < count; i++) {
        uint32_t start = mods[i].mod_start, end = mods[i].mod_end;
        if (end < start)
            FAIL("boot module %u has end below start", i);
        rc = hold("boot module", start, end - start, true, why, why_len);
    }
    return rc;
}

static int reserve(const char *what, struct mem_range r, char *why, size_t why_len)
{
    int rc = pmm_reserve(&frames, r.base, r.end - r.base);
    if (rc)
        FAIL("cannot reserve %s: %s", what, bv_strerror(rc));
    kprintf("       reserved %p - %p  %s\n", (void *)r.base, (void *)r.end, what);
    return 0;
}

/* Sizes the frame bitmaps for the managed map and puts them in boot-mapped RAM no one else uses. */
static int init_frames(char *why, size_t why_len)
{
    uint64_t words = pmm_words_for(&map), base;
    struct mem_range avoid[MAX_HELD];
    for (size_t i = 0; i < held_count; i++)
        avoid[i] = held[i].r;
    int rc = pmm_place(&map, 2 * words * sizeof(uint64_t), avoid, held_count, MM_BOOT_MAPPED, &base);
    if (rc)
        FAIL("no room below 1 GiB for the frame records (%lu KiB): %s",
             (unsigned long)(2 * words * sizeof(uint64_t) / 1024), bv_strerror(rc));
    records = (struct mem_range){ base, base + ((2 * words * sizeof(uint64_t) + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1)) };
    uint64_t *used = phys_to_virt(base), *reserved = used + words;
    rc = pmm_init(&frames, used, reserved, words, &map);
    if (rc)
        FAIL("frame allocator init failed: %s", bv_strerror(rc));
    for (size_t i = 0; !rc && i < held_count; i++) {
        rc = reserve(held[i].what, held[i].r, why, why_len);
        if (!rc && held[i].ro && held[i].r.end > held[i].r.base)
            boot_data[boot_data_count++] = held[i].r;
    }
    return rc ? rc : reserve("frame allocator records", records, why, why_len);
}

static int frame_selfcheck(char *why, size_t why_len)
{
    uint64_t before = frames.free_frames, a, b;
    if (pmm_alloc(&frames, &a) || pmm_alloc(&frames, &b))
        FAIL("frame self-check: allocation failed");
    uint64_t ks = (uintptr_t)__kernel_start, ke = (uintptr_t)__kernel_end;
    if (a == b || a % PAGE_SIZE || b % PAGE_SIZE || a < MM_LOW_RESERVED || b < MM_LOW_RESERVED ||
        (a >= ks && a < ke) || (b >= ks && b < ke) || (a >= records.base && a < records.end) ||
        (b >= records.base && b < records.end))
        FAIL("frame self-check: bad frames %p %p", (void *)a, (void *)b);

    volatile uint64_t *pa = phys_to_virt(a), *pb = phys_to_virt(b);
    for (uint64_t i = 0; i < PAGE_SIZE / 8; i++) {
        pa[i] = a ^ i;
        pb[i] = ~(b ^ i);
    }
    for (uint64_t i = 0; i < PAGE_SIZE / 8; i++)
        if (pa[i] != (a ^ i) || pb[i] != ~(b ^ i))
            FAIL("frame self-check: pattern mismatch at %p", (void *)(a + i * 8));

    if (pmm_free(&frames, a) || pmm_free(&frames, b))
        FAIL("frame self-check: free failed");
    if (pmm_free(&frames, a) != -BV_EALREADY)
        FAIL("frame self-check: double free not detected");
    if (pmm_free(&frames, ks) != -BV_EPERM || pmm_free(&frames, records.base) != -BV_EPERM)
        FAIL("frame self-check: freeing a kernel or frame-record frame was not refused");
    if (pmm_free(&frames, a + 8) != -BV_EINVAL)
        FAIL("frame self-check: misaligned free was not refused");
    if (frames.free_frames != before)
        FAIL("frame self-check: free count drifted");
    if (pmm_check(&frames))
        FAIL("frame self-check: bitmaps and counters disagree");
    kprintf("[ OK ] Frame allocator self-check passed\n");
    return 0;
}

/* Highest physical address the CPU can form, capped at what the kernel is built to manage. */
static uint64_t managed_limit(unsigned *bits)
{
    uint32_t a, b, c, d;
    cpuid(0x80000000u, &a, &b, &c, &d);
    *bits = 36;
    if (a >= 0x80000008u) {
        cpuid(0x80000008u, &a, &b, &c, &d);
        if ((a & 0xff) >= 32 && (a & 0xff) <= 52)
            *bits = a & 0xff;
    }
    uint64_t width = 1ull << *bits;
    return width < MM_PHYS_MAX ? width : MM_PHYS_MAX;
}

int mm_init(const volatile struct multiboot_info *mb, char *why, size_t why_len)
{
    if (!(mb->flags & MULTIBOOT_INFO_MMAP))
        FAIL("boot loader provided no memory map");
    uint32_t mmap_addr = mb->mmap_addr, mmap_len = mb->mmap_length;
    if (!boot_mapped(mmap_addr, mmap_len))
        FAIL("memory map lies outside mapped memory");
    const void *raw = phys_to_virt(mmap_addr);

    struct mb_mmap_entry e;
    uint32_t off = 0;
    for (unsigned i = 0; memmap_raw_next(raw, mmap_len, &off, &e) == 1; i++)
        kprintf("       mmap[%u] %p - %p  %s\n", i, (void *)e.base, (void *)(e.base + e.len),
                memmap_type_name(e.type));

    unsigned bits;
    phys_limit = managed_limit(&bits);
    int rc = memmap_parse(raw, mmap_len, phys_limit, &map);
    if (rc)
        FAIL("invalid memory map: %s", bv_strerror(rc));
    kprintf("[ OK ] Physical address width: %u bits; RAM managed up to %lu MiB\n", bits,
            (unsigned long)(phys_limit >> 20));
    kprintf("[ OK ] Memory map: %u entries, %lu KiB usable in %zu ranges\n", map.raw_entries,
            (unsigned long)(memmap_usable_bytes(&map) / 1024), map.count);
    if (map.skipped_entries)
        kprintf("[WARN] Memory map: %u zero-length or wrapping entries ignored\n", map.skipped_entries);
    if (map.clipped_bytes)
        kprintf("[WARN] Memory map: %lu KiB of RAM above the %lu MiB managed limit excluded\n",
                (unsigned long)(map.clipped_bytes / 1024), (unsigned long)(phys_limit >> 20));

    rc = collect_boot_data(mb, why, why_len);
    if (!rc)
        rc = init_frames(why, why_len);
    if (rc)
        return rc;
    kprintf("[ OK ] Physical frames: %lu KiB usable, %lu KiB reserved, %lu KiB free (%lu frames, highest %p)\n",
            (unsigned long)(frames.usable_frames * 4), (unsigned long)(frames.reserved_frames * 4),
            (unsigned long)(frames.free_frames * 4), (unsigned long)frames.free_frames,
            (void *)(frames.nframes * PAGE_SIZE));
    return frame_selfcheck(why, why_len);
}

int kframe_alloc(uint64_t *phys)
{
    mm_write_begin();
    int rc = pmm_alloc(&frames, phys);
    mm_write_end();
    return rc;
}

int kframe_alloc_below(uint64_t limit, uint64_t *phys)
{
    mm_write_begin();
    int rc = pmm_alloc_below(&frames, limit, phys);
    mm_write_end();
    return rc;
}

int kframe_free(uint64_t phys)
{
    mm_write_begin();
    int rc = pmm_free(&frames, phys);
    mm_write_end();
    return rc;
}

int kframe_pin(uint64_t phys)
{
    mm_write_begin();
    int rc = pmm_pin(&frames, phys);
    mm_write_end();
    return rc;
}

static bool touches(struct mem_range r, uint64_t phys)
{
    return r.base < phys + PAGE_SIZE && phys < r.end;
}

/* Only a pinned page table may be unpinned: never a boot reservation, the records or unusable RAM. */
int kframe_unpin(uint64_t phys)
{
    if (phys % PAGE_SIZE || touches(records, phys))
        return -BV_EPERM;
    for (size_t i = 0; i < held_count; i++)
        if (touches(held[i].r, phys))
            return -BV_EPERM;
    bool usable = false;
    for (size_t i = 0; i < map.count && !usable; i++)
        usable = map.usable[i].base <= phys && phys + PAGE_SIZE <= map.usable[i].end;
    if (!usable)
        return -BV_EPERM;
    mm_write_begin();
    int rc = pmm_unpin(&frames, phys);
    mm_write_end();
    return rc;
}

int kframe_check(void)
{
    return pmm_check(&frames);
}

struct mem_range kframe_records(void)
{
    return records;
}

uint64_t mm_phys_limit(void)
{
    return phys_limit;
}

const struct memmap *mm_memmap(void)
{
    return &map;
}

size_t mm_boot_data(const struct mem_range **ranges)
{
    *ranges = boot_data;
    return boot_data_count;
}

const struct pmm *kframe_stats(void)
{
    return &frames;
}
