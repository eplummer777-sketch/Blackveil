/* Kernel address space: identity map with per-section permissions, guard pages and self-check. */
#include <bv/console.h>
#include <bv/errno.h>
#include <bv/format.h>
#include <bv/io.h>
#include <bv/mm.h>
#include <bv/panic.h>
#include <bv/trap.h>

#define EFER_MSR   0xC0000080u
#define EFER_NXE   (1ull << 11)
#define CR0_WP     (1ull << 16)
#define VGA_BASE   0xB8000ull
#define VGA_END    0xC0000ull
#define SCRATCH_VA 0xFFFF900000000000ull

extern char __kernel_start[], __text_end[], __rodata_end[], __kernel_end[];
extern char boot_stack_guard[], boot_page_tables[];

#define BOOT_TABLE_BYTES (3 * PAGE_SIZE) /* PML4, PDPT, PD from boot.S; dead after the CR3 switch */

static MM_META struct vmm kvm;
static MM_META bool paging_active;
static uint64_t rw_probe; /* an ordinary writable kernel variable for the self-check */

static const struct {
    const char *name;
    unsigned ist_slot; /* 0 = boot stack */
} guards[] = {
    { "boot stack", 0 },
    { "#DF emergency stack", IST_DOUBLE_FAULT },
    { "NMI emergency stack", IST_NMI },
    { "#MC emergency stack", IST_MACHINE_CHECK },
};

#define FAIL(...)                              \
    do {                                       \
        bv_snprintf(why, why_len, __VA_ARGS__); \
        return -BV_EINVAL;                     \
    } while (0)

static int k_alloc(void *ctx, uint64_t *phys)
{
    (void)ctx;
    /* Until CR3 switches, new tables are zeroed and filled through the boot map's first 1 GiB. */
    return paging_active ? kframe_alloc(phys) : kframe_alloc_below(MM_BOOT_MAPPED, phys);
}

static void k_release(void *ctx, uint64_t phys)
{
    (void)ctx;
    kframe_free(phys);
}

/* A new table frame is pinned and its identity-map entry made read-only before it is linked in. */
static void k_commit(void *ctx, uint64_t phys)
{
    (void)ctx;
    if (kframe_pin(phys))
        panic("page table frame %p could not be pinned", (void *)phys);
    if (paging_active && vmm_protect(&kvm, phys, PAGE_SIZE, 0))
        panic("page table frame %p could not be made read-only", (void *)phys);
}

/* Once live, no new writable mapping may reach a reserved frame (tables, metadata, kernel, boot data). */
static int k_allow(void *ctx, uint64_t pa, unsigned flags)
{
    (void)ctx;
    if (!paging_active || !(flags & VMM_WRITE))
        return 0;
    return pmm_state_of(kframe_stats(), pa) == PMM_RESERVED ? -BV_EPERM : 0;
}

static void k_write_begin(void *ctx)
{
    (void)ctx;
    mm_write_begin();
}

static void k_write_end(void *ctx)
{
    (void)ctx;
    mm_write_end();
}

static void k_flush_all(void *ctx)
{
    (void)ctx;
    write_cr3(read_cr3());
}

/*
 * The frame is unreachable and no longer cached. Its identity alias is made writable again only
 * after it stops being reserved, so k_allow never sees a writable alias of a live table.
 */
static void k_retire(void *ctx, uint64_t phys)
{
    (void)ctx;
    if (phys == kvm.root)
        panic("page table reclamation reached the root table %p", (void *)phys);
    int rc = kframe_unpin(phys);
    if (rc)
        panic("reclaimed page table %p could not be unpinned: %s", (void *)phys, bv_strerror(rc));
    if (paging_active && (rc = vmm_protect(&kvm, phys, PAGE_SIZE, VMM_WRITE)) != 0)
        panic("reclaimed page table %p could not be made writable: %s", (void *)phys, bv_strerror(rc));
    if ((rc = kframe_free(phys)) != 0)
        panic("reclaimed page table %p could not be freed: %s", (void *)phys, bv_strerror(rc));
}

static void *k_virt(void *ctx, uint64_t phys)
{
    (void)ctx;
    return phys_to_virt(phys);
}

static void k_flush(void *ctx, uint64_t va)
{
    (void)ctx;
    invlpg(va);
}

static const struct vmm_ops kernel_ops = { k_alloc, k_release,     k_commit,    k_virt, k_flush, k_flush_all,
                                           k_retire, k_allow,  k_write_begin, k_write_end, NULL };

static uint64_t guard_addr(size_t i)
{
    return guards[i].ist_slot ? cpu_ist_guard(guards[i].ist_slot) : (uint64_t)(uintptr_t)boot_stack_guard;
}

static const char *perm(unsigned flags)
{
    return (flags & VMM_WRITE) ? "rw-" : (flags & VMM_EXEC) ? "r-x" : "r--";
}

static int map(const char *what, uint64_t base, uint64_t end, unsigned flags, char *why, size_t why_len)
{
    if (end <= base)
        return 0;
    int rc = vmm_map(&kvm, base, base, end - base, flags);
    if (rc)
        FAIL("cannot map %s at %p: %s", what, (void *)base, bv_strerror(rc));
    kprintf("       map %p - %p  %s  %s\n", (void *)base, (void *)end, perm(flags), what);
    return 0;
}

static int map_ram(char *why, size_t why_len)
{
    uint64_t ks = (uintptr_t)__kernel_start, ke = (uintptr_t)__kernel_end;
    const struct memmap *m = mm_memmap();
    int rc = 0;
    for (size_t i = 0; !rc && i < m->count; i++) {
        uint64_t lo = m->usable[i].base < MM_LOW_RESERVED ? MM_LOW_RESERVED : m->usable[i].base;
        uint64_t hi = m->usable[i].end;
        if (lo >= hi)
            continue;
        rc = map("RAM", lo, hi < ks ? hi : ks, VMM_WRITE, why, why_len);
        if (!rc)
            rc = map("RAM", lo > ke ? lo : ke, hi, VMM_WRITE, why, why_len);
    }
    return rc;
}

static int protect_boot_data(char *why, size_t why_len)
{
    const struct mem_range *r;
    size_t n = mm_boot_data(&r);
    for (size_t i = 0; i < n; i++) {
        uint64_t b = r[i].base & ~(uint64_t)(PAGE_SIZE - 1);
        uint64_t e = (r[i].end + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
        if (b < VGA_END && e > VGA_BASE)
            FAIL("boot data at %p overlaps the VGA buffer", (void *)r[i].base);
        int rc = vmm_protect(&kvm, b, e - b, 0);
        if (rc == -BV_ENOENT)
            rc = vmm_map(&kvm, b, b, e - b, 0);
        if (rc)
            FAIL("cannot make boot data at %p read-only: %s", (void *)b, bv_strerror(rc));
    }
    kprintf("       boot data (%zu ranges) made read-only\n", n);
    return 0;
}

struct sweep {
    uint64_t bad, bad_phys;
    bool check;
};

static void sweep_table(void *arg, uint64_t phys)
{
    struct sweep *s = arg;
    unsigned flags;
    bool ok = s->check ? vmm_query(&kvm, phys, NULL, &flags) == 0 && !(flags & VMM_WRITE) &&
                             pmm_state_of(kframe_stats(), phys) == PMM_RESERVED
                       : vmm_protect(&kvm, phys, PAGE_SIZE, 0) == 0;
    if (!ok && !s->bad++)
        s->bad_phys = phys;
}

/* Removes every writable alias of paging and allocator metadata from the new address space. */
static int protect_metadata(char *why, size_t why_len)
{
    uint64_t ms = (uintptr_t)__mm_meta_start, me = (uintptr_t)__mm_meta_end, bt = (uintptr_t)boot_page_tables;
    struct mem_range rec = kframe_records();
    if (vmm_protect(&kvm, ms, me - ms, 0) || vmm_protect(&kvm, bt, BOOT_TABLE_BYTES, 0) ||
        vmm_protect(&kvm, rec.base, rec.end - rec.base, 0))
        FAIL("cannot make memory-manager metadata read-only");
    kprintf("       frame records %p - %p made read-only\n", (void *)rec.base, (void *)rec.end);
    struct sweep s = { 0 };
    uint64_t n = vmm_walk_tables(&kvm, sweep_table, &s);
    if (s.bad || n != kvm.tables)
        FAIL("cannot make page table %p read-only (%lu of %lu tables)", (void *)s.bad_phys, (unsigned long)s.bad,
             (unsigned long)n);
    kprintf("       metadata %p - %p, boot tables and %lu table pages made read-only\n", (void *)ms, (void *)me,
            (unsigned long)n);
    return 0;
}

static int build(char *why, size_t why_len)
{
    uint64_t ks = (uintptr_t)__kernel_start, te = (uintptr_t)__text_end, re = (uintptr_t)__rodata_end;
    uint64_t ke = (uintptr_t)__kernel_end;
    int rc = map("low memory (page 0 left unmapped)", PAGE_SIZE, VGA_BASE, 0, why, why_len);
    if (!rc)
        rc = map("VGA text buffer", VGA_BASE, VGA_END, VMM_WRITE, why, why_len);
    if (!rc)
        rc = map("BIOS area", VGA_END, MM_LOW_RESERVED, 0, why, why_len);
    if (!rc)
        rc = map("kernel code", ks, te, VMM_EXEC, why, why_len);
    if (!rc)
        rc = map("kernel read-only data", te, re, 0, why, why_len);
    if (!rc)
        rc = map("kernel data + bss", re, ke, VMM_WRITE, why, why_len);
    if (!rc)
        rc = map_ram(why, why_len);
    if (!rc)
        rc = protect_boot_data(why, why_len);
    for (size_t i = 0; !rc && i < sizeof guards / sizeof guards[0]; i++) {
        rc = vmm_unmap(&kvm, guard_addr(i), PAGE_SIZE);
        if (rc)
            FAIL("cannot unmap %s guard: %s", guards[i].name, bv_strerror(rc));
    }
    return rc ? rc : protect_metadata(why, why_len);
}

static int expect(uint64_t va, int want_rc, unsigned want, const char *what, char *why, size_t why_len)
{
    unsigned flags = 0;
    int rc = vmm_query(&kvm, va, NULL, &flags);
    if (!kvm.nx)
        want |= VMM_EXEC;
    if (rc != want_rc || (rc == 0 && flags != want))
        FAIL("paging self-check: %s at %p is %s", what, (void *)va, rc ? "unmapped" : perm(flags));
    return 0;
}

int vm_verify_protection(char *why, size_t why_len)
{
    int rc = 0;
    for (uint64_t a = (uintptr_t)__mm_meta_start; !rc && a < (uintptr_t)__mm_meta_end; a += PAGE_SIZE)
        rc = expect(a, 0, 0, "allocator metadata", why, why_len);
    struct mem_range rec = kframe_records();
    for (uint64_t a = rec.base; !rc && a < rec.end; a += PAGE_SIZE)
        rc = expect(a, 0, 0, "frame records", why, why_len);
    for (uint64_t off = 0; !rc && off < BOOT_TABLE_BYTES; off += PAGE_SIZE)
        rc = expect((uintptr_t)boot_page_tables + off, 0, 0, "boot page tables", why, why_len);
    if (rc)
        return rc;
    struct sweep s = { .check = true };
    uint64_t n = vmm_walk_tables(&kvm, sweep_table, &s);
    if (s.bad || n != kvm.tables)
        FAIL("page table %p is writable or not pinned (%lu bad, %lu of %lu found)", (void *)s.bad_phys,
             (unsigned long)s.bad, (unsigned long)n, (unsigned long)kvm.tables);
    if (kframe_check())
        FAIL("frame allocator bitmaps and counters disagree");
    if (!(read_cr0() & CR0_WP))
        FAIL("CR0.WP is clear outside the write window");
    return 0;
}

static int selfcheck(char *why, size_t why_len)
{
    int rc = expect(0, -BV_ENOENT, 0, "null page", why, why_len);
    if (!rc)
        rc = expect((uintptr_t)__kernel_start, 0, VMM_EXEC, "kernel code", why, why_len);
    if (!rc)
        rc = expect((uintptr_t)__text_end, 0, 0, "read-only data", why, why_len);
    if (!rc)
        rc = expect((uintptr_t)&rw_probe, 0, VMM_WRITE, "kernel data", why, why_len);
    if (!rc)
        rc = expect(VGA_BASE, 0, VMM_WRITE, "VGA buffer", why, why_len);
    for (size_t i = 0; !rc && i < sizeof guards / sizeof guards[0]; i++)
        rc = expect(guard_addr(i), -BV_ENOENT, 0, "stack guard", why, why_len);
    const struct mem_range *r;
    size_t n = mm_boot_data(&r);
    for (size_t i = 0; !rc && i < n; i++)
        rc = expect(r[i].base, 0, 0, "boot data", why, why_len);
    if (rc)
        return rc;
    if (!(read_cr0() & CR0_WP) || read_cr3() != kvm.root)
        FAIL("paging self-check: CR0.WP or CR3 not set");
    if (kvm.nx != !!(rdmsr(EFER_MSR) & EFER_NXE))
        FAIL("paging self-check: EFER.NXE does not match NX support");

    uint64_t f;
    if (kframe_alloc(&f))
        FAIL("paging self-check: no frame for the scratch mapping");
    volatile uint64_t *direct = phys_to_virt(f), *alias = (volatile uint64_t *)SCRATCH_VA;
    direct[0] = 0x5AFE0000C0DEull;
    if (vmm_map(&kvm, SCRATCH_VA, f, PAGE_SIZE, VMM_WRITE))
        FAIL("paging self-check: scratch map failed");
    bool alias_ok = alias[0] == 0x5AFE0000C0DEull;
    alias[1] = 0x1234;
    alias_ok = alias_ok && direct[1] == 0x1234;
    int busy = vmm_map(&kvm, SCRATCH_VA, f, PAGE_SIZE, 0);
    int wx = vmm_map(&kvm, SCRATCH_VA + PAGE_SIZE, f, PAGE_SIZE, VMM_WRITE | VMM_EXEC);
    int odd = vmm_map(&kvm, SCRATCH_VA + 8, f, PAGE_SIZE, 0);
    int unmap = vmm_unmap(&kvm, SCRATCH_VA, PAGE_SIZE);
    int gone = vmm_query(&kvm, SCRATCH_VA, NULL, NULL);
    int again = vmm_unmap(&kvm, SCRATCH_VA, PAGE_SIZE);
    int freed = kframe_free(f);
    if (!alias_ok || busy != -BV_EBUSY || wx != -BV_EINVAL || odd != -BV_EINVAL || unmap || gone != -BV_ENOENT ||
        again != -BV_ENOENT || freed)
        FAIL("paging self-check: map/unmap behaviour wrong (%d %d %d %d %d %d %d %d)", alias_ok, busy, wx, odd,
             unmap, gone, again, freed);
    if (kframe_free(kvm.root) != -BV_EPERM)
        FAIL("paging self-check: a page-table frame could be freed");
    if (vmm_map(&kvm, SCRATCH_VA, kvm.root, PAGE_SIZE, VMM_WRITE) != -BV_EPERM ||
        vmm_protect(&kvm, kvm.root, PAGE_SIZE, VMM_WRITE) != -BV_EPERM)
        FAIL("paging self-check: a writable alias of a page table was allowed");
    char sub[120];
    if (vm_verify_protection(sub, sizeof sub))
        FAIL("paging self-check: %s", sub);
    kprintf("[ OK ] Paging self-check passed\n");
    kprintf("[ OK ] Page tables: all %lu table pages read-only and pinned; writable aliases refused\n",
            (unsigned long)kvm.tables);
    kprintf("[ OK ] Allocator metadata: read-only, consistency check passed\n");
    return 0;
}

int vm_init(char *why, size_t why_len)
{
    uint32_t a, b, c, d;
    cpuid(0x80000001u, &a, &b, &c, &d);
    bool nx = d & (1u << 20);

    int rc = vmm_init(&kvm, &kernel_ops, nx);
    if (rc)
        FAIL("no frame for the top-level page table: %s", bv_strerror(rc));
    rc = build(why, why_len);
    if (rc)
        return rc;

    if (nx)
        wrmsr(EFER_MSR, rdmsr(EFER_MSR) | EFER_NXE);
    /* Last writes to the metadata through the boot tables; from here only the write window can. */
    paging_active = true;
    mm_write_enable();
    write_cr3(kvm.root);
    write_cr0(read_cr0() | CR0_WP);

    kprintf("[ OK ] Paging: kernel page tables active (CR3=%p, %lu table pages)\n", (void *)kvm.root,
            (unsigned long)kvm.tables);
    if (nx)
        kprintf("[ OK ] W^X: code read-only, data, stacks and free RAM non-executable (EFER.NXE)\n");
    else
        kprintf("[WARN] CPU lacks NX: data pages stay executable; code is still read-only\n");
    kprintf("[ OK ] Write protection: kernel code, read-only data, boot data, page tables and allocator "
            "metadata (CR0.WP)\n");
    kprintf("[ OK ] Guard pages: null page, boot stack and %zu emergency stacks\n", sizeof guards / sizeof guards[0] - 1);
    return selfcheck(why, why_len);
}

struct vmm *kernel_vmm(void)
{
    return &kvm;
}

const char *vm_guard_name(uint64_t addr)
{
    if (!paging_active)
        return NULL;
    for (size_t i = 0; i < sizeof guards / sizeof guards[0]; i++)
        if (addr - guard_addr(i) < PAGE_SIZE)
            return guards[i].name;
    return NULL;
}
