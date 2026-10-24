/* Emulator-only memory-protection tests, selected with bv.test=prot-* (see selftest.c). */
#include <bv/console.h>
#include <bv/errno.h>
#include <bv/io.h>
#include <bv/mm.h>
#include <bv/panic.h>
#include <bv/selftest.h>

void bv_trigger_write(uint64_t addr);
extern char __kernel_start[], __kernel_end[], boot_page_tables[];

#define ALIAS_VA 0xFFFF900000001000ull /* the scratch slot used by the other paging tests */
#define NEW_VA   0xFFFFC00000000000ull /* empty 512 GiB slot: mapping here creates 3 new tables */
#define PTE_ADDR 0x000FFFFFFFFFF000ull
#define CR0_WP   (1ull << 16)
#define RFLAGS_IF 0x200ull

static void verify(const char *test)
{
    char why[160];
    if (vm_verify_protection(why, sizeof why))
        panic("%s: %s", test, why);
}

static uint64_t rflags(void)
{
    uint64_t f;
    __asm__ volatile("pushfq; popq %0" : "=r"(f));
    return f;
}

void selftest_prot_pt_write(void)
{
    uint64_t root = kernel_vmm()->root;
    verify("prot-pt-write");
    kprintf("[TEST] prot-pt-write: writing the top-level page table at %p\n", (void *)root);
    bv_trigger_write(root);
}

void selftest_prot_new_table(void)
{
    struct vmm *v = kernel_vmm();
    uint64_t f;
    if (kframe_alloc(&f) || vmm_map(v, NEW_VA, f, PAGE_SIZE, VMM_WRITE))
        panic("prot-new-table: setup failed");
    const uint64_t *pml4 = phys_to_virt(v->root);
    uint64_t pdpt = pml4[(NEW_VA >> 39) & 511] & PTE_ADDR;
    verify("prot-new-table");
    kprintf("[TEST] prot-new-table: writing a page table created after boot at %p\n", (void *)pdpt);
    bv_trigger_write(pdpt);
}

void selftest_prot_pmm_write(void)
{
    uint64_t bitmap = (uintptr_t)kframe_stats()->used;
    verify("prot-pmm-write");
    kprintf("[TEST] prot-pmm-write: writing the frame allocator bitmap at %p\n", (void *)bitmap);
    bv_trigger_write(bitmap);
}

void selftest_prot_boot_pt(void)
{
    kprintf("[TEST] prot-boot-pt: writing the boot page tables at %p\n", (void *)boot_page_tables);
    bv_trigger_write((uintptr_t)boot_page_tables);
}

void selftest_prot_alias(void)
{
    struct vmm *v = kernel_vmm();
    uint64_t root = v->root, meta = (uintptr_t)__mm_meta_start, tables = v->tables;
    if (vmm_map(v, ALIAS_VA, root, PAGE_SIZE, VMM_WRITE) != -BV_EPERM ||
        vmm_map(v, ALIAS_VA, meta, PAGE_SIZE, VMM_WRITE) != -BV_EPERM ||
        vmm_map(v, ALIAS_VA, (uintptr_t)boot_page_tables, PAGE_SIZE, VMM_WRITE) != -BV_EPERM ||
        vmm_query(v, ALIAS_VA, NULL, NULL) != -BV_ENOENT || v->tables != tables)
        panic("prot-alias: a writable alias was allowed or left state behind");
    unsigned fl;
    if (vmm_map(v, ALIAS_VA, root, PAGE_SIZE, 0) || vmm_protect(v, ALIAS_VA, PAGE_SIZE, VMM_WRITE) != -BV_EPERM ||
        vmm_query(v, ALIAS_VA, NULL, &fl) || (fl & VMM_WRITE) ||
        *(volatile uint64_t *)ALIAS_VA != *(const volatile uint64_t *)phys_to_virt(root))
        panic("prot-alias: read-only alias setup failed");
    verify("prot-alias");
    kprintf("[TEST] prot-alias: writable aliases of a page table, allocator metadata and boot tables refused\n");
    kprintf("[TEST] prot-alias: writing a read-only alias of the top-level page table at %p\n", (void *)ALIAS_VA);
    bv_trigger_write(ALIAS_VA);
}

static void controlled_updates(struct vmm *v)
{
    uint64_t tables = v->tables, f, flags = rflags();
    if (kframe_alloc(&f) || vmm_map(v, NEW_VA, f, PAGE_SIZE, VMM_WRITE))
        panic("prot-checks: map through the write window failed");
    volatile uint64_t *va = (volatile uint64_t *)NEW_VA, *direct = phys_to_virt(f);
    va[0] = 0xB1ACC0DEull;
    unsigned fl = VMM_WRITE, step = 0;
    if (direct[0] == 0xB1ACC0DEull && ++step && v->tables == tables + 3 && ++step) {
        verify("prot-checks");
        if (!vmm_protect(v, NEW_VA, PAGE_SIZE, 0) && !vmm_query(v, NEW_VA, NULL, &fl) && !(fl & VMM_WRITE) &&
            ++step && !vmm_protect(v, NEW_VA, PAGE_SIZE, VMM_WRITE) && !vmm_unmap(v, NEW_VA, PAGE_SIZE) && ++step &&
            vmm_query(v, NEW_VA, NULL, NULL) == -BV_ENOENT && !kframe_free(f) && ++step &&
            (read_cr0() & CR0_WP) && (rflags() & RFLAGS_IF) == (flags & RFLAGS_IF))
            step = 0;
    }
    if (step)
        panic("prot-checks: controlled page-table update failed after step %u (tables %lu -> %lu)", step,
              (unsigned long)tables, (unsigned long)v->tables);
    verify("prot-checks");
    kprintf("[TEST] prot-checks: map, protect and unmap through the write window work; 3 new table pages "
            "read-only and pinned; CR0.WP and interrupt flag restored\n");
}

static void corruption_detected(const struct pmm *st, uint64_t root)
{
    uint64_t g;
    if (kframe_alloc(&g) || kframe_free(g))
        panic("prot-checks: no free frame");
    uint64_t gw = g / PAGE_SIZE / 64, gb = 1ull << (g / PAGE_SIZE % 64);
    uint64_t rw = root / PAGE_SIZE / 64, rb = 1ull << (root / PAGE_SIZE % 64);
    int rc[3];
    mm_write_begin();
    st->used[gw] |= gb;
    rc[0] = kframe_check();
    st->used[gw] &= ~gb;
    st->reserved[gw] |= gb;
    rc[1] = kframe_check();
    st->reserved[gw] &= ~gb;
    st->reserved[rw] &= ~rb;
    rc[2] = kframe_check();
    st->reserved[rw] |= rb;
    mm_write_end();
    if (rc[0] != -BV_EFAULT || rc[1] != -BV_EFAULT || rc[2] != -BV_EFAULT || kframe_check())
        panic("prot-checks: metadata corruption not detected (%d %d %d)", rc[0], rc[1], rc[2]);
    kprintf("[TEST] prot-checks: 3 kinds of allocator metadata corruption detected; restored and consistent\n");
}

static void no_reserved_frames_handed_out(const struct pmm *st)
{
    uint64_t head = UINT64_MAX, phys, n = 0, bad = 0, ks = (uintptr_t)__kernel_start, ke = (uintptr_t)__kernel_end;
    while (kframe_alloc(&phys) == 0) {
        bad += phys < MM_LOW_RESERVED || (phys >= ks && phys < ke) || pmm_state_of(st, phys) != PMM_USED;
        *(volatile uint64_t *)phys_to_virt(phys) = head;
        head = phys;
        n++;
    }
    bool oom_ok = st->free_frames == 0 && kframe_alloc(&phys) == -BV_ENOMEM && st->free_frames == 0 && !kframe_check();
    while (head != UINT64_MAX) {
        uint64_t next = *(volatile uint64_t *)phys_to_virt(head);
        if (kframe_free(head))
            panic("prot-checks: could not return frame %p", (void *)head);
        head = next;
    }
    if (bad || !oom_ok)
        panic("prot-checks: %lu reserved frames handed out (oom ok %d)", (unsigned long)bad, oom_ok);
    kprintf("[TEST] prot-checks: all %lu free frames allocated, none reserved, a page table or metadata; "
            "out of memory changed nothing\n", (unsigned long)n);
}

static void bad_frees_refused(struct vmm *v, const struct pmm *st)
{
    uint64_t g, free = st->free_frames, rsv = st->reserved_frames, tables = v->tables;
    if (kframe_alloc(&g) || kframe_free(g))
        panic("prot-checks: no free frame");
    int rc[9] = {
        kframe_free(v->root),          kframe_free((uintptr_t)__mm_meta_start), kframe_free((uintptr_t)boot_page_tables),
        kframe_free(g),                kframe_free(g + 8),                      kframe_free(st->nframes * PAGE_SIZE),
        kframe_pin(g),                 kframe_pin(v->root),
        vmm_map(v, NEW_VA, v->root - PAGE_SIZE, 3 * PAGE_SIZE, VMM_WRITE),
    };
    static const int want[9] = { -BV_EPERM,  -BV_EPERM, -BV_EPERM, -BV_EALREADY, -BV_EINVAL,
                                 -BV_EINVAL, -BV_EINVAL, -BV_EPERM, -BV_EPERM };
    for (int i = 0; i < 9; i++)
        if (rc[i] != want[i])
            panic("prot-checks: refused operation %d returned %d (want %d)", i, rc[i], want[i]);
    if (st->free_frames != free || st->reserved_frames != rsv || v->tables != tables ||
        vmm_query(v, NEW_VA, NULL, NULL) != -BV_ENOENT || kframe_check())
        panic("prot-checks: a refused operation changed state");
    kprintf("[TEST] prot-checks: frees of page tables, metadata and boot tables, double, misaligned and "
            "out-of-range frees, bad pins and a writable alias refused with no change\n");
}

void selftest_prot_checks(void)
{
    struct vmm *v = kernel_vmm();
    const struct pmm *st = kframe_stats();
    verify("prot-checks");
    controlled_updates(v);
    corruption_detected(st, v->root);
    no_reserved_frames_handed_out(st);
    bad_frees_refused(v, st);
    verify("prot-checks");
    kprintf("[TEST] prot-checks: all protection checks passed\n");
}
