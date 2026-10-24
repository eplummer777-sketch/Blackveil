/*
 * Emulator-only fault tests, selected with "bv.test=<name>" on the Multiboot command
 * line (QEMU -append). The command line comes from the boot loader, which is trusted.
 */
#include <bv/console.h>
#include <bv/errno.h>
#include <bv/mm.h>
#include <bv/trap.h>
#include <bv/panic.h>
#include <bv/selftest.h>
#include <bv/string.h>

void bv_trigger_de(void);
void bv_trigger_bp(void);
void bv_trigger_ud(void);
void bv_trigger_gp(void);
void bv_trigger_pf(void);
void bv_trigger_df(void);
void bv_trigger_write(uint64_t addr);
uint64_t bv_trigger_read(uint64_t addr);
void bv_trigger_stack_overflow(void);

/* Targets for the page-permission tests; global so the boot tests can find them by symbol. */
const uint64_t bv_ro_canary = 0xB1ACC7E11u;
uint8_t bv_nx_buf[16] = { 0xC3 }; /* ret */

#define TEST_VA     0xFFFF900000001000ull /* next to the paging self-check's scratch page */
#define FRESH_VA    0xFFFFA00000000000ull /* nothing mapped in this 512 GiB slot */

static const char *test_cmdline;

static void trigger_panic(void)
{
    panic("deliberate panic requested by bv.test=panic");
}

static void trigger_nested(void)
{
    panic_inject_fault();
    bv_trigger_ud();
}

extern char __kernel_start[], __kernel_end[];

/* Hands out every free frame (chained through the frames themselves), then returns them all. */
static void test_pmm_drain(void)
{
    const struct pmm *st = kframe_stats();
    uint64_t start_free = st->free_frames, head = UINT64_MAX, count = 0, phys;
    uint64_t ks = (uintptr_t)__kernel_start, ke = (uintptr_t)__kernel_end;
    while (kframe_alloc(&phys) == 0) {
        if (phys < MM_LOW_RESERVED || (phys >= ks && phys < ke) || pmm_state_of(st, phys) != PMM_USED)
            panic("pmm-drain: allocator returned protected frame %p", (void *)phys);
        *(volatile uint64_t *)phys_to_virt(phys) = head;
        head = phys;
        count++;
    }
    if (count != start_free || st->free_frames != 0)
        panic("pmm-drain: got %lu frames, expected %lu", (unsigned long)count, (unsigned long)start_free);
    kprintf("[TEST] pmm-drain: allocated %lu of %lu free frames, then out of memory\n", (unsigned long)count,
            (unsigned long)start_free);
    while (head != UINT64_MAX) {
        uint64_t next = *(volatile uint64_t *)phys_to_virt(head);
        if (kframe_free(head) != 0)
            panic("pmm-drain: frame %p handed out twice", (void *)head);
        head = next;
    }
    if (st->free_frames != start_free)
        panic("pmm-drain: free count %lu after return, expected %lu", (unsigned long)st->free_frames,
              (unsigned long)start_free);
    kprintf("[TEST] pmm-drain: all frames returned, free count restored\n");
}

static void test_null(void) { bv_trigger_read(0); }
static void test_wp_text(void) { bv_trigger_write((uintptr_t)bv_trigger_write); }
static void test_wp_rodata(void) { bv_trigger_write((uintptr_t)&bv_ro_canary); }
static void test_wp_bootinfo(void) { bv_trigger_write((uintptr_t)test_cmdline); }
static void test_guard_stack(void) { bv_trigger_stack_overflow(); }
static void test_guard_ist(void) { bv_trigger_write(cpu_ist_guard(IST_DOUBLE_FAULT)); }

static void run_code_at(void *p)
{
    ((void (*)(void))(uintptr_t)p)();
}

static void test_nx_data(void) { run_code_at(bv_nx_buf); }

static void test_nx_stack(void)
{
    volatile uint8_t code[16] = { 0xC3 };
    run_code_at((void *)code);
}

static void test_nx_ram(void)
{
    uint64_t f;
    if (kframe_alloc(&f))
        panic("nx-ram: no free frame");
    *(volatile uint8_t *)phys_to_virt(f) = 0xC3;
    run_code_at(phys_to_virt(f));
}

/* Proves the TLB entry is dropped on unmap: the page is used (cached), unmapped, then touched again. */
static void test_unmap_fault(void)
{
    uint64_t f;
    if (kframe_alloc(&f) || vmm_map(kernel_vmm(), TEST_VA, f, PAGE_SIZE, VMM_WRITE))
        panic("unmap-fault: setup failed");
    volatile uint64_t *p = (volatile uint64_t *)TEST_VA;
    *p = 0x77;
    if (*p != 0x77 || vmm_unmap(kernel_vmm(), TEST_VA, PAGE_SIZE))
        panic("unmap-fault: mapping did not work");
    kprintf("[TEST] unmap-fault: %p was mapped and used, now unmapped\n", (void *)TEST_VA);
    bv_trigger_read(TEST_VA);
}

/* Leaves exactly `keep` frames free; the taken frames are chained through themselves. */
static uint64_t drain_to(uint64_t keep)
{
    uint64_t head = UINT64_MAX, phys;
    while (kframe_stats()->free_frames > keep && kframe_alloc(&phys) == 0) {
        *(volatile uint64_t *)phys_to_virt(phys) = head;
        head = phys;
    }
    return head;
}

static void refill(uint64_t head)
{
    while (head != UINT64_MAX) {
        uint64_t next = *(volatile uint64_t *)phys_to_virt(head);
        if (kframe_free(head))
            panic("vmm-rollback: could not return frame %p", (void *)head);
        head = next;
    }
}

static void test_vmm_rollback(void)
{
    struct vmm *v = kernel_vmm();
    const struct pmm *st = kframe_stats();
    uint64_t target;
    if (kframe_alloc(&target))
        panic("vmm-rollback: no frame to map");
    for (uint64_t keep = 0; keep < 3; keep++) {
        uint64_t head = drain_to(keep), tables = v->tables, rsv = st->reserved_frames;
        int rc = vmm_map(v, FRESH_VA, target, PAGE_SIZE, VMM_WRITE);
        if (rc != -BV_ENOMEM || st->free_frames != keep || v->tables != tables || st->reserved_frames != rsv ||
            vmm_query(v, FRESH_VA, NULL, NULL) != -BV_ENOENT)
            panic("vmm-rollback: map with %lu free frames left state behind (rc %d)", (unsigned long)keep, rc);
        refill(head);
    }
    if (kframe_free(target))
        panic("vmm-rollback: could not return the mapped frame");
    kprintf("[TEST] vmm-rollback: out of memory with 0, 1 and 2 frames left changed nothing\n");

    uint64_t tables = v->tables;
    if (vmm_map(v, TEST_VA + PAGE_SIZE, 0x200000, PAGE_SIZE, 0) ||
        vmm_map(v, TEST_VA, 0x300000, 3 * PAGE_SIZE, 0) != -BV_EBUSY ||
        vmm_query(v, TEST_VA, NULL, NULL) != -BV_ENOENT || vmm_unmap(v, TEST_VA, 3 * PAGE_SIZE) != -BV_ENOENT ||
        vmm_query(v, TEST_VA + PAGE_SIZE, NULL, NULL) != 0 || vmm_unmap(v, TEST_VA + PAGE_SIZE, PAGE_SIZE) ||
        v->tables != tables)
        panic("vmm-rollback: overlapping map or partial unmap left state behind");
    kprintf("[TEST] vmm-rollback: overlapping map and partial unmap refused with no change\n");
}

static const struct {
    const char *name;
    void (*run)(void);
} tests[] = {
    { "de", bv_trigger_de },   { "bp", bv_trigger_bp },     { "ud", bv_trigger_ud },
    { "gp", bv_trigger_gp },   { "pf", bv_trigger_pf },     { "df", bv_trigger_df },
    { "panic", trigger_panic }, { "nested", trigger_nested }, { "pmm-drain", test_pmm_drain },
    { "null", test_null },     { "wp-text", test_wp_text }, { "wp-rodata", test_wp_rodata },
    { "wp-bootinfo", test_wp_bootinfo }, { "nx-data", test_nx_data }, { "nx-stack", test_nx_stack },
    { "nx-ram", test_nx_ram }, { "guard-stack", test_guard_stack }, { "guard-ist", test_guard_ist },
    { "unmap-fault", test_unmap_fault }, { "vmm-rollback", test_vmm_rollback },
    { "heap-stress", selftest_heap_stress }, { "heap-exhaust", selftest_heap_exhaust },
    { "heap-nx", selftest_heap_nx }, { "heap-overrun", selftest_heap_overrun },
    { "prot-pt-write", selftest_prot_pt_write }, { "prot-new-table", selftest_prot_new_table },
    { "prot-pmm-write", selftest_prot_pmm_write }, { "prot-boot-pt", selftest_prot_boot_pt },
    { "prot-alias", selftest_prot_alias }, { "prot-checks", selftest_prot_checks },
    { "highmem", selftest_highmem }, { "reclaim", selftest_reclaim }, { "reclaim-stale", selftest_reclaim_stale },
};

static const char *find_test_arg(const char *cmdline, size_t *len)
{
    static const char key[] = "bv.test=";
    for (const char *p = cmdline; *p; p++) {
        if ((p == cmdline || p[-1] == ' ') && memcmp(p, key, sizeof key - 1) == 0) {
            const char *v = p + sizeof key - 1;
            *len = 0;
            while (v[*len] && v[*len] != ' ')
                (*len)++;
            return v;
        }
    }
    return NULL;
}

void selftest_run_from_cmdline(const char *cmdline)
{
    size_t len;
    const char *arg = cmdline ? find_test_arg(cmdline, &len) : NULL;
    if (!arg)
        return;
    test_cmdline = cmdline;
    for (size_t i = 0; i < sizeof tests / sizeof tests[0]; i++) {
        if (strlen(tests[i].name) == len && memcmp(tests[i].name, arg, len) == 0) {
            kprintf("[TEST] running fault test '%s'\n", tests[i].name);
            tests[i].run();
            kprintf("[TEST] fault test '%s' returned\n", tests[i].name);
            return;
        }
    }
    panic("unknown bv.test value on kernel command line");
}
