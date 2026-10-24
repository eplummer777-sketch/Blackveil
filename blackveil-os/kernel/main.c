#include <bv/console.h>
#include <bv/io.h>
#include <bv/mm.h>
#include <bv/multiboot.h>
#include <bv/panic.h>
#include <bv/trap.h>
#include <stdint.h>

#ifdef BV_TEST_BUILD
#include <bv/selftest.h>
#define BV_BUILD "test (emulator test hooks compiled in)"
#else
#define BV_BUILD "release (no test hooks)"
#endif

#define BV_VERSION "0.3.0-m3.5"
#define EFER_MSR 0xC0000080u
#define EFER_LMA (1u << 10)

extern char __kernel_start[], __kernel_end[];

static __attribute__((noreturn)) void boot_fail(const char *why)
{
    kprintf("BLACKVEIL_BOOT_FAIL: %s\n", why);
    system_finish(DEBUG_EXIT_FAIL);
}

void kmain(uint32_t magic, uint32_t info_addr)
{
    serial_init();
    vga_init();

    kprintf("\n=== Blackveil OS %s (x86_64) ===\n", BV_VERSION);
    kprintf("[ OK ] Build: %s\n", BV_BUILD);

    cpu_tables_init();
    char why[96];
    if (idt_selftest(why, sizeof why) != 0)
        boot_fail(why);
    kprintf("[ OK ] Exception handlers: %d vectors installed, #DF/NMI/#MC on separate stacks\n",
            TRAP_EXCEPTION_COUNT);

    if (magic != MULTIBOOT_LOADER_MAGIC)
        boot_fail("kernel was not started by a Multiboot loader");
    /* volatile: GCC 14 -O2 ICEs (peephole2) when it merges the adjacent loads of this struct. */
    const volatile struct multiboot_info *mb = (const volatile struct multiboot_info *)(uintptr_t)info_addr;
    kprintf("[ OK ] Multiboot handoff (info at %p, flags %x)\n", (const void *)(uintptr_t)info_addr, mb->flags);
    if (mb->flags & MULTIBOOT_INFO_LOADER)
        kprintf("[ OK ] Loaded by: %s\n", (const char *)(uintptr_t)mb->boot_loader_name);

    uint64_t efer = rdmsr(EFER_MSR);
    if (!(efer & EFER_LMA))
        boot_fail("long mode is not active");
    kprintf("[ OK ] 64-bit long mode active (EFER=%lx, CR0=%lx, CR4=%lx)\n", efer, read_cr0(), read_cr4());

    uint32_t max_leaf;
    union {
        uint32_t reg[4];
        char text[16];
    } vendor = { { 0 } };
    cpuid(0, &max_leaf, &vendor.reg[0], &vendor.reg[2], &vendor.reg[1]);
    kprintf("[ OK ] CPU vendor: %s (max leaf %u)\n", vendor.text, max_leaf);

    if (mb->flags & MULTIBOOT_INFO_MEMORY)
        kprintf("[ OK ] Memory: %u KiB low, %u KiB high\n", mb->mem_lower, mb->mem_upper);
    kprintf("[ OK ] Kernel image %p - %p (%lu bytes)\n", (void *)__kernel_start, (void *)__kernel_end,
            (unsigned long)((uintptr_t)__kernel_end - (uintptr_t)__kernel_start));
    kprintf("[ OK ] Serial console: %s\n", serial_ready() ? "COM1 ready" : "not detected");

    if (mm_init(mb, why, sizeof why) != 0)
        boot_fail(why);
    if (vm_init(why, sizeof why) != 0)
        boot_fail(why);
    if (kheap_init(why, sizeof why) != 0)
        boot_fail(why);

#ifdef BV_TEST_BUILD
    if (mb->flags & MULTIBOOT_INFO_CMDLINE)
        selftest_run_from_cmdline((const char *)(uintptr_t)mb->cmdline);
#endif

    kprintf("BLACKVEIL_BOOT_OK\n");
    system_finish(DEBUG_EXIT_OK);
}
