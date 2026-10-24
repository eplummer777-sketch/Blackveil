/* Kernel panic: one readable report on serial + VGA, then a controlled halt. */
#include <bv/console.h>
#include <bv/format.h>
#include <bv/io.h>
#include <bv/mm.h>
#include <bv/string.h>
#include <bv/panic.h>

#define DEBUG_EXIT_PORT 0xF4

static volatile int panic_depth;
static volatile bool inject_fault;
static char report[2048];

void system_finish(uint8_t code)
{
    outb(DEBUG_EXIT_PORT, code);
    halt_forever();
}

bool panic_in_progress(void)
{
    return panic_depth != 0;
}

/* A fault while already panicking: print a fixed string only (no formatting, no shared buffers). */
void panic_nested(void)
{
    __asm__ volatile("cli");
    if (++panic_depth > 2)
        halt_forever();
    serial_write("BLACKVEIL_PANIC_NESTED: fault while reporting a panic; halting without further output\n");
    vga_write("\nNested fault during panic. System halted.\n");
    system_finish(DEBUG_EXIT_FAIL);
}

/* Returns only for the first panic; any re-entry is diverted to panic_nested(). */
static void panic_enter(void)
{
    __asm__ volatile("cli");
    if (panic_depth != 0)
        panic_nested();
    panic_depth = 1;
}

static __attribute__((noreturn)) void panic_emit(void)
{
    vga_panic_screen();
    serial_write("\n");
    serial_write(report);
    vga_write(report);
    if (inject_fault) {
        inject_fault = false;
        __asm__ volatile("ud2");
    }
    system_finish(DEBUG_EXIT_FAIL);
}

void panic_inject_fault(void)
{
    inject_fault = true;
}

void panic_exception(const struct trap_frame *f)
{
    panic_enter();
    uint64_t cr2, cr3;
    __asm__ volatile("mov %%cr2, %0" : "=r"(cr2));
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
    size_t n = trap_format_report(report, sizeof report, f, cr2, cr3);
    const char *guard = vm_guard_name(cr2);
    if (guard && (f->vector == VEC_PF || f->vector == VEC_DF) && n < sizeof report)
        bv_snprintf(report + n, sizeof report - n, "Stack guard page hit: %s overflow (CR2=0x%016lx)\n", guard,
                    cr2);
    panic_emit();
}

void panic(const char *fmt, ...)
{
    panic_enter();
    char msg[256];
    va_list ap;
    va_start(ap, fmt);
    bv_vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    bv_snprintf(report, sizeof report,
                "BLACKVEIL_PANIC: %s\n"
                "================== Blackveil OS kernel panic ==================\n"
                "Reason    : %s\n"
                "Called from 0x%016lx\n"
                "System halted: recovery is not supported.\n"
                "===============================================================\n",
                msg, msg, (unsigned long)(uintptr_t)__builtin_return_address(0));
    panic_emit();
}
