/* Exception names and the panic report text. Pure formatting: also built and tested on the host. */
#include <bv/format.h>
#include <bv/trap.h>

static const struct {
    const char *mnemonic;
    const char *name;
} exceptions[TRAP_EXCEPTION_COUNT] = {
    { "#DE", "Divide Error" },
    { "#DB", "Debug" },
    { "NMI", "Non-Maskable Interrupt" },
    { "#BP", "Breakpoint" },
    { "#OF", "Overflow" },
    { "#BR", "Bound Range Exceeded" },
    { "#UD", "Invalid Opcode" },
    { "#NM", "Device Not Available" },
    { "#DF", "Double Fault" },
    { "CSO", "Coprocessor Segment Overrun" },
    { "#TS", "Invalid TSS" },
    { "#NP", "Segment Not Present" },
    { "#SS", "Stack-Segment Fault" },
    { "#GP", "General Protection Fault" },
    { "#PF", "Page Fault" },
    { "RSV", "Reserved" },
    { "#MF", "x87 Floating-Point Error" },
    { "#AC", "Alignment Check" },
    { "#MC", "Machine Check" },
    { "#XM", "SIMD Floating-Point Exception" },
    { "#VE", "Virtualization Exception" },
    { "#CP", "Control Protection Exception" },
    { "RSV", "Reserved" },
    { "RSV", "Reserved" },
    { "RSV", "Reserved" },
    { "RSV", "Reserved" },
    { "RSV", "Reserved" },
    { "RSV", "Reserved" },
    { "#HV", "Hypervisor Injection Exception" },
    { "#VC", "VMM Communication Exception" },
    { "#SX", "Security Exception" },
    { "RSV", "Reserved" },
};

const char *trap_mnemonic(uint64_t vector)
{
    return vector < TRAP_EXCEPTION_COUNT ? exceptions[vector].mnemonic : "INT";
}

const char *trap_name(uint64_t vector)
{
    return vector < TRAP_EXCEPTION_COUNT ? exceptions[vector].name : "Unknown Interrupt";
}

int trap_has_error_code(uint64_t vector)
{
    switch (vector) {
    case 8: case 10: case 11: case 12: case 13: case 14: case 17: case 21: case 29: case 30:
        return 1;
    default:
        return 0;
    }
}

struct out {
    char *buf;
    size_t size, len;
};

__attribute__((format(printf, 2, 3))) static void put(struct out *o, const char *fmt, ...)
{
    size_t room = o->len < o->size ? o->size - o->len : 0;
    va_list ap;
    va_start(ap, fmt);
    size_t n = bv_vsnprintf(room ? o->buf + o->len : NULL, room, fmt, ap);
    va_end(ap);
    o->len += n;
}

static void put_error_code(struct out *o, uint64_t vector, uint64_t err)
{
    put(o, "Error code: 0x%016lx", err);
    if (vector == VEC_PF) {
        put(o, " (%s, %s, %s%s%s)", (err & 1) ? "protection violation" : "not-present page",
            (err & 2) ? "write" : "read", (err & 4) ? "user" : "kernel", (err & 8) ? ", reserved bit" : "",
            (err & 16) ? ", instruction fetch" : "");
    } else if (err && vector != VEC_DF && vector != 17 && vector != 21) {
        static const char *const tables[4] = { "GDT", "IDT", "LDT", "IDT" };
        put(o, " (selector index %lu in %s%s)", (unsigned long)((err >> 3) & 0x1FFF), tables[(err >> 1) & 3],
            (err & 1) ? ", external event" : "");
    }
    put(o, "\n");
}

size_t trap_format_report(char *buf, size_t size, const struct trap_frame *f, uint64_t cr2, uint64_t cr3)
{
    struct out o = { buf, size, 0 };
    if (size)
        buf[0] = '\0';

    put(&o, "BLACKVEIL_PANIC: CPU exception %lu %s %s\n", (unsigned long)f->vector, trap_mnemonic(f->vector),
        trap_name(f->vector));
    put(&o, "================== Blackveil OS kernel panic ==================\n");
    put(&o, "Exception : %s %s (vector %lu)\n", trap_mnemonic(f->vector), trap_name(f->vector),
        (unsigned long)f->vector);
    if (trap_has_error_code(f->vector))
        put_error_code(&o, f->vector, f->error_code);
    if (f->vector == VEC_PF)
        put(&o, "Fault addr: 0x%016lx (CR2)\n", cr2);
    put(&o, "RIP=0x%016lx CS=0x%04lx RFLAGS=0x%016lx\n", f->rip, f->cs, f->rflags);
    put(&o, "RSP=0x%016lx SS=0x%04lx CR3=0x%016lx\n", f->rsp, f->ss, cr3);
    put(&o, "RAX=0x%016lx RBX=0x%016lx RCX=0x%016lx\n", f->rax, f->rbx, f->rcx);
    put(&o, "RDX=0x%016lx RSI=0x%016lx RDI=0x%016lx\n", f->rdx, f->rsi, f->rdi);
    put(&o, "RBP=0x%016lx R8 =0x%016lx R9 =0x%016lx\n", f->rbp, f->r8, f->r9);
    put(&o, "R10=0x%016lx R11=0x%016lx R12=0x%016lx\n", f->r10, f->r11, f->r12);
    put(&o, "R13=0x%016lx R14=0x%016lx R15=0x%016lx\n", f->r13, f->r14, f->r15);
    put(&o, "System halted: recovery from this exception is not supported.\n");
    put(&o, "===============================================================\n");
    return o.len;
}
