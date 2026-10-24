/* GDT with a TSS (for interrupt stack table entries) and the IDT for CPU exceptions. */
#include <bv/format.h>
#include <bv/trap.h>
#include <stdint.h>

#define IST_STACK_SIZE 8192
#define GATE_INTERRUPT_PRESENT 0x8E /* present, DPL 0, 64-bit interrupt gate */

struct idt_gate {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t ist;
    uint8_t type_attr;
    uint16_t offset_mid;
    uint32_t offset_high;
    uint32_t reserved;
};
_Static_assert(sizeof(struct idt_gate) == 16, "IDT gate size");

struct tss64 {
    uint32_t reserved0;
    uint32_t rsp[6];   /* rsp0..rsp2 as 32-bit halves: keeps every member naturally aligned */
    uint32_t reserved1[2];
    uint32_t ist[14];  /* ist1..ist7 as low/high halves */
    uint32_t reserved2[2];
    uint16_t reserved3;
    uint16_t iomap_base;
};
_Static_assert(sizeof(struct tss64) == 104, "TSS size");

struct __attribute__((packed)) table_ptr {
    uint16_t limit;
    uint64_t base;
};

extern const uint64_t isr_stub_table[TRAP_EXCEPTION_COUNT];

static struct idt_gate idt[256] __attribute__((aligned(16)));
static struct tss64 tss __attribute__((aligned(16)));
static uint64_t gdt[5] __attribute__((aligned(16)));
/* The guard page below each stack is unmapped by the paging code, so an overflow faults. */
static struct {
    uint8_t guard[4096];
    uint8_t stack[IST_STACK_SIZE];
} ist_stacks[3] __attribute__((aligned(4096)));

uint64_t cpu_ist_guard(unsigned slot)
{
    return (uint64_t)(uintptr_t)ist_stacks[slot - 1].guard;
}

static uint8_t expected_ist(unsigned vector)
{
    switch (vector) {
    case VEC_DF: return IST_DOUBLE_FAULT;
    case VEC_NMI: return IST_NMI;
    case VEC_MC: return IST_MACHINE_CHECK;
    default: return 0;
    }
}

static void set_ist(unsigned slot, void *top)
{
    uint64_t v = (uint64_t)(uintptr_t)top;
    tss.ist[(slot - 1) * 2] = (uint32_t)v;
    tss.ist[(slot - 1) * 2 + 1] = (uint32_t)(v >> 32);
}

static void load_gdt_tss(void)
{
    uint64_t base = (uint64_t)(uintptr_t)&tss;
    uint64_t limit = sizeof tss - 1;

    gdt[0] = 0;
    gdt[1] = 0x00AF9A000000FFFFull; /* 0x08 kernel code, same as boot.S */
    gdt[2] = 0x00CF92000000FFFFull; /* 0x10 kernel data */
    gdt[3] = (limit & 0xFFFF) | ((base & 0xFFFFFF) << 16) | (0x89ull << 40) /* available 64-bit TSS */
             | (((limit >> 16) & 0xF) << 48) | (((base >> 24) & 0xFF) << 56);
    gdt[4] = base >> 32;

    struct table_ptr p = { sizeof gdt - 1, (uint64_t)(uintptr_t)gdt };
    __asm__ volatile(
        "lgdt %0\n\t"
        "pushq %1\n\t"
        "leaq 1f(%%rip), %%rax\n\t"
        "pushq %%rax\n\t"
        "lretq\n"
        "1:\n\t"
        "movw %w2, %%ax\n\t"
        "movw %%ax, %%ds\n\t"
        "movw %%ax, %%es\n\t"
        "movw %%ax, %%ss\n\t"
        "movw %%ax, %%fs\n\t"
        "movw %%ax, %%gs\n\t"
        "ltr %w3"
        :
        : "m"(p), "i"(KERNEL_CS), "r"(KERNEL_DS), "r"(KERNEL_TSS)
        : "rax", "memory");
}

void cpu_tables_init(void)
{
    tss.iomap_base = sizeof tss; /* no I/O permission bitmap */
    for (unsigned slot = 1; slot <= 3; slot++)
        set_ist(slot, ist_stacks[slot - 1].stack + IST_STACK_SIZE);
    load_gdt_tss();

    for (unsigned v = 0; v < TRAP_EXCEPTION_COUNT; v++) {
        uint64_t h = isr_stub_table[v];
        idt[v] = (struct idt_gate){
            .offset_low = (uint16_t)h,
            .selector = KERNEL_CS,
            .ist = expected_ist(v),
            .type_attr = GATE_INTERRUPT_PRESENT,
            .offset_mid = (uint16_t)(h >> 16),
            .offset_high = (uint32_t)(h >> 32),
        };
    }
    struct table_ptr p = { sizeof idt - 1, (uint64_t)(uintptr_t)idt };
    __asm__ volatile("lidt %0" : : "m"(p) : "memory");
}

/* Reads the live CPU state back and checks every exception gate. Returns 0 when all is correct. */
int idt_selftest(char *why, size_t why_size)
{
    struct table_ptr p;
    uint16_t tr;
    __asm__ volatile("sidt %0" : "=m"(p));
    __asm__ volatile("str %0" : "=r"(tr));

    if (p.base != (uint64_t)(uintptr_t)idt || p.limit != sizeof idt - 1) {
        bv_snprintf(why, why_size, "IDTR does not point at the kernel IDT");
        return -1;
    }
    if (tr != KERNEL_TSS) {
        bv_snprintf(why, why_size, "task register is %x, expected %x", tr, KERNEL_TSS);
        return -1;
    }
    for (unsigned v = 0; v < TRAP_EXCEPTION_COUNT; v++) {
        const struct idt_gate *g = &idt[v];
        uint64_t h = g->offset_low | ((uint64_t)g->offset_mid << 16) | ((uint64_t)g->offset_high << 32);
        if (h != isr_stub_table[v] || g->selector != KERNEL_CS || g->type_attr != GATE_INTERRUPT_PRESENT ||
            g->ist != expected_ist(v)) {
            bv_snprintf(why, why_size, "gate %u is not installed correctly", v);
            return -1;
        }
    }
    for (unsigned v = TRAP_EXCEPTION_COUNT; v < 256; v++) {
        if (idt[v].type_attr & 0x80) {
            bv_snprintf(why, why_size, "unexpected gate %u is present", v);
            return -1;
        }
    }
    return 0;
}
