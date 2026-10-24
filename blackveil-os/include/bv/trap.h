#ifndef BV_TRAP_H
#define BV_TRAP_H

#include <stddef.h>
#include <stdint.h>

#define TRAP_EXCEPTION_COUNT 32
#define KERNEL_CS 0x08
#define KERNEL_DS 0x10
#define KERNEL_TSS 0x18

/* Interrupt stack table slots (1-based, as stored in the IDT gate). */
#define IST_DOUBLE_FAULT 1
#define IST_NMI          2
#define IST_MACHINE_CHECK 3

#define VEC_DE 0
#define VEC_NMI 2
#define VEC_BP 3
#define VEC_UD 6
#define VEC_DF 8
#define VEC_GP 13
#define VEC_PF 14
#define VEC_MC 18

/* Layout written by isr_common in arch/x86_64/isr.S, lowest address first. */
struct trap_frame {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rbp, rdi, rsi, rdx, rcx, rbx, rax;
    uint64_t vector, error_code;
    uint64_t rip, cs, rflags, rsp, ss;
};

_Static_assert(sizeof(struct trap_frame) == 22 * 8, "trap_frame must match isr.S");

const char *trap_mnemonic(uint64_t vector);
const char *trap_name(uint64_t vector);
int trap_has_error_code(uint64_t vector);
size_t trap_format_report(char *buf, size_t size, const struct trap_frame *f, uint64_t cr2, uint64_t cr3);

void cpu_tables_init(void);
int idt_selftest(char *why, size_t why_size);
uint64_t cpu_ist_guard(unsigned slot); /* address of the guard page below IST stack `slot` */
void trap_dispatch(struct trap_frame *f);

#endif
