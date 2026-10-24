/*
 * Deliberate CPU exceptions for emulator tests, selected with bv.test=<name> on the
 * kernel command line. The bv_fault_* labels mark the faulting instruction so the
 * boot tests can check the reported RIP against the symbol table.
 */
#ifndef BV_TEST_BUILD
#error "crash triggers must only be built into the test kernel"
#endif
.section .text
.code64

.global bv_trigger_de, bv_fault_de
bv_trigger_de:
    xor %eax, %eax
    xor %edx, %edx
    xor %ecx, %ecx
bv_fault_de:
    div %ecx
    ret

.global bv_trigger_bp
bv_trigger_bp:
    int3
    ret

.global bv_trigger_ud, bv_fault_ud
bv_trigger_ud:
bv_fault_ud:
    ud2
    ret

.global bv_trigger_gp, bv_fault_gp
bv_trigger_gp:
    movabs $0x8000000000000000, %rax  /* non-canonical address */
bv_fault_gp:
    mov (%rax), %rax
    ret

.global bv_trigger_pf, bv_fault_pf
bv_trigger_pf:
    movabs $0xFFFF800000000000, %rax  /* canonical but unmapped */
bv_fault_pf:
    movq $0x42, (%rax)
    ret

/* Page-permission probes: rdi = target address. */
.global bv_trigger_write, bv_fault_write
bv_trigger_write:
bv_fault_write:
    movq $0x42, (%rdi)
    ret

.global bv_trigger_read, bv_fault_read
bv_trigger_read:
bv_fault_read:
    mov (%rdi), %rax
    ret

/* Runs the current stack down into its guard page. */
.global bv_trigger_stack_overflow
bv_trigger_stack_overflow:
1:  pushq $0
    jmp 1b

/* Unmapped stack: the #PF cannot be delivered on it, so the CPU raises #DF (handled on IST1). */
.global bv_trigger_df
bv_trigger_df:
    movabs $0x0000004000000000, %rsp
    pushq $0
    ud2
