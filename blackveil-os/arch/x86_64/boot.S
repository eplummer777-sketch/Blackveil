/*
 * Blackveil OS boot trampoline.
 * Entered in 32-bit protected mode by a Multiboot (v1) loader, builds identity
 * page tables for the first 1 GiB, enables long mode and jumps to kmain().
 */
#define MB_MAGIC     0x1BADB002
#define MB_FLAGS     0x00000003
#define DEBUG_EXIT   0xF4
#define COM1         0x3F8

.section .multiboot, "a"
.align 4
.long MB_MAGIC
.long MB_FLAGS
.long -(MB_MAGIC + MB_FLAGS)

.section .bss
.align 4096
.global boot_page_tables
boot_page_tables:
pml4:        .skip 4096
pdpt:        .skip 4096
pd:          .skip 4096
/* Left unmapped once the kernel page tables are live: an overflow faults instead of corrupting. */
.global boot_stack_guard, boot_stack_top
boot_stack_guard: .skip 4096
boot_stack:  .skip 16384
boot_stack_top:

.section .data
mb_magic:    .long 0
mb_info:     .long 0

.section .rodata
.align 16
gdt64:
    .quad 0
    .quad 0x00AF9A000000FFFF        /* 0x08: 64-bit kernel code */
    .quad 0x00CF92000000FFFF        /* 0x10: kernel data */
gdt64_end:
gdt64_ptr:
    .word gdt64_end - gdt64 - 1
    .quad gdt64
msg_no_lm:
    .asciz "BLACKVEIL_BOOT_FAIL: CPU lacks 64-bit long mode\r\n"

.section .text
.code32
.global _start
_start:
    cli
    cld
    mov $boot_stack_top, %esp
    mov %eax, mb_magic
    mov %ebx, mb_info

    /* CPUID present? (ID flag toggles) */
    pushfl
    pop %eax
    mov %eax, %ecx
    xor $0x00200000, %eax
    push %eax
    popfl
    pushfl
    pop %eax
    push %ecx
    popfl
    cmp %eax, %ecx
    je no_long_mode

    /* Extended leaf + LM bit */
    mov $0x80000000, %eax
    cpuid
    cmp $0x80000001, %eax
    jb no_long_mode
    mov $0x80000001, %eax
    cpuid
    test $(1 << 29), %edx
    jz no_long_mode

    /* PML4[0] -> PDPT, PDPT[0] -> PD, PD[i] -> 2 MiB identity pages */
    mov $pdpt, %eax
    or $0x3, %eax
    mov %eax, pml4
    mov $pd, %eax
    or $0x3, %eax
    mov %eax, pdpt
    xor %ecx, %ecx
1:  mov %ecx, %eax
    shl $21, %eax
    or $0x83, %eax                  /* present | writable | huge */
    mov %eax, pd(,%ecx,8)
    movl $0, pd+4(,%ecx,8)
    inc %ecx
    cmp $512, %ecx
    jne 1b

    mov $pml4, %eax
    mov %eax, %cr3
    mov %cr4, %eax
    or $(1 << 5), %eax              /* PAE */
    mov %eax, %cr4
    mov $0xC0000080, %ecx           /* EFER */
    rdmsr
    or $(1 << 8), %eax              /* LME */
    wrmsr
    mov %cr0, %eax
    or $0x80000001, %eax            /* PG | PE */
    mov %eax, %cr0

    lgdt gdt64_ptr
    ljmp $0x08, $long_mode_entry

no_long_mode:
    mov $msg_no_lm, %esi
2:  lodsb
    test %al, %al
    jz 3f
    mov %al, %bl
    mov $(COM1 + 5), %dx
4:  inb %dx, %al
    test $0x20, %al
    jz 4b
    mov $COM1, %dx
    mov %bl, %al
    outb %al, %dx
    jmp 2b
3:  mov $0x11, %al
    outb %al, $DEBUG_EXIT
5:  hlt
    jmp 5b

.code64
long_mode_entry:
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov %ax, %fs
    mov %ax, %gs
    mov $boot_stack_top, %rsp
    xor %rbp, %rbp
    movl mb_magic, %edi
    movl mb_info, %esi
    call kmain
6:  cli
    hlt
    jmp 6b
