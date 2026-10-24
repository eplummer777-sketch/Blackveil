ENTRY(_start)

/* Every boundary below is page aligned so each part can get its own page permissions. */
SECTIONS
{
    . = 1M;
    __kernel_start = .;

    .text : ALIGN(4K) {
        KEEP(*(.multiboot))
        *(.text .text.*)
    }
    . = ALIGN(4K);
    __text_end = .;

    .rodata : ALIGN(4K) { *(.rodata .rodata.*) }
    . = ALIGN(4K);
    __rodata_end = .;

    .data : ALIGN(4K) { *(.data .data.*) }
    /* Memory-manager metadata: mapped read-only, written only inside mm_write_begin/end. */
    .bss : ALIGN(4K) {
        __mm_meta_start = .;
        *(.bss.mm_meta)
        . = ALIGN(4K);
        __mm_meta_end = .;
        *(COMMON)
        *(.bss .bss.*)
    }
    . = ALIGN(4K);
    __kernel_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame .eh_frame_hdr)
    }
}
