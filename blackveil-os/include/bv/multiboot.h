#ifndef BV_MULTIBOOT_H
#define BV_MULTIBOOT_H

#include <stdint.h>

#define MULTIBOOT_LOADER_MAGIC 0x2BADB002u
#define MULTIBOOT_INFO_MEMORY  (1u << 0)
#define MULTIBOOT_INFO_CMDLINE (1u << 2)
#define MULTIBOOT_INFO_MODS    (1u << 3)
#define MULTIBOOT_INFO_MMAP    (1u << 6)
#define MULTIBOOT_INFO_LOADER  (1u << 9)

/* Multiboot v1 information structure (fields used so far). */
struct multiboot_info {
    uint32_t flags;
    uint32_t mem_lower;
    uint32_t mem_upper;
    uint32_t boot_device;
    uint32_t cmdline;
    uint32_t mods_count;
    uint32_t mods_addr;
    uint32_t syms[4];
    uint32_t mmap_length;
    uint32_t mmap_addr;
    uint32_t drives_length;
    uint32_t drives_addr;
    uint32_t config_table;
    uint32_t boot_loader_name;
};

/* All fields are naturally aligned uint32_t, so no packing is needed (packing also
   triggered a GCC 14 peephole2 internal compiler error). */
_Static_assert(__builtin_offsetof(struct multiboot_info, boot_loader_name) == 64, "multiboot_info layout");

struct multiboot_module {
    uint32_t mod_start;
    uint32_t mod_end;
    uint32_t string;
    uint32_t reserved;
};

#endif
