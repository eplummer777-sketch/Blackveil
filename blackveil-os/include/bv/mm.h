#ifndef BV_MM_H
#define BV_MM_H

#include <bv/heap.h>
#include <bv/multiboot.h>
#include <bv/pmm.h>
#include <bv/vmm.h>
#include <stddef.h>
#include <stdint.h>

/*
 * The boot trampoline identity-maps only the first 1 GiB, so everything touched before the kernel
 * page tables are live (boot data, frame records, new page tables) must lie below MM_BOOT_MAPPED.
 * The kernel tables then identity-map all managed RAM, up to MM_PHYS_MAX or the CPU's physical
 * address width, whichever is lower.
 */
#define MM_BOOT_MAPPED (1ull << 30)
#define MM_PHYS_MAX    (16ull << 30)
#define MM_LOW_RESERVED   0x100000ull

/* Parses the memory map, reserves in-use memory and self-checks. On failure writes `why` and returns < 0. */
int mm_init(const volatile struct multiboot_info *mb, char *why, size_t why_len);

int kframe_alloc(uint64_t *phys);
int kframe_alloc_below(uint64_t limit, uint64_t *phys);
struct mem_range kframe_records(void); /* the frame bitmaps, outside the kernel image */
uint64_t mm_phys_limit(void);
int kframe_free(uint64_t phys);
const struct pmm *kframe_stats(void);
int kframe_pin(uint64_t phys);
int kframe_unpin(uint64_t phys); /* -BV_EPERM for boot reservations, the records and unusable RAM */
int kframe_check(void); /* -BV_EFAULT if the frame bitmaps or counters are inconsistent */
const struct memmap *mm_memmap(void);
size_t mm_boot_data(const struct mem_range **ranges); /* loader data to keep read-only */

/* Builds and activates the kernel page tables. On failure writes `why` and returns < 0. */
int vm_init(char *why, size_t why_len);
struct vmm *kernel_vmm(void);

/*
 * Page tables and allocator metadata are mapped read-only once paging is live (CR0.WP enforces it
 * for kernel writes too). mm_write_begin/end bracket the only code allowed to change them: they
 * disable interrupts and clear CR0.WP on this CPU, and nest. No-ops until mm_write_enable().
 */
#define MM_META __attribute__((section(".bss.mm_meta")))
extern char __mm_meta_start[], __mm_meta_end[];
void mm_write_enable(void);
void mm_write_begin(void);
void mm_write_end(void);
/* Every live table, the metadata pages and the old boot tables are read-only; frame metadata consistent. */
int vm_verify_protection(char *why, size_t why_len);
const char *vm_guard_name(uint64_t addr); /* which stack a guard page belongs to, or NULL */

/* Kernel heap in its own 512 GiB slot, so it never aliases the identity map or test pages. */
#define KHEAP_BASE 0xFFFFB00000000000ull
#define KHEAP_SIZE (1ull << 30)

int kheap_init(char *why, size_t why_len);
int kheap_alloc(size_t size, size_t align, void **out); /* see heap_alloc() */
int kheap_free(void *ptr);                              /* see heap_free() */
const struct heap *kheap(void);
/* Checks heap metadata and that every heap page is rw-, no-execute and backed by an ordinary frame. */
int kheap_verify(char *why, size_t why_len);
void *kmalloc(size_t size); /* NULL on failure */
void kfree(void *ptr);      /* panics on an invalid, double or corrupted free */

static inline void *phys_to_virt(uint64_t phys)
{
    return (void *)(uintptr_t)phys;
}

#endif
