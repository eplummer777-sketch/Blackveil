/* Controlled write window for read-only memory-manager metadata (single CPU). */
#include <bv/io.h>
#include <bv/mm.h>

#define CR0_WP  (1ull << 16)
#define RFLAGS_IF 0x200ull

static MM_META struct {
    bool live;
    unsigned depth;
    uint64_t rflags;
} win;

void mm_write_enable(void)
{
    win.live = true;
}

void mm_write_begin(void)
{
    if (!win.live)
        return;
    uint64_t rflags;
    __asm__ volatile("pushfq; popq %0; cli" : "=r"(rflags) : : "memory");
    uint64_t cr0 = read_cr0();
    /* WP set means no window is open; the window state itself is only writable once WP is clear. */
    if (cr0 & CR0_WP) {
        write_cr0(cr0 & ~CR0_WP);
        win.depth = 0;
        win.rflags = rflags;
    }
    win.depth++;
}

void mm_write_end(void)
{
    if (!win.live || --win.depth)
        return;
    bool irq = win.rflags & RFLAGS_IF;
    write_cr0(read_cr0() | CR0_WP);
    if (irq)
        __asm__ volatile("sti" : : : "memory");
}
