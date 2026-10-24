#include <bv/console.h>
#include <bv/panic.h>
#include <bv/trap.h>

/* Called from isr_common with interrupts disabled (interrupt gates). */
void trap_dispatch(struct trap_frame *f)
{
    if (panic_in_progress())
        panic_nested();

    /* int3 is the only exception the kernel can safely resume from: RIP already points past it. */
    if (f->vector == VEC_BP) {
        kprintf("[TRAP] #BP breakpoint at RIP=0x%016lx, resuming\n", f->rip);
        return;
    }
    panic_exception(f);
}
