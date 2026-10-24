#ifndef BV_PANIC_H
#define BV_PANIC_H

#include <bv/trap.h>
#include <stdbool.h>
#include <stdint.h>

#define DEBUG_EXIT_OK   0x10 /* QEMU exit status (0x10 << 1) | 1 = 33 */
#define DEBUG_EXIT_FAIL 0x11 /* QEMU exit status 35 */

/* Signals the emulator (isa-debug-exit, harmless without it) and halts. */
__attribute__((noreturn)) void system_finish(uint8_t code);

__attribute__((noreturn, format(printf, 1, 2))) void panic(const char *fmt, ...);
__attribute__((noreturn)) void panic_exception(const struct trap_frame *f);
bool panic_in_progress(void);
__attribute__((noreturn)) void panic_nested(void);

/* Test hook: makes the next panic fault while reporting, to exercise the nested-fault guard. */
void panic_inject_fault(void);

#endif
