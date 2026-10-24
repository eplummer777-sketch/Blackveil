#ifndef BV_CONSOLE_H
#define BV_CONSOLE_H

#include <stdbool.h>

void serial_init(void);
bool serial_ready(void);
void serial_write(const char *s);

void vga_init(void);
void vga_write(const char *s);
void vga_panic_screen(void);

void kprintf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#endif
