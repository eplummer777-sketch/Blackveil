#ifndef BV_FORMAT_H
#define BV_FORMAT_H

#include <stdarg.h>
#include <stddef.h>

/*
 * Bounded formatter. Always NUL-terminates when size > 0 and never writes
 * past buf[size - 1]. Returns the number of characters written (excluding NUL).
 * Supports: %% %c %s %d %i %u %x %X %p with optional '0' flag, width, and l/ll/z.
 */
size_t bv_vsnprintf(char *buf, size_t size, const char *fmt, va_list ap);
size_t bv_snprintf(char *buf, size_t size, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

#endif
