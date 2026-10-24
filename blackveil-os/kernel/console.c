#include <bv/console.h>
#include <bv/format.h>

void kprintf(const char *fmt, ...)
{
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    bv_vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    serial_write(line);
    vga_write(line);
}
