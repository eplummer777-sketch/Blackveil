#include <bv/console.h>
#include <stdint.h>

#define VGA_COLS 80
#define VGA_ROWS 25
#define VGA_ATTR       0x0B /* cyan on black */
#define VGA_PANIC_ATTR 0x4F /* bright white on red */

static volatile uint16_t *const vga = (volatile uint16_t *)0xB8000;
static int row, col;
static uint8_t attr = VGA_ATTR;

static void vga_scroll(void)
{
    for (int i = 0; i < VGA_COLS * (VGA_ROWS - 1); i++)
        vga[i] = vga[i + VGA_COLS];
    for (int i = VGA_COLS * (VGA_ROWS - 1); i < VGA_COLS * VGA_ROWS; i++)
        vga[i] = (uint16_t)(attr << 8) | ' ';
    row = VGA_ROWS - 1;
}

static void vga_clear(uint8_t new_attr)
{
    attr = new_attr;
    for (int i = 0; i < VGA_COLS * VGA_ROWS; i++)
        vga[i] = (uint16_t)(attr << 8) | ' ';
    row = col = 0;
}

void vga_init(void)
{
    vga_clear(VGA_ATTR);
}

void vga_panic_screen(void)
{
    vga_clear(VGA_PANIC_ATTR);
}

void vga_write(const char *s)
{
    for (; *s; s++) {
        if (*s == '\n') {
            col = 0;
            row++;
        } else {
            vga[row * VGA_COLS + col] = (uint16_t)(attr << 8) | (uint8_t)*s;
            if (++col == VGA_COLS) {
                col = 0;
                row++;
            }
        }
        if (row == VGA_ROWS)
            vga_scroll();
    }
}
