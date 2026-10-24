#include <bv/console.h>
#include <bv/io.h>

#define COM1 0x3F8
#define LSR_TX_EMPTY 0x20

static bool present;

void serial_init(void)
{
    outb(COM1 + 1, 0x00); /* disable interrupts */
    outb(COM1 + 3, 0x80); /* DLAB on */
    outb(COM1 + 0, 0x03); /* 38400 baud */
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03); /* 8N1 */
    outb(COM1 + 2, 0xC7); /* FIFO on, cleared, 14-byte threshold */
    outb(COM1 + 4, 0x1E); /* loopback for self-test */
    outb(COM1 + 0, 0xAE);
    present = inb(COM1 + 0) == 0xAE;
    outb(COM1 + 4, 0x0F); /* normal operation */
}

bool serial_ready(void)
{
    return present;
}

static void serial_putc(char c)
{
    for (int spins = 0; spins < 100000 && !(inb(COM1 + 5) & LSR_TX_EMPTY); spins++)
        ;
    outb(COM1, (uint8_t)c);
}

void serial_write(const char *s)
{
    if (!present)
        return;
    for (; *s; s++) {
        if (*s == '\n')
            serial_putc('\r');
        serial_putc(*s);
    }
}
