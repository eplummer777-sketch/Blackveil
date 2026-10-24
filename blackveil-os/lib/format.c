#include <bv/format.h>
#include <stdbool.h>
#include <stdint.h>

#define MAX_WIDTH 64

struct out {
    char *buf;
    size_t size;
    size_t len;
};

static void put(struct out *o, char c)
{
    if (o->size && o->len < o->size - 1)
        o->buf[o->len++] = c;
}

static void put_num(struct out *o, uint64_t v, unsigned base, bool upper, bool neg, int width, char pad)
{
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    char tmp[24];
    int n = 0;
    do {
        tmp[n++] = digits[v % base];
        v /= base;
    } while (v);

    int total = n + (neg ? 1 : 0);
    if (neg && pad == '0')
        put(o, '-');
    for (; total < width; total++)
        put(o, pad);
    if (neg && pad != '0')
        put(o, '-');
    while (n)
        put(o, tmp[--n]);
}

size_t bv_vsnprintf(char *buf, size_t size, const char *fmt, va_list ap)
{
    struct out o = { buf, size, 0 };

    for (const char *p = fmt; p && *p; p++) {
        if (*p != '%') {
            put(&o, *p);
            continue;
        }
        p++;
        char pad = ' ';
        if (*p == '0') {
            pad = '0';
            p++;
        }
        int width = 0;
        while (*p >= '0' && *p <= '9') {
            if (width < MAX_WIDTH)
                width = width * 10 + (*p - '0');
            p++;
        }
        if (width > MAX_WIDTH)
            width = MAX_WIDTH;
        int longs = 0;
        while (*p == 'l' || *p == 'z') {
            longs++;
            p++;
        }

        switch (*p) {
        case '%':
            put(&o, '%');
            break;
        case 'c':
            put(&o, (char)va_arg(ap, int));
            break;
        case 's': {
            const char *s = va_arg(ap, const char *);
            if (!s)
                s = "(null)";
            int len = 0;
            while (s[len] && len < 4096)
                len++;
            for (int i = len; i < width; i++)
                put(&o, ' ');
            for (int i = 0; i < len; i++)
                put(&o, s[i]);
            break;
        }
        case 'd':
        case 'i': {
            int64_t x = longs ? va_arg(ap, long long) : va_arg(ap, int);
            uint64_t mag = x < 0 ? (uint64_t)(-(x + 1)) + 1 : (uint64_t)x;
            put_num(&o, mag, 10, false, x < 0, width, pad);
            break;
        }
        case 'u':
        case 'x':
        case 'X': {
            uint64_t x = longs ? va_arg(ap, unsigned long long) : va_arg(ap, unsigned int);
            put_num(&o, x, *p == 'u' ? 10 : 16, *p == 'X', false, width, pad);
            break;
        }
        case 'p':
            put(&o, '0');
            put(&o, 'x');
            put_num(&o, (uint64_t)(uintptr_t)va_arg(ap, void *), 16, false, false, 16, '0');
            break;
        case '\0':
            p--;
            break;
        default:
            put(&o, '%');
            put(&o, *p);
            break;
        }
    }

    if (size)
        buf[o.len] = '\0';
    return o.len;
}

size_t bv_snprintf(char *buf, size_t size, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    size_t n = bv_vsnprintf(buf, size, fmt, ap);
    va_end(ap);
    return n;
}
