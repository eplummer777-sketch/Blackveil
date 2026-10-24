/* Shared helpers for host-side unit tests. */
#ifndef BV_TEST_CHECK_H
#define BV_TEST_CHECK_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures, total;

#define CHECK(cond)                                                     \
    do {                                                                \
        total++;                                                        \
        if (!(cond)) {                                                  \
            failures++;                                                 \
            printf("  FAIL  %s:%d  %s\n", __FILE__, __LINE__, #cond);   \
        }                                                               \
    } while (0)

#define CHECK_EQ(got, want)                                                                     \
    do {                                                                                        \
        unsigned long long g_ = (unsigned long long)(got), w_ = (unsigned long long)(want);    \
        total++;                                                                                \
        if (g_ != w_) {                                                                         \
            failures++;                                                                         \
            printf("  FAIL  %s:%d  %s = %#llx, want %#llx\n", __FILE__, __LINE__, #got, g_, w_); \
        }                                                                                       \
    } while (0)

static int report(const char *suite)
{
    printf("host %s tests: %d passed, %d failed\n", suite, total - failures, failures);
    return failures ? 1 : 0;
}

/* Builds Multiboot v1 memory-map entries (size field + 20-byte body) into a byte buffer. */
struct mbmap {
    uint8_t buf[4096];
    uint32_t len;
};

__attribute__((unused)) static void mbmap_add_sized(struct mbmap *m, uint32_t size, uint64_t base, uint64_t len, uint32_t type)
{
    memcpy(m->buf + m->len, &size, 4);
    memcpy(m->buf + m->len + 4, &base, 8);
    memcpy(m->buf + m->len + 12, &len, 8);
    memcpy(m->buf + m->len + 20, &type, 4);
    m->len += 4 + size;
}

__attribute__((unused)) static void mbmap_add(struct mbmap *m, uint64_t base, uint64_t len, uint32_t type)
{
    mbmap_add_sized(m, 20, base, len, type);
}

/* The map QEMU reports for -m 128M. */
__attribute__((unused)) static void mbmap_qemu_128m(struct mbmap *m)
{
    mbmap_add(m, 0x0, 0x9fc00, 1);
    mbmap_add(m, 0x9fc00, 0x400, 2);
    mbmap_add(m, 0xf0000, 0x10000, 2);
    mbmap_add(m, 0x100000, 0x7ee0000, 1);
    mbmap_add(m, 0x7fe0000, 0x20000, 2);
    mbmap_add(m, 0xfffc0000, 0x40000, 2);
}

#endif
