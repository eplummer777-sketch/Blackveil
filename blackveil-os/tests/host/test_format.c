/* Host-side unit tests for the kernel's bounded formatter (lib/format.c). */
#include <bv/format.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures, total;

#define CHECK_FMT(expect, ...)                                                   \
    do {                                                                         \
        char b[128];                                                             \
        memset(b, 'Z', sizeof b);                                                \
        bv_snprintf(b, sizeof b, __VA_ARGS__);                                   \
        total++;                                                                 \
        if (strcmp(b, expect) != 0) {                                            \
            failures++;                                                          \
            printf("  FAIL  %s:%d got \"%s\" want \"%s\"\n", __FILE__, __LINE__, b, expect); \
        }                                                                        \
    } while (0)

int main(void)
{
    CHECK_FMT("plain", "plain");
    CHECK_FMT("42 -7 0", "%d %i %u", 42, -7, 0u);
    CHECK_FMT("-9223372036854775808", "%lld", (long long)INT64_MIN);
    CHECK_FMT("18446744073709551615", "%llu", (unsigned long long)UINT64_MAX);
    CHECK_FMT("ff FF 00ff", "%x %X %04x", 255u, 255u, 255u);
    CHECK_FMT("0x00000000000b8000", "%p", (void *)0xB8000);
    CHECK_FMT("[   ab]", "[%5s]", "ab");
    CHECK_FMT("(null)", "%s", (char *)NULL);
    CHECK_FMT("-005", "%04d", -5);
    CHECK_FMT("100%", "100%%");
    CHECK_FMT("c=Q", "c=%c", 'Q');
    CHECK_FMT("%q", "%q");

    /* Truncation: never writes past the buffer and always terminates. */
    char small[6];
    memset(small, 'Z', sizeof small);
    size_t n = bv_snprintf(small, sizeof small, "abcdefghij");
    total++;
    if (n != 5 || strcmp(small, "abcde") != 0) {
        failures++;
        printf("  FAIL  truncation got \"%s\" (%zu)\n", small, n);
    }

    char guard[4] = { 'A', 'B', 'C', 'D' };
    bv_snprintf(guard, 0, "xyz");
    total++;
    if (guard[0] != 'A') {
        failures++;
        printf("  FAIL  size 0 wrote to buffer\n");
    }

    /* Oversized width is clamped instead of overflowing. */
    char wide[200];
    n = bv_snprintf(wide, sizeof wide, "%999999999d", 1);
    total++;
    if (n != 64) {
        failures++;
        printf("  FAIL  width clamp got length %zu\n", n);
    }

    printf("host format tests: %d passed, %d failed\n", total - failures, failures);
    return failures ? 1 : 0;
}
