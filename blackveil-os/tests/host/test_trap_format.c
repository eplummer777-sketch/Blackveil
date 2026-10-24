/* Host-side unit tests for exception names and the panic report (kernel/trap_format.c). */
#include <bv/trap.h>
#include <stdio.h>
#include <string.h>

static int failures, total;

static void check(int cond, const char *what)
{
    total++;
    if (!cond) {
        failures++;
        printf("  FAIL  %s\n", what);
    }
}

static int contains(const char *hay, const char *needle)
{
    return strstr(hay, needle) != NULL;
}

static struct trap_frame sample(uint64_t vector, uint64_t err)
{
    struct trap_frame f;
    memset(&f, 0, sizeof f);
    f.vector = vector;
    f.error_code = err;
    f.rip = 0x10012e;
    f.cs = 0x08;
    f.ss = 0x10;
    f.rflags = 0x10006;
    f.rsp = 0x10bf38;
    f.rax = 0xdeadbeef;
    f.r15 = 0x1515;
    return f;
}

int main(void)
{
    char buf[2048];

    check(strcmp(trap_mnemonic(0), "#DE") == 0, "vector 0 is #DE");
    check(strcmp(trap_mnemonic(14), "#PF") == 0, "vector 14 is #PF");
    check(strcmp(trap_name(8), "Double Fault") == 0, "vector 8 is Double Fault");
    check(strcmp(trap_name(31), "Reserved") == 0, "vector 31 is Reserved");
    check(strcmp(trap_name(200), "Unknown Interrupt") == 0, "out-of-range vector is Unknown");

    static const int with_err[] = { 8, 10, 11, 12, 13, 14, 17, 21, 29, 30 };
    int n_err = 0;
    for (int v = 0; v < 32; v++)
        n_err += trap_has_error_code((uint64_t)v);
    check(n_err == 10, "exactly 10 exceptions push an error code");
    for (size_t i = 0; i < sizeof with_err / sizeof with_err[0]; i++)
        check(trap_has_error_code((uint64_t)with_err[i]), "error-code vector flagged");

    struct trap_frame f = sample(6, 0);
    size_t len = trap_format_report(buf, sizeof buf, &f, 0, 0x105000);
    check(len == strlen(buf), "returned length matches text");
    check(strncmp(buf, "BLACKVEIL_PANIC: CPU exception 6 #UD Invalid Opcode\n", 52) == 0, "#UD headline");
    check(contains(buf, "RIP=0x000000000010012e CS=0x0008"), "RIP and CS printed");
    check(contains(buf, "CR3=0x0000000000105000"), "CR3 printed");
    check(contains(buf, "RAX=0x00000000deadbeef"), "RAX printed");
    check(contains(buf, "R15=0x0000000000001515"), "R15 printed");
    check(!contains(buf, "Error code"), "#UD has no error code line");
    check(!contains(buf, "CR2"), "#UD has no fault address line");
    check(contains(buf, "System halted"), "halt notice printed");

    f = sample(14, 0x2);
    trap_format_report(buf, sizeof buf, &f, 0xffff800000000000ull, 0);
    check(contains(buf, "Error code: 0x0000000000000002 (not-present page, write, kernel)"), "#PF error decoded");
    check(contains(buf, "Fault addr: 0xffff800000000000 (CR2)"), "#PF CR2 printed");

    f = sample(14, 0x1D);
    trap_format_report(buf, sizeof buf, &f, 0, 0);
    check(contains(buf, "(protection violation, read, user, reserved bit, instruction fetch)"), "#PF all flags");

    f = sample(13, 0x0B);
    trap_format_report(buf, sizeof buf, &f, 0, 0);
    check(contains(buf, "(selector index 1 in IDT, external event)"), "#GP selector decoded");

    f = sample(13, 0);
    trap_format_report(buf, sizeof buf, &f, 0, 0);
    check(contains(buf, "Error code: 0x0000000000000000\n"), "#GP zero error code plain");

    f = sample(8, 0);
    trap_format_report(buf, sizeof buf, &f, 0, 0);
    check(contains(buf, "CPU exception 8 #DF Double Fault"), "#DF headline");

    /* Truncation: small buffers stay terminated and are never overrun. */
    char small[40];
    memset(small, 'Z', sizeof small);
    len = trap_format_report(small, 32, &f, 0, 0);
    check(len == 31 && small[31] == '\0' && small[32] == 'Z', "report truncates safely at 32 bytes");
    small[0] = 'Z';
    len = trap_format_report(small, 0, &f, 0, 0);
    check(len == 0 && small[0] == 'Z', "size 0 writes nothing");

    printf("host trap-format tests: %d passed, %d failed\n", total - failures, failures);
    return failures ? 1 : 0;
}
