#ifndef BV_SELFTEST_H
#define BV_SELFTEST_H

#ifndef BV_TEST_BUILD
#error "emulator test code must only be built into the test kernel"
#endif

void selftest_run_from_cmdline(const char *cmdline);

void selftest_heap_stress(void);
void selftest_heap_exhaust(void);
void selftest_heap_nx(void);
void selftest_heap_overrun(void);

void selftest_prot_pt_write(void);
void selftest_prot_new_table(void);
void selftest_prot_pmm_write(void);
void selftest_prot_boot_pt(void);
void selftest_prot_alias(void);
void selftest_prot_checks(void);

void selftest_highmem(void);
void selftest_reclaim(void);
void selftest_reclaim_stale(void);

#endif
