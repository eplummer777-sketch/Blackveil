# Blackveil OS build. Run `make help` for targets.
KCC     ?= gcc
LD      ?= ld
OBJCOPY ?= objcopy
HOSTCC  ?= gcc

BUILD   := build
# Two kernels from one tree, each with its own object directory:
#   release - no test dispatcher, crash triggers or emulator self-tests; ignores bv.test=
#   test    - everything, built with -DBV_TEST_BUILD; used by `make test`
REL     := $(BUILD)/release
TST     := $(BUILD)/test
IMAGE   ?= release

CFLAGS := -std=c11 -O2 -g -Wall -Wextra -Werror -Iinclude \
	-ffreestanding -fno-builtin -fno-stack-protector -fno-stack-clash-protection \
	-fcf-protection=none -fno-pic -fno-pie -mno-red-zone -mgeneral-regs-only \
	-mno-mmx -mno-sse -mno-sse2 -mcmodel=small -fno-asynchronous-unwind-tables \
	-fno-tree-loop-distribute-patterns
ASFLAGS := -m64 -Iinclude -Wa,--noexecstack
LDFLAGS := -m elf_x86_64 -nostdlib -static -z max-page-size=0x1000 -z noexecstack \
	--build-id=none -T arch/x86_64/linker.ld
TESTDEF := -DBV_TEST_BUILD

SRCS      := $(wildcard arch/x86_64/*.S arch/x86_64/*.c) $(wildcard kernel/*.c drivers/*.c lib/*.c mm/*.c)
TEST_SRCS := arch/x86_64/fault_triggers.S kernel/selftest.c $(wildcard kernel/*_selftest.c)
CORE_SRCS := $(filter-out $(TEST_SRCS),$(SRCS))
REL_OBJS  := $(patsubst %,$(REL)/%.o,$(CORE_SRCS))
TST_OBJS  := $(patsubst %,$(TST)/%.o,$(CORE_SRCS) $(TEST_SRCS))

QEMU_BASE := -kernel $(BUILD)/$(IMAGE)/blackveil-mb32.elf -m 128M -no-reboot

# Per-binary limit for host tests; a hang is reported and fails the run.
HOST_TIMEOUT ?= 120
define host_run
@ASAN_OPTIONS=verify_asan_link_order=0 timeout -k 5 $(HOST_TIMEOUT) $(BUILD)/host/$(1); rc=$$?; \
	if [ $$rc -eq 124 ] || [ $$rc -eq 137 ]; then echo "host $(1): TIMED OUT after $(HOST_TIMEOUT) s (failure)"; fi; \
	exit $$rc
endef

.PHONY: all release test-kernel help run run-headless test host-test boot-test check-tools clean

all: release test-kernel
release: $(REL)/blackveil-mb32.elf
test-kernel: $(TST)/blackveil-mb32.elf

help:
	@echo "make              build both kernels: $(REL)/ and $(TST)/ (blackveil.elf + bootable blackveil-mb32.elf)"
	@echo "make release      build only the release kernel (no test hooks)"
	@echo "make test-kernel  build only the test kernel (bv.test= hooks)"
	@echo "make run          boot in QEMU with a VGA window; serial on this terminal (IMAGE=release|test)"
	@echo "make run-headless boot in QEMU without a window (serial only) (IMAGE=release|test)"
	@echo "make test         host unit tests + automated emulator boot tests (both kernels)"
	@echo "make check-tools  show which build tools were found"
	@echo "make clean        delete build output"

$(REL)/%.c.o: %.c
	@mkdir -p $(dir $@)
	$(KCC) $(CFLAGS) -MMD -MP -c $< -o $@

$(REL)/%.S.o: %.S
	@mkdir -p $(dir $@)
	$(KCC) $(ASFLAGS) -MMD -MP -c $< -o $@

$(TST)/%.c.o: %.c
	@mkdir -p $(dir $@)
	$(KCC) $(CFLAGS) $(TESTDEF) -MMD -MP -c $< -o $@

$(TST)/%.S.o: %.S
	@mkdir -p $(dir $@)
	$(KCC) $(ASFLAGS) $(TESTDEF) -MMD -MP -c $< -o $@

$(REL)/blackveil.elf: $(REL_OBJS) arch/x86_64/linker.ld
	$(LD) $(LDFLAGS) $(REL_OBJS) -o $@

$(TST)/blackveil.elf: $(TST_OBJS) arch/x86_64/linker.ld
	$(LD) $(LDFLAGS) $(TST_OBJS) -o $@

# QEMU's built-in Multiboot loader only accepts 32-bit ELF images; the 32-bit
# trampoline in boot.S switches the CPU to 64-bit mode itself.
$(BUILD)/%/blackveil-mb32.elf: $(BUILD)/%/blackveil.elf
	$(OBJCOPY) -O elf32-i386 $< $@

run: $(BUILD)/$(IMAGE)/blackveil-mb32.elf
	sh scripts/qemu.sh $(QEMU_BASE) -serial stdio

run-headless: $(BUILD)/$(IMAGE)/blackveil-mb32.elf
	sh scripts/qemu.sh $(QEMU_BASE) -display none -serial stdio

host-test:
	@mkdir -p $(BUILD)/host
	$(HOSTCC) -std=c11 -Wall -Wextra -Werror -Wno-format -Iinclude -fsanitize=address,undefined \
		tests/host/test_format.c lib/format.c -o $(BUILD)/host/test_format
	$(HOSTCC) -std=c11 -Wall -Wextra -Werror -Wno-format -Iinclude -fsanitize=address,undefined \
		tests/host/test_trap_format.c kernel/trap_format.c lib/format.c -o $(BUILD)/host/test_trap_format
	$(HOSTCC) -std=c11 -Wall -Wextra -Werror -Iinclude -fsanitize=address,undefined \
		tests/host/test_memmap.c mm/memmap.c -o $(BUILD)/host/test_memmap
	$(HOSTCC) -std=c11 -Wall -Wextra -Werror -Iinclude -fsanitize=address,undefined \
		tests/host/test_pmm.c mm/pmm.c mm/memmap.c -o $(BUILD)/host/test_pmm
	$(HOSTCC) -std=c11 -Wall -Wextra -Werror -Iinclude -fsanitize=address,undefined \
		tests/host/test_vmm.c mm/vmm.c -o $(BUILD)/host/test_vmm
	$(HOSTCC) -std=c11 -Wall -Wextra -Werror -Iinclude -fsanitize=address,undefined \
		tests/host/test_heap.c mm/heap.c -o $(BUILD)/host/test_heap
	$(call host_run,test_format)
	$(call host_run,test_trap_format)
	$(call host_run,test_memmap)
	$(call host_run,test_pmm)
	$(call host_run,test_vmm)
	$(call host_run,test_heap)

boot-test: $(TST)/blackveil-mb32.elf $(REL)/blackveil-mb32.elf
	sh tests/boot-test.sh $(TST)/blackveil-mb32.elf $(TST)/blackveil.elf \
		$(REL)/blackveil-mb32.elf $(REL)/blackveil.elf

test: host-test boot-test

check-tools:
	@for t in $(KCC) $(LD) $(OBJCOPY) nm strings python3; do printf '%-12s ' $$t; command -v $$t || echo MISSING; done
	@printf '%-12s ' qemu; sh scripts/qemu.sh --version | head -1 || echo MISSING

clean:
	rm -rf $(BUILD)

-include $(REL_OBJS:.o=.d) $(TST_OBJS:.o=.d)
