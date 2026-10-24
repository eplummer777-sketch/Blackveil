# Troubleshooting

**`qemu-system-x86_64: not found`** – install QEMU, set `QEMU=/path/to/qemu-system-x86_64`, or run
`./scripts/fetch-qemu.sh` (no root needed; Debian/Ubuntu apt sources required).

**QEMU: "Cannot load x86-64 image, give a 32bit one"** – you passed `build/<release|test>/blackveil.elf`.
Boot `blackveil-mb32.elf` from the same directory.

**`bv.test=` does nothing** - you booted the release kernel, which has no test hooks. Use
`build/test/blackveil-mb32.elf` (`make run IMAGE=test`).

**QEMU: "could not load PC BIOS"** with the fetched QEMU – use `scripts/qemu.sh`, which adds the
`-L` firmware paths and `LD_LIBRARY_PATH`.

**Exit status 35 / `BLACKVEIL_BOOT_FAIL: CPU lacks 64-bit long mode`** – the emulated CPU is 32-bit.
Use the default CPU or `-cpu qemu64`.

**Exit status 1 or 0 instead of 33** – the `isa-debug-exit` device was not attached, or the kernel
hung/triple-faulted. Add `-d int,cpu_reset -no-reboot` to see why.

**GCC 14 internal compiler error in `change_address_1` (peephole2)** – seen when `kmain` read
adjacent Multiboot info fields at `-O2`. The info structure is read through a `volatile` pointer,
which avoids the bug. If it appears in new code, build that file with `-fno-peephole2` and record it here.

**Reading a `BLACKVEIL_PANIC` report** – the headline names the CPU exception. Find the code with
`addr2line -e build/<release|test>/blackveil.elf <RIP>` or `nm -n` on the same file (the one that was booted). For `#PF`, `Fault addr`
is the address touched and the error code says read/write and not-present/protection. `#GP` with
error code 0 usually means a non-canonical address or a bad instruction operand.

**`BLACKVEIL_PANIC_NESTED`** – the panic reporter itself faulted (often VGA/serial code or stack
corruption). Only the first report is reliable; debug with `-d int -no-reboot` and `-s -S` + gdb.

**Machine resets with no panic report** – a triple fault: the fault happened before
`cpu_tables_init()` ran, or the IST stack/IDT itself was corrupted. Use `-d int,cpu_reset -no-reboot`.

**`BLACKVEIL_BOOT_FAIL: gate N is not installed correctly` / `task register ...`** – the IDT/TSS
self-check failed; the CPU tables do not match what the kernel wrote.

**`BLACKVEIL_PANIC: unknown bv.test value`** – a misspelt test name was passed with `-append`.
Valid names: de, bp, ud, gp, pf, df, panic, nested.

**Fault tests on real hardware** – never boot with `bv.test=` outside an emulator; the tests
deliberately crash the kernel. They are only ever run by `tests/boot-test.sh` inside QEMU.

**`Permission denied` running scripts** – restore execute bits: `chmod +x scripts/*.sh tests/boot-test.sh`.

**ASan "runtime does not come first"** in `make host-test` – the host preloads a library;
the Makefile sets `ASAN_OPTIONS=verify_asan_link_order=0` for the test binary.
