# Blackveil OS (kernel)

A from-scratch x86-64 kernel written in C and GNU assembly. It is **not** Linux, does not run Linux
binaries, and is not Docker-compatible. The browser "Blackveil OS" desktop in the parent web app
remains the management UI; this directory is a separate bootable project.

Current milestone: **M2 – CPU exception handling and kernel panic (verified in QEMU)**.
Crash handling is diagnostic only; it is not memory protection or isolation. See `docs/ROADMAP.md`.

## Quickstart

```sh
make check-tools        # verify gcc, ld, objcopy, python3, qemu
./scripts/fetch-qemu.sh # only if no qemu-system-x86_64 is installed (rootless, Debian/Ubuntu)
make                    # build/release/ and build/test/: blackveil.elf (64-bit) + blackveil-mb32.elf (bootable)
make test               # host unit tests + automated QEMU boot tests (test kernel, then release checks)
make run                # boot the release kernel in a QEMU window (IMAGE=test for the test kernel)
make run-headless       # serial only, Ctrl-A X to quit
```

Manual emulator command:

```sh
qemu-system-x86_64 -kernel build/release/blackveil-mb32.elf -serial stdio -display none \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04 -no-reboot -m 128M
```

Exit status 33 = kernel reported success, 35 = kernel reported failure.

## External components (not written by this project)

| Component | Role | Source |
|---|---|---|
| QEMU built-in Multiboot v1 loader (`-kernel`) | Loads the 32-bit ELF and enters `_start` in protected mode | QEMU |
| SeaBIOS | Firmware QEMU runs before the loader | Shipped with QEMU |
| GCC, GNU ld/objcopy | Toolchain | Host system |

GRUB, UEFI and Limine are **not** used. Everything inside `arch/`, `kernel/`, `drivers/`, `lib/` is
original code with no third-party sources.

## Layout

```
arch/x86_64/   boot.S (Multiboot header, long-mode trampoline), linker.ld,
               cpu_tables.c (GDT/TSS/IDT), isr.S (exception stubs), fault_triggers.S (tests)
kernel/        kmain, kprintf console, trap dispatch, panic, report formatting, bv.test hooks
drivers/       COM1 serial, VGA text mode
lib/           bounded formatter, string routines
include/bv/    headers
tests/         host unit tests, boot-test.sh, multiboot header checker
scripts/       qemu launcher, rootless QEMU fetcher
docs/          BUILD, ARCHITECTURE, ROADMAP, SECURITY, PROTOCOL (draft), TROUBLESHOOTING
```
