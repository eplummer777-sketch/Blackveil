# Building and testing

## Requirements
- x86-64 Linux host
- GCC (tested with 14.x), GNU binutils (`ld`, `objcopy`), GNU make, python3
- `qemu-system-x86_64` (system package, `$QEMU`, or `./scripts/fetch-qemu.sh` into `.tools/qemu`)

## Targets
| Target | What it does |
|---|---|
| `make` | Builds the release kernel in `build/release/` and the test kernel in `build/test/` (each `blackveil.elf` plus the bootable `blackveil-mb32.elf`); `make release` / `make test-kernel` build one |
| `make host-test` | Host unit tests (formatter, panic report, memory map, frame allocator, page tables, heap) with ASan/UBSan, each under `HOST_TIMEOUT` (default 120 s) |
| `make boot-test` | Header check + real QEMU boots: normal boot, 32-bit CPU refusal, recoverable int3, and deliberate #DE/#UD/#GP/#PF/#DF/panic/nested-fault cases (each must give exit 35, one complete report, correct RIP), the memory tests, and release-kernel isolation checks |
| `make test` | Both of the above |
| `make run` / `make run-headless` | Interactive boot of the release kernel (`IMAGE=test` for the test kernel) |
| `make clean` | Removes `build/` |

All kernel code is compiled with `-Wall -Wextra -Werror`, freestanding, no red zone and general
registers only (no SSE state to save in future interrupt handlers).

## Why two ELF files
QEMU's Multiboot loader only accepts 32-bit ELF. The kernel is linked as ELF64 and then converted
with `objcopy -O elf32-i386`; the code is unchanged and the 32-bit trampoline in `boot.S`
switches the CPU to long mode before calling C.

## Test evidence
Boot logs are written to `build/test-logs/`. The tests check QEMU's real exit status (via the
`isa-debug-exit` device) and the serial output; nothing is simulated.
