# Security principles

- No backdoors, debug accounts, hardcoded passwords, keys or tokens in source or images.
- No remote administration without authentication; network services stay off until M8/M9 and
  every remote action will require a per-device credential issued by Blackveil Security.
- Least privilege: user programs run in ring 3 (M5); every syscall that touches files, users or
  devices is permission-checked (M7) and security-relevant decisions are audit-logged.
- Memory hygiene: bounded formatting and copying only; W^X and NX page mappings; guard pages on
  stacks.
- Fail closed: unsupported CPU, bad loader handoff, a failed boot-time self-check or any CPU
  exception halts with a clear message.

## Current protections (0.3.0-m3.5)
- Kernel-owned page tables: code read+execute, read-only data and low memory read-only+NX, data,
  stacks, free RAM and the heap read/write+NX (EFER.NXE); page 0 unmapped.
- CR0.WP: kernel code, read-only data, boot data, page-table pages and frame allocator records are
  read-only to the kernel itself; page-table pages are pinned and writable aliases refused.
- Guard pages below the boot stack and the 3 emergency stacks; #DF, NMI and #MC on separate stacks.
- Heap: every block, link and neighbour is validated before any change; double frees, frees of
  non-heap pointers and overruns into the slack are refused. Header/footer tags are integrity
  checks bound to the block address, not secrets: a deliberate forger can recompute them.
  Freed memory is poisoned (0x6B); writes after free are detected only when they hit poisoned
  bytes before reuse, and reads after free are not detected.

## Build configurations
- The **release** kernel (`build/release/`) contains no test dispatcher, crash triggers or
  emulator self-tests and never reads `bv.test=`. `make test` verifies this by symbol and string
  inspection and by booting it with `bv.test=` values that must have no effect.
- The **test** kernel (`build/test/`) keeps the `bv.test=` hooks for the emulator suite. It must
  not be deployed. Anyone who controls its boot loader can crash it on purpose.

## Current limitations
- Supervisor mode only; there are no user processes and no isolation between kernel components
  yet (M5).
- Single CPU; no locking (SMP design pending).
- Panic reports print full register contents to the serial port and screen. Once real data is
  handled, reports must be reviewed so they do not leak secrets to an untrusted console.
- Not suitable for any production or security-sensitive use.
