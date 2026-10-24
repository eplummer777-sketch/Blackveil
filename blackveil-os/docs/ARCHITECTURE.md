# Architecture (as of 0.3.0-m3.5, M3 hardening stage 8)

## Boot flow
1. SeaBIOS starts; QEMU's Multiboot loader reads the header (magic `0x1BADB002`, flags 3) in the
   first 8 KiB and loads the image at 1 MiB.
2. `_start` (32-bit protected mode) saves the loader magic and info pointer, sets a 16 KiB stack.
3. CPUID check for extended leaf 0x80000001 and the LM bit. On failure: message on COM1 and
   exit code 0x11 to port 0xF4, then halt.
4. Builds PML4 -> PDPT -> PD identity-mapping the first 1 GiB with 2 MiB pages.
5. Enables CR4.PAE, EFER.LME, CR0.PG; loads a 64-bit GDT (code 0x08, data 0x10); far jump.
6. 64-bit code reloads segments and calls `kmain(magic, info)`.
7. `kmain` initialises COM1 (loopback self-test) and VGA, verifies magic and EFER.LMA, prints
   CPU vendor, memory and image range, then runs the M3 memory setup below, prints
   `BLACKVEIL_BOOT_OK` and signals QEMU.

## Memory layout and protection (M3)
The boot identity map (first 1 GiB, RWX) is only used until `vm_init` switches to kernel-owned
page tables:
| Range | Mapping |
|---|---|
| page 0 | Unmapped (null dereferences fault) |
| 0x1000 - 0xB8000 | Low memory, read-only, no-execute |
| 0xB8000 | VGA text buffer |
| 0x100000 | Kernel image: `.text` read+execute, `.rodata` read-only+NX, `.data`/`.bss` read/write+NX |
| Free RAM | Read/write, no-execute (EFER.NXE) |
| 0xFFFFB00000000000 (1 GiB) | Kernel heap, read/write, no-execute, grows on demand |

- CR0.WP is set: kernel code, read-only data, boot data, every page-table page and the frame
  allocator's records are read-only even to the kernel; page-table pages are pinned and a writable
  alias of them is refused. Writes go through a short, checked write window.
- Guard pages: the null page, below the boot stack and below the 3 emergency (IST) stacks.
- Physical frames: bitmap allocator over the Multiboot map, RAM managed up to 16 GiB bounded by
  the CPU's physical address width; self-check at boot.
- Page-table reclamation: empty tables are unlinked, all translations flushed, then the frame is
  unpinned and freed; the root is never freed.
- Heap: first-fit, address-ordered free list with coalescing; tagged headers and footers,
  overrun slack, freed memory poisoned with 0x6B. Every block and link is validated before the
  heap or its statistics change. Tags are integrity checks, not secrets.
- Boot-time checks in every build: IDT/TSS, frame allocator, paging, allocator metadata and heap
  self-checks. Any failure stops the boot.

## Console
`kprintf` formats into a 512-byte buffer with a bounded formatter (always NUL-terminated,
width clamped) and writes to COM1 (CRLF) and VGA (cyan on black, scrolling).

## CPU tables (M2)
`cpu_tables_init()` (arch/x86_64/cpu_tables.c) runs right after the banner:
- New GDT: null, 0x08 kernel code, 0x10 kernel data (same values as boot.S), 0x18 64-bit TSS.
- TSS interrupt stack table: IST1 = #DF, IST2 = NMI, IST3 = #MC, 8 KiB static stacks each, so a
  corrupted or exhausted kernel stack still produces a report.
- IDT: 256 entries; vectors 0-31 are present 64-bit interrupt gates (DPL 0, selector 0x08).
  Vectors 32-255 are not present; hardware interrupts stay disabled until M4, and any stray
  vector raises #GP, which is reported.
- `idt_selftest()` reads IDTR and TR back from the CPU and checks every gate (handler address,
  selector, type, IST). Any mismatch stops the boot with `BLACKVEIL_BOOT_FAIL`.

## Exception path
1. `isr.S`: one stub per vector pushes a dummy error code when the CPU does not, then the vector,
   then all 15 general registers, forming `struct trap_frame` (include/bv/trap.h).
2. `trap_dispatch()` (kernel/trap.c):
   - If a panic is already in progress -> `panic_nested()`.
   - `#BP` (int3) is the only recoverable exception: it is logged and execution resumes.
   - Everything else -> `panic_exception()`.
3. `panic_exception()` / `panic()` (kernel/panic.c): disable interrupts, mark the panic, read
   CR2/CR3, format the report (kernel/trap_format.c) into a static 2 KiB buffer, switch VGA to
   white-on-red, print the report to serial and VGA, write 0x11 to port 0xF4 (QEMU exit 35), halt.

Report contents: `BLACKVEIL_PANIC:` headline with vector, mnemonic and name; decoded error code
(page-fault flags, or selector index/table for segment exceptions); CR2 for #PF; RIP, CS, RFLAGS,
RSP, SS, CR3 and all general registers. For #DF the saved RIP is architecturally undefined.

## Nested-fault guard
A fault while reporting a panic prints one fixed line (`BLACKVEIL_PANIC_NESTED: ...`) with no
formatting or shared buffers, signals failure and halts. A third fault halts silently. This
prevents diagnostic loops.

## Build configurations
`make` builds two kernels from the same sources, in separate object directories:
| Image | Directory | Contents |
|---|---|---|
| Release | `build/release/` | Core kernel only. Never reads `bv.test=`; prints `Build: release (no test hooks)` |
| Test | `build/test/` | Core kernel built with `-DBV_TEST_BUILD`, plus `kernel/selftest.c`, `kernel/*_selftest.c` and `arch/x86_64/fault_triggers.S`; prints `Build: test (...)` |

The test-only sources refuse to compile without `BV_TEST_BUILD` (`#error` in
`include/bv/selftest.h` and `fault_triggers.S`), and `kmain` calls the test dispatcher only under
that define. `make test` boots the test image for sections 1-13 and checks the release image in
section 14: no test-only object, none of the test-only symbols (derived from the test objects),
no test strings, and seven boots with and without `bv.test=` values that must all boot normally
with no test output. `make run IMAGE=test` boots the test image by hand.

## Test-only hooks (test image only)
`bv.test=<name>` on the Multiboot command line (QEMU `-append`) runs one test after the boot
checks. The command line is set by the boot loader (trusted). An unknown value panics.
| Group | Names |
|---|---|
| CPU exceptions and panic | `de` `bp` `ud` `gp` `pf` `df` `panic` `nested` |
| Frame allocator | `pmm-drain` |
| Paging and permissions | `null` `wp-text` `wp-rodata` `wp-bootinfo` `nx-data` `nx-stack` `nx-ram` `guard-stack` `guard-ist` `unmap-fault` `vmm-rollback` |
| Heap | `heap-stress` `heap-exhaust` `heap-nx` `heap-overrun` |
| Write protection | `prot-pt-write` `prot-new-table` `prot-pmm-write` `prot-boot-pt` `prot-alias` `prot-checks` |
| High memory and reclamation | `highmem` `reclaim` `reclaim-stale` |

Host unit tests (`make host-test`) run each binary under a time limit (`HOST_TIMEOUT`, default
120 s); a hang is reported as `TIMED OUT` and fails the run.
