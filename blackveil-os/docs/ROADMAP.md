# Roadmap

Each milestone is only started after the previous one passes `make test` in QEMU.

| # | Milestone | Status |
|---|---|---|
| M1 | Boot, long mode, serial + VGA banner, automated boot tests | **Done, verified** |
| M2 | GDT+TSS with IST stacks, IDT, CPU exception reports, panic, nested-fault guard, fault tests | **Done, verified** |
| M3 | Physical frame allocator, own page tables (W^X, NX), kernel heap | **In progress** (0.3.0-m3.5; core done, hardening stages below) |
| M4 | PIT/APIC timer, kernel threads, preemptive scheduler | Planned |
| M5 | User GDT segments + TSS.rsp0, ring 3, syscall/sysret, first user program | Planned |
| M6 | VFS, in-memory filesystem, user-mode shell | Planned |
| M7 | Users, permission checks on VFS/syscalls, append-only audit log | Planned |
| M8 | PCI enumeration, virtio-blk storage, virtio-net + minimal network stack | Planned |
| M9 | Service manager, health reporting, native agent for Blackveil Security (see PROTOCOL.md) | Planned |

## M3 core (done)
1. Parse the Multiboot memory map (flag bit 6) and reserve the kernel image, boot tables, low memory.
2. Bitmap physical frame allocator with self-tests (alloc/free/exhaustion/double-free panic).
3. Kernel-owned page tables replacing the boot identity map: .text RX, .rodata R+NX, .data/.bss
   RW+NX (enable EFER.NXE), unmapped guard page below each stack, page 0 unmapped.
4. Kernel heap (kmalloc/kfree) with tagged headers/footers and overrun checks.
5. Emulator tests: write to .text and execute from .data must produce a #PF panic; null
   dereference must produce a #PF with CR2=0.

## M3 hardening stages

| Stage | Work | Status |
|---|---|---|
| 5 | High-memory physical allocation (up to a 16 GiB managed limit, bounded by CPU address width) | **Done** |
| 6 | Safe page-table reclamation | **Done** (per recorded run, see below) |
| 7 | Heap safety and allocator integrity | **Done** (per recorded run, see below) |
| 8 | Release / test kernel separation (plus host-test time limits, QEMU setup fix, ARCHITECTURE.md / SECURITY.md update) | **Done** (per recorded run, see below) |
| - | SMP synchronization design (written design only; no SMP support claimed) | Pending |

### Stage 6 record
- Empty page tables are unlinked inside the write window, then all translations are flushed
  (`flush_all`), then the frame is unpinned and freed (`retire`). The root is never freed; a table
  holding any entry is never touched. Unpinning refuses boot data, the kernel, allocator records,
  low memory, unusable memory and non-table frames.
- Recorded results: host tests 4,330 vmm and 1,914 heap checks, 0 failed; `make test` in QEMU
  419 passed, 0 failed (380 at Stage 5).
- New emulator coverage: reclamation at 128 MiB, 4 GiB and 16 GiB; 10,000 map/unmap cycles
  reclaiming 30,000 tables; out-of-memory with 0, 1 and 2 free frames changes nothing;
  `fault-reclaim-stale` (reclaimed tables overwritten with forged entries must not be followed).
- 16 GiB adjustment: the exhaustion step tracks drained frames in a heap bitmap instead of
  chaining through each free frame, which committed all guest RAM on the host and got the run
  killed. No assertion was removed or weakened.
- Limitation: QEMU TCG does not model the paging-structure caches, so `fault-reclaim-stale`
  alone cannot prove the flush is required. The host tests check that the flush happens before
  any table frame is retired.

### Stage 7 record
- Every free block and free-list link is validated before use: header and footer tags, bounds,
  alignment, free state, both link directions, address order and non-adjacency. The allocation
  walk, unlinking, neighbour merges and heap growth all check first and return `-BV_EFAULT`
  without changing the heap, its statistics or calling the grow hook.
- Tags are integrity checks bound to the block address, not secrets; a deliberate forger can
  recompute them.
- Poisoning: free payloads are filled with `HEAP_POISON` (0x6B) from header+16 (after the list
  links) to the footer, including stale header/footer words absorbed by a merge. Poison is checked
  on the bytes handed out by an allocation, on the tail before growth, and by `heap_check`.
  Writes after free are detected only when they hit poisoned bytes and before those bytes are
  reused; reads after free are not detected.
- Recorded results: host heap 2,019 checks (1,914 earlier + 105 new), vmm 4,330, pmm 183,
  memmap 48, trap-format 33, format 15, all 0 failed; `make test` in QEMU 420 passed, 0 failed
  (new: `heap-stress` poison and write-after-free check).

### Stage 8 record
- `make` builds `build/release/` (core kernel only) and `build/test/` (core built with
  `-DBV_TEST_BUILD` plus the dispatcher, crash triggers and emulator self-tests). Test sources
  refuse to compile without that define. The release kernel never reads `bv.test=`; boot-time
  integrity checks run in both.
- Release isolation is checked in `make test` section 14: no test-only objects, none of the 62
  symbols defined only by test objects, none of the strings `bv.test`, `[TEST]`, `fault test`,
  `deliberate panic`, and seven release boots (none, `panic`, `pf`, `df`, `heap-overrun`,
  `reclaim-stale`, an unknown name) that must boot normally with no test output.
- Host tests run under `HOST_TIMEOUT` (default 120 s); a hang fails with `TIMED OUT`. Checked
  with the Stage 7 mutation that removes the allocation-walk check: it now fails after the limit
  instead of hanging. `scripts/fetch-qemu.sh` runs `qemu.sh` through `sh`.
- Recorded results: host 6,628 checks (format 15, trap-format 33, memmap 48, pmm 183,
  vmm 4,330, heap 2,019), 0 failed, unchanged from the Stage 7 baseline. `make test` in QEMU
  492 passed, 0 failed: all 420 baseline checks (19 compare addresses that moved with the new
  build line) + 1 build-line check on the test kernel + 71 release checks.
