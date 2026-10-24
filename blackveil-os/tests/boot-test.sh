#!/usr/bin/env sh
# Boots the real kernel image in QEMU and checks its serial output and exit code.
# QEMU's isa-debug-exit device turns the kernel's port-0xF4 write into the
# emulator's exit status: 33 = kernel reported success, 35 = kernel reported failure.
set -u
# Sections 1-13 boot the test kernel; section 14 checks the release kernel.
IMG=${1:-build/test/blackveil-mb32.elf}
ELF=${2:-build/test/blackveil.elf}
REL_IMG=${3:-build/release/blackveil-mb32.elf}
REL_ELF=${4:-build/release/blackveil.elf}
BOOT_IMG=$IMG
DIR=$(cd "$(dirname "$0")/.." && pwd)
LOGS="$DIR/build/test-logs"
mkdir -p "$LOGS"
PASS=0
FAIL=0

ok()  { PASS=$((PASS + 1)); echo "  PASS  $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL  $1"; }

boot() { # name, extra qemu args...  (MEM overrides the 128M default, TIMEOUT the 30 s limit)
  name=$1; shift
  timeout "${TIMEOUT:-30}" sh "$DIR/scripts/qemu.sh" -kernel "$BOOT_IMG" -m "${MEM:-128M}" -no-reboot -display none \
    -serial "file:$LOGS/$name.log" -device isa-debug-exit,iobase=0xf4,iosize=0x04 "$@" \
    >"$LOGS/$name.qemu.txt" 2>&1
  echo $?
}

expect_log() { # name, text
  if grep -qF "$2" "$LOGS/$1.log"; then ok "$1: serial shows '$2'"; else bad "$1: serial missing '$2'"; fi
}

expect_absent() { # name, text
  if grep -qF "$2" "$LOGS/$1.log"; then bad "$1: serial unexpectedly shows '$2'"; else ok "$1: no '$2'"; fi
}

sym() { nm "$ELF" | awk -v s="$1" '$3 == s { print $1 }'; }

# Boots with bv.test=<case> and checks a single, complete, fatal report.
fault_case() { # case, headline, [symbol of faulting instruction]
  name=fault-$1
  code=$(boot "$name" -append "bv.test=$1")
  [ "$code" = "35" ] && ok "$name: exit status 35 (controlled halt)" || bad "$name: exit status $code (want 35)"
  expect_log "$name" "$2"
  expect_log "$name" "System halted"
  count=$(grep -c "BLACKVEIL_PANIC" "$LOGS/$name.log")
  [ "$count" = "1" ] && ok "$name: exactly one panic report" || bad "$name: $count panic lines (want 1)"
  expect_absent "$name" "BLACKVEIL_BOOT_OK"
  if [ -n "${3:-}" ]; then
    addr=$(sym "$3")
    if [ -n "$addr" ]; then expect_log "$name" "RIP=0x$addr"; else bad "$name: symbol $3 not found"; fi
  fi
}

echo "[1] Multiboot header placement"
if python3 "$DIR/tests/check_multiboot.py" "$IMG"; then ok "header valid in first 8 KiB"; else bad "multiboot header"; fi

echo "[2] Normal boot on a 64-bit CPU"
code=$(boot boot-x86_64)
[ "$code" = "33" ] && ok "boot-x86_64: kernel exit status 33 (success)" || bad "boot-x86_64: exit status $code (want 33)"
expect_log boot-x86_64 "=== Blackveil OS"
expect_log boot-x86_64 "[ OK ] Build: test (emulator test hooks compiled in)"
expect_log boot-x86_64 "[ OK ] Multiboot handoff"
expect_log boot-x86_64 "[ OK ] 64-bit long mode active"
expect_log boot-x86_64 "[ OK ] Memory:"
expect_log boot-x86_64 "[ OK ] Exception handlers: 32 vectors installed"
expect_log boot-x86_64 "[ OK ] Memory map: 7 entries, 130556 KiB usable in 2 ranges"
expect_log boot-x86_64 "reserved 0x0000000000000000 - 0x0000000000100000  low memory"
expect_log boot-x86_64 "  kernel image"
expect_log boot-x86_64 "  memory map"
expect_log boot-x86_64 "[ OK ] Physical frames: 130556 KiB usable"
expect_log boot-x86_64 "[ OK ] Frame allocator self-check passed"
expect_log boot-x86_64 "[ OK ] Physical address width: "
expect_log boot-x86_64 "bits; RAM managed up to 16384 MiB"
expect_log boot-x86_64 "  frame allocator records"
expect_log boot-x86_64 "made read-only"
expect_log boot-x86_64 "r-x  kernel code"
expect_log boot-x86_64 "r--  kernel read-only data"
expect_log boot-x86_64 "rw-  kernel data + bss"
expect_log boot-x86_64 "map 0x0000000000001000 - 0x00000000000b8000  r--  low memory (page 0 left unmapped)"
expect_log boot-x86_64 "[ OK ] Paging: kernel page tables active"
expect_log boot-x86_64 "[ OK ] W^X: code read-only, data, stacks and free RAM non-executable (EFER.NXE)"
expect_log boot-x86_64 "[ OK ] Guard pages: null page, boot stack and 3 emergency stacks"
expect_log boot-x86_64 "[ OK ] Paging self-check passed"
expect_log boot-x86_64 "boot tables and "
expect_log boot-x86_64 "table pages made read-only"
expect_log boot-x86_64 "[ OK ] Write protection: kernel code, read-only data, boot data, page tables and allocator metadata (CR0.WP)"
expect_log boot-x86_64 "table pages read-only and pinned; writable aliases refused"
expect_log boot-x86_64 "[ OK ] Allocator metadata: read-only, consistency check passed"
expect_log boot-x86_64 "0.3.0-m3.5"
expect_log boot-x86_64 "[ OK ] Heap: 0xffffb00000000000 - 0xffffb00040000000, read/write, no-execute, grows on demand"
expect_log boot-x86_64 "[ OK ] Heap self-check passed"
expect_absent boot-x86_64 "[WARN]"
expect_absent boot-x86_64 "BLACKVEIL_PANIC"
expect_log boot-x86_64 "BLACKVEIL_BOOT_OK"
if grep -q "BLACKVEIL_BOOT_FAIL" "$LOGS/boot-x86_64.log"; then bad "boot-x86_64: unexpected failure line"; else ok "boot-x86_64: no failure lines"; fi

echo "[3] Safe refusal on a 32-bit-only CPU"
code=$(boot boot-no-longmode -cpu qemu32)
[ "$code" = "35" ] && ok "boot-no-longmode: kernel exit status 35 (reported failure)" || bad "boot-no-longmode: exit status $code (want 35)"
expect_log boot-no-longmode "BLACKVEIL_BOOT_FAIL: CPU lacks 64-bit long mode"

echo "[4] Recoverable breakpoint (int3) resumes and boot completes"
code=$(boot fault-bp -append "bv.test=bp")
[ "$code" = "33" ] && ok "fault-bp: exit status 33 (resumed)" || bad "fault-bp: exit status $code (want 33)"
expect_log fault-bp "[TRAP] #BP breakpoint at RIP="
expect_log fault-bp "[TEST] fault test 'bp' returned"
expect_log fault-bp "BLACKVEIL_BOOT_OK"
expect_absent fault-bp "BLACKVEIL_PANIC"

echo "[5] Fatal CPU exceptions (emulator only)"
fault_case de "BLACKVEIL_PANIC: CPU exception 0 #DE Divide Error" bv_fault_de
fault_case ud "BLACKVEIL_PANIC: CPU exception 6 #UD Invalid Opcode" bv_fault_ud
fault_case gp "BLACKVEIL_PANIC: CPU exception 13 #GP General Protection Fault" bv_fault_gp
expect_log fault-gp "Error code: 0x0000000000000000"
fault_case pf "BLACKVEIL_PANIC: CPU exception 14 #PF Page Fault" bv_fault_pf
expect_log fault-pf "Error code: 0x0000000000000002 (not-present page, write, kernel)"
expect_log fault-pf "Fault addr: 0xffff800000000000 (CR2)"
fault_case df "BLACKVEIL_PANIC: CPU exception 8 #DF Double Fault"

echo "[6] Kernel panic and nested-fault guard"
fault_case panic "BLACKVEIL_PANIC: deliberate panic requested by bv.test=panic"
fault_case unknown "BLACKVEIL_PANIC: unknown bv.test value"
name=fault-nested
code=$(boot "$name" -append "bv.test=nested")
[ "$code" = "35" ] && ok "$name: exit status 35 (controlled halt)" || bad "$name: exit status $code (want 35)"
expect_log "$name" "BLACKVEIL_PANIC: CPU exception 6 #UD"
expect_log "$name" "BLACKVEIL_PANIC_NESTED: fault while reporting a panic"
count=$(grep -c "BLACKVEIL_PANIC" "$LOGS/$name.log")
[ "$count" = "2" ] && ok "$name: no report loop (2 panic lines)" || bad "$name: $count panic lines (want 2)"

echo "[7] Physical frame allocator"
name=pmm-drain
code=$(boot "$name" -append "bv.test=pmm-drain")
[ "$code" = "33" ] && ok "$name: exit status 33" || bad "$name: exit status $code (want 33)"
counts=$(sed -n 's/.*pmm-drain: allocated \([0-9]*\) of \([0-9]*\) free frames, then out of memory.*/\1 \2/p' "$LOGS/$name.log")
set -- $counts
if [ -n "${1:-}" ] && [ "$1" = "${2:-}" ] && [ "$1" -gt 30000 ]; then ok "$name: drained all $1 free frames"; else bad "$name: drain counts '$counts'"; fi
expect_log "$name" "[TEST] pmm-drain: all frames returned, free count restored"
expect_absent "$name" "BLACKVEIL_PANIC"
expect_log "$name" "BLACKVEIL_BOOT_OK"

for mem in 32M 512M 2G; do
  name=boot-mem-$mem
  code=$(MEM=$mem boot "$name")
  [ "$code" = "33" ] && ok "$name: exit status 33" || bad "$name: exit status $code (want 33)"
  expect_log "$name" "[ OK ] Frame allocator self-check passed"
  expect_log "$name" "[ OK ] Paging self-check passed"
  expect_log "$name" "[ OK ] Allocator metadata: read-only, consistency check passed"
  expect_log "$name" "[ OK ] Heap self-check passed"
  expect_log "$name" "BLACKVEIL_BOOT_OK"
done
expect_absent boot-mem-2G "[WARN]"
expect_log boot-mem-2G "[ OK ] Memory map: 7 entries, 2096636 KiB usable in 2 ranges"
expect_log boot-mem-2G "highest 0x000000007ffe0000)"
expect_absent boot-mem-512M "[WARN]"
name=pmm-drain-512M
code=$(MEM=512M boot "$name" -append "bv.test=pmm-drain")
[ "$code" = "33" ] && ok "$name: exit status 33" || bad "$name: exit status $code (want 33)"
expect_log "$name" "[TEST] pmm-drain: all frames returned, free count restored"

echo "[8] Hardware-enforced page permissions and guard pages"
pf_case() { # case, error-code text, [CR2 address without 0x], [RIP symbol]
  fault_case "$1" "BLACKVEIL_PANIC: CPU exception 14 #PF Page Fault" "${4:-}"
  expect_log "fault-$1" "$2"
  [ -n "${3:-}" ] && expect_log "fault-$1" "Fault addr: 0x$3 (CR2)"
}
hex16() { printf '%016s' "$1" | tr ' ' 0; }
PROT_W="Error code: 0x0000000000000003 (protection violation, write, kernel)"
NX_FETCH="Error code: 0x0000000000000011 (protection violation, read, kernel, instruction fetch)"
pf_case null "Error code: 0x0000000000000000 (not-present page, read, kernel)" 0000000000000000 bv_fault_read
pf_case wp-text "$PROT_W" "$(hex16 "$(sym bv_trigger_write)")" bv_fault_write
pf_case wp-rodata "$PROT_W" "$(hex16 "$(sym bv_ro_canary)")" bv_fault_write
pf_case wp-bootinfo "$PROT_W" "" bv_fault_write
cl=$(sed -n 's/.*reserved 0x\([0-9a-f]*\) - .*command line.*/\1/p' "$LOGS/fault-wp-bootinfo.log")
[ -n "$cl" ] && expect_log fault-wp-bootinfo "Fault addr: 0x$cl (CR2)" || bad "fault-wp-bootinfo: no command line address"
pf_case nx-data "$NX_FETCH" "$(hex16 "$(sym bv_nx_buf)")" bv_nx_buf
pf_case nx-stack "$NX_FETCH"
pf_case nx-ram "$NX_FETCH"
fault_case guard-stack "BLACKVEIL_PANIC: CPU exception 8 #DF Double Fault"
expect_log fault-guard-stack "Stack guard page hit: boot stack overflow (CR2=0x"
cr2=$(sed -n 's/.*boot stack overflow (CR2=0x\([0-9a-f]*\)).*/\1/p' "$LOGS/fault-guard-stack.log")
g=$(sym boot_stack_guard)
if [ -n "$cr2" ] && [ -n "$g" ] && [ $((0x$cr2 >> 12)) -eq $((0x$g >> 12)) ]; then ok "fault-guard-stack: CR2 inside the boot stack guard page"; else bad "fault-guard-stack: CR2 '$cr2' vs guard '$g'"; fi
pf_case guard-ist "Error code: 0x0000000000000002 (not-present page, write, kernel)" "" bv_fault_write
expect_log fault-guard-ist "Stack guard page hit: #DF emergency stack overflow"
pf_case unmap-fault "Error code: 0x0000000000000000 (not-present page, read, kernel)" ffff900000001000 bv_fault_read
expect_log fault-unmap-fault "[TEST] unmap-fault: 0xffff900000001000 was mapped and used, now unmapped"
name=vmm-rollback
code=$(boot "$name" -append "bv.test=vmm-rollback")
[ "$code" = "33" ] && ok "$name: exit status 33" || bad "$name: exit status $code (want 33)"
expect_log "$name" "[TEST] vmm-rollback: out of memory with 0, 1 and 2 frames left changed nothing"
expect_log "$name" "[TEST] vmm-rollback: overlapping map and partial unmap refused with no change"
expect_absent "$name" "BLACKVEIL_PANIC"

echo "[9] CPU without NX support"
name=boot-no-nx
code=$(boot "$name" -cpu qemu64,-nx)
[ "$code" = "33" ] && ok "$name: exit status 33" || bad "$name: exit status $code (want 33)"
expect_log "$name" "[WARN] CPU lacks NX: data pages stay executable; code is still read-only"
expect_log "$name" "[ OK ] Paging self-check passed"
expect_log "$name" "table pages read-only and pinned; writable aliases refused"
expect_log "$name" "[ OK ] Heap self-check passed"
name=fault-wp-text-no-nx
code=$(boot "$name" -cpu qemu64,-nx -append "bv.test=wp-text")
[ "$code" = "35" ] && ok "$name: exit status 35" || bad "$name: exit status $code (want 35)"
expect_log "$name" "$PROT_W"

echo "[10] Kernel heap"
name=heap-stress
code=$(boot "$name" -append "bv.test=heap-stress")
[ "$code" = "33" ] && ok "$name: exit status 33" || bad "$name: exit status $code (want 33)"
expect_log "$name" "[TEST] heap-stress: 132 allocations at every alignment from 1 B to 2 MiB were aligned and intact"
expect_log "$name" "[TEST] heap-stress: 20000 random operations; contents intact, statistics exact, all memory coalesced"
expect_log "$name" "[TEST] heap-stress: frees of kernel code, stack, boot data, page tables and non-heap pointers refused"
expect_log "$name" "[TEST] heap-stress: double frees and a 1-byte overrun detected without changing the heap"
expect_log "$name" "[TEST] heap-stress: freed memory poisoned and a write after free detected"
expect_absent "$name" "BLACKVEIL_PANIC"
for mem in 32M 128M 512M; do
  name=heap-exhaust-$mem
  code=$(MEM=$mem boot "$name" -append "bv.test=heap-exhaust")
  [ "$code" = "33" ] && ok "$name: exit status 33" || bad "$name: exit status $code (want 33)"
  left=$(sed -n 's/.*then out of memory with \([0-9]*\) frames left.*/\1/p' "$LOGS/$name.log")
  [ -n "$left" ] && [ "$left" -le 4 ] && ok "$name: heap used all memory ($left frames left)" || bad "$name: frames left '$left'"
  expect_log "$name" "[TEST] heap-exhaust: the failed allocation changed nothing and returned every frame it took"
  expect_log "$name" "without growing; statistics consistent"
  expect_absent "$name" "BLACKVEIL_PANIC"
done
pf_case heap-nx "$NX_FETCH"
ha=$(sed -n 's/.*heap-nx: executing heap memory at 0x\([0-9a-f]*\).*/\1/p' "$LOGS/fault-heap-nx.log")
[ -n "$ha" ] && expect_log fault-heap-nx "Fault addr: 0x$ha (CR2)" || bad "fault-heap-nx: no heap address"
[ -n "$ha" ] && expect_log fault-heap-nx "RIP=0x$ha" || bad "fault-heap-nx: no heap address"
pf_case heap-overrun "Error code: 0x0000000000000002 (not-present page, write, kernel)" "" bv_fault_write
he=$(sed -n 's/.*heap-overrun: writing at the heap end 0x\([0-9a-f]*\).*/\1/p' "$LOGS/fault-heap-overrun.log")
[ -n "$he" ] && expect_log fault-heap-overrun "Fault addr: 0x$he (CR2)" || bad "fault-heap-overrun: no heap end address"

echo "[11] Page-table and allocator metadata protection"
# Each write goes through an ordinary kernel mapping; the CPU must refuse it with a write-protection #PF.
prot_pf() { # case, log text before the address
  pf_case "$1" "$PROT_W" "" bv_fault_write
  a=$(sed -n "s/.*$2 0x\([0-9a-f]*\).*/\1/p" "$LOGS/fault-$1.log")
  [ -n "$a" ] && expect_log "fault-$1" "Fault addr: 0x$a (CR2)" || bad "fault-$1: no target address"
}
prot_pf prot-pt-write "writing the top-level page table at"
prot_pf prot-new-table "writing a page table created after boot at"
prot_pf prot-pmm-write "writing the frame allocator bitmap at"
prot_pf prot-boot-pt "writing the boot page tables at"
expect_log fault-prot-boot-pt "Fault addr: 0x$(hex16 "$(sym boot_page_tables)") (CR2)"
prot_pf prot-alias "writing a read-only alias of the top-level page table at"
expect_log fault-prot-alias "Fault addr: 0xffff900000001000 (CR2)"
expect_log fault-prot-alias "[TEST] prot-alias: writable aliases of a page table, allocator metadata and boot tables refused"
name=fault-prot-pt-write-no-nx
code=$(boot "$name" -cpu qemu64,-nx -append "bv.test=prot-pt-write")
[ "$code" = "35" ] && ok "$name: exit status 35" || bad "$name: exit status $code (want 35)"
expect_log "$name" "$PROT_W"
for mem in 32M 128M 512M; do
  name=prot-checks-$mem
  code=$(MEM=$mem boot "$name" -append "bv.test=prot-checks")
  [ "$code" = "33" ] && ok "$name: exit status 33" || bad "$name: exit status $code (want 33)"
  expect_log "$name" "[TEST] prot-checks: map, protect and unmap through the write window work; 3 new table pages read-only and pinned; CR0.WP and interrupt flag restored"
  expect_log "$name" "[TEST] prot-checks: 3 kinds of allocator metadata corruption detected; restored and consistent"
  expect_log "$name" "none reserved, a page table or metadata; out of memory changed nothing"
  expect_log "$name" "out-of-range frees, bad pins and a writable alias refused with no change"
  expect_log "$name" "[TEST] prot-checks: all protection checks passed"
  expect_log "$name" "BLACKVEIL_BOOT_OK"
  expect_absent "$name" "BLACKVEIL_PANIC"
done

echo "[12] Physical memory above 1 GiB"
# Guest RAM is reserved lazily so large guests boot on small hosts; only touched pages use host memory.
big() { # mem, name, extra args...
  m=$1; shift
  MEM=$m TIMEOUT=240 boot "$@" -object "memory-backend-ram,id=ram0,size=$m,reserve=off" -machine memory-backend=ram0
}
for mem in 2G 4G 16G; do
  name=highmem-$mem
  code=$(big $mem "$name" -append "bv.test=highmem")
  [ "$code" = "33" ] && ok "$name: exit status 33" || bad "$name: exit status $code (want 33)"
  line=$(sed -n 's/.*highmem: allocated all \([0-9]*\) free frames (\([0-9]*\) above 1 GiB, \([0-9]*\) above 4 GiB, highest 0x\([0-9a-f]*\)).*/\1 \2 \3 \4/p' "$LOGS/$name.log")
  set -- $line
  [ "${2:-0}" -gt 0 ] && ok "$name: $2 of ${1:-0} allocated frames lie above 1 GiB" || bad "$name: no frames above 1 GiB ('$line')"
  case $mem in
    2G) want_top=7ffdf000 ;;
    4G) want_top=13ffff000 ;;
    16G) want_top=3fffff000 ;;
  esac
  [ "${4:-}" = "$(printf '%016x' 0x$want_top)" ] && ok "$name: highest frame 0x$want_top allocated" || bad "$name: highest frame '${4:-}' (want $want_top)"
  if [ "$mem" != 2G ]; then
    [ "${3:-0}" -gt 0 ] && ok "$name: $3 frames above 4 GiB allocated" || bad "$name: no frames above 4 GiB"
  fi
  expect_log "$name" "none reserved, duplicated or out of range"
  expect_log "$name" "frames above 1 GiB, including 0x$(printf '%016x' 0x$want_top)"
  expect_log "$name" "[TEST] highmem: out of memory refused and the failed mapping rolled back with no change"
  expect_log "$name" "and above are read-only and pinned; alias of"
  expect_log "$name" "above 1 GiB; 2 MiB written and verified"
  expect_log "$name" "counters and protection consistent"
  expect_absent "$name" "BLACKVEIL_PANIC"
  expect_log "$name" "BLACKVEIL_BOOT_OK"
done
for mem in 4G 16G; do
  name=boot-mem-$mem
  code=$(big $mem "$name")
  [ "$code" = "33" ] && ok "$name: exit status 33" || bad "$name: exit status $code (want 33)"
  expect_log "$name" "[ OK ] Paging self-check passed"
  expect_log "$name" "[ OK ] Allocator metadata: read-only, consistency check passed"
  expect_log "$name" "[ OK ] Heap self-check passed"
  expect_log "$name" "BLACKVEIL_BOOT_OK"
done
expect_absent boot-mem-4G "[WARN]"
expect_log boot-mem-4G "highest 0x0000000140000000)"
expect_log boot-mem-16G "[WARN] Memory map: 1048576 KiB of RAM above the 16384 MiB managed limit excluded"
expect_log boot-mem-16G "highest 0x0000000400000000)"
name=boot-mem-20G
code=$(big 20G "$name")
[ "$code" = "33" ] && ok "$name: exit status 33" || bad "$name: exit status $code (want 33)"
expect_log "$name" "[WARN] Memory map: 5242880 KiB of RAM above the 16384 MiB managed limit excluded"
expect_log "$name" "highest 0x0000000400000000)"
expect_log "$name" "BLACKVEIL_BOOT_OK"
name=pmm-drain-2G
code=$(big 2G "$name" -append "bv.test=pmm-drain")
[ "$code" = "33" ] && ok "$name: exit status 33" || bad "$name: exit status $code (want 33)"
expect_log "$name" "[TEST] pmm-drain: all frames returned, free count restored"
for t in prot-checks vmm-rollback; do
  name=$t-4G
  code=$(big 4G "$name" -append "bv.test=$t")
  [ "$code" = "33" ] && ok "$name: exit status 33" || bad "$name: exit status $code (want 33)"
  expect_absent "$name" "BLACKVEIL_PANIC"
  expect_log "$name" "BLACKVEIL_BOOT_OK"
done
expect_log prot-checks-4G "[TEST] prot-checks: all protection checks passed"
prot_hi() { # case, log text before the address: write-protection #PF must still fire at 4 GiB
  n=fault-$1-4G
  code=$(big 4G "$n" -append "bv.test=$1")
  [ "$code" = "35" ] && ok "$n: exit status 35" || bad "$n: exit status $code (want 35)"
  expect_log "$n" "$PROT_W"
  a=$(sed -n "s/.*$2 0x\([0-9a-f]*\).*/\1/p" "$LOGS/$n.log")
  [ -n "$a" ] && expect_log "$n" "Fault addr: 0x$a (CR2)" || bad "$n: no target address"
}
prot_hi prot-pmm-write "writing the frame allocator bitmap at"
prot_hi prot-pt-write "writing the top-level page table at"

echo "[13] Page-table reclamation"
for mem in 128M 4G 16G; do
  name=reclaim-$mem
  if [ "$mem" = 128M ]; then code=$(boot "$name" -append "bv.test=reclaim"); else code=$(big $mem "$name" -append "bv.test=reclaim"); fi
  [ "$code" = "33" ] && ok "$name: exit status 33" || bad "$name: exit status $code (want 33)"
  expect_log "$name" "unlinked, flushed, unpinned and freed; their memory is writable again"
  expect_log "$name" "[TEST] reclaim: the freed frames were reused for data, then as zeroed tables again; no stale entry survived"
  expect_log "$name" "[TEST] reclaim: nested tables go lowest level first; a table still in use was kept; a range across 1 GiB returned all 5"
  expect_log "$name" "[TEST] reclaim: 10000 map/unmap cycles reclaimed 30000 tables; frame and table counts back to the start"
  expect_log "$name" "non-table frames refused; live tables still cannot be freed"
  expect_log "$name" "[TEST] reclaim: out of memory with 0, 1 and 2 frames changed nothing; the last 3 frames became tables, came back on unmap and were reused"
  expect_log "$name" "tables live as at the start; protection verified"
  expect_absent "$name" "BLACKVEIL_PANIC"
  expect_log "$name" "BLACKVEIL_BOOT_OK"
done
pf_case reclaim-stale "Error code: 0x0000000000000000 (not-present page, read, kernel)" ffffe00000000000 bv_fault_read
expect_log fault-reclaim-stale "reclaimed and overwritten with forged entries; reading 0xffffe00000000000"

echo "[14] Release kernel: no test code, bv.test= ignored"
if python3 "$DIR/tests/check_multiboot.py" "$REL_IMG"; then ok "release: multiboot header valid"; else bad "release: multiboot header"; fi
REL_DIR=$(dirname "$REL_ELF")
TST_DIR=$(dirname "$ELF")
leaked=$(find "$REL_DIR" \( -name '*selftest*' -o -name 'fault_triggers*' \) | head -3)
[ -z "$leaked" ] && ok "release: no test-only objects built" || bad "release: test objects present: $leaked"
# Symbols defined by test-only objects and by no core object of the test build.
tsyms=$(find "$TST_DIR" \( -name '*selftest*.o' -o -name 'fault_triggers*.o' \) -exec nm {} + |
  awk 'NF == 3 && $2 ~ /[TtDdBbRr]/ { print $3 }' | sort -u)
csyms=$(find "$TST_DIR" -name '*.o' ! -name '*selftest*' ! -name 'fault_triggers*' -exec nm {} + |
  awk 'NF == 3 { print $3 }' | sort -u)
only=$(printf '%s\n' "$tsyms" | grep -vxF "$csyms")
n=$(printf '%s\n' "$only" | grep -c .)
in_test=$(nm "$ELF" | awk '{ print $3 }' | sort -u | grep -cxF "$only")
in_rel=$(nm "$REL_ELF" | awk '{ print $3 }' | grep -xF "$only" | head -3)
[ "$n" -gt 40 ] && [ "$in_test" = "$n" ] && ok "test kernel: all $n test-only symbols present" ||
  bad "test kernel: $in_test of $n test-only symbols present"
[ -z "$in_rel" ] && ok "release: none of the $n test-only symbols present" || bad "release: test symbols present: $in_rel"
for pat in bv_trigger_ bv_fault_ selftest_run selftest_heap selftest_prot selftest_reclaim selftest_highmem; do
  c=$(nm "$REL_ELF" | grep -c "$pat")
  [ "$c" = 0 ] && ok "release: no $pat* symbols" || bad "release: $c $pat* symbols"
done
for s in "bv.test" "[TEST]" "fault test" "deliberate panic"; do
  t=$(strings -a "$ELF" | grep -cF "$s"); r=$(strings -a "$REL_ELF" | grep -cF "$s")
  [ "$t" -gt 0 ] && [ "$r" = 0 ] && ok "release: string '$s' absent (test kernel has $t)" ||
    bad "release: string '$s' in release $r, test $t"
done

BOOT_IMG=$REL_IMG
release_boot() { # name, [cmdline]
  name=$1
  if [ -n "${2:-}" ]; then code=$(boot "$name" -append "$2"); else code=$(boot "$name"); fi
  [ "$code" = "33" ] && ok "$name: exit status 33 (normal boot)" || bad "$name: exit status $code (want 33)"
  expect_log "$name" "[ OK ] Build: release (no test hooks)"
  expect_log "$name" "[ OK ] Paging self-check passed"
  expect_log "$name" "[ OK ] Heap self-check passed"
  expect_log "$name" "BLACKVEIL_BOOT_OK"
  expect_absent "$name" "[TEST]"
  expect_absent "$name" "BLACKVEIL_PANIC"
}
release_boot release-boot
n=release-boot
expect_log $n "[ OK ] Exception handlers: 32 vectors installed"
expect_log $n "[ OK ] W^X: code read-only, data, stacks and free RAM non-executable (EFER.NXE)"
expect_log $n "[ OK ] Guard pages: null page, boot stack and 3 emergency stacks"
expect_log $n "[ OK ] Write protection: kernel code, read-only data, boot data, page tables and allocator metadata (CR0.WP)"
expect_log $n "[ OK ] Allocator metadata: read-only, consistency check passed"
expect_log $n "[ OK ] Heap: 0xffffb00000000000 - 0xffffb00040000000, read/write, no-execute, grows on demand"
expect_absent $n "[WARN]"
release_boot release-bv-panic "bv.test=panic"
release_boot release-bv-pf "bv.test=pf"
release_boot release-bv-df "quiet bv.test=df"
release_boot release-bv-heap "bv.test=heap-overrun"
release_boot release-bv-reclaim "bv.test=reclaim-stale"
release_boot release-bv-unknown "bv.test=no-such-test"

echo
echo "boot tests: $PASS passed, $FAIL failed (logs in build/test-logs)"
[ "$FAIL" -eq 0 ]
