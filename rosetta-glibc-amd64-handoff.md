# Rosetta glibc `linux/amd64` — bring-up handoff

Branch: `feat/rosetta-glibc-amd64` (off `main`). Design/plan:
`docs/superpowers/specs/2026-06-01-rosetta-glibc-amd64-design.md`,
`docs/superpowers/plans/2026-06-01-rosetta-glibc-amd64.md`.

## Status: Phase 1 COMPLETE ✅ · fork+signal + high-VA alias bugs RESOLVED ✅

`carrick run --platform linux/amd64 --fs host {debian:stable,ubuntu:24.04} /bin/uname -m`
→ **`x86_64`**, exit 0. arm64 → `aarch64`. amd64 `/bin/sh` pipelines that fork
(SIGCHLD) and trap signals now run cleanly. Rebased onto current `origin/main`.
carrick-hvf/abi/mem unit tests green; no new no-panic-gate clippy violations.
See the "Phase 2 — session 2 update" section below for details and open items.

12 commits on the branch (2 docs + 10 code). The unmerged `feat/rosetta-ttbr1`
layer is re-ported onto current `main` (trap.rs→carrick-hvf, PageTableManager→
carrick-mem, signal subsystem rewritten), then two real bugs in the high-VA alias
path — invisible on `main` because it boots TTBR0-only — were found and fixed.

### The re-port (Tasks 1–9, committed)
CarrickSigframe→Linux rt_sigframe (siginfo@0); `uname`→x86_64; `getrlimit(163)`;
16-bit pointer-tag strip; TTBR1 upper-half enablement (both bring-up sites);
EL0 feature-ID MRS emulation; `esr_context` in fault frames; high-VA mmap→
`MapHostAlias`; alias/identity L0 collision guard. (`rt_tgsigqueueinfo(240)` and
SCTLR UCI/UCT/DZE were already on `main` — dropped.)

### The two bugs found at the gate (committed fixes)
1. **Stage-1 over-map** (`66ab084`): the high-VA `MapHostAlias` path mapped a
   16 KiB-rounded length in stage-1, so a sub-16 KiB mmap mapped extra 4 KiB
   guest pages, clobbering an ADJACENT region's L3 entries and redirecting its
   fetches to the wrong IPA → guest fetched undefined instructions (EC=0) from
   freshly-JIT'd code, abort ~70 syscalls in. Fix: stage-1 maps the exact
   page-aligned `length`; `hv_vm_map`'s 16 KiB granule is rounded separately in
   `map_host_alias` (carrick-hvf/src/trap.rs).
2. **Overlap resolution** (`f61c5f1`): a MAP_FIXED high-VA mmap overlaying an
   earlier mapping pushes a new `HvfMappedRegion` without removing the old one;
   `mapping_for_range` used `.find` (first match) and returned the STALE region,
   while the guest's stage-1 points to the overlay. Syscall reads of high-VA
   buffers read a zeroed older backing (`uname` stdout came out as 7 NUL bytes).
   Fix: resolve NEWEST-first (reverse iteration).

### Investigation notes (so the next session doesn't re-derive)
Disproven by direct measurement: hardware TSO not engaging (`ACTLR_EL1.EnTSO`
flips 0→1 at the `prctl` and stays set); null-`x18` (stable `0xfffffeebc9` at
every syscall — the `vcpu-fault-regs` `xRn` is the documented unreliable read).
Proven via a `BRK`-marker write to the alias backing: the guest's instruction
fetch resolved to a DIFFERENT physical page than carrick's `read_guest_bytes`
(→ the stage-1/stage-2 split above), not I-cache staleness (a host
`sys_icache_invalidate` of the correct backing did nothing). Use the project's
`.agents/skills/carrick-trace` skill; `carrick trace` auto-sudos (NOPASSWD now
set for the binary path + `/usr/sbin/dtrace`). `CARRICK_TRACE_TRAPS=1` and
`CARRICK_TRACE_REGS=1`/`CARRICK_FAULT_DEBUG=1` are useful env gates. Always set
a unique `CARRICK_RUN_ID` and reap only your own guests.

## Phase 2 (workload ladder) — session 2 update

Rebased onto current `origin/main` (post-procfs; was force-updated). One conflict
(`uname` in `dispatch/proc.rs`): merged main's runtime-resolved nodename with the
Rosetta x86_64 machine string — added `LinuxUtsname::carrick_x86_64_with_nodename`
so amd64 `uname -a` now reports both (`… x86_64 …`, nodename = host short name).
Branch builds + signs clean; carrick-hvf/abi/mem tests green. (5 carrick-runtime
integration failures are all pre-existing on `origin/main` — io_blocking_guard,
capget/capset, syscall_table manifest, and main's new procfs surface test — none
in the Rosetta layer.)

### Both rung-1 blockers RESOLVED (committed)
- **fork TTBR1/ACTLR restore** (`fix(rosetta/fork)`): `VcpuSnapshot` captured
  `TTBR0_EL1` but not `TTBR1_EL1`/`ACTLR_EL1`. A fork/clone rebuilds the vCPU from
  the snapshot, so the post-fork guest lost the x86-64 upper-half root (TTBR1
  walked from base 0 → high-VA faults/garbage) and hardware TSO (EnTSO). Capture +
  restore both after TTBR0 in `restore_vcpu` and `restore_vcpu_thread_start`.
- **rt_sigreturn from `uc_mcontext` at SP** (`fix(rosetta/signal)`): the old
  private-magic gate rejected every Rosetta signal return. Measured root cause:
  carrick injects (e.g. SIGCHLD), Rosetta runs the x86 handler out of carrick's
  frame, then rebuilds a FRESH standard AArch64 `rt_sigframe` at a new SP
  (observed SP = inject base + 0x140, valid siginfo at SP+0) and rt_sigreturns
  through THAT — carrick's private magic is absent (and the original frame
  overwritten). Fix: restore from `ucontext.uc_mcontext` at SP exactly as the
  kernel does, validating the resume PSTATE targets EL0 (the load-bearing half of
  `valid_user_regs`) instead of the magic. Native AArch64 unaffected.

### Correctness battery (amd64 Rosetta vs arm64 native, ubuntu:24.04, no network)
11 of 12 byte-identical to native arm64: 64-bit arith, awk/perl sums, sha256,
numeric sort, **fork+exec ×200** (exercises the fork fix), **SIGUSR1 trap+handler**
(exercises rt_sigreturn), 2M-element perl alloc (high-VA mmap), deep pipes,
base64 round-trip, `wc -c`/`wc -l`. The translation core is sound.

### Open items
- **(R, FIXED — commit `fix(rosetta/mem): resolve high-VA alias syscall buffers by
  stage-1 IPA`) syscall writes to an mmap'd buffer landed at the wrong backing.**
  `cat -n` (any `cat` option) emitted the line number then NUL bytes; `tr`/`cut`/
  `nl`/plain `cat` were fine. Confirmed carrick's (Docker's Rosetta is correct) and
  localized to glibc-`mmap`'d (high-VA alias) buffers (forcing brk worked). Root
  cause: alias regions overlap by VA because `HvfMappedRegion.end = va + host_size`
  and the host size is rounded up to the 16 KiB HVF granule while stage-1 maps only
  the exact `len` — so `mapping_for_range`'s newest-first VA scan could pick a
  region the guest's stage-1 does NOT use (measured: cat's inbuf `0x7fffff525000`
  resolved to region A whose rounded `end` over-claimed region B, whose stage-1
  leaf IPA `0x1821001000` the guest actually used). Fix: for high-VA, prefer the
  region whose `hv_vm_map`'d IPA window owns the guest's OWN stage-1 translation
  (`PageTableManager::translate`), fallback to the VA scan when stage-1 has no
  entry (early boot). Low-VA fast path untouched. The full amd64-vs-arm64 battery
  is 11/12 (cat/tac/grep/compute all match); unit tests added.
- **(G, carrick bug, OPEN — separate from R) dash misparses a long parser TOKEN
  (>~1340 bytes) under carrick.** A long quoted string → "unterminated quoted
  string" (so `gunzip` and any `#!/bin/sh` wrapper with a long quoted block break);
  a long UNQUOTED token → dash silently misparses (swallows the rest of the input,
  runs a corrupted assignment, exits 0 with no `echo` output). **Precisely
  characterized:**
  - Confirmed carrick's, not Apple's (Docker's Rosetta parses both fine).
  - NOT the (R) alias class: forcing brk (`MALLOC_MMAP_THRESHOLD_`) does NOT fix it.
  - NOT a read bug: file content is byte-correct (md5 + reads at offset
    0/1024/2048 match arm64; `dd bs=8192/4096/1024/512/100` all return the full
    file — a single large `read()` does not truncate).
  - NOT a crash/fault: `CARRICK_FAULT_DEBUG` shows no guest fault; dash exits 0.
  - NOT quote- or newline-specific: a long SINGLE-LINE quote fails; an unquoted
    token fails; the failure tracks TOKEN LENGTH, not lines or input refills.
  - Threshold (single-line quoted, all `a`): N≤1320 OK and intact (`${#q}`==N);
    N≈1340 silently empty; N≥1350 "unterminated". dash's accumulation is correct
    up to 1300, so the corruption is at the parser-buffer GROW around ~1340 B.
  So it is a carrick-specific correctness defect in dash's token/string
  accumulation as its parse buffer grows past ~1340 bytes — no fault, no bad read,
  guest-internal (dash writes the buffer and reads it back), Docker-correct.
  Suspects: dash's `growstackblock` realloc-move interacting with how carrick
  faults in / maps the grown pages, or a Rosetta JIT path for the accumulation
  loop steered by carrick's emulated EL0 CPU-ID/cache regs (Task 7). Pinning it
  needs a WORKING `carrick trace` (the `-o` file came back empty here — a tooling/
  env issue to resolve) or a dash built with instrumentation, watching the
  parser-buffer grow at the ~1340 B boundary.
- **(syscall workstream, not Rosetta layer) `FUTEX_LOCK_PI_PRIVATE` → ENOSYS.**
  `grep` aborts with `rosetta error: futex(FUTEX_LOCK_PI_PRIVATE) failure: 38`;
  the Rosetta runtime needs priority-inheritance futexes. carrick returns ENOSYS.
- **(network, deferred) apt secure verify.** `apt-get update` reaches the archive
  and downloads InRelease, but gpgv-under-Rosetta yields `GOODSIG` with no
  `VALIDSIG` line → apt "Good signature, but could not determine key fingerprint".
  Native arm64 verifies fine. `ls -la /` ENODATA is likewise a host-fs/getdents
  path matter, not the Rosetta translation layer.

## Remaining plan (Rosetta layer)
- Localize and fix (G) the dash long-quoted-string parse bug (trace skill).
- Lock-in tests: the fork-restore + rt_sigreturn fixes, plus the high-VA over-map
  and overlap fixes (assert `mapping_for_range` returns the newest overlapping
  region; a sub-16 KiB high-VA mmap doesn't perturb a neighbour's L3 entries).
- Self-skipping `linux/amd64` conformance lane in
  `crates/carrick-cli/tests/conformance.rs`; `x86_64-unknown-linux-musl` probe
  build path in `scripts/build-probes.sh`.
- Rewrite `docs/rosetta.md` ("TTBR1/upper-half is the next step" → done).

Safety: pre-rebase branch state preserved at `feat/rosetta-glibc-amd64-prerebase`.
