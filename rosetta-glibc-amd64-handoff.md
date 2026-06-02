# Rosetta glibc `linux/amd64` — bring-up handoff

Branch: `feat/rosetta-glibc-amd64` (off `main`). Design/plan:
`docs/superpowers/specs/2026-06-01-rosetta-glibc-amd64-design.md`,
`docs/superpowers/plans/2026-06-01-rosetta-glibc-amd64.md`.

## Status: Phase 1 COMPLETE ✅ · Phase 2 fork+signal blockers RESOLVED ✅

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
- **(R, carrick high-VA alias bug, OPEN — needs robust fix) syscall writes to an
  mmap'd buffer land at the wrong backing.** Symptom: `cat -n` (any `cat` option)
  emits the line number then NUL bytes instead of the line body; dash misparses
  `/usr/bin/gunzip`. **Confirmed carrick's, not Apple's:** the SAME ubuntu `cat`
  under Docker's Rosetta is correct — only carrick corrupts it. **Localized:**
  forcing glibc to brk (`MALLOC_MMAP_THRESHOLD_=big`) FIXES `cat -n`; the bug only
  hits buffers glibc serves via `mmap` (high-VA alias under Rosetta x86_64). It's
  the same class as the `uname`-NUL bug: carrick's `read()` writes the file bytes
  via `mapping_for_range_mut` (VA→region, linear `host_addr + (va - start)`,
  newest-first), but the guest reads via its stage-1 page tables (VA→IPA→host).
  When those disagree the guest reads zeros. **Direct measurement** (CARRICK_ALIAS_DEBUG
  diag, now reverted): cat's inbuf `0x7fffff525000` is in alias region B
  (`start=0x7fffff524000 ipa=0x1821000000`), but region A
  (`start=0x7fffff482000 len=0xa2000`) had `end = va + hostsize` where hostsize is
  the 16 KiB-rounded `0xa4000` — so A's `end` over-claimed 8 KiB into B's VA span,
  and newest-first picked A. The guest's stage-1 (leaf IPA `0x1821001000`) pointed
  to B. **A one-line fix** (`end: va + len`, exact stage-1 coverage) FIXES `cat -n`
  but REGRESSES `tac` (`seq 1 100000 | tac | head -1` → 8635 not 100000), so it is
  NOT safe — `tac` exposes a second facet of the same VA→host-vs-stage-1 mismatch.
  **The robust fix** is to resolve syscall memory access through the guest's actual
  stage-1 walk (VA→IPA, then IPA→host by the region owning that IPA), instead of
  the linear `region.start..end` heuristic — guaranteeing carrick reads/writes
  exactly where the guest does, for overlaps, 16 KiB rounding, and the non-linear
  static Rosetta window alike. That is a meaty, hot-path change deferred for its
  own careful cycle. (The trivial `end: va + len` change is captured here but was
  reverted because of the `tac` regression.)
- **(syscall workstream, not Rosetta layer) `FUTEX_LOCK_PI_PRIVATE` → ENOSYS.**
  `grep` aborts with `rosetta error: futex(FUTEX_LOCK_PI_PRIVATE) failure: 38`;
  the Rosetta runtime needs priority-inheritance futexes. carrick returns ENOSYS.
- **(network, deferred) apt secure verify.** `apt-get update` reaches the archive
  and downloads InRelease, but gpgv-under-Rosetta yields `GOODSIG` with no
  `VALIDSIG` line → apt "Good signature, but could not determine key fingerprint".
  Native arm64 verifies fine. `ls -la /` ENODATA is likewise a host-fs/getdents
  path matter, not the Rosetta translation layer.

## Remaining plan (Rosetta layer)
- Localize and fix (R) `cat -n`/dash divergence (trace skill).
- Lock-in tests: the fork-restore + rt_sigreturn fixes, plus the high-VA over-map
  and overlap fixes (assert `mapping_for_range` returns the newest overlapping
  region; a sub-16 KiB high-VA mmap doesn't perturb a neighbour's L3 entries).
- Self-skipping `linux/amd64` conformance lane in
  `crates/carrick-cli/tests/conformance.rs`; `x86_64-unknown-linux-musl` probe
  build path in `scripts/build-probes.sh`.
- Rewrite `docs/rosetta.md` ("TTBR1/upper-half is the next step" → done).

Safety: pre-rebase branch state preserved at `feat/rosetta-glibc-amd64-prerebase`.
