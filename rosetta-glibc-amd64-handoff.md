# Rosetta glibc `linux/amd64` — bring-up handoff

Branch: `feat/rosetta-glibc-amd64` (off `main`). Design/plan:
`docs/superpowers/specs/2026-06-01-rosetta-glibc-amd64-design.md`,
`docs/superpowers/plans/2026-06-01-rosetta-glibc-amd64.md`.

## Status: Phase 1 COMPLETE ✅

`carrick run --platform linux/amd64 --fs host {debian:stable,ubuntu:24.04} /bin/uname -m`
→ **`x86_64`**, exit 0. arm64 → `aarch64`. All host unit tests green (363/0).
Clippy: no new no-panic-gate violations (carrick-runtime stays at its 4 pre-existing).

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

## Phase 2 (workload ladder) — IN PROGRESS

Rung 0 (`uname`) ✅. Rung 1 (`/bin/sh` pipeline) partially works:
`sh -c 'ls -la / | wc -l'` forks/execs/pipes correctly (`wc` counts 23) and
`echo`/`id -u` produce correct output — but two issues:

- **(A) `ls` `ENODATA` on `/` entries.** `ls -la /` prints `/: No data available`
  (errno 61) for some directory entries — a getdents/`statx`/listxattr gap on the
  host-fs backend under the amd64 path. Non-fatal (the pipeline still produced a
  count). Trace `newfstatat`/`statx`/`getdents64`/`listxattr` returns on `/`.
- **(B) `rt_sigreturn: bad sigframe magic` (BLOCKER).** A fork→`SIGCHLD` (or the
  shell's exit-path signal) triggers signal delivery; on `rt_sigreturn` (139)
  `restore_from_sigframe` reads `frame.magic` = `0x7ff` ≠ `CARRICK_SIGFRAME_MAGIC`
  at `SP_EL0`. The program's OUTPUT is correct before this; the failure is in
  signal cleanup. `inject_signal` writes the full `CarrickSigframe` at `new_sp`,
  sets `SP_EL0=new_sp`, and `x1`/`x2` via `offset_of!` — so the reorder is
  offset_of-consistent and `restore` decodes the same struct. The magic mismatch
  therefore means the frame at `rt_sigreturn`'s SP is NOT carrick's frame:
  suspect Rosetta's own signal-frame emulation (it runs the x86 handler from
  carrick's AArch64 frame, then `rt_sigreturn`s) — SP or the carrick-private tail
  may differ. **Next step:** trace `signal-inject`'s `new_sp` vs the SP at the
  `139` trap (and dump the frame bytes at both) to see whether Rosetta moved SP
  or rebuilt the frame; then make carrick's frame identification survive Rosetta's
  signal path (e.g. validate/locate the frame independent of a fixed magic-at-SP,
  or anchor on the saved-PC/ucontext Rosetta preserves). uname doesn't fork → no
  signal → it never hit this; the pipeline does.

## Remaining plan
- Phase 2 rungs: fix (A)+(B); then `python3` (use a glibc python image, e.g.
  `python:3.12-slim`), `python3 -m http.server`, `apt-get install`.
- Phase 3: Rosetta unit tests (redirect-argv, ioctl-handshake, platform
  round-trip); the high-VA over-map + overlap fixes deserve unit tests too
  (e.g. assert `mapping_for_range` returns the newest overlapping region, and a
  sub-16 KiB high-VA mmap doesn't perturb a neighbour's L3 entries); the
  self-skipping `linux/amd64` conformance lane in
  `crates/carrick-cli/tests/conformance.rs`; the `x86_64-unknown-linux-musl`
  probe build path in `scripts/build-probes.sh`.
- Phase 4: rewrite `docs/rosetta.md` ("TTBR1/upper-half is the next step" → done).
