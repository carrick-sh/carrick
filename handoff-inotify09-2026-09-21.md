# Carrick conformance handoff — 2026-09-21

User requested wrapping up so another session can finish. The thread goal is
paused, not complete. Resume only in the next authorized session. No new
experiments or jobs remain running from this session. Nothing was pushed.

## Objective (unchanged)

Autonomously achieve Carrick conformance parity on the canonical macOS/HVF ARM64
lane: fix demonstrated semantic and structural contract failures using VM-free
reductions, preserve Linux authority and unchanged budgets, and complete signed
probe -> smoke -> full conformance gates with exact artifact provenance and
scoped cleanup. Include the frozen 2,127-suite core-emulation denominator and
the <=2x Docker performance requirement; do not count skips, known gaps, retries,
or incomplete observations as parity. Production fixes are authorized; preserve
unrelated work and do not push.

## Start here

Worktree: `/Volumes/CaseSensitive/carrick`, branch `main`.
Last implementation/evidence commit before this handoff: `97377eb64`.
Read `AGENTS.md`, the conformance-contract, carrick-trace and ltp-conformance
skills, and `docs/perf-results/2026-09-20-hvpatch-syscall-portal/assessment.md`.
The assessment preserves the actual sequence and rejected alternatives; do not
restart already-completed profiling or conclude that time in Vcpu::run is pure
trap overhead. The older sections of `handoff.md` retain the full closure scope
but their August checkpoint is stale; this handoff supersedes that checkpoint.

## Main conclusion and next work

The existing clean-room `perf_inotify09_scale` now has `write-seek-only`, built
from the same source for macOS and Linux. At scale 65,536, 21 complete samples:

| Uninstrumented write(64) + lseek(0), p50 ns/iteration | Cost |
| --- | ---: |
| native macOS | 1,193 |
| Carrick | 5,326 |
| native ARM64 Docker | 449 |

Carrick/Linux is 11.86x; Carrick/native macOS is 4.46x. The direct native macOS
sequence itself costs 2.66x Linux. This is a diagnostic control, not a hardware
lower bound and not an excuse to weaken the Linux target. Merely shaving host
dispatch cannot reach 2x for this measured sequence. Next isolate native
`pwrite(fd, ..., 0)` versus write+seek on the same workload before choosing an
architecture that reduces host I/O work and crossings. The component's file
offset/dup/fork/append/sparse/rlimit authority must remain correct; do not deploy
an offset cache without contracts and exact ownership. Use structs/typed ABI,
not raw byte offsets. Do not reintroduce the rejected portal/default changes.

This is the next investigation, not a measured pwrite result or an approved
claim that a particular fast path works. Seek a large shared-mechanism fix;
the last micro-optimization was only about 1% and is not the main answer.

## Recent commits and impact

- `ccc42d7ad`: reuse owned inode identity for sparse-write bookkeeping; removed
  hundreds of thousands of redundant fstats in the diagnostic. Previous
  write/seek measurement improved about 7%; full inotify09 still timed out.
- `aea6ecb76`: reconciled service timing and native Linux bpftrace baseline.
- `25415c7b7`: CPU attribution evidence and explicit limits.
- `e11b87dbf`: restored live-oracle public probe gate for the pre-fix artifact.
- `4d8f0ac7e`: defer syscall trace task/MM identity resolution until USDT enabled.
  Regression was red (one resolution instead of zero), then green; all 83
  observability tests and 24 VM-free kernel-example contracts passed. Balanced
  uninstrumented ABBA: 2 warmup + 20 measured blocks, 40 samples/artifact,
  after/before median block ratio 0.989704, bootstrap 95% CI [0.982084, 0.992882].
  Signed enabled trace reconciled 512,636 services, no open windows/join errors.
- `97377eb64`: native macOS control mode and new artifact's public probe receipt.
  Non-Linux invocation without write-seek-only fails before Linux syscall
  numbers execute; that negative control passed. All final control runs passed.

## Current artifact and gate evidence

`target/release/carrick` was built with `RUSTC_WRAPPER= just build` from e11b87dbf
plus the production changes now committed in 4d8f0ac7e. Later commits change
only diagnostics/docs; no later runtime relink occurred.

- SHA-256: `a05fb6c4c3dfb6329ff4195f29d86109a8a82e99d1cfda848f450b2bb768d424`
- CDHash: `2a51964d55bf3a0e86c6a9b8c56d9eba839bf757`
- LC_UUID: `4E80856F-613E-3B8E-97BF-DC6FFAD483AD`
- Hypervisor entitlement and `__dof_carrick` verified.
- Pinned image: `localhost:5050/ltp@sha256:bc75ded40c5827f2ec9e1891edc23b988beae3f428f5be2c8fd7e3ee52fee80b`

`RUSTC_WRAPPER= CARRICK_RUN_ID=lazy-service-probes just --no-deps conformance-probes`
completed exit 0 on this exact CLI: all three generic shards, dedicated signed
scenarios, negative entitlement controls and CLI contract passed. Retained
ARM64 probes: 33 musl and 33 GNU PASS rows. GNU retained results are report-only
in this public recipe; strict closure mode was NOT run. Remaining AMD64
report-only diffs/skips are outside the canonical lane. Do not call all-arch
parity from this run. The performance-only probe source was edited during the
gate; no runtime/conformance source was changed or CLI relinked during it.

Committed evidence under `docs/perf-results/2026-09-20-hvpatch-syscall-portal/`:

- `lazy-service-probes.json` and `lazy-service-{generic,dedicated}-signed-artifacts.jsonl`
- `lazy-service-abba.jsonl`, `lazy-service-traced.trace`, `lazy-service-traced.json`
- `write-seek-controls.json` and `write-seek-control-{macos,carrick,docker}.{out,err}`
- `inotify-linux-service-time.{out,err}`, `inotify-accounting-drained.{trace,json}`

Full local public-gate log:
`target/perf/inotify-sustained/lazy-service-probes.log` (SHA in committed receipt).
Source/probe hashes, full commands and row completeness are in the control JSON.
Scoped cleanup found zero processes for lazy-service-probes, its -cli scope,
lazy-service-traced, lazy-service-before, write-seek-final-carrick and
write-seek-control-carrick; ABBA subprocesses all completed and no matching
ABBA guest remained. Do not poll old session handles; all are terminal.

## What remains unproven / failed

- Full inotify09 last measured on the prior runtime: >40s declared budget versus
  fresh Docker ~5.75s. No full-test performance closure on the new artifact.
- Strict probe closure, frozen 2,127-suite closure, smoke/full promotion and
  <=2x performance are NOT complete. The known >=10x component remains a
  correctness pathology, so a public probe pass alone cannot promote parity.
- Final broad `just ci` is not newly completed on this checkpoint. No push.
- Current public-probe success does not transfer to any subsequent relink.
- Mailbox transport improved dispatch ~10%, but stdio/pipe guards failed its
  promotion criteria; default remains unchanged. Earlier helper portal was
  slower and exposed cancellation issues; it was reverted. See assessment.
- EL1 raw pid/tid/time paths already beat Linux in the measured probe. Invalid
  lseek is the actual host-dispatch floor; do not use getpid as a trap metric.
- CPU samples in Vcpu::run include guest spinning/execution. Installed KDKs
  (27.0) do not match running macOS kernel 27.2; unresolved kernel PCs cannot
  be named using those symbols.

## Diagnostic tools and constraints

- `scripts/dtrace/hvpatch-inotify09-hotpath.d`: admit 8s, drain 2s; aggregates
  totals rather than racy global increments. Retain nonzero inactive TLS state.
- `scripts/perf/inotify-service-report.py`: rejects joins/open windows/count
  mismatch. Four validator tests pass. Service CPU excludes VM transition time.
- `scripts/bpftrace/inotify-service-time.bt`: qualified bpftrace 0.20.2 inside
  native ARM64 Docker. ~12 million selected syscall pairs reconciled; Linux
  inotify09 passed. Linux elapsed time cannot be subtracted from Darwin CPU time.
- Docker had been stopped; launching Docker restored it. Recheck availability.
- Never overlap Carrick guest and Docker oracle phases. Avoid performance
  measurements during builds/gates. `RUSTC_WRAPPER=` avoids sccache issues;
  macOS DTrace header generation needs the normal escalated execution context.
- Linux perf probes build in `conformance-probes` with cargo --target
  aarch64-unknown-linux-musl. Native control uses aarch64-apple-darwin. Both
  final source and binary identities are recorded; do not reuse stale binaries.

## Preserve unrelated work

These three untracked files predate this work; do not stage/delete them:

- `docs/superpowers/plans/2026-09-13-loopback-tcp-correctness.md`
- `docs/superpowers/plans/2026-09-13-partial-dontfork.md`
- `docs/superpowers/plans/2026-09-13-user-resolution-startup.md`
