# EL1 paused handoff — 2026-09-29

## Start here

**Execution is PAUSED at the user's requested stopping point.** This document
records the current implementation and unfinished branches; it does not authorize
resuming the migration. The goal and hourly progress monitor remain paused.
Nothing has been pushed. X86 migration and hardware qualification are explicitly
deferred by the user: “go all the way but don't do x86 for now.”

The source baseline is local main `180b8d586711c9b683337c2c96ec7e28dcad5ba5`,
clean before this documentation update. Current implementation, controller and
incorporated foundations are on main. Older unfinished branches were deliberately
excluded at the user's direction. Their presence is not an instruction to merge
them. No checkpoint or end-to-end migration completion is claimed.

Use main's [completion controller](2026-09-26-el1-completion.md),
[accepted design](../specs/2026-09-24-el1-kernel.md), and
[stopping receipt](../../perf-results/2026-09-29-el1-memory-integration/stopping-point.md).
The old `.worktrees/EL1-HANDOFF-2026-09-29.md` and controllers in older worktrees
are historical. This document and the current controller supersede their status,
ordering and x86 instructions. Historical “next” instructions do not override the
pause.

## What reached main, and what the evidence proves

Main includes adapter `0c8204e11`, controller/lifecycle `66b1a21d4`, integration
merge `c90ce118e`, inventory-position commit `4d3484cc2`, and stopping receipt
`180b8d586`. Incorporated work includes memory ownership foundations, IPC routing,
descriptor/copyout/COW caller conversions, sparse publication, slot liveness,
pgrp/ICMP fixes, generation-authenticated deferred handback and notifications.
The merge preserves IPC operation tokens through cancellation, captures exact
`RecordRef` in host wake callbacks, and unlinks waits before queue publication.

| Area | Retained evidence | Still open |
| --- | --- | --- |
| Scheduler/lifecycle integration | 80 scheduler tests passed | Full lifecycle and batch-3 acceptance |
| EL1 integration | 116 EL1 tests passed | Full checkpoint and workload acceptance |
| Runtime IPC adapters | 2 tests passed; earlier focused IPC slices retained in controller | Multiprocess blocking, complete ownership/lifetime qualification |
| Descriptor service on actual EL1 | Signed isolated-root service witness passed | Backed/two-live-MM operation, production COW/retirement, TLB workload proof and full admission |
| Build/static checks | Affected all-target Clippy and formatting passed | Domain inventory review; full CI was not run for consolidation |

The signed test was rebuilt **from main source `4d3484cc2`**, run ID
`el1-main-stop-20260929-a`, using:

```sh
scripts/test-signed.sh carrick-vmm-hvf serial_host_el1_descriptor_service --ignored --nocapture
```

It uses persistent executor bringup, the actual EL1 image and production
`EngineDrainVenue`. An unpublished MM is refused without changing the live leaf;
a published MM permits actual EL1 ForkArm to change RW to RO, with exact receipt
settlement and host edits fenced. The root backing is retained by the test.
Unentitled negative control passed and both cleanup scopes reported zero.
This is a service witness, not full COW or migration acceptance.

Executable SHA-256, CDHash, LC_UUID, entitlements and DOF are retained in
[artifact receipts](../../perf-results/2026-09-29-el1-memory-integration/main-stop-signed-artifacts.jsonl)
and the [signed log](../../perf-results/2026-09-29-el1-memory-integration/main-stop-signed.log).
`180b8d586` and this handoff change documentation only relative to the checked
product/test source. No runtime tests were rerun for this handoff.

**Domain lint is red.** Seventeen IPC abort sites lack reviewed classifications.
The inventory reconciler also refuses a retired `FileTable::install` lock row
and changed K1 mapping/description/table/lifecycle classifications. Position-only
updates and a 595-row compiler capture were retained, without blanket reblessing.
See [inventory output](../../perf-results/2026-09-29-el1-memory-integration/integration-inventories.log)
and [main lint output](../../perf-results/2026-09-29-el1-memory-integration/main-stop-lint.log).

## Resume order, when requested

1. Review the explicit inventory gaps on main and reconcile classifications on
   a clean tracked snapshot. Do not make the gate green by accepting every row.
2. Finish the remaining live descriptor writers in lifecycle groups, using the
   [writer worklist](../../perf-results/2026-09-29-el1-memory-integration/descriptor-writers.md):
   replacement/retirement; protection/unmap/alias; foreign-MM/exec. These include
   `prepare_el1_frame_grant` retirement ordering, `materialize_retired_reuse`,
   foreign sparse publication and `perform_foreign_cow_transaction`, engine
   protection/bus tags/discard/unmap/alias paths, and distinguishing offline
   root construction from live mutation/rollback.
3. Extend the bounded hardware service proof to real backing lifetime and two
   live MMs. Production admission in `crates/carrick-runtime/src/vcpu_loop/signal.rs`
   still has `host_copyout=false` and `backend_writers=false`. Do not bypass these
   guards to make a fixture pass. The isolated service proof is already done;
   avoid repeating it as a substitute for the missing integration.
4. Finish anonymous `SharedReservations` brk/mmap policy and fork/exec/exit
   ownership, then qualify pause removal and checkpoint-2 acceptance. Port useful
   ownership witnesses from the test branch below only with real observations.
5. Complete IPC/batch-3 acceptance, including the unresolved multiprocess blocking
   1/8/64 investigations. Earlier vector-eventfd and inherited-lifetime signed
   slices do not close checkpoint 3. The old broad-capture quota was exhausted;
   require a discriminating hypothesis before another broad capture.
6. Continue the controller's remaining ARM64 stages: namespace cost, remaining
   descriptors/IPC/signals, names/page cache and process lifecycle. Preserve the
   full semantics and controlled per-workload ≤2x native-Linux objective. X86
   remains deferred, not complete.

Measure progress by ownership removed from host paths and acceptance gaps closed,
not helper counts or new diagnostics. Each bounded slice should name its user
impact, decisive evidence, stop condition and next dependency. If it produces only
more instrumentation or repeats an already-proven service path, step back and
reprioritize. No new transport/framework, inflated budgets, retries until green,
polling or concurrency reduction as closure. Keep signed evidence tied to the
exact rebuilt artifact and never run Docker and Carrick guests concurrently.

## Unfinished branches preserved outside main

Paths below are relative to `/Volumes/CaseSensitive/carrick`. Heads, ancestry and
working-tree status were inspected live on 2026-09-29. Commit-message validation
claims are historical claims unless corroborated by the main receipts above.

### Ownership witnesses — `work/cp2-ownership-tests`

- Worktree: `.worktrees/wt-cp2-tests`; clean.
- Head: `45fa941243fd30791b5a6685cc4e2373ea03d47b`.
- Unmerged commits: `86b9f31e5`, `45fa94124`.
- Seven-file branch delta adds anonymous reservation/retirement, fork-COW and
  pause-free contracts, embed tests, and fixture operations. The primary files
  are `crates/carrick-embed/tests/el1_sched.rs` and
  `fixtures/embed-el1-sched/src/main.rs`.
- Deliberately unfinished: `host_cow_resolutions()` in the embed test panics with
  `dedicated host COW counter not yet available`. Host fault exits are not a
  substitute for actual host COW resolutions. These are red ownership witnesses,
  not passing migration acceptance.
- Main now contains `HostCowStats` in
  `crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs`. It still needs correct
  guest/carrier-scoped exposure to the test report; do not replace the panic with
  zero or an unrelated counter.
- Historical commit claims include 19 report-validator tests, no-run compilation,
  fmt and Clippy; they were not rerun for this handoff.
- Resume by porting useful contracts/witnesses onto current main without replacing
  its newer `el1_sched.rs`. Wire authentic scoped metrics, keep ownership failures
  red until implemented, and execute signed against the exact artifact.

### Rejected IPC fixture — `work/cp3-ipc-fixture`

- Worktree: `.worktrees/wt-cp3-fixture`; clean.
- Head/only unmerged commit: `fd27e748d80aa9efe7aac5f87f7215ca9907ba67`.
- Twelve-file delta adds seven IPC contracts, inventory/surface entries,
  `crates/carrick-embed/tests/el1_ipc.rs`, and
  `fixtures/embed-el1-sched/src/ipc.rs` plus main wiring.
- **Rejected as acceptance evidence:** guest parks/resumes and host counts are
  calculated from a feature flag and loop count; generations are fixed to 1;
  signal mode lacks signal/partial-write operations; whole-container counters
  are labeled as a steady-state window. The main controller records this review.
- Do not merge or enable these reports unchanged. Salvage useful test intent and
  contract scaffolding only after comparing with main's newer production routing,
  lifetime and mixed-venue tests. Replace synthetic observations and missing
  semantic cases; do not duplicate the current implementation.

### Unverified signal-test change — `work/rt-sigsuspend-parallel-flake`

- Worktree: `.worktrees/wt-sigsuspend`; clean.
- Head/only unmerged commit: `5011caffaa9fc34ecb07d3e3ff38d9a1caf39eba`.
- Test-only change to `crates/carrick-kernel/src/dispatch/signal.rs`, in
  `rt_sigsuspend_releases_dispatch_before_waiting`: removes the elapsed-time
  `<100ms` assertion and argues that `DispatchOutcome::WaitOnSignals` proves
  nonblocking dispatch.
- Commit is explicitly interrupted/unverified WIP. It did not establish the
  pre-change failure rate or root cause. This is not a runtime signal fix.
- Returning an expected variant after arbitrary delay does not alone prove
  dispatch did not block or retain a lock. Compare the current main test first;
  establish actual dispatch/lock-release/owned-continuation evidence before
  accepting a structural replacement. Do not treat deletion of the timing
  assertion as architectural closure. Preserve original authorship if ported.

### Inotify implementation and dirty diagnostics — `agy/el1-inotify`

- Worktree: `.worktrees/el1-inotify`.
- Head: `7eb9a6853a22ae7dff2dec8d305400c4cfc46aab`.
- Four ancestry-unmerged commits: `a62a21f6b` neutral no_std core,
  `d883dcea3` EL1 types/cache/dispatch, `482c596c2` kernel delegation/hooks,
  `7eb9a6853` contracts/embed tests/oracle results.
- **Overlap:** `git cherry main agy/el1-inotify` marks `a62a21f6b` and
  `7eb9a6853` patch-equivalent to main. Do not duplicate them. The two remaining
  commits require semantic comparison against main; ancestry alone does not
  prove every line of their implementation is absent.
- The branch's merge-base delta spans core/ABI, EL1 inotify, kernel delegation and
  notification hooks, embed tests and contracts. That delta is not a list of
  missing main features.

Uncommitted state, deliberately preserved:

| Status | File | Purpose and caveat |
| --- | --- | --- |
| Modified | `crates/carrick-kernel/src/el1_delegation.rs` | Marked `DIRECTOR DIAGNOSTIC (not for commit)`; global mutex/map counters, per-call wall-time and caller tracking around delegation/recall. Intrusive measurement overhead; not production code or fair timing evidence. |
| Untracked | `crates/carrick-embed/tests/el1_inotify09_probe.rs` | Runs actual LTP inotify09 from `localhost:5050/ltp:arm64`, prints served/forwarded and delegation diagnostics; also contains a 200000-iteration Perl watch/write/lseek/remove benchmark and getpid comparison. Depends on the dirty diagnostic hooks. |

Preserve both files before any future rebase, archival or cleanup; never stash.
Review the two unique implementation commits against current main before porting.
For performance, establish actual workload call shape and completed operation
counts, control instrumentation and host I/O, and retain native controls. Avoid
launching another broad capture campaign without a specific discriminating
question. No validation of these dirty files is claimed by this handoff.

## Already incorporated branches: do not merge again

All heads below are ancestors of main `180b8d586`; all listed worktrees are clean.
Keeping the checkout does not imply work remains unmerged. This is source
integration, not acceptance of every migration contract.

| Branch | Head | Worktree under `.worktrees/` |
| --- | --- | --- |
| `integ/batch3` | `66b1a21d4` | `wt-batch3` |
| `work/cp2-hvf-cow-adapters` | `d581dd099` | `wt-cp2-cow` |
| `work/cp2-el1-descriptor-owner` | `c555f5dd1` | `wt-cp2-descr` |
| `work/cp2-el1-reservations` | `f2efa3716` | `wt-cp2-reserve` |
| `work/cp2-elastic-return` | `8f268dee4` | `wt-cp2-return` |
| `work/cp3-ipc-adapter` | `4d3484cc2` | `wt-cp3-adapter` |
| `work/cp3-ipc-host` | `77b6f40a1` | `wt-cp3-host` |
| `work/cp3-ipc-shared-objects` | `bb93917a4` | `wt-cp3-objects` |
| `work/cp3-ipc-object-waits` | `7debfcc13` | `wt-cp3-waits` |
| `work/icmp-bind-zero-flake` | `2a097c0bd` | `wt-icmpflake` |
| `work/pgrp-snapshot-invariant` | `849e2119c` | `wt-pgrpsnap` |
| `work/slot-live-root-cause` | `1cd5071d6` | `wt-slotlive` |
| `work/syscall-return-cost` | `56f848a2b` | `wt-sysret` |

## Safe recovery checks

Run from `/Volumes/CaseSensitive/carrick`; verify live state before any mutation:

```sh
git -c core.fsmonitor=false status --short
git worktree list --porcelain
git log --oneline main..work/cp2-ownership-tests
git log --oneline main..work/cp3-ipc-fixture
git log --oneline main..work/rt-sigsuspend-parallel-flake
git cherry main agy/el1-inotify
git -C .worktrees/el1-inotify diff -- crates/carrick-kernel/src/el1_delegation.rs
git -C .worktrees/el1-inotify status --short
```

No branches, dirty diagnostics or worktrees were removed for this handoff. Main's
controller is authoritative; do not resume from the older `wt-batch3` controller.
Rebuild and sign after future product integration, review diffs rather than
worker reports, and keep unrelated work intact. Resume the goal/monitor only on
user request; retain progress updates focused on impact, upcoming dependencies
and whether the current work is becoming a rabbit hole.
