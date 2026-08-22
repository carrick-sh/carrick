# HVPatch Fork Lifecycle Closure — Design

**Date:** 2026-08-22
**Lane:** macOS / Apple Silicon / HVF / HVPatch, Linux arm64 guest (canonical)
**Supersedes nothing.** Task 7 and Task 8 of
`docs/superpowers/plans/2026-08-20-hvpatch-kernel-mn-executors.md` are absorbed
into this design's Phase 1 and Phase 3; that plan's Tasks 1-6 stay as landed.

---

## Problem

HVPatch process fork is broken on the default path, and the gates that should
have caught it were not gating.

Four defects were found on the fork/exec path on 2026-08-21/22. Three are fixed;
the fourth is open. All four are invisible with exactly ONE live Linux process
and deterministic with two — the blind spot `docs/identity-and-scope-domains.md`
names. Every Task 6 receipt was a single-process `run-elf --raw` fixture, so the
battery structurally could not have caught them.

| # | Defect | State |
|---|---|---|
| 1 | vfork/`CLONE_VM` child's `execve` died past its point of no return on an empty-vs-absent retirement transaction | FIXED `f96aabdd4` |
| 2 | Every forked PROCESS aborted the carrier: `cow_deferred_publications` fell through `..Default::default()` to `None` | FIXED `8709213ce` |
| 3 | A forked process's stage-2 extent was released twice: fork parked its lease in a holder with zero readers, and retirement's fallback released it anyway | FIXED `84e385655` |
| 4 | A forked child's MM inventory authority never leaves `Active`, so its drop aborts the carrier | OPEN — authority transition wired in `d0ed04105` but **not reached**; the child's terminal does not run |

Two further breakages, independent of the above:

- **vfork+exec teardown.** Guest output is correct but persistent-executor pool
  shutdown fails in two timing-dependent shapes — a stale dormant binding
  (`fail_blocked_exact` → `UnknownThread` for a binding whose Thread was already
  reaped) and `EL0Fault during scoped EL1 ASID maintenance`. `carrick run
  ubuntu:24.04 --raw --fs host /bin/sh -c '/bin/echo hi'` prints `hi` and exits
  **125**.
- **The gates were not gating.** `just ci` died at clippy, so lint-domains,
  deny, check-matrix, check, doc, test and test-integration never ran
  (fixed `4acd8cc9f`). Behind it sat a SECOND red gate, `lint-domains`, whose
  host-authority census reports 4 genuinely unreviewed host-thread uses added by
  the persistent-executor campaign. Separately, two probes (`waitidsiuid`,
  `mqnotifycrossproc`) had no built binaries in either arm64 lane and were being
  silently skipped, because the ordinary probe gate treats a missing binary as
  `SKIP` and still returns green.

### Root shape

`ExecutionBackend` (`crates/carrick-runtime/src/page_profile.rs:14-19`) is a
**single-variant enum**. Every "is this HVPatch?" test is therefore a tautology,
and `launch_vcpu_until_exit` (`vcpu_loop/mod.rs:8276`) returns unconditionally at
its first statement — making ~2,900 lines unreachable. That dead region is not
merely dead: it held a live responsibility. Defect 4's investigation first
mis-read process inventory retirement as living only there, and the real gap
turned out to be a state-machine transition with zero callers. A codebase where
half the paths are a mirage cannot be debugged reliably.

---

## Goal

Make the HVPatch kernel's process lifecycle correct on ONE honest code path:
retire the dead execution model, fix fork and exec teardown, and restore every
gate to actually gating.

Complete only when all five hold together on ONE signed artifact:

1. **One execution path.** `ExecutionBackend` gone as a single-variant enum; the
   welded-thread loop, transitional runner pool and `CompatibilityThreadWaiter`
   deleted; every `include_str!` gate that asserts deleted text is PRESENT is
   inverted to assert it is ABSENT.
2. **fork-then-exit correct.** A forked child completes teardown: its MM
   inventory authority reaches `Retired`, its stage-2 extents release exactly
   once, and it does not outlive its parent's exit. The 15 blocked probes pass.
3. **vfork+exec correct.** The `/bin/sh -c` reducer exits **0**; both shutdown
   shapes gone.
4. **`just ci` green end to end**, exit status read from a FILE not a pipe,
   including `lint-domains` with the census reconciled by reviewing or
   eliminating what survives deletion — never a bulk re-bless.
5. **Probe gate green in CLOSURE mode** (`just conformance-probes-closure`),
   which rejects skips, so "all probes ran" is proven rather than assumed.

### Out of scope

Stated so it cannot creep in: non-macOS hardware lanes (bsdvm, KVM smoke); the
2,127-suite full conformance closure; all performance work. The standing
2.0x-of-Docker objective in `handoff.md` is untouched and unstarted by this goal.

### Non-negotiables

No probe blessed to green. No excuse rows. No default-off mechanism introduced.
Every fix red-first, with the reducer proven against the broken binary. Every
"fixed" claim attributed against unmodified HEAD before it counts.

---

## Approach

Three phases with DIFFERENT execution models, because the constraint that
governs this work is that **guest runs cannot be parallelized**. Concurrent
carrick lanes and Docker starve each other and produce wrong verdicts; sibling
agents running guests have already cost this project hours of misattributed
failures. Fan-out is therefore safe for compile/edit work and unsafe for
anything that boots a guest.

### Phase 1 — Collapse (SOLO, one head)

Delete `ExecutionBackend` and `persistent_hvf_vm_lifecycle`
(`runtime.rs:902`), then follow the compiler through the 52 comparison sites and
8 negative guards. Doing this FIRST is the point: it converts "this code is
unreachable" from an assertion into a build failure, so any live responsibility
still hiding inside dead code surfaces as a broken build rather than a runtime
abort.

Then delete what the compiler proves orphaned:

| Item | Location | Approx. lines |
|---|---|---|
| tail of `launch_vcpu_until_exit` | `vcpu_loop/mod.rs:8292-8384` | 93 |
| `run_vcpu_until_exit` + `_inner` | `vcpu_loop/mod.rs:8942-10723` | 1,781 |
| `handle_fork` (real `libc::fork`) | `vcpu_loop/quiesce.rs:445-1176` | 732 |
| `suspend_hvpatch_continuation` | `vcpu_loop/mod.rs:6448-6685` | 238 |
| `yield_hvpatch_quantum` | `vcpu_loop/mod.rs:6686-6817` | 132 |
| `launch_compatibility_vcpu_future` | `vcpu_loop/mod.rs:8233-8253` | 21 |
| `prepare_initial_runner_handoff` | `vcpu_loop/mod.rs:8821-8921` | 101 |
| `OwnerThreadEngine` | `vcpu_loop/mod.rs:2293-2345` | 53 |
| `TransitionalDedicatedRunner` cluster | `vcpu_loop/continuation.rs:3273-4126` | ~850 + ~4,000 test |
| `CompatibilityThreadWaiter` | `vcpu_loop/mod.rs:2217-2233` | 17 |
| `VcpuThreadHandle::Job` | `vcpu_loop/mod.rs:8044` | — |
| mature-VMM bootstrap branch | `threaded_loop.rs:284-312` | 29 |

Deleting the transitional runner also removes one idle host pthread per run.

**Hazard, handled in the same commits.** These gates assert the deleted text
EXISTS, via `include_str!`, and must be inverted to assert absence:
`continuation.rs` 4907, 4922, 4949, 8471, 8482, 8526, 8542; `mod.rs` 10970,
11051. This risk is live, not theoretical — a `#[cfg(all(test, ...))]` split on
2026-08-22 already broke
`hvpatch_task_only_materializers_are_structurally_vcpu_free` exactly this way.

**Deliberately NOT deleted** (verified reachable):
`should_reclaim_vcpu_for_timed_wait` (6 live call sites via
`service_threaded_syscall`), `carrick_hal::vcpu_sched` (~30 live uses),
`io_wait::ThreadWaiter` itself, and the per-guest-thread host thread at
`threads.rs:1002` (bootstrap-only but live). Those are Task 7 *migration*, not
cleanup.

Also collapse the 18 `!persistent_vm_lifecycle` branch arms in
`carrick-vmm-hvf/src/trap.rs` — the sole production setter is the tautology
above, so every negated arm is test-only. Note the constructor default is the
DEAD value (`trap.rs:4890`, `9839` initialize it `false`), which is its own
hazard: a new construction site silently inherits retired semantics.

**Exit criteria.** `cargo build` clean; `just ci` no worse than the phase-0
baseline; and the fork battery's failure SHAPES unchanged — deletion must not
alter behaviour. Any behaviour change here is a bug in the deletion.

### Phase 2 — Sweep (FANNED OUT, cheaper models acceptable)

File-disjoint, mechanical, one agent per cluster in its own worktree, one commit
each, verified by `cargo check` + `just fmt-check` only. No guests.

1. **Dead-code markers** — ~99 `allow(dead_code)` in `carrick-runtime`, 12 in
   `carrick-vmm-hvf`. Split into "promise fulfilled, delete the marker" vs
   "genuinely dead, delete the code". Largest: `namespace/pid.rs` (whole module,
   Phase 2 never landed) and `dispatch/net/unix_pure.rs` (registry constructed on
   a production path, zero reads).
2. **Retired CLI surface** — `--native-page-profile` and the
   `native16k`/`linux4k` enum values, which now exist only to be rejected.
3. **Script and doc recipes** — 8 `.d` headers and ~12 docs whose command lines
   invoke retired backends and now hard-error. Correct the HEADERS; keep the
   scripts, which are durable artifacts.
4. **Unrun test suites** — the `carrick-cli` integration suites no gate executes,
   several of which pass the now-invalid `--native-page-profile`. Wire in or
   delete; a test no gate runs is not a test.

### Phase 3 — Fix and verify (SERIALIZED, one lane)

1. **fork-then-exit.** Start from the signal already surfaced: `authoritative
   scheduler wake rejected parent=TaskKey { id: TaskId(1), serial:
   TaskSerial(6) } ... invalid from Exited`. The child outlives its parent's exit
   even though the probe's parent `wait4`s it, which says the child's TERMINAL
   never runs — not that the inventory is wrong. The authority transition wired
   in `d0ed04105` is in place and unexercised; this phase makes it execute.
2. **vfork+exec teardown**, both shutdown shapes.
3. **Census reconciliation** — re-run AFTER phase 1, since deleting the
   transitional runner removes at least one of the four unreviewed host-thread
   uses. Classify only what survives.
4. **Closing gates** — `just ci` (redirected to a file, status read from `$?`),
   then `just conformance-probes-closure`, then a fresh signed-artifact receipt:
   source HEAD, binary SHA-256, CDHash, LC_UUID, hypervisor entitlement,
   `__TEXT,__dof_carrick`, and proven scoped cleanup.

Subagents in this phase are READ-ONLY: source analysis and adversarial
verification of diagnoses. Nothing that boots a guest runs in parallel.

---

## Testing strategy

- **Red-first is mandatory.** Each defect gets a deterministic reducer proven
  against the broken binary before the fix, and re-run after. The established
  reducers: `run-elf --raw` on `forkcow`/`clonebasic` for fork-then-exit, and
  `carrick run ubuntu:24.04 --raw --fs host /bin/sh -c '/bin/echo hi'` for
  vfork+exec, with `/bin/bash -c` as the fork-not-vfork control.
- **Attribution before fixing.** Every failure is reproduced on unmodified HEAD
  in a separate worktree before it is called a regression. This already
  overturned one wrong conclusion in this investigation.
- **Unit tests at the seam that failed**, not merely at the symptom — the
  pattern that produced `validate_cow_authority_pairing` and
  `retained_old_mm_reports_no_exec_retirement_extents`.
- **Gate logs are never truncated.** `just ci | tail` reports `tail`'s status;
  redirect to a file and read `$?`. Grep gate logs with `-a` — they carry binary
  bytes.
- **Closure mode is the closing instrument.** Ordinary probe mode is not
  acceptable as the final gate: it prints `SKIP … probe not built` and returns
  green, which is exactly how two probes went unbuilt and unnoticed.

## Risks

| Risk | Mitigation |
|---|---|
| Deleting ~2,900 lines silently removes a live responsibility | Phase 1 is compiler-driven, not grep-driven; behaviour-shape parity is an explicit exit criterion |
| `include_str!` gates break silently or match the whole file after a `split()` | Inverted in the same commit as each deletion; one such break already observed |
| Parallel agents corrupt guest verdicts | Fan-out confined to phase 2; phase 3 serialized; subagents read-only |
| Census re-bless hides a real unreviewed host-thread use | Reconcile only after deletion, classify individually, never bulk-refresh |
| A "fix" is attributed to the wrong change | Reproduce on unmodified HEAD in a worktree first |
