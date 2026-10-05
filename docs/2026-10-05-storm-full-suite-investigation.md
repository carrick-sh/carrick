# Full-suite fork-storm investigation on cloudmac

The reported `el1_thread_lifecycle_fork_during_clone_storm` failure did not
reproduce in **20 complete full `el1_` suite runs** on unchanged
`51bfe67f40f879c46ae506612c37e76f4867d5c7`. All 320 fork children reported
one live thread; all 20 reports had `bad=0` and `ok=true`. This is a
non-reproduction result, not closure of the historical failure. The original
batch log `51bfe67f40f8-20261005-031719` was no longer present.

Each invocation was `./scripts/test-signed.sh carrick-embed el1_ --nocapture`,
after sourcing `/Volumes/carrick/dev/env.sh`. The exact-SHA fixture bundle
was restored from the published bundle named
`6d3f91bfd6717d042ca3417c347300b9b81ac3f5737a142b0585f3ffced1949b.tar.gz`.
That filename is a bundle identity; the tarball SHA-256 is
`f413054012a9c507230f3493becea3e92a31eee68b97037a13dbf66b33b5e156`.
The host was Mac16,10, 10 CPUs, macOS 27.0.1 (26A434). No Docker or external
load was used. The director explicitly authorized the existing full-filter
oversubscription test's 15 internal burner processes; censuses in runs 2–20
found none left after that test, at fork-storm, or after scoped cleanup.
The signed runner already serializes libtest; the concurrency at issue is
inside each guest and the suite's oversubscription fixture.

## Evidence and limits

Artifacts are on cloudmac under
`/Volumes/carrick-build/wt/wt-storm/target/storm-investigation/`:

- `full-01.log` and `baseline-artifact/`: first run and artifact identity.
- `full-02/` through `full-20/`: complete `run.log`, exact signed `el1_sched`,
  SHA-256/CDHash/LC_UUID/entitlements/DOF in `identity.txt`, and timestamped
  `process-census.txt` at suite, storm, oversubscription and cleanup boundaries.
- `attempts.tsv`: machine-counted runs 2–20; run 1 is in its separate log.
- `environment.txt`: source, host and installed fixture manifest identity.
- `reproduce.rs`: the foreground repetition/capture driver. A storm lasting
  three seconds would trigger LLDB stacks, both event rings and a
  modified-memory core before cleanup. No storm reached that trigger.

All 20 suite invocations exited **1**, because six other tests failed in
every run. Run 7 had one additional intermittent futex-handoff failure.
These suite results must not be reported as passing acceptance. All scoped
runner cleanup checks reported zero remaining processes, including the CLI
negative-control run IDs. No storm failure core exists because the storm
never failed or stalled during these runs.

An attempted seeded storm diagnostic did not execute: the original fixture
validator rejected a dirty host-test source. Its patch and refusal are
preserved as `seeded-diagnostic.patch` and `seeded.log`; they confer no seeded
coverage. Subsequent diagnostics use the director-authorized fixture-scope
tooling revision, with unchanged guest fixture inputs and an exact-HEAD bundle.

## Recurring failures assigned to the N1 migration workstream

The director assigned these six failures to N1/n1g2. No runtime correction
for them is part of this investigation. Assertions below are from run 1;
source anchors refer to the original `51bfe67f4` snapshot.

| Test | Failing assertion | Contract |
| --- | --- | --- |
| `el1_anonymous_reservations_stay_in_guest` | expected >= 64 EL1 mmap serves, got 0 | `kernel.el1.anonymous-reservations` |
| `el1_delegated_root_concurrent_vma_ops` | expected >= 32 EL1 mmap serves, got 0 (forwarded 50) | `kernel.el1.delegated-root-fork` |
| `el1_delegated_root_map_fixed_over_cow_pages` | expected >= 12 EL1 MAP_FIXED serves, got 0 (forwarded 26) | `kernel.el1.delegated-root-fork` |
| `el1_fork_cow_resolves_in_guest` | exits=3219 exceeds ceiling 144, forks=20 pages=16 | `kernel.el1.fork-cow` |
| `el1_thread_lifecycle_ptrace_traceclone` | options_ok=false, options_errno=Some(38), clone_event=false | `kernel.el1.thread-lifecycle` |
| `el1_thread_lifecycle_spawn_slope` | forwarded clones per added thread 0.2734 must be < 0.05; exit slope 1.0000 | `kernel.el1.thread-lifecycle` |

Ranked source leads, not live root-cause proofs:

1. The three reservation failures share missing production admission edges.
   `El1AdmissionOrigin::Bind` has no production caller;
   `vcpu_loop/signal.rs::admit_bound_mm` only binds identity and selects a
   descriptor lane. `ForkCommit::admit_child_root` likewise has only a test
   caller. The fixtures request supported anonymous/private mappings. These
   are stronger leads than unsupported mapping flags or an opt-out setting.
2. Ptrace's request dispatch in `dispatch/proc.rs` has no SETOPTIONS or
   GETEVENTMSG arm and falls through to ENOSYS (38), consistent with the
   observed report.
3. Fork-COW and spawn-slope reports show forwarded lifecycle and mapping
   work. ExitNoEntry/ExitNoCurrent declines dominate; clone-pool exhaustion
   alone does not account for all forwarded clones. The existing retirement
   guards protect host authority and must not simply be removed to improve
   counters. Additional live attribution belongs to N1.

## Separate futex-handoff intermittent

Run 7 failed `el1_sched_futex_handoff_has_no_host_exits` on its first
5,000-round-trip sample: `el1_switches=4979`, below the unchanged minimum 5000.
It completed successfully as a guest in 15 ms, with `el1_parks=4980`,
`cross_wakes=4979`, `sgis=1`, `migrations=0`, `timeouts=0` and
`host_parks=0`. There were **no forwarded futex syscalls**. This is not
an observed lost wake or guest timeout. The fixture deliberately pins both
threads to CPU 0 because simultaneous execution can avoid parking and make
the handoff count depend on timing.

The director extended this worker's scope to investigate that failure. The
initial lead is affinity/residency admission, not a relaxed handoff budget.
A deterministic VM-free witness,
`scheduler_handoff::self_affinity_change_requires_migration_before_return`,
changes the running thread's mask to exclude its current CPU with an empty
run queue and another live process on the destination CPU. On unchanged
production code it fails: `should_preempt` permits guest re-entry on the
excluded CPU. Widening the mask, the other process, and the post-migration
residency are zero-preemption controls. The red log is `affinity-red.log`.
This proves a scheduler affinity defect; historical signed failure attribution
requires the additional evidence recorded below.

## Affinity return-path correction

The existing `kernel.scheduler.runnable-progress` contract covers
[sched_setaffinity(2)](https://man7.org/linux/man-pages/man2/sched_setaffinity.2.html):
when the current CPU is excluded, the thread migrates to an allowed CPU.
`dispatch/proc.rs` updates the live thread mask, but the executor's ordinary
syscall path previously consulted only queue demand and preemption reasons.
With no queued competitor it resumed the same residency regardless of that
new mask. EL1 can then keep a homed futex record on that excluded residency.

`Scheduler::should_preempt` now checks the live mask against the running
claim's guest CPU before considering fairness. An excluded residency follows
the existing settlement, affinity admission, save and load path. There is no
new scheduling path, wait, retry, timeout or pool-size change. This adds one
constant-size affinity read at an ordinary host syscall return; it does not
add work to EL1-served futex handoffs.

The real executor loop has a second VM-free red witness:
`self_affinity_syscall_migrates_before_the_next_guest_entry`. Its scripted
syscall updates the mask exactly as the dispatcher does, returns the ordinary
`ExecutorExit::Syscall`, and records the next backend entry. Before the fix,
both entries use ExecutorId(1). Afterward, there are exactly two entries on
different executors and two loads, and the destination is CPU 1. There are no
coordination sleeps or timing thresholds.

Focused post-fix results: all 22 `scheduler_handoff` tests and all 93 runtime
executor tests passed. The `just test-kernel-semantics --test scheduler_handoff`
recipe also expands `--tests`, so its broader invocation reached a retained
schedule receipt and failed its strict source hash after the scheduler edit.
The existing seed-637 recorder recaptured that receipt; comparison showed
**only `source_hash` changed**, with decisions, semantic result and work
observations identical. The original refusal is preserved in
`affinity-kernel-green.log`; focused handoff success is separately recorded in
`affinity-handoff-green.log`. Runtime red and green evidence are
`affinity-runtime-red.log` and `affinity-runtime-green.log`.

The first frozen-baseline `carrick trace` capture has 128 syscall-entry events
but no `syscall-return` events. Its process exit status is not a complete
entry/return trace receipt; no latency or return-value claim is drawn from it.
`affinity-lldb.log` captures a passing baseline at the actual affinity
mutation: the requested mask is 1 and the executor is CPU 0. That passing
observation does not attribute the historical failure.

The modified signed witness uses tooling HEAD
`805eada21aaf8325be1a87271978afb22a04ca34`, whose restored bundle contains
1,132 verified executables. Its bundle identity is
`802f853a11d295c1caa1c2b22089ce021c7f014b72da137878495f4069830507`;
the tarball SHA-256 is
`69fecc2a392c6751054a58516a52fefa0466b788b9103fba615ea26d3872e658`.
The host-test and scheduler edits remain uncommitted during signed runs so
the exact-HEAD requirement is preserved; source patches accompany the logs.

## Affinity red-first completion on 805eada21

The continuation rechecked all three pre-fix witnesses before restoring
`affinity-fix.patch`:

| Layer | Red evidence under `target/storm-investigation/` | Failure |
| --- | --- | --- |
| Kernel semantics | `affinity-kernel-red-confirm.log` | Self-affinity excludes CPU 0, but `should_preempt` permits return there with no queued competitor. |
| Runtime executor | `affinity-runtime-red-confirm.log` | Both guest entries use `ExecutorId(1)` instead of migrating before the second entry. |
| Signed controlled launch | `affinity-final-witness-red.log` | Both partners request CPU 0, but `cross_wakes=14001` instead of zero. The guest completes and the switch threshold passes, demonstrating why the stronger placement assertion is needed. |

The signed witness launches
`taskset -c 1 /bin/sh -c '/opt/carrick/el1-sched pingpong 5000; rc=$?; exit "$rc"'`.
The shell forks the fixture under inherited CPU-1 affinity; the fixture then
pins itself and its partner to CPU 0. It requires zero cross-vCPU wakes and
at least 5,000 in-guest switches. The final witness preserves the suite's
existing CPU topology. An earlier two-CPU policy override passed alone but
aborted in the full suite with `conflicting guest cpu count published`;
`affinity-full-01/run.log` preserves that failed attempt. Removing the
override required, and received, a fresh pre-fix signed red above. No guest
fixture source or executable changed.

Green evidence for the correction:

- `affinity-handoff-green-confirm.log`: 22 scheduler-handoff tests pass,
  including the two-live-process, empty-queue migration witness and its
  zero-extra-preemption controls.
- `affinity-runtime-green-confirm.log`: 93 executor tests pass, including
  exactly two loads on different workers and destination CPU 1.
- `affinity-final-witness-green.log`: the final signed witness reports
  `cross_wakes=0`, `el1_switches=14000`, and successful guest completion.
  Its signed receipt and executable are in `affinity-final-witness-green/`.
  The receipt records `input_identity`, dirty host sources, entitlement,
  DOF, negative control and zero-process cleanup. Fixture input identity is
  `6d9ff9f55be656493f4028468e2d2c589d03a473a744b690a3568bd326731c41`.

`kernel.scheduler.runnable-progress`, `kernel.el1.guest-scheduler` and
`kernel.el1.futex-handoff` now name migration before guest return after
self-affinity exclusion and bind each of these red-first witnesses. The
seed-637 replay receipt retains the predecessor's source-hash-only refresh;
its fixture hash, decisions and work observations are unchanged.

## Five full-filter runs after the correction

The director confirmed that the six N1 failures listed above are outside
this affinity PR. The authorized five-run criterion is: those same six
assertions fail as on main, and every other selected test passes. The
committed kernel, runtime, EL1 and `el1_sched.rs` sources are byte-identical
between the retained `51bfe67f4` baseline and tooling HEAD `805eada21`.

Each of `affinity-final-full-01/` through `affinity-final-full-05/` contains
the complete `run.log`, the tested `el1_sched` executable, `identity.txt`
and the dirty host-source `source.patch`. Every invocation was
`./scripts/test-signed.sh carrick-embed el1_ --nocapture`, with run IDs
`storm-affinity-final-full-01-20261005` through
`storm-affinity-final-full-05-20261005`. All five verified the same 1,132
executables from the exact `805eada21` bundle by fixture input identity.

Every run completed with **77 selected tests passing and exactly six
failing**. All 25 handoff samples (the controlled launch plus four original
samples per run) report zero cross-vCPU wakes. All five fork-storm cases
report `bad=0` and one live thread in each of their 16 fork children. Every
unentitled negative control passes, and all ten run-ID cleanup censuses
(guest and CLI IDs) report zero remaining processes. The machine audit is
`affinity-final-full-audit.log`, produced by the retained
`audit-affinity-full.rs`; raw exit codes are in
`affinity-final-full-status.tsv`.

The failures retain the baseline's exact assertion conditions: zero served
anonymous mmap, concurrent-VMA mmap and MAP_FIXED operations; fork-COW exits
above 144; ptrace SETOPTIONS errno 38 without a clone event; forwarded clone
slope above 0.05. Observed clone slopes span 0.2552–0.2812; exit slopes span
1.0000–1.0052. These measurements remain failures, not refreshed budgets.

The five signed scheduler artifacts share LC_UUID
`DEF963A4-0F44-3ADB-8379-22C95C7A59FA`. Each carries the hypervisor
entitlement and `__dof_carrick`; re-signing changes SHA-256 and CDHash:

| Run | SHA-256 | CDHash |
| --- | --- | --- |
| 01 | `f33926bd27b7c37d14aa322473ec354042bc475ea6de4948d9511bf347f90757` | `7259b6c89cf37552789cdc568e7a19ba8cb7b03c` |
| 02 | `3594925c687b66663b4d0aff1f28e0d56691ca9e0499c7c570a01d6766ecca8f` | `e547a98e207ddfd4e4645449449fb7df9ec21162` |
| 03 | `8bcf815531889f19475f5f2a5542d912cfc4c55dfafdf0ed4f8fce0e34dd4a7c` | `00d54e18cdf9f7a735364d8cb7bb047ccba7e47d` |
| 04 | `5ff31f69e1f35909f508dbbd9715954ab4eeccb1d70ecc7f58147b2bfabf869f` | `fecc3c4b3bc6782d7dc699f96aa1995f42e00fe2` |
| 05 | `7cbd310e0244a803eb5bef607cd9764b5c82ff91e4f7a8df6e8006a8183b0c62` | `c0afed006eaf8f480f0fc85d3aa0f3f218c73e65` |

All five raw suite commands exited **1** because of the six N1 failures.
This meets the director's scoped affinity criterion, but is not full EL1
acceptance. No Docker, new load, timeout increase, assertion relaxation,
concurrency reduction or retry-until-green was used. Full acceptance and
same-image Linux timing remain director-owned.

Final focused host verification: `just test-kernel-semantics` passes all
309 tests in 29 suites, including `scheduler_progress_contract` and the
seed-637 replay. `just fmt-check` and workspace `just clippy` pass.
