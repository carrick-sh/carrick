# xtask umask isolation

Issue #1682 concerns the runner-tree and skeleton-reset test changing verdict
on an unchanged CI head. The `ci_scaler_mac` integration binary has two tests
that change umask. Their `serial_host` names do not make libtest serialize
them: the xtask recipe selects the whole integration binary without filters.

Umask belongs to the process, not the thread. While the runner-tree test
expects 0002 or 0022, the run-once test can install 0277, removing owner write
permission from directories created by the runner-tree fixture or reset.
A guard restoring its saved value cannot protect concurrent threads; overlapping
guards can also restore another test's temporary mask.

## Baseline population

On this Linux runner, using the unmodified integration binary, 50 exact runs
of `serial_host_runner_tree_and_skeleton_reset_succeed_under_group_writable_umask`
passed. Running the complete `ci_scaler_mac` binary 50 times with
`--test-threads=16` gave 33 passes and 17 failures of that same test. One failure
was `PermissionDenied` at `mkdir_mode`'s `create_dir_all` call. Each run's target
verdict was counted, rather than inferring execution from a zero exit code.

This reproduces the process-state dependence without macOS, a guest, deliberate
host load, retries, sleeps or a timeout change. Raw per-run logs and the counted
population are retained by the worker under `/var/tmp/1682-evidence`.

## Isolation and verification

Both umask cases now re-execute their exact test name in a child process.
Only the child changes umask, and it runs no sibling cases. The parent checks
both the child exit status and the one-test pass summary, preventing an empty
selection from masquerading as success. Other tests remain parallel; no retry,
sleep, larger timeout or global serialization was added.

With this change, the same 50 exact runs and 50 complete integration runs
with 16 threads all passed (100 target passes). The ordinary parallel partition
and the `RUST_TEST_THREADS=1` serial-host partition also passed separately.
This is Linux evidence for the reproduced race, not a claim of macOS execution.

## Checkpoint verification on the dispatch runner

A fresh Linux run reproduced the dependence again: the baseline passed 50/50
exact selections, but only 37/50 complete integration runs with 16 test threads.
The 13 target failures included `PermissionDenied` from recursive fixture
creation and from resetting the job area. The fixed binary passed 50/50 exact
selections and 50/50 complete integration runs with the same 16-thread setting.
Every fixed complete run exited successfully, so sibling tests passed too.

These are new measurements, independent of the earlier population above.
The earlier worker's `/var/tmp/1682-evidence` directory was not present in this
ephemeral checkout. Fresh raw logs, per-run exit statuses and counted verdicts
are in the dispatch job's `agent/evidence/` directory beside the checkout.
Before counting, one exact run confirmed the harness selected and completed
one target test. Both binaries were built from this checkout, temporarily
restoring the baseline test source for the baseline build, then restoring the
committed isolation fix. No production source changed.

## Final continuation population

The continuation worker preserved the harvested commits and confirmed that the
branch was already based on admitted main. Its fresh population measured:

| Selection | Baseline target passes | Isolated target passes |
| --- | ---: | ---: |
| Exact target, 50 invocations | 50/50 | 50/50 |
| Entire integration binary, 16 threads, 50 invocations | 45/50 | 50/50 |

Eight baseline full-binary invocations failed: five failed the target and
three failed other filesystem cases. All failures reported permission denied.
This also demonstrates why locking only the two umask mutators would be
insufficient: unrelated fixture creation consumes the same process umask.
All 50 fixed full-binary invocations passed every case.

The baseline test source was extracted from admitted main and compiled as a
Rust test binary against the same unchanged production libraries used by the
fixed test. The checkout's source stayed fixed throughout. The exact compiler
arguments are saved in `agent/evidence/baseline-command.json`; raw logs,
known-answer selections, and per-invocation target verdicts are beside it.
These are Linux measurements; no macOS or signed guest result is implied.

## Admitted-main finishing round

After rebasing the four existing commits onto admitted main, a fresh Linux
population passed 50/50 exact baseline selections and 42/50 complete baseline
runs with 16 threads. The fixed binary passed 50/50 exact selections and all
50/50 complete parallel runs. Every invocation was counted on the target's
own verdict line, and both exact selections first passed a one-test
known-answer check. Baseline failures again reported errno 13 during recursive
directory creation or job-area reset; sibling filesystem cases were affected
as well.

The concrete race is creation of an intermediate directory under the other
test's temporary 0277 mask: recursive creation precedes `mkdir_mode`'s chmod
of its leaf, leaving the intermediate directory at 0500 and preventing creation
below it. Overlapping guards can also restore a stale saved mask. The inherited
child-process fix was kept unchanged: each mutator has its own process umask,
while sibling tests retain parallel execution. No new production fix was needed.

Fresh binaries, baseline source and compiler arguments, one-test checks,
per-run logs and machine-counted verdicts are saved beside the checkout in
`agent/evidence/`. Both binaries use the same production libraries; only the
baseline test source comes from admitted main. This is local Linux host-test
evidence, not macOS or signed guest evidence.
