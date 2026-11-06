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
