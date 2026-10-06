# X1 ARM signed comparison: baseline qualification

## Verdict

The four proposed bisect witnesses are already red at the pre-X1 commit
`56bf8c0caefe39fcc2260345d0a54772a74bffad`. A first-bad commit in
`56bf8c0ca..6051e19a2` therefore cannot be assigned from these tests. The
earlier broad baseline `el1_` run killed its `el1_sched` executable after a
watchdog and its `el1_files` executable during an earlier test; absence from
their failure lists was not a PASS.

No X1 source was changed for this investigation. The signed focused baseline
runs used the clean, detached `gate-n1-local` checkout with its installed
exact-SHA Linux fixture inventory. The reported X1 failures came from the
clean, detached `gate-x86-local` checkout and its exact-SHA inventory. The
current `work/x1-arm-regress` worktree contains this note only.

## Exact signed evidence

Before each focused signed run, `df -h /System/Volumes/Data` showed at least
293 GiB available (60 GiB required). Each invocation was made from the named
gate checkout. The files below are under
`/Volumes/CaseSensitive/carrick-evidence/x1-arm-regress/`.

| Witness | Baseline focused verdict | X1 focused verdict |
|---|---|---|
| `el1_memory_first_touch_stays_in_guest` | FAIL, `baseline-56bf8c0ca/focused-first-touch.log`: `HVPatch COW compound IPA 0x2e00000000 has no exact inventory coverage` | FAIL, `x1-6051e19a2/focused-first-touch.log`: same exact error |
| `el1_files_recall_on_teardown` | FAIL, `baseline-56bf8c0ca/focused-recall.log`: `restore vfork parent identity page: guest memory read is out of bounds at 0x2d001e4010 for 4 bytes` | FAIL, `x1-6051e19a2/focused-recall.log`: same exact error |
| `el1_sched_pipe_pingpong_stays_in_guest` | FAIL, `baseline-56bf8c0ca/focused-pipe.log`: `pipe-pingpong failed at 1199` | FAIL, `x1-6051e19a2/focused-pipe.log`: `failed at 1199` |
| `el1_sched_two_processes_share_vcpus` | FAIL, `baseline-56bf8c0ca/focused-two-process.log`: 120 s watchdog | FAIL, `x1-6051e19a2/focused-two-process.log`: 120 s watchdog |

The baseline commands were, with each `CARRICK_RUN_ID` exported only for its
own command:

```sh
CARRICK_RUN_ID=x1base-firsttouch-20261005 ./scripts/test-signed.sh carrick-embed el1_memory_first_touch_stays_in_guest --exact --nocapture
CARRICK_RUN_ID=x1base-recall-20261005 ./scripts/test-signed.sh carrick-embed el1_files_recall_on_teardown --exact --nocapture
CARRICK_RUN_ID=x1base-pipe-20261005 ./scripts/test-signed.sh carrick-embed el1_sched_pipe_pingpong_stays_in_guest --exact --nocapture
CARRICK_RUN_ID=x1base-twoproc-20261005 ./scripts/test-signed.sh carrick-embed el1_sched_two_processes_share_vcpus --exact --nocapture
```

The matched commands were run from `gate-x86-local`. Each exited 1 for its
selected test:

```sh
CARRICK_RUN_ID=x1head-firsttouch-20261005 ./scripts/test-signed.sh carrick-embed el1_memory_first_touch_stays_in_guest --exact --nocapture
CARRICK_RUN_ID=x1head-recall-20261005 ./scripts/test-signed.sh carrick-embed el1_files_recall_on_teardown --exact --nocapture
CARRICK_RUN_ID=x1head-pipe-20261005 ./scripts/test-signed.sh carrick-embed el1_sched_pipe_pingpong_stays_in_guest --exact --nocapture
CARRICK_RUN_ID=x1head-twoproc-20261005 ./scripts/test-signed.sh carrick-embed el1_sched_two_processes_share_vcpus --exact --nocapture
```

Each focused log shows `test-signed: resolved exact filter`, one executed test,
an entitlement negative-control PASS, and run-ID-scoped cleanup with zero
remaining Carrick processes. Each command exited 1 because the selected test
failed. These are red observations, not acceptance receipts.

The broad baseline `el1-embed.log` started `el1_sched` with 57 tests, then
watchdogged during `el1_ipc_two_processes_blocking` before the three nominated
late `el1_sched` tests appeared. It later killed `el1_files` while its first
test, `el1_files_blocking_survives_task_reschedule`, was running, before
`el1_files_recall_on_teardown`. The same broad baseline separately recorded
`el1_ipc_pipe_blocking_roundtrips` failing at pipe round 455. That broad run
cannot establish green controls for the nominated witnesses.

## Code-path and postmortem evidence

`eb8dbe4c5` is the first X1 commit that switches an ARM caller: it replaces
the local body of `carrick_el1::memory::serve_delegated_anonymous` with
`carrick_core::mm::anonymous::edit_and_commit`. `865a0ec1c` later switches
ARM `serve_transfer_hw` to `admit_transfer_service`. `4264779d0` changes the
ARM object-wait delivery callback to a borrowed closure. These are review
seams, not established causes of the four red witnesses, because the same
witnesses fail before all three changes.

The COW message is emitted by
`HvfVmState::cow_inventory_split_shape` in
`crates/carrick-vmm-hvf/src/trap/frame_inventory.rs` when no single inventory
extent contains the entire 16 KiB compound. The vfork message wraps
`stamp_identity_page` in
`crates/carrick-runtime/src/vcpu_loop/binding.rs` after a blocked vfork
parent resumes. These source locations identify where the errors are detected;
they do not identify the preceding owner/inventory mutation or prove an X1
path change.

For the baseline two-process watchdog, the retained snapshot at
`gate-n1-local/target/embed-post-mortem/x1base-twoproc-20261005/` records a
live parent task 1 and zombie child task 2, serial 45, wait status 32512. The
parent thread is blocked in `zone-futex-wait`, with an enrolled continuation.
The focused X1 snapshot at
`gate-x86-local/target/embed-post-mortem/x1head-twoproc-20261005/`
also records parent task 1 and child task 2/serial 45 with status 32512.
Its parent is likewise blocked in an enrolled `zone-futex-wait` with no event.
The baseline and X1 lldb backtraces in the respective
`focused-two-process-lldb.txt` files show the carrier waiting inside
`HvpatchLoopResult::wait_supervised` and executor guest-idle/condition wait
frames. The record IDs differ, and these snapshots do not establish why the
child exited 127 or which wake the parent was owed. The earlier broad X1
snapshot captured the parent as running, demonstrating why execution order
must not substitute for a focused comparison.

## Next diagnostic boundary

Qualify a genuinely green baseline witness before bisecting X1. If a witness
is green at `56bf8c0ca` under an exact focused signed run and red at X1 with
the same fixture and execution shape, restore Linux-published exact-SHA
bundles for candidate commits and bisect that witness. Do not attribute the
already-red COW, vfork, pipe, or two-process symptoms to the anonymous move
from the broad-suite failure-count difference alone. Investigate the baseline
COW inventory predecessor, vfork identity-page lifetime, last-round pipe
read/write result and errno, and two-process child status 127 under their
owning N1/IPC contracts; keep the exact signed artifacts and scoped cleanup
receipts.
