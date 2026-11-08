# Anonymous edit token custody

The `kernel.scheduler.runnable-progress` and
`kernel.el1.anonymous-reservations` contracts require an anonymous edit to
retain its original arguments through a wait, and terminal cancellation to
retire that wait without invoking an unrelated operation authority. Linux
semantics come from `mmap(2)`, `mprotect(2)`, `munmap(2)` and `exit_group(2)`:
an internal contention wait neither completes a syscall nor survives group
termination as an external IPC operation.

The existing `OperationToken` and `ObjectRecord` remain the only operation
custody mechanism (`carrick-sched-core/src/object_wait.rs`). The new anonymous
producer in `coordinate_anonymous_edit_wait` reuses them. Prepared edits already
have a tagged token; anonymous edits now have a separate tag and both use one
`OperationKind` classifier. IPC conversion and scheduler adapter detection
accept only the adapter kind. The host resumes scheduler-owned syscall
replays with their saved arguments instead of looking for an IPC arena slot.
No new lock, queue, operation arena or owner is introduced.

The VM-free production enrollment and host-claim binding
`anonymous_host_handback_preserves_replay_domain` was red on the untyped
producer: an anonymous operation still reported adapter ownership after its
queue was unlinked. It now requires scheduler replay custody and rejection by
IPC conversion. `exit_group_keeps_pipe_pin_distinct_from_anonymous_replay`
retains a real pinned pipe operation on the leader alongside a parked anonymous
sibling, then enters production `exit_group`: only the IPC adapter releases the
pipe operation, and the anonymous record retires without effects. Existing
signal, exit and exec bindings remain required. Cancellation domain tests also
require opaque adapter tokens at MM queue numeric indices to retain adapter
custody; queue location alone is never operation authority.
`anonymous_cancel_after_wake_has_no_ipc_handback` covers cancellation after
readiness has already unlinked and selected the waiter: the execution slot
requeues it for one terminal sweep, with zero host adapter handbacks.

Work is unchanged: one enrollment per observed release and one operation take
or terminal retirement, without polling, extra wakeups or retries. Metadata
receipts and prepared portal edits retain their separate kinds and existing
cancellation policy. The object-wait protocol/hash includes the token tags so
host and guest cannot silently disagree on the encoding.

These reductions do not execute the macOS-only host `resume_zone` consumer.
The director must rerun `el1_files_exit_group_stress` on the exact signed head
against the paired base population (ten runs per artifact), and the changed
runtime crate's Mac tests. No signed or runtime-ratio acceptance is claimed by
the VM-free bindings.
