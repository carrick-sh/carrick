# Guest-copy thread outcomes: slice 2 verification

Part of #1684, stacked on #1691. The applicable contracts are
`kernel.el1.thread-lifecycle` and `kernel.el1.signal-delivery-owner`.
This slice keeps typed `CopyOutcome` values at clone TID, exit cleanup, and
signal-frame boundaries without changing the merge-base refusal policy.

Unavailable backing does not park on these paths. Designed owner-wait
transactions are follow-ups #1719 (clone TIDs), #1723 (signal frames), and
#1724 (exit cleanup).

## Merge-base parity

- A signal-frame `NotYet` or `Fault` is a delivery fault at the final
  user-return checkpoint. The original handler is not entered.
- A robust-list or clear-child-TID `NotYet` or `Fault` declines the nonfinal
  thread exit to host custody. `SYS_exit` never returns `EFAULT`.
- A clone TID `NotYet` or `Fault` declines the in-ring clone. Clone3 keeps its
  existing immediate personality refusal. Neither path parks or exposes a
  partial TID publication.
- Equal parent and child TID addresses form one output, so publication and
  rollback touch the guest word once.

## Production-entry witnesses

The witnesses call `dispatch_arm_syscall_with_native_process` through
`arm_call` with two live threads where peer visibility matters:

- `arm_signal_frame_push_not_yet_matches_main_delivery_fault`
- `arm_non_last_thread_exit_nonresident_clear_tid_wakes_once`
- `arm_non_last_thread_exit_nonresident_clear_tid_and_robust_list_wakes_once`
- `arm_non_last_thread_exit_unmapped_clear_tid_still_exits`
- `arm_clone_nonresident_tid_destination_publishes_once`
- `arm_clone3_nonresident_tid_destination_publishes_once`
- `arm_clone_aliased_parent_and_child_tid_publishes_once`

The typed `Done` paths still improve on main: successful in-ring robust owner
death and clear-child-TID cleanup remain available, and guarded clone output
publication preserves a peer write rather than overwriting it during rollback.
