# Guest-copy thread outcomes: slice 2 verification

Part of #1684, stacked on #1691. The applicable contracts are
`kernel.el1.thread-lifecycle`, `kernel.el1.signal-delivery-owner`, and
`kernel.memory.owner-wait`. Linux authority is the contracts' clone,
set_tid_address, set_robust_list, futex and signal semantics. Only a true
copy fault may become EFAULT; unavailable backing retains the operation
through the existing memory owner rather than publishing a partial birth
or losing an exit wake or pending signal.

## Production-entry witnesses

All six witnesses call `dispatch_arm_syscall_with_native_process` through
`arm_call`, with the production TrapFrame and family routing. Refusal is
injected at the user-copy boundary, not by calling a lifecycle helper.

- `arm_clone_nonresident_tid_destination_publishes_once` and
  `arm_clone3_nonresident_tid_destination_publishes_once` begin with two
  live tasks. They refuse the child TID destination after the parent TID
  write, require both original words and the original live population on
  refusal, then require one additional child and both published words.
- `arm_non_last_thread_exit_nonresident_clear_tid_wakes_once` registers
  through set_tid_address and parks a peer through FUTEX_WAIT_PRIVATE.
  Refused clearing preserves both tasks and the waiter; completion clears
  the word and calls the wake exactly once.
- `arm_non_last_thread_exit_nonresident_clear_tid_and_robust_list_wakes_once`
  also registers a real user-memory list through set_robust_list. Refusing
  the head leaves it intact. Refusing the later clear-child-TID write
  occurs after robust cleanup; resumption does not repeat that cleanup.
  The wake log must contain exactly the robust address and clear address.
- `arm_signal_frame_push_onto_nonresident_stack_delivers_once_and_sigreturn_restores`
  and `arm_signal_frame_pop_from_nonresident_stack_restores_once` install
  an action and queue a signal through syscall entry. Push refusal keeps
  the handler unentered; pop refusal keeps the frame intact. Completion
  restores the original PC, SP, SPSR and a general register.

The red run selectively restored the former production failure behavior
while keeping the typed API and current tests buildable. It is not a
claim that an unmodified #1691 tree was run: clone3 thread routing and the
robust walker did not exist there. Clone/clone3 failed with Forward/WithWork
instead of Served; clear and robust exit returned HostCustody; signal
push and pop returned Suspended instead of Served. Six cases failed and
five unrelated nonresident controls passed. Removing that regression
patch restores all eleven focused cases.

These VM-free refusal schedules do not qualify ARM hardware fixup,
x86 execution, or a real blocked owner's release. The existing owner-wait
bindings and signed gates remain independently necessary.

## Review findings still requiring production correction

These findings concern the inherited WIP, not the test instrumentation.
Passing the focused schedules does not settle them.

- P0: `handle_exit_robust_futex` reads and writes the futex word separately.
  A concurrent waiter can set FUTEX_WAITERS between them and lose that bit.
  An atomic compare/exchange against guarded guest memory is required;
  byte copies cannot supply that contract.
- P1: `walk_exit_robust_list` starts at the head after every NotYet. A lazy
  list can revisit its completed prefix quadratically. Retain the exact
  walk cursor and pending-entry phase in the existing operation owner.
- P0: `TidOutputs::publish` and `TidOutputs::rollback` ignore the result of
  restoring a preimage. If rollback itself refuses, the unborn child's TID
  may remain published. Retain rollback custody until it completes.

The slice must remain a draft until these are corrected and witnessed.
