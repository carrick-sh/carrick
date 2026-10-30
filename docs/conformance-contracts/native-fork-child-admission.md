# Native fork child allocation and thread admission (#1100)

`kernel.el1.thread-lifecycle` binds the real native fork owner through
`native_fork_child_first_allocation_and_thread_admission`. The parent remains
live while the scheduler selects its child. Direct delegated-owner heap growth
and anonymous stack reservation preserve the parent's break, then clone uses
the child's loaned lifecycle page without manually stocked identities.

`native_fork_child_refills_retires_and_reuses_thread_stock` admits six workers,
beyond the initial four identities, over three rounds. Every worker enters
through the native owner and exits through raw exit. Namespace claims return
to the standing-stock baseline each round; final child exit returns the loaned
lifecycle and page-table extents through their existing physical owner.
`native_fork_child_capacity_refusal_is_eagain` fills the fixed lifecycle page
and requires errno 11 only at its active capacity. The final-pin witness
retains real signal projections after all workers exit, parks the next clone,
and releases one final pin: its notification resumes the preserved syscall,
which succeeds without a timer, retry limit or host fallback.

These are VM-free ownership witnesses, not an allocation-failure attribution
or a physical first-touch proof. The memory assertions call the delegated
owner directly; no guest libc or instructions execute. The original five
signed tests remain director-owned, including the distinction between stack
mmap failure and clone refusal. Existing semantic and work budgets remain.

Native stock notification-source admission uses the supplied short-lock wait
policy while the carrier's completion queue finishes its bounded initialization.
`busy_initializer_finishes_through_the_supplied_wait_policy` forces Busy once,
then publishes initialization and succeeds; an explicitly refusing wait policy
retains Busy. Native initialization contention cannot become pool exhaustion.

The #1100 review bindings require lazy stock priming at the first clone:
fork itself reserves no spare visible thread IDs, and process-only recovery
and nested-fork witnesses retain exact contiguous-PID assertions. A sibling's
Claimed entry is temporary contention, so its clone waiter enrols on the stock
release source and birth settlement publishes the wake after returning the
claim. A refusing short-lock admission preserves typed Busy, rather than
scanning it into capacity exhaustion.

`native_fork_child_clone_storm_recycles_exited_pinned_controls` cycles seven
workers over 32 rounds while the parent remains live. Every round drops the
signal projection before a release-less final control pin. A missing wake
bounded-fails at the fixture's WFI trap, with no timer or retry. The control
publishes its release target before arming MEMBER_WAITER; only the final
reference decrement consumes that bit and notifies, then clears the target.
Terminal publication and nonfinal decrements must preserve the wake debt.
The exhaustive control manifest keeps the waiter at bytes 240..256 and the
slot at 384 bytes, with the service cell still starting at byte 256.

The managed clone copyout binding requires errno 14, rollback of unpublished
service, object-wait and record bindings, no Born enqueue, and a successful
subsequent clone. These VM-free bindings do not establish that the signed
clone-storm, spawn-slope or scheduler populations complete without hangs;
the signed comparison and physical artifact acceptance remain director-owned.
The fixed lifecycle-page ceiling and graph-wide UID scan are tracked in #1142.

The ordinary-exit binding
`native_fork_child_exiting_sibling_wakes_parked_clone` keeps the native child
leader and its last worker live while six retired worker controls remain pinned.
The existing raw-exit hook pauses that worker after production membership and
scheduler release, with its ABI entry still `ExitingBorn`. The leader enrolls a
clone wait through `prepare_thread_birth`; completing the original raw exit must
notify, resume the preserved clone and create its thread. An empty runnable
population reaches the fixture's immediate WFI refusal, bounding a missing wake
without a timer or polling. This extends `kernel.el1.thread-lifecycle` with the
ordinary sibling-exit interleaving; signed execution remains director-owned.
