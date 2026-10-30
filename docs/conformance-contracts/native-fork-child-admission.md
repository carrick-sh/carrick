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
