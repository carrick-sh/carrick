# Native fork child allocation and thread admission (#1100)

`kernel.el1.thread-lifecycle` has a diagnostic real-fork reduction in
`native_fork_child_first_allocation_and_thread_admission`. The parent remains
live while the scheduler selects its native child. Direct delegated-owner
heap growth and anonymous stack reservation must preserve the parent's break.
The next clone runs through the Linux dispatcher against the child's actual
loaned lifecycle page, without manually stocked identities. The diagnostic
requires a completed clone and two live child-group members. It currently
fails at empty-pool admission; it is deliberately red during implementation.

This is not an allocation-failure attribution or a physical first-touch proof.
The memory assertions call the delegated owner directly, and no guest libc or
instructions execute. The signed 1024-byte allocation failure can occur while
printing an earlier thread-start error. The original five signed tests and
the distinction between stack mmap failure and clone refusal remain open.
No budget, route or production implementation changes accompany this witness.
