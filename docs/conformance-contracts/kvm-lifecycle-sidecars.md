# KVM lifecycle fixture sidecar identity

Issue #1580 binds the existing real-KVM lifecycle and fork fixtures to
`kernel.el1.thread-lifecycle`. Linux clone, exit and wait4 semantics remain
the authority; the fixture must give host setup, guest execution and stopped
observation the same retained lifecycle state.

The shared x86 lifecycle layout moved its sidecars above the enlarged zone
tables and second page-table root. KVM still initialized and observed the old
physical address. The guest consequently read zero sidecar state while the
host observed an initialized copy that the guest never used. Clone declined,
and fork/wait fixtures returned incorrect results.

`LIFECYCLE_LANES_GPA` derives the physical placement from the supervisor
mapping's base and the shared guest layout's lane offset. Both host accesses
consume that typed physical address. The existing layout assertions use the
same address and prove separation from the second root, alignment of both
lanes, and containment of the full two-lane extent in the supervisor mapping.
There is no second physical placement constant to update after a layout move.

The red witnesses are the seven fork/COW/wait4 failures in `cpl0_fork_e2e`
and `cpl0_lifecycle::x5_shared_clone_exit`. The latter keeps two live MMs and
checks clone, child exit, clear-tid wake, independent words, and extended-state
restoration across 16, 64 and 256 births per MM. All assertions and budgets stay
unchanged. Physical placement is x86 fixture mechanics; no ISA-neutral Linux
policy, birth ownership, scheduler algorithm, guest instruction path, CPUID,
segment-entry or file-region semantics change. The work is a compile-time
address derivation, with no new guest work, allocation, waiting or polling.

These KVM fixtures do not confer signed HVF acceptance. CLI compiler deaths
before fixture execution and the separately tracked post-execution deadlines
in #1559 remain distinct evidence classes.
