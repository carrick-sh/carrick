# Exact physical grant completion

`kernel.mm.copyout-owner-gate` also covers the interval between physical
alias publication and its EL1 descriptor receipt. An exact live provisional
owner is a completion dependency, not a permanent supply refusal. A contender
must allocate zero extra frames, hold no host I/O lock while suspended, and
reselect through the semantic owner only after that exact publication commits
or rolls back. A reused VA or physical generation cannot satisfy its wait.
The VM-free bindings are
`concurrent_transfer_waits_for_exact_uncommitted_physical_grant` and
`transfer_partial_remap_keeps_dirty_neighbor_in_same_compound`; they cover
rollback, applied settlement, late enrollment and distinct owner completions.
Both settlement paths release the publisher's temporary physical pin before
publishing readiness or invoking callbacks; a waiter may immediately retire
that exact owner. The witnesses sample the exact stage-2 pin count inside
the callback and require zero, rather than checking only after producer Drop.
The same copyout signed fixture remains the required production binding.

`kernel.copyout.owner-refusal` also requires a native fatal signal to survive
an ordinary owner-release wake and carrier continuation cleanup. The VM-free
runtime binding
`serial_host_native_owner_wait_release_wins_then_tgkill_survives_recontention`
lets release win Ready, reacquires the real sibling editor, posts native
`tgkill(SIGKILL)` and settles its doorbell before resuming the continuation.
Native terminal custody must be entered before the renewed editor releases.
Carrier and native queue projections have distinct publication capabilities;
the shared pending observation is their read-only union. Native custody admits
one writer per control slot, even across independent retains. The writer cannot
be cloned; its destructor alone releases the claim and clears the projection.
`native_pending_writer_admission_is_exclusive_until_drop` and
`duplicate_member_projection_must_preserve_pending` exercise refusal, retained
SIGKILL and final cleanup; `NativePendingCustody` doctests reject move duplication
and cloning.

`serial_host_native_owner_wait_fatal_callback_budget` binds deterministic
publication work at 1/8/32/128 live thread wait registrations in one process.
One native process-fatal host-work publication must invoke exactly N persistent
task callbacks for N subscriptions: each exact TaskKey is notified once,
regardless of its eligible waiter population. The budget counts callback
invocations, including redundant invocations hidden by runnable latches.
Signed HVF and Docker promotion remain director-owned.
