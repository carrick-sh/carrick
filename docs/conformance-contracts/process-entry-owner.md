# Process entry native custody (`kernel.process.entry-owner`)

CPL0 process calls use the existing Linux lifecycle dispatcher and completion
owner. Before invoking native fork, wait4 or exit_group custody, the pending
family must authenticate task, task generation, MM and thread generation.
A mismatch invokes zero native effects. A matching entry invokes its one
native operation; native custody returns a LifecycleOutcome, never publishes
a second completion. ARM native process returns and the host-published getpid
projection cross the existing completed-with-work boundary. The host consumes
one `SyscallCompletionToken` and publishes the actual return through
`publish_return`; it never replays the already served call. Admission refusals
that return errno use the same completed boundary. Suspended and terminal
transfers do not invent a syscall return.

The VM-free runtime witness `owned_arm_process_return_is_observed_once` binds
ARM getpid with and without a process venue, native fork/wait success and errno,
and unported process-call refusals. Each returning call records exactly one
audit return and one engine completion, with at most one native effect; a
second completion is refused. Boundary publication and consumption are constant
work. EL1's `refused_owned_process_return_retains_one_completed_boundary` also
binds the pre-dispatch refusal transport.

The VM-free `process_native_hooks_require_every_execution_identity_component`
test independently changes each binding component and checks all three hooks.
The native hook absence is red before the bridge. The
`x86_parked_context_roots_clone_through_shared_fork_owner` fixture inherits a
real anonymous reservation through the existing shared fork traits with CPL0
parked contexts and aligned, co-located reservation/zone storage. The previous
ARM-only trait implementations are structural red; context parameterization
preserves the ARM default. This is adapter and owner-custody evidence; CPU1
execution and the live two-MM PRIVATE witness remain required.

The native owner does not support ptrace attach or non-child tracees. It has
no attach venue or mutator establishing a tracer relationship. On the x86
CPL0 path, ptrace is outside `AllowedHostCrossing` and is refused with counted
ENOSYS (38). Accordingly waitpid(nonchild) has no ptrace relationship and
returns ECHILD (10), as Linux does without ptrace. This does not claim parity
with Linux waiting on an attached tracee. The VM-free
`nonchild_wait_has_no_ptrace_relationship_and_preserves_own_children` binds
that scope with two live sibling processes and the caller's own live child.

Exit preparation must remain reversible until publication: abandoning an
owned pending exit leaves live topology, revisions and resources unchanged.
`early_error_after_exit_begin_preserves_live_graph_and_reservation_custody`
checks this with both a live child and a zombie. Shared effect preparation
retains the exact exiting-task membership revision; activation refuses a
snapshot invalidated by an admitted birth without changing lifecycle.
`prepared_exit_effects_reject_stale_membership_snapshot` binds this and verifies
fresh cancellation includes both members. `PreparedExitEffects` exposes neither
cancellation nor resource transfer before activation (compile-fail witnesses).
Publication wakes the direct
parent and adopter once each, including inherited zombies;
`blocked_adopter_wait_resumes_with_an_inherited_zombie` binds this through
a parked native wait continuation.
A competing reap retains the original Any or process-group selector and
requires fresh status copying before consuming a replacement zombie;
`competing_reap_keeps_original_any_and_group_query` checks both selectors and
live/zombie replacements. Child job groups are resolved in the caller's
namespace, including groups different from the caller's own. These operations
visit the caller's children and affected exit topology, never unrelated rows.
