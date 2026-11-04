# Native service entry after terminal close (#1575)

`kernel.el1.thread-lifecycle` applies Linux `exit_group(2)` semantics: a
sibling cannot survive the group's terminal close or publish new external
work into that process. A closed lifecycle gate is a terminal verdict, not
transient contention.

The VM-free binding
`arm_closed_gate_service_entry_retires_the_sibling_instead_of_busy` uses two
live native members. The leader closes with status 7; the sibling enters
through `with_process_entry`, `begin_service`, and `settle_service_exit`, the
production ARM service sequence. It requires zero host notices, zero retained
service claims, release of the sibling's lane, retirement of its exact record,
and one completed root exit with status 7. Retirement uses the existing member
transaction once; it adds no polling, runnable retry or host backend call.

The retained-IPC variant
`arm_closed_gate_service_entry_cancels_retained_ipc_before_retirement` stages
an exact eventfd read before the sibling loses its lane, closes the numeric fd,
then lets the leader close the process. The last endpoint reference is the
operation's pin. Terminal service admission must cancel that operation through
its existing IPC owner before retiring the member: the scheduler intentionally
requeues records that still own an operation. The binding requires no host
notice, no operation on the retired record, release of the last endpoint pin,
zero service claims, and the original group exit status 7.

The implementation ports the terminal fix and witness from parked PR #1386
(`9f40da66ec`). Preparation now returns a typed request-or-retirement outcome,
so the terminal result cannot be mistaken for a service request. The claim is
released before retirement. A terminal gate without a pending close remains a
broken invariant. Claim-counter overflow likewise remains an invariant.
The old Busy diagnostic expansion is dropped: it is not needed to implement
this terminal outcome and would add ABI reason codes outside this fix.

Service admission distinguishes duplicate custody from a release dependency.
A bridge without retained IPC custody cannot also own a suspended member
row for its executing exact member. Its cell must be idle (or unbound before first admission), and its execution lane must
have consumed the previous notice before running another entry. Violating
these conditions is `Quarantined`, rather than a transient `Busy`. The
`native_service_duplicate_custody_is_an_invariant_at_bridge_settlement`
binding corrupts the cell and lane notice separately and drives production
admission and settlement; it must diagnose those broken owners without
pretending that yielding can repair them. The member-row binding
`native_service_suspended_member_cannot_admit_a_second_bridge` also requires
zero notices and claims when an executing member incorrectly retains a
suspended signal row.

The notice is per execution lane, not per process: `native_service_idle`
returns `Action::Idle` directly to the host. Both the loaded and idle paths in
`vcpu_loop::executor::backend` take the lane's native service notice before
another guest entry. An occupied notice at publication therefore cannot be a
sibling's legitimate outstanding work.

Claim, cancellation, completion and owner-wait transitions serialize on the
same native-service queue. A cell CAS refusal under that exclusion is likewise
an invariant. Normal not-yet-completed service consumption still enrolls on
that queue, and explicit MM owner dependencies still use their existing portal
queues. IPC preparation refusal keeps its retained operation and pin, including
CarrierWork with an empty preparation payload: the installed record token is
the authority, rather than the payload variant. There is no broad
Busy-to-invariant conversion at settlement: an unaudited callback
cannot acquire invariant status merely because it returned Busy.

The exec successor population checks already cancel the prepared successor or
terminate the losing image when validation fails. They do not escape through
bridge settlement and are unchanged here.

Director confirmation requires signed runs of `el1_fork_cow_resolves_in_guest`,
`el1_sched_two_processes_share_vcpus`,
`el1_thread_lifecycle_cleartid_tid_reuse`,
`el1_thread_lifecycle_spawn_slope`, and
`el1_thread_lifecycle_seccomp_clone_filter`, with zero `NativeServiceBusy`
fatals, on one artifact. The witness does not establish which fatal caused
#1578's mixed-venue, bounded-reap or bigread failures; their signed outputs
must be attributed separately. HVF and Docker evidence is not supplied by
the VM-free binding.
