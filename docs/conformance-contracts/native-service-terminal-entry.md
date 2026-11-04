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

The implementation ports the terminal fix and witness from parked PR #1386
(`9f40da66ec`). Preparation now returns a typed request-or-retirement outcome,
so the terminal result cannot be mistaken for a service request. The claim is
released before retirement. A terminal gate without a pending close remains a
broken invariant. Claim-counter overflow likewise remains an invariant.
The old Busy diagnostic expansion is dropped: it is not needed to implement
this terminal outcome and would add ABI reason codes outside this fix.

Other service waits keep their existing enrolled native-service and portal
owner queues. This change does not add a generic Busy retry: a member's own
pending row, a non-idle cell, an occupied slot notice, and exec population
checks do not expose one common release dependency. Turning them into a
runnable yield would lose staged input or poll rather than enroll. Those
sources are not covered by this terminal witness.

Director confirmation requires signed runs of `el1_fork_cow_resolves_in_guest`,
`el1_sched_two_processes_share_vcpus`,
`el1_thread_lifecycle_cleartid_tid_reuse`,
`el1_thread_lifecycle_spawn_slope`, and
`el1_thread_lifecycle_seccomp_clone_filter`, with zero `NativeServiceBusy`
fatals, on one artifact. The witness does not establish which fatal caused
#1578's mixed-venue, bounded-reap or bigread failures; their signed outputs
must be attributed separately. HVF and Docker evidence is not supplied by
the VM-free binding.
