# Executor empty host queue

`kernel.el1.deferred-handback-identity` also covers a pinned service record
evacuated when its executor enters an inline host wait. Linux affinity limits
execution to eligible CPUs; lending a CPU must leave runnable work claimable
by its borrower. The vacating actor can return and enter another inline wait
without taking service work. Requeueing a captured service record behind
that actor or another eligible driver repeatedly captures the same incarnation
and delays its readiness.
The ARM affinity venue in #703 exposes this path when the fixture's pin starts
succeeding instead of returning ENOSYS.

`service_capture_publishes_once_across_repeated_step_aways` drives real
slot evacuation and host settlement at 1, 8 and 32 turns. It requires one
capture, one host publication and zero zone queue rows, with either a pinned
or broad mask. `service_capture_does_not_bounce_between_eligible_drivers`
alternates eight step-aways between two drivers, on the same or different
eligible CPUs. It was RED with eight captures even after the away-slot
fallback was removed; service handback must end zone custody. Initial service
placement is unchanged.
`hold_is_captured_exactly_once_at_the_next_step_away` drives the same
test-only hold and production step-away hooks as the signed witness, now over
three consecutive inline waits; its RED was three identical captures.
Only first-entry births retain the fallback queue because they have no host
row to release. These assertions do not change the retired-delivery budget.
The signed binding is
`el1_sched_deferred_handback_capture_observes_guest_records`; signed execution
and end-to-end runtime acceptance remain director-owned.

Returning the service row also requires an executor wake on the mailbox
leased by its current idle entry. A persistent hardware handle can retain
a relinquished creation-time mailbox after fork or task migration. The
runtime publishes an owned idle-wake target before its final host queue
scan and holds that target through delivery and idle teardown. Zone wakes
mark durable host work on that mailbox before kicking it; physical idle
lanes retain their backend wake route.

`serial_host_captured_service_after_self_affinity_and_futex_wakes_current_idle_slot`
executes self `sched_setaffinity`, real shared-futex enrollment and wake,
service capture and scheduler publication, then the production EL1 idle
loop and host claim. The wake lands after the final queue scan but before
effective guest entry, after the mailbox moved from slot 0 to slot 12.
Its RED enters WFI without an event on both the pre-#765 fixed stack and
the rebased stack. GREEN requires no WFI, one capture, and a claim on CPU 0
after self-affinity excluded CPU 1. The supplied pre-fix signed comparison
failed with `Cannot fork` before exercising the handoff, so it cannot
establish absence of the hang under a successful fork. Signed acceptance
of both properties remains open.

`kernel.scheduler.runnable-progress` also covers pool admission and guest CPU affinity.
Native service custody extends this contract: two real fork children can publish
simultaneous requests through the fixture's sole execution slot. Each park must
release that slot. The witness rejects a stale execution generation, cancels one
request before physical acknowledgment, completes the other first, and requires
one ring consumption per request before its terminal claim is released. A member
retains at most one signal or service wait in the shared continuation table;
one retained member allocation also preserves a saved signal mask after its
wait completes, until signal delivery consumes that mask. Host
records retain backing and observe exact identities; they do not adopt children
into another process graph. Intake reuses the birth-bound MM identity even
when another admitted participant holds the reservation root. The bindings include
`native_service_intake_does_not_reacquire_the_busy_mm_root` and
`two_native_children_service_waits_release_the_only_execution_slot` in
`carrick-el1-linux`. Its companion cases preserve a completed result through
cancellation, retry an effect-free syscall with its original arguments, and
resume an interrupted instruction without changing its registers. The shared
personality receipt distinguishes effect-free deferral from a metadata commit
already owed. The runtime binding
`native_service_waits_do_not_exhaust_the_default_executor_pool` uses the real
native owner with four fork children and the default one-CPU pool (one bound
worker, two spares). All four requests must park before any acknowledgment;
no child gets a host task binding, and every worker must join. Its physical-idle
test adapter does not exercise HVF metadata pin intake. Fault supply and signed
child syscall acceptance require separate witnesses. Unsupported native requests return to the ring for its errno
or signal decision; no generic host syscall dispatcher is introduced.

Linux authority: `sched_setaffinity(2)` restricts a runnable thread to the
allowed CPUs; `sched_getaffinity(2)` and `nproc` must describe CPUs that can
execute it. Every scheduler CPU requires at least one bound executor; spares
do not cover CPUs without a bound executor to lend them its slot. Invalid
configuration must create zero workers and publish no preemption driver or
resolver. The VM-free binding
`insufficient_bound_workers_cannot_strand_a_pinned_task` explicitly requests
two workers for four CPUs and pins a runnable task to CPU 3. Before the fix,
the task makes no progress within five seconds; exact-generation cancellation
keeps teardown bounded. Signed execution and full promotion remain
director-owned; no Docker phase is authorized on cloudmac.

Admission preserves the installed policy and rejects insufficient bound capacity
with `ExecutorPoolConfigError::InsufficientBoundWorkers` before starting the
preemption driver, installing the resolver, or publishing any worker. Silently
clamping a custom policy would change the CPU IDs and affinity topology it
promises. The count includes the backend ceiling and reserve; spare executors
cannot substitute for bound workers. Even a one-CPU policy is rejected when
reserve consumes the entire budget.

Configuration audit: `carrier_scheduler` publishes the installed policy count;
the default uses `default_guest_cpu_count`, hence `CARRICK_EXPOSED_CPUS` or the
host's logical/performance-core count, clamped to `MAX_GUEST_CPUS`.
`configured_bound_executors` defaults to that same count; its explicit env
request is validated after the backend cap. Invalid text falls back to the
policy count and zero requests one worker, as before. HVF supplies
`vcpu_budget()` from its hypervisor ceiling (already reserving its overhead),
not its physical-core count; the production pool adds no reserve.
`pool_admission_covers_overrides_ceilings_reserves_and_small_hosts` checks these
admission combinations, including a two-CPU policy with two workers, execution
on the highest CPU, and corrected startup after refusal. CPU publication and
`sched_setaffinity` validation retain their existing single policy authority.

An unported affinity venue may admit a native process before carrier topology
or its control mask is published. Fork inherits that unpublished zero mask;
binding its live authority must not turn absence of policy into an empty CPU
set. `unpublished_live_affinity_does_not_restrict_placement` checks placement
before publication and enforcement after a nonempty mask is installed.
`missing_venue_affinity_alias_refuses_placement` separately requires refusal
when the current venue cannot read a bound authority. Both paths use at most one
authority load, without scanning CPUs or substituting another venue's pointer.
`child_exit_releases_control_custody_before_retire_mm_reclaims_stock` binds
this to production x86 fork, idle-peer migration and child MM retirement with
unpublished topology. Published masks still follow Linux fork inheritance;
empty `sched_setaffinity` requests remain invalid. Signed execution remains
director-owned.
For ARM native fork, `arm_native_fork_child_reinstalls_mm_after_service_ack`
binds the same runnable-progress contract after the parent has left its host
continuation: the forked record must enter through an idle executor with no
host task, park for service, and resume the same child after acknowledgment.
The witness models idle entry resetting TTBRs to the carrier root and requires
exactly one child-root installation before its first child syscall. Service
park switches to the maintenance root before releasing installed occupancy.
The signed shell and exec
probe remain the execution-layer binding.

`kernel.executor.empty-host-steal` covers an executor seeking host-runnable
work while runnable tasks are held by the in-guest scheduler. Linux blocking
and wakeup semantics remain the authority: a guest wait releases executor
capacity, and a wake must make the exact runnable generation claimable without
waiting for another guest task. The VM-free structural binding is
`zone_only_steal_has_zero_host_cpu_scan_visits` in `scheduler.rs`, at 1, 8 and
32 guest CPUs. Its budget is exactly zero host CPU queue visits per empty
steal attempt, even when a zone-held row contributes to lifecycle drain.
Host-runnable rows must remain stealable. Signed execution, same-image Docker
timing, and full promotion remain open for the integration director.
