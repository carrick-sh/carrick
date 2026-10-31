# Carrier teardown after executor failure (`runtime.carrier.failed-drain`)

`runtime.carrier.failed-drain` covers successive containers in one host process.
A failed task remains a failure; draining its executor pool must join every
worker before destroying the VM and closing carrier admission. This is a
Carrick hardware-lifecycle invariant, with no Docker timing or Linux syscall
output claim. The structural budget is exactly one VM destruction per carrier,
including repeated shutdown calls, and one fresh generation for the next VM.

The VM-free binding
`failed_executor_drain_still_completes_vm_teardown_before_next_container`
runs the production executor pool with a failing test backend in container A,
then an exiting backend in container B. The hardware substitute uses the
production vCPU topology state machine: B's pool must be admitted on generation
2, after generation 1 ends. It also checks one create, destroy and join per pool
and consecutive carrier identities. This does not prove HVF destruction;
the director's signed EL1/embed and probe batch supplies that integration gate.

The VM-free binding
`failed_worker_releases_its_loaded_binding_before_pool_shutdown` also covers
`kernel.vcpu.vm-lifetime`: both backend error and panic release the loaded
task before the failed worker waits for pool shutdown. Its vCPU stays alive
until that shutdown. Logical failure publication must not retain a binding
whose physical receipt the carrier is waiting for. This retirement gap was
already present before native signal setup allowed these guests to progress.

The VM-free bindings
`abandoned_running_lease_drains_and_closes_its_lifecycle_window` and
`abandoned_implicit_lease_stays_reachable_until_process_shutdown` cover a
running lease dropped before normal container retirement. Its custody passes
to carrier teardown: join workers, retire the exact container graph, destroy
once, then finalize the lifecycle window. The implicit owner stays reachable
until this completes. The state updates its abandoned population during the
ownership transfer and final retirement, so repeated close admission checks
are constant work rather than rescanning all prior abandoned records.
`mixed_owned_and_abandoned_leases_keep_terminal_custody_exclusive` covers
1/8/32 staggered lease drops: the remaining owner prevents destruction,
and final teardown releases the transferred population exactly once.
Failure stays visible, and a subsequent carrier can acquire a new window. Actual HVF destruction and root-slot pool invalidation
remain signed bindings; the production HVF custody owner invalidates that
pool only after successful VM destruction.

## Idle execution custody (`kernel.el1.thread-lifecycle`)

An idle slot can run a native record without loading a host task. Its installed
MM is translation authority, not execution custody for host-owned records in
that MM. Neutral scheduler admission sends such successors and stolen records
to the executor before publishing `OnCpu`; native successors remain runnable.
The two `idle_native_mm_*` scheduler witnesses fail on the prior installed-MM
shortcut and preserve the exact saved context through handback and driver
release. Signed lifecycle, parked-thread, pipe and fork-COW populations remain
the hardware binding; VM-free admission alone does not qualify those runs.

A served EL1 frame may observe host work only after its handler has returned.
In every interrupt mode that late edge is still scheduler work: the vector
preserves the final EL0 return state, recasts the retained frame as an IRQ,
and re-enters the common scheduler IRQ boundary. After the scheduler selects an
IRQ result, one neutral return boundary settles pending work for a native
switched record before that result can commit: its personality owner must
settle the completed frame, park the record, and publish the handoff first. A
request published after a concurrent affinity decision therefore cannot bypass
that switched owner. The emitted-byte
`served_native_frame_with_late_host_work_reenters_irq_boundary` witness and
the instruction-boundary interpreter's
`native_signal_work_cause_never_replays_a_served_syscall` row bind the vector
transition, while
`late_host_work_on_a_switched_native_record_enters_its_owner_boundary` and
`late_host_work_settles_native_owner_before_host_affinity_exit` bind the
scheduler state transition and its affinity interleave without a VM. The signed
populations above remain the hardware binding.
