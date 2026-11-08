# Production CPL0 thread birth remains unwired

Issue #1892 belongs to `kernel.el1.thread-lifecycle`. Its production-entry
binding is
`cpl0_entry::production_clone_thread_runs_and_exits_without_ending_parent`.
The binding is intentionally red until production thread creation is wired;
it must not be ignored or converted into an assertion that ENOSYS is correct.

The fixture already calls `Cpl0Carrier::boot_production`, loads the initial
guest MM and runs `try_run_prepared_kvm_pool`. It supplies a real issued root,
two guest CPUs and the production runtime executor pool. There is no absent
fixture pool to switch on. The initial lifecycle page has thread service
enabled and its gate open.

Production `LinuxPersonality` supplies the shared dispatcher with a
`BornInZoneSource<ParkedContextWords>`, `GuestLifecycleVenue` and registered
native process. It deliberately supplies no ARM `Zone`. However, the
`El1PendingFamilies` implementation of `LifecycleNative::has_scheduler`
requires an ARM scheduler, an ARM zone and a CPU slot. The common Linux
`serve_clone` therefore declines immediately, before checking flags, acquiring
stock, allocating a record or preparing a child. Strict x86 crossing policy
then returns counted ENOSYS (38); clone is not a host crossing. Allowlisting
it would substitute a different owner for the missing in-ring operation.

Changing that first predicate alone cannot repair the path. The same adapter's
`can_prepare_child`, `allocate_record`, `prepare_child`, `enqueue_born`,
`exit_record`, `wake_child_tid`, `release_current` and `run_next` still depend
on the ARM zone and saved frame. The production x86 scheduler instead owns
typed parked contexts and continuation receipts. Moreover, fresh native root
admission leaves `NativeResources::thread_stock` absent: root births depend
on externally supplied stock, whereas native fork children already have the
shared `NativeThreadStock` owner. Production root admission needs retained
control storage and issued, reclaimable identities, not a fixture's fabricated
entry. Stock is a subsequent blocker, not the cause of the first refusal.

`carrick-x86::cpl0_lifecycle::NativeLane` and
`cpl0_lifecycle::x5_shared_clone_exit` implement a different, explicitly bounded
hardware fixture. Its two-context sidecar cannot establish production-pool
thread creation. Moving that sidecar into the production image or preloading
a test sibling would recreate the rejected second path.

## Witness and remaining implementation

The new guest uses glibc thread flags plus CHILD_SETTID, with the parent and
child TID outputs sharing one word. Linux guarantees the parent TID write
before the parent returns from clone; CHILD_SETTID alone would race the
parent's first join. Parent and child exchange a futex handshake, the child
records its own gettid and invokes raw exit, and the parent requires clear-tid
completion and its unchanged gettid before exit_group(7). Clone errors are
reported as positive errno exit codes; other assertion failures use status 9.
Each wait is bounded to five seconds and timeout fails; there is no retry or
polling loop. The clear-tid join uses the shared futex key required by native
Linux's exit wake.

The identical generated ELF exits 7 on native x86 Linux and 38 in the
production KVM pool. This establishes a valid Linux lifecycle witness and
the initial production refusal, not production birth or retirement correctness.
The structural requirement is one guest-owned birth and nonfinal retirement,
zero host clone/exit implementations and zero counted clone refusals. Existing
thread-lifecycle scaling budgets remain unchanged and unqualified by this
single-birth case.

Remaining work is to extend the common lifecycle adapter to typed native
record/context custody, provision root stock through production admission,
and make this unchanged test green. Identity allocation, resource limits,
publication rollback, Busy-once enrollment and terminal draining stay in the
shared owners. ISA code should provide only register/TLS capture and restore.
Then add production two-live-thread exit-group and exec cancellation of a
parked anonymous operation, using the anonymous-operation changes in #1863,
and audit other two-thread x86 production bindings. No terminal witness is
claimed before that dependency and real guest thread birth exist. Signed HVF
acceptance and full lifecycle scaling evidence remain separate gates.
