# Shared in-kernel process owner and ARM adoption

The owner is `carrick-el1::personality::{process_owner,
native_process_runtime,native_process_custody,native_process_entry,
native_process_signals}`. Process identities, birth admission, topology,
exit receipts and consuming wait are implemented once in
`carrick-sched-core::process`. The host kernel consumes those same algorithms
and registry types; the native graph is not a mirror of host process rows.

The x86 production CPL0 entry selects this owner unconditionally. Ordinary
fork prepares the child through `carrick-core`'s MM fork transaction, publishes
its admitted lifecycle record, settles physical custody and queues execution.
Wait status copying precedes consuming the exact zombie and its numeric claim.
Exit keeps topology publication, cancellation and notification custody owned.
ISA-specific descriptor encoding, register return construction, copy windows,
physical crossings and CPU resume remain in their existing ISA modules.

`NativeProcessCustody::Context` makes the graph independent of saved-register
layout. The runtime is parameterized by `ProcessContext`, the storage selected
by the ISA's `ArchTypes::Context`; its ISA implementation authenticates the
retained address owner and constructs the child's zero-return context. No
register index, XSAVE/TLS layout or x86 instruction appears in the owner.
VM-free birth/exit/consuming-wait also runs with ARM `ThreadCtx` storage.
This proves shared owner storage and policy, not native ARM execution wiring.

## ARM adoption items

1. Implement `ProcessContext` for ARM's retained context, including exact MM
   generation authentication and child return/TLS/vector preservation. The
   existing `ThreadCtx` storage alone does not retain that complete address
   binding. Keep native conversion in the ARM ISA adapter.
2. Replace N1's separate process route with `NativeProcessRuntime` and
   `NativeProcessService`; bind the actual ARM MM fork prepare/commit/abort,
   physical settlement/quarantine, status copy and retirement venues to the
   shared compact MM transaction and notification authorities.
3. Adopt the real root execution record, lifecycle page/control and visible
   identity. `admit_fresh_root` currently admits one fresh leader and creates a
   local namespace/serial allocator, unit container/credential metadata and
   fresh default signal state. Full launch identity/resource import remains a
   follow-up; do not manufacture a second host process authority.
4. Extend admission for existing multi-threaded populations and native clone
   before replacing ARM thread-group handling. The current runtime retains one
   scheduler member per admitted process; it does not import an arbitrary
   existing thread group. Fresh-root admission refuses a live count other
   than one without changing it. The x86 adapter alone settles its temporary
   bootstrap census before calling the owner.
5. Wire ARM lifecycle dispatch and scheduler handoff receipts to this owner;
   preserve exact task, thread generation, MM and record incarnation. Native
   waits release execution capacity and wake through the retained source.
6. Bind ARM signal action updates, pending delivery and stop/continue events to
   `native_process_signals` and the actual typed blocked-mask source. The
   runtime currently supplies no job-control wait event and starts default
   actions; shared exit/SIGCHLD policy is already used.
7. Preserve explicit refusals for unsupported native services. Non-null wait4
   rusage is currently ENOSYS; nonzero CPU accounting and elastic per-fork
   physical loans are parked on `work/x86-process-owner`, outside this change.
   The retained x86 stock is bounded bring-up capacity, not arbitrary fork
   population support.

ARM call sites and assembly are not migrated by this PR. Signed ARM/HVF runs
are unavailable on the Linux KVM worker; the director owns that adoption gate.
