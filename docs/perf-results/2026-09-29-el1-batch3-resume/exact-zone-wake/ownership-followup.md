# Bounded service and restore follow-up

Source inspected: `1522bbc05`. This is source evidence, not a runtime or
structural acceptance receipt. Question: which production path can compete
with service delivery or ordinary zone restore to retire the same record?

## Service delivery

`el1_zone::place_service` allocates privately, publishes to a guest queue,
and frees only when placement fails. There is no ZoneWait for this record.
`ZoneTables::take_service_head` removes it under the slot lock while gaining
an owned HostTransfer; its caller in executor.rs obtains the service key,
frees the record, then takes the exact scheduler generation. Slot evacuation
also removes under the queue authority and carries its result to
`settle_vacated`. Service settlement either places the record, requeues it,
or publishes it once to `take_unplaced_service`, which frees it and releases
the held scheduler row. These alternatives do not all execute for one delivery.
The cancellation entry point found in production remains ZoneWait::drop,
which is not attached to service records.

No second service-record retirement owner was found in these production
call chains. Copyable ready references and public raw frees remain weaker
APIs than owned consumption, but their existence alone is not a reproduced
concurrent consumer. Do not add a second lock or lifetime protocol on that
basis. This finding does not license arbitrary duplicate callers.

## Restore and control scheduling

Ordinary backend load receives a RunnableTask borrowing a ThreadExecutionLease
that owns the non-cloneable continuation. Its zone residency is materialized
before the runtime resumes and consumes that continuation. The production
wait_for_materialized path is also reached from backend load; materialize_with
has only test callers in the inspected tree.

Thread::scheduler_control_wake explicitly detects a blocked ZoneWait and
claims its record with Handback::Control. Deferred and El1Held return without
queueing the thread; Claimed/AlreadyHost publish readiness. Stale is also
currently admitted there. The latter needs an explicit terminal/failed-load
association proof; it is not evidence that a currently parked record becomes
host-owned. No source-based attribution of the historical Parked restore
failure follows from this check.

## Next decisive work

Do not widen the service audit or implement a speculative second owner.
Add deterministic lifecycle proof at the existing load/continuation boundary:
exercise control delivery, terminal retirement and failed load while a zone
continuation owns its record, and assert that only the matching host-owned
record can be materialized and retired. Extend the existing signed fixture
and scoped ContractObservation/WorkSnapshot infrastructure where this requires
actual EL1 execution. Preserve the historical crash attribution separately.
Park-sequence exhaustion remains an explicit unresolved identity edge; it is
not the current explanation for the historical failures.
