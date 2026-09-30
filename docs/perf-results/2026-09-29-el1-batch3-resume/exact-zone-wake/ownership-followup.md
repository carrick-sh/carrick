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

## VM-free failed-load settlement witness

The serial kernel witness
`failed_zone_load_settlement_retires_only_its_owned_continuation` now installs
a zeroed, aligned synthetic EL1 region and uses production scheduler and
continuation transitions. A control wake claims the parked record before the
thread can be taken. The taken lease owns the original continuation ID and
RecordRef. `settle_failed(..., SnapshotRestoreFailed)` retires the record
exactly once (one incarnation advance), leaves the thread Failed and queues
nothing. Reusing the same index for a published service record followed by
the old handback preserves the replacement and leaves the queue empty.

All 110 serial kernel tests passed, including this witness; kernel all-target
Clippy and contract registry validation passed. Full logs are the adjacent
load-lifecycle files. The serial-host classification gate also passed.

Two fixture issues were corrected before acceptance: the initial module
placement duplicated the existing serial_host module, and the first reuse
check allocated an unpublished Free record, which live() correctly rejects.
The final test asserts replacement liveness before and after stale delivery.
Neither fixture failure is a kernel red or historical crash attribution.

This tests the production settlement called after failed backend load, not
an actual HVF load refusal. It proves the valid-record control/failed-load
path; it does not certify stale association handling, every terminal path,
park-sequence exhaustion or deterministic signed interleavings. No production
code changed and no new signed regression was run for this test-only change.

## Scoped retired-delivery work observation

The existing red-first deferred-slot witness now evaluates the registered
contract at populations 1, 8 and 32. It counts actual publication callback
invocations within one synthetic zone's deferred-delivery window: all three
observations report zero wakes and retain parked replacements. The contract
enforces an exact zero budget for this VM-free window. For each population,
a negative observation containing one extra wake must fail specifically with
WorkBudgetExceeded for WakePublications (actual 1, maximum 0). The separate
live-record control still requires one publication.

The receipt contains three ContractObservation rows with complete WorkSnapshot
metadata and a combined SHA-256 of el1_zone.rs, shared scheduler lib.rs and ABI
lib.rs. The saved hash was independently recomputed from those source files.
Both focused tests, kernel all-target Clippy and the 68-contract registry pass.
This is a test/descriptor-only extension to the prior red-first repair.

This closes the retired-delivery publication-count observation gap only. It
does not bound queue visits or total work, observe live guest execution,
attribute historical failures, or close signed structural/lifecycle acceptance.

## Parked restore admission control

The existing failed-load witness now first sends both a generic scheduler
wake and an exact wake bound to the owned continuation while the synthetic
record is Parked. Both leave the execution state unchanged, queue no task
and retain the same park sequence. Only the subsequent control claim makes
the record Host-owned before lease acquisition. The existing exact retirement
and stale-after-reuse assertions still pass. See `restore-admission.log`.

This is additional negative coverage of existing behavior, not a newly
reproduced kernel defect or attribution of the historical Python crash. No
production code changed. The sandboxed compile was blocked by DTrace provider
generation; the unrestricted focused serial invocation passed one test.
Do not repeat this source audit absent new evidence: the next missing proof
is the signed evacuation/retirement/reuse interleaving, not another generic
wake smoke test.
