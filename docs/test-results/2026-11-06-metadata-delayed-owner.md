# Signed delayed metadata owner population (#1572)

Current-main baseline: `0d5dfaa508e5b92edbe2b18404cd2c7d4230f719`.
On carrick-m4, one signed release executable ran the exact
`el1_metadata_allocator_delayed_owner_parks_participants` test 20 times.
There were **15 passes and five failures**, with no deadline failures.

| Runs | Count | Result |
| --- | ---: | --- |
| 1, 4–7, 10–13, 15–20 | 15 | Pass |
| 2 | 1 | Exit 1, `host_failures=960`, allocator `failures=0` |
| 8, 9 | 2 | Exit 1, `host_failures=64`, allocator `failures=0` |
| 14 | 1 | Exit 1, `host_failures=128`, allocator `failures=0` |
| 3 | 1 | Abort, `entry_binding`, `reason=EntryBinding`, `record=none` |

Every run started exactly one test. Nineteen completed libtest; the abort
did not. Every run's scoped cleanup reported zero remaining processes, and
the executable SHA-256 remained unchanged throughout the population.
No failure reached the final grant/return assertions in this sample.

Fixtures were verified and restored under the exclusive restore lease from
`/tmp/fx-3478.tar.gz`, built at `3478f3b9bf3ad5705c985b7ec6c6480095b394fe`.
The checkout input identity matched
`1e769b2a8667733a568d456e233f99ea3369f46da83f8a036d78a86a6ffe16b1`.
Build and signed execution used the shared `just lease carrick` lease.
The standard signed runner first passed the exact test and entitlement
negative control. A one-run known-answer check then established that the
population capture executed the real test and recorded its terminal result.
Each population run used `CARRICK_RUN_ID=fix1572-base-N` and scoped cleanup
through `scripts/sudo/kill.sh`. The test's existing 20-second observation
and 30-second workload bounds were unchanged; a 90-second outer alarm was
failure-only containment and did not fire.

Durable host evidence is in
`/Users/administrator/m4-host/evidence/1572/`: the fixture restore log,
standard signed artifact receipt, build log, population runner, and `base/`
with full per-run output, cleanup logs, artifact identities and population
rows. This is baseline evidence, not a fix or signed acceptance claim.

An uninstrumented diagnostic run (`fix1572-core-16`) reproduced the
EntryBinding abort and produced `core-38763`. LLDB decoded both event rings
with zero errors. Slot 1 had neither a current nor a home record. Records
6 and 7 retained claim `Retiring { incarnation: 1 }` and a detached metadata
operation (index `u64::MAX`, generation 3, queue zero). The old first-entry
records could no longer execute the adapter that consumes that operation.

The production host adoption in `vcpu_loop/executor.rs::adopt_born_record`
retains the saved retry context in the host thread, then calls
`ZoneTables::free_first_entry_activation`. That entry changes the old claim
to Retiring, but `finish_retiring_record` refuses all operation tokens.
Metadata receipts own no endpoint pin; their old-record lifetime must settle
at this transfer. The current code only discards them under cancellation,
so a successful adoption strands the old record and obstructs registry
rehome. This is an execution-authority settlement defect, not a grant leak.

The VM-free witness
`tests::adopted_first_entry_settles_detached_metadata_receipt` drives actual
record allocation, metadata queue enrollment, host notification, activation
claim and first-entry retirement. On the unchanged implementation it fails
at `adopted metadata receipt stranded a retiring first entry`. Its full red
output is `witness-red-exact.log` in the durable evidence directory.
The initial short filter selected zero tests and an initial draft fixture
refused enrollment; neither is counted as red evidence.

Ten LLDB-launched diagnostic runs passed, as did one syscall-flow trace.
The latter fired service-entry probes but zero syscall-return probes and
is not accepted as syscall-result evidence. The diagnosis uses the core;
the core's counters show uname is served in ring on this main (64 served,
zero forwarded), despite the historical fixture's `host_calls` label.

The correction settles a detached metadata operation under the first-entry
retirement owner's exact terminal claim. Existing cancellation owners keep
their prior claim checks, and queued metadata is not detached by this path.
Adapter operation tokens remain attached: the companion native witness
`first_entry_retirement_preserves_detached_adapter_receipt` requires its
record and incarnation to remain pinned. The metadata witness is green,
and the scheduler regular library suite passes all 268 tests. Its
`serial_host` partition has no tests. Signed proof remains pending.

The first correction's recipe invocation still failed with `host_failures=64`,
although its subsequent predetermined population passed 20/20. That failure
is retained and prevents claiming closure. Review found a second ordering
error: `activate_born_thread` makes the successor runnable before
`adopt_born_record` retires its old activation. Registry rehome can therefore
return Busy while the old record remains Activating, before metadata
settlement even runs.

The signed production witness
`el1_first_entry_retires_before_host_publication` pairs ExecutorTaken with
the exact thread's pre-publication event. It fails on three real records,
each still Activating (`publication-red2.log`). The first draft inspected
an absent control-slot reference; its failure is not counted as evidence.
No sleep or scheduler barrier is used by this witness.

At e7a621204, the signed publication witness passes and the fresh population
is 16/20. Runs 2 and 18 refuse 64 root uname calls each (complete census:
960 served, 64 refused). Run 6 completes the guest correctly but observes
owner=false, parked=3. Run 7 completes the guest but reports one denied
grant, with all 123 successful grants returned. No hangs or aborts occurred;
all 20 binaries finished and all run-scoped cleanup checks passed. This is
not closure; raw evidence is retained under `head2/`.

The contender-before-owner monitor witness is red then green; the monitor
now requires both observations with the original bound. Probe teardown also
waits for publication of the delayed worker's handle before joining it.

A bounded diagnostic captured the first actual uname refusal in a core
(`core-72345`, run 10 in `refusal-core-100`). The lifecycle ring decodes
with zero errors. Root task 1, execution 3, thread serial 2, MM 1 agrees
with current record 1, incarnation 205, OnCpu on slot 2; installed MM is 1.
The root CurrentTask and record both have lifecycle_page=control_slot=0.
Other live records retain nonzero lifecycle references. This explains why
the earlier native-admission and sysinfo-venue diagnostic branches did not
capture these calls: the dispatcher falls back before acquiring that venue.

The record has a `Woken` handback. That alone does not distinguish a host
futex park from an in-guest wake. All three host
park constructors in `vcpu_loop/zone.rs` explicitly set lifecycle_page and
control_slot to zero; the guest scheduler copies those fields into CurrentTask
when resuming the record. This is a candidate source, not yet an attributed cause. The earlier
mapping-Busy fallback hypothesis was not established by this core and is not
being treated as this defect's cause.

A hardware watchpoint on GRANTS_DENIED was qualified against the deliberate
allocation-denial fixture, then used for 100 bounded diagnostic delayed-owner
runs. None hit the watchpoint. These instrumented runs are not acceptance
and do not explain the one denial in the intermediate population.

Two host-park provenance witness attempts reached no host-park constructor
(timed-wait and concurrent allocator respectively). Their absent-coverage
assertions are not red witnesses of the lifecycle loss. The temporary hooks
were removed. The load-time mapping fallback remains to be classified.


## Linux continuation: checkpoint review and publication classification

The continuation preserves the ten earlier commits and rebases them onto the
admitted main `d14143ee8cf40ec4ee34b60959685ca0ee2fa139`. The checkpoint's
unconditional fatal on lifecycle mapping `Busy` is rejected and removed:
contention cannot be turned into a carrier abort. This removes a diagnostic,
not the lifecycle-authority-loss defect.

There are two code paths that permit the observed zero pair:

- `CarrierLifecycleMappings::publish` calls `publish_resolved`, which clears
  the current pair before resolution. A `Busy` result returns successful
  `HostServed`; both backend publication callers discard that outcome and
  continue loading the task. No suspension preserves publication authority.
- The production `zone_park`, `park_owner_memory_action`, and
  `ipc_park_attempt` constructors in `vcpu_loop/zone.rs` explicitly initialize
  both lifecycle references to zero. Allocation and queue publication retain
  that identity in the record. A normal futex `Woken` handback without an
  object operation is allowed by `ZoneRecord::needs_host` to run in ring.
  `carrick_el1::sched::publish_identity` copies the record's zero references
  into `CurrentTask`. An otherwise matching OnCpu execution therefore does
  not prove lifecycle authority survived the host park.

The signed core's `Woken` handback does not prove which path produced it.
Neither source is attributed as the captured failure's cause in this round.
The native-process harness allocates scheduler records directly and bypasses
these production host-park entry points; a helper-only identity test would not
close the missing witness tracked by #1758. No new reproduction or signed
population is claimed.

The structural repair remains open: authenticate the exact task ID, serial,
MM and execution generation before preserving its already published guest
alias pair through a host park, retaining its carrier mapping owners. Host
control addresses are not guest aliases. Mapping refusal also needs an owned
publication continuation enrolled on the existing release notification;
returning `HostServed` does not provide one. No timeout, polling, retry budget
or reduced concurrency is an acceptable substitute.

This Linux clone cannot run signed HVF. Original historical attribution,
paired signed population evidence and two consecutive main signed passes
remain outstanding. The diagnostic removal alone does not satisfy #1572.

## Dispatch continuation: carrier-gate comparison

The branch was already rebased onto the admitted main. The carrier-gate
fixture and its `ProcessCarrierTestGuard` are byte-identical to admitted
main; this lane does not change `prepare.rs` or `carrier.rs`.

The repository runtime recipe (`just _test-unit-runtime`) passes on this
Linux x86_64 worker: 737 passed, zero failed, six ignored. The separately
executed regular and `serial_host` partitions pass with 644 and 93 tests,
respectively (five and one ignored). Both use `RUST_TEST_THREADS=1`, as the
recipe requires for process-wide carrier lifecycle state. In particular,
`process_carrier_test_guard_isolates_leaked_and_concurrent_prepare_leases`
passes. This does not explain the preceding worker's reported failure:
without that invocation and failure output, neither a lane regression nor
test interference has been established. No fixture assertion was weakened.
The exact carrier-gate test also passes on admitted main in a detached
comparison checkout, with the same Linux feature selection and one test
thread. This comparison establishes no current differential failure.

The lifecycle investigation still distinguishes a publication defect from
an attributed cause. A stopped host-park constructor supplies zero aliases;
a subsequent ordinary futex wake can select that record in ring because
`ZoneRecord::needs_host` does not require a host handback for `Woken` without
an object operation. `Sched::load` then publishes the stored identity.
Separately, the loaded-task backend calls `publish_current_task` before
mapping lifecycle backing, and ignores the successful `HostServed` outcome
of a contended mapping. Either path can therefore reach execution without
the lifecycle pair. The observed core does not distinguish them.

Preserving arbitrary values from a vCPU's `CurrentTask` would be unsafe:
an in-ring switch can change its owner. A correction must authenticate the
exact thread and execution generation, retain the guest mapping owners,
and handle first publication as well as resumption. The native-process
fixture's direct record allocation bypasses the production host-park
constructors; injecting a zero identity there would demonstrate only the
consumer, not the publication defect's causal path. No such synthetic
fixture is presented as a red witness or a fix.
