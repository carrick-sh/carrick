# Host requests lost when an EL1 thread parks again

Source: `fb265ba9b` (`276e05673` implementation). Task A remains unaccepted.
`witness.patch` adds two deterministic tests to the real EL1 scheduler host
fixture. Apply it and run:

```
RUSTC_WRAPPER= cargo test -p carrick-el1 --lib --features host-test repark
```

Both compiled and failed in `red.log` (74 existing tests filtered out).
The patch is retained as a red witness, not installed as passing coverage.
No product source changed at this checkpoint.

## Interleaving and impact

Two live guest threads are used. A wakes B and parks; EL1 switches to B.
While B reads its next futex word, the existing UserWord test seam requests
Signal or Cancelled against B's exact original RecordRef. The host receives
El1Held. The fixture marks pending host work, modeling the claimant's kick
arriving after dispatch admission. B finishes the ordinary wait_word path
and exits idle to the host. The fixture then executes the stopped executor's
queue cancellation, wanted-handback and current-record reconciliation.

Cancellation leaves B's record alive. Signal leaves B Parked at sequence 2
instead of host-owned. Neither requires timing, sleeps, polling or a further
futex wake. The original thread's parked record remains separate. The
positive WFI bound is zero; a pending host request must not require sleeping.

Source cause: publish_park clears host_wanted and unconditionally stores
Parked, while wait_word clears the slot current. Exit reconciliation scans
queued records and the current record; B is now neither. Preserving the
cancelled tag alone does not supply a retirement owner. Direct OnCpu-to-Host
handback coverage did not exercise this re-park boundary.

The affected contracts are el1-guest-scheduler and el1-guest-run-queue.
This is VM-free evidence of request loss, not historical Python/otmp failure
attribution, signed guest proof, or migration acceptance.

## Next correction and required coverage

Park admission and a host request against OnCpu must arbitrate atomically.
A separate pre-park flag check has a check/publication window. Make the
host-requested running state explicit in the shared claim protocol, so a
park CAS either wins before the host (which then claims Parked), or loses
and leaves the thread available for the stopped executor. Keep incarnation
binding and cancellation intent. Do not add a global lock, a scan of all
parked records, a polling continuation or a timeout retry.

Audit every OnCpu transition together: park, handback_current, unswitch,
preemption/requeue, switch-in and release. A request that changes the claim
must not turn an existing one-shot CAS into a lost current record. Refused
park must remove any unpublished wait entry, preserve context and syscall
replay semantics, and avoid stale timer enrollment. Include requests before
admission, during enrollment, after park publication and direct handback;
keep ordinary ping-pong, timers, preemption and two-thread progress green.
Update the ABI hash, contract bindings and clean compiler inventory, then
run applicable VM-free and signed gates. Existing signed receipts still
belong to 40a707ba0, not this newer implementation.

Baseline control after removing the witness: all 74 existing EL1 host
tests passed (`baseline.log`). The formatted witness applies cleanly to
the unchanged source. Red-log line numbers precede rustfmt of the patch.

## Correction and current validation

The retained witness patch describes the pre-fix red. Both tests are now
ordinary regression tests. OnCpuRequested makes host-request admission part
of the atomic claim, and publish_guest_park uses CAS instead of overwriting
a running claim. A losing guest park removes its unpublished wait entry and
timer, keeps the current owner and forwards the original syscall/frame.
A winning guest park has no later producer record writes; the host then
claims the published wait through the existing transfer protocol.

Handback, unswitch, preemption and release recognize the requested running
state. Owner transitions allow the one possible OnCpu-to-OnCpuRequested
change, with at most two CAS attempts. Preemption's existing slot lock now
spans Queued publication and insertion. The shared ABI hash includes the
new encoding; the contract bindings include the regression tests.

Additional controls cover a request after enrollment, timer rollback,
a request after successful park publication, and preemption/unswitch of a
requested thread. The actual EL1 test requires forwarding to preserve every
frame register and execute zero WFIs. There is no global scan, added lock,
polling continuation, enlarged timeout or reduced workload concurrency.

VM-free validation: scheduler core 65, EL1 host 76, ABI 32, kernel/semantics
2,459 (21 binaries, one existing ignore), kernel serial 109 (four nested child
runs), runtime 630 (eight existing ignores, one nested child run). All passed.
Affected all-target Clippy with warnings denied and the 68-contract registry
passed. Logs are retained here. Signed guest proof remains outstanding.
This does not close the retirement/restore lifetime audit, exact scheduler
wakes, park-sequence wrap, WorkObservation or full task-A acceptance.

Implementation: `0e1d7c12c`. Clean compiler provenance: `b6810c6e8`.
All 595 census rows and pinned positions remained unchanged. lint-domains
passed for the macOS subset; Linux/FreeBSD/NetBSD profiles remain pending.
Contract-change initially identified omitted futex, deferred-lifetime and
shared-ABI evidence registrations. Binding-only commits `ed32f941d` and
`666f568c7` supply those mappings; the exact `afcf8676e..666f568c7` coverage
gate and final 68-contract registry passed. Both diagnostics and final
coverage log are retained. ABI bindings claim image identity checks only,
not fresh signed acceptance for GIC/fault/metadata/stage-1 behavior.

## Fresh signed regression

Clean source `8916e1fe20a6eee7e174570dc8320973384a03ef` ran:

```
CARRICK_RUN_ID=el1-b3-repark-20260929 RUSTC_WRAPPER= scripts/test-signed.sh carrick-embed el1_ --nocapture
```

Exit 0. Receipt machine validation counted 49 unique passing executions
across nine invoked executables: scheduler/memory 22, files 13, inotify 4,
inotify probe 2, transparent execution 2, GIC 2, host kicks 2, parked-thread
crash capture 1, VM lifetime 1. The unentitled negative control passed.
Both run-scoped cleanup checks found zero remaining processes. All nine
current executable SHA-256 values were independently recomputed and matched
the receipt after execution; CDHash, LC_UUID, hypervisor entitlement and
DOF presence are retained per executable in signed-artifacts.jsonl.

These fresh signed regressions cover the combined transfer, tagged-request
and atomic re-park repairs. They do not force the deterministic re-park
interleaving in a guest and do not supply missing WorkObservation bindings.
No broad conformance/workload promotion, historical failure attribution or
<=2x native-Linux acceptance is claimed. Task A and subsequent B-E remain open.
