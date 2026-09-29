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
