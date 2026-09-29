# Batch 3 resumed: delayed parent notification

Base: `66302477b6cdc507f8885c03676a605bfc52b693`, branch `integ/batch3`.
Batch 3 is **not accepted or landed**. This receipt covers one deterministic
notification defect; it does not attribute both historical gate failures to it.

## Historical failures recovered

The prior scratchpad survives under
`/private/tmp/claude-501/-Volumes-CaseSensitive-carrick/c786be17-3b68-5086-9933-e629c7f49fcd/scratchpad`.

- `batch3-r3-probes.log`: musl `otmpfileforkexec` failed in the in-process
  auditor with `wake rejected because task task#2:41 was already reaped`.
- `batch3-r3cp1.log`: multiprocessing first hit its 114-second adaptive
  budget; its automatic confirmation then crashed. The confirmation's raw
  `target/conformance/raw/conf-89705-s03.err` reports `SnapshotRestoreFailed`:
  `RecordRef { id: RecordId(1), incarnation: 35925 }` was `Parked { seq: 17965 }`
  when the executor required host ownership. MM cleanup subsequently aborted
  because the active inventory had not retired. This is a distinct observed
  boundary, not evidence of a reaped-task wake.

## Reproduction and reduction

Before edits, the filtered probe and its complete shard passed on the signed
test artifact recorded in `baseline-shard0-artifacts.jsonl`. Both libc probe
lanes ran. Negative entitlement control and scoped cleanup passed. A fixed
100-execution diagnostic sample of the filtered shard also passed, stopping
on first failure by construction. Per-execution logs remain in
`target/el1-resume-b3/otmp-sample/`. These passes do not clear the historical red.

The existing CLI completed the Python workload under `debug lldb-run` with a
180-second diagnostic capture deadline: 395 tests, 51 skipped, four test
files, SUCCESS. No failure occurred, so no LLDB/core capture was triggered.
The preserved CLI identity is discovery provenance only: this run did not
rebuild the inherited CLI. It is not candidate acceptance or a timing claim.

The VM-free reduction captures a parent's signal snapshot, exits and reaps
that exact parent, then delivers the captured endpoint notification. With
the previous `Scheduler::wake(thread.key())`, the auditor records
`WakeOfReapedTask`; see `notification-red.log`. The production method named
`wake_scheduler_exact` was not using the exact scheduler API.

The correction passes the endpoint's exact TaskKey, captured ThreadKey and
current execution generation to the existing `Scheduler::wake_exact`.
Retired identities are benign pending notifications. Child graph publication
and wake subscriptions remain unchanged. No polling, retry, timeout change,
concurrency reduction or auditor weakening is introduced.

## Verification and limits

- Runtime library: 630 passed, 8 existing ignores (`runtime-green.log`).
  The regression and existing live exact-notification test both passed.
  An initial sandbox run had five preparation failures from denied scratch
  directory access; the unrestricted full serial suite passed.
- Runtime all-target Clippy with warnings denied passed.
- Contract: `kernel.wait.child-exit-notification-lifecycle`. Its signed
  deterministic interleaving and WorkObservation bindings remain explicitly
  unresolved. Registry and inventory validation passed with 67 contracts.

Still required: signed candidate regression runs; attribution of the original
probe failure; reduction/fix of the Python parked-record failure; full batch
gate, exact-artifact promotion, and landing. Checkpoint 2/3 integration and
the remaining EL1 controller obligations are untouched.

One unproven lead for Python is deferred slot evacuation: it saves bare
RecordIds and reconstructs RecordRefs later in `settle_vacated`. Investigate
record retirement/reuse across that interval with a deterministic witness;
do not treat this observation as a demonstrated cause or patch it blindly.
