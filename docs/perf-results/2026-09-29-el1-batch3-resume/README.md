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
- The rebuilt signed shard at `df9741d88` passed both libc lanes, including
  `otmpfileforkexec`; see `candidate-shard0.log` and
  `candidate-shard0-artifacts.jsonl` for exact source, SHA-256, CDHash, UUID,
  entitlement and DOF identity. Negative entitlement control passed and both
  scoped process censuses were zero. This is regression evidence, not a
  deterministic signed witness for the notification race.
- Compiler-backed authority reconciliation retained all 595 rows unchanged;
  only its source-head stamp changed. Runtime-global-state, runtime-abort,
  dispatch-lock and exact contract-change checks passed.

Still required: attribution of the original probe failure; reduction/fix of
the Python parked-record failure; full batch
gate, exact-artifact promotion, and landing. Checkpoint 2/3 integration and
the remaining EL1 controller obligations are untouched.

## Deferred handback identity reduction

The rebuilt signed CLI at `5ce5bd059` completed the Python diagnostic on
native-arm64 image digest
`3126629643b4adcf57ba5cecdb7f9ed257e733b56cd81da70fd5fdbdc1745b30`:
395 tests, 51 skipped, SUCCESS. No fatal capture triggered; a scoped process
census found no remaining carrier or helpers. Exact executable identity,
command and full guest output are in `deferred-handback/python-before-*`
and `deferred-handback/python-before.log`. The first UUID command used the
wrong dwarfdump executable; the appended `xcrun dwarfdump` result supplies
the actual UUID. This is a pre-correction diagnostic, not acceptance or timing.

Deferred slot evacuation had a separately demonstrated identity defect.
The production path collected bare RecordIds, then reconstructed their
incarnations in `settle_vacated`. The deterministic witness evacuates a
woken waiter, lets cancellation claim and free its host-owned record,
parks a replacement in the reused record, then delivers the saved batch.
The old implementation publishes the replacement incarnation 3:
`deferred-handback/red.log`. This schedule demonstrates the gap; it does
not attribute the historical Python crash to that exact interleaving.

The correction retains RecordRef at collection and skips retired references
at settlement. It publishes the saved reference rather than reconstructing
one after the delay. The witness passes at 1/8/32 records and the live
service handback control still publishes exactly once (`green.log`). No
polling, retries, timeout changes or concurrency reduction were added.

Validation: `just test-kernel` passed 2,459 tests with one existing ignore
across 21 binaries; the separate serial-host kernel run passed 109 tests.
Kernel all-target Clippy with warnings denied, serial-host classification,
and contract registry validation (68 contracts) passed. Raw logs are in
`deferred-handback/`. Contract `kernel.el1.deferred-handback-identity` leaves
deterministic signed interleaving and WorkObservation bindings unresolved.
The producer-side transition to host ownership and every other handback
producer still need review; this correction only closes the demonstrated
deferred-batch identity gap. Batch 3 and migration acceptance remain open.

Source comparison with local main `f304f8415` finds the same bare-ID
collection and reconstruction in its older `settle_vacated` implementation;
`git log -S 'fn settle_vacated'` points to `2fbb84312`. This pattern predates
batch 3. This is source comparison, not a main-runtime Python reproduction.
Compiler-backed inventory reconciliation at `3981c0366` retained all 595
authority rows and all other inventory positions unchanged; only the source
revision stamp changed. Its first sandboxed run failed because clang could
not create a temporary assembly file; the authorized unrestricted run passed.

Signed regression source `0542e2d2f`: all 14 `el1_sched` tests passed, the
negative entitlement control passed, and the runner found zero remaining
processes for both scoped IDs. Full output is `deferred-handback/signed.log`;
`signed-artifacts.jsonl` contains one execution row per selected test and
the exact executable identities. The invoked scheduler executable has SHA-256
`5f2d5f10a70e897315368fa583f191c19de062b55abd8032ce9f982835f58082`,
CDHash `a09c781bb1bedffa492cf21cd1d6721d49f45e47`, UUID
`A5F4951D-63B1-310E-9D81-7B1F00EF4583`, entitlement and DOF present.
This is signed regression coverage, not a forced version of the new race.
`just lint-domains` passed (`lint.log`), explicitly reporting its host-authority
census as the macOS subset, with the six non-macOS profiles pending.

The original Python confirmation's two raw streams are preserved here as
`historical-python.err` and `historical-python.out` from
`target/conformance/raw/conf-89705-s03.{err,out}`. No original failure is
converted into acceptance by the successful diagnostics or focused suites.
