# Core handback identity transport

Base: `b9d7fc35e` on `integ/batch3`; separate admission fixture repair
`d5ca4673a` is documented in `admission-publication.md`.

The deferred-batch correction retained the identity captured by its caller.
The core still returned a bare RecordId after publishing Claim::Host, so a
consumer descheduled at that boundary could capture a replacement incarnation.
The callback witness models cancellation/free/reuse before the consumer reads
its argument: it received incarnation 3 where incarnation 1 was owed. The
returned wake-batch and executor-take witnesses similarly show that the old
return values lose identity across reuse. Raw reds: `core-callback-red.log`
and `core-return-red.log`. API changes adapt how the tests consume the return
values; their expected original incarnation is unchanged.

The core now captures RecordRef before the successful transition to Host and
returns it through drain_slot, take_host_wanted, relocate, wake_host,
step_away/leave_slot/vacate, wake/wake_placed result batches, and
take_service_head. Kernel batches and executor adoption carry that reference
unchanged. A stale service key no longer causes an unconditional free of its
raw table index. Shared-zone record layout and claim encodings are unchanged;
there is no second implementation or compatibility adapter.

Validation:

- Scheduler core: 53 passed; three new identity witnesses.
- EL1 host-test library: 74 passed.
- `just test-kernel`: 2,459 passed, one existing ignore, 21 binaries.
- Kernel serial-host: 109 passed.
- Runtime library, serial: 630 passed, eight existing ignores.
- Scheduler-core/kernel/runtime all-target Clippy with warnings denied passed.
- Registry: 68 contracts. Existing VM-lifetime and MM-occupancy descriptors
  record the mechanical executor-adapter review and retain their regression
  bindings; no claim is made that identity unit tests prove those contracts.

Remaining audit boundaries: a RecordRef authenticates identity, not an
exclusive lease for subsequent field reads/writes. Host publication ordering,
retirement while producers finish their record updates, and the scheduler's
untyped handback wakes still require scrutiny. The already-switched current
record captures its reference before handback in runtime zone.rs. Historical
Python/otmp attribution, deterministic signed interleavings, WorkObservation
bindings and complete batch acceptance remain open. These reductions do not
retroactively attribute a historical crash or accept checkpoint 0.

Signed regression gate at clean source `40a707ba0`:
`CARRICK_RUN_ID=el1-b3-core-handback-20260929 RUSTC_WRAPPER= scripts/test-signed.sh carrick-embed el1_ --nocapture`
exited 0. The machine-counted receipt records 49 passing positive executions
across nine executables: scheduler/memory, interrupt kicks, GIC, parked-thread
crash capture, VM lifetime, files, inotify and transparent execution. The
unentitled negative control passed; scoped cleanup recorded zero remaining
processes. `signed-artifacts.jsonl` preserves SHA-256, CDHash, LC_UUID,
entitlement and DOF presence for each invoked artifact. This broad regression
gate does not supply the missing deterministic signed interleaving bindings.

Clean compiler-backed reconciliation at `40a707ba0` retained all 595 authority
identities with one source-position adjustment. `just lint-domains` passed;
the compiler census covers the macOS subset, with other host profiles pending.
See `reconcile.log`, `lint.log` and `signed.log`.
