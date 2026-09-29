# Post-publication ownership audit checkpoint

Read-only source audit at `8916e1fe2`, while the signed regression built/ran.
These observations narrow the next investigation; they are not full closure.

## Ordinary zone wait restore

- The only production ZoneWait::new call found is runtime zone.rs settlement.
  ZoneWait is not Clone; its Drop is the only production el1_zone::cancel
  caller found. Cancel reaches raw free through Claim::Host after a live check.
- Thread::claim_runnable moves the boxed blocked continuation out of the
  execution record into ThreadExecutionLease while holding the thread lock.
  RunnableTask borrows that lease. Production backend load validates its
  task image before materialize_zone. Thus this path carries an existing
  continuation lifetime authority; a live-check source pattern alone does
  not demonstrate a cancellation race in normal load.
- The production wait_for_materialized path also originates in backend load.
  Its Zone case calls materialize_zone. TaskCpuResidency::materialize_with
  has test callers; no additional production caller was found.
- resume_zone reads the continuation from the lease, consumes the continuation
  event, reads result/kind through the original RecordRef, then frees by index.
  The non-cloneable continuation and consumed bit matter to that lifetime.

Still required: prove record/continuation association through all terminal,
control-quantum and failed-load paths; decide where existing authority must
be carried in API types rather than merely reconstructed from a RecordRef.
Public constructors, cloned residency and raw free are not a universal lease.
Do not add a second synchronization mechanism merely because live() is weak.

## Service records and deferred delivery

- place_service privately allocates a service record for an exact scheduler
  thread/generation, then places it; failed placement frees the allocation.
- take_service_head returns a ready RecordRef. The executor checks Service,
  obtains service_key and frees by index before scheduler.take_zone.
- take_unplaced_service checks live/kind/Host, obtains service_key, then frees
  by index. settle_vacated may re-place Service records or publish them to
  release their held scheduler row. These records do not have ZoneWait's
  continuation lifetime, so the ordinary loader argument cannot cover them.

Next: enumerate who can retain each ready service reference across delivery
and who may retire it; reduce any competing path before changing ownership.
The owned pending HostTransfer token does not itself prove lifetime after
it has been consumed into a copyable ready RecordRef.

## Exact wake targeting remains open

publish_zone_handback gets thread_key_of, optionally publishes readiness to
an exact thread, then calls untyped wake even when that lookup returned None.
adopt_zone_handback also calls untyped wake after an exact lookup.
wake_exact already authenticates task, thread, generation and optional
continuation ID, and treats retired targets as Pending. A captured-key/reaped
interleaving needs a deterministic reduction before converting these producers;
keep fatal auditors intact. Signed regression green does not attribute the
historical otmpfileforkexec fatal or the Python restore failure.
