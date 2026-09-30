# Open defect: host publication precedes producer completion

Source: `85abe62cf` (`99c8cd5ac` implementation, `40a707ba0` signed source).
The retained patch adds two VM-free tests to the existing scheduler-core
fixtures; no product source is changed in this diagnostic receipt. Apply it
with `git apply` and run each named test using
`RUSTC_WRAPPER= cargo test -p carrick-sched-core <test-name> -- --nocapture`.
Both ran once and exited 101 on their assertions, not on a timeout.

## Reproduced boundary and consequence

`host_claim_is_not_published_before_queue_cleanup` holds the original futex
bucket, starts the real `claim_for_host` producer, and observes its existing
LockWait callback. The producer has changed Parked to Host but still has one
queue entry to unlink. The check sees `Host { seq: 1 }` while cleanup is
blocked. It releases the lock and joins before asserting, so failure does
not leave a blocked worker.

`host_claim_cleanup_does_not_unlink_a_replacement_waiter` uses the same
boundary, then performs the cancellation decision used by `el1_zone::cancel`:
AlreadyHost permits freeing the record. It allocates and parks a replacement
in the same record slot on a different bucket, then releases the original
bucket. The old producer completes `unlink_all` against the replacement
record: its queue entry count is **0 instead of 1**, while its claim remains
Parked. The final wakeability assertion is not reached because the first
corruption assertion fails. This is a deterministic replacement-queue
mutation, not just an observation of an intermediate state.

The fixture uses channels with a five-second failure bound and the existing
LockWait boundary; it adds no product logging, sleeps or scheduler hooks.
`zone_event_admitted` also directly accepts Host as ready. `ZoneWait::drop`
calls the cancellation path when the continuation is unconsumed.

## Scope and next correction

This is an open lifecycle defect under
`kernel.el1.deferred-handback-identity`; existing green identity-transport
bindings do not cover producer mutation after handback publication. The
witness is retained as a patch so the previously signed candidate remains
reconstructible; it is an explicit red acceptance blocker, not a skipped
or expected-failure test. Promote the witnesses into the test suite with
the ownership correction and update the contract's bindings.

The source on local main `f304f8415` also publishes Host before unlinking;
no main-runtime reproduction or historical Python/otmp attribution is claimed.
The 49 passing signed regressions predate this newly reduced red and do not
close it.

The correction must express an exclusive producer transaction in the claim
protocol, defer host readiness/free/reuse until producer writes and unlinking
finish, and resolve cancellation during transfer without polling or occupying
guest execution capacity. Audit every Host transition and all cancellation,
restore, placement and wake consumers together; moving one store or adding
a non-atomic readiness flag is insufficient. Preserve record incarnation
throughout. Shared ABI changes require rebuilding and signing all affected
artifacts and new exact-source receipts.
