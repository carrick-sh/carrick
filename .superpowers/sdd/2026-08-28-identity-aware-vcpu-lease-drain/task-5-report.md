# Task 5 report — crash snapshot identity lease drain

Date: 2026-08-28

Base: `261247bff3a4b035b986335fb2c994765d9227cd`

Review-fix base: `44e49acda5f1212e701f689035a895ab3c25a823`

Scope: Task 5 only. The sole production/test source change is
`crates/carrick-runtime/src/vcpu_loop/mod.rs`; Task 6 was not started.

## RED receipts

All eight named Task 5 tests were added before any production helper or crash
path changed. The two exact prescribed filters then failed on the missing
production API:

```text
RUSTC_WRAPPER= cargo test -p carrick-runtime crash_lease_drain --lib -- --nocapture
exit 101
16 expected E0422/E0425/E0433 errors: absent CrashLeaseDrainBudget,
CrashLeaseDrainTimeout, acquire_crash_lease_drain,
crash_lease_drain_park_duration, and finish_crash_collection

RUSTC_WRAPPER= cargo test -p carrick-runtime crash_guard_source --lib -- --nocapture
exit 101
the same 16 missing-production-symbol errors while compiling the complete test
module
```

No production code existed at either red point. The pre-edit focused baseline
was also recorded:

```text
RUSTC_WRAPPER= cargo test -p carrick-runtime core_publication --lib -- --nocapture
exit 0; 9 passed; 0 failed
```

The independent acceptance review found one important coverage gap: the
timeout cleanup test assembled the authority/barrier/helper manually instead
of forcing the failure through `capture_core_for_publication`. The repaired
test was written against the real capture entry point before its test-only
budget setter existed:

```text
RUSTC_WRAPPER= cargo test -p carrick-runtime crash_lease_drain_timeout_releases_collection_and_barriers --lib -- --nocapture
exit 101; E0599: no method named install_crash_lease_drain_budget_for_test
```

The new callback-before-park test also first failed closed at its 250 ms guard.
Investigation showed its `mpsc::recv_timeout` release barrier could itself park
the worker and consume the exact `Thread::unpark` token under test. Replacing
the worker-side synchronization with atomic/yield handshakes kept the worker
out of any other park. The test now proves callback delivery with synchronized
state; the 250 ms timeout is only a fail-closed bound against the configured
one-second poll interval.

## Implementation

- `CrashLeaseDrainBudget` carries the ten-second production timeout and the
  existing 200-microsecond poll interval. Production builds still obtain the
  exact `DEFAULT`; only `cfg(test)` state carries an override. The real capture
  cleanup test installs a zero budget on its `ThreadRuntimeState`, enters
  `capture_core_for_publication`, acquires fork exclusion, advertises crash
  authority, raises task quiescing, then times out on the exact waiting sibling
  lease.
- `CrashLeaseDrainTimeout::{Waiting, Busy}` preserves the exact final sibling
  or conflicting freeze-owner `ThreadId`. `Display` converts each identity to
  an explicit runtime diagnostic, and the crash boundary deliberately maps it
  to `RuntimeError::Configuration` rather than relying on `From`/`?` inference.
- `acquire_crash_lease_drain` atomically subscribes before every observation.
  Waiting and busy subscriptions stay live across the corresponding park, and
  are dropped immediately before re-enrollment. Each park is
  `min(poll_interval, remaining)`.
- A zero/exhausted budget still nudges once and then performs one final
  `subscribe_lease_drain`. That final atomic enrollment either returns a unique
  guard or reports the current exact waiting/busy identity; no diagnostic
  `Complete` poll or remaining-count state can authorize or describe timeout.
- The crash scalar-count loop is deleted. After optional durable-task barrier
  raise, acquisition occurs inside the existing result-producing closure.
  `lease_drain_guard` is owned outside that closure and remains live through
  `prepare_core_snapshot`, process capture, every `CrashQuorum::poll`, every
  `read_core_bytes`, serialization, and construction of owned publication
  bytes.
- `finish_crash_collection` is the common epilogue for success, `Ok(None)`,
  acquisition timeout, and every later error. Its exact order is
  `stop_collecting -> end_quiesce -> end_fork -> drop guard`.

## Lifecycle and timeout-race self-review

1. `try_begin_fork` remains before crash advertisement. Failure there owns no
   collection, quiesce state, or lease guard and therefore needs no epilogue.
2. Every path after `authority.advertise` is captured as `result` inside the
   common fallible envelope. In particular, the explicit timeout mapping uses
   `?` only inside that closure, so it cannot bypass cleanup.
3. Durable task membership still decides whether to raise quiescing. Lease
   enrollment runs regardless of current task size, so a late non-owner
   registration cannot appear after an apparently empty observation.
4. A membership/thaw callback may fire before `park_timeout`; the thread's
   unpark token preserves that wake. Keeping the subscription alive through
   the park prevents cancellation from opening a lost-wakeup interval. The
   nonzero-budget race test synchronizes callback delivery while the nudge is
   still active and proves acquisition completes without waiting the full poll
   interval.
5. Early wake drops the obsolete subscription and re-enrolls against live
   registry state. Deadline wake also drops it and performs one final atomic
   enrollment, closing waiting-member removal and re-registration races.
6. A callback already claimed under the registry lock may execute after the
   subscription is dropped. That can only leave a harmless unpark token; every
   enrollment decision is re-read atomically.
7. Once minted, the unique guard is never moved into a nested snapshot value or
   dropped by an inner `?`. It moves only into the common epilogue after the
   owned bytes/result have been fully constructed.
8. The epilogue stops register collection before releasing either barrier, and
   releases both barriers before guard drop can wake registration or competing
   drain subscribers. The callback test observes `is_quiescing() == false` at
   thaw, while the timeout test proves collection is zeroed and a new fork can
   begin.
9. `CrashQuorum` remains untouched and authoritative for register inventory;
   the new lease guard authorizes only memory coherence and registration
   exclusion.

## GREEN receipts

Fresh final runs on the formatted source:

```text
RUSTC_WRAPPER= cargo test -p carrick-runtime 'vcpu_loop::tests::crash_' --lib -- --nocapture
exit 0; 9 passed; 0 failed

RUSTC_WRAPPER= cargo test -p carrick-runtime crash_lease_drain --lib -- --nocapture
exit 0; 7 passed; 0 failed

RUSTC_WRAPPER= cargo test -p carrick-runtime crash_lease_drain_callback_before_park_completes_without_poll_interval --lib -- --nocapture
exit 0; 1 passed; 0 failed

RUSTC_WRAPPER= cargo test -p carrick-runtime crash_lease_drain_timeout_releases_collection_and_barriers --lib -- --nocapture
exit 0; 1 passed; 0 failed

RUSTC_WRAPPER= cargo test -p carrick-runtime crash_guard_source --lib -- --nocapture
exit 0; 1 passed; 0 failed

RUSTC_WRAPPER= cargo test -p carrick-runtime crash_teardown_releases_barrier_before_guard --lib -- --nocapture
exit 0; 1 passed; 0 failed

RUSTC_WRAPPER= cargo test -p carrick-runtime core_publication --lib -- --nocapture
exit 0; 9 passed; 0 failed

RUSTC_WRAPPER= cargo check -p carrick-runtime
exit 0

RUSTC_WRAPPER= cargo clippy -p carrick-runtime --all-targets -- -D warnings
exit 0

RUSTC_WRAPPER= just fmt-check
exit 0

git -c core.fsmonitor=false diff --check
exit 0
```

The final source contract contains no crash-path `kicker.count()` decision.
Task 6 probe/diagnostic compatibility deletion and Task 7 campaign gates remain
deliberately unclaimed.
