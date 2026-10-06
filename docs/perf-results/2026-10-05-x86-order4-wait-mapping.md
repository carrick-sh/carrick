# Order-4 wait and lifecycle records mapping audit

Order 4 extracts the neutral wait and lifecycle record logic from:
- `crates/carrick-el1/src/personality/mm_portal/edit_wait.rs`
- `crates/carrick-el1/src/sched/object_wait.rs`

into `crates/carrick-core/src/wait.rs`, `crates/carrick-core/src/lifecycle.rs`, and their neutral ABI records in `crates/carrick-core-abi/src/wait.rs` and `crates/carrick-core-abi/src/lifecycle.rs`.

This extraction leaves Linux policy (syscall numbers, errno lowering like ESRCH/EINTR, orig_arg0 handling, TrapFrame mutations) in `carrick-el1`, while moving the neutral coordination, exact generation tracking, release-before-enroll mechanics, and single-winner continuation consumption into `carrick-core`.

## Boundary Error and Refusal Mapping

| Operation / Boundary Condition | Before extraction (EL1) | Neutral core representation | After extraction lowering in EL1 personality | Preserved errno / behavior |
| --- | --- | --- | --- | --- |
| No conflict detected during edit check | `return None` from `park_prepared_edit` (proceed with edit) | `EditWaitOutcome::NoConflict` | `return None` | Unchanged: proceed with syscall execution |
| Resumed token generation / index mismatch against active wait key | `frame.x[0] = (-3i64) as u64; Some(Served::Returned { switched: false })` | `EditWaitOutcome::StaleToken` | `sched.task.orig_arg0.store(frame.x[0], Ordering::Relaxed); frame.x[0] = (-3i64) as u64; Some(Served::Returned { switched: false })` | Exact match: Linux `ESRCH` (errno 3) return without execution |
| Successfully enrolled and parked waiter | `sched.leave_after_object_park(parked)` or `sched.resume_after_object_park(frame, parked, 0)` | `EditWaitOutcome::Parked(T)` | Passes `ObjectParked` ticket to `sched.leave_after_object_park` or `sched.resume_after_object_park` | Exact match: releases CPU / leaves for host |
| Root table lock failed or no prepared wait key in root | `return None` (forward syscall to host) | `EditWaitOutcome::Refused` | `return None` | Exact match: forward to host |
| Park attempted with deadline when slot timer occupied | `Err((ObjectWaitError::Occupied, operation))` | `Err((ObjectWaitError::Occupied, operation))` | `Err((ObjectWaitError::Occupied, operation))` | Exact match: refusal preserves operation token without loss |
| Object predicate changed before park published | `ObjectWaitError::Changed` (causes retry in loop) | `ObjectWaitError::Changed` | Loop retries root lock & check | Exact match: loops until stable or no conflict |
| Record allocation exhausted in scheduler zone | `Err((ObjectWaitError::Exhausted, operation))` | `Err((ObjectWaitError::Exhausted, operation))` | `Err((ObjectWaitError::Exhausted, operation))` | Exact match: token preserved for caller |
| Resumption identity / MM / claim mismatch on CPU | `Err(ObjectWaitError::Stale)` | `Err(ObjectWaitError::Stale)` | Lowers to `ObjectWaitError::Stale` | Exact match: rejects stale / invalid thread resumption |
| Second / concurrent call to take operation token | Returns `None` | `Ok(None)` | Returns `None` | Exact match: single-winner consumption semantics |
| Switched-in record timer expired | `record.object_wait_expired()` | `object_wait_expired(zone, slot)` | Lowers to `ETIMEDOUT` (110) in futex / wait callers | Exact match: deadline expiration detected |

## Invariant and Identity Verification

1. **Exact record generations**:
   - `coordinate_prepared_edit_wait` validates both `token.index() == u64::from(key.index())` and `token.generation() == key.generation()`.
   - Stale generations trigger immediate `EditWaitOutcome::StaleToken` without enrolling or mutating root proposals.

2. **Release-before-enroll**:
   - `coordinate_prepared_edit_wait` explicitly drops the `root` guard before invoking the `park` callback.
   - Prevents deadlock and ensures other vCPUs or host threads can access the reservation table during guest thread park.

3. **One-winner wake and cancel**:
   - `take_object_operation` atomically takes the `Option<OperationToken>` from the record, returning `Some` only to the first winner and `None` to subsequent attempts.
   - Detached handbacks and wake effects are deferred until after zone table locks are dropped.

4. **Owned continuations**:
   - `OperationToken` cannot be forged or replayed from raw integers; it is tracked through `ObjectParked` and returned on wake.
   - Resumption entry PC (`OperationResumePc`) preserves the exact instruction address (e.g. SVC entry) without re-evaluating or re-parsing user descriptors.
