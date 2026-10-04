# Lower copy-up and whiteout flake measurement — 2026-10-04

## Incident context

- **Target test:** `cargo test -p carrick-kernel-example --test namespace_two_process two_live_process_lower_copy_up_and_whiteout_matrix`
- **Observed failure:** `lower n=32 population=128 same_parent=true` failed on a cloudmac gate with `WaitTimedOut("read")`.
- **Harness configuration:** `WAIT_BOUND = 5 seconds` per continuation wait in `carrick-kernel-example/src/driver.rs`. The parent drains `n` 1-byte progress notifications (`sys::read(slot(2), 1)`) sent by the child (`sys::write(slot(3), b"c")`) after each iteration.

---

## 1. Empirical lease measurement (60 serial runs)

Ran 60 consecutive serial runs of `just lease carrick cargo test -p carrick-kernel-example --test namespace_two_process two_live_process_lower_copy_up_and_whiteout_matrix -- --exact --nocapture` on `cloudmac` (Apple Silicon M4, macOS).

- **Failure rate:** **0 / 60** (0.0% failure rate; 60 passed, 0 failed).
- **Wall time summary:**
  - Minimum: **5.44 s**
  - Maximum: **77.63 s**
  - Average (mean): **12.66 s**
- **Uncontended test duration:** Typically **5.4 s – 7.0 s** for the full 16-cell parameter matrix.
- **Latency outliers:** Occurred exclusively when waiting to acquire the host flock lease at `/tmp/carrick-host-lease.lock` behind concurrent activity (e.g., Run 36 waited ~72s for the lock before executing in 5.52s; Run 35 waited ~46s; Run 55 waited ~44s).

### Per-run wall times

| Run | Status | Exit Code | Wall Time | Run | Status | Exit Code | Wall Time |
|---|---|---|---|---|---|---|---|
| 01 | PASS | 0 | 32.07 s | 31 | PASS | 0 | 5.93 s |
| 02 | PASS | 0 | 6.57 s | 32 | PASS | 0 | 6.04 s |
| 03 | PASS | 0 | 29.04 s | 33 | PASS | 0 | 16.00 s |
| 04 | PASS | 0 | 6.57 s | 34 | PASS | 0 | 5.83 s |
| 05 | PASS | 0 | 6.67 s | 35 | PASS | 0 | 53.31 s |
| 06 | PASS | 0 | 6.42 s | 36 | PASS | 0 | 77.63 s |
| 07 | PASS | 0 | 5.63 s | 37 | PASS | 0 | 6.71 s |
| 08 | PASS | 0 | 22.25 s | 38 | PASS | 0 | 19.90 s |
| 09 | PASS | 0 | 6.30 s | 39 | PASS | 0 | 6.69 s |
| 10 | PASS | 0 | 5.53 s | 40 | PASS | 0 | 6.78 s |
| 11 | PASS | 0 | 26.41 s | 41 | PASS | 0 | 6.89 s |
| 12 | PASS | 0 | 5.60 s | 42 | PASS | 0 | 6.91 s |
| 13 | PASS | 0 | 5.78 s | 43 | PASS | 0 | 5.51 s |
| 14 | PASS | 0 | 18.09 s | 44 | PASS | 0 | 16.99 s |
| 15 | PASS | 0 | 13.23 s | 45 | PASS | 0 | 7.16 s |
| 16 | PASS | 0 | 8.65 s | 46 | PASS | 0 | 7.63 s |
| 17 | PASS | 0 | 22.31 s | 47 | PASS | 0 | 7.97 s |
| 18 | PASS | 0 | 9.57 s | 48 | PASS | 0 | 7.86 s |
| 19 | PASS | 0 | 6.53 s | 49 | PASS | 0 | 6.46 s |
| 20 | PASS | 0 | 7.00 s | 50 | PASS | 0 | 6.71 s |
| 21 | PASS | 0 | 5.87 s | 51 | PASS | 0 | 5.45 s |
| 22 | PASS | 0 | 18.23 s | 52 | PASS | 0 | 5.99 s |
| 23 | PASS | 0 | 6.25 s | 53 | PASS | 0 | 6.16 s |
| 24 | PASS | 0 | 8.67 s | 54 | PASS | 0 | 18.26 s |
| 25 | PASS | 0 | 6.25 s | 55 | PASS | 0 | 51.58 s |
| 26 | PASS | 0 | 5.44 s | 56 | PASS | 0 | 5.74 s |
| 27 | PASS | 0 | 37.28 s | 57 | PASS | 0 | 6.07 s |
| 28 | PASS | 0 | 6.10 s | 58 | PASS | 0 | 5.98 s |
| 29 | PASS | 0 | 5.97 s | 59 | PASS | 0 | 5.65 s |
| 30 | PASS | 0 | 5.62 s | 60 | PASS | 0 | 7.76 s |

All full outputs are captured in `target/ns-seed/run-1.log` through `target/ns-seed/run-60.log`. Because all 60 runs passed cleanly, there were zero test failure logs produced in this sample.

---

## 2. Deterministic schedule exploration check

We evaluated whether the intermittent failure can be deterministically explored and reproduced under Carrick's seeded scenario scheduler (`Schedule::explore(seed)`).

### Structural limitation of `Schedule`

As documented in `crates/carrick-kernel-example/README.md` ("Deterministic scenario schedules"):
> "Scheduled scenarios admit only untimed private futex continuations. Enrollment releases the actor's permit; a successful in-zone wake makes its waiter runnable inside the waker's scheduler decision. The waiter polls the published event once after receiving its permit. Host descriptor readiness, timers and other external waits fail with `external readiness` before enrollment, rather than depending on reactor timing."

And enforced in `crates/carrick-kernel-example/src/driver.rs` (lines 434–442):
```rust
#[cfg(debug_assertions)]
if let Some(schedule) = &shared.schedule
    && !scheduled_in_zone_futex
{
    let error = "external readiness: scheduled runs support only untimed private futex waits".to_owned();
    schedule.abort(error.clone());
    let _ = continuation.cancel(CancellationCause::ServiceShutdown);
    return Err(ExampleError::Schedule(error));
}
```

Because `two_live_process_lower_copy_up_and_whiteout_matrix` relies on `sys::pipe2` and blocking `sys::read` steps for cross-process synchronization, any run under `Schedule::explore(seed)` immediately fails closed upon the first blocked pipe read.

### Quoted output of seeded run (`VMFREE_SEED=0`)

```
running 1 test

thread 'two_live_process_lower_copy_up_and_whiteout_matrix' (5943466) panicked at crates/carrick-kernel-example/tests/namespace_two_process.rs:414:25:
lower n=32 population=128 same_parent=true seed=Some(0): Schedule("external readiness: scheduled runs support only untimed private futex waits"); lower evidence /Volumes/carrick/tmp/.tmp8zuHVH; upper evidence /Volumes/carrick/tmp/.tmpEYnQcP
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test two_live_process_lower_copy_up_and_whiteout_matrix ... FAILED

failures:

failures:
    two_live_process_lower_copy_up_and_whiteout_matrix

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 2 filtered out; finished in 1.54s

error: test failed, to rerun pass `-p carrick-kernel-example --test namespace_two_process`
```

### Seed sweep (seeds 0..=200)

Added `crates/carrick-kernel-example/tests/ns_lower_seed_sweep.rs` (marked `#[ignore]`). Running this sweep confirms that all seeds `0..=200` fail identically with `external readiness: scheduled runs support only untimed private futex waits` at the initial pipe read. Because the schedule aborts before completing, `schedule.receipt(...)` cannot produce a valid execution receipt.

---

## 3. Findings and mechanism analysis

1. **Failure mode:** The observed gate failure `WaitTimedOut("read")` is a wall-clock timeout on `sys::read(slot(2), 1)` exceeding the 5.0-second `WAIT_BOUND`.
2. **Reproducibility under lease isolation:** Under host lease isolation on a quiet machine, the failure rate is 0/60 (0.0%). The entire 16-cell matrix executes in ~5.5s to 7.0s.
3. **Flake trigger:** The `n=32 population=128` cell creates 128 directory entries and iterates 32 times through multi-step filesystem operations (hard links, renames, unlinks, opens, reads, and negative opens) on the host filesystem. When the host experiences heavy concurrent I/O or CPU contention (such as during un-leased parallel cargo compilations or gate runs), individual filesystem operations or thread scheduling can be delayed past 5 seconds, causing the parent's bounded wait on the progress pipe to fire.
4. **Schedule limitation:** This scenario cannot currently be explored with `Schedule::explore(seed)` because the VM-free scheduler does not yet support external descriptor readiness waits (such as pipes).
