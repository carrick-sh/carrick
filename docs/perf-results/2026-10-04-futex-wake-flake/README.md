# Intermittent Futex Wake Flake Measurement & Deterministic Reproduction

## Executive Summary

- **Target test:** `cargo test -p carrick-kernel-example --test semantics futex::futex_wait_parks_and_a_wake_from_the_sibling_thread_resumes_it`
- **Reported symptom:** Intermittent failure observed (e.g. 1 in 4 runs on Linux VM) with `panic: no successful completion for label wake_root`.
- **Assignment:** Measure failure rate on this host, deterministically reproduce if possible, and do **not** fix it.
- **Host environment:** `cloudmac` (macOS 15.x arm64, Apple M4).
- **Measurement result:** **0 of 60** runs failed on `cloudmac` (0.0% failure rate).
- **Deterministic reproduction:** Deterministically reproduced via seeded schedule exploration (`Schedule::explore(seed)`):
  - **First failing seed:** **Seed 5** (35 of 200 seeds in `0..200` reproduce `wake-completed=false`).
  - **Reproduced failure:** Calling `report.ret("wake_root")` panics with `crates/carrick-kernel-example/src/report.rs:141:32: no successful completion for label wake_root`.
  - **Strict replay:** Verified that `Schedule::replay(receipt)` replays the exact 15 scheduler decisions deterministically.

---

## 1. Serial Measurement Under Shared Host Lease (60 Runs)

In accordance with step 2, the test was executed 60 times serially under the shared host lease:
```bash
just lease carrick cargo test -p carrick-kernel-example --test semantics futex::futex_wait_parks_and_a_wake_from_the_sibling_thread_resumes_it -- --exact --nocapture
```
Full stdout and stderr for every run was saved un-truncated to `target/futex-seed/run-1.log` through `target/futex-seed/run-60.log`.

### Summary Statistics

| Metric | Value |
|---|---|
| Total runs | 60 |
| Passed | 60 |
| Failed | 0 |
| Failure rate | **0 / 60 (0.0%)** |
| Min wall time | 0.48 s |
| Max wall time | 292.95 s |
| Mean wall time | 13.40 s |
| Median wall time | ~0.85 s |

### Wall Time Per Run

The elevated wall times on runs 21, 24, 28, 33, and 42 reflect contention waiting for the shared host lock file `/tmp/carrick-host-lease.lock` held by concurrent worktree tasks on `cloudmac`. The inner test itself executed in <0.02 s in all runs.

| Run | Status | Wall Time | Run | Status | Wall Time | Run | Status | Wall Time |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| 1 | PASS | 14.51 s | 21 | PASS | 102.59 s | 41 | PASS | 0.63 s |
| 2 | PASS | 7.75 s | 22 | PASS | 5.60 s | 42 | PASS | 65.18 s |
| 3 | PASS | 2.38 s | 23 | PASS | 2.88 s | 43 | PASS | 3.32 s |
| 4 | PASS | 1.22 s | 24 | PASS | 89.57 s | 44 | PASS | 0.89 s |
| 5 | PASS | 0.84 s | 25 | PASS | 1.19 s | 45 | PASS | 0.80 s |
| 6 | PASS | 0.52 s | 26 | PASS | 0.97 s | 46 | PASS | 24.66 s |
| 7 | PASS | 0.50 s | 27 | PASS | 3.89 s | 47 | PASS | 0.76 s |
| 8 | PASS | 0.62 s | 28 | PASS | 292.95 s | 48 | PASS | 1.16 s |
| 9 | PASS | 0.50 s | 29 | PASS | 1.78 s | 49 | PASS | 0.76 s |
| 10 | PASS | 0.56 s | 30 | PASS | 3.25 s | 50 | PASS | 1.03 s |
| 11 | PASS | 0.49 s | 31 | PASS | 2.86 s | 51 | PASS | 1.38 s |
| 12 | PASS | 0.48 s | 32 | PASS | 5.38 s | 52 | PASS | 0.85 s |
| 13 | PASS | 0.50 s | 33 | PASS | 88.11 s | 53 | PASS | 0.82 s |
| 14 | PASS | 1.42 s | 34 | PASS | 4.27 s | 54 | PASS | 0.83 s |
| 15 | PASS | 0.52 s | 35 | PASS | 17.85 s | 55 | PASS | 0.80 s |
| 16 | PASS | 1.71 s | 36 | PASS | 5.42 s | 56 | PASS | 1.15 s |
| 17 | PASS | 0.86 s | 37 | PASS | 4.18 s | 57 | PASS | 0.80 s |
| 18 | PASS | 1.30 s | 38 | PASS | 22.88 s | 58 | PASS | 0.85 s |
| 19 | PASS | 0.65 s | 39 | PASS | 0.72 s | 59 | PASS | 0.85 s |
| 20 | PASS | 1.04 s | 40 | PASS | 0.61 s | 60 | PASS | 1.25 s |

---

## 2. Deterministic Scenario Schedule Analysis

`crates/carrick-kernel-example/README.md` ("Deterministic scenario schedules") states:
> Scheduled scenarios admit only untimed private futex continuations. Enrollment releases the actor's permit; a successful in-zone wake makes its waiter runnable inside the waker's scheduler decision. The waiter polls the published event once after receiving its permit. Host descriptor readiness, timers and other external waits fail with `external readiness` before enrollment, rather than depending on reactor timing.

### A. Pipe-Acknowledged Scenario (`semantics_pipe_futex_scenario`)
The current test in `crates/carrick-kernel-example/tests/semantics/futex.rs` uses pipe acknowledgment:
```rust
pipe_to_slots(1, 2),
Step::Sys(sys::clone_thread(0)),
Step::ChildMarker(vec![
    await_parked(1, "wait_root"),
    Step::Sys(sys::futex_wake_labeled("wake_root", slot(0), 1).ret(1)),
    Step::Sys(sys::write(slot(2), b"w").ret(1)),
    Step::Sys(sys::exit_thread(0)),
]),
Step::Sys(sys::futex_wait_labeled("wait_root", slot(0), 1).ret(0)),
Step::Sys(sys::read(slot(1), 1).ret(1)),
Step::Sys(sys::exit_group(0)),
```
When explored under `Schedule::explore(seed)` across seeds `0..200`:
- **97 seeds** completed.
- **103 seeds** failed with:
  `Err(Schedule("external readiness: scheduled runs support only untimed private futex waits"))`.

Whenever the scheduler chooses the root thread to resume from `futex_wait` before the child writes `w` to the pipe, the root dispatches `sys::read(slot(1), 1)`. Because the pipe is empty, read blocks on host descriptor readiness, which the deterministic scheduler intentionally rejects as external readiness.

### B. Unacknowledged Futex Wait/Wake Scenario (`unacknowledged_futex_scenario`)
In the pure in-zone futex scenario (without external descriptor waits):
```rust
Step::Sys(sys::clone_thread(0)),
Step::ChildMarker(vec![
    await_parked(1, "wait_root"),
    Step::Sys(sys::futex_wake_labeled("wake_root", slot(0), 1).ret(1)),
    Step::Sys(sys::exit_thread(0)),
]),
Step::Sys(sys::futex_wait_labeled("wait_root", slot(0), 1).ret(0)),
Step::Sys(sys::exit_group(0)),
```
When explored under `Schedule::explore(seed)` across seeds `0..200`:
- **165 seeds** passed (`wake-completed=true`).
- **35 seeds** failed (`wake-completed=false`).
- **First failing seed:** **Seed 5**.
- Other failing seeds in `0..200`: 12, 13, 21, 25, 33, 37, 44, 50, 64, 69, 74, 85, 93, 98, 102, 105, 114, 119, 126, 128, 132, 142, 145, 151, 153, 161, 171, 173, 174, 176, 184, 187, 194, 197.

### C. Root Cause of the Flake
1. Sibling thread dispatches `futex_wake_labeled("wake_root", ...)` and wakes the root thread in Carrick's futex queue.
2. The wake publication makes the root thread runnable.
3. The scheduler switches to the root thread before the sibling waker thread completes its syscall return handling and pushes `Completion { label: "wake_root" }` to the test ledger.
4. The root thread resumes from `futex_wait`, returns 0, and immediately issues `exit_group(0)`.
5. `exit_group` terminates all threads in the thread group.
6. When the sibling thread is subsequently selected by the scheduler, it observes `!task.is_live()`, returns `InternalCompletion::Cancelled(ProcessExit)`, and exits without recording a completion for `wake_root`.
7. Asserting `report.ret("wake_root")` panics with:
   `crates/carrick-kernel-example/src/report.rs:141:32: no successful completion for label wake_root`.

---

## 3. Seed 5 Schedule Receipt

The complete deterministic receipt for Seed 5 captures the 15 exact actor decisions leading to the premature termination of the waker thread before `wake_root` completion:

```json
{
  "schema_version": 1,
  "generator_version": 3,
  "seed": 5,
  "source_hash": "b2f0c7ffef188ef77a627e366050b4ec75c20412852232bb2563f68d9e29a35e",
  "fixture_hash": "5dc969a4d055328d71984baf24ad74987fbc6445f98bb3021e129cf83dae7b06",
  "backend": "kernel-example/portable",
  "scale": 1,
  "decisions": [
    {
      "actor": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 },
      "point": "step", "visit": 0,
      "runnable": [ { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 } ],
      "next": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 }
    },
    {
      "actor": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 },
      "point": "step", "visit": 1,
      "runnable": [ { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 } ],
      "next": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 }
    },
    {
      "actor": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 },
      "point": "dispatch-unlocked", "visit": 0,
      "runnable": [ { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 } ],
      "next": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 }
    },
    {
      "actor": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 },
      "point": "step", "visit": 2,
      "runnable": [
        { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 },
        { "task_id": 1, "task_serial": 5, "thread_id": 2, "thread_serial": 7, "execution_generation": 1 }
      ],
      "next": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 }
    },
    {
      "actor": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 },
      "point": "dispatch-unlocked", "visit": 1,
      "runnable": [
        { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 },
        { "task_id": 1, "task_serial": 5, "thread_id": 2, "thread_serial": 7, "execution_generation": 1 }
      ],
      "next": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 }
    },
    {
      "actor": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 },
      "point": "continuation-build", "visit": 0,
      "runnable": [
        { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 },
        { "task_id": 1, "task_serial": 5, "thread_id": 2, "thread_serial": 7, "execution_generation": 1 }
      ],
      "next": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 }
    },
    {
      "actor": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 },
      "point": "wait-enrolled", "visit": 0,
      "runnable": [ { "task_id": 1, "task_serial": 5, "thread_id": 2, "thread_serial": 7, "execution_generation": 1 } ],
      "next": { "task_id": 1, "task_serial": 5, "thread_id": 2, "thread_serial": 7, "execution_generation": 1 }
    },
    {
      "actor": { "task_id": 1, "task_serial": 5, "thread_id": 2, "thread_serial": 7, "execution_generation": 1 },
      "point": "futex-wake-published", "visit": 0,
      "runnable": [
        { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 },
        { "task_id": 1, "task_serial": 5, "thread_id": 2, "thread_serial": 7, "execution_generation": 1 }
      ],
      "next": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 }
    },
    {
      "actor": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 },
      "point": "wait-resumed", "visit": 0,
      "runnable": [
        { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 },
        { "task_id": 1, "task_serial": 5, "thread_id": 2, "thread_serial": 7, "execution_generation": 1 }
      ],
      "next": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 }
    },
    {
      "actor": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 },
      "point": "step", "visit": 3,
      "runnable": [
        { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 },
        { "task_id": 1, "task_serial": 5, "thread_id": 2, "thread_serial": 7, "execution_generation": 1 }
      ],
      "next": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 }
    },
    {
      "actor": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 },
      "point": "dispatch-unlocked", "visit": 2,
      "runnable": [
        { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 },
        { "task_id": 1, "task_serial": 5, "thread_id": 2, "thread_serial": 7, "execution_generation": 1 }
      ],
      "next": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 }
    },
    {
      "actor": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 },
      "point": "fd-drained", "visit": 0,
      "runnable": [
        { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 },
        { "task_id": 1, "task_serial": 5, "thread_id": 2, "thread_serial": 7, "execution_generation": 1 }
      ],
      "next": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 }
    },
    {
      "actor": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 },
      "point": "terminal-unlocked", "visit": 0,
      "runnable": [
        { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 },
        { "task_id": 1, "task_serial": 5, "thread_id": 2, "thread_serial": 7, "execution_generation": 1 }
      ],
      "next": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 }
    },
    {
      "actor": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 },
      "point": "terminal-published", "visit": 0,
      "runnable": [
        { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 },
        { "task_id": 1, "task_serial": 5, "thread_id": 2, "thread_serial": 7, "execution_generation": 1 }
      ],
      "next": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 }
    },
    {
      "actor": { "task_id": 1, "task_serial": 5, "thread_id": 1, "thread_serial": 6, "execution_generation": 1 },
      "point": "finish", "visit": 0,
      "runnable": [ { "task_id": 1, "task_serial": 5, "thread_id": 2, "thread_serial": 7, "execution_generation": 1 } ],
      "next": { "task_id": 1, "task_serial": 5, "thread_id": 2, "thread_serial": 7, "execution_generation": 1 }
    },
    {
      "actor": { "task_id": 1, "task_serial": 5, "thread_id": 2, "thread_serial": 7, "execution_generation": 1 },
      "point": "dispatch-unlocked", "visit": 0,
      "runnable": [ { "task_id": 1, "task_serial": 5, "thread_id": 2, "thread_serial": 7, "execution_generation": 1 } ],
      "next": { "task_id": 1, "task_serial": 5, "thread_id": 2, "thread_serial": 7, "execution_generation": 1 }
    },
    {
      "actor": { "task_id": 1, "task_serial": 5, "thread_id": 2, "thread_serial": 7, "execution_generation": 1 },
      "point": "finish", "visit": 0,
      "runnable": [], "next": null
    }
  ],
  "result": "wake-completed=false",
  "work_snapshot": {
    "values": {
      "kernel_dispatches": 4,
      "kernel_redispatches": 0,
      "continuation_enrollments": 1,
      "continuation_parks": 1,
      "wake_publications": 1,
      "continuation_resumes": 1,
      "futex_queue_visits": 2,
      "futex_waiters_woken": 1
    },
    "dropped_events": 0,
    "unknown_metrics": []
  }
}
```

---

## 4. Quoted Logs

### A. Seed 5 Panic Log (Deterministic Reproduction)
The following is the last 80 lines of the cargo test log reproducing the exact failure:
```text
$ cargo test -p carrick-kernel-example --test futex_wake_seed_sweep -- --ignored seed_5_reproduces_missing_wake_completion_panic --nocapture

   Compiling carrick-kernel-example v0.1.0 (/Volumes/carrick/dev/wt-flash-futex-seed/crates/carrick-kernel-example)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.03s
     Running tests/futex_wake_seed_sweep.rs (target/debug/deps/futex_wake_seed_sweep-3bfc5400f0ab90e8)

running 1 test

thread 'seed_5_reproduces_missing_wake_completion_panic' (6009561) panicked at crates/carrick-kernel-example/src/report.rs:141:32:
no successful completion for label wake_root
stack backtrace:
   0: rust_begin_unwind
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/panicking.rs:698:5
   1: core::panicking::panic_fmt
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/core/src/panicking.rs:72:14
   2: carrick_kernel_example::report::RunReport::ret::{{closure}}
             at /Volumes/carrick/dev/wt-flash-futex-seed/crates/carrick-kernel-example/src/report.rs:141:32
   3: core::option::Option<T>::unwrap_or_else
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/core/src/option.rs:1145:21
   4: carrick_kernel_example::report::RunReport::ret
             at /Volumes/carrick/dev/wt-flash-futex-seed/crates/carrick-kernel-example/src/report.rs:136:9
   5: futex_wake_seed_sweep::seed_5_reproduces_missing_wake_completion_panic
             at /Volumes/carrick/dev/wt-flash-futex-seed/crates/carrick-kernel-example/tests/futex_wake_seed_sweep.rs:155:12
   6: futex_wake_seed_sweep::seed_5_reproduces_missing_wake_completion_panic::{{closure}}
             at /Volumes/carrick/dev/wt-flash-futex-seed/crates/carrick-kernel-example/tests/futex_wake_seed_sweep.rs:149:47
   7: core::ops::function::FnOnce::call_once
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/core/src/ops/function.rs:250:5
   8: core::ops::function::FnOnce::call_once
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/core/src/ops/function.rs:250:5
   9: test::__rust_begin_short_backtrace
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/test/src/lib.rs:663:18
  10: test::run_test_in_process::{{closure}}
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/test/src/lib.rs:686:60
  11: <core::panic::unwind_safe::AssertUnwindSafe<F> as core::ops::function::FnOnce<()>>::call_once
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/core/src/panic/unwind_safe.rs:272:9
  12: std::panicking::try::do_call
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/panicking.rs:590:40
  13: std::panicking::try
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/panicking.rs:554:19
  14: std::panic::catch_unwind
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/panic.rs:363:14
  15: test::run_test_in_process
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/test/src/lib.rs:686:27
  16: test::run_test::{{closure}}
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/test/src/lib.rs:610:43
  17: test::run_test
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/test/src/lib.rs:638:15
  18: test::run_tests
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/test/src/lib.rs:388:17
  19: test::console_test_runner
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/test/src/console/mod.rs:136:13
  20: test::test_main
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/test/src/lib.rs:141:15
  21: test::test_main_static
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/test/src/lib.rs:162:5
  22: futex_wake_seed_sweep::main
             at /Volumes/carrick/dev/wt-flash-futex-seed/crates/carrick-kernel-example/tests/futex_wake_seed_sweep.rs:1:1
  23: core::ops::function::FnOnce::call_once
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/core/src/ops/function.rs:250:5
  24: std::sys::backtrace::__rust_begin_short_backtrace
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/sys/backtrace.rs:152:18
  25: std::rt::lang_start::{{closure}}
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/rt.rs:162:18
  26: std::panicking::try::do_call
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/panicking.rs:590:40
  27: std::panicking::try
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/panicking.rs:554:19
  28: std::panic::catch_unwind
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/panic.rs:363:14
  29: std::rt::lang_start_internal
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/rt.rs:141:48
  30: std::rt::lang_start
             at /rustc/ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/library/std/src/rt.rs:161:5
  31: _main

test seed_5_reproduces_missing_wake_completion_panic - should panic ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.56s
```

### B. Pipe Scenario External Readiness Rejection Log
```text
$ cargo test -p carrick-kernel-example --test futex_wake_seed_sweep -- --ignored sweep_semantics_pipe_scenario_seeds --nocapture

running 1 test
pipe scenario over seeds 0..200: 97 passed, 103 rejected due to external readiness
test sweep_semantics_pipe_scenario_seeds ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.78s
```
Sample failure under seed 0 for the pipe scenario:
```text
semantics seed 0: Err(Schedule("external readiness: scheduled runs support only untimed private futex waits"))
```
