# HVPatch lost-wake defect map — 2026-08-22

Produced by a read-only Antigravity worker directed for this purpose, then
checked against a live wedge (see below). Findings are CANDIDATES: two are
CONFIRMED-BY-READING by the worker, none yet confirmed by experiment. The
cleared-paths list is the search nobody has to repeat.

Live corroboration, same day: a `/bin/sh -c '/bin/true; sleep 12'` run wedged
19+ minutes on the asid-root binary; `carrick debug hvpatch-kernel` (now
working) showed ONE live thread (dash, tid 1); `sample` showed executors in
`Scheduler::take -> changed.wait()` and zero `hv_vcpu_run` frames — the
candidate-1 shape. Full core: `target/perf/asid-wedge-24520-full.core` (12G).
Measured rates on the asid-root stack under build load: `/bin/echo hi` hung
2 of 3 runs (rc=124 after printing hi); `/bin/true; sleep 12` hung 2 of 10.
Unmodified main binary, same load: 3 of 3 clean — the exec-authority stack
WIDENS the window (child teardown now genuinely runs), it did not create it:
the closure gate's 415/415 45-second timeouts predate the stack.

# Defect-Candidate Map: Lost Runnable Wakes in HVPatch Persistent Executor

## Numbered Candidate Findings

### 1. In-flight `wake_pending` on a thread settling a `BlockedContinuation` bypasses `CarrierWaitService::publish_event`, causing `ready_event()` in `resume_persistent_continuation` to fail with `MissingContinuation` and terminate the worker/task.
- **Exact Window:**
  - Start edge: [`crates/carrick-runtime/src/kernel/objects.rs:4788-4815`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/kernel/objects.rs#L4788-L4815) (`Thread::scheduler_wake` sets `wake_pending = true` while thread is `Running`/`SwitchingOut`).
  - End edge: [`crates/carrick-runtime/src/kernel/objects.rs:5334-5341`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/kernel/objects.rs#L5334-L5341) (`scheduler_park_continuation_from_executor` promotes directly to `Runnable` upon `wake_pending`) and [`crates/carrick-runtime/src/vcpu_loop/continuation.rs:1202-1206`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/vcpu_loop/continuation.rs#L1202-L1206) (`ready_event` expects `RegistrationState::Ready`).
- **Trigger Shape:** Trigger (a) (child exit) or Trigger (c) (signal delivery) overlapping with a task entering a blocking continuation (e.g. `nanosleep`/`usleep`, `epoll_wait`, `futex_wait`, `wait4`).
- **Concrete Failure Scenario:**
  1. Parent thread P (in `cloneexithandled`) calls `usleep(1000)`; vCPU loop produces `ExecutorExit::BlockedContinuation(Sleep)`.
  2. In [`crates/carrick-runtime/src/vcpu_loop/executor.rs:3320-3321`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/vcpu_loop/executor.rs#L3320-L3321), executor Y runs `prepare_registration` & `enroll`, leaving the entry in `CarrierWaitService` as `RegistrationState::Enrolled`.
  3. Fast child thread C exits before P completes settlement. C calls `notify_child_exit` -> `Scheduler::wake(P)`. Since P is still `Running`/`SwitchingOut`, `P.scheduler_wake` sets `wake_pending = true`.
  4. Executor Y calls `scheduler.settle_blocked_continuation` -> `scheduler_park_continuation_from_executor`. Seeing `wake_pending == true`, it sets P to `Runnable { G+1 }` and enqueues P in `Scheduler::queue.rows`.
  5. An executor takes P from `queue.rows` and enters [`crates/carrick-runtime/src/vcpu_loop/mod.rs:5766-5776`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/vcpu_loop/mod.rs#L5766-L5776) (`resume_persistent_continuation`), which calls `lease.blocked_continuation().ready_event()`.
  6. `ready_event()` inspects `CarrierWaitService.state.entries[&continuation_id]` and fails because `entry.state` is `Enrolled`, NOT `Ready` (`publish_event` was never called by the wait service).
  7. `resume_persistent_continuation` fails with `RuntimeError::Configuration("continuation event: MissingContinuation")`. Executor Y marks P failed via `fail_running_and_retire` ([`executor.rs:3068`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/vcpu_loop/executor.rs#L3068)) and retires it.
  8. P never completes its loop iteration; no further children are spawned; all executor threads park indefinitely in [`crates/carrick-runtime/src/kernel/scheduler.rs:955`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/kernel/scheduler.rs#L955) (`changed.wait()`) until probe timeout (45s).
- **Confidence:** CONFIRMED-BY-READING.
- **Deciding Experiment / Probe:** USDT probe or trace on `ready_event` return value or error path in `resume_persistent_continuation` during `cloneexithandled`.

---

### 2. `notify_child_exit` drops the authoritative scheduler wake when `publish_wake_subscriptions()` returns `true` for an enrolled continuation that finds no deliverable signal.
- **Exact Window:**
  - Start edge: [`crates/carrick-runtime/src/vcpu_loop/mod.rs:907-910`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/vcpu_loop/mod.rs#L907-L910) (`if !published && let Err(error) = endpoint.wake_scheduler_exact(...)`).
  - End edge: [`crates/carrick-runtime/src/vcpu_loop/continuation.rs:2039-2088`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/vcpu_loop/continuation.rs#L2039-L2088) (`SignalReadinessProbe::event()` returns `None`) & [`crates/carrick-runtime/src/vcpu_loop/continuation.rs:2356-2358`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/vcpu_loop/continuation.rs#L2356-L2358) (skips `publish_event`).
- **Trigger Shape:** Trigger (a) (child exit) when parent has an enrolled continuation on another family (e.g. `WaitOnSleep`, `WaitOnFutex`, `WaitOnFds`) and SIGCHLD is unpumped/ignored or not queued.
- **Concrete Failure Scenario:**
  1. Parent thread is parked in `nanosleep` (`WaitOnSleep`) or `futex`. It has an enrolled callback in `task.wake_listeners`.
  2. Child exits with default `SIG_DFL` SIGCHLD (or unhandled exit signal). In [`crates/carrick-runtime/src/vcpu_loop/mod.rs:893-901`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/vcpu_loop/mod.rs#L893-L901), `child_exit_signal_snapshot_needs_pump` is false, so no signal is queued to parent.
  3. `notify_child_exit` calls `signal_context.task().publish_wake_subscriptions()`. It finds the sleep/futex subscription, fires the callback, and returns `published = true`.
  4. The callback runs `publish_task_wake` -> `SignalReadinessProbe::event()`. Because family is `WaitOnSleep` (not `WaitOnHvpatchChild`) and no deliverable signal is pending, `probe.event()` returns `None`.
  5. `publish_task_wake` skips `self.publish_event` -> `scheduler.wake` is NOT called.
  6. In `notify_child_exit`, because `published == true`, line 908 skips `endpoint.wake_scheduler_exact(&signal_snapshot)`.
  7. The child exit wake is completely dropped: no row is enqueued, no condvar signaled.
- **Confidence:** CONFIRMED-BY-READING.
- **Deciding Experiment / Probe:** Check whether `notify_child_exit` calls `wake_scheduler_exact` when a child exits into a parent with an active non-child-wait continuation.

---

### 3. `HvpatchTaskWaker::wake_task` omits `Scheduler::wake`, failing to wake tasks parked in persistent scheduler generations without active host wakers.
- **Exact Window:**
  - Start edge: [`crates/carrick-runtime/src/kernel/objects.rs:3163-3168`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/kernel/objects.rs#L3163-L3168) (`Task::publish_wake` calls `waker.wake_task()`).
  - End edge: [`crates/carrick-runtime/src/vcpu_loop/mod.rs:645-658`](file:///Volumes/CaseSensitive/carrick/crates/carrick-runtime/src/vcpu_loop/mod.rs#L645-L658) (`HvpatchTaskWaker::wake_task` kicks futex, signal arrival, and vcpu kicker, but never `Scheduler::wake`).
- **Trigger Shape:** Trigger (c) (asynchronous signal / `kill` / `tgkill` / kernel topology change) targeting a task parked in `ThreadExecutionState::Blocked`.
- **Concrete Failure Scenario:**
  1. A thread parks in `Blocked` with a reason that does not enroll a `wake_listeners` subscription on `Task`.
  2. Another task sends a signal via `Task::wake()`.
  3. `Task::publish_wake(true)` invokes `HvpatchTaskWaker::wake_task()`.
  4. `HvpatchTaskWaker` kicks the host futex table, signal arrival pipe, and vcpu registry.
  5. Because the thread is not on a host pthread wait or running on a physical vcpu lease, none of these host wakes reach the persistent executor scheduler. `Scheduler::wake` is never invoked, and the thread stays `Blocked`.
- **Confidence:** PLAUSIBLE.
- **Deciding Experiment / Probe:** Audit all callers of `Task::wake()` to verify whether target tasks always have a `wake_listeners` subscription attached.

---

## Cleared Paths Found Sound

1. **`Scheduler::settle_runnable_successor` (`yield` / `preemption`)**: Transitions `Running -> Runnable`, rolls over authority in `HvpatchTaskBindingDirectory`, enqueues row in `queue.rows`, and signals `changed.notify_one()`.
2. **`ProcessDrain::for_scheduler` (Exec sibling drain / process exit drain)**: Upon last sibling decrement (`remaining == 1 -> 0`), line 3684 upgrades `Weak<Scheduler>` and calls `scheduler.wake(thread)`.
3. **`PreparedHvpatchSubmission::activate` (Fork / clone child initial publication)**: Calls `publish_unique` on `SubmissionAuthority`, enqueuing `QueueRow` and signaling `changed.notify_one()`.
4. **`CarrierWaitService` timer expiration in reactor (`run_reactor`)**: Evaluates `now >= deadline` for enrolled entries and calls `publish_event(token, Timeout)` -> `scheduler.wake(token.thread)`.
5. **`CarrierWaitService` fd / poll readiness in reactor**: Revents from `libc::poll` trigger `publish_event(token, Ready)` -> `scheduler.wake(token.thread)`.
6. **`CarrierWaitService` private futex wake (`FutexTable::wake`)**: Bucket generation bump triggers callback -> `publish_event(token, Ready)` -> `scheduler.wake(token.thread)`.
7. **`CarrierWaitService` vfork release (`VforkParentWait::release`)**: Child exec/exit triggers `release`, firing `subscribe_release` callback -> `publish_event(token, Ready)` -> `scheduler.wake(token.thread)`.
8. **`TopologyRelease` lock release (`subscribe_topology_release`)**: Lock release invokes callback -> `scheduler.wake(thread)`.

---

## Top-2 Candidates Explaining `cloneexithandled` / `clone3exithandled`

1. **Rank 1: Candidate 1 (`wake_pending` continuation bypass -> `MissingContinuation` failure)**: In `cloneexithandled`, fast child exit while parent is between `clone` return and `usleep` continuation settlement sets `wake_pending = true`. `scheduler_park_continuation_from_executor` promotes parent to `Runnable` without `CarrierWaitService::publish_event` having transitioned the registration entry to `Ready`. When parent resumes, `ready_event()` returns `MissingContinuation`, causing the parent task to be failed and retired, leaving all executors idle in `changed.wait()`.
2. **Rank 2: Candidate 2 (`notify_child_exit` boolean gate dropping scheduler wake)**: `notify_child_exit` skips `endpoint.wake_scheduler_exact` whenever `publish_wake_subscriptions()` returns `true`, even if `SignalReadinessProbe::event()` returned `None` and dropped the wake without notifying the scheduler.
