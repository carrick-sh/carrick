# Native Fork Waiter Reset Implementation Plan

> **Execution requirement:** Follow this plan with the
> `superpowers:test-driven-development` and
> `superpowers:systematic-debugging` skills. Do not implement the proposed
> reset unless Task 1 first reproduces the inherited-lock hang.

**Goal:** Make a Darwin-native fork child discard the copied, contended
`THREAD_WAITERS` parking-lot state before signal reinitialization, eliminating
the deterministic `cpython-threading` timeout without weakening signal wakeup
semantics.

**Architecture:** Replace the single `LazyLock<Mutex<HashMap<...>>>` with a
fork-resettable registry whose active backing is published through an
`AtomicPtr`. The prepare phase allocates an empty replacement before `fork(2)`
and locks the current backing. The parent unlocks normally and frees its unused
replacement. The child atomically publishes the preallocated replacement and
intentionally does not unlock or destroy the inherited contended backing. The
existing `drop(fork_signal_locks)` call remains the sole parent/child handoff.

**Tech stack:** Rust 1.96, `parking_lot`, Darwin `fork(2)`, Carrick signed native
conformance harness, LLDB/event-ring evidence when the deterministic reducer
does not match the live failure.

**Controller design:**
[`docs/superpowers/specs/2026-07-13-native-default-conformance-quality-design.md`](../specs/2026-07-13-native-default-conformance-quality-design.md)

---

## Task 1: Pin the copied-contention mechanism with a bounded red test

**Files:**

- Modify: `crates/carrick-vmm-hvf/src/host_signal.rs` (`mod tests`)

- [ ] **Step 1: Add a reusable bounded child reap helper.**

  In `host_signal::tests`, add
  `wait_for_child_exit_bounded(pid: libc::pid_t, timeout: Duration) -> i32`.
  Poll `waitpid(pid, &mut status, WNOHANG)` every 10 ms. On deadline, send
  `SIGKILL`, reap the child, and panic with the last status. This keeps a
  regression bounded instead of hanging the whole unit-test process.

- [ ] **Step 2: Add `fork_child_resets_contended_thread_waiters`.**

  The test must:

  1. hold `crate::fork_test_lock()` and `TEST_LOCK` for its whole lifetime;
  2. call `reset_after_supervisor_fork()` to start from empty waiter state;
  3. acquire `let signal_locks = hold_signal_locks_for_fork();`;
  4. start a host thread which reports that it is about to lock
     `THREAD_WAITERS`, then blocks on `THREAD_WAITERS.lock()`;
  5. wait for that report and sleep 50 ms so the waiter enters the parking-lot
     contention path;
  6. call `libc::fork()` while `signal_locks` is still held;
  7. in the child, call `drop(signal_locks)`, then `reinit_after_fork()`, then
     `_exit(0)`;
  8. in the parent, drop `signal_locks`, join the contender, and require the
     child to exit zero within two seconds.

  Keep the test on the current public prepare/drop sequence. Do not add a
  test-only child reset call that production would not execute.

- [ ] **Step 3: Run the focused test and observe RED.**

  Run:

  ```bash
  cargo test -p carrick-vmm-hvf fork_child_resets_contended_thread_waiters -- --nocapture
  ```

  Expected RED: the helper reaches its two-second deadline because the child
  blocks in `reinit_after_fork -> clear_thread_waiters -> Mutex::lock`.

- [ ] **Step 4: Stop if the expected RED is absent.**

  If current code exits promptly, do not implement the pointer-reset design.
  Repeat with LLDB attached to the child and increase only the deterministic
  contention setup. If the child blocks somewhere other than
  `clear_thread_waiters`, update the controller design and ledger with the new
  measured mechanism before continuing.

## Task 2: Introduce the fork-resettable waiter registry

**Files:**

- Modify: `crates/carrick-vmm-hvf/src/host_signal.rs` (imports, waiter static,
  prepare guard, waiter call sites)

- [ ] **Step 1: Add the explicit waiter map and registry types.**

  Define:

  ```rust
  type ThreadWaiterMap = HashMap<i32, ThreadWakeRegistration>;

  struct ForkResetWaiterRegistry {
      current: AtomicPtr<Mutex<ThreadWaiterMap>>,
  }
  ```

  Import `std::mem::ManuallyDrop` and `std::sync::atomic::AtomicPtr`. Construct
  the initial backing in `ForkResetWaiterRegistry::new()` with
  `Box::into_raw(Box::new(Mutex::new(HashMap::new())))`. Keep the registry in a
  `LazyLock` so allocation never occurs during static initialization.

  Add `lock(&self) -> parking_lot::MutexGuard<'_, ThreadWaiterMap>` which loads
  the published pointer with `Ordering::SeqCst`, documents why it is valid, and
  dereferences it in one narrowly scoped `unsafe` block. Published backings are
  never freed in that process.

- [ ] **Step 2: Add a child-aware waiter prepare guard.**

  Define a private `ThreadWaitersForkGuard` containing:

  ```rust
  registry: &'static ForkResetWaiterRegistry,
  owner_pid: libc::pid_t,
  guard: ManuallyDrop<parking_lot::MutexGuard<'static, ThreadWaiterMap>>,
  fresh: ManuallyDrop<Box<Mutex<ThreadWaiterMap>>>,
  ```

  `ForkResetWaiterRegistry::hold_for_fork(&'static self)` must allocate `fresh`
  before acquiring the active mutex, then record `libc::getpid()` and the
  acquired guard.

  Its `Drop` implementation must branch on `libc::getpid() == owner_pid`:

  - parent/error branch: manually drop the mutex guard, then the unused fresh
    box;
  - child branch: take the preallocated box, convert it with `Box::into_raw`,
    publish it with `Ordering::SeqCst`, and deliberately leave the inherited
    mutex guard/backing undropped.

  The child branch must not allocate, traverse the inherited map, unlock the
  inherited mutex, close inherited waiter fds, or run their `Arc` destructors.

- [ ] **Step 3: Keep the existing fork call-site contract.**

  Change `SignalForkLocks::_waiters` to `ThreadWaitersForkGuard`. Acquire the
  child-watch and thread-pending guards in the existing order, then acquire the
  waiter guard. Declare `_waiters` first in `SignalForkLocks` so its child-side
  reset runs before the other fields are dropped.

  Do not change `crates/carrick-runtime/src/native_darwin.rs`; it must continue
  to call:

  ```rust
  let fork_signal_locks = crate::host_signal::hold_signal_locks_for_fork();
  let child = unsafe { libc::fork() };
  drop(fork_signal_locks);
  ```

- [ ] **Step 4: Route every waiter operation through the registry.**

  Preserve the existing `THREAD_WAITERS.lock()` call shape by giving the
  registry a `lock` method. Verify all five operation classes use the active
  backing: register, unregister, clear, wake-one, and wake-all. Do not reset
  `THREAD_PENDING` or `child_watch` through this mechanism; the live stack
  reached the waiter lock only after those clears succeeded.

- [ ] **Step 5: Run the focused test and observe GREEN.**

  ```bash
  cargo test -p carrick-vmm-hvf fork_child_resets_contended_thread_waiters -- --nocapture
  ```

  Expected: the child exits zero well inside two seconds and the contender
  joins in the parent.

## Task 3: Preserve nearby signal and fork behavior

**Files:**

- Test: `crates/carrick-vmm-hvf/src/host_signal.rs`
- Test: `crates/carrick-vmm-hvf/src/fork_coord.rs`
- Test: `crates/carrick-vmm-hvf/src/vcpu_kick.rs`

- [ ] **Step 1: Run all HVF library tests.**

  ```bash
  cargo test -p carrick-vmm-hvf --lib
  ```

  Expected: all tests pass, including waiter private-pipe delivery, broadcast,
  fork coordination, and signal-pump tests.

- [ ] **Step 2: Run formatting and targeted lint gates.**

  ```bash
  just fmt-check
  cargo clippy -p carrick-vmm-hvf --all-targets -- -D warnings
  ```

  Expected: both commands pass without suppressing new warnings. Any `unsafe`
  block added for the stable backing pointer has a local safety explanation.

## Task 4: Prove the originating CPython timeout is gone

**Files:**

- Modify: `docs/native-default-conformance-campaign.md`
- Evidence: `target/conformance/native-waiter-cpython-threading-*.jsonl`

- [ ] **Step 1: Build and codesign the current CLI.**

  ```bash
  just build
  ```

  Expected: release build and codesign succeed. Do not run a guest from an
  unsigned `cargo build` artifact.

- [ ] **Step 2: Run the isolated originating suite serially.**

  ```bash
  CARRICK_RUN_ID=native-waiter-cpython-serial \
    just conformance full --lane macos-native-dsr --workers 1 \
    --suite cpython-threading \
    --jsonl target/conformance/native-waiter-cpython-threading-serial.jsonl \
    --force
  ```

  Expected: the suite completes; no child is stuck in
  `host_signal::clear_thread_waiters`. Its content verdict may still expose the
  separately tracked post-fork thread-creation guard and must be recorded
  honestly rather than projected as `MATCH`.

- [ ] **Step 3: Sample the suite under load three times.**

  Run the same suite three times with `--workers 4`, distinct
  `CARRICK_RUN_ID`s, and distinct JSONL paths ending in `load-r1`, `load-r2`,
  and `load-r3`.

  Expected: all three runs complete without `TIMEOUT` or `CARRICK_CRASH` and
  agree on their content verdict. Reap only the scoped run id with
  `scripts/sudo/kill.sh` if a run fails to clean up.

- [ ] **Step 4: Record measured evidence in the ledger.**

  Add rows for the focused unit test, serial CPython result, and three loaded
  samples. Update the P0 cluster status only from the completed artifacts. If
  a loaded timeout recurs, capture an LLDB core before changing more locks.

## Task 5: Commit the waiter reset as one logical fix

**Files:**

- Modify: `crates/carrick-vmm-hvf/src/host_signal.rs`
- Modify: `docs/native-default-conformance-campaign.md`

- [ ] **Step 1: Review the final diff and preserve unrelated dirt.**

  ```bash
  git diff --check
  git status --short
  git diff -- crates/carrick-vmm-hvf/src/host_signal.rs \
    docs/native-default-conformance-campaign.md
  ```

  Expected: only the waiter reset, its regression test, and measured ledger
  rows are in scope. Leave `.codex/` and `last_1000_commits.txt` untracked.

- [ ] **Step 2: Commit with verification receipts.**

  Use a commit such as:

  ```text
  fix(native): reset contended signal waiters after fork

  A fork child inherited the parking-lot waiter mutex with copied contention
  state and wedged while clearing signal waiters. Publish a preallocated empty
  waiter backing in the child while leaving the inherited backing untouched.

  Verified with the contended-fork regression test and repeated signed
  cpython-threading native-lane runs.

  Co-Authored-By: Codex <codex@openai.com>
  ```
