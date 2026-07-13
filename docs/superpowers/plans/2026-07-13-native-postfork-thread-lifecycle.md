# Native Post-Fork Thread Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILLS: Use
> `superpowers:executing-plans`, `superpowers:test-driven-development`,
> `superpowers:systematic-debugging`, and `carrick-native-debug`. Execute the
> evidence gate before selecting a repair branch.

**Goal:** Let a native Darwin guest create pthreads after `fork` followed by
emulated `execve`, closing the Go, CPython, and Node real-workload blocker
without exposing the known Darwin post-fork host-runtime trap.

**Architecture:** Keep the production path fail-closed while a narrowly named,
exact-value diagnostic switch bypasses the current post-fork clone rejection.
A staged static-PIE reducer performs `fork -> execve -> pthread_create`; its
unsafe run is captured under LLDB and the same experiment is sampled in Node,
Go, and CPython. If the failure belongs to copied Carrick state, add the missing
fork/exec reset with a deterministic red test. If fresh host pthread creation
is unsafe because of irreparable Apple runtime state, stop incremental repair
and design a PID-preserving self-reexec handoff before changing production
semantics. Remove the unsafe switch and the blanket guard only after the
supported path survives repeated reducer and ecosystem runs.

**Tech stack:** Rust 1.96, Darwin pthreads and `fork`, Carrick DSR, static
AArch64 musl probes, `carrick debug lldb-run`, signed native conformance lanes,
and the native arm64 Docker oracle.

**Controller design:**
[`docs/superpowers/specs/2026-07-13-native-default-conformance-quality-design.md`](../specs/2026-07-13-native-default-conformance-quality-design.md)

## Global constraints

- Post-fork guest thread creation is a real-workload requirement. It cannot be
  blessed as an accepted gap.
- The default behavior remains `EOPNOTSUPP` until a supported lifecycle is
  proved. The diagnostic switch is explicitly unsafe and accepts only the
  exact value `1`.
- Do not convert the guard into an automatic HVF fallback or a shell-level
  workaround.
- Do not add unconditional logging. Use LLDB, the native fatal record, the
  event ring, or existing opt-in diagnostics.
- Build and run the relinked CLI with `just build`; verify its signature before
  executing a guest.
- Never run Carrick and Docker concurrently. Stamp every run with a unique
  `CARRICK_RUN_ID` and reap through the canonical checkout's scoped kill helper.
- Treat a SIGABRT, libdispatch trap, timeout, or load-only failure as evidence,
  not flakiness. Preserve LLDB logs and cores under `target/conformance/`.
- Keep measured results separate from targets in
  `docs/native-default-conformance-campaign.md`.
- Commit each independently reviewable behavior change with a Conventional
  Commit body and `Co-Authored-By: Codex <codex@openai.com>`.

## Task 1: Add a fail-closed diagnostic bypass

**Files:**

- Modify: `crates/carrick-runtime/src/native_darwin.rs`

**Interfaces:**

- Produces: `native_unsafe_postfork_threads_enabled(value: Option<&OsStr>) ->
  bool`.
- Reads: `CARRICK_NATIVE_UNSAFE_POSTFORK_THREADS` only in
  `native_clone_thread_rejection`.

- [x] **Step 1: Add parser tests before implementation.**

  Add a pure unit test that requires `None`, the empty string, `0`, `true`, and
  `01` to be false, and only `Some(OsStr::new("1"))` to be true. Do not mutate
  the process environment in a parallel Rust test.

- [x] **Step 2: Run the focused test and observe RED.**

  ```bash
  cargo test -p carrick-runtime native_unsafe_postfork_threads_requires_exact_one --lib -- --nocapture
  ```

  Expected RED: the parser does not exist.

- [x] **Step 3: Implement the pure parser and guarded bypass.**

  In `native_clone_thread_rejection`, preserve the existing fork-child reason
  unless the parser accepts
  `std::env::var_os("CARRICK_NATIVE_UNSAFE_POSTFORK_THREADS").as_deref()`.
  The switch bypasses only the fork-child rejection; it must not bypass
  `native16k_clone_thread_rejection` or any W+X lifecycle check.

- [x] **Step 4: Verify the focused unit and targeted lint.**

  ```bash
  cargo test -p carrick-runtime native_unsafe_postfork_threads_requires_exact_one --lib -- --nocapture
  cargo clippy -p carrick-runtime --lib -- -D warnings
  ```

  Expected: both pass, and production behavior is unchanged without the exact
  unsafe opt-in.

## Task 2: Pin fork-exec-pthread behavior with a staged probe

**Files:**

- Add: `conformance-probes/src/bin/forkexecpthread.rs`
- Modify: `crates/carrick-cli/tests/conformance.rs`

**Interfaces:**

- Stage 1 forks and waits for one child.
- The child `execve`s the same `/tmp/p` or `argv[0]` image with `stage2`.
- Stage 2 calls `pthread_create`, waits for the worker to publish one atomic
  value, joins it, and reports deterministic booleans and any returned errno.

- [x] **Step 1: Add the line-exact probe.**

  The child must use only async-signal-safe operations between `fork` and
  `execve`. Stage 2 runs after image replacement and prints:

  ```text
  fork_exec_stage2_reached=true
  post_exec_pthread_create_ok=true
  post_exec_worker_ran=true
  post_exec_pthread_join_ok=true
  parent_observed_child_success=true
  ```

  On failure, report `post_exec_pthread_create_errno=<n>` and exit nonzero.
  Keep the parent wait bounded by the harness rather than adding probe-local
  alarm state.

- [x] **Step 2: Add the native signed test.**

  Add `native_conformance_dsr_fork_exec_can_create_thread` beside the existing
  `execfromthread` and `vforkexecthread` tests. Build through
  `ensure_native_static_pie_probe("forkexecpthread")` and run through
  `run_native_run_elf_with_args` on `native16k`.

- [x] **Step 3: Run current production behavior and observe RED.**

  ```bash
  just build
  cargo test -p carrick-cli --test conformance \
    native_conformance_dsr_fork_exec_can_create_thread \
    -- --nocapture --test-threads=1
  ```

  Expected RED: stage 2 is reached, `pthread_create` returns the typed
  `EOPNOTSUPP` path, and no host trap is exposed.

- [x] **Step 4: Prove the Linux oracle.**

  Run the probe in a Docker-only phase through the normal probe gate or
  `scripts/probe-docker.sh forkexecpthread`. Preserve the output showing all
  five booleans true. Do not use guest `strace` as oracle evidence.

## Task 3: Capture the unsafe failure boundary

**Files:**

- Evidence: `target/conformance/logs/lldb-runs/native-postfork-pthread-*`
- Evidence: `target/conformance/native-postfork-*.jsonl`
- Modify: `docs/native-default-conformance-campaign.md`

- [x] **Step 1: Rebuild, sign, and run the reducer with the unsafe opt-in.**

  ```bash
  just build
  codesign --verify --verbose=2 target/release/carrick
  CARRICK_RUN_ID=native-postfork-pthread-unsafe \
    target/release/carrick run-elf --raw --exec-backend native \
    --native-page-profile native16k \
    --forward-env CARRICK_NATIVE_UNSAFE_POSTFORK_THREADS=1 \
    conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/forkexecpthread
  ```

  Record whether the thread succeeds, Carrick returns a typed error, the host
  aborts, or the process times out. Reap the scoped run immediately.

- [x] **Step 2: Capture LLDB evidence for any abnormal result.**

  ```bash
  CARRICK_NATIVE_UNSAFE_POSTFORK_THREADS=1 \
    target/release/carrick debug lldb-run \
    --deadline-seconds 20 --run-id native-postfork-pthread-lldb -- \
    --exec-backend native --native-page-profile native16k --raw \
    --forward-env CARRICK_NATIVE_UNSAFE_POSTFORK_THREADS=1 \
    run-elf conformance-probes/target/native-pie/aarch64-unknown-linux-musl/release/forkexecpthread
  ```

  If the command's forwarding syntax differs, use `debug lldb-run --help` and
  retain the equivalent exact invocation in the ledger. For SIGABRT, preserve
  the raw LLDB backtrace because the native fatal record does not cover it.

  **Measured correction:** the subprocess exits before the LLDB runner's 200 ms
  stop poll can attach. The async-safe native fatal record is stable across
  Node, Go, and CPython; `atos` against the live shared-cache load address maps
  its PC to libdispatch's deduplicated client trap and LR to
  `_dispatch_sema4_wait+56`. These two Apple frames are the classification
  evidence; no speculative Carrick reset follows from them.

- [x] **Step 3: Sample the originating ecosystems under the same opt-in.**

  Run serial native DSR suites for `node-app-smoke`, `node-v8-smoke`,
  `go-build`, `go-runtime`, `go-sync`, and `cpython-threading`, with distinct
  JSONL files. Use the conformance runner's environment forwarding if it
  scrubs host variables; confirm the guest-facing variables are unchanged.

- [x] **Step 4: Classify ownership from captured frames and state.**

  Select exactly one branch:

  - **Carrick-owned copied state:** the failure is in a Carrick mutex,
    registry, wait primitive, DSR publication/cache state, kick target, signal
    table, dispatcher table, or readiness channel which can be replaced in the
    child without calling an unsafe Apple subsystem. Continue to Task 4.
  - **Apple host-runtime state:** the first failing operation is
    `pthread_create`, libdispatch, malloc/Objective-C initialization, or another
    host facility whose state cannot be reset through a documented child-safe
    contract. Skip Task 4 and continue to Task 5.
  - **Reducer defect:** real Linux fails identically, or the probe violates the
    post-fork async-signal-safe boundary. Fix the probe, re-prove Linux, and
    repeat Task 3 before selecting either repair.

  **Selected branch:** Apple host-runtime state. A single reducer pthread can
  run, but real subprocesses consistently execute libdispatch's client trap
  from `_dispatch_sema4_wait` after the multithreaded parent fork. Continue to
  Task 5; Task 4 is not applicable.

  Record the exact top frames, process/thread count, exit status, and selected
  branch in the campaign ledger. A stack label alone is insufficient; verify
  the relevant state or primitive directly.

## Task 4: Repair Carrick-owned post-fork state

**Execute only if Task 3 selected Carrick-owned copied state.**

**Files:**

- Modify: the exact owner identified in Task 3
- Modify: `crates/carrick-runtime/src/native_darwin.rs`
- Test: the owner's existing unit-test module

- [ ] **Step 1: Add one deterministic red fork test at the owner.**

  Hold or populate the precise parent state across `libc::fork`, then exercise
  the child reset and the first post-exec operation. Bound the child reap. The
  pre-fix test must reproduce the measured error, abort, or wedge without
  relying on timing-only load.

- [ ] **Step 2: Observe RED against the current implementation.**

  Run only the new test with `--nocapture` and preserve its exact failure. If it
  does not reproduce the measured boundary, return to Task 3 instead of adding
  a speculative reset.

- [ ] **Step 3: Replace only the copied state.**

  Extend `native_after_fork_child`, `NativeThreadRuntime::reset_after_fork_child`,
  `ProcessTranslator::reset_after_fork_for_exec`, or the measured subsystem's
  child reset as appropriate. Never unlock a mutex copied from another parent
  thread; publish a preallocated fresh backing or discard the stale owner
  without running its destructor.

- [ ] **Step 4: Prove the unit and signed reducer green.**

  Run the deterministic unit test, the complete owning crate's lib tests, and
  `native_conformance_dsr_fork_exec_can_create_thread`. Repeat the signed
  reducer three times with no unsafe switch.

- [ ] **Step 5: Remove the blanket guard and diagnostic switch.**

  Delete `CARRICK_NATIVE_UNSAFE_POSTFORK_THREADS`, its parser, and the blanket
  fork-child `EOPNOTSUPP` reason. Retain all independent page-profile and W+X
  rejections. Re-run the parser reference search to prove no unsafe escape
  remains.

## Task 5: Escalate Apple host-runtime state to self-reexec

**Execute only if Task 3 selected Apple host-runtime state.**

**Files:**

- Add: `docs/superpowers/specs/2026-07-13-native-pid-preserving-self-reexec-design.md`
- Add: `docs/superpowers/plans/2026-07-13-native-pid-preserving-self-reexec.md`
- Modify: `docs/native-default-conformance-campaign.md`

- [x] **Step 1: Stop the unsafe experiment.**

  Keep the production guard fail-closed. Do not add another reset, call an
  undocumented Apple reinitializer, or bless the failure.

- [ ] **Step 2: Write the self-reexec design from measured requirements.**

  The design must preserve the guest-visible PID while replacing the Carrick
  host runtime with a fresh process image. Specify a versioned, checksummed
  capsule; authenticated ownership and one-shot consumption; descriptor
  survival and CLOEXEC handling; namespace/process-table identity; rootfs and
  mount authority; dispatcher/VFS state; address-space and DSR reconstruction;
  signal masks/actions/pending rules; child-watch and wait state; SysV IPC;
  vfork completion; stdout/stderr; failure rollback before and after the point
  of no return; and hostile/stale capsule rejection.

- [ ] **Step 3: Write an implementation plan with red-first proof points.**

  The first end-to-end reducer remains `forkexecpthread`. Add capsule encode /
  decode corruption tests, fd-survival tests, PID identity tests, and a failed
  handoff test before ecosystem work. Review and approve this new architecture
  before implementation because it changes the process-lifecycle boundary.

- [ ] **Step 4: Record P1 as active, not blocked or blessed.**

  The broader native campaign continues on independent lanes, but Go/Node/
  CPython thread-after-exec coverage remains gating until the approved
  self-reexec plan is implemented and verified.

## Task 6: Verify ecosystem closure and resume the ladder

**Files:**

- Modify: `docs/native-default-conformance-campaign.md`
- Evidence: `target/conformance/native-postfork-*.jsonl`

- [ ] **Step 1: Run the focused signed cluster without unsafe knobs.**

  Run `forkexecpthread`, `execthreads`, `execfromthread`,
  `vforkexecthread`, `exitgroupthreads`, `forkfpreclaim`, and
  `threadstatuscount` on `native16k`. Repeat the fork-exec-pthread reducer on
  `linux4k` unless a separately measured 4K-on-16K instruction limitation
  prevents reaching the lifecycle assertion.

- [ ] **Step 2: Run the originating real workloads serially.**

  Run Node app/V8, Go build/runtime/sync, and CPython threading/subprocess.
  Require completion without the old `EOPNOTSUPP`, `uv_thread_create`
  assertion, host abort, or timeout. Content differences unrelated to thread
  lifecycle remain explicit regressions for later classification.

- [ ] **Step 3: Run actual concurrent load.**

  Run the 23-suite native smoke lane at `--workers 4` three consecutive times
  with distinct JSONL files and run IDs. This is also the first valid loaded
  proof for the P0 waiter and Direct-reservation fixes; a one-suite command with
  `--workers 4` is not load evidence.

- [ ] **Step 4: Run local quality gates.**

  ```bash
  just fmt-check
  cargo clippy -p carrick-runtime --all-targets -- -D warnings
  cargo test -p carrick-runtime --lib
  cargo test -p carrick-cli --test conformance native_conformance_ -- --test-threads=1
  ```

- [ ] **Step 5: Update the measured ledger and commit.**

  Record exact denominators, content verdicts, repeats, artifact paths, and
  remaining failure classes. Mark P1 fixed only after the unsafe knob is gone
  and the focused plus ecosystem evidence is green. Then resume the full
  Node -> Go -> CPython -> LTP -> serial complete -> workers=4 complete bless
  ladder in the controller design.
