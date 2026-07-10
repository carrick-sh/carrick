# Native Virtual Ptrace Control Plane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Darwin-native `PTRACE_TRACEME` children match Linux stop, continue, kill, and exec-stop behavior without exposing Carrick's patched-syscall `SIGTRAP` transport to the guest tracer.

**Architecture:** Select a native-only virtual ptrace control plane when `PageGeometry::native_profile` is present. Store tracer ownership and a small atomic stop state in the fork-coherent process record, use host `SIGSTOP`/`SIGCONT` only as invisible execution carriers, and synthesize the Linux stop status after `wait4` confirms the child is actually stopped. Keep the current host `ptrace(2)` implementation unchanged for HVF and every non-native backend; defer register and memory brokerage.

**Tech Stack:** Rust 1.96.0, `carrick-kernel` shared atomics, `carrick-host` process records, Darwin `wait4`/`kill`, signed native static-PIE probes, Docker arm64 oracle.

## Global Constraints

- `native16k` is the gating path; this work must not invoke the linux4k guarded instruction emulator.
- Do not call Darwin `PT_TRACE_ME` for the Darwin-native backend.
- Publish the requested Linux signal before stopping and confirm host `WIFSTOPPED(SIGSTOP)` before allowing continue, kill, or detach.
- Validate tracer PID and process-record generation; terminal exit clears every ptrace field.
- Full `PEEK*`, `POKE*`, register access, attach, and thread-level ptrace remain out of scope.
- Preserve current HVF, KVM, bhyve, and NVMM behavior.
- Use `just build` before every live native probe.

---

### Task 1: Fork-Coherent Virtual Ptrace State

**Files:**
- Modify: `crates/carrick-kernel/src/process.rs`
- Modify: `crates/carrick-host/src/guest_cpu.rs`
- Modify: `crates/carrick-runtime/src/namespace/pid.rs`

**Interfaces:**
- Produces: `VirtualPtraceState::{Untraced, Running, StopRequested, StopReported}`.
- Produces: `register_self_virtual_ptrace(tracer_pid)`, `request_self_virtual_ptrace_stop(signum)`, `report_child_virtual_ptrace_stop(pid, tracer_pid)`, `resume_child_virtual_ptrace(pid, tracer_pid)`, `kill_child_virtual_ptrace(pid, tracer_pid)`, and `detach_child_virtual_ptrace(pid, tracer_pid)`.
- Preserves: legacy `mark_self_ptrace_stop_pending` and `take_child_ptrace_stop_signal` for non-native backends.

- [ ] **Step 1: Add a failing real-fork lifecycle test**

  Add `virtual_ptrace_stop_is_reported_once_then_resumed` under the existing serialized `guest_cpu` tests. The child registers its parent, publishes Linux `SIGUSR2`, raises host `SIGSTOP`, and exits 42 after resume. The parent must confirm host `SIGSTOP`, report guest `SIGUSR2` exactly once, resume, and reap exit 42.

- [ ] **Step 2: Verify the test is red**

  Run:

  ```sh
  cargo test -p carrick-host virtual_ptrace_stop_is_reported_once_then_resumed --lib
  ```

  Expected: compile failure because the virtual ptrace state API does not exist.

- [ ] **Step 3: Implement the minimal atomic state machine**

  Reuse the explicit `ProcessRecord` padding for `ptrace_tracer_pid`, add an atomic state field, and reset tracer, state, and stop signal on claim, reuse, exit, and reap. Only allow these transitions:

  ```text
  Untraced -> Running -> StopRequested -> StopReported -> Running
                     \-> StopReported -> Untraced
                     \-> terminal exit -> Untraced
  ```

  `report_child_virtual_ptrace_stop` must CAS `StopRequested` to `StopReported`; a second report returns `None`. Resume/kill/detach must reject a wrong tracer or a state other than `StopReported`.

- [ ] **Step 4: Verify host and kernel tests**

  Run:

  ```sh
  cargo test -p carrick-host virtual_ptrace --lib
  cargo test -p carrick-kernel --lib --tests
  ```

  Expected: all selected tests pass.

- [ ] **Step 5: Commit**

  Commit only the two shared-state files with subject `feat(host): add virtual ptrace stop state` and a body naming the real-fork test.

### Task 2: Native Ptrace Requests and Wait Reporting

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/proc.rs`

**Interfaces:**
- Consumes: Task 1 virtual ptrace helpers.
- Produces: native-only request routing for `TRACEME`, `CONT`, `KILL`, and `DETACH`.
- Produces: native wait translation that adds host `WUNTRACED` internally and returns `(linux_signum << 8) | 0x7f` only after a confirmed carrier stop.

- [ ] **Step 1: Add failing request-routing and wait-state unit tests**

  Test that native transport does not select `PT_TRACE_ME`, rejects continue before `StopReported`, and preserves the existing host transport selection when no native profile is present. Extract pure selection/status helpers only where needed to make this behavior testable.

- [ ] **Step 2: Verify the tests are red**

  Run the exact new test names with:

  ```sh
  cargo test -p carrick-runtime native_virtual_ptrace --lib --no-default-features --features platform-macos
  ```

- [ ] **Step 3: Implement native request routing**

  `PTRACE_TRACEME` records `getppid()` and returns success without a Darwin ptrace call. `PTRACE_CONT` accepts data 0 in this slice, atomically transitions to running, then sends host `SIGCONT`. `PTRACE_KILL` sends host `SIGKILL`; `PTRACE_DETACH` clears ownership and resumes. Relation or state failures return Linux `ESRCH`; unsupported signal injection returns an explicit Linux error.

- [ ] **Step 4: Implement wait reporting**

  For an exact or any-child native virtual stop, internally include `WUNTRACED`. After host `wait4` returns `WIFSTOPPED` with host `SIGSTOP`, atomically report the child stop and replace only the status value with the recorded Linux signal. Never consume the Linux marker on an unrelated host stop.

- [ ] **Step 5: Verify runtime tests and commit**

  Run the focused runtime tests, then commit only `dispatch/proc.rs` with subject `feat(runtime): route native ptrace through shared state`.

### Task 3: Signal and Exec Stop Integration

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/signal.rs`
- Modify: `crates/carrick-runtime/src/vcpu_loop/signal.rs`
- Modify: `crates/carrick-runtime/src/exec_helpers.rs`
- Modify: `crates/carrick-runtime/src/native_darwin.rs`

**Interfaces:**
- Consumes: Task 1 state transitions and Task 2 wait routing.
- Produces: one shared `stop_for_ptrace_signal(dispatcher, signum)` decision used by direct self-signals and queued signal delivery.
- Produces: native traced exec requests Linux `SIGTRAP`, stops on host `SIGSTOP`, and enters the new image only after `PTRACE_CONT`.

- [ ] **Step 1: Add failing helper tests**

  Test that native ptrace signal stops choose host `SIGSTOP`, non-native ptrace retains its existing carrier behavior, `SIGKILL` remains terminal, and a detached native tracee falls back to ordinary signal delivery.

- [ ] **Step 2: Verify the helper tests are red**

  Run:

  ```sh
  cargo test -p carrick-runtime ptrace_signal_stop --lib --no-default-features --features platform-macos
  ```

- [ ] **Step 3: Route all three signal paths through the helper**

  Replace the duplicated `ptrace_traceme` checks in direct process signals, direct thread signals, and queued pending-signal delivery. Native virtual stops publish shared state and raise host `SIGSTOP`; detached tracees no longer stop. Keep the existing non-native marker path unchanged.

- [ ] **Step 4: Add native traced-exec stop**

  After image replacement, CLOEXEC closure, vfork completion, and register reset, request the virtual Linux `SIGTRAP` stop before `resume_guest_at(entry)`. The host carrier remains `SIGSTOP`; the guest wait status is `SIGTRAP`.

- [ ] **Step 5: Verify unit tests, signed probes, and commit**

  Run `just build`, then compare these byte-identical static-PIE probes with Docker: `ptracestop`, `ptracetraceme`, `ptracesignalstop`, `ptracesigdeath`, `ptracesequence`, `ptracekillcont`, `ptraceinvaliderrno`, and `traceexecstop`. Commit the four integration files with subject `fix(native): virtualize ptrace signal stops`.

### Task 4: Differential Gate and Compatibility Message

**Files:**
- Modify: `docs/2026-07-09-no-vmm-native-feasibility-evidence.md`
- Modify: `README.md`

**Interfaces:**
- Produces: current probe counts and explicit linux4k compatibility wording.

- [ ] **Step 1: Run the complete native16k probe campaign**

  Build the native PIE probes, run Carrick and Docker in separate phases, and retain the exact MATCH/DIFF set. The ptrace cluster must be byte-for-byte equal to Docker.

- [ ] **Step 2: Update user-facing compatibility text**

  State that native16k is preferred and executes guest memory instructions directly. State that linux4k is explicit, incomplete, and may reject mixed executable pages, shared-file aliases, or unsupported guarded instructions. Do not imply fallback to HVF.

- [ ] **Step 3: Run final focused gates and commit**

  Run `cargo fmt --all -- --check`, targeted clippy, the full native probe campaign, and a native16k LTP measurement. Commit evidence and compatibility text separately from runtime code.
