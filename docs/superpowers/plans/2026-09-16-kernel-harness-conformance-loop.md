# Kernel Harness Conformance Loop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Linux-semantics conformance work a tight loop that needs no VM, no codesign, no Docker and no serial lane: a VM-free in-process kernel harness, a first batch of two-process semantics tests written against it, and a `just test` whose kernel and vfs lanes run in parallel.

**Architecture:** `crates/carrick-kernel-example` already boots `carrick-kernel` with a scripted backend (one host thread, one `SyscallDispatcher` and one `LinearMemory` per Linux task; fork through `reserve_fork`/`prepare_with_mm_backend`/`commit`). This plan grows it into the harness: a generic syscall vocabulary (any `carrick_abi::syscall::nr` number, typed operands, inline expectations), a driver that parks blocked syscalls on the kernel's own continuation wait service (so a lost wake is a test failure, not a poll retry), signal delivery without handlers, and sleep/timer completion. The two-process semantics suite lives in that crate's `tests/` and is the regression net the conformance loop grows. The kernel and vfs test lanes are partitioned by a `serial_host` module convention enforced by a lint-domains ratchet, so the fork-free bulk runs on all threads.

**Tech Stack:** Rust workspace (`rust-toolchain.toml` pin), `carrick-kernel` public surface + `test-support` doubles, `carrick-hal` Null bridges, `carrick-abi` syscall table, `just`, Python 3 for the ratchet script.

**Spec:** Inline, in the *Design* section below. The owner's brief (2026-09-16): "a plan that does 1, 3 and 4 together — the goal would be to work through conformance in a tight fast loop", where 1 = VM-free kernel tests as the inner loop, 3 = multi-process tests by default, 4 = parallelize the kernel lane.

## Global Constraints

- The harness crate stays outside the product closure: root `Cargo.toml` `default-members = ["crates/carrick-cli"]`, `just check-layering` must keep reporting no `test-support` feature in the product selection, and `strings target/release/carrick | grep -cE 'NullHostSignal|NullTimerFiring|TestCarrierProcess'` stays `0`.
- The harness uses only `pub` items of `carrick-kernel`, `carrick-hal`, `carrick-abi`, `carrick-guest-mem` (the crate's existing rule, `crates/carrick-kernel-example/src/lib.rs`). Anything it needs that is `pub(crate)` becomes `pub` in the kernel with a doc comment, in the same task, never a copied body.
- No second path: one outcome driver, one fork path, one signal path. If the carrier (`crates/carrick-runtime/src/vcpu_loop/`) and the harness need the same kernel-side logic, the logic moves into `carrick-kernel` and both call it.
- Every expected value in a semantics test cites its authority in a comment on the assertion: a man page section (`man 7 pipe`, `man 2 wait4`), or an existing oracle file under `crates/carrick-cli/tests/probe-oracle/arm64-musl/<probe>` line. An expectation nobody can cite gets a probe added to `conformance-probes/src/bin/` and blessed on the Docker oracle (`just conformance-probes` Docker phase) before the test lands. Never read Linux kernel source (clean-room rule).
- A test that goes red against the current kernel is a conformance defect: fix it in-task when the root cause is in the dispatch path of that syscall and the fix touches at most two files; otherwise land the test as `#[ignore = "defect: <one line>"]`, append a `### Defect` entry to the plan's ledger, and continue. No test is deleted or weakened to go green.
- Bounded waits only: every park uses `WAIT_BOUND` (5 s) and a lost wake fails with `ExampleError::WaitTimedOut(label)`. No test sleeps to "let things settle".
- `just test` total wall time is measured before Task 11 and after Task 13 on the same host with the same command (`time just test`), recorded in the plan ledger; the kernel and vfs lanes must not lose a single test (count `test result:` lines per crate before/after).
- Conventional Commits with a Why/What/Verified body; never `git stash`; never `--no-verify`; line-pinned inventories reconciled on a clean tree after any move (`python3 scripts/migrate/reconcile-line-pinned-inventories.py`, `--rename OLD=NEW` for moved files), then `just lint-domains`.
- The fork/`Command::new`/`set_var`/`setrlimit` tests keep running, serially, under `RUST_TEST_THREADS=1`; the parallel lane must be run 10× consecutively green before the recipe changes land.

---

## Design

**What exists (measured 2026-09-16 at branch head).** `crates/carrick-kernel-example/src/scripted.rs` has `ScriptedBackend::run_root(Vec<Step>) -> Result<RunReport, ExampleError>`, a closed `Sys` enum of six syscalls (`Pipe2`, `Fork`, `Write`, `Read`, `Wait4`, `ExitGroup`), `Task::issue` that re-dispatches a blocked syscall after `yield_now()` until `WAIT_BOUND`, and `on_fork`/`on_exit` that go through the public kernel operations. Every `DispatchOutcome` other than `Returned`, `Errno`, `Exit`, `Fork`, `SchedulerYield`, `WaitOnHvpatchChild`, `WaitOnFds` is `ExampleError::Unsupported`. `LinearMemory` is 4 KiB. No signals are ever delivered (a child exit posts no SIGCHLD; `wait4` reads the zombie).

**Why polling is wrong for conformance.** Re-dispatching until ready cannot see a lost wake: the retry re-checks readiness, so the class of bug the owner cares about most ("anything flaky is an architectural flaw"; the mq_notify/multiprocessing rows) is masked by the harness. The driver must park on `carrick_kernel::kernel::continuation`'s wait service exactly as the carrier does, and only a kernel wake may resume it. A dispatch counter in the report makes this checkable: a blocked read that is later written is dispatched exactly twice.

**Vocabulary.** A `Syscall` is `{label, nr: CanonicalNr, args: [Operand; 6], saves, expect}`. Operands are literals, slots (values saved by earlier syscalls), the last forked child's pid, byte buffers materialised into the task's memory, and output buffers captured into the report. Expectations are inline (`Expect::Ret`, `Expect::Errno`, `Expect::Death`) so a failure names the syscall and the pid. Constructor functions in `sys.rs` keep tests readable (`sys::pipe2(0)`, `sys::write(slot(1), b"hi")`).

**Signals without guest code.** The harness has no guest instruction stream, so a handler cannot run. Tests use the paths that need none: default action (death, `DispatchOutcome::SignalDeath`), `SIG_IGN` (`rt_sigaction` with `SIG_IGN`), `rt_sigprocmask` + `rt_sigtimedwait`, and `signalfd4`. That covers `kill`/`tgkill`/`SIGCHLD`/`SIGPIPE`/process-group signalling and the wait-status encoding, which is the bulk of the LTP `kill*`/`wait*`/`pipe*` semantics.

**Threads and futexes** are the last phase (Tasks 14–15): a thread needs its own `KernelContext` and lease over a shared dispatcher, which is a bigger seam than the process path. Everything before it is single-threaded processes.

**Parallel lanes.** In `carrick-kernel` the fork/spawn/env/setrlimit tests are ~30 functions in 8 files (list in Task 11); every other lib test is fork-free. Convention: those tests move into a `mod serial_host { use super::*; … }` at the bottom of their file, the parallel lane runs `cargo test … -- --skip serial_host`, the serial lane runs `RUST_TEST_THREADS=1 cargo test … serial_host`, and a ratchet script fails `just lint-domains` if a `#[test]` outside a `serial_host` module calls `libc::fork`, `std::process::Command::new`, `std::env::set_var`, `libc::setrlimit` or `libc::umask`. `carrick-vfs` gets the same treatment for its fork test, the `RLIMIT_NOFILE` guard, the umask test and the eight exact-host-openat-budget tests (process-wide `HOST_XATTR_READS` and `fs_resolve_cache::PROCESS_GENERATION`).

---

## File Structure

| File | Responsibility |
|---|---|
| `crates/carrick-kernel-example/src/operand.rs` (new) | `Operand`, `Save`, `Expect`, `Syscall`, `Step`; resolution of operands against a task's slots and memory. |
| `crates/carrick-kernel-example/src/sys.rs` (new) | One constructor per syscall the suite uses; nothing else. |
| `crates/carrick-kernel-example/src/memory.rs` (new) | `TaskMemory`: `LinearMemory` plus a bump allocator and capture of output buffers. |
| `crates/carrick-kernel-example/src/driver.rs` (new) | `drive(...)`: turns a `DispatchOutcome` into a completion by parking on the kernel wait service; sleep/timer completion; signal-death handling. |
| `crates/carrick-kernel-example/src/scripted.rs` (modify) | `ScriptedBackend`, `Task`, `run_root`, fork/exit; loses `Sys`, `Task::issue`'s outcome arms move to `driver.rs`. |
| `crates/carrick-kernel-example/src/report.rs` (new) | `RunReport`: completions, outputs, deaths, dispatch counter, per-pid queries. |
| `crates/carrick-kernel-example/src/lib.rs` (modify) | Re-exports; crate doc names the harness role. |
| `crates/carrick-kernel-example/tests/semantics/mod.rs` (new) | Shared helpers for the suite (`run`, `slot`, `out`). |
| `crates/carrick-kernel-example/tests/semantics/{wait,pgrp,pipe,unix,epoll,pidfd,futex}.rs` (new) | One file per Linux domain. |
| `crates/carrick-kernel-example/tests/semantics.rs` (new) | Declares the suite modules (`mod semantics;` style single test binary). |
| `crates/carrick-kernel-example/tests/fork_pipe_wait.rs` (modify) | Rewritten on the new vocabulary; keeps its three cases. |
| `scripts/migrate/check-serial-host-tests.py` (new) | The ratchet: fork/spawn/env/setrlimit/umask calls in tests must live in `serial_host`. |
| `justfile` (modify) | `test` recipe lanes, new `test-kernel` recipe, `lint-domains` line. |
| `crates/carrick-kernel/src/**` and `crates/carrick-vfs/src/**` (modify) | Tests moved into `serial_host` modules; no test bodies change. |
| `AGENTS.md`, `crates/carrick-kernel-example/README.md`, `crates/README.md` (modify) | Inner-loop instructions and the crate's new role. |

---

## Phase A — the harness

### Task 1: Generic syscall vocabulary

**Files:**
- Create: `crates/carrick-kernel-example/src/operand.rs`
- Create: `crates/carrick-kernel-example/src/sys.rs`
- Create: `crates/carrick-kernel-example/src/memory.rs`
- Create: `crates/carrick-kernel-example/src/report.rs`
- Modify: `crates/carrick-kernel-example/src/scripted.rs` (remove `Sys`, `Operand`, `RunReport`; `Task` uses `TaskMemory`)
- Modify: `crates/carrick-kernel-example/src/lib.rs`
- Modify: `crates/carrick-kernel-example/tests/fork_pipe_wait.rs`

**Interfaces:**
- Consumes: `carrick_abi::syscall::nr::*` (`CanonicalNr`, `.raw() -> u64`), `carrick_abi::LinuxErrno`, `carrick_kernel::dispatch::{DispatchOutcome, LinearMemory, SyscallRequest}`, `carrick_observability::compat::SyscallArgs` as re-exported through `carrick_kernel::dispatch` (verify the re-export with `grep -rn "pub use.*SyscallArgs" crates/carrick-kernel/src/dispatch/`; if absent, add `pub use carrick_observability::compat::SyscallArgs;` to `crates/carrick-kernel/src/dispatch/mod.rs` with a doc comment).
- Produces (used by every later task):

```rust
// operand.rs
pub enum Operand {
    Lit(i64),
    Slot(usize),          // a value saved by an earlier syscall in this task (inherited across fork)
    LastChild,            // pid of the most recent fork child of this task
    Bytes(Vec<u8>),       // materialised into task memory; the arg is its guest address
    CStr(String),         // Bytes + NUL
    Out(usize),           // a zeroed buffer of n bytes; captured into the report after the call
}
pub enum Save {
    Ret(usize),                                    // save the return value into slot
    OutI32 { arg: usize, index: usize, slot: usize }, // read the index-th i32 of the Out buffer at arg into slot
}
pub enum Expect {
    Any,
    Ret(i64),
    Errno(LinuxErrno),
    Death(i32),            // the task dies by this signal while inside this syscall (SignalDeath)
}
pub struct Syscall {
    pub label: &'static str,
    pub nr: CanonicalNr,
    pub args: [Operand; 6],
    pub saves: Vec<Save>,
    pub expect: Expect,
}
impl Syscall {
    pub fn ret(self, v: i64) -> Self;            // sets expect = Ret(v)
    pub fn errno(self, e: LinuxErrno) -> Self;   // sets expect = Errno(e)
    pub fn death(self, signal: i32) -> Self;     // sets expect = Death(signal)
    pub fn save(self, slot: usize) -> Self;      // pushes Save::Ret(slot)
    pub fn save_out_i32(self, arg: usize, index: usize, slot: usize) -> Self;
}
pub enum Step { Sys(Syscall), ChildMarker(Vec<Step>) }
pub fn slot(i: usize) -> Operand; pub fn last_child() -> Operand;
impl From<i64> for Operand; impl From<i32> for Operand; impl From<u32> for Operand; impl From<&[u8]> for Operand; impl From<&str> for Operand /* CStr */;

// report.rs
pub struct Completion { pub pid: i32, pub label: &'static str, pub result: Result<i64, LinuxErrno> }
pub struct Output { pub pid: i32, pub label: &'static str, pub arg: usize, pub bytes: Vec<u8> }
pub struct RunReport { /* private */ }
impl RunReport {
    pub fn exit_code(&self) -> i32;                     // root's exit code
    pub fn completions(&self) -> &[Completion];
    pub fn outputs(&self) -> &[Output];
    pub fn deaths(&self) -> &[(i32, i32)];              // (pid, signal)
    pub fn tasks_started(&self) -> usize;
    pub fn dispatches(&self) -> usize;                  // total dispatcher.dispatch calls across tasks
    pub fn dispatches_for(&self, pid: i32, label: &str) -> usize;
    pub fn output(&self, label: &str) -> &[u8];         // first output with that label (panics if none)
    pub fn ret(&self, label: &str) -> i64;              // first completion with that label (panics if errno/none)
}
```

- [x] **Step 1: Write the failing test** — rewrite `tests/fork_pipe_wait.rs::fork_pipe_wait_through_the_public_surface` on the new vocabulary:

```rust
use carrick_kernel_example::{sys, slot, last_child, ScriptedBackend, Step};

#[test]
fn fork_pipe_wait_through_the_public_surface() {
    let script = vec![
        Step::Sys(sys::pipe2(0).ret(0).save_out_i32(0, 0, 0).save_out_i32(0, 1, 1)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::write(slot(1), b"hi").ret(2)),
            Step::Sys(sys::exit_group(7)),
        ]),
        Step::Sys(sys::read(slot(0), 2).ret(2)),          // man 7 pipe: read returns the bytes written
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = ScriptedBackend::new().run_root(script).expect("backend ran");
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.output("read"), b"hi");
    assert_eq!(run.output("wait4")[0..4], 7u32.wrapping_shl(8).to_le_bytes()); // man 2 wait4: WEXITSTATUS in bits 8..16
    assert_eq!(run.tasks_started(), 2);
}
```

Keep `a_forked_task_can_fork_again` and `a_lost_wake_fails_inside_the_bound` as they are in intent, rewritten on the vocabulary (the lost-wake test asserts `ExampleError::WaitTimedOut("wait4")` unchanged).

- [x] **Step 2: Run it to verify it fails** — `cargo test -p carrick-kernel-example --tests` → compile error: `sys` module and `Step::Sys` on `Syscall` do not exist.

- [x] **Step 3: Implement `operand.rs`, `sys.rs`, `memory.rs`, `report.rs`** and rewire `scripted.rs`:

`memory.rs`:
```rust
pub const GUEST_BASE: u64 = 0x1000_0000;
pub const GUEST_LEN: usize = 1 << 20;   // 1 MiB: enough for msghdr/iovec/epoll_event arrays
pub struct TaskMemory { pub linear: LinearMemory, cursor: u64 }
impl TaskMemory {
    pub fn new() -> Self { Self { linear: LinearMemory::new(GUEST_BASE, vec![0; GUEST_LEN]), cursor: GUEST_BASE } }
    pub fn alloc(&mut self, n: usize) -> u64 {          // 16-byte aligned bump; panics when exhausted (a test bug)
        let addr = (self.cursor + 15) & !15; self.cursor = addr + n as u64;
        assert!(self.cursor <= GUEST_BASE + GUEST_LEN as u64, "task memory exhausted"); addr }
    pub fn put(&mut self, bytes: &[u8]) -> u64 { let a = self.alloc(bytes.len()); self.linear.write_bytes_raw(a, bytes).expect("in range"); a }
    pub fn read(&self, addr: u64, n: usize) -> Vec<u8> { let mut v = vec![0; n]; self.linear.read_bytes_raw(addr, &mut v).expect("in range"); v }
}
impl Clone for TaskMemory { /* clone linear + cursor: the fork child inherits the parent's bump state */ }
```
(Use the `GuestMemory` trait method names that `LinearMemory` implements — `read_bytes_raw`/`write_bytes_raw` per `crates/carrick-kernel/src/dispatch/outcome.rs` ~:897-952; adjust the call spelling to the trait's actual signatures.)

Operand resolution in `scripted.rs` (replacing the old `Operand` match):
```rust
fn resolve(&mut self, syscall: &Syscall) -> ([u64; 6], Vec<(usize, u64, usize)>) /* args, out buffers (arg, addr, len) */ {
    let mut args = [0u64; 6]; let mut outs = Vec::new();
    for (i, op) in syscall.args.iter().enumerate() {
        args[i] = match op {
            Operand::Lit(v) => *v as u64,
            Operand::Slot(s) => self.slots[*s] as u64,
            Operand::LastChild => self.last_child.expect("no child forked yet") as u64,
            Operand::Bytes(b) => self.memory.put(b),
            Operand::CStr(s) => { let mut b = s.as_bytes().to_vec(); b.push(0); self.memory.put(&b) }
            Operand::Out(n) => { let a = self.memory.alloc(*n); self.memory.linear.write_bytes_raw(a, &vec![0; *n]).expect("in range"); outs.push((i, a, *n)); a }
        };
    }
    (args, outs)
}
```
After a completion: capture every `Out` buffer into `report.outputs` with `syscall.label`, apply `saves` (`OutI32` reads `i32::from_le_bytes` at `addr + 4*index` of the named out buffer), then check `expect` (mismatch → `ExampleError::Expectation { pid, label, expected: String, actual: String }`, a new variant). `RunReport` is shared across tasks through the existing `shared` `Arc` (the report fields become `parking_lot::Mutex` inside it; `dispatches` is an `AtomicUsize` incremented around every `dispatcher.dispatch` call).

`sys.rs` — the constructor pattern (add exactly the ones the tests in this plan use; later tasks add theirs):
```rust
use carrick_abi::syscall::nr;
fn call(label: &'static str, nr: CanonicalNr, args: [Operand; 6]) -> Syscall {
    Syscall { label, nr, args, saves: Vec::new(), expect: Expect::Any } }
pub fn pipe2(flags: i32) -> Syscall { call("pipe2", nr::PIPE2, [Operand::Out(8), flags.into(), 0.into(), 0.into(), 0.into(), 0.into()]) }
pub fn fork() -> Syscall { call("fork", nr::CLONE, [(carrick_abi::LINUX_SIGCHLD as i64).into(), 0.into(), 0.into(), 0.into(), 0.into(), 0.into()]) }
pub fn read(fd: impl Into<Operand>, len: usize) -> Syscall { call("read", nr::READ, [fd.into(), Operand::Out(len), (len as i64).into(), 0.into(), 0.into(), 0.into()]) }
pub fn write(fd: impl Into<Operand>, data: &[u8]) -> Syscall { call("write", nr::WRITE, [fd.into(), Operand::Bytes(data.to_vec()), (data.len() as i64).into(), 0.into(), 0.into(), 0.into()]) }
pub fn close(fd: impl Into<Operand>) -> Syscall { call("close", nr::CLOSE, [fd.into(), 0.into(), 0.into(), 0.into(), 0.into(), 0.into()]) }
pub fn wait4(pid: impl Into<Operand>, options: i32) -> Syscall { call("wait4", nr::WAIT4, [pid.into(), Operand::Out(4), options.into(), 0.into(), 0.into(), 0.into()]) }
pub fn exit_group(code: i32) -> Syscall { call("exit_group", nr::EXIT_GROUP, [code.into(), 0.into(), 0.into(), 0.into(), 0.into(), 0.into()]) }
pub fn getpid() -> Syscall { call("getpid", nr::GETPID, [0.into(); 6]) }
pub fn getppid() -> Syscall { call("getppid", nr::GETPPID, [0.into(); 6]) }
```
(The `fork()` constructor issues `clone` with `flags = SIGCHLD`, exactly what the old `Sys::Fork` did — read the old arm before deleting it and keep the same flag word. `carrick_abi::LINUX_SIGCHLD`: verify the constant name with `grep -rn "LINUX_SIGCHLD" crates/carrick-abi/src`.)

- [x] **Step 4: Run the tests** — `cargo test -p carrick-kernel-example --tests` → 3 passed. `just check-layering` → ok.

- [x] **Step 5: Commit** — `git add crates/carrick-kernel-example && git commit -m "feat(kernel-example): generic syscall vocabulary with inline expectations"` (body: Why — the closed six-variant enum caps the semantics the harness can express; What — Operand/Save/Expect/Syscall, bump-allocated task memory, a shared RunReport with a dispatch counter; Verified — the three existing tests rewritten and green, check-layering ok).

### Task 2: Park on the kernel wait service, not on a poll loop

**Files:**
- Create: `crates/carrick-kernel-example/src/driver.rs`
- Modify: `crates/carrick-kernel-example/src/scripted.rs` (`Task::issue` delegates to `driver::drive`)
- Modify: `crates/carrick-kernel-example/tests/fork_pipe_wait.rs` (new test below)
- Read first (no edits unless a `pub(crate)` blocks you): `crates/carrick-runtime/src/vcpu_loop/continuation.rs` (the carrier's consumer of the model), `crates/carrick-kernel/src/kernel/continuation.rs`, `crates/carrick-kernel/src/kernel/continuation/wait_service.rs`, `crates/carrick-kernel/src/kernel/continuation/readiness.rs`, `crates/carrick-kernel/src/kernel/continuation/test_support.rs` (`block_on`, `await_event`, `capture`, `publish`, `DISPATCH_FAMILIES`).

**Interfaces:**
- Consumes: `DispatchOutcome` wait variants (`WaitOnFds`, `BlockingFdWait`, `WaitOnHvpatchChild`, `WaitOnSignals`, `BlockingWrite`, `FutexWait`, `WaitOnSharedWord`), `carrick_kernel::kernel::continuation::{ContinuationCapture, ContinuationWakeToken, ContinuationEvent, RestartClass}`, `CarrierWaitService` (exact type name: `grep -n "pub struct .*WaitService" crates/carrick-kernel/src/kernel/continuation/wait_service.rs`).
- Produces:

```rust
// driver.rs
pub enum Completion { Value(i64), Errno(LinuxErrno), Exit(i32), Death(i32), Fork(ForkOutcome /* the existing Fork fields */) }
pub(crate) fn drive(task: &mut Task, syscall: &Syscall, args: [u64; 6]) -> Result<Completion, ExampleError>;
```
`drive` dispatches once; on a wait outcome it (1) registers the wait exactly as the carrier does for that family (the carrier's mapping from outcome to `ContinuationCapture` lives in `vcpu_loop/continuation.rs` — call the same kernel functions it calls; if any of them is `pub(crate)` in `carrick-kernel`, promote it to `pub` with a doc comment in this task), (2) parks with `block_on(await_event(service, token))` under a deadline of `WAIT_BOUND` (a timeout is `ExampleError::WaitTimedOut(syscall.label)`), (3) on the event, restarts per the capture's `RestartClass` (`RestartSyscall` → dispatch the same request again and loop; a completion-carrying event → return its value). `SchedulerYield` → `std::thread::yield_now()` and re-dispatch (this is not a wait). `BlockingWrite` is driven with `carrick_kernel::dispatch::drive_blocking_write(&mut write, host_signal)` in a loop until it reports completion, parking on its wait token between steps — never restarted from offset zero.

- [x] **Step 1: Write the failing test** (in `tests/fork_pipe_wait.rs`):

```rust
#[test]
fn a_blocked_read_is_dispatched_exactly_twice_when_the_writer_arrives() {
    // Parking, not polling: the read parks once, the kernel wakes it on the write, it restarts once.
    let script = vec![
        Step::Sys(sys::pipe2(0).ret(0).save_out_i32(0, 0, 0).save_out_i32(0, 1, 1)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::nanosleep_ms(200)),                    // added in Task 4; until then use a 200 ms host sleep step: Step::HostSleepMs(200)
            Step::Sys(sys::write(slot(1), b"late").ret(4)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::read(slot(0), 4).ret(4)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = ScriptedBackend::new().run_root(script).expect("backend ran");
    assert_eq!(run.output("read"), b"late");
    assert_eq!(run.dispatches_for(1, "read"), 2, "a parked read is dispatched exactly twice");
}
```
Add `Step::HostSleepMs(u64)` to `Step` in this task (a host-side `std::thread::sleep` between steps, used only to order two tasks; it is not a syscall and does not count as a dispatch). Root pid is `1` (`ROOT_PID = LINUX_BOOTSTRAP_PID`; confirm and use the constant in the assertion instead of the literal if it differs).

- [x] **Step 2: Run it to verify it fails** — `cargo test -p carrick-kernel-example --tests a_blocked_read` → FAIL: `dispatches_for == N` with N ≫ 2 (the poll loop).

- [x] **Step 3: Implement `driver.rs`** as specified above; delete the yield/re-dispatch arms from `Task::issue`. Write the family mapping as a table at the top of `driver.rs` (one row per `DispatchOutcome` wait variant: which kernel registration call, which restart class), so the next reader does not re-derive it.

- [x] **Step 4: Run the tests** — `cargo test -p carrick-kernel-example --tests` → all green, the new test sees exactly 2; the lost-wake test still fails inside the bound with `WaitTimedOut("wait4")` and now takes `WAIT_BOUND` because it parks (assert the elapsed window is unchanged).

- [x] **Step 5: Commit** — `git commit -m "feat(kernel-example): park blocked syscalls on the kernel wait service"` (Why — a poll loop masks lost wakes, the flaky class the suite must catch; What — driver.rs + family table, HostSleepMs step; Verified — dispatch count 2, lost-wake bound unchanged).

### Task 3: Signals without handlers

**Files:**
- Modify: `crates/carrick-kernel-example/src/driver.rs` (`SignalDeath`, `WaitOnSignals` completion, pending-signal check at syscall boundary)
- Modify: `crates/carrick-kernel-example/src/sys.rs` (add `kill`, `tgkill`, `rt_sigprocmask`, `rt_sigtimedwait`, `rt_sigaction_ign`, `rt_sigaction_dfl`, `signalfd4`)
- Modify: `crates/carrick-kernel-example/src/report.rs` (`deaths`)
- Modify: `crates/carrick-kernel-example/tests/fork_pipe_wait.rs` (tests below)
- Read first: how the carrier turns a pending default-action signal into task death — `grep -rn "SignalDeath" crates/carrick-kernel/src/dispatch crates/carrick-runtime/src/vcpu_loop` — and the kernel function it calls at a syscall boundary to dequeue a deliverable signal for the current task.

**Interfaces:**
- Produces: `sys::kill(pid, sig)`, `sys::tgkill(tgid, tid, sig)`, `sys::rt_sigprocmask_block(sigs: &[i32])` (SIG_BLOCK with a 64-bit mask built from the list, `Out(8)` old set), `sys::rt_sigtimedwait(sigs: &[i32], timeout_ms: Option<u64>)` (mask in `Bytes`, `siginfo_t` as `Out(128)`, timespec in `Bytes`; returns the signal number), `sys::rt_sigaction_ign(sig)` / `sys::rt_sigaction_dfl(sig)` (a `Bytes` `struct sigaction` with `sa_handler = SIG_IGN (1)` / `SIG_DFL (0)`, `sa_flags = 0`, `sa_mask = 0`, sigsetsize 8), `sys::signalfd4(sigs: &[i32], flags)`. Wait status helpers in `tests/semantics/mod.rs` (Task 5) decode the `wait4` out buffer.
- Driver contract: before every dispatch and after every wake, `drive` asks the kernel whether the current task has a deliverable signal whose disposition is default-terminate (the same kernel query the carrier uses); if so it records `(pid, signal)` in `report.deaths`, retires the task through the existing exit path with status `signal` (Linux wait encoding `WIFSIGNALED`: `status & 0x7f == signal`), and the task's thread ends. A `DispatchOutcome::SignalDeath { signal, .. }` from `dispatch` itself is handled the same way. `Expect::Death(sig)` matches either. `WaitOnSignals` parks like any other family (Task 2) and completes with the outcome's completion value.

- [x] **Step 1: Write the failing tests**:

```rust
#[test]
fn sigkill_from_the_parent_terminates_the_child_and_wait4_reports_the_signal() {
    let script = vec![
        Step::Sys(sys::pipe2(0).ret(0).save_out_i32(0, 0, 0).save_out_i32(0, 1, 1)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::Sys(sys::read(slot(0), 1).death(9)),          // parked in read when SIGKILL lands
            Step::Sys(sys::exit_group(0)),                        // never reached
        ]),
        Step::HostSleepMs(100),
        Step::Sys(sys::kill(last_child(), 9).ret(0)),             // man 2 kill: 0 on success
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = ScriptedBackend::new().run_root(script).expect("backend ran");
    let status = i32::from_le_bytes(run.output("wait4")[0..4].try_into().unwrap());
    assert_eq!(status & 0x7f, 9, "man 2 wait4: WTERMSIG(status) == SIGKILL");
    assert_eq!(status & 0x80, 0, "no core");
    assert_eq!(run.deaths(), &[(run.ret("wait4") as i32, 9)]);
}

#[test]
fn sigchld_is_pending_in_the_parent_after_the_child_exits() {
    let script = vec![
        Step::Sys(sys::rt_sigprocmask_block(&[17]).ret(0)),      // SIGCHLD = 17 on aarch64; block so it stays pending
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![Step::Sys(sys::exit_group(3))]),
        Step::Sys(sys::rt_sigtimedwait(&[17], Some(2_000)).ret(17)), // man 2 sigtimedwait: returns the signal number
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = ScriptedBackend::new().run_root(script).expect("backend ran");
    let info = run.output("rt_sigtimedwait");
    assert_eq!(i32::from_le_bytes(info[0..4].try_into().unwrap()), 17, "si_signo");
    // si_pid for SIGCHLD is at offset 16 in the aarch64 siginfo_t (man 2 sigaction: si_pid); the child's pid, not the carrier's
    assert_eq!(i32::from_le_bytes(info[16..20].try_into().unwrap()), run.ret("wait4") as i32);
}
```

- [x] **Step 2: Run to verify they fail** — the first fails with `ExampleError::Unsupported("SignalDeath…")` or a `WaitTimedOut("read")`; the second fails because the child exit never posts SIGCHLD (`rt_sigtimedwait` returns `EAGAIN`).

- [x] **Step 3: Implement.** In `on_exit`, the kernel's exit path already posts SIGCHLD to the parent when the carrier calls it (find it: `grep -rn "SIGCHLD" crates/carrick-kernel/src/kernel/operations/exit.rs`); if the harness's `exit_task_key_eventually` path does not post it, the harness is calling the wrong kernel function — switch to the one the carrier calls (`grep -rn "exit_task_key_eventually\|fn exit_task" crates/carrick-runtime/src/vcpu_loop`), never post the signal from the harness. Implement the deliverable-signal check in `drive` per the contract; implement the constructors in `sys.rs` (`siginfo_t` is 128 bytes; `sigset_t` is 8 bytes with bit `sig-1`).

- [x] **Step 4: Run** — `cargo test -p carrick-kernel-example --tests` → green. Cross-check raw `siginfo` offsets against `conformance-probes/src/bin/sigtimedwaitintr.rs:100-101` and committed `probe-oracle/arm64-musl/sigtimedwaitintr` lines 5–6 and 11–12; cite the probe in the assertion comment. The illustrative `sigchld` oracle path does not exist in this extraction.

- [x] **Step 5: Commit** — `git commit -m "feat(kernel-example): deliver default-action and waited signals without a guest handler"`.

### Task 4: Sleep and timer completion

**Files:**
- Modify: `crates/carrick-kernel-example/src/driver.rs` (`WaitOnSleep`)
- Modify: `crates/carrick-kernel-example/src/sys.rs` (`nanosleep_ms`, `clock_nanosleep_ms`, `timerfd_create`, `timerfd_settime_ms`)
- Modify: `crates/carrick-kernel-example/tests/fork_pipe_wait.rs`

**Interfaces:**
- Consumes: `DispatchOutcome::WaitOnSleep { .. }` (`crates/carrick-kernel/src/dispatch/outcome.rs` ~:883) — read its fields; it carries the absolute deadline and the completion the carrier returns after sleeping. Consumes the Null timer bridge already wired through `CarrierBridges` for `timerfd` (timerfd readiness is kernel-owned; `grep -rn "TimerFdRead" crates/carrick-kernel/src/kernel/continuation.rs`).
- Produces: `sys::nanosleep_ms(ms)` (a `Bytes` timespec, `Out(16)` remaining), `sys::clock_nanosleep_ms(clock, flags, ms)`, `sys::timerfd_create(clock, flags)`, `sys::timerfd_settime_ms(fd, flags, initial_ms, interval_ms)`.
- Driver: `WaitOnSleep` → sleep the host thread until the outcome's deadline (bounded by `WAIT_BOUND`), then return the outcome's completion value directly — do NOT re-dispatch (a re-dispatch restarts the full interval). A signal that becomes deliverable during the sleep (Task 3's check, evaluated after the host sleep ends) takes precedence exactly as Linux does: death for default-terminate.

- [x] **Step 1: Failing tests**:

```rust
#[test]
fn nanosleep_completes_after_its_interval_with_zero_remaining() {
    let t0 = std::time::Instant::now();
    let run = ScriptedBackend::new().run_root(vec![
        Step::Sys(sys::nanosleep_ms(150).ret(0)),                 // man 2 nanosleep: 0 when the interval elapses
        Step::Sys(sys::exit_group(0)),
    ]).expect("backend ran");
    assert!(t0.elapsed() >= std::time::Duration::from_millis(150));
    assert_eq!(run.dispatches_for(1, "nanosleep"), 1, "sleep completes from the outcome, never restarts");
}

#[test]
fn a_timerfd_read_parks_until_the_timer_fires() {
    let run = ScriptedBackend::new().run_root(vec![
        Step::Sys(sys::timerfd_create(1 /* CLOCK_MONOTONIC */, 0).save(0)),
        Step::Sys(sys::timerfd_settime_ms(slot(0), 0, 100, 0).ret(0)),
        Step::Sys(sys::read(slot(0), 8).ret(8)),                    // man 2 timerfd_create: read returns an 8-byte expiration count
        Step::Sys(sys::exit_group(0)),
    ]).expect("backend ran");
    assert_eq!(u64::from_le_bytes(run.output("read").try_into().unwrap()), 1);
    assert_eq!(run.dispatches_for(1, "read"), 2);
}
```

- [x] **Step 2: Qualify existing completion support (adjusted)** — Task 2 already implemented the generic sleep/timer continuation mapping, so these new tests passed immediately. No separate Task 4 red-first failure is claimed. Director verified elapsed-time and one-dispatch owned-completion assertions; see the execution decisions and receipts below.
- [x] **Step 3: Implement** per the driver contract. If the timerfd firing needs the timer bridge to tick (the Null bridge never fires), the kernel-owned timerfd path must not depend on a host timer at all — read `crates/carrick-kernel/src/dispatch/time.rs` for how `timerfd` readiness is computed and, if it is bridge-driven, say so in the commit and register a `TimerFiring` implementation in the harness that fires on a host thread (one body: `carrick_hal::TimerCoreBridge<HarnessTimerFiring>`).
- [x] **Step 4: Run** → green. **Step 5: Commit** — `git commit -m "feat(kernel-example): complete sleeps and timers from the kernel outcome"`.

---

## Phase B — the two-process semantics suite

Shared setup for every task in this phase, done once in Task 5:

- `crates/carrick-kernel-example/tests/semantics.rs` contains `mod semantics;` … no: a single integration binary `tests/semantics.rs` with `mod wait; mod pgrp; …` declared as `#[path = "semantics/wait.rs"] mod wait;` etc., and `tests/semantics/mod.rs` with helpers:

```rust
pub use carrick_kernel_example::{last_child, slot, sys, ScriptedBackend, Step, ExampleError, RunReport};
pub fn run(script: Vec<Step>) -> RunReport { ScriptedBackend::new().run_root(script).expect("backend ran") }
pub fn wait_status(run: &RunReport, label: &str) -> i32 { i32::from_le_bytes(run.output(label)[0..4].try_into().unwrap()) }
pub fn wexitstatus(s: i32) -> i32 { (s >> 8) & 0xff }   // man 2 wait4
pub fn wtermsig(s: i32) -> i32 { s & 0x7f }
pub fn wifexited(s: i32) -> bool { s & 0x7f == 0 }
pub fn wifsignaled(s: i32) -> bool { ((s & 0x7f) + 1) as i8 >> 1 > 0 }
pub fn pipe() -> Step { Step::Sys(sys::pipe2(0).ret(0).save_out_i32(0, 0, 0).save_out_i32(0, 1, 1)) } // slots 0 (read end), 1 (write end)
```

Each test below is one `#[test]` with the script inline; the assertion comments cite the man page. The red/green rule from Global Constraints applies: a red test is a defect to fix or to ignore-with-name.

### Task 5: wait, zombies, reparenting, autoreap

**Files:** Create `tests/semantics.rs`, `tests/semantics/mod.rs`, `tests/semantics/wait.rs`. Modify `src/sys.rs` (`waitid`, `prctl`).

Tests (write all, then run; expected results per `man 2 wait4`, `man 2 waitid`, `man 2 prctl`, `man 2 sigaction` "SA_NOCLDWAIT"/`SIG_IGN` on SIGCHLD):

```rust
#[test] fn wait4_minus_one_reaps_any_child_and_echild_when_none_remain() {
    let run = run(vec![
        Step::Sys(sys::fork()), Step::ChildMarker(vec![Step::Sys(sys::exit_group(4))]),
        Step::Sys(sys::wait4(-1, 0)),                       // reaps the child
        Step::Sys(sys::wait4(-1, 0).errno(carrick_abi::LINUX_ECHILD)), // man 2 wait4: ECHILD with no children
        Step::Sys(sys::exit_group(0))]);
    assert_eq!(wexitstatus(wait_status(&run, "wait4")), 4);
}
#[test] fn wnohang_returns_zero_while_the_child_lives_then_reaps_it() {
    let run = run(vec![
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![Step::Sys(sys::nanosleep_ms(300)), Step::Sys(sys::exit_group(2))]),
        Step::Sys(sys::wait4(last_child(), 1 /* WNOHANG */).ret(0)),   // man 2 wait4: 0 when no child has changed state
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0))]);
    assert_eq!(wexitstatus(wait_status(&run, "wait4")), 2);
}
#[test] fn a_zombie_is_reaped_exactly_once() {
    run(vec![
        Step::Sys(sys::fork()), Step::ChildMarker(vec![Step::Sys(sys::exit_group(0))]),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::wait4(last_child(), 0).errno(carrick_abi::LINUX_ECHILD)), // man 2 wait4: the pid no longer names a child
        Step::Sys(sys::exit_group(0))]);
}
#[test] fn an_orphan_is_reparented_to_init_which_can_reap_it() {
    // The harness root is pid 1, so it is init: A forks B and exits; B outlives A; root reaps A, then B (man 2 wait4;
    // man 7 credentials: an orphan's parent becomes init). B's getppid() after A's death must read 1.
    let run = run(vec![
        pipe(),
        Step::Sys(sys::fork()),                                             // A
        Step::ChildMarker(vec![
            Step::Sys(sys::fork()),                                         // B
            Step::ChildMarker(vec![
                Step::Sys(sys::nanosleep_ms(300)),
                Step::Sys(sys::getppid().ret(1)),                           // reparented to init
                Step::Sys(sys::write(slot(1), b"B").ret(1)),
                Step::Sys(sys::exit_group(6))]),
            Step::Sys(sys::exit_group(5))]),
        Step::Sys(sys::wait4(-1, 0)),                                       // A
        Step::Sys(sys::read(slot(0), 1).ret(1)),                            // B has run its checks
        Step::Sys(sys::wait4(-1, 0)),                                       // B, now a child of init
        Step::Sys(sys::wait4(-1, 0).errno(carrick_abi::LINUX_ECHILD)),
        Step::Sys(sys::exit_group(0))]);
    let statuses: Vec<i32> = run.completions().iter().filter(|c| c.label == "wait4" && c.result.is_ok()).map(|_| 0).collect();
    assert_eq!(statuses.len(), 2);
    let mut codes: Vec<i32> = run.outputs().iter().filter(|o| o.label == "wait4").map(|o| wexitstatus(i32::from_le_bytes(o.bytes[0..4].try_into().unwrap()))).collect();
    codes.sort();
    assert_eq!(codes, vec![5, 6]);
}
#[test] fn sigchld_set_to_sig_ign_autoreaps_and_wait4_reports_echild() {
    run(vec![
        Step::Sys(sys::rt_sigaction_ign(17).ret(0)),                       // man 2 sigaction: SIGCHLD ignored -> children are not transformed into zombies
        Step::Sys(sys::fork()), Step::ChildMarker(vec![Step::Sys(sys::exit_group(0))]),
        Step::Sys(sys::nanosleep_ms(200)),
        Step::Sys(sys::wait4(-1, 0).errno(carrick_abi::LINUX_ECHILD)),
        Step::Sys(sys::exit_group(0))]);
}
#[test] fn waitid_wnowait_leaves_the_zombie_and_a_second_waitid_consumes_it() {
    let run = run(vec![
        Step::Sys(sys::fork()), Step::ChildMarker(vec![Step::Sys(sys::exit_group(9))]),
        Step::Sys(sys::waitid(1 /* P_PID */, last_child(), 4 | 0x0100_0000 /* WEXITED|WNOWAIT */).ret(0)), // man 2 waitid
        Step::Sys(sys::waitid(1, last_child(), 4).ret(0)),
        Step::Sys(sys::waitid(1, last_child(), 4).errno(carrick_abi::LINUX_ECHILD)),
        Step::Sys(sys::exit_group(0))]);
    // siginfo_t: si_status at offset 24 on aarch64 (man 2 waitid: CLD_EXITED, si_status = exit code)
    for info in run.outputs().iter().filter(|o| o.label == "waitid") {
        assert_eq!(i32::from_le_bytes(info.bytes[24..28].try_into().unwrap()), 9);
    }
}
#[test] fn prctl_set_child_subreaper_receives_the_grandchild() {
    let run = run(vec![
        pipe(),
        Step::Sys(sys::prctl(36 /* PR_SET_CHILD_SUBREAPER */, 1).ret(0)),     // man 2 prctl
        Step::Sys(sys::fork()),                                             // A
        Step::ChildMarker(vec![
            Step::Sys(sys::fork()),                                         // B
            Step::ChildMarker(vec![
                Step::Sys(sys::nanosleep_ms(300)),
                Step::Sys(sys::getppid().save(2)),
                Step::Sys(sys::write(slot(1), b"B").ret(1)),
                Step::Sys(sys::exit_group(0))]),
            Step::Sys(sys::exit_group(0))]),
        Step::Sys(sys::wait4(-1, 0)),
        Step::Sys(sys::read(slot(0), 1).ret(1)),
        Step::Sys(sys::wait4(-1, 0)),
        Step::Sys(sys::exit_group(0))]);
    // B's getppid after A died is the subreaper (root, pid 1): it appears as a completion of "getppid" with value 1
    assert!(run.completions().iter().any(|c| c.label == "getppid" && c.result == Ok(1)));
}
```
Add `sys::waitid(idtype, id, options)` (`Out(128)` siginfo, rusage 0) and `sys::prctl(option, arg2)` to `sys.rs`. Run: `cargo test -p carrick-kernel-example --test semantics wait::`. Commit per green batch: `git commit -m "test(kernel-example): wait, zombie, reparent and autoreap semantics across two processes"`; a red test gets its defect fix (commit `fix(kernel): …` with the test named in Verified) or its `#[ignore = "defect: …"]` and a ledger entry.

### Task 6: process groups, sessions and group signals

**Files:** Create `tests/semantics/pgrp.rs`. Modify `src/sys.rs` (`setpgid`, `getpgid`, `getpgrp`, `setsid`, `getsid`).

Tests (`man 2 setpgid`, `man 2 setsid`, `man 2 kill`):
- `setpgid_zero_zero_makes_the_caller_a_group_leader` — `setpgid(0,0).ret(0)`, `getpgid(0)` == `getpid`.
- `a_parent_may_move_a_child_into_the_parents_group_before_exec` — parent `setpgid(child, 0)`; child (after a 100 ms host sleep) `getpgid(0)` == parent's pid.
- `setpgid_on_a_child_in_another_session_is_eperm` — child does `setsid`; parent `setpgid(child, 0).errno(EPERM)` (after the child's setsid; order with `HostSleepMs`).
- `setsid_by_a_group_leader_is_eperm` — `setpgid(0,0)` then `setsid().errno(EPERM)`.
- `kill_minus_pgid_reaches_every_member_and_kill_zero_reaches_the_callers_group` — parent forks A and B into group A; `kill(-A, SIGKILL)` kills both; `wait4` twice → both `WTERMSIG == 9`; a third child in its own group survives and is reaped normally.
- `kill_of_a_non_existent_pid_is_esrch` and `kill_signal_zero_probes_existence` (`kill(child, 0).ret(0)` before reap; after reap, the zombie still answers 0 until reaped — `man 2 kill`).

Commit: `test(kernel-example): process group and session semantics across three processes`.

### Task 7: pipe semantics across processes

**Files:** Create `tests/semantics/pipe.rs`. Modify `src/sys.rs` (`fcntl_setfl`, `ioctl_fionread`, `dup2`).

Tests (`man 7 pipe`, `man 2 read`, `man 2 write`):
- `read_returns_zero_only_after_every_writer_closes` — parent holds the write end; child closes its copy and exits; parent `read` must still park (`WaitTimedOut` would be wrong: use a bounded `ppoll` with 200 ms → 0 ready), then parent closes its write end and `read(...).ret(0)`.
- `write_to_a_pipe_with_no_readers_dies_by_sigpipe` — both processes close the read end; `write(...).death(13)`; the parent's `wait4` shows `WTERMSIG == 13`.
- `write_with_sigpipe_ignored_is_epipe` — `rt_sigaction_ign(13)` then `write(...).errno(EPIPE)`.
- `writes_up_to_pipe_buf_are_atomic_across_two_writers` — two children each write 4096 bytes of a distinct byte 8 times; parent reads all 65536 bytes in 4096-byte reads and asserts every read is uniform (`man 7 pipe`: PIPE_BUF = 4096).
- `o_nonblock_read_on_an_empty_pipe_is_eagain_and_write_to_a_full_pipe_is_eagain` — `fcntl(fd, F_SETFL, O_NONBLOCK)`; empty read → `EAGAIN`; fill 65536 bytes (default capacity, `man 7 pipe`) then one more write → `EAGAIN`.
- `fionread_reports_queued_bytes_on_the_read_end_and_on_the_write_end` — write 5 bytes; `ioctl(rfd, FIONREAD)` out == 5 AND `ioctl(wfd, FIONREAD)` out == 5 (`man 7 pipe`/`man 2 ioctl_tty`: FIONREAD is valid on either end; Linux returns the queued count on the write end too). **This is expected RED** on the known open defect "FIONREAD on a pipe write end returns 0" (memory 2026-09: pipe12); fix it in-task if the root cause is in `dispatch/io_pipe.rs` alone, else ignore-with-name.
- `a_dup2d_write_end_keeps_the_pipe_open_until_both_descriptors_close`.

Commit: `test(kernel-example): pipe EOF, SIGPIPE, PIPE_BUF, O_NONBLOCK and FIONREAD semantics across processes`.

### Task 8: AF_UNIX across fork: SCM_RIGHTS and SCM_CREDENTIALS

**Files:** Create `tests/semantics/unix.rs`. Modify `src/sys.rs` (`socketpair`, `sendmsg_fds`, `recvmsg`, `setsockopt_int`, `getsockopt`).

Tests (`man 7 unix`, `man 3 cmsg`):
- `a_descriptor_passed_over_scm_rights_reads_the_same_pipe` — parent creates a pipe and a `socketpair(AF_UNIX, SOCK_STREAM)`; child receives the pipe's read end via `recvmsg` and reads the bytes the parent wrote; assert the received fd number is the lowest free fd in the child (`man 7 unix`: "as if dup"), not the parent's number.
- `scm_credentials_carry_the_senders_pid_uid_gid` — `setsockopt(SO_PASSCRED=16)` on the receiver; sender is the child; the `struct ucred` in the control message has `pid == child's getpid()`, `uid == 0`, `gid == 0` (the two-process identity bug class: the pid must be the child's, never the carrier's).
- `so_peercred_names_the_peer_process` — `getsockopt(SO_PEERCRED=17)` on each end of the socketpair after fork: parent sees child? No — socketpair peers are the two ends' *creators* (`man 7 socket`): both report the parent's pid; assert exactly that.
- `recv_on_a_stream_socket_whose_peer_closed_returns_zero` and `send_after_peer_close_is_epipe_with_msg_nosignal`.

Commit: `test(kernel-example): AF_UNIX fd passing and credentials are per Linux process`.

### Task 9: epoll across fork

**Files:** Create `tests/semantics/epoll.rs`. Modify `src/sys.rs` (`epoll_create1`, `epoll_ctl_add`, `epoll_ctl_del`, `epoll_pwait`).

Tests (`man 7 epoll`, in particular Q&A 6 on fork and close):
- `an_epoll_instance_is_shared_across_fork_and_a_write_in_the_child_wakes_the_parent` — parent registers the pipe read end with `EPOLLIN`; child writes after 100 ms; parent `epoll_pwait` parks and returns 1 event with `data == the registered u64`; `dispatches_for(parent, "epoll_pwait") == 2`.
- `edge_triggered_reports_once_until_new_data_arrives` — `EPOLLET`; two consecutive `epoll_pwait` with 100 ms timeouts: first 1, second 0 (`man 7 epoll`: level vs edge example); after a second write, 1 again.
- `closing_the_last_descriptor_removes_the_registration_but_a_dup_keeps_it` — Q&A 6: the parent registers the read end, then closes its own copy while the child still holds one; a write by the child still produces an event in the parent's `epoll_pwait` (the registration lives on the open file description); after the child also closes it, `epoll_ctl(DEL)` on the old fd is `EBADF`.
- `epoll_ctl_add_of_a_registered_fd_is_eexist_and_del_of_an_unregistered_fd_is_enoent`.
- `epollhup_is_reported_when_every_writer_closes`.

Commit: `test(kernel-example): epoll registration, edge triggering and close semantics across fork`.

### Task 10: pidfd

**Files:** Create `tests/semantics/pidfd.rs`. Modify `src/sys.rs` (`pidfd_open`, `pidfd_send_signal`, `ppoll_one`).

Tests (`man 2 pidfd_open`, `man 2 pidfd_send_signal`):
- `a_pidfd_becomes_readable_when_the_process_exits` — `pidfd_open(child, 0)`; `ppoll` on it parks (`dispatches == 2`), returns `POLLIN` after the child exits; `wait4` still reaps.
- `pidfd_send_signal_kills_the_child` — `WTERMSIG == 9`.
- `pidfd_open_on_a_reaped_pid_is_esrch`.
- `waitid_p_pidfd_reaps_through_the_descriptor` (`P_PIDFD = 3`).

Commit: `test(kernel-example): pidfd lifecycle semantics`.

---

## Phase C — parallel test lanes

### Task 11: partition the carrick-kernel lane

**Files:**
- Modify (move tests into a `mod serial_host { use super::*; … }` at the end of each file; bodies unchanged): `crates/carrick-kernel/src/run_state.rs` (`parent_seed_races_child_blocked_publish_across_fork`), `src/exec_stamps.rs` (`stamp_appends_one_line_per_phase_when_gated`, `related_and_reap_records_bind_the_exact_child`, `run_completion_carries_the_transitive_child_cpu_denominator`, `spawned_guest_process_exit_exports_both_terminal_stamps_before_raw_exit`), `src/dispatch/sysv.rs` (`shmdt_ambiguous_backend_unmap_failure_aborts_with_sigabrt`, `proc_sysvipc_rendering_races_attachment_cleanup_and_paired_mutation_without_deadlock`, `watchdog_kills_and_reaps_on_deadlock_timeout`, `remapped_shmat_same_shmid_does_not_deadlock_and_preserves_accounting`), `src/dispatch/ioring.rs` (`host_fork_observes_shared_queue_bytes`), `src/dispatch/tests.rs` (`child_can_acquire_classic_write_lock` and every test that calls it, `policy_is_inherited_by_forked_children`), `src/dispatch/mem/tests.rs` (`shared_anon_persistent_rollback_failure_aborts_concurrent_exec_backend`, `darwin_private_file_mapping_detaches_from_truncate`, `indeterminate_private_repoint_failure_fails_stopped`, every caller of `assert_partial_private_overlay_replacement`, `post_repoint_protection_failure_aborts_instead_of_publishing_split_ownership`), `src/dispatch/mem/backing/tests.rs` (`mmap_private_hostfile_hatch_zero_keeps_snapshot_path`), `src/network/socket_namespace.rs` (the seven `fork*` tests listed in the 2026-09-16 audit: `forked_child_resolves_service_and_endpoint_records_across_the_fork`, `fork_child_closes_published_listener_fds_for_port_release`, `fork_child_closes_active_udp_transient_and_parent_reuses_proxy`, `fork_child_closes_raw_published_stream_fds_without_shutdown`, `fork_guard_unlocks_registry_and_child_abandons_parent_publications`, `published_relays_of_two_instances_do_not_cross_wire`, `forked_child_resolves_private_realm_endpoints_across_the_fork`), `src/kernel/continuation/tests.rs` (`event_future_cancelled_observation_drains_inflight_operation_safely`, `lock_ordering_opposing_locks_rendezvous_completes_without_deadlock`, and `spawn_contained_test_child` with them), `src/kernel/container.rs` (every test using `with_env`).
- Create: `scripts/migrate/check-serial-host-tests.py`
- Modify: `justfile` (`test` recipe lines for carrick-kernel; `lint-domains` adds the ratchet).

**Interfaces:**
- Produces: the convention `serial_host` (module name) and the recipe lines:

```make
# carrick-kernel: the fork-free bulk runs on every thread; the tests that
# fork, spawn, or write process-wide state live in `serial_host` modules
# (scripts/migrate/check-serial-host-tests.py keeps that true) and run
# alone under RUST_TEST_THREADS=1 — child reaping is PROCESS-wide (see
# the 2026-08-16 11-minute hang in the carrick-host note above).
cargo test -p carrick-kernel --lib --features test-support {{ARGS}} -- --skip serial_host
env RUST_TEST_THREADS=1 cargo test -p carrick-kernel --lib --features test-support {{ARGS}} serial_host
```

- [x] **Step 1: Baseline** — `time just test 2>&1 | tee /tmp/just-test-before.log`; record wall time and, per crate, the `test result:` line, in the plan ledger (`### Lane timing` at the end of this file).
- [x] **Step 2: Write the ratchet, red first** — `scripts/migrate/check-serial-host-tests.py`:

```python
#!/usr/bin/env python3
"""Every #[test] in carrick-kernel / carrick-vfs that forks, spawns, or
writes process-wide state must live inside a `mod serial_host`.
Exit 1 and name the offenders otherwise. --self-test runs the fixtures."""
import re, sys, pathlib
ROOTS = ["crates/carrick-kernel/src", "crates/carrick-vfs/src"]
CALLS = re.compile(r"\b(libc::fork|Command::new|std::env::set_var|env::set_var|libc::setrlimit|libc::umask)\s*\(")
def offenders(text: str, path: str):
    out, depth, in_serial, serial_depth, fn_name, fn_is_test, brace = [], 0, False, 0, None, False, 0
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        s = line.strip()
        if re.match(r"(pub(\(\w+\))?\s+)?mod\s+serial_host\b", s): in_serial, serial_depth = True, depth
        if re.match(r"#\[(tokio::)?test\b", s) or "#[test]" in s: fn_is_test = True
        m = re.match(r"(pub(\(\w+\))?\s+)?(async\s+)?fn\s+(\w+)", s)
        if m: fn_name = m.group(4)
        if CALLS.search(line) and fn_is_test and not in_serial: out.append(f"{path}:{i}: {fn_name} calls {CALLS.search(line).group(1)} outside mod serial_host")
        depth += line.count("{") - line.count("}")
        if in_serial and depth <= serial_depth: in_serial = False
        if s.endswith("}") and depth <= 0: fn_is_test = False
    return out
def main(argv):
    if "--self-test" in argv:
        bad = "#[test]\nfn t() { let p = unsafe { libc::fork() }; }\n"
        good = "mod serial_host { use super::*;\n#[test]\nfn t() { let p = unsafe { libc::fork() }; }\n}\n"
        assert offenders(bad, "x.rs"), "self-test: unguarded fork must be an offender"
        assert not offenders(good, "x.rs"), "self-test: fork inside serial_host must pass"
        print("check-serial-host-tests: self-test ok"); return 0
    found = []
    for root in ROOTS:
        for p in pathlib.Path(root).rglob("*.rs"):
            found += offenders(p.read_text(), str(p))
    for f in found: print(f)
    return 1 if found else 0
if __name__ == "__main__": sys.exit(main(sys.argv[1:]))
```
Note: the scanner treats a call as test code when it is inside any `fn` that follows a `#[test]` attribute; helper functions called from tests (e.g. `child_can_acquire_classic_write_lock`, `spawn_contained_test_child`, `assert_partial_private_overlay_replacement`) also contain the calls — extend `CALLS` handling so an unattributed `fn` inside a `#[cfg(test)]` module counts too (set `fn_is_test = True` for every fn while inside a `mod tests`/`cfg(test)` block), so helpers move into `serial_host` with their callers. Run `python3 scripts/migrate/check-serial-host-tests.py --self-test` (ok) and `python3 scripts/migrate/check-serial-host-tests.py` → exit 1 listing every site from the audit (≈30 lines). That list IS the move list; reconcile it against the file list above.

- [x] **Step 3: Move the tests** into `mod serial_host { use super::*; … }` blocks (pure cut/paste; keep `#[test]` attributes; `cargo test -p carrick-kernel --lib --features test-support serial_host -- --list | wc -l` equals the number moved). Re-run the ratchet → exit 0.
- [x] **Step 4: Prove the parallel lane** — run `cargo test -p carrick-kernel --lib --features test-support -- --skip serial_host` **10 times** in a row (`for i in $(seq 10); do … || break; done`), all green. Any failure is a process-global collision: move that test into `serial_host` too (name the static it collides with in the commit body) — never add a sleep or a retry. Then `RUST_TEST_THREADS=1 cargo test -p carrick-kernel --lib --features test-support serial_host` green.
- [x] **Step 5: Wire the justfile** (recipe lines above; `lint-domains` gets `python3 scripts/migrate/check-serial-host-tests.py --self-test` and `python3 scripts/migrate/check-serial-host-tests.py` next to the other `--self-test` lines). Reconcile line-pinned inventories on the clean tree (`python3 scripts/migrate/reconcile-line-pinned-inventories.py`; the moves shift positions), `just lint-domains`, `just test`.
- [x] **Step 6: Commit** — `git commit -m "test(kernel): run the fork-free kernel lane in parallel; serial_host keeps the forking tests alone"` (+ the `chore(migrate):` reconcile commit).

### Task 12: partition the carrick-vfs lane

**Files:** Modify `crates/carrick-vfs/src/fs_backend/tests.rs` (`host_backend_survives_libc_fork_for_etc_hosts`, the `RLIMIT_NOFILE` guard and every test that constructs it, `test_mkdir_mode_fidelity_under_host_umask`, and the exact-budget tests: `test_open_trusted_dir_fd_reuses_cached_dir_fd`, `test_mkdir_2000_siblings_host_openat_budget`, `test_mkdir_under_resolved_parent_zero_openat_budget`, `test_getdents64_2000_entries_host_openat_and_stat_budget`, `test_getdents64_marker_node_per_directory_interference_budget`, `test_stat_existing_path_namei_zero_host_openat`, `dir_cache_survives_a_file_create_and_unlink_storm`, `host_may_have_fifo_nodes_tracks_durable_marker`), `crates/carrick-vfs/src/vfs/rootfs.rs` (`fast_readonly_open_uses_the_immutable_lower_when_the_sparse_upper_is_absent`); `scripts/migrate/check-serial-host-tests.py` (extend `CALLS` with `test_host_openat_count|test_host_stat_count|HOST_XATTR_READS` so budget tests must be serial too); `justfile`.

Steps mirror Task 11 (ratchet red → move → 10× parallel green → serial lane green → recipe → reconcile → commit `test(vfs): parallel vfs lane; exact host-syscall budgets and process-wide state stay serial`). The recipe comment cites the 47-vs-15 measurement from the current justfile comment so the reason survives.

### Task 13: the inner-loop recipe and docs

**Files:** Modify `justfile` (new recipe), `AGENTS.md` (Commands table row + "Where key subsystems live" pointer), `crates/carrick-kernel-example/README.md`, `crates/README.md` (crate row), `docs/conformance-testing.md` (a "Kernel semantics suite" section).

- [x] **Step 1: Recipe**:

```make
# The conformance inner loop: no VM, no codesign, no Docker. Runs the
# kernel's fork-free lane in parallel and the kernel-semantics suite in
# crates/carrick-kernel-example (two-process Linux semantics against the
# scripted backend). Use this while working a conformance defect; run
# `just test` before pushing.
test-kernel *ARGS:
    cargo test -p carrick-kernel --lib --features test-support {{ARGS}} -- --skip serial_host
    cargo test -p carrick-kernel-example --tests {{ARGS}}
```
- [x] **Step 2: Docs** — AGENTS.md Commands table gains `just test-kernel` with that one-line purpose; the `just test` row names the `serial_host` convention and the ratchet; `crates/carrick-kernel-example/README.md` describes the vocabulary (Operand/Save/Expect, `dispatches_for`, `HostSleepMs`), the parking driver, what it cannot do (no exec, no guest code, no handlers, threads per Task 14), and the citation rule for expectations; `docs/conformance-testing.md` gains the section with the loop: write the semantics test (cite the man page or oracle) → `just test-kernel` → fix in `carrick-kernel` → `just test` → the signed gates before push.
- [ ] **Step 3: Timing** — `time just test` after; append the before/after table to `### Lane timing` in this plan and to the commit body.
- [x] **Step 4: Commit** — `git commit -m "docs: the kernel-semantics inner loop (just test-kernel)"`.

---

## Phase D — threads

### Task 14: threads in the harness

**Files:** Modify `src/scripted.rs` (`Task` holds `Arc<parking_lot::Mutex<SyscallDispatcher>>` per process; a thread `Task` shares it), `src/driver.rs` (`CloneThread`, `ThreadExit`, `SignalThread`), `src/sys.rs` (`clone_thread(stack_len)`, `gettid`, `exit_thread`, `set_tid_address`, `futex_wait`, `futex_wake`).
- Read first: how the carrier materialises a thread — `grep -rn "CloneThread" crates/carrick-runtime/src/vcpu_loop crates/carrick-kernel/src/kernel/operations` — the kernel operation that registers a thread in the process (`Kernel::…clone_thread…`), and `ThreadExecutionLease` (`bound_dispatcher` in `crates/carrick-kernel/src/dispatch/proc.rs` ~:4581 shows `claim_runnable`).
- Failing test first: `clone_thread_shares_the_fd_table_and_exit_group_ends_every_thread` — thread writes to a pipe the process opened; main reads it; `exit_group` from the thread ends the process with that code; `tasks_started == 2`, `wait4` in a parent process sees the code.
- Then `a_thread_exiting_alone_leaves_the_process_running` (`exit` vs `exit_group`).
- Commit: `feat(kernel-example): threads share one dispatcher and one address space`.

### Task 15: futex wait/wake between threads and PRIVATE futexes across fork

**Files:** Create `tests/semantics/futex.rs`.
- `futex_wait_parks_and_a_wake_from_the_sibling_thread_resumes_it` (`dispatches_for(tid, "futex") == 2`); `futex_wait_with_a_stale_value_is_eagain` (`man 2 futex`); `futex_wake_returns_the_number_woken`; `futex_requeue_moves_waiters_without_waking_them`; `a_private_futex_is_not_shared_across_fork` (child's wake does not wake the parent; parent's wait times out via the syscall's own `timeout` → `ETIMEDOUT`, not `WaitTimedOut`).
- Commit: `test(kernel-example): futex wait, wake and requeue semantics`.

---

## Ledger

### Execution decisions

- Implementation branch: `codex/kernel-harness-conformance-loop`, based on
  extraction revision `ce6dc16f6`; the original app worktree revision lacked
  both this plan and `carrick-kernel-example`. The plan was copied from the
  extraction worktree without changing that worktree.
- Required ordering uses bounded explicit handshakes. The illustrative
  `HostSleepMs` ordering examples conflict with the global prohibition on
  sleeping to let tasks settle; dispatch-count assertions need proof that the
  reader enrolled before the writer proceeds.
- The code is authoritative for API spelling. `SyscallArgs` is already public
  through `carrick_kernel::compat`; outcome conversion lives in
  `BlockedContinuation::from_dispatch_outcome`, not the carrier's small
  `vcpu_loop/continuation.rs` module. Reuse these public paths.
- Correct example expectations before treating a red test as a kernel defect:
  `setpgid(child, 0)` selects the child's pid as its group, whereas joining the
  parent's group requires that group's id; repeated syscall labels require
  selecting the intended successful output, not blindly taking the first;
  subreaper coverage must use a non-init subreaper to distinguish it from
  ordinary init adoption. Preserve the intended semantics coverage.
- The initial `just test` run includes compilation and overlaps the vocabulary
  worker's build. Retain it as baseline correctness evidence; obtain comparable
  quiet, warm before/after timings before claiming a lane speedup.
- Continuation completion, not illustrative dispatch counts, determines whether
  to dispatch again: the shared kernel completes a woken futex with `Return(0)`
  in `kernel/continuation.rs`. Task 15 must assert one futex dispatch plus an
  observed park/wake; redispatching it would create a new wait and lose the
  consumed wake. Ordinary read readiness still requires two dispatches.
- Task 14's shared dispatcher and memory locks must be released before parking
  a continuation. Capture the exact thread context rather than using
  `capture_one_task_context`, which selects the process leader. Use the public
  thread reservation/prepare/commit path, not the test-only `clone_thread` helper.

### Defects
(appended by executors: `- <test name> — <one line> — fixed in <sha> | ignored`)

### Lane timing
| when | `just test` wall | carrick-kernel tests | carrick-vfs tests |
|---|---|---|---|
| initial cold correctness baseline (build overlap; not a speed comparison) | 345.15 s | 2083 passed, 1 ignored | 283 passed |
| before Task 11 (warm) | 63.05 s | 2083 passed, 1 ignored | 283 passed |
| after Task 13 | | | |

### Execution checkpoint

- Initial `just test`: exit 0, log `/tmp/kernel-harness-just-test-before.log`.
- Warm `just test`: exit 0, log `/tmp/kernel-harness-just-test-warm-before.log`.
- Task 1 accepted: `fa64f1492` + `9b7406340`; director reran 11 tests,
  `just check-layering`, and crate Clippy with `-D warnings`, all exit 0.
- Task 2 worker (continuing the Task 1 conversation): `AGY_RUN_ID=kernel-harness-sep16`, name `vocabulary`, worktree
  `/Users/tjfontaine/.codex/worktrees/kernel-harness-vocabulary`.
- Tasks 11–12 partition worker: same run id, name `serial-ratchet`, worktree
  `/Users/tjfontaine/.codex/worktrees/kernel-harness-serial-ratchet`. Scanner narrowed to 388 lines using the existing lexer; 16 self-tests pass.
  A fixpoint termination fix and actual partition are in flight. No lane
  changes accepted yet.
- Task 3 shared notification worker: same run id, name `exit-signals`, worktree
  `/Users/tjfontaine/.codex/worktrees/kernel-harness-exit-signals`, brief
  `/tmp/kernel-harness-exit-signals.md`. Owns kernel exit notification and the
  carrier's remaining wake routing, not harness signal handling.
- Exact pre-partition names are saved in
  `/tmp/kernel-harness-kernel-tests-before.txt` (2084 names) and
  `/tmp/kernel-harness-vfs-tests-before.txt` (283 names).
- Draft Task 2 review is `/tmp/kernel-harness-task2-review.md`; check the final
  worker diff before sending it. The draft discarded guest writes, restarted
  owned operation completions, and copied the carrier's restart policy. None
  is accepted. Task 14–15 API notes: `/tmp/kernel-harness-thread-notes.md`.
- Next: review Task 2 and partition results using `agy_worker.py status/result`
  with the run id above. Task 2 brief: `/tmp/kernel-harness-task2.md`;
  API notes: `/tmp/kernel-harness-task2-notes.md`; partition brief:
  `/tmp/kernel-harness-partition.md`. Task 2 still polls in the director tree
  until its worker is reviewed and integrated. Then implement Tasks 3–10 and
  13–15, reconcile inventories, and run final required gates.
- Tasks 2–15 remain subject to director acceptance; no worker report is a
  completed checkbox. No signed guest acceptance or performance claim yet.

### Continuation checkpoint (supersedes Task 2 status above)

- Integrated Task 2 commits `a614708c5` and `799aca301`. Director reran
  `cargo test -p carrick-kernel-example --tests`: 1 lib + 14 integration tests
  passed, including exactly two blocked-read dispatches, bounded lost wake,
  128 KiB pipe delivery, and pselect timeout guest writes. Runtime compile,
  harness Clippy, and `just check-layering` all passed.
- Continuation completion folding, blocking-write SIGPIPE policy, and syscall
  restart policy now live in the kernel and are called by both carrier and
  harness. Explicit pre-change red receipt for Task 2 remains to be recovered;
  its red-first checkbox stays open rather than inferred.
- Harness Tasks 3–4 are running with `vocabulary`, brief
  `/tmp/kernel-harness-phase-a-finish.md`. This includes reserved-signal
  consumption, correct signal-death wait encoding, timer completion, removal
  of stale polling docs, and removal of unused host-sleep ordering support.
- Partition work ended mid-edit with a stale previous scanner result. Resumed
  the same worker with `/tmp/kernel-harness-partition-resume.md`, requiring
  restoration of `kernel_exec_publication_filters_cloexec_descriptors`, exact
  name reconciliation, and all ten-run qualification receipts before acceptance.
- Shared exit review has restored blocked-mask and pending-state coverage;
  final review must ensure the parent registry read guard is released before
  callbacks and child-exit suppression policy has one implementation.
- Tasks 3–15 remain unaccepted; the overall goal is active.

- Task 2 red-first receipt recovered from worker step404: the blocked-read
  assertion failed with 10,242 dispatches versus 2 before continuation parking.
  Extracted log: `/tmp/kernel-harness-task2-red-receipt.txt`; Task 2 is accepted.
- Director additionally ran `RUST_TEST_THREADS=1 cargo test -p carrick-runtime
  --lib vcpu_loop`: 309 passed, 1 pre-existing ignore, exit 0; log
  `/tmp/kernel-harness-task2-runtime-tests.log`.
- Final shared-exit review sent as `/tmp/kernel-harness-exit-review-final.md`.
  Partition review pending `/tmp/kernel-harness-partition-review.md` identifies
  a dropped `close_pair(pipe)` cleanup in the moved continuation test; restore
  before acceptance. Token-level comparison helper:
  `/tmp/kernel-harness-compare-partition.py` (literals require ordinary diff
  review because the reused lexer skips them).

### Inner-loop documentation draft

- Prepared Task 13 documentation in AGENTS.md, the crate map, the harness
  README, and conformance-testing.md while workers finish code. These describe
  the intended integrated interface; Task 13 remains unaccepted until the
  recipe, Phase B/D support, and final timing are verified against the docs.
- Phase A candidate `03f197a5b` is under revision: the carrier did not yet call
  its new full signal-action helper, and synchronous SIGPIPE needs same-call
  death coverage. Review brief `/tmp/kernel-harness-phase-a-review-notes.md`.
- Shared exit final review is running; pending partition cleanup review remains
  `/tmp/kernel-harness-partition-review.md` and must be sent when the worker
  becomes terminal. Do not accept a stale earlier scanner result.

### Shared-exit checkpoint

- Integrated `f976f8573` + `5701bdaab` (worker originals `3bd9b048d` +
  `d7365fbd1`). Kernel exit now owns child-signal payload/publication and
  unconditional parent wake; the carrier retains executor routing. Shared
  suppression policy covers ignored and default-ignored signals. Registry
  read guards are released before notification callbacks.
- Director verification on the final worker tree: 21 exit tests, 45 dispatch
  signal tests, the post-exec runtime SIGCHLD regression, and kernel/runtime
  lib Clippy passed. The lock test resets observations immediately before
  child exit, excluding earlier wake events. After integration, all 15 current
  harness tests and runtime compile passed.
- Task 3 as a whole remains open: `vocabulary` must finish and verify the
  harness integration, SIGCHLD payload tests, shared carrier disposition
  handling, and same-call SIGPIPE death. Final shared-exit commits above are
  available for its isolated integration.
- New `semantics` worker, same run id, worktree
  `/Users/tjfontaine/.codex/worktrees/kernel-harness-semantics`, implements
  Tasks 5–7 tests in file-disjoint test modules. Brief:
  `/tmp/kernel-harness-semantics-wait-pipe.md`. It starts on Phase A candidate
  `03f197a5b`; final acceptance will use the fully integrated harness.
- Partition third bounded attempt is running with
  `/tmp/kernel-harness-partition-review.md`: restore the unchanged named-FIFO
  test body and dropped pipe cleanup, then exact inventory and qualification.
  Prior scanner success reports were stale; no partition commit is accepted.
- Task 14/15 source and topology notes extended in
  `/tmp/kernel-harness-thread-notes.md`; distinguish process pid and thread tid
  in reports, and count all actors in a parent/child/thread script.

### Integrated Phase A/B review checkpoint

- Integrated Phase A candidate `b4c6c51d5` (worker `42dc17828`), orphan-adopter
  wiring `614dd627b`, and wait/group/pipe suites `a185a2801` + `f59c31764`.
  Director review adds deterministic SIGPIPE ordering, a parked SIGCHLD waiter,
  signal-wait versus temporary-mask coverage, and sleep dispatch-count checks.
- A missing harness bootstrap step was exposed by `F_SETPIPE_SZ`: the dispatcher
  had no active FileAuthority. The harness now activates the same public run
  authority over the root context's file table. This is harness support, not an
  ignored syscall defect. Red receipt: `/tmp/kernel-harness-pipe-nonblock-red.log`;
  green full suite: `/tmp/kernel-harness-integrated-phase-ab-green.log`.
- The plan's illustrative timerfd dispatch count of two is superseded by the
  shared continuation contract: owned `TimerFdRead` completes in one dispatch,
  just as FutexWait does. Redispatch would restart an already-owned operation.
- IPC worker is reviewing Tasks 8–10 via `/tmp/kernel-harness-ipc-review.md`.
  Thread/futex Tasks 14–15 and final product/inventory/gate acceptance remain open.

### Defect: explicit SIGCHLD ignore does not autoreap

- Retained `wait::sigchld_set_to_sig_ign_autoreaps_and_wait4_reports_echild` with
  an explicit defect ignore. Linux authority: `wait(2)` notes for SIG_IGN.
- Kernel child-exit publication suppresses the signal, but zombie creation and
  identity/parent retirement still retain a reapable child. This requires a
  kernel lifecycle transaction change, outside a two-file syscall-dispatch fix.
- The test is not weakened; the director's explicit ignored-test receipt is
  `/tmp/kernel-harness-autoreap-defect.log`.

### Partition director takeover

- After three bounded partition attempts, director took over the remaining
  mechanical classification. Exact original names reconcile after removing only
  `serial_host`: 2084 kernel and 283 VFS tests. Bodies are preserved apart from
  rustfmt's equivalent trailing commas/block formatting.
- Added closed-host-descriptor observations to serial isolation: any concurrently
  opening test can reuse a closed raw descriptor number. The ratchet checks
  closed-fd equality assertions and retains live-fd assertions in the parallel lane.
- The process-global post-mortem abort latch also collided: the debug read/abort
  tests and scheduler lost-transition test now share the serial lane. The ratchet
  covers `take_abort_request` to prevent reintroducing this collision.
- A host control test spun in its admission loop after its submitter returned
  UnexpectedEof. LLDB evidence: `/tmp/kernel-harness-partition-23826-sudo.lldb.txt`,
  `/tmp/kernel-harness-partition-packet-deep.txt`,
  `/tmp/kernel-harness-partition-io-error.txt`; modified-memory core
  `/tmp/kernel-harness-partition-23826.core`. It is moved unchanged to serial_host.
  The exact source of host-socket interference is not established; no runtime fix
  or broader correctness claim is made from that classification.
- Earlier ten-run worker receipts were superseded by further failures. Final
  director qualification is still pending; see the latest
  `/tmp/kernel-harness-director-partition-qualified-v3.log`.

### Defect: concurrent consuming wait observes exit reservation

- Existing `wait_consume_never_returns_unconsumed_zombie_under_interleaved_exit`
  failed with `Err(TaskBusy(TaskId(285)))`, not a consumed zombie, in a kernel
  owned by that test. Receipt: `/tmp/kernel-harness-director-partition-final.log`.
- `wait_child_matching` checks a selected zombie's reservation before consuming
  it; exit publishes its zombie before releasing that reservation. The test's
  wait contract does not tolerate this transitional result. This is kernel
  lifecycle/API scope, not a two-file syscall-dispatch fix or process-global test
  collision. Preserve the test body with a named defect ignore under the global
  deferral rule; do not serialize it and call the race fixed.
- This adds one disclosed ignore to the original kernel population. Original
  test names and bodies remain; no 100% conformance claim is made.

- Director Phase A follow-up `174789695`: 45 dispatch-signal tests, 77
  continuation tests, and 309 runtime vcpu_loop tests passed (one existing
  runtime ignore). Signal-interest red/green receipts are
  `/tmp/kernel-harness-signal-interest-{red,green}.log`.
- IPC candidate integrated as `ff8ea2d76`; director integrated suite reports
  1 lib + 28 driver + 34 enabled semantics tests passing, four disclosed
  semantics ignores. Epoll ignored tests still receive review corrections;
  candidate integration alone is not final acceptance.
- Partition final worker commit `f11a69254` passed director ten-run qualification:
  kernel parallel 1999 pass / 2 ignore, serial 83 pass; VFS parallel 251 pass,
  serial 32 pass. Receipt `/tmp/kernel-harness-director-partition-qualified-v5.log`.
  Exact names remain 2084 + 283. Reuseport GROUPS/reset hook is also serial.
  Kernel/VFS Clippy and 19 ratchet fixtures passed. Final integrated recipe and
  clean-tree inventories remain pending.
- Thread/futex worker `threads` starts at `174789695`, worktree
  `/Users/tjfontaine/.codex/worktrees/kernel-harness-threads`, brief
  `/tmp/kernel-harness-threads.md`. It intentionally lacks IPC candidate changes;
  director must reconcile shared harness files and preserve checked layouts,
  authority bootstrap, and exact thread context semantics during integration.

### Defect: SCM_CREDENTIALS reports socket creator instead of message sender

- Retained `unix::scm_credentials_carry_the_senders_pid_uid_gid` as a named
  defect ignore. A fork child sends the message; received credentials report
  pid 1 (socket creator), whereas the sender is pid 2. Authority: `unix(7)`
  SCM_CREDENTIALS. Receipt: `/tmp/kernel-harness-ipc-defects.log`.
- `dispatch/net/send_recv.rs` synthesizes the control message from `peer_ucred`,
  whose lifecycle cache intentionally records creation-time peer credentials
  for SO_PEERCRED. Changing that cache would break the separate SO_PEERCRED
  contract. Per-message sender identity must cross the socket transport and
  receive path; this exceeds a two-file dispatch fix. Do not replace Linux pid
  with host pid or weaken the assertion.

### Integrated host-gate checkpoint

- At `1ec9f83aa`, `just test` passed: log
  `/tmp/kernel-harness-integrated-just-test.log`, wall 174.65 s including
  compilation while isolated workers were active. This is correctness evidence,
  not the final warm lane comparison. Harness: 1 lib + 29 driver + 34 semantics
  tests passed, four semantics ignores (two epoll cases under active review).
- Reconciled exactly eight global-state ledger symbols through the new
  `serial_host` namespaces, retaining their classifications and rationales.
  `check-runtime-global-state.py --check` passes. Remaining line-pinned
  inventories wait for the final epoll/thread source tree.
- Phase A/B and partition code are integrated and independently checked.
  Epoll review, thread/futex integration, final plan/doc reconciliation,
  warm timing, product closure, and final lint gates remain open.

### Epoll and inventory acceptance

- Integrated `0fc900b20` + `a68254ea5`: epoll readiness follows the retained
  open description after local close, fork inheritance, duplicate retention,
  and numeric slot reuse. Both alias defects are now enabled. The new reuse
  witness proves the recycled fd number, event payload, and enrolled wake.
  Original red receipt: `/tmp/kernel-harness-ipc-defects.log`; integrated green:
  `/tmp/kernel-harness-epoll-integrated.log` (37 semantics pass, two ignores).
- Director strengthened SCM_RIGHTS coverage in `66fe091de`: send fd 10, receive
  fd 3 after closing inherited aliases. This now distinguishes transferred
  open-description identity from copying the sender's integer.
- K1 inventory reconciliation correctly refused two removed direct
  `.description.read()` sites. Reviewed removals are `net.rs::host_fd_for_poll`
  and `epoll_ops.rs::host_read_avail_for_poll`: their bodies now delegate to
  description-owned helpers, which still acquire read guards. Removed exactly
  those two syntactic callsites and their taxonomy rows, retaining every other
  row/classification. This is factoring, not a claim of two fewer runtime locks.
- Preserved the original `cfg(test)` attribute on the moved subprocess helper
  (`15e4ea804`). Two existing bounded subprocess watchdog loops have explicit
  Semgrep exceptions (`b0dcc8dde`); their sleeps only pace external child-status
  observation and do not arrange the tested interleaving. No test body or
  deadline was changed.

### Director acceptance status

| Tasks | Result |
|---|---|
| 1–2 | Generic checked vocabulary and shared kernel continuation completion accepted. |
| 3–4 | Shared signal policy/child notification and sleep/timer completion accepted; Task 4 red-first deviation disclosed above. |
| 5–7 | 20 wait/group/pipe tests pass; SIGCHLD autoreap test retained as a named defect. |
| 8–10 | 17 IPC/epoll/pidfd tests pass; SCM_CREDENTIALS test retained as a named defect. Epoll alias defects fixed. |
| 11–12 | Parallel/serial partition and ratchet accepted after ten-run qualification and exact name reconciliation. |
| 13 | Recipe/docs implemented; final warm timing awaits thread integration. |
| 14–15 | Thread/futex implementation accepted; integrated host gates below remain the final closure check. |

- Integrated kernel test inventory: 2092 names (2084 original plus eight
  signal/exit regressions), with zero original names lost. VFS: 283 names,
  unchanged. Receipts: `/tmp/kernel-harness-{kernel,vfs}-tests-final.txt`.
- `just ci` passed through Clippy, lint-domains, deny, matrix, layering,
  portability and workspace compile, then caught an unresolved harness rustdoc
  link. The link is fixed and `just doc` now passes; final host tests and
  integration acceptance follow the thread merge. Do not call the interrupted
  aggregate command green.
- `just build` produced a signed product from `a68254ea5`; all three forbidden
  test-double string counts are zero. SHA-256, CDHash, UUID, entitlement and DOF
  receipts: `/tmp/kernel-harness-product-receipt.json`. This proves build and
  product closure only. No signed guest conformance run or push is claimed.

### Thread and futex acceptance

- Integrated worker `e79901b3c` as `8e892b8ce`, preserving IPC checked layouts,
  tagged outputs and exact thread contexts. Threads share dispatcher, memory,
  descriptor authority and the process-local futex table. Fork copies memory
  and allocates a separate futex table. Exit versus exit_group, root/sibling
  cancellation, clear_child_tid, wake counts, requeue and private fork isolation
  are covered without sleep-based ordering.
- Director added exact-thread signal wake routing, matching the carrier's
  already-posted signal protocol. Red: `/tmp/kernel-harness-thread-signal-red.log`
  (`WaitTimedOut("wait4")`); green: `/tmp/kernel-harness-thread-final-green.log`.
  Initial new dispatch-count assertion was corrected from one to two:
  WaitOnSignals redispatches to consume the pending signal. Futex completion
  instead returns directly and dispatches once; Task 15's illustrative count
  of two would duplicate a successful wait and is intentionally not followed.
- Serialized clone/fork reservations and terminal publication in the same
  per-process lock order. Thread retirement releases that lock before waiting
  on reservation events; terminal reporting uses the committed zombie status.
- Final targeted verification: 1 library + 29 driver + 48 semantics pass,
  two named semantics defects ignored; targeted Clippy passes. Receipts:
  `/tmp/kernel-harness-thread-final-{green,clippy}.log`.
