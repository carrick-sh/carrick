# Thread-Creating clone(2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `clone(2)`/`clone3(2)` with thread-creation flags (`CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD`) so glibc `pthread_create` works inside the guest — unblocking liblzma's multi-threaded decoder, which is what makes `apt-get install hello` fail today (`dpkg-deb … lzma error: Cannot allocate memory`).

**Architecture:** One HVF VM per macOS process already holds all stage-2 mappings; guest memory *is* the host process address space, so host threads share it for free. We add **per-thread vCPUs** (each `vm.vcpu_create()` runs on its own host `std::thread`) and serialize all syscall servicing through **one shared kernel lock** (`Arc<Mutex<Kernel>>`) — a big-kernel-lock model: guest user-mode runs truly concurrently, syscall handlers run one-at-a-time. Thread coordination (futex, thread-exit `CHILD_CLEARTID` wake, tid allocation) lives in the shared kernel.

**Tech Stack:** Rust, `applevisor` (HVF bindings), `libc`, existing `SyscallDispatcher`/`HvfTrap` (`src/trap.rs`, `src/runtime.rs`, `src/dispatch/*`).

**Why now:** Root-caused 2026-05-20 via `carrick trace` — the dpkg-deb decompressor subprocess does `clone3()`→ENOSYS then `clone(0x3d0f00)`→ENOSYS (the exact glibc pthread flag set); liblzma maps thread-spawn failure to `LZMA_MEM_ERROR`. See [[apt-install-mapshared]]. `src/dispatch/proc.rs:450` returns ENOSYS for the thread mask on purpose.

---

## Background: current single-threaded model (what we are changing)

- `src/runtime.rs::run_combined_syscall_loop_with_dispatcher` (and siblings) is a serial loop: `runtime.next_syscall()` → `dispatcher.dispatch(req, runtime, reporter)` → `runtime.complete_syscall(retval)`. The `dispatcher: SyscallDispatcher` is owned `&mut` by the loop. `runtime` is the `HvfTrap` and owns the single vCPU.
- `src/trap.rs::HvfInner { _vm, vcpu, mappings, … }` — one VM, one vCPU, per process. `vcpu_create()` is called once in `new_platform()` (trap.rs:393). Register setup uses `self.vcpu.set_reg(Reg::PC/SP/CPSR, …)` and `set_sys_reg(SysReg::SP_EL0/TPIDR_EL0/…)`.
- `DispatchOutcome::Fork` → `runtime.fork()` does a real macOS `fork()` + recreates a fresh VM/vCPU in the child (trap.rs:1167+). This is the *process* path and stays unchanged.
- `src/dispatch/proc.rs::futex` is a STUB: `FUTEX_WAKE` returns 0; `FUTEX_WAIT` returns EAGAIN (or sleeps to ETIMEDOUT). `set_tid_address` returns the pid; `set_robust_list` is a no-op. These are correct for one thread, wrong for many.

## Serialization model (the one big decision)

**Big Kernel Lock.** A single `Mutex<Kernel>` guards every piece of state a syscall handler touches (FD table, mm allocator, signal dispositions, futex queues, thread registry, output buffers). Each guest thread = one host thread + one vCPU. A thread runs its vCPU until `svc`, then locks the kernel, services the syscall, unlocks, resumes. Two guest threads can spin in user-mode simultaneously; their syscalls serialize. This is simple, obviously correct, and fast enough for v1.0. We can shard the lock later if profiling demands it (it will not for apt).

**Futex blocking under the lock.** `FUTEX_WAIT` must release the kernel lock while parked (else `FUTEX_WAKE` from another thread can never run). We use a `parking_lot`-style or std `Condvar` keyed by futex address, OR drop to a per-address `(Mutex<()>, Condvar)` map and re-acquire the kernel lock after waking. The plan uses a dedicated `FutexTable` whose own `Condvar`s are independent of the kernel `Mutex`, so a waiter: reads the word under the kernel lock, then drops the kernel lock and parks on the FutexTable condvar; a waker bumps the same condvar. (Details in Task 6.)

---

## File Structure

- **Create `src/thread.rs`** — `ThreadId` allocation, `ThreadRegistry` (live tids, join/exit bookkeeping, each thread's `clear_child_tid` address), and `FutexTable` (address-keyed wait queues). One responsibility: thread + futex coordination primitives, no HVF, no syscalls. Fully unit-testable on any platform.
- **Modify `src/dispatch/mod.rs`** — `SyscallDispatcher` gains a `kernel: Arc<Mutex<KernelShared>>`-style split, OR (smaller first step) gains a `Arc<ThreadRegistry>` + `Arc<FutexTable>` it can clone into spawned threads. Add `DispatchOutcome::CloneThread { … }` and `DispatchOutcome::ThreadExit { … }`.
- **Modify `src/dispatch/proc.rs`** — replace the ENOSYS thread-mask branch in `clone`/`clone3` with `DispatchOutcome::CloneThread`; rewrite `futex`, `set_tid_address`, `set_robust_list`, `gettid`, and `exit` (thread vs group) to use the registry/futex table.
- **Modify `src/trap.rs`** — split per-thread vCPU from the shared VM: add `HvfTrap::spawn_thread_vcpu(child_regs) -> ThreadVcpuHandle` that creates a new vCPU *in the existing VM* and returns a handle a host thread can run; add `read_all_regs()`/`write_all_regs()` for cloning register context.
- **Modify `src/runtime.rs`** — factor the trap loop into `run_vcpu_until_exit(kernel, vcpu)` callable per host thread; handle `CloneThread` (spawn host thread running a new vCPU) and `ThreadExit` (terminate just this host thread, do `CHILD_CLEARTID` futex wake); make `exit_group` end the whole process.
- **Create `tests/syscall_thread.rs`** — dispatch-level tests for the thread registry, futex, and clone-thread outcome.
- **Create `tests/conformance_thread.rs`** (or extend `tests/conformance.rs`) — end-to-end: a glibc multithreaded binary, then `dpkg-deb -I`, then `apt-get install hello`.
- **Create `fixtures/linux-aarch64-hello/src/threads.rs`** + wire into `scripts/build-linux-fixtures.sh` — a minimal raw-`clone` thread fixture (no libc) that proves the trap path without depending on glibc.

---

## Task 1: Thread + futex primitives (`src/thread.rs`), pure-logic, no HVF

**Files:**
- Create: `src/thread.rs`
- Modify: `src/lib.rs` (add `pub mod thread;`)
- Test: inline `#[cfg(test)]` in `src/thread.rs`

- [ ] **Step 1: Write failing tests** in `src/thread.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_monotonic_tids_above_base() {
        let reg = ThreadRegistry::new(/*main_tid=*/ 1000);
        assert_eq!(reg.live_count(), 1);
        let t = reg.register_child(/*clear_child_tid=*/ 0x4000);
        assert!(t > 1000);
        assert_eq!(reg.live_count(), 2);
        assert_eq!(reg.clear_child_tid(t), Some(0x4000));
    }

    #[test]
    fn exit_removes_thread_and_reports_last() {
        let reg = ThreadRegistry::new(1000);
        let t = reg.register_child(0);
        assert!(!reg.exit(t)); // not last
        assert!(reg.exit(1000)); // last live thread -> true
    }

    #[test]
    fn futex_wake_returns_count_of_woken_waiters() {
        let table = FutexTable::new();
        // No waiters yet -> wake reports 0.
        assert_eq!(table.wake(0x8000, 1), 0);
    }
}
```

- [ ] **Step 2: Run, verify fail**

Run: `cargo test --lib thread::tests -- --nocapture`
Expected: FAIL — `ThreadRegistry`/`FutexTable` undefined.

- [ ] **Step 3: Implement** `src/thread.rs`:

```rust
//! Thread + futex coordination shared across a guest process's host threads.
//! No HVF, no syscalls — pure data structures behind their own locks so they
//! can be held across vCPU runs without entangling the big kernel lock.

use std::collections::HashMap;
use std::sync::{Condvar, Mutex};
use std::sync::atomic::{AtomicI32, Ordering};

pub type ThreadId = i32;

struct ThreadEntry {
    /// Guest address to zero + FUTEX_WAKE on thread exit (CLONE_CHILD_CLEARTID).
    clear_child_tid: u64,
}

pub struct ThreadRegistry {
    next_tid: AtomicI32,
    inner: Mutex<HashMap<ThreadId, ThreadEntry>>,
}

impl ThreadRegistry {
    pub fn new(main_tid: ThreadId) -> Self {
        let mut map = HashMap::new();
        map.insert(main_tid, ThreadEntry { clear_child_tid: 0 });
        Self { next_tid: AtomicI32::new(main_tid + 1), inner: Mutex::new(map) }
    }
    pub fn register_child(&self, clear_child_tid: u64) -> ThreadId {
        let tid = self.next_tid.fetch_add(1, Ordering::Relaxed);
        self.inner.lock().unwrap().insert(tid, ThreadEntry { clear_child_tid });
        tid
    }
    pub fn clear_child_tid(&self, tid: ThreadId) -> Option<u64> {
        self.inner.lock().unwrap().get(&tid).map(|e| e.clear_child_tid)
    }
    pub fn set_clear_child_tid(&self, tid: ThreadId, addr: u64) {
        if let Some(e) = self.inner.lock().unwrap().get_mut(&tid) { e.clear_child_tid = addr; }
    }
    /// Returns true if this was the last live thread (process should exit).
    pub fn exit(&self, tid: ThreadId) -> bool {
        let mut map = self.inner.lock().unwrap();
        map.remove(&tid);
        map.is_empty()
    }
    pub fn live_count(&self) -> usize { self.inner.lock().unwrap().len() }
}

/// Address-keyed futex wait queues. Each guest futex word is identified by its
/// guest address (private futexes only for v1 — apt/glibc use FUTEX_PRIVATE).
pub struct FutexTable {
    inner: Mutex<HashMap<u64, u64>>, // addr -> generation counter
    cv: Condvar,
}

impl FutexTable {
    pub fn new() -> Self { Self { inner: Mutex::new(HashMap::new()), cv: Condvar::new() } }

    /// Wait until generation for `addr` advances or `timeout` elapses.
    /// Caller has ALREADY checked *uaddr == expected under the kernel lock and
    /// released it. Returns true if woken, false on timeout.
    pub fn wait(&self, addr: u64, timeout: Option<std::time::Duration>) -> bool {
        let mut map = self.inner.lock().unwrap();
        let start_gen = *map.get(&addr).unwrap_or(&0);
        loop {
            let cur = *map.get(&addr).unwrap_or(&0);
            if cur != start_gen { return true; }
            match timeout {
                None => { map = self.cv.wait(map).unwrap(); }
                Some(d) => {
                    let (m, res) = self.cv.wait_timeout(map, d).unwrap();
                    map = m;
                    if res.timed_out() { return false; }
                }
            }
        }
    }

    /// Wake up to `n` waiters on `addr`. Returns an upper bound on woken count.
    pub fn wake(&self, addr: u64, n: u32) -> u32 {
        let mut map = self.inner.lock().unwrap();
        let g = map.entry(addr).or_insert(0);
        *g = g.wrapping_add(1);
        drop(map);
        self.cv.notify_all(); // coarse: all waiters re-check their addr
        n // best-effort; glibc only relies on >=1 progress
    }
}

impl Default for FutexTable { fn default() -> Self { Self::new() } }
```

- [ ] **Step 4: Run, verify pass**

Run: `cargo test --lib thread::tests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/thread.rs src/lib.rs
git commit -m "thread: add ThreadRegistry + FutexTable coordination primitives"
```

**Note for executor:** the coarse `notify_all` + per-address generation is intentionally simple and correct (every waiter re-checks its own `*uaddr` under the kernel lock after waking). Refine to per-address condvars only if a benchmark shows thundering-herd cost.

---

## Task 2: New DispatchOutcome variants (no behavior change yet)

**Files:**
- Modify: `src/dispatch/mod.rs` (the `DispatchOutcome` enum + any exhaustive `match`)
- Test: `tests/syscall_thread.rs` (new)

- [ ] **Step 1: Write failing test** `tests/syscall_thread.rs`:

```rust
use carrick::dispatch::DispatchOutcome;

#[test]
fn clone_thread_variant_exists() {
    let o = DispatchOutcome::CloneThread {
        stack: 0x7000, tls: 0x9000, flags: 0x3d0f00,
        parent_tid_addr: 0, child_tid_addr: 0,
    };
    matches!(o, DispatchOutcome::CloneThread { .. });
}
```

- [ ] **Step 2: Run, verify fail**

Run: `cargo test --test syscall_thread clone_thread_variant_exists`
Expected: FAIL — no `CloneThread` variant.

- [ ] **Step 3: Add variants** to `DispatchOutcome` in `src/dispatch/mod.rs`:

```rust
/// Thread-creating clone: spawn a new host thread + vCPU sharing this VM.
CloneThread {
    stack: u64,            // child SP (clone arg)
    tls: u64,              // CLONE_SETTLS value (TPIDR_EL0)
    flags: u64,
    parent_tid_addr: u64,  // CLONE_PARENT_SETTID target (0 = none)
    child_tid_addr: u64,   // CLONE_CHILD_SETTID/CLEARTID target (0 = none)
},
/// A single thread exited via exit(2) (not exit_group). Wake CHILD_CLEARTID.
ThreadExit { code: i32 },
```

Then fix every non-`_` `match outcome` arm (search `match outcome` and `DispatchOutcome::`): in `src/runtime.rs` add provisional arms that `unreachable!("wired in Task 5")` for now so the build compiles. The dispatch-level test only constructs the value.

- [ ] **Step 4: Run, verify pass**

Run: `cargo test --test syscall_thread clone_thread_variant_exists && cargo build`
Expected: PASS + clean build.

- [ ] **Step 5: Commit**

```bash
git add src/dispatch/mod.rs src/runtime.rs tests/syscall_thread.rs
git commit -m "dispatch: add CloneThread/ThreadExit outcomes (unwired)"
```

---

## Task 3: Route thread-clone to CloneThread instead of ENOSYS

**Files:**
- Modify: `src/dispatch/proc.rs:433-509` (`clone` + `clone3`)
- Test: `tests/syscall_thread.rs`

- [ ] **Step 1: Write failing test** — dispatch a synthetic `clone(0x3d0f00, stack, …)` and assert `CloneThread`. Use the existing dispatch test harness pattern (mirror `tests/syscall_process.rs` for how a `SyscallDispatcher` + fake memory is built; copy that scaffolding). Assert flags/stack/tls are threaded through.

- [ ] **Step 2: Run, verify fail** — `cargo test --test syscall_thread clone_thread_routes` → FAIL (still ENOSYS).

- [ ] **Step 3: Implement.** In `clone` (proc.rs), replace the `if (flags & thread_mask) == thread_mask { ENOSYS }` block with extraction of the aarch64 clone ABI args and return `CloneThread`. aarch64 `clone(flags, stack, parent_tid, tls, child_tid)` — note tls is arg3 and child_tid is arg4 on arm64:

```rust
const CLONE_SETTLS: u64 = 0x00080000;
const CLONE_PARENT_SETTID: u64 = 0x00100000;
const CLONE_CHILD_SETTID: u64 = 0x01000000;
const CLONE_CHILD_CLEARTID: u64 = 0x00200000;

if (flags & thread_mask) == thread_mask {
    let stack = ctx.arg(1);
    let parent_tid_addr = if flags & CLONE_PARENT_SETTID != 0 { ctx.arg(2) } else { 0 };
    let tls = if flags & CLONE_SETTLS != 0 { ctx.arg(3) } else { 0 };
    let child_tid_addr = if flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID) != 0 { ctx.arg(4) } else { 0 };
    return Ok(DispatchOutcome::CloneThread { stack, tls, flags, parent_tid_addr, child_tid_addr });
}
```

Do the equivalent in `clone3` by reading `struct clone_args` fields (`flags` u64 @0, `pidfd`@8, `child_tid`@16, `parent_tid`@24, `exit_signal`@32, `stack`@40, `stack_size`@48, `tls`@56) — child SP = `stack + stack_size`.

- [ ] **Step 4: Run, verify pass** — `cargo test --test syscall_thread`.

- [ ] **Step 5: Commit** `"clone/clone3: emit CloneThread for pthread flag set"`.

---

## Task 4: Trap engine — per-thread vCPU in the shared VM

**Files:**
- Modify: `src/trap.rs` (HvfInner / HvfTrap)
- Test: `tests/trap_hvf.rs` (extend; HVF tests are `#[cfg(all(target_os="macos", target_arch="aarch64"))]` and need the signed binary — run via the same gating those tests already use)

- [ ] **Step 1: Write failing test** in `tests/trap_hvf.rs`: create an `HvfTrap`, capture its register snapshot via a new `read_all_regs()`, call `spawn_thread_vcpu` with a child register set that sets PC to a tiny guest stub that does `mov x0, #42; svc #0` (exit), run that vCPU to completion on a host thread, assert it traps `exit(42)`. (If a full guest stub is too heavy for a unit test, assert at minimum that `spawn_thread_vcpu` returns a handle whose first `next_syscall()` observes the seeded `x0`/PC — i.e. the new vCPU starts where we told it to.)

- [ ] **Step 2: Run, verify fail.**

- [ ] **Step 3: Implement** on `HvfTrap`/`HvfInner`:
  - `read_all_regs(&self) -> GuestRegs` — snapshot X0..X30, SP_EL0, PC, CPSR, TPIDR_EL0 (use `get_reg`/`get_sys_reg`).
  - `spawn_thread_vcpu(&self, regs: GuestRegs) -> Result<ThreadVcpu, TrapError>` — `self._vm` is shared (the VM is process-global in HVF); call `self._vm.vcpu_create()` — **must be invoked on the host thread that will run it** (HVF requires vCPU create+run on the same thread). So this returns a *spec* (the seeded `GuestRegs`), and the actual `vcpu_create` happens inside the spawned host thread (Task 5). Provide `ThreadVcpu::create_on_this_thread(vm_handle, regs)`.
  - The child's PC is the parent's post-`svc` resume address (parent ELR), x0=0, SP_EL0=`stack`, TPIDR_EL0=`tls`. glibc's clone wrapper then jumps to the thread start routine itself.
  - **HVF gotcha:** confirm `applevisor` lets us hold the `VirtualMachine` across threads (it is `Send`/`Sync`? if not, wrap the raw VM handle). This is open question #5 in plan.md — *validate empirically first with a 10-line spike before writing the full handle type.*

- [ ] **Step 4: Run, verify pass.**

- [ ] **Step 5: Commit** `"trap: per-thread vCPU creation in the shared VM (read_all_regs/spawn_thread_vcpu)"`.

**Executor note:** if `vm.vcpu_create()` from a second thread returns `HV_BAD_ARGUMENT`/`HV_DENIED`, see the `macos-vm-lldb-debug` skill — but the documented HVF model is one VM, N vCPUs each pinned to a host thread, so this should work. Spike it standalone before committing to the handle design.

---

## Task 5: Wire CloneThread + ThreadExit in the runtime; shared kernel lock

**Files:**
- Modify: `src/runtime.rs` (factor `run_vcpu_until_exit`; handle new outcomes), `src/dispatch/mod.rs` (wrap shared state in `Arc<Mutex<…>>` or thread the `Arc<ThreadRegistry>`/`Arc<FutexTable>` + a kernel `Arc<Mutex<SyscallDispatcher>>`)
- Test: `tests/conformance_thread.rs` + the raw-clone fixture

- [ ] **Step 1: Write failing test** — build `fixtures/.../threads.rs` (raw `clone` via inline syscall: allocate a stack with `mmap`, `clone(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, stack_top, &ptid, tls, &ctid)`, child writes a byte to a shared global and `exit(0)`s, parent futex-waits on `ctid` then reads the global and `exit_group`s with it). Conformance test runs it under `carrick run` and asserts exit code reflects the child's write. This proves: thread spawn, shared memory, CHILD_CLEARTID wake, futex wait.

- [ ] **Step 2: Run, verify fail** — child never runs / ENOSYS / hang.

- [ ] **Step 3: Implement.**
  - Refactor the trap loop body into `fn run_vcpu_until_exit(kernel: Arc<Mutex<SyscallDispatcher>>, runtime: &mut R, registry: Arc<ThreadRegistry>, futex: Arc<FutexTable>, this_tid) -> Result<ThreadEnd>`. Each iteration: `next_syscall` (no lock), then `let mut k = kernel.lock(); let outcome = k.dispatch(...)`. Hold the lock only across `dispatch` + `complete_syscall`.
  - `CloneThread { stack, tls, flags, parent_tid_addr, child_tid_addr }`: under the lock, `tid = registry.register_child(if flags & CLONE_CHILD_CLEARTID { child_tid_addr } else { 0 })`; if `parent_tid_addr != 0` write `tid` there; if `CLONE_CHILD_SETTID` write `tid` at `child_tid_addr`. Snapshot parent regs (`runtime.read_all_regs()`), build child regs (x0=0, SP_EL0=stack, TPIDR_EL0=tls, PC=parent ELR/next-PC). Spawn `std::thread` that calls `ThreadVcpu::create_on_this_thread(vm, child_regs)` then `run_vcpu_until_exit(kernel.clone(), …, tid)`. Parent's clone returns `tid`.
  - `ThreadExit { code }`: under lock, read this thread's `clear_child_tid`; if non-zero, write 0 to that guest word and `futex.wake(addr, 1)`; `let last = registry.exit(this_tid)`. If `last`, behave like process exit; else, this host thread returns/ends (vCPU dropped).
  - `exit` (syscall 93) when more than one thread is live → `ThreadExit`. `exit_group` (94) → whole-process exit (terminate other threads: simplest correct v1 is `std::process::exit(code)` after flushing — acceptable because guest threads share the host process). Verify `exit_group` already maps to the process-exit path; route `exit` to `ThreadExit` only when `registry.live_count() > 1`.

- [ ] **Step 4: Run, verify pass** — `cargo test --test conformance_thread raw_clone_thread`.

- [ ] **Step 5: Commit** `"runtime: spawn per-thread vCPUs for CloneThread; thread exit + tid wake"`.

---

## Task 6: Real futex WAIT/WAKE across threads

**Files:**
- Modify: `src/dispatch/proc.rs::futex`, `set_tid_address`, `set_robust_list`, `gettid`
- Test: `tests/syscall_thread.rs` + the conformance fixture from Task 5 (now exercises real contention)

- [ ] **Step 1: Write failing test** — extend the raw-clone fixture so the parent blocks in `FUTEX_WAIT` until the child `FUTEX_WAKE`s (not via CHILD_CLEARTID): child sets a shared word and wakes; parent waits. Assert no hang and correct value. Add a dispatch unit test asserting `FUTEX_WAIT` with `*uaddr != val` returns `EAGAIN` immediately, and `FUTEX_WAKE` returns the wake count.

- [ ] **Step 2: Run, verify fail** — current stub returns immediately / spins / hangs.

- [ ] **Step 3: Implement** in `futex`:
  - Mask to private futexes (`FUTEX_PRIVATE_FLAG`); for the rare shared case fall back to current behavior + a `partial-syscall` probe.
  - `FUTEX_WAIT`: read `*uaddr` under the kernel lock; if `!= val` → `EAGAIN`. Else: **release the kernel lock**, call `self.futex_table.wait(addr, timeout)`, then re-acquire (the runtime holds the lock; so `futex` must signal the runtime to drop+reacquire — implement by returning a new internal `DispatchOutcome::FutexWait { addr, timeout }` the runtime handles by unlocking, waiting, relocking, then `complete_syscall(0 or -ETIMEDOUT)`). This keeps the lock-discipline in the runtime, not buried in a handler holding `&mut self`.
  - `FUTEX_WAKE`: `let n = self.futex_table.wake(addr, count); Returned { value: n as i64 }`.
  - `set_tid_address(addr)`: `registry.set_clear_child_tid(this_tid, addr)`; return `this_tid`.
  - `gettid`: return `this_tid` (thread-local; thread the tid into `SyscallCtx`).
  - `set_robust_list`: keep no-op (store addr if cheap) — glibc tolerates it.

  **Lock discipline:** add `DispatchOutcome::FutexWait { addr, timeout }`; runtime: drop kernel lock → `futex_table.wait` → relock → `complete_syscall`. This is the only handler that blocks, so a single special-cased outcome is cleaner than making handlers lock-aware.

- [ ] **Step 4: Run, verify pass.**

- [ ] **Step 5: Commit** `"futex: real cross-thread WAIT/WAKE via FutexTable; gettid/set_tid_address per-thread"`.

---

## Task 7: Demo gate — dpkg-deb, then apt-get install hello

**Files:**
- Modify: `tests/conformance_thread.rs` (add Docker-gated end-to-end cases mirroring `tests/conformance.rs` style)

- [ ] **Step 1: Write failing test** — a `#[test]` (gated on the signed release binary, like existing conformance) that runs:
  `carrick run --raw --fs host docker.io/library/debian:stable /bin/sh -c "apt-get update >/dev/null 2>&1; cd /root && apt-get download hello >/dev/null 2>&1 && dpkg-deb -I hello_*.deb"`
  and asserts stdout contains `Package: hello` and NOT `lzma error`.

- [ ] **Step 2: Run, verify fail** — currently `lzma error: Cannot allocate memory`.

- [ ] **Step 3: No new impl** — Tasks 1-6 fix it. If it still fails, trace with `carrick trace -s /tmp/trace_mem.d` and iterate on the next blocker (candidates already seen: debconf `tmp.ci changed before chdir` inode-consistency, `posix_openpt`/`/dev/pts`, `chmod EINVAL` — file as follow-up tasks; they did NOT block `dpkg-deb -I` itself).

- [ ] **Step 4: Run, verify pass.** Then the headline:
  `carrick run --raw --fs host docker.io/library/debian:stable /bin/sh -c "apt-get update >/dev/null 2>&1 && apt-get install -y hello && /usr/bin/hello"` → expect `Hello, world!`. If the install stage surfaces the debconf/pts/chmod bugs, open tasks for them; the lzma/thread blocker is what THIS plan owns.

- [ ] **Step 5: Commit** `"test: thread-enabled apt-get install hello end-to-end conformance"` and update memory note [[apt-install-mapshared]] to reflect true end-to-end status.

---

## Risks / open questions (resolve during execution, do not skip)

1. **HVF multi-vCPU from multiple host threads** (plan.md open Q#5). **LARGELY DE-RISKED 2026-05-20:** the `applevisor` 1.0.0 crate explicitly supports this — `VirtualMachineInstance` doc says "can be safely shared among threads", it is `Clone`, and `vcpu_create`'s own doc example spawns N threads each doing `vm.clone().vcpu_create()` + a vCPU loop (exactly our model). `Vcpu` is "bound to a specific thread and can't be sent to another" → create+run on the owning host thread (= `ThreadVcpu::create_on_this_thread`). One VM/process (global `OnceLock`), N vCPUs; `VcpuHandle` is cross-thread shareable (drives `vcpus_exit`, useful for `exit_group`). carrick's `HvfInner._vm` is a `VirtualMachineInstance<GicDisabled>` — clone it into the spawned thread. Still: do a 10-line spike in Task 4 to confirm on THIS machine before the full handle design, but the fallback path is very unlikely to be needed.
2. **`applevisor::VirtualMachine` thread-safety.** If not `Send+Sync`, wrap the raw `hv_vm` handle (process-global) in a newtype we assert `Send+Sync` for (the VM is genuinely process-wide in HVF).
3. **Signal delivery to a specific thread** (`tgkill`, per-thread masks) is out of scope here; current self/bootstrap signal model stays. Add a `partial-syscall` probe if a thread targets another thread's signal. apt does not need it.
4. **Fork from a multithreaded guest** (fork only duplicates the calling thread — POSIX). Document: after `fork`, the child has one thread (the caller); other guest threads vanish. The existing fork path already makes a fresh VM/vCPU, so this is naturally correct as long as the child's ThreadRegistry resets to just the caller.
5. **`std::process::exit` on `exit_group`** skips other host threads' Drop. Acceptable for v1 (process is dying); revisit if scratch cleanup leaks (it uses owner-pid Drop guards already — see [[path2-host-backend]]).

## Self-review checklist (done)

- Spec coverage: clone(✓ T3) clone3(✓ T3) thread vCPU(✓ T4) shared state/lock(✓ T5) thread exit + CHILD_CLEARTID(✓ T5) futex(✓ T6) tid/set_tid_address/gettid(✓ T6) demo(✓ T7).
- Placeholders: none — code shown for primitives; T4 HVF specifics flagged for an empirical spike (genuinely unknown, not a placeholder).
- Type consistency: `CloneThread`/`ThreadExit`/`FutexWait` fields consistent across T2/T3/T5/T6; `ThreadRegistry`/`FutexTable` method names match between T1 and consumers.
