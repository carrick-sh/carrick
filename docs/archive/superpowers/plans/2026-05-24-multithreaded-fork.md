# Multithreaded fork/vfork Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a multithreaded guest `fork`/`vfork`(+`execve`) correctly, replacing the `live_count>1 → ENOSYS` guard, so Go's `os/exec` works.

**Architecture:** Hybrid — a process-wide quiesce barrier pauses all other guest vCPU threads at the lock-safe run-loop top before `libc::fork` (clean locks in the child), and the child resets per-thread bookkeeping (registry/futex/kicker/threads) to single-threaded. Folds in `CLONE_PIDFD` + `waitid(P_PIDFD)`.

**Tech Stack:** Rust, `parking_lot`/`std::sync` (Mutex/Condvar/Atomic), the existing `VcpuKicker`, `FutexTable`, `ThreadRegistry`, HVF fork path.

---

## File structure

- Create: `src/fork_quiesce.rs` — process-wide `QuiesceBarrier` (the novel concurrency primitive), unit-tested in isolation.
- Modify: `src/lib.rs` — `pub(crate) mod fork_quiesce;`
- Modify: `src/runtime.rs` — run-loop-top quiesce check; `handle_fork` orchestration (replace ENOSYS guard); extend `ForkOutcome::Child` reset.
- Modify: `src/thread.rs` — add a `notify_quiesce`-style wake reuse (or reuse `notify_signal_pending`); the futex wait predicate already takes an `interrupted` closure — the caller folds quiescing into it.
- Modify: `src/dispatch/proc.rs` + `src/dispatch/mod.rs` — `CLONE_PIDFD` plumbing + `waitid(P_PIDFD)`.

## Reference facts (verified in tree)

- Run loop: `run_vcpu_until_exit` (`src/runtime.rs` ~1186) — `for traps in 1..=state.max_traps { let frame = match engine.next_syscall() { ... } }`. The top of the loop body, before `next_syscall`, holds **no** carrick lock.
- `handle_fork` (`src/runtime.rs` ~1050): `if self.registry.live_count() > 1 { engine.complete_syscall(-ENOSYS)?; return Ok(None); }` then `engine.fork()` → `ForkOutcome::Parent{child_pid}` / `Child`.
- `ForkOutcome::Child` arm (~1079) already does: fresh `ThreadRegistry::new(this_tid)`, `set_current_registry`, `host_signal::reinit_after_fork`, fresh `waiter`, `kicker.register`, `guest_cpu::reset`.
- `VcpuKicker::kick_all_except(except: ThreadId)` exists; `FutexTable::notify_signal_pending()` wakes ALL futex waiters (process-directed wake); `ThreadRegistry::live_count()` exists; `VcpuKicker::new()`, `FutexTable::new()` exist.
- `self.futex: Arc<FutexTable>`, `self.kicker: Arc<VcpuKicker>`, `self.threads: Arc<Mutex<Vec<JoinHandle<()>>>>`, `self.registry: Arc<ThreadRegistry>` on `ThreadRuntimeState`.

---

### Task 1: `QuiesceBarrier` primitive

**Files:**
- Create: `src/fork_quiesce.rs`
- Modify: `src/lib.rs` (add `pub(crate) mod fork_quiesce;` near the other `mod` lines)

- [ ] **Step 1: Write the failing unit test**

Create `src/fork_quiesce.rs` with the test first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn quiesce_waits_for_all_others_then_releases() {
        let barrier = Arc::new(QuiesceBarrier::new());
        let resumed = Arc::new(AtomicUsize::new(0));
        let n = 3;
        let mut handles = Vec::new();
        for _ in 0..n {
            let b = Arc::clone(&barrier);
            let r = Arc::clone(&resumed);
            handles.push(std::thread::spawn(move || {
                // Simulate a run loop hitting the top repeatedly.
                for _ in 0..1000 {
                    b.park_if_quiescing();
                    std::thread::yield_now();
                }
                r.fetch_add(1, Ordering::SeqCst);
            }));
        }
        // Let the workers spin up.
        std::thread::sleep(Duration::from_millis(20));
        barrier.set_quiescing();
        assert!(barrier.wait_quiesced(n, Duration::from_secs(5)), "all others should quiesce");
        barrier.end_quiesce();
        for h in handles { h.join().unwrap(); }
        assert_eq!(resumed.load(Ordering::SeqCst), n);
    }

    #[test]
    fn wait_quiesced_times_out_when_a_thread_never_parks() {
        let barrier = QuiesceBarrier::new();
        barrier.set_quiescing();
        // Expect 1 other thread, but none will park.
        assert!(!barrier.wait_quiesced(1, Duration::from_millis(100)));
        barrier.end_quiesce();
    }
}
```

- [ ] **Step 2: Run the tests, verify they fail to compile (no `QuiesceBarrier`)**

Run: `cargo test --lib fork_quiesce 2>&1 | tail`
Expected: compile error `cannot find type QuiesceBarrier`.

- [ ] **Step 3: Implement `QuiesceBarrier`**

Prepend to `src/fork_quiesce.rs`:

```rust
//! Stop-the-world barrier for forking a multithreaded guest. The forking
//! thread quiesces every other guest vCPU thread at the lock-safe run-loop top
//! before `libc::fork`, so the child inherits no carrick lock held by a thread
//! that won't exist in the child. See docs/superpowers/specs/2026-05-24-
//! multithreaded-fork-design.md.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub(crate) struct QuiesceBarrier {
    quiescing: AtomicBool,
    paused: Mutex<usize>,
    cv: Condvar,
}

impl QuiesceBarrier {
    pub(crate) fn new() -> Self {
        Self {
            quiescing: AtomicBool::new(false),
            paused: Mutex::new(0),
            cv: Condvar::new(),
        }
    }

    /// Step 1 (forking thread): raise the quiesce flag. The caller then wakes
    /// the other threads (kick in-guest vCPUs + notify blocked waiters) and
    /// calls `wait_quiesced`. Split from the wait so the wakes happen between.
    pub(crate) fn set_quiescing(&self) {
        self.quiescing.store(true, Ordering::SeqCst);
    }

    /// Step 2 (forking thread): wait until `others` threads have parked at the
    /// barrier, or `timeout`. Returns false on timeout (caller aborts the fork).
    pub(crate) fn wait_quiesced(&self, others: usize, timeout: Duration) -> bool {
        if others == 0 {
            return true;
        }
        let deadline = Instant::now() + timeout;
        let mut paused = self.paused.lock().unwrap();
        while *paused < others {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let (g, res) = self.cv.wait_timeout(paused, deadline - now).unwrap();
            paused = g;
            if res.timed_out() && *paused < others {
                return false;
            }
        }
        true
    }

    /// Is a quiesce in progress? Cheap; checked at the run-loop top.
    pub(crate) fn is_quiescing(&self) -> bool {
        self.quiescing.load(Ordering::SeqCst)
    }

    /// Called by every OTHER thread at the lock-safe run-loop top. If a quiesce
    /// is in progress, register as paused and block until it ends.
    pub(crate) fn park_if_quiescing(&self) {
        if !self.is_quiescing() {
            return;
        }
        let mut paused = self.paused.lock().unwrap();
        *paused += 1;
        self.cv.notify_all(); // wake the forking thread's count-wait
        while self.quiescing.load(Ordering::SeqCst) {
            paused = self.cv.wait(paused).unwrap();
        }
        *paused -= 1;
    }

    /// Called by the forking thread (parent path or timeout abort) to release
    /// the parked threads.
    pub(crate) fn end_quiesce(&self) {
        self.quiescing.store(false, Ordering::SeqCst);
        let _g = self.paused.lock().unwrap();
        self.cv.notify_all();
    }
}
```

- [ ] **Step 4: Run the tests, verify pass**

Run: `cargo test --lib fork_quiesce -- --test-threads=4 2>&1 | tail`
Expected: `test result: ok. 2 passed`.

- [ ] **Step 5: Commit**

```bash
git add src/fork_quiesce.rs src/lib.rs
git commit -m "feat(fork): QuiesceBarrier stop-the-world primitive for multithreaded fork"
```

---

### Task 2: Run-loop quiesce check + a process-wide barrier instance

**Files:**
- Modify: `src/runtime.rs`

The barrier must be reachable from the run loop AND `handle_fork` without
threading it through every signature. Use a process-wide `OnceLock` (one VM per
process; like `host_signal`'s globals).

- [ ] **Step 1: Add the global accessor** near the top of `src/runtime.rs`:

```rust
fn fork_barrier() -> &'static crate::fork_quiesce::QuiesceBarrier {
    static BARRIER: std::sync::OnceLock<crate::fork_quiesce::QuiesceBarrier> =
        std::sync::OnceLock::new();
    BARRIER.get_or_init(crate::fork_quiesce::QuiesceBarrier::new)
}
```

- [ ] **Step 2: Park at the run-loop top.** In `run_vcpu_until_exit`, immediately inside `for traps in 1..=state.max_traps {` and BEFORE `let frame = match engine.next_syscall()`:

```rust
        // Lock-safe point: no carrick lock is held here. If another thread is
        // forking, park until it completes so the child inherits clean locks.
        fork_barrier().park_if_quiescing();
```

- [ ] **Step 3: Run regression (must not change behavior when no fork)**

Run: `cargo test --release --lib 2>&1 | grep "test result" | tail -1`
Expected: `ok. 213 passed` (unchanged); the barrier is a no-op when not quiescing.

- [ ] **Step 4: Commit**

```bash
git add src/runtime.rs
git commit -m "feat(fork): park vCPU run loops at the lock-safe top during quiesce"
```

---

### Task 3: `handle_fork` orchestration (replace the ENOSYS guard)

**Files:**
- Modify: `src/runtime.rs` (`handle_fork`, ~1050; `ForkOutcome::Child` arm, ~1079)

- [ ] **Step 1: Replace the ENOSYS guard with quiesce.** Change the opening of `handle_fork`:

```rust
        let others = self.registry.live_count().saturating_sub(1);
        if others > 0 {
            // Stop-the-world: pause every other guest vCPU thread at its
            // lock-safe run-loop top so the child inherits no held carrick lock.
            // 1) raise the flag, 2) wake every other thread so it reaches the
            // run-loop top, 3) wait for all to park.
            let barrier = fork_barrier();
            barrier.set_quiescing();
            self.kicker.kick_all_except(self.this_tid); // in-guest vCPUs
            self.futex.notify_signal_pending();         // blocked futex waiters
            crate::host_signal::wake_all_waiters();      // blocked io_wait waiters
            if !barrier.wait_quiesced(others, std::time::Duration::from_secs(5)) {
                barrier.end_quiesce();
                engine.complete_syscall(-(crate::linux_abi::LINUX_EAGAIN as i64))?;
                return Ok(None);
            }
        }
```

- [ ] **Step 2: Wrap the existing `engine.fork()` + outcome.** After the quiesce block, the existing `prepare_host_fork()` / `engine.fork()` / match stays. In the **Parent** arm, add `fork_barrier().end_quiesce();` as the FIRST line (resume the parked threads). In the error arm, add `fork_barrier().end_quiesce();` before returning.

- [ ] **Step 3: Extend the Child reset.** In the `ForkOutcome::Child` arm, after `self.registry = Arc::new(ThreadRegistry::new(self.this_tid));`, add:

```rust
                // The other guest threads do not exist in the child. Drop their
                // stale bookkeeping: fresh futex table (no phantom waiters),
                // fresh kicker (only this vCPU), empty thread-handle vec.
                self.futex = Arc::new(crate::thread::FutexTable::new());
                self.kicker = Arc::new(crate::vcpu_kick::VcpuKicker::new());
                self.threads = Arc::new(parking_lot::Mutex::new(Vec::new()));
                // The child is not quiescing; ensure the (copied) barrier flag is clear.
                fork_barrier().end_quiesce();
```

(Place BEFORE the existing `self.kicker.register(self.this_tid, engine.vcpu_kick_handle());` so the fresh kicker gets this vCPU. Keep that register call.)

- [ ] **Step 4: Add `host_signal::wake_all_waiters` if absent.** If `src/host_signal.rs` lacks a "wake every per-thread + process waiter pipe" fn, add one that writes a byte to every registered waiter pipe (mirror `notify_*`). If an equivalent exists (e.g., `notify_process_directed`), call that instead and drop this step.

- [ ] **Step 5: Run the gate + probe (see Task 6) — defer assertions to Task 6.** For now build:

Run: `cargo build --release 2>&1 | grep -E "^error" | head; echo done`
Expected: `done` with no errors.

- [ ] **Step 6: Commit**

```bash
git add src/runtime.rs src/host_signal.rs
git commit -m "feat(fork): quiesce-then-fork for multithreaded guests; reset child thread state"
```

---

### Task 4: CLONE_PIDFD write + waitid(P_PIDFD)

**Files:**
- Modify: `src/dispatch/mod.rs` (`DispatchOutcome::Fork`), `src/dispatch/proc.rs` (clone/clone3, waitid)

- [ ] **Step 1: Carry the pidfd-out address on Fork.** In `src/dispatch/mod.rs`, change `DispatchOutcome::Fork` to `Fork { pidfd_out: Option<u64> }`. Update all constructors/matches (compiler-guided). In `proc.rs` `clone`: when `flags & 0x1000 (CLONE_PIDFD) != 0`, set `pidfd_out = Some(ctx.arg(2))` (the parent_tid arg); else `None`. In `clone3`: `pidfd_out = if flags & 0x1000 != 0 { Some(args.pidfd) } else { None }`.

- [ ] **Step 2: Write the pidfd in the parent.** In `runtime.rs` `ForkOutcome::Parent { child_pid }` arm, when the Fork carried `pidfd_out = Some(addr)`: `let fd = self.dispatcher-or-kernel.open_pidfd(child_pid, 0)` (returns `DispatchOutcome::Returned{value:fd}`); extract the fd; `engine.write_bytes(addr, &(fd as i32).to_le_bytes())`. (Thread `pidfd_out` from `handle_fork`'s caller — the run loop's `DispatchOutcome::Fork` match — into `handle_fork`.)

- [ ] **Step 3: waitid(P_PIDFD).** In `proc.rs` `waitid`: if `idtype == 3 (P_PIDFD)`, resolve `self.pidfd_host_pid(arg1 as i32)` → `waitpid(host_pid, ...)` reusing `wait4`'s status translation; ESRCH/EINVAL on a non-pidfd.

- [ ] **Step 4: Build + defer assertions to Task 6.**

Run: `cargo build --release 2>&1 | grep -E "^error"; echo done`
Expected: `done`.

- [ ] **Step 5: Commit**

```bash
git add src/dispatch/mod.rs src/dispatch/proc.rs src/runtime.rs
git commit -m "feat(pidfd): write CLONE_PIDFD on fork + waitid(P_PIDFD)"
```

---

### Task 5: Multithreaded fork+exec probe (differential)

**Files:**
- Create: `fixtures/mn-probes/src/bin/fork_exec_mt.rs`
- Modify: `fixtures/mn-probes/Cargo.toml`

- [ ] **Step 1: Write the probe** `fixtures/mn-probes/src/bin/fork_exec_mt.rs`:

```rust
// Probe G — fork+exec from a multithreaded process. Spawns worker threads doing
// futex/compute, then (from the main thread) fork+execs /bin/echo and verifies
// the child ran. Mirrors Go os/exec's multithreaded spawn.
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

static SPIN: AtomicU64 = AtomicU64::new(0);

fn main() {
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut workers = Vec::new();
    for _ in 0..6 {
        let s = Arc::clone(&stop);
        workers.push(thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                SPIN.fetch_add(1, Ordering::Relaxed);
                thread::sleep(Duration::from_micros(50));
            }
        }));
    }
    thread::sleep(Duration::from_millis(50)); // ensure threads are live
    // fork+exec from the multithreaded process.
    let out = Command::new("/bin/echo").arg("FORK_EXEC_OK").output();
    stop.store(true, Ordering::Relaxed);
    for w in workers { let _ = w.join(); }
    match out {
        Ok(o) if o.status.success() && String::from_utf8_lossy(&o.stdout).contains("FORK_EXEC_OK") => {
            println!("PROBE_G_OK spin={}", SPIN.load(Ordering::Relaxed));
        }
        Ok(o) => { println!("PROBE_G_FAIL status={:?} out={:?}", o.status, String::from_utf8_lossy(&o.stdout)); std::process::exit(1); }
        Err(e) => { println!("PROBE_G_FAIL err={e}"); std::process::exit(1); }
    }
}
```

Add to `fixtures/mn-probes/Cargo.toml`:
```toml
[[bin]]
name = "fork-exec-mt"
path = "src/bin/fork_exec_mt.rs"
```

- [ ] **Step 2: Build it (alpine arm64 container)** and run the Docker oracle:

```bash
docker run --rm --platform linux/arm64 -v "$PWD/fixtures/mn-probes":/work -w /work rust:alpine sh -c 'cargo build --release --bin fork-exec-mt'
docker run --rm --platform linux/arm64 -v "$PWD/fixtures/mn-probes/target/release":/b -w /b alpine sh -c 'apk add coreutils -q; ./fork-exec-mt'
```
Expected: `PROBE_G_OK spin=...`. (Note: alpine `/bin/echo`; if missing, the probe uses busybox echo — fine.)

- [ ] **Step 3: Commit**

```bash
git add fixtures/mn-probes/Cargo.toml fixtures/mn-probes/Cargo.lock fixtures/mn-probes/src/bin/fork_exec_mt.rs
git commit -m "test(mn-probes): multithreaded fork+exec probe"
```

---

### Task 6: Validate end-to-end + no-regression

**Files:** none (validation).

- [ ] **Step 1: Build+sign**: `./scripts/build-signed.sh` (expect exit 0).

- [ ] **Step 2: The probe under carrick** (the failing test now passes):

Run: `pkill -9 -f "carrick run-elf"; CARRICK_EXPOSED_CPUS=10 timeout -s KILL 40 target/release/carrick run-elf --raw --fs host fixtures/mn-probes/target/release/fork-exec-mt; pkill -9 -f "carrick run-elf"`
Expected: `PROBE_G_OK ...` (was: ENOSYS / hang).

- [ ] **Step 3: os/exec conformance gate**:

Run: `bash scripts/go-conformance.sh os/exec sync os/signal 2>&1 | grep -E "^\[|TOTAL"`
Expected: `os/exec` carrick PASS count near Docker's 36 (was 10); `sync` `TestMutexMisuse` cleared; total carrick-only failures dropped sharply.

- [ ] **Step 4: No-regression**:

Run (each must hold):
- `cargo test --release --lib 2>&1 | grep "test result" | tail -1` → `ok` (no failures).
- Go default c50 ×6 (the multithreaded oracle) → all pass: `art=...go-hello; for i in $(seq 6); do timeout -s KILL 70 target/release/carrick run-elf --raw --fs host "$art" -- -benchmark -c 50 -n 300 >/dev/null 2>&1 && echo ok || echo FAIL; pkill -9 -f "carrick run-elf"; done`.
- Single-threaded fork still works: `apt-get install hello` smoke (the v1 milestone) OR a single-threaded fork mn-probe — confirms the quiesce path with `others==0` is a no-op.

- [ ] **Step 5: Update baseline + commit**

Update `docs/superpowers/go-conformance-baseline.md` with the new os/exec tally. Commit.

```bash
git add docs/superpowers/go-conformance-baseline.md
git commit -m "docs(go-conformance): os/exec passes after multithreaded fork support"
```

## PROGRESS (2026-05-24) — quiesce done; HVF vCPU teardown is the last layer

Tasks 1–3 + the wait-predicate quiescing are **implemented, committed, and
incrementally validated** against `os/exec` TestEcho:

- `clone(CLONE_VM|CLONE_VFORK|CLONE_PIDFD)` from multithreaded Go: ENOSYS →
  (quiesce timeout) EAGAIN → **quiesce now completes** (all sibling threads park
  at the run-loop-top barrier).
- The fork is now ATTEMPTED. New, deeper error: **HV_BUSY (`0xfae94002`) in
  `engine.fork()`'s pre-fork `hv_vm_destroy()`** — the parked sibling threads
  still hold their HVF vCPUs, and `hv_vm_destroy` refuses while vCPUs exist.

**The remaining layer — vCPU release/rebuild across the barrier (Task 3b):**
`engine.fork()` tears down HVF (`hv_vcpu_destroy` + `hv_vm_destroy`) before
`libc::fork` (HVF state isn't fork-safe). With siblings, the teardown must
account for THEIR vCPUs too. Protocol:

1. Sibling at the barrier (in `park_if_quiescing` / the run loop): snapshot its
   vCPU registers, `hv_vcpu_destroy` its own vCPU, mark "vCPU released"
   (a second barrier counter), then park.
2. Forking thread waits for `released == others` (not just `paused`), then does
   the existing own-vCPU + VM teardown (now succeeds — no live vCPUs) and forks.
3. **Parent**: rebuild the VM (existing path), then publish the new VM handle to
   the siblings and signal "VM ready"; each sibling `hv_vcpu_create`s in the new
   VM, restores its snapshot (like `from_thread_spec`), and resumes.
4. **Child**: single-threaded — the existing rebuild (own vCPU + VM); siblings
   don't exist, so nothing to recreate.

Key difficulty: the **shared VM handle** (`HvfInner._vm`, an `Arc` shared with
thread siblings via `from_thread_spec`) changes across the parent's rebuild, so
siblings must pick up the NEW handle — needs a shared cell (e.g.
`Arc<Mutex<Option<VmHandle>>>`) the barrier publishes. This is an HVF-lifecycle
change touching `trap.rs` `fork()`/`from_thread_spec` and the sibling run loop;
it should be designed as its own careful step (Task 3b) — do NOT rush it.

## Self-review

- **Spec coverage:** QuiesceBarrier (T1), run-loop park + global (T2), handle_fork quiesce/resume + child reset (T3), CLONE_PIDFD + waitid (T4), probe (T5), validation + no-regression (T6). All spec sections covered. The wait-predicate quiescing wake is realized via the existing `futex.notify_signal_pending()` + `host_signal` waiter wake in T3 Step 1/4 (blocked waiters return to the run-loop top and park there) — no separate predicate change needed, since the run-loop-top park is the single quiesce point.
- **Placeholders:** none — QuiesceBarrier is complete code; T4 uses compiler-guided enum changes with explicit field semantics.
- **Consistency:** `set_quiescing`/`wait_quiesced`/`park_if_quiescing`/`end_quiesce`/`is_quiescing` signatures match across T1–T3; `open_pidfd`/`pidfd_host_pid` are the committed pidfd helpers.
- **Ordering invariant (T3 Step 1):** the flag is raised (`set_quiescing`) BEFORE the wakes, and `wait_quiesced` runs AFTER — so a thread woken by the kick/notify observes `is_quiescing()==true` at the run-loop top and parks. This is the load-bearing ordering.
