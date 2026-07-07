# Carrick-Kernel Arena Foundation Implementation Plan (spec steps 1–2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create the `carrick-kernel` crate (arena layout, claim-sentinel records, robust bucket locks, generations) and relocate the HVF vCPU permit table into the arena with unchanged semantics.

**Architecture:** One file-backed `MAP_SHARED` "kernel arena" region per run, mapped before the first guest fork and inherited by every descendant; a fixed `#[repr(C)]` layout of typed sections synchronized with atomics; a robust bucket lock (owner pid + generation) waited on via a pluggable `WaitWake` trait. Step 2 re-homes the existing `SharedPermitTable` (currently a private `MAP_ANON|MAP_SHARED` page inside `carrick-vmm-hvf`) into the arena as its first section, leaving CAS logic, occupancy derivation, backpressure, and the reaper untouched.

**Tech Stack:** Rust (edition 2024, workspace lints deny unwrap/expect/panic/todo), `libc` crate for mmap/ftruncate (per repo rule: always the `libc` crate, never hand-rolled FFI), `std::sync::atomic`.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-07-06-carrick-kernel-authority-design.md` (rev 2).
- One Linux process = one macOS process; hot paths gain ZERO IPC — everything here is shared memory + atomics.
- Section exhaustion is LOUD: a typed error, never a silent process-local fallback.
- Every slot naming a process carries (host pid, generation); stale releases must be no-ops.
- `members = ["crates/*"]` — a new dir under `crates/` auto-joins the workspace.
- Workspace lints: `unwrap_used`/`expect_used`/`panic`/`todo`/`unimplemented` = deny; `unreachable_patterns` = deny. Tests may `#![allow]` locally (see `hvf_fork_probe.rs` precedent).
- Build via `just build` (codesigned); plain `cargo test -p carrick-kernel --lib` is fine for this crate (no HVF).
- NEVER `git commit --no-verify`; pre-commit runs `just fmt-check`.
- Clean-room rule: semantics from man pages/oracle only; no Linux kernel source.

---

### Task 1: Crate scaffold + typed domains

**Files:**
- Create: `crates/carrick-kernel/Cargo.toml`
- Create: `crates/carrick-kernel/src/lib.rs`
- Create: `crates/carrick-kernel/src/domains.rs`

**Interfaces:**
- Produces: `carrick_kernel::domains::{HostPid, ProcessGeneration, LeaseGeneration, ExecGeneration, BucketKey, RunToken}` — all `#[repr(transparent)]` newtypes with `pub const fn new(raw) -> Self` and `pub const fn raw(self) -> <int>`.
- Note: `carrick-runtime` already has its own `HostPid(pub u32)` in `crates/carrick-runtime/src/dispatch/abi_args.rs:40`. That one stays; conversion at the boundary is explicit (`domains::HostPid::new(abi.0)`). `carrick-kernel` must NOT depend on `carrick-runtime` (the dependency will run the other way).

- [ ] **Step 1: Write `Cargo.toml`** (mirrors `crates/carrick-signal-core/Cargo.toml`)

```toml
[package]
name = "carrick-kernel"
version.workspace = true
edition.workspace = true
license.workspace = true

[lib]
name = "carrick_kernel"
path = "src/lib.rs"

[lints]
workspace = true

[dependencies]
libc.workspace = true
```

- [ ] **Step 2: Write the failing test** (in `src/domains.rs` under `#[cfg(test)]`)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_round_trip_and_do_not_mix() {
        let pid = HostPid::new(1234);
        assert_eq!(pid.raw(), 1234);
        let generation = ProcessGeneration::new(7);
        assert_eq!(generation.raw(), 7);
        // Generation 0 is reserved for "no owner" everywhere in the arena.
        assert!(ProcessGeneration::NONE.raw() == 0);
        let key = BucketKey::new(0xdead_beef);
        assert_eq!(key.raw(), 0xdead_beef);
    }
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test -p carrick-kernel --lib 2>&1 | tail -5`
Expected: compile error — crate/module does not exist yet.

- [ ] **Step 4: Implement `src/domains.rs` and `src/lib.rs`**

`src/lib.rs`:
```rust
//! carrick-kernel: the per-run KERNEL ARENA — one file-backed `MAP_SHARED`
//! region holding the Linux-visible cross-process delta (identity, leases,
//! shared kernel objects) that the host kernel cannot express. There is NO
//! authority daemon: processes operate on the arena with atomics and robust
//! bucket locks; the run supervisor only sweeps after hard death.
//! Spec: docs/superpowers/specs/2026-07-06-carrick-kernel-authority-design.md.

pub mod domains;
```

`src/domains.rs`:
```rust
//! Typed identity domains for arena state. Raw integers cross only at the
//! `#[repr(C)]` slot layouts and host libc calls; constructors name the
//! crossing (`HostPid::new(libc::getpid() as u32)`).

/// A host (Darwin/Linux/BSD) process id as stored in arena slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct HostPid(u32);

/// Monotonic per-process-record generation defeating pid reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ProcessGeneration(u32);

/// Monotonic per-lease generation defeating stale release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct LeaseGeneration(u32);

/// Bumped on successful `execve`; late releases stamped with the old image
/// generation must not apply to the new image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct ExecGeneration(u32);

/// Hash-bucket key for multi-record critical sections (futex requeue, SysV).
/// Lock ordering is by ascending `BucketKey`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct BucketKey(u64);

/// Run-scope token mixed into the arena header (hash of `CARRICK_RUN_ID`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct RunToken(u64);

macro_rules! domain_impl {
    ($name:ident, $raw:ty) => {
        impl $name {
            pub const fn new(raw: $raw) -> Self {
                Self(raw)
            }
            pub const fn raw(self) -> $raw {
                self.0
            }
        }
    };
}
domain_impl!(HostPid, u32);
domain_impl!(ProcessGeneration, u32);
domain_impl!(LeaseGeneration, u32);
domain_impl!(ExecGeneration, u32);
domain_impl!(BucketKey, u64);
domain_impl!(RunToken, u64);

impl ProcessGeneration {
    /// Reserved: "no owner". Arena generation counters start at 1.
    pub const NONE: ProcessGeneration = ProcessGeneration(0);
}
```
(then the test module from Step 2 at the bottom of `domains.rs`)

- [ ] **Step 5: Run tests + lints, then commit**

Run: `cargo test -p carrick-kernel --lib && cargo clippy -p carrick-kernel --all-targets`
Expected: test passes, clippy clean.

```bash
git add crates/carrick-kernel
git commit -m "feat(kernel): carrick-kernel crate scaffold + typed domains"
```

---

### Task 2: WaitWake trait + test backend

**Files:**
- Create: `crates/carrick-kernel/src/wait.rs`
- Modify: `crates/carrick-kernel/src/lib.rs` (add `pub mod wait;`)

**Interfaces:**
- Produces:
  - `trait WaitWake { fn wait(&self, word: &AtomicU64, expected: u64, timeout: Option<Duration>) -> WaitOutcome; fn wake(&self, word: &AtomicU64, count: u32) -> u32; }`
  - `enum WaitOutcome { Woken, ValueChanged, TimedOut }`
  - `struct SpinYield;` — a portable fallback/test implementation.
- Consumes: nothing.
- Platform note: production impls are the existing per-host futex primitives — macOS `os_sync_wait_on_address(_SHARED)` already wrapped in `crates/carrick-host/src/ulock.rs`, Linux `futex`, FreeBSD `_umtx_op`. Wiring those is part of the CALLER crates (they already depend on their host crate); `carrick-kernel` itself stays host-agnostic and ships only `SpinYield`.

- [ ] **Step 1: Write the failing test** (bottom of `src/wait.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    #[test]
    fn spin_yield_returns_value_changed_when_word_moves() {
        let word = AtomicU64::new(1);
        word.store(2, Ordering::Release);
        let out = SpinYield.wait(&word, 1, Some(Duration::from_millis(50)));
        assert_eq!(out, WaitOutcome::ValueChanged);
    }

    #[test]
    fn spin_yield_times_out_when_word_holds() {
        let word = AtomicU64::new(1);
        let out = SpinYield.wait(&word, 1, Some(Duration::from_millis(20)));
        assert_eq!(out, WaitOutcome::TimedOut);
    }
}
```

- [ ] **Step 2: Run to verify it fails** — `cargo test -p carrick-kernel --lib wait` — compile error.

- [ ] **Step 3: Implement `src/wait.rs`**

```rust
//! Pluggable block/wake primitive for arena waiters. The arena never sleeps
//! on its own: callers supply the host futex (macOS `os_sync_wait_on_address`
//! via carrick-host ulock, Linux futex, FreeBSD `_umtx_op`). `SpinYield` is
//! the portable fallback used by unit tests and non-hot diagnostics.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// A waker woke us (or the backend cannot distinguish; treat as retry).
    Woken,
    /// The word no longer holds `expected`; retry the caller's CAS loop.
    ValueChanged,
    /// The bounded wait elapsed.
    TimedOut,
}

pub trait WaitWake {
    /// Block while `*word == expected`, bounded by `timeout` (None = unbounded
    /// for the backend, but arena callers ALWAYS pass a bound — a broken wake
    /// path must surface as a timeout diagnostic, not a hang).
    fn wait(&self, word: &AtomicU64, expected: u64, timeout: Option<Duration>) -> WaitOutcome;
    /// Wake up to `count` waiters; returns how many the backend reports woken
    /// (0 when unknown).
    fn wake(&self, word: &AtomicU64, count: u32) -> u32;
}

/// Portable spin/yield fallback. Correct, not fast; test-grade.
pub struct SpinYield;

impl WaitWake for SpinYield {
    fn wait(&self, word: &AtomicU64, expected: u64, timeout: Option<Duration>) -> WaitOutcome {
        let start = Instant::now();
        loop {
            if word.load(Ordering::Acquire) != expected {
                return WaitOutcome::ValueChanged;
            }
            if let Some(t) = timeout
                && start.elapsed() >= t
            {
                return WaitOutcome::TimedOut;
            }
            std::thread::yield_now();
        }
    }

    fn wake(&self, _word: &AtomicU64, _count: u32) -> u32 {
        0 // spinners notice the store themselves
    }
}
```

- [ ] **Step 4: Run tests** — `cargo test -p carrick-kernel --lib wait` — 2 pass.

- [ ] **Step 5: Commit**

```bash
git add crates/carrick-kernel
git commit -m "feat(kernel): WaitWake trait + SpinYield test backend"
```

---

### Task 3: Robust bucket lock

**Files:**
- Create: `crates/carrick-kernel/src/lock.rs`
- Modify: `crates/carrick-kernel/src/lib.rs` (add `pub mod lock;`)

**Interfaces:**
- Consumes: `domains::{HostPid, ProcessGeneration}`, `wait::{WaitWake, WaitOutcome}`.
- Produces:
  - `#[repr(transparent)] struct RobustLock { word: AtomicU64 }` with:
    - `const fn new() -> Self`
    - `fn lock<'a>(&'a self, me: LockOwner, ww: &dyn WaitWake, timeout: Duration) -> Result<RobustGuard<'a>, LockError>`
    - `fn force_break(&self, dead: LockOwner) -> bool` — supervisor sweep API: frees the lock iff still held by `dead`.
    - `fn holder(&self) -> Option<LockOwner>`
  - `struct LockOwner { pid: HostPid, generation: ProcessGeneration }`
  - `enum LockError { Timeout { holder: Option<LockOwner> } }`
  - `fn lock_pair<'a>(a: &'a RobustLock, b: &'a RobustLock, ...) -> Result<(RobustGuard<'a>, RobustGuard<'a>), LockError>` — address-ordered, for two-bucket ops (futex requeue). Callers order buckets by ascending `BucketKey`; `lock_pair` additionally orders by address as a belt-and-braces tie-break.
- Word packing (documented in code): `bits 63..62 state (0=free, 1=held)`, `bits 61..32 owner generation (30b)`, `bits 31..0 owner pid` — deliberately the SAME shape as the landed permit slot (`crates/carrick-vmm-hvf/src/trap.rs:962-997`) so one packing discipline serves both.

- [ ] **Step 1: Write the failing tests** (bottom of `src/lock.rs`)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains::{HostPid, ProcessGeneration};
    use crate::wait::SpinYield;
    use std::time::Duration;

    fn me(pid: u32, generation: u32) -> LockOwner {
        LockOwner {
            pid: HostPid::new(pid),
            generation: ProcessGeneration::new(generation),
        }
    }

    #[test]
    fn lock_unlock_round_trip() {
        let l = RobustLock::new();
        assert!(l.holder().is_none());
        let g = l
            .lock(me(10, 1), &SpinYield, Duration::from_millis(100))
            .map_err(|e| format!("{e:?}"))
            .unwrap_or_else(|e| panic!("lock failed: {e}"));
        assert_eq!(l.holder(), Some(me(10, 1)));
        drop(g);
        assert!(l.holder().is_none());
    }

    #[test]
    fn contended_lock_times_out_and_names_holder() {
        let l = RobustLock::new();
        let _g = l
            .lock(me(10, 1), &SpinYield, Duration::from_millis(100))
            .unwrap_or_else(|_| panic!("first lock"));
        let e = l
            .lock(me(11, 2), &SpinYield, Duration::from_millis(20))
            .err()
            .unwrap_or_else(|| panic!("second lock must time out"));
        let LockError::Timeout { holder } = e;
        assert_eq!(holder, Some(me(10, 1)));
    }

    #[test]
    fn force_break_frees_only_the_named_dead_owner() {
        let l = RobustLock::new();
        let g = l
            .lock(me(10, 1), &SpinYield, Duration::from_millis(100))
            .unwrap_or_else(|_| panic!("lock"));
        std::mem::forget(g); // simulate the holder dying without unlock
        assert!(!l.force_break(me(10, 2))); // wrong generation: no-op
        assert!(l.force_break(me(10, 1))); // exact owner: broken
        assert!(l.holder().is_none());
        // now lockable again
        let _g2 = l
            .lock(me(12, 3), &SpinYield, Duration::from_millis(100))
            .unwrap_or_else(|_| panic!("relock"));
    }

    #[test]
    fn lock_pair_orders_by_address_and_survives_reversed_call() {
        let a = RobustLock::new();
        let b = RobustLock::new();
        let (g1, g2) = lock_pair(&a, &b, me(10, 1), &SpinYield, Duration::from_millis(100))
            .unwrap_or_else(|_| panic!("pair ab"));
        drop((g1, g2));
        let (g1, g2) = lock_pair(&b, &a, me(10, 1), &SpinYield, Duration::from_millis(100))
            .unwrap_or_else(|_| panic!("pair ba"));
        drop((g1, g2));
    }
}
```

(Note the tests use `unwrap_or_else(|| panic!(...))` inside `#[cfg(test)]`; add `#![allow(clippy::panic)]` is NOT needed — put `#[allow(clippy::panic)]` on the tests module, matching workspace test conventions.)

- [ ] **Step 2: Run to verify failure** — `cargo test -p carrick-kernel --lib lock` — compile error.

- [ ] **Step 3: Implement `src/lock.rs`**

```rust
//! Robust bucket lock: a single fork-shared `AtomicU64` whose holder is
//! (host pid, generation)-stamped, so a holder that dies mid-critical-section
//! is detectable and breakable by the supervisor sweep — the shared-memory
//! answer to "what if there is no daemon to serialize this".
//!
//! Packing (same discipline as the vCPU permit slot, trap.rs:962):
//!   bits 63..62  state       (0 = free, 1 = held)
//!   bits 61..32  generation  (30 bits)
//!   bits 31..0   owner pid   (32 bits)

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::domains::{HostPid, ProcessGeneration};
use crate::wait::{WaitOutcome, WaitWake};

const STATE_SHIFT: u32 = 62;
const STATE_HELD: u64 = 1 << STATE_SHIFT;
const GEN_SHIFT: u32 = 32;
const GEN_BITS: u32 = 30;
const GEN_MASK_VALUE: u64 = (1 << GEN_BITS) - 1;
const PID_MASK: u64 = 0xFFFF_FFFF;
const FREE: u64 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockOwner {
    pub pid: HostPid,
    pub generation: ProcessGeneration,
}

#[derive(Debug)]
pub enum LockError {
    Timeout { holder: Option<LockOwner> },
}

fn pack(owner: LockOwner) -> u64 {
    STATE_HELD
        | ((u64::from(owner.generation.raw()) & GEN_MASK_VALUE) << GEN_SHIFT)
        | u64::from(owner.pid.raw())
}

fn unpack(word: u64) -> Option<LockOwner> {
    if word & STATE_HELD == 0 {
        return None;
    }
    Some(LockOwner {
        pid: HostPid::new((word & PID_MASK) as u32),
        generation: ProcessGeneration::new(((word >> GEN_SHIFT) & GEN_MASK_VALUE) as u32),
    })
}

#[repr(transparent)]
pub struct RobustLock {
    word: AtomicU64,
}

impl RobustLock {
    pub const fn new() -> Self {
        Self {
            word: AtomicU64::new(FREE),
        }
    }

    pub fn holder(&self) -> Option<LockOwner> {
        unpack(self.word.load(Ordering::Acquire))
    }

    pub fn lock<'a>(
        &'a self,
        me: LockOwner,
        ww: &dyn WaitWake,
        timeout: Duration,
    ) -> Result<RobustGuard<'a>, LockError> {
        let packed = pack(me);
        let start = Instant::now();
        loop {
            match self
                .word
                .compare_exchange(FREE, packed, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return Ok(RobustGuard { lock: self }),
                Err(observed) => {
                    let remaining = timeout.saturating_sub(start.elapsed());
                    if remaining.is_zero() {
                        return Err(LockError::Timeout {
                            holder: unpack(observed),
                        });
                    }
                    match ww.wait(&self.word, observed, Some(remaining)) {
                        WaitOutcome::Woken | WaitOutcome::ValueChanged => continue,
                        WaitOutcome::TimedOut => {
                            return Err(LockError::Timeout {
                                holder: self.holder(),
                            });
                        }
                    }
                }
            }
        }
    }

    /// Supervisor sweep: free the lock iff still held by exactly `dead`
    /// (pid AND generation). Returns whether it broke the lock. The caller
    /// must have confirmed the owner process is gone (EVFILT_PROC + liveness
    /// re-check, as in vcpu_permit_reaper.rs).
    pub fn force_break(&self, dead: LockOwner) -> bool {
        self.word
            .compare_exchange(pack(dead), FREE, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn unlock(&self) {
        self.word.store(FREE, Ordering::Release);
    }
}

impl Default for RobustLock {
    fn default() -> Self {
        Self::new()
    }
}

pub struct RobustGuard<'a> {
    lock: &'a RobustLock,
}

impl Drop for RobustGuard<'_> {
    fn drop(&mut self) {
        self.lock.unlock();
    }
}

/// Two-bucket critical section (futex requeue, SysV multi-sem): callers order
/// buckets by ascending BucketKey; this additionally orders by address so a
/// mis-ordered call cannot deadlock against a correctly-ordered one.
pub fn lock_pair<'a>(
    a: &'a RobustLock,
    b: &'a RobustLock,
    me: LockOwner,
    ww: &dyn WaitWake,
    timeout: Duration,
) -> Result<(RobustGuard<'a>, RobustGuard<'a>), LockError> {
    let (first, second) = if (a as *const RobustLock) <= (b as *const RobustLock) {
        (a, b)
    } else {
        (b, a)
    };
    let g1 = first.lock(me, ww, timeout)?;
    let g2 = second.lock(me, ww, timeout)?;
    Ok((g1, g2))
}
```

Note for the implementer: `RobustGuard::drop` does not `wake` — the waiter side re-CASes after `WaitOutcome::ValueChanged`/`TimedOut` and `SpinYield` observes stores directly. When a real futex backend is wired by a caller crate, unlock must wake; add a `RobustLock::unlock_and_wake(&self, ww: &dyn WaitWake)` in that integration if profiling shows spurious timeout retries. Do NOT pre-build it here (YAGNI) — the permit path in Task 6 does not park on bucket locks.

- [ ] **Step 4: Run tests** — `cargo test -p carrick-kernel --lib lock` — 4 pass.
- [ ] **Step 5: Clippy + commit**

```bash
cargo clippy -p carrick-kernel --all-targets
git add crates/carrick-kernel
git commit -m "feat(kernel): robust bucket lock with owner generations and force_break"
```

---

### Task 4: Cross-process kill-9 robust-lock test

Real-process proof that a SIGKILLed holder is recoverable — the shape the supervisor sweep relies on. Uses `libc::fork` in a test, following the precedent of `crates/carrick-vmm-hvf/src/vcpu_permit_reaper.rs:398` (`fork_short_lived_child`).

**Files:**
- Create: `crates/carrick-kernel/tests/robust_lock_kill9.rs`

**Interfaces:**
- Consumes: `RobustLock` on a real `MAP_SHARED` page (raw mmap in the test), `LockOwner`, `force_break`.

- [ ] **Step 1: Write the failing test**

```rust
//! A child that takes a shared-memory RobustLock and is SIGKILLed must be
//! recoverable via force_break from the surviving process.
#![allow(clippy::panic, clippy::unwrap_used)]

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use carrick_kernel::domains::{HostPid, ProcessGeneration};
use carrick_kernel::lock::{LockOwner, RobustLock};
use carrick_kernel::wait::SpinYield;

#[repr(C)]
struct Shared {
    lock: RobustLock,
    child_holds: AtomicU32,
}

fn map_shared() -> &'static Shared {
    let size = std::mem::size_of::<Shared>();
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANON | libc::MAP_SHARED,
            -1,
            0,
        )
    };
    assert!(ptr != libc::MAP_FAILED);
    unsafe { &*(ptr as *const Shared) }
}

#[test]
fn kill9_holder_is_recoverable() {
    let shared = map_shared();
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        // Child: take the lock, signal, then spin forever (never unlock).
        let me = LockOwner {
            pid: HostPid::new(unsafe { libc::getpid() } as u32),
            generation: ProcessGeneration::new(1),
        };
        let g = shared
            .lock
            .lock(me, &SpinYield, Duration::from_secs(5))
            .unwrap_or_else(|_| std::process::exit(2));
        shared.child_holds.store(1, Ordering::Release);
        std::mem::forget(g);
        loop {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    // Parent: wait for the child to hold the lock.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while shared.child_holds.load(Ordering::Acquire) == 0 {
        assert!(std::time::Instant::now() < deadline, "child never locked");
        std::thread::yield_now();
    }
    // SIGKILL the holder and reap it.
    unsafe {
        libc::kill(child, libc::SIGKILL);
        let mut status = 0;
        libc::waitpid(child, &mut status, 0);
    }
    // The lock still names the dead owner; a contender times out against it.
    let survivor = LockOwner {
        pid: HostPid::new(unsafe { libc::getpid() } as u32),
        generation: ProcessGeneration::new(2),
    };
    assert!(
        shared
            .lock
            .lock(survivor, &SpinYield, Duration::from_millis(50))
            .is_err()
    );
    let dead = shared.lock.holder().unwrap();
    assert_eq!(dead.pid.raw(), child as u32);
    // Sweep: break the dead owner's lock, then lock normally.
    assert!(shared.lock.force_break(dead));
    let _g = shared
        .lock
        .lock(survivor, &SpinYield, Duration::from_secs(1))
        .unwrap_or_else(|_| panic!("lock after break"));
}
```

- [ ] **Step 2: Run to verify it fails** — it should PASS immediately if Task 3 is correct; the "fail first" point here is running it with `force_break` stubbed to `false` mentally — instead, verify the test actually exercises the path: `cargo test -p carrick-kernel --test robust_lock_kill9 -- --nocapture`. Expected: PASS. If it hangs, the child fork/lock ordering is wrong — fix the test, not the lock, unless `holder()` misreports.
- [ ] **Step 3: Commit**

```bash
git add crates/carrick-kernel/tests/robust_lock_kill9.rs
git commit -m "test(kernel): kill-9 holder recoverable via force_break (real fork)"
```

---

### Task 5: The arena region (header, sections, file-backed mapping, generations)

**Files:**
- Create: `crates/carrick-kernel/src/arena.rs`
- Modify: `crates/carrick-kernel/src/lib.rs` (add `pub mod arena;`)

**Interfaces:**
- Consumes: `domains::*`, `lock::RobustLock`.
- Produces:
  - `#[repr(C)] pub struct ArenaHeader { magic: AtomicU32, version: AtomicU32, run_token: AtomicU64, next_generation: AtomicU32 }`
  - `#[repr(C)] pub struct ArenaLayout { pub header: ArenaHeader, pub permits: PermitSection }` — sections are added as later plans land (process section is the next plan); layout changes bump `ARENA_VERSION`.
  - `#[repr(C)] pub struct PermitSection { pub magic: AtomicU32, pub version: AtomicU32, pub next_generation: AtomicU32, pub slots: [AtomicU64; PERMIT_MAX_SLOTS] }` with `pub const PERMIT_MAX_SLOTS: usize = 128` — byte-compatible with `SharedPermitTable` (`crates/carrick-vmm-hvf/src/trap.rs:1048-1054`), same magic `0x4352_5031` ("CRP1"), same version 1, so Task 6's relocation is a pointer swap.
  - `pub struct KernelArena` with:
    - `pub fn create() -> std::io::Result<KernelArena>` — file-backed `MAP_SHARED` (unlinked temp file), header published magic-last.
    - `pub fn init_global() -> &'static KernelArena` — process-wide `OnceLock`, MUST be called before the first guest fork (same contract as `run_state::init_table`, `guest_cpu::init_child_table`); lazy-creates when not pre-initialized so unit tests and non-runtime binaries keep working.
    - `pub fn global() -> &'static KernelArena` — alias of `init_global` (explicit name at call sites that intend lazy init).
    - `pub fn layout(&self) -> &ArenaLayout`
    - `pub fn allocate_generation(&self) -> ProcessGeneration` — shared monotonic counter, 30-bit wrap, skipping 0.
    - `pub const ARENA_MAGIC: u32 = 0x434b_4131; // "CKA1"` and `pub const ARENA_VERSION: u32 = 1;`
  - `pub enum ArenaError { Exhausted { section: &'static str, capacity: usize } }` — the LOUD exhaustion type later sections return.

- [ ] **Step 1: Write the failing tests** (bottom of `src/arena.rs`)

```rust
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn create_publishes_versioned_header() {
        let arena = KernelArena::create().unwrap();
        let l = arena.layout();
        assert_eq!(
            l.header.magic.load(std::sync::atomic::Ordering::Acquire),
            ARENA_MAGIC
        );
        assert_eq!(
            l.header.version.load(std::sync::atomic::Ordering::Relaxed),
            ARENA_VERSION
        );
        // permit section is pre-initialized, byte-compatible with trap.rs's
        // SharedPermitTable: magic "CRP1", version 1, generations start at 1.
        assert_eq!(
            l.permits.magic.load(std::sync::atomic::Ordering::Acquire),
            0x4352_5031
        );
        assert_eq!(
            l.permits
                .next_generation
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn generations_are_monotonic_and_skip_zero() {
        let arena = KernelArena::create().unwrap();
        let g1 = arena.allocate_generation();
        let g2 = arena.allocate_generation();
        assert_ne!(g1.raw(), 0);
        assert_ne!(g2.raw(), 0);
        assert_ne!(g1, g2);
    }

    #[test]
    fn arena_is_visible_across_fork() {
        let arena = KernelArena::create().unwrap();
        let l = arena.layout();
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            // Child writes a generation; MAP_SHARED makes it visible above.
            l.header
                .run_token
                .store(0x5eed, std::sync::atomic::Ordering::Release);
            std::process::exit(0);
        }
        let mut status = 0;
        unsafe { libc::waitpid(child, &mut status, 0) };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while l.header.run_token.load(std::sync::atomic::Ordering::Acquire) != 0x5eed {
            assert!(std::time::Instant::now() < deadline, "child write not visible");
            std::thread::yield_now();
        }
    }
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p carrick-kernel --lib arena` — compile error.

- [ ] **Step 3: Implement `src/arena.rs`**

```rust
//! The kernel arena: ONE file-backed `MAP_SHARED` region per run, mapped
//! before the first guest fork and inherited by every descendant. Fixed
//! `#[repr(C)]` layout; version-stamped header published magic-last; all
//! cross-process access is atomics (+ RobustLock for multi-record sections).
//!
//! File-backed (not MAP_ANON) deliberately: the PID-namespace region
//! (carrick-runtime/src/namespace/pid.rs map_region) proved file backing is
//! what lets an outside process (`carrick exec`, diagnostics) attach late,
//! and cores carry the mapping either way. The file is created under the
//! run temp dir and unlinked after mmap; the fd is inherited across fork.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::domains::ProcessGeneration;

pub const ARENA_MAGIC: u32 = 0x434b_4131; // "CKA1"
pub const ARENA_VERSION: u32 = 1;

/// Permit-section constants — MUST stay byte-identical to the landed
/// `SharedPermitTable` (carrick-vmm-hvf/src/trap.rs:1048): magic "CRP1",
/// version 1, 128 slots. Task 6 swaps trap.rs onto this section.
pub const PERMIT_MAGIC: u32 = 0x4352_5031;
pub const PERMIT_VERSION: u32 = 1;
pub const PERMIT_MAX_SLOTS: usize = 128;

#[repr(C)]
pub struct ArenaHeader {
    pub magic: AtomicU32,
    pub version: AtomicU32,
    pub next_generation: AtomicU32,
    _pad: AtomicU32,
    pub run_token: AtomicU64,
}

#[repr(C)]
pub struct PermitSection {
    pub magic: AtomicU32,
    pub version: AtomicU32,
    pub next_generation: AtomicU32,
    // #[repr(C)] pads 4 bytes here to 8-align slots — same as SharedPermitTable.
    pub slots: [AtomicU64; PERMIT_MAX_SLOTS],
}

/// The whole arena. Adding a section = append a field + bump ARENA_VERSION.
#[repr(C)]
pub struct ArenaLayout {
    pub header: ArenaHeader,
    pub permits: PermitSection,
}

#[derive(Debug)]
pub enum ArenaError {
    /// A fixed-capacity section is full. LOUD by design: callers translate to
    /// a Linux errno (EAGAIN/ENOSPC) and fire a probe; there is NO silent
    /// process-local fallback (the run-state 510-slot lesson).
    Exhausted {
        section: &'static str,
        capacity: usize,
    },
}

pub struct KernelArena {
    base: usize,
}

// SAFETY: `base` is a process-lifetime MAP_SHARED mapping; all access to it
// goes through atomics.
unsafe impl Send for KernelArena {}
unsafe impl Sync for KernelArena {}

impl KernelArena {
    /// Create the region: unlinked temp file, ftruncate, MAP_SHARED, header
    /// published magic-last (Release) so any reader that sees the magic also
    /// sees an initialized layout.
    pub fn create() -> std::io::Result<KernelArena> {
        let size = std::mem::size_of::<ArenaLayout>();
        let dir = std::env::temp_dir();
        let path = dir.join(format!("carrick-kernel-arena-{}", std::process::id()));
        let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| std::io::Error::other("arena path contains NUL"))?;
        // SAFETY: plain open/ftruncate/mmap/unlink via the libc crate on a
        // path we just built; every rc is checked.
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_EXCL, 0o600) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let rc = unsafe { libc::ftruncate(fd, size as libc::off_t) };
        if rc != 0 {
            let e = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
                libc::unlink(cpath.as_ptr());
            }
            return Err(e);
        }
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        // Unlink immediately: the mapping + inherited fd keep it alive; no
        // stale files if we crash. (Late attach by path is a follow-up that
        // will move creation into the run temp root and defer the unlink.)
        unsafe { libc::unlink(cpath.as_ptr()) };
        if ptr == libc::MAP_FAILED {
            let e = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e);
        }
        // fd intentionally left open: inherited across fork, keeps the file.
        let arena = KernelArena { base: ptr as usize };
        let l = arena.layout();
        l.header.next_generation.store(1, Ordering::Relaxed);
        l.header.version.store(ARENA_VERSION, Ordering::Relaxed);
        l.permits.next_generation.store(1, Ordering::Relaxed);
        l.permits.version.store(PERMIT_VERSION, Ordering::Relaxed);
        l.permits.magic.store(PERMIT_MAGIC, Ordering::Release);
        l.header.magic.store(ARENA_MAGIC, Ordering::Release);
        Ok(arena)
    }

    /// Process-wide singleton. MUST run in the root guest process before the
    /// first guest fork (same contract as run_state::init_table and
    /// guest_cpu::init_child_table); safe to call again afterwards.
    pub fn init_global() -> &'static KernelArena {
        static GLOBAL: OnceLock<KernelArena> = OnceLock::new();
        GLOBAL.get_or_init(|| match KernelArena::create() {
            Ok(a) => a,
            Err(e) => {
                // Fail closed and loud: without the arena there is no safe
                // cross-process ownership story. (Never a silent private
                // fallback — a private arena would "work" in the parent and
                // desync every child.)
                panic!("carrick-kernel arena creation failed: {e}");
            }
        })
    }

    pub fn global() -> &'static KernelArena {
        Self::init_global()
    }

    pub fn layout(&self) -> &ArenaLayout {
        // SAFETY: base is a live, correctly-sized, zero-initialized-then-
        // published mapping for the process lifetime.
        unsafe { &*(self.base as *const ArenaLayout) }
    }

    /// Shared monotonic generation: 30-bit wrap, never 0.
    pub fn allocate_generation(&self) -> ProcessGeneration {
        let l = self.layout();
        loop {
            let g = l.header.next_generation.fetch_add(1, Ordering::AcqRel) & ((1 << 30) - 1);
            if g != 0 {
                return ProcessGeneration::new(g);
            }
        }
    }
}
```

Implementer notes:
- `panic!` is workspace-denied; this ONE panic is the designed fail-closed path — annotate the function with `#[allow(clippy::panic)]` and a comment referencing the spec's failure model ("arena attach/create fails closed").
- `as_encoded_bytes` needs no unsafe; if the borrow checker or MSRV objects, use `path.to_str()` + `ok_or` instead.

- [ ] **Step 4: Run tests** — `cargo test -p carrick-kernel --lib arena` — 3 pass.
- [ ] **Step 5: Clippy, fmt, commit**

```bash
cargo clippy -p carrick-kernel --all-targets && cargo fmt --all -- --check
git add crates/carrick-kernel
git commit -m "feat(kernel): file-backed kernel arena with versioned header and permit section"
```

---

### Task 6: Relocate the HVF permit table into the arena

Semantics unchanged: same bit layout, same magic, same CAS/occupancy/reaper code. The ONLY change is where the shared page comes from.

**Files:**
- Modify: `crates/carrick-vmm-hvf/Cargo.toml` (add `carrick-kernel = { path = "../carrick-kernel" }`)
- Modify: `crates/carrick-vmm-hvf/src/trap.rs:1074-1116` (`PermitRegion::map_shared_table`, `new_shared_global`)

**Interfaces:**
- Consumes: `carrick_kernel::arena::{KernelArena, PermitSection, PERMIT_MAX_SLOTS, PERMIT_MAGIC, PERMIT_VERSION}`.
- Produces: no API change. `SharedPermitTable` stays as trap.rs's view type; a compile-time layout assertion pins it to `PermitSection`.

- [ ] **Step 1: Write the failing test** (in trap.rs's existing `#[cfg(test)]` mod, near `resource_growing_vm_creation_uses_global_permit` at trap.rs:5339)

```rust
#[test]
fn permit_table_is_the_arena_permit_section() {
    // Layout pin: SharedPermitTable and carrick_kernel::arena::PermitSection
    // must remain byte-identical (Task 6 relocation contract).
    assert_eq!(
        std::mem::size_of::<SharedPermitTable>(),
        std::mem::size_of::<carrick_kernel::arena::PermitSection>()
    );
    assert_eq!(
        std::mem::offset_of!(SharedPermitTable, slots),
        std::mem::offset_of!(carrick_kernel::arena::PermitSection, slots)
    );
    // The global region must point INTO the arena, not at a private page.
    let arena = carrick_kernel::arena::KernelArena::global();
    let section = &arena.layout().permits as *const _ as usize;
    assert_eq!(global_vcpu_permit_region().table, section);
}
```

(`global_vcpu_permit_region()` — use the existing accessor for the process singleton `PermitRegion`; it is the `OnceLock` init around trap.rs:1111 `new_shared_global`. If the current code inlines it, add a `pub(crate) fn global_vcpu_permit_region() -> &'static PermitRegion` accessor as part of Step 3.)

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p carrick-vmm-hvf permit_table_is_the_arena --lib`
Expected: FAIL — either `carrick_kernel` unresolved (dep not added) or the address assertion fails (still a private mmap).

- [ ] **Step 3: Implement the swap**

In `crates/carrick-vmm-hvf/Cargo.toml` `[dependencies]`:
```toml
carrick-kernel = { path = "../carrick-kernel" }
```

In `trap.rs`, replace the body of `PermitRegion::new_shared_global` (keep `map_shared_table` for the injectable-test-region constructor ONLY — rename it `map_private_table_for_tests` and mark `#[cfg(test)]`):

```rust
fn new_shared_global() -> PermitRegion {
    // The permit table is the arena's permit section: created before the
    // first guest fork (KernelArena::init_global), inherited by every
    // descendant, already initialized with CRP1 magic + generation 1.
    let arena = carrick_kernel::arena::KernelArena::global();
    PermitRegion {
        table: &arena.layout().permits as *const _ as usize,
        local: std::sync::Mutex::new(HashMap::new()),
    }
}
```

Keep everything else byte-for-byte: `atomic_permit_slot`, `table()`, occupancy `SeqCst` discipline, `reset_local_after_fork_child`, `reset_admission_permits_after_fork_child`, the reaper. The existing `SharedPermitTable` struct stays as the view type; its private header init in `map_shared_table` moves under `#[cfg(test)]` with it.

- [ ] **Step 4: Run the permit + reaper test suites**

Run: `cargo test -p carrick-vmm-hvf --lib 2>&1 | tail -20`
Expected: all existing permit/reaper tests pass plus the new layout test. Watch specifically: `note_exit_reclaims_owner_slot`, `register_after_exit_reclaims_via_readiness_check` (vcpu_permit_reaper.rs:422,457) and the `global_permit_budget` tests (trap.rs:5339-5373).

- [ ] **Step 5: Arena preinit in the runtime boot path**

Modify `crates/carrick-runtime/src/runtime.rs` — the root-process preinit block that already calls `preinit_waiter_table` (runtime.rs:722 area, BEFORE `maybe_fork_ns_supervisor` and before any VM creation). Add, with `carrick-kernel = { path = "../carrick-kernel" }` in `crates/carrick-runtime/Cargo.toml`:

```rust
// Kernel arena MUST exist before the first fork (supervisor split included)
// so every descendant inherits one shared mapping.
let _ = carrick_kernel::arena::KernelArena::init_global();
```

Run: `just build` (signed) then the fast gate: `just test`.
Expected: build green, host lib tests green.

- [ ] **Step 6: End-to-end smoke — permits still admit under fork storm**

Run: `just conformance smoke`
Expected: exit 0, no regressions (the smoke tier exercises fork-heavy suites through the admission path).

- [ ] **Step 7: Commit**

```bash
git add crates/carrick-kernel crates/carrick-vmm-hvf crates/carrick-runtime
git commit -m "refactor(hvf): vCPU permit table relocates into the kernel arena"
```

---

### Task 7: Loud-exhaustion contract test for the permit section

Pins the spec rule "exhaustion is LOUD" at the arena boundary, so later sections copy a tested pattern rather than inventing one.

**Files:**
- Modify: `crates/carrick-kernel/src/arena.rs` (add `PermitSection::try_claim_slot` used by tests and, later, by trap.rs if it wants to converge; trap.rs keeps its own CAS today)
- Test: in-module tests

**Interfaces:**
- Produces: `impl PermitSection { pub fn try_claim_slot(&self, pid: HostPid, generation: ProcessGeneration) -> Result<usize, ArenaError> }` — claims the first FREE slot with `compare_exchange(FREE_WORD, packed(STATE_ACQUIRING,...))`; returns `ArenaError::Exhausted { section: "permits", capacity: PERMIT_MAX_SLOTS }` when full. Packing identical to `atomic_permit_slot::pack` (state 2b @62 / generation 30b @32 / pid 32b).

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn permit_section_exhaustion_is_loud() {
    let arena = KernelArena::create().unwrap();
    let l = arena.layout();
    for i in 0..PERMIT_MAX_SLOTS {
        let claimed = l.permits.try_claim_slot(
            crate::domains::HostPid::new(100 + i as u32),
            arena.allocate_generation(),
        );
        assert!(claimed.is_ok(), "slot {i} should claim");
    }
    let full = l
        .permits
        .try_claim_slot(crate::domains::HostPid::new(9999), arena.allocate_generation());
    match full {
        Err(ArenaError::Exhausted { section, capacity }) => {
            assert_eq!(section, "permits");
            assert_eq!(capacity, PERMIT_MAX_SLOTS);
        }
        other => panic!("expected loud exhaustion, got {other:?}"),
    }
}
```

- [ ] **Step 2: Run to verify failure** — method missing → compile error.
- [ ] **Step 3: Implement `try_claim_slot`**

```rust
impl PermitSection {
    const STATE_ACQUIRING: u64 = 1 << 62;

    fn pack(pid: crate::domains::HostPid, generation: crate::domains::ProcessGeneration) -> u64 {
        Self::STATE_ACQUIRING
            | ((u64::from(generation.raw()) & ((1 << 30) - 1)) << 32)
            | u64::from(pid.raw())
    }

    pub fn try_claim_slot(
        &self,
        pid: crate::domains::HostPid,
        generation: crate::domains::ProcessGeneration,
    ) -> Result<usize, ArenaError> {
        let packed = Self::pack(pid, generation);
        for (i, slot) in self.slots.iter().enumerate() {
            if slot
                .compare_exchange(0, packed, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(i);
            }
        }
        Err(ArenaError::Exhausted {
            section: "permits",
            capacity: PERMIT_MAX_SLOTS,
        })
    }
}
```
(`SeqCst` on the success ordering matches the trap.rs occupancy discipline — see the store-buffering comment at trap.rs:1127-1134.)

- [ ] **Step 4: Run** — `cargo test -p carrick-kernel --lib` — all pass.
- [ ] **Step 5: Commit**

```bash
git add crates/carrick-kernel
git commit -m "feat(kernel): loud-exhaustion claim API on the permit section"
```

---

### Task 8: Gate run + docs breadcrumb

- [ ] **Step 1: Full local gate for touched crates**

Run: `just ci` (memory: CI runs fmt→clippy→build→test sequentially and a red clippy masks later stages — `just ci` locally is the honest equivalent), then `just conformance smoke`.
Expected: green, exit 0.

- [ ] **Step 2: Record in the spec's migration checklist**

Append to `docs/2026-07-07-conformance-bless-diary.md` (or the current diary) a short dated entry: arena foundation landed (steps 1–2 of the kernel-authority migration), permit table relocated, no admission behavior change, gates run and green. Reference commits.

- [ ] **Step 3: Commit**

```bash
git add docs/
git commit -m "docs(kernel): record arena foundation landing (migration steps 1-2)"
```

---

## Self-Review Notes

- Spec coverage: step 1 (crate: layout ✓ Task 5, claim-sentinel ✓ Task 7 pattern + Task 5, robust locks ✓ Tasks 3–4, generations ✓ Tasks 1/5, kill-9 repair ✓ Task 4); step 2 (permit relocation ✓ Task 6, reaper unchanged ✓ Task 6 Step 4, flock fallback untouched — retiring it is deliberately deferred to the flag owner).
- The `WaitWake` production backends are intentionally NOT wired here (no arena consumer parks on bucket locks yet); first real consumer is the futex-requeue move (spec step 6, separate plan).
- Type consistency: `HostPid`/`ProcessGeneration` used in Tasks 3/4/7 are Task 1's; `PermitSection` constants in Task 6's assertions are Task 5's.
