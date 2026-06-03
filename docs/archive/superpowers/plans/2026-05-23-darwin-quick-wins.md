# Darwin Quick-Wins Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace three private/heavy macOS mechanisms in carrick with stable, SDK-supported, lighter ones — without changing guest-visible behavior except to close a correctness race.

**Architecture:** Three independent changes shipped as separate commits, safest first: (1) swap the thread registry's `std::sync::Mutex` for the already-used `parking_lot::Mutex`; (2) reimplement `src/ulock.rs`'s two functions on the public macOS 14.4 `os_sync_wait_on_address` API instead of private `__ulock` syscalls 515/516; (3) replace the per-arm `setitimer` OS-thread with `EVFILT_TIMER` events on the existing signal-pump kqueue, and audit `timerfd` for correctness.

**Tech Stack:** Rust, macOS 26 SDK (`<os/os_sync_wait_on_address.h>`, `EVFILT_TIMER`), `parking_lot`, Apple Hypervisor.framework, LTP-in-Docker conformance oracle.

**Spec:** `docs/superpowers/specs/2026-05-23-darwin-quick-wins-design.md`

**Cross-cutting build/test notes (apply to every task):**
- Build with `./scripts/build-signed.sh` (HVF entitlement; an unsigned `cargo build` hits `HV_DENIED` at runtime). For pure compile/lint checks `cargo build` / `cargo test --lib` are fine.
- Crate lints (`Cargo.toml`): `unwrap_used = "deny"`, `expect_used = "deny"`, `panic = "deny"`. Production code MUST NOT add `.unwrap()`/`.expect()`/`panic!`. (Test code under `#[cfg(test)]` is exempt — existing tests use `.expect(...)`.)
- LTP conformance: follow the `ltp-conformance` skill. Build `--release` and run probes FIRST or it silently skips. The differential oracle is Docker (Linux) vs carrick — verdicts must MATCH.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `src/thread.rs` | Thread registry + futex table | Modify: registry locks → `parking_lot` |
| `src/ulock.rs` | Cross-process futex wait/wake | Rewrite `imp` module on `os_sync_*` |
| `src/darwin_kqueue.rs` | kqueue/kevent wrappers | Add: `Kevent::timer`, `timer_ident`, `apply_changes` |
| `src/itimer.rs` (NEW) | Process-global interval-timer table (which↔ident↔signum, re-arm intervals) | Create |
| `src/lib.rs` | Module list | Add: `pub(crate) mod itimer;` |
| `src/host_signal.rs` | Process-global signal hub | Add: `pump_kqueue()` getter |
| `src/dispatch/time.rs` | `setitimer`/`getitimer`/`timerfd` | Modify `setitimer`; delete `spawn_itimer_thread`; audit timerfd |
| `src/dispatch/proc.rs` | Per-process state | Remove `itimer_gen` field + doc |
| `src/vcpu_kick.rs` | Signal pump loop | Add `EVFILT_TIMER` dispatch branch |

---

## Task 1: parking_lot thread registry

**Files:**
- Modify: `src/thread.rs:7` (imports), `:27` (`inner` field), `:35-36` (`CURRENT_REGISTRY` static), `:41` + `:48-52` (helper poison handling), `:67-68` (`ThreadRegistry::new`), and the 8 lock sites at `:76-78, 92-94, 102-105, 116, 124-126, 133-136, 145-149, 162-166`.
- Test: `src/thread.rs` (existing `#[cfg(test)]` module + `cargo test --lib`).

- [ ] **Step 1: Change the imports**

In `src/thread.rs:7`, the line is:
```rust
use std::sync::{Arc, Mutex};
```
Change to (drop `Mutex`, keep `Arc`):
```rust
use std::sync::Arc;
```
`parking_lot::Mutex as ParkingMutex` is already imported at `:9` and will be used for the registry too.

- [ ] **Step 2: Change the `inner` field type**

In `src/thread.rs:25-28`, change:
```rust
pub struct ThreadRegistry {
    next_tid: AtomicI32,
    inner: Mutex<HashMap<ThreadId, ThreadEntry>>,
}
```
to:
```rust
pub struct ThreadRegistry {
    next_tid: AtomicI32,
    inner: ParkingMutex<HashMap<ThreadId, ThreadEntry>>,
}
```

- [ ] **Step 3: Change the `CURRENT_REGISTRY` static**

In `src/thread.rs:35-36`, change:
```rust
static CURRENT_REGISTRY: std::sync::Mutex<Option<std::sync::Arc<ThreadRegistry>>> =
    std::sync::Mutex::new(None);
```
to (`parking_lot::Mutex::new` is `const fn`, so a plain `static` still works):
```rust
static CURRENT_REGISTRY: ParkingMutex<Option<Arc<ThreadRegistry>>> =
    ParkingMutex::new(None);
```

- [ ] **Step 4: Update the two `CURRENT_REGISTRY` helpers (remove poison handling)**

In `src/thread.rs:40-44`, change:
```rust
pub fn set_current_registry(registry: std::sync::Arc<ThreadRegistry>) {
    if let Ok(mut g) = CURRENT_REGISTRY.lock() {
        *g = Some(registry);
    }
}
```
to:
```rust
pub fn set_current_registry(registry: Arc<ThreadRegistry>) {
    *CURRENT_REGISTRY.lock() = Some(registry);
}
```

In `src/thread.rs:47-53`, change:
```rust
pub fn current_thread_states() -> Vec<(ThreadId, char)> {
    CURRENT_REGISTRY
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|r| r.thread_states()))
        .unwrap_or_default()
}
```
to:
```rust
pub fn current_thread_states() -> Vec<(ThreadId, char)> {
    CURRENT_REGISTRY
        .lock()
        .as_ref()
        .map(|r| r.thread_states())
        .unwrap_or_default()
}
```

- [ ] **Step 5: Update `ThreadRegistry::new`**

In `src/thread.rs:65-68`, change `inner: Mutex::new(map),` to:
```rust
            inner: ParkingMutex::new(map),
```

- [ ] **Step 6: Remove the 8 `.expect(...)` poison-handling sites**

In `src/thread.rs`, every method body has the pattern:
```rust
        // INVARIANT: ... poisoned ...
        #[allow(clippy::expect_used)]
        self.inner
            .lock()
            .expect("thread registry mutex poisoned")
```
For ALL 8 occurrences (in `register_child`, `clear_child_tid`, `set_clear_child_tid`, `exit`, `live_count`, `is_live`, `record_thread_port`, `thread_states`), remove the `#[allow(clippy::expect_used)]` attribute and the preceding `// INVARIANT:` poison comment, and change `.lock().expect("thread registry mutex poisoned")` to just `.lock()`. parking_lot's `lock()` returns the guard directly (no `Result`).

Example — `register_child` (`:71-87`) becomes:
```rust
    pub fn register_child(&self, clear_child_tid: u64) -> ThreadId {
        let tid = self.next_tid.fetch_add(1, Ordering::Relaxed);
        self.inner.lock().insert(
            tid,
            ThreadEntry {
                clear_child_tid,
                mach_port: 0,
            },
        );
        tid
    }
```
Apply the same mechanical removal to the other 7 methods. The `exit` method keeps its `let mut map = self.inner.lock();` (just without `.expect`).

- [ ] **Step 7: Build and lint**

Run: `cargo build 2>&1 | tail -20`
Expected: compiles clean. No `expect_used`/`unwrap_used` lint errors from `thread.rs`. If the compiler flags an unused `Mutex` import elsewhere, that is unexpected — `Mutex` was only used by the registry; recheck Step 1.

- [ ] **Step 8: Run thread + futex tests**

Run: `cargo test --lib thread 2>&1 | tail -20`
Expected: PASS (existing registry/futex tests green; the API is unchanged).

- [ ] **Step 9: Commit**

```bash
git add src/thread.rs
git commit -m "refactor(thread): use parking_lot for the thread registry (no poisoning)

ThreadRegistry::inner and CURRENT_REGISTRY move from std::sync::Mutex to
parking_lot::Mutex (already used for the futex shards in this file),
removing 8 .expect(\"...poisoned\") panic vectors and their clippy allows.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: os_sync futex (replace `__ulock`)

**Files:**
- Rewrite: `src/ulock.rs` (the `#[cfg(macos+aarch64)] mod imp` block, `:24-72`, and the module doc `:1-22`).
- Test: `src/ulock.rs` (`#[cfg(test)]` module, new).

- [ ] **Step 1: Write the failing test**

Append to `src/ulock.rs` a test module. The `os_sync` SHARED path works in-process too, so a wait on a private word that never changes, with a short timeout, deterministically returns `-ETIMEDOUT`; a wait whose value already differs returns `>= 0` immediately.

```rust
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod tests {
    use super::{wait, wake};
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn wait_times_out_with_etimedout() {
        let word = AtomicU32::new(7);
        let addr = &word as *const AtomicU32 as usize;
        // Value matches (7), so we block; 10ms timeout -> -ETIMEDOUT.
        let rc = wait(addr, 7, 10_000);
        assert_eq!(rc, -(libc::ETIMEDOUT as i64), "expected -ETIMEDOUT, got {rc}");
    }

    #[test]
    fn wait_returns_nonneg_on_value_mismatch() {
        let word = AtomicU32::new(1);
        let addr = &word as *const AtomicU32 as usize;
        // Expected 999 != actual 1 -> returns immediately, >= 0.
        let rc = wait(addr, 999, 10_000);
        assert!(rc >= 0, "value mismatch should not error, got {rc}");
    }

    #[test]
    fn wake_with_no_waiters_is_nonfatal() {
        let word = AtomicU32::new(0);
        let addr = &word as *const AtomicU32 as usize;
        // No waiter parked: os_sync returns -1/ENOENT; wrapper maps to -errno.
        let rc = wake(addr, true);
        assert!(rc < 0, "wake with no waiters should report an error, got {rc}");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib ulock::tests 2>&1 | tail -20`
Expected: FAIL — the current `__ulock` impl returns `__ulock`'s own error encoding (`ULF_NO_ERRNO` gives `-ETIMEDOUT` already for the timeout case, so that test may pass, but `wait_returns_nonneg_on_value_mismatch` and the wake test pin the new contract). Treat any compile error or assertion mismatch as the expected failing state before the rewrite.

- [ ] **Step 3: Rewrite the module doc comment**

Replace `src/ulock.rs:1-22` with:
```rust
//! Cross-process futex via the public macOS `os_sync_wait_on_address` API.
//!
//! macOS has no `futex(2)`. For a guest FUTEX on private/anon memory carrick
//! parks in-process (the parking-lot `FutexTable`), which is enough for a
//! single multi-threaded guest (e.g. Go's runtime). But a FUTEX on a genuine
//! `MAP_SHARED` file mapping is an inter-PROCESS rendezvous — LTP's
//! `tst_checkpoint` (used pervasively for parent↔child sync) does
//! `FUTEX_WAIT`/`FUTEX_WAKE` on a futex word in a shared tmpfs page. carrick
//! forks each guest process as a real macOS process, and a guest `MAP_SHARED`
//! file mapping is backed by a host `MAP_SHARED` of the real file, so the same
//! PHYSICAL page is visible across processes.
//!
//! `os_sync_wait_on_address` with `OS_SYNC_WAIT_ON_ADDRESS_SHARED` (and the
//! matching `OS_SYNC_WAKE_BY_ADDRESS_SHARED` on wake) keys on the physical page
//! rather than the per-task virtual address, so a wait in one process and a
//! wake in another rendezvous correctly — the stable, public (macOS 14.4+,
//! `<os/os_sync_wait_on_address.h>`) equivalent of the private
//! `UL_COMPARE_AND_WAIT_SHARED` `__ulock` op carrick used previously.
//!
//! Wrappers are thin and map to a `-errno`-on-error contract: `wait` returns
//! `>= 0` when woken or the value already differed (the caller re-checks the
//! word), or `-errno` (`-ETIMEDOUT`, `-EINTR`, …). `wake` returns `>= 0` on
//! success or `-errno` (e.g. `-ENOENT` when there was no waiter).
```

- [ ] **Step 4: Rewrite the `imp` module**

Replace `src/ulock.rs:24-72` (the `#[cfg(all(target_os = "macos", target_arch = "aarch64"))] mod imp { ... }` block) with:
```rust
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod imp {
    use std::ffi::c_void;

    /// Cross-process, physical-page-keyed synchronization (the SHARED flag).
    /// Value confirmed from `<os/os_sync_wait_on_address.h>`.
    const OS_SYNC_WAIT_ON_ADDRESS_SHARED: u32 = 0x0000_0001;
    const OS_SYNC_WAKE_BY_ADDRESS_SHARED: u32 = 0x0000_0001;
    /// `os_clockid_t` for the deadline clock (`<os/clock.h>`,
    /// `OS_CLOCK_MACH_ABSOLUTE_TIME = 32`).
    const OS_CLOCK_MACH_ABSOLUTE_TIME: u32 = 32;
    /// 32-bit futex word.
    const FUTEX_WORD_SIZE: libc::size_t = 4;

    #[link(name = "System")]
    extern "C" {
        fn os_sync_wait_on_address(
            addr: *mut c_void,
            value: u64,
            size: libc::size_t,
            flags: u32,
        ) -> libc::c_int;

        fn os_sync_wait_on_address_with_timeout(
            addr: *mut c_void,
            value: u64,
            size: libc::size_t,
            flags: u32,
            clockid: u32,
            timeout_ns: u64,
        ) -> libc::c_int;

        fn os_sync_wake_by_address_any(
            addr: *mut c_void,
            size: libc::size_t,
            flags: u32,
        ) -> libc::c_int;

        fn os_sync_wake_by_address_all(
            addr: *mut c_void,
            size: libc::size_t,
            flags: u32,
        ) -> libc::c_int;
    }

    fn neg_errno() -> i64 {
        let e = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EINVAL);
        -(e as i64)
    }

    /// Wait while `*host_addr == value`. `timeout_us` of 0 waits indefinitely.
    /// Returns `>= 0` when woken (or the value already differed — the caller
    /// re-checks), or `-errno` (e.g. `-ETIMEDOUT`, `-EINTR`).
    pub fn wait(host_addr: usize, value: u32, timeout_us: u32) -> i64 {
        let flags = OS_SYNC_WAIT_ON_ADDRESS_SHARED;
        // SAFETY: a plain libSystem call; `host_addr` points into a live host
        // MAP_SHARED region (the caller obtained it from the memory backend)
        // and is 4-byte aligned; the kernel only reads 4 bytes for the compare.
        let rc = unsafe {
            if timeout_us == 0 {
                os_sync_wait_on_address(
                    host_addr as *mut c_void,
                    value as u64,
                    FUTEX_WORD_SIZE,
                    flags,
                )
            } else {
                os_sync_wait_on_address_with_timeout(
                    host_addr as *mut c_void,
                    value as u64,
                    FUTEX_WORD_SIZE,
                    flags,
                    OS_CLOCK_MACH_ABSOLUTE_TIME,
                    (timeout_us as u64).saturating_mul(1000),
                )
            }
        };
        if rc < 0 {
            neg_errno()
        } else {
            rc as i64
        }
    }

    /// Wake waiters on `host_addr`. Returns `>= 0` on success, `-errno`
    /// (e.g. `-ENOENT`) when there was no waiter.
    pub fn wake(host_addr: usize, all: bool) -> i64 {
        let flags = OS_SYNC_WAKE_BY_ADDRESS_SHARED;
        // SAFETY: plain libSystem call against a live shared host address.
        let rc = unsafe {
            if all {
                os_sync_wake_by_address_all(host_addr as *mut c_void, FUTEX_WORD_SIZE, flags)
            } else {
                os_sync_wake_by_address_any(host_addr as *mut c_void, FUTEX_WORD_SIZE, flags)
            }
        };
        if rc < 0 {
            neg_errno()
        } else {
            rc as i64
        }
    }
}
```
Leave the `#[cfg(not(...))] mod imp` stub (`:74-82`) and `pub use imp::{wait, wake};` (`:84`) unchanged.

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test --lib ulock::tests 2>&1 | tail -20`
Expected: PASS (all three tests).

- [ ] **Step 6: Build + lint**

Run: `cargo build 2>&1 | tail -20`
Expected: clean compile, no lint errors (note `neg_errno` uses `unwrap_or`, not `unwrap`).

- [ ] **Step 7: Verify no `__ulock` references remain**

Run: `grep -n "515\|516\|__ulock\|ULF_\|UL_COMPARE" src/ulock.rs`
Expected: no output.

- [ ] **Step 8: Cross-process conformance (LTP)**

Per the `ltp-conformance` skill: build `--release`, run probes first, then run the `tst_checkpoint`-based futex tests in carrick and in Docker. Expected: verdicts MATCH (parent↔child wait/wake rendezvous over a shared mapping still works). Record the comparison.

- [ ] **Step 9: Commit**

```bash
git add src/ulock.rs
git commit -m "feat(ulock): cross-process futex via public os_sync_wait_on_address

Replace the private __ulock syscalls (515/516, UL_COMPARE_AND_WAIT_SHARED)
with the stable macOS 14.4 os_sync_wait_on_address API and its SHARED flags.
Public wait/wake interface unchanged; errors mapped to -errno.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: kqueue timer helpers (`darwin_kqueue.rs`)

**Files:**
- Modify: `src/darwin_kqueue.rs` — add `Kevent::timer`, `Kevent::timer_ident`, and a free `apply_changes`.
- Test: `src/darwin_kqueue.rs` (`#[cfg(test)]` module, new test).

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `src/darwin_kqueue.rs` (after `user_trigger_wakes_registered_kqueue`):
```rust
    #[test]
    fn oneshot_timer_fires_and_reports_ident() {
        let kqueue = Kqueue::new_internal().expect("kqueue should open");
        let ident = 0xC1_0000usize;
        // 1ms one-shot timer.
        kqueue
            .apply(&[Kevent::timer(ident, libc::EV_ADD | libc::EV_ONESHOT, 1_000_000)])
            .expect("register timer");

        let timeout = libc::timespec { tv_sec: 1, tv_nsec: 0 };
        let mut out = [Kevent::empty()];
        let n = kqueue.wait(&[], &mut out, Some(&timeout)).expect("wait timer");
        assert_eq!(n, 1);
        assert_eq!(out[0].timer_ident(), Some(ident));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --lib darwin_kqueue::tests::oneshot_timer_fires_and_reports_ident 2>&1 | tail -20`
Expected: FAIL to compile — `Kevent::timer` and `timer_ident` do not exist yet.

- [ ] **Step 3: Add the `timer` constructor**

In `src/darwin_kqueue.rs`, after the `user` constructor (`:105-107`), add:
```rust
    /// One-shot or periodic timer. `interval_ns` is the period in nanoseconds
    /// (`NOTE_NSECONDS`); pass `EV_ADD | EV_ONESHOT` for a single fire or
    /// `EV_ADD` for a repeating timer, and `EV_DELETE` (with `interval_ns` 0)
    /// to disarm. The `ident` lives in the EVFILT_TIMER namespace, distinct
    /// from EVFILT_READ fds and EVFILT_USER idents.
    pub(crate) fn timer(ident: usize, flags: u16, interval_ns: i64) -> Self {
        let mut ev = Self::new(ident, libc::EVFILT_TIMER, flags, libc::NOTE_NSECONDS);
        ev.0.data = interval_ns as isize;
        ev
    }
```
Note: `Self::new` already takes `fflags: u32`; `libc::NOTE_NSECONDS` is `u32`. `libc::kevent.data` is `isize` on macOS (matches `empty()`'s `data: 0`).

- [ ] **Step 4: Add the `timer_ident` accessor**

In `src/darwin_kqueue.rs`, after `is_read` (`:128-130`), add:
```rust
    /// If this event is an EVFILT_TIMER firing, its timer ident; else `None`.
    pub(crate) fn timer_ident(self) -> Option<usize> {
        if self.0.filter == libc::EVFILT_TIMER {
            Some(self.0.ident)
        } else {
            None
        }
    }
```

- [ ] **Step 5: Add the `apply_changes` free function**

In `src/darwin_kqueue.rs`, after the existing `trigger_user` free function (`:138-155`), add a sibling that registers arbitrary changes on a raw kq fd (used by `setitimer`, which runs off-pump and only has the published fd):
```rust
/// Apply kevent changes to a kqueue identified by raw fd (no RAII owner).
/// Used to register/disarm timers on the signal pump's published kqueue from
/// a different thread, mirroring `trigger_user`.
pub(crate) fn apply_changes(kq: RawFd, changes: &[Kevent]) -> Result<(), i32> {
    let rc = unsafe {
        libc::kevent(
            kq,
            changes.as_ptr().cast::<libc::kevent>(),
            changes.len() as libc::c_int,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    };
    if rc < 0 {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    } else {
        Ok(())
    }
}
```

- [ ] **Step 6: Run to verify it passes**

Run: `cargo test --lib darwin_kqueue::tests::oneshot_timer_fires_and_reports_ident 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/darwin_kqueue.rs
git commit -m "feat(kqueue): add EVFILT_TIMER helpers (timer, timer_ident, apply_changes)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: process-global itimer table (`src/itimer.rs`)

**Files:**
- Create: `src/itimer.rs`
- Modify: `src/lib.rs:34` (add module)
- Test: `src/itimer.rs` (`#[cfg(test)]`)

- [ ] **Step 1: Write the failing test (inside the new file in Step 2)**

The test is included in the file content below. After creating the file, Step 4 runs it.

- [ ] **Step 2: Create `src/itimer.rs`**

```rust
//! Process-global interval-timer (`setitimer`) state, shared between the
//! `setitimer` syscall handler (writer) and the signal pump (reader).
//!
//! Delivery moved off a per-arm OS thread onto `EVFILT_TIMER` events on the
//! signal pump's kqueue. The pump has no access to per-process `ProcState`, so
//! the re-arm interval for each `which` lives here as a process-global atomic.
//! Each `which` (REAL/VIRTUAL/PROF) owns one stable EVFILT_TIMER ident, so
//! arming/disarming is a single EV_ADD/EV_DELETE that supersedes any prior arm
//! (no generation counter needed).

use std::sync::atomic::{AtomicU64, Ordering};

/// Base of the EVFILT_TIMER ident range for itimers. Idents are
/// `BASE + which` for `which` in 0..3. The EVFILT_TIMER ident namespace is
/// distinct from EVFILT_READ (fds) and EVFILT_USER (ident 0) on the pump kq,
/// so this only needs to be internally distinct across the 3 timers.
pub const TIMER_IDENT_BASE: usize = 0x00C1_0000;

/// Number of `setitimer` `which` slots: ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF.
const WHICH_COUNT: usize = 3;

/// Re-arm interval in nanoseconds per `which`; 0 means "one-shot, no repeat".
/// Read by the pump when an EV_ONESHOT timer fires to decide whether to
/// re-register a periodic timer.
static INTERVAL_NS: [AtomicU64; WHICH_COUNT] =
    [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];

/// EVFILT_TIMER ident for a `which`.
pub fn ident_for(which: usize) -> usize {
    TIMER_IDENT_BASE + which
}

/// The `which` an EVFILT_TIMER ident belongs to, or `None` if out of range.
pub fn which_for_ident(ident: usize) -> Option<usize> {
    ident
        .checked_sub(TIMER_IDENT_BASE)
        .filter(|&which| which < WHICH_COUNT)
}

/// Linux signal number delivered when `which`'s timer expires.
pub fn signum_for(which: usize) -> i32 {
    match which {
        1 => crate::linux_abi::LINUX_SIGVTALRM, // ITIMER_VIRTUAL
        2 => crate::linux_abi::LINUX_SIGPROF,   // ITIMER_PROF
        _ => crate::linux_abi::LINUX_SIGALRM,   // ITIMER_REAL
    }
}

/// Record the re-arm interval for `which` (0 = no repeat). Called by
/// `setitimer` on arm/disarm. Out-of-range `which` is ignored.
pub fn set_interval_ns(which: usize, ns: u64) {
    if let Some(slot) = INTERVAL_NS.get(which) {
        slot.store(ns, Ordering::SeqCst);
    }
}

/// The re-arm interval for `which` in nanoseconds (0 = no repeat).
pub fn interval_ns(which: usize) -> u64 {
    INTERVAL_NS.get(which).map_or(0, |slot| slot.load(Ordering::SeqCst))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ident_round_trips_for_each_which() {
        for which in 0..WHICH_COUNT {
            assert_eq!(which_for_ident(ident_for(which)), Some(which));
        }
    }

    #[test]
    fn out_of_range_ident_is_none() {
        assert_eq!(which_for_ident(TIMER_IDENT_BASE - 1), None);
        assert_eq!(which_for_ident(TIMER_IDENT_BASE + WHICH_COUNT), None);
        assert_eq!(which_for_ident(0), None);
    }

    #[test]
    fn signum_mapping() {
        assert_eq!(signum_for(0), crate::linux_abi::LINUX_SIGALRM);
        assert_eq!(signum_for(1), crate::linux_abi::LINUX_SIGVTALRM);
        assert_eq!(signum_for(2), crate::linux_abi::LINUX_SIGPROF);
    }
}
```

- [ ] **Step 3: Register the module**

In `src/lib.rs`, after line `:21` (`pub mod interactive_supervisor;`) — keeping alphabetical-ish order — add:
```rust
pub(crate) mod itimer;
```

- [ ] **Step 4: Run the tests**

Run: `cargo test --lib itimer::tests 2>&1 | tail -20`
Expected: PASS (3 tests). If `LINUX_SIGVTALRM`/`LINUX_SIGPROF`/`LINUX_SIGALRM` are not found, confirm their path in `src/linux_abi.rs` (they are referenced today in `src/dispatch/time.rs:315-317` as `crate::linux_abi::LINUX_SIG*`).

- [ ] **Step 5: Commit**

```bash
git add src/itimer.rs src/lib.rs
git commit -m "feat(itimer): process-global itimer table (which/ident/signum, re-arm intervals)

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: expose the pump kqueue fd (`host_signal.rs`)

**Files:**
- Modify: `src/host_signal.rs` (add a getter near `set_pump_kqueue`, `:192`).
- Test: covered by Task 6's integration (no standalone unit test — it's a trivial atomic load).

- [ ] **Step 1: Add the getter**

In `src/host_signal.rs`, immediately after `set_pump_kqueue` (`:192-194`), add:
```rust
/// The signal pump's kqueue fd, or `-1` if the pump has not registered yet.
/// `setitimer` uses this to arm `EVFILT_TIMER` events on the pump's kqueue.
pub fn pump_kqueue() -> i32 {
    PUMP_KQUEUE.load(Ordering::SeqCst)
}
```

- [ ] **Step 2: Build**

Run: `cargo build 2>&1 | tail -20`
Expected: clean compile.

- [ ] **Step 3: Commit**

```bash
git add src/host_signal.rs
git commit -m "feat(host_signal): expose pump_kqueue() fd getter for itimer arming

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: setitimer → EVFILT_TIMER; pump dispatch; remove the timer thread

**Files:**
- Modify: `src/dispatch/time.rs` — `setitimer` (`:257-337`); delete `spawn_itimer_thread` (`:612-645`).
- Modify: `src/dispatch/proc.rs` — remove `itimer_gen` field (`:42`), its init (`:153-157`), and update the doc comment (`:31-42`).
- Modify: `src/vcpu_kick.rs` — add an `EVFILT_TIMER` branch to the pump loop (`:243-248`).
- Test: LTP conformance (setitimer/getitimer) + `cargo build`.

- [ ] **Step 1: Add the EVFILT_TIMER branch to the signal pump loop**

In `src/vcpu_kick.rs`, the event loop currently is (`:243-248`):
```rust
                for event in out.iter().take(n) {
                    if event.is_read() {
                        crate::host_signal::drain_pump_pipe();
                        continue;
                    }
                }
```
Replace with:
```rust
                for event in out.iter().take(n) {
                    if event.is_read() {
                        crate::host_signal::drain_pump_pipe();
                        continue;
                    }
                    if let Some(ident) = event.timer_ident() {
                        if let Some(which) = crate::itimer::which_for_ident(ident) {
                            let signum = crate::itimer::signum_for(which);
                            crate::probes::itimer_fire(signum, 0);
                            crate::host_signal::publish_process_signal(signum);
                            // EV_ONESHOT consumed the registration. If this timer
                            // has a repeat interval, re-arm it as periodic on our
                            // own kqueue (EV_ADD, no EV_ONESHOT). interval 0 = done.
                            let interval = crate::itimer::interval_ns(which);
                            if interval > 0 {
                                let _ = kq.apply(&[crate::darwin_kqueue::Kevent::timer(
                                    ident,
                                    libc::EV_ADD,
                                    interval as i64,
                                )]);
                            }
                        }
                        continue;
                    }
                }
```
(`kq` is the pump's `Kqueue`, in scope here. `publish_process_signal` sets process-pending + wakes; the existing `has_process_pending()` block below then kicks all vCPUs/futex waiters, so no extra work is needed.)

- [ ] **Step 2: Rewrite `setitimer`'s arm/disarm to use kqueue**

In `src/dispatch/time.rs`, replace the body from `let idx = which as usize;` (`:285`) through the end of the `if let Some(v) = new_value { ... }` block (`:335`) with the version below. It drops the `itimer_gen` generation dance and `spawn_itimer_thread`, storing the interval in the global `itimer` table and arming an `EV_ONESHOT` timer on the pump kqueue.

Replace `:285-335`:
```rust
        let idx = which as usize;
        // Write the old value before applying the new one (the kernel does the
        // same, so a read-modify-write sees the prior timer).
        if old_address != 0 {
            let prev = itimerval_from_state(self.proc.lock().itimers[idx]);
            let outcome = write_kernel_struct(memory, old_address, &prev);
            if !matches!(outcome, DispatchOutcome::Returned { .. }) {
                return Ok(outcome);
            }
        }
        if let Some(v) = new_value {
            let value = duration_from_timeval(v.it_value);
            let interval = duration_from_timeval(v.it_interval);
            // A zero it_value disarms the timer (matching the kernel).
            self.proc.lock().itimers[idx] = if value.is_zero() {
                None
            } else {
                Some(crate::dispatch::proc::ItimerState {
                    set_at: std::time::Instant::now(),
                    value,
                    interval,
                })
            };

            let ident = crate::itimer::ident_for(idx);
            let kq = crate::host_signal::pump_kqueue();
            if value.is_zero() {
                // Disarm: clear the repeat interval and delete the kevent.
                crate::itimer::set_interval_ns(idx, 0);
                if kq >= 0 {
                    let _ = crate::darwin_kqueue::apply_changes(
                        kq,
                        &[crate::darwin_kqueue::Kevent::timer(ident, libc::EV_DELETE, 0)],
                    );
                }
            } else {
                // Arm: record the repeat interval (ns; 0 = one-shot), then
                // register a one-shot timer for the initial it_value. The pump
                // re-arms a periodic timer on fire if the interval is non-zero.
                let interval_ns = u64::try_from(interval.as_nanos()).unwrap_or(u64::MAX);
                crate::itimer::set_interval_ns(idx, interval_ns);
                let value_ns = i64::try_from(value.as_nanos()).unwrap_or(i64::MAX);
                let signum = crate::itimer::signum_for(idx);
                let signal_name = match signum {
                    crate::linux_abi::LINUX_SIGVTALRM => "SIGVTALRM",
                    crate::linux_abi::LINUX_SIGPROF => "SIGPROF",
                    _ => "SIGALRM",
                };
                ctx.reporter
                    .record(crate::compat::CompatEvent::partial_syscall(
                        103,
                        "setitimer",
                        ctx.request.args,
                        format!(
                            "setitimer delivery is emulated with an EVFILT_TIMER on the signal pump kqueue and {signal_name}"
                        ),
                    ));
                if kq >= 0 {
                    let _ = crate::darwin_kqueue::apply_changes(
                        kq,
                        &[crate::darwin_kqueue::Kevent::timer(
                            ident,
                            libc::EV_ADD | libc::EV_ONESHOT,
                            value_ns,
                        )],
                    );
                }
            }
        }
        Ok(DispatchOutcome::Returned { value: 0 })
```
Note: `LINUX_SIGVTALRM`/`LINUX_SIGPROF`/`signum` were previously matched off `which`; `itimer::signum_for(idx)` now produces the same value. The local `signum` binding is only for the `signal_name` label.

- [ ] **Step 3: Delete `spawn_itimer_thread`**

In `src/dispatch/time.rs`, delete the entire `spawn_itimer_thread` function and its doc comment (`:612-645`, from `/// Spawn the per-arm interval-timer thread.` through the closing `}` of the function). Nothing else calls it (it was only called from `setitimer`, now replaced).

- [ ] **Step 4: Remove `itimer_gen` from ProcState**

In `src/dispatch/proc.rs`:
- Delete the field `pub itimer_gen: std::sync::Arc<[std::sync::atomic::AtomicU64; 3]>,` (`:42`).
- In `ProcState::new` (`:144-159`), delete the `itimer_gen: std::sync::Arc::new([ ... ]),` initializer (`:153-157`) and the now-unused `use std::sync::atomic::AtomicU64;` (`:143`) **only if** `AtomicU64` is no longer used elsewhere in `new` (it is not — it was only for `itimer_gen`).
- Update the doc comment on `itimers` (`:31-42`): remove the sentences describing the per-arm timer thread and `itimer_gen` generation counter; replace with: `The matching expiry signal (SIGALRM/SIGVTALRM/SIGPROF) is delivered by an EVFILT_TIMER event on the signal pump's kqueue (see crate::itimer). VIRTUAL/PROF are approximated with a wall-clock timer (carrick has no per-process CPU-time accounting).`

- [ ] **Step 5: Build and fix references**

Run: `cargo build 2>&1 | tail -30`
Expected: clean compile. If the compiler reports `itimer_gen` still referenced, search: `grep -rn "itimer_gen" src/` and remove the stragglers (there should be none outside the three sites above). Confirm no `spawn_itimer_thread` references remain: `grep -rn "spawn_itimer_thread\|carrick-itimer" src/` → no output.

- [ ] **Step 6: Lib tests**

Run: `cargo test --lib 2>&1 | tail -20`
Expected: existing suite green (113+ tests), plus the itimer/kqueue/ulock unit tests from earlier tasks.

- [ ] **Step 7: Signed build for runtime conformance**

Run: `./scripts/build-signed.sh 2>&1 | tail -20`
Expected: builds and signs (HVF entitlement) with no error.

- [ ] **Step 8: setitimer/getitimer LTP conformance**

Per the `ltp-conformance` skill (build `--release`, run probes first), run in carrick and Docker and compare:
- `setitimer01`, `getitimer01`
- a periodic case where `it_value != it_interval` (initial delay differs from repeat period) — verify the FIRST signal lands after `it_value` and SUBSEQUENT signals every `it_interval`.

Expected: verdicts MATCH Docker. Record the comparison. If the periodic re-arm misbehaves, inspect with `CARRICK_TRACE_TRAPS` (USDT under sudo is unreliable per project notes).

- [ ] **Step 9: Commit**

```bash
git add src/dispatch/time.rs src/dispatch/proc.rs src/vcpu_kick.rs
git commit -m "feat(time): deliver setitimer via EVFILT_TIMER on the signal pump kqueue

Replace the per-arm 'carrick-itimer' OS thread (and its itimer_gen generation
counter) with a one-shot EVFILT_TIMER armed on the pump's kqueue; the pump
re-arms a periodic timer on fire when it_interval is set. One stable ident per
which (REAL/VIRTUAL/PROF) makes arm/disarm a single EV_ADD/EV_DELETE, closing
the generation-counter race. getitimer still reports remaining from ItimerState.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: timerfd correctness audit

**Files:**
- Read: `src/dispatch/time.rs` — `timerfd_create`/`timerfd_settime`/`timerfd_gettime` (`:6-94`), and the helpers `refresh_timerfd_locked`, `timerfd_itimerspec`, `itimerspec_durations`, `read_itimerspec`, and `TimerFdState` (grep for them in `src/dispatch/time.rs` and wherever `TimerFdState` is defined).
- Output: a short findings note appended to the spec or a new `docs/` note; a conformance probe only if a gap is found.

- [ ] **Step 1: Locate the timerfd internals**

Run: `grep -n "fn refresh_timerfd_locked\|fn timerfd_itimerspec\|fn itimerspec_durations\|struct TimerFdState\|expirations\|deadline\|fn read_timerfd\|changed" src/dispatch/time.rs`
Read each function. `timerfd` blocks on the `TimerFdState` condvar (`state.changed`) and computes deadlines on demand — there is no thread to replace.

- [ ] **Step 2: Audit against Linux semantics (checklist)**

Verify each, writing down the actual code behavior vs Linux:
- **Expiration count:** on read of an expired periodic timer, the returned `u64` count = number of full intervals elapsed since the deadline, and the deadline advances accordingly (Linux `timerfd_read` semantics). Confirm `refresh_timerfd_locked` computes `1 + elapsed_since_deadline / interval` for a periodic timer and advances `deadline` by that many intervals (not just to "now").
- **One-shot vs periodic:** `interval == 0` ⇒ a single expiration, then the timer disarms (no further reads return non-zero).
- **`TFD_TIMER_ABSTIME` (`LINUX_TIMER_ABSTIME`):** `timerfd_settime` with the abs flag treats `it_value` as an absolute time on the timer's clock; without it, relative to `now`. Confirm `timerfd_settime` (`:62-70`) does `now.saturating_add(value)` only when the flag is absent (it does — verify).
- **`timerfd_gettime`:** returns time remaining (`it_value`) and the configured interval (`it_interval`), refreshed via `refresh_timerfd_locked` (`:90-93` calls it — verify it does not consume expirations as a side effect that would corrupt a subsequent read).

- [ ] **Step 3: Decide — document or fix**

- If all checks pass: append a short "timerfd audited correct on <date>" note (with the specific behaviors verified) to `docs/superpowers/specs/2026-05-23-darwin-quick-wins-design.md` under a new "## timerfd audit findings" heading. No code change.
- If a gap is found: write a minimal LTP-style conformance probe (a small C program run identically in carrick and Docker per the `ltp-conformance` skill) demonstrating the divergence, then fix the helper and re-run to MATCH. Keep the fix minimal and scoped to the gap.

- [ ] **Step 4: timerfd LTP conformance**

Per the `ltp-conformance` skill, run the `timerfd`-family LTP tests in carrick vs Docker. Expected: MATCH. Record the comparison.

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/specs/2026-05-23-darwin-quick-wins-design.md
# plus src/dispatch/time.rs and any probe, IF a fix was needed
git commit -m "docs(timerfd): audit findings (correct as-is) [or: fix <gap> found in audit]

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: final verification

- [ ] **Step 1: Clean signed build**

Run: `./scripts/build-signed.sh 2>&1 | tail -20`
Expected: builds + signs with no error.

- [ ] **Step 2: Full lib test suite**

Run: `cargo test --lib 2>&1 | tail -20`
Expected: all green (existing 113+ plus the new ulock/kqueue/itimer unit tests).

- [ ] **Step 3: Clippy (no-panic lints)**

Run: `cargo clippy --all-targets 2>&1 | tail -30`
Expected: no `unwrap_used`/`expect_used`/`panic` denials in changed production code.

- [ ] **Step 4: No stale references**

Run:
```bash
grep -rn "515\|516\|__ulock" src/ulock.rs
grep -rn "spawn_itimer_thread\|carrick-itimer\|itimer_gen" src/
```
Expected: no output from either.

- [ ] **Step 5: Acceptance criteria (from the spec)**

Confirm each:
- [ ] `src/ulock.rs` uses `os_sync_*`, no 515/516/`__ulock`; futex LTP MATCHes Docker.
- [ ] `src/thread.rs` uses `parking_lot`; zero `.expect("thread registry mutex poisoned")`.
- [ ] `spawn_itimer_thread`/`itimer_gen` gone; `setitimer` arms `EVFILT_TIMER`; periodic works with `it_value != it_interval`; setitimer/getitimer LTP MATCHes Docker.
- [ ] `timerfd` audited (documented correct or fixed); timerfd LTP MATCHes Docker.
- [ ] Signed build clean; lib tests green; new unit tests present.

---

## Notes for the implementer

- **Order matters for safety, not correctness:** Tasks 3–5 are pure additions (new helpers/getter) with no behavior change; Task 6 is the only one that flips `setitimer`'s mechanism and depends on 3, 4, 5. Tasks 1 and 2 are fully independent and can land in any order.
- **The signal pump must be running** for `setitimer` timers to fire (it owns the kqueue). It is spawned for normal `carrick run` workloads; if `pump_kqueue()` returns `-1`, the timer simply does not arm — acceptable degradation, recorded via the `CompatEvent` reporter, never a panic (matches spec error handling).
- **Self-wake is benign:** `publish_process_signal` calls `notify_pump` (NOTE_TRIGGER on the pump's own EVFILT_USER). When the pump itself publishes from the timer branch, that's one extra coalesced wake — harmless.
