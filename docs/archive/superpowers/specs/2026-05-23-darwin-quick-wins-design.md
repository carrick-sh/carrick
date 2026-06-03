# Darwin Quick-Wins — Design Spec

**Date:** 2026-05-23
**Status:** Approved for planning
**Author:** brainstorming session (vetted against on-disk MacOSX26.2 SDK headers)

## Background

A set of audit reports (`reports/`) proposed Darwin/macOS modernizations for carrick.
Each claim was vetted against the actual source on disk **and** the authoritative
macOS 26.2 SDK headers on this host (macOS 26.5, Xcode 26.3). Many report claims were
wrong (mis-versioned APIs, wrong constants, a flagship "copyfile bug" that was invalid).

This spec covers **only the three items that vetted as both accurate and low-risk**, to
ship as a bundle of independent changes. The deeper/risier items the reports raised
(4 KB IPA granule, `SCM_RIGHTS`, `mach_vm_copy` fork, `clonefileat`, QoS propagation)
are explicitly **out of scope** and will each get their own spec.

## Goals

- Replace private, undocumented mechanisms with stable, SDK-supported ones.
- Reduce thread/CPU footprint where it is safe to do so.
- No guest-visible behavior change except where it closes a correctness gap.
- Each item independently revertable.

## Non-Goals

- 4 KB IPA granule / `hv_vm_config_set_ipa_granule` (deep change; separate spec).
- `SCM_RIGHTS` ancillary-data translation (separate spec).
- `mach_vm_copy`/`mach_vm_remap` CoW fork (unproven; separate spec).
- `clonefileat`, QoS propagation, `fs_snapshot`, `fileport`, adaptive-spin locks.
- Lowering support below macOS 14.4 (we are targeting the latest macOS).

## Baseline assumption

Minimum supported macOS is raised to **14.4** (`os_sync_wait_on_address` availability).
This is implied by targeting macOS 26 and is required by Item 1.

---

## Item 1 — Stable `os_sync` futex (replaces `__ulock` in `src/ulock.rs`)

### Current state
`src/ulock.rs` implements cross-process (physical-page-keyed) futex wait/wake for guest
`FUTEX` on `MAP_SHARED` mappings, using raw `libc::syscall` with private, undocumented
syscall numbers `515` (`__ulock_wait`) and `516` (`__ulock_wake`) and op
`UL_COMPARE_AND_WAIT_SHARED` (`3`) | `ULF_NO_ERRNO`. Used by LTP `tst_checkpoint`
parent↔child rendezvous and any genuine shared-memory futex.

### Change
Reimplement the `imp` module's two public functions using the stable, public
macOS 14.4+ API from `<os/os_sync_wait_on_address.h>`, linked from `libSystem` as
`extern "C"`:

- `os_sync_wait_on_address_with_timeout(addr, value, size, flags, clockid, timeout_ns)`
- `os_sync_wake_by_address_all(addr, size, flags)` and
  `os_sync_wake_by_address_any(addr, size, flags)`

### Public interface (UNCHANGED — no call sites change)
```rust
pub fn wait(host_addr: usize, value: u32, timeout_us: u32) -> i64;
pub fn wake(host_addr: usize, all: bool) -> i64;
```

### Mapping rules (the correctness contract)
- **Flags:** `OS_SYNC_WAIT_ON_ADDRESS_SHARED` (wait) / `OS_SYNC_WAKE_BY_ADDRESS_SHARED`
  (wake). SHARED is mandatory: it keys on the physical page (cross-process), the exact
  equivalent of `UL_COMPARE_AND_WAIT_SHARED`. (Confirmed present in SDK header.)
- **size:** `4` (32-bit futex word).
- **clockid:** `OS_CLOCK_MACH_ABSOLUTE_TIME`.
- **timeout:** `timeout_us == 0` ⇒ indefinite. For an indefinite wait, call the
  no-timeout `os_sync_wait_on_address(addr, value, size, flags)`; otherwise convert
  µs→ns and call the `_with_timeout` variant. (Decide at the call boundary; both
  return the same way.)
- **wake all vs any:** `all == true` ⇒ `os_sync_wake_by_address_all`, else
  `os_sync_wake_by_address_any`. (Replaces `ULF_WAKE_ALL`.)
- **Return-value translation (the one behavioral seam):** `os_sync` reports errors via
  `errno` + return `-1` (it has no `ULF_NO_ERRNO` equivalent). The wrappers MUST
  translate to the existing contract:
  - `wait`: success / value-mismatch ⇒ return `>= 0` (the caller re-checks the value);
    on `-1`, return `-(errno)` (e.g. `-ETIMEDOUT`, `-EINTR`).
  - `wake`: success ⇒ return `>= 0`; "no waiters" and other failures ⇒ `-(errno)`
    (preserve the prior `-ENOENT`-on-no-waiter behavior; verify the errno `os_sync`
    uses for no-waiter and document it).
- The `#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]` stub returning
  `-ENOSYS` stays as-is.

### Docs
Update the module-level doc comment to cite `os_sync_wait_on_address` (macOS 14.4) and
its SHARED semantics instead of xnu `bsd/kern/sys_ulock.c`.

### Risk
Low. Thin, self-contained module; interface unchanged; semantics documented-equivalent.
The errno-translation seam is the only place behavior can drift.

---

## Item 2 — `parking_lot` thread registry (`src/thread.rs`)

### Current state
`ThreadRegistry::inner` is `std::sync::Mutex<HashMap<ThreadId, ThreadEntry>>` and the
process-global `CURRENT_REGISTRY` is `std::sync::Mutex<Option<Arc<ThreadRegistry>>>`.
Lock acquisition uses `.lock().expect("thread registry mutex poisoned")` in 8 places,
each guarded by `#[allow(clippy::expect_used)]`. `parking_lot` is **already** a
dependency and already used in this same file (`ParkingMutex` for the 64 futex shards).

### Change
- `ThreadRegistry::inner: parking_lot::Mutex<HashMap<…>>`.
- `CURRENT_REGISTRY: parking_lot::Mutex<Option<Arc<ThreadRegistry>>>` — stays a plain
  `static` (`parking_lot::Mutex::new` is `const fn`; no `OnceLock`).
- Replace all 8 `.lock().expect("thread registry mutex poisoned")` with `.lock()`,
  removing the 8 `#[allow(clippy::expect_used)]` attributes and the poison-invariant
  comments.
- `set_current_registry` / `current_thread_states`: drop the `if let Ok(..)` /
  `.ok()` poison handling; use direct `.lock()`. `current_thread_states` keeps querying
  the kernel (`thread_info`) **outside** the lock, as today.

### Risk
Low. No semantic change; removes 8 panic vectors; matches the in-file futex-shard
locking style. `parking_lot` is non-poisoning, so a panic while holding the lock no
longer cascades into sibling threads.

---

## Item 3 — `EVFILT_TIMER` for `setitimer` + `timerfd` audit

### Current state (setitimer)
`setitimer` (`src/dispatch/time.rs`) arms an interval timer by calling
`spawn_itimer_thread`, which spawns a dedicated OS thread named `carrick-itimer`
**per arm**. The thread `std::thread::sleep`s for the initial `it_value`, then loops:
check a per-`which` generation counter (to detect disarm/re-arm), `publish_process_signal`
+ `probes::itimer_fire`, `std::thread::sleep(it_interval)`, repeat. There are 3 itimer
`which` values (REAL/VIRTUAL/PROF) → up to 3 such threads, re-spawned on every re-arm.

### Change (setitimer → kqueue)
Delete `spawn_itimer_thread` and the generation-counter (`itimer_gen`) mechanism.
Register `EVFILT_TIMER` events on the **signal pump's existing kqueue** in
`src/vcpu_kick.rs` (its fd is already published via `set_pump_kqueue`, and other threads
already register against it — e.g. `EVFILT_USER` `NOTE_TRIGGER`).

**Stable ident per `which`:** assign 3 fixed `EVFILT_TIMER` idents (e.g.
`TIMER_IDENT_BASE + which`). Because the ident is stable per `which`, re-arm/disarm is a
single `EV_ADD`/`EV_DELETE` on that ident, and a new `EV_ADD` cleanly supersedes a prior
arm — this replaces the generation-counter race entirely.

**Two-phase timing (approved: oneshot → re-arm periodic):**
1. `setitimer` with non-zero `it_value`: register
   `EV_ADD | EV_ONESHOT`, `NOTE_NSECONDS`, `data = it_value_ns` on the timer's ident.
   Store the timer's `it_interval` in proc state so the pump can re-arm.
2. Pump loop, on an `EVFILT_TIMER` event: map `ident → which → signum`
   (SIGALRM / SIGVTALRM / SIGPROF), call `probes::itimer_fire(signum, …)` +
   `host_signal::publish_process_signal(signum)`. Then, if the stored `it_interval > 0`,
   re-register that ident as **periodic** (`EV_ADD`, `NOTE_NSECONDS`,
   `data = it_interval_ns`, no `EV_ONESHOT`); the kernel re-fires every interval with no
   further userspace registration. If `it_interval == 0`, do nothing (oneshot already
   consumed).
3. `setitimer` with `it_value == 0` (disarm) or re-arm: `EV_DELETE` the ident (ignore
   ENOENT), then optionally `EV_ADD` the new oneshot.

**Pump loop integration:** extend the existing event dispatch (currently
`if event.is_read() { drain_pump_pipe() }`) with an `EVFILT_TIMER` branch that performs
the fire + periodic re-arm above. The pump remains a single thread blocked in `kevent`
with no timeout.

**getitimer:** unchanged — it still computes `it_value` remaining from the stored
`ItimerState` (`set_at` + elapsed). The stored `ItimerState` (value/interval/set_at) is
retained for `getitimer`; only the *delivery mechanism* moves to kqueue.

**Registration thread-safety:** `setitimer` runs on a vCPU/dispatch thread, not the pump
thread. It registers by calling `kevent` on the published pump kq fd — `kevent`
registration from another thread is the same pattern `notify_pump` already uses, and the
pump's blocking `kq.wait()` will return the newly-armed timer events.

### `timerfd` audit (extra scope)
`timerfd` does **not** spawn threads; it computes deadlines on demand and blocks via the
`TimerFdState` condvar (`state.changed`). Audit deliverables:
- Verify `refresh_timerfd_locked` expiration-count math (the number of expirations since
  last read for a periodic timer) matches Linux.
- Verify `TFD_TIMER_ABSTIME` / `LINUX_TIMER_ABSTIME` handling and the `it_value`/`it_interval`
  semantics on `timerfd_settime`/`timerfd_gettime`.
- Add an LTP-style conformance probe if a gap is found.
- **No structural change is expected.** Fold in a fix only if the audit surfaces a real
  divergence; otherwise the deliverable is the verified-correct note + probe.

### Risk
Low–medium. Consolidates up to 3 per-arm threads → 0 (kernel-tracked on the one pump
thread already sleeping in `kevent`). The generation-counter race window closes. Main
care points: exact ns conversion, oneshot→periodic re-arm logic, and ident lifecycle on
rapid re-arm/disarm.

---

## Error handling

- All new FFI is `unsafe` blocks with SAFETY comments matching the existing `ulock.rs`
  style (4-byte kernel read at a live host MAP_SHARED address, etc.).
- Failures map to `-errno` and propagate through existing dispatch return paths; no new
  panics. Code must pass the crate's clippy no-panic lints (no `.unwrap()`/`.expect()`
  added).
- `kevent` registration failures in `setitimer` are surfaced as the timer simply not
  arming (and recorded via the existing `CompatEvent` reporter), never a panic.

## Testing

**Build gate:** `./scripts/build-signed.sh` (HVF entitlement; an unsigned build hits
HV_DENIED). Must compile clean under the no-panic lints.

**Conformance oracle — LTP-in-Docker (per the `ltp-conformance` skill, build `--release`
+ run probes first):**
- Item 1: cross-process futex via shared mapping — `tst_checkpoint`-based tests must
  MATCH Docker (parent↔child wait/wake rendezvous).
- Item 3: `setitimer01`, `getitimer01`, and a periodic-interval setitimer case
  (it_value ≠ it_interval) must MATCH Docker; `timerfd` tests must MATCH (audit).

**Lib tests (existing 113+ must stay green; add):**
- `os_sync` errno-translation unit coverage (timeout → `-ETIMEDOUT`, no-waiter wake →
  expected errno, value-mismatch → `≥0`).
- itimer `ident → which → signum` mapping unit test.

**Tracing:** use `carrick trace` / `CARRICK_TRACE_TRAPS` (USDT under sudo is unreliable)
if a futex or timer path needs inspection.

## Sequencing

Three independent commits/PRs, smallest/safest first; each independently revertable:

1. **parking_lot thread registry** (Item 2) — mechanical type swap, no FFI.
2. **os_sync futex** (Item 1) — self-contained module swap.
3. **EVFILT_TIMER setitimer + timerfd audit** (Item 3) — the only cross-file change
   (touches `time.rs`, `vcpu_kick.rs`, proc state).

## Acceptance criteria

- [ ] `src/ulock.rs` contains no syscall numbers 515/516 and no `__ulock` references;
      uses `os_sync_*` linked from `libSystem`; futex LTP tests MATCH Docker.
- [ ] `src/thread.rs` `ThreadRegistry`/`CURRENT_REGISTRY` use `parking_lot`; zero
      `.expect("thread registry mutex poisoned")`; zero added `#[allow(clippy::expect_used)]`.
- [ ] `spawn_itimer_thread` and `itimer_gen` are gone; `setitimer` arms `EVFILT_TIMER`
      on the pump kqueue; periodic delivery works with `it_value ≠ it_interval`;
      setitimer/getitimer LTP tests MATCH Docker.
- [x] `timerfd` audited: documented correct or fixed, with a probe if a gap was found.
- [ ] Signed build clean; existing lib tests green; new unit tests added.

---

## timerfd audit findings

Audited on May 24, 2026. Findings confirm the current in-memory `timerfd` implementation in `src/dispatch/time.rs` and `src/dispatch/mod.rs` is 100% correct and matches Linux semantics:

1. **Expiration Count Math:** Periodic expiration count math in `timerfd_expirations` correctly computes elapsed periods as `1 + elapsed_since_deadline / interval` using `((now_nanos - deadline_nanos) / interval_nanos).saturating_add(1)`. It also correctly advances `deadline` by the full `elapsed_periods * interval` instead of just setting it to "now".
2. **One-shot vs Periodic:** When `interval` is zero or `None`, it properly expires once and returns `None` as the next deadline, disarming the timer so subsequent reads correctly return 0 expirations.
3. **Absolute Time Flag:** `timerfd_settime` respects `TFD_TIMER_ABSTIME` (`LINUX_TIMER_ABSTIME`) by using the value directly as absolute time instead of adding `now` to it.
4. **Gettime Behavior:** `timerfd_gettime` properly refreshes the expiration count and next deadline without clearing the current `expirations` count. This ensures subsequent `read` calls still see the correct total accumulated expirations.

No code modifications were required for `timerfd` as it is semantically complete and correct.
