# carrick-embed Plan — Phase A — Fix-now commits

> Part of [`2026-08-25-carrick-embed-phase-a-c-plan.md`](2026-08-25-carrick-embed-phase-a-c-plan.md); read that index and the spec first. Line numbers verified at `39426141`; quoted existing text is the authority.


<!-- cluster A1-clock-bypasses -->
## Cluster A1-clock-bypasses

> **Status:** verifier-corrected and cross-cluster reconciled (fixes applied: 6; notes: Verified in-tree: conformance.rs:4996-5002 asserts DEDICATED_PROBE_RUNNERS.len()==20, generic 419, 439, 878 — so A1's generic 420/440/880 edit is required (the original draft only bumped PROBE_SOURCE_COUNT and would have failed that guard). DEDICATED stays 20 for A1; A4 (Tasks 8-10) and B4 (Tasks 22-23) bump it to 21/22. | Verified in-tree: the post-exec identity stamp site is vcpu_loop/exec.rs:1673 `super::stamp_identity_page_at(engine, &kernel.dispatcher, &committed_context, identity_base)`; `stamp_identity_page_at` (vcpu_loop/mod.rs:1802) is a private free fn taking `&mut M: GuestMemory` and `&SyscallDispatcher`, so calling `kernel.dispatcher.sync_vvar_realtime_offset(engine)` right after it is type-correct. Fix 11 named it `stamp_identity_page_at` in exec.rs; the fn is defined in vcpu_loop/mod.rs and called from exec.rs — plan text reflects both. | The exec'd-process live check in Task 3 Step 7 is a guarantee check, not a red-first reproducer: a fresh MM authority starts at epoch u64::MAX, so the first syscall already re-stamps it and `date` issues syscalls before reading the clock. The plan says so explicitly and the commit body states it; the red-first evidence for the task is the Step 4 dispatcher tests plus the Step 8 probe. | Fix 11 also says B3 must delete `realtime_base_duration` and `realtime_test_support` — those are A1-produced and now explicitly listed in Task 3's Interfaces as Phase B deletions; nothing in B3's text was edited here (not my cluster). | Fix 11's).

### Task 1: Route the raw host wall-clock reads through the guest realtime authority

> Line numbers below are against the CURRENT checkout HEAD `39426141` (the draft was written at `3dc6cc72`, 33 commits back; `dispatch/mod.rs`, `mqueue.rs`, `sysv.rs` and `trap.rs` moved since). The quoted existing text is the authority; re-`grep` before editing if the tree has moved again.

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs:6616-6646` (`relative_from_absolute_timespec`; the realtime branch is `:6633-6644`), `:7540` (`realtime_duration` visibility), `:8905-8924` (`resolve_utimensat_timespec` / `now_realtime_timespec`), append test modules after `:8986` (the closing `}` of `mod exec_vector_tests`, just before the `vfs_md_to_rootfs_md` adapter)
- Modify: `crates/carrick-runtime/src/dispatch/mqueue.rs:1106-1114` (`deadline_expired`), append a test inside the existing `mod tests` (starts `:1118`, file ends `:2581`)
- Modify: `crates/carrick-runtime/src/dispatch/sysv.rs:1180-1185` (`unix_now_secs`) and the eight inline `std::time::SystemTime::now()` stamps at `:2141-2144`, `:2575-2578`, `:2661-2664`, `:2730-2733`, `:2834-2837`, `:3166-3169`, `:3999-4002`, `:4063-4066`; append a test inside `mod ipc_set_tests` (`:4350`, runs to end of file)
- Modify: `crates/carrick-runtime/src/vfs/proc.rs:63` (import), `:2865-2872` (`boot_epoch_secs`); append a test inside `mod tests` (`:4186`)
- Modify: `crates/carrick-runtime/src/dispatch/time.rs:1503-1514` (existing `guest_realtime_offset_virtual_clock` test — serialize it through the new helper)
- Test: all under `just test` (no HVF); focused scratch runs via `cargo test -p carrick-runtime --lib <filter> -- --test-threads=1` (the `just test` recipe additionally isolates `CARRICK_DSR_STORE_DIR`; use the recipe for the final pass)

**Interfaces:**
- Consumes: `crate::dispatch::set_guest_realtime_offset_ns(i64)` / `get_guest_realtime_offset_ns() -> i64` (existing, `dispatch/mod.rs:7532-7538`), `fn realtime_duration() -> Duration` (existing, `dispatch/mod.rs:7540`), `pub(crate) fn boottime_duration()` (existing, `:7610`, already used by `vfs/proc.rs::boot_elapsed`)
- Produces: `pub(crate) fn realtime_duration() -> Duration` (visibility widened; THE guest `CLOCK_REALTIME` authority for every wall-clock consumer in the runtime); `#[cfg(test)] pub(crate) mod dispatch::realtime_test_support { pub(crate) fn with_guest_realtime_offset<R>(delta_ns: i64, f: impl FnOnce() -> R) -> R }`
- Phase B note: the new `realtime_duration` callers this task creates (mqueue `deadline_expired`, sysv `unix_now_secs`, proc `boot_epoch_secs`, `relative_from_absolute_timespec`, `now_realtime_timespec`) are the sites Phase B's clock cluster (Tasks 20-21, `ClockDomain`) converts to `task.container().clock().realtime_now()`; it also deletes `realtime_duration` and replaces `realtime_test_support` with `ClockDomain` test helpers. Nothing here anticipates that — this task lands the single carrier-wide authority first.
- Scope note: `mqueue.rs`, `sysv.rs` and `time.rs` all `use super::*;`, so `realtime_duration` is in scope there unqualified; the fully-qualified `crate::dispatch::realtime_duration()` spelling below is used where it reads clearer.

- [ ] **Step 1: Add the serialized test helper and the red futex/utimensat tests**

Append after line 8986 of `crates/carrick-runtime/src/dispatch/mod.rs` (the closing `}` of `mod exec_vector_tests`):

```rust
#[cfg(test)]
pub(crate) mod realtime_test_support {
    use std::sync::{Mutex, MutexGuard};

    static GUEST_REALTIME_OFFSET_LOCK: Mutex<()> = Mutex::new(());

    struct ResetOnDrop {
        _guard: MutexGuard<'static, ()>,
    }

    impl Drop for ResetOnDrop {
        fn drop(&mut self) {
            super::set_guest_realtime_offset_ns(0);
        }
    }

    /// Run `f` with the guest CLOCK_REALTIME delta set to `delta_ns`,
    /// serialized against every other offset-moving test, and reset to 0
    /// afterwards (also on panic). `just test` already runs carrick-runtime
    /// under RUST_TEST_THREADS=1; the lock keeps a focused parallel
    /// `cargo test -p carrick-runtime` honest too.
    pub(crate) fn with_guest_realtime_offset<R>(delta_ns: i64, f: impl FnOnce() -> R) -> R {
        let guard = GUEST_REALTIME_OFFSET_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _reset = ResetOnDrop { _guard: guard };
        super::set_guest_realtime_offset_ns(delta_ns);
        f()
    }
}

#[cfg(test)]
mod realtime_authority_tests {
    use super::realtime_test_support::with_guest_realtime_offset;
    use super::*;

    const HOUR_NS: i64 = 3_600 * 1_000_000_000;

    fn host_wall_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// FUTEX_WAIT_BITSET|FUTEX_CLOCK_REALTIME: the guest built its absolute
    /// deadline on ITS CLOCK_REALTIME, so "now" must be read from the same
    /// authority. Reading the host wall clock instead put every deadline one
    /// hour in the future once the guest had moved its clock forward.
    #[test]
    fn futex_realtime_deadline_is_measured_on_the_guest_clock() {
        with_guest_realtime_offset(HOUR_NS, || {
            let deadline = realtime_duration() + Duration::from_millis(200);
            let remaining = relative_from_absolute_timespec(
                deadline.as_secs() as i64,
                i64::from(deadline.subsec_nanos()),
                true,
            );
            assert!(
                remaining <= Duration::from_millis(200),
                "deadline 200ms past the guest clock must not wait longer: {remaining:?}"
            );
            assert!(
                remaining >= Duration::from_millis(100),
                "deadline 200ms past the guest clock must not be already past: {remaining:?}"
            );
        });
    }

    /// `utimensat(UTIME_NOW)` and the NULL-times form stamp the file with the
    /// GUEST's wall clock, like every other realtime read.
    #[test]
    fn utimensat_utime_now_stamps_the_guest_clock() {
        with_guest_realtime_offset(HOUR_NS, || {
            let (sec, nsec) = now_realtime_timespec();
            assert!((0..1_000_000_000).contains(&nsec));
            assert!(
                sec - host_wall_secs() >= 3_599,
                "NULL-times stamp must carry the guest offset: sec={sec}"
            );
            let resolved = resolve_utimensat_timespec(LinuxTimespec::new(0, LINUX_UTIME_NOW))
                .expect("UTIME_NOW resolves to a concrete stamp");
            assert!(
                resolved.0 - host_wall_secs() >= 3_599,
                "UTIME_NOW must carry the guest offset: sec={}",
                resolved.0
            );
        });
    }
}
```

(`SystemTime`, `UNIX_EPOCH`, `Duration` come from `mod.rs:139`; `LinuxTimespec` from the `carrick_abi` import at `:606`; `LINUX_UTIME_NOW: i64` from `:542` — all reachable through `use super::*`.)

- [ ] **Step 2: Run the new tests and watch them fail for the right reason**

Run: `cargo test -p carrick-runtime --lib realtime_authority_tests -- --test-threads=1`

Expected: `test result: FAILED. 0 passed; 2 failed` with
`deadline 200ms past the guest clock must not wait longer: 3600.2…s` (the host "now" is an hour behind the guest deadline) and
`NULL-times stamp must carry the guest offset`.

- [ ] **Step 3: Route the futex realtime deadline and `now_realtime_timespec` through `realtime_duration`**

In `crates/carrick-runtime/src/dispatch/mod.rs`, replace the realtime branch of `relative_from_absolute_timespec` (lines 6633-6644):

```rust
    //
    // The FUTEX_CLOCK_REALTIME case reads the host wall clock, correct because
    // the guest's vDSO CLOCK_REALTIME is calibrated to the same wall clock.
    // Probe: futexrealtime.
    let now_ns: i128 = if realtime {
        let mut now: libc::timespec = unsafe { std::mem::zeroed() };
        // SAFETY: clock_gettime writes a timespec for a valid clock id.
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) };
        (now.tv_sec as i128) * 1_000_000_000 + now.tv_nsec as i128
    } else {
        monotonic_duration().as_nanos() as i128
    };
```

with:

```rust
    //
    // The FUTEX_CLOCK_REALTIME case reads the GUEST's CLOCK_REALTIME
    // (`realtime_duration`: host calibration + the guest-settable offset).
    // Reading the raw host wall clock here was wrong the moment a guest moved
    // its clock with `clock_settime`: every absolute deadline was then computed
    // against a "now" one step behind. Probe: futexrealtime.
    let now_ns: i128 = if realtime {
        realtime_duration().as_nanos() as i128
    } else {
        monotonic_duration().as_nanos() as i128
    };
```

Widen the visibility at line 7540:

```rust
fn realtime_duration() -> Duration {
```

to:

```rust
/// The guest's `CLOCK_REALTIME`: THE wall-clock authority for every realtime
/// consumer in the runtime (clock reads, absolute deadlines, file and IPC
/// stamps, `/proc` epochs). Nothing else in the runtime may read the host wall
/// clock for a guest-visible value.
pub(crate) fn realtime_duration() -> Duration {
```

Replace `now_realtime_timespec` (lines 8919-8924):

```rust
/// Current CLOCK_REALTIME as a (sec, nsec) pair, for UTIME_NOW / NULL times.
fn now_realtime_timespec() -> (i64, i64) {
    let mut ts: libc::timespec = unsafe { core::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    (ts.tv_sec as i64, ts.tv_nsec as i64)
}
```

with:

```rust
/// The guest's current CLOCK_REALTIME as a (sec, nsec) pair, for UTIME_NOW /
/// NULL times.
fn now_realtime_timespec() -> (i64, i64) {
    let now = realtime_duration();
    (now.as_secs() as i64, i64::from(now.subsec_nanos()))
}
```

- [ ] **Step 4: Re-run the futex/utimensat tests**

Run: `cargo test -p carrick-runtime --lib realtime_authority_tests -- --test-threads=1`
Expected: `test result: ok. 2 passed; 0 failed`.

- [ ] **Step 5: Red test for the mqueue deadline**

Append inside `mod tests` of `crates/carrick-runtime/src/dispatch/mqueue.rs` (the module opens at `:1118` with `use super::*;`; add after the last `#[test]`, before the module's closing `}` at end of file):

```rust
    /// `mq_timedsend`/`mq_timedreceive` deadlines are absolute CLOCK_REALTIME
    /// values the guest built on ITS clock; expiry must be judged on the same
    /// clock, not the host's.
    #[test]
    fn mq_deadline_expiry_is_measured_on_the_guest_clock() {
        crate::dispatch::realtime_test_support::with_guest_realtime_offset(
            3_600 * 1_000_000_000,
            || {
                let host_now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                // 30 minutes past the HOST clock is already 30 minutes in the
                // guest's past.
                assert!(deadline_expired(Some(((host_now.as_secs() + 1_800) as i64, 0))));
                // 30 minutes past the GUEST clock is still in the future.
                let guest_now = crate::dispatch::realtime_duration();
                assert!(!deadline_expired(Some(((guest_now.as_secs() + 1_800) as i64, 0))));
            },
        );
    }
```

Run: `cargo test -p carrick-runtime --lib mq_deadline_expiry_is_measured_on_the_guest_clock -- --test-threads=1`
Expected: FAILED on the first `assert!` (host clock says a host+30min deadline has not expired).

- [ ] **Step 6: Route `deadline_expired` through `realtime_duration`**

Replace in `crates/carrick-runtime/src/dispatch/mqueue.rs` (lines 1106-1114):

```rust
fn deadline_expired(deadline: Option<(i64, i64)>) -> bool {
    let Some((sec, nsec)) = deadline else {
        return false;
    };
    let mut now: libc::timespec = unsafe { core::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) };
    let now_sec = now.tv_sec as i64;
    let now_nsec = now.tv_nsec as i64;
    (now_sec, now_nsec) >= (sec, nsec)
}
```

with:

```rust
/// Whether an absolute CLOCK_REALTIME deadline has passed on the GUEST's clock
/// (`crate::dispatch::realtime_duration`, the single realtime authority).
fn deadline_expired(deadline: Option<(i64, i64)>) -> bool {
    let Some((sec, nsec)) = deadline else {
        return false;
    };
    let now = crate::dispatch::realtime_duration();
    (now.as_secs() as i64, i64::from(now.subsec_nanos())) >= (sec, nsec)
}
```

Run: `cargo test -p carrick-runtime --lib mqueue -- --test-threads=1`
Expected: every mqueue test passes, including the new one.

- [ ] **Step 7: Red test + grep assertion for the SysV IPC stamps**

Append inside `mod ipc_set_tests` of `crates/carrick-runtime/src/dispatch/sysv.rs` (opens at `:4350`, `use super::*;`, runs to end of file):

```rust
    /// `shm_ctime`/`shm_atime`/`shm_dtime`, `sem_otime`/`sem_ctime` and the
    /// msg queue stamps are guest-visible wall-clock values: they come from the
    /// guest's CLOCK_REALTIME, not the host's.
    #[test]
    fn sysv_ipc_stamps_follow_the_guest_clock() {
        crate::dispatch::realtime_test_support::with_guest_realtime_offset(
            3_600 * 1_000_000_000,
            || {
                let host_now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                assert!(
                    unix_now_secs() >= host_now + 3_599,
                    "SysV stamp must carry the guest offset"
                );
            },
        );
    }
```

Run: `cargo test -p carrick-runtime --lib sysv_ipc_stamps_follow_the_guest_clock -- --test-threads=1`
Expected: FAILED (`unix_now_secs` reads the host clock).

Run: `rg -c 'std::time::SystemTime::now\(\)' crates/carrick-runtime/src/dispatch/sysv.rs`
Expected: `9` (the helper plus eight inline stamps) — this must become "no matches" after Step 8.

- [ ] **Step 8: Make `unix_now_secs` the only stamp source and route it through `realtime_duration`**

In `crates/carrick-runtime/src/dispatch/sysv.rs` replace lines 1180-1185:

```rust
fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
```

with:

```rust
/// Seconds since the Epoch on the GUEST's CLOCK_REALTIME, for every
/// `ipc_perm`-adjacent stamp (`*_ctime`/`*_atime`/`*_dtime`/`*_otime`,
/// `msg_stime`/`msg_rtime`). The single SysV stamp source; never read the
/// host wall clock inline.
fn unix_now_secs() -> u64 {
    realtime_duration().as_secs()
}
```

Then replace each of the eight inline stamps with a call to `unix_now_secs()`. The exact existing text and its replacement, per site:

`:2141-2144` (shmget segment creation):
```rust
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
```
→
```rust
    let now = unix_now_secs();
```

`:2575-2578` (inside `reservation.commit(`):
```rust
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.as_secs())
                                    .unwrap_or(0),
```
→
```rust
                                unix_now_secs(),
```

`:2661-2664` (`HostAliasShmatCommit { atime: … }`):
```rust
                    atime: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
```
→
```rust
                    atime: unix_now_secs(),
```

`:2730-2733` (shmdt):
```rust
            let dtime = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
```
→
```rust
            let dtime = unix_now_secs();
```

`:2834-2837` (shmctl IPC_SET):
```rust
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
```
→
```rust
                    let now = unix_now_secs();
```

`:3166-3169` (semget):
```rust
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
```
→
```rust
            let now = unix_now_secs();
```

`:3999-4002` (semop completion closure):
```rust
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
```
→
```rust
            let now = unix_now_secs();
```

`:4063-4066` (semctl):
```rust
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
```
→
```rust
        let now = unix_now_secs();
```

Run: `rg -c 'std::time::SystemTime::now\(\)' crates/carrick-runtime/src/dispatch/sysv.rs; echo "exit=$?"`
Expected: no count line, `exit=1` (zero matches).

Run: `cargo test -p carrick-runtime --lib sysv -- --test-threads=1`
Expected: all sysv tests pass including `sysv_ipc_stamps_follow_the_guest_clock`.

- [ ] **Step 9: Red test for `/proc/stat` `btime`**

Append inside `mod tests` of `crates/carrick-runtime/src/vfs/proc.rs` (the module at line 4186):

```rust
    /// `btime` is `now - uptime` on the GUEST's wall clock; it moves with
    /// `clock_settime` exactly as Linux's does.
    #[test]
    fn proc_stat_btime_follows_the_guest_clock() {
        crate::dispatch::realtime_test_support::with_guest_realtime_offset(
            3_600 * 1_000_000_000,
            || {
                let host_now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let btime = boot_epoch_secs();
                assert!(
                    btime + boot_elapsed().as_secs() >= host_now + 3_599,
                    "btime {btime} must be derived from the guest clock"
                );
            },
        );
    }
```

Run: `cargo test -p carrick-runtime --lib proc_stat_btime_follows_the_guest_clock -- --test-threads=1`
Expected: FAILED (`boot_epoch_secs` subtracts uptime from the host wall clock).

- [ ] **Step 10: Route `boot_epoch_secs` through `realtime_duration` and drop the dead imports**

In `crates/carrick-runtime/src/vfs/proc.rs` replace line 63:

```rust
use std::time::{Duration, SystemTime, UNIX_EPOCH};
```

with:

```rust
use std::time::Duration;
```

(`SystemTime`/`UNIX_EPOCH` have exactly one other use in the file — the function below; `Duration` stays for `boot_elapsed`.) Replace lines 2865-2872:

```rust
/// Boot time in seconds since the Epoch, for `/proc/stat`'s `btime` line:
/// now - uptime. Non-zero so `start_epoch = btime + starttime/HZ` math works.
fn boot_epoch_secs() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now.saturating_sub(boot_elapsed().as_secs())
}
```

with:

```rust
/// Boot time in seconds since the Epoch, for `/proc/stat`'s `btime` line:
/// guest now - uptime, both from the dispatch clock authorities
/// (`realtime_duration` / `boottime_duration`) so `btime` moves with
/// `clock_settime` like Linux's. Non-zero so `start_epoch = btime +
/// starttime/HZ` math works.
fn boot_epoch_secs() -> u64 {
    crate::dispatch::realtime_duration()
        .as_secs()
        .saturating_sub(boot_elapsed().as_secs())
}
```

Run: `cargo test -p carrick-runtime --lib vfs::proc -- --test-threads=1`
Expected: all proc tests pass including the new one.

- [ ] **Step 11: Serialize the pre-existing offset test through the helper**

Replace lines 1503-1514 of `crates/carrick-runtime/src/dispatch/time.rs`:

```rust
    #[test]
    fn guest_realtime_offset_virtual_clock() {
        use crate::dispatch::{get_guest_realtime_offset_ns, set_guest_realtime_offset_ns};

        set_guest_realtime_offset_ns(0);
        assert_eq!(get_guest_realtime_offset_ns(), 0);

        set_guest_realtime_offset_ns(1_000_000_000);
        assert_eq!(get_guest_realtime_offset_ns(), 1_000_000_000);

        set_guest_realtime_offset_ns(0);
    }
```

with:

```rust
    #[test]
    fn guest_realtime_offset_virtual_clock() {
        crate::dispatch::realtime_test_support::with_guest_realtime_offset(1_000_000_000, || {
            assert_eq!(crate::dispatch::get_guest_realtime_offset_ns(), 1_000_000_000);
        });
        assert_eq!(crate::dispatch::get_guest_realtime_offset_ns(), 0);
    }
```

- [ ] **Step 12: Whole-crate check, format, lint**

Run: `just fmt && just test`
Expected: `test result: ok` for every crate; the recipe runs carrick-runtime serially (`RUST_TEST_THREADS=1`) with `CARRICK_DSR_STORE_DIR` isolated — do not substitute a bare `cargo test -p carrick-runtime --lib` here.

Run: `just clippy && just lint-domains`
Expected: both exit 0 (no `unused import` from proc.rs, no new domain-lint hits).

- [ ] **Step 13: Commit**

```bash
git add crates/carrick-runtime/src/dispatch/mod.rs \
        crates/carrick-runtime/src/dispatch/mqueue.rs \
        crates/carrick-runtime/src/dispatch/sysv.rs \
        crates/carrick-runtime/src/dispatch/time.rs \
        crates/carrick-runtime/src/vfs/proc.rs
git commit -F - <<'EOF'
fix(runtime): route every wall-clock read through the guest realtime authority

Why: `realtime_duration()` is the guest's CLOCK_REALTIME (host calibration
plus the CAP_SYS_TIME-settable offset from `clock_settime`/`settimeofday`),
but five consumers bypassed it and read the host wall clock directly:
FUTEX_WAIT_BITSET|FUTEX_CLOCK_REALTIME deadline conversion
(`relative_from_absolute_timespec`), `utimensat` UTIME_NOW / NULL times
(`now_realtime_timespec`), mqueue `mq_timedsend`/`mq_timedreceive` expiry
(`deadline_expired`), every SysV IPC `*_ctime`/`*_atime`/`*_dtime`/`*_otime`
stamp, and `/proc/stat` `btime`. After a guest moved its clock, an absolute
futex/mqueue deadline was judged against a "now" one step behind (waits
lasting the whole step, or expiring instantly), file and IPC stamps carried
the host's time, and `btime` disagreed with `clock_gettime`. Linux has one
wall-clock authority; so must carrick.

What: `realtime_duration()` is now `pub(crate)` and documented as THE
realtime authority; the five sites read it. SysV's eight inline
`SystemTime::now()` stamps collapse into the existing `unix_now_secs()`,
which reads the authority. No host wall-clock read remains in
`dispatch/sysv.rs`; `vfs/proc.rs` drops its `SystemTime`/`UNIX_EPOCH`
imports.

Verified: red-first unit tests that set a +1h guest offset and assert each
path observes it — `realtime_authority_tests::{futex_realtime_deadline_is_
measured_on_the_guest_clock, utimensat_utime_now_stamps_the_guest_clock}`,
`mqueue::tests::mq_deadline_expiry_is_measured_on_the_guest_clock`,
`sysv::ipc_set_tests::sysv_ipc_stamps_follow_the_guest_clock`,
`vfs::proc::tests::proc_stat_btime_follows_the_guest_clock` — each failed
against the pre-fix code and passes after. Offset-moving tests serialize
through `dispatch::realtime_test_support::with_guest_realtime_offset`.
`just clippy` and `just lint-domains` clean; `just test` green.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01VJcvGV5u1ErqZREKWUy6rU
EOF
```

### Task 2: `clocksettimevdso` probe with per-probe capability grants (red, excused)

**Files:**
- Create: `conformance-probes/src/bin/clocksettimevdso.rs`
- Modify: `conformance-probes/probe-inventory.json:162-166` (insert the new row after `clocknanosleepcpu`, keeping alphabetical order; `clone3args` follows)
- Modify: `crates/carrick-cli/tests/conformance.rs:39-63` (`KNOWN_PROBE_GAPS` entry), `:3229-3251` (`PROBE_SOURCE_COUNT` doc + const, 465 → 466), `:3471-3485` (add `probe_capabilities` beside `UNCONFINED_PROBES` / `probe_needs_unconfined`), `:3643-3696` (`run_carrick_probe_with_deadline` / `_named` / `_with_policy`), `:3700-3752` (`run_carrick_bound_probe_named` / `_with_policy`), `:3871-3895` (`run_docker_probe` / `_named` / `_with_policy`), `:4996-5002` (the absolute counts inside `closure_probe_inventory_enforces_authoritative_runners_and_denominator`: generic 419 → 420, 439 → 440, 878 → 880; `DEDICATED_PROBE_RUNNERS.len() == 20` is unchanged by this task), `:5107-5113` (unit test beside `clone_files_probes_run_without_container_seccomp`)
- Test: needs an HVF guest (signed binary via `just build`) and Docker for the live oracle; the Rust unit tests run under `cargo test -p carrick-cli --test conformance clock_settime_probe_is_granted` and `cargo test -p carrick-cli --test conformance closure_probe_inventory_enforces_authoritative_runners_and_denominator` (the conformance harness is only exercised by `just conformance-probes`, never by `just test`)
- NOT touched: `crates/carrick-cli/tests/probe-oracle/`. The gate prefers a committed cache row but runs the live Docker oracle on a miss whenever Docker is reachable (`conformance.rs:4556-4562`); the committed cache is a hand-picked set of 9 rows for Docker-less hosts, and `bless_probe_oracle` has no per-probe filter (it would re-run Docker for every probe of every set and write hundreds of files). Do not bless.
- Denominator ordering (landing order A1 → A3 → A4 → B4): this task is the FIRST to move the probe denominator and owns 466 / generic 420 / 440 / 880. Task 5 (A3, `ProcessLimitExceeded` probe) then moves to 467/421/441/882 and Task 6 (A3) to 468/422/442/884; Task 8-10 (A4, net.rs) to 469 with `DEDICATED == 21` (422+21 == 443, 886); Task 22-23 (B4) to 470 with `DEDICATED == 22` (444, 888). Final tree: 470 sources, 422 generic, 22 dedicated. Every later cluster's absolute numbers assume this task landed first.
- `--raw` note: the `run --raw` spellings quoted below (`run_carrick_probe_with_policy`, `run_carrick_bound_probe_with_policy`, and the hand-run commands in Steps 6/8) are the CURRENT tree's; Task 13 (A5, `--raw` deletion) later removes `--raw` from the seven `run` sites in `conformance.rs` and lands after this task. Do not pre-empt it here.

**Interfaces:**
- Consumes: `carrick run --cap-add <NAME>` (`crates/carrick-cli/src/args.rs:503-511`, routed by `SyscallDispatcher::apply_launch_privileges` → `grant_launch_capabilities`; already used by `crates/carrick-conformance/src/generate.rs:136` for `ltp-clock_settime01`); `docker run --cap-add`
- Produces: `fn probe_capabilities(name: &str) -> &'static [&'static str]` and `const SYS_TIME_PROBES: &[&str]` in `crates/carrick-cli/tests/conformance.rs`; new parameter `caps: &[&str]` on `run_carrick_probe_with_policy`, `run_carrick_bound_probe_with_policy`, `run_docker_probe_with_policy`

- [ ] **Step 1: Write the harness unit test (red: `probe_capabilities` does not exist)**

Insert after line 5113 of `crates/carrick-cli/tests/conformance.rs` (after `clone_files_probes_run_without_container_seccomp`):

```rust
#[test]
fn clock_settime_probe_is_granted_cap_sys_time_on_both_sides() {
    assert_eq!(probe_capabilities("clocksettimevdso"), ["SYS_TIME"]);
    assert!(probe_capabilities("futexrealtime").is_empty());
    assert!(probe_capabilities("clonefileshare").is_empty());
}
```

Run: `cargo test -p carrick-cli --test conformance clock_settime_probe_is_granted -- --nocapture`
Expected: compile error `cannot find function `probe_capabilities``.

- [ ] **Step 2: Add the capability table and thread it through the three runners**

Insert after line 3485 of `crates/carrick-cli/tests/conformance.rs` (after `fn probe_needs_unconfined`):

```rust
/// Capabilities a probe needs BEYOND the Docker default set, granted with
/// `--cap-add` to BOTH carrick and the Docker oracle. Same reasoning as
/// `UNCONFINED_PROBES`: the oracle must measure Linux, not its own privilege
/// (a Docker root without `CAP_SYS_TIME` gets EPERM from `clock_settime` and
/// the row would measure Docker's cap set). `clocksettimevdso` steps
/// CLOCK_REALTIME.
const SYS_TIME_PROBES: &[&str] = &["clocksettimevdso"];

fn probe_capabilities(name: &str) -> &'static [&'static str] {
    if SYS_TIME_PROBES.contains(&name) {
        &["SYS_TIME"]
    } else {
        &[]
    }
}
```

Replace lines 3643-3696 (the three carrick injection runners):

```rust
fn run_carrick_probe_with_deadline(
    bin: &PathBuf,
    lane: Lane,
    stdin_bytes: &[u8],
    deadline: Duration,
) -> String {
    run_carrick_probe_with_policy(bin, lane, stdin_bytes, deadline, false).normalized_output
}

fn run_carrick_probe_with_deadline_named(
    bin: &PathBuf,
    lane: Lane,
    stdin_bytes: &[u8],
    deadline: Duration,
    name: &str,
) -> CarrickProbeExecution {
    run_carrick_probe_with_policy(
        bin,
        lane,
        stdin_bytes,
        deadline,
        probe_needs_unconfined(name),
    )
}

fn run_carrick_probe_with_policy(
    bin: &PathBuf,
    lane: Lane,
    stdin_bytes: &[u8],
    deadline: Duration,
    unconfined: bool,
) -> CarrickProbeExecution {
    let mut command = Command::new(bin);
    command.args(["run", "--platform", lane.platform, "--raw", "--fs", "host"]);
    if unconfined {
        command.args(["--security-opt", "seccomp=unconfined"]);
    }
```

with:

```rust
fn run_carrick_probe_with_deadline(
    bin: &PathBuf,
    lane: Lane,
    stdin_bytes: &[u8],
    deadline: Duration,
) -> String {
    run_carrick_probe_with_policy(bin, lane, stdin_bytes, deadline, false, &[]).normalized_output
}

fn run_carrick_probe_with_deadline_named(
    bin: &PathBuf,
    lane: Lane,
    stdin_bytes: &[u8],
    deadline: Duration,
    name: &str,
) -> CarrickProbeExecution {
    run_carrick_probe_with_policy(
        bin,
        lane,
        stdin_bytes,
        deadline,
        probe_needs_unconfined(name),
        probe_capabilities(name),
    )
}

fn run_carrick_probe_with_policy(
    bin: &PathBuf,
    lane: Lane,
    stdin_bytes: &[u8],
    deadline: Duration,
    unconfined: bool,
    caps: &[&str],
) -> CarrickProbeExecution {
    let mut command = Command::new(bin);
    command.args(["run", "--platform", lane.platform, "--raw", "--fs", "host"]);
    if unconfined {
        command.args(["--security-opt", "seccomp=unconfined"]);
    }
    for cap in caps {
        command.args(["--cap-add", cap]);
    }
```

(the rest of `run_carrick_probe_with_policy` — `command.args([lane.image, "/bin/sh", "-c", PROBE_SNIPPET])…` — is unchanged.)

Replace lines 3700-3716 (bound-probe runner head):

```rust
fn run_carrick_bound_probe_named(
    bin: &PathBuf,
    lane: Lane,
    probe: &Path,
    deadline: Duration,
    name: &str,
) -> CarrickProbeExecution {
    run_carrick_bound_probe_with_policy(bin, lane, probe, deadline, probe_needs_unconfined(name))
}

fn run_carrick_bound_probe_with_policy(
    bin: &PathBuf,
    lane: Lane,
    probe: &Path,
    deadline: Duration,
    unconfined: bool,
) -> CarrickProbeExecution {
```

with:

```rust
fn run_carrick_bound_probe_named(
    bin: &PathBuf,
    lane: Lane,
    probe: &Path,
    deadline: Duration,
    name: &str,
) -> CarrickProbeExecution {
    run_carrick_bound_probe_with_policy(
        bin,
        lane,
        probe,
        deadline,
        probe_needs_unconfined(name),
        probe_capabilities(name),
    )
}

fn run_carrick_bound_probe_with_policy(
    bin: &PathBuf,
    lane: Lane,
    probe: &Path,
    deadline: Duration,
    unconfined: bool,
    caps: &[&str],
) -> CarrickProbeExecution {
```

and, in the same function (`:3741-3747`), replace:

```rust
    if unconfined {
        command.args(["--security-opt", "seccomp=unconfined"]);
    }
    command
        .arg(lane.image)
        .arg("/tmp/carrick-init")
```

with:

```rust
    if unconfined {
        command.args(["--security-opt", "seccomp=unconfined"]);
    }
    for cap in caps {
        command.args(["--cap-add", cap]);
    }
    command
        .arg(lane.image)
        .arg("/tmp/carrick-init")
```

Replace lines 3871-3890 (Docker runners):

```rust
fn run_docker_probe(lane: Lane, stdin_bytes: &[u8]) -> std::io::Result<String> {
    run_docker_probe_with_policy(lane, stdin_bytes, false)
}

fn run_docker_probe_named(lane: Lane, name: &str, stdin_bytes: &[u8]) -> std::io::Result<String> {
    run_docker_probe_with_policy(lane, stdin_bytes, probe_needs_unconfined(name))
}

fn run_docker_probe_with_policy(
    lane: Lane,
    stdin_bytes: &[u8],
    unconfined: bool,
) -> std::io::Result<String> {
    use std::io::Write;
    let mut command = Command::new("docker");
    command.args(["run", "-i", "--rm", "--platform", lane.platform]);
    if unconfined {
        command.args(["--security-opt", "seccomp=unconfined"]);
    }
```

with:

```rust
fn run_docker_probe(lane: Lane, stdin_bytes: &[u8]) -> std::io::Result<String> {
    run_docker_probe_with_policy(lane, stdin_bytes, false, &[])
}

fn run_docker_probe_named(lane: Lane, name: &str, stdin_bytes: &[u8]) -> std::io::Result<String> {
    run_docker_probe_with_policy(
        lane,
        stdin_bytes,
        probe_needs_unconfined(name),
        probe_capabilities(name),
    )
}

fn run_docker_probe_with_policy(
    lane: Lane,
    stdin_bytes: &[u8],
    unconfined: bool,
    caps: &[&str],
) -> std::io::Result<String> {
    use std::io::Write;
    let mut command = Command::new("docker");
    command.args(["run", "-i", "--rm", "--platform", lane.platform]);
    if unconfined {
        command.args(["--security-opt", "seccomp=unconfined"]);
    }
    for cap in caps {
        command.args(["--cap-add", cap]);
    }
```

Run: `cargo test -p carrick-cli --test conformance clock_settime_probe_is_granted -- --nocapture`
Expected: `test result: ok. 1 passed`.

- [ ] **Step 3: Write the probe**

Create `conformance-probes/src/bin/clocksettimevdso.rs` (Cargo `autobins = true`; `libc = "0.2"` is already a dependency of the probe crate):

```rust
//! `clock_settime(CLOCK_REALTIME)` coherence between the vDSO fast path and
//! the syscall path.
//!
//! Linux keeps ONE wall-clock authority: a `clock_settime` step is visible at
//! once through both `clock_gettime` routes — the vDSO (what glibc and musl
//! call when a vDSO is mapped) and the raw `svc`. carrick models the step as a
//! carrier-wide offset consulted by the trapping syscall path, but the vvar
//! word its vDSO adds to `CNTVCT_EL0` (`VVAR_OFF_REALTIME_OFF_NS`) was stamped
//! once at process construction and never re-stamped, so after a step the two
//! routes disagreed by the full step: a guest that set the clock and read it
//! back through libc saw the OLD time.
//!
//! Needs `CAP_SYS_TIME` on BOTH sides: the harness grants `--cap-add SYS_TIME`
//! to carrick and to the Docker oracle for this probe (`probe_capabilities`
//! in `crates/carrick-cli/tests/conformance.rs`). Running it by hand needs
//! `carrick run --cap-add SYS_TIME …`; `scripts/run-probe.sh` does not add it.
//!
//! Steps the clock forward by `STEP_SECS` and restores it before exiting. On
//! the Docker oracle that is a real, brief step of the LinuxKit VM clock
//! (CLOCK_REALTIME is not namespaced), which is why the step is small.
//! Deterministic: booleans only, judged with a 5 s tolerance against a 20 s
//! step so scheduling jitter between two adjacent reads cannot flip a line.

const STEP_SECS: i64 = 20;
const TOLERANCE_NS: i128 = 5_000_000_000;

fn ns(ts: &libc::timespec) -> i128 {
    (ts.tv_sec as i128) * 1_000_000_000 + ts.tv_nsec as i128
}

/// CLOCK_REALTIME through the raw syscall — never the vDSO.
fn syscall_realtime() -> libc::timespec {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_clock_gettime,
            libc::CLOCK_REALTIME,
            &mut ts as *mut libc::timespec,
        )
    };
    assert_eq!(rc, 0, "raw clock_gettime");
    ts
}

/// CLOCK_REALTIME through libc, which resolves `__kernel_clock_gettime` from
/// the vDSO when one is mapped (glibc and musl both do on aarch64).
fn vdso_realtime() -> libc::timespec {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    assert_eq!(rc, 0, "libc clock_gettime");
    ts
}

fn main() {
    let before = syscall_realtime();
    let target = libc::timespec {
        tv_sec: before.tv_sec + STEP_SECS,
        tv_nsec: before.tv_nsec,
    };
    let rc = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &target) };
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    println!("settime_ok={}", rc == 0);
    if rc != 0 {
        // An oracle without CAP_SYS_TIME lands here: the row then measures
        // privilege, not Linux — fix the grant, do not bless this output.
        println!("settime_errno={errno}");
        return;
    }
    let after_vdso = vdso_realtime();
    let after_sys = syscall_realtime();
    let step_ns = (STEP_SECS as i128) * 1_000_000_000;
    println!(
        "syscall_stepped={}",
        ns(&after_sys) - ns(&before) >= step_ns - TOLERANCE_NS
    );
    println!(
        "vdso_stepped={}",
        ns(&after_vdso) - ns(&before) >= step_ns - TOLERANCE_NS
    );
    println!(
        "vdso_matches_syscall={}",
        (ns(&after_vdso) - ns(&after_sys)).abs() <= TOLERANCE_NS
    );
    // Put the clock back, relative to the stepped syscall clock, so the host
    // is left where it was modulo this probe's own runtime.
    let now = syscall_realtime();
    let restore = libc::timespec {
        tv_sec: now.tv_sec - STEP_SECS,
        tv_nsec: now.tv_nsec,
    };
    let rc = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &restore) };
    println!("restored={}", rc == 0);
}
```

- [ ] **Step 4: Register the probe in the inventory and the source-count guard**

In `conformance-probes/probe-inventory.json`, after the `clocknanosleepcpu` row (lines 162-166):

```json
  "clocknanosleepcpu": {
    "class": "conformance",
    "excluded": false,
    "runner": "generic"
  },
```

insert:

```json
  "clocksettimevdso": {
    "class": "conformance",
    "excluded": false,
    "runner": "generic"
  },
```

Run: `python3 scripts/probe-inventory.py check`
Expected: exit 0 and `probe inventory checked: 466 sources {'conformance': 440, 'helper': 1, 'performance': 25}` (it was `465 sources {'conformance': 439, …}` before; the checker compares the JSON against `src/bin/` so Step 3 must precede this).

Red first for the denominator guard — run it BEFORE touching the constants:

Run: `cargo test -p carrick-cli --test conformance closure_probe_inventory_enforces_authoritative_runners_and_denominator`
Expected: FAILED at `assert_eq!(sources.len(), PROBE_SOURCE_COUNT)` — `left: 466, right: 465` (the new source is on disk and in the inventory; the guard's absolute numbers are stale).

In `crates/carrick-cli/tests/conformance.rs` replace lines 3250-3251:

```rust
/// variants.
const PROBE_SOURCE_COUNT: usize = 465;
```

with:

```rust
/// variants. `clocksettimevdso` (the `clock_settime` vDSO/syscall coherence
/// reducer: a stepped CLOCK_REALTIME must read identically through the vDSO
/// and the raw syscall) moves the denominator from 465 to 466 and the gating
/// rows from 878 to 880 — 440 conformance sources (420 generic + the 20
/// dedicated runners) under both variants.
const PROBE_SOURCE_COUNT: usize = 466;
```

and, inside `closure_probe_inventory_enforces_authoritative_runners_and_denominator` (lines 4996-5002), replace:

```rust
    let sources = all_probe_source_names();
    assert_eq!(DEDICATED_PROBE_RUNNERS.len(), 20);
    assert_eq!(sources.len(), PROBE_SOURCE_COUNT);
    let generic = validate_closure_probe_rows(&inventory(), &sources)
        .expect("checked-in closure probe inventory must match the source denominator");
    assert_eq!(generic.len(), 419);
    assert_eq!(generic.len() + DEDICATED_PROBE_RUNNERS.len(), 439);
    assert_eq!(2 * (generic.len() + DEDICATED_PROBE_RUNNERS.len()), 878);
```

with:

```rust
    let sources = all_probe_source_names();
    assert_eq!(DEDICATED_PROBE_RUNNERS.len(), 20);
    assert_eq!(sources.len(), PROBE_SOURCE_COUNT);
    let generic = validate_closure_probe_rows(&inventory(), &sources)
        .expect("checked-in closure probe inventory must match the source denominator");
    assert_eq!(generic.len(), 420);
    assert_eq!(generic.len() + DEDICATED_PROBE_RUNNERS.len(), 440);
    assert_eq!(2 * (generic.len() + DEDICATED_PROBE_RUNNERS.len()), 880);
```

Run: `cargo test -p carrick-cli --test conformance closure_probe_inventory_enforces_authoritative_runners_and_denominator`
Expected: `test result: ok. 1 passed`.

- [ ] **Step 5: Build the probe binaries (a Docker phase on the Mac)**

Run: `./scripts/build-probes.sh`
Expected: exit 0; `ls -l conformance-probes/target/aarch64-unknown-linux-musl/release/clocksettimevdso conformance-probes/target/aarch64-unknown-linux-gnu/release/clocksettimevdso` lists both ELFs.

Notes: on macOS/arm64 this script builds inside `rust:alpine` / `rust:bookworm` containers — it is Docker work, so no carrick guest may be running meanwhile. `just conformance-probes` only invokes this script on x86_64 hosts, so on the Mac this step is mandatory before Steps 6/8.

- [ ] **Step 6: Red run against the current (pre-Task-3) carrick — never concurrently with Docker**

Run:
```bash
just build
CARRICK_RUN_ID=cr-clocksettime-red target/release/carrick run --platform linux/arm64 --raw --fs host \
  --cap-add SYS_TIME docker.io/library/ubuntu:24.04 \
  /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p' \
  < <(base64 < conformance-probes/target/aarch64-unknown-linux-musl/release/clocksettimevdso)
```
Expected (this is the defect):
```
settime_ok=true
syscall_stepped=true
vdso_stepped=false
vdso_matches_syscall=false
restored=true
```
If carrick prints `settime_ok=false` / `settime_errno=1` instead: `scripts/conformance/baseline.jsonl` records carrick as TBROK x3 on `ltp-clock_settime01` (non-gating) even though `generate.rs` grants it `--cap-add SYS_TIME`, so a broken cap-grant → `has_effective_capability` path is a live possibility. That is a SEPARATE defect to attribute first (`apply_launch_privileges` → `grant_launch_capabilities` → the task's `CapabilitySet::effective`); do not widen the `KNOWN_PROBE_GAPS` excuse to cover it.

Then, only after the carrick run has exited, the oracle:
```bash
docker run -i --rm --platform linux/arm64 --cap-add SYS_TIME docker.io/library/ubuntu:24.04 \
  /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p' \
  < <(base64 < conformance-probes/target/aarch64-unknown-linux-musl/release/clocksettimevdso)
```
Expected:
```
settime_ok=true
syscall_stepped=true
vdso_stepped=true
vdso_matches_syscall=true
restored=true
```
Tree evidence that the oracle honours the step: `scripts/conformance/oracle-cache.jsonl` row `ltp-clock_settime01` with `docker_flags: ["--cap-add","SYS_TIME"]` records 4/4 pass (`clock_settime(N): was able to advance time` / `recede time`) on the arm64 Docker oracle. If the oracle nonetheless prints `settime_ok=false` / `settime_errno=1`, the Docker host refused the step: that is an under-privileged oracle (AGENTS.md "inversion" rule). Stop and resolve the grant before committing — never commit a row whose oracle output is an EPERM.

- [ ] **Step 7: Excuse the known gap until Task 3 (`clock_settime` re-stamps the vvar realtime word for every MM) lands**

In `crates/carrick-cli/tests/conformance.rs` replace lines 62-63:

```rust
    // epollstaledel FIXED in M3 (pending_ready keyed by fd) — now PASSES.
];
```

with:

```rust
    // epollstaledel FIXED in M3 (pending_ready keyed by fd) — now PASSES.
    // clocksettimevdso: clock_settime moves the syscall-path offset but never
    // re-stamps VVAR_OFF_REALTIME_OFF_NS, so the vDSO CLOCK_REALTIME lags the
    // syscall by the full step. Fixed by the embed Phase A vvar re-stamp
    // (removed in the same commit that lands it).
    "clocksettimevdso",
];
```

- [ ] **Step 8: Run the probe gate (live Docker oracle; two-phase inside the harness)**

Focused first (the harness accepts a comma list in `CARRICK_PROBE_FILTER`):

Run: `CARRICK_PROBE_FILTER=clocksettimevdso just conformance-probes 2>&1 | tee target/conformance/task2-probe-focused.log; echo "status=${PIPESTATUS[0]}"`
Expected: `status=0`; `grep -a 'clocksettimevdso' target/conformance/task2-probe-focused.log` shows `XFAIL arm64:musl:clocksettimevdso (known gap)` followed by the diff (`vdso_stepped`/`vdso_matches_syscall` false vs true), and the report-only gnu row.

Then the full gate:

Run: `just conformance-probes 2>&1 | tee target/conformance/task2-probe-gate.log; echo "status=${PIPESTATUS[0]}"`
Expected: `status=0`; `grep -a -E '^(FAIL|UNEXPECTED PASS)' target/conformance/task2-probe-gate.log` prints nothing. Read the whole log, never a tail.

- [ ] **Step 9: Commit**

```bash
just fmt
git add conformance-probes/src/bin/clocksettimevdso.rs conformance-probes/probe-inventory.json \
        crates/carrick-cli/tests/conformance.rs
git commit -F - <<'EOF'
test(conformance): clocksettimevdso probe with per-probe capability grants

Why: a guest `clock_settime(CLOCK_REALTIME)` moves carrick's syscall-path
offset but nothing re-stamps the vDSO's `VVAR_OFF_REALTIME_OFF_NS` word, so
libc's vDSO `clock_gettime` and the raw syscall disagree by the full step
afterwards (Linux keeps them coherent). No probe covered it because the
default Docker cap set lacks CAP_SYS_TIME, so the step itself was EPERM on
both sides and the row could only measure privilege.

What: `clocksettimevdso` steps CLOCK_REALTIME by 20 s, compares the vDSO
and syscall reads (5 s tolerance), and restores the clock. The harness
gains `probe_capabilities` beside `probe_needs_unconfined`: a probe's
`--cap-add` grants go to BOTH carrick and the Docker oracle, so the oracle
measures Linux semantics rather than Docker's cap set (the AGENTS.md
under-privileged-oracle rule). The probe is excused in `KNOWN_PROBE_GAPS`
until the re-stamp lands; the UNEXPECTED PASS guard forces that entry out
with the fix. `PROBE_SOURCE_COUNT` 465 -> 466 (generic 419 -> 420, gating
rows 878 -> 880). The oracle is the live Docker run (no probe-oracle cache
row: the committed cache is the small Docker-less-host set and
`bless_probe_oracle` has no per-probe filter).

Verified: red against the current signed binary — `vdso_stepped=false`,
`vdso_matches_syscall=false` under carrick versus all-true under
`docker run --cap-add SYS_TIME ubuntu:24.04` (phases run serially; the
oracle-cache row for `ltp-clock_settime01` under the same grant already
shows Docker advancing/receding the clock); `python3
scripts/probe-inventory.py check` clean; the denominator guard
`closure_probe_inventory_enforces_authoritative_runners_and_denominator`
red (466 vs 465) then green; `just conformance-probes` green with
`XFAIL arm64:musl:clocksettimevdso`.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01VJcvGV5u1ErqZREKWUy6rU
EOF
```

### Task 3: `clock_settime` re-stamps the vvar realtime word for every MM

**Files:**
- Modify: `crates/carrick-mem/src/vdso.rs:55-72` (add the ONE pure vvar-word helper `vvar_realtime_off_ns(host_off_ns, delta_ns)` after `pub fn realtime_off_ns`, whose closing `}` is line 72), a test appended inside `mod tests` (`:846-1068`; a second module `rosetta_vdso_size_test` follows at `:1070`). Nothing stateful moves into this crate: the guest offset static STAYS in `dispatch/mod.rs` (Phase B, Tasks 20-21, moves it into the container's `ClockDomain`, which a `carrick-mem` static could not become).
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs:2305-2324` (`DispatchMmAuthority` gains `vvar_realtime_epoch`; it has exactly two constructors, `new` and `fork_private`), `:4450-4480` (insert `sync_vvar_realtime_offset` / `set_guest_realtime` after `new_with_host_resolver`, before `pub(crate) fn begin_host_alias_dispatch` at `:4482`), `:5953-5960` (`dispatch_threaded` hook), `:6288-6298` (`dispatch_inner` hook), `:7529-7568` (the dispatch-local static gains an epoch; `realtime_duration` splits into `realtime_base_duration` + delta); the `realtime_test_support` helper from Task 1 is unchanged
- Modify: `crates/carrick-runtime/src/dispatch/time.rs:309-345` (`clock_settime`), `:785-816` (`settimeofday`); append `mod realtime_vvar_tests`
- Modify: `crates/carrick-runtime/src/vcpu_loop/exec.rs:1673-1684` (the post-exec identity-stamp site `super::stamp_identity_page_at(engine, &kernel.dispatcher, &committed_context, identity_base)`: the exec'd image's vvar is re-stamped there, before the new image runs its first instruction)
- Modify: `crates/carrick-cli/tests/conformance.rs:62-67` (remove the `KNOWN_PROBE_GAPS` excuse)
- Modify: `docs/syscalls-emulation-map.md:245`
- NOT touched: the four VMM vvar stampers — `crates/carrick-vmm-hvf/src/trap.rs:15745-15762` (`populate_vdso_data_page`), `crates/carrick-vmm-kvm/src/guest_setup.rs:1349,1369-1372` (`populate_vdso_vvar`), `crates/carrick-x86/src/vdso.rs:17-20,141-144` (`populate_vdso_vvar`), `crates/carrick-dsr-aarch64/src/mapped_memory.rs:1586` (`stamp_vdso_vvar`). They keep stamping the HOST calibration only (`realtime_off`, delta 0). A VMM crate cannot read a per-container delta (Phase B's `ClockDomain` lives in carrick-runtime), so folding the delta into those stampers would be dead the moment Phase B lands; the guest delta reaches every MM through the dispatcher's re-stamp instead (first syscall of a fresh/forked MM, the post-exec stamp site, and every epoch change).
- Test: unit tests under `just test`; the guest probe needs the signed binary (`just build` / `just conformance-probes`)

**Interfaces:**
- Consumes: `GuestMemory::write_bytes_unchecked(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError>` (`crates/carrick-guest-mem/src/lib.rs:598`, default = `write_bytes_raw`; the aarch64 engine's override at `crates/carrick-aarch64/src/engine.rs:1505-1523` does the `PrivilegedInternal` frame-COW split then `translated_write_unchecked`; an unmapped VA surfaces as `MemoryError::OutOfBounds` — the enum's only other variants are `Unsupported` and `HostMap`); `carrick_mem::vdso::{realtime_off_ns, set_realtime_off_ns, LINUX_VVAR_BASE: u64, VVAR_OFF_REALTIME_OFF_NS: usize}` (existing; `crate::vdso` in carrick-runtime is the `carrick_mem::vdso` re-export at `lib.rs:156`); `crate::dispatch::{get_guest_realtime_offset_ns, set_guest_realtime_offset_ns, realtime_duration}` (Task 1); `TaskRef::with_caps` (`crates/carrick-runtime/src/kernel/objects.rs:2971`) and `CapabilitySet { effective: u64, … }` (`namespace/process.rs:126`) in tests; `CAP_SYS_TIME: u32` (`namespace/process.rs:54`); `From<MemoryError> for DispatchError` (`dispatch/mod.rs:2069`); the handler macro binds `this = &self` and `cx: &mut SyscallCtx<M>` and returns `Result<DispatchOutcome, DispatchError>` (`dispatch/mod.rs:634-660`), so `?` on a `MemoryError` result is legal inside handlers; `vcpu_loop/mod.rs::stamp_identity_page_at<M: GuestMemory>(memory: &mut M, dispatcher: &SyscallDispatcher, kernel_context, base)` (`:1802`) and its post-exec caller at `vcpu_loop/exec.rs:1673`
- Produces (in `carrick_mem::vdso`): `pub fn vvar_realtime_off_ns(host_off_ns: u64, delta_ns: i64) -> u64` — the ONLY `VVAR_OFF_REALTIME_OFF_NS` word computation in the tree. (In `carrick_runtime::dispatch`): `pub(crate) fn guest_realtime_epoch() -> u64` (a `GUEST_REALTIME_EPOCH: AtomicU64` beside the existing `GUEST_REALTIME_OFFSET_NS`; `set_guest_realtime_offset_ns` now bumps it), `fn realtime_base_duration() -> Duration`, `pub(crate) fn SyscallDispatcher::sync_vvar_realtime_offset(&self, memory: &mut impl GuestMemory) -> Result<(), MemoryError>`, `pub(crate) fn SyscallDispatcher::set_guest_realtime(&self, memory: &mut impl GuestMemory, target: Duration) -> Result<(), MemoryError>`, `DispatchMmAuthority.vvar_realtime_epoch: AtomicU64`. Still ONE carrier-wide offset + epoch: Phase B (Tasks 20-21, B3's `ClockDomain { realtime_offset_ns: AtomicI64, epoch: AtomicU64 }`) moves both into the container, rewires `sync_vvar_realtime_offset` to compare the MM epoch against `task.container().clock().epoch()`, and deletes `GUEST_REALTIME_OFFSET_NS`, `get_/set_guest_realtime_offset_ns`, `realtime_duration`, `realtime_base_duration` and `realtime_test_support`; `carrick_mem::vdso::vvar_realtime_off_ns` and the per-MM epoch re-stamp survive unchanged.
- Production entry points the hook must cover: `vcpu_loop/mod.rs:7349` (`dispatch_threaded`, the HVPatch path, `memory` = the engine) and `runtime.rs:1405` / `dispatch()` → `dispatch_inner` (`dispatch/mod.rs:5780-5790`). `dispatch_threaded_independent` (the lockless hot path) is reached only after the hook. The post-exec identity stamp (`vcpu_loop/exec.rs:1673`) is the third entry: a freshly exec'd image must read the moved clock from its first instruction, before any syscall.

- [ ] **Step 1: Red test for the leaf vvar-word helper**

Append inside `mod tests` of `crates/carrick-mem/src/vdso.rs` (the module at `:846`, closing `}` at `:1068`):

```rust
    /// The vvar word is `host calibration + guest delta` in two's complement,
    /// so the vDSO's `counter_ns + word` yields the shifted wall clock. Pure:
    /// the delta is an argument, never a static in this crate.
    #[test]
    fn vvar_realtime_word_carries_the_guest_offset() {
        assert_eq!(vvar_realtime_off_ns(1_000, 0), 1_000);
        assert_eq!(vvar_realtime_off_ns(1_000, 3_600_000_000_000), 3_600_000_001_000);
        assert_eq!(vvar_realtime_off_ns(1_000, -2_000), 1_000u64.wrapping_sub(2_000));
    }
```

Run: `cargo test -p carrick-mem --lib vdso::tests`
Expected: compile error `cannot find function `vvar_realtime_off_ns``.

- [ ] **Step 2: Add the word helper to `carrick_mem::vdso`**

Insert after line 72 of `crates/carrick-mem/src/vdso.rs` (the closing `}` of `pub fn realtime_off_ns`):

```rust
/// The exact `u64` the vvar must carry at `VVAR_OFF_REALTIME_OFF_NS` for a host
/// calibration of `host_off_ns` (`unix_ns - counter_ns`) and a guest-settable
/// CLOCK_REALTIME delta of `delta_ns` (`clock_settime`/`settimeofday` under
/// CAP_SYS_TIME): the vDSO computes `realtime = counter_ns + word`, so the
/// guest delta rides inside the word (two's-complement wrapping add, so a
/// negative delta works). This is the ONLY place the word is computed; the
/// VMM stampers publish it with `delta_ns = 0` at vCPU construction (host
/// calibration only) and the runtime dispatcher re-stamps it per MM with the
/// live delta (`SyscallDispatcher::sync_vvar_realtime_offset`). The delta
/// itself is runtime state (carrier-wide today, the container's `ClockDomain`
/// in Phase B) and deliberately does not live in this crate.
pub fn vvar_realtime_off_ns(host_off_ns: u64, delta_ns: i64) -> u64 {
    host_off_ns.wrapping_add(delta_ns as u64)
}
```

Run: `cargo test -p carrick-mem --lib vdso::tests`
Expected: `test result: ok` including the new test.

- [ ] **Step 3: Give the dispatch-local offset an epoch and split `realtime_duration` (red, then green)**

Red first. Append inside `mod realtime_authority_tests` of `crates/carrick-runtime/src/dispatch/mod.rs` (the Task 1 module; add after `utimensat_utime_now_stamps_the_guest_clock`):

```rust
    /// Every offset change advances the epoch each MM compares against, so a
    /// sibling MM can tell "the clock moved since I last stamped my vvar"
    /// with one atomic load.
    #[test]
    fn every_offset_change_advances_the_epoch() {
        with_guest_realtime_offset(0, || {
            let start = guest_realtime_epoch();
            set_guest_realtime_offset_ns(5);
            set_guest_realtime_offset_ns(0);
            assert_eq!(guest_realtime_epoch(), start + 2);
            assert_eq!(get_guest_realtime_offset_ns(), 0);
        });
    }
```

Run: `env RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib every_offset_change_advances_the_epoch`
Expected: compile error `cannot find function `guest_realtime_epoch``.

Then in `crates/carrick-runtime/src/dispatch/mod.rs` replace lines 7529-7568 (post-Task-1 text):

```rust
static GUEST_REALTIME_OFFSET_NS: std::sync::atomic::AtomicI64 =
    std::sync::atomic::AtomicI64::new(0);

pub(crate) fn get_guest_realtime_offset_ns() -> i64 {
    GUEST_REALTIME_OFFSET_NS.load(std::sync::atomic::Ordering::SeqCst)
}

pub(crate) fn set_guest_realtime_offset_ns(delta_ns: i64) {
    GUEST_REALTIME_OFFSET_NS.store(delta_ns, std::sync::atomic::Ordering::SeqCst);
}

/// The guest's `CLOCK_REALTIME`: THE wall-clock authority for every realtime
/// consumer in the runtime (clock reads, absolute deadlines, file and IPC
/// stamps, `/proc` epochs). Nothing else in the runtime may read the host wall
/// clock for a guest-visible value.
pub(crate) fn realtime_duration() -> Duration {
    let offset_ns = get_guest_realtime_offset_ns();
    let base = {
        #[cfg(not(target_os = "linux"))]
        {
            if let Some(off_ns) = crate::vdso::realtime_off_ns()
                && let Some(uptime) = host_clock_duration(carrick_portable::CLOCK_UPTIME_RAW)
            {
                Duration::from_nanos((uptime.as_nanos() as u64).wrapping_add(off_ns))
            } else {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or(Duration::ZERO)
            }
        }
        #[cfg(target_os = "linux")]
        {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
        }
    };
    if offset_ns >= 0 {
        base.saturating_add(Duration::from_nanos(offset_ns as u64))
    } else {
        base.saturating_sub(Duration::from_nanos((-offset_ns) as u64))
    }
}
```

with:

```rust
/// The guest-settable CLOCK_REALTIME delta (`clock_settime`/`settimeofday`
/// under CAP_SYS_TIME), in nanoseconds, applied on top of the host
/// calibration published in `carrick_mem::vdso::realtime_off_ns`.
/// Carrier-wide: every Linux process in the carrier shares one wall clock, as
/// processes under one Linux kernel do. Phase B moves it (with its epoch)
/// into the container's `ClockDomain`. Two consumers must agree on it — the
/// syscall path (`realtime_duration`) and each MM's vvar word, which the
/// dispatcher re-stamps through `carrick_mem::vdso::vvar_realtime_off_ns`
/// (`SyscallDispatcher::sync_vvar_realtime_offset`).
static GUEST_REALTIME_OFFSET_NS: std::sync::atomic::AtomicI64 =
    std::sync::atomic::AtomicI64::new(0);

/// Bumped (Release) on every offset change, AFTER the new delta is stored, so
/// a reader that observes the new epoch (Acquire) also observes the new delta.
/// Each Linux MM records the epoch its vvar word was stamped under
/// (`DispatchMmAuthority::vvar_realtime_epoch`) and re-stamps itself when it
/// falls behind.
static GUEST_REALTIME_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub(crate) fn get_guest_realtime_offset_ns() -> i64 {
    GUEST_REALTIME_OFFSET_NS.load(std::sync::atomic::Ordering::SeqCst)
}

/// Publish a new guest CLOCK_REALTIME delta and advance the epoch.
pub(crate) fn set_guest_realtime_offset_ns(delta_ns: i64) {
    GUEST_REALTIME_OFFSET_NS.store(delta_ns, std::sync::atomic::Ordering::SeqCst);
    GUEST_REALTIME_EPOCH.fetch_add(1, std::sync::atomic::Ordering::Release);
}

/// The current offset epoch (see [`set_guest_realtime_offset_ns`]). Read on
/// every syscall entry by every MM: one Acquire load.
pub(crate) fn guest_realtime_epoch() -> u64 {
    GUEST_REALTIME_EPOCH.load(std::sync::atomic::Ordering::Acquire)
}

/// The guest's CLOCK_REALTIME WITHOUT the guest-settable delta: host
/// calibration only (`uptime + vvar host offset`, the same base the vDSO adds
/// its word to; the live wall clock when no vvar was ever stamped).
fn realtime_base_duration() -> Duration {
    #[cfg(not(target_os = "linux"))]
    {
        if let Some(off_ns) = crate::vdso::realtime_off_ns()
            && let Some(uptime) = host_clock_duration(carrick_portable::CLOCK_UPTIME_RAW)
        {
            Duration::from_nanos((uptime.as_nanos() as u64).wrapping_add(off_ns))
        } else {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
        }
    }
    #[cfg(target_os = "linux")]
    {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
    }
}

/// The guest's `CLOCK_REALTIME`: THE wall-clock authority for every realtime
/// consumer in the runtime (clock reads, absolute deadlines, file and IPC
/// stamps, `/proc` epochs). Nothing else in the runtime may read the host wall
/// clock for a guest-visible value. `realtime_base_duration` plus the guest
/// delta — the same delta the dispatcher folds into every MM's vvar word, so
/// the vDSO fast path and the trapping syscall agree.
pub(crate) fn realtime_duration() -> Duration {
    let offset_ns = get_guest_realtime_offset_ns();
    let base = realtime_base_duration();
    if offset_ns >= 0 {
        base.saturating_add(Duration::from_nanos(offset_ns as u64))
    } else {
        base.saturating_sub(Duration::from_nanos(offset_ns.unsigned_abs()))
    }
}
```

Run: `env RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib realtime`
Expected: every Task 1 test still passes (`realtime_authority_tests` now 3, `guest_realtime_offset_virtual_clock`); `every_offset_change_advances_the_epoch` green.

- [ ] **Step 4: Red dispatcher tests — the caller's vvar word and a sibling MM's**

Append at the end of `crates/carrick-runtime/src/dispatch/time.rs`:

```rust
#[cfg(test)]
mod realtime_vvar_tests {
    use super::*;
    use crate::dispatch::realtime_test_support::with_guest_realtime_offset;
    use crate::vdso::{LINUX_VVAR_BASE, VVAR_OFF_REALTIME_OFF_NS};

    /// A plausible `unix_ns - uptime_ns` host calibration.
    const HOST_OFF_NS: u64 = 1_700_000_000_000_000_000;
    const TIMESPEC_ADDR: u64 = LINUX_VVAR_BASE + 0x800;
    const VVAR_WORD_ADDR: u64 = LINUX_VVAR_BASE + VVAR_OFF_REALTIME_OFF_NS as u64;

    /// Install the fake host calibration for one test and clear it again on
    /// drop (also on panic), so a failing test cannot leak `HOST_OFF_NS` into
    /// every later carrick-runtime test in the same serial process.
    /// (`with_guest_realtime_offset` resets only the guest delta.)
    struct HostCalibration;

    impl HostCalibration {
        fn install() -> Self {
            crate::vdso::set_realtime_off_ns(HOST_OFF_NS);
            Self
        }
    }

    impl Drop for HostCalibration {
        fn drop(&mut self) {
            // 0 = "not calibrated": `realtime_off_ns()` reads back `None`.
            crate::vdso::set_realtime_off_ns(0);
        }
    }

    /// One guest page standing in for the vvar page, counting the
    /// carrick-internal (permission-bypassing) writes the dispatcher makes.
    struct VvarPage {
        page: LinearMemory,
        internal_writes: usize,
    }

    impl VvarPage {
        fn new() -> Self {
            Self {
                page: LinearMemory::new(LINUX_VVAR_BASE, vec![0u8; 0x1000]),
                internal_writes: 0,
            }
        }

        fn realtime_word(&self) -> u64 {
            let bytes = self.read_bytes(VVAR_WORD_ADDR, 8).expect("vvar word");
            u64::from_le_bytes(bytes.try_into().expect("8 bytes"))
        }
    }

    impl GuestMemory for VvarPage {
        fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
            self.page.read_bytes_raw(address, length)
        }

        fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
            self.page.write_bytes_raw(address, bytes)
        }

        fn write_bytes_unchecked(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
            self.internal_writes += 1;
            self.page.write_bytes_unchecked(address, bytes)
        }
    }

    fn grant_sys_time(context: &crate::kernel::KernelContext) {
        context.task().with_caps(|caps| {
            caps.effective |= 1u64 << crate::namespace::process::CAP_SYS_TIME;
        });
    }

    /// Dispatch `clock_settime(CLOCK_REALTIME, guest_now + 1h)` on `dispatcher`.
    fn step_clock_one_hour(
        dispatcher: &mut SyscallDispatcher,
        context: &crate::kernel::KernelContext,
        memory: &mut VvarPage,
    ) {
        let target = realtime_duration() + Duration::from_secs(3_600);
        memory
            .write_bytes(
                TIMESPEC_ADDR,
                LinuxTimespec::new(target.as_secs() as i64, i64::from(target.subsec_nanos()))
                    .as_bytes(),
            )
            .expect("timespec fits the page");
        let outcome = dispatcher
            .dispatch(
                context,
                SyscallRequest::new(
                    112,
                    SyscallArgs([LINUX_CLOCK_REALTIME, TIMESPEC_ADDR, 0, 0, 0, 0]),
                ),
                memory,
                &CompatReporter::default(),
            )
            .expect("clock_settime dispatches");
        assert!(
            matches!(outcome, DispatchOutcome::Returned { value: 0 }),
            "clock_settime under CAP_SYS_TIME: {outcome:?}"
        );
    }

    fn expected_word() -> u64 {
        crate::vdso::vvar_realtime_off_ns(
            HOST_OFF_NS,
            crate::dispatch::get_guest_realtime_offset_ns(),
        )
    }

    /// After `clock_settime` the CALLER's vvar word already carries the new
    /// delta — a vDSO read issued right after the syscall returns agrees with
    /// the syscall path.
    #[test]
    fn clock_settime_restamps_the_callers_vvar_word() {
        with_guest_realtime_offset(0, || {
            let _calibration = HostCalibration::install();
            let mut dispatcher = SyscallDispatcher::new();
            let context = dispatcher.capture_one_task_context().expect("task context");
            grant_sys_time(&context);
            let mut memory = VvarPage::new();

            step_clock_one_hour(&mut dispatcher, &context, &mut memory);

            let delta = crate::dispatch::get_guest_realtime_offset_ns();
            assert!(
                (3_599_000_000_000..=3_601_000_000_000).contains(&delta),
                "delta {delta}"
            );
            assert_eq!(memory.realtime_word(), expected_word());
        });
    }

    /// A DIFFERENT MM (another dispatcher, i.e. another Linux process) has its
    /// own vvar page. It re-stamps itself on its next syscall entry — once —
    /// and not again while the offset is unchanged.
    #[test]
    fn a_sibling_mm_restamps_its_vvar_on_its_next_syscall() {
        with_guest_realtime_offset(0, || {
            let _calibration = HostCalibration::install();
            let mut setter = SyscallDispatcher::new();
            let setter_context = setter.capture_one_task_context().expect("task context");
            grant_sys_time(&setter_context);
            let mut setter_memory = VvarPage::new();
            step_clock_one_hour(&mut setter, &setter_context, &mut setter_memory);

            let mut sibling = SyscallDispatcher::new();
            let sibling_context = sibling.capture_one_task_context().expect("task context");
            let mut sibling_memory = VvarPage::new();
            let read_clock = |sibling: &mut SyscallDispatcher, memory: &mut VvarPage| {
                sibling
                    .dispatch(
                        &sibling_context,
                        SyscallRequest::new(
                            113,
                            SyscallArgs([LINUX_CLOCK_REALTIME, TIMESPEC_ADDR, 0, 0, 0, 0]),
                        ),
                        memory,
                        &CompatReporter::default(),
                    )
                    .expect("clock_gettime dispatches");
            };

            read_clock(&mut sibling, &mut sibling_memory);
            assert_eq!(sibling_memory.realtime_word(), expected_word());
            assert_eq!(sibling_memory.internal_writes, 1, "one re-stamp on the first entry");

            read_clock(&mut sibling, &mut sibling_memory);
            assert_eq!(sibling_memory.internal_writes, 1, "no re-stamp while the epoch is unchanged");
        });
    }
}
```

(`SyscallArgs` is `pub struct SyscallArgs(pub [u64; 6])` in `carrick-observability/src/compat.rs:62`; `CompatReporter: Default` at `:241`; `LinuxTimespec::as_bytes` is zerocopy `IntoBytes`, imported in `dispatch/mod.rs:632` and reachable through `use super::*`; `SyscallDispatcher::dispatch(&mut self, &KernelContext, SyscallRequest, &mut impl GuestMemory, &CompatReporter)` at `dispatch/mod.rs:5780` calls `dispatch_inner`; `capture_one_task_context(&self)` returns an owned `KernelContext` and each `SyscallDispatcher::new()` bootstraps its own task graph, as `rlimit_tests` in this file already relies on.)

Run: `env RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib realtime_vvar_tests`
Expected: both FAILED — `assertion failed: left: 0, right: 1700000003600000000000…` (the word is never written) and `one re-stamp on the first entry: left: 0, right: 1`.

- [ ] **Step 5: Give each MM authority a stamped epoch and add the dispatcher helpers**

In `crates/carrick-runtime/src/dispatch/mod.rs` replace lines 2305-2324:

```rust
pub(crate) struct DispatchMmAuthority {
    mem: Arc<mem::MemAuthority>,
    host_alias_transactions: Arc<HostAliasTransactions>,
}

impl DispatchMmAuthority {
    fn new() -> Self {
        Self {
            mem: Arc::new(mem::MemAuthority::new(mem::MemState::new())),
            host_alias_transactions: Arc::new(HostAliasTransactions::new()),
        }
    }

    fn fork_private(&self) -> Self {
        Self {
            mem: self.mem.fork_private(),
            host_alias_transactions: Arc::new(HostAliasTransactions::new()),
        }
    }
```

with:

```rust
pub(crate) struct DispatchMmAuthority {
    mem: Arc<mem::MemAuthority>,
    host_alias_transactions: Arc<HostAliasTransactions>,
    /// The `guest_realtime_epoch()` under which THIS MM's vvar
    /// `VVAR_OFF_REALTIME_OFF_NS` word was last stamped by the dispatcher
    /// (`SyscallDispatcher::sync_vvar_realtime_offset`). The vvar page is per
    /// MM (it also carries the per-process RNG generation), so the stamp state
    /// is MM state. `u64::MAX` = never: a fresh or forked MM re-stamps once on
    /// its first syscall (or at the post-exec identity stamp), an idempotent
    /// 8-byte write of the word the VMM stamper already published when the
    /// delta is 0 (a fork child's vvar frame is already COW-split by the
    /// HVPatch RNG-generation re-stamp, `trap.rs:11281`).
    vvar_realtime_epoch: std::sync::atomic::AtomicU64,
}

impl DispatchMmAuthority {
    fn new() -> Self {
        Self {
            mem: Arc::new(mem::MemAuthority::new(mem::MemState::new())),
            host_alias_transactions: Arc::new(HostAliasTransactions::new()),
            vvar_realtime_epoch: std::sync::atomic::AtomicU64::new(u64::MAX),
        }
    }

    fn fork_private(&self) -> Self {
        Self {
            mem: self.mem.fork_private(),
            host_alias_transactions: Arc::new(HostAliasTransactions::new()),
            vvar_realtime_epoch: std::sync::atomic::AtomicU64::new(u64::MAX),
        }
    }
```

Insert after line 4480 (the closing `}` of `fn new_with_host_resolver`, immediately before `pub(crate) fn begin_host_alias_dispatch` at `:4482`):

```rust
    /// Keep the CALLING MM's vvar `VVAR_OFF_REALTIME_OFF_NS` word coherent with
    /// the guest realtime offset, so the userspace vDSO `clock_gettime` and the
    /// trapping syscall agree after `clock_settime` / `settimeofday`.
    ///
    /// The vvar page is per MM, and a foreign MM has no stage-1 walker bound to
    /// it, so a change cannot be broadcast from the setter. Instead every MM
    /// re-stamps ITSELF at its next syscall entry when the global epoch has
    /// moved (and at the post-exec identity stamp, so an exec'd image reads
    /// the moved clock before its first syscall). Per-syscall cost when
    /// nothing changed: one Acquire load of the epoch, one `ArcSwap::load` of
    /// the current MM authority and one Acquire load — no write, no lock. One
    /// 8-byte carrick-internal write per MM per change. The setter's own MM is
    /// stamped inline by [`Self::set_guest_realtime`] before the syscall
    /// returns, so a vDSO read issued right after it already agrees.
    ///
    /// The VMM stampers publish the host calibration only; the guest delta
    /// enters the word here, through the single
    /// `carrick_mem::vdso::vvar_realtime_off_ns` computation.
    ///
    /// `write_bytes_unchecked` bypasses the guest-visible read-only permission
    /// of the vvar and splits a fork-shared frame (`PrivilegedInternal`), like
    /// the RNG-generation re-stamp. An MM with no vvar mapped at
    /// `LINUX_VVAR_BASE` (`CARRICK_DISABLE_VDSO=1`, the relocated native-lane
    /// vvar) has nothing to keep coherent: `OutOfBounds` at that fixed VA means
    /// exactly that (the aarch64 engine's `syscall_buffer_chunk` reports an
    /// unmapped VA as `OutOfBounds`) and is not an error. Any other failure is.
    pub(crate) fn sync_vvar_realtime_offset(
        &self,
        memory: &mut impl GuestMemory,
    ) -> Result<(), MemoryError> {
        let epoch = guest_realtime_epoch();
        let authority = self.mm_binding.current.load();
        if authority
            .vvar_realtime_epoch
            .load(std::sync::atomic::Ordering::Acquire)
            == epoch
        {
            return Ok(());
        }
        if let Some(host_off_ns) = crate::vdso::realtime_off_ns() {
            let word =
                crate::vdso::vvar_realtime_off_ns(host_off_ns, get_guest_realtime_offset_ns());
            match memory.write_bytes_unchecked(
                crate::vdso::LINUX_VVAR_BASE + crate::vdso::VVAR_OFF_REALTIME_OFF_NS as u64,
                &word.to_le_bytes(),
            ) {
                Ok(()) | Err(MemoryError::OutOfBounds { .. }) => {}
                Err(error) => return Err(error),
            }
        }
        authority
            .vvar_realtime_epoch
            .store(epoch, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    /// `clock_settime(CLOCK_REALTIME)` / `settimeofday`: move the guest wall
    /// clock so that "now" reads `target`, then stamp the caller's vvar at once.
    /// The delta is measured against the host-calibrated base, never against a
    /// transiently-zeroed offset, so concurrent readers never observe a
    /// momentary jump back to host time.
    pub(crate) fn set_guest_realtime(
        &self,
        memory: &mut impl GuestMemory,
        target: Duration,
    ) -> Result<(), MemoryError> {
        let base = realtime_base_duration();
        let delta_ns = if target >= base {
            i64::try_from((target - base).as_nanos()).unwrap_or(i64::MAX)
        } else {
            i64::try_from((base - target).as_nanos())
                .map(|n| -n)
                .unwrap_or(i64::MIN)
        };
        set_guest_realtime_offset_ns(delta_ns);
        self.sync_vvar_realtime_offset(memory)
    }
```

Hook the multi-threaded path: in `dispatch_threaded` (lines 5953-5960) replace:

```rust
        // seccomp veto applies on the multi-threaded path too (filters are
        // process-wide), before any handler — including the lockless hot path.
        if let Some(outcome) = self.seccomp_precheck(&request) {
            return Ok(outcome);
        }
        if let Some(result) = self
            .dispatch_threaded_independent(kernel, request, memory, reporter, tid, registry, futex)
        {
            return result;
        }
```

with:

```rust
        // seccomp veto applies on the multi-threaded path too (filters are
        // process-wide), before any handler — including the lockless hot path.
        if let Some(outcome) = self.seccomp_precheck(&request) {
            return Ok(outcome);
        }
        // The calling MM's vDSO realtime word follows a guest `clock_settime`
        // made by any process (one atomic compare when nothing changed).
        if let Err(error) = self.sync_vvar_realtime_offset(memory) {
            tracing::error!("vvar realtime re-stamp failed: {error}");
            return Err(DispatchError::from(error));
        }
        if let Some(result) = self
            .dispatch_threaded_independent(kernel, request, memory, reporter, tid, registry, futex)
        {
            return result;
        }
```

Hook the single-threaded path: in `dispatch_inner` (lines 6288-6298) replace:

```rust
        // seccomp: installed cBPF filters get to veto the syscall before its
        // handler runs (ERRNO / kill), mirroring the kernel's pre-syscall check.
        if let Some(outcome) = self.seccomp_precheck(&request) {
            let (retval, errno) = outcome.retval_errno();
            reporter.record(CompatEvent::SyscallReturn {
                number: request.number.raw(),
                name: ::std::borrow::Cow::Borrowed(name),
                retval,
                errno,
            });
            return Ok(outcome);
        }
```

with:

```rust
        // seccomp: installed cBPF filters get to veto the syscall before its
        // handler runs (ERRNO / kill), mirroring the kernel's pre-syscall check.
        if let Some(outcome) = self.seccomp_precheck(&request) {
            let (retval, errno) = outcome.retval_errno();
            reporter.record(CompatEvent::SyscallReturn {
                number: request.number.raw(),
                name: ::std::borrow::Cow::Borrowed(name),
                retval,
                errno,
            });
            return Ok(outcome);
        }
        // The calling MM's vDSO realtime word follows a guest `clock_settime`
        // made by any process (see `dispatch_threaded`).
        if let Err(error) = self.sync_vvar_realtime_offset(memory) {
            tracing::error!("vvar realtime re-stamp failed: {error}");
            return Err(DispatchError::from(error));
        }
```

- [ ] **Step 6: Make the two handlers set the clock through `set_guest_realtime`**

In `crates/carrick-runtime/src/dispatch/time.rs` replace lines 328-343 (the post-Task-1 text; the handlers still call the bare `set_guest_realtime_offset_ns` reached through `use super::*`):

```rust
            if clock_id == LINUX_CLOCK_REALTIME {
                let target_secs = timespec.tv_sec.max(0) as u64;
                let target_nanos = (timespec.tv_nsec as u32).min(999_999_999);
                let target_duration = Duration::new(target_secs, target_nanos);
                let raw_now = {
                    set_guest_realtime_offset_ns(0);
                    realtime_duration()
                };
                let delta_ns = if target_duration >= raw_now {
                    (target_duration - raw_now).as_nanos() as i64
                } else {
                    -((raw_now - target_duration).as_nanos() as i64)
                };
                set_guest_realtime_offset_ns(delta_ns);
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
```

with:

```rust
            if clock_id == LINUX_CLOCK_REALTIME {
                let target_secs = timespec.tv_sec.max(0) as u64;
                let target_nanos = (timespec.tv_nsec as u32).min(999_999_999);
                // Moves the carrier-wide guest wall clock and re-stamps THIS
                // MM's vvar so a vDSO read right after the syscall agrees;
                // other MMs re-stamp at their next syscall entry
                // (`sync_vvar_realtime_offset`). Probe: clocksettimevdso.
                this.set_guest_realtime(&mut *cx.memory, Duration::new(target_secs, target_nanos))?;
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
```

(`let memory = &*cx.memory;` at line 310 stays: its last use is `read_timespec(memory, address.0)?` at line 314, so the later `&mut *cx.memory` reborrow is legal. `this` is `&SyscallDispatcher` per the `define_syscall!` macro; `?` converts `MemoryError` via `From<MemoryError> for DispatchError`.)

Replace lines 802-815 in `settimeofday`:

```rust
            let target_secs = tv_sec.max(0) as u64;
            let target_nanos = (tv_usec as u32) * 1000;
            let target_duration = Duration::new(target_secs, target_nanos);
            let raw_now = {
                set_guest_realtime_offset_ns(0);
                realtime_duration()
            };
            let delta_ns = if target_duration >= raw_now {
                (target_duration - raw_now).as_nanos() as i64
            } else {
                -((raw_now - target_duration).as_nanos() as i64)
            };
            set_guest_realtime_offset_ns(delta_ns);
            Ok(DispatchOutcome::Returned { value: 0 })
```

with:

```rust
            let target_secs = tv_sec.max(0) as u64;
            let target_nanos = (tv_usec as u32) * 1000;
            this.set_guest_realtime(&mut *cx.memory, Duration::new(target_secs, target_nanos))?;
            Ok(DispatchOutcome::Returned { value: 0 })
```

(`let memory = &*cx.memory;` at line 786 is last used by `memory.read_bytes(timeval.0, 16)?` at line 796.)

Run: `env RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib realtime`
Expected: `realtime_vvar_tests` (2), `realtime_authority_tests` (3) and `guest_realtime_offset_virtual_clock` all pass.

- [ ] **Step 7: Re-stamp the exec'd image's vvar at the post-exec identity stamp**

The VMM stampers are NOT edited: they keep publishing the host calibration only (delta 0). A freshly exec'd image's vvar is therefore stamped with the pre-step word until the dispatcher re-stamps it, and its MM authority starts at epoch `u64::MAX`, so its FIRST syscall would re-stamp it — but a vDSO `clock_gettime` issued before that first syscall (ld.so and libc init read the clock only after several syscalls in practice, yet nothing guarantees it) would read the old clock. Close that window at the same site that re-stamps the identity page for the new image.

In `crates/carrick-runtime/src/vcpu_loop/exec.rs` replace lines 1673-1684:

```rust
        if let Err(error) = super::stamp_identity_page_at(
            engine,
            &kernel.dispatcher,
            &committed_context,
            identity_base,
        ) {
            return Self::exec_failed_past_no_return(
                kernel,
                engine,
                &format!("stamp HVPatch exec identity page: {error}"),
            )
            .map(Some);
        }
```

with:

```rust
        if let Err(error) = super::stamp_identity_page_at(
            engine,
            &kernel.dispatcher,
            &committed_context,
            identity_base,
        ) {
            return Self::exec_failed_past_no_return(
                kernel,
                engine,
                &format!("stamp HVPatch exec identity page: {error}"),
            )
            .map(Some);
        }
        // The new image's vvar was published with the host calibration only;
        // fold in the guest CLOCK_REALTIME delta before the image runs its
        // first instruction, so a vDSO read before any syscall already agrees
        // with the syscall path (`sync_vvar_realtime_offset`; probe
        // clocksettimevdso, `date -s` followed by an exec'd `date`).
        if let Err(error) = kernel.dispatcher.sync_vvar_realtime_offset(engine) {
            return Self::exec_failed_past_no_return(
                kernel,
                engine,
                &format!("stamp HVPatch exec vvar realtime word: {error}"),
            )
            .map(Some);
        }
```

(`engine` is the `&mut M: GuestMemory` already passed to `stamp_identity_page_at`; `kernel.dispatcher` is the `SyscallDispatcher` the same call borrows. `sync_vvar_realtime_offset` tolerates an MM without a vvar at `LINUX_VVAR_BASE`, so `CARRICK_DISABLE_VDSO=1` images are unaffected.)

Run: `just check && just clippy`
Expected: both exit 0. This compiles carrick-mem, carrick-runtime and every VMM crate that is a macOS workspace member; no VMM stamper was edited, so no Linux-host compile check is needed for this task.

Live check of the exec'd-process case (signed binary; not concurrently with Docker). `date -s` is a `clock_settime` from one process and the following `date` is a NEW exec'd process reading through its vDSO:

```bash
just build
CARRICK_RUN_ID=cr-clocksettime-exec target/release/carrick run --platform linux/arm64 --raw --fs host \
  --cap-add SYS_TIME docker.io/library/ubuntu:24.04 \
  /bin/sh -c 'a=$(date +%s); date -s "@$((a + 3600))" >/dev/null; b=$(date +%s); date -s "@$(( $(date +%s) - 3600 ))" >/dev/null; echo "exec_diff=$((b - a))"'
```
Expected: `exec_diff=3600` (or 3601). Before this step (Steps 1-6 only) the exec'd `date` still reads the moved clock in practice because coreutils' `date` issues syscalls before its `clock_gettime`, so this command is a guard for the guarantee rather than a red-first reproducer; the red-first evidence for the task is Step 4 plus the Step 8 probe. State that plainly in the commit body.

- [ ] **Step 8: Unit gates, then the live guest probe (green)**

Run: `just fmt && just clippy && just lint-domains && just test`
Expected: all exit 0; the carrick-runtime serial pass includes `realtime_vvar_tests`, `realtime_authority_tests`, mqueue/sysv/proc clock tests.

Run:
```bash
just build
CARRICK_RUN_ID=cr-clocksettime-green target/release/carrick run --platform linux/arm64 --raw --fs host \
  --cap-add SYS_TIME docker.io/library/ubuntu:24.04 \
  /bin/sh -c 'base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p' \
  < <(base64 < conformance-probes/target/aarch64-unknown-linux-musl/release/clocksettimevdso)
```
Expected:
```
settime_ok=true
syscall_stepped=true
vdso_stepped=true
vdso_matches_syscall=true
restored=true
```
Confirm the new code is in the signed binary first: `strings target/release/carrick | grep -c 'vvar realtime re-stamp failed'` prints a non-zero count (the literal sits at two hook sites; the linker may or may not merge them, so 1 or 2 — 0 means a stale binary).

- [ ] **Step 9: Remove the known-gap excuse and run the probe gate**

In `crates/carrick-cli/tests/conformance.rs` replace lines 62-67:

```rust
    // epollstaledel FIXED in M3 (pending_ready keyed by fd) — now PASSES.
    // clocksettimevdso: clock_settime moves the syscall-path offset but never
    // re-stamps VVAR_OFF_REALTIME_OFF_NS, so the vDSO CLOCK_REALTIME lags the
    // syscall by the full step. Fixed by the embed Phase A vvar re-stamp
    // (removed in the same commit that lands it).
    "clocksettimevdso",
];
```

with:

```rust
    // epollstaledel FIXED in M3 (pending_ready keyed by fd) — now PASSES.
    // clocksettimevdso FIXED (embed Phase A: per-MM vvar realtime re-stamp) — now PASSES.
];
```

Focused first:

Run: `CARRICK_PROBE_FILTER=clocksettimevdso just conformance-probes 2>&1 | tee target/conformance/task3-probe-focused.log; echo "status=${PIPESTATUS[0]}"`
Expected: `status=0`; `grep -a 'clocksettimevdso' target/conformance/task3-probe-focused.log` shows `PASS arm64:musl:clocksettimevdso` (and the gnu report-only row) and no `UNEXPECTED PASS`.

Then the full gate:

Run: `just conformance-probes 2>&1 | tee target/conformance/task3-probe-gate.log; echo "status=${PIPESTATUS[0]}"`
Expected: `status=0`; `grep -a -E '^(FAIL|UNEXPECTED PASS)' target/conformance/task3-probe-gate.log` prints nothing (gating failures print `FAIL {lane}:{libc}:{probe}`; report-only rows print `DIFF …`). Read the whole log, never a tail.

- [ ] **Step 10: Update the emulation map row**

In `docs/syscalls-emulation-map.md` replace line 245:

```markdown
| `clock_settime`, `settimeofday`, `clock_adjtime`, `adjtimex` | 112,170,266,171 | Emulated (Partial) | EPERM (no CAP_SYS_TIME) | Unprivileged set → EPERM, matching Linux. |
```

with:

```markdown
| `clock_settime`, `settimeofday`, `clock_adjtime`, `adjtimex` | 112,170,266,171 | Emulated (Partial) | carrier-wide CLOCK_REALTIME delta (`dispatch/mod.rs`), re-stamped into each MM's vvar word by the dispatcher | Needs `CAP_SYS_TIME` (`--cap-add SYS_TIME`), else EPERM like Linux. vDSO and syscall reads agree after a step (probe `clocksettimevdso`); `adjtimex`/`clock_adjtime` are read-state only. |
```

- [ ] **Step 11: Commit**

```bash
just fmt
git add crates/carrick-mem/src/vdso.rs \
        crates/carrick-runtime/src/dispatch/mod.rs \
        crates/carrick-runtime/src/dispatch/time.rs \
        crates/carrick-runtime/src/vcpu_loop/exec.rs \
        crates/carrick-cli/tests/conformance.rs \
        docs/syscalls-emulation-map.md
git commit -F - <<'EOF'
fix(runtime): re-stamp the vDSO realtime word when the guest sets the clock

Why: `clock_settime(CLOCK_REALTIME)` / `settimeofday` moved
`GUEST_REALTIME_OFFSET_NS`, which only the trapping syscall path consulted.
The vDSO computes CLOCK_REALTIME as `CNTVCT/freq + VVAR_OFF_REALTIME_OFF_NS`
from a word stamped once at process construction, so after a step libc's
`clock_gettime` (vDSO) and the raw syscall disagreed by the full step, and a
process exec'd after the step read the OLD clock from its first
instruction. Linux has one wall-clock authority visible through both routes
(probe `clocksettimevdso`, red in the previous commit).

What:
- `carrick_mem::vdso::vvar_realtime_off_ns(host_off_ns, delta_ns)` is the
  ONE computation of the vvar word. The VMM stampers (HVF, KVM, x86, native
  DSR) are untouched and keep publishing the host calibration only: a VMM
  crate cannot see the guest delta, which stays runtime state
  (`dispatch/mod.rs`, still one carrier-wide static; Phase B moves it and
  its epoch into the container's `ClockDomain`).
- `set_guest_realtime_offset_ns` bumps an epoch (Release; Acquire on read).
  Each `DispatchMmAuthority` (one per Linux MM) records the epoch its vvar
  word was stamped under; `SyscallDispatcher::sync_vvar_realtime_offset`
  runs at every syscall entry (`dispatch_threaded` and `dispatch_inner`)
  and at the post-exec identity stamp (`vcpu_loop/exec.rs`) and, when
  behind, writes the word through `GuestMemory::write_bytes_unchecked`
  (privileged frame-COW split + permission bypass, like the RNG-generation
  re-stamp). Cost when nothing changed: one Acquire epoch load, one
  `ArcSwap::load`, one compare. `OutOfBounds` at the fixed vvar VA means no
  vvar is mapped in this MM (`CARRICK_DISABLE_VDSO=1`, the relocated
  native-lane vvar) and is not an error.
- The setter's own MM is stamped inline by `SyscallDispatcher::
  set_guest_realtime` before the syscall returns; the delta is measured
  against `realtime_base_duration` (host calibration only), removing the
  handlers' transient zeroing of the offset that other threads could
  observe.

Approximation, stated plainly: a sibling process that never issues another
syscall keeps reading the pre-step clock through its vDSO until it does;
Linux's single shared vvar page updates every process at once. The native
(DSR) lane maps its vvar at a relocated VA and does not re-stamp live.

Verified: red-first unit tests `realtime_vvar_tests::{clock_settime_
restamps_the_callers_vvar_word, a_sibling_mm_restamps_its_vvar_on_its_
next_syscall}` (word never written, then written once per epoch),
`realtime_authority_tests::every_offset_change_advances_the_epoch`, leaf
test `vdso::tests::vvar_realtime_word_carries_the_guest_offset`; `just
test`, `just clippy`, `just lint-domains` clean; signed binary runs
`clocksettimevdso` all-true matching `docker run --cap-add SYS_TIME`; the
exec'd-process guard (`date -s` then an exec'd `date`) reports the moved
clock (a guarantee check, not a red-first reproducer: coreutils' `date`
issues syscalls before reading the clock, so the per-MM first-syscall
re-stamp already covered it); `just conformance-probes` green with
`PASS arm64:musl:clocksettimevdso` and the known-gap excuse removed.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01VJcvGV5u1ErqZREKWUy6rU
EOF
```

- [ ] **Step 12: Full local gate before pushing**

Run: `just ci 2>&1 | tee target/ci-task3.log; echo "status=${PIPESTATUS[0]}"`
Expected: `status=0` (check-frame-pointers → fmt-check → clippy → lint-domains → deny → check-matrix → check → doc → test → test-integration all green). Read the log in full; a red early step masks later ones.


<details><summary>Verifier problems fixed in place (14) and claims still unverified (7)</summary>

- fixed: STALE HEAD: the draft cites HEAD 3dc6cc72 but the checkout is 39426141 (33 commits later, 3dc6cc72 is an ancestor). dispatch/mod.rs (+51), mqueue.rs (+127), sysv.rs (+44), carrick-vmm-hvf/src/trap.rs (+128) and carrick-cli/src/args.rs changed since, so most mod.rs/mqueue/trap line numbers were off by 20-100 lines (e.g. relative_from_absolute_timespec 6567->6616, realtime_duration 7491->7540, now_realtime_timespec 8870->8919, end of exec_vector_tests 8937->8986, mqueue deadline_expired 1085->1106, sysv semop/semctl stamps 3996->3999 and 4060->4063, ipc_set_tests 4346->4350, proc boot_epoch_secs 2863->2865, DispatchMmAuthority 2257->2305, new_with_host_resolver end 4432->4480, dispatch_threaded hook 5901->5953, dispatch_inner seccomp block 6241->6288, GUEST_REALTIME_OFFSET_NS 7480->7529, trap.rs populate_vdso_data_page stamp 15647->15745, objects.rs with_caps 2967->2971, PROBE_SOURCE_COUNT const 3256->3251). Every quoted 'existing text' block DOES match the tree verbatim; all line numbers rewritten to 39426141.
- fixed: Task 3 Step 7 compile-closure command is wrong: `cargo check -p carrick-runtime --no-default-features --features platform-linux` fails because carrick-runtime has no `platform-linux` feature (it lives on carrick-cli; see justfile `_platform_features`). Moreover carrick-vmm-kvm is `#![cfg(target_os = "linux")]` (cfg-empty on macOS), so NO macOS command compiles guest_setup.rs; carrick-x86's vdso.rs IS a workspace member compiled by `just clippy` on macOS. Replaced with `just check && just clippy` on macOS plus an explicit Linux-host/lima `cargo check -p carrick-cli --no-default-features --features syscall-shim,platform-linux` for the KVM stamper, and an honesty note for the commit body if that box is unavailable.
- fixed: Task 2 Step 8 (bless) is wrong for this tree: `bless_probe_oracle` has no per-probe filter and runs the Docker oracle for EVERY probe binary of every lane/set, writing hundreds of new files (the committed cache holds 9 hand-picked arm64-musl rows and no arm64-gnu directory exists). The gate prefers the cache but runs live Docker on a miss whenever Docker is reachable (conformance.rs:4556-4562), so no bless is needed. Removed the step, the two 'Create (by the bless step)' oracle files, and their `git add`; renumbered and reworded the commit body.
- fixed: Task 2 'Test:' line used `cargo test ... conformance probe_capabilities` — libtest filters match TEST NAMES, and the test is `clock_settime_probe_is_granted_cap_sys_time_on_both_sides`; fixed to `clock_settime_probe_is_granted`.
- fixed: Task 2 'unverified' item about Docker honouring clock_settime under `--cap-add SYS_TIME` is answerable from the tree: scripts/conformance/oracle-cache.jsonl row `ltp-clock_settime01` with docker_flags `--cap-add SYS_TIME` records 4/4 pass (`was_able_to_advance_time`, `was_able_to_recede_time`) on the arm64 Docker oracle. Added as evidence to Step 6. Conversely scripts/conformance/baseline.jsonl records CARRICK as TBROK x3 on that same (non-gating) LTP case, so the carrick red run may print `settime_ok=false`; added an attribution note (that would be a separate cap-grant/handler defect to root-cause first, never something to fold into the excuse).
- fixed: Task 3 Step 8 `strings … | grep -c 'vvar realtime re-stamp failed'` 'prints 1' is unsafe: the literal appears at two hook sites and the linker may or may not merge them; changed to 'prints a non-zero count'.
- fixed: Task 1 Step 12 ran `env RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib` directly, bypassing the `just test` recipe's `CARRICK_DSR_STORE_DIR` isolation (guest-running runtime tests would publish into the real persistent store). Changed to `just test`; focused runs keep `--test-threads=1` and are explicitly scratch-only.
- fixed: Task 3 `realtime_vvar_tests` reset the fake host calibration with a trailing `crate::vdso::set_realtime_off_ns(0)` that is skipped on panic, leaking `HOST_OFF_NS` into every later carrick-runtime test in the same serial process (`with_guest_realtime_offset` resets only the guest delta). Added a `HostCalibration` drop guard.
- fixed: Task 3 Step 2 insertion point: the closing brace of `pub fn realtime_off_ns` is vdso.rs line 72 (73 is blank); fixed.
- fixed: Task 1 Step 11 quoted the `#[test]` attribute but gave the range 1504-1514; the attribute is line 1503; fixed to 1503-1514.
- fixed: Task 2 Step 5 / Step 9: `scripts/build-probes.sh` on macOS/arm64 builds inside rust:alpine / rust:bookworm containers (a Docker phase, must not overlap a carrick run), and `just conformance-probes` only invokes it on x86_64 hosts — so Step 5 is mandatory before the gate on the Mac. Added both notes.
- fixed: Task 2 Step 4 expected census wording: the checker prints `probe inventory checked: 466 sources {'conformance': 440, 'helper': 1, 'performance': 25}`; fixed.
- fixed: Hot-path cost (AGENTS.md zero-overhead gate): `sync_vvar_realtime_offset` adds a SeqCst epoch load plus an `ArcSwap::load` to EVERY syscall entry. Made the epoch accessors Acquire/Release (offset store stays SeqCst and precedes the bump, so readers that see the new epoch see the new delta) and documented the per-syscall cost explicitly in the doc comment so it is measured, not assumed.
- fixed: Minor: added `CARRICK_PROBE_FILTER=clocksettimevdso` focused gate runs (the harness accepts a comma list, conformance.rs:3196) before each full `just conformance-probes`, and stated that the gating failure line format is `FAIL {qualified}` (report-only gnu prints `DIFF`).
- UNVERIFIED: That Docker Desktop's LinuxKit VM honours `clock_settime` for a container root granted `--cap-add SYS_TIME` (the probe's oracle side). Docker's default seccomp profile lists clock_settime/settimeofday as cap-conditional on CAP_SYS_TIME, and `crates/carrick-conformance/src/generate.rs:136` already grants SYS_TIME to `ltp-clock_settime01`, but I could not run Docker. Task 2 Step 6 checks `settime_ok=true` on the oracle before blessing and stops otherwise.
- UNVERIFIED: That dispatching syscall 113 (`clock_gettime`) through `SyscallDispatcher::dispatch` on a bare `SyscallDispatcher::new()` + `capture_one_task_context()` works without further kernel setup in the sibling-MM unit test; the mqueue and time.rs tests dispatch other numbers through the same entry, but 113 specifically was not exercised in a test I read. If it needs process state, any pure syscall (e.g. 172 getpid) serves the same purpose.
- UNVERIFIED: That the `#[allow]`-free `struct ResetOnDrop { _guard: MutexGuard<'static, ()> }` and the `VvarPage` mock compile clean under `-D warnings` (dead-code on a held-only field is suppressed by the underscore prefix; not compiled here — READ-ONLY brief).
- UNVERIFIED: The 20 s step / 5 s tolerance constants: chosen so a step is unambiguous while the oracle host clock is disturbed as little as possible; not measured under the 8-worker gate load. If the serial tail ever flips a line, add `clocksettimevdso` to `TIMING_SENSITIVE_PROBES` (which also disables its oracle cache) rather than widening the tolerance blindly.
- UNVERIFIED: Exact line numbers cited for `conformance.rs:3643-3696`, `:3700-3752`, `:3871-3895`, `:5107-5113`, and `time.rs:1504-1514` shift by the insertions earlier in the same task; the quoted existing text is the authority, the numbers are the pre-edit positions at HEAD 3dc6cc72.
- UNVERIFIED: KVM (aarch64), x86 and native-DSR lane behaviour after the change is compile-closure only (`cargo check --features platform-linux`); those lanes were not run. On the native lane the vvar lives at a relocated VA, so `sync_vvar_realtime_offset` sees `OutOfBounds` and skips — documented as a lane limitation, not verified live.
- UNVERIFIED: That `just check` on macOS also compiles `carrick-vmm-kvm`/`carrick-x86` (they are pulled only by non-macOS feature sets); hence the explicit `cargo check -p carrick-runtime --no-default-features --features platform-linux` in Task 3 Step 7, which itself was not run here.

</details>


<!-- cluster A2-seccomp-atomic -->
## Cluster A2-seccomp-atomic

> **Status:** verifier-corrected and cross-cluster reconciled (fixes applied: 3; notes: No mismatch item 2-24 names A2 or any symbol this cluster touches (`seccomp.rs`, `SeccompState`, `identity_fast_path_allowed`); the body is returned verbatim apart from the heading renumber. | Re-verified read-only against the checked-out tip 39426141 before returning: `identity_fast_path_allowed` field at seccomp.rs:330, `restore` at :348, `is_active` at :400, `strict_mode_kills_everything_except_linux_strict_set` at :766; zero out-of-file users of the word (`grep -rn identity_fast_path_allowed crates --include='*.rs'` excluding seccomp.rs = 0); call sites dispatch/mod.rs:5856 and :5910, proc.rs:1696 — all anchors in the plan still hold. | The plan's `just test` expectation (`seccomp::tests` 12/12) remains conditional on A1 (Task 1-3) not adding cases to `seccomp::tests`; A1's produced surface (conformance.rs caps, vdso word fn, dispatch epoch re-stamp) does not touch seccomp.rs, so the count stands. B3 later consumes `SyscallDispatcher::apply_launch_privileges(&mut self, SeccompPolicy, &Container)` (Task 20/21) and `apply_seccomp_policy`, which call `SeccompState::install`; the lock-free `is_active` is unaffected by those signature changes. | Landing order: A2 (Task 4) depends on nothing in A1 and edits only seccomp.rs, so it can land before or after Tasks 1-3 without rebasing; the `git diff --stat` single-file check in Step 6 assumes a clean tree at the start of the task.).

### Task 4: Lock-free `SeccompState::is_active` (Phase A item 3)

> Line numbers below were verified against the checked-out tip `39426141` (the brief's `3dc6cc72` is an ancestor; `dispatch/mod.rs` moved by ~50 lines between them). Treat every line number as a hint and the backticked symbol as the anchor — `grep -n` for the symbol before editing.

**Files:**
- Modify: `crates/carrick-runtime/src/seccomp.rs` — the field doc of `identity_fast_path_allowed` (`:326-330`), the body of `restore` (`:348-357`), and the body of `is_active` (`:400-403`)
- Test: `crates/carrick-runtime/src/seccomp.rs` `mod tests` (append two cases after `strict_mode_kills_everything_except_linux_strict_set`, whose closing `}` is at line 812, before the module's closing `}` at line 813)
- Read-only (unchanged, verified call sites): `crates/carrick-runtime/src/dispatch/mod.rs` `seccomp_precheck` (`:5855`, call at `:5856`; itself called from `dispatch_threaded` at `:5955` and `:6291`), `identity_fast_path_enabled` (`:5905`, call at `:5910`; consumed from `crates/carrick-runtime/src/vcpu_loop/mod.rs:1816` when a vCPU context is published), `crates/carrick-runtime/src/dispatch/proc.rs:1696` (`LINUX_PR_GET_SECCOMP` arm)

**Interfaces:**
- Consumes: `crate::seccomp::SeccompState { programs: parking_lot::Mutex<SeccompSnapshot>, identity_fast_path_allowed: AtomicU32 }` (existing, `seccomp.rs:324-331`, `use parking_lot::Mutex` at `:71`, `use std::sync::atomic::{AtomicU32, Ordering}` at `:73`); the existing writers `install` (`:369-388`), `install_strict` (`:390-394`), `restore` (`:348-357`), `fork_clone` (`:359-366`). `install` and `install_strict` already store `identity_fast_path_allowed` while holding the `programs` guard; `fork_clone` builds a fresh struct nobody else can observe yet; `restore` is the one writer that stores AFTER its guard is dropped (`*self.programs.lock() = snapshot.clone();` releases the guard at the semicolon) and is fixed in Step 4.
- Produces: `pub(crate) fn SeccompState::is_active(&self) -> bool` — same signature, now a single `Ordering::Acquire` load of `identity_fast_path_allowed` (`== 0`), no lock. No sibling `active: AtomicBool` is added: the existing word is already maintained at every mutation site with exactly the required value, and a second atomic would be a second answer to reconcile (AGENTS.md "no second path").

Design note (verified by reading `seccomp.rs:342-403` at `39426141`): the word is the only atomic in the struct, is written only by the four mutation paths, and is never touched outside `seccomp.rs` (`grep -rn identity_fast_path_allowed crates --include='*.rs'` matches only `seccomp.rs`; `SeccompState::restore` has no callers outside `seccomp.rs` and carries `#[allow(dead_code)]`). `install` stores `0` before `programs.filters.push(prog)` (`:385-386`) on purpose — the JIT identity gate must close before the filter is live (see the doc on `SyscallDispatcher::identity_fast_path_word` in `dispatch/mod.rs`, `:5916-5918`: "guest seccomp transitions flip the returned atomic word from 1 to 0 before publishing their filter"). That early flip is harmless for `is_active`: filters are irreversible, so a reader that sees `true` slightly early only proceeds into `check`, which still locks `programs` and therefore observes the pushed filter. The opposite order — filters published before the word flips — would let a lock-free reader skip `check` for a live filter, which is why `restore` must store under its guard too (Step 4).

- [ ] **Step 1: Write the failing lock-contention test**

Append to `mod tests` in `crates/carrick-runtime/src/seccomp.rs`, immediately after the closing brace of `strict_mode_kills_everything_except_linux_strict_set` (the `}` at line 812) and before the module's final `}` (line 813):

```rust
    /// `seccomp_precheck` asks `is_active` on every guest syscall that goes
    /// through `dispatch_threaded` (and `identity_fast_path_enabled` asks it
    /// whenever a vCPU context is published), so it must be a plain atomic
    /// load: taking `programs` there serialises every vCPU thread of a Linux
    /// process on one mutex, in the common case where no filter is
    /// installed. Hold the lock on this thread and prove a sibling thread's
    /// `is_active` still answers.
    #[test]
    fn is_active_does_not_take_the_programs_lock() {
        let state = SeccompState::default();
        state
            .install(deny_nr_filter(101, 1))
            .expect("install valid filter");
        let (tx, rx) = std::sync::mpsc::channel::<bool>();
        std::thread::scope(|scope| {
            // Declared INSIDE the scope closure so a failing assertion drops
            // the guard during unwinding, before `scope` joins the sibling.
            let held = state.programs.lock();
            let state = &state;
            scope.spawn(move || {
                let _ = tx.send(state.is_active());
            });
            let answer = rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("is_active blocked behind the programs lock");
            assert!(answer, "an installed filter must report active");
            drop(held);
        });
    }
```

- [ ] **Step 2: Run the new test and watch it fail for the right reason**

Run from the repo root (this is exactly the `carrick-runtime` line of the `just test` recipe, `justfile:196` — serial, single crate — never a bare `cargo test --workspace --lib`):

```sh
env RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib seccomp::tests::is_active_does_not_take_the_programs_lock
```

Expected: the test FAILS after ~2 s with

```
thread 'seccomp::tests::is_active_does_not_take_the_programs_lock' panicked at crates/carrick-runtime/src/seccomp.rs:...:
is_active blocked behind the programs lock: Timeout
...
test result: FAILED. 0 passed; 1 failed
```

because the current `is_active` (`seccomp.rs:400-403`) does `self.programs.lock()` and blocks behind the guard the test holds. The process exits (the guard is dropped during unwinding, the sibling thread completes, `scope` resumes the panic) — if instead the command hangs, the guard was declared outside the `scope` closure; move it back inside.

- [ ] **Step 3: Write the existing-behaviour guard (green before and after)**

Append directly after the test from Step 1:

```rust
    /// `is_active` must equal `strict || !filters.is_empty()` after every
    /// transition, and a filter is irreversible: once active, every later
    /// install, snapshot/restore and fork keeps it active. This pins the
    /// contract the lock-free read relies on: each writer stores the atomic
    /// word as exactly `u32::from(!active)` before its programs are visible.
    #[test]
    fn is_active_tracks_installed_filters_and_never_reverts() {
        fn locked_truth(state: &SeccompState) -> bool {
            let programs = state.programs.lock();
            programs.strict || !programs.filters.is_empty()
        }

        let state = SeccompState::default();
        assert!(!state.is_active());
        assert_eq!(state.is_active(), locked_truth(&state));

        state
            .install(deny_nr_filter(101, 1))
            .expect("install first filter");
        assert!(state.is_active());
        assert_eq!(state.is_active(), locked_truth(&state));

        state
            .install(deny_nr_filter(202, 1))
            .expect("install second filter");
        assert!(state.is_active(), "a second install must keep it active");
        assert_eq!(state.is_active(), locked_truth(&state));

        // A rejected install must not flip an inactive state.
        let fresh = SeccompState::default();
        assert_eq!(
            fresh.install(Vec::new()),
            Err(SeccompInstallError::InvalidProgram)
        );
        assert!(!fresh.is_active());
        assert_eq!(fresh.is_active(), locked_truth(&fresh));

        // Restore follows the snapshot: active stays active, empty stays off.
        let restored = SeccompState::default();
        restored
            .restore(&state.snapshot())
            .expect("restore active snapshot");
        assert!(restored.is_active());
        assert_eq!(restored.is_active(), locked_truth(&restored));
        let empty = SeccompState::default();
        empty
            .restore(&SeccompSnapshot::default())
            .expect("restore empty snapshot");
        assert!(!empty.is_active());
        assert_eq!(empty.is_active(), locked_truth(&empty));

        // Fork inherits the parent's activity in both directions.
        let child = state.fork_clone();
        assert!(child.is_active());
        assert_eq!(child.is_active(), locked_truth(&child));
        let quiet_child = SeccompState::default().fork_clone();
        assert!(!quiet_child.is_active());
        assert_eq!(quiet_child.is_active(), locked_truth(&quiet_child));

        // Strict mode is active with no filter program at all.
        let strict = SeccompState::default();
        strict.install_strict();
        assert!(strict.is_active());
        assert_eq!(strict.is_active(), locked_truth(&strict));
    }
```

(`SeccompSnapshot` derives `Default`, `SeccompInstallError` derives `PartialEq + Debug`, `restore` returns `Result<(), &'static str>`, and `filter_path_insns(&[])` is `Some(0)` so the empty snapshot validates — all at `39426141`.)

Run it:

```sh
env RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib seccomp::tests::is_active_tracks_installed_filters_and_never_reverts
```

Expected: `test result: ok. 1 passed; 0 failed` — this case is the regression guard for the semantic the atomic swap must preserve; it is green on the locking implementation and must stay green after Step 4.

- [ ] **Step 4: Make `is_active` read the atomic word, and make `restore` honour the invariant**

In `crates/carrick-runtime/src/seccomp.rs`, replace the field doc at lines 326-330:

```rust
    /// Live JIT gate: 1 only while no guest-installed filter exists. Emitted
    /// identity code reads this aligned atomic word directly with acquire-safe
    /// x86 load semantics, so a sibling's seccomp install disables every active
    /// context without waiting for a Rust gateway boundary.
    identity_fast_path_allowed: AtomicU32,
```

with:

```rust
    /// Live JIT gate AND the lock-free source of truth for [`Self::is_active`]:
    /// 1 only while no guest-installed filter exists. Emitted identity code
    /// reads this aligned atomic word directly with acquire-safe x86 load
    /// semantics, so a sibling's seccomp install disables every active context
    /// without waiting for a Rust gateway boundary. Invariant: every writer
    /// (`install`, `install_strict`, `restore`; `fork_clone` builds a fresh
    /// struct) stores it as exactly `u32::from(!(strict || !filters.is_empty()))`
    /// while holding `programs`, BEFORE the new programs become visible, so a
    /// reader never needs the lock to learn whether seccomp is active and can
    /// never skip `check` for a filter that is already live.
    identity_fast_path_allowed: AtomicU32,
```

Replace the body of `restore` at lines 348-357:

```rust
    pub(crate) fn restore(&self, snapshot: &SeccompSnapshot) -> Result<(), &'static str> {
        if !snapshot.validate() {
            return Err("invalid seccomp snapshot");
        }
        let active = snapshot.strict || !snapshot.filters.is_empty();
        *self.programs.lock() = snapshot.clone();
        self.identity_fast_path_allowed
            .store(u32::from(!active), Ordering::Release);
        Ok(())
    }
```

with (keep the `#[allow(dead_code)]` attribute above it as-is):

```rust
    pub(crate) fn restore(&self, snapshot: &SeccompSnapshot) -> Result<(), &'static str> {
        if !snapshot.validate() {
            return Err("invalid seccomp snapshot");
        }
        let active = snapshot.strict || !snapshot.filters.is_empty();
        // Hold the guard across the store and flip the word BEFORE the
        // programs are visible — the same order `install` uses — so a
        // lock-free `is_active` reader can never see restored filters while
        // the word still says "inactive".
        let mut programs = self.programs.lock();
        self.identity_fast_path_allowed
            .store(u32::from(!active), Ordering::Release);
        *programs = snapshot.clone();
        Ok(())
    }
```

and replace the method at lines 400-403:

```rust
    pub(crate) fn is_active(&self) -> bool {
        let programs = self.programs.lock();
        programs.strict || !programs.filters.is_empty()
    }
```

with:

```rust
    /// `true` once strict mode is set or any filter is installed — the
    /// per-syscall gate for `seccomp_precheck` and the identity shim. One
    /// acquire load of `identity_fast_path_allowed`, never a lock on
    /// `programs` (see the field's invariant). The word flips to 0 BEFORE a
    /// filter is pushed so the JIT gate can never race past a live filter; a
    /// reader that observes that early `true` only proceeds into `check`,
    /// which does lock and therefore sees the pushed filter. Filters are
    /// irreversible, so the word never goes back to 1.
    pub(crate) fn is_active(&self) -> bool {
        self.identity_fast_path_allowed.load(Ordering::Acquire) == 0
    }
```

- [ ] **Step 5: Run the whole seccomp unit module**

```sh
env RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib seccomp::tests
```

Expected: `test result: ok. 12 passed; 0 failed` (the 10 pre-existing cases — `installing_a_filter_closes_the_live_identity_gate`, `install_enforces_the_complete_filter_path_and_overhead`, `seccomp_data_arch_follows_guest_abi`, `x86_guest_survives_its_own_arch_gated_profile`, `deny_filter_blocks_target_and_allows_others`, `arch_and_arg_loads_and_jset_work`, `malformed_or_runaway_filter_fails_closed`, `state_stacks_filters_and_takes_most_restrictive`, `kill_process_filter_is_not_silently_ignored`, `strict_mode_kills_everything_except_linux_strict_set` — plus the two new ones; `seccomp` is the only module named that way in `carrick-runtime`, so the filter matches nothing else). `is_active_does_not_take_the_programs_lock` now completes in milliseconds, not 2 s.

- [ ] **Step 6: Prove the call sites are untouched**

```sh
git diff --stat
grep -n -B1 'self.seccomp.is_active()' crates/carrick-runtime/src/dispatch/mod.rs
grep -n 'this.seccomp.is_active()' crates/carrick-runtime/src/dispatch/proc.rs
```

Expected: `git diff --stat` lists exactly one file, `crates/carrick-runtime/src/seccomp.rs`. The first grep prints exactly two matches: one inside `fn seccomp_precheck` (the line right after its opening brace, `if !self.seccomp.is_active() {`) and one inside `fn identity_fast_path_enabled` (`!self.seccomp.is_active()` following its comment block) — at `39426141` these are lines 5856 and 5910, but the numbers drift; the enclosing function names are the check. The second grep prints exactly one match, the `LINUX_PR_GET_SECCOMP` arm (`:1696` at `39426141`). The `seccomp_precheck` doc line "Fast path: no lock when no filter is installed." (the line immediately above `fn seccomp_precheck`) was false before this task and is now true without editing it. Also run the dispatcher-level policy test that exercises the gate (it lives in `crates/carrick-runtime/src/dispatch/tests.rs`, which is `include!`d into `dispatch/mod.rs`, so `--lib` runs it):

```sh
env RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib docker_default_policy_keeps_identity_fast_path
```

Expected: `test result: ok. 1 passed; 0 failed`.

- [ ] **Step 7: Format, lint, and run the host test gate**

```sh
just fmt
just clippy
just test
```

Expected: `just fmt` rewrites nothing outside `seccomp.rs` (if it touches unrelated files, that is toolchain skew — `git checkout` those); `just clippy` finishes with no warnings (`-D warnings`); `just test` finishes with every crate reporting `test result: ok` including the serial `carrick-runtime --lib` pass.

- [ ] **Step 8: Commit**

```sh
git add crates/carrick-runtime/src/seccomp.rs
git commit -F - <<'EOF'
perf(runtime): make SeccompState::is_active a lock-free atomic load

Why: `seccomp_precheck` calls `SeccompState::is_active` on every guest
syscall that goes through `dispatch_threaded` (and
`identity_fast_path_enabled` asks it whenever a vCPU context is
published), and `is_active` took the `programs` parking_lot mutex to
compute `strict || !filters.is_empty()`. Every vCPU thread of a Linux
process therefore serialised on one mutex per syscall — in the common
case where NO filter is installed and the answer never changes. The
"Fast path: no lock when no filter is installed" doc on
`seccomp_precheck` described a fast path that did not exist.

What: `is_active` now performs one acquire load of the existing
`identity_fast_path_allowed` word (1 = no filter, 0 = active), so the
JIT gate and the dispatcher gate share one authority instead of a
second atomic to keep in step. `install` and `install_strict` already
store that word under the `programs` guard, BEFORE the filter is
pushed, as exactly `u32::from(!(strict || !filters.is_empty()))`;
`fork_clone` builds a fresh struct. `restore` stored it only after its
guard had been released, which a locked `is_active` never noticed but a
lock-free one could (restored filters visible while the word still said
inactive); it now holds the guard and stores before assigning
`programs`, matching `install`. `restore` has no callers today, so this
closes a latent window rather than a shipped bug. A reader that sees
the early `true` only proceeds into `check`, which still locks and sees
the pushed filter. Filters are irreversible, so the word never returns
to 1. No call site changes: `dispatch/mod.rs` `seccomp_precheck` /
`identity_fast_path_enabled` and `proc.rs` `PR_GET_SECCOMP` are
untouched.

Verified: red-first — `is_active_does_not_take_the_programs_lock` holds
the `programs` lock on the test thread and calls `is_active` from a
sibling thread with a 2 s timeout; it timed out on the locking
implementation and answers `true` immediately after.
`is_active_tracks_installed_filters_and_never_reverts` asserts
`is_active() == (strict || !filters.is_empty())` read under the lock
after default, install, second install, rejected install, restore
(active and empty), fork_clone (both directions) and strict transitions.
`seccomp::tests` 12/12 and `docker_default_policy_keeps_identity_fast_path`
green under `RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib`;
`just fmt`, `just clippy`, `just test` clean.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
```

<details><summary>Verifier problems fixed in place (3) and claims still unverified (4)</summary>

- fixed: Stale base revision / line numbers: the brief and draft cite HEAD as 3dc6cc72, but the checkout's actual HEAD is 39426141 (3dc6cc72 is an ancestor; `crates/carrick-runtime/src/dispatch/mod.rs` gained 50 lines between them). Every `dispatch/mod.rs` line number in the draft (5804, 5807, 5861, 5867-5869) is therefore wrong at the tip: at 39426141 the `seccomp_precheck` doc line is 5854, its `is_active` call 5856, `identity_fast_path_enabled`'s call 5910, and the `identity_fast_path_word` doc 5916-5918. Even at 3dc6cc72 the 'Fast path: no lock' doc line was 5805, not 5804. Step 6's expected grep output ('prints lines 5807 and 5861') would fail verbatim. FIX: all references re-anchored to symbol names with 39426141 line numbers noted as drift-prone; Step 6 now expects two matches identified by enclosing function, not by line number.
- fixed: False invariant in the design note, Step 4 field doc, and commit body: 'every writer stores the word while holding `programs`'. `SeccompState::restore` (seccomp.rs:348-357) does `*self.programs.lock() = snapshot.clone();` — the guard is a statement temporary dropped at the semicolon — and only then stores `identity_fast_path_allowed`, so after this task a lock-free `is_active` reader could observe `false` while the restored filters are already installed (the locking implementation could not, because it read `programs` itself). `restore` is currently `#[allow(dead_code)]` with no callers outside seccomp.rs (verified by grep), so the window is dormant, but the plan must not document an invariant the code does not satisfy. FIX: Step 4 now also rewrites `restore` to hold the guard across the store and to store the word BEFORE assigning `programs` (the same ordering `install`/`install_strict` use); the field doc, design note and commit body describe the real invariant.
- fixed: Inaccurate call-frequency claim in the Step 1 doc comment and commit body: `identity_fast_path_enabled` is not consulted 'on every guest syscall' — its only non-test caller is `crates/carrick-runtime/src/vcpu_loop/mod.rs:1816`, where the vCPU context is published. Only `seccomp_precheck` (called from `dispatch_threaded` at dispatch/mod.rs:5955 and again at :6291) is on the per-syscall path. FIX: wording corrected in the test comment and commit message; the perf motivation is unchanged.
- UNVERIFIED: The exact rustc panic line number in the Step 2 expected output (written as `seccomp.rs:...`) depends on where the executor appends the test; only the message text `is_active blocked behind the programs lock: Timeout` is asserted.
- UNVERIFIED: The `12 passed` count in Step 5 assumes no other seccomp tests land between now (10 `#[test]` cases at HEAD 3dc6cc72) and execution.
- UNVERIFIED: Whether `just fmt` reflows the new test/doc lines was not run (read-only brief); the code blocks were written to rustfmt's default width but Step 7 runs `just fmt` regardless.
- UNVERIFIED: The perf effect (removing one parking_lot lock/unlock per syscall from `dispatch_threaded`) is asserted structurally, not measured; no controlled experiment was run.

</details>


<!-- cluster A3-rlimits -->
## Cluster A3-rlimits

> **Status:** verifier-corrected and cross-cluster reconciled (fixes applied: 3; notes: No other consistency mismatch names A3: fixes 3-24 touch A1/A4/A5/B*/C* only, and A3 defines no shared type in the FINAL SIGNATURES besides `KernelOperationError::ProcessLimitExceeded { uid: NsUid, count: usize, limit: u64 }`, which already matches the 'Phase A leftovers unchanged by resolution' entry verbatim. | The conformance.rs line anchors (3251, 5000-5002) and the operations.rs/mem.rs anchors are those of the pre-Phase-A tree; A1 edits conformance.rs first (SYS_TIME_PROBES, probe_capabilities, the `caps` parameters), so the absolute line numbers there will shift. The plan now says to re-anchor by symbol; the replace-from values (466 / 420 / 440 / 880) are A1's landed values, not the original 465/419/439/878. | Not verified live against the repo (read-only reconcile of the markdown; no grep was needed because none of the A3 code anchors were changed by any fix).).

### Task 5: Enforce `RLIMIT_NPROC` at fork reservation (guest `EAGAIN`)

**Files:**
- Create: `conformance-probes/src/bin/rlimitnproc.rs`
- Modify: `conformance-probes/probe-inventory.json` (insert one row after the `"rlimitnofile"` row, before `"rlimitresource"`)
- Modify: `crates/carrick-cli/tests/conformance.rs:3251` (`PROBE_SOURCE_COUNT`), `:5000-5002` (the three `generic.len()` denominator asserts) — line numbers are as of the pre-Phase-A tree; re-anchor by symbol after Task 1-3 (A1) land, since A1 edits this file first
- Modify: `crates/carrick-runtime/src/kernel/operations.rs:2548-2554` (insert the check inside `reserve_fork`'s registry write-lock block, after the pointer checks), `:4250-4252` (new `KernelOperationError` variant), `:4168-4172` (new free helper after `next_revision`), `:4377` (new unit test after the `bootstrap` helper)
- Test: unit test `fork_reservation_enforces_rlimit_nproc_per_real_uid`; `just conformance-probes` (the arm64 lane oracles a new probe live against Docker on this host — see Step 8)

**Interfaces:**
- Consumes: `Kernel::reserve_fork(self: &Arc<Self>, parent: &KernelContext, plan: ClonePlan, diagnostic_name: String, failpoint: Option<KernelFailpoint>) -> Result<ForkReservation, KernelOperationError>` (operations.rs:2496); `Task::rlimit(&self, LinuxResource) -> LinuxRlimit` (objects.rs:2926); `Task::caps(&self) -> CapabilitySet` (objects.rs:2962); `Task::with_caps<R>(&self, impl FnOnce(&mut CapabilitySet) -> R) -> R` (objects.rs:2971); `CapabilitySet::has_effective(&self, u32) -> bool` (namespace/process.rs:242); `ThreadResources::credentials(&self) -> Arc<Credentials>` (objects.rs:2441); `Credentials::ruid(&self) -> NsUid` (objects.rs:1703); `KernelContext { resources: Arc<ThreadResources>, thread, shared, .. }` — `pub(super)` FIELDS (core.rs:24-30; there is no `resources()` accessor, `reserve_fork` reads `parent.resources` directly at 2549); `RegistryState.tasks: BTreeMap<TaskId, TaskRecord>` (core.rs:1537); `TaskRecord.thread_claims: BTreeMap<LinuxTid, ThreadClaim>` (core.rs:1559); `Task::thread(&self, LinuxTid) -> Option<ThreadRef>` (objects.rs:3928, `pub(super)`); `Thread::resources(&self) -> Arc<ThreadResources>` (objects.rs:6022, `pub(super)`); `crate::namespace::process::{CAP_SYS_ADMIN = 21, CAP_SYS_RESOURCE = 24}` (process.rs:51,53); `carrick_abi::NsUid::ROOT` (lib.rs:2870). Landing order: this task lands AFTER Task 1-3 (A1, which sets `PROBE_SOURCE_COUNT = 466` / generic 420 / 440 / 880) and BEFORE Task 8-10 (A4) and Task 22-23 (B4), which bump the same denominators next.
- Produces: `KernelOperationError::ProcessLimitExceeded { uid: NsUid, count: usize, limit: u64 }`; `fn enforce_rlimit_nproc(state: &RegistryState, caller: &KernelContext) -> Result<(), KernelOperationError>` (private free fn in `kernel::operations`); `PROBE_SOURCE_COUNT = 467`, generic 421 / 441 / 882.

**Why reservation, not `PreparedFork::commit`.** The spec names `PreparedFork::commit`, but the single caller (`crates/carrick-runtime/src/vcpu_loop/quiesce.rs:1131-1140`) `std::process::abort()`s on a commit error because the frame inventory and the parent's backend transaction are already committed by then. The last point in the same fork transaction whose error still lowers to guest `EAGAIN` is `reserve_fork` (`quiesce.rs:706-716`: `"hvpatch kernel child reservation failed; fork(2) = EAGAIN"` at 713). The check runs under the same registry write lock `commit` later validates under, so the population it counts is the one `commit` publishes into.

**Rule implemented** (setrlimit(2), `RLIMIT_NPROC`): the limit is on the number of extant threads for the REAL user ID of the calling process; while that count is `>=` the soft limit, `fork(2)` fails with `EAGAIN`; not enforced for real uid 0 or a caller holding effective `CAP_SYS_ADMIN` or `CAP_SYS_RESOURCE`. Carrick counts every live thread claim of every live task in the kernel graph whose thread's own real uid equals the caller's (credentials are per thread). Approximations, stated in the doc comment: zombies, retired threads and in-flight reservations are not counted (two forks racing exactly at the limit can both win by one), and `clone_thread` (CLONE_THREAD) is not gated. Docker's default capability set (`DOCKER_DEFAULT_CAPS = 0xa804_25fb`, `namespace/process.rs:36`, applied by `CapabilitySet::docker_default()` at `:137`) has bits 21 and 24 clear, so an unprivileged real uid is the only thing the probe needs to arrange.

- [ ] **Step 1: Write the guest probe (red first).** Create `conformance-probes/src/bin/rlimitnproc.rs`:

```rust
//! RLIMIT_NPROC is enforced at fork(2): once the number of live threads owned
//! by the caller's REAL uid reaches the soft limit, fork fails with EAGAIN
//! (setrlimit(2)). Real uid 0 and CAP_SYS_ADMIN/CAP_SYS_RESOURCE holders are
//! exempt, so the probe first drops to an unprivileged real uid with raw
//! setresuid — both the Docker oracle and carrick start the probe as root.
//! carrick stored the limit (default 8192) but never consulted it, so every
//! fork past the limit succeeded. Deterministic booleans only.
//!
//! Sequence (soft limit 2 for the new uid, whose only live thread is this one):
//!   fork A (blocks on a pipe)        -> succeeds (count 1 -> 2)
//!   fork B                           -> EAGAIN   (2 >= 2)
//!   release + reap A, fork C         -> succeeds (count back to 1 -> 2)
//!   raise the soft limit to 3, fork D -> succeeds while C is alive (2 -> 3)
//! Every child _exit(0)s and the parent reaps all of them, so no zombie can
//! leak into the count. UID 47231 is arbitrary and unallocated on both sides:
//! the count is per real uid across the whole (initial) user namespace, so a
//! uid a host daemon might own would make the count nondeterministic.

use conformance_probes::{errno, pipe2};
use std::os::raw::c_void;

const PROBE_UID: i64 = 47231;

fn set_nproc(cur: u64, max: u64) -> bool {
    let rl = libc::rlimit {
        rlim_cur: cur,
        rlim_max: max,
    };
    unsafe {
        libc::syscall(
            libc::SYS_prlimit64,
            0i64,
            libc::RLIMIT_NPROC as i64,
            &rl as *const libc::rlimit as i64,
            0i64,
        ) == 0
    }
}

/// Fork a child that blocks on a 1-byte pipe read and exits 0 when released.
fn fork_blocked() -> (libc::pid_t, i32) {
    let (r, w) = pipe2();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::close(w);
            let mut byte = 0u8;
            libc::read(r, &mut byte as *mut u8 as *mut c_void, 1);
            libc::_exit(0);
        }
    }
    unsafe { libc::close(r) };
    (pid, w)
}

fn release_and_reap(pid: libc::pid_t, w: i32) -> bool {
    let mut status = 0i32;
    unsafe {
        libc::close(w);
        libc::waitpid(pid, &mut status, 0) == pid
            && libc::WIFEXITED(status)
            && libc::WEXITSTATUS(status) == 0
    }
}

/// A fork that must be refused. If it wrongly succeeds, the child exits at
/// once and is reaped so the rest of the sequence stays well-defined.
fn fork_expect_eagain() -> bool {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::_exit(0) };
    }
    if pid > 0 {
        let mut status = 0i32;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        return false;
    }
    errno() == libc::EAGAIN
}

fn main() {
    // Set the limit while still root (soft 2, hard 3): raising a SOFT limit
    // within the hard limit later needs no privilege.
    println!("setrlimit_nproc_2={}", set_nproc(2, 3));
    let dropped = unsafe {
        libc::syscall(libc::SYS_setresuid, PROBE_UID, PROBE_UID, PROBE_UID) == 0
    };
    println!("setresuid_unprivileged={dropped}");
    if !dropped {
        return;
    }

    let (a, a_release) = fork_blocked();
    println!("fork_a_ok={}", a > 0);
    println!("fork_b_eagain={}", fork_expect_eagain());
    println!("reap_a_ok={}", release_and_reap(a, a_release));

    let (c, c_release) = fork_blocked();
    println!("fork_c_after_reap_ok={}", c > 0);

    println!("setrlimit_nproc_3={}", set_nproc(3, 3));
    let (d, d_release) = fork_blocked();
    println!("fork_d_ok={}", d > 0);

    println!("reap_c_ok={}", release_and_reap(c, c_release));
    println!("reap_d_ok={}", release_and_reap(d, d_release));
}
```

- [ ] **Step 2: Register the probe in the inventory and the harness denominators.** In `conformance-probes/probe-inventory.json`, directly after the `"rlimitnofile"` row (lines 1707-1711; the file is a JSON object of `{class, excluded, runner}` rows kept in sorted key order, so `rlimitnofile < rlimitnproc < rlimitresource`), add:

```json
  "rlimitnproc": {
    "class": "conformance",
    "excluded": false,
    "runner": "generic"
  },
```

In `crates/carrick-cli/tests/conformance.rs` replace line 3251 (as left by Task 1-3 / A1, which landed `466`)

```rust
const PROBE_SOURCE_COUNT: usize = 466;
```
with
```rust
const PROBE_SOURCE_COUNT: usize = 467;
```
and replace lines 5000-5002 (as left by A1: 420/440/880)

```rust
    assert_eq!(generic.len(), 420);
    assert_eq!(generic.len() + DEDICATED_PROBE_RUNNERS.len(), 440);
    assert_eq!(2 * (generic.len() + DEDICATED_PROBE_RUNNERS.len()), 880);
```
with
```rust
    assert_eq!(generic.len(), 421);
    assert_eq!(generic.len() + DEDICATED_PROBE_RUNNERS.len(), 441);
    assert_eq!(2 * (generic.len() + DEDICATED_PROBE_RUNNERS.len()), 882);
```
(All three encode the same denominator; bumping only the first leaves the test red.)

Run from the repo root: `python3 scripts/probe-inventory.py check` — expected: exit 0 and `probe inventory checked: 467 sources ...`. Then `cargo test -p carrick-cli --test conformance closure_probe_inventory -- --nocapture 2>&1 | tail -3` — expected: `closure_probe_inventory_enforces_authoritative_runners_and_denominator ... ok`.

- [ ] **Step 3: Build the probe set and prove the probe is RED under carrick, GREEN under Docker (two-phase, never concurrent).**

```sh
./scripts/build-probes.sh
just build
target/release/carrick run --platform linux/arm64 --fs host \
  -v "$PWD/conformance-probes/target/aarch64-unknown-linux-musl/release:/p:ro" \
  docker.io/library/ubuntu:24.04 /p/rlimitnproc
```
(`-v HOST:GUEST[:ro]` is the CLI's bind-mount flag, `crates/carrick-cli/src/args.rs:219`; `ubuntu:24.04` is the harness's arm64 lane image. Use `carrick run`, not `run-elf`: `run-elf` runs the probe as YOU, and the probe must start as root to `setresuid`.) Expected BEFORE the fix (carrick): the line `fork_b_eagain=false` (every other line `true`). Then, only after carrick has exited:
```sh
docker run --rm --platform linux/arm64 \
  -v "$PWD/conformance-probes/target/aarch64-unknown-linux-musl/release:/p:ro" \
  docker.io/library/ubuntu:24.04 /p/rlimitnproc
```
Expected (Linux oracle), exactly:
```
setrlimit_nproc_2=true
setresuid_unprivileged=true
fork_a_ok=true
fork_b_eagain=true
reap_a_ok=true
fork_c_after_reap_ok=true
setrlimit_nproc_3=true
fork_d_ok=true
reap_c_ok=true
reap_d_ok=true
```

- [ ] **Step 4: Write the failing kernel-graph unit test.** In `crates/carrick-runtime/src/kernel/operations.rs`, inside `mod tests`, immediately after the `bootstrap` helper (lines 4369-4377, ending `Kernel::bootstrap_root(input).expect("kernel")` / `}`), add:

```rust
    /// `RLIMIT_NPROC` is counted per REAL uid over live threads and refused at
    /// fork RESERVATION — the last point whose error still lowers to guest
    /// `EAGAIN` (`vcpu_loop/quiesce.rs` aborts the carrier on a `commit`
    /// failure). It needs TWO live tasks to mean anything: a single task can
    /// never be at a limit of two.
    #[test]
    fn fork_reservation_enforces_rlimit_nproc_per_real_uid() {
        use carrick_abi::{LinuxResource, LinuxRlimit};
        use std::convert::Infallible;

        let (kernel, root) = bootstrap(9_300);
        let user = kernel
            .update_credentials(&root, |credentials| {
                credentials
                    .seed_identity(carrick_abi::NsUid::new(1000), carrick_abi::NsGid::new(1000))
            })
            .expect("seed unprivileged credentials");
        let fork_plan = || ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let set_nproc = |soft: u64| {
            user.task()
                .replace_rlimit(LinuxResource::Nproc, |_| {
                    Ok::<_, Infallible>(LinuxRlimit::new(soft, 8_192))
                })
                .expect("set RLIMIT_NPROC");
        };

        // One live thread for uid 1000 and a soft limit of one: refused.
        set_nproc(1);
        assert!(matches!(
            kernel.reserve_fork(&user, fork_plan(), "refused-at-one".to_owned(), None),
            Err(KernelOperationError::ProcessLimitExceeded { uid, count: 1, limit: 1 })
                if uid == carrick_abi::NsUid::new(1000)
        ));

        // Limit two: the first fork publishes; the second is refused because
        // the child's leader thread carries the same real uid.
        set_nproc(2);
        let reservation = kernel
            .reserve_fork(&user, fork_plan(), "first child".to_owned(), None)
            .expect("reserve first child");
        let child_id = reservation.child_id();
        let published = reservation
            .prepare_reference(ThreadId::synthetic_for_tests(9_301))
            .expect("prepare first child")
            .commit()
            .expect("publish first child");
        drop(published);
        assert!(kernel.task_is_live(child_id));
        assert!(matches!(
            kernel.reserve_fork(&user, fork_plan(), "refused-at-two".to_owned(), None),
            Err(KernelOperationError::ProcessLimitExceeded { count: 2, limit: 2, .. })
        ));

        // CAP_SYS_RESOURCE exempts the caller even at the limit.
        user.task().with_caps(|caps| {
            caps.effective |= 1u64 << crate::namespace::process::CAP_SYS_RESOURCE;
        });
        let exempt = kernel
            .reserve_fork(&user, fork_plan(), "cap-exempt".to_owned(), None)
            .expect("CAP_SYS_RESOURCE exempts RLIMIT_NPROC")
            .prepare_reference(ThreadId::synthetic_for_tests(9_302))
            .expect("prepare exempt child")
            .commit()
            .expect("publish exempt child");
        drop(exempt);

        // Real uid 0 is exempt: a limit of one with one live thread still forks.
        let (kernel, root) = bootstrap(9_400);
        root.task()
            .replace_rlimit(LinuxResource::Nproc, |_| {
                Ok::<_, Infallible>(LinuxRlimit::new(1, 1))
            })
            .expect("set RLIMIT_NPROC on root");
        let root_child = kernel
            .reserve_fork(&root, fork_plan(), "root-exempt".to_owned(), None)
            .expect("real uid 0 is exempt from RLIMIT_NPROC")
            .prepare_reference(ThreadId::synthetic_for_tests(9_401))
            .expect("prepare root child")
            .commit()
            .expect("publish root child");
        drop(root_child);
    }
```
(`ClonePlan`, `LinuxCloneFlags`, `ThreadId`, `KernelOperationError` are already in scope in `mod tests` via `use super::*` / its own `use carrick_abi::{LinuxCloneFlags, ...}`; `prepare_reference` is `#[cfg(test)] pub(crate)` at operations.rs:582; `task_is_live` at :1358; `update_credentials` at :2947 returns the re-captured `KernelContext`.)

Run: `RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib -- fork_reservation_enforces_rlimit_nproc_per_real_uid` (the serialization `just test` applies to `carrick-runtime`). Expected: compile error `no variant named ProcessLimitExceeded` — red for the right reason.

- [ ] **Step 5: Add the error variant.** In `crates/carrick-runtime/src/kernel/operations.rs`, replace lines 4249-4252

```rust
    #[error("selected fork parent exited before commit")]
    ForkParentExited,
    #[error("selected fork parent changed before commit")]
    ForkParentChanged,
```
with
```rust
    #[error("selected fork parent exited before commit")]
    ForkParentExited,
    #[error("selected fork parent changed before commit")]
    ForkParentChanged,
    #[error("RLIMIT_NPROC reached for real uid {uid:?}: {count} live threads, soft limit {limit}")]
    ProcessLimitExceeded {
        uid: NsUid,
        count: usize,
        limit: u64,
    },
```
(`NsUid` is already imported at operations.rs:4; `KernelOperationError` derives only `Debug, thiserror::Error`, so no extra derives are needed on the payload.)

Re-run the Step 4 command. Expected: compiles; the test FAILS at the first `assert!(matches!(...))` (`reserve_fork` returned `Ok`).

- [ ] **Step 6: Enforce at `reserve_fork`.** In `crates/carrick-runtime/src/kernel/operations.rs`, replace lines 2548-2554

```rust
            if !Arc::ptr_eq(&caller_thread, &parent.thread)
                || !Arc::ptr_eq(&caller_thread.resources(), &parent.resources)
                || !Arc::ptr_eq(&caller_record.task.shared(), &parent.shared)
            {
                return Err(KernelOperationError::StaleContext);
            }
            let caller_revision = caller_record.revision;
```
with
```rust
            if !Arc::ptr_eq(&caller_thread, &parent.thread)
                || !Arc::ptr_eq(&caller_thread.resources(), &parent.resources)
                || !Arc::ptr_eq(&caller_record.task.shared(), &parent.shared)
            {
                return Err(KernelOperationError::StaleContext);
            }
            let caller_revision = caller_record.revision;
            enforce_rlimit_nproc(&state, parent)?;
```
(`state` is the `RwLockWriteGuard<RegistryState>` taken at 2510; `&state` deref-coerces to `&RegistryState`.) Then add the helper as a free function directly after `next_revision` (lines 4168-4172, i.e. after its closing `}` and before `fn remove_group_member`) — `reserve_fork` itself sits inside the `impl Kernel` block that starts at line 1182, so the free fn cannot go next to it:

```rust
/// `RLIMIT_NPROC` at fork reservation — setrlimit(2): while the number of
/// extant threads for the caller's REAL user ID is greater than or equal to
/// the soft limit, `fork(2)` fails with `EAGAIN`; not enforced for real uid 0
/// or a caller holding effective `CAP_SYS_ADMIN` or `CAP_SYS_RESOURCE`.
///
/// Reservation, not `PreparedFork::commit`, is the enforcement point: by the
/// time `commit` runs, the frame inventory and the parent's backend
/// transaction have already committed and `vcpu_loop/quiesce.rs` aborts the
/// carrier on a commit error. Every reservation error still lowers to guest
/// `EAGAIN` there, and this runs under the same registry write lock `commit`
/// validates under.
///
/// Counting rule (Linux counts threads, not thread-group leaders): every live
/// thread claim of every live task in the registry whose thread's own real
/// uid equals the caller's — credentials are per thread. Zombies, retired
/// threads and in-flight reservations are NOT counted, so two forks racing
/// exactly at the limit can both win by one; `clone_thread` is not gated.
/// Both are deliberate approximations.
fn enforce_rlimit_nproc(
    state: &RegistryState,
    caller: &KernelContext,
) -> Result<(), KernelOperationError> {
    let ruid = caller.resources.credentials().ruid();
    if ruid == NsUid::ROOT {
        return Ok(());
    }
    let limit = caller
        .task()
        .rlimit(carrick_abi::LinuxResource::Nproc)
        .rlim_cur;
    if limit == carrick_abi::LINUX_RLIM_INFINITY {
        return Ok(());
    }
    let caps = caller.task().caps();
    if caps.has_effective(crate::namespace::process::CAP_SYS_ADMIN)
        || caps.has_effective(crate::namespace::process::CAP_SYS_RESOURCE)
    {
        return Ok(());
    }
    // Fast path for the default (8192): fewer live threads in the whole
    // kernel graph than the limit means no uid can be at it — the ordinary
    // fork reads no per-thread credentials.
    let total_threads: usize = state
        .tasks
        .values()
        .map(|record| record.thread_claims.len())
        .sum();
    if u64::try_from(total_threads).is_ok_and(|total| total < limit) {
        return Ok(());
    }
    let count = state
        .tasks
        .values()
        .flat_map(|record| {
            record
                .thread_claims
                .keys()
                .filter_map(|tid| record.task.thread(*tid))
        })
        .filter(|thread| thread.resources().credentials().ruid() == ruid)
        .count();
    if u64::try_from(count).is_ok_and(|count| count < limit) {
        return Ok(());
    }
    Err(KernelOperationError::ProcessLimitExceeded { uid: ruid, count, limit })
}
```
(`RegistryState` and `KernelContext` are imported at operations.rs:12-16; `KernelContext.resources` is a `pub(super)` field — there is no `resources()` accessor — exactly as `reserve_fork` reads it; `Task::thread` and `Thread::resources` are `pub(super)` in `kernel::objects`, visible here; `NsUid::ROOT` is `carrick_abi` lib.rs:2870.)

Re-run the Step 4 command. Expected: `test kernel::operations::tests::fork_reservation_enforces_rlimit_nproc_per_real_uid ... ok`.

- [ ] **Step 7: Prove the probe GREEN under carrick and re-run the neighbours.**

```sh
just build
target/release/carrick run --platform linux/arm64 --fs host \
  -v "$PWD/conformance-probes/target/aarch64-unknown-linux-musl/release:/p:ro" \
  docker.io/library/ubuntu:24.04 /p/rlimitnproc
```
Expected: byte-identical to the Docker output in Step 3 (`fork_b_eagain=true`). Then `just test` — expected: all green, including the pre-existing `objects.rs` rlimit tests (`fork_inherits_rlimits_as_a_copy`, objects.rs:6810) and every operations test.

- [ ] **Step 8: Run the probe gate (no Docker phase while any carrick process is running).** The arm64 probe-oracle cache (`crates/carrick-cli/tests/probe-oracle/arm64-musl/`) holds only 9 committed entries; the gate prefers a cached oracle and falls back to live Docker per probe (conformance.rs:4548-4562), and it is itself two-phase (all carrick, then all Docker). Do NOT run `bless_probe_oracle` here: it writes an entry for every deterministic probe with a binary, i.e. hundreds of new arm64-musl files. From the repo root:

```sh
just conformance-probes
```
Expected: `arm64:musl:rlimitnproc` reports `MATCH`/PASS (the musl set is the gating one; the arm64 `gnu` set is `gating: false`, report-only, and should also show MATCH) and the failure list is unchanged from `main`.

- [ ] **Step 9: Format and commit.**

```sh
just fmt
git add conformance-probes/src/bin/rlimitnproc.rs conformance-probes/probe-inventory.json \
  crates/carrick-cli/tests/conformance.rs crates/carrick-runtime/src/kernel/operations.rs
git commit -F - <<'EOF'
fix(runtime): enforce RLIMIT_NPROC at fork reservation

Why: `RLIMIT_NPROC` was stored on the task (default 8192) and read by
`getrlimit`/`/proc/<pid>/limits`, but no fork path ever consulted it, so a
guest that lowered the limit could still fork without bound. setrlimit(2)
says fork(2) fails with EAGAIN while the caller's real uid already owns at
least `rlim_cur` threads, exempting real uid 0 and effective CAP_SYS_ADMIN
or CAP_SYS_RESOURCE.

What: the check lives in `Kernel::reserve_fork`, under the registry write
lock, not in `PreparedFork::commit` as first planned — `vcpu_loop/quiesce.rs`
aborts the carrier on a commit error because the frame inventory is already
published, while every reservation error still lowers to guest EAGAIN. It
counts live thread claims of live tasks whose thread real uid matches the
caller (Linux counts threads, credentials are per thread), with a fast path
that skips the per-thread walk whenever the whole graph holds fewer threads
than the limit. Approximations, documented on the helper: zombies, retired
threads and in-flight reservations are not counted, and `clone_thread` is
not gated. New `KernelOperationError::ProcessLimitExceeded { uid, count,
limit }`.

Verified: `conformance-probes/src/bin/rlimitnproc` (drops to real uid 47231,
soft limit 2, blocked child A, fork B) was red against the pre-fix binary
(`fork_b_eagain=false`) and matches the Docker arm64 oracle after the fix;
unit test `fork_reservation_enforces_rlimit_nproc_per_real_uid` covers the
refusal at one and two live tasks, the CAP_SYS_RESOURCE exemption and the
uid-0 exemption; `just test`, `just conformance-probes`.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01VJcvGV5u1ErqZREKWUy6rU
EOF
```

---

### Task 6: Enforce `RLIMIT_AS` and `RLIMIT_DATA` at `mmap`/`brk`/`mremap` (guest `ENOMEM`)

**Files:**
- Create: `conformance-probes/src/bin/rlimitasdata.rs`
- Modify: `conformance-probes/probe-inventory.json` (insert one row directly BEFORE the `"rlimitnofile"` row, keeping the sorted order `rlimitasdata < rlimitnofile`)
- Modify: `crates/carrick-cli/tests/conformance.rs:3251` (467 → 468), `:5000-5002` (421/441/882 → 422/442/884)
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs:426-427` (import `LINUX_RLIMIT_AS`, `LINUX_RLIMIT_DATA` into the `use crate::linux_abi::{…}` block)
- Modify: `crates/carrick-runtime/src/dispatch/mem.rs:955` (accounting helpers after `project_vma_summaries`), `:2703-2706` (brk grow), `:2851-2852` (mmap admission), `:4732-4735` (mremap admission), `:6294` (limit helper directly above `prepare_fresh_mmap_locked_length`)
- Modify: `crates/carrick-runtime/src/dispatch/mem/tests.rs` (three new unit tests appended at the END of the file — it is 6,656 lines)
- Test: unit tests below; `just conformance-probes` (live Docker oracle for the new arm64 probe, as in Task 5 (Enforce `RLIMIT_NPROC` at fork reservation) Step 8)

**Interfaces:**
- Consumes: `SyscallDispatcher::effective_resource_limit(&self, resource: u64) -> LinuxRlimit` (time.rs:108; in unit tests `task_rlimits()` at time.rs:117-129 reads the captured context's task under `cfg(test)`, so `replace_rlimit` on `context.task()` is honoured); `MemState { layout: MemoryLayout, brk_current: u64, mmap_next: u64, address_space_regions: Option<Vec<ProcMapsEntry>>, dynamic_maps: Vec<ProcMapsEntry>, growdown_ranges: Vec<(u64, u64, u64)> /* (low_bound, current_start, end) */, .. }` (mem.rs:271-371; `MemState::new()` at :436 is `pub(super)`); `fn project_vma_summaries(mem: &MemState) -> Vec<crate::kernel::VmaSummary>` (mem.rs:919-955; `VmaSummary { start: GuestVa, end: GuestVa }` at kernel/address.rs:66, `GuestVa(pub u64)`); `fn boot_region_is_hidden_reservation(map: &ProcMapsEntry, layout: MemoryLayout) -> bool` (mem.rs:912); `ProcMapsEntry { start, end, read, write, execute, sharing: ProcMapSharing, path }` (vfs/proc.rs:79-87; `ProcMapSharing` derives `PartialEq`); `MmapSharing` (mem.rs:1035-1039, derives `Clone, Copy, Debug, PartialEq, Eq`); `MremapMappingMetadata { prot: LinuxProtFlags, sharing: ProcMapSharing, .. }` (mem.rs:1065-1072); `MmapRefusal::Spec(&'static str)` (mem.rs:104-108) and `MmapRequest::refused(self, MmapRefusal, LinuxErrno) -> DispatchOutcome` (mem.rs:135); `align_up_u64(u64, u64) -> Option<u64>` (`carrick_abi` lib.rs:274, in scope via `use super::*`); `SyscallDispatcher::linux_page_size(&self) -> u64` (mod.rs:4655); `SyscallDispatcher::mem(&self) -> arc_swap::Guard<Arc<DispatchMmAuthority>>` (mod.rs:3810, `.lock()` yields the `MemState` guard); `carrick_abi::{LINUX_RLIMIT_AS = 9, LINUX_RLIMIT_DATA = 2, LINUX_RLIM_INFINITY}` (lib.rs:3943, 3937, 3810); `LINUX_ENOMEM: LinuxErrno` (lib.rs:3095, imported in mod.rs:230); `DispatchOutcome::errno(LinuxErrno)` (mod.rs:1947); `PROBE_SOURCE_COUNT = 467`, generic 421 / 441 / 882 as left by Task 5.
- Produces (private to `dispatch::mem`): `fn committed_va_bytes(mem: &MemState) -> u64`; `fn data_va_bytes(mem: &MemState) -> u64`; `fn mapped_overlap_bytes(mem: &MemState, start: u64, len: u64) -> u64`; `fn mapping_is_data(write: bool, private: bool, growsdown: bool) -> bool`; `SyscallDispatcher::check_address_space_limits(&self, mem: &MemState, grow: u64, data: bool) -> Result<(), LinuxErrno>`. Also: `PROBE_SOURCE_COUNT = 468`, generic 422 / 442 / 884 (the values Task 8-10 (A4) then bumps to 469 / 422+21 == 443 / 886, and Task 22-23 (B4) to 470 / 444 / 888).

**Rules implemented** (setrlimit(2)): `RLIMIT_AS` — maximum size of the process's virtual memory; `brk(2)`, `mmap(2)`, `mremap(2)` fail with `ENOMEM` on exceeding it. `RLIMIT_DATA` — maximum size of the data segment (initialized data, uninitialized data, heap); `brk(2)`, `sbrk(2)` and, since Linux 4.7, `mmap(2)` fail with `ENOMEM` at the soft limit. Carrick measures AS as the union of the Linux-visible VMAs (`project_vma_summaries`, the same authority `/proc/<pid>/maps` and the core publisher use, so limit and reported size cannot disagree) and DATA as the brk heap span plus every private, writable, non-grow-down mapping (proc(5) `VmData`): `PROT_NONE` reservations and `MAP_SHARED` mappings are address space but not data. Both checks compare `current + page-rounded growth > rlim_cur` against the SOFT limit. A `MAP_FIXED` replacement is charged only for bytes not already mapped. `brk` reports `ENOMEM` the way Linux does — by returning the unchanged break. Zero cost while both limits are infinite (carrick's defaults): two `ArcSwap` loads, no VMA walk. Stated approximation: mremap-with-move is charged `new_size - old_size` like an in-place grow.

- [ ] **Step 1: Write the guest probe (red first).** Create `conformance-probes/src/bin/rlimitasdata.rs`:

```rust
//! RLIMIT_AS and RLIMIT_DATA are enforced at the SOFT limit by mmap(2), brk(2)
//! and mremap(2) with ENOMEM (setrlimit(2)); brk reports it by returning the
//! unchanged break. RLIMIT_DATA charges the heap plus private writable
//! non-stack mappings (proc(5) VmData): PROT_NONE reservations and MAP_SHARED
//! mappings are address space but not data. Both limits are inherited by a
//! fork child. carrick stored both and enforced neither.
//!
//! Sizes leave wide margins so the baseline VmSize/VmData of a static musl
//! probe (a few MiB on Linux; the visible boot regions under carrick) sits
//! well below every threshold. Raw syscalls throughout; no sizes, addresses or
//! pids are printed.

use conformance_probes::errno;

const MIB: u64 = 1024 * 1024;

fn set_limit(resource: i64, cur: u64) -> bool {
    let rl = libc::rlimit {
        rlim_cur: cur,
        rlim_max: libc::RLIM_INFINITY,
    };
    unsafe {
        libc::syscall(
            libc::SYS_prlimit64,
            0i64,
            resource,
            &rl as *const libc::rlimit as i64,
            0i64,
        ) == 0
    }
}

/// Raw brk(2): returns the (possibly unchanged) break.
fn brk(addr: u64) -> u64 {
    unsafe { libc::syscall(libc::SYS_brk, addr) as u64 }
}

/// Raw anonymous mmap: Ok(addr) or Err(errno).
fn map(len: u64, prot: i32, flags: i32) -> Result<u64, i32> {
    let r = unsafe {
        libc::syscall(
            libc::SYS_mmap,
            0u64,
            len,
            prot as i64,
            (flags | libc::MAP_ANONYMOUS) as i64,
            -1i64,
            0i64,
        )
    };
    if r == -1 { Err(errno()) } else { Ok(r as u64) }
}

fn unmap(addr: u64, len: u64) -> bool {
    unsafe { libc::syscall(libc::SYS_munmap, addr, len) == 0 }
}

/// Raw mremap(MREMAP_MAYMOVE): Ok(new_addr) or Err(errno).
fn remap(addr: u64, old: u64, new: u64) -> Result<u64, i32> {
    let r = unsafe {
        libc::syscall(
            libc::SYS_mremap,
            addr,
            old,
            new,
            libc::MREMAP_MAYMOVE as i64,
            0u64,
        )
    };
    if r == -1 { Err(errno()) } else { Ok(r as u64) }
}

fn main() {
    let rw = libc::PROT_READ | libc::PROT_WRITE;
    let rlimit_data = libc::RLIMIT_DATA as i64;
    let rlimit_as = libc::RLIMIT_AS as i64;

    // ---- RLIMIT_DATA: heap + private writable mappings; not PROT_NONE, not shared.
    println!("data_limit_set={}", set_limit(rlimit_data, 64 * MIB));
    let initial = brk(0);
    let grown = brk(initial + 16 * MIB);
    println!("brk_16mib_ok={}", grown == initial + 16 * MIB);
    // 16 + 56 = 72 MiB > 64 MiB: the break must not move.
    println!(
        "brk_past_data_unchanged={}",
        brk(grown + 56 * MIB) == grown
    );
    // 16 MiB heap + 56 MiB private RW = 72 > 64.
    println!(
        "mmap_rw_private_past_data_enomem={}",
        map(56 * MIB, rw, libc::MAP_PRIVATE) == Err(libc::ENOMEM)
    );
    let reserve = map(128 * MIB, libc::PROT_NONE, libc::MAP_PRIVATE);
    println!("mmap_prot_none_not_data={}", reserve.is_ok());
    let shared = map(16 * MIB, rw, libc::MAP_SHARED);
    println!("mmap_shared_rw_not_data={}", shared.is_ok());
    println!("brk_shrink_ok={}", brk(initial) == initial);
    let data = map(32 * MIB, rw, libc::MAP_PRIVATE);
    println!("mmap_rw_private_within_data_ok={}", data.is_ok());

    // ---- RLIMIT_AS: everything mapped counts; mremap growth counts.
    // Mapped now: 128 (PROT_NONE) + 16 (shared) + 32 (RW) = 176 MiB + baseline.
    println!("as_limit_set={}", set_limit(rlimit_as, 320 * MIB));
    let within = map(96 * MIB, libc::PROT_NONE, libc::MAP_PRIVATE);
    println!("mmap_within_as_ok={}", within.is_ok());
    // 272 + 96 = 368 MiB > 320.
    println!(
        "mmap_past_as_enomem={}",
        map(96 * MIB, libc::PROT_NONE, libc::MAP_PRIVATE) == Err(libc::ENOMEM)
    );
    let (remap_past, remap_within) = match data {
        Ok(addr) => (
            // 272 + (200 - 32) = 440 MiB > 320.
            remap(addr, 32 * MIB, 200 * MIB) == Err(libc::ENOMEM),
            // 272 + (48 - 32) = 288 MiB <= 320.
            remap(addr, 32 * MIB, 48 * MIB).is_ok(),
        ),
        Err(_) => (false, false),
    };
    println!("mremap_past_as_enomem={remap_past}");
    println!("mremap_within_as_ok={remap_within}");

    // ---- Fork inheritance: the child sees the same RLIMIT_AS.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let refused = map(96 * MIB, libc::PROT_NONE, libc::MAP_PRIVATE) == Err(libc::ENOMEM);
        unsafe { libc::_exit(if refused { 0 } else { 1 }) };
    }
    let mut status = 0i32;
    let reaped = unsafe { libc::waitpid(pid, &mut status, 0) } == pid;
    println!(
        "child_inherits_as_limit={}",
        pid > 0 && reaped && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    );

    if let Ok(addr) = within {
        let _ = unmap(addr, 96 * MIB);
    }
}
```

- [ ] **Step 2: Register the probe.** In `conformance-probes/probe-inventory.json`, directly BEFORE the `"rlimitnofile"` row add:

```json
  "rlimitasdata": {
    "class": "conformance",
    "excluded": false,
    "runner": "generic"
  },
```
In `crates/carrick-cli/tests/conformance.rs` replace `const PROBE_SOURCE_COUNT: usize = 467;` (line 3251) with `const PROBE_SOURCE_COUNT: usize = 468;`, and at lines 5000-5002 replace `421` → `422`, `441` → `442`, `882` → `884`. Run `python3 scripts/probe-inventory.py check` — expected: exit 0, `468 sources`. Run `cargo test -p carrick-cli --test conformance closure_probe_inventory` — expected: `ok`.

- [ ] **Step 3: Prove the probe RED under carrick, GREEN under Docker (two-phase).**

```sh
./scripts/build-probes.sh
just build
target/release/carrick run --platform linux/arm64 --fs host \
  -v "$PWD/conformance-probes/target/aarch64-unknown-linux-musl/release:/p:ro" \
  docker.io/library/ubuntu:24.04 /p/rlimitasdata
```
Expected BEFORE the fix (carrick): `brk_past_data_unchanged=false`, `mmap_rw_private_past_data_enomem=false`, `mmap_past_as_enomem=false`, `mremap_past_as_enomem=false`, `child_inherits_as_limit=false`; every other line `true`. After carrick exits:
```sh
docker run --rm --platform linux/arm64 \
  -v "$PWD/conformance-probes/target/aarch64-unknown-linux-musl/release:/p:ro" \
  docker.io/library/ubuntu:24.04 /p/rlimitasdata
```
Expected (Linux oracle), exactly:
```
data_limit_set=true
brk_16mib_ok=true
brk_past_data_unchanged=true
mmap_rw_private_past_data_enomem=true
mmap_prot_none_not_data=true
mmap_shared_rw_not_data=true
brk_shrink_ok=true
mmap_rw_private_within_data_ok=true
as_limit_set=true
mmap_within_as_ok=true
mmap_past_as_enomem=true
mremap_past_as_enomem=true
mremap_within_as_ok=true
child_inherits_as_limit=true
```

- [ ] **Step 4: Write the failing unit tests.** Append to the END of `crates/carrick-runtime/src/dispatch/mem/tests.rs` (the file already has `use super::*;` at line 1 and `use crate::memory::{LINUX_HEAP_BASE, LINUX_MMAP_BASE};` at line 3; `CountingMmapMemory::new(base, len)` is at :196, `returned(DispatchOutcome) -> i64` at :553, `capture_one_task_context()` is `SyscallDispatcher`'s at mod.rs:4104, and `dispatch(&mut self, &KernelContext, SyscallRequest, &mut impl GuestMemory, &CompatReporter)` at mod.rs:5780):

```rust
/// `RLIMIT_DATA` (proc(5) `VmData`) charges the brk heap and private
/// writable mappings only; `RLIMIT_AS` charges the union of every VMA.
#[test]
fn data_va_bytes_counts_only_private_writable_mappings_and_the_heap() {
    let mut mem = MemState::new();
    let entry = |start: u64, end: u64, write: bool, sharing: ProcMapSharing| ProcMapsEntry {
        start,
        end,
        read: true,
        write,
        execute: false,
        sharing,
        path: String::new(),
    };
    mem.dynamic_maps.push(entry(
        LINUX_MMAP_BASE,
        LINUX_MMAP_BASE + 3 * LINUX_PAGE_SIZE,
        true,
        ProcMapSharing::Private,
    ));
    mem.dynamic_maps.push(entry(
        LINUX_MMAP_BASE + 0x10_0000,
        LINUX_MMAP_BASE + 0x10_0000 + LINUX_PAGE_SIZE,
        true,
        ProcMapSharing::Shared,
    ));
    mem.dynamic_maps.push(entry(
        LINUX_MMAP_BASE + 0x20_0000,
        LINUX_MMAP_BASE + 0x20_0000 + LINUX_PAGE_SIZE,
        false,
        ProcMapSharing::Private,
    ));
    mem.brk_current = mem.layout.heap_base + 2 * LINUX_PAGE_SIZE;

    assert_eq!(data_va_bytes(&mem), 5 * LINUX_PAGE_SIZE);
    assert_eq!(committed_va_bytes(&mem), 7 * LINUX_PAGE_SIZE);
    assert_eq!(
        mapped_overlap_bytes(&mem, LINUX_MMAP_BASE + LINUX_PAGE_SIZE, 4 * LINUX_PAGE_SIZE),
        2 * LINUX_PAGE_SIZE
    );
}

/// `mmap` past the `RLIMIT_AS` soft limit is ENOMEM before any allocator or
/// VMA mutation: the arena cursor must not move.
#[test]
fn mmap_refuses_growth_past_rlimit_as_with_enomem() {
    const SYS_MMAP: u64 = 222;
    let mut dispatcher = SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().unwrap();
    let baseline = committed_va_bytes(&dispatcher.mem().lock());
    context
        .task()
        .replace_rlimit(carrick_abi::LinuxResource::As, |_| {
            Ok::<_, std::convert::Infallible>(carrick_abi::LinuxRlimit::new(
                baseline + 2 * LINUX_PAGE_SIZE,
                LINUX_RLIM_INFINITY,
            ))
        })
        .expect("set RLIMIT_AS");
    let mut memory = CountingMmapMemory::new(LINUX_MMAP_BASE, (4 * LINUX_PAGE_SIZE) as usize);
    let reporter = CompatReporter::default();
    let map = |len: u64| {
        SyscallRequest::new(
            SYS_MMAP,
            SyscallArgs([
                0,
                len,
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS,
                u64::MAX,
                0,
            ]),
        )
    };

    let first = dispatcher
        .dispatch(&context, map(2 * LINUX_PAGE_SIZE), &mut memory, &reporter)
        .expect("mmap dispatch");
    assert_eq!(returned(first), LINUX_MMAP_BASE as i64);

    let cursor = dispatcher.mem().lock().mmap_next;
    let second = dispatcher
        .dispatch(&context, map(LINUX_PAGE_SIZE), &mut memory, &reporter)
        .expect("mmap dispatch");
    assert_eq!(second, DispatchOutcome::errno(LINUX_ENOMEM));
    assert_eq!(dispatcher.mem().lock().mmap_next, cursor);
}

/// `brk` past the `RLIMIT_DATA` soft limit reports ENOMEM the way Linux does:
/// by returning the UNCHANGED break.
#[test]
fn brk_growth_past_rlimit_data_returns_the_unchanged_break() {
    const SYS_BRK: u64 = 214;
    let mut dispatcher = SyscallDispatcher::new();
    let context = dispatcher.capture_one_task_context().unwrap();
    let initial = dispatcher.mem().lock().layout.heap_base;
    let data_now = data_va_bytes(&dispatcher.mem().lock());
    context
        .task()
        .replace_rlimit(carrick_abi::LinuxResource::Data, |_| {
            Ok::<_, std::convert::Infallible>(carrick_abi::LinuxRlimit::new(
                data_now + LINUX_PAGE_SIZE,
                LINUX_RLIM_INFINITY,
            ))
        })
        .expect("set RLIMIT_DATA");
    let mut memory = CountingMmapMemory::new(initial, (2 * LINUX_PAGE_SIZE) as usize);
    let reporter = CompatReporter::default();
    let grow = |to: u64| SyscallRequest::new(SYS_BRK, SyscallArgs([to, 0, 0, 0, 0, 0]));

    let one = dispatcher
        .dispatch(&context, grow(initial + LINUX_PAGE_SIZE), &mut memory, &reporter)
        .expect("brk dispatch");
    assert_eq!(returned(one), (initial + LINUX_PAGE_SIZE) as i64);

    let two = dispatcher
        .dispatch(&context, grow(initial + 2 * LINUX_PAGE_SIZE), &mut memory, &reporter)
        .expect("brk dispatch");
    assert_eq!(
        returned(two),
        (initial + LINUX_PAGE_SIZE) as i64,
        "brk past RLIMIT_DATA must report the unchanged break"
    );
    assert_eq!(dispatcher.mem().lock().brk_current, initial + LINUX_PAGE_SIZE);
}
```

Run: `RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib -- dispatch::mem::tests::data_va_bytes_counts dispatch::mem::tests::mmap_refuses_growth_past_rlimit_as dispatch::mem::tests::brk_growth_past_rlimit_data`. Expected: compile errors `cannot find function data_va_bytes / committed_va_bytes / mapped_overlap_bytes` — red for the right reason.

- [ ] **Step 5: Import the two resource numbers.** In `crates/carrick-runtime/src/dispatch/mod.rs`, inside the `use crate::linux_abi::{ … }` block that starts at line 154 (`crate::linux_abi` is `pub use carrick_abi as linux_abi`, lib.rs:151), replace lines 426-427

```rust
    LINUX_RLIM_NLIMITS,
    LINUX_RLIMIT_MEMLOCK,
```
with
```rust
    LINUX_RLIM_NLIMITS,
    LINUX_RLIMIT_AS,
    LINUX_RLIMIT_DATA,
    LINUX_RLIMIT_MEMLOCK,
```
(`mem.rs:52` is `use super::*;`, which is how `LINUX_RLIMIT_MEMLOCK` and `LINUX_RLIM_INFINITY` already reach it; `just fmt` will settle the ordering.)

- [ ] **Step 6: Add the accounting helpers.** In `crates/carrick-runtime/src/dispatch/mem.rs`, directly after `project_vma_summaries` (its closing `}` is line 955, before the doc comment `/// Exact Linux-visible mapping metadata used by the live core publisher.`), insert:

```rust
/// Linux-visible virtual size of this mm in bytes — the `VmSize` that
/// `RLIMIT_AS` is measured against — as the union of the projected VMAs. Same
/// authority as `/proc/<pid>/maps` and the core publisher, so the limit and
/// the reported size cannot disagree.
fn committed_va_bytes(mem: &MemState) -> u64 {
    project_vma_summaries(mem)
        .iter()
        .map(|vma| vma.end.0.saturating_sub(vma.start.0))
        .sum()
}

/// Bytes of `[start, start + len)` that are already mapped. A `MAP_FIXED`
/// replacement is charged only for the remainder, as Linux charges it after
/// unmapping the overlap.
fn mapped_overlap_bytes(mem: &MemState, start: u64, len: u64) -> u64 {
    let end = start.saturating_add(len);
    project_vma_summaries(mem)
        .iter()
        .map(|vma| vma.end.0.min(end).saturating_sub(vma.start.0.max(start)))
        .sum()
}

/// Whether a mapping counts toward `RLIMIT_DATA` (proc(5) `VmData`): private,
/// writable, and not a grow-down stack VMA — anonymous or file-backed alike.
/// `PROT_NONE` reservations and `MAP_SHARED` mappings are address space, not
/// data.
fn mapping_is_data(write: bool, private: bool, growsdown: bool) -> bool {
    write && private && !growsdown
}

/// Bytes charged to `RLIMIT_DATA`: the brk heap span plus every private
/// writable mapping in the visible boot image (`.data`/`.bss`) and the dynamic
/// VMAs. A dynamic map overlapping a grow-down range is stack, not data.
fn data_va_bytes(mem: &MemState) -> u64 {
    let heap = mem.brk_current.saturating_sub(mem.layout.heap_base);
    let is_growdown = |map: &ProcMapsEntry| {
        mem.growdown_ranges
            .iter()
            .any(|(low, _, end)| map.start < *end && map.end > *low)
    };
    let maps: u64 = mem
        .address_space_regions
        .iter()
        .flatten()
        .filter(|map| !boot_region_is_hidden_reservation(map, mem.layout))
        .chain(mem.dynamic_maps.iter())
        .filter(|map| map.start < map.end)
        .filter(|map| {
            mapping_is_data(
                map.write,
                map.sharing == ProcMapSharing::Private,
                is_growdown(map),
            )
        })
        .map(|map| map.end - map.start)
        .sum();
    heap.saturating_add(maps)
}
```

Re-run the Step 4 command. Expected: `data_va_bytes_counts_only_private_writable_mappings_and_the_heap ... ok`; the other two FAIL (`mmap` returns `Returned` instead of `Errno`, `brk` moves the break).

- [ ] **Step 7: Add the limit helper on the dispatcher.** In `crates/carrick-runtime/src/dispatch/mem.rs`, directly above line 6294 (`    fn prepare_fresh_mmap_locked_length(`, i.e. after the `}` at 6292 that closes the previous method), insert:

```rust
    /// `RLIMIT_AS` / `RLIMIT_DATA` admission for a mapping change that grows
    /// this mm by `grow` page-rounded bytes; `data` says whether the grown
    /// bytes are data (`mapping_is_data`). setrlimit(2): both limits fail
    /// brk(2)/mmap(2)/mremap(2) with ENOMEM at the SOFT limit. Zero cost
    /// while both limits are infinite (carrick's defaults): two `ArcSwap`
    /// loads and no VMA walk. The caller holds the `MemState` lock so the
    /// population it reads is the one it is about to mutate.
    fn check_address_space_limits(
        &self,
        mem: &MemState,
        grow: u64,
        data: bool,
    ) -> Result<(), LinuxErrno> {
        let as_limit = self.effective_resource_limit(LINUX_RLIMIT_AS).rlim_cur;
        if as_limit != LINUX_RLIM_INFINITY
            && committed_va_bytes(mem)
                .checked_add(grow)
                .is_none_or(|total| total > as_limit)
        {
            return Err(LINUX_ENOMEM);
        }
        if data {
            let data_limit = self.effective_resource_limit(LINUX_RLIMIT_DATA).rlim_cur;
            if data_limit != LINUX_RLIM_INFINITY
                && data_va_bytes(mem)
                    .checked_add(grow)
                    .is_none_or(|total| total > data_limit)
            {
                return Err(LINUX_ENOMEM);
            }
        }
        Ok(())
    }

```

- [ ] **Step 8: Gate `mmap`.** In `crates/carrick-runtime/src/dispatch/mem.rs`, replace lines 2851-2852

```rust
            let length_usize =
                usize::try_from(length).map_err(|_| DispatchError::LengthTooLarge(length))?;
```
with
```rust
            let length_usize =
                usize::try_from(length).map_err(|_| DispatchError::LengthTooLarge(length))?;

            // RLIMIT_AS / RLIMIT_DATA admission before any allocator, backing
            // or VMA mutation. A MAP_FIXED replacement is charged only for the
            // bytes not already mapped.
            {
                let mem_authority_rlimit = this.mem();
                let mem = mem_authority_rlimit.lock();
                let grow = if map_flags.contains(LinuxMmapFlags::FIXED) {
                    length.saturating_sub(mapped_overlap_bytes(&mem, requested.0, length))
                } else {
                    length
                };
                let data = mapping_is_data(
                    prot_flags.contains(LinuxProtFlags::WRITE),
                    map_sharing == MmapSharing::Private,
                    map_flags.contains(LinuxMmapFlags::GROWSDOWN),
                );
                if let Err(errno) = this.check_address_space_limits(&mem, grow, data) {
                    return Ok(request.refused(
                        MmapRefusal::Spec("RLIMIT_AS or RLIMIT_DATA soft limit reached"),
                        errno,
                    ));
                }
            }
```
(At this point in the handler no `MemState` lock is held — the handler takes `this.mem().lock()` ad hoc, e.g. `dynamic_mapping_overlaps` at 2880 — so the scoped lock cannot self-deadlock. `map_sharing` is the unwrapped `MmapSharing` after the let-else at 2836-2841; `MmapSharing` already derives `PartialEq, Eq` (mem.rs:1035); `requested` is the `GuestVa`-typed address argument (`requested.0`, cf. 2829); `prot_flags`/`map_flags` are the parsed `LinuxProtFlags`/`LinuxMmapFlags`; `LinuxMmapFlags::{FIXED, GROWSDOWN}` and `LinuxProtFlags::WRITE` are `carrick_abi` lib.rs:4696-4698, 4798.)

Re-run the Step 4 command. Expected: `mmap_refuses_growth_past_rlimit_as_with_enomem ... ok`; the brk test still fails. (If it does NOT pass because the anonymous-private path in the unit harness records no `dynamic_maps` entry after the first mapping — existing tests at tests.rs:2614-2621 show entries ARE recorded after mmap under `threaded_memory_call`, so this is unlikely — the second assertion pinpoints it and the growth must then be read from the arena cursor delta instead of the VMA union.)

- [ ] **Step 9: Gate `brk`.** In `crates/carrick-runtime/src/dispatch/mem.rs`, replace lines 2703-2706

```rust
                if requested != current {
                    mem.brk_current = requested;
                    host_alias_dispatch.mark_vma_revision(this.mem().revision_publisher());
                }
```
with
```rust
                if requested > current {
                    // RLIMIT_AS / RLIMIT_DATA on the page-rounded growth; the
                    // heap is data by definition. brk(2) reports ENOMEM by
                    // returning the unchanged break.
                    let page_size = this.linux_page_size();
                    let grow = align_up_u64(requested, page_size)
                        .zip(align_up_u64(current, page_size))
                        .map_or(u64::MAX, |(new_end, old_end)| new_end.saturating_sub(old_end));
                    if this.check_address_space_limits(&mem, grow, true).is_err() {
                        return Ok(DispatchOutcome::Returned {
                            value: current as i64,
                        });
                    }
                }
                if requested != current {
                    mem.brk_current = requested;
                    host_alias_dispatch.mark_vma_revision(this.mem().revision_publisher());
                }
```
(Here `mem` is the `MemState` guard the handler already holds — `let mut mem = mem_authority_13.lock();` at 2661 — and `&mem` reborrows it immutably for the read-only check; `align_up_u64` is the `carrick_abi` `Option<u64>` helper the shrink branch above already uses.)

Re-run the Step 4 command. Expected: all three tests `ok`.

- [ ] **Step 10: Gate `mremap` growth.** In `crates/carrick-runtime/src/dispatch/mem.rs`, replace lines 4732-4735

```rust
            let source_metadata = match this.mremap_mapping_metadata(memory, old_address.0, old_size) {
                Ok(metadata) => metadata,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
```
with
```rust
            let source_metadata = match this.mremap_mapping_metadata(memory, old_address.0, old_size) {
                Ok(metadata) => metadata,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            if new_size > old_size {
                // RLIMIT_AS / RLIMIT_DATA on the growth, before any page-table,
                // allocator or VMA mutation. A move is charged like an in-place
                // grow (`new_size - old_size`): the source is unmapped again.
                let mem_authority_rlimit = this.mem();
                let mem = mem_authority_rlimit.lock();
                let data = mapping_is_data(
                    source_metadata.prot.contains(LinuxProtFlags::WRITE),
                    source_metadata.sharing == ProcMapSharing::Private,
                    false,
                );
                if this
                    .check_address_space_limits(&mem, new_size - old_size, data)
                    .is_err()
                {
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
            }
```
(`old_size`/`new_size` are the page-rounded sizes bound just above via `align_up_u64`; no `MemState` lock is held here — the handler reads `this.mem().lock().layout` ad hoc at 4726.)

Run `just clippy` — expected: clean (the `-D warnings` gate; in particular no unused-import or unused-`mut` warnings from the new tests).

- [ ] **Step 11: Prove the probe GREEN under carrick; regression-check the memory neighbours.**

```sh
just build
target/release/carrick run --platform linux/arm64 --fs host \
  -v "$PWD/conformance-probes/target/aarch64-unknown-linux-musl/release:/p:ro" \
  docker.io/library/ubuntu:24.04 /p/rlimitasdata
```
Expected: byte-identical to the Docker output in Step 3. Then `just test` — expected: green, including every existing `dispatch::mem::tests` case (the defaults are infinite, so no existing mmap/brk/mremap test crosses a limit).

- [ ] **Step 12: Run the probe gate.** As in Task 5 (Enforce `RLIMIT_NPROC` at fork reservation) Step 8 — do NOT bless (the arm64 cache is sparse and bless rewrites every deterministic probe); with no other carrick or Docker lane running:

```sh
just conformance-probes
```
Expected: `arm64:musl:rlimitasdata` MATCH (gating) and `arm64:gnu:rlimitasdata` MATCH (report-only); `brkheapgrow`, `mmapmunmap`, `mmapreuse`, `bigallocfree`, `rlimitroundtrip`, `rlimitresource`, `rlimitnofile` unchanged from `main`.

- [ ] **Step 13: Format and commit.**

```sh
just fmt
git add conformance-probes/src/bin/rlimitasdata.rs conformance-probes/probe-inventory.json \
  crates/carrick-cli/tests/conformance.rs crates/carrick-runtime/src/dispatch/mod.rs \
  crates/carrick-runtime/src/dispatch/mem.rs crates/carrick-runtime/src/dispatch/mem/tests.rs
git commit -F - <<'EOF'
fix(runtime): enforce RLIMIT_AS and RLIMIT_DATA at mmap, brk and mremap

Why: both limits were stored on the task and reported by `getrlimit` and
`/proc/<pid>/limits`, but `mmap`, `brk` and `mremap` never consulted them,
so a guest that capped its address space or data segment could keep
growing. setrlimit(2) makes all three fail with ENOMEM at the soft limit
(RLIMIT_DATA covering mmap since Linux 4.7), and brk reports it by
returning the unchanged break.

What: `RLIMIT_AS` is measured as the union of the Linux-visible VMAs
(`project_vma_summaries`, the same authority `/proc/<pid>/maps` and the
core publisher read, so the limit and the reported VmSize cannot disagree).
`RLIMIT_DATA` is the brk heap plus private, writable, non-grow-down
mappings (proc(5) VmData) — PROT_NONE reservations and MAP_SHARED maps are
address space, not data. `check_address_space_limits` runs before any
allocator, backing or VMA mutation in the three handlers; a MAP_FIXED
replacement is charged only for bytes not already mapped, and an mremap
move is charged like an in-place grow (stated approximation). The disabled
path — both limits infinite, carrick's defaults — is two `ArcSwap` loads
and no VMA walk.

Verified: `conformance-probes/src/bin/rlimitasdata` (DATA 64 MiB, AS
320 MiB; brk, private/PROT_NONE/shared mmaps, mremap growth, fork child
inheritance) was red against the pre-fix binary on five lines and matches
the Docker arm64 oracle after the fix; unit tests
`data_va_bytes_counts_only_private_writable_mappings_and_the_heap`,
`mmap_refuses_growth_past_rlimit_as_with_enomem` (arena cursor unchanged
on refusal) and `brk_growth_past_rlimit_data_returns_the_unchanged_break`;
`just test`, `just clippy`, `just conformance-probes`.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01VJcvGV5u1ErqZREKWUy6rU
EOF
```

---

### Task 7: Record the enforced limits in the syscall map and run the full gate

**Files:**
- Modify: `docs/syscalls-emulation-map.md:315` (the `getrlimit`/`setrlimit`/`prlimit64` row)
- Test: grep assertion (below); `just ci`; `just conformance-probes`

**Interfaces:** Consumes: nothing new. Produces: documentation only. (Enforcement sites the row cites, verified at HEAD: `RLIMIT_NOFILE` via `file_authority::types::NofileAllocationCeiling`; `RLIMIT_FSIZE` fs.rs:2011/7001; `RLIMIT_SIGPENDING` kernel/operations.rs:1858; `RLIMIT_MEMLOCK` mem.rs:6307; `RLIMIT_CORE` proc.rs:4671 + mod.rs:4774; `RLIMIT_CPU` time.rs:148 `arm_rlimit_cpu` enforcement pthread.)

- [ ] **Step 1: Failing assertion.** Run:

```sh
grep -c "RLIMIT_NPROC" docs/syscalls-emulation-map.md
```
Expected: `0` (exit status 1) — the map does not yet say which limits are enforced.

- [ ] **Step 2: Update the row.** In `docs/syscalls-emulation-map.md`, replace line 315

```
| `getrlimit`/`setrlimit`/`prlimit64` | 163,164,261 | Emulated (Partial) | per-process rlimit state | `prlimit64` (#261) emulated; `getrlimit`/`setrlimit` (#163/#164) are `Deferred` in the table but exercised through the `prlimit64`/`rlimitroundtrip` paths; invalid resource (≥16) → EINVAL. |
```
with
```
| `getrlimit`/`setrlimit`/`prlimit64` | 163,164,261 | Emulated (Partial) | per-task `RlimitSet` (`ArcSwap`) | `prlimit64` (#261) emulated; `getrlimit`/`setrlimit` (#163/#164) are `Deferred` in the table but exercised through the `prlimit64`/`rlimitroundtrip` paths; invalid resource (≥16) → EINVAL. Enforced: `RLIMIT_NOFILE`, `RLIMIT_FSIZE`, `RLIMIT_SIGPENDING`, `RLIMIT_MEMLOCK`, `RLIMIT_CORE`, `RLIMIT_CPU` (enforcement pthread), `RLIMIT_NPROC` (per real uid over live threads at fork reservation → `EAGAIN`; uid 0 / `CAP_SYS_ADMIN` / `CAP_SYS_RESOURCE` exempt; zombies and `clone_thread` not counted), `RLIMIT_AS` (union of visible VMAs at `mmap`/`brk`/`mremap` → `ENOMEM`), `RLIMIT_DATA` (heap + private writable non-stack mappings, proc(5) `VmData`, at `mmap`/`brk`/`mremap` → `ENOMEM`). Not enforced: `RLIMIT_STACK` (fixed layout; not consulted), `RLIMIT_RSS`, `RLIMIT_LOCKS`, `RLIMIT_MSGQUEUE`, `RLIMIT_NICE`, `RLIMIT_RTPRIO`, `RLIMIT_RTTIME`. Probes: `rlimitnproc`, `rlimitasdata`. |
```

Run `grep -c "RLIMIT_NPROC" docs/syscalls-emulation-map.md` — expected: `1`.

- [ ] **Step 3: Full local gate.** Run `just ci` — expected: `fmt-check → clippy → lint-domains → deny → check-matrix → check → doc → test → test-integration` all green. Then, with no other carrick or Docker lane running, `just conformance-probes` — expected: `rlimitnproc` and `rlimitasdata` MATCH on `arm64:musl` (gating) and the failure set is identical to the one recorded on `main` before Task 5 (Enforce `RLIMIT_NPROC` at fork reservation).

- [ ] **Step 4: Commit.**

```sh
git add docs/syscalls-emulation-map.md
git commit -F - <<'EOF'
docs: record RLIMIT_NPROC/AS/DATA enforcement in the syscall map

Why: the `getrlimit`/`setrlimit`/`prlimit64` row described only the
prlimit64 plumbing and said nothing about which of the sixteen limits the
runtime actually enforces, so a reader could not tell a stored limit from
an enforced one — the exact confusion the NPROC/AS/DATA fixes closed.

What: the row now lists the enforced set (NOFILE, FSIZE, SIGPENDING,
MEMLOCK, CORE, CPU, NPROC, AS, DATA) with the rule and errno for each of
the three new ones, the stated approximations (zombies and clone_thread
uncounted for NPROC; mremap moves charged as in-place growth), the limits
still unenforced, and the two gating probes.

Verified: `grep -c RLIMIT_NPROC docs/syscalls-emulation-map.md` = 1;
`just ci`; `just conformance-probes` with `rlimitnproc` and `rlimitasdata`
passing.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01VJcvGV5u1ErqZREKWUy6rU
EOF
```

<details><summary>Verifier problems fixed in place (18) and claims still unverified (7)</summary>

- fixed: Checked-out HEAD is 39426141, not 3dc6cc72 as the brief states; every anchor below was verified against 39426141.
- fixed: Task 4 line anchors in kernel/operations.rs are stale: `reserve_fork` is at 2496 (draft 2476); the ptr_eq/StaleContext block to extend is 2548-2554 (draft 2521-2527); `ForkParentExited`/`ForkParentChanged` are at 4250-4252 (draft 4165-4168); the `bootstrap` test helper is at 4369-4377 (draft 'ends at 4293'); `next_revision` (the natural free-fn neighbour) is at 4168.
- fixed: Task 4 objects.rs anchors are each off by 4: `ThreadResources::credentials` 2441, `Credentials::ruid` 1703, `Task::rlimit` 2926, `Task::caps` 2962, `Task::thread` 3928, `Thread::resources` 6022.
- fixed: Task 4 helper calls `caller.resources()` but `KernelContext` (kernel/core.rs:24-30) has only `kernel()`, `task()`, `thread()` accessors; `resources`, `thread`, `shared` are `pub(super)` FIELDS (that is what `reserve_fork` itself reads at 2549). Fixed to `caller.resources.credentials().ruid()`.
- fixed: Task 4 said to put the free fn `enforce_rlimit_nproc` 'directly above `pub fn reserve_fork`' — that is inside the `impl Kernel` block that starts at operations.rs:1182 and would not compile. Fixed: place it after the free fn `next_revision` (4168-4172).
- fixed: `ForkReservation::prepare_reference` is `#[cfg(test)] pub(crate)` (operations.rs:582-586), not `pub(super)`.
- fixed: `CapabilitySet::docker_default()` lives at namespace/process.rs:137 with `DOCKER_DEFAULT_CAPS = 0xa80425fb` at :36 (bits 21/24 clear), not at dispatch/time.rs:989-1001 (that is the prlimit hard-limit EPERM check).
- fixed: conformance.rs denominators: `assert_eq!(generic.len(), 419)` is at line 5000 (draft 4998), and lines 5001 (`generic.len() + DEDICATED_PROBE_RUNNERS.len() == 439`) and 5002 (`2 * (...) == 878`) also hard-code the count; the draft bumped only one of three, so `closure_probe_inventory_enforces_authoritative_runners_and_denominator` would still fail. Fixed to 466/420/440/880 (Task 4) and 467/421/441/882 (Task 5).
- fixed: Steps 8 (Task 4) and 12 (Task 5) expect `bless_probe_oracle` to write 'exactly one new file'. The gate prefers the committed cache and falls back to LIVE Docker per probe (conformance.rs:4548-4562); `probe-oracle/arm64-musl` holds only 9 committed entries (amd64-gnu 268, amd64-musl 273), so on this Mac a new arm64 probe is oracled live and running bless would write an entry for every deterministic probe with a binary (~440 new arm64-musl files). Replaced with `just conformance-probes` as the gate; removed the oracle file from Files/`git add`.
- fixed: The arm64 `gnu` probe set is `gating: false` (report-only, conformance.rs ~217); only the musl set gates. Expected-PASS wording fixed.
- fixed: quiesce.rs EAGAIN lowering block is 706-716 (warn at 713), commit-abort is 1131-1140 — corrected the first range.
- fixed: Task 4 probe printed `setrlimit_nproc_2=true{}` with a `_FAILED` suffix hack; simplified to a plain boolean line, matching the expected oracle output. Manual run commands switched from `alpine` to the lane image `docker.io/library/ubuntu:24.04` (what the harness uses, so it is already pulled).
- fixed: Task 5 probe hand-numbered `RLIMIT_DATA = 2`/`RLIMIT_AS = 9`; replaced with `libc::RLIMIT_DATA as i64`/`libc::RLIMIT_AS as i64`, the same shape Task 4 already uses for `RLIMIT_NPROC`.
- fixed: Task 5 mem.rs anchors: the brk hunk is at 2703-2706 (draft 2705-2708); `prepare_fresh_mmap_locked_length` starts at 6294 (draft 6293); `MmapSharing` (mem.rs:1035-1039) ALREADY derives `Clone, Copy, Debug, PartialEq, Eq`, so the 'add the derive if needed' caveat is dead and was removed; `MremapMappingMetadata` is at 1065-1072 with `prot: LinuxProtFlags`, `sharing: ProcMapSharing` as claimed.
- fixed: Task 5 `dispatch/mod.rs:426-427` is inside `use crate::linux_abi::{...}` (`linux_abi` is `pub use carrick_abi as linux_abi`, lib.rs:151), not a `carrick_abi::` block — noted so the engineer edits the right block.
- fixed: Task 5 tests.rs anchor 'line 6040' is meaningless: the file is 6,656 lines. Fixed to 'append at end of file'. Also aligned the ENOMEM assertion with the file's idiom (`DispatchOutcome::errno(LINUX_ENOMEM)`, which exists at mod.rs:1947).
- fixed: Task 5 unit test used `carrick_abi::NsUid`-style fully-qualified paths inconsistently; harmonized. Task 4 unit test now uses `carrick_abi::NsUid::new` like the neighbouring tests at operations.rs:5423.
- fixed: Task 6 doc row: enforcement claims verified in-tree (NOFILE via file_authority `NofileAllocationCeiling`, FSIZE fs.rs:2011/7001, SIGPENDING operations.rs:1858, MEMLOCK mem.rs:6307, CORE proc.rs:4671 + mod.rs:4774, CPU time.rs:148 `arm_rlimit_cpu`); 'carrier-scoped helper' reworded to 'enforcement pthread' to match time.rs:131-135.
- UNVERIFIED: The exact `-v host:guest:ro` mount syntax for `carrick run` used in the manual red-first commands (the harness's own probe mount at conformance.rs:3676-3740 was not read in full; adjust to whatever run_carrick_probe_with_policy passes).
- UNVERIFIED: That the anonymous-private mmap path records a `dynamic_maps` entry in the unit harness before the second mmap (so `committed_va_bytes` grows after the first mapping in `mmap_refuses_growth_past_rlimit_as_with_enomem`); if it does not, the test's second assertion exposes it and the check must read the arena cursor delta instead.
- UNVERIFIED: Whether `MmapSharing` (mem.rs:1036) already derives `PartialEq`; Step 8 says to add the derive if the `==` fails to compile.
- UNVERIFIED: The `probe-oracle/arm64-musl` layout is the only arm64 cache directory (ls showed amd64-gnu, amd64-musl, arm64-musl); the gnu arm64 lane is assumed to run against live Docker or be uncached.
- UNVERIFIED: Carrick's baseline visible VmSize/VmData for a static musl probe is assumed below 32 MiB (the margins in rlimitasdata rely on it); a larger baseline would show as a DIFF on `mmap_within_as_ok` / `mmap_rw_private_within_data_ok` and the sizes must then be raised, not the runtime bent.
- UNVERIFIED: The exact RLIMIT_DATA mapping predicate on Linux (private+writable+non-stack, since 4.7) is taken from setrlimit(2)/proc(5) wording and is verified only differentially by the probe.
- UNVERIFIED: `SyscallDispatcher::dispatch` takes `&mut self` (mod.rs:5732) — the new tests declare `let mut dispatcher` accordingly; the existing brk/mmap tests do the same.

</details>


<!-- cluster A4-dns-epoll -->
## Cluster A4-dns-epoll

> **Status:** verifier-corrected and cross-cluster reconciled (fixes applied: 3; notes: Fix 3: the A4 'deviation/consumes text' that says 'A6 deletion cluster' is not part of the markdown I was given (my cluster text begins at Task 6/8). If that text lives in a cluster preamble the orchestrator holds, it must be rewritten there: 'the A6 deletion cluster' -> 'A5 (Task 12, the `--raw` deletion)'. | Fix 2 landing order assumed: A1 -> A3 Task 6 (467) -> A3 Task 7 (468) -> this Task 10 (469) -> B4 Task 23 (470). The fix list stated A3's increments as 'Task 4: 467, Task 5: 468' in OLD numbering, i.e. new Tasks 5 and 6 — but the renumber table maps A3 to 5-7 and the collision note names A3 Task 6 (old) as the syscall-map doc row, so the two A3 source-adding tasks could be new 5+6 or 6+7. My text says 'A3 Task 6 ... 467 and A3 Task 7 ... 468' in one place; the A3 cluster's reconciled output is authoritative for WHICH of its tasks carry the increments — only the entry value 468 matters to this cluster. | Because A1 and A3 rewrite the PROBE_SOURCE_COUNT doc comment before this task, I could not quote the exact pre-edit doc-comment text; Task 10 Step 4 now appends a paragraph after A3's last `///` line and quotes only the constant line. The unmodified-tree line numbers (3251, 4996, 5001-5002, 1527, 3257-3262) are confirmed at HEAD 39426141 but will shift; the plan instructs `rg -n` re-derivation. | Verified at HEAD: conformance.rs:3251 `PROBE_SOURCE_COUNT: usize = 465`, :4996 dedicated pin 20, :5001-5002 pins 439/878; closure-probe-scenarios.py:18-19 pins 20/14 — the base ).

### Task 8: `epoll_ready_events` reports a queued synthetic datagram as EPOLLIN

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/net.rs:974-978` (the host-backed arm of `epoll_ready_events`, `stream_socket_fd` capture before `drop(open)`), `:1077-1085` (tail of the same arm, before the final mask), `:1090-1108` (`host_read_avail_for_poll`)
- Test: `crates/carrick-runtime/src/dispatch/net.rs` — new `#[cfg(test)] mod synthetic_datagram_readiness_tests`, inserted after the closing `}` of `mod icmp_ping_tests` (line 3273; line 3274 is blank) and before the `#[cfg(test)]` of `mod recvmmsg_tests` (lines 3275-3276)

**Interfaces:**
- Consumes: `SyscallDispatcher::host_socket_install(&self, family: i32, type_: i32, protocol: i32) -> DispatchOutcome` (net.rs:2077), `SyscallDispatcher::open_file(&self, fd: i32) -> Option<OpenFile>` (`dispatch/fs/fd_helpers.rs:213`, `pub(in crate::dispatch)`), `OpenDescription::HostSocket { synthetic_recv: VecDeque<(Vec<u8>, Vec<u8>)>, .. }` (`dispatch/fd_table.rs:1070-1085`), `fn synthetic_datagram_drain(&self, fd: i32) -> Option<(Vec<u8>, Vec<u8>)>` (net.rs:2762), `socket_addr_to_linux_sockaddr(std::net::SocketAddr) -> Option<Vec<u8>>` (net.rs:273), `LINUX_EPOLLIN: u32` / `LINUX_AF_INET: i32` / `LINUX_SOCK_DGRAM: i32` (`carrick-abi/src/lib.rs:4022,4504,4509`, already in scope via `use super::*`).
- Produces: no new signatures; `fn epoll_ready_events(&self, fd: i32, requested_events: u32) -> u32` now ORs `LINUX_EPOLLIN` in when `synthetic_recv` is non-empty, and `fn host_read_avail_for_poll(&self, fd: i32) -> u64` counts queued synthetic payload bytes.

Background (verified by reading the tree at HEAD `39426141`): `epoll_ready_events` (net.rs:864) has one `HostSocket` arm, guarded on `base.pending_socket_error().is_some()` (net.rs:933); every other host socket falls into the `_` arm (net.rs:940) and answers from a zero-timeout host `libc::poll` (net.rs:997). A datagram carrick queues in-process lives in `synthetic_recv` and is invisible to that poll. `poll_ready_events` DOES consult it (net.rs:1945-1960); `epoll_pwait` re-samples every host-backed interest through `epoll_ready_events` (net.rs:3829, :3953, :4082), so an epoll-driven resolver never sees the reply. `host_read_avail_for_poll` (net.rs:1090) feeds the `EPOLLET` read-growth baseline (`last_read_avail`) and likewise only reads FIONREAD on the host fd.

Landing order note: this cluster lands AFTER A1 (Tasks 1-3), A2 (Task 4) and A3 (Tasks 5-7). None of those touch `net.rs`, so the `net.rs` anchors above are stable; the `crates/carrick-cli/tests/conformance.rs` anchors in Task 10 are NOT (A1 and A3 both edit that file and its probe counts) and must be re-derived at landing time, as Task 10 says.

- [ ] **Step 1: Record the pre-fix base revision (Task 10's red-first needs it)**

```bash
cd /Volumes/CaseSensitive/carrick
SCRATCH=/private/tmp/claude-501/-Volumes-CaseSensitive-carrick/8f7faeb9-0217-4567-9ce8-8b805a8618e1/scratchpad
mkdir -p "$SCRATCH"
git rev-parse HEAD | tee "$SCRATCH/a4-base-sha"
```
Expected: one 40-hex SHA printed and saved (the tree's HEAD before any A4 change — i.e. the revision AFTER A3 Task 7 (syscall-map doc row) landed; it was `39426141…` when this plan was verified against the unmodified tree — a different SHA is fine, it only has to be the revision BEFORE Task 8's edit).

- [ ] **Step 2: Write the failing unit test**

Insert after the closing `}` of `mod icmp_ping_tests` (net.rs line 3273, keep the blank line 3274) and before `#[cfg(test)] mod recvmmsg_tests` (lines 3275-3276):

```rust
#[cfg(test)]
mod synthetic_datagram_readiness_tests {
    use super::*;

    /// A datagram carrick itself queued on a host-backed UDP socket (the bridge
    /// DNS gateway's answer, a loopback ICMP echo reply) lives in
    /// `synthetic_recv`, not in the host kernel, so the host `poll(2)` that
    /// `epoll_ready_events` trusts for sockets can never see it. Linux reports
    /// EPOLLIN for any queued datagram; so must the recompute `epoll_pwait`
    /// runs on every host-backed interest, and the ET read-growth baseline
    /// must count its bytes the way it counts an in-memory pipe's.
    #[test]
    fn queued_synthetic_datagram_is_epollin_ready() {
        let dispatcher = SyscallDispatcher::new();
        let fd = match dispatcher.host_socket_install(LINUX_AF_INET, LINUX_SOCK_DGRAM, 0) {
            DispatchOutcome::Returned { value } => value as i32,
            other => panic!("udp socket creation failed: {other:?}"),
        };
        // An unbound, unconnected UDP socket: the host kernel has nothing
        // queued, so any readiness below comes from the synthetic queue alone.
        assert_eq!(dispatcher.epoll_ready_events(fd, LINUX_EPOLLIN), 0);
        assert_eq!(dispatcher.host_read_avail_for_poll(fd), 0);

        let payload = b"\x12\x34\x81\x80reply".to_vec();
        let source = socket_addr_to_linux_sockaddr("172.31.0.1:53".parse().unwrap()).unwrap();
        {
            let open_file = dispatcher.open_file(fd).expect("udp socket open file");
            let mut open = open_file.description.write();
            let OpenDescription::HostSocket { synthetic_recv, .. } = &mut *open else {
                panic!("udp socket must be a HostSocket");
            };
            synthetic_recv.push_back((payload.clone(), source));
        }

        let ready = dispatcher.epoll_ready_events(fd, LINUX_EPOLLIN);
        assert_eq!(
            ready & LINUX_EPOLLIN,
            LINUX_EPOLLIN,
            "synthetic datagram must make the socket EPOLLIN-ready, got {ready:#x}"
        );
        assert_eq!(
            dispatcher.host_read_avail_for_poll(fd),
            payload.len() as u64,
            "the ET read-growth baseline must count synthetic bytes"
        );

        // Draining the queue takes the readiness with it.
        assert!(dispatcher.synthetic_datagram_drain(fd).is_some());
        assert_eq!(dispatcher.epoll_ready_events(fd, LINUX_EPOLLIN), 0);
        assert_eq!(dispatcher.host_read_avail_for_poll(fd), 0);
    }
}
```

- [ ] **Step 3: Run the test and watch it fail for the right reason**

```bash
cd /Volumes/CaseSensitive/carrick
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib synthetic_datagram_readiness_tests -- --nocapture
```
Expected: `test dispatch::net::synthetic_datagram_readiness_tests::queued_synthetic_datagram_is_epollin_ready ... FAILED` with the panic `synthetic datagram must make the socket EPOLLIN-ready, got 0x0` (left `0`, right `1`). (This is a single-crate focused run, not the forbidden bare workspace `--lib`; the `RUST_TEST_THREADS=1` matches how the `just test` recipe runs `carrick-runtime` — justfile:196.)

- [ ] **Step 4: Capture synthetic-queue readiness in the host-backed arm of `epoll_ready_events`**

In `crates/carrick-runtime/src/dispatch/net.rs` replace these exact lines (974-978):

```rust
                let stream_socket_fd = match &*open {
                    OpenDescription::HostSocket { host_fd, .. } => Some(host_fd.raw()),
                    _ => None,
                };
                drop(open);
```

with:

```rust
                // A datagram carrick itself queued (the bridge DNS gateway's
                // answer, a loopback ICMP echo reply) sits in `synthetic_recv`,
                // invisible to the host poll below: it is readable to the
                // guest, so it is EPOLLIN here too. `poll_ready_events` already
                // does this; `epoll_pwait` recomputes host-backed readiness
                // through THIS function, so it must as well.
                let (stream_socket_fd, synthetic_datagram_ready) = match &*open {
                    OpenDescription::HostSocket {
                        host_fd,
                        synthetic_recv,
                        ..
                    } => (Some(host_fd.raw()), !synthetic_recv.is_empty()),
                    _ => (None, false),
                };
                drop(open);
```

Then replace the tail of the same arm (lines 1077-1085):

```rust
                if requested_events & LINUX_EPOLLRDHUP != 0
                    && let Some(socket_fd) = stream_socket_fd
                    && host_stream_socket_read_eof(socket_fd)
                {
                    ready |= LINUX_EPOLLIN | LINUX_EPOLLRDHUP;
                }
                // Only report events the caller is watching, plus the
                // always-reported HUP/ERR conditions Linux delivers regardless.
                ready & (requested_events | LINUX_EPOLLHUP | LINUX_EPOLLERR)
```

with:

```rust
                if requested_events & LINUX_EPOLLRDHUP != 0
                    && let Some(socket_fd) = stream_socket_fd
                    && host_stream_socket_read_eof(socket_fd)
                {
                    ready |= LINUX_EPOLLIN | LINUX_EPOLLRDHUP;
                }
                // Asserted AFTER the SO_REUSEPORT turn-taking above: a synthetic
                // datagram is addressed to this exact socket (it answered this
                // socket's query), never to the group, so the group mask must
                // not hide it.
                if requested_events & LINUX_EPOLLIN != 0 && synthetic_datagram_ready {
                    ready |= LINUX_EPOLLIN;
                }
                // Only report events the caller is watching, plus the
                // always-reported HUP/ERR conditions Linux delivers regardless.
                ready & (requested_events | LINUX_EPOLLHUP | LINUX_EPOLLERR)
```

- [ ] **Step 5: Count synthetic bytes in `host_read_avail_for_poll`**

Replace the whole function (net.rs:1090-1108):

```rust
    fn host_read_avail_for_poll(&self, fd: i32) -> u64 {
        if let Some(open_file) = self.open_file(fd) {
            let open = open_file.description.read();
            if let OpenDescription::PipeReader { pipe, .. } = &*open {
                return pipe.buffered_bytes() as u64;
            }
        }
        let Some(host_fd) = self.host_fd_for_poll(fd) else {
            return 0;
        };
        let mut avail: libc::c_int = 0;
        let rc = unsafe { libc::ioctl(host_fd.get(), libc::FIONREAD, &mut avail) };
        let host = if rc == 0 && avail > 0 {
            avail as u64
        } else {
            0
        };
        host.saturating_add(self.staged_splice_pipe_bytes(fd) as u64)
    }
```

with:

```rust
    fn host_read_avail_for_poll(&self, fd: i32) -> u64 {
        // Bytes carrick queued on a socket outside the host kernel
        // (`synthetic_recv`). Counted into the ET read-growth baseline so a
        // gateway reply is a visible arrival, exactly as `pipe.buffered_bytes()`
        // is for an in-memory pipe; FIONREAD on the host fd cannot see them.
        let mut synthetic_bytes = 0u64;
        if let Some(open_file) = self.open_file(fd) {
            let open = open_file.description.read();
            match &*open {
                OpenDescription::PipeReader { pipe, .. } => return pipe.buffered_bytes() as u64,
                OpenDescription::HostSocket { synthetic_recv, .. } => {
                    synthetic_bytes = synthetic_recv
                        .iter()
                        .map(|(payload, _source)| payload.len() as u64)
                        .sum();
                }
                _ => {}
            }
        }
        let Some(host_fd) = self.host_fd_for_poll(fd) else {
            return synthetic_bytes;
        };
        let mut avail: libc::c_int = 0;
        let rc = unsafe { libc::ioctl(host_fd.get(), libc::FIONREAD, &mut avail) };
        let host = if rc == 0 && avail > 0 {
            avail as u64
        } else {
            0
        };
        host.saturating_add(self.staged_splice_pipe_bytes(fd) as u64)
            .saturating_add(synthetic_bytes)
    }
```

- [ ] **Step 6: Run the test again**

```bash
cd /Volumes/CaseSensitive/carrick
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib synthetic_datagram_readiness_tests -- --nocapture
```
Expected: `test dispatch::net::synthetic_datagram_readiness_tests::queued_synthetic_datagram_is_epollin_ready ... ok`, `test result: ok. 1 passed`.

- [ ] **Step 7: Format, lint, and run the host test gate**

```bash
cd /Volumes/CaseSensitive/carrick
just fmt
just clippy
just test
```
Expected: `just fmt` changes only `net.rs` (if anything); `just clippy` exits 0 with no warnings; `just test` prints `test result: ok` for every crate (the `carrick-runtime` serial pass includes the new test and the existing `icmp_ping_tests`, `epoll_kqueue_tests`, `staged_splice_readiness_tests`).

- [ ] **Step 8: Commit**

```bash
cd /Volumes/CaseSensitive/carrick
git add crates/carrick-runtime/src/dispatch/net.rs
git commit -F - <<'EOF'
fix(runtime): report queued synthetic datagrams as EPOLLIN in epoll

Why: `epoll_ready_events` answers HostSocket readiness with a zero-timeout
host `poll(2)`, but a datagram carrick queues in-process -- the bridge DNS
gateway's answer, a loopback ICMP echo reply -- lives in the socket's
`synthetic_recv` and never reaches the host kernel. `poll_ready_events`
already reports it as POLLIN; the epoll recompute did not, so an
epoll-driven resolver (Go's netpoller, libuv/c-ares) that queried
`172.31.0.1:53` under `--net bridge` sat in `epoll_wait` until its timeout
while the reply was already queued. Linux reports EPOLLIN for any queued
datagram.

What:
- `epoll_ready_events`: the host-backed arm captures
  `!synthetic_recv.is_empty()` before dropping the description lock and
  ORs EPOLLIN in after the SO_REUSEPORT turn mask (the reply is addressed
  to this socket, never to the group).
- `host_read_avail_for_poll`: counts synthetic payload bytes into the
  EPOLLET read-growth baseline, the way `pipe.buffered_bytes()` already
  does for in-memory pipes, so a reply is a visible arrival to the latch.

Verified: red-first unit test
`synthetic_datagram_readiness_tests::queued_synthetic_datagram_is_epollin_ready`
(0 before the fix, EPOLLIN after; draining the queue clears it and the
read-avail count); `just test`; `just clippy`.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
```

### Task 9: The DNS gateway publishes readiness when it queues a reply

**Files:**
- Modify: `crates/carrick-runtime/src/dispatch/net.rs:2692-2760` (`maybe_queue_icmp_echo_reply` and `maybe_queue_dns_response`; a shared `queue_synthetic_datagram` helper is added between `maybe_queue_dns_response` and `synthetic_datagram_drain` at :2762)
- Test: `crates/carrick-runtime/src/dispatch/net.rs` — new `#[cfg(test)] mod dns_gateway_wake_tests`, inserted directly after the `synthetic_datagram_readiness_tests` module from Task 8 (`epoll_ready_events` reports a queued synthetic datagram as EPOLLIN)

**Interfaces:**
- Consumes: `SyscallDispatcher::notify_inmem_epoll(&self)` (`dispatch/mod.rs:4659`; delegates to `epoll_shim::notify_inmem_epoll(&EpollWakeRegistry)` at `dispatch/epoll_shim.rs:52`, which triggers the user-wake fd of every registered epoll instance), `crate::dispatch::EpollKqueue` (`pub(crate) struct`, `dispatch/mod.rs:2789`) with `pub(crate) fn new(mux: Box<dyn carrick_hal::event::EventMultiplexer>, wake_registry: EpollWakeRegistry) -> Self` (:2806) and `pub(crate) fn poll_fd(&self) -> i32` (:2824), `crate::event_mux::make_event_multiplexer() -> Result<Box<dyn EventMultiplexer>, OsError>` (`event_mux.rs:41`), `EventMultiplexer::register_user(&mut self, ident: u64)` (trait already in scope in net.rs — used at :4435), `SyscallDispatcher::captured_file_table(&self) -> Arc<crate::kernel::FileTable>` (`dispatch/mod.rs:5598`; under `cfg(test)` it captures the dispatcher's one-task context, whose file table is stable across calls — the existing ICMP test's `host_socket_install` → `open_file` already depends on that), `FileTable::epoll_wake_registry(&self) -> &EpollWakeRegistry` (`kernel/objects.rs:1324`; `EpollWakeRegistry = Arc<Mutex<Vec<i32>>>`, `epoll_shim.rs:7`, hence `Arc::clone`), `crate::network::RuntimeNetwork::create(&NetworkNamespaceSpec) -> Result<Self, String>` (`network/mod.rs:386`; `pub spec` field at :336, `spec.gateway_v4: Ipv4Addr` is `pub` in `carrick-spec/src/lib.rs:475`), `carrick_spec::NetworkNamespaceSpec::bridge_default(Option<String>, Vec<String>, Vec<PortMapping>)` (`carrick-spec/src/lib.rs:487`), `hickory_proto::op::Message::{query, to_vec, from_vec}` and `.metadata.id` (hickory-proto 0.26.1, a regular dependency at `carrick-runtime/Cargo.toml:127`; the same calls are used by `network/dns.rs:93-118` and its tests at :192-197).
- Produces: `fn queue_synthetic_datagram(&self, fd: i32, payload: Vec<u8>, source: Vec<u8>) -> bool` (private method on `SyscallDispatcher` in net.rs; the single push-then-broadcast owner for every in-process datagram producer — Phase H's network mocking should call it rather than touching `synthetic_recv`).

Background (verified at HEAD `39426141`): `maybe_queue_icmp_echo_reply` pushes and then calls `self.notify_inmem_epoll()` (net.rs:2722-2724); `maybe_queue_dns_response` pushes and returns (net.rs:2758-2759) — no broadcast. Both are called from `sendto` (net.rs:6655, :6662) and `sendmsg` (net.rs:7759-7761). A waiter already parked in `epoll_wait` sits on the instance's kqueue `poll_fd`; only a host-kernel filter or `notify_inmem_epoll` (`EVFILT_USER(0)` on macOS, the user-wake eventfd on Linux — `epoll_shim.rs:40-58`) can pop it, and after the pop `epoll_pwait` re-samples host-backed interests through `epoll_ready_events` (net.rs:3941-3953), which Task 8 (`epoll_ready_events` reports a queued synthetic datagram as EPOLLIN) made synthetic-aware. `crate::host_signal::wake_all_waiters` is NOT added to the helper: the netlink producer calls it (net.rs:2688) because a netlink fd has no host backing to park on, whereas a blocking `recvfrom`/`recvmsg` on a host UDP socket drains `synthetic_recv` BEFORE it parks (net.rs:6833, :8031), so the sending thread's own follow-up receive needs no nudge. (Note the function is real on macOS — `carrick_vmm_hvf::host_signal::wake_all_waiters`, `host_signal.rs:923`, broadcasts to every parked private waiter; it is the empty stub only on the Linux/FreeBSD/NetBSD `host_signal` module, `lib.rs:487-954`.) A thread ALREADY parked in a blocking `recvfrom` on the same socket while a sibling thread sends the query is a pre-existing gap shared with the ICMP path and is out of this cluster's scope.

- [ ] **Step 1: Write the failing unit test**

Insert directly after the closing `}` of `mod synthetic_datagram_readiness_tests`:

```rust
#[cfg(test)]
mod dns_gateway_wake_tests {
    use super::*;
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{Name, RecordType};

    fn poll_fd_readable(fd: i32) -> bool {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd as *mut _, 1, 0) };
        rc == 1 && pfd.revents & libc::POLLIN != 0
    }

    /// The bridge DNS gateway answers a guest query in-process, straight into
    /// the socket's `synthetic_recv`. A thread already parked in `epoll_wait`
    /// on that socket sits on the instance kqueue, which only the host kernel
    /// or `notify_inmem_epoll` can pulse; the host never sees the reply, so
    /// the gateway must publish the wake itself (as the ICMP echo path does).
    #[test]
    fn dns_gateway_reply_wakes_parked_epoll_instance() {
        let network = crate::network::RuntimeNetwork::create(
            &carrick_spec::NetworkNamespaceSpec::bridge_default(
                Some("dns-epoll-wake".to_string()),
                Vec::new(),
                Vec::new(),
            ),
        )
        .expect("create bridge network");
        // Direct field assignment (net.rs is a child module of `dispatch`, so
        // the private field is visible) rather than
        // `SyscallDispatcher::with_network`: that constructor also publishes
        // the root net view process-wide and mounts `/etc/resolv.conf`,
        // neither of which this test needs and the former of which would leak
        // into sibling tests in the same process.
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.network = Arc::new(network);
        let gateway = std::net::SocketAddr::new(
            std::net::IpAddr::V4(dispatcher.network.spec.gateway_v4),
            53,
        );
        assert!(dispatcher.is_dns_gateway_addr(gateway));

        let fd = match dispatcher.host_socket_install(LINUX_AF_INET, LINUX_SOCK_DGRAM, 0) {
            DispatchOutcome::Returned { value } => value as i32,
            other => panic!("udp socket creation failed: {other:?}"),
        };

        // Exactly what `epoll_create1` builds (net.rs:4430-4439): a multiplexer
        // with its user-wake armed, registered in THIS dispatcher's wake
        // registry.
        let mut mux = crate::event_mux::make_event_multiplexer().expect("event multiplexer");
        mux.register_user(0).expect("register user wake");
        let epoll = crate::dispatch::EpollKqueue::new(
            mux,
            Arc::clone(dispatcher.captured_file_table().epoll_wake_registry()),
        );
        assert!(
            !poll_fd_readable(epoll.poll_fd()),
            "a fresh epoll instance must be quiet"
        );

        let mut query = Message::query();
        query.add_query(Query::query(
            Name::from_ascii("localhost.").expect("name"),
            RecordType::A,
        ));
        let request = query.to_vec().expect("encode query");

        assert!(
            dispatcher.maybe_queue_dns_response(fd, &request, gateway),
            "the gateway must answer a query addressed to gateway_v4:53"
        );
        assert!(
            poll_fd_readable(epoll.poll_fd()),
            "DNS gateway reply must wake the epoll instance's poll fd"
        );

        let (reply, source) = dispatcher
            .synthetic_datagram_drain(fd)
            .expect("reply queued on the querying socket");
        assert_eq!(
            Message::from_vec(&reply).expect("parse reply").metadata.id,
            query.metadata.id
        );
        assert_eq!(source, socket_addr_to_linux_sockaddr(gateway).unwrap());
    }
}
```

- [ ] **Step 2: Run the test and watch it fail for the right reason**

```bash
cd /Volumes/CaseSensitive/carrick
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib dns_gateway_wake_tests -- --nocapture
```
Expected: `test dispatch::net::dns_gateway_wake_tests::dns_gateway_reply_wakes_parked_epoll_instance ... FAILED` with the panic `DNS gateway reply must wake the epoll instance's poll fd` (the earlier asserts — gateway address recognised, fresh instance quiet, `maybe_queue_dns_response` returned `true` — all pass, proving the reply was queued but no wake was published). `localhost.` resolves through `resolve_host_a` → the HOST's `/etc/hosts` (`network/dns.rs:33-38`), so no real nameserver round-trip happens; even an empty lookup still yields an NXDOMAIN reply and `true`.

- [ ] **Step 3: Add the shared producer and route both in-process datagram sources through it**

In `crates/carrick-runtime/src/dispatch/net.rs`, replace the tail of `maybe_queue_icmp_echo_reply` (these exact lines, 2713-2726):

```rust
        let checksum = internet_checksum(&response);
        response[2..4].copy_from_slice(&checksum.to_be_bytes());
        let Some(open_file) = self.open_file(fd) else {
            return false;
        };
        let mut open = open_file.description.write();
        let OpenDescription::HostSocket { synthetic_recv, .. } = &mut *open else {
            return false;
        };
        synthetic_recv.push_back((response, source));
        drop(open);
        self.notify_inmem_epoll();
        true
    }
```

with:

```rust
        let checksum = internet_checksum(&response);
        response[2..4].copy_from_slice(&checksum.to_be_bytes());
        self.queue_synthetic_datagram(fd, response, source)
    }
```

Replace the tail of `maybe_queue_dns_response` (these exact lines, 2748-2760):

```rust
        }) else {
            return false;
        };
        let Some(open_file) = self.open_file(fd) else {
            return false;
        };
        let mut open = open_file.description.write();
        let OpenDescription::HostSocket { synthetic_recv, .. } = &mut *open else {
            return false;
        };
        synthetic_recv.push_back((response, source));
        true
    }
```

with:

```rust
        }) else {
            return false;
        };
        self.queue_synthetic_datagram(fd, response, source)
    }

    /// Park a datagram carrick produced in-process on `fd`'s synthetic receive
    /// queue and publish the readiness change.
    ///
    /// The host kernel never sees these bytes, so nothing on an epoll
    /// instance's kqueue fires for them: a waiter already parked in
    /// `epoll_wait` must be pulsed through `notify_inmem_epoll`, after which
    /// its re-sample (`epoll_ready_events`) reports the queue as EPOLLIN. A
    /// `recvfrom`/`recvmsg` issued after the send needs no wake -- it drains
    /// this queue before touching the host fd (`synthetic_datagram_drain`).
    /// Every in-process datagram producer (ICMP echo, the DNS gateway) goes
    /// through here so none can forget the broadcast again.
    fn queue_synthetic_datagram(&self, fd: i32, payload: Vec<u8>, source: Vec<u8>) -> bool {
        let Some(open_file) = self.open_file(fd) else {
            return false;
        };
        {
            let mut open = open_file.description.write();
            let OpenDescription::HostSocket { synthetic_recv, .. } = &mut *open else {
                return false;
            };
            synthetic_recv.push_back((payload, source));
        }
        self.notify_inmem_epoll();
        true
    }
```

- [ ] **Step 4: Run the new test and the ICMP sibling**

```bash
cd /Volumes/CaseSensitive/carrick
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib dns_gateway_wake_tests -- --nocapture
RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib icmp_ping_tests -- --nocapture
```
Expected: `dns_gateway_reply_wakes_parked_epoll_instance ... ok` and `loopback_echo_reply_is_queued_with_valid_checksum ... ok` (the ICMP path still queues a checksummed reply through the shared helper).

- [ ] **Step 5: Format, lint, and run the host test gate**

```bash
cd /Volumes/CaseSensitive/carrick
just fmt
just clippy
just test
```
Expected: `just clippy` exits 0 with no warnings (no `dead_code` — both producers call the helper); `just test` prints `test result: ok` for every crate.

- [ ] **Step 6: Commit**

```bash
cd /Volumes/CaseSensitive/carrick
git add crates/carrick-runtime/src/dispatch/net.rs
git commit -F - <<'EOF'
fix(runtime): wake parked epoll waiters when the DNS gateway answers

Why: `maybe_queue_dns_response` filled `synthetic_recv` and returned;
unlike its ICMP sibling it never called `notify_inmem_epoll`. A thread
already parked in `epoll_wait` on the querying socket sits on the
instance kqueue, which only the host kernel or that broadcast can pulse,
and the host never sees the in-process reply -- so a resolver whose
poller was parked before the query was sent (Go's netpoller M, libuv's
loop thread with c-ares) slept through the answer until its deadline.
With the previous commit the re-sample after a wake reports EPOLLIN;
this commit provides the wake.

What: one `queue_synthetic_datagram(fd, payload, source)` now owns the
push-then-broadcast for both in-process datagram producers (ICMP echo
and the DNS gateway), deleting the duplicated queue code in each. A
blocking `recvfrom`/`recvmsg` issued after the send needs no wake: it
drains the synthetic queue before touching the host fd. A sibling
thread already parked in a blocking `recvfrom` on the same socket is a
pre-existing gap shared with the ICMP path and is not addressed here.

Verified: red-first unit test
`dns_gateway_wake_tests::dns_gateway_reply_wakes_parked_epoll_instance`
-- a bridge-mode dispatcher, an `EpollKqueue` registered in its wake
registry, `maybe_queue_dns_response` for `localhost.` addressed to
`gateway_v4:53`; the instance poll fd was not readable before the fix
and is after; `icmp_ping_tests` still green; `just test`; `just clippy`.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
```

### Task 10: Guest probe `bridge_dns_epoll_wake` with a dedicated bridge runner

**Files:**
- Create: `conformance-probes/src/bin/bridge_dns_epoll_wake.rs`
- Modify: `conformance-probes/probe-inventory.json:67-76` (new row between `bridge_compose_server` and `bridge_loopback_isolation`), `crates/carrick-cli/tests/conformance.rs` — the `PROBE_SOURCE_COUNT` doc + value (at `:3225-3251` on the unmodified tree), `DEDICATED_PROBE_RUNNERS` (`:3257-3262` unmodified), the `assert_eq!(DEDICATED_PROBE_RUNNERS.len(), 20)` pin (`:4996` unmodified), the gating-row pins in the same test (`:5001-5002` unmodified), new `#[test] fn conformance_bridge_dns_epoll_wake` inserted before the `#[test]` of `fn conformance_bridge_reuse_sockopts` (`:1527-1528` unmodified), `scripts/conformance/closure-probe-scenarios.py:18-19`, `docs/conformance-coverage.md:107` (new bridge-table row after `bridge_udp_sendto_unreachable`)
- Test: `crates/carrick-cli/tests/conformance.rs::closure_probe_inventory_enforces_authoritative_runners_and_denominator` (pure, no guest) and `conformance_bridge_dns_epoll_wake` (HVF guest + Docker oracle, signed recipe)

**Landing-order denominators (this task lands after A1 Tasks 1-3 and A3 Tasks 5-7, which each add probe sources to the SAME counters):** A1 moves the tree to `PROBE_SOURCE_COUNT = 466` / generic 420 / gating rows 440 / 880; A3 Task 6 (`ProcessLimitExceeded` probe) to 467 / 421 / 441 / 882 and A3 Task 7 to 468 / 422 / 442 / 884. Neither adds a dedicated runner, so `DEDICATED_PROBE_RUNNERS.len()` is still 20 and `closure-probe-scenarios.py` still pins 20 / 14 when this task starts. This task therefore moves: `PROBE_SOURCE_COUNT` 468 -> **469**, `DEDICATED_PROBE_RUNNERS.len()` 20 -> **21**, gating rows 442 -> **443** (`generic.len()` stays **422**) and 884 -> **886**, `DEDICATED_SOURCE_COUNT` 20 -> 21, `DEDICATED_RUNNER_COUNT` 14 -> 15. (B4 Task 23 later moves them once more to 470 / 22 / 444 / 888 — the final tree.) Every `conformance.rs` line number quoted below is the UNMODIFIED-tree anchor and MUST be re-derived with `rg -n` at landing time, because A1 and A3 insert text into that file first; the replaced TEXT (constant values, allowlist entries, pins) is what to match on.

**Interfaces:**
- Consumes (harness, all in `crates/carrick-cli/tests/conformance.rs`, unmodified-tree anchors): `CONFORMANCE_LOCK` (:32), `ARM64: Lane` (:206), `carrick_bin() -> Option<PathBuf>` (:353), `lane_runnable_here(&Lane) -> bool` (:2388), `probes_dir(&str) -> PathBuf` (:3206), `selected_dedicated_probe_target(&Lane) -> Result<&'static str, String>` (:2382), `ensure_signed(&PathBuf)` (:2540), `run_bridge_probe(&PathBuf, Lane, &[u8]) -> String` (:509, injects `--net bridge` via `bridge_probe_args` :393 — note `bridge_probe_args` is one of the seven `run --raw` sites A5 Task 12 rewrites in this file; that edit is A5's, not this cluster's, and this runner is unaffected by it either way), `run_docker_probe(Lane, &[u8]) -> io::Result<String>` (:3871, plain `docker run -i --rm --platform … ubuntu:24.04` on Docker's default network), `diff_lines(&str, &str) -> Option<String>` (:3912); `conformance_probes::report!` (`conformance-probes/src/lib.rs:172`, `#[macro_export]`).
- Produces: probe binary `bridge_dns_epoll_wake` (auto-discovered bin, `conformance-probes/Cargo.toml` `autobins = true`), runner `conformance_bridge_dns_epoll_wake`; `PROBE_SOURCE_COUNT == 469`, `DEDICATED_PROBE_RUNNERS.len() == 21`, gating rows `422 + 21 == 443` / `886`, `DEDICATED_SOURCE_COUNT = 21`, `DEDICATED_RUNNER_COUNT = 15` (the values B4 Task 23 starts from).

Background (verified): generic probes run under the default host network, where `embedded_dns` is false (`HostNetworkProvider::capabilities`, `network/mod.rs:217`), so the DNS gateway is only exercised by a dedicated `--net bridge` runner. Adding a probe source without its inventory row fails `validate_closure_probe_rows` (conformance.rs:3350 unmodified) and the `PROBE_SOURCE_COUNT` denominator (:3251 unmodified; 465 on the unmodified tree, 468 when this task starts); dedicated runners are the allowlist `DEDICATED_PROBE_RUNNERS` (:3256 unmodified, 20 entries, asserted at :4996 unmodified), and the SAME test pins the gating rows (:5001-5002 unmodified) as `generic + dedicated` and `2 * (generic + dedicated)` — dedicated sources ARE part of the gating rows, so a new dedicated source moves them (from 442/884 to 443/886 at this task's landing point). `scripts/conformance/closure-probe-scenarios.py` pins `DEDICATED_SOURCE_COUNT = 20` / `DEDICATED_RUNNER_COUNT = 14`. Under bridge mode the guest's `/etc/resolv.conf` is rendered from the resolver model (`network/model.rs:276-277`), whose nameserver list is the bridge gateway when the spec carries no `dns_servers` (`model.rs:635-637`), i.e. `nameserver 172.31.0.1`; the Docker oracle runs on Docker's default bridge with whatever nameserver its `/etc/resolv.conf` carries. The probe therefore prints only booleans (never an rcode or timing) and the runner asserts the two wake invariants on carrick's output BEFORE the diff, so an oracle-side resolver outage (both sides `false`) cannot pass as a MATCH.

- [ ] **Step 1: Write the probe**

Create `conformance-probes/src/bin/bridge_dns_epoll_wake.rs`:

```rust
//! A datagram the runtime answers IN-PROCESS must wake `epoll_wait` exactly
//! like one the kernel delivered.
//!
//! Under `--net bridge` the `/etc/resolv.conf` nameserver is the embedded DNS
//! gateway (`172.31.0.1:53`); carrick answers a query from `sendto` itself and
//! parks the reply on the socket, never on the host kernel. Linux semantics
//! (epoll(7)): a queued datagram makes the socket EPOLLIN-ready, and a thread
//! already blocked in `epoll_wait` on it wakes when the datagram arrives. Both
//! halves are checked, each bounded by an `epoll_wait` timeout so a missed
//! wake prints `false` instead of hanging the harness. Only booleans are
//! printed: the oracle's resolver may answer NXDOMAIN where carrick answers
//! `localhost.` from `/etc/hosts`, and the diff must not see that.

use conformance_probes::report;
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;

const EPOLLIN: u32 = libc::EPOLLIN as u32;
const QUERY_ID_READY: u16 = 0x1234;
const QUERY_ID_PARKED: u16 = 0x5678;

#[derive(Default)]
struct Results {
    nameserver_ok: bool,
    socket_ok: bool,
    add_ok: bool,
    send_ok: bool,
    ready_after_send: bool,
    reply_id_matches: bool,
    wake_while_parked: bool,
    parked_reply_id_matches: bool,
}

fn report_results(r: &Results) {
    report!(
        dns_epoll_nameserver_ok = r.nameserver_ok,
        dns_epoll_socket_ok = r.socket_ok,
        dns_epoll_add_ok = r.add_ok,
        dns_epoll_send_ok = r.send_ok,
        dns_epoll_ready_after_send = r.ready_after_send,
        dns_epoll_reply_id_matches = r.reply_id_matches,
        dns_epoll_wake_while_parked = r.wake_while_parked,
        dns_epoll_parked_reply_id_matches = r.parked_reply_id_matches,
    );
}

/// First IPv4 `nameserver` of `/etc/resolv.conf`, as a stub resolver reads it.
fn resolv_conf_nameserver() -> Option<Ipv4Addr> {
    let text = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    text.lines().find_map(|line| {
        let mut fields = line.split('#').next().unwrap_or("").split_whitespace();
        match fields.next() {
            Some("nameserver") => fields.next()?.parse::<Ipv4Addr>().ok(),
            _ => None,
        }
    })
}

/// A minimal RFC 1035 A query: header (id, RD, QDCOUNT=1) and one question.
fn dns_a_query(id: u16, name: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&[0u8; 6]); // ANCOUNT, NSCOUNT, ARCOUNT
    for label in name.split('.').filter(|label| !label.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0); // root label
    out.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
    out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    out
}

unsafe fn send_query(sock: i32, nameserver: Ipv4Addr, id: u16) -> bool {
    let query = dns_a_query(id, "localhost.");
    let mut addr: libc::sockaddr_in = std::mem::zeroed();
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = 53u16.to_be();
    addr.sin_addr = libc::in_addr {
        s_addr: u32::from_ne_bytes(nameserver.octets()),
    };
    let rc = libc::sendto(
        sock,
        query.as_ptr().cast::<libc::c_void>(),
        query.len(),
        0,
        (&addr as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
    );
    rc == query.len() as isize
}

/// One bounded `epoll_wait`; true iff exactly one EPOLLIN event came back.
fn wait_epollin(epfd: i32, timeout_ms: i32) -> bool {
    let mut out = [libc::epoll_event { events: 0, u64: 0 }; 1];
    let n = unsafe { libc::epoll_wait(epfd, out.as_mut_ptr(), 1, timeout_ms) };
    n == 1 && out[0].events & EPOLLIN != 0
}

/// Drain one reply without blocking and return its transaction id.
unsafe fn recv_reply_id(sock: i32) -> Option<u16> {
    let mut buf = [0u8; 512];
    let n = libc::recv(
        sock,
        buf.as_mut_ptr().cast::<libc::c_void>(),
        buf.len(),
        libc::MSG_DONTWAIT,
    );
    if n < 2 {
        return None;
    }
    Some(u16::from_be_bytes([buf[0], buf[1]]))
}

unsafe fn run(r: &mut Results) {
    let Some(nameserver) = resolv_conf_nameserver() else {
        return;
    };
    r.nameserver_ok = true;

    let sock = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
    r.socket_ok = sock >= 0;
    if !r.socket_ok {
        return;
    }
    let epfd = libc::epoll_create1(0);
    if epfd >= 0 {
        let mut ev = libc::epoll_event {
            events: EPOLLIN,
            u64: sock as u64,
        };
        r.add_ok = libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, sock, &mut ev) == 0;
    }
    if !r.add_ok {
        if epfd >= 0 {
            libc::close(epfd);
        }
        libc::close(sock);
        return;
    }

    // (a) Reply queued before the wait: the readiness sample must see it.
    r.send_ok = send_query(sock, nameserver, QUERY_ID_READY);
    if r.send_ok {
        r.ready_after_send = wait_epollin(epfd, 2000);
        r.reply_id_matches = recv_reply_id(sock) == Some(QUERY_ID_READY);
    }

    // (b) Waiter parked first, reply arrives later: the wake must be
    // published. The sleep only makes "parked first" likely; if the send
    // lands before the park, case (a) applies and the boolean is still true.
    let waiter = thread::spawn(move || wait_epollin(epfd, 3000));
    thread::sleep(Duration::from_millis(300));
    if send_query(sock, nameserver, QUERY_ID_PARKED) {
        r.wake_while_parked = waiter.join().unwrap_or(false);
        r.parked_reply_id_matches = recv_reply_id(sock) == Some(QUERY_ID_PARKED);
    } else {
        let _ = waiter.join();
    }

    libc::close(epfd);
    libc::close(sock);
}

fn main() {
    let mut results = Results::default();
    unsafe { run(&mut results) };
    report_results(&results);
}
```

- [ ] **Step 2: Run the inventory gate and watch it fail (source exists, no row, stale denominator)**

```bash
cd /Volumes/CaseSensitive/carrick
cargo test -p carrick-cli --test conformance closure_probe_inventory_enforces_authoritative_runners_and_denominator -- --exact --nocapture
```
Expected: `FAILED` at `assert_eq!(sources.len(), PROBE_SOURCE_COUNT)` (conformance.rs:4997 on the unmodified tree; re-derive) — `left: 469, right: 468`. (The preceding `assert_eq!(DEDICATED_PROBE_RUNNERS.len(), 20)` still passes at this point. If `right` is not 468, A1 Tasks 1-3 or A3 Tasks 5-7 have not landed in the order this plan assumes — stop and reconcile the denominator chain before continuing. Run from the repo root: from any other cwd `all_probe_source_names` finds no sources and the test reports a green that gated nothing.)

- [ ] **Step 3: Add the inventory row**

In `conformance-probes/probe-inventory.json`, replace these exact lines (67-76):

```json
  "bridge_compose_server": {
    "class": "conformance",
    "excluded": false,
    "runner": "conformance_bridge_compose_pair"
  },
  "bridge_loopback_isolation": {
    "class": "conformance",
    "excluded": false,
    "runner": "conformance_bridge_loopback_isolation"
  },
```

with:

```json
  "bridge_compose_server": {
    "class": "conformance",
    "excluded": false,
    "runner": "conformance_bridge_compose_pair"
  },
  "bridge_dns_epoll_wake": {
    "class": "conformance",
    "excluded": false,
    "runner": "conformance_bridge_dns_epoll_wake"
  },
  "bridge_loopback_isolation": {
    "class": "conformance",
    "excluded": false,
    "runner": "conformance_bridge_loopback_isolation"
  },
```

- [ ] **Step 4: Register the dedicated runner and move the denominators**

In `crates/carrick-cli/tests/conformance.rs`, locate the `PROBE_SOURCE_COUNT` constant (`rg -n 'const PROBE_SOURCE_COUNT' crates/carrick-cli/tests/conformance.rs`). After A3 Task 7 its doc comment ends with A3's sentence moving the denominator to 468 and the gating rows to 884, followed by:

```rust
const PROBE_SOURCE_COUNT: usize = 468;
```

Append this paragraph to the END of that doc comment (directly above the constant, after A3's last `///` line) and change the value:

```rust
/// `bridge_dns_epoll_wake` (a datagram the bridge DNS gateway answers
/// in-process must make the socket EPOLLIN-ready and wake a thread already
/// parked in `epoll_wait`) moves the denominator from 468 to 469 and the
/// gating rows from 884 to 886 — 443 conformance sources under both
/// variants; it runs under the dedicated `conformance_bridge_dns_epoll_wake`
/// runner, so the generic set stays at 422.
const PROBE_SOURCE_COUNT: usize = 469;
```

Replace in `DEDICATED_PROBE_RUNNERS` (lines 3257-3262 on the unmodified tree; match on the text):

```rust
    ("bridge_compose_client", "conformance_bridge_compose_pair"),
    ("bridge_compose_server", "conformance_bridge_compose_pair"),
    (
        "bridge_loopback_isolation",
        "conformance_bridge_loopback_isolation",
    ),
```

with:

```rust
    ("bridge_compose_client", "conformance_bridge_compose_pair"),
    ("bridge_compose_server", "conformance_bridge_compose_pair"),
    ("bridge_dns_epoll_wake", "conformance_bridge_dns_epoll_wake"),
    (
        "bridge_loopback_isolation",
        "conformance_bridge_loopback_isolation",
    ),
```

Replace the dedicated-runner pin (line 4996 on the unmodified tree):

```rust
    assert_eq!(DEDICATED_PROBE_RUNNERS.len(), 20);
```

with:

```rust
    assert_eq!(DEDICATED_PROBE_RUNNERS.len(), 21);
```

Replace the gating-row pins in the same test (lines 5001-5002 on the unmodified tree; the `generic.len()` pin on the line before them reads `422` after A3 Task 7 and stays 422):

```rust
    assert_eq!(generic.len() + DEDICATED_PROBE_RUNNERS.len(), 442);
    assert_eq!(2 * (generic.len() + DEDICATED_PROBE_RUNNERS.len()), 884);
```

with:

```rust
    assert_eq!(generic.len() + DEDICATED_PROBE_RUNNERS.len(), 443);
    assert_eq!(2 * (generic.len() + DEDICATED_PROBE_RUNNERS.len()), 886);
```

In `scripts/conformance/closure-probe-scenarios.py` replace lines 18-19:

```python
DEDICATED_SOURCE_COUNT = 20
DEDICATED_RUNNER_COUNT = 14
```

with:

```python
DEDICATED_SOURCE_COUNT = 21
DEDICATED_RUNNER_COUNT = 15
```

- [ ] **Step 5: Add the runner**

In `crates/carrick-cli/tests/conformance.rs`, insert immediately before the `#[test]` attribute (line 1527 on the unmodified tree; `rg -n 'fn conformance_bridge_reuse_sockopts'`) of `fn conformance_bridge_reuse_sockopts` (the function that follows `conformance_bridge_udp_sendto_unreachable`, whose body at :1472-1525 unmodified is the template):

```rust
#[test]
fn conformance_bridge_dns_epoll_wake() {
    let _serial = CONFORMANCE_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let Some(bin) = carrick_bin() else {
        eprintln!("SKIP conformance_bridge_dns_epoll_wake: target/release/carrick not built");
        return;
    };
    let lane = ARM64;
    if !lane_runnable_here(&lane) {
        eprintln!(
            "SKIP conformance_bridge_dns_epoll_wake: host ({}) cannot run {} guests",
            std::env::consts::ARCH,
            lane.platform
        );
        return;
    }
    let docker_ok = Command::new("docker")
        .arg("version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !docker_ok {
        eprintln!("SKIP conformance_bridge_dns_epoll_wake: Docker not reachable");
        return;
    }
    let probe = probes_dir(
        selected_dedicated_probe_target(&lane).expect("select dedicated probe artifact"),
    )
    .join("bridge_dns_epoll_wake");
    if !probe.exists() {
        eprintln!(
            "SKIP conformance_bridge_dns_epoll_wake: probe not built ({})",
            probe.display()
        );
        return;
    }

    ensure_signed(&bin);
    let raw = std::fs::read(&probe).expect("read bridge_dns_epoll_wake probe");
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD
        .encode(raw)
        .into_bytes();
    let carrick_out = run_bridge_probe(&bin, lane, &encoded);
    // The invariant is Linux's, not the oracle's: a datagram the gateway
    // answered must wake epoll. Assert it on carrick's output BEFORE the diff
    // so an oracle-side resolver outage (both sides `false`) cannot pass as a
    // MATCH.
    for line in [
        "dns_epoll_ready_after_send=true",
        "dns_epoll_wake_while_parked=true",
    ] {
        assert!(
            carrick_out.contains(line),
            "bridge dns epoll wake: carrick did not report {line}:\n{carrick_out}"
        );
    }
    let docker_out = run_docker_probe(lane, &encoded).expect("docker bridge dns epoll wake probe");
    if let Some(diff) = diff_lines(&carrick_out, &docker_out) {
        panic!("bridge dns epoll wake conformance mismatch:\n{diff}");
    }
}
```

- [ ] **Step 6: Document the gate**

In `docs/conformance-coverage.md`, insert this row directly after the `bridge_udp_sendto_unreachable` row (line 107) of the bridge-namespace probes table:

```markdown
| `bridge_dns_epoll_wake` | A UDP A-query to the bridge nameserver (`/etc/resolv.conf` → the embedded gateway `172.31.0.1:53`) is answered in-process; the answer must make the socket `EPOLLIN`-ready for a following `epoll_wait` AND wake a thread already parked in `epoll_wait` on it, and each reply id must match its query. Prevents the DNS gateway from filling `synthetic_recv` without publishing readiness (`notify_inmem_epoll`) and the epoll readiness recompute from trusting only the host `poll(2)`. |
```

- [ ] **Step 7: Re-run the inventory gates (no guest)**

```bash
cd /Volumes/CaseSensitive/carrick
cargo test -p carrick-cli --test conformance closure_probe_inventory_enforces_authoritative_runners_and_denominator -- --exact --nocapture
python3 scripts/probe-inventory.py check
python3 - <<'EOF'
import importlib.util, json
spec = importlib.util.spec_from_file_location("scen", "scripts/conformance/closure-probe-scenarios.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
plan = m.build_plan(json.load(open("conformance-probes/probe-inventory.json")))
print(len(plan.sources), len(plan.commands))
EOF
```
Expected: the cargo test prints `test closure_probe_inventory_enforces_authoritative_runners_and_denominator ... ok` (all of `21`, `469`, `422`, `443`, `886` now hold); `probe-inventory.py check` exits 0 silently; the plan script prints `21 15`.

- [ ] **Step 8: Build the probe binaries (Docker arm64 build, no guest)**

```bash
cd /Volumes/CaseSensitive/carrick
./scripts/build-probes.sh
ls -l conformance-probes/target/aarch64-unknown-linux-musl/release/bridge_dns_epoll_wake \
      conformance-probes/target/aarch64-unknown-linux-gnu/release/bridge_dns_epoll_wake
```
Expected: both probe ELFs listed (musl static, gnu dynamic). Docker must not be running a carrick guest at the same time.

- [ ] **Step 9: Red-first — prove the probe fails against the pre-fix runtime (HVF guest; signed recipe)**

```bash
cd /Volumes/CaseSensitive/carrick
SCRATCH=/private/tmp/claude-501/-Volumes-CaseSensitive-carrick/8f7faeb9-0217-4567-9ce8-8b805a8618e1/scratchpad
git checkout "$(cat "$SCRATCH/a4-base-sha")" -- crates/carrick-runtime/src/dispatch/net.rs
just build
cargo test -p carrick-cli --test conformance conformance_bridge_dns_epoll_wake -- --exact --nocapture 2>&1 | tee "$SCRATCH/a4-probe-red.log"
```
Expected: `test conformance_bridge_dns_epoll_wake ... FAILED` with `bridge dns epoll wake: carrick did not report dns_epoll_ready_after_send=true`, and the dumped carrick output showing `dns_epoll_send_ok=true`, `dns_epoll_ready_after_send=false`, `dns_epoll_reply_id_matches=true` (the follow-up `recv` still drains the queued reply), `dns_epoll_wake_while_parked=false` (the runner never reaches Docker in this arm). Do not `tail`/`grep` the log away — keep the full file as the red receipt. Note `just build` is the codesigning recipe; a bare `cargo build` binary dies with `HV_DENIED`. (The `a4-base-sha` recorded in Task 8 Step 1 is the post-A3 revision, so checking out only `net.rs` from it reverts exactly Tasks 8 and 9 and nothing from A1-A3.)

- [ ] **Step 10: Restore the fixed runtime, rebuild signed, and prove green (HVF guest then Docker oracle, serial)**

```bash
cd /Volumes/CaseSensitive/carrick
SCRATCH=/private/tmp/claude-501/-Volumes-CaseSensitive-carrick/8f7faeb9-0217-4567-9ce8-8b805a8618e1/scratchpad
git checkout HEAD -- crates/carrick-runtime/src/dispatch/net.rs
git diff --quiet HEAD -- crates/carrick-runtime/src/dispatch/net.rs && echo restored
just build
cargo test -p carrick-cli --test conformance conformance_bridge_dns_epoll_wake -- --exact --nocapture 2>&1 | tee "$SCRATCH/a4-probe-green.log"
```
Expected: `restored`; then `test conformance_bridge_dns_epoll_wake ... ok` — carrick output contains `dns_epoll_ready_after_send=true`, `dns_epoll_reply_id_matches=true`, `dns_epoll_wake_while_parked=true`, `dns_epoll_parked_reply_id_matches=true`, and the Docker diff is empty. The runner itself runs the carrick phase to completion before starting the Docker phase, so the two VMs never overlap.

- [ ] **Step 11: Format and lint**

```bash
cd /Volumes/CaseSensitive/carrick
just fmt
just fmt-check
just clippy
git status --short
```
Expected: `fmt-check` and `clippy` exit 0; `git status` lists exactly the five files of this task (`conformance-probes/src/bin/bridge_dns_epoll_wake.rs`, `conformance-probes/probe-inventory.json`, `crates/carrick-cli/tests/conformance.rs`, `scripts/conformance/closure-probe-scenarios.py`, `docs/conformance-coverage.md`) plus whatever untracked files were already present before this cluster (at verification time: four `docs/superpowers/**` files), and nothing under `crates/carrick-runtime`.

- [ ] **Step 12: Commit**

```bash
cd /Volumes/CaseSensitive/carrick
SCRATCH=/private/tmp/claude-501/-Volumes-CaseSensitive-carrick/8f7faeb9-0217-4567-9ce8-8b805a8618e1/scratchpad
BASE="$(cat "$SCRATCH/a4-base-sha" | cut -c1-8)"
git add conformance-probes/src/bin/bridge_dns_epoll_wake.rs conformance-probes/probe-inventory.json \
        crates/carrick-cli/tests/conformance.rs scripts/conformance/closure-probe-scenarios.py \
        docs/conformance-coverage.md
git commit -F - <<EOF
test(conformance): probe bridge DNS gateway replies waking epoll

Why: the two runtime fixes before this were proven by dispatcher unit
tests only; nothing in the gate ran a guest that resolves through the
bridge DNS gateway with epoll, which is how the defect stayed invisible
(the generic probe lane runs under host networking, where the embedded
gateway is not in play).

What: \`bridge_dns_epoll_wake\`, a dedicated \`--net bridge\` probe. It sends
a hand-encoded A query for \`localhost.\` to the \`/etc/resolv.conf\`
nameserver on a UDP socket registered for EPOLLIN, then checks (a)
\`epoll_wait\` after the send returns EPOLLIN, (b) a thread already parked
in \`epoll_wait\` is woken by a second query's reply, (c) each reply id
matches its query. Only booleans are printed. The runner asserts (a) and
(b) on carrick's output BEFORE diffing against Docker, so a resolver
outage on the oracle side (both \`false\`) cannot pass as a MATCH. The
inventory row, \`PROBE_SOURCE_COUNT\` 468 -> 469, the dedicated runner
allowlist 20 -> 21, the gating-row pins 442/884 -> 443/886 (generic
stays 422), the closure scenario counts 21/15 and the coverage doc row
move together.

Verified: \`closure_probe_inventory_enforces_authoritative_runners_and_denominator\`
red (469 != 468) then green; probes rebuilt (\`scripts/build-probes.sh\`);
red-first against the pre-fix \`net.rs\` (${BASE}) rebuilt signed --
\`dns_epoll_ready_after_send=false\`, \`dns_epoll_wake_while_parked=false\`;
restored HEAD, rebuilt signed -- runner \`ok\`, carrick and Docker outputs
identical; \`just fmt-check\`; \`just clippy\`.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
```


<details><summary>Verifier problems fixed in place (12) and claims still unverified (7)</summary>

- fixed: Task 8 Step 4 would leave the inventory gate RED: `closure_probe_inventory_enforces_authoritative_runners_and_denominator` also pins `generic.len() + DEDICATED_PROBE_RUNNERS.len() == 439` and `2 * (...) == 878` at conformance.rs:5001-5002. Dedicated sources ARE counted in those gating rows (419 generic + 20 dedicated = 439), so adding `bridge_dns_epoll_wake` moves them to 440/880. The draft only changed the `== 20` assert at :4996 and its doc-comment text claimed 'the generic gating rows stay at 878' — both wrong. Fixed: replace :5001-5002 (440/880), corrected the PROBE_SOURCE_COUNT doc comment, the Files header, Step 7 expectation and the commit body.
- fixed: Task 7 background/deviation misattributes the empty `wake_all_waiters`: lib.rs:954 sits inside the `#[cfg(any(platform-linux, platform-freebsd, platform-netbsd))] pub mod host_signal` block (lib.rs:487-492); on the reference macOS lane `host_signal` is the real `carrick_vmm_hvf::host_signal::wake_all_waiters` (host_signal.rs:923), which broadcasts to every parked private waiter. Corrected the justification: the omission rests on the blocking recvfrom/recvmsg draining `synthetic_recv` before it parks (net.rs:6833, :8031), not on the function being a no-op; the cross-thread 'parked in recvfrom while a sibling sends' case is recorded as a pre-existing gap shared with the ICMP path.
- fixed: Task 7 quoted-block line ranges are off: the ICMP tail `let checksum ... }` is net.rs:2713-2726 (draft said 2711-2725) and the DNS tail `}) else { ... }` is :2748-2760 (draft said 2750-2760). The quoted text itself matches HEAD exactly; only the numbers were fixed.
- fixed: Task 7 interface line references are stale against HEAD: `SyscallDispatcher::notify_inmem_epoll` is dispatch/mod.rs:4659 (draft 4610); `EpollKqueue` + `new`/`poll_fd` are mod.rs:2789-2826 (draft 2759-2782); `NetworkNamespaceSpec::bridge_default` is carrick-spec/src/lib.rs:487 (draft 485); `epoll_wake_registry()` lives at kernel/objects.rs:1324 and returns `&EpollWakeRegistry` where `EpollWakeRegistry = Arc<Mutex<Vec<i32>>>` (epoll_shim.rs:7), so `Arc::clone(...)` is correct; `captured_file_table()` (mod.rs:5598) returns an owned `Arc<FileTable>` and under `cfg(test)` captures the dispatcher's one-task context (stable across calls — the existing ICMP test's install→open_file already depends on it). Fixed in place.
- fixed: Task 7 background call-site line numbers drifted by +50 at HEAD: sendto calls are net.rs:6655/:6662 (draft 6605/6612), sendmsg :7759-7761 (draft 7709-7711), recvfrom/recvmsg synthetic drains :6833/:8031 (draft 6783/7981), DNS push+return :2758-2759. Fixed.
- fixed: Task 6 test-module insertion point is off by one: `mod icmp_ping_tests` closes at net.rs:3273 (3274 is blank), `#[cfg(test)]` at 3275, `mod recvmmsg_tests` at 3276. Draft said 3274/3275. Fixed.
- fixed: Task 6 background line refs: the HostSocket pending-error arm is net.rs:933 (draft 927), the `_` arm is :940 (draft 935), the zero-timeout `libc::poll` is :997 (draft 996). All other Task 6 ranges (974-978, 1077-1085, 1090-1108, 864, 1945-1960, 3829/3953/4082, fd_table.rs:1070-1085, fd_helpers.rs:213, 2077, 2762) verified exact. Fixed.
- fixed: Task 8 Step 11 says `git status` lists 'exactly the six files' then enumerates five; also the tree already carries untracked `docs/superpowers/*` files that will appear. Corrected to five and noted the pre-existing untracked files.
- fixed: Task 8 probe: replaced the hand-numbered `const EPOLLIN: u32 = 0x001` with `libc::EPOLLIN as u32` and `MaybeUninit::zeroed().assume_init()` with the sibling probes' `std::mem::zeroed()` (AGENTS.md: use the libc crate; no hand-numbered tables). Also closes `epfd` on the `epoll_ctl` failure path. Verified `libc::epoll_event { events, u64 }`, `epoll_create1`, `epoll_ctl`, `epoll_wait`, `MSG_DONTWAIT`, and `conformance_probes::report!` (`#[macro_export]`, lib.rs:172) all exist for the linux probe targets.
- fixed: Task 8 header/background: `validate_closure_probe_rows` is conformance.rs:3350 (draft 3349); resolv.conf rendering is network/model.rs:276-277 with the bridge gateway substituted at :635-637 (draft :274); `conformance_bridge_reuse_sockopts` fn is at :1528 (its `#[test]` at :1527). Fixed.
- fixed: Task 6 Step 1 expectation named the plan-time HEAD `177870d1`; at verification time HEAD is `39426141` (the requested `3dc6cc72` and `177870d1` are both ancestors). Reworded so the engineer does not treat a different SHA as an error.
- fixed: Task 7 test: added a comment explaining why `SyscallDispatcher::with_network` (mod.rs:4564, the production constructor) is deliberately not used — it also calls `crate::kernel::publish_root_net_view` (process-global) and mounts `/etc/resolv.conf`, neither needed and the former would leak across sibling unit tests; direct field assignment is legal because net.rs is a child module of `dispatch`. Verified `use super::*` brings `Arc`, `VecDeque`, the `EventMultiplexer` trait (used at net.rs:4435) and `hickory_proto` (regular dep, carrick-runtime/Cargo.toml:127) into scope; `Message::query`/`to_vec`/`from_vec`/`metadata.id`/`Name::from_ascii` verified against hickory-proto 0.26.1 (op/message.rs:127/499/493) and network/dns.rs:93-118,192-197.
- UNVERIFIED: Docker-oracle behaviour of the probe: that the oracle container's /etc/resolv.conf carries an IPv4 nameserver that answers (with any rcode) a query for `localhost.` so all eight probe lines match. Mitigated by the runner asserting the two wake invariants on carrick's output before the diff; if the oracle diverges only on `dns_epoll_nameserver_ok`, the probe needs an oracle-side fallback (not designed here).
- UNVERIFIED: That `Name::from_ascii("localhost.")` / `Message::query()` / `Message::to_vec()` compile exactly as written against hickory-proto 0.26.1 (Message::query at op/message.rs:127 and to_vec at :499 were located in the registry source; from_ascii and metadata.id are used by the tree's own dns.rs tests).
- UNVERIFIED: That `RuntimeNetwork::create` for a bridge spec inside a `carrick-runtime --lib` unit test has no side effects beyond what the existing `bridge_provider_creates_nonzero_lease` test already tolerates (it writes the file-backed endpoint registry and destroys it on Drop).
- UNVERIFIED: That the harness line numbers cited (conformance.rs 1472-1527, 3245-3262, 4996; probe-inventory.json 67-76; net.rs 974-978, 1077-1085, 1090-1108, 2711-2725, 2750-2760, 3274) are still exact at execution time -- they were read at HEAD 177870d1 and will shift once sibling Phase A clusters (notably A6, which edits conformance.rs's `--raw` handling) land first; the quoted old-text blocks are the authority for the Edit steps.
- UNVERIFIED: Exact panic text of the red runs (the assert messages are written into the tests, so the wording is deterministic, but the `left/right` framing is rustc's).
- UNVERIFIED: Whether `just test` currently passes on an unmodified tree (a pre-existing failure elsewhere would mask nothing here but would change the expected `just test` result line).
- UNVERIFIED: The wake-while-parked probe scenario relies on a 300 ms sleep to make 'waiter parked first' likely inside the guest; the boolean is true in either ordering when the runtime is correct, but the scenario only certainly exercises the notify path when the park wins the race.

</details>


<!-- cluster A5-deletions -->
## Cluster A5-deletions

> **Status:** verifier-corrected and cross-cluster reconciled (fixes applied: 4; notes: Fix 3 as written assumed A5 omitted conformance.rs; the draft I received already edited all seven `run --raw` sites in Task 8 (now Task 12) Step 4 and committed the file. I made the ownership explicit (and the 'A6' -> 'A5' wording lives in A4's text, not mine) rather than duplicating the sed/edit steps into Step 4b, which would have made the same file edited twice. | The Task 11 commit body still says `forked_child_die_by_signal` stays 'a follow-up'; no cluster in the mismatch list claims that follow-up, so it remains unowned (not a consistency break, just noting it). | Task 13 Step 2 references `posix_spawn` of `__carrier-entry` in lifecycle.rs prose; this describes HEAD behaviour and is unaffected by the B/C clusters as far as the mismatch list states, but B4 (carrier, Tasks 22-23) and C2 (Task 28) rewrite neighbouring runtime.rs/execute.rs text — Task 13's runtime.rs module-doc rewrite lands before them (Phase A), so those clusters must re-derive their runtime.rs anchors after Task 13, as they already must after Task 11. | CARRICK_RUN_ID stamps were renamed to a5-task11/12/13; these are run identifiers only and do not affect any gate.).

### Task 11: Delete the fork-era tokio guard and the vestigial forked-child exit paths

**Files:**
- Modify: `crates/carrick-runtime/src/execute.rs:191-201`
- Modify: `crates/carrick-runtime/Cargo.toml:139` (move `tokio` to `[dev-dependencies]`, which starts at line 174)
- Modify: `crates/carrick-runtime/src/runtime.rs:98-108, 136-139, 843-844, 870-878, 942-948, 959-964, 1350-1355`
- Modify: `crates/carrick-runtime/src/exec_helpers.rs:1, 282-330, 358`
- Modify: `crates/carrick-runtime/src/runtime/exec.rs:1-6, 164-170`
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs:5413-5421` (delete the caller-less `clear_output_buffers`)
- Modify: `crates/carrick-runtime/src/vcpu_loop/mod.rs:512-515, 526-529`
- Modify: `crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs:1014-1017` (comment cites the deleted gate)
- Modify: `crates/carrick-cli/src/commands.rs:45-52, 1004-1008, 1012, 1019-1031`
- Test: grep assertions (below) + `just check` + `just clippy` + `just lint-domains` + `just test`; HVF smoke via the signed `just build` binary

**Interfaces:**
- Consumes: `carrick_runtime::Runtime::execute(spec: &RunSpec) -> Result<RunResult, RuntimeError>` (signature unchanged; the tokio precondition is removed so Task 29 (C3, the `carrick-embed` crate)'s `run()` = `spawn_blocking(execute)` is legal).
- Produces: `Runtime::execute` callable with a live tokio `Handle` (no debug assert). This task is the SINGLE owner of that deletion and of demoting `tokio` to a dev-dependency of `carrick-runtime`: Task 28 (C2, `Runtime::prepare` / prepare.rs) and Task 29 (C3, `carrick-embed`) consume it as already done and must not repeat it. `crate::exec_helpers::forked_child_exit` and `SyscallDispatcher::clear_output_buffers` are deleted; `SyscallTrap::is_forked_child` (carrick-hal, default `false`) is no longer consulted by any loop in `runtime.rs`.

- [ ] **Step 1: Red-first grep assertions (must print these counts BEFORE the change)**

```sh
cd /Volumes/CaseSensitive/carrick
grep -c 'tokio::runtime::Handle::try_current' crates/carrick-runtime/src/execute.rs        # expect 1
grep -c 'runtime.is_forked_child() || dispatcher.is_forked_guest_process()' crates/carrick-runtime/src/runtime.rs   # expect 4
grep -rn 'fn forked_child_exit' crates/carrick-runtime/src | wc -l                          # expect 1
grep -rn 'fn clear_output_buffers' crates/carrick-runtime/src | wc -l                       # expect 1 (and zero callers: `grep -rn 'clear_output_buffers(' crates | grep -v 'fn clear_output_buffers'` prints nothing)
grep -c 'libc::_exit(125)' crates/carrick-cli/src/commands.rs                               # expect 2 (module doc line 50 + the code at 1027)
grep -n '^tokio' crates/carrick-runtime/Cargo.toml                                          # expect exactly "139:tokio.workspace = true" (above [dev-dependencies] at 174)
```

- [ ] **Step 2: Delete the tokio guard in `Runtime::execute`**

In `crates/carrick-runtime/src/execute.rs` replace this exact block (lines 191-201):

```rust
        // Guardrail: execute() may still enter the separately-scoped
        // interactive-session boundary. A live tokio runtime must NOT survive
        // into here — its blocking-pool threads do not survive that host fork,
        // so the interactive child would deadlock in BlockingPool::shutdown.
        // Callers resolve the image under tokio, DROP the runtime, then execute.
        debug_assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "tokio runtime must not be live when Runtime::execute is called \
             (tokio-fork-isolation invariant)"
        );
        if spec.platform == Platform::Amd64 {
```

with:

```rust
        if spec.platform == Platform::Amd64 {
```

- [ ] **Step 3: Demote `tokio` to a dev-dependency of `carrick-runtime`**

The only remaining `tokio` use in the crate is `#[tokio::test]` in `crates/carrick-runtime/tests/integration/oci_layout.rs:39`. In `crates/carrick-runtime/Cargo.toml` delete line 139:

```toml
tokio.workspace = true
```

and add the same line under `[dev-dependencies]` (line 174), directly after `tempfile.workspace = true`:

```toml
tempfile.workspace = true
tokio.workspace = true
carrick-image = { path = "../carrick-image" }
```

- [ ] **Step 4: Delete the four vestigial forked-child checks in the single-threaded fixture loop**

`runtime.rs:826` `run_combined_syscall_loop_with_dispatcher` runs one logical process (`DispatchOutcome::Fork` lowers to `EOPNOTSUPP` at `runtime.rs:989-996`), and the HVF engine never sets `is_forked_child` (the only `is_forked_child = true` writers are `carrick-x86/src/engine.rs:2132` and a `#[cfg(test)]` struct literal at `vcpu_loop/mod.rs:9574`). Make these four edits in `crates/carrick-runtime/src/runtime.rs`:

(A) lines 870-878, replace

```rust
                    if let Some(signum) = action.term_signal {
                        if runtime.is_forked_child() || dispatcher.is_forked_guest_process() {
                            forked_child_die_by_signal(
                                signum,
                                dispatcher.stdout(),
                                dispatcher.stderr(),
                            );
                        }
                        return Ok(RunResult {
```

with

```rust
                    if let Some(signum) = action.term_signal {
                        return Ok(RunResult {
```

(B) lines 942-948, replace

```rust
            DispatchOutcome::Exit { code } => {
                crate::probes::guest_exit(code);
                if runtime.is_forked_child() || dispatcher.is_forked_guest_process() {
                    dispatcher.cleanup_sysv_ipc_on_process_exit();
                    forked_child_exit(code, dispatcher.stdout(), dispatcher.stderr());
                }
                dispatcher.cleanup_sysv_ipc_on_process_exit();
```

with

```rust
            DispatchOutcome::Exit { code } => {
                crate::probes::guest_exit(code);
                dispatcher.cleanup_sysv_ipc_on_process_exit();
```

(C) lines 959-964, replace

```rust
            DispatchOutcome::SignalDeath { signum } => {
                if runtime.is_forked_child() || dispatcher.is_forked_guest_process() {
                    dispatcher.cleanup_sysv_ipc_on_process_exit();
                    forked_child_die_by_signal(signum, dispatcher.stdout(), dispatcher.stderr());
                }
                dispatcher.cleanup_sysv_ipc_on_process_exit();
```

with

```rust
            DispatchOutcome::SignalDeath { signum } => {
                dispatcher.cleanup_sysv_ipc_on_process_exit();
```

(D) lines 1350-1355, replace

```rust
            if let Some(signum) = action.term_signal {
                if runtime.is_forked_child() || dispatcher.is_forked_guest_process() {
                    dispatcher.cleanup_sysv_ipc_on_process_exit();
                    forked_child_die_by_signal(signum, dispatcher.stdout(), dispatcher.stderr());
                }
                dispatcher.cleanup_sysv_ipc_on_process_exit();
```

with

```rust
            if let Some(signum) = action.term_signal {
                dispatcher.cleanup_sysv_ipc_on_process_exit();
```

Then fix the now-unused imports at lines 136-139, replacing

```rust
use exec::{
    forked_child_die_by_signal, forked_child_exit, load_execve_image, stop_after_traced_exec,
    stop_by_signal,
};
```

with

```rust
use exec::{load_execve_image, stop_after_traced_exec, stop_by_signal};
```

Delete the module-doc paragraph that justified the checks (lines 98-108, including the trailing blank `//!`), i.e. remove exactly:

```rust
//! # The forked-child `_exit` rule (do not break this)
//!
//! A `libc::fork`ed child shares the parent's fd table. Unwinding through an
//! fd-owning `Drop` (the dispatcher's buffers, an `applevisor::Vcpu`) in the
//! child double-closes an inherited fd — tripping std's IO-safety abort — or
//! runs the no-VM `Vcpu` Drop and panics. So on **every** exit path the loops
//! check `is_forked_child()` / `is_forked_guest_process()` and route through the
//! `_exit`-based [`exec`] helpers (`forked_child_exit` flushes buffered stdio to
//! the inherited host fds then `_exit`s; `forked_child_die_by_signal` re-raises
//! the signal so the parent's `wait4` reports `WIFSIGNALED`).
//!
```

(The rest of the module doc is rewritten in Task 13 (retire fork-era prose, fix the `interactive_tty` binary path, correct the `justfile` test comment).) Also replace the comment at lines 843-844

```rust
    // Per-thread blocking-I/O waiter (owns this thread's kqueue). Recreated in
    // a forked child below (kqueue is not inherited across fork).
```

with

```rust
    // Per-thread blocking-I/O waiter (owns this thread's kqueue).
```

The HVF engine's `process_exit_cleanup` comment cites the gate just deleted. In `crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs` replace lines 1014-1017

```rust
        // Called on the exiting fork-child's OWN thread (vcpu_loop/mod.rs:1469/
        // 1500/1884 — the child-exit / signal-death paths, gated by
        // `is_forked_child() || is_forked_guest_process()`, so it NEVER runs on
        // the parent), BEFORE `_exit` skips Rust drops.
```

with

```rust
        // Called on the exiting task's OWN thread from the vcpu_loop
        // child-exit / signal-death paths (`vcpu_loop/exec.rs` and
        // `vcpu_loop/mod.rs`, behind `requires_no_unwind_host_exit`), before
        // any host-process exit would skip Rust drops.
```

- [ ] **Step 5: Delete `forked_child_exit`, `clear_output_buffers`, and the re-exports**

In `crates/carrick-runtime/src/exec_helpers.rs` delete lines 282-330 in full (the doc comment starting `/// Called from a forked child when the guest hits \`exit_group\`.` through the closing `}` after `unsafe { libc::_exit(code) };`). `forked_child_die_by_signal` (line 340 onward) stays: it is still named by `vcpu_loop/mod.rs:8525`, `vcpu_loop/signal.rs:276` and `vcpu_loop/exec.rs:871` behind `requires_no_unwind_host_exit` (out of this task's scope). Replace the dangling reference at line 358

```rust
    // Enqueue-before-record, as in `forked_child_exit`: the reaping wait4
```

with

```rust
    // Enqueue-before-record: the reaping wait4
```

and the module doc line 1

```rust
//! Cross-platform forked-child exit helpers and shebang resolution.
```

with

```rust
//! Cross-platform signal-death / stop helpers and shebang resolution.
```

In `crates/carrick-runtime/src/runtime/exec.rs` replace the module doc at lines 1-6

```rust
//! execve image loading + forked-child exit paths, split out of runtime.rs
//! (WS-F3): load_execve_image (rootfs/overlay ELF + shebang + Rosetta
//! redirect) and the no-unwind forked_child_exit / forked_child_die_by_signal
//! helpers. The shebang helpers (resolve_shebang, parse_shebang) and
//! forked-child exit functions now live in `crate::exec_helpers` (cross-
//! platform); they are re-exported here for existing call sites.
```

with

```rust
//! execve image loading, split out of runtime.rs (WS-F3): load_execve_image
//! (rootfs/overlay ELF + shebang + Rosetta redirect). The shebang helpers
//! (resolve_shebang, parse_shebang) and the signal-death / stop helpers live
//! in `crate::exec_helpers` (cross-platform); they are re-exported here for
//! existing call sites.
```

and lines 164-170

```rust
// Shebang resolution and forked-child exit helpers are now in the
// cross-platform `exec_helpers` module. Re-export them here so the existing
// call sites in `runtime.rs` (`use exec::{…}`) and the vcpu_loop macOS import
// (`use crate::runtime::exec::{…}`) continue to resolve without change.
pub(super) use crate::exec_helpers::resolve_shebang;
pub(crate) use crate::exec_helpers::{
    forked_child_die_by_signal, forked_child_exit, stop_after_traced_exec, stop_by_signal,
};
```

with

```rust
// Shebang resolution and the signal-death / stop helpers live in the
// cross-platform `exec_helpers` module. Re-export them here so the call sites
// in `runtime.rs` (`use exec::{…}`) and the vcpu_loop macOS import
// (`use crate::runtime::exec::{…}`) resolve without change.
pub(super) use crate::exec_helpers::resolve_shebang;
pub(crate) use crate::exec_helpers::{
    forked_child_die_by_signal, stop_after_traced_exec, stop_by_signal,
};
```

In `crates/carrick-runtime/src/dispatch/mod.rs` delete lines 5413-5421 in full — the caller-less post-fork helper and its comment:

```rust
    /// Called after `libc::fork(2)` returns into a child: the child
    /// inherited the parent's buffered stdout/stderr, but we don't
    /// want to re-print those bytes when the child eventually exits
    /// via the `forked_child_exit` path. The parent's full buffer
    /// goes out through its own JSON report.
    pub fn clear_output_buffers(&self) {
        self.io.stdout.lock().clear();
        self.io.stderr.lock().clear();
    }
```

In `crates/carrick-runtime/src/vcpu_loop/mod.rs` replace lines 512-515

```rust
    pub(super) use crate::exec_helpers::{
        forked_child_die_by_signal, forked_child_exit, stop_after_traced_exec, stop_by_signal,
    };
```

with

```rust
    pub(super) use crate::exec_helpers::{
        forked_child_die_by_signal, stop_after_traced_exec, stop_by_signal,
    };
```

and lines 526-529

```rust
use macos_helper_stubs::{
    forked_child_die_by_signal, forked_child_exit, hardware_tso_for_debug, load_execve_image,
    stop_after_traced_exec, stop_by_signal,
};
```

with

```rust
use macos_helper_stubs::{
    forked_child_die_by_signal, hardware_tso_for_debug, load_execve_image,
    stop_after_traced_exec, stop_by_signal,
};
```

- [ ] **Step 6: Delete the CLI's fork-era resolve/execute comments and the `_exit` error arm**

In `crates/carrick-cli/src/commands.rs` replace lines 1004-1008

```rust
            // Resolve (pull + build the spec) under the tokio runtime, then DROP
            // the runtime before executing — so no tokio thread is alive across
            // the fork in Runtime::execute. (Forking with a live tokio runtime
            // deadlocks the child in BlockingPool::shutdown.)
            let spec = match block_on_oci(engine.resolve(req.clone())) {
```

with

```rust
            // Resolve (pull + build the spec) on a short-lived current-thread
            // tokio runtime; `block_on_oci` drops it before `Runtime::execute`
            // runs the guest synchronously in this carrier.
            let spec = match block_on_oci(engine.resolve(req.clone())) {
```

and the sibling comment at line 1012

```rust
                // resolve runs in the PARENT (no fork yet) → normal exit is safe.
```

with

```rust
                // No guest has started yet → normal exit is safe.
```

Replace the error arm at lines 1017-1032

```rust
            let result = match carrick_runtime::Runtime::execute(&spec) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("carrick: {e:#}");
                    if tty {
                        // The separately-scoped interactive TTY supervisor may
                        // put this error arm in its forked runtime child. Do not
                        // unwind fd-owning state there.
                        // SAFETY: `_exit` skips atexit/Drop; stderr is unbuffered.
                        unsafe { libc::_exit(125) };
                    }
                    // Ordinary/raw HVPatch execution is the original carrier,
                    // so normal process cleanup and terminal receipts are safe.
                    std::process::exit(125);
                }
            };
```

with

```rust
            let result = match carrick_runtime::Runtime::execute(&spec) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("carrick: {e:#}");
                    std::process::exit(125);
                }
            };
```

(`tty` remains used at the destructure, in the `CliRunRequest`, and at `if tty || interactive` on line ~1057, so no unused-variable warning.) Delete the module-doc section at lines 45-52:

```rust
//! ## Fork-safety on the engine error path
//!
//! An interactive run may cross the separately-scoped TTY supervisor boundary
//! inside `Runtime::execute`, so an HVF/setup failure can surface in the `Err`
//! arm while already in a forked runtime child. That child uses
//! `libc::_exit(125)` because normal atexit/Drop cleanup after fork can
//! double-close an inherited fd and trip an IO-safety abort. The ordinary/raw
//! carrier uses `std::process::exit(125)` and retains normal cleanup.
//!
```

- [ ] **Step 7: Green greps and the host gates**

```sh
cd /Volumes/CaseSensitive/carrick
grep -c 'tokio::runtime::Handle::try_current' crates/carrick-runtime/src/execute.rs        # expect 0
grep -c 'runtime.is_forked_child() || dispatcher.is_forked_guest_process()' crates/carrick-runtime/src/runtime.rs   # expect 0
grep -rn 'forked_child_exit' crates/carrick-runtime/src | wc -l                             # expect 0
grep -rn 'clear_output_buffers' crates | wc -l                                              # expect 0
grep -c 'libc::_exit(125)' crates/carrick-cli/src/commands.rs                               # expect 0
grep -n '^tokio' crates/carrick-runtime/Cargo.toml                                          # expect one line, numbered > the [dev-dependencies] line
just fmt
just check          # expect: Finished (no warnings)
just clippy         # expect: Finished, zero warnings (catches any import left dangling)
just lint-domains   # expect: semgrep gates + `check-carrier-only-process-invariant.py` PASS (no new fork/_exit sites)
just test           # expect: every crate "test result: ok"; carrick-runtime lib runs serially and finishes
```

- [ ] **Step 8: HVF live smoke (signed binary required — Rule 0)**

The justfile has no `set positional-arguments`, so a quoted `-c '…; exit 3'` cannot be passed through `just run` (the `{{ARGS}}` splice drops the quotes and the recipe shell would run `exit 3` itself). Build signed, then call the binary directly:

```sh
cd /Volumes/CaseSensitive/carrick
just build
CARRICK_RUN_ID=a5-task11 ./target/release/carrick run --fs host ubuntu:24.04 /bin/sh -c '/bin/echo hi; exit 3'; echo "exit=$?"
```

Expected: prints `hi` and `exit=3` (streamed stdio, container exit code adopted; no assertion, no `BlockingPool` hang). Reap with `scripts/sudo/kill.sh a5-task11` if anything lingers.

- [ ] **Step 9: Commit**

```sh
cd /Volumes/CaseSensitive/carrick
git add crates/carrick-runtime/src/execute.rs crates/carrick-runtime/Cargo.toml \
  crates/carrick-runtime/src/runtime.rs crates/carrick-runtime/src/exec_helpers.rs \
  crates/carrick-runtime/src/runtime/exec.rs crates/carrick-runtime/src/dispatch/mod.rs \
  crates/carrick-runtime/src/vcpu_loop/mod.rs crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs \
  crates/carrick-cli/src/commands.rs
git commit -F- <<'EOF'
refactor(runtime): delete fork-era tokio guard and forked-child exit paths

Why: no product path forks a host process any more (NsSupervisor collapsed
into the carrier in 76495a04, the interactive supervisor became a thread
PtyRelay in af6270ce, the FileAuthority helper died in 36d141d6, and
`scripts/migrate/check-carrier-only-process-invariant.py` enforces it from
`just lint-domains` inside `just ci`). Three relics still described that
world: the `debug_assert!(tokio::runtime::Handle::try_current().is_err())`
in `Runtime::execute`, whose comment cites a host fork that does not exist
and which forbids the embed API's `spawn_blocking(execute)`; the
`is_forked_child() || is_forked_guest_process()` `_exit` branches in the
single-threaded fixture loop, which can never be taken (the HVF engine never
sets `is_forked_child`, and that loop lowers `DispatchOutcome::Fork` to
`EOPNOTSUPP`); and the CLI's `if tty { libc::_exit(125) }` error arm, kept
for a forked runtime child that no longer exists.

What: delete the assert and demote `tokio` to a dev-dependency of
`carrick-runtime` (only `#[tokio::test]` in the oci_layout integration test
still needs it); delete the four forked-child branches in
`run_combined_syscall_loop_with_dispatcher`, the now-dead
`exec_helpers::forked_child_exit` with its re-exports, and the caller-less
post-fork `SyscallDispatcher::clear_output_buffers`; collapse the CLI error
arm to `std::process::exit(125)`; drop the module prose that justified each
and the HVF `process_exit_cleanup` comment that cited the gate.
`forked_child_die_by_signal` stays because `vcpu_loop` still names it behind
`requires_no_unwind_host_exit` (always false) — a follow-up.

Verified: red-first greps (1/4/1/1/2 -> 0/0/0/0/0), `just check`, `just
clippy`, `just lint-domains`, `just test`, and the signed binary running
`run --fs host ubuntu:24.04 /bin/sh -c '/bin/echo hi; exit 3'` printing `hi`
with exit 3.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
```

### Task 12: Delete `carrick compat-report`, the no-op `run --raw` flag, and correct the EL1-shim comments

**Files:**
- Modify: `crates/carrick-cli/src/args.rs:25-27, 35-38, 390-394, 743-752`
- Modify: `crates/carrick-cli/src/commands.rs:42-43, 418, 848, 1083-1087, 1231-1241`
- Modify: `crates/carrick-cli/src/runtime_util.rs:32-35`
- Modify: `crates/carrick-cli/src/main.rs:51`
- Modify: `crates/carrick-cli/tests/conformance.rs:363, 398, 420, 452, 2694, 2903, 2940, 3676, 3734` (the seven `run --raw` argv sites — `bridge_probe_args`, the `run_carrick_probe_*` family, the lane runner — plus two prose lines; THIS cluster (A5) owns these edits, there is no "A6" cluster; the two `run-elf --raw` sites at 4869/4879 stay)
- Modify: `crates/carrick-cli/tests/dsr_trace_overhead.rs:761`
- Modify: `crates/carrick-cli/tests/perf_support/invoke.rs:316`, `crates/carrick-cli/tests/perf_support/xboundary.rs:100`, `crates/carrick-cli/tests/perf_runner.rs:126, 317`
- Modify: `crates/carrick-conformance/src/generate.rs:337, 347, 881, 890, 901, 907, 935, 959, 995, 1002`
- Modify: `crates/carrick-conformance/src/manifest.rs:92, 243`, `crates/carrick-conformance/src/oracle.rs:441`, `crates/carrick-conformance/src/engine.rs:10-11`
- Modify: `scripts/conformance/suites.toml` (2,127 `carrick_flags` lines, mechanical sed)
- Modify: the non-Rust `carrick run … --raw` callers listed in Step 4b (scripts/, docker/, .agents/skills/, docs/, README.md, handoff.md)
- Modify: `crates/carrick-runtime/src/execute.rs:155`, `crates/carrick-runtime/src/dispatch/fs.rs:7675`
- Modify: `handoff.md:28, 711, 2164`
- Modify: `docs/diagnostics-and-debugging.md:6-7, 519-545, 558`, `docs/syscalls-emulation-map.md:16-17, 334-341`, `README.md:104`
- Modify: `crates/carrick-mem/src/memory.rs:194-201`, `crates/carrick-cli/Cargo.toml:15-18`
- Test: grep assertions + `target/debug/carrick … --help` + `just test`; harness live check via `just conformance-quick` (signed)

**Interfaces:**
- Consumes: `carrick_runtime::compat::{CompatReporter, CompatReport}` (unchanged; still produced by `carrick run --json`).
- Produces: `carrick run` no longer accepts `--raw` (`run-elf --raw` is a different, live flag and stays); `Commands::CompatReport` is gone; `carrick-conformance` suite `carrick_flags` base becomes `["--fs", "host"]`. Because clap rejects `--raw` with exit 2 after Step 3, every probe gate that still passed `run --raw` would go red — so this task ALSO owns removing the seven `run --raw` argv sites in `crates/carrick-cli/tests/conformance.rs` (Step 4) and commits that file in the same commit as the clap deletion (Step 5). Task 10 (A4, net.rs test module) defers exactly that edit to this cluster.

- [ ] **Step 1: Red-first assertions for all three deletions**

```sh
cd /Volumes/CaseSensitive/carrick
grep -c 'CompatReport {' crates/carrick-cli/src/args.rs                                  # expect 1
grep -c 'Commands::CompatReport' crates/carrick-cli/src/commands.rs                      # expect 1
grep -rn -e '"--raw"' crates --include='*.rs' | wc -l                                    # expect 33
grep -c '^carrick_flags = \["--raw", "--fs", "host"' scripts/conformance/suites.toml     # expect 2127
grep -rn -e '--raw' scripts docker .agents docs/conformance-testing.md docs/native-dsr-dtrace-profile.md docs/hvpatch-exec-authority-routing-plan.md README.md handoff.md --exclude='*.jsonl' --exclude=suites.toml | grep -v 'run-elf' | wc -l   # expect 35 (the Step 4b list)
grep -c 'getpid/getuid/geteuid/getgid/getegid' crates/carrick-mem/src/memory.rs          # expect 1
grep -c 'getpid/get\*id/gettid' crates/carrick-cli/Cargo.toml                            # expect 1
# ground truth the shim comments must match:
grep -n 'IDENTITY_SYSCALLS: &\[(u16, u64)\] = &\[(172, IDENTITY_OFF_PID)\]' crates/carrick-mem/src/memory.rs   # expect line 291
grep -n 'pub const GETTID_NR: u16 = 178;' crates/carrick-mem/src/memory.rs               # expect line 297
```

- [ ] **Step 2: Delete the `compat-report` subcommand (clap arm + handler + docs)**

In `crates/carrick-cli/src/args.rs` delete lines 743-752:

```rust
    /// `compat-report` renders the HVF syscall-coverage report; macOS-only.
    #[cfg(feature = "platform-macos")]
    CompatReport {
        // `CompatReportFormat` parses via `FromStr`/`Display` (not a clap
        // `ValueEnum` derive) so its home crate carrick-observability does not
        // pull `clap` into every backend's compile closure.
        #[arg(long, default_value_t = CompatReportFormat::Json)]
        format: CompatReportFormat,
        #[arg(last = true)]
        command: Vec<String>,
    },
```

and the now-unused import at lines 35-38:

```rust
// `compat-report --format` uses the HVF report renderer (`CompatReportFormat`),
// which is macOS-only; the subcommand is gated off on platform-linux.
#[cfg(feature = "platform-macos")]
use carrick_runtime::compat::CompatReportFormat;
```

In `crates/carrick-cli/src/commands.rs` delete lines 1231-1241:

```rust
        #[cfg(feature = "platform-macos")]
        Commands::CompatReport { format, command } => {
            if command.is_empty() {
                bail!("compat-report needs a command after --");
            }
            tracing::warn!(
                "compat-report runtime hooks are scaffolded; returning an empty report for {:?}",
                command
            );
            let report = CompatReporter::default().finish();
            println!("{}", report.render(format)?);
        }
```

(`CompatReporter` stays imported: the `DispatchSyscall` arm at line ~1262 uses it.) In `crates/carrick-cli/src/main.rs` replace line 51

```rust
//!   the `debug` module), `syscalls` / `trap-capabilities` / `compat-report`
```

with

```rust
//!   the `debug` module), `syscalls` / `trap-capabilities`
```

In `README.md` replace line 104

```md
- **Diagnostics:** `carrick trace`, static USDT probes, `compat-report`, and the
```

with

```md
- **Diagnostics:** `carrick trace`, static USDT probes, the `run --json` compat report, and the
```

In `docs/diagnostics-and-debugging.md` replace lines 6-7

```md
binary. Three of them are first-class subcommands of the `carrick` CLI
(`carrick trace`, `carrick debug …`, `carrick compat-report`); the rest are
```

with

```md
binary. Two of them are first-class subcommands of the `carrick` CLI
(`carrick trace`, `carrick debug …`) plus the `carrick run --json` envelope; the rest are
```

and replace the section heading + command block at lines 519-524

```md
## 4. `carrick compat-report` — what did the guest need that we don't handle?

```sh
carrick compat-report [--format json|text] -- <cmd>
# or, on a container run, the same envelope as a flag:
carrick run --json <image> -- <cmd>
```
```

with

```md
## 4. The compat report (`carrick run --json`) — what did the guest need that we don't handle?

```sh
carrick run --json <image> <cmd…>
```
```

and line 527 and the paragraph at lines 538-545

```md
`compat-report` runs the guest and, on exit, emits a USDT-backed aggregation of
```
```md
The report is emitted as pretty JSON by default (`--format json`) or as a human
summary (`--format text`). The same envelope (exit code + traps + report) is
available on a normal container run via `carrick run --json …` (off by default;
`run` otherwise behaves like `docker run`, streaming guest stdio and matching the
guest's exit code). Internally each gap is a `CompatEvent` recorded through the
carrick USDT provider, so the same data is visible live under `carrick trace`
(`carrick*:::unhandled-syscall`, etc.) — `compat-report` is the batch
aggregation, `carrick trace` is the live stream.
```

with

```md
`carrick run --json` runs the guest and, on exit, emits a USDT-backed aggregation of
```
```md
The envelope (exit code + traps + report) is pretty JSON on stdout; it is off
by default (`run` otherwise behaves like `docker run`, streaming guest stdio
and matching the guest's exit code). Internally each gap is a `CompatEvent`
recorded through the carrick USDT provider, so the same data is visible live
under `carrick trace` (`carrick*:::unhandled-syscall`, etc.) — `--json` is the
batch aggregation, `carrick trace` is the live stream.
```

and line 558

```md
  translation map a `compat-report` gap points back into.
```

with

```md
  translation map a `run --json` compat-report gap points back into.
```

In `docs/syscalls-emulation-map.md` replace line 17

```md
to the `compat-report` reporter and to the per-syscall handler grouping.
```

with

```md
to the `CompatReporter` behind `carrick run --json` and to the per-syscall handler grouping.
```

and lines 334-341

```md
- To see what a *specific workload* actually exercises (and which calls fell
  through to `ENOSYS`), run the compat reporter, which aggregates the USDT
  probes at the dispatch boundary:

  ```sh
  carrick compat-report -- /path/to/guest-binary args…
  ```
```

with

```md
- To see what a *specific workload* actually exercises (and which calls fell
  through to `ENOSYS`), run it with the JSON envelope, which aggregates the
  USDT probes at the dispatch boundary:

  ```sh
  carrick run --json <image> /path/to/guest-binary args…
  ```
```

Verify and commit this deletion on its own (the greps match the SUBCOMMAND spellings only — `compat-report envelope` prose in `args.rs`/`commands.rs` describes the live `--json` output and is rewritten in Step 3; the dated records under `docs/2026-*` and `docs/superpowers/` are history and stay):

```sh
cd /Volumes/CaseSensitive/carrick
grep -rn 'CompatReport {\|Commands::CompatReport\|CompatReportFormat' crates/carrick-cli/src | wc -l   # expect 0
grep -rn 'carrick compat-report\|compat-report --\|compat-report`);\|`compat-report`,\|`compat-report` gap\|`compat-report` reporter\|`compat-report` is the' docs/diagnostics-and-debugging.md docs/syscalls-emulation-map.md crates/carrick-cli/src README.md | wc -l   # expect 0
just fmt && just check   # expect: Finished (produces the unsigned target/debug/carrick)
target/debug/carrick compat-report --help; echo "exit=$?"   # expect: clap "unrecognized subcommand" and exit=2
env RUST_MIN_STACK=8388608 cargo test -p carrick-cli --bin carrick   # expect: test result: ok
git add crates/carrick-cli/src/args.rs crates/carrick-cli/src/commands.rs crates/carrick-cli/src/main.rs \
  docs/diagnostics-and-debugging.md docs/syscalls-emulation-map.md README.md
git commit -F- <<'EOF'
refactor(cli): delete the scaffolded compat-report subcommand

Why: `carrick compat-report -- <cmd>` never ran a guest. Since the bootstrap
commit (05081274) its handler logged "runtime hooks are scaffolded" and
printed `CompatReporter::default().finish()` — an empty report — for any
command, so every doc pointing a user at it produced a false "nothing
unhandled" answer. The real aggregation already ships on `carrick run
--json`.

What: delete the `Commands::CompatReport` clap arm, its handler and the
macOS-only `CompatReportFormat` import; repoint `docs/diagnostics-and-
debugging.md` section 4, `docs/syscalls-emulation-map.md` and the README's
diagnostics bullet at `carrick run --json <image> <cmd…>`.
`CompatReporter`/`CompatReport` themselves are untouched (the `--json`
envelope and `dispatch-syscall` use them).

Verified: red-first grep (1 clap arm, 1 handler -> 0/0); `just check`;
`target/debug/carrick compat-report --help` now fails with clap's
unrecognized-subcommand error (exit 2); the carrick-cli bin tests pass.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
```

- [ ] **Step 3: Delete the no-op `run --raw` flag from the CLI and every caller**

`run --raw` became a no-op in 7ab32190 (default `run` is docker-shaped). `run-elf --raw` (`args.rs:205-210`) is a live, different flag and is NOT touched. In `crates/carrick-cli/src/args.rs` delete lines 390-394:

```rust
        /// Deprecated/no-op: the default `run` output is now docker-shaped
        /// (streamed stdio + the container's exit code). Kept so existing
        /// `--raw` invocations keep working; use `--json` for the old envelope.
        #[arg(long)]
        raw: bool,
```

and replace the module-doc bullet at lines 25-27

```rust
//! - **`--raw` vs `--json` on `run`** select the output envelope: `--raw` is now
//!   a no-op alias for the default docker-shaped streaming output, `--json` opts
//!   back into the legacy compat-report envelope.
```

with

```rust
//! - **`--json` on `run`** opts out of the default docker-shaped streaming
//!   output into the JSON envelope (exit code, traps, compat report).
```

In `crates/carrick-cli/src/commands.rs`: delete line 418 `                raw: !interactive,` (inside the `Commands::Shell` → `Commands::Run` normalisation) and line 848 `            raw,` (inside the `Commands::Run { … }` destructure; the `raw` at 544/609/660 belongs to the `run-elf` arm and stays; `native_shape_profile.rs:98` destructures `Commands::Run` with `..` and needs nothing); replace lines 42-43

```rust
//!    bytes and adopts the code); `--json` opts into the legacy compat-report
//!    envelope; `--raw` is now a no-op alias for the default.
```

with

```rust
//!    bytes and adopts the code); `--json` opts into the JSON compat
//!    envelope.
```

and lines 1083-1087

```rust
            // Default (and the back-compat `--raw`): behave like `docker run`.
            // The guest's stdout/stderr already streamed byte-exact; flush any
            // residual buffered bytes, surface a trap-limit failure on stderr
            // (never polluting stdout), and exit with the container's code.
            let _ = raw; // `--raw` is now the default behavior; accepted for compat.
```

with

```rust
            // Default: behave like `docker run`. The guest's stdout/stderr
            // already streamed byte-exact; flush any residual buffered bytes,
            // surface a trap-limit failure on stderr (never polluting stdout),
            // and exit with the container's code.
```

In `crates/carrick-cli/src/runtime_util.rs` replace lines 32-35

```rust
/// When `--raw` is set, emit the guest's buffered stdout/stderr to the
/// carrick host process's fd 1 / fd 2 instead of wrapping them in JSON.
/// This makes carrick feel like a normal command runner: `carrick run
/// alpine /bin/busybox echo hi --raw` prints just `hi`.
```

with

```rust
/// Emit the guest's residual buffered stdout/stderr to the carrick host
/// process's fd 1 / fd 2 (the default `run` path and `run-elf --raw`) instead
/// of wrapping them in JSON, so `carrick run alpine /bin/busybox echo hi`
/// prints just `hi`.
```

In `crates/carrick-runtime/src/execute.rs` replace the line-155 fragment `Goes to stderr so it never corrupts a \`--raw\`` (line 156 stays `/// guest's stdout.`) with `Goes to stderr so it never corrupts a streaming`; in `crates/carrick-runtime/src/dispatch/fs.rs:7675` replace `// stdio is wired to our host fds (stream_stdio / --raw),` with `// stdio is wired to our host fds (stream_stdio),`.

- [ ] **Step 4: Remove `--raw` from every `carrick run` argv the Rust tests and harness build (including the seven `run` sites in `crates/carrick-cli/tests/conformance.rs` — owned by this cluster, A5)**

After Step 3 clap rejects `run --raw` with exit 2, so every probe gate (`bridge_probe_args`, the `run_carrick_probe_*` family, the lane runner in `conformance.rs`) goes red until these argv sites are fixed; they are in this task's commit (Step 5), not deferred to any other cluster.

```sh
cd /Volumes/CaseSensitive/carrick
# carrick-cli/tests/conformance.rs — the four vec! sites (363/398/420/452) and the two .args([...]) sites (2694/3734)
sed -i '' -e '/^        "--raw".to_string(),$/d' -e '/^            "--raw",$/d' crates/carrick-cli/tests/conformance.rs
# the single-line site at 3676
sed -i '' 's/command.args(\["run", "--platform", lane.platform, "--raw", "--fs", "host"\]);/command.args(["run", "--platform", lane.platform, "--fs", "host"]);/' crates/carrick-cli/tests/conformance.rs
grep -c '"--raw"' crates/carrick-cli/tests/conformance.rs   # expect 2 (both `run-elf` lines at ~4869/4879)
```

Then Edit these remaining sites by hand (each block is unique in its file):

`crates/carrick-cli/tests/conformance.rs` prose at 2903 and 2940: replace `// Default-run contract: unlike \`conformance\` (which runs \`--raw\` and merges` with `// Default-run contract: unlike \`conformance\` (which merges` and `/// Run a snippet under carrick on the DEFAULT path (no \`--raw\`): returns` with `/// Run a snippet under carrick on the DEFAULT path: returns`.

`crates/carrick-cli/tests/dsr_trace_overhead.rs` (DirectV8 block only, line 761; the four `run-elf` blocks at 730/739/748/773 keep their `--raw`):

```rust
            "--max-traps".to_owned(),
            u64::MAX.to_string(),
            "--raw".to_owned(),
            "--fs".to_owned(),
```
→
```rust
            "--max-traps".to_owned(),
            u64::MAX.to_string(),
            "--fs".to_owned(),
```

`crates/carrick-cli/tests/perf_support/invoke.rs:313-319`:

```rust
        "run".into(),
        "--platform".into(),
        PLATFORM.into(),
        "--raw".into(),
        "--fs".into(),
```
→
```rust
        "run".into(),
        "--platform".into(),
        PLATFORM.into(),
        "--fs".into(),
```

`crates/carrick-cli/tests/perf_support/xboundary.rs:97-102`: delete the line `                    "--raw",` between `PLATFORM,` and `"--fs",`.

`crates/carrick-cli/tests/perf_runner.rs:126`: delete `        "--raw".to_owned(),` from `v8_backend_args`; and at 314-321 delete `        "--raw",` from the `required` list of `v8_backend_commands_share_the_workload_contract`.

`crates/carrick-conformance/src/generate.rs`:

```sh
sed -i '' 's/\["--raw", "--fs", "host"/["--fs", "host"/g' crates/carrick-conformance/src/generate.rs   # rewrites the 8 test expectations (881/890/901/907/935/959/995/1002)
```
then replace line 347

```rust
    let mut flags = vec!["--raw".to_string(), "--fs".to_string(), "host".to_string()];
```
with
```rust
    let mut flags = vec!["--fs".to_string(), "host".to_string()];
```
and line 337 `/// carrick's launch flags for a suite. The base is \`--raw --fs host\`; on top` with `/// carrick's launch flags for a suite. The base is \`--fs host\`; on top`.

`crates/carrick-conformance/src/manifest.rs:92`: `/// carrick-only envelope flags (e.g. \`["--raw","--fs","host"]\`).` → `/// carrick-only envelope flags (e.g. \`["--fs","host"]\`).`; line 243 `carrick_flags = ["--raw", "--fs", "host"]` → `carrick_flags = ["--fs", "host"]`.

`crates/carrick-conformance/src/oracle.rs:441`: `carrick_flags: vec!["--raw".into(), "--fs".into(), "host".into()],` → `carrick_flags: vec!["--fs".into(), "host".into()],`.

`crates/carrick-conformance/src/engine.rs:10-11`:

```rust
//! after it is handed to the guest. Therefore ALL envelope flags (`--raw`,
//! `--fs`, `-v`, `-w`, `-e`, `--entrypoint`) go BEFORE the image, and only `cmd`
```
→
```rust
//! after it is handed to the guest. Therefore ALL envelope flags (`--fs`,
//! `-v`, `-w`, `-e`, `--entrypoint`) go BEFORE the image, and only `cmd`
```

The generated manifest (2,127 suites, all with the identical base prefix — Step 1 proved the count):

```sh
sed -i '' 's/^carrick_flags = \["--raw", "--fs", "host"/carrick_flags = ["--fs", "host"/' scripts/conformance/suites.toml
grep -c -- '--raw' scripts/conformance/suites.toml                     # expect 0
grep -c '^carrick_flags = \["--fs", "host"' scripts/conformance/suites.toml   # expect 2127
```

`handoff.md`: line 28 `` `carrick run ubuntu:24.04 --raw --fs host /bin/sh -c '/bin/echo hi'` exits 0, `` → `` `carrick run ubuntu:24.04 --fs host /bin/sh -c '/bin/echo hi'` exits 0, ``; line 711 `` `base64 < probe | carrick run --raw --fs host ubuntu:24.04 /bin/sh -c `` → `` `base64 < probe | carrick run --fs host ubuntu:24.04 /bin/sh -c ``; line 2164 `` maintenance`. `carrick run ubuntu:24.04 --raw --fs host /bin/sh -c '/bin/echo hi'` `` → `` maintenance`. `carrick run ubuntu:24.04 --fs host /bin/sh -c '/bin/echo hi'` ``. (Lines 1854 and 2097 say `run-elf --raw` and stay.)

- [ ] **Step 4b: Remove `--raw` from every non-Rust `carrick run` caller (these BREAK after Step 3 — clap rejects the flag, or, spelled after the image, hands `--raw` to the guest as its command; the Rust callers, `crates/carrick-cli/tests/conformance.rs` included, were handled in Step 4)**

Exhaustive list at HEAD (35 lines; `grep -rn -e '--raw' scripts docker .agents docs/conformance-testing.md docs/native-dsr-dtrace-profile.md docs/hvpatch-exec-authority-routing-plan.md README.md handoff.md --exclude='*.jsonl' --exclude=suites.toml | grep -v run-elf`, minus the three handoff.md lines already done in Step 4). Every site is a `carrick run` argv or a doc/header quoting one; none is a `run-elf`:

- Live harness/tool scripts: `scripts/conformance/carrier-topology-gate.py:1011,1045` (driven by `just carrier-topology-gate`), `scripts/conformance/bhyve-grind.sh:65`, `scripts/conformance/vcpu-admission-gate.sh:130` (log text), `scripts/run-probe.sh:60`, `scripts/test-parallel-cleanup.sh:14-15`, `scripts/go-deadlock-capture.sh:103`, `scripts/go-deadlock-capture-ext.sh:80`, `scripts/go-conformance-image.sh:53`, `scripts/go-conformance.sh:200`, `scripts/cpython-parity.py:85`, `scripts/ltp-reduce.py:101`, `scripts/ltp-baseline.py:102`, `scripts/perf/native_budget.py:208`, `scripts/perf/native_compiler_budget.py:3310`, `scripts/perf/tier_d_node_reliability.py:83`, `scripts/perf/bisect-epoll-p50.sh:14`, `scripts/repro/hvpatch-thread-spawn-wedge.sh:35`, `.agents/skills/ltp-conformance/scripts/ltp-check.sh:57`, `.agents/skills/ltp-conformance/scripts/ltp-full-sweep.sh:82`.
- The nodejs-conformance entrypoint and its dry-run test: `docker/nodejs-conformance/nodejs-conformance:138` (`local args=(run --raw --entrypoint /bin/bash …` → `local args=(run --entrypoint /bin/bash …`) and `scripts/test-nodejs-conformance-dry-run.sh:91` — DELETE the line `contains "$carrick_out" "<--raw>"` (it would otherwise start failing).
- Comment-only: `docker/go-conformance/Dockerfile:22`; the durable dtrace headers `scripts/dtrace/guest_stack.d:33`, `scripts/dtrace/hvpatch-clone08-control-flow.d:29`, `scripts/dtrace/msgstress-sysv.d:7`, `scripts/dtrace/hvpatch-phase2-exit-census.d:26`, `scripts/dtrace/vfork-smash-signal-injections.d:77` (header prose only — the D program bytes are unchanged, so `program_sha256` is unaffected); docs `docs/conformance-testing.md:106,215`, `docs/native-dsr-dtrace-profile.md:54`, `docs/hvpatch-exec-authority-routing-plan.md:14`; skills `.agents/skills/carrick-native-debug/SKILL.md:166`, `.agents/skills/ltp-conformance/SKILL.md:112`, `.agents/skills/carrick-lldb/SKILL.md:80`.

The three token shapes are uniform (` --raw` followed by a space or end of line; `"--raw", ` inline in a Python list; a standalone `"--raw",` list line). Apply one run-elf-guarded sed to exactly that file list, then read every hunk:

```sh
cd /Volumes/CaseSensitive/carrick
files='scripts/conformance/carrier-topology-gate.py scripts/conformance/bhyve-grind.sh scripts/conformance/vcpu-admission-gate.sh
scripts/run-probe.sh scripts/test-parallel-cleanup.sh scripts/go-deadlock-capture.sh scripts/go-deadlock-capture-ext.sh
scripts/go-conformance-image.sh scripts/go-conformance.sh scripts/cpython-parity.py scripts/ltp-reduce.py scripts/ltp-baseline.py
scripts/perf/native_budget.py scripts/perf/native_compiler_budget.py scripts/perf/tier_d_node_reliability.py scripts/perf/bisect-epoll-p50.sh
scripts/repro/hvpatch-thread-spawn-wedge.sh .agents/skills/ltp-conformance/scripts/ltp-check.sh .agents/skills/ltp-conformance/scripts/ltp-full-sweep.sh
docker/nodejs-conformance/nodejs-conformance docker/go-conformance/Dockerfile
scripts/dtrace/guest_stack.d scripts/dtrace/hvpatch-clone08-control-flow.d scripts/dtrace/msgstress-sysv.d scripts/dtrace/hvpatch-phase2-exit-census.d scripts/dtrace/vfork-smash-signal-injections.d
docs/conformance-testing.md docs/native-dsr-dtrace-profile.md docs/hvpatch-exec-authority-routing-plan.md
.agents/skills/carrick-native-debug/SKILL.md .agents/skills/ltp-conformance/SKILL.md .agents/skills/carrick-lldb/SKILL.md'
sed -i '' -E '/run-elf/!{s/ --raw( |$)/\1/; s/"--raw", //; /^ *"--raw",$/d;}' $files
sed -i '' '/^contains "\$carrick_out" "<--raw>"$/d' scripts/test-nodejs-conformance-dry-run.sh
git diff --stat -- $files scripts/test-nodejs-conformance-dry-run.sh   # expect exactly 33 files, 35 hunks; read each: every removed token is on a `carrick run` line or a comment quoting one
grep -rn -e '--raw' $files scripts/test-nodejs-conformance-dry-run.sh | grep -v 'run-elf' | wc -l   # expect 0
sh -n scripts/run-probe.sh scripts/go-conformance.sh scripts/go-conformance-image.sh docker/nodejs-conformance/nodejs-conformance   # expect: silent (array syntax intact)
python3 -m py_compile scripts/conformance/carrier-topology-gate.py scripts/cpython-parity.py scripts/ltp-reduce.py scripts/ltp-baseline.py scripts/perf/native_budget.py scripts/perf/native_compiler_budget.py scripts/perf/tier_d_node_reliability.py   # expect: silent
sh scripts/test-nodejs-conformance-dry-run.sh   # expect: passes with the `<--raw>` assertion gone
```

Note on `scripts/conformance/baseline*.jsonl`: `baseline.jsonl` carries 2,064 (and `baseline.kvm.jsonl`/`baseline.bhyve.jsonl` 9 each) `carrick_argv` receipts that include `--raw`. They are result receipts (`verdict.rs:84`), not inputs — `check-matrix` renders verdicts and never reads the argv, and they refresh on the next `--bless` — so they are deliberately NOT edited here and are excluded from the greps.

- [ ] **Step 5: Green checks for the `--raw` deletion, then commit**

```sh
cd /Volumes/CaseSensitive/carrick
grep -rn -e '"--raw"' crates --include='*.rs' | wc -l          # expect 9
grep -rn -e '"--raw"' crates --include='*.rs' | grep -v 'run-elf' | grep -v 'to_owned()' | wc -l   # expect 0 (every survivor is a run-elf argv; the to_owned() ones are the 4 run-elf blocks in dsr_trace_overhead.rs and invoke.rs:163)
grep -rn -e '--raw' crates/carrick-cli/src crates/carrick-runtime/src crates/carrick-conformance/src scripts docker .agents docs/conformance-testing.md docs/native-dsr-dtrace-profile.md docs/hvpatch-exec-authority-routing-plan.md README.md handoff.md --exclude='*.jsonl' | grep -v 'run-elf' | wc -l   # expect 0
just fmt && just check
target/debug/carrick run --help | grep -c -- '--raw'          # expect 0
target/debug/carrick run-elf --help | grep -c -- '--raw'      # expect 1
target/debug/carrick run --raw ubuntu:24.04 /bin/true; echo "exit=$?"   # expect clap "unexpected argument '--raw' found" and exit=2 (`image` has no allow_hyphen_values, so clap never treats it as a positional; no guest starts, no signing needed)
just clippy
just test                                                     # expect ok; includes carrick-conformance's --bins tests (generate.rs committed_manifest_* now assert ["--fs","host",…])
just check-matrix                                             # expect: no drift (the baseline `carrick_argv` receipts are not rendered)
```

HVF-gated harness proof (signed; two-phase, never concurrent with Docker):

```sh
CARRICK_RUN_ID=a5-task12 just conformance-quick
```

Expected: the quick tier completes with the same verdicts as before this change and the raw logs (`grep -a` them) contain no `unexpected argument '--raw'`. Then:

```sh
git add crates/carrick-cli/src/args.rs crates/carrick-cli/src/commands.rs crates/carrick-cli/src/runtime_util.rs \
  crates/carrick-cli/tests/conformance.rs crates/carrick-cli/tests/dsr_trace_overhead.rs \
  crates/carrick-cli/tests/perf_support/invoke.rs crates/carrick-cli/tests/perf_support/xboundary.rs \
  crates/carrick-cli/tests/perf_runner.rs crates/carrick-conformance/src/generate.rs \
  crates/carrick-conformance/src/manifest.rs crates/carrick-conformance/src/oracle.rs \
  crates/carrick-conformance/src/engine.rs scripts/conformance/suites.toml \
  crates/carrick-runtime/src/execute.rs crates/carrick-runtime/src/dispatch/fs.rs handoff.md \
  $files scripts/test-nodejs-conformance-dry-run.sh
git status --short   # expect: only the files above staged, nothing unstaged
git commit -F- <<'EOF'
refactor(cli): delete the no-op run --raw flag

Why: `carrick run --raw` has done nothing since 7ab32190 made the default
`run` output docker-shaped; the handler read `let _ = raw` and the help text
called it "Deprecated/no-op … kept so existing invocations keep working".
Carrick carries no compatibility spellings, and every harness argv that
still passed it was documenting a mode that does not exist. The engine's
`RunSpec.raw` field is a separate matter and is replaced by `StdioMode` in
Phase C (Task 24, the `StdioMode` / `RunRequest` engine task).

What: delete the clap field and its destructures (`Commands::Run`, the
`shell` normalisation), the "back-compat --raw" comments, and every
`carrick run … --raw` argv: the CLI tests (`tests/conformance.rs` probe
runners included), the conformance harness
(`carrick_flags_for` base is now `["--fs","host"]`, the manifest example, the
oracle-cache fixture), the generated `scripts/conformance/suites.toml`
(2,127 rows, mechanical sed of the identical prefix), the topology /
bhyve-grind / run-probe / ltp / go / cpython / perf scripts, the
nodejs-conformance entrypoint (and its dry-run assertion), and the docs,
skills and dtrace headers that quoted the flag. `run-elf --raw` is a
different, live flag (stream vs JSON) and is untouched. The oracle cache key
does not include `carrick_flags`, so no re-bless is triggered; the
`carrick_argv` receipts in `baseline*.jsonl` still show `--raw` until the
next bless and are not read by any gate.

Verified: red-first counts (33 `"--raw"` literals -> 9, all `run-elf`;
suites.toml 2127 -> 0; 35 non-Rust caller lines -> 0); `carrick run --help`
lists no `--raw`, `run-elf --help` still does; `carrick run --raw …` now
fails in clap with exit 2; `sh -n`/`py_compile` on every touched script and
the nodejs dry-run test; `just clippy`, `just test`, `just check-matrix`; and
a signed `just conformance-quick` with unchanged verdicts and no argv errors
in the raw logs.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
```

- [ ] **Step 6: Correct the two stale EL1-shim comments (getpid/gettid only)**

Ground truth (verified): `memory.rs:291` `IDENTITY_SYSCALLS = &[(172, IDENTITY_OFF_PID)]` and `memory.rs:297` `GETTID_NR = 178`, served by `el1_vectors_bytes_shim` (`memory.rs:3148`, gettid from `CONTEXTIDR_EL1` at 3232); the identity page holds only `IDENTITY_OFF_PID` / `IDENTITY_OFF_SHIM_ENABLED` / `IDENTITY_OFF_SHIM_SYSCALLS` (no uid/gid fields), so uid/gid reads trap. In `crates/carrick-mem/src/memory.rs` replace lines 194-198

```rust
// Carrick's per-process identity data page. The EL1 syscall-shim vector
// dispatcher (`el1_vectors_bytes_shim`) reads pid/uid/gid from here to service
// getpid/getuid/geteuid/getgid/getegid entirely at EL1 — no VM exit. It sits
// immediately past the EL1 maintenance trampoline, still inside the kernel
// hole's first 2 MiB block, so it inherits the kernel-only (AP=00) block
```

with

```rust
// Carrick's per-process identity data page. The EL1 syscall-shim vector
// dispatcher (`el1_vectors_bytes_shim`) reads the pid from here to service
// `getpid` (172) entirely at EL1 — no VM exit; the same shim serves `gettid`
// (178) from the vCPU's `CONTEXTIDR_EL1`. Every other syscall, the
// `getuid`/`geteuid`/`getgid`/`getegid` credential reads included, traps and
// dispatches through the captured `KernelContext`. The page sits
// immediately past the EL1 maintenance trampoline, still inside the kernel
// hole's first 2 MiB block, so it inherits the kernel-only (AP=00) block
```

In `crates/carrick-cli/Cargo.toml` replace lines 15-18

```toml
# Guest-side syscall shim (forwarded to carrick-runtime). The base shim
# (getpid/get*id/gettid, answered guest-side from the identity page / TPIDR_EL1)
# is default ON. Build with `--no-default-features` for the legacy trap-only
# vector path.
```

with

```toml
# Guest-side EL1 syscall shim (forwarded to carrick-runtime). It serves exactly
# `getpid` (172, from the identity page) and `gettid` (178, from
# `CONTEXTIDR_EL1`) without a VM exit; every other syscall — the `get*id`
# credential reads included — traps and dispatches. Default ON; build with
# `--no-default-features` for the trap-only vector path.
```

```sh
cd /Volumes/CaseSensitive/carrick
grep -c 'getpid/getuid/geteuid/getgid/getegid' crates/carrick-mem/src/memory.rs   # expect 0
grep -c 'getpid/get\*id/gettid' crates/carrick-cli/Cargo.toml                     # expect 0
just fmt && just check && just doc                                                # expect: Finished, no rustdoc warnings
git add crates/carrick-mem/src/memory.rs crates/carrick-cli/Cargo.toml
git commit -F- <<'EOF'
docs(mem): state the EL1 shim serves only getpid and gettid

Why: two comments claimed the EL1 syscall shim answers
getpid/getuid/geteuid/getgid/getegid (and "get*id") from the identity page.
The code says otherwise: `IDENTITY_SYSCALLS` holds exactly `(172, pid)` and
`el1_vectors_bytes_shim` adds `gettid` (178) from `CONTEXTIDR_EL1`; the
identity page has no uid/gid field and every credential read traps and
dispatches. The embed observer design depends on knowing precisely which
syscalls bypass dispatch, so the prose must match.

What: rewrite the identity-page comment in `carrick-mem/src/memory.rs` and
the `syscall-shim` feature comment in `carrick-cli/Cargo.toml`. No code
change.

Verified: grep of the wrong phrases 1/1 -> 0/0 against `IDENTITY_SYSCALLS`
(memory.rs:291) and `GETTID_NR` (memory.rs:297); `just check`, `just doc`.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
```

### Task 13: Retire fork-era prose, fix the `interactive_tty` binary path, and correct the `justfile` test comment

**Files:**
- Modify: `crates/carrick-runtime/src/runtime.rs:1-98` (module doc after Task 11 (delete the fork-era tokio guard and the vestigial forked-child exit paths)), `:~1006-1007`
- Modify: `crates/carrick-runtime/src/threaded_loop.rs:106-114, 184`
- Modify: `crates/carrick-runtime/src/dispatch/mod.rs:87`
- Modify: `crates/carrick-cli/src/lifecycle.rs:25-36`
- Modify: `crates/carrick-cli/src/supervisor_perf.rs:30-58, 67-81`
- Modify: `crates/carrick-runtime/src/lib.rs:729-747`
- Modify: `crates/carrick-runtime/src/pty_relay.rs:17-20, 262-264`
- Modify: `crates/carrick-cli/src/main.rs:204-209, 276-281`
- Modify: `crates/carrick-cli/src/commands.rs:~1049-1052`
- Modify: `crates/carrick-runtime/tests/interactive_tty.rs:24`
- Modify: `justfile:170-173`
- Test: grep assertions + `just doc` + `just clippy`; `cargo test -p carrick-runtime --test interactive_tty -- --ignored` against a signed binary (HVF-gated)

Line numbers below are measured at HEAD before Tasks 11 (tokio guard / forked-child exit paths) and 12 (`compat-report` / `run --raw` deletion); `runtime.rs` and `commands.rs` shift after those tasks — match on the quoted text.

**Interfaces:**
- Consumes: nothing new (prose + one test path + one recipe comment).
- Produces: `crates/carrick-runtime/tests/interactive_tty.rs::signed_bin()` resolves `<workspace>/target/release/carrick` (the `just build` output) instead of the nonexistent `crates/carrick-runtime/target/release/carrick`.

- [ ] **Step 1: Red-first grep assertions (run AFTER Task 11 (delete the fork-era tokio guard and the vestigial forked-child exit paths) has landed)**

```sh
cd /Volumes/CaseSensitive/carrick
grep -c 'libc::fork' crates/carrick-runtime/src/runtime.rs                          # expect 5 (all in the module doc: lines 28, 42, 46, 53, 59; it is 6 before Task 11 removes the `_exit` paragraph)
grep -c 'handle_fork' crates/carrick-runtime/src/threaded_loop.rs                   # expect 1
grep -c 'real `libc::fork` against the trap engine' crates/carrick-runtime/src/dispatch/mod.rs   # expect 1
grep -c 'bare `fork(2)`' crates/carrick-cli/src/lifecycle.rs                        # expect 1
grep -c 'fork_interactive_session' crates/carrick-cli/src/supervisor_perf.rs        # expect 2
grep -c 'interactive_supervisor::adopt_stdio' crates/carrick-runtime/src/lib.rs     # expect 1
grep -c 'before the runtime child is' crates/carrick-runtime/src/pty_relay.rs       # expect 1
grep -c 'host self-re-exec' crates/carrick-cli/src/main.rs                          # expect 1
grep -c 'interactive `-t` runs fork' crates/carrick-cli/src/main.rs                 # expect 1
grep -c 'fork descendants that also reach this tail' crates/carrick-cli/src/commands.rs   # expect 1 (the phrase is line-wrapped there, so the main.rs spelling does not match)
grep -c '"/target/release/carrick"' crates/carrick-runtime/tests/interactive_tty.rs # expect 1
grep -c 'run_elf_command_' justfile                                                 # expect 1
grep -c 'run_elf_command_' crates/carrick-cli/tests/cli.rs                          # expect 0 (the cases the comment cites do not exist)
```

- [ ] **Step 2: Rewrite the `runtime.rs` module doc**

After Task 11 (delete the fork-era tokio guard and the vestigial forked-child exit paths) the doc occupies lines 1-98 (`//! The run lifecycle…` through `//! [\`AddressSpace\`]: crate::memory::AddressSpace`). Replace the whole `//!` block with:

```rust
//! The run lifecycle: load an image, drive the trap→dispatch→complete loop, and
//! own the process/thread, signal-delivery, and fault-handling models.
//!
//! # The loop
//!
//! Every `run_*` entry point converges on [`finish_and_run_image`], which
//! finalises a loaded [`AddressSpace`] (EL0 trampoline → EL1 vectors → stage-1
//! page tables → vDSO) and enters the trap engine. The core of the runtime is a
//! tight loop:
//!
//! 1. `next_syscall` runs the vCPU (`hv_vcpu_run`) until the guest executes
//!    `svc #0`, faults synchronously at EL0, or is forced out by a cross-thread
//!    kick.
//! 2. The trapped frame (`x8` = syscall number, `x0..x5` = args) is handed to
//!    the [`SyscallDispatcher`], which emulates it against Darwin host
//!    primitives and returns a [`DispatchOutcome`].
//! 3. The loop acts on the outcome — write the return value into `x0` and resume
//!    (`Returned`/`Errno`), block on host fds and re-dispatch on readiness
//!    (`WaitOn*`), create or retire a logical process or thread
//!    (`Fork`/`CloneThread`/`Execve`/`Exit`), or pop a signal frame (`SigReturn`).
//! 4. Between syscalls it delivers any pending signal ([`deliver_pending_signal`]).
//!
//! There are **two** loop implementations:
//!
//! - **Single-threaded fixture loop** ([`run_combined_syscall_loop_with_dispatcher`],
//!   and its split-view sibling [`run_split_loop`]): one vCPU, no thread
//!   registry. Retained only as a deterministic syscall/memory fixture for the
//!   in-process test harnesses and `run-elf`. It runs exactly one logical
//!   process: a guest `fork(2)` here lowers to `EOPNOTSUPP`.
//! - **HVPatch unified kernel loop** ([`run_threaded_hvf_loop`] →
//!   `threaded_loop::run_threaded_loop` → `vcpu_loop::run_vcpu_until_exit`):
//!   every Linux process and thread of the container is a logical task in
//!   Carrick's kernel graph, multiplexed inside ONE host process (the carrier)
//!   and ONE HVF VM. Each logical guest thread has a host pthread, but HVF
//!   vCPUs are a bounded, reclaimable set of leases (`carrick_hal::vcpu_sched`).
//!   Shared kernel state lives behind [`KernelState`](crate::vcpu_loop::KernelState)
//!   (an `Arc`, each subsystem internally synchronised — there is no single big
//!   lock). This is the path every product run takes (Go, CPython, Node,
//!   apt/dpkg).
//!
//! Both loops produce a [`RunResult`] (exit code + captured stdio + the
//! [`CompatReport`](crate::compat::CompatReport)).
//!
//! # The process/thread model
//!
//! No guest operation creates a host process. macOS HVF allows one VM per host
//! process (a second `hv_vm_create` returns `HV_BUSY`), and the kernel graph
//! makes that irrelevant:
//!
//! - **`clone(2)` that creates a thread** (`CLONE_VM`):
//!   [`DispatchOutcome::CloneThread`] spawns a host thread that acquires a vCPU
//!   lease in the *same* VM and runs `run_vcpu_until_exit`.
//! - **`fork(2)` / `vfork(2)` / process-creating `clone(2)`**:
//!   [`DispatchOutcome::Fork`] is a logical kernel-graph fork
//!   (`prepare_in_process_fork` → `complete_persistent_process_fork` in
//!   `vcpu_loop`): the child gets its own mm, pid, credentials and wait edges
//!   inside the carrier, COW-armed private pages, and a fresh logical thread.
//!   Process-fork admission must win before the child waits for a vCPU lease,
//!   and fork participates in exec/exit cancellation.
//! - **`execve(2)`**: [`DispatchOutcome::Execve`] tears down the task's address
//!   space and reloads the new ELF in place; the host process is untouched.
//!
//! Orthogonal to fork, a stage-1 **page-table edit** (mmap/mprotect/munmap that
//! changes a mm's shared descriptors) is a lighter stop-the-world: `pt_pause`
//! (in `vcpu_loop`) kicks in-guest siblings of that mm out so none walks a
//! half-edited table, but *keeps* every vCPU alive. The handshake between an
//! editing coordinator and a vCPU about to enter the guest is a Dekker pattern
//! on `quiescing` ↔ `in_guest` (SeqCst), so neither side misses the other.
//!
//! # PID-namespace placement
//!
//! A container `carrick run` that requests PID-ns placement initializes the
//! kernel arena and namespace table directly in the one VM carrier. Guest
//! processes remain logical Carrick-kernel tasks; launch placement never forks
//! a host namespace-supervisor process. `run-elf` never requests placement, so
//! it stays in the identity namespace.
//!
//! # Faults are signals
//!
//! A synchronous guest EL0 fault (nil deref, bad access, `BRK`, single-step) is
//! not fatal to carrick: [`crate::vcpu_loop`]'s `deliver_fault_signal` maps the
//! `ESR_EL1`
//! to the Linux `(signum, si_code)` the kernel would deliver (SIGSEGV/SIGBUS/
//! SIGTRAP) and injects it into the guest, so Go's `sigpanic`/`recover`, glibc
//! backtraces, and any installed handler run exactly as on Linux.
//!
//! # Exit is an unwind, never `_exit`
//!
//! Because no guest exit is a host-process exit, every exit path of both loops
//! returns a [`RunResult`] and unwinds normally through `Drop`.
//!
//! [`AddressSpace`]: crate::memory::AddressSpace
```

Also replace the stale comment at lines ~1006-1007 (pre-Task-11 numbering; ~995-996 after)

```rust
                // Reflect the new program into the host process name
                // (`carrick: <argv>`), so a hung forked-exec'd
                // child is identifiable in `ps -M` / Activity Monitor.
```

with

```rust
                // Reflect the new program into the host process name
                // (`carrick: <argv>`), so a hung exec'd guest is
                // identifiable in `ps -M` / Activity Monitor.
```

- [ ] **Step 3: Move and correct the misattached loop doc in `threaded_loop.rs`**

Lines 106-114 attach the threaded-loop description to `publish_initial_frame_inventory`. Replace

```rust
/// The ONE threaded vCPU run loop, parameterized over the host seam
/// [`HostBackend`]. Replaces `run_threaded_kvm_loop` / `run_threaded_bhyve_loop`
/// (and any future kick+futex backend's): builds the shared scaffold + the
/// host's four trait objects, installs the kick handler / pump via the
/// coordinator, wires timer delivery, and drives the generic
/// `vcpu_loop::run_vcpu_until_exit`. `handle_fork` (real `libc::fork` + child VM
/// rebuild), `spawn_clone_thread` (sibling vCPUs), and the private/shared futex
/// paths all flow through the shared loop.
fn publish_initial_frame_inventory<Inventory>(
```

with

```rust
/// Publish the root mm's initial frame inventory as one reserve→commit
/// transaction; a rejected publication aborts, because the HVF mappings
/// already exist and running with two truths is not recoverable.
fn publish_initial_frame_inventory<Inventory>(
```

and put the corrected loop doc on `run_threaded_loop` (line 184), replacing

```rust
pub(crate) fn run_threaded_loop<E, H>(
```

with

```rust
/// The ONE threaded vCPU run loop, parameterized over the host seam
/// [`HostBackend`]: builds the shared scaffold + the host's trait objects,
/// installs the kick handler / pump via the coordinator, wires timer
/// delivery, and drives the generic `vcpu_loop::run_vcpu_until_exit`. Logical
/// process fork (`DispatchOutcome::Fork`, no host process), sibling-vCPU
/// thread clone, and the private/shared futex paths all flow through it.
pub(crate) fn run_threaded_loop<E, H>(
```

- [ ] **Step 4: Fix the remaining fork-era sentences (one edit each)**

`crates/carrick-runtime/src/dispatch/mod.rs:87`:
```rust
//!   [`DispatchOutcome::Fork`] (real `libc::fork` against the trap engine),
```
→
```rust
//!   [`DispatchOutcome::Fork`] (a logical kernel-graph fork inside the carrier;
//!   no host process is created),
```

`crates/carrick-cli/src/lifecycle.rs:25-36`:
```rust
//! `run -d` is a bare `fork(2)`, done here in the CLI while it is still
//! single-threaded (no tokio runtime is live — `block_on_oci` builds and drops
//! its own per-call runtime; see [`crate::runtime_util`]). The PARENT writes a
//! `Created` registry entry, prints the container id, and returns, freeing the
//! user's shell. The CHILD becomes the container's lifetime:
//! `setsid()` → redirect stdio (stdin←`/dev/null`, stdout/stderr→`output.log`,
//! so `carrick logs` can replay it) → export `CARRICK_CONTAINER_ID` → run the
//! engine in that same process. The carrier records itself as `Running`, owns
//! every logical guest task, and marks the entry `Exited` (or removes it for
//! `--rm`) on normal completion. `run_detached_carrier` is the shared post-fork
//! body; `start`/`restart` reuse it, additionally setting `CARRICK_EXEC_OVERLAY`
//! to re-attach an already-extracted rootfs overlay instead of re-extracting.
```
→
```rust
//! `run -d` is a `posix_spawn` of this same binary as the hidden
//! `__carrier-entry` subcommand (`CarrierLauncher::launch`, the one product
//! boundary allowed to create a carrier; it carries no borrowed Rust/tokio
//! state, so it is equally safe from the API server's multi-threaded runtime).
//! The LAUNCHER writes a `Created` registry entry, waits for the carrier's
//! readiness receipt, prints the container id, and returns, freeing the user's
//! shell. The CARRIER (`carrier_entry`) becomes the container's lifetime:
//! `setsid()` → redirect stdio (stdin←`/dev/null`, stdout/stderr→`output.log`,
//! so `carrick logs` can replay it) → export `CARRICK_CONTAINER_ID` → run the
//! engine in that same process. It records itself as `Running`, owns every
//! logical guest task, and marks the entry `Exited` (or removes it for `--rm`)
//! on normal completion. `run_detached_carrier` is the shared carrier body;
//! `start`/`restart` reuse it, additionally setting `CARRICK_EXEC_OVERLAY` to
//! re-attach an already-extracted rootfs overlay instead of re-extracting.
```

`crates/carrick-cli/src/supervisor_perf.rs:30-58` (from `//! ## Why the emitter is gated on PROCESS IDENTITY, not call-site placement` through `//! the totals fold transitively up to the Launcher by exit.`) → replace with:

```rust
//! ## Why the emitter is gated on PROCESS IDENTITY, not call-site placement
//!
//! Under HVPatch one `carrick run` is one host process: every guest process
//! and thread is a logical kernel-graph task on the carrier's own threads, so
//! `RUSAGE_SELF` already covers the whole guest tree and `RUSAGE_CHILDREN` is
//! the CPU of real host children only (none on the run path). Exactly one
//! process therefore reaches `Commands::Run`'s tail per invocation. The pid
//! gate stays as the fail-closed guard for the two ways a second image can
//! exist: a detached `run -d` `posix_spawn`s `__carrier-entry`, which runs
//! `main` (recording its own pid) but dispatches to `carrier_entry`, never to
//! `Commands::Run`; and `carrick trace`'s sudo re-exec (`trace_cli`) replaces
//! this image with `exec` before any run, so the pre-exec image never reaches
//! the tail and the re-exec'd carrick is simply the one top-level process of
//! its own pid. A path that reaches the emit site without passing through
//! `main` — no recorded pid — fails quiet rather than double-reporting, since
//! `parse_nativeperf` hard-fails on a duplicate supervisor line.
//!
//! The discriminator is process identity: `main` records `getpid()` in
//! [`TOP_LEVEL_PID`] before any dispatch, and only the process whose
//! `getpid()` matches may emit.
```

and lines 67-81 (the `TOP_LEVEL_PID` doc, from `/// The pid of the ONE true top-level \`carrick\` process, recorded exactly once` through `/// cannot reach the emit site.`; the `static` itself is line 82 and stays) → replace with:

```rust
/// The pid of the ONE true top-level `carrick` process, recorded exactly once
/// at CLI entry (`main`, before any command dispatch). Under HVPatch a run
/// never forks a host descendant, so this is a fail-closed guard, not a
/// disambiguator: a `posix_spawn`ed `__carrier-entry` carrier records its own
/// pid but dispatches to `carrier_entry`, never `Commands::Run`; and
/// `carrick trace`'s sudo re-exec replaces the pre-exec image outright, so the
/// re-exec'd process records afresh and is the only image of its pid that
/// can reach the emit site.
```

`crates/carrick-runtime/src/lib.rs:729-747` (the doc on the non-macOS `reset_after_supervisor_fork`, from `/// Reset inherited host-signal state in the runtime child after the` through `/// \`PUMP_STARTED == true\` guard and leaving a dead pump.`; the `pub fn` is line 748) → replace with:

```rust
    /// Reset the process-wide host-signal state to its pristine boot shape.
    /// No product path forks a host process any more (guest `fork` is a
    /// logical kernel-graph clone inside the carrier); the remaining callers
    /// are in-process test harnesses that boot several dispatchers in one
    /// test process and must not inherit a previous boot's pending signals,
    /// mirrored dispositions, child-exit watches or signal-pump guards.
    ///
    /// NEUTRAL vs GLUE (mirrors the HVF arm,
    /// `carrick_vmm_hvf::host_signal::reset_after_supervisor_fork`). The
    /// load-bearing clears are the platform-NEUTRAL `carrick-signal-core`
    /// state — pending / disposition / child-watch. The PUMP re-arm is KVM
    /// GLUE: it resets the pump guards (`PUMP_STARTED` / `SIGCHLD_INSTALLED` /
    /// the stale `SELF_PIPE_W`) so the next `start_signal_pump` spawns a fresh
    /// pump instead of no-opping on `PUMP_STARTED == true`.
```

`crates/carrick-runtime/src/pty_relay.rs:17-20`:
```rust
//! [`PtyRelay::stop`] terminates the thread without a signal or timeout), a
//! SIGWINCH self-pipe, and an out-of-band winsize-message fd (used when a helper
//! stayed behind in the original terminal session — see
//! [`interactive_supervisor`](crate::interactive_supervisor)). The user's real
```
→
```rust
//! [`PtyRelay::stop`] terminates the thread without a signal or timeout), a
//! SIGWINCH self-pipe, and an optional out-of-band winsize-message fd
//! (`winsize_r`; the carrier-local [`interactive_supervisor`](crate::interactive_supervisor)
//! passes none, so that fifth slot is inert in production). The user's real
```

and lines 262-264 (the doc on `start_with_pair`, which is line 265):
```rust
    /// Production entry using a pty allocated before the runtime child is
    /// forked. The interactive supervisor uses this to set the child pgrp as
    /// foreground before any relay traffic reaches the guest.
```
→
```rust
    /// Production entry over a pty the caller already allocated: the
    /// carrier-local [`InteractiveSession`](crate::interactive_supervisor::InteractiveSession)
    /// allocates the pair, starts this relay, then `dup2`s the slave over the
    /// carrier's fds 0-2 before any guest traffic flows.
```

`crates/carrick-cli/src/main.rs:204-209`:
```rust
/// One output file per process, because a cold `go build` runs ~70 of them.
/// The profiler must outlive all guest work, so `main` holds it to the end; a
/// process that `execve`s (carrick's guest-exec is a host self-re-exec) never
/// drops it and writes nothing, which is expected -- the POST-exec image is the
/// one that does the guest work and exits normally, so it is the one that
/// reports.
```
→
```rust
/// One output file per carrier process. The profiler must outlive all guest
/// work, so `main` holds it to the end; the only host re-exec left is
/// `carrick trace`'s sudo re-exec (`trace_cli`), whose pre-exec image never
/// drops it and writes nothing, which is expected -- the POST-exec image does
/// the work and reports.
```

and lines 276-281 (the comment above `supervisor_perf::record_top_level_pid();` at 282):
```rust
    // FIRST, before any dispatch or fork: record this process as the one
    // true top-level `carrick` invocation. The NATIVEPERF supervisor record
    // (supervisor_perf) is gated on this pid — interactive `-t` runs fork a
    // pty-relay supervisor and a runtime child that BOTH bubble back through
    // `Commands::Run`'s tail with `CARRICK_DSR_PROFILE` inherited, and only
    // the process recorded here may emit.
```
→
```rust
    // FIRST, before any dispatch: record this process as the one true
    // top-level `carrick` invocation. The NATIVEPERF supervisor record
    // (supervisor_perf) is gated on this pid so an image that reaches
    // `Commands::Run`'s tail without passing through `main` fails quiet.
```

`crates/carrick-cli/src/commands.rs:~1049-1052` (pre-Task-11/12 numbering; match the text):
```rust
            // share the one-true-top-level PID check: interactive `-t` runs
            // fork descendants that also reach this tail, but only the
            // Launcher has reaped the complete guest tree. Placed before every
            // exit path (interactive/json/raw) so both exports fire uniformly.
```
→
```rust
            // share the one-true-top-level PID check (see `supervisor_perf`).
            // Placed before every exit path (interactive/json/default) so both
            // exports fire uniformly.
```

- [ ] **Step 5: Green greps, rustdoc and clippy, then commit the prose**

```sh
cd /Volumes/CaseSensitive/carrick
grep -c 'libc::fork' crates/carrick-runtime/src/runtime.rs                          # expect 0
grep -c 'handle_fork' crates/carrick-runtime/src/threaded_loop.rs                   # expect 0
grep -c 'real `libc::fork` against the trap engine' crates/carrick-runtime/src/dispatch/mod.rs   # expect 0
grep -c 'bare `fork(2)`' crates/carrick-cli/src/lifecycle.rs                        # expect 0
grep -c 'fork_interactive_session' crates/carrick-cli/src/supervisor_perf.rs        # expect 0
grep -c 'interactive_supervisor::adopt_stdio' crates/carrick-runtime/src/lib.rs     # expect 0
grep -c 'before the runtime child is' crates/carrick-runtime/src/pty_relay.rs       # expect 0
grep -c 'host self-re-exec' crates/carrick-cli/src/main.rs                          # expect 0
grep -c 'interactive `-t` runs fork' crates/carrick-cli/src/main.rs                 # expect 0
grep -c 'fork descendants that also reach this tail' crates/carrick-cli/src/commands.rs   # expect 0
just fmt
just doc        # expect: no rustdoc warnings (`--document-private-items` is on, so the pub(crate)/private links resolve: finish_and_run_image, run_split_loop, run_threaded_hvf_loop, deliver_pending_signal, KernelState, DispatchOutcome::{Fork,CloneThread,Execve}, InteractiveSession)
just clippy     # expect: clean
git add crates/carrick-runtime/src/runtime.rs crates/carrick-runtime/src/threaded_loop.rs \
  crates/carrick-runtime/src/dispatch/mod.rs crates/carrick-cli/src/lifecycle.rs \
  crates/carrick-cli/src/supervisor_perf.rs crates/carrick-runtime/src/lib.rs \
  crates/carrick-runtime/src/pty_relay.rs crates/carrick-cli/src/main.rs crates/carrick-cli/src/commands.rs
git commit -F- <<'EOF'
docs(runtime): retire fork-era prose across the run lifecycle

Why: the module docs of `runtime.rs`, `threaded_loop.rs`, `dispatch/mod.rs`,
`lifecycle.rs`, `supervisor_perf.rs`, `pty_relay.rs`, the non-macOS
`host_signal` shim in `lib.rs`, and the CLI's `main.rs`/`commands.rs` still
described guest fork as `libc::fork`, `run -d` as a bare `fork(2)`, an
interactive run as a Launcher/Supervisor/runtime-child triple, and guest exec
as a host self-re-exec. Every one of those mechanisms is gone (76495a04,
af6270ce, 36d141d6; `check-carrier-only-process-invariant.py` enforces it),
and the embed design reads these docs to place Container on the kernel
graph, so they must describe the HVPatch carrier: one host process, one VM,
logical fork/clone/exec, bounded vCPU leases, `posix_spawn` of
`__carrier-entry` as the only carrier birth.

What: rewrite the `runtime.rs` module doc (loop, process/thread model,
pt_pause, placement, faults, unwind-on-exit); re-home the threaded-loop doc
that was attached to `publish_initial_frame_inventory` onto
`run_threaded_loop`; correct the `DispatchOutcome::Fork` bullet, the detach
handshake, the NATIVEPERF pid-gate rationale (RUSAGE_SELF now covers the
whole guest tree), the `reset_after_supervisor_fork` doc (test-harness
reset, no fork), the pty-relay entry docs, and the alloc-census/exec
comments. No code change.

Verified: red-first greps for each stale phrase (5/1/1/1/2/1/1/1/1/1 -> all 0),
`just doc` under `-D warnings` (all intra-doc links resolve), `just clippy`.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
```

- [ ] **Step 6: Fix the `interactive_tty` binary path and the `justfile` test comment**

`CARGO_MANIFEST_DIR` for this test is `crates/carrick-runtime`, so the current expression looks for `crates/carrick-runtime/target/release/carrick`, which never exists; every run has printed `SKIP: … not found` and tested nothing. In `crates/carrick-runtime/tests/interactive_tty.rs` replace line 24

```rust
    let bin = concat!(env!("CARGO_MANIFEST_DIR"), "/target/release/carrick");
```

with

```rust
    let bin = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/release/carrick");
```

(the same `../../` shape `crates/carrick-cli/tests/trace_profile.rs:65` already uses for `scripts/dtrace`). In the `justfile` replace lines 170-173

```make
        # NOT added: carrick-cli's `tests/cli.rs`, whose `run_elf_command_*`
        # cases execute real guests. This recipe is defined as the tests that do
        # NOT need the HVF runtime or Docker; those belong to a guest-capable
        # lane.
```

with

```make
        # NOT added: carrick-cli's `tests/` integration targets. `cli.rs` and
        # `fs_backend_flag.rs` drive the cargo-built binary via assert_cmd and
        # run no guest (adding `--test cli --test fs_backend_flag` here is a
        # follow-up; the recipe body is unchanged in this commit). The others
        # (`conformance.rs`, `perf_runner.rs`, `dsr_trace_overhead.rs`,
        # `trace_profile.rs`) shell out to the SIGNED `target/release/carrick`
        # and run real guests or dtrace. This recipe is defined as the tests
        # that do NOT need the HVF runtime or Docker; those belong to a
        # guest-capable lane (`just conformance*`,
        # `cargo test -p carrick-cli --test <name>`).
```

- [ ] **Step 7: Prove the path fix end-to-end (HVF-gated: needs the signed binary and a terminal)**

```sh
cd /Volumes/CaseSensitive/carrick
grep -c '"/target/release/carrick"' crates/carrick-runtime/tests/interactive_tty.rs        # expect 0
grep -c '"/../../target/release/carrick"' crates/carrick-runtime/tests/interactive_tty.rs  # expect 1
grep -c 'run_elf_command_' justfile                                                        # expect 0
cargo test -p carrick-runtime --test interactive_tty --no-run                              # expect: compiles
just build                                                                                 # signed target/release/carrick (Rule 0)
CARRICK_RUN_ID=a5-task13 cargo test -p carrick-runtime --test interactive_tty -- --ignored --nocapture 2>&1 | tee /private/tmp/claude-501/-Volumes-CaseSensitive-carrick/8f7faeb9-0217-4567-9ce8-8b805a8618e1/scratchpad/interactive_tty.log
grep -c 'SKIP: .*not found' /private/tmp/claude-501/-Volumes-CaseSensitive-carrick/8f7faeb9-0217-4567-9ce8-8b805a8618e1/scratchpad/interactive_tty.log   # expect 0 (before the fix this is >0 on every run)
just test          # expect: unchanged, still ok (recipe body is untouched; only its comment changed)
```

Expected: the ignored tests actually execute against `target/release/carrick` (they pull `docker.io/library/debian:stable` and `docker.io/library/alpine`; they pass, or they fail with a real guest/pty diagnosis — either way the `SKIP: … not found` line that masked them is gone). Reap with `scripts/sudo/kill.sh a5-task13` if a guest lingers.

- [ ] **Step 8: Commit**

```sh
cd /Volumes/CaseSensitive/carrick
git add crates/carrick-runtime/tests/interactive_tty.rs justfile
git commit -F- <<'EOF'
test(runtime): point interactive_tty at the workspace binary; fix test recipe comment

Why: `tests/interactive_tty.rs` built its binary path as
`concat!(env!("CARGO_MANIFEST_DIR"), "/target/release/carrick")`, i.e.
`crates/carrick-runtime/target/release/carrick`, which never exists, so the
four `run -t` smoke tests have printed `SKIP: … not found` and tested
nothing since they were written. The `justfile` `test` recipe comment
excused not running `carrick-cli/tests/cli.rs` because of its
`run_elf_command_*` cases; no such cases exist, `cli.rs` runs no guest at
all (it drives the cargo-built binary via assert_cmd), and the targets that
actually need a signed binary are the other integration files.

What: resolve `<workspace>/target/release/carrick` via `../../` from the
crate manifest dir (the shape `trace_profile.rs` already uses); rewrite the
recipe comment to name the real excluded targets, which of them need HVF,
and the lanes that run them. Recipe commands are unchanged.

Verified: the path greps (1 -> 0 old, 0 -> 1 new); the test target compiles;
after `just build`, `cargo test -p carrick-runtime --test interactive_tty --
--ignored --nocapture` no longer prints the SKIP line and drives the signed
binary; `just test` unchanged.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
```

<details><summary>Verifier problems fixed in place (20) and claims still unverified (6)</summary>

- fixed: HEAD is ea0dac4c (3dc6cc72 is 35 commits back). All quoted code blocks and most line numbers still match at HEAD; the ones that drifted are fixed below.
- fixed: Task 7 Step 1: `grep -c 'libc::_exit(125)' crates/carrick-cli/src/commands.rs` prints 2, not 1 — the module doc at commands.rs:50 names the call as well as the code at :1027. Fixed the expected count (both go away, so the green count 0 stands).
- fixed: Task 7: the remaining `forked_child_die_by_signal` call sites are `vcpu_loop/mod.rs:8525`, `vcpu_loop/signal.rs:276`, `vcpu_loop/exec.rs:871` (draft said mod.rs:8482 / exec.rs:736), and the `#[cfg(test)]` `is_forked_child: true` literal is at `vcpu_loop/mod.rs:9574` (draft said 9459). Fixed.
- fixed: Task 7 Step 7: `grep -rn 'forked_child_exit' crates/carrick-runtime/src | wc -l # expect 0` cannot reach 0 with the draft's edits: `runtime/exec.rs:1-6` module doc and the `dispatch/mod.rs:5413-5417` comment on `clear_output_buffers` still name it. Added: rewrite the exec.rs module doc; delete `SyscallDispatcher::clear_output_buffers` outright (zero callers anywhere in `crates/`, it existed only for the post-`libc::fork` child).
- fixed: Task 7: `crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs:1014-1017` documents `process_exit_cleanup` as gated by the very `is_forked_child() || is_forked_guest_process()` branch Task 7 deletes (and cites stale vcpu_loop line numbers). Added a comment fix to Step 4 and the file to the commit.
- fixed: Task 7 Step 6: the sibling comment `// resolve runs in the PARENT (no fork yet) → normal exit is safe.` at commands.rs:1012 is fork-era too; added to the same edit.
- fixed: Task 7 Step 8: `just run run … /bin/sh -c '/bin/echo hi; exit 3'` is broken — the justfile has no `set positional-arguments`, so `{{ARGS}}` is spliced as text into the recipe's shell line and the quotes vanish (`; exit 3` becomes a second shell command). Replaced with `just build` followed by a direct `./target/release/carrick run …` invocation.
- fixed: Task 8 Step 2: the green grep `grep -rn 'compat-report' docs crates/carrick-cli/src README.md | wc -l # expect 0` is false: README.md:104 lists `compat-report` as a diagnostic, docs/diagnostics-and-debugging.md:558 references a `compat-report` gap, commands.rs:42/1061 and args.rs:27/205/395 use 'compat-report envelope' wording (some are only rewritten later in Step 3), and dated records (`docs/2026-06-29-*`, `docs/superpowers/specs/*`) mention it by name. Added README.md:104 and diag:558 edits and narrowed the grep to the subcommand form (`carrick compat-report`, `compat-report --`, `Commands::CompatReport`, `CompatReportFormat`).
- fixed: Task 8 Step 2: the paragraph quoted as `docs/diagnostics-and-debugging.md:542-545` actually spans 538-545. Fixed.
- fixed: Task 8 Step 3: the `stream_stdio / --raw` comment is at `crates/carrick-runtime/src/dispatch/fs.rs:7675`, not 7648. Fixed.
- fixed: Task 8 Step 4 misses most live callers of `carrick run … --raw` outside the Rust tree; every one of them breaks once clap rejects the flag (and the after-image spellings like `run "$IMAGE" --raw --fs host` would otherwise be swallowed as the guest command): scripts/conformance/carrier-topology-gate.py:1011,1045 (driven by `just carrier-topology-gate`), scripts/conformance/bhyve-grind.sh:65, scripts/conformance/vcpu-admission-gate.sh:130, scripts/run-probe.sh:60, scripts/test-parallel-cleanup.sh:14-15, scripts/go-deadlock-capture.sh:103, scripts/go-deadlock-capture-ext.sh:80, scripts/go-conformance-image.sh:53, scripts/go-conformance.sh:200, scripts/cpython-parity.py:85, scripts/ltp-reduce.py:101, scripts/ltp-baseline.py:102, scripts/perf/native_budget.py:208, scripts/perf/native_compiler_budget.py:3310, scripts/perf/tier_d_node_reliability.py:83, scripts/perf/bisect-epoll-p50.sh:14, scripts/repro/hvpatch-thread-spawn-wedge.sh:35, .agents/skills/ltp-conformance/scripts/ltp-check.sh:57 and ltp-full-sweep.sh:82, docker/nodejs-conformance/nodejs-conformance:138 plus its dry-run assertion scripts/test-nodejs-conformance-dry-run.sh:91 (`contains "$carrick_out" "<--raw>"` would start FAILING), docker/go-conformance/Dockerfile:22, five scripts/dtrace headers (guest_stack.d:33, hvpatch-clone08-control-flow.d:29, msgstress-sysv.d:7, hvpatch-phase2-exit-census.d:26, vfork-smash-signal-injections.d:77), docs/conformance-testing.md:106,215, docs/native-dsr-dtrace-profile.md:54, docs/hvpatch-exec-authority-routing-plan.md:14, and .agents/skills/{carrick-native-debug:166, ltp-conformance:112, carrick-lldb:80}/SKILL.md. Added a Step 4b with the exact list, a run-elf-safe sed, a hunk check, and put the files in the commit.
- fixed: Task 8 Step 5: `grep -rn -e '--raw' … scripts/conformance | wc -l # expect 0` would also hit scripts/conformance/baseline.jsonl (2,064 `carrick_argv` receipts containing `--raw`, plus 9 each in baseline.kvm.jsonl / baseline.bhyve.jsonl). Those are verdict receipts (`verdict.rs:84`), not inputs — `check-matrix` does not read them and they refresh on the next `--bless` — so the draft's parenthetical '(baseline.jsonl carries no carrick_flags)' is corrected to say that, and the greps exclude `*.jsonl`.
- fixed: Task 9 Step 1: `grep -c 'libc::fork' crates/carrick-runtime/src/runtime.rs` is 6 at HEAD and 5 after Task 7 (module-doc lines 28, 42, 46, 53, 59), not 3. Fixed.
- fixed: Task 9 Step 1/5: `grep -c 'interactive `-t` runs fork' … commands.rs` prints 0, not 1 — the phrase is line-wrapped at commands.rs:1049-1050 ('runs' / '// fork descendants'). Replaced the commands.rs assertion with `fork descendants that also reach this tail`.
- fixed: Task 9 line drift: `supervisor_perf.rs` TOP_LEVEL_PID doc is 67-81 (static at 82), not 66-82; `lib.rs` `reset_after_supervisor_fork` doc is 729-747 (fn at 748), not 731-749; `pty_relay.rs` `start_with_pair` doc is 262-264 (fn at 265), not 263-265; `main.rs` record-pid comment is 276-281 (call at 282), not 278-282; `run_threaded_loop` is at threaded_loop.rs:184; the runtime.rs module doc ends at line 98 (not 99) after Task 7. Text anchors were right; numbers fixed.
- fixed: Task 9 Step 4 (supervisor_perf): the claim that `carrick trace`'s sudo re-exec 'wipes the slot and re-records … neither reaches `Commands::Run`'s emit site' is wrong in direction: `trace_cli.rs:55` replaces THIS image via `exec()`; the re-exec'd carrick is a fresh process whose own `main` records its own pid, and it is legitimately the one top-level process of that pid. Reworded so the pre-exec image is the one that never reaches the tail.
- fixed: Task 9 Step 4 (pty_relay): 'production polls four fds' — with `winsize_r = -1` the fifth `pollfd` is still built with `events = 0` (pty_relay.rs:583, 606); reworded to 'the fifth slot is inert'.
- fixed: Task 9 Step 6 (justfile comment): the replacement text claims the excluded carrick-cli `tests/` targets shell out to the signed binary, but `tests/cli.rs` and `tests/fs_backend_flag.rs` use `assert_cmd::Command::cargo_bin("carrick")` (the unsigned cargo build) and run no guest — the old comment's excuse was wrong for a second reason. Reworded to name the two groups accurately and flag adding `--test cli` as a follow-up (recipe body still unchanged).
- fixed: Noted, not added (outside every file the draft lists): `crates/carrick-dsr-aarch64/src/mapped_memory.rs:57-62` documents `NATIVE_FORKED_GUEST_CHILD` in terms of `exec_helpers::forked_child_exit` and the deleted `is_forked_guest_process` branch, and no code outside that file references the static — a follow-up deletion candidate.
- fixed: Verified as correct (no change): Task 7 tokio demotion (tokio used only at execute.rs:198 and tests/integration/oci_layout.rs:39; `just doc`/`just check` unaffected); `is_forked_guest_process` keeps a caller (dispatch/sysv.rs:2478) and `PreHostExit`/`flush_fork_child_fd` keep callers, so no dead-code fallout; Task 8 clap behaviour (`run`'s `image` positional has no `allow_hyphen_values`, so `run --raw …` fails with exit 2); OracleKey (oracle.rs:29-44) has no `carrick_flags`; `just doc` passes `--document-private-items`, so links to `pub(crate)` `KernelState`/`finish_and_run_image`/`run_split_loop` resolve; every new symbol in the rewritten runtime.rs doc exists (`vcpu_sched` = `carrick_hal::vcpu_sched`, `prepare_in_process_fork` quiesce.rs:399, `complete_persistent_process_fork` mod.rs:3314, `pt_pause` quiesce.rs:386, `deliver_fault_signal` signal.rs:221, `CloneThread`/`Execve`/`SigReturn`/`WaitOn*` variants); lifecycle claims (`CarrierLauncher::launch` :128/145, `posix_spawn` :236, `__carrier-entry` args.rs:122, `carrier_entry` :357, `run_detached_carrier` :568, `CARRICK_EXEC_OVERLAY` :588, `start` :860, `restart` :1079); `publish_initial_frame_inventory` really aborts on a rejected `apply` (threaded_loop.rs:151-158); the cited commits 76495a04 / af6270ce / 36d141d6 / ae0e3d29 / 7ab32190 / 05081274 exist with the stated subjects; `check-carrier-only-process-invariant.py` runs from `scripts/lint-domains.sh:53` inside `just lint-domains` inside `just ci`.
- UNVERIFIED: Line numbers quoted for Task 9 assume Tasks 7 and 8 have been applied first (e.g. the runtime.rs module doc ends at line 99 after Task 7 removes the 11-line `_exit` paragraph; commands.rs line numbers shift by the deleted arm/comment lines). Executors should match on the quoted text, not the numbers.
- UNVERIFIED: That `just doc` currently passes with the existing module doc's links to pub(crate)/private items (`finish_and_run_image`, `run_split_loop`) was inferred from the doc already linking them, not from running the gate; the new doc links only names the old doc already linked plus `DispatchOutcome::{Fork,CloneThread,Execve}` (pub enum variants) and `InteractiveSession` (pub struct in a pub module). If `just doc` flags `private_intra_doc_links`, drop the square brackets on the offending name.
- UNVERIFIED: Whether the non-macOS `macos_helper_stubs` import of `forked_child_exit` (vcpu_loop/mod.rs:527) was already an unused import on platform-linux builds could not be checked without a cross-platform build; removing it is safe in every case.
- UNVERIFIED: The `just conformance-quick` and `interactive_tty --ignored` verification steps require the signed HVF binary, a terminal, and the Docker oracle (two-phase); expected outcomes are stated but were not executed here (read-only brief). `interactive_tty.rs`'s header also says the tests need the debian image and Docker.
- UNVERIFIED: Counts in the red-first greps (33 `"--raw"` literals, 2127 suites.toml rows, 3 `libc::fork` mentions in runtime.rs, etc.) were measured on main at 3dc6cc72; a rebase onto later commits may shift them.
- UNVERIFIED: `git log -S` attributions: tokio assert introduced in ae0e3d29 ('fix(run): isolate tokio from fork — split Engine::resolve from execute'), `--raw` made a no-op in 7ab32190, compat-report scaffold present since 05081274 — read from `git log -S` output, not from the diffs themselves.

</details>
