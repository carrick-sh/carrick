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

#[derive(Clone, Copy, Debug, Default)]
pub struct WaiterDebugCounts {
    pub count: u32,
    pub requeue_wake: u32,
    pub requeue_count: u32,
    pub logical_requeued: u32,
    pub logical_wake: u32,
    pub self_woken: u32,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod imp {
    use super::WaiterDebugCounts;
    use std::ffi::c_void;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

    /// Cross-process, physical-page-keyed synchronization (the SHARED flag).
    /// Value confirmed from `<os/os_sync_wait_on_address.h>`.
    const OS_SYNC_WAIT_ON_ADDRESS_SHARED: u32 = 0x0000_0001;
    const OS_SYNC_WAKE_BY_ADDRESS_SHARED: u32 = 0x0000_0001;
    /// `os_clockid_t` for the deadline clock (`<os/clock.h>`,
    /// `OS_CLOCK_MACH_ABSOLUTE_TIME = 32`).
    const OS_CLOCK_MACH_ABSOLUTE_TIME: u32 = 32;
    /// 32-bit futex word.
    const FUTEX_WORD_SIZE: libc::size_t = 4;
    const WAITER_SLOTS: usize = 8192;

    #[repr(C)]
    struct WaiterSlot {
        key: AtomicU64,
        count: AtomicU32,
        requeue_wake: AtomicU32,
        requeue_count: AtomicU32,
        requeue_to_host: AtomicU64,
        requeue_to_key: AtomicU64,
        requeue_to_value: AtomicU32,
        logical_requeued: AtomicU32,
        logical_wake: AtomicU32,
        /// Physical wakes whose `count` decrement the WAKER already performed
        /// (`note_logical_dequeues`): the woken waiter settles one credit on
        /// exit instead of decrementing `count` again. Keeps `count`
        /// synchronous with the kernel queue — Linux's FUTEX_WAKE return
        /// value counts dequeues AT WAKE TIME, while a woken-but-not-yet-
        /// rescheduled waiter's own bookkeeping lags by its reschedule
        /// latency (unbounded under load; probe futexforkrequeue counted 431
        /// "waiters" on a queue holding 200).
        wake_credits: AtomicU32,
        /// Waiters that left the wait WOKEN without a waker's credit — the
        /// slice loop's value re-check or an os_sync at-entry mismatch. On
        /// Linux they would still be queued until a FUTEX_WAKE dequeued and
        /// counted them, so they stay claimable by the next wake (see
        /// `settle_waiter_exit` / `wake_counted`).
        self_woken: AtomicU32,
    }

    #[link(name = "System")]
    unsafe extern "C" {
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

    fn waiter_table() -> Option<&'static [WaiterSlot]> {
        static CELL: OnceLock<usize> = OnceLock::new();
        let base = *CELL.get_or_init(|| {
            let bytes = WAITER_SLOTS.saturating_mul(std::mem::size_of::<WaiterSlot>());
            if bytes == 0 {
                return 0;
            }
            // SAFETY: a fresh anonymous shared mapping owned for process lifetime.
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    bytes,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_ANON | libc::MAP_SHARED,
                    -1,
                    0,
                )
            };
            if p == libc::MAP_FAILED { 0 } else { p as usize }
        });
        if base == 0 {
            return None;
        }
        // SAFETY: `base` points at WAITER_SLOTS zeroed WaiterSlot values for the
        // process lifetime; MAP_SHARED makes them coherent across fork.
        Some(unsafe { std::slice::from_raw_parts(base as *const WaiterSlot, WAITER_SLOTS) })
    }

    fn waiter_slot(host_addr: usize) -> Option<&'static WaiterSlot> {
        let key = host_addr as u64;
        if key == 0 {
            return None;
        }
        let table = waiter_table()?;
        let mut idx = (key as usize >> 2) & (WAITER_SLOTS - 1);
        for _ in 0..WAITER_SLOTS {
            let slot = &table[idx];
            let seen = slot.key.load(Ordering::Acquire);
            if seen == key {
                return Some(slot);
            }
            if seen == 0
                && slot
                    .key
                    .compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                return Some(slot);
            }
            idx = (idx + 1) & (WAITER_SLOTS - 1);
        }
        None
    }

    fn waiter_count(host_addr: usize) -> u32 {
        waiter_slot(host_addr)
            .map(|slot| slot.count.load(Ordering::Acquire))
            .unwrap_or(0)
    }

    pub fn waiter_debug_counts(waiter_key: usize) -> WaiterDebugCounts {
        let Some(slot) = waiter_slot(waiter_key) else {
            return WaiterDebugCounts::default();
        };
        WaiterDebugCounts {
            count: slot.count.load(Ordering::Acquire),
            requeue_wake: slot.requeue_wake.load(Ordering::Acquire),
            requeue_count: slot.requeue_count.load(Ordering::Acquire),
            logical_requeued: slot.logical_requeued.load(Ordering::Acquire),
            logical_wake: slot.logical_wake.load(Ordering::Acquire),
            self_woken: slot.self_woken.load(Ordering::Acquire),
        }
    }

    fn consume_one(counter: &AtomicU32) -> bool {
        let mut cur = counter.load(Ordering::Acquire);
        while cur != 0 {
            match counter.compare_exchange_weak(cur, cur - 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return true,
                Err(next) => cur = next,
            }
        }
        false
    }

    fn add_logical_requeued(waiter_key: usize, count: u32) {
        if count == 0 {
            return;
        }
        if let Some(slot) = waiter_slot(waiter_key) {
            slot.logical_requeued.fetch_add(count, Ordering::AcqRel);
        }
    }

    fn reserve_logical_wakes(waiter_key: usize, count: u32) {
        if count == 0 {
            return;
        }
        if let Some(slot) = waiter_slot(waiter_key) {
            slot.logical_wake.fetch_add(count, Ordering::AcqRel);
        }
    }

    pub fn preinit_waiter_table() -> bool {
        waiter_table().is_some()
    }

    pub fn waiter_enter(host_addr: usize) {
        if let Some(slot) = waiter_slot(host_addr) {
            slot.count.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// An exiting waiter settles ONE accounting unit: the credit its waker
    /// pre-paid (`note_logical_dequeues`) when present, else its own `count`
    /// entry. A no-credit exit that was nonetheless WOKEN left the queue on
    /// its own (the ≤20 ms slice loop's value re-check, or an os_sync
    /// at-entry value mismatch) — on Linux that waiter would STAY QUEUED
    /// until a FUTEX_WAKE dequeued (and counted) it, so its unit moves to
    /// the claimable `self_woken` pool for the next wake's count instead of
    /// vanishing (probe futexforkrequeue under load: the guest stores
    /// word0=1, a waiter self-wakes on the re-check before the guest's
    /// FUTEX_WAKE lands, and the wake reported 199 of Linux's exact 200). A
    /// timeout/EINTR exit left the queue on Linux too, so its unit is
    /// dropped. A racing waiter that self-settled before its waker's
    /// transfer landed leaves `count` transiently low plus one stale credit,
    /// which the NEXT exit consumes — bounded and self-repairing, unlike the
    /// unbounded reschedule-latency lag of pure self-accounting.
    fn settle_waiter_exit(slot: &WaiterSlot, woken: bool) {
        if consume_one(&slot.wake_credits) {
            return;
        }
        if consume_one(&slot.count) && woken {
            slot.self_woken.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// Transfer `n` dequeued waiters' accounting to the WAKER: decrement
    /// `count` now — Linux dequeues under the futex bucket lock at wake time,
    /// so its FUTEX_WAKE return value never re-counts an already-woken waiter
    /// — and leave `n` credits for the woken waiters' [`settle_waiter_exit`].
    /// The claim is LOGICAL: `count` is the queue Linux would dequeue from,
    /// and the os_sync wakes issued afterwards are best-effort hints (a
    /// waiter between its ≤20 ms wait slices is physically missed but still
    /// logically dequeued; it returns through its slice loop and settles the
    /// credit). Count-first/credit-second ordering: the failure mode of the
    /// opposite order is a permanently-high `count` (a racing waiter consumes
    /// the credit AND the waker still decrements), while this order's worst
    /// transient self-repairs on the next exit.
    fn note_logical_dequeues(slot: &WaiterSlot, n: u32) {
        for _ in 0..n {
            let _ = consume_one(&slot.count);
        }
        if n > 0 {
            slot.wake_credits.fetch_add(n, Ordering::AcqRel);
        }
    }

    /// `woken` is the guest-visible outcome of the wait this exit closes
    /// (`true` for FUTEX_WAIT returning 0 — physical wake or value re-check;
    /// `false` for ETIMEDOUT/EINTR): it selects whether a no-credit unit
    /// stays claimable (see [`settle_waiter_exit`]).
    pub fn waiter_exit(host_addr: usize, woken: bool) {
        if let Some(slot) = waiter_slot(host_addr) {
            settle_waiter_exit(slot, woken);
        }
    }

    pub fn requeued_waiter_enter(waiter_key: usize) -> bool {
        let Some(slot) = waiter_slot(waiter_key) else {
            return false;
        };
        if consume_one(&slot.logical_wake) {
            let _ = consume_one(&slot.logical_requeued);
            return true;
        }
        slot.count.fetch_add(1, Ordering::AcqRel);
        if consume_one(&slot.logical_wake) {
            let _ = consume_one(&slot.count);
            let _ = consume_one(&slot.logical_requeued);
            return true;
        }
        false
    }

    pub fn requeued_waiter_complete(waiter_key: usize) -> bool {
        let Some(slot) = waiter_slot(waiter_key) else {
            return false;
        };
        if consume_one(&slot.logical_wake) {
            // Requeued-waiter completion is by definition waker-initiated
            // (the logical-wake credit) — never a claimable self-wake.
            settle_waiter_exit(slot, false);
            let _ = consume_one(&slot.logical_requeued);
            return true;
        }
        false
    }

    pub fn requeued_waiter_exit(waiter_key: usize, _host_addr: usize, _value: u32) -> bool {
        let Some(slot) = waiter_slot(waiter_key) else {
            return true;
        };
        let had_credit = consume_one(&slot.logical_wake);
        // Destination-side exits keep the simpler drop semantics: the
        // logical_requeued/logical_wake machinery already covers in-flight
        // requeued waiters, and layering self_woken on top risks
        // double-claims (a requeue after a value change is inherently racy).
        settle_waiter_exit(slot, false);
        if had_credit {
            let _ = consume_one(&slot.logical_requeued);
            true
        } else {
            false
        }
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
        if rc < 0 { neg_errno() } else { rc as i64 }
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
        if rc < 0 { neg_errno() } else { rc as i64 }
    }

    /// Wake up to `n` waiters and return a Linux-style waiter count. Darwin's
    /// os_sync wake calls report success/failure, not the number of waiters
    /// released, so carrick counts waiters in a fork-shared side table while
    /// they are parked in `wait`.
    pub fn wake_counted(host_addr: usize, waiter_key: usize, n: u32) -> i64 {
        if n == 0 {
            return 0;
        }
        let Some(slot) = waiter_slot(waiter_key) else {
            return 0;
        };
        let parked = slot.count.load(Ordering::Acquire);
        let self_woken = slot.self_woken.load(Ordering::Acquire);
        let logical = slot.logical_requeued.load(Ordering::Acquire);
        let target = parked.saturating_add(self_woken).max(logical).min(n);
        if target == 0 {
            return 0;
        }
        // Claim self-woken units FIRST: those waiters already returned via
        // the value re-check (Linux would dequeue them from the bucket right
        // here), so they need neither a credit nor a physical wake — they
        // only need counting.
        let mut self_claim = 0u32;
        while self_claim < target.min(self_woken) && consume_one(&slot.self_woken) {
            self_claim += 1;
        }
        let physical_target = parked.min(target - self_claim);
        // Logical dequeue next (claim-then-wake: a woken waiter must always
        // find its credit already reserved), then best-effort os_sync hints.
        note_logical_dequeues(slot, physical_target);
        issue_physical_wakes(host_addr, physical_target, parked);
        let logical_woke = target.min(logical);
        reserve_logical_wakes(waiter_key, logical_woke);
        i64::from((self_claim + physical_target).max(logical_woke))
    }

    /// Best-effort os_sync wake hints for up to `target` of `parked` waiters.
    /// Return codes are deliberately NOT fed back into the count: a waiter
    /// between its ≤20 ms wait slices yields ENOENT here yet is still
    /// logically dequeued (see `note_logical_dequeues`), returning through
    /// its slice loop.
    fn issue_physical_wakes(host_addr: usize, target: u32, parked: u32) {
        if target == 0 {
            return;
        }
        if target == 1 {
            let _ = wake(host_addr, false);
        } else if target >= parked {
            let _ = wake(host_addr, true);
        } else {
            for _ in 0..target {
                if wake(host_addr, false) < 0 {
                    break;
                }
            }
        }
    }

    fn wake_physical_counted(host_addr: usize, waiter_key: usize, n: u32) -> i64 {
        if n == 0 {
            return 0;
        }
        let Some(slot) = waiter_slot(waiter_key) else {
            return 0;
        };
        let parked = slot.count.load(Ordering::Acquire);
        if parked == 0 {
            return 0;
        }
        let target = parked.min(n);
        note_logical_dequeues(slot, target);
        issue_physical_wakes(host_addr, target, parked);
        i64::from(target)
    }

    pub fn requeue_counted(
        from_host_addr: usize,
        from_waiter_key: usize,
        to_host_addr: usize,
        to_waiter_key: usize,
        wake_count: u32,
        requeue_count: u32,
    ) -> (u32, u32) {
        let parked = waiter_count(from_waiter_key);
        if parked == 0 {
            return (0, 0);
        }
        let total = parked.min(wake_count.saturating_add(requeue_count));
        let wake_actual = wake_count.min(total);
        let requeue_actual = requeue_count.min(total.saturating_sub(wake_actual));
        if let Some(slot) = waiter_slot(from_waiter_key) {
            let to_value = unsafe { (*(to_host_addr as *const AtomicU32)).load(Ordering::SeqCst) };
            slot.requeue_to_host
                .store(to_host_addr as u64, Ordering::Release);
            slot.requeue_to_key
                .store(to_waiter_key as u64, Ordering::Release);
            slot.requeue_to_value.store(to_value, Ordering::Release);
            slot.requeue_wake.store(wake_actual, Ordering::Release);
            slot.requeue_count.store(requeue_actual, Ordering::Release);
        }
        let woke = wake_physical_counted(from_host_addr, from_waiter_key, total).max(0) as u32;
        let wake_done = wake_actual.min(woke);
        let requeue_done = requeue_actual.min(woke.saturating_sub(wake_done));
        if requeue_done != 0 {
            add_logical_requeued(to_waiter_key, requeue_done);
        }
        (wake_done, requeue_done)
    }

    pub fn take_requeue(waiter_key: usize) -> Option<(usize, usize, u32)> {
        let slot = waiter_slot(waiter_key)?;
        let mut wake = slot.requeue_wake.load(Ordering::Acquire);
        while wake != 0 {
            match slot.requeue_wake.compare_exchange_weak(
                wake,
                wake - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return None,
                Err(next) => wake = next,
            }
        }

        let mut requeue = slot.requeue_count.load(Ordering::Acquire);
        while requeue != 0 {
            match slot.requeue_count.compare_exchange_weak(
                requeue,
                requeue - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    let host = slot.requeue_to_host.load(Ordering::Acquire) as usize;
                    let key = slot.requeue_to_key.load(Ordering::Acquire) as usize;
                    let value = slot.requeue_to_value.load(Ordering::Acquire);
                    return (host != 0 && key != 0).then_some((host, key, value));
                }
                Err(next) => requeue = next,
            }
        }
        None
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
mod imp {
    use super::WaiterDebugCounts;

    pub fn wait(_host_addr: usize, _value: u32, _timeout_us: u32) -> i64 {
        -(libc::ENOSYS as i64)
    }
    pub fn wake(_host_addr: usize, _all: bool) -> i64 {
        -(libc::ENOSYS as i64)
    }
    pub fn wake_counted(_host_addr: usize, _waiter_key: usize, _n: u32) -> i64 {
        -(libc::ENOSYS as i64)
    }
    pub fn waiter_debug_counts(_waiter_key: usize) -> WaiterDebugCounts {
        WaiterDebugCounts::default()
    }
    pub fn requeue_counted(
        _from_host_addr: usize,
        _from_waiter_key: usize,
        _to_host_addr: usize,
        _to_waiter_key: usize,
        _wake_count: u32,
        _requeue_count: u32,
    ) -> (u32, u32) {
        (0, 0)
    }
    pub fn take_requeue(_waiter_key: usize) -> Option<(usize, usize, u32)> {
        None
    }
    pub fn preinit_waiter_table() -> bool {
        true
    }
    pub fn waiter_enter(_host_addr: usize) {}
    pub fn waiter_exit(_host_addr: usize, _woken: bool) {}
    pub fn requeued_waiter_enter(_host_addr: usize) -> bool {
        false
    }
    pub fn requeued_waiter_complete(_host_addr: usize) -> bool {
        false
    }
    pub fn requeued_waiter_exit(_waiter_key: usize, _host_addr: usize, _value: u32) -> bool {
        true
    }
}

pub use imp::{
    preinit_waiter_table, requeue_counted, requeued_waiter_complete, requeued_waiter_enter,
    requeued_waiter_exit, take_requeue, wait, waiter_debug_counts, waiter_enter, waiter_exit, wake,
    wake_counted,
};

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod tests {
    use super::{wait, wake};
    use std::sync::atomic::AtomicU32;

    #[test]
    fn wait_times_out_with_etimedout() {
        let word = AtomicU32::new(7);
        let addr = &word as *const AtomicU32 as usize;
        // Value matches (7), so we block; 10ms timeout -> -ETIMEDOUT.
        let rc = wait(addr, 7, 10_000);
        assert_eq!(
            rc,
            -(libc::ETIMEDOUT as i64),
            "expected -ETIMEDOUT, got {rc}"
        );
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
        assert!(
            rc < 0,
            "wake with no waiters should report an error, got {rc}"
        );
    }

    /// Linux's FUTEX_WAKE return value counts waiters dequeued from the
    /// KERNEL queue at wake time. carrick counts via the fork-shared side
    /// table, which the WOKEN waiter used to decrement ITSELF on resume — so
    /// a woken-but-not-yet-rescheduled waiter (descheduled under load) stayed
    /// counted, and a subsequent wake re-counted it. Probe futexforkrequeue:
    /// `wake_original_count=431` with exactly 200 waiters actually remaining
    /// (the requeue's 800 physically-woken waiters lingering in word0's
    /// count). The waker must transfer the decrement at physical-wake time,
    /// leaving a credit the woken waiter settles instead of re-decrementing.
    #[test]
    fn wake_counted_excludes_woken_but_unexited_waiters() {
        use super::{waiter_debug_counts, waiter_enter, waiter_exit, wake_counted};
        use std::time::{Duration, Instant};
        static WORD: AtomicU32 = AtomicU32::new(0);
        let addr = &WORD as *const AtomicU32 as usize;
        let mut joins = Vec::new();
        for _ in 0..3 {
            joins.push(std::thread::spawn(move || {
                waiter_enter(addr);
                let woken = wait(addr, 0, 15_000_000) >= 0; // 15s cap; woken below
                // A woken waiter that the scheduler has not run yet: its own
                // bookkeeping (wait_end) lags the wake by the reschedule
                // latency — the load-coupled window this test freezes open.
                std::thread::sleep(Duration::from_secs(2));
                waiter_exit(addr, woken);
            }));
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while waiter_debug_counts(addr).count < 3 {
            assert!(Instant::now() < deadline, "waiters never registered");
            std::thread::yield_now();
        }
        // Registration precedes the kernel park; retry (bounded) until two
        // waiters have actually blocked in os_sync and been woken. Each
        // successful wake happens strictly before the woken thread's
        // waiter_exit (it sleeps 2s first), so the lag window stays open.
        let mut woke_direct = 0i64;
        while woke_direct < 2 {
            assert!(Instant::now() < deadline, "never woke 2 waiters");
            woke_direct += wake_counted(addr, addr, (2 - woke_direct) as u32).max(0);
            if woke_direct < 2 {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        assert_eq!(woke_direct, 2);
        // Exactly ONE waiter remains in the kernel queue; the two just-woken
        // (still sleeping before their wait_end) must not be re-counted.
        // Bounded retry only for the remaining waiter's own park latency — a
        // single wake report must never exceed the 1 real waiter.
        let mut woke_rest = 0i64;
        while woke_rest == 0 {
            assert!(Instant::now() < deadline, "never woke the last waiter");
            woke_rest = wake_counted(addr, addr, u32::MAX).max(0);
            if woke_rest == 0 {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        assert_eq!(
            woke_rest, 1,
            "woken-but-unexited waiters re-counted by a subsequent wake"
        );
        for j in joins {
            j.join().expect("join waiter");
        }
    }

    /// A waiter that exits WOKEN without a waker credit left via the slice
    /// loop's value re-check (carrick's lost-wake recovery). Linux has no
    /// such exit: that waiter stays queued until a FUTEX_WAKE dequeues and
    /// COUNTS it. So the unit must stay claimable by the next wake — probe
    /// futexforkrequeue under load: the guest stores word0=1, one of the 200
    /// remaining waiters self-wakes on its ≤20 ms re-check before the guest's
    /// FUTEX_WAKE lands, and the wake reported 199 instead of Linux's exact
    /// 200. A timeout/EINTR exit left the queue on Linux too and must NOT be
    /// claimable.
    #[test]
    fn wake_counts_self_woken_waiters_exactly_once() {
        use super::{waiter_enter, waiter_exit, wake_counted};
        static WORD3: AtomicU32 = AtomicU32::new(0);
        let addr = &WORD3 as *const AtomicU32 as usize;

        // Self-woken exit (value re-check): claimable exactly once.
        waiter_enter(addr);
        waiter_exit(addr, true);
        assert_eq!(
            wake_counted(addr, addr, u32::MAX),
            1,
            "a self-woken waiter must be counted by the next wake"
        );
        assert_eq!(
            wake_counted(addr, addr, u32::MAX),
            0,
            "a self-woken waiter must be claimable exactly once"
        );

        // Timeout/EINTR exit: gone from the queue on Linux too — never
        // claimable.
        waiter_enter(addr);
        waiter_exit(addr, false);
        assert_eq!(
            wake_counted(addr, addr, u32::MAX),
            0,
            "a timed-out waiter must not be counted by a later wake"
        );
    }
}
