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

    pub fn waiter_exit(host_addr: usize) {
        if let Some(slot) = waiter_slot(host_addr) {
            let _ = consume_one(&slot.count);
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
            let _ = consume_one(&slot.count);
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
        let _ = consume_one(&slot.count);
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
        let logical = slot.logical_requeued.load(Ordering::Acquire);
        let target = parked.max(logical).min(n);
        if target == 0 {
            return 0;
        }
        let physical_target = parked.min(target);
        let physical_woke = if physical_target == 0 {
            0
        } else if physical_target == 1 {
            if wake(host_addr, false) >= 0 { 1 } else { 0 }
        } else if physical_target >= parked {
            if wake(host_addr, true) >= 0 {
                physical_target
            } else {
                0
            }
        } else {
            let mut woke = 0u32;
            for _ in 0..physical_target {
                if wake(host_addr, false) < 0 {
                    break;
                }
                woke += 1;
            }
            woke
        };
        let logical_woke = target.min(logical);
        reserve_logical_wakes(waiter_key, logical_woke);
        i64::from(physical_woke.max(logical_woke))
    }

    fn wake_physical_counted(host_addr: usize, waiter_key: usize, n: u32) -> i64 {
        if n == 0 {
            return 0;
        }
        let parked = waiter_count(waiter_key);
        if parked == 0 {
            return 0;
        }
        let target = parked.min(n);
        if target == 1 {
            return if wake(host_addr, false) >= 0 { 1 } else { 0 };
        }
        if n >= parked {
            return if wake(host_addr, true) >= 0 {
                i64::from(target)
            } else {
                0
            };
        }
        let mut woke = 0i64;
        for _ in 0..target {
            if wake(host_addr, false) < 0 {
                break;
            }
            woke += 1;
        }
        woke
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
    pub fn waiter_exit(_host_addr: usize) {}
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
}
