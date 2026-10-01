//! Deterministic per-call budget meter for VM-free kernel tests.
//!
//! Counts locks taken, heap allocations, fd-table lookups, authority checks,
//! and host syscalls during an operation window on the current thread.

use std::cell::Cell;

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetSnapshot {
    pub table_read_locks: u64,
    pub table_write_locks: u64,
    pub table_lookups: u64,
    pub authority_checks: u64,
    pub host_reads: u64,
    pub host_writes: u64,
    pub host_closes: u64,
    pub host_syscalls: u64,
    pub allocations: u64,
    pub allocated_bytes: u64,
}

thread_local! {
    static ACTIVE_SNAPSHOT: Cell<Option<BudgetSnapshot>> = const { Cell::new(None) };
    #[cfg(target_os = "macos")]
    static FIRST_ALLOCATION_TRACE: Cell<Option<AllocationTrace>> = const { Cell::new(None) };
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
struct AllocationTrace {
    frames: [*mut libc::c_void; 64],
    len: libc::c_int,
}

#[cfg(target_os = "macos")]
impl AllocationTrace {
    const fn empty() -> Self {
        Self {
            frames: [std::ptr::null_mut(); 64],
            len: 0,
        }
    }
}

#[inline]
#[allow(dead_code)]
pub fn is_active() -> bool {
    ACTIVE_SNAPSHOT.with(|cell| cell.get().is_some())
}

#[inline]
pub fn record_table_read_lock() {
    ACTIVE_SNAPSHOT.with(|cell| {
        if let Some(mut s) = cell.get() {
            s.table_read_locks = s.table_read_locks.saturating_add(1);
            cell.set(Some(s));
        }
    });
}

#[inline]
pub fn record_table_write_lock() {
    ACTIVE_SNAPSHOT.with(|cell| {
        if let Some(mut s) = cell.get() {
            s.table_write_locks = s.table_write_locks.saturating_add(1);
            cell.set(Some(s));
        }
    });
}

#[inline]
pub fn record_table_lookup() {
    ACTIVE_SNAPSHOT.with(|cell| {
        if let Some(mut s) = cell.get() {
            s.table_lookups = s.table_lookups.saturating_add(1);
            cell.set(Some(s));
        }
    });
}

#[inline]
pub fn record_authority_check() {
    ACTIVE_SNAPSHOT.with(|cell| {
        if let Some(mut s) = cell.get() {
            s.authority_checks = s.authority_checks.saturating_add(1);
            cell.set(Some(s));
        }
    });
}

#[inline]
pub fn record_host_read() {
    ACTIVE_SNAPSHOT.with(|cell| {
        if let Some(mut s) = cell.get() {
            s.host_reads = s.host_reads.saturating_add(1);
            s.host_syscalls = s.host_syscalls.saturating_add(1);
            cell.set(Some(s));
        }
    });
}

#[inline]
pub fn record_host_write() {
    ACTIVE_SNAPSHOT.with(|cell| {
        if let Some(mut s) = cell.get() {
            s.host_writes = s.host_writes.saturating_add(1);
            s.host_syscalls = s.host_syscalls.saturating_add(1);
            cell.set(Some(s));
        }
    });
}

#[inline]
pub fn record_host_close() {
    ACTIVE_SNAPSHOT.with(|cell| {
        if let Some(mut s) = cell.get() {
            s.host_closes = s.host_closes.saturating_add(1);
            s.host_syscalls = s.host_syscalls.saturating_add(1);
            cell.set(Some(s));
        }
    });
}

#[inline]
pub fn record_allocation(bytes: usize) {
    let _ = ACTIVE_SNAPSHOT.try_with(|cell| {
        if let Some(mut s) = cell.get() {
            s.allocations = s.allocations.saturating_add(1);
            s.allocated_bytes = s.allocated_bytes.saturating_add(bytes as u64);
            cell.set(Some(s));
            #[cfg(target_os = "macos")]
            if s.allocations == 1 {
                let _ = FIRST_ALLOCATION_TRACE.try_with(|trace| {
                    if let Some(mut first) = trace.get() {
                        // SAFETY: the fixed array has room for all 64 frames.
                        // libc unwinding does not call the Rust allocator.
                        first.len = unsafe { libc::backtrace(first.frames.as_mut_ptr(), 64) };
                        trace.set(Some(first));
                    }
                });
            }
        }
    });
}

/// Measure a zero-allocation operation, retaining its first allocating stack
/// on macOS. Unwinding uses fixed TLS storage; symbolization happens only after
/// the measurement window closes, and only on a failed budget.
pub fn measure_no_allocations<T>(f: impl FnOnce() -> T) -> (T, BudgetSnapshot) {
    #[cfg(target_os = "macos")]
    FIRST_ALLOCATION_TRACE.with(|trace| trace.set(Some(AllocationTrace::empty())));
    struct ResetTrace;
    impl Drop for ResetTrace {
        fn drop(&mut self) {
            #[cfg(target_os = "macos")]
            FIRST_ALLOCATION_TRACE.with(|trace| trace.set(None));
        }
    }
    let _reset = ResetTrace;
    let result = measure(f);
    #[cfg(target_os = "macos")]
    if result.1.allocations != 0 {
        FIRST_ALLOCATION_TRACE.with(|trace| {
            if let Some(first) = trace.get() {
                // SAFETY: backtrace initialized exactly `len` frame entries;
                // stderr is the test harness's diagnostic stream.
                unsafe { libc::backtrace_symbols_fd(first.frames.as_ptr(), first.len, 2) };
            }
        });
    }
    assert_eq!(
        result.1.allocations, 0,
        "allocations budget exceeded: got {} ({} bytes), expected 0",
        result.1.allocations, result.1.allocated_bytes
    );
    result
}

pub fn measure<T>(f: impl FnOnce() -> T) -> (T, BudgetSnapshot) {
    ACTIVE_SNAPSHOT.with(|cell| cell.set(Some(BudgetSnapshot::default())));
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ACTIVE_SNAPSHOT.with(|cell| cell.set(None));
        }
    }
    let _reset = Reset;
    let res = f();
    let snapshot = ACTIVE_SNAPSHOT.with(|cell| cell.get()).unwrap_or_default();
    (res, snapshot)
}

#[test]
fn concurrent_thread_allocation_is_not_counted() {
    use std::sync::Barrier;
    let start = Barrier::new(2);
    let finish = Barrier::new(2);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            // Initialize this thread's barrier parking state before measuring.
            start.wait();
            finish.wait();
            start.wait();
            let allocation = std::hint::black_box(vec![0u8; 44]);
            finish.wait();
            allocation
        });
        start.wait();
        finish.wait();
        let ((), snapshot) = measure(|| {
            start.wait();
            finish.wait();
        });
        assert_eq!(snapshot.allocations, 0);
        assert_eq!(snapshot.allocated_bytes, 0);
        assert_eq!(worker.join().unwrap().len(), 44);
    });
}

#[test]
fn same_thread_allocation_is_counted() {
    let (allocation, snapshot) = measure(|| std::hint::black_box(vec![0u8; 44]));
    assert_eq!(snapshot.allocations, 1);
    assert_eq!(snapshot.allocated_bytes, 44);
    assert_eq!(allocation.len(), 44);
}

#[test]
#[should_panic(expected = "allocations budget exceeded: got 1 (44 bytes), expected 0")]
fn zero_allocation_measurement_rejects_an_allocation() {
    measure_no_allocations(|| std::hint::black_box(vec![0u8; 44]));
}
