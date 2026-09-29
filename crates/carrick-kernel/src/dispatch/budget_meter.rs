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
        }
    });
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
