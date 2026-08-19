//! Runtime lock-order validator to prevent hierarchy inversions and ABBA deadlocks.
//!
//! # Hierarchy (outermost to innermost)
//!
//! 1. `PtPause` (Page table pause)
//! 2. `HostAlias` (Host alias / memory transactions)
//! 3. `FdTable` (FD table & open descriptions)
//! 4. `FsState` (Filesystem overlay state)
//! 5. `PtyTable` (PTY registry)
//! 6. `Proc` (Process registry & identity)
//! 7. `SysV` (SysV IPC state)
//! 8. `Signal` (Signal registry)
//! 9. `ThreadRegistry` (Thread registry)
//!
//! Acquiring a lock at level `N` while holding a lock at level `>= N` is a
//! hierarchy violation.

use std::cell::Cell;

#[allow(dead_code)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LockLevel {
    PtPause = 0,
    HostAlias = 1,
    FdTable = 2,
    FsState = 3,
    PtyTable = 4,
    Proc = 5,
    SysV = 6,
    Signal = 7,
    ThreadRegistry = 8,
}

thread_local! {
    static HELD_LOCKS: Cell<u16> = const { Cell::new(0) };
}

#[allow(dead_code)]
#[must_use = "lock guard must be held while the underlying lock is active"]
pub struct LockOrderGuard {
    level: LockLevel,
}

#[allow(dead_code)]
impl LockOrderGuard {
    /// Asserts that no lock at level >= `level` is held by the current thread,
    /// then marks `level` as held. In release builds without debug assertions,
    /// this compiles away to zero cost.
    #[inline]
    pub fn acquire(level: LockLevel) -> Self {
        #[cfg(debug_assertions)]
        {
            let bit = 1u16 << (level as u8);
            let held = HELD_LOCKS.with(|h| h.get());
            // Check if any lock at level >= requested level is already held
            let mask_higher_or_equal = !((1u16 << (level as u8)) - 1);
            let violations = held & mask_higher_or_equal;
            assert!(
                violations == 0,
                "Lock order hierarchy violation: attempting to acquire {:?} (level {}) while holding mask {:#06b}",
                level,
                level as u8,
                held
            );
            HELD_LOCKS.with(|h| h.set(held | bit));
        }
        Self { level }
    }
}

impl Drop for LockOrderGuard {
    #[inline]
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        {
            let bit = 1u16 << (self.level as u8);
            HELD_LOCKS.with(|h| {
                let held = h.get();
                h.set(held & !bit);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order_acquisitions_succeed() {
        let _g1 = LockOrderGuard::acquire(LockLevel::PtPause);
        let _g2 = LockOrderGuard::acquire(LockLevel::HostAlias);
        let _g3 = LockOrderGuard::acquire(LockLevel::FdTable);
        let _g4 = LockOrderGuard::acquire(LockLevel::Proc);
        let _g5 = LockOrderGuard::acquire(LockLevel::SysV);
    }

    #[test]
    #[should_panic(expected = "Lock order hierarchy violation")]
    fn out_of_order_acquisition_panics() {
        let _g1 = LockOrderGuard::acquire(LockLevel::SysV);
        let _g2 = LockOrderGuard::acquire(LockLevel::Proc); // Proc < SysV -> violation!
    }

    #[test]
    #[should_panic(expected = "Lock order hierarchy violation")]
    fn reentrant_acquisition_panics() {
        let _g1 = LockOrderGuard::acquire(LockLevel::Proc);
        let _g2 = LockOrderGuard::acquire(LockLevel::Proc); // Same level -> violation!
    }
}
