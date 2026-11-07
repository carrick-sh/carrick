//! SpinLock for in-guest synchronization.

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

pub struct SpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

// SAFETY: acquiring the atomic lock is the only way to access the data;
// ownership of the protected value may move between guest CPUs when T: Send.
unsafe impl<T: Send> Sync for SpinLock<T> {}
// SAFETY: moving a lock transfers its exclusively owned data when T: Send.
unsafe impl<T: Send> Send for SpinLock<T> {}

pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

/// A spinlock held with local interrupts masked until the lock is released.
/// Field order is intentional: Rust drops `lock` before `irq`.
pub struct IrqSpinGuard<'a, T> {
    lock: SpinLockGuard<'a, T>,
    _irq: crate::substrate::sched::hw::IrqGuard,
}

impl<T> SpinLock<T> {
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    #[cfg(any(test, feature = "host-test"))]
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        self.locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| SpinLockGuard { lock: self })
    }

    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        while self.locked.swap(true, Ordering::Acquire) {
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
        SpinLockGuard { lock: self }
    }

    pub fn lock_irqsave(&self) -> IrqSpinGuard<'_, T> {
        let irq = crate::substrate::sched::hw::disable_irq_save();
        let lock = self.lock();
        IrqSpinGuard { lock, _irq: irq }
    }
}

impl<T> Deref for IrqSpinGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.lock
    }
}

impl<T> DerefMut for IrqSpinGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.lock
    }
}

impl<T> Deref for SpinLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        // SAFETY: this guard owns the exclusive lock until Drop releases it.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: this guard owns the exclusive lock and &mut self is unique.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spinlock_mutual_exclusion() {
        let lock = SpinLock::new(42);
        {
            let mut guard = lock.lock();
            assert_eq!(*guard, 42);
            *guard = 100;
        }
        {
            let guard = lock.lock();
            assert_eq!(*guard, 100);
        }
    }
}
