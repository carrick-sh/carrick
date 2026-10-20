//! Process-local backing custody for signal locks across a real host fork.
//!
//! Published backings live until process exit: a loaded reference or a copied
//! mutex queue must never become dangling. Each child transition retains one
//! old backing; each parent/failed fork frees its unused prepared replacement.
//! There is no per-event allocation. Active carrier launch uses re-exec and
//! guest HVPatch fork does not use this host-fork transfer.

use std::mem::ManuallyDrop;
use std::sync::atomic::{AtomicPtr, Ordering};

/// One process-local backing, replaced only by the sole surviving fork child.
/// `T` includes the lock and the data/queue whose lifetime it protects.
pub struct ForkResetBacking<T: Send + Sync + 'static> {
    current: AtomicPtr<T>,
}

impl<T: Send + Sync + 'static> ForkResetBacking<T> {
    pub fn new(backing: T) -> Self {
        Self {
            current: AtomicPtr::new(Box::into_raw(Box::new(backing))),
        }
    }

    pub fn get(&self) -> &T {
        let backing = self.current.load(Ordering::SeqCst);
        // SAFETY: construction and child transfer publish non-null boxed T's.
        // Published backings are never freed, including when this handle drops.
        unsafe { &*backing }
    }

    /// Allocate before acquiring ANY locks in the caller's fork bundle.
    pub fn prepare(&'static self, fresh: T) -> PreparedForkBacking<T> {
        PreparedForkBacking {
            backing: self,
            fresh: Box::new(fresh),
        }
    }
}

/// A clean allocation not yet holding the current backing's lock.
pub struct PreparedForkBacking<T: Send + Sync + 'static> {
    backing: &'static ForkResetBacking<T>,
    fresh: Box<T>,
}

impl<T: Send + Sync + 'static> PreparedForkBacking<T> {
    /// Acquire the current backing. The guard must be dropped immediately in
    /// both fork branches, before any child-side use of this authority.
    pub fn hold<G>(self, lock: impl FnOnce(&'static T) -> G) -> ForkBackingGuard<T, G> {
        let guard = lock(self.backing.get());
        ForkBackingGuard {
            backing: self.backing,
            // SAFETY: getpid has no pointer or initialization preconditions.
            owner_pid: unsafe { libc::getpid() },
            guard: ManuallyDrop::new(guard),
            fresh: ManuallyDrop::new(self.fresh),
        }
    }
}

/// Parent unlocks normally; child abandons the copied held lock AND its queue.
/// No allocator, destructor or mutex operation runs in the child branch.
pub struct ForkBackingGuard<T: Send + Sync + 'static, G> {
    backing: &'static ForkResetBacking<T>,
    owner_pid: libc::pid_t,
    guard: ManuallyDrop<G>,
    fresh: ManuallyDrop<Box<T>>,
}

impl<T: Send + Sync + 'static, G> ForkBackingGuard<T, G> {
    pub fn guard_mut(&mut self) -> &mut G {
        &mut self.guard
    }
}

impl<T: Send + Sync + 'static, G> Drop for ForkBackingGuard<T, G> {
    fn drop(&mut self) {
        // SAFETY: getpid has no pointer or initialization preconditions.
        if unsafe { libc::getpid() } == self.owner_pid {
            // SAFETY: these owned values are dropped exactly once, in order.
            unsafe {
                ManuallyDrop::drop(&mut self.guard);
                ManuallyDrop::drop(&mut self.fresh);
            }
        } else {
            // SAFETY: the fork child is single-threaded and this owned guard is
            // dropped once. Do not unlock/destroy copied std or parking_lot
            // mutex state: either may retain vanished parent waiters.
            let fresh = unsafe { ManuallyDrop::take(&mut self.fresh) };
            self.backing
                .current
                .store(Box::into_raw(fresh), Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn parent_and_failed_fork_release_current_and_dispose_unused_backing() {
        use std::sync::{Arc, atomic::AtomicUsize};
        struct DropWitness(Arc<AtomicUsize>);
        impl Drop for DropWitness {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let drops = Arc::new(AtomicUsize::new(0));
        let fresh = |value| Mutex::new((value, DropWitness(Arc::clone(&drops))));
        let backing = Box::leak(Box::new(ForkResetBacking::new(fresh(7))));
        let original = backing.get() as *const _;
        // Aborted before lock acquisition; no transfer was admitted.
        drop(backing.prepare(fresh(8)));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        for expected_drops in 2..=3 {
            // Parent success and failed-fork use the same branch.
            let hold = backing.prepare(fresh(9)).hold(|lock| lock.lock().unwrap());
            assert!(matches!(
                backing.get().try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ));
            drop(hold);
            assert_eq!(backing.get().lock().unwrap().0, 7);
            assert_eq!(backing.get() as *const _, original);
            assert_eq!(drops.load(Ordering::SeqCst), expected_drops);
        }
    }

    #[test]
    fn child_transfer_branch_abandons_held_mutex_and_publishes_clean_backing() {
        let backing = Box::leak(Box::new(ForkResetBacking::new(Mutex::new(7))));
        let old = backing.get();
        let mut hold = backing
            .prepare(Mutex::new(0))
            .hold(|lock| lock.lock().unwrap());
        // Exercise the actual child Drop branch without an OS fork. This
        // private fixture has no peers. It cannot prove platform fork safety
        // or copied contended queue behavior; the HVF artifact test must do so.
        hold.owner_pid = -1;
        drop(hold);
        assert!(matches!(
            old.try_lock(),
            Err(std::sync::TryLockError::WouldBlock)
        ));
        assert_ne!(backing.get() as *const _, old as *const _);
        assert_eq!(*backing.get().lock().unwrap(), 0);
    }
}
