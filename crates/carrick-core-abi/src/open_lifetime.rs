//! One terminal decision for a host reference group and owned ring references.

use core::sync::atomic::{AtomicU64, Ordering};

const HOST: u64 = 1 << 31;
const COUNT: u64 = HOST - 1;

/// Atomic 64-bit word backing [`OpenLifetime`].
///
/// Implemented for [`core::sync::atomic::AtomicU64`] in production and for
/// Loom's `AtomicU64` under `#[cfg(all(test, feature = "loom"))]` in test
/// crates so Loom models exercise the real [`OpenLifetime`] state machine
/// without affecting `--all-features` builds.
pub trait OpenLifetimeAtomic {
    fn load(&self, order: Ordering) -> u64;
    fn compare_exchange(
        &self,
        current: u64,
        new: u64,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64>;
}

impl OpenLifetimeAtomic for AtomicU64 {
    #[inline]
    fn load(&self, order: Ordering) -> u64 {
        AtomicU64::load(self, order)
    }

    #[inline]
    fn compare_exchange(
        &self,
        current: u64,
        new: u64,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64> {
        AtomicU64::compare_exchange(self, current, new, success, failure)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenReferenceKey {
    pub handle: u32,
    pub incarnation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenRelease {
    Live,
    Terminal,
    Stale,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenReferenceWork {
    pub cas_attempts: u64,
}

/// Generation and population change in one CAS, including terminal admission.
/// A zero population cannot be resurrected. Generation exhaustion refuses.
#[repr(transparent)]
#[derive(Debug, Default)]
pub struct OpenLifetime<A = AtomicU64>(A);

impl OpenLifetime<AtomicU64> {
    pub const fn new() -> Self {
        Self(AtomicU64::new(0))
    }
}

impl<A: OpenLifetimeAtomic> OpenLifetime<A> {
    pub const fn from_atomic(atomic: A) -> Self {
        Self(atomic)
    }
    /// Caller exclusively owns an unpublished or retired record.
    pub fn initialize(&self, incarnation: u64, host: bool) -> bool {
        let Ok(generation) = u32::try_from(incarnation) else {
            return false;
        };
        if generation == 0 {
            return false;
        }
        let old = self.0.load(Ordering::Acquire);
        if old & (HOST | COUNT) != 0 || incarnation <= old >> 32 {
            return false;
        }
        self.0
            .compare_exchange(
                old,
                (u64::from(generation) << 32) | if host { HOST } else { 1 },
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
    /// # Safety
    /// Admission has published no root, fd view, or owned ring reference.
    pub unsafe fn abort_admission(&self, incarnation: u64) {
        let terminal = incarnation << 32;
        assert!(
            self.0
                .compare_exchange(
                    terminal | HOST,
                    terminal,
                    Ordering::AcqRel,
                    Ordering::Acquire
                )
                .is_ok()
                || self.0.load(Ordering::Acquire) == terminal
        );
    }
    fn update(&self, incarnation: u64, f: impl Fn(u64) -> Option<u64>) -> OpenRelease {
        self.update_observed(incarnation, f, |_| {})
    }
    fn update_observed(
        &self,
        incarnation: u64,
        f: impl Fn(u64) -> Option<u64>,
        mut observe: impl FnMut(OpenReferenceWork),
    ) -> OpenRelease {
        let mut work = OpenReferenceWork { cas_attempts: 0 };
        let mut old = self.0.load(Ordering::Acquire);
        loop {
            if old >> 32 != incarnation || old & (HOST | COUNT) == 0 {
                observe(work);
                return OpenRelease::Stale;
            }
            let Some(low) = f(old & (HOST | COUNT)) else {
                observe(work);
                return OpenRelease::Stale;
            };
            work.cas_attempts += 1;
            let new = (old & !(HOST | COUNT)) | low;
            match self
                .0
                .compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    observe(work);
                    return if low == 0 {
                        OpenRelease::Terminal
                    } else {
                        OpenRelease::Live
                    };
                }
                Err(actual) => old = actual,
            }
        }
    }
    pub fn retain(&self, incarnation: u64) -> bool {
        self.update(incarnation, |low| (low & COUNT < COUNT).then_some(low + 1))
            == OpenRelease::Live
    }
    pub fn release(&self, incarnation: u64) -> OpenRelease {
        self.release_observed(incarnation, |_| {})
    }
    pub fn release_observed(
        &self,
        incarnation: u64,
        observe: impl FnMut(OpenReferenceWork),
    ) -> OpenRelease {
        self.update_observed(
            incarnation,
            |low| (low & COUNT != 0).then_some(low - 1),
            observe,
        )
    }
    pub fn release_host(&self, incarnation: u64) -> OpenRelease {
        self.update(incarnation, |low| (low & HOST != 0).then_some(low & !HOST))
    }
    pub fn is_terminal(&self, incarnation: u64) -> bool {
        self.0.load(Ordering::Acquire) == incarnation.checked_shl(32).unwrap_or(0)
            && incarnation != 0
            && incarnation <= u64::from(u32::MAX)
    }
    pub fn ring_references(&self, incarnation: u64) -> Option<u32> {
        let state = self.0.load(Ordering::Acquire);
        (state >> 32 == incarnation).then_some((state & COUNT) as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_open_lifetime_rejects_replay_and_generation_reuse() {
        let lifetime = OpenLifetime::new();
        assert!(!lifetime.initialize(0, true));
        assert!(!lifetime.initialize(u64::from(u32::MAX) + 1, true));
        assert!(lifetime.initialize(7, true));
        assert!(lifetime.retain(7));
        assert!(!lifetime.initialize(8, true));
        assert!(!lifetime.retain(8));
        assert_eq!(lifetime.release_host(7), OpenRelease::Live);
        assert_eq!(lifetime.release_host(7), OpenRelease::Stale);
        assert_eq!(lifetime.release(8), OpenRelease::Stale);
        assert_eq!(lifetime.release(7), OpenRelease::Terminal);
        assert_eq!(lifetime.release(7), OpenRelease::Stale);
        assert!(!lifetime.retain(7));
        assert!(!lifetime.initialize(7, false));
        assert!(lifetime.initialize(8, false));
        assert_eq!(lifetime.release(7), OpenRelease::Stale);
        assert_eq!(lifetime.release(8), OpenRelease::Terminal);
    }
}
