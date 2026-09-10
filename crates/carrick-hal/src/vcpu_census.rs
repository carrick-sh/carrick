//! Typed vCPU census accounting and admission leases.
//!
//! Provides [`VcpuCensus`], which tracks live vCPU counts against a ceiling
//! and hands out RAII [`VcpuLease`] tokens that decrement the census on drop.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

/// Admission was refused because the census ceiling has been reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionRefused {
    pub current: usize,
    pub ceiling: usize,
}

impl fmt::Display for AdmissionRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "vCPU admission refused: current count {} reached ceiling {}",
            self.current, self.ceiling
        )
    }
}

impl std::error::Error for AdmissionRefused {}

#[derive(Debug)]
struct CensusInner {
    live: AtomicI64,
    ceiling: usize,
}

/// Typed vCPU census accounting object.
///
/// Owns an atomic live counter and enforces a ceiling on admissions.
/// Calling [`VcpuCensus::admit`] returns an RAII [`VcpuLease`], which automatically
/// decrements the live count on drop.
#[derive(Clone, Debug)]
pub struct VcpuCensus {
    inner: Arc<CensusInner>,
    keyed_leases: Arc<Mutex<BTreeMap<u64, VcpuLease>>>,
}

impl VcpuCensus {
    /// Construct a new census with the given ceiling.
    pub fn new(ceiling: usize) -> Self {
        Self {
            inner: Arc::new(CensusInner {
                live: AtomicI64::new(0),
                ceiling,
            }),
            keyed_leases: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Construct an unbounded census (`ceiling = usize::MAX`).
    pub fn unbounded() -> Self {
        Self::new(usize::MAX)
    }

    /// Current number of live vCPUs.
    pub fn live(&self) -> i64 {
        self.inner.live.load(Ordering::SeqCst)
    }

    /// The configured ceiling.
    pub fn ceiling(&self) -> usize {
        self.inner.ceiling
    }

    /// Admit one vCPU lease.
    ///
    /// Atomically verifies that the current live count is below `ceiling` and
    /// increments it. Returns `Ok(VcpuLease)` on success or `Err(AdmissionRefused)`
    /// if the ceiling is reached.
    pub fn admit(&self) -> Result<VcpuLease, AdmissionRefused> {
        let mut current = self.inner.live.load(Ordering::SeqCst);
        loop {
            if current < 0 || (current as usize) >= self.inner.ceiling {
                return Err(AdmissionRefused {
                    current: current.max(0) as usize,
                    ceiling: self.inner.ceiling,
                });
            }
            match self.inner.live.compare_exchange_weak(
                current,
                current + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    return Ok(VcpuLease {
                        inner: Arc::clone(&self.inner),
                        disarmed: false,
                    });
                }
                Err(actual) => current = actual,
            }
        }
    }

    /// Adopt an existing admitted lease slot without incrementing the live count.
    pub fn adopt_lease(&self) -> VcpuLease {
        VcpuLease {
            inner: Arc::clone(&self.inner),
            disarmed: false,
        }
    }

    /// Reset the census counter to a specific value.
    pub fn reset(&self, count: i64) {
        self.inner.live.store(count, Ordering::SeqCst);
    }

    /// Store an admitted lease under an ID (e.g. vCPU ID).
    pub fn store_lease(&self, id: u64, lease: VcpuLease) {
        let mut leases = self.keyed_leases.lock().unwrap_or_else(|e| e.into_inner());
        leases.insert(id, lease);
    }

    /// Remove and drop a previously stored lease by ID, releasing it back to the census.
    pub fn remove_lease(&self, id: u64) -> bool {
        let mut leases = self.keyed_leases.lock().unwrap_or_else(|e| e.into_inner());
        leases.remove(&id).is_some()
    }
}

impl Default for VcpuCensus {
    fn default() -> Self {
        Self::unbounded()
    }
}

/// An RAII lease representing an admitted live vCPU.
#[derive(Debug)]
pub struct VcpuLease {
    inner: Arc<CensusInner>,
    disarmed: bool,
}

impl VcpuLease {
    /// Disarm this lease so dropping it does not decrement the census.
    pub fn disarm(mut self) {
        self.disarmed = true;
    }
}

impl Drop for VcpuLease {
    fn drop(&mut self) {
        if !self.disarmed {
            self.inner.live.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

static GLOBAL_CENSUS: OnceLock<VcpuCensus> = OnceLock::new();

/// Return the process-global vCPU census.
pub fn global() -> &'static VcpuCensus {
    GLOBAL_CENSUS.get_or_init(VcpuCensus::unbounded)
}

/// Install the process-global vCPU census.
pub fn install_global(census: VcpuCensus) {
    let _ = GLOBAL_CENSUS.set(census);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vcpu_census_admit_and_release_lifecycle() {
        let census = VcpuCensus::new(3);
        assert_eq!(census.live(), 0);
        assert_eq!(census.ceiling(), 3);

        let lease1 = match census.admit() {
            Ok(l) => l,
            Err(e) => panic!("admit 1 should succeed, got {e}"),
        };
        assert_eq!(census.live(), 1);

        let lease2 = match census.admit() {
            Ok(l) => l,
            Err(e) => panic!("admit 2 should succeed, got {e}"),
        };
        assert_eq!(census.live(), 2);

        let lease3 = match census.admit() {
            Ok(l) => l,
            Err(e) => panic!("admit 3 should succeed, got {e}"),
        };
        assert_eq!(census.live(), 3);

        // One more must be refused
        let err = match census.admit() {
            Ok(_) => panic!("admit 4 should be refused"),
            Err(e) => e,
        };
        assert_eq!(
            err,
            AdmissionRefused {
                current: 3,
                ceiling: 3
            }
        );
        assert_eq!(census.live(), 3);

        // Dropping a lease re-admits
        drop(lease2);
        assert_eq!(census.live(), 2);

        let lease4 = match census.admit() {
            Ok(l) => l,
            Err(e) => panic!("re-admit after drop should succeed, got {e}"),
        };
        assert_eq!(census.live(), 3);

        // Ceiling reached again
        assert!(census.admit().is_err());

        drop(lease1);
        drop(lease3);
        drop(lease4);
        assert_eq!(census.live(), 0);
    }

    #[test]
    fn vcpu_census_disarm_and_adopt_lease() {
        let census = VcpuCensus::new(2);
        let lease1 = match census.admit() {
            Ok(l) => l,
            Err(e) => panic!("admit 1 should succeed: {e}"),
        };
        assert_eq!(census.live(), 1);

        // Adopt a lease (transfer without increment)
        let adopted = census.adopt_lease();
        assert_eq!(census.live(), 1);

        // Disarm original lease so its drop does not decrement
        lease1.disarm();
        assert_eq!(census.live(), 1);

        // Dropping adopted lease decrements
        drop(adopted);
        assert_eq!(census.live(), 0);
    }

    #[test]
    fn vcpu_census_reset_and_unbounded() {
        let census = VcpuCensus::unbounded();
        assert_eq!(census.ceiling(), usize::MAX);
        let lease = match census.admit() {
            Ok(l) => l,
            Err(e) => panic!("admit should succeed: {e}"),
        };
        assert_eq!(census.live(), 1);
        census.reset(10);
        assert_eq!(census.live(), 10);
        drop(lease);
        assert_eq!(census.live(), 9);
    }

    #[test]
    fn vcpu_census_keyed_lease_store_and_remove() {
        let census = VcpuCensus::new(4);
        let lease1 = match census.admit() {
            Ok(l) => l,
            Err(e) => panic!("admit 1 failed: {e}"),
        };
        let lease2 = match census.admit() {
            Ok(l) => l,
            Err(e) => panic!("admit 2 failed: {e}"),
        };
        assert_eq!(census.live(), 2);

        census.store_lease(100, lease1);
        census.store_lease(200, lease2);
        assert_eq!(census.live(), 2);

        // Removing by ID drops the lease and decrements the census
        assert!(census.remove_lease(100));
        assert_eq!(census.live(), 1);

        // Removing non-existent ID returns false and does not alter live count
        assert!(!census.remove_lease(100));
        assert_eq!(census.live(), 1);

        assert!(census.remove_lease(200));
        assert_eq!(census.live(), 0);
    }
}
