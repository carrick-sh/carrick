//! Process-global typed vCPU census accounting and RAII liveness guards.
//!
//! Provides [`VcpuCensus`], which tracks live vCPU counts via an atomic counter
//! and hands out RAII [`VcpuLiveGuard`] tokens that decrement the census on drop.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

/// Typed vCPU census accounting object.
///
/// Tracks live vCPU counts via an atomic counter. Calling [`VcpuCensus::created`]
/// increments the counter and returns an RAII [`VcpuLiveGuard`], which automatically
/// decrements the live count on drop.
#[derive(Clone, Debug)]
pub struct VcpuCensus {
    live: Arc<AtomicU64>,
}

impl VcpuCensus {
    /// Construct a new empty census.
    pub fn new() -> Self {
        Self {
            live: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Return the process-global vCPU census.
    pub fn global() -> &'static Self {
        static GLOBAL_CENSUS: OnceLock<VcpuCensus> = OnceLock::new();
        GLOBAL_CENSUS.get_or_init(Self::new)
    }

    /// Record a newly created vCPU, incrementing the live count and returning
    /// an RAII guard that decrements the count on drop.
    pub fn created(&self) -> VcpuLiveGuard {
        self.live.fetch_add(1, Ordering::SeqCst);
        VcpuLiveGuard {
            live: Arc::clone(&self.live),
        }
    }

    /// Current number of live vCPUs.
    pub fn live(&self) -> u64 {
        self.live.load(Ordering::SeqCst)
    }

    /// Reset the census counter to a specific value.
    pub fn reset(&self, count: u64) {
        self.live.store(count, Ordering::SeqCst);
    }
}

impl Default for VcpuCensus {
    fn default() -> Self {
        Self::new()
    }
}

/// An RAII guard representing a live vCPU. Decrements the census on drop.
#[derive(Debug)]
pub struct VcpuLiveGuard {
    live: Arc<AtomicU64>,
}

impl Drop for VcpuLiveGuard {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Return the process-global vCPU census.
pub fn global() -> &'static VcpuCensus {
    VcpuCensus::global()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vcpu_census_created_and_drop_lifecycle() {
        let census = VcpuCensus::new();
        assert_eq!(census.live(), 0);

        let g1 = census.created();
        assert_eq!(census.live(), 1);

        let g2 = census.created();
        assert_eq!(census.live(), 2);

        drop(g1);
        assert_eq!(census.live(), 1);

        drop(g2);
        assert_eq!(census.live(), 0);
    }

    #[test]
    fn vcpu_census_reset() {
        let census = VcpuCensus::new();
        let _g = census.created();
        assert_eq!(census.live(), 1);

        census.reset(10);
        assert_eq!(census.live(), 10);
    }
}
