//! Process-local private-JIT epoch ownership and translator reset statistics.
//!
//! This module used to own the H004 direct-binding cell sidecar: per-unit
//! zeroed cell blocks, `ADRP`/`ADD`-relocated stubs, cold-exit eligibility
//! classification, descriptor leases, and the fork/exec cell-clearing walks.
//! All of it existed because immutable translation units could not take
//! per-process direct-link patches. The native-tap unit format removed that
//! premise: installed unit blocks replay through `publish_emitted` and take
//! patched direct links at their trusted entries exactly like native blocks
//! (`docs/perf-results/2026-08-03-store-template-parity-mechanism.md`), so
//! the sidecar and its registry are deleted. What remains is the private JIT
//! epoch token the exec-reset seam validates, and the typed statistics the
//! runtime's fork/exec diagnostics consume.

use std::sync::Arc;
use std::time::Duration;

/// Process-owner token for one append-only private JIT address epoch.
#[derive(Debug)]
pub struct PrivateJitEpoch {
    _private: (),
}

impl PrivateJitEpoch {
    /// Creates the sole process-owner reference for a new private JIT epoch.
    pub fn process_owner() -> Arc<Self> {
        Arc::new(Self { _private: () })
    }

    /// Reports descriptor leases in addition to the process-owner reference.
    pub fn live_descriptor_leases(process_owner: &Arc<Self>) -> usize {
        Arc::strong_count(process_owner).saturating_sub(1)
    }
}

/// Sparse child-side repair statistics for inherited translator state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ForkBindingClearStats {
    pub cells_cleared: u64,
    pub pages_touched: u64,
    pub duration: Duration,
}

/// Whole-image translator teardown statistics for exec diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExecBindingClearStats {
    pub cells_cleared: u64,
    pub pages_touched: u64,
    pub descriptors_dropped: u64,
    pub units_dropped: u64,
    pub duration: Duration,
}
