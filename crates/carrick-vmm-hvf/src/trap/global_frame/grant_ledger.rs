//! Grant accounting is a leaf lock, never an execution venue for fork custody.
//!
//! Only this module can obtain its guard. ForkStock receives an accounting
//! handle, not a guard; its commit, Abort, failed Reserve, reclaim and teardown
//! retain their shared ownership semantics and can destroy physical custody
//! without holding accounting. Directory -> receipt -> ledger is the order.
//! The sole non-leaf operation is exact terminal receipt publication below:
//! it consumes the existing neutral terminal verdict, never ForkStock custody.

use super::{
    CarrierVmCustody, El1FrameGrantMm, El1FrameGrantReceipt, El1FrameGrantScope,
    El1FrameGrantStats, GlobalFrameHostOwner, TrapError, finalize_terminal_stage2_record_using,
};

#[derive(Debug, Default)]
pub(crate) struct El1FrameGrantLedger {
    state: parking_lot::Mutex<LedgerState>,
}

impl El1FrameGrantLedger {
    pub(crate) fn mark_grant(
        &self,
        base: u64,
        length: u64,
        mm: El1FrameGrantMm,
    ) -> Result<(), TrapError> {
        self.state.lock().mark_grant(base, length, mm)
    }

    pub(crate) fn mark_return(
        &self,
        base: u64,
        length: u64,
        mm: El1FrameGrantMm,
        release_ipa: bool,
    ) {
        self.state.lock().mark_return(base, length, mm, release_ipa);
    }

    pub(crate) fn snapshot(&self) -> El1FrameGrantStats {
        self.state.lock().stats.clone()
    }

    pub(crate) fn snapshot_mm(&self, mm: El1FrameGrantMm) -> Option<El1FrameGrantStats> {
        self.state.lock().by_mm.get(&mm).cloned()
    }

    pub(super) fn snapshots_by_mm(&self) -> Vec<El1FrameGrantStats> {
        self.state.lock().by_mm.values().cloned().collect()
    }

    pub(super) fn backing_released(
        &self,
        mm: El1FrameGrantMm,
        length: u64,
        returned: bool,
        pooled: bool,
    ) {
        self.state.lock().update(mm, |stats| {
            if !returned {
                stats.complete = false;
            }
            let counter = if pooled {
                &mut stats.pooled_reusable_bytes
            } else {
                &mut stats.host_backing_released_bytes
            };
            add_grant_counter(counter, &mut stats.complete, length);
        });
    }

    /// Keep exact return publication serialized with regrant after IPA release.
    /// This private operation takes a terminal owner identity, never arbitrary
    /// caller code or physical-retention values. The backend release callback
    /// is the existing stage-2 test seam, not a ledger-access callback.
    pub(super) fn finalize_return(
        &self,
        custody: &CarrierVmCustody,
        owner: &GlobalFrameHostOwner,
        receipt: &mut El1FrameGrantReceipt,
        release_ipa_fn: &mut dyn FnMut(u64, u64) -> Result<(), TrapError>,
    ) -> Result<(), TrapError> {
        let mut state = self.state.lock();
        let snapshot = owner.snapshot();
        let release_ipa = snapshot.is_some_and(|snapshot| snapshot.release_ipa);
        finalize_terminal_stage2_record_using(custody, owner.record_identity, release_ipa_fn)?;
        if !receipt.returned {
            state.mark_return(receipt.base, receipt.length, receipt.mm, release_ipa);
            receipt.returned = true;
        }
        Ok(())
    }
}

impl carrick_hal::fork_stock::ForkTableLedger for &El1FrameGrantLedger {
    fn grant(
        &mut self,
        page: carrick_guest_arch::RootGpa,
        mm: carrick_el1_abi::ReservationMm,
    ) -> bool {
        El1FrameGrantMm::new(mm.raw())
            .is_some_and(|mm| self.mark_grant(page.address().raw(), 4096, mm).is_ok())
    }
    fn give_back(&mut self, page: carrick_guest_arch::RootGpa, mm: carrick_el1_abi::ReservationMm) {
        if let Some(mm) = El1FrameGrantMm::new(mm.raw()) {
            self.mark_return(page.address().raw(), 4096, mm, false);
        }
    }
}

#[derive(::core::fmt::Debug)]
struct LedgerState {
    active: std::collections::BTreeSet<(u64, u64)>,
    returned: std::collections::BTreeSet<(u64, u64)>,
    stats: El1FrameGrantStats,
    by_mm: std::collections::BTreeMap<El1FrameGrantMm, El1FrameGrantStats>,
}

impl Default for LedgerState {
    fn default() -> Self {
        Self {
            active: Default::default(),
            returned: Default::default(),
            by_mm: Default::default(),
            stats: El1FrameGrantStats {
                scope: Some(El1FrameGrantScope(std::sync::Arc::new(()))),
                complete: true,
                ..Default::default()
            },
        }
    }
}

fn add_grant_counter(counter: &mut u64, complete: &mut bool, amount: u64) {
    match counter.checked_add(amount) {
        Some(value) => *counter = value,
        None => {
            *complete = false;
            *counter = u64::MAX;
        }
    }
}

impl LedgerState {
    fn mark_grant(&mut self, base: u64, length: u64, mm: El1FrameGrantMm) -> Result<(), TrapError> {
        if length == 0
            || !base.is_multiple_of(4096)
            || !length.is_multiple_of(4096)
            || base.checked_add(length).is_none()
        {
            return Err(TrapError::Hypervisor(format!(
                "EL1 frame grant has an invalid physical extent: base=0x{base:x} length=0x{length:x}"
            )));
        }
        let key = (base, length);
        if self.active.contains(&key) {
            return Err(TrapError::Hypervisor(format!(
                "EL1 frame regrant precedes exact return: base=0x{base:x} length=0x{length:x}"
            )));
        }
        self.active.insert(key);
        let reused = self.returned.contains(&key);
        self.update(mm, |stats| {
            add_grant_counter(&mut stats.grants_succeeded, &mut stats.complete, 1);
            add_grant_counter(&mut stats.bytes_granted, &mut stats.complete, length);
            if reused {
                add_grant_counter(&mut stats.reused_grants, &mut stats.complete, 1);
            }
        });
        Ok(())
    }

    fn update(&mut self, mm: El1FrameGrantMm, mut update: impl FnMut(&mut El1FrameGrantStats)) {
        let scoped = self.by_mm.entry(mm).or_insert_with(|| El1FrameGrantStats {
            scope: self.stats.scope.clone(),
            mm: Some(mm),
            complete: true,
            ..Default::default()
        });
        update(scoped);
        update(&mut self.stats);
    }

    fn mark_return(&mut self, base: u64, length: u64, mm: El1FrameGrantMm, release_ipa: bool) {
        if self.active.remove(&(base, length)) {
            self.returned.insert((base, length));
            self.update(mm, |stats| {
                add_grant_counter(&mut stats.returns_completed, &mut stats.complete, 1);
                add_grant_counter(&mut stats.bytes_returned, &mut stats.complete, length);
                if release_ipa {
                    add_grant_counter(&mut stats.ipa_bytes_returned, &mut stats.complete, length);
                }
            });
        } else {
            self.update(mm, |stats| stats.complete = false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{El1FrameGrantMm, LedgerState};
    #[test]
    fn overflow_marks_accounting_incomplete() {
        let mut state = LedgerState::default();
        state.stats.bytes_granted = u64::MAX;
        state
            .mark_grant(0x8000_0000, 0x4000, El1FrameGrantMm::new(1).unwrap())
            .unwrap();
        assert!(!state.stats.complete);
        assert_eq!(state.stats.retained_backing_bytes(), None);
    }
}
