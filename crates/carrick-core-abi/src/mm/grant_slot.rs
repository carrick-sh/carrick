//! An EL1-authorized lazy window and an isolated descriptor submission. The
//! ordinary descriptor drain cannot publish this grant before root revalidation.

use carrick_mmu_core::aarch64::descriptor_txn::{
    DescriptorReceipt, DescriptorTxn, DescriptorTxnSlot,
};

use core::sync::atomic::{AtomicU64, Ordering};

use super::{El1MmHandle, PortalGrantWindow, PortalOwnerWait, PortalWaitCause, ReservationMm};
#[repr(C, align(64))]
pub struct PortalGrantSlot {
    state: AtomicU64,
    window: [AtomicU64; 13],
    fault_generation: AtomicU64,
    descriptor: DescriptorTxnSlot,
}
impl Default for PortalGrantSlot {
    fn default() -> Self {
        Self::new()
    }
}
impl PortalGrantSlot {
    pub const fn new() -> Self {
        Self {
            state: AtomicU64::new(0),
            window: [const { AtomicU64::new(0) }; 13],
            fault_generation: AtomicU64::new(0),
            descriptor: DescriptorTxnSlot::new(),
        }
    }
    pub fn publish_fault_selection(
        &self,
        request_generation: u64,
        window: PortalGrantWindow,
    ) -> bool {
        if request_generation == 0 || !window.valid() {
            return false;
        }
        let mut current = self.state.load(Ordering::Acquire);
        loop {
            if current != 0 && current != 3 && current != 4 {
                return false;
            }
            match self
                .state
                .compare_exchange_weak(current, 1, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        for (word, value) in self.window.iter().zip(window.words()) {
            word.store(value, Ordering::Relaxed);
        }
        self.fault_generation
            .store(request_generation, Ordering::Relaxed);
        self.state.store(3, Ordering::Release);
        true
    }
    /// A busy owner resource has a producer; carry its exact pre-probe
    /// revision across the EL1 exit instead of falling through host sparse.
    pub fn publish_fault_wait(&self, fault_va: u64, wait: PortalOwnerWait) -> bool {
        let mut current = self.state.load(Ordering::Acquire);
        loop {
            if current != 0 && current != 3 && current != 4 {
                return false;
            }
            match self
                .state
                .compare_exchange_weak(current, 1, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        let values = [
            wait.handle().carrier().get(),
            wait.handle().mm().raw(),
            wait.handle().incarnation().get(),
            wait.cause().encode(),
            wait.revision(),
            fault_va & !4095,
        ];
        for (word, value) in self.window.iter().zip(values) {
            word.store(value, Ordering::Relaxed);
        }
        self.state.store(4, Ordering::Release);
        true
    }
    pub fn take_fault_wait(&self, mm_key: u64, fault_va: u64) -> Option<PortalOwnerWait> {
        if self.state.load(Ordering::Acquire) != 4 {
            return None;
        }
        let values: [u64; 6] = core::array::from_fn(|i| self.window[i].load(Ordering::Relaxed));
        if values[1] != mm_key || values[5] != fault_va & !4095 {
            return None;
        }
        let carrier = core::num::NonZeroU64::new(values[0])?;
        let mm = ReservationMm::new(values[1])?;
        let incarnation = core::num::NonZeroU64::new(values[2])?;
        let cause = PortalWaitCause::decode(values[3])?;
        if self
            .state
            .compare_exchange(4, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return None;
        }
        // SAFETY: publication accepts an owner-issued wait sampled from the
        // exact live source before its failed resource probe.
        Some(unsafe {
            PortalOwnerWait::from_owner(
                El1MmHandle::from_admitted_owner(carrier, mm, incarnation),
                cause,
                values[4],
            )
        })
    }
    pub fn fault_selection(
        &self,
        mm_key: u64,
        request_generation: u64,
    ) -> Option<PortalGrantWindow> {
        if self.state.load(Ordering::Acquire) != 3
            || self.fault_generation.load(Ordering::Relaxed) != request_generation
        {
            return None;
        }
        let window = PortalGrantWindow::decode(core::array::from_fn(|i| {
            self.window[i].load(Ordering::Relaxed)
        }))?;
        (window.operation.mm.raw() == mm_key).then_some(window)
    }
    pub fn pending_fault_selection(
        &self,
        mm_key: u64,
        fault_va: u64,
    ) -> Option<(u64, PortalGrantWindow)> {
        if self.state.load(Ordering::Acquire) != 3 {
            return None;
        }
        let generation = self.fault_generation.load(Ordering::Relaxed);
        let window = self.fault_selection(mm_key, generation)?;
        (window.fault_page == fault_va & !4095).then_some((generation, window))
    }
    pub fn cancel_fault_selection(
        &self,
        window: PortalGrantWindow,
        request_generation: u64,
    ) -> bool {
        if self.fault_selection(window.operation.mm.raw(), request_generation) != Some(window) {
            return false;
        }
        self.state
            .compare_exchange(3, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
    pub fn cancel_fault_for_page(&self, mm_key: u64, fault_page: u64) -> bool {
        let state = self.state.load(Ordering::Acquire);
        let fault_page = fault_page & !4095;
        if state == 3 {
            let generation = self.fault_generation.load(Ordering::Relaxed);
            let Some(window) = self.fault_selection(mm_key, generation) else {
                return false;
            };
            if window.fault_page == fault_page {
                return self.cancel_fault_selection(window, generation);
            }
        } else if state == 4 {
            let values: [u64; 6] = core::array::from_fn(|i| self.window[i].load(Ordering::Relaxed));
            if values[1] == mm_key && values[5] == fault_page {
                return self
                    .state
                    .compare_exchange(4, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok();
            }
        }
        false
    }
    /// Final-MM teardown cancels an unconsumed fault selection after its
    /// mailbox request or refusal has been withdrawn. The source MM cannot
    /// fault again, and keeping this selection blocks every later MM on the
    /// same persistent worker slot.
    pub fn withdraw_retired_mm_selection(&self, mm_key: u64) -> bool {
        let state = self.state.load(Ordering::Acquire);
        if state == 3 {
            let generation = self.fault_generation.load(Ordering::Relaxed);
            let Some(window) = self.fault_selection(mm_key, generation) else {
                return false;
            };
            return self.cancel_fault_selection(window, generation);
        }
        if state == 4 {
            let recorded_mm = self.window[1].load(Ordering::Relaxed);
            if recorded_mm == mm_key {
                return self
                    .state
                    .compare_exchange(4, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok();
            }
        }
        false
    }
    pub fn has_outstanding_for(&self, mm_key: u64) -> bool {
        let state = self.state.load(Ordering::Acquire);
        if state == 4 {
            return self.window[1].load(Ordering::Relaxed) == mm_key;
        }
        state != 0
            && (state == 1
                || PortalGrantWindow::decode(core::array::from_fn(|i| {
                    self.window[i].load(Ordering::Relaxed)
                }))
                .is_none_or(|window| window.operation.mm.raw() == mm_key))
    }
    pub fn submit(&self, window: PortalGrantWindow, txn: &DescriptorTxn) -> bool {
        if !window.valid() || txn.id.mm_key.get() != window.operation.mm.raw() {
            return false;
        }
        let mut current = self.state.load(Ordering::Acquire);
        loop {
            if current != 0 && current != 3 && current != 4 {
                return false;
            }
            match self
                .state
                .compare_exchange_weak(current, 1, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        if !self.descriptor.submit(txn) {
            self.state.store(0, Ordering::Release);
            return false;
        }
        for (word, value) in self.window.iter().zip(window.words()) {
            word.store(value, Ordering::Relaxed);
        }
        self.state.store(2, Ordering::Release);
        true
    }
    pub fn window(&self) -> Option<PortalGrantWindow> {
        if self.state.load(Ordering::Acquire) != 2 {
            return None;
        }
        PortalGrantWindow::decode(core::array::from_fn(|i| {
            self.window[i].load(Ordering::Relaxed)
        }))
    }
    /// The caller validates this slot's window under the exact MM editor before
    /// passing this isolated slot to the existing descriptor executor.
    pub fn descriptor(&self) -> &DescriptorTxnSlot {
        &self.descriptor
    }
    pub fn withdraw(&self, window: PortalGrantWindow, txn: &DescriptorTxn) -> bool {
        if self.window() != Some(window) || !self.descriptor.withdraw(txn.id) {
            return false;
        }
        self.state.store(0, Ordering::Release);
        true
    }
    pub fn take_receipt(
        &self,
        window: PortalGrantWindow,
        txn: &DescriptorTxn,
    ) -> Option<DescriptorReceipt> {
        if self.window() != Some(window) {
            return None;
        }
        let receipt = self.descriptor.take_receipt(txn.id)?;
        self.state.store(0, Ordering::Release);
        Some(receipt)
    }
}

/// Borrowed transport views, with no reservation or grant authority of their own.
pub trait GrantSlotVenue {
    fn carrier(&self) -> Option<core::num::NonZeroU64>;
    fn grant(&self, slot: usize) -> Option<&PortalGrantSlot>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{
        FrameGrantMailbox, FrameGrantRequest, PortalOperation, ReservationGeneration,
        ReservationProtection, ReservationRange,
    };
    use core::num::NonZeroU64;

    fn window(mm_key: u64) -> PortalGrantWindow {
        PortalGrantWindow {
            operation: PortalOperation {
                carrier: NonZeroU64::new(1).unwrap(),
                mm: ReservationMm::new(mm_key).unwrap(),
                incarnation: NonZeroU64::new(1).unwrap(),
                sequence: NonZeroU64::new(1).unwrap(),
            },
            generation: ReservationGeneration::new(1).unwrap(),
            range: ReservationRange::new(0x6000, 0x7000).unwrap(),
            protection: ReservationProtection::from_bits(3).unwrap(),
            fault_page: 0x6000,
            host_backing: None,
            fork_sequence: None,
        }
    }

    fn dummy_txn(mm_key: u64) -> DescriptorTxn {
        use carrick_mmu_core::aarch64::descriptor_txn::{
            BackingIdentity, DescriptorOp, DescriptorTxnId, PageSpan, TableGrants,
        };
        use carrick_mmu_core::aarch64::{GuestLeafPublication, SubstrateGpa};
        let nz = |n| NonZeroU64::new(n).unwrap();
        DescriptorTxn {
            id: DescriptorTxnId {
                mm_key: nz(mm_key),
                generation: nz(1),
            },
            root: SubstrateGpa(0x1000),
            op: DescriptorOp::Prepare {
                publication: GuestLeafPublication {
                    va: 0x6000,
                    ipa: 0x10000,
                    len: 0x1000,
                    writable: true,
                    executable: false,
                },
                resident: PageSpan::new(0x6000, 4096),
                backing: BackingIdentity {
                    frame_id: nz(1),
                    mapping_id: nz(2),
                    owner_generation: nz(3),
                    inventory_revision: nz(4),
                },
            },
            tables: TableGrants::NONE,
        }
    }

    #[test]
    fn retired_mm_withdraws_mailbox_and_fault_selection_before_slot_reuse() {
        let slot = PortalGrantSlot::new();
        let mailbox = FrameGrantMailbox::new();
        assert!(slot.publish_fault_selection(1, window(7)));
        assert!(mailbox.try_publish_request(FrameGrantRequest {
            mm_key: 7,
            request_generation: 1,
            fault_va: 0x6000,
            requested_len: 4096,
            access: 2,
        }));
        assert!(mailbox.withdraw_mm(7));
        assert!(slot.withdraw_retired_mm_selection(7));
        assert!(!slot.has_outstanding_for(7));
        assert!(slot.publish_fault_selection(2, window(8)));
        assert!(slot.pending_fault_selection(8, 0x6000).is_some());
    }

    #[test]
    fn unconsumed_fault_selection_allows_subsequent_submit_on_same_slot() {
        let slot = PortalGrantSlot::new();
        assert!(slot.publish_fault_selection(1, window(7)));
        let other_window = window(8);
        let txn = dummy_txn(8);
        assert!(slot.submit(other_window, &txn));
    }

    #[test]
    fn unconsumed_fault_wait_allows_subsequent_submit_on_same_slot() {
        let slot = PortalGrantSlot::new();
        let wait = unsafe {
            PortalOwnerWait::from_owner(
                El1MmHandle::from_admitted_owner(
                    NonZeroU64::new(1).unwrap(),
                    ReservationMm::new(7).unwrap(),
                    NonZeroU64::new(1).unwrap(),
                ),
                PortalWaitCause::Editor,
                10,
            )
        };
        assert!(slot.publish_fault_wait(0x6000, wait));
        let txn = dummy_txn(8);
        assert!(slot.submit(window(8), &txn));
    }

    #[test]
    fn unconsumed_fault_wait_allows_new_fault_selection_on_same_slot() {
        let slot = PortalGrantSlot::new();
        let wait = unsafe {
            PortalOwnerWait::from_owner(
                El1MmHandle::from_admitted_owner(
                    NonZeroU64::new(1).unwrap(),
                    ReservationMm::new(7).unwrap(),
                    NonZeroU64::new(1).unwrap(),
                ),
                PortalWaitCause::Editor,
                10,
            )
        };
        assert!(slot.publish_fault_wait(0x6000, wait));
        assert!(slot.publish_fault_selection(2, window(8)));
        assert!(slot.pending_fault_selection(8, 0x6000).is_some());
    }

    #[test]
    fn retired_mm_withdraws_fault_wait_before_slot_reuse() {
        let slot = PortalGrantSlot::new();
        let wait = unsafe {
            PortalOwnerWait::from_owner(
                El1MmHandle::from_admitted_owner(
                    NonZeroU64::new(1).unwrap(),
                    ReservationMm::new(7).unwrap(),
                    NonZeroU64::new(1).unwrap(),
                ),
                PortalWaitCause::Editor,
                10,
            )
        };
        assert!(slot.publish_fault_wait(0x6000, wait));
        assert!(slot.withdraw_retired_mm_selection(7));
        assert!(!slot.has_outstanding_for(7));
        assert!(slot.publish_fault_selection(2, window(8)));
    }

    #[test]
    fn late_completion_from_old_generation_is_refused_after_reclaim_and_reissue() {
        let slot = PortalGrantSlot::new();
        let win1 = window(7);
        let mut txn1 = dummy_txn(7);
        txn1.id.generation = NonZeroU64::new(1).unwrap();
        assert!(slot.submit(win1, &txn1));

        // Reclaim / withdraw the slot for generation 1
        assert!(slot.withdraw(win1, &txn1));

        // Reissue on the same slot for generation 2
        let mut win2 = window(7);
        win2.generation = ReservationGeneration::new(2).unwrap();
        let mut txn2 = dummy_txn(7);
        txn2.id.generation = NonZeroU64::new(2).unwrap();
        assert!(slot.submit(win2, &txn2));

        // A late completion from the old generation 1 must be refused
        assert!(slot.take_receipt(win1, &txn1).is_none());
        assert!(!slot.withdraw(win1, &txn1));

        // The current generation 2 window remains intact
        assert_eq!(slot.window(), Some(win2));
    }

    #[test]
    fn late_fault_cancellation_from_old_generation_is_refused_after_reissue() {
        let slot = PortalGrantSlot::new();
        let win1 = window(7);
        assert!(slot.publish_fault_selection(1, win1));

        // Cancel generation 1
        assert!(slot.cancel_fault_selection(win1, 1));

        // Reissue on the same slot for generation 2
        let mut win2 = window(7);
        win2.generation = ReservationGeneration::new(2).unwrap();
        assert!(slot.publish_fault_selection(2, win2));

        // Late cancellation from old generation 1 must be refused
        assert!(!slot.cancel_fault_selection(win1, 1));

        // Slot must still hold generation 2
        assert_eq!(slot.fault_selection(7, 2), Some(win2));
    }
}
