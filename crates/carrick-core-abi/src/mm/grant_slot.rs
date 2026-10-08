//! An EL1-authorized lazy window and an isolated descriptor submission. The
//! ordinary descriptor drain cannot publish this grant before root revalidation.

use carrick_mmu_core::aarch64::descriptor_txn::{
    DescriptorReceipt, DescriptorTxn, DescriptorTxnSlot,
};

use core::sync::atomic::{AtomicU64, Ordering};

use super::PortalGrantWindow;
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
        if request_generation == 0
            || !window.valid()
            || self
                .state
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return false;
        }
        for (word, value) in self.window.iter().zip(window.words()) {
            word.store(value, Ordering::Relaxed);
        }
        self.fault_generation
            .store(request_generation, Ordering::Relaxed);
        self.state.store(3, Ordering::Release);
        true
    }
    /// Select a physical replacement loan; this never admits a Prepare descriptor.
    pub fn publish_cow_fault_selection(
        &self,
        request_generation: u64,
        window: PortalGrantWindow,
    ) -> bool {
        if request_generation == 0
            || !window.valid()
            || window.host_backing.is_some()
            || window.range.len() != 4096
            || window.range.start() != window.fault_page
            || self
                .state
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return false;
        }
        for (word, value) in self.window.iter().zip(window.words()) {
            word.store(value, Ordering::Relaxed);
        }
        self.fault_generation
            .store(request_generation, Ordering::Relaxed);
        self.state.store(4, Ordering::Release);
        true
    }
    pub fn pending_cow_fault_selection(
        &self,
        mm_key: u64,
        fault_va: u64,
    ) -> Option<(u64, PortalGrantWindow)> {
        if self.state.load(Ordering::Acquire) != 4 {
            return None;
        }
        let generation = self.fault_generation.load(Ordering::Relaxed);
        let window = PortalGrantWindow::decode(core::array::from_fn(|i| {
            self.window[i].load(Ordering::Relaxed)
        }))?;
        (window.operation.mm.raw() == mm_key && window.fault_page == fault_va & !4095)
            .then_some((generation, window))
    }
    /// Consume the exact demand only after its replacement loan is published.
    /// The caller retains exact-MM exclusion across inspection and consumption.
    pub fn take_cow_fault_selection(&self, window: PortalGrantWindow) -> bool {
        if self
            .pending_cow_fault_selection(window.operation.mm.raw(), window.fault_page)
            .map(|(_, selected)| selected)
            != Some(window)
        {
            return false;
        }
        self.state
            .compare_exchange(4, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
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
    pub fn has_outstanding_for(&self, mm_key: u64) -> bool {
        let state = self.state.load(Ordering::Acquire);
        state != 0
            && (state == 1
                || PortalGrantWindow::decode(core::array::from_fn(|i| {
                    self.window[i].load(Ordering::Relaxed)
                }))
                .is_none_or(|window| window.operation.mm.raw() == mm_key))
    }
    pub fn submit(&self, window: PortalGrantWindow, txn: &DescriptorTxn) -> bool {
        if !window.valid() || txn.id.mm_key.get() != window.operation.mm.raw() || {
            let state = self.state.load(Ordering::Acquire);
            let selected = state == 3
                && PortalGrantWindow::decode(core::array::from_fn(|i| {
                    self.window[i].load(Ordering::Relaxed)
                })) == Some(window);
            (!selected && state != 0)
                || self
                    .state
                    .compare_exchange(state, 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
        } {
            return false;
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

// Literal wire layout captured from 3fd7862be on a 64-bit host.
// Keep these values fixed when moving the shared kernel implementation.
#[cfg(test)]
mod layout_manifest {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    macro_rules! field {
        ($record:ty, $field:ident, $ty:ty, $offset:literal, $size:literal, $align:literal) => {
            // Type-check the manifest's field type without constructing a record.
            let _ = |record: &$record| {
                let _: &$ty = &record.$field;
            };
            assert_eq!(
                (
                    offset_of!($record, $field),
                    size_of::<$ty>(),
                    align_of::<$ty>()
                ),
                ($offset, $size, $align),
                concat!(stringify!($record), "::", stringify!($field))
            );
        };
    }

    #[test]
    fn cow_selection_is_distinct_exact_and_consumed_once() {
        let window =
            PortalGrantWindow::decode([1, 77, 2, 3, 4, 0x4000, 0x5000, 3, 0x4000, 0, 0, 0, 0])
                .unwrap();
        let slot = PortalGrantSlot::new();
        assert!(slot.publish_cow_fault_selection(3, window));
        assert!(slot.pending_fault_selection(77, 0x4003).is_none());
        assert_eq!(
            slot.pending_cow_fault_selection(77, 0x4003),
            Some((3, window))
        );
        assert!(slot.pending_cow_fault_selection(78, 0x4003).is_none());
        assert!(slot.pending_cow_fault_selection(77, 0x5000).is_none());
        let mut stale = window;
        stale.operation.incarnation = core::num::NonZeroU64::new(9).unwrap();
        assert!(!slot.take_cow_fault_selection(stale));
        assert!(slot.take_cow_fault_selection(window));
        assert!(!slot.take_cow_fault_selection(window));
        assert!(slot.publish_fault_selection(4, window));
        assert!(slot.pending_cow_fault_selection(77, 0x4000).is_none());
        assert_eq!(slot.pending_fault_selection(77, 0x4000), Some((4, window)));
    }

    #[test]
    fn portal_grant_slot() {
        assert_eq!(
            (size_of::<PortalGrantSlot>(), align_of::<PortalGrantSlot>()),
            (512, 64)
        );
        // Exhaustive pattern makes newly added fields require a manifest entry.
        let _ = |PortalGrantSlot {
                     state: _,
                     window: _,
                     fault_generation: _,
                     descriptor: _,
                 }: PortalGrantSlot| {};
        field!(PortalGrantSlot, state, AtomicU64, 0, 8, 8);
        field!(PortalGrantSlot, window, [AtomicU64; 13], 8, 104, 8);
        field!(PortalGrantSlot, fault_generation, AtomicU64, 112, 8, 8);
        field!(PortalGrantSlot, descriptor, DescriptorTxnSlot, 128, 384, 64);
    }
}
