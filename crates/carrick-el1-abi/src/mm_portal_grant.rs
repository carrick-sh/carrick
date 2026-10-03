//! An EL1-authorized lazy window and an isolated descriptor submission. The
//! ordinary descriptor drain cannot publish this grant before root revalidation.
use crate::{PortalOperation, ReservationGeneration, ReservationProtection, ReservationRange};
use carrick_mmu_core::aarch64::descriptor_txn::{
    DescriptorReceipt, DescriptorTxn, DescriptorTxnSlot,
};
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

pub const MM_PORTAL_GRANT_ESR: u64 = 0x4352_4d4d_4752_0003;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortalGrantWindow {
    pub operation: PortalOperation,
    pub generation: ReservationGeneration,
    pub range: ReservationRange,
    pub protection: ReservationProtection,
    pub fault_page: u64,
    pub host_backing: Option<crate::HostBackingIdentity>,
}
impl PortalGrantWindow {
    pub fn valid(self) -> bool {
        self.range.len() <= crate::EL1_FRAME_GRANT_TARGET_SIZE
            && self.range.contains(self.fault_page)
            && self.fault_page.is_multiple_of(4096)
            && self.protection.bits() != 0
            && self
                .host_backing
                .is_none_or(|source| source.advance(self.range.len()).is_some())
    }
    fn words(self) -> [u64; 12] {
        [
            self.operation.carrier.get(),
            self.operation.mm.raw(),
            self.operation.incarnation.get(),
            self.operation.sequence.get(),
            self.generation.raw(),
            self.range.start(),
            self.range.end(),
            self.protection.bits(),
            self.fault_page,
            self.host_backing.map_or(0, |source| source.handle().get()),
            self.host_backing
                .map_or(0, |source| source.generation().get()),
            self.host_backing.map_or(0, |source| source.offset()),
        ]
    }
    fn decode(w: [u64; 12]) -> Option<Self> {
        let value = Self {
            operation: PortalOperation {
                carrier: NonZeroU64::new(w[0])?,
                mm: crate::ReservationMm::new(w[1])?,
                incarnation: NonZeroU64::new(w[2])?,
                sequence: NonZeroU64::new(w[3])?,
            },
            generation: ReservationGeneration::new(w[4])?,
            range: ReservationRange::new(w[5], w[6])?,
            protection: ReservationProtection::from_bits(w[7])?,
            fault_page: w[8],
            host_backing: if w[9] == 0 {
                if w[10] != 0 || w[11] != 0 {
                    return None;
                }
                None
            } else {
                Some(crate::HostBackingIdentity::new(
                    NonZeroU64::new(w[9])?,
                    NonZeroU64::new(w[10])?,
                    w[11],
                ))
            },
        };
        value.valid().then_some(value)
    }
}
#[repr(C, align(64))]
pub struct PortalGrantSlot {
    state: AtomicU64,
    window: [AtomicU64; 12],
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
            window: [const { AtomicU64::new(0) }; 12],
            descriptor: DescriptorTxnSlot::new(),
        }
    }
    pub fn submit(&self, window: PortalGrantWindow, txn: &DescriptorTxn) -> bool {
        if !window.valid()
            || txn.id.mm_key.get() != window.operation.mm.raw()
            || self
                .state
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
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
