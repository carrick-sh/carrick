//! An EL1-authorized lazy window and an isolated descriptor submission. The
//! ordinary descriptor drain cannot publish this grant before root revalidation.

use carrick_mmu_core::aarch64::descriptor_txn::{
    DescriptorReceipt, DescriptorTxn, DescriptorTxnSlot,
};

use carrick_mmu_core::live_descriptor_words::GrantRefusalTrace;

use core::sync::atomic::{AtomicU64, Ordering};

use super::PortalGrantWindow;

/// Why [`PortalGrantSlot::supply_cow_selection`] supplied nothing. The slot
/// holds no selection of the lane's after any of these.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum CowSupplyRefusal<E> {
    /// Another selection occupies the lane's slot; nothing was published.
    SlotOccupied,
    /// The window is not a single-page replacement demand; nothing was
    /// published. A caller bug, never contention.
    Invalid,
    /// The carrier supplied nothing and the lane withdrew its selection,
    /// with the crossing's own refusal when it reported one. A crossing that
    /// reports none met contention (the MM's editor held elsewhere).
    Unserved(Option<E>),
    /// The selection was neither supplied nor withdrawable by the lane.
    Lost,
}

/// Why [`PortalGrantSlot::lease_cow_selection`] published nothing.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum CowLeaseRefusal {
    /// Another selection occupies the lane's slot.
    SlotOccupied,
    /// The window is not a single-page replacement demand: a caller bug.
    Invalid,
}

/// A lane's published copy-on-write selection, held until the carrier takes
/// it. Dropping the lease withdraws exactly this selection (reserved, so a
/// successor is never consumed in its place); nothing else ends it but the
/// carrier's take, which [`Self::settle`] observes.
#[must_use = "dropping a COW selection lease withdraws the selection"]
pub struct CowSelectionLease<'a> {
    slot: &'a PortalGrantSlot,
    window: PortalGrantWindow,
}

/// What became of a leased selection after the carrier's crossing.
#[must_use]
pub enum CowSettlement<'a> {
    /// The carrier took the exact selection: the lease is consumed.
    Taken,
    /// The selection is still published; dropping the lease withdraws it.
    Unserved(CowSelectionLease<'a>),
    /// The slot holds another selection: a broken invariant, since only the
    /// leasing lane publishes into its slot. Nothing is withdrawn.
    Lost,
}

impl<'a> CowSelectionLease<'a> {
    pub fn window(&self) -> PortalGrantWindow {
        self.window
    }
    /// Read the slot after the carrier's crossing returned.
    pub fn settle(self) -> CowSettlement<'a> {
        let slot = self.slot;
        let window = self.window;
        match slot.state.load(Ordering::Acquire) {
            0 => {
                core::mem::forget(self);
                CowSettlement::Taken
            }
            4 if slot.fault_generation.load(Ordering::Relaxed)
                == window.operation.sequence.get()
                && PortalGrantWindow::decode(core::array::from_fn(|i| {
                    slot.window[i].load(Ordering::Relaxed)
                })) == Some(window) =>
            {
                CowSettlement::Unserved(self)
            }
            _ => {
                core::mem::forget(self);
                CowSettlement::Lost
            }
        }
    }
}

impl Drop for CowSelectionLease<'_> {
    fn drop(&mut self) {
        // Exact and reserved: a slot that no longer holds this selection is
        // left as it is.
        let _ = self.slot.take_cow_fault_selection(self.window);
    }
}

#[repr(C, align(64))]
#[derive(zerocopy::FromZeros)]
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
    /// Included in the image ABI hash: older hosts cannot serve this demand.
    pub const PREPARED_SELECTION_STATE: u64 = 5;
    /// Terminal backing-capacity refusal for an authenticated fault selection.
    pub const REFUSED_SELECTION_STATE: u64 = 6;
    /// A reservation-pool wait reply ([`Self::complete_pool_wait`]), with
    /// the pool queue's pre-probe revision carried in `fault_generation`.
    pub const POOL_WAIT_STATE: u64 = 7;

    pub fn publish_prepared_fault_selection(
        &self,
        request_generation: u64,
        window: PortalGrantWindow,
    ) -> bool {
        if window.range.len() != 4096
            || window.range.start() != window.fault_page
            || !self.publish_fault_selection(request_generation, window)
        {
            return false;
        }
        // The publishing ring lane still exclusively owns its slot. Intake
        // cannot start until the lane stamps the retained service request.
        self.state
            .store(Self::PREPARED_SELECTION_STATE, Ordering::Release);
        true
    }

    pub fn pending_prepared_fault_selection(
        &self,
        mm: u64,
        address: u64,
    ) -> Option<(u64, PortalGrantWindow)> {
        if self.state.load(Ordering::Acquire) != Self::PREPARED_SELECTION_STATE {
            return None;
        }
        let generation = self.fault_generation.load(Ordering::Relaxed);
        let window = PortalGrantWindow::decode(core::array::from_fn(|i| {
            self.window[i].load(Ordering::Relaxed)
        }))?;
        (window.operation.mm.raw() == mm && window.fault_page == address & !4095)
            .then_some((generation, window))
    }

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
    /// Read the exact selected operation while the ring still owns this lane.
    pub fn native_fault_sequence(&self, mm: u64, address: u64) -> Option<core::num::NonZeroU64> {
        let (generation, window) = self
            .pending_cow_fault_selection(mm, address)
            .or_else(|| self.pending_prepared_fault_selection(mm, address))
            .or_else(|| self.pending_fault_selection(mm, address))?;
        (generation == window.operation.sequence.get()).then_some(window.operation.sequence)
    }
    /// Read-only diagnostic view of this lane slot: its protocol state, the
    /// stamped request generation and, when it decodes, the stamped window.
    /// Grants no authority; a refused intake reports it with real values.
    pub fn selection_snapshot(&self) -> (u64, u64, Option<PortalGrantWindow>) {
        let state = self.state.load(Ordering::Acquire);
        let generation = self.fault_generation.load(Ordering::Relaxed);
        let window = PortalGrantWindow::decode(core::array::from_fn(|i| {
            self.window[i].load(Ordering::Relaxed)
        }));
        (state, generation, window)
    }
    /// Transfer only the selection stamped into the retained native request.
    pub(crate) fn take_native_fault_selection<
        P: core::ops::Deref<Target = crate::service::ServiceCell>,
    >(
        &self,
        ticket: &crate::service::ServiceTicket<P>,
    ) -> Result<Option<crate::service::ServiceFaultSupply>, crate::service::ServiceError> {
        use crate::service::{ServiceError, ServiceFaultSupply, ServiceOperation};
        let request = ticket.request();
        let ServiceOperation::Fault(fault) = request.operation else {
            return Ok(None);
        };
        let state = self.state.load(Ordering::Acquire);
        let Some(sequence) = request.fault_sequence else {
            return if state == 0 {
                Ok(None)
            } else {
                Err(ServiceError::Stale)
            };
        };
        if !matches!(state, 3 | 4 | Self::PREPARED_SELECTION_STATE) {
            return Err(ServiceError::Stale);
        }
        self.state
            .compare_exchange(state, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ServiceError::Stale)?;
        // Reservation excludes publication and reclamation while the stamp and
        // payload are checked, including ABA through a same-MM/page successor.
        let selected = PortalGrantWindow::decode(core::array::from_fn(|i| {
            self.window[i].load(Ordering::Relaxed)
        }))
        .filter(|window| {
            window.operation.sequence == sequence
                && self.fault_generation.load(Ordering::Relaxed) == sequence.get()
                && window.operation.mm == request.identity.birth.mm.mm()
                && window.operation.carrier == request.identity.birth.mm.carrier()
                && window.operation.incarnation == request.identity.birth.mm.incarnation()
                && window.fault_page == fault.address.raw() & !4095
        });
        let Some(window) = selected else {
            self.state.store(state, Ordering::Release);
            return Err(ServiceError::Stale);
        };
        self.state.store(0, Ordering::Release);
        Ok(Some(if state == Self::PREPARED_SELECTION_STATE {
            ServiceFaultSupply::Prepared(window)
        } else if state == 4 {
            ServiceFaultSupply::Cow(window)
        } else {
            ServiceFaultSupply::Backing(window)
        }))
    }
    /// Consume the exact demand only after its replacement loan is published.
    /// Reservation (state 1) excludes publication and every other take while
    /// the stamped generation and window are compared, so a same-MM/page
    /// successor can never be consumed in this one's place.
    pub fn take_cow_fault_selection(&self, window: PortalGrantWindow) -> bool {
        if self
            .state
            .compare_exchange(4, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        let exact = self.fault_generation.load(Ordering::Relaxed)
            == window.operation.sequence.get()
            && PortalGrantWindow::decode(core::array::from_fn(|i| {
                self.window[i].load(Ordering::Relaxed)
            })) == Some(window);
        self.state
            .store(if exact { 0 } else { 4 }, Ordering::Release);
        exact
    }
    /// Publish `window` as this lane's copy-on-write demand and lease it to
    /// the lane until the carrier takes it. The lease is linear: only the
    /// carrier's exact take consumes it ([`CowSelectionLease::settle`]), and
    /// dropping it on any other path, an unwind included, withdraws exactly
    /// this selection, so a selection the carrier did not serve is never left
    /// for a later request on this CPU (#3040). The caller is the publishing
    /// lane, which exclusively owns this slot while it holds the lease.
    pub fn lease_cow_selection(
        &self,
        window: PortalGrantWindow,
    ) -> Result<CowSelectionLease<'_>, CowLeaseRefusal> {
        if self.publish_cow_fault_selection(window.operation.sequence.get(), window) {
            return Ok(CowSelectionLease { slot: self, window });
        }
        Err(if self.state.load(Ordering::Acquire) == 0 {
            CowLeaseRefusal::Invalid
        } else {
            CowLeaseRefusal::SlotOccupied
        })
    }
    /// Lease the copy-on-write selection this lane already published for
    /// `mm`'s page at `address` (an EL0 fault's selection), on the same
    /// terms as [`Self::lease_cow_selection`].
    pub fn adopt_cow_selection(&self, mm: u64, address: u64) -> Option<CowSelectionLease<'_>> {
        let (generation, window) = self.pending_cow_fault_selection(mm, address)?;
        (generation == window.operation.sequence.get())
            .then_some(CowSelectionLease { slot: self, window })
    }
    /// Ask the carrier for `window`'s copy-on-write replacement through the
    /// lane's synchronous supply crossing, leaving this slot empty on every
    /// outcome (#3040): the lane leases its selection, crosses, and a supply
    /// the carrier did not take is withdrawn when the lease drops.
    pub fn supply_cow_selection<E>(
        &self,
        window: PortalGrantWindow,
        cross: impl FnOnce() -> Result<(), E>,
    ) -> Result<(), CowSupplyRefusal<E>> {
        let lease = self
            .lease_cow_selection(window)
            .map_err(|refusal| match refusal {
                CowLeaseRefusal::SlotOccupied => CowSupplyRefusal::SlotOccupied,
                CowLeaseRefusal::Invalid => CowSupplyRefusal::Invalid,
            })?;
        let crossed = cross();
        match (lease.settle(), crossed) {
            (CowSettlement::Taken, Ok(())) => Ok(()),
            // Dropping the returned lease withdraws the exact selection.
            (CowSettlement::Unserved(_), crossed) => Err(CowSupplyRefusal::Unserved(crossed.err())),
            // Taken while the crossing refused, or replaced under the lane:
            // the slot no longer names this lane's request.
            (CowSettlement::Taken | CowSettlement::Lost, _) => Err(CowSupplyRefusal::Lost),
        }
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
    /// Observe a selected window for stopped native-service file preparation.
    /// This grants no service, MM or backing authority; intake claims the exact
    /// ticket and takes this same window before any physical publication.
    pub fn pending_fault_selection_for_mm(
        &self,
        mm: super::ReservationMm,
    ) -> Option<(u64, PortalGrantWindow)> {
        if self.state.load(Ordering::Acquire) != 3 {
            return None;
        }
        let generation = self.fault_generation.load(Ordering::Relaxed);
        let window = self.fault_selection(mm.raw(), generation)?;
        Some((generation, window))
    }

    pub fn pending_fault_selection(
        &self,
        mm_key: u64,
        fault_va: u64,
    ) -> Option<(u64, PortalGrantWindow)> {
        self.pending_fault_selection_for_mm(super::ReservationMm::new(mm_key)?)
            .filter(|(_, window)| window.fault_page == fault_va & !4095)
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
    /// Complete a pending fault selection with a reservation-pool wait (a
    /// temporary carrier table shortage, #3017), keeping the slot's window
    /// identity until the faulting ring lane consumes it with
    /// [`Self::take_pool_wait`]. Only that one cause travels this way: an
    /// Editor wait cancels the selection instead.
    pub fn complete_pool_wait(
        &self,
        window: PortalGrantWindow,
        request_generation: u64,
        wait: crate::PortalOwnerWait,
    ) -> bool {
        let handle = wait.handle();
        if wait.cause() != crate::PortalWaitCause::ReservationPool
            || handle.carrier() != window.operation.carrier
            || handle.mm() != window.operation.mm
            || handle.incarnation() != window.operation.incarnation
            || self
                .state
                .compare_exchange(3, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return false;
        }
        let matches = self.fault_generation.load(Ordering::Relaxed) == request_generation
            && PortalGrantWindow::decode(core::array::from_fn(|i| {
                self.window[i].load(Ordering::Relaxed)
            })) == Some(window);
        if !matches {
            self.state.store(3, Ordering::Release);
            return false;
        }
        self.fault_generation
            .store(wait.revision(), Ordering::Relaxed);
        self.state.store(Self::POOL_WAIT_STATE, Ordering::Release);
        true
    }
    /// Consume a reservation-pool wait published by
    /// [`Self::complete_pool_wait`] for this exact MM and fault page, and
    /// return this slot to idle (`0`).
    pub fn take_pool_wait(&self, mm_key: u64, fault_va: u64) -> Option<crate::PortalOwnerWait> {
        self.state
            .compare_exchange(
                Self::POOL_WAIT_STATE,
                1,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()?;
        let selected = PortalGrantWindow::decode(core::array::from_fn(|i| {
            self.window[i].load(Ordering::Relaxed)
        }))
        .filter(|window| {
            window.operation.mm.raw() == mm_key && window.fault_page == fault_va & !4095
        });
        let Some(window) = selected else {
            self.state.store(Self::POOL_WAIT_STATE, Ordering::Release);
            return None;
        };
        let revision = self.fault_generation.load(Ordering::Relaxed);
        // SAFETY: `complete_pool_wait` matched the wait's handle against
        // `window.operation.{carrier, mm, incarnation}` before publishing it.
        let handle = unsafe {
            crate::El1MmHandle::from_admitted_owner(
                window.operation.carrier,
                window.operation.mm,
                window.operation.incarnation,
            )
        };
        self.state.store(0, Ordering::Release);
        Some(crate::PortalOwnerWait::reservation_pool(handle, revision))
    }
    /// Mark a pending fault selection terminally refused for backing capacity
    /// so the faulting ring lane delivers `SIGSEGV` and resets the slot.
    pub fn refuse_fault_selection(
        &self,
        window: PortalGrantWindow,
        request_generation: u64,
    ) -> bool {
        if self
            .state
            .compare_exchange(3, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        let matches = self.fault_generation.load(Ordering::Relaxed) == request_generation
            && PortalGrantWindow::decode(core::array::from_fn(|i| {
                self.window[i].load(Ordering::Relaxed)
            })) == Some(window);
        if !matches {
            self.state.store(3, Ordering::Release);
            return false;
        }
        self.state
            .store(Self::REFUSED_SELECTION_STATE, Ordering::Release);
        true
    }
    /// Consume a terminal backing-capacity refusal published by
    /// [`Self::refuse_fault_selection`] and return this slot to idle (`0`).
    pub fn take_refused_fault_selection(&self, mm_key: u64, fault_va: u64) -> bool {
        if self
            .state
            .compare_exchange(
                Self::REFUSED_SELECTION_STATE,
                1,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        let matches = PortalGrantWindow::decode(core::array::from_fn(|i| {
            self.window[i].load(Ordering::Relaxed)
        }))
        .is_some_and(|window| {
            window.operation.mm.raw() == mm_key && window.fault_page == fault_va & !4095
        });
        if !matches {
            self.state
                .store(Self::REFUSED_SELECTION_STATE, Ordering::Release);
            return false;
        }
        self.state.store(0, Ordering::Release);
        true
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
        self.submit_with_trace(window, txn, false)
    }

    pub fn submit_with_trace(
        &self,
        window: PortalGrantWindow,
        txn: &DescriptorTxn,
        trace: bool,
    ) -> bool {
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
        if !self.descriptor.submit_with_grant_trace(txn, trace) {
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
    /// Inspect an exact receipt without returning the transport to IDLE.
    /// The serialized native publication owner settles physical and table
    /// custody before calling take_receipt to acknowledge it.
    pub fn inspect_receipt(
        &self,
        window: PortalGrantWindow,
        txn: &DescriptorTxn,
    ) -> Option<DescriptorReceipt> {
        (self.window() == Some(window)).then(|| self.descriptor.inspect_receipt(txn.id))?
    }
    pub fn inspect_receipt_with_trace(
        &self,
        window: PortalGrantWindow,
        txn: &DescriptorTxn,
    ) -> Option<(DescriptorReceipt, Option<GrantRefusalTrace>)> {
        (self.window() == Some(window))
            .then(|| self.descriptor.inspect_receipt_with_grant_trace(txn.id))?
    }

    pub fn take_receipt_with_trace(
        &self,
        window: PortalGrantWindow,
        txn: &DescriptorTxn,
    ) -> Option<(DescriptorReceipt, Option<GrantRefusalTrace>)> {
        self.consume_receipt(window, || {
            self.descriptor.take_receipt_with_grant_trace(txn.id)
        })
    }

    pub fn take_receipt(
        &self,
        window: PortalGrantWindow,
        txn: &DescriptorTxn,
    ) -> Option<DescriptorReceipt> {
        self.consume_receipt(window, || self.descriptor.take_receipt(txn.id))
    }

    fn consume_receipt<T>(
        &self,
        window: PortalGrantWindow,
        take: impl FnOnce() -> Option<T>,
    ) -> Option<T> {
        if self.window() != Some(window) {
            return None;
        }
        let receipt = take()?;
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
    extern crate std;

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

    /// #3040 / #3042: a leased COW selection ends only by the carrier's
    /// exact take; every other end of the lease, an unwind included,
    /// withdraws exactly that selection and leaves a successor alone.
    #[test]
    fn cow_selection_lease_is_withdrawn_unless_the_carrier_takes_it() {
        let window =
            PortalGrantWindow::decode([1, 77, 2, 3, 4, 0x4000, 0x5000, 3, 0x4000, 0, 0, 0, 0])
                .unwrap();
        let (mm, page) = (window.operation.mm.raw(), window.fault_page);
        let slot = PortalGrantSlot::new();
        let idle = |slot: &PortalGrantSlot| slot.selection_snapshot().0 == 0;

        // Dropped: withdrawn.
        let lease = slot.lease_cow_selection(window).unwrap();
        assert_eq!(lease.window(), window);
        assert_eq!(
            slot.pending_cow_fault_selection(mm, page),
            Some((window.operation.sequence.get(), window))
        );
        // The lane's slot holds one selection at a time.
        assert!(matches!(
            slot.lease_cow_selection(window),
            Err(CowLeaseRefusal::SlotOccupied)
        ));
        drop(lease);
        assert!(idle(&slot));

        // Unwound through the crossing: withdrawn.
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _lease = slot.lease_cow_selection(window).unwrap();
            panic!("crossing unwound");
        }));
        assert!(unwound.is_err());
        assert!(idle(&slot));

        // Unserved after the crossing: still published, withdrawn on drop.
        let lease = slot.lease_cow_selection(window).unwrap();
        let CowSettlement::Unserved(unserved) = lease.settle() else {
            panic!("an untaken selection is unserved");
        };
        assert!(!idle(&slot));
        drop(unserved);
        assert!(idle(&slot));

        // Taken by the carrier: consumed, nothing to withdraw.
        let lease = slot.lease_cow_selection(window).unwrap();
        assert!(slot.take_cow_fault_selection(window));
        assert!(matches!(lease.settle(), CowSettlement::Taken));
        assert!(idle(&slot));

        // Replaced under the lane: lost, and the successor stays.
        let lease = slot.lease_cow_selection(window).unwrap();
        assert!(slot.take_cow_fault_selection(window));
        assert!(slot.publish_fault_selection(9, window));
        assert!(matches!(lease.settle(), CowSettlement::Lost));
        assert_eq!(slot.pending_fault_selection(mm, page), Some((9, window)));
        assert!(slot.cancel_fault_selection(window, 9));

        // A dropped lease never consumes a same-page successor of another
        // generation.
        let lease = slot.lease_cow_selection(window).unwrap();
        assert!(slot.take_cow_fault_selection(window));
        let mut successor = window;
        successor.operation.sequence = core::num::NonZeroU64::new(5).unwrap();
        assert!(slot.publish_cow_fault_selection(5, successor));
        drop(lease);
        assert_eq!(
            slot.pending_cow_fault_selection(mm, page),
            Some((5, successor))
        );
        assert!(slot.take_cow_fault_selection(successor));

        // Adopting an EL0 fault's published selection: the same terms.
        assert!(slot.publish_cow_fault_selection(window.operation.sequence.get(), window));
        assert!(slot.adopt_cow_selection(mm + 1, page).is_none());
        assert!(slot.adopt_cow_selection(mm, page + 4096).is_none());
        drop(slot.adopt_cow_selection(mm, page + 3).unwrap());
        assert!(idle(&slot));
        // A selection stamped with another generation is not the lane's.
        assert!(slot.publish_cow_fault_selection(window.operation.sequence.get() + 1, window));
        assert!(slot.adopt_cow_selection(mm, page).is_none());
        assert!(!slot.take_cow_fault_selection(window));
        assert!(!idle(&slot));

        // Not a single-page demand: nothing published.
        let fresh = PortalGrantSlot::new();
        let mut invalid = window;
        invalid.fault_page += 4096;
        assert!(matches!(
            fresh.lease_cow_selection(invalid),
            Err(CowLeaseRefusal::Invalid)
        ));
        assert!(idle(&fresh));
    }

    #[test]
    fn fault_wait_and_refused_selection_preserve_identity_and_consume_once() {
        let window =
            PortalGrantWindow::decode([1, 77, 2, 3, 4, 0x4000, 0x5000, 3, 0x4000, 0, 0, 0, 0])
                .unwrap();
        let slot = PortalGrantSlot::new();
        assert!(slot.publish_fault_selection(3, window));
        // SAFETY: test fixture matches window.operation identity.
        let handle = unsafe {
            crate::El1MmHandle::from_admitted_owner(
                window.operation.carrier,
                window.operation.mm,
                window.operation.incarnation,
            )
        };
        let wait = crate::PortalOwnerWait::reservation_pool(handle, 0xdead_beef_cafe_1234);
        assert!(!slot.complete_pool_wait(window, 99, wait));
        assert!(
            !slot.complete_pool_wait(window, 3, crate::PortalOwnerWait::host_readiness(handle, 1)),
            "only a reservation-pool wait travels through the grant slot"
        );
        assert!(slot.complete_pool_wait(window, 3, wait));
        assert!(slot.has_outstanding_for(77));
        assert!(!slot.has_outstanding_for(78));
        assert!(slot.take_pool_wait(78, 0x4003).is_none());
        assert!(slot.take_pool_wait(77, 0x5000).is_none());
        assert_eq!(slot.take_pool_wait(77, 0x4003), Some(wait));
        assert!(slot.take_pool_wait(77, 0x4003).is_none());
        assert!(!slot.has_outstanding_for(77));

        assert!(slot.publish_fault_selection(5, window));
        assert!(!slot.refuse_fault_selection(window, 99));
        assert!(slot.refuse_fault_selection(window, 5));
        assert!(slot.has_outstanding_for(77));
        assert!(!slot.take_refused_fault_selection(78, 0x4003));
        assert!(!slot.take_refused_fault_selection(77, 0x5000));
        assert!(slot.take_refused_fault_selection(77, 0x4003));
        assert!(!slot.take_refused_fault_selection(77, 0x4003));
        assert!(!slot.has_outstanding_for(77));
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
