//! Shared host-to-EL1 descriptor drain, used by fork and host copyout.

use carrick_hal::{ThreadedEngine, TrapError};
use carrick_mmu_core::aarch64::GuestTxnSettleError;
use carrick_mmu_core::aarch64::descriptor_txn::{
    DescriptorOutcome, DescriptorRefusal, ReceiptError,
};

/// The two EL1 answers that leave no store of a transaction live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanRefusal {
    /// Refused before the first live store.
    Refused(DescriptorRefusal),
    /// Every journaled store restored; EL1 invalidated the ASID.
    RolledBack(DescriptorRefusal),
}

/// Why a guest descriptor publication produced no verified completion.
///
/// The distinction is what EL1 left live, not how the failure is worded: a
/// caller holding prepared backing may roll it back only when EL1 provably
/// left nothing that could name it.
#[derive(Debug)]
pub enum GuestPublishError {
    /// EL1 answered this exact transaction (id and digest authenticated) and
    /// left no store live: `Refused` before its first store, or `RolledBack`
    /// with every journaled store restored and the ASID invalidated by EL1
    /// before it answered. Its table grants are returned, and no earlier
    /// transaction of the same publication was applied.
    NotApplied {
        outcome: CleanRefusal,
        error: TrapError,
    },
    /// Anything else: an indeterminate rollback, an unauthenticated or
    /// inconsistent receipt, a lost drain, or a refusal after an earlier
    /// transaction of the same publication applied. Live state is unknown.
    Unsettled(TrapError),
}

impl GuestPublishError {
    /// Classify a settlement failure by its typed receipt error.
    #[must_use]
    pub fn from_settle(error: GuestTxnSettleError, context: &str) -> Self {
        let trap = TrapError::Hypervisor(format!("{context}: {error:?}"));
        match error {
            GuestTxnSettleError::Receipt(ReceiptError::NotApplied(DescriptorOutcome::Refused(
                refusal,
            ))) => Self::NotApplied {
                outcome: CleanRefusal::Refused(refusal),
                error: trap,
            },
            GuestTxnSettleError::Receipt(ReceiptError::NotApplied(
                DescriptorOutcome::RolledBack(refusal),
            )) => Self::NotApplied {
                outcome: CleanRefusal::RolledBack(refusal),
                error: trap,
            },
            GuestTxnSettleError::Receipt(_) | GuestTxnSettleError::Manager(_) => {
                Self::Unsettled(trap)
            }
        }
    }

    /// The one classification every guest publication site applies after
    /// preparing backing: `Ok` is a clean refusal the caller returns as an
    /// ordinary error (dropping its prepared backing rolls it back); `Err`
    /// is an unknown outcome the caller must fail-stop on.
    pub fn into_clean_refusal(self) -> Result<TrapError, TrapError> {
        match self {
            Self::NotApplied { outcome, error } => Ok(TrapError::Hypervisor(format!(
                "EL1 did not apply the guest descriptor transaction ({outcome:?}): {error}"
            ))),
            Self::Unsettled(error) => Err(error),
        }
    }
}

impl From<TrapError> for GuestPublishError {
    /// An untyped failure is never proof that nothing was stored.
    fn from(error: TrapError) -> Self {
        Self::Unsettled(error)
    }
}

impl From<GuestPublishError> for TrapError {
    fn from(error: GuestPublishError) -> Self {
        match error {
            GuestPublishError::NotApplied { error, .. } | GuestPublishError::Unsettled(error) => {
                error
            }
        }
    }
}

impl std::fmt::Display for GuestPublishError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotApplied { outcome, error } => {
                write!(formatter, "not applied ({outcome:?}): {error}")
            }
            Self::Unsettled(error) => write!(formatter, "unsettled: {error}"),
        }
    }
}

/// The venue a synchronous guest descriptor drain runs on: the exact vCPU
/// (slot, TTBR0) of the MM, the host-driven EL1 call, and receipt settlement.
pub trait GuestDrainVenue {
    fn slot(&self) -> Option<usize>;
    fn live_ttbr0(&mut self) -> Result<u64, TrapError>;
    /// Run the EL1 drain call with `frame` on this vCPU; return the frame
    /// EL1 answered.
    fn drain_call(
        &mut self,
        frame: carrick_el1_abi::TrapFrame,
    ) -> Result<carrick_el1_abi::TrapFrame, TrapError>;
    fn settle(
        &mut self,
        txn: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
        receipt: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt,
    ) -> Result<
        carrick_mmu_core::aarch64::descriptor_txn::VerifiedDescriptorReceipt,
        GuestPublishError,
    >;
}

/// The production venue: the engine's own vCPU and the shared EL1 region.
pub struct EngineDrainVenue<'a, E>(pub &'a mut E);

impl<E: ThreadedEngine> GuestDrainVenue for EngineDrainVenue<'_, E> {
    fn slot(&self) -> Option<usize> {
        self.0.mailbox_slot()
    }

    fn live_ttbr0(&mut self) -> Result<u64, TrapError> {
        self.0.live_ttbr0()
    }

    fn drain_call(
        &mut self,
        frame: carrick_el1_abi::TrapFrame,
    ) -> Result<carrick_el1_abi::TrapFrame, TrapError> {
        run_drain_call(frame, |entry, frame_va| {
            self.0.run_el1_service_call(entry, frame_va)
        })
    }

    fn settle(
        &mut self,
        txn: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
        receipt: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt,
    ) -> Result<
        carrick_mmu_core::aarch64::descriptor_txn::VerifiedDescriptorReceipt,
        GuestPublishError,
    > {
        // The engine's settlement is untyped: never treated as a clean refusal.
        self.0
            .settle_el1_descriptor_receipt(txn, receipt)
            .map_err(GuestPublishError::Unsettled)
    }
}

/// Apply `txns` for one MM synchronously, in order, on the venue's vCPU while
/// the host holds that MM: each is submitted into a free slot, EL1 applies it
/// through the host-driven drain call under the host's delegated custody, and
/// its exact receipt is settled before the next one is submitted. Any
/// refusal, blocked drain or unauthenticated receipt is an error; the caller
/// decides whether that is fatal. Only a clean refusal of the FIRST
/// transaction is [`GuestPublishError::NotApplied`]: once one applied, a later
/// refusal leaves the publication partial.
pub fn apply_guest_descriptor_txns_now<V: GuestDrainVenue>(
    venue: &mut V,
    slots: &carrick_el1_abi::DescriptorTxnSlots,
    txns: &[carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn],
) -> Result<
    Vec<carrick_mmu_core::aarch64::descriptor_txn::VerifiedDescriptorReceipt>,
    GuestPublishError,
> {
    let fail = |what: String| TrapError::Hypervisor(format!("guest descriptor drain: {what}"));
    let own = venue
        .slot()
        .ok_or_else(|| fail("vCPU has no slot".to_owned()))?;
    let mut verified = Vec::with_capacity(txns.len());
    for txn in txns {
        let ttbr0 = venue.live_ttbr0()?;
        if ttbr0 & 0x0000_FFFF_FFFF_F000 != txn.root.raw() {
            return Err(GuestPublishError::Unsettled(fail(format!(
                "vCPU TTBR0 0x{ttbr0:x} is not the transaction root 0x{:x}",
                txn.root.raw()
            ))));
        }
        let used = (0..slots.as_slice().len())
            .map(|offset| (own + offset) % slots.as_slice().len())
            .find(|&slot| slots.submit(slot, txn))
            .ok_or_else(|| fail("every descriptor slot is busy".to_owned()))?;
        let frame = drain_frame(own, txn.id.mm_key.get(), ttbr0);
        let answered = match venue.drain_call(frame) {
            Ok(answered) => answered,
            Err(error) => {
                let _ = slots.withdraw(used, txn.id);
                return Err(error.into());
            }
        };
        if answered.x[0] & carrick_el1_abi::DESCRIPTOR_DRAIN_BLOCKED != 0 {
            let _ = slots.withdraw(used, txn.id);
            return Err(fail("EL1 could not claim the MM".to_owned()).into());
        }
        let receipt = slots
            .take_receipt(used, txn.id)
            .ok_or_else(|| fail(format!("no receipt for {:?}", txn.id)))?;
        match venue.settle(txn, &receipt) {
            Ok(receipt) => verified.push(receipt),
            Err(GuestPublishError::NotApplied { outcome, error }) if !verified.is_empty() => {
                return Err(GuestPublishError::Unsettled(TrapError::Hypervisor(
                    format!(
                        "guest descriptor {:?} not applied ({outcome:?}) after {} applied: {error}",
                        txn.id,
                        verified.len()
                    ),
                )));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(verified)
}

/// Publish one prepared copyout page through the existing guest executor.
pub fn publish_copyout<V: GuestDrainVenue>(
    venue: &mut V,
    authority: &crate::stage1_authority::Stage1Authority,
    slots: &carrick_el1_abi::DescriptorTxnSlots,
    mm: std::num::NonZeroU64,
    page: u64,
    ipa: u64,
) -> Result<carrick_mmu_core::aarch64::descriptor_txn::VerifiedDescriptorReceipt, TrapError> {
    use carrick_mmu_core::aarch64::descriptor_txn::{DescriptorOp, PageSpan};
    use carrick_mmu_core::aarch64::{LeafAccess, SubstrateGpa};
    let txn = authority
        .prepare_guest_descriptor_txn(
            mm,
            DescriptorOp::Publish {
                span: PageSpan::new(page, 4096),
                expected_ipa: SubstrateGpa(ipa),
                access: LeafAccess::Write,
            },
        )
        .map_err(|error| TrapError::Hypervisor(format!("prepare guest copyout: {error:?}")))?;
    let mut receipts = apply_guest_descriptor_txns_now(venue, slots, &[txn])?;
    receipts
        .pop()
        .ok_or_else(|| TrapError::Hypervisor("guest copyout has no verified receipt".to_owned()))
}

/// The host-driven drain call's frame: drain `mm_key` on the live graph
/// `ttbr0` names, on `slot`'s EL1 stack.
pub fn drain_frame(slot: usize, mm_key: u64, ttbr0: u64) -> carrick_el1_abi::TrapFrame {
    let mut frame = carrick_el1_abi::TrapFrame {
        esr: carrick_el1_abi::DESCRIPTOR_DRAIN_ESR,
        slot: slot as u64,
        ..carrick_el1_abi::TrapFrame::default()
    };
    frame.x[carrick_el1_abi::DESCRIPTOR_DRAIN_MM] = mm_key;
    frame.x[carrick_el1_abi::DESCRIPTOR_DRAIN_TTBR0] = ttbr0;
    frame
}

/// Run the host-driven drain for another MM on a borrowed caller vCPU:
/// `set_ttbr0` installs the target's TTBR0 for exactly the call (EL1's COW
/// copy window lives in the target's tables) and restores the caller's own.
/// `admission` (the target ASID generation's residency) is armed before the
/// install, so the generation's retirement flushes whatever this vCPU cached.
/// Failing to restore the TTBR0 is fatal: the vCPU would resume in another MM.
pub(crate) fn run_foreign_drain_call(
    slot: usize,
    mm_key: u64,
    ttbr0: u64,
    admission: &mut dyn carrick_guest_mem::BorrowedTtbr0Admission,
    mut get_ttbr0: impl FnMut() -> Result<u64, TrapError>,
    mut set_ttbr0: impl FnMut(u64) -> Result<(), TrapError>,
    run: impl FnMut(u64, u64) -> Result<(), TrapError>,
) -> Result<u64, TrapError> {
    let own = get_ttbr0()?;
    admission
        .arm()
        .map_err(|error| TrapError::Hypervisor(format!("admit borrowed target ASID: {error}")))?;
    set_ttbr0(ttbr0)?;
    let answered = run_drain_call(drain_frame(slot, mm_key, ttbr0), run);
    if let Err(error) = set_ttbr0(own) {
        carrick_fatal::carrick_fatal!(
            "aarch64::descriptor_drain",
            "restore caller TTBR0 after a foreign descriptor drain: {error}"
        );
    }
    Ok(answered?.x[0])
}

/// Run the shared descriptor service using an already borrowed driving vCPU.
pub(crate) fn run_drain_call(
    frame: carrick_el1_abi::TrapFrame,
    mut run: impl FnMut(u64, u64) -> Result<(), TrapError>,
) -> Result<carrick_el1_abi::TrapFrame, TrapError> {
    let unavailable = |what: &str| TrapError::Hypervisor(format!("guest drain call: {what}"));
    let region = carrick_el1_abi::get_el1_region_host_ptr();
    if region == 0 {
        return Err(unavailable("no EL1 region"));
    }
    let offset = carrick_el1_abi::descriptor_drain_frame_offset(frame.slot as usize)
        .ok_or_else(|| unavailable("slot out of range"))?;
    // SAFETY: the EL1 region owner keeps the region alive while it is
    // installed; the header is its first 32 bytes.
    let header = carrick_el1_abi::ImageHeader::read_from_prefix(unsafe {
        std::slice::from_raw_parts(
            region as *const u8,
            std::mem::size_of::<carrick_el1_abi::ImageHeader>(),
        )
    })
    .ok_or_else(|| unavailable("no EL1 image header"))?;
    let host_frame = (region + offset as usize) as *mut carrick_el1_abi::TrapFrame;
    // SAFETY: the offset lies in this vCPU slot's own EL1 stack, below the
    // vector's trap frame, 16-aligned; this host thread owns the vCPU.
    unsafe { host_frame.write_volatile(frame) };
    run(
        carrick_el1_abi::EL1_REGION_BASE + header.entry_offset,
        carrick_el1_abi::EL1_REGION_BASE + offset,
    )?;
    // SAFETY: as above; EL1 answered in place before `hvc #1`.
    Ok(unsafe { host_frame.read_volatile() })
}
