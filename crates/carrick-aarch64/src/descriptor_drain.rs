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
    /// The same failure once another transaction of the publication
    /// applied: live state is partial, never a clean refusal.
    #[must_use]
    pub fn into_partial(self) -> Self {
        match self {
            Self::NotApplied { outcome, error } => Self::Unsettled(TrapError::Hypervisor(format!(
                "refused ({outcome:?}) after another transaction of the publication applied: \
                 {error}"
            ))),
            unsettled @ Self::Unsettled(_) => unsettled,
        }
    }

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
    /// Apply `txn` with the host as the MM's editor when this thread holds
    /// the MM's EL1 editor exclusion: EL1's executor run on the host, the
    /// receipt's ASID invalidation already done, no drain call (no VM exit
    /// beyond a required invalidation). `None`: no such exclusion here, and
    /// the EL1 drain applies it.
    fn apply_as_host(
        &mut self,
        _txn: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
        _slots: &carrick_el1_abi::DescriptorTxnSlots,
    ) -> Option<Result<carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt, TrapError>>
    {
        None
    }
}

/// The host-as-editor application every venue shares: when this thread
/// holds `txn`'s MM EL1 editor exclusion, first apply any submission already
/// waiting for the MM (in order, as EL1's drain would), then run EL1's
/// executor on the live words through `tables`, with break-before-make
/// invalidations through `maintenance` and `invalidate_asid` wherever a
/// receipt requires it, all before `check` (the venue's own failure check)
/// and before anything settles the receipt. `None` without the exclusion,
/// for a COW repoint, or when a waiting submission must be EL1's (EL1
/// copies a COW repoint's page as it applies it): the EL1 drain applies
/// the transaction and everything ahead of it.
pub fn apply_as_host_if_excluded<M>(
    tables: &crate::stage1_authority::Stage1Authority,
    slots: &carrick_el1_abi::DescriptorTxnSlots,
    txn: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
    maintenance: &M,
    // The required invalidation of a completed transaction (run now, or owed
    // to the syscall's return); `maintenance` runs break-before-make ones,
    // including the one before an emptied table is unlinked and reclaimed.
    invalidate_asid: &dyn Fn(),
    check: impl FnOnce() -> Result<(), TrapError>,
) -> Option<Result<carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt, TrapError>>
where
    M: carrick_mmu_core::aarch64::descriptor_txn::TableMaintenance + ?Sized,
{
    if matches!(
        txn.op,
        carrick_mmu_core::aarch64::descriptor_txn::DescriptorOp::CowRepoint { .. }
    ) {
        return None;
    }
    let failed = |error| {
        TrapError::Hypervisor(format!(
            "host-applied guest descriptor {:?}: {error:?}",
            txn.id
        ))
    };
    carrick_hal::el1_editor_exclusion::with_held_exclusion(txn.id.mm_key.get(), |excluded| {
        let excluded = excluded?;
        // Submissions already waiting for the MM (a frame grant EL1 has yet
        // to apply) land first, in submission order: applied after them, a
        // retirement could be overtaken by a grant's prepare onto the freed
        // range (windowcoherence lane on: "prepare ... Refused(Occupied)").
        match tables.apply_submitted_as_host(slots, excluded, maintenance, invalidate_asid) {
            Ok(true) => {}
            Ok(false) => return None,
            Err(error) => return Some(Err(failed(error))),
        }
        Some(
            tables
                .execute_guest_descriptor_txn_as_host(txn, excluded, maintenance)
                .map_err(failed)
                .and_then(|receipt| {
                    if carrick_mmu_core::aarch64::descriptor_txn::outcome_requires_invalidation(
                        &receipt.outcome,
                    ) {
                        invalidate_asid();
                    }
                    check().map(|()| receipt)
                }),
        )
    })
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
        let suspended = self.0.suspended_el1_stack_pointer()?;
        run_drain_call(frame, suspended, |entry, frame_va| {
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
/// the host holds that MM. The transactions are submitted into free slots
/// in order and ride one host-driven drain call (one VM exit, however many
/// there are; more only when the slots run out); EL1 applies every
/// submission for the MM in submission order under the host's delegated
/// custody, and each exact receipt is settled in that order. Any refusal,
/// blocked drain or unauthenticated receipt is an error; the caller decides
/// whether that is fatal. Only a call in which EL1 applied nothing and
/// refused the FIRST transaction cleanly is [`GuestPublishError::NotApplied`]:
/// once one applied, a refusal leaves the publication partial.
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
    let count = slots.as_slice().len();
    let mut verified = Vec::with_capacity(txns.len());
    let mut rest = txns;
    while let Some(first) = rest.first() {
        // The host holds the MM's EL1 editor: it applies the transaction
        // itself, in order, and settles it exactly as a drained one.
        if let Some(applied) = venue.apply_as_host(first, slots) {
            let receipt = applied.map_err(GuestPublishError::Unsettled)?;
            match venue.settle(first, &receipt) {
                Ok(receipt) => verified.push(receipt),
                Err(error) if verified.is_empty() => return Err(error),
                Err(error) => return Err(error.into_partial()),
            }
            rest = &rest[1..];
            continue;
        }
        let ttbr0 = venue.live_ttbr0()?;
        if ttbr0 & 0x0000_FFFF_FFFF_F000 != first.root.raw() {
            return Err(GuestPublishError::Unsettled(fail(format!(
                "vCPU TTBR0 0x{ttbr0:x} is not the transaction root 0x{:x}",
                first.root.raw()
            ))));
        }
        // Submit in order into free slots, as many as fit, all for one root.
        let mut submitted = Vec::new();
        let mut cursor = 0;
        for txn in rest {
            if txn.root != first.root || txn.id.mm_key != first.id.mm_key {
                break;
            }
            let Some(used) = (cursor..count)
                .map(|offset| (own + offset) % count)
                .find(|&slot| slots.submit(slot, txn))
            else {
                break;
            };
            cursor = (used + count - own) % count + 1;
            submitted.push((used, txn));
        }
        if submitted.is_empty() {
            return Err(fail("every descriptor slot is busy".to_owned()).into());
        }
        let withdraw = |from: &[(
            usize,
            &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
        )]| {
            for &(used, txn) in from {
                let _ = slots.withdraw(used, txn.id);
            }
        };
        let frame = drain_frame(own, first.id.mm_key.get(), ttbr0);
        let answered = match venue.drain_call(frame) {
            Ok(answered) => answered,
            Err(error) => {
                withdraw(&submitted);
                return Err(error.into());
            }
        };
        if answered.x[0] & carrick_el1_abi::DESCRIPTOR_DRAIN_BLOCKED != 0 {
            withdraw(&submitted);
            return Err(fail("EL1 could not claim the MM".to_owned()).into());
        }
        // Settle every receipt in order; consume them all even after an
        // error so no slot keeps this call's receipt.
        let mut first_error = None;
        let mut applied_after_error = false;
        for &(used, txn) in &submitted {
            let Some(receipt) = slots.take_receipt(used, txn.id) else {
                let _ = slots.withdraw(used, txn.id);
                first_error.get_or_insert(GuestPublishError::Unsettled(fail(format!(
                    "no receipt for {:?}",
                    txn.id
                ))));
                continue;
            };
            match venue.settle(txn, &receipt) {
                Ok(receipt) if first_error.is_none() => verified.push(receipt),
                Ok(_) => applied_after_error = true,
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        if let Some(error) = first_error {
            return Err(if verified.is_empty() && !applied_after_error {
                error
            } else {
                error.into_partial()
            });
        }
        rest = &rest[submitted.len()..];
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
    get_ttbr0: impl FnMut() -> Result<u64, TrapError>,
    set_ttbr0: impl FnMut(u64) -> Result<(), TrapError>,
    suspended_sp: Option<u64>,
    run: impl FnMut(u64, u64) -> Result<(), TrapError>,
) -> Result<u64, TrapError> {
    Ok(run_foreign_service_call(
        drain_frame(slot, mm_key, ttbr0),
        ttbr0,
        admission,
        get_ttbr0,
        set_ttbr0,
        suspended_sp,
        run,
    )?
    .x[0])
}

/// Exact borrowed-root envelope shared by descriptor drains and UserTransfer.
pub(crate) fn run_foreign_service_call(
    frame: carrick_el1_abi::TrapFrame,
    ttbr0: u64,
    admission: &mut dyn carrick_guest_mem::BorrowedTtbr0Admission,
    mut get_ttbr0: impl FnMut() -> Result<u64, TrapError>,
    mut set_ttbr0: impl FnMut(u64) -> Result<(), TrapError>,
    suspended_sp: Option<u64>,
    run: impl FnMut(u64, u64) -> Result<(), TrapError>,
) -> Result<carrick_el1_abi::TrapFrame, TrapError> {
    let own = get_ttbr0()?;
    admission
        .arm()
        .map_err(|error| TrapError::Hypervisor(format!("admit borrowed target ASID: {error}")))?;
    set_ttbr0(ttbr0)?;
    let answered = run_drain_call(frame, suspended_sp, run);
    if let Err(error) = set_ttbr0(own) {
        carrick_fatal::carrick_fatal!(
            "aarch64::descriptor_drain",
            "restore caller TTBR0 after foreign service: {error}"
        );
    }
    answered
}

/// Run the shared descriptor service using an already borrowed driving vCPU.
/// `suspended_sp` is the vCPU's EL1 stack pointer when the call interrupts
/// EL1 mid-operation (a stage-1 COW fault EL1 took): the frame and the
/// call's stack go below it, never over the suspended operation's frames.
pub(crate) fn run_drain_call(
    frame: carrick_el1_abi::TrapFrame,
    suspended_sp: Option<u64>,
    mut run: impl FnMut(u64, u64) -> Result<(), TrapError>,
) -> Result<carrick_el1_abi::TrapFrame, TrapError> {
    let unavailable = |what: &str| TrapError::Hypervisor(format!("guest drain call: {what}"));
    let region = carrick_el1_abi::get_el1_region_host_ptr();
    if region == 0 {
        return Err(unavailable("no EL1 region"));
    }
    let offset =
        carrick_el1_abi::descriptor_drain_frame_offset_below(frame.slot as usize, suspended_sp)
            .ok_or_else(|| unavailable("no room below the vCPU's EL1 stack"))?;
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
    // vector's trap frame and any suspended EL1 stack, 16-aligned; this host
    // thread owns the vCPU.
    unsafe { host_frame.write_volatile(frame) };
    run(
        carrick_el1_abi::EL1_REGION_BASE + header.entry_offset,
        carrick_el1_abi::EL1_REGION_BASE + offset,
    )?;
    // SAFETY: as above; EL1 answered in place before `hvc #1`.
    Ok(unsafe { host_frame.read_volatile() })
}

/// The production venue for an EL1 frame grant served outside the mailbox
/// (a host copyout into never-touched memory): the engine's own prepare,
/// publish, complete and rollback, and the guest lane's transaction applied
/// on this vCPU now through the shared drain.
pub struct EngineGrantVenue<'a, E>(pub &'a mut E);

impl<E: ThreadedEngine> carrick_hal::threaded::El1FrameGrantVenue for EngineGrantVenue<'_, E> {
    fn prepare(
        &mut self,
        request: carrick_hal::El1FrameGrantRequest,
    ) -> Result<Option<carrick_hal::El1FrameGrantReady>, TrapError> {
        self.0.prepare_el1_frame_grant(request)
    }

    fn publish(
        &mut self,
        grant: carrick_hal::threaded::El1FrameGrantPublication,
    ) -> Result<carrick_hal::threaded::El1FrameGrantPublished, TrapError> {
        self.0.publish_el1_frame_grant(grant)
    }

    fn apply_guest_publication(
        &mut self,
        txn: carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
    ) -> Result<carrick_mmu_core::aarch64::descriptor_txn::VerifiedDescriptorReceipt, TrapError>
    {
        let slots = carrick_el1_abi::descriptor_txn_slots_host().ok_or_else(|| {
            TrapError::Hypervisor("host copyout grant has no descriptor slots".to_owned())
        })?;
        match apply_guest_descriptor_txns_now(&mut EngineDrainVenue(&mut *self.0), slots, &[txn]) {
            Ok(mut receipts) => receipts.pop().ok_or_else(|| {
                TrapError::Hypervisor("host copyout grant has no verified receipt".to_owned())
            }),
            Err(GuestPublishError::NotApplied { error, .. }) => Err(error),
            // EL1 may have stored part of the grant: its backing can be
            // neither rolled back nor committed.
            Err(GuestPublishError::Unsettled(error)) => carrick_fatal::carrick_fatal!(
                "hvpatch::host_copyout_grant",
                "host copyout grant publication is unsettled: {error}"
            ),
        }
    }

    fn settle_receipt(
        &mut self,
        txn: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
        receipt: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt,
    ) -> Result<carrick_mmu_core::aarch64::descriptor_txn::VerifiedDescriptorReceipt, TrapError>
    {
        self.0.settle_el1_descriptor_receipt(txn, receipt)
    }

    fn complete(
        &mut self,
        grant: carrick_hal::threaded::El1FrameGrantRollback,
    ) -> Result<(), TrapError> {
        self.0.complete_el1_frame_grant(grant)
    }

    fn roll_back(
        &mut self,
        grant: carrick_hal::threaded::El1FrameGrantRollback,
    ) -> Result<bool, TrapError> {
        self.0.roll_back_el1_frame_grant(grant)
    }
}
