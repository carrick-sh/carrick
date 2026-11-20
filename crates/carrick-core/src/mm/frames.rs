//! One lazy grant authentication, logical residency publication and settlement.
use crate::mm::reservation::{ReservationFaultPlan, ReservationGeometry, ReservationPolicy};
use crate::mm::transaction::{MmError, MmPortal, OwnerVenue};
use carrick_core_abi::*;
use carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords;
use carrick_mmu_core::owner_mmu::{OwnerGrantMmu, OwnerMmu};
use carrick_sched_core::SpaceEditor;

/// The one descriptor-authoritative span selected for a frame grant.
///
/// Callers must move this value into their semantic plan before adopting
/// provenance or preparing backing. Keeping the selected range typed avoids
/// carrying an unnarrowed plan beside a narrowed service request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelectedBackingPlan {
    range: ReservationRange,
    fault_page: u64,
}

/// A publication refusal that may be retried only after an observed change.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationNotNow {
    /// Another MM owner holds the authority needed by this publication.
    Contended,
    /// A bounded store must grow, or the next plan must be strictly smaller.
    Capacity(carrick_mmu_core::descriptor_refusal::DescriptorRefusal),
}

/// The exhaustive disposition of a descriptor publication refusal.
///
/// This type prevents the host lane from treating every refusal as an
/// instruction rerun. Only `NotNow` may retain an owned continuation;
/// deterministic refusals are terminal for the request, while an occupied
/// fault page must use the inherited-Prepared supply path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationDecline {
    NotNow(PublicationNotNow),
    InheritedPrepared,
    Terminal(PublicationTerminal),
}

/// A deterministic publication refusal. Repeating the same request cannot
/// change this answer, so the fault entry must publish a terminal outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationTerminal {
    Descriptor(carrick_mmu_core::descriptor_refusal::DescriptorRefusal),
    PublishUnsupported,
}

/// The non-successful mailbox completion presented to the shared publication
/// policy.  The carrier translates the wire completion into this type, then
/// only executes the returned action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationCompletion {
    Declined(Option<PublicationDecline>),
    SlotNotWorking,
    StaleRequest,
    InvalidReady,
}

/// A broken mailbox invariant.  These are the only publication completions
/// that are fatal; descriptor refusals remain typed policy outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationInvariant {
    MissingDecline,
    SlotNotWorking,
    StaleRequest,
    InvalidReady,
}

/// The one ISA-neutral next action for a refused frame-grant publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicationNextAction {
    Fatal(PublicationInvariant),
    ParkOnMmRelease { mm_key: u64 },
    RerunWith(SelectedBackingPlan),
    ReplanInheritedPrepared,
    TerminalRefusal(PublicationTerminal),
}

/// Decide a refused publication without performing carrier work.
///
/// Capacity gets at most one strictly smaller attempt because a one-page plan
/// has no fallback.  Contention retains the MM identity needed by the owned
/// continuation, and deterministic answers never become instruction reruns.
pub fn publication_next_action(
    completion: PublicationCompletion,
    selected: SelectedBackingPlan,
    mm_key: u64,
) -> PublicationNextAction {
    let decline = match completion {
        PublicationCompletion::Declined(Some(decline)) => decline,
        PublicationCompletion::Declined(None) => {
            return PublicationNextAction::Fatal(PublicationInvariant::MissingDecline);
        }
        PublicationCompletion::SlotNotWorking => {
            return PublicationNextAction::Fatal(PublicationInvariant::SlotNotWorking);
        }
        PublicationCompletion::StaleRequest => {
            return PublicationNextAction::Fatal(PublicationInvariant::StaleRequest);
        }
        PublicationCompletion::InvalidReady => {
            return PublicationNextAction::Fatal(PublicationInvariant::InvalidReady);
        }
    };
    match decline {
        PublicationDecline::NotNow(PublicationNotNow::Contended) => {
            PublicationNextAction::ParkOnMmRelease { mm_key }
        }
        PublicationDecline::NotNow(PublicationNotNow::Capacity(reason)) => selected
            .capacity_fallback()
            .map(PublicationNextAction::RerunWith)
            .unwrap_or(PublicationNextAction::TerminalRefusal(
                PublicationTerminal::Descriptor(reason),
            )),
        PublicationDecline::InheritedPrepared => PublicationNextAction::ReplanInheritedPrepared,
        PublicationDecline::Terminal(refusal) => PublicationNextAction::TerminalRefusal(refusal),
    }
}

impl PublicationDecline {
    pub fn from_descriptor(
        reason: carrick_mmu_core::descriptor_refusal::DescriptorRefusal,
    ) -> Self {
        use carrick_mmu_core::descriptor_refusal::DescriptorRefusal;
        match reason {
            DescriptorRefusal::Contended => Self::NotNow(PublicationNotNow::Contended),
            DescriptorRefusal::TablesExhausted
            | DescriptorRefusal::JournalCapacity
            | DescriptorRefusal::ResidencyCapacity => {
                Self::NotNow(PublicationNotNow::Capacity(reason))
            }
            DescriptorRefusal::Occupied | DescriptorRefusal::AlreadyValid => {
                Self::InheritedPrepared
            }
            _ => Self::Terminal(PublicationTerminal::Descriptor(reason)),
        }
    }

    pub const fn unsupported() -> Self {
        Self::Terminal(PublicationTerminal::PublishUnsupported)
    }
}

#[cfg(test)]
mod publication_decline_tests {
    use super::{PublicationDecline, PublicationNotNow, SelectedBackingPlan};
    use carrick_core_abi::ReservationRange;
    use carrick_mmu_core::descriptor_refusal::DescriptorRefusal;

    #[test]
    fn publication_declines_distinguish_progress_from_terminal_refusals() {
        assert_eq!(
            PublicationDecline::from_descriptor(DescriptorRefusal::Contended),
            PublicationDecline::NotNow(PublicationNotNow::Contended),
        );
        for reason in [
            DescriptorRefusal::TablesExhausted,
            DescriptorRefusal::JournalCapacity,
            DescriptorRefusal::ResidencyCapacity,
        ] {
            assert_eq!(
                PublicationDecline::from_descriptor(reason),
                PublicationDecline::NotNow(PublicationNotNow::Capacity(reason)),
            );
        }
        assert_eq!(
            PublicationDecline::from_descriptor(DescriptorRefusal::Occupied),
            PublicationDecline::InheritedPrepared,
        );
        for reason in [
            DescriptorRefusal::StaleRoot,
            DescriptorRefusal::WrongMm,
            DescriptorRefusal::Malformed,
            DescriptorRefusal::BadEncoding,
            DescriptorRefusal::NotPrivateAnonymous,
            DescriptorRefusal::PermissionWidening,
            DescriptorRefusal::CowArmed,
            DescriptorRefusal::ExcludedOutput,
            DescriptorRefusal::CarrickOwnedWindow,
        ] {
            assert_eq!(
                PublicationDecline::from_descriptor(reason),
                PublicationDecline::Terminal(super::PublicationTerminal::Descriptor(reason)),
            );
        }
        assert_eq!(
            PublicationDecline::unsupported(),
            PublicationDecline::Terminal(super::PublicationTerminal::PublishUnsupported),
        );
    }

    #[test]
    fn capacity_fallback_is_one_strictly_smaller_fault_page() {
        let admitted = ReservationRange::new(0x4000, 0x8000).unwrap();
        let selected = SelectedBackingPlan::new(admitted, admitted, 0x6000).unwrap();
        let fallback = selected.capacity_fallback().unwrap();
        assert_eq!(
            fallback.range(),
            ReservationRange::new(0x6000, 0x7000).unwrap()
        );
        assert_eq!(fallback.fault_page(), 0x6000);
        assert!(fallback.capacity_fallback().is_none());
    }
}

impl SelectedBackingPlan {
    /// Authenticate a selected span against the admitted request and its
    /// page-aligned fault identity. Callers cannot manufacture a plan for a
    /// neighbouring request or widen it after the descriptor walk.
    pub fn new(
        admitted: ReservationRange,
        range: ReservationRange,
        fault_page: u64,
    ) -> Result<Self, carrick_mmu_core::descriptor_refusal::DescriptorRefusal> {
        use carrick_mmu_core::descriptor_refusal::DescriptorRefusal;
        if fault_page & 0xfff != 0
            || range.start() < admitted.start()
            || range.end() > admitted.end()
            || !(range.start() <= fault_page && fault_page < range.end())
        {
            return Err(DescriptorRefusal::BadRange);
        }
        Ok(Self { range, fault_page })
    }

    /// Return the fault page as the one strictly bounded capacity fallback.
    ///
    /// A publication venue may use this only after refusing the selected
    /// multi-page span for capacity.  The returned plan retains the admitted
    /// fault identity while guaranteeing that the next attempt is smaller;
    /// a one-page selection has no smaller retry and therefore returns
    /// `None` instead of permitting an unbounded retry loop.
    pub fn capacity_fallback(self) -> Option<Self> {
        const PAGE_SIZE: u64 = 4096;
        if self.range.len() <= PAGE_SIZE {
            return None;
        }
        let range = ReservationRange::new(self.fault_page, self.fault_page + PAGE_SIZE)?;
        Some(Self {
            range,
            fault_page: self.fault_page,
        })
    }

    pub fn range(self) -> ReservationRange {
        self.range
    }

    pub fn fault_page(self) -> u64 {
        self.fault_page
    }
}

/// Select the contiguous unused part of an admitted window containing the
/// fault. The caller retains this MM's editor while reading descriptors.
/// Residency is not a census of inherited live or prepared leaves.
pub fn select_backing_window<B: OwnerGrantMmu, W: LiveDescriptorWords + ?Sized>(
    words: &W,
    root: u64,
    mut window: PortalGrantWindow,
) -> Result<PortalGrantWindow, carrick_mmu_core::descriptor_refusal::DescriptorRefusal> {
    use carrick_mmu_core::descriptor_refusal::DescriptorRefusal;
    if !window.valid() {
        return Err(DescriptorRefusal::BadRange);
    }
    let range = select_backing_span::<B, W>(words, root, window.range, window.fault_page)?;
    let start = range.start();
    if let Some(backing) = window.host_backing {
        window.host_backing = Some(
            backing
                .advance(start - window.range.start())
                .ok_or(DescriptorRefusal::BadRange)?,
        );
    }
    window.range = range;
    Ok(window)
}

/// Select the authoritative descriptor-free span containing `fault_page`.
/// Both host and in-guest planners use this one live-descriptor walk.
pub fn select_backing_span<B: OwnerGrantMmu, W: LiveDescriptorWords + ?Sized>(
    words: &W,
    root: u64,
    range: ReservationRange,
    fault_page: u64,
) -> Result<ReservationRange, carrick_mmu_core::descriptor_refusal::DescriptorRefusal> {
    select_backing_plan::<B, W>(words, root, range, fault_page).map(SelectedBackingPlan::range)
}

/// Select the single plan that every later grant phase must consume.
pub fn select_backing_plan<B: OwnerGrantMmu, W: LiveDescriptorWords + ?Sized>(
    words: &W,
    root: u64,
    range: ReservationRange,
    fault_page: u64,
) -> Result<SelectedBackingPlan, carrick_mmu_core::descriptor_refusal::DescriptorRefusal> {
    use carrick_mmu_core::descriptor_refusal::DescriptorRefusal;
    let mut start = range.start();
    let mut end = range.end();
    for page in (start..end).step_by(4096) {
        if grant_page_available::<B, _>(words, root, page)? {
            continue;
        }
        if page == fault_page {
            let root = B::root(root).map_err(|_| DescriptorRefusal::StaleRoot)?;
            return match B::translate(
                words,
                root,
                carrick_guest_arch::UserVa::new(page),
                carrick_mmu_core::aarch64::LeafAccess::Read,
                false,
            ) {
                Ok(Some(_)) => Err(DescriptorRefusal::AlreadyValid),
                Ok(None) => Err(DescriptorRefusal::Occupied),
                Err(_) => Err(DescriptorRefusal::Malformed),
            };
        }
        if page < fault_page {
            start = page + 4096;
        } else {
            end = page;
            break;
        }
    }
    let selected = ReservationRange::new(start, end).ok_or(DescriptorRefusal::BadRange)?;
    SelectedBackingPlan::new(range, selected, fault_page)
}

fn grant_page_available<B: OwnerGrantMmu, W: LiveDescriptorWords + ?Sized>(
    words: &W,
    root: u64,
    va: u64,
) -> Result<bool, carrick_mmu_core::descriptor_refusal::DescriptorRefusal> {
    use carrick_mmu_core::descriptor_refusal::DescriptorRefusal;
    let mut table = B::root(root)
        .map_err(|_| DescriptorRefusal::StaleRoot)?
        .address()
        .raw();
    for (level, shift) in [39, 30, 21, 12].into_iter().enumerate() {
        let word = words
            .load(table + ((va >> shift) & 511) * 8)
            .map_err(|_| DescriptorRefusal::TableOutsidePrimary)?;
        if word == 0 {
            return Ok(true);
        }
        if !B::is_table(word, level) {
            return Ok(level != 0 && B::is_retired(word));
        }
        table = word & B::ADDRESS_MASK;
    }
    Ok(false)
}

/// An editor retained from target admission through descriptor completion.
/// The caller owns the immutable window snapshot; authentication and execution
/// borrow that same snapshot instead of copying it onto each nested frame.
pub struct GrantTarget<
    'a,
    C: Copy + Send + Sync + zerocopy::FromZeros = carrick_sched_core::ThreadCtx,
> {
    window: &'a carrick_core_abi::PortalGrantWindow,
    grant: carrick_sched_core::SpaceGrant,
    _editor: SpaceEditor<'a, C>,
    authenticated: bool,
}

impl<'a, C: Copy + Send + Sync + zerocopy::FromZeros> GrantTarget<'a, C> {
    pub fn grant(&self) -> carrick_sched_core::SpaceGrant {
        self.grant
    }
    fn into_parts(
        self,
    ) -> (
        &'a PortalGrantWindow,
        carrick_sched_core::SpaceGrant,
        SpaceEditor<'a, C>,
        bool,
    ) {
        (self.window, self.grant, self._editor, self.authenticated)
    }
}

pub fn grant_target<
    'a,
    P: PinnedMetadataExtent,
    Policy: ReservationPolicy,
    Geometry: ReservationGeometry,
    Venue: OwnerVenue<Context>,
    B: OwnerMmu,
    Context: Copy + Send + Sync + zerocopy::FromZeros,
>(
    portal: &'a MmPortal<'_, P, Policy, Geometry, Venue, B, Context>,
    window: &'a carrick_core_abi::PortalGrantWindow,
    worker: u32,
) -> Result<GrantTarget<'a, Context>, MmError> {
    if window.operation.carrier != portal.carrier {
        return Err(MmError::Stale);
    }
    // SAFETY: this is only a candidate identity. editor_for authenticates its
    // exact notification source before admitting it; root_for and the fault
    // plan below validate incarnation, generation, range, protection and source.
    let handle = unsafe {
        El1MmHandle::from_admitted_owner(
            window.operation.carrier,
            window.operation.mm,
            window.operation.incarnation,
        )
    };
    let gate = portal.observe_wait(handle, carrick_core_abi::PortalWaitCause::Gate)?;
    let editor = portal.editor_for(handle, worker)?;
    let index = portal
        .spaces
        .find(window.operation.mm.raw())
        .ok_or(MmError::Stale)?;
    // A host can raise the gate after admission, then wait for this editor.
    // Observe before probing and release the editor before parking that wait.
    let grant = portal
        .spaces
        .grant(index, window.operation.mm.raw())
        .ok_or_else(|| gate.map_or(MmError::Busy, MmError::Wait))?;
    let mut root = portal.root_for(handle, worker)?;
    authenticate_target(window, grant, editor, &mut root)
}

/// Admit a grant through an already borrowed owner root and its typed
/// scheduler source. The root and editor retain the same parked-context ABI;
/// publication uses the same authentication as the portal owner below.
pub fn grant_target_in<
    'a,
    Policy: ReservationPolicy,
    Geometry: ReservationGeometry,
    C: Copy + Send + Sync + zerocopy::FromZeros,
>(
    carrier: core::num::NonZeroU64,
    window: &'a PortalGrantWindow,
    spaces: carrick_sched_core::spaces::notification::SpaceAccess<'a, C>,
    worker: u32,
    root: &mut crate::mm::reservation::Reservations<'_, Policy, Geometry, C>,
) -> Result<GrantTarget<'a, C>, MmError> {
    if carrier != window.operation.carrier || root.mm() != window.operation.mm {
        return Err(MmError::Stale);
    }
    let index = spaces
        .find(window.operation.mm.raw())
        .ok_or(MmError::Stale)?;
    let owner = core::num::NonZeroU64::new(u64::from(worker) + 1).ok_or(MmError::Invalid)?;
    let editor = spaces
        .try_begin_edit(index, window.operation.mm.raw(), owner)
        .ok_or(MmError::Busy)?;
    let grant = spaces
        .grant(index, window.operation.mm.raw())
        .ok_or(MmError::Busy)?;
    authenticate_target(window, grant, editor, root)
}

fn authenticate_target<
    'a,
    Policy: ReservationPolicy,
    Geometry: ReservationGeometry,
    C: Copy + Send + Sync + zerocopy::FromZeros,
>(
    window: &'a PortalGrantWindow,
    grant: carrick_sched_core::SpaceGrant,
    editor: SpaceEditor<'a, C>,
    root: &mut crate::mm::reservation::Reservations<'_, Policy, Geometry, C>,
) -> Result<GrantTarget<'a, C>, MmError> {
    if root.mm() != window.operation.mm
        || root.incarnation().raw() != window.operation.incarnation.get()
    {
        return Err(MmError::Stale);
    }
    let authenticated = root.authenticate_fork_transfer_fault(
        ReservationFaultPlan {
            mm: window.operation.mm,
            mapping_incarnation: window.mapping_incarnation,
            range: window.range,
            protection: window.protection,
            fault_page: window.fault_page,
        },
        window.host_backing,
        window.fork_sequence,
    );
    Ok(GrantTarget {
        window,
        grant,
        _editor: editor,
        authenticated,
    })
}

/// Outcome of one grant-application attempt under the exact MM editor.
/// `ResidencyCapacity` releases both the descriptor claim (`SUBMITTED`) and
/// the MM editor without publishing a terminal receipt so the caller can grow
/// carrier residency storage outside the editor or park on a typed not-now.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum GrantApplyOutcome {
    Empty,
    Completed(carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt),
    ResidencyCapacity { observed_extensions: usize },
}

/// Owned continuation returned when residency growth is temporarily refused
/// (metadata allocation pressure, concurrent segment publisher, or full
/// segment directory). Holds no MM editor or descriptor claim; the submission
/// remains `SUBMITTED` in the grant slot so the caller can enrol on the next
/// retirement or metadata progress, probe once via [`Self::ready_to_retry`],
/// and rerun without returning a fatal error or errno.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct ResidencyGrowthContinuation {
    pub observed_extensions: usize,
    pub observed_retirement: u64,
    pub refusal: ResidencyGrowthRefusal,
    pub owner_wait: Option<PortalOwnerWait>,
}

impl ResidencyGrowthContinuation {
    /// Probe once after enrolling on the next retirement or metadata progress.
    /// Returns true if a retirement or segment publication already advanced
    /// past the observed refusal.
    pub fn ready_to_retry(&self, table: &FrameGrantResidencyTable) -> bool {
        table.extension_count() > self.observed_extensions
            || table.retirement_epoch() != self.observed_retirement
            || (self.refusal == ResidencyGrowthRefusal::Publishing && !table.is_publishing())
    }
}

/// Outcome of serving one owner grant with automatic residency growth.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum GrantServeOutcome {
    Empty,
    Completed(carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt),
    NotNow(ResidencyGrowthContinuation),
}

/// Attempt to grow residency outside any MM editor; if growth is refused,
/// package the typed not-now continuation so the caller can probe once for a
/// racing retirement/publication or park on its wait source.
#[inline(never)]
pub fn grow_residency_or_not_now(
    table: &FrameGrantResidencyTable,
    allocator: &impl ReservationMetadataAllocator,
    observed_extensions: usize,
    observed_retirement: u64,
    owner_wait: Option<PortalOwnerWait>,
) -> Result<(), ResidencyGrowthContinuation> {
    match table.grow(allocator, observed_extensions) {
        Ok(()) => Ok(()),
        Err(refusal) => Err(ResidencyGrowthContinuation {
            observed_extensions,
            observed_retirement,
            refusal,
            owner_wait,
        }),
    }
}

/// Revalidate an owner-selected lazy window and apply its isolated submission,
/// growing the carrier residency table outside the MM editor when existing
/// segments are saturated. A refused growth returns a typed
/// [`GrantServeOutcome::NotNow`] continuation with both the MM editor and
/// descriptor claim released.
///
/// # Safety
/// `table` must live in the same guest allocator venue as `allocator`: every
/// published segment address must remain mapped in this venue for the call.
#[allow(clippy::too_many_arguments)]
pub unsafe fn serve_grant_with_venue<
    P: PinnedMetadataExtent,
    Policy: ReservationPolicy,
    Geometry: ReservationGeometry,
    Venue: OwnerVenue<Context>,
    B: OwnerGrantMmu,
    Context: Copy + Send + Sync + zerocopy::FromZeros,
>(
    portal: &MmPortal<'_, P, Policy, Geometry, Venue, B, Context>,
    slot: &carrick_core_abi::PortalGrantSlot,
    table: &FrameGrantResidencyTable,
    allocator: &impl ReservationMetadataAllocator,
    worker: u32,
    mut apply_in_venue: impl FnMut(
        GrantTarget<'_, Context>,
        &FrameGrantResidencyTable<ResidencyRows<'_>>,
    ) -> Result<GrantApplyOutcome, MmError>,
) -> Result<GrantServeOutcome, MmError> {
    let Some(window) = slot.window() else {
        return Ok(GrantServeOutcome::Empty);
    };
    // SAFETY: candidate handle authenticated by `observe_wait` and
    // `grant_target` below before any descriptor or residency effect.
    let handle = unsafe {
        El1MmHandle::from_admitted_owner(
            window.operation.carrier,
            window.operation.mm,
            window.operation.incarnation,
        )
    };
    for attempt in 0..2 {
        let observed_retirement = table.retirement_epoch();
        let owner_wait =
            portal.observe_wait(handle, carrick_core_abi::PortalWaitCause::Metadata)?;
        let target = grant_target(portal, &window, worker)?;
        // SAFETY: caller guarantees `table` is in `allocator`'s guest venue.
        let view = unsafe { table.guest_view() };
        match apply_in_venue(target, &view)? {
            GrantApplyOutcome::Completed(receipt) => {
                return Ok(GrantServeOutcome::Completed(receipt));
            }
            GrantApplyOutcome::Empty => return Ok(GrantServeOutcome::Empty),
            GrantApplyOutcome::ResidencyCapacity {
                observed_extensions,
            } => {
                // Both the descriptor claim and MM editor are released before
                // asking the carrier metadata allocator for another segment.
                match grow_residency_or_not_now(
                    table,
                    allocator,
                    observed_extensions,
                    observed_retirement,
                    owner_wait,
                ) {
                    Ok(()) => continue,
                    Err(continuation) => {
                        if attempt == 0 && continuation.ready_to_retry(table) {
                            continue;
                        }
                        return Ok(GrantServeOutcome::NotNow(continuation));
                    }
                }
            }
        }
    }
    let owner_wait = portal.observe_wait(handle, carrick_core_abi::PortalWaitCause::Metadata)?;
    Ok(GrantServeOutcome::NotNow(ResidencyGrowthContinuation {
        observed_extensions: table.extension_count(),
        observed_retirement: table.retirement_epoch(),
        refusal: ResidencyGrowthRefusal::Publishing,
        owner_wait,
    }))
}

/// Revalidate an owner-selected lazy window and apply its isolated submission
/// over an existing [`LiveDescriptorWords`] view, growing residency storage
/// outside the MM editor when needed.
///
/// # Safety
/// `table` must live in the same guest allocator venue as `allocator`.
#[allow(clippy::too_many_arguments)]
pub unsafe fn serve_grant_with_allocator<
    P: PinnedMetadataExtent,
    Policy: ReservationPolicy,
    Geometry: ReservationGeometry,
    Venue: OwnerVenue<Context>,
    B: OwnerGrantMmu,
    W: LiveDescriptorWords + ?Sized,
    Context: Copy + Send + Sync + zerocopy::FromZeros,
>(
    portal: &MmPortal<'_, P, Policy, Geometry, Venue, B, Context>,
    slot: &carrick_core_abi::PortalGrantSlot,
    words: &W,
    table: &FrameGrantResidencyTable,
    allocator: &impl ReservationMetadataAllocator,
    worker: u32,
    mut invalidate: impl FnMut(),
) -> Result<GrantServeOutcome, MmError> {
    // SAFETY: forwarded from caller.
    unsafe {
        serve_grant_with_venue(
            portal,
            slot,
            table,
            allocator,
            worker,
            |target, residency| {
                Ok(try_apply_grant::<B, _>(
                    slot,
                    words,
                    residency,
                    target,
                    &mut invalidate,
                ))
            },
        )
    }
}

/// Revalidate an owner-selected lazy window and apply its isolated submission
/// through the existing descriptor executor. Normal descriptor drains cannot
/// see the submission before this exact-generation check.
pub fn serve_grant<
    P: PinnedMetadataExtent,
    Policy: ReservationPolicy,
    Geometry: ReservationGeometry,
    Venue: OwnerVenue<Context>,
    B: OwnerGrantMmu,
    W: LiveDescriptorWords + ?Sized,
    Context: Copy + Send + Sync + zerocopy::FromZeros,
>(
    portal: &MmPortal<'_, P, Policy, Geometry, Venue, B, Context>,
    slot: &carrick_core_abi::PortalGrantSlot,
    words: &W,
    residency: &FrameGrantResidencyTable<impl FrameGrantResidencyAccess>,
    worker: u32,
    invalidate: impl FnOnce(),
) -> Result<Option<carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt>, MmError> {
    let Some(window) = slot.window() else {
        return Ok(None);
    };
    let target = grant_target(portal, &window, worker)?;
    Ok(apply_grant::<B, _>(
        slot, words, residency, target, invalidate,
    ))
}

/// Attempt one grant application under `target`'s MM editor. On residency
/// capacity exhaustion, releases both the descriptor claim (`SUBMITTED`) and
/// the MM editor without publishing a terminal refusal receipt.
pub fn try_apply_grant<B: OwnerGrantMmu, W: LiveDescriptorWords + ?Sized>(
    slot: &carrick_core_abi::PortalGrantSlot,
    words: &W,
    residency: &FrameGrantResidencyTable<impl FrameGrantResidencyAccess>,
    target: GrantTarget<'_, impl Copy + Send + Sync + zerocopy::FromZeros>,
    invalidate: impl FnOnce(),
) -> GrantApplyOutcome {
    apply_grant_inner::<B, _>(slot, words, residency, target, invalidate, true)
}

pub fn apply_grant<B: OwnerGrantMmu, W: LiveDescriptorWords + ?Sized>(
    slot: &carrick_core_abi::PortalGrantSlot,
    words: &W,
    residency: &FrameGrantResidencyTable<impl FrameGrantResidencyAccess>,
    target: GrantTarget<'_, impl Copy + Send + Sync + zerocopy::FromZeros>,
    invalidate: impl FnOnce(),
) -> Option<carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt> {
    match apply_grant_inner::<B, _>(slot, words, residency, target, invalidate, false) {
        GrantApplyOutcome::Completed(receipt) => Some(receipt),
        GrantApplyOutcome::Empty | GrantApplyOutcome::ResidencyCapacity { .. } => None,
    }
}

#[inline(never)]
fn apply_grant_inner<B: OwnerGrantMmu, W: LiveDescriptorWords + ?Sized>(
    slot: &carrick_core_abi::PortalGrantSlot,
    words: &W,
    residency: &FrameGrantResidencyTable<impl FrameGrantResidencyAccess>,
    target: GrantTarget<'_, impl Copy + Send + Sync + zerocopy::FromZeros>,
    invalidate: impl FnOnce(),
    release_on_capacity: bool,
) -> GrantApplyOutcome {
    use carrick_mmu_core::aarch64::descriptor_txn::{
        DescriptorOp, DescriptorOutcome, DescriptorRefusal,
    };
    let (window, grant, editor, authenticated) = target.into_parts();
    let mm = window.operation.mm;
    let Some(claimed) = slot.descriptor().claim_for_mm(mm.raw()) else {
        return GrantApplyOutcome::Empty;
    };
    use carrick_mmu_core::live_descriptor_words::{GrantRefusalTrace, ObservedDescriptorWords};

    let trace_requested = claimed.grant_trace_requested();
    let trace = ::core::cell::Cell::new(GrantRefusalTrace::default());
    let observe = |event| {
        let mut sample = trace.get();
        sample.record(event);
        trace.set(sample);
    };
    let words = &ObservedDescriptorWords {
        words,
        observe: trace_requested.then_some(&observe as &dyn Fn(_)),
    };
    enum OutcomeOrCapacity {
        Terminal(DescriptorOutcome),
        Capacity(usize),
    }
    let outcome = (|| {
        let Ok(txn) = claimed.txn() else {
            return OutcomeOrCapacity::Terminal(DescriptorOutcome::Refused(
                DescriptorRefusal::BadEncoding,
            ));
        };
        if !authenticated {
            return OutcomeOrCapacity::Terminal(DescriptorOutcome::Refused(
                DescriptorRefusal::StaleRoot,
            ));
        }
        if let DescriptorOp::Publish { span, access, .. } = txn.op {
            // This reply owns existing fork custody, not a fresh grant. The
            // descriptor executor checks the exact output and consumes the
            // leaf's deferred fork COW: the output is published COW-armed,
            // so the first write from either process copies it.
            let permitted = match access {
                carrick_mmu_core::aarch64::LeafAccess::Read => {
                    window
                        .protection
                        .permits(carrick_core_abi::ReservationProtection::READ)
                        || window
                            .protection
                            .permits(carrick_core_abi::ReservationProtection::WRITE)
                }
                carrick_mmu_core::aarch64::LeafAccess::Execute => window
                    .protection
                    .permits(carrick_core_abi::ReservationProtection::EXECUTE),
                carrick_mmu_core::aarch64::LeafAccess::Write => false,
            };
            if window.range.len() != 4096
                || window.range.start() != window.fault_page
                || span.va != window.fault_page
                || span.len != 4096
                || !txn.tables.as_slice().is_empty()
                || !permitted
            {
                return OutcomeOrCapacity::Terminal(DescriptorOutcome::Refused(
                    DescriptorRefusal::BadEncoding,
                ));
            }
            // Another publisher may have made this instruction usable while
            // the owner retained its reply, including at a different output
            // after COW. Do not turn that valid publication into WrongBacking
            // and a fatal native completion. An invalid leaf still needs the
            // exact retained output authenticated by Publish below.
            if let Ok(root) = B::root(grant.ttbr0)
                && matches!(
                    B::translate(
                        words,
                        root,
                        carrick_guest_arch::UserVa::new(window.fault_page),
                        access,
                        true
                    ),
                    Ok(Some(_))
                )
            {
                return OutcomeOrCapacity::Terminal(DescriptorOutcome::Refused(
                    DescriptorRefusal::Occupied,
                ));
            }
            return OutcomeOrCapacity::Terminal(B::execute_grant(words, grant.ttbr0, txn));
        }
        let DescriptorOp::Prepare {
            publication,
            resident,
            backing,
        } = txn.op
        else {
            return OutcomeOrCapacity::Terminal(DescriptorOutcome::Refused(
                DescriptorRefusal::BadEncoding,
            ));
        };
        if publication.va != window.range.start()
            || publication.len > window.range.len()
            || publication.len == 0
            || !publication.len.is_multiple_of(4096)
            || window.fault_page >= publication.va + publication.len
            || publication.writable
                != window
                    .protection
                    .permits(carrick_core_abi::mm::ReservationProtection::WRITE)
            || publication.executable
                != window
                    .protection
                    .permits(carrick_core_abi::mm::ReservationProtection::EXECUTE)
            || resident.va != window.fault_page
            || resident.len != 4096
        {
            return OutcomeOrCapacity::Terminal(DescriptorOutcome::Refused(
                DescriptorRefusal::BadEncoding,
            ));
        }
        // The authenticated remapped root may replace a core-typed retired
        // terminal with fresh backing. Never revive its output, or replace a
        // prepared/live predecessor. The window is at most 512 pages.
        for va in (publication.va..publication.va + publication.len).step_by(4096) {
            match grant_page_available::<B, _>(words, grant.ttbr0, va) {
                Ok(true) => {}
                Ok(false) => {
                    return OutcomeOrCapacity::Terminal(DescriptorOutcome::Refused(
                        DescriptorRefusal::Occupied,
                    ));
                }
                Err(reason) => {
                    return OutcomeOrCapacity::Terminal(DescriptorOutcome::Refused(reason));
                }
            }
        }
        let identity = carrick_core_abi::FrameGrantResidencyIdentity {
            mm_key: mm.raw(),
            semantic_base: publication.va,
            physical_ipa: publication.ipa,
            len: publication.len,
            mapping_id: backing.mapping_id.get(),
            frame_id: backing.frame_id.get(),
            owner_generation: backing.owner_generation.get(),
            inventory_revision: backing.inventory_revision.get(),
        };
        let residency_slot = match residency.try_publish(identity) {
            Ok(slot) => slot,
            Err(FrameGrantResidencyRefusal::InvalidIdentity) => {
                return OutcomeOrCapacity::Terminal(DescriptorOutcome::Refused(
                    DescriptorRefusal::BadEncoding,
                ));
            }
            Err(FrameGrantResidencyRefusal::Overlap) => {
                // The descriptor walk above ruled out an occupied leaf. A
                // live overlapping record now indicates mismatched custody.
                return OutcomeOrCapacity::Terminal(DescriptorOutcome::Refused(
                    DescriptorRefusal::WrongBacking,
                ));
            }
            Err(FrameGrantResidencyRefusal::Capacity) => {
                if release_on_capacity {
                    return OutcomeOrCapacity::Capacity(residency.published_extensions());
                }
                if words.observe_residency_failure() {
                    words.descriptor_diagnostic(
                        carrick_mmu_core::live_descriptor_words::DescriptorDiagnostic::ResidencyRefused {
                            mm_key: identity.mm_key,
                            va: identity.semantic_base,
                            len: identity.len,
                            slots_used: residency.observed_slots_used(),
                            slots_total: residency.slot_capacity(),
                        },
                    );
                }
                return OutcomeOrCapacity::Terminal(DescriptorOutcome::Refused(
                    DescriptorRefusal::ResidencyCapacity,
                ));
            }
        };
        let outcome = B::execute_grant(words, grant.ttbr0, txn);
        if let DescriptorOutcome::Applied(_) = outcome {
            if let Some(page) = residency.lookup(mm.raw(), window.fault_page) {
                residency.record_commit(page);
            }
        } else {
            if matches!(outcome, DescriptorOutcome::Refused(_)) {
                words.descriptor_diagnostic(
                    carrick_mmu_core::live_descriptor_words::DescriptorDiagnostic::ResidencyPublishedBeforeRefusal,
                );
            }
            residency.retire(residency_slot, identity);
        }
        OutcomeOrCapacity::Terminal(outcome)
    })();
    match outcome {
        OutcomeOrCapacity::Capacity(observed_extensions) => {
            claimed.release_unapplied();
            drop(editor);
            GrantApplyOutcome::ResidencyCapacity {
                observed_extensions,
            }
        }
        OutcomeOrCapacity::Terminal(outcome) => {
            let receipt = claimed.complete_with_grant_trace(
                outcome,
                invalidate,
                trace_requested.then(|| trace.get()),
            );
            drop(editor);
            GrantApplyOutcome::Completed(receipt)
        }
    }
}

/// Logical leaf references for one physical backing. The backend owns storage
/// and the inventory's one journal; this value is the journaled logical state.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::default::Default,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct FrameReferences {
    mapping_count: u32,
    retire_on_last_unmap: bool,
}
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum ReferenceError {
    Exhausted,
    Underflow,
}
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum ReferenceRetirement {
    Ready,
    AlreadyPending,
    Deferred,
}
impl FrameReferences {
    pub const fn count(self) -> u32 {
        self.mapping_count
    }
    pub fn retain(&mut self) -> Result<(), ReferenceError> {
        self.mapping_count = self
            .mapping_count
            .checked_add(1)
            .ok_or(ReferenceError::Exhausted)?;
        // A new holder takes responsibility for retirement.
        self.retire_on_last_unmap = false;
        Ok(())
    }
    pub fn unmap(&mut self) -> Result<bool, ReferenceError> {
        self.mapping_count = self
            .mapping_count
            .checked_sub(1)
            .ok_or(ReferenceError::Underflow)?;
        Ok(self.mapping_count == 0 && self.retire_on_last_unmap)
    }
    pub fn request_retirement(&mut self) -> ReferenceRetirement {
        if self.mapping_count == 0 {
            ReferenceRetirement::Ready
        } else if self.retire_on_last_unmap {
            ReferenceRetirement::AlreadyPending
        } else {
            self.retire_on_last_unmap = true;
            ReferenceRetirement::Deferred
        }
    }
}
