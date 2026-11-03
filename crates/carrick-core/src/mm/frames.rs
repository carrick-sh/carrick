//! One lazy grant authentication, logical residency publication and settlement.
use crate::mm::reservation::{ReservationFaultPlan, ReservationGeometry, ReservationPolicy};
use crate::mm::transaction::{MmError, MmPortal, OwnerVenue};
use carrick_core_abi::*;
use carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords;
use carrick_mmu_core::owner_mmu::{OwnerGrantMmu, OwnerMmu};
use carrick_sched_core::SpaceEditor;

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
    let mut start = window.range.start();
    let mut end = window.range.end();
    for page in (start..end).step_by(4096) {
        if grant_page_available::<B, _>(words, root, page)? {
            continue;
        }
        if page == window.fault_page {
            // Occupancy is not residency: fork also inherits invalid prepared
            // outputs without a lazy-grant residency row. Only a live walk
            // under the caller's editor can authorize retrying the instruction.
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
        if page < window.fault_page {
            start = page + 4096;
        } else {
            end = page;
            break;
        }
    }
    if let Some(backing) = window.host_backing {
        window.host_backing = Some(
            backing
                .advance(start - window.range.start())
                .ok_or(DescriptorRefusal::BadRange)?,
        );
    }
    window.range = ReservationRange::new(start, end).ok_or(DescriptorRefusal::BadRange)?;
    Ok(window)
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
    residency: &FrameGrantResidencyTable,
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

pub fn apply_grant<B: OwnerGrantMmu, W: LiveDescriptorWords + ?Sized>(
    slot: &carrick_core_abi::PortalGrantSlot,
    words: &W,
    residency: &FrameGrantResidencyTable,
    target: GrantTarget<'_, impl Copy + Send + Sync + zerocopy::FromZeros>,
    invalidate: impl FnOnce(),
) -> Option<carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt> {
    use carrick_mmu_core::aarch64::descriptor_txn::{
        DescriptorOp, DescriptorOutcome, DescriptorRefusal,
    };
    let (window, grant, editor, authenticated) = target.into_parts();
    let mm = window.operation.mm;
    let claimed = slot.descriptor().claim_for_mm(mm.raw())?;
    let outcome = (|| {
        let Ok(txn) = claimed.txn() else {
            return DescriptorOutcome::Refused(DescriptorRefusal::BadEncoding);
        };
        if !authenticated {
            return DescriptorOutcome::Refused(DescriptorRefusal::StaleRoot);
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
                return DescriptorOutcome::Refused(DescriptorRefusal::BadEncoding);
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
                return DescriptorOutcome::Refused(DescriptorRefusal::Occupied);
            }
            return B::execute_grant(words, grant.ttbr0, txn);
        }
        let DescriptorOp::Prepare {
            publication,
            resident,
            backing,
        } = txn.op
        else {
            return DescriptorOutcome::Refused(DescriptorRefusal::BadEncoding);
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
            return DescriptorOutcome::Refused(DescriptorRefusal::BadEncoding);
        }
        // The authenticated remapped root may replace a core-typed retired
        // terminal with fresh backing. Never revive its output, or replace a
        // prepared/live predecessor. The window is at most 512 pages.
        for va in (publication.va..publication.va + publication.len).step_by(4096) {
            match grant_page_available::<B, _>(words, grant.ttbr0, va) {
                Ok(true) => {}
                Ok(false) => return DescriptorOutcome::Refused(DescriptorRefusal::Occupied),
                Err(reason) => return DescriptorOutcome::Refused(reason),
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
        let Some(residency_slot) = residency.publish(identity) else {
            return DescriptorOutcome::Refused(DescriptorRefusal::JournalCapacity);
        };
        let outcome = B::execute_grant(words, grant.ttbr0, txn);
        if let DescriptorOutcome::Applied(_) = outcome {
            if let Some(page) = residency.lookup(mm.raw(), window.fault_page) {
                residency.record_commit(page);
            }
        } else {
            residency.retire(residency_slot, identity);
        }
        outcome
    })();
    let receipt = claimed.complete(outcome, invalidate);
    drop(editor);
    Some(receipt)
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
    claimed_count: u32,
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
        if self.mapping_count == self.claimed_count {
            return Err(ReferenceError::Underflow);
        }
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

/// Stable inventory-owned storage. Implementations must always access the same
/// counter, including after `Clone`, and serialize access with the inventory
/// transaction lock. Overlays may copy `FrameReferences`; they must update this cell only at commit.
pub trait FrameReferenceCell: Clone {
    fn with_references<R>(&self, update: impl FnOnce(&mut FrameReferences) -> R) -> R;
}

/// An owned unit of one stable inventory counter, outside copied overlay rows.
/// There is no API accepting a token and a second counter: every operation
/// consumes the token's own cell.
/// ```compile_fail
/// fn cannot_duplicate<C: carrick_core::mm::frames::FrameReferenceCell>(
///     reference: carrick_core::mm::frames::FrameRef<C>,
/// ) { let _ = reference.clone(); }
/// ```
#[must_use]
pub struct FrameRef<C: FrameReferenceCell> {
    cell: C,
}
impl<C: FrameReferenceCell> FrameRef<C> {
    pub fn claim(cell: C) -> Result<Self, ReferenceError> {
        cell.with_references(|references| {
            if references.mapping_count == references.claimed_count {
                return Err(ReferenceError::Underflow);
            }
            references.claimed_count += 1;
            Ok(())
        })?;
        Ok(Self { cell })
    }
    pub fn restore(self) {
        self.cell
            .with_references(|references| references.claimed_count -= 1);
    }
    pub fn release(self, policy: ReferenceReleasePolicy) -> ReferenceRelease {
        self.cell.with_references(|references| {
            references.claimed_count -= 1;
            references.mapping_count -= 1;
            references.retire_on_last_unmap |= policy == ReferenceReleasePolicy::RetireIfLast;
            match (references.mapping_count, references.retire_on_last_unmap) {
                (0, true) => ReferenceRelease::Last,
                (0, false) => ReferenceRelease::Zero,
                _ => ReferenceRelease::Shared,
            }
        })
    }
    /// Replace one owned unit with `pieces` owned units in the same cell.
    /// Failure returns the original unit without changing the counter.
    pub fn split(self, pieces: core::num::NonZeroU32) -> Result<alloc::vec::Vec<Self>, Self> {
        let extra = pieces.get() - 1;
        let mut units = alloc::vec::Vec::new();
        if units.try_reserve_exact(pieces.get() as usize).is_err() {
            return Err(self);
        }
        let accepted = self.cell.with_references(|references| {
            let Some(count) = references.mapping_count.checked_add(extra) else {
                return false;
            };
            references.mapping_count = count;
            references.claimed_count += extra;
            true
        });
        if !accepted {
            return Err(self);
        }
        for _ in 0..extra {
            units.push(Self {
                cell: self.cell.clone(),
            });
        }
        units.push(self);
        Ok(units)
    }
}
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum ReferenceReleasePolicy {
    IfRequested,
    RetireIfLast,
}
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum ReferenceRelease {
    Shared,
    Zero,
    Last,
}

#[cfg(test)]
mod frame_ref_tests {
    use super::*;
    use alloc::sync::Arc;
    use parking_lot::Mutex;

    #[derive(::core::clone::Clone)]
    struct Cell(Arc<Mutex<FrameReferences>>);
    impl FrameReferenceCell for Cell {
        fn with_references<R>(&self, update: impl FnOnce(&mut FrameReferences) -> R) -> R {
            update(&mut self.0.lock())
        }
    }
    fn retained() -> Cell {
        let cell = Cell(Arc::new(Mutex::new(FrameReferences::default())));
        cell.0.lock().retain().unwrap();
        cell
    }
    #[test]
    fn owned_reference_blocks_unmap_and_restore_keeps_the_retained_unit() {
        let cell = retained();
        let claim = FrameRef::claim(cell.clone()).unwrap();
        assert_eq!(cell.0.lock().unmap(), Err(ReferenceError::Underflow));
        assert!(FrameRef::claim(cell.clone()).is_err());
        claim.restore();
        assert_eq!(cell.0.lock().count(), 1);
        assert_eq!(cell.0.lock().unmap(), Ok(false));
    }
    #[test]
    fn owned_release_distinguishes_zero_and_requested_last() {
        for requested in [false, true] {
            let cell = retained();
            let claim = FrameRef::claim(cell.clone()).unwrap();
            if requested {
                assert_eq!(
                    cell.0.lock().request_retirement(),
                    ReferenceRetirement::Deferred
                );
            }
            assert_eq!(
                claim.release(ReferenceReleasePolicy::IfRequested),
                if requested {
                    ReferenceRelease::Last
                } else {
                    ReferenceRelease::Zero
                }
            );
            assert_eq!(cell.0.lock().count(), 0);
        }
        let claim = FrameRef::claim(retained()).unwrap();
        assert_eq!(
            claim.release(ReferenceReleasePolicy::RetireIfLast),
            ReferenceRelease::Last
        );
    }
    #[test]
    fn split_claim_releases_shared_until_the_last_sibling() {
        let cell = retained();
        let claim = FrameRef::claim(cell.clone()).unwrap();
        cell.0.lock().request_retirement();
        let mut pieces = claim
            .split(core::num::NonZeroU32::new(3).unwrap())
            .ok()
            .unwrap();
        assert_eq!(cell.0.lock().count(), 3);
        assert_eq!(
            pieces
                .pop()
                .unwrap()
                .release(ReferenceReleasePolicy::IfRequested),
            ReferenceRelease::Shared
        );
        assert_eq!(
            pieces
                .pop()
                .unwrap()
                .release(ReferenceReleasePolicy::IfRequested),
            ReferenceRelease::Shared
        );
        assert_eq!(
            pieces
                .pop()
                .unwrap()
                .release(ReferenceReleasePolicy::IfRequested),
            ReferenceRelease::Last
        );
    }
    #[test]
    fn overflowing_split_returns_the_unchanged_owned_unit() {
        let cell = retained();
        let claim = FrameRef::claim(cell.clone()).unwrap();
        // Exercise the full u32 counter capacity without allocating its rows.
        cell.0.lock().mapping_count = u32::MAX;
        let claim = claim
            .split(core::num::NonZeroU32::new(2).unwrap())
            .err()
            .unwrap();
        assert_eq!(cell.0.lock().count(), u32::MAX);
        claim.restore();
        assert_eq!(cell.0.lock().claimed_count, 0);
    }
}
