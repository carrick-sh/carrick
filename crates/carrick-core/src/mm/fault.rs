//! Shared lazy-supply generations and exact reservation fault admission.
use carrick_core_abi::{
    EL1_FRAME_GRANT_TARGET_SIZE, FrameGrantMailbox, FrameGrantRequest, FrameGrantResidencyTable,
};
use carrick_guest_arch::{RootGpa, UserVa};
use carrick_mmu_core::aarch64::LeafAccess;
use carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords;
use carrick_mmu_core::owner_mmu::OwnerForkMmu;
use carrick_sched_core::spaces::notification::{SpaceAccess, SpaceWaitCause};
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_FRAME_GRANT_GENERATION: AtomicU64 = AtomicU64::new(1);
/// Zero is permanent exhaustion and cannot publish a mailbox or grant slot.
pub fn next_frame_grant_generation() -> u64 {
    frame_grant_generation(&NEXT_FRAME_GRANT_GENERATION)
}
fn frame_grant_generation(counter: &AtomicU64) -> u64 {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .unwrap_or(0)
}

/// The one lazy-supply protocol, shared by faults and stopped-target transfers.
/// Failed mailbox admission leaves the caller's owned continuation resumable.
pub fn request_lazy_frames(mailbox: &FrameGrantMailbox, mm_key: u64, va: u64, access: u64) -> bool {
    mailbox.try_publish_request(FrameGrantRequest {
        mm_key,
        request_generation: next_frame_grant_generation(),
        fault_va: va,
        requested_len: EL1_FRAME_GRANT_TARGET_SIZE,
        access,
    })
}

/// Whether a delegated MM's root lets this prepared page be committed:
/// `None` when the MM has no admitted root (its host arming decided), else
/// whether a node covers `page` and, for plain anonymous memory, permits
/// `access`. A busy root answers `Some(false)`: the host decides.
pub fn root_admits_commit<
    Policy: crate::mm::reservation::ReservationPolicy,
    Geometry: crate::mm::reservation::ReservationGeometry,
>(
    roots: Option<&crate::mm::reservation::SharedReservations<Policy, Geometry>>,
    spaces: SpaceAccess<'_>,
    slot: u32,
    mm_key: u64,
    page: u64,
    access: LeafAccess,
) -> Option<bool> {
    let roots = roots?;
    let mm = carrick_core_abi::ReservationMm::new(mm_key)?;
    let index = spaces.find(mm_key)?.index();
    if !roots.admitted(index, mm) {
        return None;
    }
    let Ok(mut model) = roots.lock_in(spaces, index, mm, slot) else {
        return Some(false);
    };
    let bits = match access {
        LeafAccess::Read => 1,
        LeafAccess::Write => 2,
        LeafAccess::Execute => 4,
    };
    Some(model.mapping(page).is_some_and(|mapping| {
        !mapping.anonymous
            || carrick_core_abi::ReservationProtection::from_bits(bits)
                .is_some_and(|access| mapping.protection.permits(access))
    }))
}

use core::num::NonZeroU64;

pub struct FileFaultVenue<
    'a,
    Policy: crate::mm::reservation::ReservationPolicy,
    Geometry: crate::mm::reservation::ReservationGeometry,
    Slots: carrick_core_abi::GrantSlotVenue,
> {
    pub roots: &'a crate::mm::reservation::SharedReservations<Policy, Geometry>,
    pub spaces: SpaceAccess<'a>,
    pub slots: &'a Slots,
    pub worker: u32,
    pub mailbox: &'a FrameGrantMailbox,
}
impl<
    Policy: crate::mm::reservation::ReservationPolicy,
    Geometry: crate::mm::reservation::ReservationGeometry,
    Slots: carrick_core_abi::GrantSlotVenue,
> FileFaultVenue<'_, Policy, Geometry, Slots>
{
    pub fn publish(&self, mm_key: u64, va: u64, access: u64) -> bool {
        let owner_source = core::cell::Cell::new(false);
        let run = || -> Option<bool> {
            let mm = carrick_core_abi::ReservationMm::new(mm_key)?;
            let index = self.spaces.find(mm_key)?;
            if !self.roots.admitted(index.index(), mm) {
                return None;
            }
            let mut root = self
                .roots
                .lock_in(self.spaces, index.index(), mm, self.worker)
                .ok()?;
            root.mapping(va)?.host_backing?;
            owner_source.set(true);
            let protection = carrick_core_abi::ReservationProtection::from_bits(access)?;
            let plan = root
                .transfer_fault_plan(va & !4095, 4096, protection)
                .ok()?;
            let mapping = root.mapping(plan.range.start())?;
            let source = mapping
                .host_backing?
                .advance(plan.range.start().checked_sub(mapping.range.start())?)?;
            let sequence = root.next_transfer_sequence().ok()?;
            let carrier = self.slots.carrier()?;
            let operation = carrick_core_abi::PortalOperation {
                carrier,
                mm,
                incarnation: NonZeroU64::new(root.incarnation().raw())?,
                sequence,
            };
            let window = carrick_core_abi::PortalGrantWindow {
                operation,
                generation: plan.generation,
                range: plan.range,
                protection: plan.protection,
                fault_page: plan.fault_page,
                host_backing: Some(source),
                fork_sequence: None,
            };
            drop(root);
            let slot = self.slots.grant(self.worker as usize)?;
            let generation = next_frame_grant_generation();
            if !slot.publish_fault_selection(generation, window) {
                return Some(true);
            }
            if !self.mailbox.try_publish_request(FrameGrantRequest {
                mm_key,
                request_generation: generation,
                fault_va: va,
                requested_len: plan.range.len(),
                access,
            }) {
                slot.cancel_fault_selection(window, generation);
            }
            Some(true)
        };
        run().unwrap_or(owner_source.get())
    }
}

/// Exact MM scope for consulting physical grants while selecting a new fault
/// window; a live grant owns its pages even before guest VALID is published.
pub struct OwnerFaultResidency<'a> {
    table: &'a FrameGrantResidencyTable,
    mm: carrick_core_abi::ReservationMm,
}

impl<'a> OwnerFaultResidency<'a> {
    pub const fn new(
        table: &'a FrameGrantResidencyTable,
        mm: carrick_core_abi::ReservationMm,
    ) -> Self {
        Self { table, mm }
    }
}

/// Select a bounded contiguous unbacked neighborhood inside the exact live
/// reservation. The caller holds this MM's editor and reservation root.
/// Prepared stock is physical ownership even though hardware VALID is clear.
pub fn owner_fault_plan<
    Policy: crate::mm::reservation::ReservationPolicy,
    Geometry: crate::mm::reservation::ReservationGeometry,
    B: OwnerForkMmu,
    W: LiveDescriptorWords + ?Sized,
>(
    root: &mut crate::mm::reservation::Reservations<'_, Policy, Geometry>,
    words: &W,
    residency: OwnerFaultResidency<'_>,
    hardware_root: RootGpa,
    address: UserVa,
    access: carrick_core_abi::ReservationProtection,
    fork_sequence: Option<NonZeroU64>,
) -> Result<crate::mm::reservation::ReservationFaultPlan, crate::mm::reservation::Refusal> {
    use crate::mm::reservation::Refusal;
    let mapping = root.mapping(address.raw()).ok_or(Refusal::Hole)?;
    let target = if mapping.host_backing.is_some() {
        4096
    } else {
        EL1_FRAME_GRANT_TARGET_SIZE
    };
    let mut plan = root.fork_transfer_fault_plan(address.raw(), target, access, fork_sequence)?;
    let table = hardware_root.address().raw();
    let fault_page = plan.fault_page;
    // The MM editor keeps this walk's table lineage stable. Adjacent pages
    // share upper descriptors, so retain those exact loaded child tables
    // while inspecting the bounded grant window.
    let mut cached_indices = [0u64; 3];
    let mut cached_tables = [0u64; 3];
    let mut cached_depth = 0usize;
    let mut unbacked = |va: u64| -> Result<bool, Refusal> {
        // VALID can still be clear for a host-published grant's untouched
        // pages. Its live residency owns the physical range, so a later VMA
        // extension must stop before that range instead of selecting an
        // overlapping grant. The fault page itself must reach the host's
        // exact-generation peer-resident alias retry; treating it as a
        // neighbor returns Busy without any release producer.
        if residency.table.lookup(residency.mm.raw(), va).is_some() {
            // A fault on a grant-owned page must reach the host's exact
            // peer-resident resolution even when its old stage-1 terminal is
            // still VALID. That terminal can name physical custody already
            // retired from stage-2; returning Busy here leaves no publisher
            // to wake the fault. Neighboring grants remain hard boundaries.
            return Ok(va == fault_page);
        }
        let mut table = table;
        for (level, shift) in [39, 30, 21, 12].into_iter().enumerate() {
            let index = (va >> shift) & 511;
            if level < cached_depth && cached_indices[level] == index {
                table = cached_tables[level];
                continue;
            }
            let word = words.load(table + index * 8).map_err(|_| Refusal::Stale)?;
            if word == 0 {
                cached_depth = level;
                return Ok(true);
            }
            if B::is_table(word, level) {
                table = word & B::ADDRESS_MASK;
                cached_indices[level] = index;
                cached_tables[level] = table;
                cached_depth = level + 1;
            } else {
                cached_depth = level;
                return Ok(B::is_retired(word) || B::is_absent_unowned(word));
            }
        }
        Err(Refusal::Stale)
    };
    if !unbacked(plan.fault_page)? {
        return Err(Refusal::Busy);
    }
    let mut start = plan.fault_page;
    while start > plan.range.start() && unbacked(start - 4096)? {
        start -= 4096;
    }
    let mut end = plan.fault_page + 4096;
    while end < plan.range.end() && unbacked(end)? {
        end += 4096;
    }
    plan.range = carrick_core_abi::ReservationRange::new(start, end).ok_or(Refusal::Invalid)?;
    Ok(plan)
}

pub struct OwnerFaultVenue<
    'a,
    Policy: crate::mm::reservation::ReservationPolicy,
    Geometry: crate::mm::reservation::ReservationGeometry,
    Slots: carrick_core_abi::GrantSlotVenue,
> {
    pub roots: &'a crate::mm::reservation::SharedReservations<Policy, Geometry>,
    pub spaces: SpaceAccess<'a>,
    pub slots: &'a Slots,
    pub residency: &'a FrameGrantResidencyTable,
    pub worker: u32,
    pub mailbox: &'a FrameGrantMailbox,
}
impl<
    Policy: crate::mm::reservation::ReservationPolicy,
    Geometry: crate::mm::reservation::ReservationGeometry,
    Slots: carrick_core_abi::GrantSlotVenue,
> OwnerFaultVenue<'_, Policy, Geometry, Slots>
{
    pub fn publish<B: OwnerForkMmu, W: LiveDescriptorWords + ?Sized>(
        &self,
        _: B,
        words: &W,
        mm_key: u64,
        va: u64,
        access: u64,
    ) -> bool {
        let owner_admitted = core::cell::Cell::new(false);
        let run = || -> Option<bool> {
            let mm = carrick_core_abi::ReservationMm::new(mm_key)?;
            let index = self.spaces.find(mm_key)?;
            if !self.roots.admitted(index.index(), mm) {
                return None;
            }
            owner_admitted.set(true);
            let source = self.spaces.current_notification(index, mm_key);
            let editor_wait = source
                .as_ref()
                .map(|source| source.observe(SpaceWaitCause::Editor));
            let Some(_editor) = self.spaces.try_begin_edit(
                index,
                mm_key,
                NonZeroU64::new(u64::from(self.worker) + 1)?,
            ) else {
                if let Some(snapshot) = editor_wait {
                    let _ = self.publish_wait(
                        source.as_ref()?,
                        mm,
                        va,
                        carrick_core_abi::PortalWaitCause::Editor,
                        snapshot.revision(),
                    );
                }
                return Some(true);
            };
            let grant = self.spaces.table().grant(index, mm_key)?;
            let reservation_wait = source
                .as_ref()
                .map(|source| source.observe(SpaceWaitCause::Reservations));
            let mut root = match self
                .roots
                .lock_in(self.spaces, index.index(), mm, self.worker)
            {
                Ok(root) => root,
                Err(crate::mm::reservation::Refusal::Busy) => {
                    if let (Some(source), Some(snapshot)) = (source.as_ref(), reservation_wait) {
                        let _ = self.publish_wait(
                            source,
                            mm,
                            va,
                            carrick_core_abi::PortalWaitCause::Reservations,
                            snapshot.revision(),
                        );
                    }
                    return Some(true);
                }
                Err(_) => return Some(true),
            };
            let protection = carrick_core_abi::ReservationProtection::from_bits(access)?;
            let plan = owner_fault_plan::<_, _, B, _>(
                &mut root,
                words,
                OwnerFaultResidency::new(self.residency, mm),
                B::root(grant.ttbr0).ok()?,
                UserVa::new(va),
                protection,
                None,
            )
            .ok()?;
            let mapping = root.mapping(plan.range.start())?;
            let source = match mapping.host_backing {
                Some(source) => {
                    Some(source.advance(plan.range.start().checked_sub(mapping.range.start())?)?)
                }
                None => None,
            };
            let sequence = root.next_transfer_sequence().ok()?;
            let carrier = self.slots.carrier()?;
            let operation = carrick_core_abi::PortalOperation {
                carrier,
                mm,
                incarnation: NonZeroU64::new(root.incarnation().raw())?,
                sequence,
            };
            let window = carrick_core_abi::PortalGrantWindow {
                operation,
                generation: plan.generation,
                range: plan.range,
                protection: plan.protection,
                fault_page: plan.fault_page,
                host_backing: source,
                fork_sequence: None,
            };
            drop(root);
            let slot = self.slots.grant(self.worker as usize)?;
            let generation = next_frame_grant_generation();
            if !slot.publish_fault_selection(generation, window) {
                return Some(true);
            }
            if !self.mailbox.try_publish_request(FrameGrantRequest {
                mm_key,
                request_generation: generation,
                fault_va: va,
                requested_len: plan.range.len(),
                access,
            }) {
                slot.cancel_fault_selection(window, generation);
            }
            Some(true)
        };
        run().unwrap_or(owner_admitted.get())
    }
    fn publish_wait(
        &self,
        source: &carrick_sched_core::spaces::notification::SpaceNotificationLease<'_>,
        mm: carrick_core_abi::ReservationMm,
        va: u64,
        cause: carrick_core_abi::PortalWaitCause,
        revision: u64,
    ) -> bool {
        let Some(carrier) = self.slots.carrier() else {
            return false;
        };
        let Some(slot) = self.slots.grant(self.worker as usize) else {
            return false;
        };
        let identity = source.identity();
        if identity.mm.get() != mm.raw() {
            return false;
        }
        // SAFETY: caller sampled this exact admitted owner's live cause
        // source before probing the editor or reservation root.
        let wait = unsafe {
            carrick_core_abi::PortalOwnerWait::from_owner(
                carrick_core_abi::El1MmHandle::from_admitted_owner(
                    carrier,
                    mm,
                    identity.incarnation,
                ),
                cause,
                revision,
            )
        };
        slot.publish_fault_wait(va, wait)
    }
}

#[cfg(test)]
mod generation_tests {
    use super::*;
    #[test]
    fn exhausted_frame_request_generation_refuses_without_reusing_one() {
        let counter = AtomicU64::new(u64::MAX - 1);
        let last = frame_grant_generation(&counter);
        let exhausted = frame_grant_generation(&counter);
        let repeated = frame_grant_generation(&counter);
        assert_ne!(repeated, 1, "exhaustion reused request incarnation one");
        assert_eq!(last, u64::MAX - 1);
        assert_eq!(exhausted, 0);
        assert_eq!(repeated, 0);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }
}
