//! ISA-neutral custody of an exec successor: the closed-space publication that
//! precedes host preparation, and the consuming adoption/cancellation crossings
//! that follow it. Per-ISA code supplies only the physical crossing and the
//! identity its space table sealed.
extern crate alloc;

use crate::native_process_runtime::{ExecSuccessorSlot, NativeProcessError};
use alloc::boxed::Box;
use carrick_core::mm::reservation::{ReservationGeometry, ReservationPolicy};
use carrick_core::mm::transaction::{MmPortal, OwnerVenue};
use carrick_core_abi::service::{
    ExecAdoptionReceipt, ExecSuccessorManifest, ExecSuccessorManifestView, ServiceIdentity,
};
use carrick_core_abi::{El1MmHandle, ReservationMm, ReservationRange};
use carrick_el1::memory::reservations::Layout;
use carrick_guest_arch::{
    AddressContext, ContextGeneration, KernelVa, MmGeneration, ProcessContext, RootGpa,
};
use carrick_mmu_core::owner_mmu::OwnerMmu;
use carrick_sched_core::{SpaceIndex, ZoneTables};
use core::marker::PhantomData;
use core::num::NonZeroU64;

use carrick_core::mm::reservation::SharedReservations;
use carrick_core_abi::PinnedMetadataExtent;

/// The closed, never-installed root published for an exec successor. Dropping
/// the token before `commit` retires the root and frees its space, so every
/// refusal between preparation and adoption leaves the predecessor untouched.
pub struct ClosedExecSuccessorSlot<'a, Pin, Policy, Geometry, Venue, B, C>
where
    Pin: PinnedMetadataExtent,
    Policy: ReservationPolicy,
    Geometry: ReservationGeometry,
    Venue: OwnerVenue<C>,
    B: OwnerMmu + Copy,
    C: Copy + Send + Sync + zerocopy::FromZeros,
{
    zone: &'a ZoneTables<C>,
    roots: &'a SharedReservations<Policy, Geometry>,
    carrier: NonZeroU64,
    worker: u32,
    index: SpaceIndex,
    mm: ReservationMm,
    generation: NonZeroU64,
    armed: bool,
    mmu: B,
    portal: PhantomData<fn() -> (Pin, Venue)>,
}

impl<'a, Pin, Policy, Geometry, Venue, B, C>
    ClosedExecSuccessorSlot<'a, Pin, Policy, Geometry, Venue, B, C>
where
    Pin: PinnedMetadataExtent,
    Policy: ReservationPolicy,
    Geometry: ReservationGeometry,
    Venue: OwnerVenue<C>,
    B: OwnerMmu + Copy,
    C: Copy + Send + Sync + zerocopy::FromZeros,
{
    fn portal(&self) -> MmPortal<'a, Pin, Policy, Geometry, Venue, B, C> {
        MmPortal::for_zone(self.carrier, self.roots, self.zone).with_mmu(self.mmu)
    }
}

impl<Pin, Policy, Geometry, Venue, B, C> ExecSuccessorSlot
    for ClosedExecSuccessorSlot<'_, Pin, Policy, Geometry, Venue, B, C>
where
    Pin: PinnedMetadataExtent,
    Policy: ReservationPolicy + Send + Sync,
    Geometry: ReservationGeometry + Send + Sync,
    Venue: OwnerVenue<C>,
    B: OwnerMmu + Copy + Send,
    C: Copy + Send + Sync + zerocopy::FromZeros,
{
    fn mm(&self) -> ReservationMm {
        self.mm
    }

    fn root_generation(&self) -> NonZeroU64 {
        self.generation
    }

    fn prepare_adoption(&self) -> Result<El1MmHandle, NativeProcessError> {
        let portal = self.portal();
        let mut root = portal
            .root_any(self.mm, self.worker)
            .map_err(|_| NativeProcessError::Stale)?;
        if root.incarnation().raw() != self.generation.get() {
            return Err(NativeProcessError::Stale);
        }
        root.finish_import()
            .map_err(|_| NativeProcessError::Stale)?;
        // SAFETY: this token owns the exact root just admitted above.
        Ok(unsafe { El1MmHandle::from_admitted_owner(self.carrier, self.mm, self.generation) })
    }

    fn commit(mut self: Box<Self>) {
        self.armed = false;
    }
}

impl<Pin, Policy, Geometry, Venue, B, C> Drop
    for ClosedExecSuccessorSlot<'_, Pin, Policy, Geometry, Venue, B, C>
where
    Pin: PinnedMetadataExtent,
    Policy: ReservationPolicy,
    Geometry: ReservationGeometry,
    Venue: OwnerVenue<C>,
    B: OwnerMmu + Copy,
    C: Copy + Send + Sync + zerocopy::FromZeros,
{
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(root) = self.portal().root_any(self.mm, self.worker) {
            let _ = root.retire();
        }
        self.zone.spaces.free(self.index);
    }
}

/// The heap and mmap arena every Linux successor root starts with. The same
/// constants lay out every ISA's guest (`guest_setup_x86` shares them).
fn successor_layout() -> Result<Layout, NativeProcessError> {
    let heap = ReservationRange::new(
        carrick_personality_linux::mm::LINUX_HEAP_BASE,
        carrick_personality_linux::mm::LINUX_HEAP_BASE
            + carrick_personality_linux::mm::LINUX_HEAP_SIZE,
    )
    .ok_or(NativeProcessError::Invalid)?;
    let arena = ReservationRange::new(
        carrick_personality_linux::mm::LINUX_MMAP_BASE,
        carrick_personality_linux::mm::LINUX_MMAP_BASE
            + carrick_personality_linux::mm::LINUX_MMAP_SIZE_MAX,
    )
    .ok_or(NativeProcessError::Invalid)?;
    Ok(Layout {
        heap,
        arena,
        brk: heap.start(),
        address_limit: u64::MAX,
        data_limit: u64::MAX,
        external_address_bytes: 0,
        external_data_bytes: 0,
    })
}

/// Publish the successor's closed space and root, armed for rollback. Nothing
/// of the predecessor is touched: the slot is a new, unbound publication.
pub fn prepare_closed_exec_successor_slot<'a, Pin, Policy, Geometry, Venue, B, C>(
    zone: &'a ZoneTables<C>,
    roots: &'a SharedReservations<Policy, Geometry>,
    carrier: NonZeroU64,
    worker: u32,
    mm: ReservationMm,
    mmu: B,
) -> Result<Box<dyn ExecSuccessorSlot + 'a>, NativeProcessError>
where
    Pin: PinnedMetadataExtent + 'a,
    Policy: ReservationPolicy + Send + Sync + 'a,
    Geometry: ReservationGeometry + Send + Sync + 'a,
    Venue: OwnerVenue<C> + 'a,
    B: OwnerMmu + Copy + Send + 'a,
    C: Copy + Send + Sync + zerocopy::FromZeros + 'a,
{
    let layout = successor_layout()?;
    let index = zone
        .spaces
        .publish_closed_with_layout(mm.raw(), 0, 0, layout.heap.start(), layout.arena.start())
        .ok_or(NativeProcessError::Exhausted)?;
    if !zone.spaces.mark_initial_bindable(index) {
        zone.spaces.free(index);
        return Err(NativeProcessError::Stale);
    }
    if roots.publish(index.index(), mm, layout).is_err() {
        zone.spaces.free(index);
        return Err(NativeProcessError::Stale);
    }
    let portal: MmPortal<'a, Pin, Policy, Geometry, Venue, B, C> =
        MmPortal::for_zone(carrier, roots, zone).with_mmu(mmu);
    let generation = match portal.root_any(mm, worker) {
        Ok(root) => NonZeroU64::new(root.incarnation().raw()),
        Err(_) => None,
    };
    let Some(generation) = generation else {
        if let Ok(root) = portal.root_any(mm, worker) {
            let _ = root.retire();
        }
        zone.spaces.free(index);
        return Err(NativeProcessError::Stale);
    };
    Ok(Box::new(ClosedExecSuccessorSlot::<
        'a,
        Pin,
        Policy,
        Geometry,
        Venue,
        B,
        C,
    > {
        zone,
        roots,
        carrier,
        worker,
        index,
        mm,
        generation,
        armed: true,
        mmu,
        portal: PhantomData,
    }))
}

/// A sealed manifest the adopter has authenticated and the physical crossing
/// has accepted: the successor's address context, never yet installed.
pub struct AdoptedSuccessor {
    pub view: ExecSuccessorManifestView,
    pub address: AddressContext<RootGpa>,
}

/// The per-ISA step before the consuming adoption crossing: everything an
/// ISA can refuse, and any successor build it runs there. AArch64 only checks
/// its sealed translation identity; x86 also builds the successor's tables.
pub trait PrepareCross {
    /// Check the opened `successor`, and return the root identity its closed
    /// space must carry once the crossing binds it (`closed_root_identity`).
    /// This runs before the crossing, the point of no return: a refusal
    /// leaves the receipt unconsumed and every published state unchanged.
    fn prepare_cross(
        &mut self,
        successor: &ExecSuccessorManifestView,
    ) -> Result<u64, NativeProcessError>;
}

/// Authenticate `manifest`, run the ISA's `prepare` against the published
/// space, run the consuming adoption crossing, and return the successor's
/// address context. `cross` receives the adoption record's address and
/// performs the physical crossing.
pub fn adopt_closed_exec_successor<C: ProcessContext>(
    zone: &ZoneTables<C>,
    identity: ServiceIdentity,
    receipt: ExecAdoptionReceipt,
    manifest: &ExecSuccessorManifest,
    prepare: &mut impl PrepareCross,
    cross: impl FnOnce(u64) -> Result<(), NativeProcessError>,
) -> Result<AdoptedSuccessor, NativeProcessError> {
    let successor = manifest
        .open(identity, receipt)
        .ok_or(NativeProcessError::Stale)?;
    let index = zone
        .spaces
        .find(successor.successor_mm.raw())
        .ok_or(NativeProcessError::Stale)?;
    let expected = prepare.prepare_cross(&successor)?;
    let manifest_address = KernelVa::new(core::ptr::from_ref(manifest).addr() as u64);
    let mut adoption = carrick_el1_abi::NativeExecAdoption::new(receipt, manifest_address)
        .ok_or(NativeProcessError::Invalid)?;
    let crossed = cross(&raw mut adoption as *mut _ as u64);
    let accepted = adoption.take(receipt, manifest_address);
    if crossed.is_err() || accepted != Some(Ok(())) {
        return Err(NativeProcessError::Stale);
    }
    if zone
        .spaces
        .closed_root_identity(index, successor.successor_mm.raw())
        != Some(expected)
    {
        return Err(NativeProcessError::Stale);
    }
    let address = AddressContext {
        root: successor.root,
        mm: MmGeneration::new(
            NonZeroU64::new(successor.successor_mm.raw()).ok_or(NativeProcessError::Stale)?,
        ),
        generation: ContextGeneration::new(successor.root_generation),
    };
    Ok(AdoptedSuccessor {
        view: successor,
        address,
    })
}

/// The consuming cancellation crossing for a prepared exec. A stale or
/// repeated receipt refuses.
pub fn cancel_prepared_exec(
    receipt: ExecAdoptionReceipt,
    cross: impl FnOnce(u64) -> Result<(), NativeProcessError>,
) -> Result<(), NativeProcessError> {
    let mut cancellation = carrick_el1_abi::NativeExecCancellation::new(receipt);
    let crossed = cross(&raw mut cancellation as *mut _ as u64);
    let accepted = cancellation.take(receipt);
    if crossed.is_ok() && accepted == Some(Ok(())) {
        Ok(())
    } else {
        Err(NativeProcessError::Stale)
    }
}
