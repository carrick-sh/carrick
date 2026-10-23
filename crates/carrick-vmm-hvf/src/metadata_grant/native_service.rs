//! Backing custody for a ring-owned request; no host task or process adoption.
use super::*;
use carrick_core_abi::service::{ServiceCell, ServiceError, ServiceRequest, ServiceTicket};
use carrick_sched_core::object_wait::ObjectWaitKey;
use core::ops::Deref;

struct ServicePin {
    cell: core::ptr::NonNull<ServiceCell>,
    _mapping: HostMetadataExtentPin,
    _carrier: Arc<crate::trap::CarrierVmCustody>,
}
impl Deref for ServicePin {
    type Target = ServiceCell;
    fn deref(&self) -> &ServiceCell {
        // SAFETY: intake retained the complete aligned member allocation;
        // this pin outlives the reference and service access uses atomics.
        unsafe { self.cell.as_ref() }
    }
}

/// A unique physical service ticket. The ring retains its continuation, MM,
/// and member; this host object retains only backing and carrier observation.
#[must_use]
pub struct NativeService {
    ticket: ServiceTicket<ServicePin>,
    custody: Arc<crate::trap::CarrierVmCustody>,
    slot: carrick_sched_core::SlotId,
    cow: Option<carrick_core_abi::service::ServiceFaultSupply>,
}
impl core::fmt::Debug for NativeService {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NativeService")
            .field("request", &self.request())
            .field("cow", &self.cow)
            .finish_non_exhaustive()
    }
}
impl NativeService {
    pub fn request(&self) -> ServiceRequest {
        self.ticket.request()
    }

    /// An unsupported service is refused to its ring owner, which alone
    /// chooses errno or signal. There is no host syscall dispatch fallback.
    pub fn refuse(self) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        self.complete(false)
    }

    /// The carrier delivered the completed instruction's owed work. Its
    /// result remains exclusively in the ring continuation.
    pub fn acknowledge_work(self) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        if !matches!(
            self.request().operation,
            carrick_core_abi::service::ServiceOperation::CarrierWork { .. }
        ) {
            return Err(stale());
        }
        self.complete(true)
    }

    pub fn slot(&self) -> carrick_sched_core::SlotId {
        self.slot
    }

    /// Supply exact-MM physical COW stock; the ring owns fault policy and retry.
    pub fn supply(
        self,
        deliver: for<'z> fn(
            &'z carrick_sched_core::ZoneTables<carrick_el1_abi::Aarch64ParkedContext>,
            carrick_sched_core::Waker,
            carrick_sched_core::object_wait::OwnedObjectWakeEffects<
                'z,
                carrick_el1_abi::Aarch64ParkedContext,
            >,
        ),
    ) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        use carrick_sched_core::spaces::notification::{
            SpaceAccess, SpaceReleaseVenue, SpaceWaitCause, SpaceWakeDelivery,
        };
        let Some(carrick_core_abi::service::ServiceFaultSupply::Cow(window)) = self.cow else {
            return self.refuse();
        };
        let custody = Arc::clone(&self.custody);
        let region = retained_abi_region(&custody).ok_or_else(stale)?;
        let (_, zone) = stopped_records(
            region,
            carrick_guest_arch::CpuId::new(u32::from(self.slot.raw())),
        )
        .ok_or_else(stale)?;
        let handle = self.request().identity.birth.mm;
        let entry = zone
            .space_entry(core::num::NonZeroU64::new(handle.mm().raw()).ok_or_else(stale)?)
            .ok_or_else(stale)?;
        let source = entry
            .notifications(handle.incarnation())
            .map_err(|_| stale())?;
        // Observe the exact editor producer before raising its gate/probing.
        let revision = source.observe(SpaceWaitCause::Editor).revision();
        let access = SpaceAccess::notified(SpaceReleaseVenue {
            zone,
            waker: carrick_sched_core::Waker::Host,
            deliver: SpaceWakeDelivery::Function(deliver),
        });
        let index = zone.spaces.find(handle.mm().raw()).ok_or_else(stale)?;
        let exclusion = match access.try_exclude_editor(index, handle.mm().raw()) {
            Ok(exclusion) => exclusion,
            Err(carrick_sched_core::spaces::notification::ExclusionRefusal::Busy) => {
                // SAFETY: authenticated source above, sampled before the probe.
                let wait = unsafe {
                    carrick_el1_abi::PortalOwnerWait::from_owner(
                        handle,
                        carrick_el1_abi::PortalWaitCause::Editor,
                        revision,
                    )
                };
                return self.complete_wait(wait);
            }
            Err(_) => return self.refuse(),
        };
        let pool = carrick_el1_abi::cow_grant_pool_host().ok_or_else(stale)?;
        let mut stock = custody.fork_stock.lock();
        if stock.owner.child_owner(handle.mm()) != Some(handle)
            || stock.owner.is_quarantined(handle.mm())
        {
            return self.refuse();
        }
        let root = stock.owner.child_root(handle.mm()).ok_or_else(stale)?;
        let inventory = stock.inventory().ok_or_else(stale)?;
        let physical = stock
            .owner
            .child_physical_mut(handle.mm(), root)
            .ok_or_else(stale)?;
        let owner = carrick_hal::GuestFrameOwner {
            native_mm: carrick_guest_arch::MmGeneration::new(
                core::num::NonZeroU64::new(handle.mm().raw()).ok_or_else(stale)?,
            ),
            root_generation: carrick_guest_arch::ContextGeneration::new(handle.incarnation()),
        };
        let grants = physical
            .supplied
            .get_or_insert_with(|| carrick_hal::physical_grants::NativePhysicalGrants::new(owner));
        if grants.owner() != owner || physical.rollback.failed() {
            return Err(stale());
        }
        grants.settle(pool, exclusion.proof(), |va| {
            native_output(&custody, root, va)
        })?;
        if pool.ready(handle.mm().raw()).next().is_none() {
            for _ in 0..carrick_hal::physical_grants::NativePhysicalGrants::<
                crate::fork_stock::NativeFrameBacking,
            >::REFILL_GRANTS
            {
                let (_, ipa, generation) = crate::trap::allocate_grant_compound(
                    &custody,
                    applevisor::memory::MemPerms::ReadWrite,
                )?;
                let retained = Arc::new(crate::fork_stock::NativeFrameBacking {
                    carrier: Arc::downgrade(&custody),
                    ipa,
                    generation,
                });
                custody
                    .native_frame_backings
                    .lock()
                    .insert((ipa, generation), Arc::downgrade(&retained));
                let staged = carrick_hal::physical_grants::StagedPhysicalGrants::stage(
                    Arc::clone(&physical.rollback),
                    Arc::clone(&inventory),
                    [carrick_guest_arch::FrameGpa::new(ipa)],
                    0,
                    carrick_el1_abi::COW_GRANT_SIZE,
                    core::num::NonZeroU64::new(generation).ok_or_else(stale)?,
                    owner,
                )?;
                grants.publish_cow(staged, retained, pool, exclusion.proof())?;
            }
        }
        let supplied = pool.ready(window.operation.mm.raw()).next().is_some();
        drop(stock);
        drop(exclusion);
        drop(source);
        self.complete(supplied)
    }

    fn complete_wait(
        self,
        wait: carrick_el1_abi::PortalOwnerWait,
    ) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        self.finish(Some(wait), false)
    }
    fn complete(self, supplied: bool) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        self.finish(None, supplied)
    }
    fn finish(
        self,
        wait: Option<carrick_el1_abi::PortalOwnerWait>,
        supplied: bool,
    ) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        let region = retained_abi_region(&self.custody).ok_or_else(stale)?;
        let (_, zone) = stopped_records(
            region,
            carrick_guest_arch::CpuId::new(u32::from(self.slot.raw())),
        )
        .ok_or_else(stale)?;
        let key = ObjectWaitKey::native_service(self.request().identity.birth.record)
            .ok_or_else(stale)?;
        let queue = zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin)
            .map_err(|_| stale())?;
        // Claim, cancel, and complete share this queue lock. WRITING is never
        // treated as a stale generation merely because another CPU is active.
        if let Some(wait) = wait {
            self.ticket.complete_wait(wait).map_err(|_| stale())?;
        } else {
            self.ticket.complete(supplied).map_err(|_| stale())?;
        }
        let mut effects = carrick_sched_core::WakeEffects::default();
        queue
            .notify_object(self.slot, &mut effects)
            .map_err(|_| stale())?;
        Ok(effects)
    }
}
fn stale() -> TrapError {
    TrapError::Hypervisor("native service custody mismatch".into())
}

pub(super) fn take(
    custody: &Arc<crate::trap::CarrierVmCustody>,
    cpu: carrick_guest_arch::CpuId,
) -> Result<Option<NativeService>, TrapError> {
    let region = retained_abi_region(custody).ok_or_else(stale)?;
    let (task, zone) = stopped_records(region, cpu).ok_or_else(stale)?;
    let Some(selector) = task.service_notice.take().map_err(|_| stale())? else {
        return Ok(None);
    };
    let Some(key) = ObjectWaitKey::native_service(selector.record) else {
        return Ok(None);
    };
    let Ok(queue) = zone.object_wait(key, &carrick_sched_core::ShortLockSpin) else {
        return Ok(None);
    };
    let Some(identity) = queue.native_service_member(selector.record) else {
        return Ok(None);
    };
    if identity.generation != selector.execution.raw() {
        return Ok(None);
    }
    let Some(generation) = custody.live_generation() else {
        return Err(stale());
    };
    let address = carrick_guest_arch::KernelVa::new(identity.control_slot);
    let Some((_, base, len)) = retained_dynamic_metadata(
        custody,
        address,
        core::mem::size_of::<carrick_el1_abi::ThreadControlSlot>(),
    ) else {
        return Ok(None);
    };
    let offset = identity.control_slot.checked_sub(base).ok_or_else(stale)? as usize;
    if offset
        .checked_add(core::mem::size_of::<carrick_el1_abi::ThreadControlSlot>())
        .is_none_or(|end| end > len)
    {
        return Err(stale());
    }
    let pin = {
        let aperture = metadata_aperture(custody).lock();
        let index =
            ((base - EL1_DYNAMIC_METADATA_BASE) / EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64) as usize;
        let Some(mapping) = aperture.slots.get(index).and_then(Option::as_ref) else {
            return Ok(None);
        };
        let extent = MetadataExtent::new(base, len as u64, mapping.token).ok_or_else(stale)?;
        aperture
            .pin_extent(extent, generation.0)
            .map_err(|_| stale())?
    };
    // SAFETY: checked whole control range inside the pinned metadata extent.
    let control = unsafe {
        pin.host_base()
            .as_ptr()
            .add(offset)
            .cast::<carrick_el1_abi::ThreadControlSlot>()
    };
    if !control
        .addr()
        .is_multiple_of(core::mem::align_of::<carrick_el1_abi::ThreadControlSlot>())
    {
        return Err(stale());
    }
    // SAFETY: initialized control belongs to the exact live native record;
    // the service queue serializes cancellation/consumption with this intake.
    let control = unsafe { &*control };
    if control.zone_record() != Some(selector.record) || !control.native_signal_owner() {
        return Ok(None);
    }
    let pin = ServicePin {
        cell: core::ptr::NonNull::from(&control.service),
        _mapping: pin,
        _carrier: Arc::clone(custody),
    };
    // SAFETY: exact record/control and native birth authenticated above. The
    // ring's active service claim retains its admitted MM through ticket ACK.
    let ticket =
        unsafe { ServiceCell::claim_notice(pin, selector, custody.transfer_carrier, identity) };
    match ticket {
        Ok(mut ticket) => {
            let portal = region
                .record_ptr::<carrick_el1_abi::MmPortalSlots>(
                    carrick_el1_abi::EL1_MM_PORTAL_OFFSET as usize,
                )
                .ok_or_else(stale)?;
            // SAFETY: initialized portal in the retained carrier ABI region.
            let portal = unsafe { &*portal };
            let cow = ticket
                .take_fault_selection(portal.grant(cpu.raw() as usize).ok_or_else(stale)?)
                .map_err(|_| stale())?;
            Ok(Some(NativeService {
                ticket,
                cow,
                custody: Arc::clone(custody),
                slot: carrick_sched_core::SlotId::from_index(cpu.raw() as usize)
                    .ok_or_else(stale)?,
            }))
        }
        // A stale selector cannot acknowledge or complete a successor.
        Err(ServiceError::Stale) => Ok(None),
        Err(_) => Err(stale()),
    }
}

// The stock lock retains the table arenas; exclusion prevents descriptor edits.
fn native_output(
    custody: &crate::trap::CarrierVmCustody,
    root: carrick_guest_arch::RootGpa,
    va: u64,
) -> Option<u64> {
    let mut table = root.address().raw();
    for (level, index) in carrick_mmu_core::aarch64::indices(va)
        .into_iter()
        .enumerate()
    {
        let pointer = crate::fork_stock::ForkStockHostCustody::physical_ptr::<AtomicU64>(
            custody,
            carrick_guest_arch::FrameGpa::new(table + index as u64 * 8),
        )
        .ok()?;
        // SAFETY: retained stock tables and exact owner exclusion, atomic word.
        let word = unsafe { &*pointer }.load(Ordering::Acquire);
        if level == 3 {
            return (word != 0).then_some(word & carrick_sched_core::AARCH64_ROOT_ADDRESS_MASK);
        }
        if word & 3 != 3 {
            return None;
        }
        table = word & carrick_sched_core::AARCH64_ROOT_ADDRESS_MASK;
    }
    None
}

pub(crate) fn settle_native_cow(
    custody: &crate::trap::CarrierVmCustody,
    pool: &carrick_el1_abi::CowGrantPool,
    excluded: &carrick_sched_core::ExcludedEditor<'_>,
) -> Result<Option<usize>, TrapError> {
    let mm = carrick_el1_abi::ReservationMm::new(excluded.key()).ok_or_else(stale)?;
    let mut stock = custody.fork_stock.lock();
    let Some(root) = stock.owner.child_root(mm) else {
        return Ok(None);
    };
    let physical = stock.owner.child_physical_mut(mm, root).ok_or_else(stale)?;
    let Some(grants) = &mut physical.supplied else {
        return if pool.has_completions_for(mm.raw()) {
            Err(stale())
        } else {
            Ok(Some(0))
        };
    };
    grants
        .settle(pool, excluded, |va| native_output(custody, root, va))
        .map(Some)
}
