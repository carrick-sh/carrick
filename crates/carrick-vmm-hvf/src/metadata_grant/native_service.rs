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
}
impl core::fmt::Debug for NativeService {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NativeService")
            .field("request", &self.request())
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

    fn complete(self, supplied: bool) -> Result<carrick_sched_core::WakeEffects, TrapError> {
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
        self.ticket.complete(supplied).map_err(|_| stale())?;
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
    let Ok(_queue) = zone.object_wait(key, &carrick_sched_core::ShortLockSpin) else {
        return Ok(None);
    };
    let Some(record) = zone
        .live(selector.record)
        .filter(|record| record.is_native_owned())
    else {
        return Ok(None);
    };
    let identity = record.identity();
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
        Ok(ticket) => Ok(Some(NativeService {
            ticket,
            custody: Arc::clone(custody),
            slot: carrick_sched_core::SlotId::from_index(cpu.raw() as usize).ok_or_else(stale)?,
        })),
        // A stale selector cannot acknowledge or complete a successor.
        Err(ServiceError::Stale) => Ok(None),
        Err(_) => Err(stale()),
    }
}
