//! Backing custody for a ring-owned request; no host task or process adoption.
use super::*;
use carrick_core_abi::service::{
    ServiceCell, ServiceError, ServiceFailureCode, ServiceRequest, ServiceSelector, ServiceTicket,
};
use carrick_sched_core::object_wait::ObjectWaitKey;
use core::ops::Deref;

/// Carrier-retained file/loader service. It owns no task lookup; the service
/// cell has already authenticated `request` against the stopped ring member.
pub trait NativeExecHostService: core::fmt::Debug + Send + Sync + 'static {
    fn prepare(
        &self,
        request: ServiceRequest,
        payload: &[u8],
    ) -> Result<Box<dyn NativeExecPreparation>, ServiceFailureCode>;
}

/// Opaque fallibly prepared image. Exact carrier custody retains this result
/// until the ring consumes successor adoption or terminal cleanup drops it.
pub trait NativeExecPreparation: core::fmt::Debug + Send + 'static {
    fn into_mapping_plan(self: Box<Self>) -> crate::trap::GuestMappingPlan;
}

struct ServicePin {
    cell: core::ptr::NonNull<ServiceCell>,
    _mapping: HostMetadataExtentPin,
    _carrier: Arc<crate::trap::CarrierVmCustody>,
}
struct RetainedExecPayload {
    pointer: core::ptr::NonNull<u8>,
    len: usize,
    _mapping: Option<HostMetadataExtentPin>,
}
enum NativeServiceReply {
    Fault(core::ptr::NonNull<carrick_el1_abi::PortalGrantSlot>),
    Exec(core::ptr::NonNull<carrick_core_abi::service::ExecSuccessorManifest>),
}

impl RetainedExecPayload {
    fn bytes(&self) -> &[u8] {
        // SAFETY: intake authenticated the whole contiguous range against the
        // exact live stage-1 root. The ring retains the allocation through ACK;
        // a dynamic aperture allocation additionally retains its host mapping.
        unsafe { core::slice::from_raw_parts(self.pointer.as_ptr(), self.len) }
    }
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
    reply: Option<NativeServiceReply>,
    _reply_pin: Option<HostMetadataExtentPin>,
    exec_payload: Option<RetainedExecPayload>,
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
        let request = self.request();
        if let carrick_core_abi::service::ServiceOperation::Crossing { ordinal } = request.operation
        {
            carrick_observability::probes::hvpatch_native_crossing_refused(
                request.identity.birth.mm.mm().raw(),
                request.identity.birth.mm.incarnation().get(),
                request.identity.birth.record.id.raw(),
                request.identity.sequence.get(),
                ordinal.raw(),
            );
        }
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

    /// The single contiguous ring-owned input for a typed exec request.
    pub fn exec_payload(&self) -> Option<&[u8]> {
        self.exec_payload.as_ref().map(RetainedExecPayload::bytes)
    }

    /// Resolve and run the retained exec service selected by the authenticated
    /// request. Preparation performs all fallible file and loader work before
    /// publishing `Supplied`; the result remains carrier-owned by exact
    /// birth/MM/execution/sequence.
    pub fn prepare_exec(self) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        let request = self.request();
        let (capability, payload) = match request.operation {
            carrick_core_abi::service::ServiceOperation::Exec {
                capability,
                payload: _,
            } => (capability, self.exec_payload().ok_or_else(stale)?),
            _ => return self.refuse(),
        };
        let (successor_mm, manifest) = match self.reply.as_ref() {
            Some(NativeServiceReply::Exec(manifest)) => {
                // SAFETY: intake pinned the complete aligned ring-owned reply;
                // request completion has not yet released that allocation.
                let successor_mm = unsafe { manifest.as_ref() }
                    .proposal(request.identity)
                    .ok_or_else(stale)?;
                (successor_mm, *manifest)
            }
            _ => return Err(stale()),
        };
        let service = self
            .custody
            .native_exec_service(capability)
            .ok_or_else(stale)?;
        match service.prepare(request, payload) {
            Ok(prepared) => {
                let prepared = match crate::trap::prepare_native_exec_successor(
                    Arc::clone(&self.custody),
                    prepared.into_mapping_plan(),
                ) {
                    Ok(prepared) => prepared,
                    Err(_) => {
                        return self.finish_exec_failure(
                            ServiceFailureCode::new(12).unwrap_or(ServiceFailureCode::MINIMUM),
                        );
                    }
                };
                self.publish_exec_prepared(successor_mm, manifest, prepared)
            }
            Err(failure) => self.finish_exec_failure(failure),
        }
    }

    fn publish_exec_prepared(
        self,
        successor_mm: carrick_el1_abi::ReservationMm,
        manifest: core::ptr::NonNull<carrick_core_abi::service::ExecSuccessorManifest>,
        prepared: crate::trap::PreparedNativeExecSuccessor,
    ) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        let identity = self.request().identity;
        let custody = Arc::clone(&self.custody);
        let receipt = custody.reserve_native_exec_receipt().map_err(|()| {
            TrapError::Hypervisor("native exec receipt space exhausted".to_owned())
        })?;
        let asid = prepared.prepared_asid().ok_or_else(stale)?;
        let sealed = unsafe { manifest.as_ref() }
            .seal(
                identity,
                receipt,
                carrick_core_abi::service::ExecSuccessorBacking {
                    root: prepared.root(),
                    root_generation: receipt.raw(),
                    asid: asid.asid(),
                    asid_generation: core::num::NonZeroU64::new(asid.generation())
                        .ok_or_else(stale)?,
                },
                carrick_core_abi::service::ExecSuccessorEntry {
                    entry: carrick_guest_arch::UserVa::new(prepared.entry()),
                    stack_pointer: carrick_guest_arch::UserVa::new(
                        prepared.stack_pointer().ok_or_else(stale)?,
                    ),
                },
            )
            .ok_or_else(stale)?;
        if sealed
            .open(identity, receipt)
            .is_none_or(|view| view.successor_mm != successor_mm)
        {
            return Err(stale());
        }
        self.finish_exec_ticket(|ticket| {
            match ticket.publish_exec_prepared(receipt, prepared, |receipt, prepared| {
                custody.retain_native_exec_preparation(receipt, identity, prepared);
                // SAFETY: the exact ticket retains this pinned, aligned reply
                // until the release-store completion below.
                unsafe { manifest.as_ptr().write(sealed) };
            }) {
                Ok(()) => Ok(()),
                Err((_, ticket, prepared)) => {
                    drop(prepared);
                    ticket.complete(false).map_err(|_| stale())
                }
            }
        })
    }

    fn finish_exec_failure(
        self,
        failure: ServiceFailureCode,
    ) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        self.finish_exec_ticket(|ticket| ticket.complete_failure(failure).map_err(|_| stale()))
    }

    fn finish_exec_ticket(
        self,
        complete: impl FnOnce(ServiceTicket<ServicePin>) -> Result<(), TrapError>,
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
        complete(self.ticket)?;
        let mut effects = carrick_sched_core::WakeEffects::default();
        queue
            .notify_object(self.slot, &mut effects)
            .map_err(|_| stale())?;
        Ok(effects)
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
        if let Some(selection) = self.cow {
            use carrick_core_abi::service::ServiceFaultSupply;
            use carrick_observability::probes::HvpatchNativeFaultPhase;
            let (phase, window) = match selection {
                ServiceFaultSupply::Cow(window) => (HvpatchNativeFaultPhase::Cow, window),
                ServiceFaultSupply::Backing(window) => (HvpatchNativeFaultPhase::Backing, window),
            };
            carrick_observability::probes::hvpatch_native_fault_supply(
                self.request().identity.birth.mm.mm().raw(),
                self.request().identity.sequence.get(),
                phase,
                window.fault_page,
                window.range.len(),
            );
        } else if let carrick_core_abi::service::ServiceOperation::Fault(fault) =
            self.request().operation
        {
            carrick_observability::probes::hvpatch_native_fault_supply(
                self.request().identity.birth.mm.mm().raw(),
                self.request().identity.sequence.get(),
                carrick_observability::probes::HvpatchNativeFaultPhase::Unselected,
                fault.address.raw() & !4095,
                0,
            );
        }
        let window = match self.cow {
            Some(carrick_core_abi::service::ServiceFaultSupply::Cow(window)) => window,
            Some(carrick_core_abi::service::ServiceFaultSupply::Backing(window)) => {
                return self.supply_backing(window);
            }
            None => return self.refuse(),
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
        grants.settle(pool, exclusion.proof())?;
        if pool.ready(handle.mm().raw()).next().is_none() {
            for _ in 0..carrick_hal::physical_grants::NativePhysicalGrants::<
                crate::fork_stock::NativeFrameBacking,
            >::REFILL_GRANTS
            {
                let (_, ipa, generation) = crate::trap::allocate_grant_compound(
                    &custody,
                    crate::trap::hvf_mem_perms(carrick_hal::physical_grants::COW_GRANT_PERMISSIONS),
                )?;
                let retained = Arc::new(crate::fork_stock::NativeFrameBacking {
                    carrier: Arc::downgrade(&custody),
                    ipa,
                    generation,
                    length: carrick_el1_abi::COW_GRANT_SIZE,
                });
                custody
                    .native_frame_backings
                    .lock()
                    .insert((ipa, generation), Arc::downgrade(&retained));
                let staged =
                    carrick_hal::physical_grants::StagedPhysicalGrants::stage_with_permissions(
                        Arc::clone(&physical.rollback),
                        Arc::clone(&inventory),
                        [carrick_guest_arch::FrameGpa::new(ipa)],
                        0,
                        carrick_el1_abi::COW_GRANT_SIZE,
                        owner,
                        carrick_hal::physical_grants::COW_GRANT_PERMISSIONS,
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

    fn supply_backing(
        self,
        window: carrick_el1_abi::PortalGrantWindow,
    ) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        use carrick_mmu_core::aarch64::descriptor_txn::{
            DescriptorOp, DescriptorTxn, DescriptorTxnId, MAX_TABLE_GRANTS, PageSpan,
        };
        use carrick_mmu_core::aarch64::{GuestLeafPublication, SubstrateGpa};
        let Some(NativeServiceReply::Fault(reply)) = self.reply else {
            return self.refuse();
        };
        let custody = Arc::clone(&self.custody);
        let handle = self.request().identity.birth.mm;
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
        let source = window
            .host_backing
            .map(|identity| physical.sources.retain(identity, || None).ok_or_else(stale))
            .transpose()?;
        // File I/O retains only its bounded source capability. It must not
        // hold carrier-wide stock custody while another native child exits.
        drop(stock);
        let bytes = if let Some(source) = source {
            let identity = window.host_backing.ok_or_else(stale)?;
            let read = carrick_hal::fork_stock::HostBackingRead::new(
                identity,
                window.range.len() as usize,
            )
            .ok_or_else(stale)?;
            match source.read(read) {
                Ok(bytes) => Some(bytes),
                Err(
                    carrick_hal::fork_stock::HostBackingReadError::Inaccessible
                    | carrick_hal::fork_stock::HostBackingReadError::Unavailable,
                ) => {
                    return self.finish(None, false, true);
                }
                Err(_) => return self.refuse(),
            }
        } else {
            None
        };
        let mut stock = custody.fork_stock.lock();
        if stock.owner.child_owner(handle.mm()) != Some(handle)
            || stock.owner.child_root(handle.mm()) != Some(root)
            || stock.owner.is_quarantined(handle.mm())
        {
            return self.refuse();
        }
        let physical = stock
            .owner
            .child_physical_mut(handle.mm(), root)
            .ok_or_else(stale)?;
        let publication_len = bytes
            .as_ref()
            .map_or(window.range.len(), |bytes| bytes.len() as u64);
        if window.fault_page >= window.range.start() + publication_len {
            return self.finish(None, false, true);
        }
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
        let data_len = publication_len.next_multiple_of(carrick_el1_abi::COW_GRANT_SIZE);
        let executable = window
            .protection
            .permits(carrick_el1_abi::ReservationProtection::EXECUTE);
        // Like the existing private-backing adapter, preserve physical COW
        // and later executable-publication capacity. The exact MM's inventory
        // and stage-1 publication below retain the selected access policy.
        let perms = crate::trap::hvf_mem_perms(carrick_hal::physical_grants::COW_GRANT_PERMISSIONS);
        let length = data_len;
        let (host, ipa, generation) = crate::trap::allocate_grant_extent(&custody, perms, length)?;
        let retained = Arc::new(crate::fork_stock::NativeFrameBacking {
            carrier: Arc::downgrade(&custody),
            ipa,
            generation,
            length,
        });
        custody
            .native_frame_backings
            .lock()
            .insert((ipa, generation), Arc::downgrade(&retained));
        if let Some(bytes) = bytes {
            // SAFETY: retained writable allocation contains this bounded data span.
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), host, bytes.len());
            }
        }
        if executable {
            crate::trap::invalidate_instruction_cache(host, data_len);
        }
        let staged = carrick_hal::physical_grants::StagedPhysicalGrants::stage_with_permissions(
            Arc::clone(&physical.rollback),
            inventory,
            [carrick_guest_arch::FrameGpa::new(ipa)],
            0,
            data_len,
            owner,
            carrick_hal::MemPerms {
                read: true,
                write: window
                    .protection
                    .permits(carrick_el1_abi::ReservationProtection::WRITE),
                exec: executable,
            },
        )?;
        let rows = grants.retain_backing(staged, retained)?;
        let data = rows.first().ok_or_else(stale)?;
        let table_reservation = match stock.owner.reserve_native_descriptor_tables(
            &mut crate::fork_stock::fork_table_accounting(&custody),
            handle,
            root,
            MAX_TABLE_GRANTS,
        ) {
            Ok(reservation) => reservation,
            Err(_) => {
                drop(stock);
                return self.refuse();
            }
        };
        let txn = DescriptorTxn {
            id: DescriptorTxnId {
                mm_key: core::num::NonZeroU64::new(handle.mm().raw()).ok_or_else(stale)?,
                generation: window.operation.sequence,
            },
            root: SubstrateGpa(root.address().raw()),
            op: DescriptorOp::Prepare {
                publication: GuestLeafPublication {
                    va: window.range.start(),
                    ipa: data.gpa.raw(),
                    len: publication_len,
                    writable: window
                        .protection
                        .permits(carrick_el1_abi::ReservationProtection::WRITE),
                    executable,
                },
                resident: PageSpan::new(window.fault_page, 4096),
                backing: data.identity,
            },
            tables: table_reservation.descriptor_tables(),
        };
        if stock
            .owner
            .track_native_descriptor_tables(
                &mut crate::fork_stock::fork_table_accounting(&custody),
                table_reservation,
                txn,
            )
            .is_err()
        {
            drop(stock);
            return self.refuse();
        }
        // SAFETY: intake pinned and authenticated the request-owned reply. The
        // ring retains it through ACK, then revalidates and executes this slot.
        let submitted = unsafe { reply.as_ref() }.submit(window, &txn);
        if !submitted {
            stock
                .owner
                .cancel_submitted_native_descriptor_tables(
                    &mut crate::fork_stock::fork_table_accounting(&custody),
                    handle,
                    root,
                    txn.id.generation,
                )
                .map_err(|_| stale())?;
        }
        drop(stock);
        self.complete(submitted)
    }
    fn complete_wait(
        self,
        wait: carrick_el1_abi::PortalOwnerWait,
    ) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        self.finish(Some(wait), false, false)
    }
    fn complete(self, supplied: bool) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        self.finish(None, supplied, false)
    }
    fn finish(
        self,
        wait: Option<carrick_el1_abi::PortalOwnerWait>,
        supplied: bool,
        backing_fault: bool,
    ) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        let request = self.request();
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
        if backing_fault {
            self.ticket.complete_backing_fault().map_err(|_| stale())?;
        } else if let Some(wait) = wait {
            self.ticket.complete_wait(wait).map_err(|_| stale())?;
        } else {
            self.ticket.complete(supplied).map_err(|_| stale())?;
        }
        let mut effects = carrick_sched_core::WakeEffects::default();
        queue
            .notify_object(self.slot, &mut effects)
            .map_err(|_| stale())?;
        if matches!(
            request.operation,
            carrick_core_abi::service::ServiceOperation::Fault(_)
        ) {
            use carrick_observability::probes::HvpatchNativeFaultPhase;
            let phase = if backing_fault {
                HvpatchNativeFaultPhase::BackingFault
            } else if wait.is_some() {
                HvpatchNativeFaultPhase::OwnerWait
            } else if supplied {
                HvpatchNativeFaultPhase::Supplied
            } else {
                HvpatchNativeFaultPhase::Refused
            };
            carrick_observability::probes::hvpatch_native_fault_supply(
                request.identity.birth.mm.mm().raw(),
                request.identity.sequence.get(),
                phase,
                0,
                0,
            );
        }
        Ok(effects)
    }
}
fn stale() -> TrapError {
    TrapError::Hypervisor("native service custody mismatch".into())
}

/// Once the lane notice is consumed, absence is no longer a valid intake
/// result: the ring member remains parked until this host owner completes it.
struct ConsumedServiceNotice(ServiceSelector);
impl ConsumedServiceNotice {
    fn selector(&self) -> ServiceSelector {
        self.0
    }

    fn miss<T>(&self, reason: &'static str) -> Result<T, TrapError> {
        Err(TrapError::Hypervisor(format!(
            "native service intake failed after consuming record {}:{} sequence {}: {reason}",
            self.0.record.id.raw(),
            self.0.record.incarnation,
            self.0.sequence,
        )))
    }
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
    let consumed = ConsumedServiceNotice(selector);
    let service = (|| {
        let selector = consumed.selector();
        let Some(key) = ObjectWaitKey::native_service(selector.record) else {
            return consumed.miss("invalid native-service wait key");
        };
        let Ok(queue) = zone.object_wait(key, &carrick_sched_core::ShortLockSpin) else {
            return consumed.miss("native-service wait queue unavailable");
        };
        let Some(identity) = queue.native_service_member(selector.record) else {
            return consumed.miss("native-service member absent");
        };
        if identity.generation != selector.execution.raw() {
            return consumed.miss("native-service execution generation changed");
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
            return consumed.miss("native-service control metadata absent");
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
            let index = ((base - EL1_DYNAMIC_METADATA_BASE)
                / EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64) as usize;
            let Some(mapping) = aperture.slots.get(index).and_then(Option::as_ref) else {
                return consumed.miss("native-service metadata aperture absent");
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
            return consumed.miss("native-service control owner changed");
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
                let (reply, reply_pin) = if let Some(address) = ticket.reply_address() {
                    match ticket.request().operation {
                        carrick_core_abi::service::ServiceOperation::Fault(fault)
                            if !fault.present =>
                        {
                            let (pointer, pin) = retain_reply::<carrick_el1_abi::PortalGrantSlot>(
                                custody, region, address,
                            )?;
                            (Some(NativeServiceReply::Fault(pointer)), pin)
                        }
                        carrick_core_abi::service::ServiceOperation::Exec { .. } => {
                            let (pointer, pin) =
                                retain_reply::<carrick_core_abi::service::ExecSuccessorManifest>(
                                    custody, region, address,
                                )?;
                            (Some(NativeServiceReply::Exec(pointer)), pin)
                        }
                        _ => return Err(stale()),
                    }
                } else {
                    (None, None)
                };
                let exec_payload = match ticket.request().operation {
                    carrick_core_abi::service::ServiceOperation::Exec { payload, .. } => {
                        Some(retain_exec_payload(
                            custody,
                            region,
                            ticket.request().identity.birth.mm,
                            payload,
                        )?)
                    }
                    _ => None,
                };
                Ok(NativeService {
                    reply,
                    _reply_pin: reply_pin,
                    exec_payload,
                    ticket,
                    cow,
                    custody: Arc::clone(custody),
                    slot: carrick_sched_core::SlotId::from_index(cpu.raw() as usize)
                        .ok_or_else(stale)?,
                })
            }
            // A stale selector cannot acknowledge or complete a successor.
            Err(ServiceError::Stale) => consumed.miss("native-service cell rejected selector"),
            Err(_) => Err(stale()),
        }
    })()?;
    Ok(Some(service))
}

fn retain_exec_payload(
    custody: &Arc<crate::trap::CarrierVmCustody>,
    region: RetainedAbiRegion<'_>,
    handle: carrick_core_abi::El1MmHandle,
    payload: carrick_core_abi::service::ExecPayloadDescriptor,
) -> Result<RetainedExecPayload, TrapError> {
    let address = payload.address().raw();
    let len = usize::try_from(payload.length().raw()).map_err(|_| stale())?;
    let end = address.checked_add(len as u64).ok_or_else(stale)?;

    // Authentication is against the request's retained MM incarnation, not
    // whichever task a host process lookup happens to find.
    {
        let stock = custody.fork_stock.lock();
        if stock.owner.child_owner(handle.mm()) != Some(handle) {
            return Err(stale());
        }
        let root = stock.owner.child_root(handle.mm()).ok_or_else(stale)?;
        let mut cursor = address;
        while cursor < end {
            if native_output(custody, root, cursor) != Some(cursor & !4095) {
                return Err(stale());
            }
            cursor = end.min((cursor | 4095).checked_add(1).ok_or_else(stale)?);
        }
    }

    let bootstrap_start = carrick_el1_abi::EL1_BOOTSTRAP_METADATA_BASE;
    let bootstrap_end = bootstrap_start + carrick_el1_abi::EL1_BOOTSTRAP_METADATA_SIZE;
    if address >= bootstrap_start && end <= bootstrap_end {
        let offset =
            usize::try_from(address - carrick_el1_abi::EL1_REGION_BASE).map_err(|_| stale())?;
        let pointer = core::ptr::NonNull::new(region.record_ptr::<u8>(offset).ok_or_else(stale)?)
            .ok_or_else(stale)?;
        return Ok(RetainedExecPayload {
            pointer,
            len,
            _mapping: None,
        });
    }

    let address = carrick_guest_arch::KernelVa::new(address);
    let (_, base, extent_len) =
        retained_dynamic_metadata(custody, address, len).ok_or_else(stale)?;
    let generation = custody.live_generation().ok_or_else(stale)?;
    let pin = {
        let aperture = metadata_aperture(custody).lock();
        let index =
            ((base - EL1_DYNAMIC_METADATA_BASE) / EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64) as usize;
        let mapping = aperture
            .slots
            .get(index)
            .and_then(Option::as_ref)
            .ok_or_else(stale)?;
        aperture
            .pin_extent(
                MetadataExtent::new(base, extent_len as u64, mapping.token).ok_or_else(stale)?,
                generation.0,
            )
            .map_err(|_| stale())?
    };
    // SAFETY: retained_dynamic_metadata checked the complete payload range.
    let pointer = unsafe {
        pin.host_base()
            .as_ptr()
            .add((address.raw() - base) as usize)
    };
    Ok(RetainedExecPayload {
        pointer: core::ptr::NonNull::new(pointer).ok_or_else(stale)?,
        len,
        _mapping: Some(pin),
    })
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
    grants.settle(pool, excluded).map(Some)
}

/// Consume the exact reply-slot receipt while the native child still owns its
/// synchronous service continuation. A refused or unclaimed submission returns
/// all table grants; an applied receipt retains only its linked prefix.
pub(super) fn settle_native_descriptor_reply(
    custody: &Arc<crate::trap::CarrierVmCustody>,
    region: RetainedAbiRegion<'_>,
    execution: carrick_hal::fork_stock::GrantExecution,
    settlement: &mut carrick_el1_abi::NativeDescriptorSettlement,
) -> bool {
    let accepted = (|| -> Result<(), ()> {
        let (owner, generation, reply_address) = settlement.request().ok_or(())?;
        if execution.binding.mm.raw() != owner.mm().raw() {
            return Err(());
        }
        let (reply, _pin) =
            retain_reply::<carrick_el1_abi::PortalGrantSlot>(custody, region, reply_address)
                .map_err(|_| ())?;
        // SAFETY: retain_reply pins the complete aligned slot until settlement.
        let reply = unsafe { reply.as_ref() };
        let window = reply.window().ok_or(())?;
        if window.operation.carrier != owner.carrier()
            || window.operation.mm != owner.mm()
            || window.operation.incarnation != owner.incarnation()
            || window.operation.sequence != generation
        {
            return Err(());
        }
        let mut stock = custody.fork_stock.lock();
        if stock.owner.child_owner(owner.mm()) != Some(owner)
            || stock.owner.child_root(owner.mm()) != Some(execution.context.root)
        {
            return Err(());
        }
        let txn = stock
            .owner
            .pending_native_descriptor_transaction(owner, execution.context.root, generation)
            .ok_or(())?;
        let mut ledger = crate::fork_stock::fork_table_accounting(custody);
        if let Some(receipt) = reply.take_receipt(window, &txn) {
            stock
                .owner
                .settle_native_descriptor_tables(
                    &mut ledger,
                    owner,
                    execution.context.root,
                    &receipt,
                )
                .map_err(|_| ())?;
        } else if reply.withdraw(window, &txn) {
            stock
                .owner
                .cancel_submitted_native_descriptor_tables(
                    &mut ledger,
                    owner,
                    execution.context.root,
                    generation,
                )
                .map_err(|_| ())?;
        } else {
            return Err(());
        }
        Ok(())
    })()
    .is_ok();
    if accepted {
        settlement.accept()
    } else {
        settlement.refuse()
    }
}

pub(super) fn retain_reply<T>(
    custody: &Arc<crate::trap::CarrierVmCustody>,
    region: RetainedAbiRegion<'_>,
    address: carrick_guest_arch::KernelVa,
) -> Result<(core::ptr::NonNull<T>, Option<HostMetadataExtentPin>), TrapError> {
    let size = core::mem::size_of::<T>();
    if address.raw() < EL1_DYNAMIC_METADATA_BASE {
        let offset = address
            .raw()
            .checked_sub(carrick_el1_abi::EL1_REGION_BASE)
            .and_then(|offset| usize::try_from(offset).ok())
            .filter(|offset| fork_custody_in_retained_region(*offset, size))
            .ok_or_else(stale)?;
        return Ok((
            core::ptr::NonNull::new(region.record_ptr(offset).ok_or_else(stale)?)
                .ok_or_else(stale)?,
            None,
        ));
    }
    let (_, base, len) = retained_dynamic_metadata(custody, address, size).ok_or_else(stale)?;
    let generation = custody.live_generation().ok_or_else(stale)?;
    let pin = {
        let aperture = metadata_aperture(custody).lock();
        let index =
            ((base - EL1_DYNAMIC_METADATA_BASE) / EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64) as usize;
        let mapping = aperture
            .slots
            .get(index)
            .and_then(Option::as_ref)
            .ok_or_else(stale)?;
        aperture
            .pin_extent(
                MetadataExtent::new(base, len as u64, mapping.token).ok_or_else(stale)?,
                generation.0,
            )
            .map_err(|_| stale())?
    };
    // SAFETY: the exact request retains the whole aligned ring-owned reply.
    let pointer = unsafe {
        pin.host_base()
            .as_ptr()
            .add((address.raw() - base) as usize)
    };
    if !pointer.addr().is_multiple_of(core::mem::align_of::<T>()) {
        return Err(stale());
    }
    Ok((
        core::ptr::NonNull::new(pointer.cast()).ok_or_else(stale)?,
        Some(pin),
    ))
}

#[cfg(test)]
mod intake_tests {
    use super::*;
    use carrick_core_abi::{EntryThreadGeneration, SnapshotGeneration};
    use carrick_guest_arch::NativeOrdinal;
    use carrick_sched_core::{
        RecordId, RecordRef,
        process::{TaskId, TaskKey, TaskSerial},
    };
    use core::num::{NonZeroI32, NonZeroU64};

    fn birth() -> carrick_core_abi::service::ServiceBirth {
        let generation = NonZeroU64::MIN;
        carrick_core_abi::service::ServiceBirth {
            process: TaskKey {
                id: TaskId::from_registry_allocation(NonZeroI32::new(1).unwrap()),
                serial: TaskSerial::from_registry_allocation(generation),
            },
            thread: EntryThreadGeneration::from_raw(generation.get()),
            record: RecordRef {
                id: RecordId::from_raw(1).unwrap(),
                incarnation: generation.get(),
            },
            // SAFETY: this protocol-only fixture never authorizes memory access.
            mm: unsafe {
                carrick_el1_abi::El1MmHandle::from_admitted_owner(
                    NonZeroU64::MIN,
                    carrick_el1_abi::ReservationMm::new(1).unwrap(),
                    generation,
                )
            },
        }
    }

    #[test]
    fn consumed_notice_intake_miss_is_loud_with_sigkill_pending() {
        let cell = ServiceCell::new();
        let birth = birth();
        cell.bind(birth).unwrap();
        let request = cell
            .publish(
                birth,
                SnapshotGeneration::INITIAL,
                carrick_core_abi::service::ServiceOperation::Crossing {
                    ordinal: NativeOrdinal::new(1),
                },
                None,
            )
            .unwrap();
        let notice = carrick_core_abi::service::ServiceNotice::new();
        notice.publish(request.identity.into()).unwrap();
        let consumed = ConsumedServiceNotice(notice.take().unwrap().unwrap());

        assert_eq!(
            cell.cancel(request.identity),
            Ok(false),
            "SIGKILL cancellation waits for the physical intake owner"
        );
        let intake: Result<(), TrapError> = consumed.miss("missing host intake member");
        assert!(
            intake.is_err(),
            "a consumed notice cannot silently leave the parked member REQUESTED"
        );

        let ticket = cell.claim(request).unwrap();
        assert!(ticket.complete(false).is_ok());
        assert_eq!(
            cell.consume(request.identity),
            Ok(carrick_core_abi::service::ServiceResult::Cancelled)
        );
    }
}
