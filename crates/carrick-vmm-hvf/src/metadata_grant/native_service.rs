//! Backing custody for a ring-owned request; no host task or process adoption.
use super::*;
use carrick_core_abi::service::{
    ServiceCell, ServiceError, ServiceFailureCode, ServiceRequest, ServiceSelector, ServiceTicket,
};
use carrick_sched_core::object_wait::ObjectWaitKey;
use core::ops::Deref;

struct ServicePin {
    cell: core::ptr::NonNull<ServiceCell>,
    /// `None` for a control in the ring's bootstrap arena, which the retained
    /// carrier ABI region backs (see [`retain_ring_record`]).
    _mapping: Option<HostMetadataExtentPin>,
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
    fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as `bytes`; additionally the parked ring continuation does not
        // touch a host-file record until it consumes this ticket's ACK, and this
        // unique ticket is the only carrier view of it.
        unsafe { core::slice::from_raw_parts_mut(self.pointer.as_ptr(), self.len) }
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

mod root_wait;
pub(crate) use root_wait::NativeRootWaitLedger;

/// One root service owns one reply until its exact descriptor receipt settles.
/// At most one service exists per zone record, so this directory is bounded by
/// the admitted record population, independently of mappings and faults.
pub(crate) struct NativeRootReplyLedger {
    entries: Vec<NativeRootReply>,
}
impl Default for NativeRootReplyLedger {
    fn default() -> Self {
        Self {
            // Admission bounds every later push, including the one beneath
            // the service queue: no allocator or directory growth there.
            entries: Vec::with_capacity(carrick_sched_core::ZONE_RECORDS),
        }
    }
}
impl core::fmt::Debug for NativeRootReplyLedger {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NativeRootReplyLedger")
            .field("pending", &self.entries.len())
            .finish()
    }
}
struct NativeRootReply {
    identity: carrick_core_abi::service::ServiceIdentity,
    root: carrick_guest_arch::RootGpa,
    reply: carrick_guest_arch::KernelVa,
    window: carrick_el1_abi::PortalGrantWindow,
    grant: Box<dyn carrick_aarch64::user_transfer::TransferGrant>,
    _pin: Option<Arc<MetadataBacking>>,
}
impl NativeRootReplyLedger {
    fn admits(&self, entry: &NativeRootReply) -> bool {
        self.entries.len() < carrick_sched_core::ZONE_RECORDS
            && !self.entries.iter().any(|held| {
                held.identity.birth.record.id == entry.identity.birth.record.id
                    || held.reply == entry.reply
            })
    }
    /// Called only after the carrier's successful backend destruction. Each
    /// grant independently authenticates its terminal physical owner before
    /// abandoning descriptor visibility; failed destruction never reaches here.
    pub(crate) fn release_destroyed_vm(&mut self) -> Result<(), TrapError> {
        for entry in &mut self.entries {
            entry.grant.release_destroyed_vm()?;
        }
        self.entries.clear();
        Ok(())
    }
}

/// A unique physical service ticket. The ring retains its continuation, MM,
/// and member; this host object retains only backing and carrier observation.
#[must_use]
pub struct NativeService {
    census: core::ptr::NonNull<carrick_el1_abi::Counters>,
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
fn with_native_sources_of<R>(
    custody: &crate::trap::CarrierVmCustody,
    handle: carrick_core_abi::El1MmHandle,
    f: impl FnOnce(&mut carrick_hal::fork_stock::ForkHostBackingCustody) -> R,
) -> Option<R> {
    let mut stock = custody.fork_stock.lock();
    if stock.owner.child_owner(handle.mm()) != Some(handle)
        || stock.owner.is_quarantined(handle.mm())
    {
        return None;
    }
    let root = stock.owner.child_root(handle.mm())?;
    let physical = stock.owner.child_physical_mut(handle.mm(), root)?;
    Some(f(&mut physical.sources))
}

impl NativeService {
    fn record_venue_refusal(&self, ordinal: carrick_guest_arch::NativeOrdinal) {
        // SAFETY: intake selected this exact carrier's initialized fixed
        // counters; the service ticket retains carrier custody through ACK.
        unsafe { self.census.as_ref() }.record_refusal(
            ordinal,
            self.request().identity.birth.origin,
            carrick_el1_abi::RefusalVenue::Carrier,
        );
    }

    pub fn request(&self) -> ServiceRequest {
        self.ticket.request()
    }

    /// An unsupported service is refused to its ring owner, which alone
    /// chooses errno or signal. There is no host syscall dispatch fallback.
    pub fn refuse(self) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        let request = self.request();
        let ordinal = match request.operation {
            carrick_core_abi::service::ServiceOperation::Crossing { ordinal } => Some(ordinal),
            carrick_core_abi::service::ServiceOperation::Exec { payload, .. } => {
                Some(payload.ordinal())
            }
            carrick_core_abi::service::ServiceOperation::HostFile { payload, .. } => {
                Some(payload.ordinal())
            }
            _ => None,
        };
        if let Some(ordinal) = ordinal {
            self.record_venue_refusal(ordinal);
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

    /// The carrier delivered the completed instruction's owed work and
    /// answers the request's own demand with `reply`. The syscall's result
    /// remains exclusively in the ring continuation; a reply that does not
    /// answer this request's demand is refused as stale.
    pub fn acknowledge_work(
        self,
        reply: carrick_core_abi::service::CarrierWorkReply,
    ) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        let carrick_core_abi::service::ServiceOperation::CarrierWork { demand, .. } =
            self.request().operation
        else {
            return Err(stale());
        };
        let supplied = reply.supplied_for(demand).ok_or_else(stale)?;
        self.complete(supplied)
    }

    pub fn slot(&self) -> carrick_sched_core::SlotId {
        self.slot
    }

    /// The single contiguous ring-owned input for a typed exec request.
    pub fn exec_payload(&self) -> Option<&[u8]> {
        self.exec_payload.as_ref().map(RetainedExecPayload::bytes)
    }

    /// Serve authenticated, retained entropy staging and publish its reply
    /// before acknowledging the same ticket. The adapter owns RNG semantics.
    pub fn serve_entropy(
        mut self,
        serve: impl FnOnce(&mut [u8]) -> bool,
    ) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        if !matches!(
            self.request().operation,
            carrick_core_abi::service::ServiceOperation::Entropy { .. }
        ) {
            return Err(stale());
        }
        let record = self.exec_payload.as_mut().ok_or_else(stale)?;
        if !serve(record.bytes_mut()) {
            return Err(stale());
        }
        self.finish_exec_ticket(|ticket| ticket.complete(true).map_err(|_| stale()))
    }

    /// Serve the ring-staged host-file record through the retained file
    /// capability the request names. The reply is written before the ticket
    /// completes; a refusal leaves no reply and answers counted ENOSYS.
    pub fn serve_host_file(mut self) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        let request = self.request();
        let carrick_core_abi::service::ServiceOperation::HostFile { capability, .. } =
            request.operation
        else {
            return self.refuse();
        };
        let Ok(service) = self.custody.native_exec_services.resolve(capability) else {
            return self.refuse_host_file();
        };
        let Some(record) = self.exec_payload.as_mut() else {
            return Err(stale());
        };
        let operation =
            match carrick_core_abi::host_file::HostFileRequestView::parse(record.bytes_mut()) {
                Ok(view) => view.header().op,
                Err(_) => return self.refuse_host_file(),
            };
        let executable = if operation == carrick_core_abi::host_file::HostFileOp::Readlinkat {
            self.with_native_sources(|sources| sources.executable())
                .flatten()
        } else {
            None
        };
        if operation == carrick_core_abi::host_file::HostFileOp::MapPrivate {
            // The shared source owner handles retirements and writes ENOMEM at
            // the bound before either ISA invokes the host file service.
            let mut record = self.exec_payload.take().ok_or_else(stale)?;
            let admitted = self
                .with_native_sources(|sources| sources.prepare_private_mapping(record.bytes_mut()))
                .ok_or_else(stale)?;
            self.exec_payload = Some(record);
            match admitted {
                Err(_) => return self.refuse_host_file(),
                Ok(false) => {
                    return self
                        .finish_exec_ticket(|ticket| ticket.complete(true).map_err(|_| stale()));
                }
                Ok(true) => {}
            }
        }
        let Some(record) = self.exec_payload.as_mut() else {
            return Err(stale());
        };
        let served = service.serve_host_file(request, record.bytes_mut(), executable);
        match served {
            Ok(reply @ carrick_hal::fork_stock::NativeHostFileReply::HostReadyWait { .. }) => {
                // No reply was written: the member waits on its own
                // host-readiness queue and publishes the call's record again (#231).
                let wait = reply
                    .owner_wait(request.identity.birth.mm)
                    .ok_or_else(stale)?;
                self.finish_exec_ticket(|ticket| ticket.complete_wait(wait).map_err(|_| stale()))
            }
            Ok(carrick_hal::fork_stock::NativeHostFileReply::Replied(None)) => {
                self.finish_exec_ticket(|ticket| ticket.complete(true).map_err(|_| stale()))
            }
            Ok(carrick_hal::fork_stock::NativeHostFileReply::Replied(Some(source))) => {
                // The reply names this source: it must be the caller's exact
                // MM's before the ring can map it, or nothing is supplied.
                let identity = source.identity();
                if self
                    .with_native_sources(|sources| sources.inherit(source))
                    .is_none()
                {
                    return Err(stale());
                }
                let custody = Arc::clone(&self.custody);
                let owner = request.identity.birth.mm;
                let finished =
                    self.finish_exec_ticket(|ticket| ticket.complete(true).map_err(|_| stale()));
                if finished.is_err() {
                    // No ring owner received the reply: nothing will retire
                    // this source, so it is released here.
                    with_native_sources_of(&custody, owner, |sources| {
                        sources.release(identity.handle(), identity.generation())
                    });
                }
                finished
            }
            Err(carrick_hal::fork_stock::NativeHostFileRefused) => self.refuse_host_file(),
        }
    }

    /// Run `f` over the requesting native child's exact MM's byte sources,
    /// where `supply_backing` resolves its private file faults.
    fn with_native_sources<R>(
        &self,
        f: impl FnOnce(&mut carrick_hal::fork_stock::ForkHostBackingCustody) -> R,
    ) -> Option<R> {
        with_native_sources_of(&self.custody, self.request().identity.birth.mm, f)
    }

    fn refuse_host_file(self) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        let request = self.request();
        let carrick_core_abi::service::ServiceOperation::HostFile { payload, .. } =
            request.operation
        else {
            return Err(stale());
        };
        // The census counts the refused syscall; the probe names the refused
        // venue operation, above every syscall ordinal.
        self.record_venue_refusal(payload.ordinal());
        let ordinal = self.exec_payload.as_ref().map_or(
            carrick_core_abi::host_file::HOST_FILE_REFUSAL_ORDINAL_BASE,
            |record| carrick_core_abi::host_file::refusal_ordinal(record.bytes()),
        );
        carrick_observability::probes::hvpatch_native_crossing_refused(
            request.identity.birth.mm.mm().raw(),
            request.identity.birth.mm.incarnation().get(),
            request.identity.birth.record.id.raw(),
            request.identity.sequence.get(),
            ordinal,
        );
        self.finish_exec_ticket(|ticket| ticket.complete(false).map_err(|_| stale()))
    }

    /// Resolve and run the retained exec service selected by the authenticated
    /// request. The carrier's exec owner reserves the request's receipt at
    /// claim, before any preparation. Preparation performs all fallible file
    /// and loader work before publishing `Supplied`; the result remains
    /// carrier-owned by that receipt and the exact birth/MM/execution/sequence.
    pub fn prepare_exec(self) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        let request = self.request();
        let (capability, payload) = match request.operation {
            carrick_core_abi::service::ServiceOperation::Exec {
                capability,
                payload: _,
            } => (capability, self.exec_payload().ok_or_else(|| stale())?),
            _ => return self.refuse(),
        };
        let (successor_mm, root_generation, manifest) = match self.reply.as_ref() {
            Some(NativeServiceReply::Exec(manifest)) => {
                // SAFETY: intake pinned the complete aligned ring-owned reply;
                // request completion has not yet released that allocation.
                let (successor_mm, root_generation) = unsafe { manifest.as_ref() }
                    .proposal(request.identity)
                    .ok_or_else(|| stale())?;
                (successor_mm, root_generation, *manifest)
            }
            _ => return Err(stale()),
        };
        let receipt =
            match self
                .custody
                .claim_native_exec(request.identity, successor_mm, root_generation)
            {
                Ok(receipt) => receipt,
                Err(_) => {
                    return self.finish_exec_failure(
                        ServiceFailureCode::new(11).unwrap_or(ServiceFailureCode::MINIMUM),
                    );
                }
            };
        let refuse = |this: Self, failure: ServiceFailureCode| {
            // Refused before the seal: the row retires and nothing past it
            // was owed.
            this.custody
                .retire_native_exec(receipt, carrick_hal::exec_owner::ExecRetireReason::Refused);
            this.finish_exec_failure(failure)
        };
        let service = match self.custody.native_exec_services.resolve(capability) {
            Ok(service) => service,
            Err(unrouted) => return refuse(self, unrouted),
        };
        match service.prepare(request, payload, successor_mm) {
            Ok(prepared) => {
                let prepared = match crate::trap::prepare_native_exec_successor(
                    Arc::clone(&self.custody),
                    prepared.into_parts(),
                ) {
                    Ok(prepared) => prepared,
                    Err(_) => {
                        return refuse(
                            self,
                            ServiceFailureCode::new(12).unwrap_or(ServiceFailureCode::MINIMUM),
                        );
                    }
                };
                self.publish_exec_prepared(
                    receipt,
                    successor_mm,
                    root_generation,
                    manifest,
                    prepared,
                )
            }
            Err(failure) => refuse(self, failure),
        }
    }

    fn publish_exec_prepared(
        self,
        receipt: carrick_core_abi::service::ExecAdoptionReceipt,
        successor_mm: carrick_el1_abi::ReservationMm,
        root_generation: core::num::NonZeroU64,
        manifest: core::ptr::NonNull<carrick_core_abi::service::ExecSuccessorManifest>,
        prepared: crate::trap::PreparedNativeExecSuccessor,
    ) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        let identity = self.request().identity;
        let custody = Arc::clone(&self.custody);
        let asid = prepared.prepared_asid();
        let sealed = core::num::NonZeroU64::new(asid.generation())
            .and_then(|asid_generation| {
                // SAFETY: intake pinned the complete aligned ring-owned reply;
                // the request completion has not yet released it.
                unsafe { manifest.as_ref() }.seal(
                    identity,
                    receipt,
                    carrick_core_abi::service::ExecSuccessorBacking {
                        root: prepared.root(),
                        asid: asid.asid(),
                        asid_generation,
                    },
                    carrick_core_abi::service::ExecSuccessorEntry {
                        entry: carrick_guest_arch::UserVa::new(prepared.entry()),
                        stack_pointer: carrick_guest_arch::UserVa::new(prepared.stack_pointer()),
                    },
                )
            })
            .filter(|sealed| {
                sealed.open(identity, receipt).is_some_and(|view| {
                    view.successor_mm == successor_mm && view.root_generation == root_generation
                })
            });
        let Some(sealed) = sealed else {
            drop(prepared);
            custody.retire_native_exec(receipt, carrick_hal::exec_owner::ExecRetireReason::Refused);
            return Err(stale());
        };
        // The owner holds the sealed row before the ring can see its
        // manifest, so an adoption always finds it.
        if custody
            .seal_native_exec_preparation(receipt, prepared)
            .is_err()
        {
            return Err(stale());
        }
        let census = self.census;
        let request = self.request();
        self.finish_exec_ticket(|ticket| {
            match ticket.publish_exec_prepared(receipt, (), |_, ()| {
                // SAFETY: the exact ticket retains this pinned, aligned reply
                // until the release-store completion below.
                unsafe { manifest.as_ptr().write(sealed) };
            }) {
                Ok(()) => Ok(()),
                Err((_, ticket, ())) => {
                    if let carrick_core_abi::service::ServiceOperation::Exec { payload, .. } =
                        request.operation
                    {
                        // SAFETY: the returned ticket retains the same carrier.
                        unsafe { census.as_ref() }.record_refusal(
                            payload.ordinal(),
                            request.identity.birth.origin,
                            carrick_el1_abi::RefusalVenue::Carrier,
                        );
                    }
                    custody.retire_native_exec(
                        receipt,
                        carrick_hal::exec_owner::ExecRetireReason::PublishCancelled,
                    );
                    ticket.complete(false).map_err(|_| stale())
                }
            }
        })
    }

    fn finish_exec_failure(
        self,
        failure: ServiceFailureCode,
    ) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        if failure.raw() == 38 {
            if let carrick_core_abi::service::ServiceOperation::Exec { payload, .. } =
                self.request().operation
            {
                self.record_venue_refusal(payload.ordinal());
            }
        }
        self.finish_exec_ticket(|ticket| ticket.complete_failure(failure).map_err(|_| stale()))
    }

    fn finish_exec_ticket(
        self,
        complete: impl FnOnce(ServiceTicket<ServicePin>) -> Result<(), TrapError>,
    ) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        let region = retained_abi_region(&self.custody).ok_or_else(|| stale())?;
        let (_, zone) = stopped_records(
            region,
            carrick_guest_arch::CpuId::new(u32::from(self.slot.raw())),
        )
        .ok_or_else(|| stale())?;
        let key = ObjectWaitKey::native_service(self.request().identity.birth.record)
            .ok_or_else(|| stale())?;
        let queue = zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
                carrick_el1::substrate::sched::object_wait::deliver_host_completion(
                    owned.zone(),
                    owned,
                )
            })
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
                ServiceFaultSupply::Prepared(window) => (HvpatchNativeFaultPhase::Backing, window),
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
            Some(carrick_core_abi::service::ServiceFaultSupply::Prepared(window)) => {
                return self.supply_prepared(window);
            }
            None => return self.refuse(),
        };
        let custody = Arc::clone(&self.custody);
        let region = retained_abi_region(&custody).ok_or_else(|| stale())?;
        let (_, zone) = stopped_records(
            region,
            carrick_guest_arch::CpuId::new(u32::from(self.slot.raw())),
        )
        .ok_or_else(|| stale())?;
        let handle = self.request().identity.birth.mm;
        let entry = zone
            .space_entry(core::num::NonZeroU64::new(handle.mm().raw()).ok_or_else(|| stale())?)
            .ok_or_else(|| stale())?;
        let source = entry
            .notifications(handle.incarnation())
            .map_err(|_| stale())?;
        use carrick_core_abi::wait::{PortalWaitAuthority, ReleaseTicketPortalExt};
        use carrick_sched_core::refusal::{
            Attempt, ContentionSource, Refusal, ReleaseCause, Settled,
        };
        let access = SpaceAccess::notified(SpaceReleaseVenue {
            zone,
            waker: carrick_sched_core::Waker::Host,
            deliver: SpaceWakeDelivery::Function(deliver),
        });
        let index = zone.spaces.find(handle.mm().raw()).ok_or_else(|| stale())?;
        let exclusion =
            match source.contend(
                || match access.try_exclude_editor(index, handle.mm().raw()) {
                    Ok(exclusion) => Ok(exclusion),
                    Err(carrick_sched_core::spaces::notification::ExclusionRefusal::Busy) => Err(
                        Attempt::Contended(ReleaseCause::Space(SpaceWaitCause::Editor)),
                    ),
                    Err(carrick_sched_core::spaces::notification::ExclusionRefusal::Stale) => {
                        Err(Attempt::<()>::Settled(Settled::Invariant(
                            carrick_sched_core::refusal::InvariantKind {
                                domain: "native_service_exclusion",
                                code: 1,
                            },
                        )))
                    }
                },
            ) {
                Ok(exclusion) => exclusion,
                Err(Refusal::Contended(ticket)) => {
                    // SAFETY: stopped_records borrowed this zone from the retained
                    // custody that authenticated this service's exact carrier.
                    let authority =
                        unsafe { PortalWaitAuthority::from_retained_zone(zone, handle) };
                    let wait = ticket.into_portal_wait(&authority).map_err(|_| stale())?;
                    return self.complete_wait(wait);
                }
                Err(Refusal::Invariant(_)) => return Err(stale()),
                Err(Refusal::Guest(())) => return self.refuse(),
            };
        // Every exclusion settles the MM's COW completions, then its owed
        // returns (#1369 slice 3, #1482 P0-3); a skipped or contended
        // settlement leaves them owed.
        super::settle_native_exclusion(&custody, exclusion.proof())?;
        let pool = carrick_el1_abi::cow_grant_pool_host().ok_or_else(|| stale())?;
        let (root, inventory, split_tables, refill) = {
            let stage2 = custody.stage2.lock();
            let mut stock = custody.fork_stock.lock();
            if stock.owner.child_owner(handle.mm()) != Some(handle)
                || stock.owner.is_quarantined(handle.mm())
            {
                drop(stock);
                drop(stage2);
                return self.refuse();
            }
            let root = stock.owner.child_root(handle.mm()).ok_or_else(|| stale())?;
            let inventory = stock.inventory().ok_or_else(|| stale())?;
            settle_native_cow_grants(&custody, &mut stock, handle, root, pool, exclusion.proof())?;
            // A first write into an armed block needs one grant carrying its split
            // tables (#2276); a page write refills table-less grants.
            let split_tables =
                native_cow_fault_split_in(&stage2, root, window.fault_page).unwrap_or(0);
            let refill = if pool
                .ready(handle.mm().raw())
                .any(|grant| grant.serves(split_tables))
            {
                0
            } else if split_tables == 0 {
                carrick_hal::physical_grants::NativePhysicalGrants::<
                    crate::fork_stock::NativeFrameBacking,
                >::REFILL_GRANTS
            } else {
                1
            };
            (root, inventory, split_tables, refill)
        };
        let owner = carrick_hal::GuestFrameOwner {
            native_mm: carrick_guest_arch::MmGeneration::new(
                core::num::NonZeroU64::new(handle.mm().raw()).ok_or_else(|| stale())?,
            ),
            root_generation: carrick_guest_arch::ContextGeneration::new(handle.incarnation()),
        };
        if refill > 0 {
            let mut allocated = Vec::with_capacity(refill);
            for _ in 0..refill {
                let (_, ipa, generation) = crate::trap::allocate_grant_compound(
                    &custody,
                    carrick_hal::physical_grants::COW_GRANT_PERMISSIONS,
                )?;
                let retained = Arc::new(crate::fork_stock::NativeFrameBacking {
                    carrier: Arc::downgrade(&custody),
                    ipa,
                    generation,
                    length: carrick_el1_abi::COW_GRANT_SIZE,
                    retained_owner: Default::default(),
                });
                custody
                    .native_frame_backings
                    .lock()
                    .insert((ipa, generation), Arc::downgrade(&retained));
                allocated.push((ipa, retained));
            }
            let keep_alive: Vec<Arc<crate::fork_stock::NativeFrameBacking>> = allocated
                .iter()
                .map(|(_, backing)| Arc::clone(backing))
                .collect();
            let publish_result = (|| -> Result<Option<()>, TrapError> {
                let mut stock = custody.fork_stock.lock();
                if stock.owner.child_owner(handle.mm()) != Some(handle)
                    || stock.owner.child_root(handle.mm()) != Some(root)
                    || stock.owner.is_quarantined(handle.mm())
                {
                    return Ok(None);
                }
                for (ipa, retained) in allocated {
                    let tables = if split_tables == 0 {
                        carrick_el1_abi::CowSplitTables::NONE
                    } else {
                        stock
                            .owner
                            .reserve_native_cow_split_tables(
                                &mut crate::fork_stock::fork_table_accounting(&custody),
                                handle,
                                root,
                                ipa,
                                split_tables,
                            )
                            .map_err(|_| stale())?
                    };
                    let physical = stock
                        .owner
                        .child_physical_mut(handle.mm(), root)
                        .ok_or_else(|| stale())?;
                    let grants = physical.supplied.get_or_insert_with(|| {
                        carrick_hal::physical_grants::NativePhysicalGrants::new(owner)
                    });
                    if grants.owner() != owner || grants.failed() || physical.rollback.failed() {
                        return Err(stale());
                    }
                    let published =
                        carrick_hal::physical_grants::StagedPhysicalGrants::stage_with_permissions(
                            Arc::clone(&physical.rollback),
                            Arc::clone(&inventory),
                            [carrick_guest_arch::FrameGpa::new(ipa)],
                            0,
                            carrick_el1_abi::COW_GRANT_SIZE,
                            owner,
                            carrick_hal::physical_grants::COW_GRANT_PERMISSIONS,
                        )
                        .and_then(|staged| {
                            grants.publish_cow(
                                staged.with_backing(retained),
                                pool,
                                exclusion.proof(),
                                tables,
                            )
                        });
                    if let Err(error) = published {
                        if !tables.is_empty() {
                            stock
                                .owner
                                .cancel_native_cow_split_tables(
                                    &mut crate::fork_stock::fork_table_accounting(&custody),
                                    handle,
                                    ipa,
                                )
                                .map_err(|_| stale())?;
                        }
                        return Err(error);
                    }
                }
                Ok(Some(()))
            })();
            // Drop outside fork_stock: handed-off grants retain their backing;
            // only backings with no remaining owner are retired.
            drop(keep_alive);
            match publish_result {
                Ok(Some(())) => {}
                Ok(None) => {
                    drop(exclusion);
                    drop(source);
                    return self.refuse();
                }
                Err(error) => return Err(error),
            }
        }
        let supplied = pool
            .ready(window.operation.mm.raw())
            .any(|grant| grant.serves(split_tables));
        drop(exclusion);
        drop(source);
        self.complete(supplied)
    }

    fn supply_prepared(
        self,
        window: carrick_el1_abi::PortalGrantWindow,
    ) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        let Some(NativeServiceReply::Fault(reply)) = self.reply else {
            return self.refuse();
        };
        let custody = Arc::clone(&self.custody);
        let handle = self.request().identity.birth.mm;
        let mut stock = custody.fork_stock.lock();
        if stock.owner.child_owner(handle.mm()).is_none()
            && !stock.owner.is_quarantined(handle.mm())
        {
            drop(stock);
            return self.supply_root(window);
        }
        if stock.owner.child_owner(handle.mm()) != Some(handle)
            || stock.owner.is_quarantined(handle.mm())
        {
            drop(stock);
            return self.refuse();
        }
        let root = stock.owner.child_root(handle.mm()).ok_or_else(stale)?;
        // SAFETY: intake retains this authenticated request-owned reply.
        let reply = unsafe { reply.as_ref() };
        let Some(txn) = stock.owner.stage_native_prepared_reply(
            &mut crate::fork_stock::fork_table_accounting(&custody),
            handle,
            root,
            reply,
            window,
        )?
        else {
            drop(stock);
            return self.refuse();
        };
        drop(stock);
        self.finish_backing_supply(handle, root, reply, &txn)
    }

    /// Root MMs retain their existing exact host transfer authority. Fork
    /// children continue through ForkStock; neither authority substitutes for
    /// the other and this service never borrows a running engine.
    fn supply_root(
        mut self,
        window: carrick_el1_abi::PortalGrantWindow,
    ) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        use carrick_aarch64::user_transfer::{TransferPreparation, TransferTarget};
        let custody = Arc::clone(&self.custody);
        let request = self.request();
        let handle = request.identity.birth.mm;
        let Some(NativeServiceReply::Fault(pointer)) = self.reply else {
            return self.refuse();
        };
        let address = self.ticket.reply_address().ok_or_else(stale)?;
        let state = custody
            .guest_cow_state(handle.mm().raw())
            .map_err(|_| stale())?
            .ok_or_else(stale)?;
        let root = state
            .page_tables_authority()
            .root_base()
            .ok_or_else(stale)?;
        let asid = state
            .cow_runtime
            .read()
            .as_ref()
            .ok_or_else(stale)?
            .identity
            .asid;
        let target = TransferTarget::from_handle(handle, root | (u64::from(asid) << 48));
        let context = crate::trap::RootTransferContext::for_transfer(
            state,
            Arc::clone(&custody),
            target,
            window,
        )?;
        let region = retained_abi_region(&custody).ok_or_else(stale)?;
        let (_, zone) = stopped_records(
            region,
            carrick_guest_arch::CpuId::new(u32::from(self.slot.raw())),
        )
        .ok_or_else(stale)?;
        custody.native_root_waits.clear_admitted(request, zone)?;
        let sample = NativeRootWaitLedger::sample(request, zone)?;
        let preparation = match self.cow {
            Some(carrick_core_abi::service::ServiceFaultSupply::Prepared(_)) => {
                context.prepare_resident_transfer(window)
            }
            Some(carrick_core_abi::service::ServiceFaultSupply::Backing(_)) => {
                context.prepare_transfer(window)
            }
            _ => return Err(stale()),
        };
        let grant = match preparation {
            Ok(TransferPreparation::Grant(grant)) => grant,
            Ok(TransferPreparation::Pending(wait)) => {
                let wait = custody
                    .native_root_waits
                    .enroll(&custody, request, sample, wait)?;
                return self.complete_wait(wait);
            }
            Ok(TransferPreparation::PeerResident) => return self.complete(true),
            Ok(TransferPreparation::Declined) => return self.refuse(),
            Err(TrapError::HostBackingEof) => return self.finish(None, false, true),
            Err(error) => return Err(error),
        };
        // Physical I/O and table preparation finish before this bounded
        // directory/queue cutover. One exact service per record owns a row.
        let txn = *grant.transaction();
        let mut prepared = Some(NativeRootReply {
            identity: request.identity,
            root: carrick_guest_arch::RootGpa::page_aligned(carrick_guest_arch::FrameGpa::new(
                root,
            ))
            .ok_or_else(stale)?,
            reply: address,
            window,
            grant,
            _pin: self._reply_pin.take().map(|pin| pin._backing),
        });
        let region = retained_abi_region(&custody).ok_or_else(stale)?;
        let (_, zone) = stopped_records(
            region,
            carrick_guest_arch::CpuId::new(u32::from(self.slot.raw())),
        )
        .ok_or_else(stale)?;
        let key = ObjectWaitKey::native_service(request.identity.birth.record).ok_or_else(stale)?;
        let mut ledger = custody.native_root_replies.lock();
        if !prepared.as_ref().is_some_and(|entry| ledger.admits(entry)) {
            drop(ledger);
            drop(prepared);
            return Err(stale());
        }
        let queue = zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
                carrick_el1::substrate::sched::object_wait::deliver_host_completion(
                    owned.zone(),
                    owned,
                )
            })
            .map_err(|_| stale())?;
        // SAFETY: the request and prepared entry retain the exact aligned slot.
        let reply = unsafe { pointer.as_ref() };
        let mut offered = false;
        let delivery = self.ticket.publish_prepared((), |()| {
            let entry = prepared.take().ok_or(())?;
            if !reply.submit_with_trace(
                window,
                &txn,
                carrick_hal::diagnostic_capture::trace_grant_refusals(),
            ) {
                prepared = Some(entry);
                return Err(());
            }
            // No fallible action follows descriptor exposure. Its exact grant
            // enters the bounded ledger before ServiceCell ACK can wake EL1.
            ledger.entries.push(entry);
            offered = true;
            Ok(())
        });
        let queue = match delivery {
            Ok(()) => {
                drop(ledger);
                queue
            }
            Err((_, ticket, ())) => {
                drop(queue);
                drop(ledger);
                // Cancellation before delivery returns the never-exposed
                // prepared grant. Its sole Drop rolls back outside the queue.
                drop(prepared);
                let queue = zone
                    .object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
                        carrick_el1::substrate::sched::object_wait::deliver_host_completion(
                            owned.zone(),
                            owned,
                        )
                    })
                    .map_err(|_| stale())?;
                ticket.complete(false).map_err(|_| stale())?;
                queue
            }
        };
        let mut effects = carrick_sched_core::WakeEffects::default();
        queue
            .notify_object(self.slot, &mut effects)
            .map_err(|_| stale())?;
        drop(queue);
        carrick_observability::probes::hvpatch_native_fault_supply(
            handle.mm().raw(),
            request.identity.sequence.get(),
            if offered {
                carrick_observability::probes::HvpatchNativeFaultPhase::Supplied
            } else {
                carrick_observability::probes::HvpatchNativeFaultPhase::Refused
            },
            0,
            0,
        );
        Ok(effects)
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
        if stock.owner.child_owner(handle.mm()).is_none()
            && !stock.owner.is_quarantined(handle.mm())
        {
            drop(stock);
            return self.supply_root(window);
        }
        if stock.owner.child_owner(handle.mm()) != Some(handle)
            || stock.owner.is_quarantined(handle.mm())
        {
            drop(stock);
            return self.refuse();
        }
        let root = stock.owner.child_root(handle.mm()).ok_or_else(|| stale())?;
        let inventory = stock.inventory().ok_or_else(|| stale())?;
        let physical = stock
            .owner
            .child_physical_mut(handle.mm(), root)
            .ok_or_else(|| stale())?;
        let source = window
            .host_backing
            .map(|identity| {
                physical
                    .sources
                    .retain(identity, || None)
                    .ok_or_else(|| stale())
            })
            .transpose()?;
        // File I/O retains only its bounded source capability. It must not
        // hold carrier-wide stock custody while another native child exits.
        drop(stock);
        let bytes = if let Some(source) = source {
            let identity = window.host_backing.ok_or_else(|| stale())?;
            let read = carrick_hal::fork_stock::HostBackingRead::new(
                identity,
                window.range.len() as usize,
            )
            .ok_or_else(|| stale())?;
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
        let owner = carrick_hal::GuestFrameOwner {
            native_mm: carrick_guest_arch::MmGeneration::new(
                core::num::NonZeroU64::new(handle.mm().raw()).ok_or_else(|| stale())?,
            ),
            root_generation: carrick_guest_arch::ContextGeneration::new(handle.incarnation()),
        };
        // SAFETY: intake retains this authenticated request-owned reply.
        let reply_slot = unsafe { reply.as_ref() };
        let publication_len = bytes
            .as_ref()
            .map_or(window.range.len(), |bytes| bytes.len() as u64);
        let rollback = {
            let mut stock = custody.fork_stock.lock();
            if stock.owner.child_owner(handle.mm()) != Some(handle)
                || stock.owner.child_root(handle.mm()) != Some(root)
                || stock.owner.is_quarantined(handle.mm())
            {
                drop(stock);
                return self.refuse();
            }
            let physical = stock
                .owner
                .child_physical_mut(handle.mm(), root)
                .ok_or_else(|| stale())?;
            if window.fault_page >= window.range.start() + publication_len {
                drop(stock);
                return self.finish(None, false, true);
            }
            let grants = physical.supplied.get_or_insert_with(|| {
                carrick_hal::physical_grants::NativePhysicalGrants::new(owner)
            });
            if grants.owner() != owner || grants.failed() || physical.rollback.failed() {
                return Err(stale());
            }
            if !grants.backing_reply_available(reply_slot, window) {
                drop(stock);
                return self.refuse();
            }
            Arc::clone(&physical.rollback)
        };
        let data_len = publication_len.next_multiple_of(carrick_el1_abi::COW_GRANT_SIZE);
        let executable = window
            .protection
            .permits(carrick_el1_abi::ReservationProtection::EXECUTE);
        // Like the existing private-backing adapter, preserve physical COW
        // and later executable-publication capacity. The exact MM's inventory
        // and stage-1 publication below retain the selected access policy.
        let perms = carrick_hal::physical_grants::COW_GRANT_PERMISSIONS;
        let length = data_len;
        let (host, ipa, generation) = crate::trap::allocate_grant_extent(&custody, perms, length)?;
        let retained = Arc::new(crate::fork_stock::NativeFrameBacking {
            carrier: Arc::downgrade(&custody),
            ipa,
            generation,
            length,
            retained_owner: Default::default(),
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
        let staged_result =
            carrick_hal::physical_grants::StagedPhysicalGrants::stage_with_permissions(
                Arc::clone(&rollback),
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
            );
        let staged = match staged_result {
            Ok(staged) => staged,
            Err(error) => {
                // Staging can fail after applying inventory. Its guard then
                // attempts undo; an unknown undo already retained the receipt.
                // Couple this allocation to that failure custody before any
                // backend release can discard its bytes.
                if rollback.failed() {
                    rollback.retain_allocation(retained);
                    let mut stock = custody.fork_stock.lock();
                    stock
                        .owner
                        .quarantine_native_supply(handle, root)
                        .map_err(|_| stale())?;
                    return Err(error);
                }
                match retained.release_unused() {
                    Ok(carrick_hal::physical_grants::PhysicalGrantRelease::Released) => {}
                    Ok(
                        carrick_hal::physical_grants::PhysicalGrantRelease::RetainUntilMmRetirement,
                    ) => {
                        rollback.retain_until_mm_retirement(retained);
                    }
                    Err(release_error) => {
                        rollback.retain_allocation(retained);
                        let mut stock = custody.fork_stock.lock();
                        stock
                            .owner
                            .quarantine_native_supply(handle, root)
                            .map_err(|_| stale())?;
                        return Err(release_error);
                    }
                }
                return Err(error);
            }
        };
        let keep_alive = Arc::clone(&retained);
        let unpublished = staged.with_backing(retained);
        let Some(&data) = unpublished.grants().first() else {
            let _ = unpublished.abort_with_release(|backing| backing.release_unused());
            drop(keep_alive);
            return Err(stale());
        };
        enum StageOutcome {
            Committed(DescriptorTxn),
            Refuse(
                carrick_hal::physical_grants::UnpublishedPhysicalGrant<
                    Arc<crate::fork_stock::NativeFrameBacking>,
                >,
            ),
        }
        let mut deferred_releases: Vec<(
            Arc<carrick_hal::physical_grants::PhysicalGrantRollback>,
            Arc<crate::fork_stock::NativeFrameBacking>,
        )> = Vec::new();
        let mm_key = core::num::NonZeroU64::new(handle.mm().raw()).ok_or_else(|| stale())?;
        let writable = window
            .protection
            .permits(carrick_el1_abi::ReservationProtection::WRITE);
        let staged_res = {
            let mut stock = custody.fork_stock.lock();
            if stock.owner.child_owner(handle.mm()) != Some(handle)
                || stock.owner.child_root(handle.mm()) != Some(root)
                || stock.owner.is_quarantined(handle.mm())
                || rollback.failed()
            {
                Ok(StageOutcome::Refuse(unpublished))
            } else {
                match stock.owner.reserve_native_descriptor_tables(
                    &mut crate::fork_stock::fork_table_accounting(&custody),
                    handle,
                    root,
                    MAX_TABLE_GRANTS,
                ) {
                    Err(_) => Ok(StageOutcome::Refuse(unpublished)),
                    Ok(table_reservation) => {
                        let txn = DescriptorTxn {
                            id: DescriptorTxnId {
                                mm_key,
                                generation: window.operation.sequence,
                            },
                            root: SubstrateGpa(root.address().raw()),
                            op: DescriptorOp::Prepare {
                                publication: GuestLeafPublication {
                                    va: window.range.start(),
                                    ipa: data.gpa.raw(),
                                    len: publication_len,
                                    writable,
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
                            Ok(StageOutcome::Refuse(unpublished))
                        } else {
                            let staged = stock
                                .owner
                                .child_physical_mut(handle.mm(), root)
                                .ok_or_else(|| stale())?
                                .supplied
                                .as_mut()
                                .ok_or_else(|| stale())?
                                .stage_backing_reply(reply_slot, window, txn, unpublished, |backing| {
                                    deferred_releases
                                        .push((Arc::clone(&rollback), Arc::clone(backing)));
                                    Ok(carrick_hal::physical_grants::PhysicalGrantRelease::Released)
                                });
                            if let Err(error) = staged {
                                stock
                                    .owner
                                    .quarantine_native_supply(handle, root)
                                    .map_err(|_| stale())?;
                                Err(error)
                            } else {
                                Ok(StageOutcome::Committed(txn))
                            }
                        }
                    }
                }
            }
        };
        let release_err = release_deferred_backings(&custody, handle, root, deferred_releases);
        drop(keep_alive);
        release_err?;
        let txn = match staged_res? {
            StageOutcome::Committed(txn) => txn,
            StageOutcome::Refuse(unpublished) => {
                if let Err(error) =
                    unpublished.abort_with_release(|backing| backing.release_unused())
                {
                    let mut stock = custody.fork_stock.lock();
                    stock
                        .owner
                        .quarantine_native_supply(handle, root)
                        .map_err(|_| stale())?;
                    return Err(error);
                }
                return self.refuse();
            }
        };
        self.finish_backing_supply(handle, root, reply_slot, &txn)
    }
    /// Reserve delivery against cancellation before making the physical reply
    /// consumable. Cancellation before delivery rolls back while retaining the
    /// ticket; cancellation after delivery belongs to the ring continuation.
    fn finish_backing_supply(
        self,
        handle: carrick_el1_abi::El1MmHandle,
        root: carrick_guest_arch::RootGpa,
        reply: &carrick_el1_abi::PortalGrantSlot,
        txn: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
    ) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        let custody = Arc::clone(&self.custody);
        let request = self.request();
        let region = retained_abi_region(&custody).ok_or_else(stale)?;
        let (_, zone) = stopped_records(
            region,
            carrick_guest_arch::CpuId::new(u32::from(self.slot.raw())),
        )
        .ok_or_else(stale)?;
        let key = ObjectWaitKey::native_service(request.identity.birth.record).ok_or_else(stale)?;
        let mut deferred_releases = Vec::new();
        let (delivery_result, offered) = {
            let mut stock = custody.fork_stock.lock();
            if stock.owner.child_owner(handle.mm()) != Some(handle)
                || stock.owner.child_root(handle.mm()) != Some(root)
                || stock.owner.is_quarantined(handle.mm())
            {
                return Err(stale());
            }
            let grants = stock
                .owner
                .child_physical_mut(handle.mm(), root)
                .and_then(|physical| physical.supplied.as_mut())
                .ok_or_else(stale)?;
            // Acquire the host mutex before the guest queue, never beneath it.
            // No native-service queue holder acquires ForkStock. This queue spans
            // only the bounded ServiceCell/descriptor publication and notification;
            // cancellation releases it before physical/table undo or backing drop.
            let queue = zone
                .object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
                    carrick_el1::substrate::sched::object_wait::deliver_host_completion(
                        owned.zone(),
                        owned,
                    )
                })
                .map_err(|_| stale())?;
            let mut offered = false;
            let delivery = self.ticket.publish_prepared((), |()| {
                offered = grants.offer_backing_reply(reply, txn);
                if offered { Ok(()) } else { Err(()) }
            });
            match delivery {
                Ok(()) => (Ok(queue), offered),
                Err((reason, ticket, ())) => {
                    drop(queue);
                    // The returned ticket keeps the service BUSY and reply pinned
                    // until rollback settles. No queue guard spans this release.
                    let settled = settle_backing_and_tables(
                        &custody,
                        &mut stock,
                        handle,
                        root,
                        reply,
                        txn,
                        &mut deferred_releases,
                    )?;
                    (Err((reason, ticket, settled)), offered)
                }
            }
        };
        release_deferred_backings(&custody, handle, root, deferred_releases)?;
        let queue = match delivery_result {
            Ok(queue) => queue,
            Err((reason, ticket, settled)) => {
                if !settled {
                    return Err(stale());
                }
                if !matches!(
                    reason,
                    carrick_core_abi::service::PreparedDeliveryError::Cancelled
                        | carrick_core_abi::service::PreparedDeliveryError::Refused
                ) {
                    return Err(stale());
                }
                let queue = zone
                    .object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
                        carrick_el1::substrate::sched::object_wait::deliver_host_completion(
                            owned.zone(),
                            owned,
                        )
                    })
                    .map_err(|_| stale())?;
                ticket.complete(false).map_err(|_| stale())?;
                queue
            }
        };
        let mut effects = carrick_sched_core::WakeEffects::default();
        queue
            .notify_object(self.slot, &mut effects)
            .map_err(|_| stale())?;
        drop(queue);
        carrick_observability::probes::hvpatch_native_fault_supply(
            handle.mm().raw(),
            request.identity.sequence.get(),
            if offered {
                carrick_observability::probes::HvpatchNativeFaultPhase::Supplied
            } else {
                carrick_observability::probes::HvpatchNativeFaultPhase::Refused
            },
            0,
            0,
        );
        Ok(effects)
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
        let region = retained_abi_region(&self.custody).ok_or_else(|| stale())?;
        let (_, zone) = stopped_records(
            region,
            carrick_guest_arch::CpuId::new(u32::from(self.slot.raw())),
        )
        .ok_or_else(|| stale())?;
        let key = ObjectWaitKey::native_service(self.request().identity.birth.record)
            .ok_or_else(|| stale())?;
        let queue = zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
                carrick_el1::substrate::sched::object_wait::deliver_host_completion(
                    owned.zone(),
                    owned,
                )
            })
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
#[track_caller]
fn stale() -> TrapError {
    TrapError::Hypervisor(format!(
        "native service custody mismatch at {}",
        core::panic::Location::caller(),
    ))
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
    let region = retained_abi_region(custody).ok_or_else(|| stale())?;
    let (task, zone) = stopped_records(region, cpu).ok_or_else(|| stale())?;
    let Some(selector) = task.service_notice.take().map_err(|_| stale())? else {
        return Ok(None);
    };
    let consumed = ConsumedServiceNotice(selector);
    let service = (|| {
        let selector = consumed.selector();
        let Some(key) = ObjectWaitKey::native_service(selector.record) else {
            return consumed.miss("invalid native-service wait key");
        };
        let Ok(queue) = zone.object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
            carrick_el1::substrate::sched::object_wait::deliver_host_completion(owned.zone(), owned)
        }) else {
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
        // Metadata retention can acquire host mutexes. Snapshot the member,
        // retain its allocation outside the queue, then revalidate at claim.
        drop(queue);
        // A member's control is ring metadata: the carrier's loaned slab for
        // the lifecycle page's own entries, a segment from the ring's
        // allocator past them (#2734). One resolver retains either venue.
        let address = carrick_guest_arch::KernelVa::new(identity.control_slot);
        let (control, pin) = match retain_ring_record::<carrick_el1_abi::ThreadControlSlot>(
            custody, region, address,
        ) {
            Ok(retained) => retained,
            Err(RingRecordMiss::Absent) => {
                return consumed.miss("native-service control metadata absent");
            }
            Err(RingRecordMiss::ApertureAbsent) => {
                return consumed.miss("native-service metadata aperture absent");
            }
            Err(RingRecordMiss::Invalid) => return Err(stale()),
        };
        // SAFETY: the resolver retains initialized control storage. The exact
        // member and control identity are revalidated under the service queue.
        let control = unsafe { control.as_ref() };
        let pin = ServicePin {
            cell: core::ptr::NonNull::from(&control.service),
            _mapping: pin,
            _carrier: Arc::clone(custody),
        };
        let queue = zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
                carrick_el1::substrate::sched::object_wait::deliver_host_completion(
                    owned.zone(),
                    owned,
                )
            })
            .map_err(|_| stale())?;
        if custody.live_generation() != Some(generation)
            || queue.native_service_member(selector.record) != Some(identity)
        {
            drop(queue);
            return consumed.miss("native-service member changed during metadata retention");
        }
        if control.zone_record() != Some(selector.record) || !control.native_signal_owner() {
            drop(queue);
            return consumed.miss("native-service control owner changed");
        }
        // A refused claim consumes its pin. Keep the allocation alive until
        // after the queue drops even if teardown removed its aperture entry.
        let claim_backing = pin
            ._mapping
            .as_ref()
            .map(|mapping| Arc::clone(&mapping._backing));
        // SAFETY: exact member/control revalidated under its queue above. The
        // ring's active service claim retains its admitted MM through ticket ACK.
        let ticket =
            unsafe { ServiceCell::claim_notice(pin, selector, custody.transfer_carrier, identity) };
        drop(queue);
        drop(claim_backing);
        match ticket {
            Ok(mut ticket) => {
                let portal = region
                    .record_ptr::<carrick_el1_abi::MmPortalSlots>(
                        carrick_el1_abi::EL1_MM_PORTAL_OFFSET as usize,
                    )
                    .ok_or_else(|| stale())?;
                // SAFETY: initialized portal in the retained carrier ABI region.
                let portal = unsafe { &*portal };
                let cow = ticket
                    .take_fault_selection(portal.grant(cpu.raw() as usize).ok_or_else(|| stale())?)
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
                            payload.address().raw(),
                            payload.length().raw(),
                        )?)
                    }
                    carrick_core_abi::service::ServiceOperation::HostFile { payload, .. } => {
                        Some(retain_exec_payload(
                            custody,
                            region,
                            ticket.request().identity.birth.mm,
                            payload.address().raw(),
                            payload.length().raw(),
                        )?)
                    }
                    carrick_core_abi::service::ServiceOperation::Entropy { payload } => {
                        Some(retain_exec_payload(
                            custody,
                            region,
                            ticket.request().identity.birth.mm,
                            payload.address().raw(),
                            payload.length().raw(),
                        )?)
                    }
                    _ => None,
                };
                Ok(NativeService {
                    census: core::ptr::NonNull::new(
                        region
                            .record_ptr::<carrick_el1_abi::Counters>(
                                carrick_el1_abi::EL1_COUNTERS_OFFSET as usize,
                            )
                            .ok_or_else(stale)?,
                    )
                    .ok_or_else(stale)?,
                    reply,
                    _reply_pin: reply_pin,
                    exec_payload,
                    ticket,
                    cow,
                    custody: Arc::clone(custody),
                    slot: carrick_sched_core::SlotId::from_index(cpu.raw() as usize)
                        .ok_or_else(|| stale())?,
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
    address: u64,
    length: u64,
) -> Result<RetainedExecPayload, TrapError> {
    let len = usize::try_from(length).map_err(|_| stale())?;
    let end = address.checked_add(len as u64).ok_or_else(|| stale())?;

    // Authentication is against the request's retained MM incarnation, not
    // whichever task a host process lookup happens to find.
    {
        let stage2 = custody.stage2.lock();
        let stock = custody.fork_stock.lock();
        if stock.owner.child_owner(handle.mm()) != Some(handle) {
            return Err(stale());
        }
        let root = stock.owner.child_root(handle.mm()).ok_or_else(|| stale())?;
        let mut cursor = address;
        while cursor < end {
            if native_output_in(&stage2, root, cursor) != Some(cursor & !4095) {
                return Err(stale());
            }
            cursor = end.min((cursor | 4095).checked_add(1).ok_or_else(|| stale())?);
        }
    }

    let bootstrap_start = carrick_el1_abi::EL1_BOOTSTRAP_METADATA_BASE;
    let bootstrap_end = bootstrap_start + carrick_el1_abi::EL1_BOOTSTRAP_METADATA_SIZE;
    if address >= bootstrap_start && end <= bootstrap_end {
        let offset =
            usize::try_from(address - carrick_el1_abi::EL1_REGION_BASE).map_err(|_| stale())?;
        let pointer =
            core::ptr::NonNull::new(region.record_ptr::<u8>(offset).ok_or_else(|| stale())?)
                .ok_or_else(|| stale())?;
        return Ok(RetainedExecPayload {
            pointer,
            len,
            _mapping: None,
        });
    }

    let address = carrick_guest_arch::KernelVa::new(address);
    let (_, base, extent_len) =
        retained_dynamic_metadata(custody, address, len).ok_or_else(|| stale())?;
    let generation = custody.live_generation().ok_or_else(|| stale())?;
    let pin = {
        let aperture = metadata_aperture(custody).lock();
        let index =
            ((base - EL1_DYNAMIC_METADATA_BASE) / EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64) as usize;
        let mapping = aperture
            .slots
            .get(index)
            .and_then(Option::as_ref)
            .ok_or_else(|| stale())?;
        aperture
            .pin_extent(
                MetadataExtent::new(base, extent_len as u64, mapping.token)
                    .ok_or_else(|| stale())?,
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
        pointer: core::ptr::NonNull::new(pointer).ok_or_else(|| stale())?,
        len,
        _mapping: Some(pin),
    })
}

// The stock lock retains the table arenas; exclusion prevents descriptor edits.
fn native_output_in(
    stage2: &carrick_aarch64::stage2::custody::Stage2CustodyState<
        crate::trap::CarrierStage2Records,
    >,
    root: carrick_guest_arch::RootGpa,
    va: u64,
) -> Option<u64> {
    native_output_from(root, va, |address| {
        let pointer = crate::fork_stock::ForkStockHostCustody::physical_ptr_in::<AtomicU64>(
            stage2,
            carrick_guest_arch::FrameGpa::new(address),
        )
        .ok()?;
        // SAFETY: retained stock tables and exact owner exclusion, atomic word.
        Some(unsafe { &*pointer }.load(Ordering::Acquire))
    })
}

fn native_output_from(
    root: carrick_guest_arch::RootGpa,
    va: u64,
    mut load: impl FnMut(u64) -> Option<u64>,
) -> Option<u64> {
    use carrick_mmu_core::owner_mmu::{Aarch64Mmu, OwnerMmuRefusal};
    Aarch64Mmu::translate_with(
        root,
        carrick_guest_arch::UserVa::new(va),
        carrick_mmu_core::aarch64::LeafAccess::Read,
        false,
        |address| load(address).ok_or(OwnerMmuRefusal::Unreachable),
    )
    .ok()
    .flatten()
    .map(|translation| translation.output.raw() & !4095)
}

pub(crate) fn settle_native_cow(
    custody: &crate::trap::CarrierVmCustody,
    pool: &carrick_el1_abi::CowGrantPool,
    excluded: &carrick_sched_core::ExcludedEditor<'_>,
) -> Result<Option<usize>, TrapError> {
    let mm = carrick_el1_abi::ReservationMm::new(excluded.key()).ok_or_else(|| stale())?;
    let mut stock = custody.fork_stock.lock();
    let Some(root) = stock.owner.child_root(mm) else {
        return Ok(None);
    };
    let owner = stock.owner.child_owner(mm).ok_or_else(|| stale())?;
    settle_native_cow_grants(custody, &mut stock, owner, root, pool, excluded).map(Some)
}

/// Settle one live child's USED grants under its exclusion, then the split
/// tables their repoints linked (#2276): the linked prefix joins the child's
/// table custody and the rest returns to fork stock.
fn settle_native_cow_grants(
    custody: &crate::trap::CarrierVmCustody,
    stock: &mut crate::fork_stock::ForkStockHostCustody,
    owner: carrick_el1_abi::El1MmHandle,
    root: carrick_guest_arch::RootGpa,
    pool: &carrick_el1_abi::CowGrantPool,
    excluded: &carrick_sched_core::ExcludedEditor<'_>,
) -> Result<usize, TrapError> {
    let physical = stock
        .owner
        .child_physical_mut(owner.mm(), root)
        .ok_or_else(|| stale())?;
    let Some(grants) = &mut physical.supplied else {
        return if pool.has_completions_for(owner.mm().raw()) {
            Err(stale())
        } else {
            Ok(0)
        };
    };
    let settled = grants.settle(pool, excluded)?;
    for completion in &settled {
        stock
            .owner
            .settle_native_cow_split_tables(
                &mut crate::fork_stock::fork_table_accounting(custody),
                owner,
                completion,
            )
            .map_err(|_| stale())?;
    }
    Ok(settled.len())
}

/// Tables the first EL1 COW write at `va` in a live child must link: the
/// live terminal is an EL1-private, COW-armed, Linux-writable page or block.
fn native_cow_fault_split_in(
    stage2: &carrick_aarch64::stage2::custody::Stage2CustodyState<
        crate::trap::CarrierStage2Records,
    >,
    root: carrick_guest_arch::RootGpa,
    va: u64,
) -> Option<usize> {
    use carrick_mmu_core::aarch64::descriptor_txn::guest_cow::{
        is_guest_cow_write_leaf, split_tables_for_level,
    };
    let mut table = root.address().raw();
    for (level, shift) in [39u64, 30, 21, 12].into_iter().enumerate() {
        let pointer = crate::fork_stock::ForkStockHostCustody::physical_ptr_in::<AtomicU64>(
            stage2,
            carrick_guest_arch::FrameGpa::new(table + ((va >> shift) & 511) * 8),
        )
        .ok()?;
        // SAFETY: retained stock tables and exact owner exclusion, atomic word.
        let descriptor = unsafe { &*pointer }.load(Ordering::Acquire);
        if level == 3 || descriptor & 3 != 3 {
            return is_guest_cow_write_leaf(level, descriptor)
                .then(|| split_tables_for_level(level));
        }
        table = descriptor & 0x0000_ffff_ffff_f000;
    }
    None
}

/// Consume the exact reply-slot receipt while the native child still owns its
/// synchronous service continuation. A refused or unclaimed submission returns
/// all table grants; an applied receipt retains only its linked prefix.
pub(super) fn settle_native_descriptor_reply(
    custody: &Arc<crate::trap::CarrierVmCustody>,
    region: RetainedAbiRegion<'_>,
    execution: carrick_hal::fork_stock::GrantExecution,
    settlement: &mut carrick_el1_abi::NativeDescriptorSettlement,
) -> Result<bool, TrapError> {
    let accepted = (|| -> Result<bool, TrapError> {
        let Some((owner, generation, reply_address)) = settlement.request() else {
            return Ok(false);
        };
        if execution.binding.mm.raw() != owner.mm().raw() {
            return Ok(false);
        }
        let Ok((reply, _pin)) =
            retain_reply::<carrick_el1_abi::PortalGrantSlot>(custody, region, reply_address)
        else {
            return Ok(false);
        };
        // SAFETY: retain_reply pins the complete aligned slot until settlement.
        let reply = unsafe { reply.as_ref() };
        let Some(window) = reply.window() else {
            return Ok(false);
        };
        if window.operation.carrier != owner.carrier()
            || window.operation.mm != owner.mm()
            || window.operation.incarnation != owner.incarnation()
            || window.operation.sequence != generation
        {
            return Ok(false);
        }
        // A root publication belongs to the exact same producer as synchronous
        // transfer. Match its retained window, reply and root before consulting
        // child stock; an unknown receipt never releases physical custody.
        let mut ledger = custody.native_root_replies.lock();
        if let Some(index) = ledger.entries.iter().position(|entry| {
            entry.identity.birth.mm == owner
                && entry.root == execution.context.root
                && entry.reply == reply_address
                && entry.window == window
                && entry.identity.birth.thread == execution.binding.thread_generation
        }) {
            let entry = &mut ledger.entries[index];
            let txn = *entry.grant.transaction();
            let Some((receipt, trace)) = reply.inspect_receipt_with_trace(window, &txn) else {
                // Terminal cancellation may skip applying a delivered reply.
                // Only confirmed withdrawal proves no descriptor was claimed;
                // unknown visibility keeps the complete grant in this ledger.
                if !reply.withdraw(window, &txn) {
                    return Ok(false);
                }
                let unpublished = ledger.entries.swap_remove(index);
                drop(ledger);
                drop(unpublished);
                return Ok(true);
            };
            // settle validates the full transaction digest and refuses unknown
            // visibility. Keep the row through physical/table settlement and
            // reply acknowledgment; no bare generation can retire its grant.
            entry.grant.settle(&receipt, trace)?;
            if reply.take_receipt(window, &txn) != Some(receipt) {
                return Err(stale());
            }
            let settled = ledger.entries.swap_remove(index);
            drop(ledger);
            drop(settled);
            return Ok(true);
        }
        drop(ledger);
        let mut deferred_releases = Vec::new();
        let outcome = {
            let mut stock = custody.fork_stock.lock();
            if !stock.owner.child_execution_matches(execution, owner) {
                return Ok(false);
            }
            let Some(txn) = stock
                .owner
                .child_physical_mut(owner.mm(), execution.context.root)
                .and_then(|physical| physical.supplied.as_ref())
                .and_then(|grants| grants.pending_backing_reply(reply, generation))
            else {
                return Ok(false);
            };
            settle_backing_and_tables(
                custody,
                &mut stock,
                owner,
                execution.context.root,
                reply,
                &txn,
                &mut deferred_releases,
            )
        };
        release_deferred_backings(custody, owner, execution.context.root, deferred_releases)?;
        outcome
    })();
    match accepted {
        Ok(true) => Ok(settlement.accept()),
        Ok(false) => {
            settlement.refuse();
            Ok(false)
        }
        Err(error) => {
            settlement.refuse();
            Err(error)
        }
    }
}

fn release_deferred_backings(
    custody: &Arc<crate::trap::CarrierVmCustody>,
    owner: carrick_el1_abi::El1MmHandle,
    root: carrick_guest_arch::RootGpa,
    deferred_releases: Vec<(
        Arc<carrick_hal::physical_grants::PhysicalGrantRollback>,
        Arc<crate::fork_stock::NativeFrameBacking>,
    )>,
) -> Result<(), TrapError> {
    for (rollback, backing) in deferred_releases {
        match backing.release_unused() {
            Ok(carrick_hal::physical_grants::PhysicalGrantRelease::Released) => {}
            Ok(carrick_hal::physical_grants::PhysicalGrantRelease::RetainUntilMmRetirement) => {
                rollback.retain_until_mm_retirement(backing);
            }
            Err(error) => {
                rollback.retain_allocation(backing);
                let mut stock = custody.fork_stock.lock();
                let _ = stock.owner.quarantine_native_supply(owner, root);
                return Err(error);
            }
        }
    }
    Ok(())
}

/// The shared physical owner authenticates the outcome and owns rollback.
/// Tables settle from that SAME outcome before the reply is acknowledged.
fn settle_backing_and_tables(
    custody: &Arc<crate::trap::CarrierVmCustody>,
    stock: &mut crate::fork_stock::ForkStockHostCustody,
    owner: carrick_el1_abi::El1MmHandle,
    root: carrick_guest_arch::RootGpa,
    reply: &carrick_el1_abi::PortalGrantSlot,
    txn: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
    deferred_releases: &mut Vec<(
        Arc<carrick_hal::physical_grants::PhysicalGrantRollback>,
        Arc<crate::fork_stock::NativeFrameBacking>,
    )>,
) -> Result<bool, TrapError> {
    let rollback = stock
        .owner
        .child_physical_mut(owner.mm(), root)
        .map(|physical| Arc::clone(&physical.rollback))
        .ok_or_else(stale)?;
    stock.owner.settle_native_backing_reply(
        &mut crate::fork_stock::fork_table_accounting(custody),
        owner,
        root,
        reply,
        txn,
        |backing| {
            deferred_releases.push((Arc::clone(&rollback), Arc::clone(backing)));
            Ok(carrick_hal::physical_grants::PhysicalGrantRelease::Released)
        },
    )
}

/// Why [`retain_ring_record`] could not retain a ring-owned record.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub(super) enum RingRecordMiss {
    /// No retained metadata covers the whole record.
    Absent,
    /// The granted extent's aperture entry is gone.
    ApertureAbsent,
    /// The address or the extent contradicts the metadata layout.
    Invalid,
}

/// Retain one record the ring's metadata allocator owns, for a host reader.
///
/// The ring allocates from two venues and a reader must not care which:
/// - its bootstrap arena inside the carrier ABI region, which the retained
///   region itself backs (no pin);
/// - a granted dynamic extent, which the returned pin keeps mapped.
///
/// Replies, successor manifests and thread controls all resolve here. A
/// lifecycle page's own controls sit in a loaned extent; a control in an
/// extension segment (#2734) sits wherever the allocator placed the segment.
pub(super) fn retain_ring_record<T>(
    custody: &Arc<crate::trap::CarrierVmCustody>,
    region: RetainedAbiRegion<'_>,
    address: carrick_guest_arch::KernelVa,
) -> Result<(core::ptr::NonNull<T>, Option<HostMetadataExtentPin>), RingRecordMiss> {
    let size = core::mem::size_of::<T>();
    if address.raw() < EL1_DYNAMIC_METADATA_BASE {
        let offset = address
            .raw()
            .checked_sub(carrick_el1_abi::EL1_REGION_BASE)
            .and_then(|offset| usize::try_from(offset).ok())
            .filter(|offset| fork_custody_in_retained_region(*offset, size))
            .ok_or(RingRecordMiss::Absent)?;
        return Ok((
            core::ptr::NonNull::new(region.record_ptr(offset).ok_or(RingRecordMiss::Invalid)?)
                .ok_or(RingRecordMiss::Invalid)?,
            None,
        ));
    }
    let (_, base, len) =
        retained_dynamic_metadata(custody, address, size).ok_or(RingRecordMiss::Absent)?;
    let offset = usize::try_from(
        address
            .raw()
            .checked_sub(base)
            .ok_or(RingRecordMiss::Invalid)?,
    )
    .map_err(|_| RingRecordMiss::Invalid)?;
    if offset.checked_add(size).is_none_or(|end| end > len) {
        return Err(RingRecordMiss::Invalid);
    }
    // A reader that snapshotted a generation revalidates it after this pin.
    let generation = custody.live_generation().ok_or(RingRecordMiss::Invalid)?;
    let pin = {
        let aperture = metadata_aperture(custody).lock();
        let index =
            ((base - EL1_DYNAMIC_METADATA_BASE) / EL1_DYNAMIC_METADATA_EXTENT_SIZE as u64) as usize;
        let mapping = aperture
            .slots
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(RingRecordMiss::ApertureAbsent)?;
        aperture
            .pin_extent(
                MetadataExtent::new(base, len as u64, mapping.token)
                    .ok_or(RingRecordMiss::Invalid)?,
                generation.0,
            )
            .map_err(|_| RingRecordMiss::Invalid)?
    };
    // SAFETY: the checked record lies wholly inside the pinned extent.
    let pointer = unsafe { pin.host_base().as_ptr().add(offset) };
    if !pointer.addr().is_multiple_of(core::mem::align_of::<T>()) {
        return Err(RingRecordMiss::Invalid);
    }
    Ok((
        core::ptr::NonNull::new(pointer.cast()).ok_or(RingRecordMiss::Invalid)?,
        Some(pin),
    ))
}

/// A reply the exact request retains: any miss is a custody mismatch.
pub(super) fn retain_reply<T>(
    custody: &Arc<crate::trap::CarrierVmCustody>,
    region: RetainedAbiRegion<'_>,
    address: carrick_guest_arch::KernelVa,
) -> Result<(core::ptr::NonNull<T>, Option<HostMetadataExtentPin>), TrapError> {
    retain_ring_record(custody, region, address).map_err(|_| stale())
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
            origin: carrick_core_abi::service::ServiceOrigin::Initial,
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

    /// Protocol-only double: actual descriptor transport and production
    /// settlement own its lifetime; no physical allocation is fabricated.
    struct RootReplyDropWitness {
        txn: carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
        custody: std::sync::Weak<crate::trap::CarrierVmCustody>,
        drops: Arc<std::sync::atomic::AtomicUsize>,
        outside_ledger: Arc<std::sync::atomic::AtomicBool>,
    }
    impl carrick_aarch64::user_transfer::TransferGrant for RootReplyDropWitness {
        fn transaction(&self) -> &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn {
            &self.txn
        }
        fn settle(
            &mut self,
            _: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorReceipt,
            _: Option<carrick_mmu_core::live_descriptor_words::GrantRefusalTrace>,
        ) -> Result<bool, TrapError> {
            panic!("unclaimed or unknown descriptor cannot manufacture a receipt")
        }
    }
    impl Drop for RootReplyDropWitness {
        fn drop(&mut self) {
            use std::sync::atomic::Ordering;
            let outside = self
                .custody
                .upgrade()
                .is_none_or(|custody| custody.native_root_replies.try_lock().is_some());
            self.outside_ledger.store(outside, Ordering::Release);
            self.drops.fetch_add(1, Ordering::AcqRel);
        }
    }

    struct RootReplyFixture {
        region: carrick_test_support::ZeroedBox<carrick_test_support::TestEl1Region>,
        custody: Arc<crate::trap::CarrierVmCustody>,
        owner: carrick_el1_abi::El1MmHandle,
        window: carrick_el1_abi::PortalGrantWindow,
        txn: carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
        execution: carrick_hal::fork_stock::GrantExecution,
        address: carrick_guest_arch::KernelVa,
        drops: Arc<std::sync::atomic::AtomicUsize>,
        outside_ledger: Arc<std::sync::atomic::AtomicBool>,
    }
    impl RootReplyFixture {
        fn new() -> Self {
            use carrick_mmu_core::aarch64::descriptor_txn::{
                DescriptorOp, DescriptorTxn, DescriptorTxnId, PageSpan, TableGrants,
            };
            let mut region = carrick_test_support::TestEl1Region::zeroed();
            let custody = Arc::new(crate::trap::CarrierVmCustody::new_live_fixture());
            let mut birth = birth();
            // SAFETY: this tests transport custody only, never physical access.
            birth.mm = unsafe {
                carrick_el1_abi::El1MmHandle::from_admitted_owner(
                    custody.transfer_carrier,
                    birth.mm.mm(),
                    birth.mm.incarnation(),
                )
            };
            let window = carrick_el1_abi::PortalGrantWindow::decode([
                custody.transfer_carrier.get(),
                1,
                1,
                7,
                1,
                0x4000,
                0x5000,
                1,
                0x4000,
                0,
                0,
                0,
                0,
            ])
            .unwrap();
            let root = carrick_guest_arch::RootGpa::page_aligned(
                carrick_guest_arch::FrameGpa::new(0x1000),
            )
            .unwrap();
            let txn = DescriptorTxn {
                id: DescriptorTxnId {
                    mm_key: NonZeroU64::MIN,
                    generation: NonZeroU64::new(23).unwrap(),
                },
                root: carrick_mmu_core::aarch64::SubstrateGpa(root.address().raw()),
                tables: TableGrants::NONE,
                op: DescriptorOp::Publish {
                    span: PageSpan::new(0x4000, 4096),
                    expected_ipa: carrick_mmu_core::aarch64::SubstrateGpa(0xa000),
                    access: carrick_mmu_core::aarch64::LeafAccess::Read,
                },
            };
            let address =
                carrick_guest_arch::KernelVa::new(carrick_el1_abi::EL1_BOOTSTRAP_METADATA_BASE);
            // SAFETY: TestEl1Region owns aligned complete ABI storage and
            // bootstrap metadata admits this retained reply allocation.
            let reply = unsafe {
                let pointer = region
                    .as_mut_ptr()
                    .add(carrick_el1_abi::EL1_BOOTSTRAP_METADATA_OFFSET as usize)
                    .cast::<carrick_el1_abi::PortalGrantSlot>();
                pointer.write(carrick_el1_abi::PortalGrantSlot::new());
                &*pointer
            };
            assert!(reply.submit(window, &txn));
            let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let outside_ledger = Arc::new(std::sync::atomic::AtomicBool::new(false));
            custody
                .native_root_replies
                .lock()
                .entries
                .push(NativeRootReply {
                    identity: carrick_core_abi::service::ServiceIdentity {
                        birth,
                        execution: SnapshotGeneration::INITIAL,
                        sequence: NonZeroU64::new(2).unwrap(),
                    },
                    root,
                    reply: address,
                    window,
                    grant: Box::new(RootReplyDropWitness {
                        txn,
                        custody: Arc::downgrade(&custody),
                        drops: drops.clone(),
                        outside_ledger: outside_ledger.clone(),
                    }),
                    _pin: None,
                });
            let execution = carrick_hal::fork_stock::GrantExecution::new(
                carrick_guest_arch::CpuId::new(0),
                carrick_core_abi::ExecutionBinding {
                    task: carrick_core_abi::EntryTaskKey::from_raw(1),
                    generation: SnapshotGeneration::INITIAL,
                    mm: carrick_core_abi::EntryMmKey::from_raw(1),
                    thread_generation: birth.thread,
                },
                carrick_guest_arch::AddressContext {
                    root,
                    mm: carrick_guest_arch::MmGeneration::new(NonZeroU64::MIN),
                    generation: carrick_guest_arch::ContextGeneration::new(NonZeroU64::MIN),
                },
            );
            Self {
                region,
                custody,
                owner: birth.mm,
                window,
                txn,
                execution,
                address,
                drops,
                outside_ledger,
            }
        }

        fn reply(&self) -> &carrick_el1_abi::PortalGrantSlot {
            // SAFETY: complete initialized aligned slot retained by this fixture.
            unsafe {
                &*self
                    .region
                    .as_ptr()
                    .add(carrick_el1_abi::EL1_BOOTSTRAP_METADATA_OFFSET as usize)
                    .cast::<carrick_el1_abi::PortalGrantSlot>()
            }
        }

        fn settle(
            &self,
            owner: carrick_el1_abi::El1MmHandle,
            address: carrick_guest_arch::KernelVa,
        ) -> bool {
            let mut settlement = carrick_el1_abi::NativeDescriptorSettlement::EMPTY;
            settlement
                .initialize(owner, self.window.operation.sequence, address)
                .unwrap();
            // SAFETY: this fixture retains the aligned entire region across
            // the production settlement entry and its atomic reply accesses.
            let region = unsafe {
                RetainedAbiRegion::new(
                    self.region.as_ptr().cast_mut(),
                    carrick_el1_abi::EL1_REGION_SIZE as usize,
                )
                .unwrap()
            };
            let accepted = settle_native_descriptor_reply(
                &self.custody,
                region,
                self.execution,
                &mut settlement,
            )
            .unwrap();
            assert_eq!(
                settlement.take(owner, self.window.operation.sequence, address),
                Some(if accepted { Ok(()) } else { Err(()) })
            );
            accepted
        }
    }
    impl Drop for RootReplyFixture {
        fn drop(&mut self) {
            let entries = std::mem::take(&mut self.custody.native_root_replies.lock().entries);
            drop(entries);
        }
    }

    #[test]
    fn root_grant_destroy_proof_failure_retains_custody_and_blocks_reuse() {
        use std::sync::atomic::Ordering;
        let fixture = RootReplyFixture::new();
        let raw_destroys = crate::trap::raw_stage2_destroy_count;
        let destroys_before = raw_destroys();
        let releases = core::cell::Cell::new(0);
        // The test grant has no destroyed-VM proof. The production destroy
        // entry must retain it after successful raw destruction, not publish
        // release or permit a second raw destroy against a successor: the
        // second attempt finds the generation `Gone` and never reaches the
        // backend's raw destroy.
        for _ in 0..2 {
            let result = crate::trap::destroy_vm_with_custody_using(
                &fixture.custody,
                "root grant proof failure",
                carrick_aarch64::stage2::Stage2Status::SUCCESS,
                || releases.set(releases.get() + 1),
            );
            assert!(result.is_err());
            assert_eq!(raw_destroys() - destroys_before, 1);
            assert_eq!(releases.get(), 0);
            assert_eq!(fixture.drops.load(Ordering::Acquire), 0);
            assert_eq!(fixture.custody.native_root_replies.lock().entries.len(), 1);
            assert_eq!(fixture.custody.live_generation(), None);
            assert!(fixture.custody.begin_create().is_err());
            assert!(matches!(
                fixture.custody.stage2.lifecycle(),
                carrick_aarch64::stage2::custody::Stage2Lifecycle::Gone(_)
            ));
        }
    }

    #[test]
    fn root_descriptor_cancel_withdraws_unclaimed_reply_and_drops_once() {
        use std::sync::atomic::Ordering;
        let fixture = RootReplyFixture::new();
        assert!(fixture.settle(fixture.owner, fixture.address));
        assert_eq!(fixture.drops.load(Ordering::Acquire), 1);
        assert!(fixture.outside_ledger.load(Ordering::Acquire));
        assert!(
            fixture
                .custody
                .native_root_replies
                .lock()
                .entries
                .is_empty()
        );
        assert!(fixture.reply().window().is_none());
        assert!(
            !fixture.settle(fixture.owner, fixture.address),
            "no second settlement"
        );
        assert_eq!(fixture.drops.load(Ordering::Acquire), 1);
    }

    #[test]
    fn root_descriptor_cancel_retains_claimed_unknown_visibility() {
        use std::sync::atomic::Ordering;
        let fixture = RootReplyFixture::new();
        let _claimed = fixture.reply().descriptor().claim_for_mm(1).unwrap();
        assert!(!fixture.settle(fixture.owner, fixture.address));
        assert_eq!(fixture.drops.load(Ordering::Acquire), 0);
        assert_eq!(fixture.custody.native_root_replies.lock().entries.len(), 1);
        assert_eq!(fixture.reply().window(), Some(fixture.window));
    }

    #[test]
    fn root_descriptor_cancel_refuses_foreign_owner_or_reply() {
        use std::sync::atomic::Ordering;
        let fixture = RootReplyFixture::new();
        // SAFETY: a forged candidate grants no authority to this fixture.
        let foreign = unsafe {
            carrick_el1_abi::El1MmHandle::from_admitted_owner(
                fixture.owner.carrier(),
                fixture.owner.mm(),
                NonZeroU64::new(2).unwrap(),
            )
        };
        assert!(!fixture.settle(foreign, fixture.address));
        assert!(!fixture.settle(
            fixture.owner,
            carrick_guest_arch::KernelVa::new(fixture.address.raw() + 4096)
        ));
        assert_eq!(fixture.drops.load(Ordering::Acquire), 0);
        assert_eq!(fixture.custody.native_root_replies.lock().entries.len(), 1);
        assert_eq!(fixture.reply().window(), Some(fixture.window));
        assert!(fixture.reply().withdraw(fixture.window, &fixture.txn));
    }

    #[test]
    fn native_exec_payload_authenticates_a_live_metadata_block() {
        let root =
            carrick_guest_arch::RootGpa::page_aligned(carrick_guest_arch::FrameGpa::new(0x1000))
                .unwrap();
        let address = carrick_el1_abi::EL1_DYNAMIC_METADATA_BASE + 0x1234;
        let indices = carrick_mmu_core::aarch64::indices(address);
        let words = std::collections::BTreeMap::from([
            (0x1000 + indices[0] as u64 * 8, 0x2003),
            (0x2000 + indices[1] as u64 * 8, 0x3003),
            (
                0x3000 + indices[2] as u64 * 8,
                (address & !0x1f_ffff) | 0x401,
            ),
        ]);
        let mut loads = 0;
        assert_eq!(
            native_output_from(root, address, |slot| {
                loads += 1;
                words.get(&slot).copied()
            }),
            Some(address & !4095)
        );
        assert_eq!(loads, 3, "a block terminates the authenticated walk");
    }

    /// #2734: a thread born into an extension entry keeps its control in a
    /// lifecycle segment, which the ring's allocator may place in its
    /// bootstrap arena. Intake resolved only granted extents and died with
    /// "native-service control metadata absent" (signed HVF, `5184cadfe`).
    #[test]
    fn intake_resolves_a_segment_control_in_the_ring_bootstrap_arena() {
        use carrick_el1_abi::{ThreadControlSlot, ThreadLifecyclePage, ThreadLifecycleSegment};
        let mut region = carrick_test_support::TestEl1Region::zeroed();
        let custody = Arc::new(crate::trap::CarrierVmCustody::new_live_fixture());
        let offset = (carrick_el1_abi::EL1_BOOTSTRAP_METADATA_OFFSET as usize)
            .next_multiple_of(core::mem::align_of::<ThreadLifecycleSegment>());
        // SAFETY: TestEl1Region owns aligned complete ABI storage; the
        // bootstrap arena admits one whole segment at this offset.
        let segment = unsafe {
            let segment = region
                .as_mut_ptr()
                .add(offset)
                .cast::<ThreadLifecycleSegment>();
            ThreadLifecycleSegment::initialize_at(segment);
            core::ptr::NonNull::new(segment).unwrap()
        };
        let page = ThreadLifecyclePage::new();
        // SAFETY: initialized above and retained by `region` past `page`.
        unsafe { page.publish_extension(segment) };
        let first = carrick_el1_abi::THREAD_POOL_ENTRIES;
        let control = page
            .extension_control(first + 3)
            .expect("linked segment control");
        let record = birth().record;
        control.bind_zone_record(record);
        let address = carrick_guest_arch::KernelVa::new(
            carrick_el1_abi::EL1_REGION_BASE
                + (core::ptr::from_ref(control).addr() - region.as_ptr().addr()) as u64,
        );
        assert!(address.raw() >= carrick_el1_abi::EL1_BOOTSTRAP_METADATA_BASE);
        assert!(
            retained_dynamic_metadata(&custody, address, core::mem::size_of::<ThreadControlSlot>())
                .is_none(),
            "a bootstrap-arena control is in no granted extent: the old intake's miss"
        );
        // SAFETY: this fixture retains the aligned entire region.
        let retained = unsafe {
            RetainedAbiRegion::new(
                region.as_mut_ptr(),
                carrick_el1_abi::EL1_REGION_SIZE as usize,
            )
            .unwrap()
        };
        let (resolved, pin) =
            retain_ring_record::<ThreadControlSlot>(&custody, retained, address).unwrap();
        assert!(pin.is_none(), "the retained ABI region backs the arena");
        assert!(core::ptr::eq(resolved.as_ptr().cast_const(), control));
        // SAFETY: the resolver returned the initialized segment control.
        assert_eq!(unsafe { resolved.as_ref() }.zone_record(), Some(record));

        // Below the arena is carrier ABI state, never ring metadata.
        let below = carrick_guest_arch::KernelVa::new(
            carrick_el1_abi::EL1_BOOTSTRAP_METADATA_BASE
                - core::mem::size_of::<ThreadControlSlot>() as u64,
        );
        assert_eq!(
            retain_ring_record::<ThreadControlSlot>(&custody, retained, below).err(),
            Some(RingRecordMiss::Absent)
        );
        // A granted-extent address with no extent behind it is absent too.
        let ungranted = carrick_guest_arch::KernelVa::new(EL1_DYNAMIC_METADATA_BASE);
        assert_eq!(
            retain_ring_record::<ThreadControlSlot>(&custody, retained, ungranted).err(),
            Some(RingRecordMiss::Absent)
        );
        // SAFETY: no reader of the extension entries remains.
        unsafe { page.detach_extension(|_| {}) };
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
