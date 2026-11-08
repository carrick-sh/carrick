//! Backing custody for a ring-owned request; no host task or process adoption.
use super::*;
use carrick_core_abi::service::{
    ExecCapabilityId, ServiceCell, ServiceError, ServiceFailureCode, ServiceRequest,
    ServiceSelector, ServiceTicket,
};
use carrick_sched_core::object_wait::ObjectWaitKey;
use core::ops::Deref;

/// Counted ENOSYS for an exec request whose capability names no live service.
const UNROUTED_EXEC: ServiceFailureCode = match ServiceFailureCode::new(38) {
    Some(code) => code,
    None => ServiceFailureCode::MINIMUM,
};

/// Carrier-retained file/loader service. It owns no task lookup; the service
/// cell has already authenticated `request` against the stopped ring member.
pub trait NativeExecHostService: core::fmt::Debug + Send + Sync + 'static {
    /// Prepare the image of `successor`, whose published reservation root is
    /// still unadmitted: the service imports the image's rows into it.
    fn prepare(
        &self,
        request: ServiceRequest,
        payload: &[u8],
        successor: carrick_el1_abi::ReservationMm,
    ) -> Result<Box<dyn NativeExecPreparation>, ServiceFailureCode>;

    /// Serve one ring-staged host-file record
    /// ([`carrick_core_abi::host_file`]) under the caller's own access
    /// context, which a path record carries by value, writing its reply in
    /// place. `Err` refuses the exact request
    /// (the ring answers counted ENOSYS); no reply may have been written. A
    /// private-mapping record returns the retained byte source, which the
    /// carrier registers for the caller's MM before acknowledging.
    fn serve_host_file(
        &self,
        request: ServiceRequest,
        record: &mut [u8],
    ) -> Result<Option<Arc<dyn carrick_hal::fork_stock::HostBackingRetention>>, NativeHostFileRefused>;

    /// Serve the root fork seed crossing: write the host-served root's live
    /// cwd and root into `record` once ([`carrick_core_abi::service::RootForkSeed::serve`]).
    /// `false` refuses it; the fork then fails without a child.
    fn root_fork_seed(&self, record: &mut carrick_core_abi::service::RootForkSeed) -> bool;
}

pub use carrick_hal::fork_stock::NativeHostFileRefused;

/// Opaque fallibly prepared image. Exact carrier custody retains this result
/// until the ring consumes successor adoption or terminal cleanup drops it.
pub trait NativeExecPreparation: core::fmt::Debug + Send + 'static {
    fn into_parts(self: Box<Self>) -> NativeExecParts;
}

/// A prepared successor image: the carrier maps `plan` except its lazy
/// regions, which the successor's ring owner supplies from `sources`.
pub struct NativeExecParts {
    pub plan: crate::trap::GuestMappingPlan,
    pub lazy_regions: Vec<(u64, u64)>,
    pub sources: Vec<Arc<dyn carrick_hal::fork_stock::HostBackingRetention>>,
}

/// Exact carrier registration for a retained exec service.
///
/// The directory, rather than the run that installed it, owns the service
/// while guest work can name its capability.  The returned registration is
/// the run's unique removal authority and must settle after its process tree
/// has joined but before container resources are retired.
#[derive(::core::fmt::Debug, ::core::default::Default)]
pub(crate) struct NativeExecServiceDirectory {
    services: parking_lot::Mutex<Vec<(ExecCapabilityId, Arc<dyn NativeExecHostService>)>>,
}

#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum NativeExecRegistrationError {
    Duplicate,
    Absent,
}

impl NativeExecServiceDirectory {
    pub(crate) fn install(
        self: &Arc<Self>,
        capability: ExecCapabilityId,
        service: Arc<dyn NativeExecHostService>,
    ) -> Result<NativeExecServiceRegistration, NativeExecRegistrationError> {
        let mut services = self.services.lock();
        if services.iter().any(|(id, _)| *id == capability) {
            return Err(NativeExecRegistrationError::Duplicate);
        }
        services.push((capability, service));
        Ok(NativeExecServiceRegistration {
            directory: Arc::clone(self),
            capability,
            armed: true,
        })
    }

    pub(crate) fn service(
        &self,
        capability: ExecCapabilityId,
    ) -> Option<Arc<dyn NativeExecHostService>> {
        self.services
            .lock()
            .iter()
            .find(|(id, _)| *id == capability)
            .map(|(_, service)| Arc::clone(service))
    }

    /// The service a guest exec request names, or the counted ENOSYS a
    /// request receives when no live service holds that capability (for
    /// example a fork child of a root whose image the host replaced). A
    /// guest-selected capability is never carrier custody to fail on.
    pub(crate) fn resolve(
        &self,
        capability: ExecCapabilityId,
    ) -> Result<Arc<dyn NativeExecHostService>, ServiceFailureCode> {
        self.service(capability).ok_or(UNROUTED_EXEC)
    }

    fn remove(&self, capability: ExecCapabilityId) -> Result<(), NativeExecRegistrationError> {
        let mut services = self.services.lock();
        let index = services
            .iter()
            .position(|(id, _)| *id == capability)
            .ok_or(NativeExecRegistrationError::Absent)?;
        services.swap_remove(index);
        Ok(())
    }
}

/// Consuming authority to release one carrier-retained exec service.
#[must_use]
pub struct NativeExecServiceRegistration {
    directory: Arc<NativeExecServiceDirectory>,
    capability: ExecCapabilityId,
    armed: bool,
}

impl NativeExecServiceRegistration {
    pub fn retire(mut self) -> Result<(), NativeExecRegistrationError> {
        self.directory.remove(self.capability)?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for NativeExecServiceRegistration {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.directory.remove(self.capability);
        }
    }
}

#[cfg(test)]
mod native_exec_service_registration_tests {
    use super::*;

    #[derive(Debug)]
    struct RetainedService {
        _retained: Arc<()>,
    }

    impl NativeExecHostService for RetainedService {
        fn prepare(
            &self,
            _request: ServiceRequest,
            _payload: &[u8],
            _successor: carrick_el1_abi::ReservationMm,
        ) -> Result<Box<dyn NativeExecPreparation>, ServiceFailureCode> {
            Err(ServiceFailureCode::MINIMUM)
        }

        fn serve_host_file(
            &self,
            _request: ServiceRequest,
            _record: &mut [u8],
        ) -> Result<
            Option<Arc<dyn carrick_hal::fork_stock::HostBackingRetention>>,
            NativeHostFileRefused,
        > {
            Err(NativeHostFileRefused)
        }

        fn root_fork_seed(&self, _record: &mut carrick_core_abi::service::RootForkSeed) -> bool {
            false
        }
    }

    /// #936: a native child of a post-exec root names the root's original
    /// exec capability, which the host exec retired. The request must be a
    /// counted ENOSYS (as on main), never a carrier custody fatal.
    #[test]
    fn retired_or_unknown_exec_capability_is_a_counted_enosys() {
        let directory = Arc::new(NativeExecServiceDirectory::default());
        let capability = carrick_core_abi::service::ExecCapabilityId::new(
            core::num::NonZeroU64::new(7).unwrap(),
        );
        assert_eq!(
            directory
                .resolve(capability)
                .err()
                .map(ServiceFailureCode::raw),
            Some(38)
        );
        let service: Arc<dyn NativeExecHostService> = Arc::new(RetainedService {
            _retained: Arc::new(()),
        });
        let registration = directory.install(capability, service).unwrap();
        assert!(directory.resolve(capability).is_ok());
        registration.retire().unwrap();
        assert_eq!(
            directory
                .resolve(capability)
                .err()
                .map(ServiceFailureCode::raw),
            Some(38)
        );
    }

    #[test]
    fn native_exec_registration_retirement_releases_installed_service() {
        let directory = Arc::new(NativeExecServiceDirectory::default());
        let retained = Arc::new(());
        let witness = Arc::downgrade(&retained);
        let capability = carrick_core_abi::service::ExecCapabilityId::new(
            core::num::NonZeroU64::new(1).unwrap(),
        );
        let service: Arc<dyn NativeExecHostService> = Arc::new(RetainedService {
            _retained: Arc::clone(&retained),
        });
        drop(retained);

        let registration = directory.install(capability, service).unwrap();
        assert!(
            witness.upgrade().is_some(),
            "installed service was not retained"
        );
        assert!(
            directory.service(capability).is_some(),
            "plain root exec capability must resolve before retirement"
        );
        registration.retire().unwrap();
        assert!(
            witness.upgrade().is_none(),
            "settled registration retained the service owner"
        );
    }
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
        let is_mapping =
            match carrick_core_abi::host_file::HostFileRequestView::parse(record.bytes_mut()) {
                Ok(view) => view.header().op == carrick_core_abi::host_file::HostFileOp::MapPrivate,
                Err(_) => return self.refuse_host_file(),
            };
        if is_mapping {
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
        let served = service.serve_host_file(request, record.bytes_mut());
        match served {
            Ok(None) => {
                self.finish_exec_ticket(|ticket| ticket.complete(true).map_err(|_| stale()))
            }
            Ok(Some(source)) => {
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
            Err(NativeHostFileRefused) => self.refuse_host_file(),
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
    /// request. Preparation performs all fallible file and loader work before
    /// publishing `Supplied`; the result remains carrier-owned by exact
    /// birth/MM/execution/sequence.
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
        let service = match self.custody.native_exec_services.resolve(capability) {
            Ok(service) => service,
            Err(unrouted) => return self.finish_exec_failure(unrouted),
        };
        match service.prepare(request, payload, successor_mm) {
            Ok(prepared) => {
                let prepared = match crate::trap::prepare_native_exec_successor(
                    Arc::clone(&self.custody),
                    prepared.into_parts(),
                ) {
                    Ok(prepared) => prepared,
                    Err(_) => {
                        return self.finish_exec_failure(
                            ServiceFailureCode::new(12).unwrap_or(ServiceFailureCode::MINIMUM),
                        );
                    }
                };
                self.publish_exec_prepared(successor_mm, root_generation, manifest, prepared)
            }
            Err(failure) => self.finish_exec_failure(failure),
        }
    }

    fn publish_exec_prepared(
        self,
        successor_mm: carrick_el1_abi::ReservationMm,
        root_generation: core::num::NonZeroU64,
        manifest: core::ptr::NonNull<carrick_core_abi::service::ExecSuccessorManifest>,
        prepared: crate::trap::PreparedNativeExecSuccessor,
    ) -> Result<carrick_sched_core::WakeEffects, TrapError> {
        let identity = self.request().identity;
        let custody = Arc::clone(&self.custody);
        let receipt = match custody.reserve_native_exec_receipt() {
            Ok(receipt) => receipt,
            Err(()) => {
                drop(prepared);
                return self.finish_exec_failure(
                    ServiceFailureCode::new(11).unwrap_or(ServiceFailureCode::MINIMUM),
                );
            }
        };
        let asid = prepared.prepared_asid();
        let sealed = unsafe { manifest.as_ref() }
            .seal(
                identity,
                receipt,
                carrick_core_abi::service::ExecSuccessorBacking {
                    root: prepared.root(),
                    asid: asid.asid(),
                    asid_generation: core::num::NonZeroU64::new(asid.generation())
                        .ok_or_else(|| stale())?,
                },
                carrick_core_abi::service::ExecSuccessorEntry {
                    entry: carrick_guest_arch::UserVa::new(prepared.entry()),
                    stack_pointer: carrick_guest_arch::UserVa::new(prepared.stack_pointer()),
                },
            )
            .ok_or_else(|| stale())?;
        if sealed.open(identity, receipt).is_none_or(|view| {
            view.successor_mm != successor_mm || view.root_generation != root_generation
        }) {
            return Err(stale());
        }
        let census = self.census;
        let request = self.request();
        self.finish_exec_ticket(|ticket| {
            match ticket.publish_exec_prepared(receipt, prepared, |receipt, prepared| {
                custody.retain_native_exec_preparation(receipt, identity, prepared);
                // SAFETY: the exact ticket retains this pinned, aligned reply
                // until the release-store completion below.
                unsafe { manifest.as_ptr().write(sealed) };
            }) {
                Ok(()) => Ok(()),
                Err((_, ticket, prepared)) => {
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
                carrick_sched_core::LockWait::complete_object_wake(
                    &carrick_kernel::el1_zone::HostLockWait,
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
        let pool = carrick_el1_abi::cow_grant_pool_host().ok_or_else(|| stale())?;
        let mut stock = custody.fork_stock.lock();
        if stock.owner.child_owner(handle.mm()) != Some(handle)
            || stock.owner.is_quarantined(handle.mm())
        {
            return self.refuse();
        }
        let root = stock.owner.child_root(handle.mm()).ok_or_else(|| stale())?;
        let inventory = stock.inventory().ok_or_else(|| stale())?;
        let physical = stock
            .owner
            .child_physical_mut(handle.mm(), root)
            .ok_or_else(|| stale())?;
        let owner = carrick_hal::GuestFrameOwner {
            native_mm: carrick_guest_arch::MmGeneration::new(
                core::num::NonZeroU64::new(handle.mm().raw()).ok_or_else(|| stale())?,
            ),
            root_generation: carrick_guest_arch::ContextGeneration::new(handle.incarnation()),
        };
        let grants = physical
            .supplied
            .get_or_insert_with(|| carrick_hal::physical_grants::NativePhysicalGrants::new(owner));
        if grants.owner() != owner || grants.failed() || physical.rollback.failed() {
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
                    retained_owner: Default::default(),
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
                grants.publish_cow(staged.with_backing(retained), pool, exclusion.proof())?;
            }
        }
        let supplied = pool.ready(window.operation.mm.raw()).next().is_some();
        drop(stock);
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
                carrick_sched_core::LockWait::complete_object_wake(
                    &carrick_kernel::el1_zone::HostLockWait,
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
            if !reply.submit(window, &txn) {
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
                        carrick_sched_core::LockWait::complete_object_wake(
                            &carrick_kernel::el1_zone::HostLockWait,
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
            .ok_or_else(|| stale())?;
        let publication_len = bytes
            .as_ref()
            .map_or(window.range.len(), |bytes| bytes.len() as u64);
        if window.fault_page >= window.range.start() + publication_len {
            return self.finish(None, false, true);
        }
        let owner = carrick_hal::GuestFrameOwner {
            native_mm: carrick_guest_arch::MmGeneration::new(
                core::num::NonZeroU64::new(handle.mm().raw()).ok_or_else(|| stale())?,
            ),
            root_generation: carrick_guest_arch::ContextGeneration::new(handle.incarnation()),
        };
        let grants = physical
            .supplied
            .get_or_insert_with(|| carrick_hal::physical_grants::NativePhysicalGrants::new(owner));
        if grants.owner() != owner || grants.failed() || physical.rollback.failed() {
            return Err(stale());
        }
        // SAFETY: intake retains this authenticated request-owned reply.
        let reply_slot = unsafe { reply.as_ref() };
        if !grants.backing_reply_available(reply_slot, window) {
            drop(stock);
            return self.refuse();
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
            );
        let staged = match staged_result {
            Ok(staged) => staged,
            Err(error) => {
                // Staging can fail after applying inventory. Its guard then
                // attempts undo; an unknown undo already retained the receipt.
                // Couple this allocation to that failure custody before any
                // backend release can discard its bytes.
                if physical.rollback.failed() {
                    physical.rollback.retain_allocation(retained);
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
                        physical.rollback.retain_until_mm_retirement(retained);
                    }
                    Err(release_error) => {
                        physical.rollback.retain_allocation(retained);
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
        let unpublished = staged.with_backing(retained);
        let data = *unpublished.grants().first().ok_or_else(|| stale())?;
        let table_reservation = match stock.owner.reserve_native_descriptor_tables(
            &mut crate::fork_stock::fork_table_accounting(&custody),
            handle,
            root,
            MAX_TABLE_GRANTS,
        ) {
            Ok(reservation) => reservation,
            Err(_) => {
                if let Err(error) =
                    unpublished.abort_with_release(|backing| backing.release_unused())
                {
                    stock
                        .owner
                        .quarantine_native_supply(handle, root)
                        .map_err(|_| stale())?;
                    return Err(error);
                }
                drop(stock);
                return self.refuse();
            }
        };
        let txn = DescriptorTxn {
            id: DescriptorTxnId {
                mm_key: core::num::NonZeroU64::new(handle.mm().raw()).ok_or_else(|| stale())?,
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
            if let Err(error) = unpublished.abort_with_release(|backing| backing.release_unused()) {
                stock
                    .owner
                    .quarantine_native_supply(handle, root)
                    .map_err(|_| stale())?;
                return Err(error);
            }
            drop(stock);
            return self.refuse();
        }
        let staged = stock
            .owner
            .child_physical_mut(handle.mm(), root)
            .ok_or_else(|| stale())?
            .supplied
            .as_mut()
            .ok_or_else(|| stale())?
            .stage_backing_reply(reply_slot, window, txn, unpublished, |backing| {
                backing.release_unused()
            });
        if let Err(error) = staged {
            stock
                .owner
                .quarantine_native_supply(handle, root)
                .map_err(|_| stale())?;
            return Err(error);
        }
        drop(stock);
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
                carrick_sched_core::LockWait::complete_object_wake(
                    &carrick_kernel::el1_zone::HostLockWait,
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
        let queue = match delivery {
            Ok(()) => {
                drop(stock);
                queue
            }
            Err((reason, ticket, ())) => {
                drop(queue);
                // The returned ticket keeps the service BUSY and reply pinned
                // until rollback settles. No queue guard spans this release.
                if !settle_backing_and_tables(&custody, &mut stock, handle, root, reply, txn)? {
                    return Err(stale());
                }
                if !matches!(
                    reason,
                    carrick_core_abi::service::PreparedDeliveryError::Cancelled
                        | carrick_core_abi::service::PreparedDeliveryError::Refused
                ) {
                    return Err(stale());
                }
                drop(stock);
                let queue = zone
                    .object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
                        carrick_sched_core::LockWait::complete_object_wake(
                            &carrick_kernel::el1_zone::HostLockWait,
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
                carrick_sched_core::LockWait::complete_object_wake(
                    &carrick_kernel::el1_zone::HostLockWait,
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
            carrick_sched_core::LockWait::complete_object_wake(
                &carrick_kernel::el1_zone::HostLockWait,
                owned.zone(),
                owned,
            )
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
        let address = carrick_guest_arch::KernelVa::new(identity.control_slot);
        let Some((_, base, len)) = retained_dynamic_metadata(
            custody,
            address,
            core::mem::size_of::<carrick_el1_abi::ThreadControlSlot>(),
        ) else {
            return consumed.miss("native-service control metadata absent");
        };
        let offset = identity
            .control_slot
            .checked_sub(base)
            .ok_or_else(|| stale())? as usize;
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
            let extent =
                MetadataExtent::new(base, len as u64, mapping.token).ok_or_else(|| stale())?;
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
        // SAFETY: the pin retains initialized control storage. The exact
        // member and control identity are revalidated under the service queue.
        let control = unsafe { &*control };
        let pin = ServicePin {
            cell: core::ptr::NonNull::from(&control.service),
            _mapping: pin,
            _carrier: Arc::clone(custody),
        };
        let queue = zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin, &|owned| {
                carrick_sched_core::LockWait::complete_object_wake(
                    &carrick_kernel::el1_zone::HostLockWait,
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
        let claim_backing = Arc::clone(&pin._mapping._backing);
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
        let stock = custody.fork_stock.lock();
        if stock.owner.child_owner(handle.mm()) != Some(handle) {
            return Err(stale());
        }
        let root = stock.owner.child_root(handle.mm()).ok_or_else(|| stale())?;
        let mut cursor = address;
        while cursor < end {
            if native_output(custody, root, cursor) != Some(cursor & !4095) {
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
fn native_output(
    custody: &crate::trap::CarrierVmCustody,
    root: carrick_guest_arch::RootGpa,
    va: u64,
) -> Option<u64> {
    native_output_from(root, va, |address| {
        let pointer = crate::fork_stock::ForkStockHostCustody::physical_ptr::<AtomicU64>(
            custody,
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
    let physical = stock
        .owner
        .child_physical_mut(mm, root)
        .ok_or_else(|| stale())?;
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
            let Some(receipt) = reply.inspect_receipt(window, &txn) else {
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
            entry.grant.settle(&receipt)?;
            if reply.take_receipt(window, &txn) != Some(receipt) {
                return Err(stale());
            }
            let settled = ledger.entries.swap_remove(index);
            drop(ledger);
            drop(settled);
            return Ok(true);
        }
        drop(ledger);
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
        )
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

/// The shared physical owner authenticates the outcome and owns rollback.
/// Tables settle from that SAME outcome before the reply is acknowledged.
fn settle_backing_and_tables(
    custody: &Arc<crate::trap::CarrierVmCustody>,
    stock: &mut crate::fork_stock::ForkStockHostCustody,
    owner: carrick_el1_abi::El1MmHandle,
    root: carrick_guest_arch::RootGpa,
    reply: &carrick_el1_abi::PortalGrantSlot,
    txn: &carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
) -> Result<bool, TrapError> {
    stock.owner.settle_native_backing_reply(
        &mut crate::fork_stock::fork_table_accounting(custody),
        owner,
        root,
        reply,
        txn,
        |backing| backing.release_unused(),
    )
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
            .ok_or_else(|| stale())?;
        return Ok((
            core::ptr::NonNull::new(region.record_ptr(offset).ok_or_else(|| stale())?)
                .ok_or_else(|| stale())?,
            None,
        ));
    }
    let (_, base, len) =
        retained_dynamic_metadata(custody, address, size).ok_or_else(|| stale())?;
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
                MetadataExtent::new(base, len as u64, mapping.token).ok_or_else(|| stale())?,
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
        core::ptr::NonNull::new(pointer.cast()).ok_or_else(|| stale())?,
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
        region: Box<carrick_test_support::TestEl1Region>,
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
        let destroys = core::cell::Cell::new(0);
        let releases = core::cell::Cell::new(0);
        // The test grant has no destroyed-VM proof. The production destroy
        // entry must retain it after successful raw destruction, not publish
        // release or permit a second raw destroy against a successor.
        for _ in 0..2 {
            let result = crate::trap::destroy_vm_with_custody_using(
                &fixture.custody,
                "root grant proof failure",
                || {
                    destroys.set(destroys.get() + 1);
                    0
                },
                || releases.set(releases.get() + 1),
            );
            assert!(result.is_err());
            assert_eq!(destroys.get(), 1);
            assert_eq!(releases.get(), 0);
            assert_eq!(fixture.drops.load(Ordering::Acquire), 0);
            assert_eq!(fixture.custody.native_root_replies.lock().entries.len(), 1);
            assert_eq!(fixture.custody.live_generation(), None);
            assert!(fixture.custody.begin_create().is_err());
            assert!(matches!(
                fixture.custody.state.lock().lifecycle,
                crate::trap::CarrierVmLifecycle::Destroying(_)
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
