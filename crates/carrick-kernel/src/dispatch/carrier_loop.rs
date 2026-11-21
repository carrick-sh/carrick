//! Shared host-carrier stage-1 alias publication, first-touch + stale-leaf
//! fault resolution, and `ReservationBusy` owner-wait helpers.
//!
//! Used by both the multi-thread HVPatch vCPU run loop (`carrick-runtime`) and
//! the single-process soft AArch64 runner (`carrick-softcpu-aarch64-host`) so
//! neither frame-inventory alias commits nor first-touch/stale-stage-1 fault
//! resolution can drift across carrier lanes.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use carrick_abi::LinuxProtFlags;
use carrick_el1_abi::{
    Aarch64ParkedContext, El1TaskId, MmPortalSlots, PortalOwnerWait, RecordRef, ThreadIdentity,
    ZoneTables,
};
use carrick_guest_mem::{Gpa, GuestVa, MappingSharing, MemoryError};
use carrick_hal::{
    FrameEventCapacity, FrameInventoryCommit, HostAliasBacking, ThreadedEngine, TrapError,
};
use carrick_mmu_core::aarch64::{LeafAccess, Stage1FaultKind};
use carrick_sched_core::object_wait::{ObjectWaitError, OperationToken, OwnedObjectWakeEffects};

use crate::dispatch::host_alias::{HostAliasInstallGuard, HostAliasTransaction};
use crate::dispatch::mem::ReservationBusy;
use crate::dispatch::mm_mutation::MmMutationGuard;
use crate::dispatch::{DispatchOutcome, SyscallDispatcher};
use crate::el1_zone::{HandbackEvent, HandbackPublisher, HostLockWait};
use crate::kernel::debug::HvpatchAliasInstallSite;
use crate::kernel::{FrameInventoryError, KernelContext};
use crate::linux_abi::{
    LINUX_ENOMEM, LINUX_PAGE_SIZE, LINUX_PROT_EXEC, LINUX_PROT_READ, LINUX_PROT_WRITE,
};

/// Publish a backend-staged alias [`FrameInventoryCommit`] to the kernel's
/// authoritative [`crate::kernel::FrameInventoryAuthority`] for `context`'s MM.
pub fn apply_alias_frame_inventory(
    context: &KernelContext,
    commit: FrameInventoryCommit<()>,
) -> Result<(), FrameInventoryError> {
    context
        .kernel()
        .frame_inventory()
        .apply(context.shared().mm().id(), commit)
        .map(|_| ())
}

/// Structured failure from [`finish_host_alias_stage1_install`] after stage-2
/// alias publication has already committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasStage1InstallFailure {
    pub site: HvpatchAliasInstallSite,
    pub message: String,
}

/// Complete post-inventory stage-1 protection, sharing, `SIGBUS` tail arming,
/// and dispatcher VMA commit for an installed host alias mapping.
#[allow(clippy::too_many_arguments)]
pub fn finish_host_alias_stage1_install<E: ThreadedEngine>(
    engine: &mut E,
    dispatcher: &SyscallDispatcher,
    install: HostAliasInstallGuard<'_>,
    va: GuestVa,
    len: u64,
    prot: u64,
    prot_none: bool,
    shared: bool,
    success_retval: i64,
) -> Result<DispatchOutcome, AliasStage1InstallFailure> {
    use HvpatchAliasInstallSite as Site;

    let Ok(len_bytes) = usize::try_from(len) else {
        return Err(AliasStage1InstallFailure {
            site: Site::LenOverflow,
            message: "range length does not fit usize".to_owned(),
        });
    };
    // Backends publish aliases read-only or read/write and never executable;
    // `PROT_NONE` and `PROT_EXEC` are applied on stage-1 before the guest sees
    // the mapping.
    let prot_flags = LinuxProtFlags::from_bits_truncate(prot);
    let exec = prot_flags.contains(LinuxProtFlags::EXEC);
    if (prot_none || exec)
        && let Err(error) =
            engine.protect_range(va.raw(), len_bytes, if prot_none { 0 } else { prot })
    {
        return Err(AliasStage1InstallFailure {
            site: Site::ProtectNone,
            message: error.to_string(),
        });
    }
    engine.set_mapping_protection_and_sharing(
        va.raw(),
        len_bytes,
        prot_none,
        !prot_flags.contains(LinuxProtFlags::WRITE),
        if shared {
            MappingSharing::Shared
        } else {
            MappingSharing::Private
        },
    );
    if let Some((bus_start, bus_len)) = install.bus_fault_range() {
        let Ok(bus_len) = usize::try_from(bus_len) else {
            return Err(AliasStage1InstallFailure {
                site: Site::BusFaultLenOverflow,
                message: format!("bus-fault tail length {bus_len:#x} does not fit usize"),
            });
        };
        if let Err(error) = engine.protect_range(bus_start, bus_len, 0) {
            return Err(AliasStage1InstallFailure {
                site: Site::BusFaultProtect,
                message: format!("bus-fault tail {bus_start:#x}+{bus_len:#x}: {error}"),
            });
        }
        engine.set_no_access(bus_start, bus_len, true);
    }
    if let Err(error) = dispatcher.commit_host_alias_install(install) {
        return Err(AliasStage1InstallFailure {
            site: Site::DispatcherCommit,
            message: format!("{error:?}"),
        });
    }
    Ok(DispatchOutcome::Returned {
        value: success_retval,
    })
}

/// Reserve frame inventory, install a host alias through `engine`, apply its
/// [`FrameInventoryCommit`] to `context`'s kernel authority, and finish the
/// stage-1 protection/VMA commit under `dispatcher`'s MM mutation lease.
#[allow(clippy::too_many_arguments)]
pub fn install_host_alias_with_inventory<E: ThreadedEngine>(
    engine: &mut E,
    dispatcher: &mut SyscallDispatcher,
    context: &KernelContext,
    transaction: HostAliasTransaction,
    va: GuestVa,
    ipa: Gpa,
    len: u64,
    payload: &[u8],
    backing: HostAliasBacking,
    prot: u64,
    prot_none: bool,
    success_retval: i64,
) -> Result<i64, String> {
    let shared = backing.is_shared();
    dispatcher
        .with_mm_executor_mutation(|disp, mutation| -> Result<i64, String> {
            let permit = mutation.host_alias_permit();
            let Some(install) = transaction.claim(&permit) else {
                drop(backing);
                return Ok(LINUX_ENOMEM.guest_retval());
            };
            let capacity = FrameEventCapacity::for_event_count(2)
                .map_err(|e| format!("alias frame event capacity: {e}"))?;
            let reservation = context
                .kernel()
                .reserve_frame_inventory(1, 1, capacity)
                .map_err(|e| format!("reserve alias frame inventory: {e}"))?;
            let inventory_transaction = reservation.transaction();
            if let Err(error) = engine.begin_alias_inventory(reservation) {
                let _ = context
                    .kernel()
                    .frame_inventory()
                    .abandon(inventory_transaction);
                return Err(format!("begin_alias_inventory: {error}"));
            }
            if let Err(_error) = engine.map_host_alias(va, ipa, len, payload, backing) {
                engine.abandon_alias_inventory();
                let _ = context
                    .kernel()
                    .frame_inventory()
                    .abandon(inventory_transaction);
                drop(install);
                return Ok(LINUX_ENOMEM.guest_retval());
            }
            let Some(commit) = engine.take_alias_inventory() else {
                return Err("backend staged no alias inventory commit".to_owned());
            };
            apply_alias_frame_inventory(context, commit).map_err(|error| {
                format!(
                    "apply_alias_frame_inventory(frame={:?}): {error}",
                    error.frame()
                )
            })?;
            match finish_host_alias_stage1_install(
                engine,
                disp,
                install,
                va,
                len,
                prot,
                prot_none,
                shared,
                success_retval,
            ) {
                Ok(DispatchOutcome::Returned { value }) => Ok(value),
                Ok(other) => Err(format!("unexpected alias install outcome: {other:?}")),
                Err(failure) => Err(format!(
                    "alias stage-1 install failed at {:?}: {}",
                    failure.site, failure.message
                )),
            }
        })
        .map_err(|e| format!("MM executor mutation for MapHostAlias: {e}"))?
}

/// Apply Linux stage-1 first-touch permission rules: any accessible leaf in
/// Carrick's lowering satisfies a read fault; write and execute require their
/// respective permission bits.
pub fn apply_first_touch(
    prot: u64,
    access: Option<LeafAccess>,
    protect: impl FnOnce() -> bool,
    commit: impl FnOnce(),
) -> Option<bool> {
    let required = match access {
        Some(LeafAccess::Read) => LINUX_PROT_READ | LINUX_PROT_WRITE | LINUX_PROT_EXEC,
        Some(LeafAccess::Write) => LINUX_PROT_WRITE,
        Some(LeafAccess::Execute) => LINUX_PROT_EXEC,
        None => return Some(false),
    };
    if prot & required == 0 {
        return Some(false);
    }
    if !protect() {
        return None;
    }
    commit();
    Some(true)
}

/// Resident-fault sub-step result inside [`HostFirstTouchStep`].
#[derive(Debug)]
pub enum HostResidentAttempt {
    NotReached,
    NoPlan,
    Committed,
    ArmingDenied,
    BackendRefused {
        page: u64,
        prot: u64,
        error: MemoryError,
    },
}

/// `MAP_GROWSDOWN` sub-step result inside [`HostFirstTouchStep`].
#[derive(Debug)]
pub enum HostGrowdownAttempt {
    NotReached,
    NoPlan,
    Committed,
    ProtectFailed { start: u64, error: MemoryError },
}

/// Stale stage-1 leaf retry sub-step result inside [`HostFirstTouchStep`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostStaleAttempt {
    NotReached,
    AccessUnknown,
    Retried,
    NotRetried,
}

/// Combined outcome of one host first-touch + `MAP_GROWSDOWN` + stale-stage-1
/// fault-resolution attempt under an outer [`MmMutationGuard`].
#[derive(Debug)]
pub struct HostFirstTouchStep {
    pub resolved: bool,
    pub resident: HostResidentAttempt,
    pub growdown: HostGrowdownAttempt,
    pub stale: HostStaleAttempt,
}

/// Run one host-side resident first-touch, `MAP_GROWSDOWN`, and stale-stage-1
/// leaf retry pass under `mutation`. Returns `Ok(Err(busy))` on
/// [`ReservationBusy`] so the caller releases `mutation`, enrols on the
/// holder's release, probes once, and reruns.
pub fn resolve_host_first_touch_or_stale<E: ThreadedEngine>(
    dispatcher: &SyscallDispatcher,
    engine: &mut E,
    mutation: &MmMutationGuard<'_>,
    address: u64,
    access: Option<LeafAccess>,
    fault_kind: Option<Stage1FaultKind>,
) -> Result<Result<HostFirstTouchStep, ReservationBusy>, TrapError> {
    let mut step = HostFirstTouchStep {
        resolved: false,
        resident: HostResidentAttempt::NotReached,
        growdown: HostGrowdownAttempt::NotReached,
        stale: HostStaleAttempt::NotReached,
    };

    {
        let permit = mutation.host_alias_permit();
        let plan = match dispatcher.resident_fault_plan(&permit, address) {
            Ok(plan) => plan,
            Err(busy) => return Ok(Err(busy)),
        };
        if let Some(plan) = plan {
            let page = plan.page();
            let prot = plan.prot();
            let mut backend_error = None;
            match apply_first_touch(
                prot,
                access,
                || match engine.protect_range(page, LINUX_PAGE_SIZE as usize, prot) {
                    Ok(()) => true,
                    Err(err) => {
                        backend_error = Some(err);
                        false
                    }
                },
                || dispatcher.commit_resident_fault(plan),
            ) {
                Some(true) => {
                    step.resolved = true;
                    step.resident = HostResidentAttempt::Committed;
                    return Ok(Ok(step));
                }
                Some(false) => {
                    step.resident = HostResidentAttempt::ArmingDenied;
                    return Ok(Ok(step));
                }
                None => {
                    step.resident = HostResidentAttempt::BackendRefused {
                        page,
                        prot,
                        error: backend_error.unwrap_or_else(|| {
                            MemoryError::HostMap("protect_range refused resident fault".to_owned())
                        }),
                    };
                }
            }
        } else {
            step.resident = HostResidentAttempt::NoPlan;
        }
    }

    {
        let permit = mutation.host_alias_permit();
        step.growdown = match dispatcher.mmap_growdown_fault_plan(&permit, address) {
            None => HostGrowdownAttempt::NoPlan,
            Some(plan) => {
                let start = plan.start();
                let len = plan.len();
                match engine.protect_range(start, len, LINUX_PROT_READ | LINUX_PROT_WRITE) {
                    Ok(()) => {
                        dispatcher.commit_mmap_growdown(plan);
                        step.resolved = true;
                        step.growdown = HostGrowdownAttempt::Committed;
                        return Ok(Ok(step));
                    }
                    Err(error) => HostGrowdownAttempt::ProtectFailed { start, error },
                }
            }
        };
    }

    let (Some(access), Some(fault_kind)) = (access, fault_kind) else {
        step.stale = HostStaleAttempt::AccessUnknown;
        return Ok(Ok(step));
    };
    let retried = engine.resolve_stale_stage1_fault(address, access, fault_kind)?;
    step.resolved = retried;
    step.stale = if retried {
        HostStaleAttempt::Retried
    } else {
        HostStaleAttempt::NotRetried
    };
    Ok(Ok(step))
}

/// Lock-free single-waiter handback wakeup slot for single-carrier host threads
/// parking on [`ZoneTables`] (`SpaceWaitCause::Reservations`).
pub struct SingleCarrierHandbackWait {
    waiter_thread: std::thread::Thread,
    expected_incarnation: AtomicU64,
    ready: AtomicBool,
}

impl SingleCarrierHandbackWait {
    /// Bind a wakeup slot to the calling carrier thread.
    #[must_use]
    pub fn for_current_thread() -> Self {
        Self {
            waiter_thread: std::thread::current(),
            expected_incarnation: AtomicU64::new(0),
            ready: AtomicBool::new(false),
        }
    }

    /// Build a [`HandbackPublisher`] that wakes this carrier thread when its
    /// parked `RecordRef` is handed back as [`HandbackEvent::Ready`].
    #[must_use]
    pub fn publisher(self: &Arc<Self>) -> HandbackPublisher {
        let slot = Arc::clone(self);
        Arc::new(move |event| {
            if let HandbackEvent::Ready(record) = event {
                slot.notify_ready(record);
            }
        })
    }

    /// Notify this slot if `record` matches the currently armed park incarnation.
    pub fn notify_ready(&self, record: RecordRef) {
        let expected = self.expected_incarnation.load(Ordering::Acquire);
        if expected != 0 && record.incarnation == expected {
            self.ready.store(true, Ordering::Release);
            self.waiter_thread.unpark();
        }
    }

    fn arm(&self, record: RecordRef) {
        self.ready.store(false, Ordering::Relaxed);
        self.expected_incarnation
            .store(record.incarnation, Ordering::Release);
    }

    fn disarm(&self) {
        self.expected_incarnation.store(0, Ordering::Release);
        self.ready.store(false, Ordering::Release);
    }

    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
}

/// Outcome of one [`wait_for_owner_memory_release_in_zone`] enrollment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerMemoryWaitStep {
    /// The holder had already released before or during enrollment's queue-locked
    /// probe-once check.
    ProbeOnceReady,
    /// Enrolled on `SpaceWaitCause::Reservations`, parked until the holder's
    /// release handed back the zone record, and retired the record.
    ParkedAndWoken,
}

/// Authenticate `wait` against `(zone, portal)`, enrol on the holder's release
/// (`PortalWaitEnrollment::park_host`, which probes the space notification
/// revision once under the queue lock), and sleep via `std::thread::park()`
/// until `complete_wake` publishes readiness.
pub fn wait_for_owner_memory_release_in_zone(
    zone: &ZoneTables,
    portal: &MmPortalSlots,
    context: &KernelContext,
    wait: PortalOwnerWait,
    wake_slot: &SingleCarrierHandbackWait,
    complete_wake: &impl Fn(&ZoneTables, OwnedObjectWakeEffects<'_, Aarch64ParkedContext>),
) -> Result<OwnerMemoryWaitStep, String> {
    let enrollment = match portal.authenticate_wait(zone, wait) {
        Ok(enrollment) => enrollment,
        Err(ObjectWaitError::Stale) => return Ok(OwnerMemoryWaitStep::ProbeOnceReady),
        Err(error) => {
            return Err(format!("owner wait receipt rejected: {error:?}"));
        }
    };
    let serial = context.thread().key().serial.raw();
    let token = OperationToken::metadata_request(serial)
        .ok_or_else(|| "owner wait thread serial is zero".to_owned())?;
    let identity = ThreadIdentity {
        tid: El1TaskId::from_linux_tid(context.thread().key().tid.raw()).raw(),
        serial,
        mm: wait.handle().mm().raw(),
        file_table: context.resources().files().id().raw(),
        generation: 0,
        affinity_source: context.thread().control_slot().affinity_source(),
        affinity: context.thread().affinity().words()[0],
        lifecycle_page: 0,
        control_slot: 0,
    };
    let record = zone
        .alloc_record(identity)
        .map_err(|error| format!("owner wait record unavailable: {error:?}"))?;
    let record_ref = zone.record_ref(record);
    wake_slot.arm(record_ref);
    let complete = |effects: OwnedObjectWakeEffects<'_, Aarch64ParkedContext>| {
        complete_wake(zone, effects);
    };
    match enrollment.park_host(record, token, &complete) {
        Ok(()) => {
            zone.counters.host_parks.fetch_add(1, Ordering::Relaxed);
            while !wake_slot.is_ready() && zone.host_resume_readiness(record_ref) != Some(true) {
                std::thread::park();
            }
            wake_slot.disarm();
            zone.free_record(record);
            Ok(OwnerMemoryWaitStep::ParkedAndWoken)
        }
        Err((ObjectWaitError::Stale, _)) => {
            wake_slot.disarm();
            let _ = zone.claim_for_host(
                record_ref,
                None,
                carrick_el1_abi::Handback::Cancelled,
                &HostLockWait,
                &|owned| complete_wake(owned.zone(), owned),
            );
            zone.free_record(record);
            Ok(OwnerMemoryWaitStep::ProbeOnceReady)
        }
        Err((error, _)) => {
            wake_slot.disarm();
            let _ = zone.claim_for_host(
                record_ref,
                None,
                carrick_el1_abi::Handback::Cancelled,
                &HostLockWait,
                &|owned| complete_wake(owned.zone(), owned),
            );
            zone.free_record(record);
            Err(format!("owner wait park_host failed: {error:?}"))
        }
    }
}

/// Enrol on the published EL1 aperture's `ZoneTables` + `MmPortalSlots` for
/// `wait` and park until the reservation holder releases.
pub fn wait_for_owner_memory_release(
    context: &KernelContext,
    wait: PortalOwnerWait,
    wake_slot: &SingleCarrierHandbackWait,
) -> Result<OwnerMemoryWaitStep, String> {
    let region = carrick_el1_abi::get_el1_region_host_ptr();
    let Some(zone) = carrick_el1_abi::zone_tables() else {
        return Err("owner memory wait has no published EL1 ZoneTables".to_owned());
    };
    if region == 0
        || region.checked_add(carrick_el1_abi::EL1_ZONE_OFFSET as usize)
            != Some(core::ptr::from_ref(zone) as usize)
    {
        return Err("owner memory wait EL1 region does not match ZoneTables".to_owned());
    }
    let portal_addr = region
        .checked_add(carrick_el1_abi::EL1_MM_PORTAL_OFFSET as usize)
        .ok_or_else(|| "owner memory wait EL1 portal offset overflow".to_owned())?;
    // SAFETY: `zone_tables()` validated the live EL1 region mapping, and
    // `EL1_MM_PORTAL_OFFSET` lies inside that same fixed ABI region.
    let portal = unsafe { &*(portal_addr as *const MmPortalSlots) };
    wait_for_owner_memory_release_in_zone(zone, portal, context, wait, wake_slot, &|z, effects| {
        carrick_sched_core::LockWait::complete_object_wake(&HostLockWait, z, effects);
    })
}

/// Resolve a synchronous EL0 fault on a single-carrier engine using shared
/// [`resolve_host_first_touch_or_stale`]; on [`ReservationBusy`], drops the MM
/// mutation lease, enrols on the holder's release via
/// [`wait_for_owner_memory_release`], probes once, and reruns without polling.
pub fn resolve_host_first_touch_with_owner_wait<E: ThreadedEngine>(
    engine: &mut E,
    dispatcher: &mut SyscallDispatcher,
    context: &KernelContext,
    wake_slot: &SingleCarrierHandbackWait,
    address: u64,
    access: Option<LeafAccess>,
    fault_kind: Option<Stage1FaultKind>,
) -> Result<(bool, u64), String> {
    let mut owner_waits = 0u64;
    loop {
        let outcome = dispatcher
            .with_mm_executor_mutation(|disp, mutation| {
                resolve_host_first_touch_or_stale(
                    disp, engine, mutation, address, access, fault_kind,
                )
            })
            .map_err(|e| format!("MM executor mutation for first-touch fault: {e}"))?
            .map_err(|e| format!("first-touch fault resolution trap error: {e}"))?;
        match outcome {
            Ok(HostFirstTouchStep {
                resident:
                    HostResidentAttempt::BackendRefused {
                        page, prot, error, ..
                    },
                resolved: false,
                ..
            }) => {
                return Err(format!(
                    "first-touch protect_range({page:#x}, prot={prot:#x}): {error}"
                ));
            }
            Ok(HostFirstTouchStep {
                growdown: HostGrowdownAttempt::ProtectFailed { start, error },
                resolved: false,
                ..
            }) => {
                return Err(format!("growdown protect_range({start:#x}): {error}"));
            }
            Ok(step) => return Ok((step.resolved, owner_waits)),
            Err(contended) => {
                // MM mutation lease was dropped on return from `with_mm_executor_mutation`;
                // enrol on the holder's release, probe once, and rerun.
                wait_for_owner_memory_release(context, contended.wait, wake_slot)?;
                owner_waits += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::NonZeroU64;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn apply_first_touch_enforces_linux_stage1_access_matrix() {
        let mut committed = false;
        assert_eq!(
            apply_first_touch(
                LINUX_PROT_WRITE,
                Some(LeafAccess::Read),
                || true,
                || committed = true
            ),
            Some(true)
        );
        assert!(committed);

        assert_eq!(
            apply_first_touch(LINUX_PROT_READ, Some(LeafAccess::Write), || true, || {}),
            Some(false)
        );
        assert_eq!(
            apply_first_touch(
                LINUX_PROT_READ | LINUX_PROT_WRITE,
                Some(LeafAccess::Execute),
                || true,
                || {}
            ),
            Some(false)
        );
        assert_eq!(
            apply_first_touch(LINUX_PROT_READ, None, || true, || {}),
            Some(false)
        );
        assert_eq!(
            apply_first_touch(LINUX_PROT_WRITE, Some(LeafAccess::Write), || false, || {}),
            None
        );
    }

    #[test]
    fn owner_memory_wait_parks_once_on_reservation_busy_and_resumes_after_release() {
        use carrick_el1::memory::reservations::{
            Layout, NoRootWait, Refusal, RootReleaseVenue, SharedReservations,
        };
        use carrick_el1_abi::{
            El1MmHandle, PortalOwnerWait, PortalWaitCause, ReservationMm, ReservationRange,
        };
        use carrick_sched_core::spaces::notification::{
            SpaceReleaseVenue, SpaceWaitCause, SpaceWakeDelivery,
        };

        let dispatcher = SyscallDispatcher::new();
        let ctx = dispatcher.capture_one_task_context().unwrap();
        let region = carrick_test_support::TestEl1Region::zeroed();
        let region_ptr = region.as_ptr();
        let carrier_id = NonZeroU64::new(region_ptr as u64).unwrap();
        // SAFETY: `region` owns a full aligned `TestEl1Region` for this test.
        let zone = unsafe {
            &*region_ptr
                .add(carrick_el1_abi::EL1_ZONE_OFFSET as usize)
                .cast::<ZoneTables>()
        };
        // SAFETY: `EL1_MM_PORTAL_OFFSET` is aligned inside `TestEl1Region`.
        let portal = unsafe {
            &*region_ptr
                .add(carrick_el1_abi::EL1_MM_PORTAL_OFFSET as usize)
                .cast::<MmPortalSlots>()
        };
        // SAFETY: `EL1_RESERVATIONS_OFFSET` is aligned inside `TestEl1Region`.
        let reservations = unsafe {
            &*region_ptr
                .add(carrick_el1_abi::EL1_RESERVATIONS_OFFSET as usize)
                .cast::<SharedReservations>()
        };
        assert!(portal.bind_carrier(carrier_id));

        let mm = ReservationMm::new(ctx.shared().mm().id().raw()).unwrap();
        let space_idx = zone
            .spaces
            .publish_closed(mm.raw(), 0x30000, 0x30000)
            .unwrap()
            .index();
        reservations
            .publish(
                space_idx,
                mm,
                Layout {
                    heap: ReservationRange::new(0x1000_0000, 0x2000_0000).unwrap(),
                    arena: ReservationRange::new(0x4000_0000, 0x8000_0000).unwrap(),
                    brk: 0x1000_0000,
                    address_limit: u64::MAX,
                    data_limit: u64::MAX,
                    external_address_bytes: 0,
                    external_data_bytes: 0,
                },
            )
            .unwrap();

        let observe_reservations_wait = || -> PortalOwnerWait {
            let source = zone
                .space_entry(NonZeroU64::new(mm.raw()).unwrap())
                .unwrap()
                .live_notifications()
                .unwrap();
            // SAFETY: `space_idx` was published above in `zone.spaces` for `(carrier_id, mm)`.
            let handle = unsafe {
                El1MmHandle::from_admitted_owner(carrier_id, mm, source.identity().incarnation)
            };
            // SAFETY: sampled from the live notification source before probing the root lock.
            unsafe {
                PortalOwnerWait::from_owner(
                    handle,
                    PortalWaitCause::Reservations,
                    source.observe(SpaceWaitCause::Reservations).revision(),
                )
            }
        };

        let wake_slot = Arc::new(SingleCarrierHandbackWait::for_current_thread());
        let wake_for_complete = Arc::clone(&wake_slot);
        let complete_wake =
            move |z: &ZoneTables, owned: OwnedObjectWakeEffects<'_, Aarch64ParkedContext>| {
                let (_waker, _effects) = owned.deliver_handbacks(&mut |record| {
                    z.counters.host_handbacks.fetch_add(1, Ordering::Relaxed);
                    wake_for_complete.notify_ready(record);
                });
            };

        let attempts = AtomicUsize::new(0);
        let (held_tx, held_rx) = std::sync::mpsc::sync_channel(1);
        std::thread::scope(|s| {
            let wake_for_holder = Arc::clone(&wake_slot);
            s.spawn(move || {
                let deliver =
                    |z: &ZoneTables,
                     _: carrick_sched_core::Waker,
                     owned: OwnedObjectWakeEffects<'_, Aarch64ParkedContext>| {
                        let (_waker, _effects) = owned.deliver_handbacks(&mut |record| {
                            z.counters.host_handbacks.fetch_add(1, Ordering::Relaxed);
                            wake_for_holder.notify_ready(record);
                        });
                    };
                let venue = RootReleaseVenue::new(
                    reservations,
                    SpaceReleaseVenue {
                        zone,
                        waker: carrick_sched_core::Waker::Host,
                        deliver: SpaceWakeDelivery::Captured(&deliver),
                    },
                )
                .unwrap();
                let held = venue.lock_el1(space_idx, mm, 3).unwrap();
                held_tx.send(()).unwrap();
                while zone.counters.host_parks.load(Ordering::Acquire) == 0 {
                    std::hint::spin_loop();
                }
                drop(held);
            });

            held_rx.recv().unwrap();
            let noop_deliver =
                |_: &ZoneTables,
                 _: carrick_sched_core::Waker,
                 _: OwnedObjectWakeEffects<'_, Aarch64ParkedContext>| {};
            let mut steps = Vec::new();
            loop {
                attempts.fetch_add(1, Ordering::Relaxed);
                let observed_wait = observe_reservations_wait();
                let venue = RootReleaseVenue::new(
                    reservations,
                    SpaceReleaseVenue {
                        zone,
                        waker: carrick_sched_core::Waker::Host,
                        deliver: SpaceWakeDelivery::Captured(&noop_deliver),
                    },
                )
                .unwrap();
                match venue.lock(space_idx, mm, &NoRootWait) {
                    Ok(_guard) => break,
                    Err(Refusal::Busy) => {
                        let step = wait_for_owner_memory_release_in_zone(
                            zone,
                            portal,
                            &ctx,
                            observed_wait,
                            &wake_slot,
                            &complete_wake,
                        )
                        .unwrap();
                        steps.push(step);
                    }
                    Err(other) => panic!("unexpected refusal: {other:?}"),
                }
            }
            assert_eq!(steps, vec![OwnerMemoryWaitStep::ParkedAndWoken]);
        });

        assert_eq!(
            attempts.load(Ordering::Relaxed),
            2,
            "Busy once, then success: expected exactly 2 attempts without polling"
        );
        assert_eq!(zone.counters.host_parks.load(Ordering::Relaxed), 1);
        assert_eq!(zone.counters.host_handbacks.load(Ordering::Relaxed), 1);
    }
}
