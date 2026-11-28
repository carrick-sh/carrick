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
use carrick_core::mm::frames::{
    PublicationCompletion, PublicationInvariant, PublicationNextAction, PublicationTerminal,
    SelectedBackingPlan, publication_next_action,
};
use carrick_el1_abi::{
    Aarch64ParkedContext, El1TaskId, MmPortalSlots, PortalOwnerWait, RecordRef, SlotId,
    ThreadIdentity, ZoneTables,
};
use carrick_guest_mem::{Gpa, GuestVa, MappingSharing, MemoryError};
use carrick_hal::{
    FrameEventCapacity, FrameInventoryCommit, HostAliasBacking, ThreadedEngine, TrapError,
};
use carrick_mmu_core::aarch64::{LeafAccess, Stage1FaultKind};
use carrick_sched_core::object_wait::{ObjectWaitError, OperationToken, OwnedObjectWakeEffects};

use crate::dispatch::host_alias::{HostAliasInstallGuard, HostAliasTransaction};
use crate::dispatch::mem::ReservationBusy;
use crate::dispatch::mem::fault::{PublishedFrameGrantRefusal, ResidentFrameGrantPlan};
use crate::dispatch::mm_mutation::{HostAliasPermit, MmMutationGuard};
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

/// Run a carrier's MM mutation as the task's `executor` when the carrier
/// holds it, else under a fresh exact-MM executor admission.
fn with_carrier_mutation<T>(
    dispatcher: &mut SyscallDispatcher,
    executor: Option<&mut crate::dispatch::MmExecutorParticipation>,
    run: impl FnOnce(
        &mut SyscallDispatcher,
        &mut crate::dispatch::mm_mutation::MmMutationGuard<'_>,
    ) -> T,
) -> Result<T, crate::dispatch::DispatchError> {
    match executor {
        Some(executor) => dispatcher.with_mm_executor_mutation_by(executor, run),
        None => dispatcher.with_mm_executor_mutation(run),
    }
}

/// Reserve frame inventory, install a host alias through `engine`, apply its
/// [`FrameInventoryCommit`] to `context`'s kernel authority, and finish the
/// stage-1 protection/VMA commit under `dispatcher`'s MM mutation lease, as
/// `executor` when the carrier holds the task's executor participation.
#[allow(clippy::too_many_arguments)]
pub fn install_host_alias_with_inventory<E: ThreadedEngine>(
    engine: &mut E,
    dispatcher: &mut SyscallDispatcher,
    executor: Option<&mut crate::dispatch::MmExecutorParticipation>,
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
    with_carrier_mutation(
        dispatcher,
        executor,
        |disp, mutation| -> Result<i64, String> {
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
        },
    )
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

/// The carrier's next step for an EL1 frame-grant publication that was
/// declined after its prepared backing was rolled back. The shared
/// publication policy chooses the action; this step performs its mailbox and
/// release-source effects so the HVF fault handler only reruns, parks or
/// returns.
pub enum DeclinedFrameGrantStep<'permit> {
    /// The MM editor is held: the claim is released, and the fault parks on
    /// this release source before it reruns.
    ParkOnMmRelease(PortalOwnerWait),
    /// Capacity: prepare and publish again, under the same claim, with this
    /// strictly smaller plan.
    RerunWith {
        plan: Box<ResidentFrameGrantPlan<'permit>>,
        selected: SelectedBackingPlan,
    },
    /// The fault page already holds an (inherited) output: the claim is
    /// released and the faulting instruction reruns against the live image.
    Replan,
    /// A deterministic refusal: EL1 consumes the denial and forwards the
    /// fault.
    Refused(PublicationTerminal),
}

/// A declined publication that broke the mailbox or plan invariants. Each
/// is carrier-fatal: no rerun can repair it.
#[derive(Debug, PartialEq, Eq)]
pub enum DeclinedFrameGrantFatal {
    Invariant(PublicationInvariant),
    PublishedAction,
    MmIdentity,
    ClaimLost,
    ReleaseSource(carrick_el1::memory::reservations::Refusal),
    PlanConsumed,
    Narrow(PublishedFrameGrantRefusal),
    RefusalNotPublished,
}

/// Take the shared publication policy's next action for a declined frame
/// grant whose claim `request` this carrier still holds on `mailbox`.
/// `plan` is the unsettled plan the declined attempt published from.
pub fn settle_declined_frame_grant<'permit>(
    dispatcher: &SyscallDispatcher,
    permit: &HostAliasPermit<'_>,
    mailbox: &carrick_el1_abi::FrameGrantMailbox,
    request: carrick_el1_abi::FrameGrantRequest,
    completion: PublicationCompletion,
    selected: SelectedBackingPlan,
    plan: Option<ResidentFrameGrantPlan<'permit>>,
) -> Result<DeclinedFrameGrantStep<'permit>, DeclinedFrameGrantFatal> {
    match publication_next_action(completion, selected, request.mm_key) {
        PublicationNextAction::Published => Err(DeclinedFrameGrantFatal::PublishedAction),
        PublicationNextAction::Fatal(invariant) => {
            Err(DeclinedFrameGrantFatal::Invariant(invariant))
        }
        PublicationNextAction::ParkOnMmRelease { mm_key } => {
            if mm_key != request.mm_key {
                return Err(DeclinedFrameGrantFatal::MmIdentity);
            }
            if !mailbox.release_declined_publication(request) {
                return Err(DeclinedFrameGrantFatal::ClaimLost);
            }
            dispatcher
                .frame_grant_release_wait(permit)
                .map(DeclinedFrameGrantStep::ParkOnMmRelease)
                .map_err(DeclinedFrameGrantFatal::ReleaseSource)
        }
        PublicationNextAction::RerunWith(fallback) => {
            let plan = plan
                .ok_or(DeclinedFrameGrantFatal::PlanConsumed)?
                .narrow_to(fallback)
                .map_err(DeclinedFrameGrantFatal::Narrow)?;
            Ok(DeclinedFrameGrantStep::RerunWith {
                plan: Box::new(plan),
                selected: fallback,
            })
        }
        PublicationNextAction::ReplanInheritedPrepared => {
            if !mailbox.release_declined_publication(request) {
                return Err(DeclinedFrameGrantFatal::ClaimLost);
            }
            Ok(DeclinedFrameGrantStep::Replan)
        }
        PublicationNextAction::TerminalRefusal(terminal) => {
            if !mailbox.publish_refusal(carrick_el1_abi::FRAME_GRANT_ERR_DENIED) {
                return Err(DeclinedFrameGrantFatal::RefusalNotPublished);
            }
            Ok(DeclinedFrameGrantStep::Refused(terminal))
        }
    }
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

    /// A witness's watchdog: release a parked waiter whose wake never came,
    /// so a broken wake fails the witness instead of hanging its partition.
    /// The caller records the miss ([`MissedWake`]) and must fail on it.
    #[cfg(test)]
    pub(crate) fn release_missed_wake_for_test(&self) -> MissedWake {
        self.ready.store(true, Ordering::Release);
        self.waiter_thread.unpark();
        MissedWake(())
    }
}

/// Proof that a witness's watchdog, not the production wake, released a
/// parked waiter. Only [`SingleCarrierHandbackWait::release_missed_wake_for_test`]
/// mints it.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MissedWake(());

/// Outcome of one [`wait_for_owner_memory_release`] enrollment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerMemoryWaitStep {
    /// The holder had already released before or during enrollment's
    /// queue-locked probe-once check.
    ProbeOnceReady,
    /// Enrolled on `SpaceWaitCause::Reservations`, parked until the holder's
    /// release handed back the zone record, and retired the record.
    ParkedAndWoken,
}

/// The carrier zone and MM portal an owner-memory wait enrols on.
#[derive(Clone, Copy)]
pub struct OwnerWaitVenue<'a> {
    zone: &'a ZoneTables,
    portal: &'a MmPortalSlots,
}

impl<'a> OwnerWaitVenue<'a> {
    /// A venue over one carrier's co-located zone tables and MM portal;
    /// `MmPortalSlots::authenticate_wait` checks the pair's relation.
    #[must_use]
    pub fn new(zone: &'a ZoneTables, portal: &'a MmPortalSlots) -> Self {
        Self { zone, portal }
    }
}

impl OwnerWaitVenue<'static> {
    /// The venue of the published EL1 aperture
    /// (`carrick_el1_abi::record_el1_region_host_ptr`).
    pub fn published() -> Result<Self, String> {
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
        // `EL1_MM_PORTAL_OFFSET` lies inside that same fixed ABI region, which
        // stays mapped while its aperture is published.
        let portal = unsafe { &*(portal_addr as *const MmPortalSlots) };
        Ok(Self { zone, portal })
    }
}

/// Authenticate `wait` against `venue`, enrol on the holder's release
/// (`PortalWaitEnrollment::park_host`, which probes the space notification
/// revision once under the queue lock), and park this carrier thread until
/// the release hands its zone record back through the registered
/// [`HandbackPublisher`] (`wake_slot`). Never polls.
pub fn wait_for_owner_memory_release(
    venue: OwnerWaitVenue<'_>,
    context: &KernelContext,
    wait: PortalOwnerWait,
    wake_slot: &SingleCarrierHandbackWait,
) -> Result<OwnerMemoryWaitStep, String> {
    let OwnerWaitVenue { zone, portal } = venue;
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
        carrick_sched_core::LockWait::complete_object_wake(&HostLockWait, zone, effects);
    };
    let cancel = |zone: &ZoneTables| {
        wake_slot.disarm();
        let _ = zone.claim_for_host(
            record_ref,
            None,
            carrick_el1_abi::Handback::Cancelled,
            &HostLockWait,
            &|owned| {
                carrick_sched_core::LockWait::complete_object_wake(
                    &HostLockWait,
                    owned.zone(),
                    owned,
                );
            },
        );
        zone.free_record(record);
    };
    match enrollment.park_host(record, token, &complete) {
        Ok(()) => {
            zone.counters.host_parks.fetch_add(1, Ordering::Relaxed);
            // `park` may return spuriously; the handback (or the zone's own
            // readiness) is the only wake condition.
            while !wake_slot.is_ready() && zone.host_resume_readiness(record_ref) != Some(true) {
                std::thread::park();
            }
            wake_slot.disarm();
            zone.free_record(record);
            Ok(OwnerMemoryWaitStep::ParkedAndWoken)
        }
        Err((ObjectWaitError::Stale, _)) => {
            cancel(zone);
            Ok(OwnerMemoryWaitStep::ProbeOnceReady)
        }
        Err((error, _)) => {
            cancel(zone);
            Err(format!("owner wait park_host failed: {error:?}"))
        }
    }
}

/// The single-carrier "not now" driver: run `attempt`; on
/// [`ReservationBusy`] (whose MM mutation lease `attempt` has already
/// released) enrol on the holder's release at `venue`, probe once, and rerun.
/// Returns the attempt's result and how many owner waits it took.
pub fn rerun_after_owner_release<'v, T>(
    context: &KernelContext,
    wake_slot: &SingleCarrierHandbackWait,
    venue: impl Fn() -> Result<OwnerWaitVenue<'v>, String>,
    mut attempt: impl FnMut() -> Result<Result<T, ReservationBusy>, String>,
) -> Result<(T, u64), String> {
    let mut owner_waits = 0u64;
    loop {
        match attempt()? {
            Ok(done) => return Ok((done, owner_waits)),
            Err(contended) => {
                wait_for_owner_memory_release(venue()?, context, contended.wait, wake_slot)?;
                owner_waits += 1;
            }
        }
    }
}

/// Resolve a synchronous EL0 fault on a single-carrier engine with
/// [`resolve_host_first_touch_or_stale`], rerunning through
/// [`rerun_after_owner_release`] at the published EL1 aperture on
/// [`ReservationBusy`]. Returns whether the fault was resolved and how many
/// owner waits it took.
#[allow(clippy::too_many_arguments)]
pub fn resolve_host_first_touch_with_owner_wait<E: ThreadedEngine>(
    engine: &mut E,
    dispatcher: &mut SyscallDispatcher,
    mut executor: Option<&mut crate::dispatch::MmExecutorParticipation>,
    context: &KernelContext,
    wake_slot: &SingleCarrierHandbackWait,
    address: u64,
    access: Option<LeafAccess>,
    fault_kind: Option<Stage1FaultKind>,
) -> Result<(bool, u64), String> {
    let (step, owner_waits) =
        rerun_after_owner_release(context, wake_slot, OwnerWaitVenue::published, || {
            with_carrier_mutation(dispatcher, executor.as_deref_mut(), |disp, mutation| {
                resolve_host_first_touch_or_stale(
                    disp, engine, mutation, address, access, fault_kind,
                )
            })
            .map_err(|e| format!("MM executor mutation for first-touch fault: {e}"))?
            .map_err(|e| format!("first-touch fault resolution trap error: {e}"))
        })?;
    match step {
        HostFirstTouchStep {
            resident:
                HostResidentAttempt::BackendRefused {
                    page, prot, error, ..
                },
            resolved: false,
            ..
        } => Err(format!(
            "first-touch protect_range({page:#x}, prot={prot:#x}): {error}"
        )),
        HostFirstTouchStep {
            growdown: HostGrowdownAttempt::ProtectFailed { start, error },
            resolved: false,
            ..
        } => Err(format!("growdown protect_range({start:#x}): {error}")),
        step => Ok((step.resolved, owner_waits)),
    }
}

/// Occupy the executor's vCPU slot with the task's MM, then publish the
/// vCPU registration. The occupancy comes first so a pause of the MM can
/// see the vCPU before the registration lets it run.
pub fn enter_mm_executor_then_register<F>(
    dispatcher: &SyscallDispatcher,
    thread: Option<crate::kernel::ThreadRef>,
    registry: Arc<dyn carrick_hal::VcpuRegistry>,
    tid: carrick_hal::ThreadId,
    slot: crate::kernel::ExecutionSlot,
    register: F,
) -> Result<
    (
        crate::dispatch::MmExecutorParticipation,
        carrick_hal::VcpuRegistrationEnrollment,
    ),
    crate::kernel::MmOccupancyError,
>
where
    F: FnOnce() -> carrick_hal::VcpuRegistrationEnrollment,
{
    let participation = dispatcher.enter_mm_executor_for_thread(thread, registry, tid, slot)?;
    let enrollment = register();
    Ok((participation, enrollment))
}

/// The operator's choice for the guest descriptor lane, read once per carrier.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
enum DescriptorLaneHatch {
    /// The lane is admitted wherever the writer census admits it.
    Default,
    /// `CARRICK_EL1_DESCRIPTOR_LANE=0`: every MM stays on the host-owned
    /// lane, whatever the census says.
    Disabled,
}

impl DescriptorLaneHatch {
    /// Parse `CARRICK_EL1_DESCRIPTOR_LANE`: exactly `0` (trimmed) disables.
    fn from_env_value(value: Option<&str>) -> Self {
        match value {
            Some(value) if value.trim() == "0" => Self::Disabled,
            _ => Self::Default,
        }
    }

    /// This carrier's hatch.
    fn current() -> Self {
        static HATCH: std::sync::OnceLock<DescriptorLaneHatch> = std::sync::OnceLock::new();
        *HATCH.get_or_init(|| {
            Self::from_env_value(
                ::std::env::var("CARRICK_EL1_DESCRIPTOR_LANE")
                    .ok()
                    .as_deref(),
            )
        })
    }
}

/// Every host writer family that still stores live stage-1 descriptors. The
/// guest-owned lane is admitted for an MM only when every one of them submits
/// descriptor transactions instead; a single unconverted writer would be
/// refused on that lane and turn an ordinary host edit into a guest fault.
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::PartialEq,
    ::core::cmp::Eq,
)]
struct GuestDescriptorLanePrecondition {
    /// The descriptor transaction slots are placed in the installed EL1 region.
    slots_placed: bool,
    /// Bulk first-touch frame grants (this path).
    frame_grants: bool,
    /// Host syscall copyout into prepared pages (`commit_prepared_host_write`).
    host_copyout: bool,
    /// Fork parent COW arming (`build_process_spec`): built as EL1
    /// transactions, applied synchronously on the forking vCPU through the
    /// host-driven drain call and settled before the fork commits
    /// (`apply_guest_fork_arm`); EL1 drains an MM's submissions before any of
    /// its threads returns to EL0.
    fork_parent_arming: bool,
    /// Backend COW, sparse/foreign materialization and exec publication.
    backend_writers: bool,
}

impl GuestDescriptorLanePrecondition {
    /// The writer census of this build. Host copyout publishes through the
    /// verified EL1 Publish/Write receipt before the kernel commits residency
    /// (`commit_prepared_host_write` -> `publish_copyout`). Every backend
    /// writer family submits descriptor transactions on the guest lane: the
    /// shared terminal rule (mprotect, munmap retirement, retired reset, BUS
    /// tags, fork arming), table reclaim receipts, alias maps, retained
    /// reuse, sparse/file materialization, frame-grant replacement and
    /// foreign-MM COW; exec publishes an offline image before the new MM
    /// selects its lane.
    fn current() -> Self {
        Self {
            slots_placed: carrick_el1_abi::descriptor_txn_slots_host().is_some(),
            frame_grants: true,
            host_copyout: true,
            fork_parent_arming: true,
            backend_writers: true,
        }
    }

    fn admits(self) -> bool {
        self.slots_placed
            && self.frame_grants
            && self.host_copyout
            && self.fork_parent_arming
            && self.backend_writers
    }

    /// Whether an MM may select the guest lane under `hatch`. The operator
    /// hatch is its own reason, never folded into a census field.
    fn admission(
        self,
        hatch: DescriptorLaneHatch,
    ) -> Result<(), carrick_mmu_core::aarch64::GuestLaneRefusal> {
        use carrick_mmu_core::aarch64::GuestLaneRefusal;
        if hatch == DescriptorLaneHatch::Disabled {
            return Err(GuestLaneRefusal::OperatorHatch);
        }
        if !self.admits() {
            return Err(GuestLaneRefusal::Census);
        }
        Ok(())
    }
}

/// Publish a first load's closed address space from the root its stage-1
/// lease names, and open it. `None` declines publication (the engine's
/// switchable roots are absent or are not the leased root, or the
/// dispatcher refused the exact BIND); the MM then stays host-installed.
/// An `Err` is an owner-admission failure after the BIND was published.
pub fn publish_leased_first_address_space<E: ThreadedEngine>(
    dispatcher: &SyscallDispatcher,
    participation: &mut crate::dispatch::MmExecutorParticipation,
    engine: &mut E,
    lease_ttbr0: u64,
) -> Result<Option<crate::kernel::AddressSpacePublication>, TrapError> {
    let asid = lease_ttbr0 >> 48;
    carrick_observability::probes::hvpatch_el1_root_candidate(asid, 1, lease_ttbr0, 0);
    let Some((ttbr0, ttbr1)) = engine.el1_switchable_roots() else {
        carrick_observability::probes::hvpatch_el1_root_candidate(asid, 2, lease_ttbr0, 0);
        return Ok(None);
    };
    if ttbr0 != lease_ttbr0 {
        carrick_observability::probes::hvpatch_el1_root_candidate(asid, 3, ttbr0, ttbr1);
        return Ok(None);
    }
    let Some(closed) =
        dispatcher.publish_bound_address_space(participation, &mut *engine, ttbr0, ttbr1)
    else {
        carrick_observability::probes::hvpatch_el1_root_candidate(asid, 4, ttbr0, ttbr1);
        return Ok(None);
    };
    let publication = open_first_address_space(engine, closed)?;
    carrick_observability::probes::hvpatch_el1_root_candidate(asid, 5, ttbr0, ttbr1);
    Ok(Some(publication))
}

/// Finish the first-load publication while its root is still closed. Exact
/// reservation import and legacy root-fact release ran before this call;
/// the owner guard excludes host copies from BIND through descriptor/venue
/// selection and the final EL1 installation-gate opening.
pub fn open_first_address_space<E: ThreadedEngine>(
    engine: &mut E,
    closed: crate::kernel::UnpublishedInitialAddressSpace,
) -> Result<crate::kernel::AddressSpacePublication, TrapError> {
    use carrick_mmu_core::aarch64::LiveDescriptorOwner;
    carrick_observability::probes::hvpatch_el1_owner_selection(0);
    if engine.live_descriptor_owner() != LiveDescriptorOwner::Guest {
        if let Err(reason) =
            GuestDescriptorLanePrecondition::current().admission(DescriptorLaneHatch::current())
        {
            carrick_observability::probes::hvpatch_el1_owner_selection(1);
            engine.record_guest_descriptor_lane_refusal(reason);
            return Ok(closed.open_legacy());
        }
    }
    let Some(authority) = engine.user_memory_admission_authority() else {
        carrick_observability::probes::hvpatch_el1_owner_selection(2);
        return Ok(closed.open_legacy());
    };
    let carrier = engine.owner_transfer_carrier().ok_or_else(|| {
        carrick_observability::probes::hvpatch_el1_owner_selection(3);
        TrapError::Hypervisor("admitted user-memory backend lost its transfer carrier".into())
    })?;
    let token = closed.bind_token(carrier).ok_or_else(|| {
        carrick_observability::probes::hvpatch_el1_owner_selection(4);
        TrapError::Hypervisor("first-load root is not an exact closed BIND publication".into())
    })?;
    let mut guard = authority.begin_selection().map_err(|reason| {
        TrapError::Hypervisor(format!(
            "first-load user-memory admission guard refused: {reason:?}"
        ))
    })?;
    carrick_observability::probes::hvpatch_el1_owner_selection(5);
    let selected = engine.select_live_descriptor_owner_under_guard(
        LiveDescriptorOwner::Guest,
        &mut guard,
        Some(token),
    )?;
    carrick_observability::probes::hvpatch_el1_owner_selection(6);
    if !selected || guard.selection_handle().is_none() {
        carrick_observability::probes::hvpatch_el1_owner_selection(8);
        return Err(TrapError::Hypervisor(
            "first-load owner failed to select immediate live backing".into(),
        ));
    }
    carrick_observability::probes::hvpatch_el1_owner_selection(7);
    closed
        .open_admitted(&guard)
        .map_err(|_| TrapError::Hypervisor("first-load owner guard selected another MM".into()))
}

/// Enter and leave the zone around a carrier executor's run of its vCPU on
/// `slot`, including entries following a host-served syscall. While the
/// slot is in the guest, a host claim of a thread EL1 holds there kicks it.
pub fn run_guest<R>(
    thread: Option<&crate::kernel::Thread>,
    zone_slot: Option<(&ZoneTables, SlotId)>,
    run: impl FnOnce() -> R,
) -> R {
    if let Some((zone, slot)) = zone_slot {
        if let Some(thread) = thread {
            zone.bind_slot_affinity(slot, thread.control_slot().affinity_source());
        }
        zone.enter_guest(slot);
    }
    let result = run();
    if let Some((zone, slot)) = zone_slot {
        zone.leave_guest(slot, &crate::el1_zone::HostLockWait);
    }
    result
}

/// What an executor's stopped slot holds for it at an exit, once
/// [`settle_zone_exit`] settled the slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ZoneExitSettlement {
    /// EL1 switched the executor's own thread back in and it simply runs
    /// again: its record is retired, and the exit is the thread's.
    Released,
    /// The own thread was switched in at the SVC of its pending object
    /// operation, which never re-executed (EL1 left with host work after the
    /// switch, or a kick stopped it at EL0): its record `own` is back at the
    /// head of the run queue. The thread settles into its zone wait on it,
    /// exactly as a thread EL1 parked or preempted; its next load resumes
    /// the operation, and this exit (no call of the thread's) is abandoned.
    Requeued { own: carrick_sched_core::RecordId },
    /// Anything else: the switched-in record and the slot's own (host)
    /// record, for the executor to settle.
    Held {
        current: Option<carrick_sched_core::RecordId>,
        own: Option<carrick_sched_core::RecordId>,
    },
}

/// Settle what EL1 did on `slot` since its executor last ran it, before
/// anything uses the exit: complete the detached wake claims EL1
/// transferred, sweep cancelled records, hand back what the host wants, and
/// move another thread's timed park on this slot's timer to the host
/// (nothing serves the timer until the vCPU returns). Nothing of the
/// executor's own thread stays switched in on the slot past this boundary.
pub fn settle_zone_exit(zone: &ZoneTables, slot: SlotId) -> ZoneExitSettlement {
    crate::el1_zone::hand_back_completions();
    zone.sweep_cancelled(slot);
    crate::el1_zone::hand_back_wanted(slot);
    crate::el1_zone::hand_back_foreign_timer(slot);
    let s = zone.slot(slot);
    let (current, own) = (s.current(), s.host_record());
    if let (Some(switched), Some(own)) = (current, own)
        && switched == own
    {
        return match zone.release_current(slot, own, &crate::el1_zone::HostLockWait) {
            carrick_sched_core::CurrentRelease::Released => ZoneExitSettlement::Released,
            carrick_sched_core::CurrentRelease::Requeued => ZoneExitSettlement::Requeued { own },
        };
    }
    ZoneExitSettlement::Held { current, own }
}

/// The zone's driver identity of an executor. Never 0, which means none.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ZoneSlotDriver(std::num::NonZeroU64);

impl ZoneSlotDriver {
    pub const fn new(raw: std::num::NonZeroU64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0.get()
    }
}

/// The task a stopped vCPU slot is about to run: its slot, its executor's
/// driver identity and guest-CPU binding, the loaded thread's MM and
/// serial, and its affinity source.
#[derive(Clone, Copy, Debug)]
pub struct StoppedSlotLoad {
    pub slot: SlotId,
    pub driver: ZoneSlotDriver,
    pub mm: crate::kernel::MmId,
    pub serial: crate::kernel::ThreadSerial,
    /// The guest CPU the slot's executor is bound to. `None`: any.
    pub bound_cpu: Option<carrick_hal::GuestCpuId>,
    pub affinity: carrick_sched_core::AffinitySource,
}

/// The backend mechanics of a stopped-slot publication: how the slot's vCPU
/// is interrupted, and the executor-local driver handoff.
pub trait StoppedSlotBackend {
    type Error;
    /// The reschedule target that reaches this slot's vCPU, published before
    /// its first entry so a remote affinity kick cannot be lost.
    fn reschedule_target(&mut self) -> Result<u64, Self::Error>;
    /// Hand this executor's driver role to `slot`, vacating a slot it drove
    /// before, before the driver and CPU publish together.
    fn prepare_driver(&mut self, slot: SlotId, driver: ZoneSlotDriver) -> Result<(), Self::Error>;
}

/// What the slot still held when a task was loaded on it: the record EL1
/// left switched in (its claim, identity, pending object operation and
/// handback), the slot's host record and its queue.
#[derive(Debug)]
pub struct StoppedSlotHeld {
    pub current: Option<(
        carrick_sched_core::RecordId,
        carrick_sched_core::Claim,
        ThreadIdentity,
        bool,
        Option<carrick_sched_core::Handback>,
    )>,
    pub host_record: Option<carrick_sched_core::RecordId>,
    pub queued: usize,
}

impl core::fmt::Display for StoppedSlotHeld {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "current={:?} host_record={:?} queued={}",
            self.current, self.host_record, self.queued
        )
    }
}

/// Why a stopped-slot publication did not complete.
#[derive(Debug)]
pub enum StoppedSlotRefusal<E> {
    Backend(E),
    /// A protocol violation the backend reports as its carrier fault.
    Held(Box<StoppedSlotHeld>),
}

/// Publish the zone identity of the task just loaded on a stopped slot: its
/// process's zone key (0 when the zone is off, so EL1 forwards every futex
/// operation), its thread serial, and the slot's reschedule target. No
/// thread may be switched in on the slot (the previous residency's last exit
/// settled it); queued threads stay (one of another address space waits for
/// this executor to load it), and a slot this executor drove before is left.
pub fn publish_stopped_zone_slot<B: StoppedSlotBackend>(
    load: StoppedSlotLoad,
    backend: &mut B,
) -> Result<(), StoppedSlotRefusal<B::Error>> {
    let StoppedSlotLoad {
        slot,
        driver,
        mm,
        serial,
        bound_cpu,
        affinity,
    } = load;
    let bound_cpu = bound_cpu.map(carrick_hal::GuestCpuId::as_u32);
    let Some(zone) = crate::el1_zone::zone() else {
        if let Some(zone) = carrick_el1_abi::zone_tables() {
            zone.slot(slot)
                .set_sgi_target(carrick_sched_core::HOST_RESCHEDULE_TARGET);
            zone.publish_slot_with_affinity(slot, 0, bound_cpu, affinity);
        }
        carrick_el1_abi::publish_zone_identity(slot.index(), 0, serial.raw());
        return Ok(());
    };
    // A compute-only residency must be reachable before its first entry;
    // publishing this only in EL1 idle would lose a remote affinity kick.
    zone.slot(slot).set_sgi_target(
        backend
            .reschedule_target()
            .map_err(StoppedSlotRefusal::Backend)?,
    );
    backend
        .prepare_driver(slot, driver)
        .map_err(StoppedSlotRefusal::Backend)?;
    // What the slot still holds, for the refusal below.
    let current = zone.slot(slot).current().map(|record| {
        let rec = zone.record(record);
        (
            record,
            rec.claim(),
            rec.identity(),
            rec.has_object_operation(),
            rec.handback(),
        )
    });
    let host_record = zone.slot(slot).host_record();
    let queued = zone.slot(slot).queued();
    // The reset clears the slot's timer: a timed park another executor's
    // thread left on it goes to the host first.
    crate::el1_zone::hand_back_foreign_timer(slot);
    if !zone.reset_slot(slot) {
        return Err(StoppedSlotRefusal::Held(Box::new(StoppedSlotHeld {
            current,
            host_record,
            queued,
        })));
    }
    // Threads queued here for another address space stay: EL1 leaves
    // the vCPU for this executor when one reaches the head, and the
    // executor loads it.
    zone.drive_and_publish(slot, driver.raw(), mm.raw(), bound_cpu, affinity);
    carrick_el1_abi::publish_zone_identity(slot.index(), mm.raw(), serial.raw());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn every_writer_family_is_converted_and_the_hatch_refuses_by_its_own_reason() {
        use carrick_mmu_core::aarch64::GuestLaneRefusal;
        let current = GuestDescriptorLanePrecondition::current();
        assert!(current.frame_grants && current.fork_parent_arming);
        assert!(current.host_copyout && current.backend_writers);
        let placed = GuestDescriptorLanePrecondition {
            slots_placed: true,
            ..current
        };
        assert_eq!(placed.admission(DescriptorLaneHatch::Default), Ok(()));
        assert_eq!(
            placed.admission(DescriptorLaneHatch::Disabled),
            Err(GuestLaneRefusal::OperatorHatch)
        );
        let unplaced = GuestDescriptorLanePrecondition {
            slots_placed: false,
            ..current
        };
        assert_eq!(
            unplaced.admission(DescriptorLaneHatch::Default),
            Err(GuestLaneRefusal::Census)
        );
        assert_eq!(
            unplaced.admission(DescriptorLaneHatch::Disabled),
            Err(GuestLaneRefusal::OperatorHatch),
            "the hatch is reported as itself, never as a census gap"
        );
        for (value, hatch) in [
            (None, DescriptorLaneHatch::Default),
            (Some("0"), DescriptorLaneHatch::Disabled),
            (Some(" 0\n"), DescriptorLaneHatch::Disabled),
            (Some("1"), DescriptorLaneHatch::Default),
            (Some(""), DescriptorLaneHatch::Default),
            (Some("00"), DescriptorLaneHatch::Default),
        ] {
            assert_eq!(
                DescriptorLaneHatch::from_env_value(value),
                hatch,
                "{value:?}"
            );
        }
    }

    #[test]
    fn the_lane_is_refused_while_any_writer_family_is_unconverted() {
        let all = GuestDescriptorLanePrecondition {
            slots_placed: true,
            frame_grants: true,
            host_copyout: true,
            fork_parent_arming: true,
            backend_writers: true,
        };
        assert!(all.admits());
        for missing in 0..5 {
            let mut partial = all;
            match missing {
                0 => partial.slots_placed = false,
                1 => partial.frame_grants = false,
                2 => partial.host_copyout = false,
                3 => partial.fork_parent_arming = false,
                _ => partial.backend_writers = false,
            }
            assert!(!partial.admits(), "missing writer {missing}");
        }
    }

    struct RegistrationTestKick;

    impl carrick_hal::VcpuKickDyn for RegistrationTestKick {
        fn kick(&self) {}
    }

    #[test]
    fn occupancy_precedes_registry_publication() {
        use carrick_hal::VcpuRegistry;
        let registry = Arc::new(carrick_hal::GenericVcpuRegistry::new());
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().expect("task context");
        let thread = context.thread().clone();
        let first = carrick_hal::ThreadId::synthetic_for_tests(70_201);
        let second = carrick_hal::ThreadId::synthetic_for_tests(70_202);
        let (first_slot, second_slot) = (
            crate::kernel::HostExecutionSlot::allocate().unwrap(),
            crate::kernel::HostExecutionSlot::allocate().unwrap(),
        );
        let _first_participation = dispatcher
            .enter_mm_executor_for_thread(None, registry.clone(), first, first_slot.slot())
            .expect("first participation");
        let freeze = match registry.subscribe_lease_drain(first, Arc::new(|| {})) {
            carrick_hal::VcpuLeaseDrainEnrollment::Frozen(guard) => guard,
            _ => panic!("first thread must freeze an empty sibling lease set"),
        };
        let second_in_guest = carrick_hal::InGuestFlag::for_guest_thread();
        let occupants = dispatcher.mm_occupancy_probe();

        let (second_participation, attempt) = enter_mm_executor_then_register(
            &dispatcher,
            Some(thread.clone()),
            registry.clone(),
            second,
            second_slot.slot(),
            || {
                assert_eq!(
                    occupants(),
                    2,
                    "slot occupancy must precede registry publication"
                );
                assert!(
                    thread.is_crash_safe_point_participant(),
                    "crash participation must precede registry publication"
                );
                registry.subscribe_register(
                    second,
                    Box::new(RegistrationTestKick),
                    &second_in_guest,
                    Arc::new(|| {}),
                )
            },
        )
        .expect("second participation");

        assert_eq!(occupants(), 2);
        assert!(matches!(
            &attempt,
            carrick_hal::VcpuRegistrationEnrollment::Waiting { .. }
        ));
        assert_eq!(
            registry.poll_lease_drain(first),
            carrick_hal::VcpuLeaseDrainPoll::Complete
        );
        drop(second_participation);
        assert_eq!(occupants(), 1);
        drop(attempt);
        drop(freeze);
    }

    #[test]
    fn failed_crash_admission_suppresses_registry_publication() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().expect("task context");
        let thread = context.thread().clone();
        let _outside = thread
            .enter_crash_safe_point_participation()
            .expect("outside crash participation");
        let register_called = std::sync::atomic::AtomicBool::new(false);
        let slot = crate::kernel::HostExecutionSlot::allocate().unwrap();

        assert!(matches!(
            enter_mm_executor_then_register(
                &dispatcher,
                Some(thread.clone()),
                Arc::new(carrick_hal::GenericVcpuRegistry::new()),
                carrick_hal::ThreadId::synthetic_for_tests(70_205),
                slot.slot(),
                || {
                    register_called.store(true, std::sync::atomic::Ordering::Release);
                    panic!("failed admission must not invoke registry publication")
                }
            ),
            Err(crate::kernel::MmOccupancyError::CrashParticipationAlreadyActive {
                thread: rejected
            }) if rejected == thread.key()
        ));
        assert!(!register_called.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(dispatcher.mm_occupancy_probe()(), 0);
    }

    fn heap_zone() -> &'static ZoneTables {
        let layout = std::alloc::Layout::new::<ZoneTables>();
        // SAFETY: all-zero is the valid empty zone state; the fixture is
        // leaked so the scoped test binding may name it as `'static`.
        unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<ZoneTables>();
            assert!(!ptr.is_null());
            &*ptr
        }
    }

    /// Records each backend call; `target` answers the reschedule target.
    struct RecordingSlotBackend {
        target: Result<u64, &'static str>,
        targets: usize,
        drivers: Vec<(SlotId, ZoneSlotDriver)>,
    }

    impl StoppedSlotBackend for RecordingSlotBackend {
        type Error = &'static str;
        fn reschedule_target(&mut self) -> Result<u64, Self::Error> {
            self.targets += 1;
            self.target
        }
        fn prepare_driver(
            &mut self,
            slot: SlotId,
            driver: ZoneSlotDriver,
        ) -> Result<(), Self::Error> {
            self.drivers.push((slot, driver));
            Ok(())
        }
    }

    const STOPPED_MM: u64 = 0x51;

    fn stopped_load(slot: SlotId) -> StoppedSlotLoad {
        StoppedSlotLoad {
            slot,
            driver: ZoneSlotDriver::new(std::num::NonZeroU64::new(7).unwrap()),
            mm: crate::kernel::MmId::from_raw_u64(STOPPED_MM).unwrap(),
            serial: crate::kernel::ThreadSerial::from_raw_u64(9).unwrap(),
            bound_cpu: Some(carrick_hal::GuestCpuId::new(2)),
            affinity: carrick_sched_core::AffinitySource::UNBOUND,
        }
    }

    #[test]
    fn stopped_slot_publication_targets_then_drives_the_loaded_task() {
        let zone = heap_zone();
        let slot = SlotId::new(4);
        let mut backend = RecordingSlotBackend {
            target: Ok(0x55),
            targets: 0,
            drivers: Vec::new(),
        };
        let published = crate::el1_zone::with_test_zone(zone, || {
            publish_stopped_zone_slot(stopped_load(slot), &mut backend)
        });
        assert!(published.is_ok());
        assert_eq!(backend.targets, 1);
        assert_eq!(
            backend.drivers,
            [(
                slot,
                ZoneSlotDriver::new(std::num::NonZeroU64::new(7).unwrap())
            )]
        );
        assert_eq!(zone.slot(slot).sgi_target(), 0x55);
        assert_eq!(zone.slot(slot).driver(), Some(7));
        assert_eq!(zone.slot(slot).mm(), STOPPED_MM);
        assert_eq!(zone.slot(slot).current(), None);
    }

    #[test]
    fn failed_reschedule_target_publishes_nothing_on_the_slot() {
        let zone = heap_zone();
        let slot = SlotId::new(4);
        let mut backend = RecordingSlotBackend {
            target: Err("stale vCPU"),
            targets: 0,
            drivers: Vec::new(),
        };
        let published = crate::el1_zone::with_test_zone(zone, || {
            publish_stopped_zone_slot(stopped_load(slot), &mut backend)
        });
        assert!(matches!(
            published,
            Err(StoppedSlotRefusal::Backend("stale vCPU"))
        ));
        assert!(
            backend.drivers.is_empty(),
            "no driver handoff after a refusal"
        );
        assert_eq!(zone.slot(slot).sgi_target(), 0);
        assert_eq!(zone.slot(slot).driver(), None);
        assert_eq!(zone.slot(slot).mm(), 0);
    }

    #[test]
    fn held_slot_refuses_publication_and_is_left_undriven() {
        let zone = heap_zone();
        let slot = SlotId::new(4);
        let uaddr = 0x1000;
        // A thread EL1 left switched in on the slot.
        let identity = ThreadIdentity {
            tid: 11,
            serial: 110,
            mm: STOPPED_MM,
            file_table: 1,
            generation: 1,
            affinity_source: carrick_sched_core::AffinitySource::UNBOUND,
            affinity: 0,
            lifecycle_page: 0,
            control_slot: 0,
        };
        let record = zone.alloc_record(identity).unwrap();
        let guard = zone
            .lock(
                ZoneTables::bucket_of_with_context(STOPPED_MM, uaddr),
                &HostLockWait,
            )
            .unwrap();
        let seq = zone.next_seq(record);
        zone.enqueue(&guard, record, seq, STOPPED_MM, uaddr, u32::MAX, 0)
            .unwrap();
        zone.publish_park(record, seq);
        // Another executor drives the slot and runs this address space.
        zone.drive(slot, 3);
        zone.publish_slot(slot, STOPPED_MM, None, 0);
        let here = carrick_sched_core::occupancy::ExecutionSlot::zone(slot);
        zone.occupancy.vacate_any(here);
        assert!(zone.occupancy.replace(here, 0, STOPPED_MM));
        let mut woken = [const { carrick_el1_abi::WakeRecord::Empty }; 4];
        let count = zone.wake(
            &guard,
            STOPPED_MM,
            uaddr,
            u32::MAX,
            1,
            carrick_sched_core::Waker::El1 { slot },
            &mut woken,
        );
        drop(guard);
        assert_eq!(count, 1);
        for woken in &mut woken[..1] {
            let _ = woken.take_ready(&HostLockWait, &|owned| {
                let _ = owned.into_parts();
            });
        }
        assert_eq!(zone.switch_in(slot), Some(record));
        let mut backend = RecordingSlotBackend {
            target: Ok(0x55),
            targets: 0,
            drivers: Vec::new(),
        };
        let published = crate::el1_zone::with_test_zone(zone, || {
            publish_stopped_zone_slot(stopped_load(slot), &mut backend)
        });
        let Err(StoppedSlotRefusal::Held(held)) = published else {
            panic!("a switched-in record must refuse the load");
        };
        assert_eq!(held.current.map(|current| current.0), Some(record));
        assert!(held.to_string().starts_with("current=Some(("));
        // The refusal leaves the slot as EL1 left it: its previous driver
        // and target, the record still switched in.
        assert_eq!(zone.slot(slot).driver(), Some(3));
        assert_eq!(zone.slot(slot).current(), Some(record));
    }

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
    fn first_touch_busy_root_enrols_once_then_reruns_without_polling() {
        use crate::dispatch::mem::delegated_tests::Root;
        use std::time::{Duration, Instant};

        let mut dispatcher = SyscallDispatcher::new();
        let root = Root::admit(&dispatcher);
        let ctx = dispatcher.capture_one_task_context().unwrap();
        let venue = root.owner_wait_venue();
        let wake_slot = Arc::new(SingleCarrierHandbackWait::for_current_thread());
        let address = crate::memory::LINUX_MMAP_BASE;
        let attempts = AtomicUsize::new(0);
        let (held_tx, held_rx) = std::sync::mpsc::sync_channel(1);

        let outcome = crate::el1_zone::with_test_handback_publisher(wake_slot.publisher(), || {
            std::thread::scope(|scope| {
                scope.spawn(|| {
                    // A peer EL1 slot owns the MM root.
                    let held = root.lock_el1_slot(9);
                    held_tx.send(()).unwrap();
                    // Release only after the carrier thread enrolled and
                    // parked, so the rerun must come from the handback.
                    let deadline = Instant::now() + Duration::from_secs(10);
                    while venue.zone.counters.host_parks.load(Ordering::Acquire) == 0 {
                        assert!(Instant::now() < deadline, "carrier never parked");
                        std::hint::spin_loop();
                    }
                    drop(held);
                });
                held_rx.recv().unwrap();
                // The production driver the soft runner's first-touch
                // path uses, over the production resident-fault planner.
                rerun_after_owner_release(
                    &ctx,
                    &wake_slot,
                    || Ok(venue),
                    || {
                        attempts.fetch_add(1, Ordering::Relaxed);
                        dispatcher
                            .with_mm_executor_mutation(|disp, mutation| {
                                disp.resident_fault_plan(&mutation.host_alias_permit(), address)
                                    .map(|plan| plan.is_some())
                            })
                            .map_err(|error| error.to_string())
                    },
                )
            })
        });

        assert_eq!(outcome, Ok((false, 1)), "Busy once, then the rerun answers");
        assert_eq!(
            attempts.load(Ordering::Relaxed),
            2,
            "Busy once, then success: exactly two attempts, no yield loop"
        );
        assert_eq!(venue.zone.counters.host_parks.load(Ordering::Relaxed), 1);
    }
}
