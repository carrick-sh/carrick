//! Production single-process runner over [`SoftAarch64Engine`] and
//! [`carrick_kernel::dispatch::SyscallDispatcher`].
//!
//! Loads an AArch64 static or dynamic ELF into an [`AddressSpace`], brings up
//! [`SoftAarch64Vmm`] (`Aarch64EngineCore<SoftAarch64Vmm>`), binds the EL1
//! kernel and IPC descriptor-table windows for slot 0, and serves every
//! forwarded `HVC #2` syscall through production `SyscallDispatcher` and
//! `carrick-personality-linux` without fixture syscall replies.

use std::mem::offset_of;
use std::num::NonZeroU64;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use carrick_aarch64::{Aarch64Vcpu as _, Aarch64Vmm as _};
use carrick_abi::syscall::nr;
use carrick_abi::{CanonicalNr, SigBlockMask, SigSet};
use carrick_el1_abi::{
    Counters, CurrentTask, EL1_COUNTERS_BASE, EL1_CURRENT_TASKS_OFFSET, EL1_MM_PORTAL_OFFSET,
    El1TaskId, IpcWindow, MmPortalSlots, SignalFrameCustody, SlotId, SnapshotGeneration,
    clear_current_task_record, clear_el1_region_host_ptr_if, get_el1_region_host_ptr,
    ipc_table_map_host, record_el1_region_host_ptr, record_ipc_window_host,
};
use carrick_guest_arch::ContextGeneration;
use carrick_guest_mem::GuestMemory;
use carrick_hal::{
    GuestTimerBridge, HostSignalBridge, InGuestFlag, NO_PENDING_SIGNAL, PosixTimerSpec,
    SyscallTrap, ThreadedEngine, TimerDelivery, TimerSpecNs, TrapError, VcpuRegistry,
};
use carrick_kernel::compat::CompatReporter;
use carrick_kernel::dispatch::carrier_lifecycle::CarrierLifecycleMappings;
use carrick_kernel::dispatch::carrier_loop::{
    SingleCarrierHandbackWait, StoppedSlotBackend, StoppedSlotLoad, StoppedSlotRefusal,
    ZoneExitSettlement, ZoneSlotDriver, enter_mm_executor_then_register,
    install_host_alias_with_inventory, publish_leased_first_address_space,
    publish_stopped_zone_slot, resolve_host_first_touch_with_owner_wait, run_guest,
    settle_zone_exit,
};
use carrick_kernel::dispatch::{
    CarrierBridges, DispatchOutcome, MmExecutorParticipation, SyscallDispatcher, SyscallRequest,
    boot_private_file_backings,
};
use carrick_kernel::el1_delegation::{
    get_orig_arg0, publish_current_task, recall_all_delegated, revalidate_current_task,
    settle_el1_boundary_for, settle_pending_host_work_for,
};
use carrick_kernel::el1_zone::{
    GuestSchedulerScope, SlotKickerRegistration, register_handback_publisher, register_slot_kicker,
};
use carrick_kernel::kernel::continuation::ipc::{host_window_backing, publish_file_table};
use carrick_kernel::kernel::exec_transaction::{
    core_file_mappings_from_address_space, proc_maps_from_address_space,
};
use carrick_kernel::kernel::identity_page::stamp_identity_page;
use carrick_kernel::kernel::{
    FrameInventorySnapshot, Kernel, VmaSummary, execution_slot_for_current_thread,
    is_default_ignore_signal, is_default_stop_signal, publish_idle_root,
};
use carrick_mem::linux_abi::{
    LINUX_AT_HWCAP2, LINUX_AT_NULL, LinuxAarch64Hwcap, syscall::lookup_aarch64,
};
use carrick_mem::memory::{AddressSpace, El1IrqMode, LINUX_EL1_KERNEL_BASE, LINUX_EL1_KERNEL_SIZE};
use carrick_softcpu_aarch64::GUEST_CPU_PROFILE;
use carrick_softcpu_aarch64::dispatch::ExecuteBlock;
use carrick_vfs::rootfs::RootFs;

use crate::HostBlockRunner;
use crate::facade::{GUEST_PAGE_BYTES, SoftAarch64Engine, SoftAarch64Vmm, SoftRetainedMetadata};

/// Fail-closed signal bridge for single-process soft-CPU bring-up before
/// `#2645` wires guest signal delivery: passive pending queries report empty,
/// and any attempt to publish or arm host signal delivery is counted and refused.
#[derive(Default)]
struct RefusingSoftSignalBridge {
    refused_ops: AtomicU64,
}

impl HostSignalBridge for RefusingSoftSignalBridge {
    fn has_unblocked_pending_for(&self, _tid: i32, _block_mask: SigBlockMask) -> bool {
        false
    }

    fn claim_pending_in_for(&self, _tid: i32, _eligible: SigSet) -> bool {
        false
    }

    fn take_pending_for(&self, _tid: i32) -> i32 {
        NO_PENDING_SIGNAL
    }

    fn take_pending_in_for(&self, _tid: i32, _wait_set: SigSet) -> i32 {
        NO_PENDING_SIGNAL
    }

    fn publish_pending_for(&self, _tid: i32, _signum: i32) {
        self.refused_ops.fetch_add(1, Ordering::Relaxed);
    }

    fn publish_process_signal(&self, _signum: i32) {
        self.refused_ops.fetch_add(1, Ordering::Relaxed);
    }

    fn last_sender_for(&self, _signum: i32) -> i32 {
        0
    }

    fn raise_for_self(&self, _signum: i32) {
        self.refused_ops.fetch_add(1, Ordering::Relaxed);
    }

    fn wake_all_waiters(&self) {}

    fn ensure_host_handler(&self, _linux_signum: i32) {
        self.refused_ops.fetch_add(1, Ordering::Relaxed);
    }

    fn set_host_ignore(&self, _linux_signum: i32) {
        self.refused_ops.fetch_add(1, Ordering::Relaxed);
    }

    fn set_host_default(&self, _linux_signum: i32) {
        self.refused_ops.fetch_add(1, Ordering::Relaxed);
    }

    fn reset_routed_handlers_after_execve(&self, _ignored: SigSet) {}

    fn xsig_enqueue(
        &self,
        _target_host_pid: i32,
        _signum: i32,
        _code: i32,
        _sender_ns_pid: i32,
        _sender_uid: u32,
        _value: i64,
        _target_ns_tid: i32,
    ) -> bool {
        self.refused_ops.fetch_add(1, Ordering::Relaxed);
        false
    }

    fn xsig_nudge(&self, _target_host_pid: i32) {
        self.refused_ops.fetch_add(1, Ordering::Relaxed);
    }

    fn xsig_drain_for_self(&self) -> Vec<(i32, i32, i32, u32, i64, i32)> {
        Vec::new()
    }

    fn host_to_linux_signum(&self, host_signum: i32) -> i32 {
        host_signum
    }

    fn linux_to_host_signum(&self, linux_signum: i32) -> i32 {
        linux_signum
    }
}

/// Fail-closed timer bridge for single-process soft-CPU bring-up: implements
/// [`GuestTimerBridge`] directly without allocating `TimerCoreBridge` slots.
#[derive(Default)]
struct RefusingSoftTimerBridge {
    refused_ops: AtomicU64,
}

impl GuestTimerBridge for RefusingSoftTimerBridge {
    fn itimer_arm(&self, _which: usize, _spec: TimerSpecNs, _needs_periodic: bool) -> u64 {
        self.refused_ops.fetch_add(1, Ordering::Relaxed);
        0
    }

    fn itimer_disarm(&self, _which: usize) {
        self.refused_ops.fetch_add(1, Ordering::Relaxed);
    }

    fn itimer_signum_for(&self, _which: usize) -> i32 {
        0
    }

    fn itimer_spawn_fallback_timer(&self, _which: usize, _generation: u64, _spec: TimerSpecNs) {
        self.refused_ops.fetch_add(1, Ordering::Relaxed);
    }

    fn posix_create_with_target_and_value(
        &self,
        _clock_id: i32,
        _signum: i32,
        _target_tid: Option<i32>,
        _si_value: i64,
    ) -> i32 {
        self.refused_ops.fetch_add(1, Ordering::Relaxed);
        -1
    }

    fn posix_arm(&self, _id: i32, _spec: TimerSpecNs) -> Option<PosixTimerSpec> {
        self.refused_ops.fetch_add(1, Ordering::Relaxed);
        None
    }

    fn posix_remaining(&self, _id: i32) -> Option<TimerSpecNs> {
        None
    }

    fn posix_getoverrun(&self, _id: i32) -> Option<u32> {
        None
    }

    fn posix_seed_overrun(&self, _id: i32, _count: u32) {
        self.refused_ops.fetch_add(1, Ordering::Relaxed);
    }

    fn posix_exists(&self, _id: i32) -> bool {
        false
    }

    fn posix_clock_id(&self, _id: i32) -> i32 {
        0
    }

    fn posix_delete(&self, _id: i32) -> bool {
        false
    }

    fn deliver(&self, _signum: i32) {
        self.refused_ops.fetch_add(1, Ordering::Relaxed);
    }

    fn delivery(&self) -> Option<Arc<dyn TimerDelivery>> {
        None
    }
}

fn refusing_soft_bridges() -> CarrierBridges {
    CarrierBridges {
        host_signal: Arc::new(RefusingSoftSignalBridge::default()),
        timers: Arc::new(RefusingSoftTimerBridge::default()),
    }
}

/// Timer and signal calls that need guest signal or timer delivery, which
/// the single-process soft runner does not wire yet (`#2645`): each fails
/// closed with counted `ENOSYS`.
const SINGLE_PROCESS_REFUSED_TIMER_OR_SIGNAL: [CanonicalNr; 26] = [
    nr::SIGNALFD4,
    nr::TIMERFD_CREATE,
    nr::TIMERFD_SETTIME,
    nr::TIMERFD_GETTIME,
    nr::GETITIMER,
    nr::SETITIMER,
    nr::TIMER_CREATE,
    nr::TIMER_GETTIME,
    nr::TIMER_GETOVERRUN,
    nr::TIMER_SETTIME,
    nr::TIMER_DELETE,
    nr::KILL,
    nr::TKILL,
    nr::TGKILL,
    nr::SIGALTSTACK,
    nr::RT_SIGSUSPEND,
    nr::RT_SIGPENDING,
    nr::RT_SIGTIMEDWAIT,
    nr::RT_SIGQUEUEINFO,
    nr::RT_SIGRETURN,
    nr::RT_TGSIGQUEUEINFO,
    nr::TIMER_GETTIME64,
    nr::TIMER_SETTIME64,
    nr::TIMERFD_GETTIME64,
    nr::TIMERFD_SETTIME64,
    nr::PIDFD_SEND_SIGNAL,
];

/// Determine whether a forwarded timer or signal syscall must fail closed with
/// counted `ENOSYS` on the single-process soft-CPU bring-up runner before
/// `#2645` wires guest signal and timer delivery.
fn should_refuse_single_process_timer_or_signal_syscall<X>(
    engine: &SoftAarch64Engine<X>,
    number: CanonicalNr,
    args: &[u64; 6],
) -> bool
where
    X: ExecuteBlock + Send + 'static,
    X::Error: core::fmt::Debug,
{
    if number == nr::RT_SIGACTION {
        // `SIG_DFL` (0), `SIG_IGN` (1), and read-only queries
        // (`new_action == 0`) live purely in `carrick-kernel`'s `SignalTable`
        // (honored for broken-pipe `SIGPIPE = SIG_IGN` -> `-EPIPE` and default
        // fault death), whereas installing a custom user handler (`sa_handler`
        // outside `SIG_DFL`/`SIG_IGN`) requires guest signal frame delivery
        // and must fail closed with `-ENOSYS`.
        let new_action = args[1];
        if new_action == 0 {
            return false;
        }
        let Ok(bytes) = engine.read_bytes(new_action, 8) else {
            // Let `SyscallDispatcher::rt_sigaction` surface `-EFAULT`.
            return false;
        };
        let Ok(word) = <[u8; 8]>::try_from(bytes.as_slice()) else {
            return true;
        };
        let sa_handler = u64::from_le_bytes(word);
        return sa_handler != carrick_abi::LINUX_SIG_DFL
            && sa_handler != carrick_abi::LINUX_SIG_IGN;
    }
    // `rt_sigprocmask` updates only the in-zone thread signal mask.
    SINGLE_PROCESS_REFUSED_TIMER_OR_SIGNAL.contains(&number)
}

/// Parameters for launching one single-process AArch64 guest through the
/// production kernel dispatcher.
pub struct SoftSingleProcessConfig<'a> {
    pub elf_bytes: &'a [u8],
    pub executable_path: &'a str,
    pub argv: Vec<Vec<u8>>,
    pub envp: Vec<Vec<u8>>,
    pub rootfs_dir: Option<&'a Path>,
    pub el1_elf_override: Option<&'a [u8]>,
    pub max_syscalls: usize,
}

impl<'a> SoftSingleProcessConfig<'a> {
    #[must_use]
    pub fn new(elf_bytes: &'a [u8], executable_path: &'a str) -> Self {
        Self {
            elf_bytes,
            executable_path,
            argv: vec![executable_path.as_bytes().to_vec()],
            envp: Vec::new(),
            rootfs_dir: None,
            el1_elf_override: None,
            max_syscalls: 4096,
        }
    }
}

/// Per-reply census of forwarded `HVC #2` syscall completions, recorded at the
/// completion boundary by whichever production responder answered the mailbox.
/// The runner has no fixture responder: every reply is one of these sources.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Hvc2ReplyCensus {
    /// Served in ring by the EL1 image and completed at the boundary.
    pub ring_completed: u64,
    /// Answered by the production `SyscallDispatcher`.
    pub kernel_dispatched: u64,
    /// Refused by this runner with counted `ENOSYS`; also in `counted_enosys`.
    pub runner_refused: u64,
}

impl Hvc2ReplyCensus {
    /// Every reply the runner completed, whatever its source.
    #[must_use]
    pub const fn total(&self) -> u64 {
        self.ring_completed + self.kernel_dispatched + self.runner_refused
    }
}

/// Terminal synchronous EL0 fault lowered to Linux default signal death when
/// neither first-touch nor stale-stage-1 fault resolution applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoftFaultTermination {
    pub signum: i32,
    pub si_code: i32,
    pub fault_addr: u64,
    pub elr: u64,
    pub syndrome: u64,
}

/// Outcome and post-exit inspection handle for [`run_single_process`].
pub struct SoftProcessRun<X = HostBlockRunner>
where
    X: ExecuteBlock + Send + 'static,
    X::Error: core::fmt::Debug,
{
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub syscalls_dispatched: u64,
    pub reply_census: Hvc2ReplyCensus,
    pub terminating_fault: Option<SoftFaultTermination>,
    /// `(aarch64_nr, syscall_name, count)` refused with `ENOSYS` in EL1 ring or host dispatch.
    pub counted_enosys: Vec<(u64, &'static str, u64)>,
    pub vmas: Vec<VmaSummary>,
    pub frame_inventory: FrameInventorySnapshot,
    pub engine: SoftAarch64Engine<X>,
}

static SOFT_CARRIER_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Returned when a second soft AArch64 single-process carrier attempts to run
/// concurrently in the same host process while the process-global EL1 aperture
/// and IPC window are already bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoftCarrierActiveError;

impl core::fmt::Display for SoftCarrierActiveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("a soft AArch64 single-process carrier is already active in this host process")
    }
}

impl std::error::Error for SoftCarrierActiveError {}

struct SoftCarrierLease;

impl SoftCarrierLease {
    fn try_acquire() -> Result<Self, SoftCarrierActiveError> {
        SOFT_CARRIER_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self)
            .map_err(|_| SoftCarrierActiveError)
    }
}

impl Drop for SoftCarrierLease {
    fn drop(&mut self) {
        SOFT_CARRIER_ACTIVE.store(false, Ordering::Release);
    }
}

struct El1ApertureScope {
    el1_host_ptr: usize,
    /// The root's retained lifecycle mappings. They retire after slot 0's
    /// publication clears and before the aperture is unpublished.
    lifecycle: Option<CarrierLifecycleMappings<SoftRetainedMetadata>>,
    /// The carrier's in-guest zone. It closes first: the root's address
    /// space and slot leave the zone while the aperture is still published.
    zone: Option<SoftZone>,
    _lease: SoftCarrierLease,
}

impl Drop for El1ApertureScope {
    fn drop(&mut self) {
        drop(self.zone.take());
        if self.el1_host_ptr != 0 {
            if get_el1_region_host_ptr() == self.el1_host_ptr {
                recall_all_delegated();
                clear_current_task_record(0);
                record_ipc_window_host(None);
            }
            drop(self.lifecycle.take());
            let _ = clear_el1_region_host_ptr_if(self.el1_host_ptr);
        }
    }
}

/// The soft carrier's one execution slot: mailbox slot 0, its single vCPU.
const SOFT_ZONE_SLOT: SlotId = SlotId::new(0);
/// The zone driver identity of the soft carrier's only executor.
const SOFT_ZONE_DRIVER: ZoneSlotDriver = ZoneSlotDriver::new(NonZeroU64::MIN);
/// The root's process ASID (ASID 0 is the carrier maintenance root's).
const SOFT_ROOT_ASID: u16 = 1;

/// The soft carrier's in-guest zone for one run, set up the way an HVF
/// executor sets up its first load: the guest scheduler on, the slot kicker
/// registered, the root executor admitted and registered, its vCPU slot
/// occupied and published, and the root's address space BOUND for EL1 to
/// install itself. Everything is carrier-scoped and leaves with this value.
struct SoftZone {
    /// The root's address space, open for EL1. Dropped first: it waits for
    /// no vCPU to have the space installed, then retires its entry.
    publication: Option<carrick_kernel::kernel::AddressSpacePublication>,
    participation: Option<MmExecutorParticipation>,
    registry: Arc<dyn VcpuRegistry>,
    tid: carrick_hal::ThreadId,
    mm: carrick_kernel::kernel::MmId,
    in_guest: InGuestFlag,
    /// The zone was closed: its slot left, its space retired.
    closed: bool,
    _kicker: SlotKickerRegistration,
    _scheduler: GuestSchedulerScope,
}

/// Whose exit a settled soft vCPU exit is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SoftZoneExit {
    /// The root's own: a syscall, fault or kick of its thread.
    Root,
    /// EL1's idle exit, with the root parked in the zone.
    IdleWithRootParked,
}

/// The soft mechanics of the stopped-slot publication: its vCPU's own SGI
/// target (affinity 0) and the one executor's driver role.
struct SoftStoppedSlot;

impl StoppedSlotBackend for SoftStoppedSlot {
    type Error = String;

    fn reschedule_target(&mut self) -> Result<u64, String> {
        Ok(carrick_guest_arch::sgi_target_of(0))
    }

    /// The soft carrier's one executor drives only slot 0: there is no
    /// slot it drove before to leave.
    fn prepare_driver(&mut self, _slot: SlotId, _driver: ZoneSlotDriver) -> Result<(), String> {
        Ok(())
    }
}

impl SoftZone {
    fn start<X>(
        engine: &mut SoftAarch64Engine<X>,
        dispatcher: &SyscallDispatcher,
        root: &carrick_kernel::kernel::KernelContext,
    ) -> Result<Self, String>
    where
        X: ExecuteBlock + Send + 'static,
        X::Error: core::fmt::Debug,
    {
        // The root runs under its own ASID, so EL1 can switch this vCPU
        // between the root's space and the maintenance root.
        engine
            .configure_process_asid(SOFT_ROOT_ASID)
            .map_err(|e| format!("configure the soft root's ASID: {e}"))?;
        let lease_ttbr0 = engine
            .vcpu()
            .get_sys_reg(carrick_hal::SysReg::Ttbr0)
            .map_err(|e| format!("read the soft root's TTBR0: {e}"))?;
        // The soft vCPU has a GIC CPU interface and an EL1 virtual timer,
        // the interrupts the in-guest scheduler needs.
        let scheduler = GuestSchedulerScope::enable(true);
        let kick = engine.kick_handle();
        let kicker = register_slot_kicker(Box::new(move |slot| {
            if slot == SOFT_ZONE_SLOT {
                carrick_hal::VcpuKick::kick(&kick);
            }
        }));
        let carrier_root = engine
            .vm()
            .carrier_maintenance_root()
            .map_err(|e| format!("soft carrier maintenance root: {e}"))?;
        publish_idle_root(carrier_root.raw());

        let registry = engine.vm().fresh_fork_kicker();
        let tid = root.thread().registry_id();
        let in_guest = InGuestFlag::for_guest_thread();
        let slot = execution_slot_for_current_thread(Some(SOFT_ZONE_SLOT.index()))
            .map_err(|e| format!("soft root execution slot: {e}"))?;
        let (mut participation, enrollment) = enter_mm_executor_then_register(
            dispatcher,
            Some(Arc::clone(root.thread())),
            Arc::clone(&registry),
            tid,
            slot,
            || {
                registry.subscribe_register(
                    tid,
                    Box::new(engine.kick_handle()),
                    &in_guest,
                    Arc::new(|| {}),
                )
            },
        )
        .map_err(|e| format!("admit the soft root executor: {e}"))?;
        let mm = root.shared().mm().id();
        let mut zone = Self {
            publication: None,
            participation: None,
            registry,
            tid,
            mm,
            in_guest,
            closed: false,
            _kicker: kicker,
            _scheduler: scheduler,
        };
        // The soft carrier runs one thread: nothing can freeze its
        // registration.
        if !matches!(
            enrollment,
            carrick_hal::VcpuRegistrationEnrollment::Registered
        ) {
            return Err("the soft root's vCPU registration is frozen".to_owned());
        }
        participation
            .occupy_slot(slot)
            .map_err(|e| format!("occupy the soft root's slot: {e}"))?;
        publish_stopped_zone_slot(
            StoppedSlotLoad {
                slot: SOFT_ZONE_SLOT,
                driver: SOFT_ZONE_DRIVER,
                mm,
                serial: root.thread().key().serial,
                bound_cpu: None,
                affinity: root.thread().control_slot().affinity_source(),
            },
            &mut SoftStoppedSlot,
        )
        .map_err(|refusal| match refusal {
            StoppedSlotRefusal::Backend(error) => error,
            StoppedSlotRefusal::Held(held) => {
                format!("soft zone slot 0 still held threads at the root's load: {held}")
            }
        })?;
        zone.publication =
            publish_leased_first_address_space(dispatcher, &mut participation, engine, lease_ttbr0)
                .map_err(|e| format!("BIND the soft root's address space: {e}"))?;
        zone.participation = Some(participation);
        if zone.publication.is_none() {
            return Err("the soft root's address space was not BOUND".to_owned());
        }
        Ok(zone)
    }

    /// Run the root's vCPU in the zone: the slot is in the guest, and the
    /// root's executor registration reads in-guest, for exactly the run.
    fn run_guest<R>(&self, thread: &carrick_kernel::kernel::Thread, run: impl FnOnce() -> R) -> R {
        let zone = carrick_kernel::el1_zone::zone().map(|zone| (zone, SOFT_ZONE_SLOT));
        self.in_guest.enter_guest();
        let result = run_guest(Some(thread), zone, run);
        self.in_guest.leave_guest();
        result
    }

    /// Settle slot 0 at a vCPU exit, as an HVF executor does
    /// ([`settle_zone_exit`]). The exit is the root's to handle when nothing
    /// of it stays switched in and its own address space is installed. EL1
    /// may instead have left its idle loop with the root parked in the zone
    /// (host work arrived while it waited): that exit carries no call of
    /// the root's, and the slot must have vacated the root's space.
    fn settle_exit(&self) -> Result<SoftZoneExit, String> {
        let Some(zone) = carrick_kernel::el1_zone::zone() else {
            return Err("the soft carrier's zone turned off under its run".to_owned());
        };
        let installed = zone.installed_space(SOFT_ZONE_SLOT);
        let (exit, expected) = match settle_zone_exit(zone, SOFT_ZONE_SLOT) {
            ZoneExitSettlement::Released
            | ZoneExitSettlement::Held {
                current: None,
                own: None,
            } => (SoftZoneExit::Root, self.mm.raw()),
            ZoneExitSettlement::Held {
                current: None,
                own: Some(_),
            } => (SoftZoneExit::IdleWithRootParked, 0),
            other => {
                return Err(format!(
                    "the soft root's slot settled into a state its single executor cannot own: {other:?}"
                ));
            }
        };
        if installed != expected {
            return Err(format!(
                "soft zone slot 0 exited ({exit:?}) with space {installed:#x} installed, not {expected:#x}"
            ));
        }
        Ok(exit)
    }

    /// Serve an idle exit EL1 took with the root parked in the zone: settle
    /// the host work it left for, then return the vCPU to the idle entry.
    /// EL1 keeps the root's wait (and its deadline on this slot's timer) and
    /// runs the root again when the wait ends; the root's next exit is an
    /// ordinary one.
    fn serve_idle_exit<X>(
        &self,
        engine: &mut SoftAarch64Engine<X>,
        dispatcher: &SyscallDispatcher,
    ) -> Result<(), String>
    where
        X: ExecuteBlock + Send + 'static,
        X::Error: core::fmt::Debug,
    {
        settle_pending_host_work_for(SOFT_ZONE_SLOT.index(), dispatcher);
        let frame = carrick_el1_abi::prepare_idle_frame(SOFT_ZONE_SLOT.index())
            .ok_or("the soft idle entry has no EL1 region")?;
        engine
            .enter_idle_entry(frame)
            .map_err(|e| format!("return the soft vCPU to the idle entry: {e}"))
    }

    /// Close the zone in order: the root's address space retires, its
    /// executor leaves its slot and registry, and slot 0 is left undriven.
    fn close(&mut self) -> Result<(), String> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        drop(self.publication.take());
        drop(self.participation.take());
        self.registry.unregister(self.tid);
        carrick_kernel::el1_zone::leave_slot(SOFT_ZONE_SLOT, SOFT_ZONE_DRIVER.raw(), None)
            .map_err(|refused| format!("soft zone slot 0 refused to leave: {refused}"))
    }
}

impl Drop for SoftZone {
    fn drop(&mut self) {
        // An unwinding or failed run: the refusal has no one to report to.
        let _ = self.close();
    }
}

/// Patch `AT_HWCAP2` in the initial stack region to match [`GUEST_CPU_PROFILE`]
/// (`AT_HWCAP` is masked up front via [`AddressSpace::without_auxv_hwcap`]),
/// returning the serialized auxv bytes.
fn patch_stack_auxv_hwcap2(image: &mut AddressSpace) -> Result<Vec<u8>, String> {
    let Some(sp) = image.initial_stack_pointer() else {
        return Ok(image.linux_auxv_image().to_vec());
    };
    let stack_idx = image
        .regions()
        .iter()
        .position(|r| sp >= r.start && sp < r.end)
        .ok_or_else(|| format!("initial SP {sp:#x} outside AddressSpace regions"))?;
    let region_start = image.regions()[stack_idx].start;
    let bytes = image
        .region_bytes_mut(stack_idx)
        .ok_or_else(|| "missing stack region bytes".to_owned())?;

    let sp_off =
        usize::try_from(sp - region_start).map_err(|_| "initial SP offset overflow".to_owned())?;
    let read_u64_at = |buf: &[u8], off: usize| -> Result<u64, String> {
        let slice = buf
            .get(off..off.saturating_add(8))
            .ok_or_else(|| format!("initial stack auxv truncated at offset {off:#x}"))?;
        let mut word = [0u8; 8];
        word.copy_from_slice(slice);
        Ok(u64::from_le_bytes(word))
    };

    let argc = usize::try_from(read_u64_at(bytes, sp_off)?)
        .map_err(|_| "initial stack argc overflow".to_owned())?;
    // Skip argc + argv[0..argc] + NULL.
    let mut cursor = sp_off
        .checked_add((1usize.saturating_add(argc).saturating_add(1)).saturating_mul(8))
        .ok_or_else(|| "initial stack argv cursor overflow".to_owned())?;
    // Skip envp until NULL.
    loop {
        let env_ptr = read_u64_at(bytes, cursor)?;
        cursor = cursor
            .checked_add(8)
            .ok_or_else(|| "initial stack envp cursor overflow".to_owned())?;
        if env_ptr == 0 {
            break;
        }
    }

    let auxv_start = cursor;
    let hwcap2 = GUEST_CPU_PROFILE.hwcap2().bits();
    loop {
        let tag = read_u64_at(bytes, cursor)?;
        let val_off = cursor
            .checked_add(8)
            .ok_or_else(|| "initial stack auxv val offset overflow".to_owned())?;
        if tag == LINUX_AT_HWCAP2 {
            bytes[val_off..val_off + 8].copy_from_slice(&hwcap2.to_le_bytes());
        }
        cursor = cursor
            .checked_add(16)
            .ok_or_else(|| "initial stack auxv cursor overflow".to_owned())?;
        if tag == LINUX_AT_NULL {
            break;
        }
    }
    Ok(bytes[auxv_start..cursor].to_vec())
}

/// One per-ordinal EL1 counter array at `offset` in [`Counters`].
fn sample_el1_counter_array<X>(engine: &SoftAarch64Engine<X>, offset: usize) -> Option<Vec<u64>>
where
    X: ExecuteBlock + Send + 'static,
    X::Error: core::fmt::Debug,
{
    use carrick_aarch64::Aarch64Vmm as _;

    let bytes = engine
        .backend()
        .read_gpa(EL1_COUNTERS_BASE + offset as u64, 512 * 8)
        .ok()?;
    Some(
        bytes
            .chunks_exact(8)
            .map(|word| {
                let mut raw = [0u8; 8];
                raw.copy_from_slice(word);
                u64::from_le_bytes(raw)
            })
            .collect(),
    )
}

/// The nonzero `(aarch64_nr, syscall_name, count)` entries of `counts`.
fn named_counts(counts: impl Iterator<Item = u64>) -> Vec<(u64, &'static str, u64)> {
    counts
        .enumerate()
        .filter(|&(_, count)| count != 0)
        .map(|(nr, count)| {
            let nr = nr as u64;
            (
                nr,
                lookup_aarch64(nr).map_or("unknown", |call| call.name),
                count,
            )
        })
        .collect()
}

/// Sample counted `ENOSYS` refusals from `EL1_COUNTERS_BASE` (`refused` + `venue_refused`).
pub fn sample_el1_counted_enosys<X>(engine: &SoftAarch64Engine<X>) -> Vec<(u64, &'static str, u64)>
where
    X: ExecuteBlock + Send + 'static,
    X::Error: core::fmt::Debug,
{
    let (Some(ring), Some(venue)) = (
        sample_el1_counter_array(engine, offset_of!(Counters, refused)),
        sample_el1_counter_array(engine, offset_of!(Counters, venue_refused)),
    ) else {
        return Vec::new();
    };
    named_counts(
        ring.into_iter()
            .zip(venue)
            .map(|(ring, venue)| ring.saturating_add(venue)),
    )
}

/// Sample the syscalls the EL1 ring completed without leaving the guest
/// (`Counters::served`), per native ordinal.
pub fn sample_el1_served<X>(engine: &SoftAarch64Engine<X>) -> Vec<(u64, &'static str, u64)>
where
    X: ExecuteBlock + Send + 'static,
    X::Error: core::fmt::Debug,
{
    sample_el1_counter_array(engine, offset_of!(Counters, served))
        .map_or_else(Vec::new, |served| named_counts(served.into_iter()))
}

/// Syscalls the EL1 ring routed, summed over every native ordinal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct El1RouteCensus {
    /// Completed at EL1 without leaving the guest (`Counters::served`).
    pub served: u64,
    /// Forwarded to the host through `HVC #2` (`Counters::forwarded`).
    pub forwarded: u64,
}

/// Sample the EL1 ring's served and forwarded totals from `EL1_COUNTERS_BASE`.
pub fn sample_el1_routes<X>(engine: &SoftAarch64Engine<X>) -> Option<El1RouteCensus>
where
    X: ExecuteBlock + Send + 'static,
    X::Error: core::fmt::Debug,
{
    let total = |offset: usize| {
        sample_el1_counter_array(engine, offset)
            .map(|counts| counts.into_iter().fold(0u64, u64::saturating_add))
    };
    Some(El1RouteCensus {
        served: total(offset_of!(Counters, served))?,
        forwarded: total(offset_of!(Counters, forwarded))?,
    })
}

/// What the host published for the root task on mailbox slot 0, read from
/// the carrier's EL1 region and, for the lifecycle records, through the
/// guest's own stage-2 view of the dynamic metadata aperture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoftRootPublication {
    /// `CurrentTask[0]`'s loaded task (its kernel TID, 0: none).
    pub task_tid: u64,
    /// `CurrentTask[0]`'s published lifecycle page (guest address, 0: none).
    pub lifecycle_page: u64,
    /// `CurrentTask[0]`'s published control slot (guest address, 0: none).
    pub control_slot: u64,
    /// Both records lie inside the EL1 dynamic metadata aperture.
    pub in_metadata_aperture: bool,
    /// The namespace TID the mapped control slot carries.
    pub control_visible_tid: Option<u32>,
    /// The mapped lifecycle page lets EL1 serve thread or sigmask calls.
    pub page_serves_ring: bool,
    /// The carrier the MM portal at `EL1_MM_PORTAL_BASE` is bound to.
    pub portal_carrier: Option<NonZeroU64>,
    /// The carrier's own identity, the one its stage-2 core and transfer
    /// custody hold. The portal must be bound to exactly this.
    pub carrier: NonZeroU64,
    /// The published owner-memory wait venue is this region's zone and portal.
    pub portal_is_owner_wait_venue: bool,
}

impl SoftRootPublication {
    /// Whether the root's lifecycle, control and MM portal are what the EL1
    /// ring reads on its first entry.
    #[must_use]
    pub fn ring_ready(&self) -> bool {
        self.in_metadata_aperture
            && self.control_visible_tid.is_some()
            && self.page_serves_ring
            && self.portal_carrier == Some(self.carrier)
            && self.portal_is_owner_wait_venue
    }
}

/// Sample [`SoftRootPublication`] from a brought-up soft carrier.
pub fn sample_root_publication<X>(
    engine: &SoftAarch64Engine<X>,
) -> Result<SoftRootPublication, String>
where
    X: ExecuteBlock + Send + 'static,
    X::Error: core::fmt::Debug,
{
    use carrick_el1_abi::{
        EL1_DYNAMIC_METADATA_BASE, EL1_DYNAMIC_METADATA_SIZE, EL1_REGION_BASE, EL1_REGION_SIZE,
        ThreadControlSlot, ThreadLifecyclePage,
    };
    use carrick_hal::GuestVmBackend as _;

    let backend = engine.backend();
    let region = backend
        .host_ptr(EL1_REGION_BASE, EL1_REGION_SIZE as usize)
        .ok_or_else(|| "soft carrier EL1 region is not mapped".to_owned())?;
    // SAFETY: the carrier maps the whole fixed EL1 region; `CurrentTask` and
    // `MmPortalSlots` are aligned ABI records inside it.
    let (task, portal) = unsafe {
        (
            &*region
                .add(EL1_CURRENT_TASKS_OFFSET as usize)
                .cast::<CurrentTask>(),
            &*region
                .add(EL1_MM_PORTAL_OFFSET as usize)
                .cast::<MmPortalSlots>(),
        )
    };
    let task_tid = task.execution.task.load(Ordering::Acquire);
    let lifecycle_page = task.metadata.lifecycle_page.load(Ordering::Acquire);
    let control_slot = task.metadata.control_slot.load(Ordering::Acquire);
    let inside = |gpa: u64, len: usize| {
        gpa >= EL1_DYNAMIC_METADATA_BASE
            && gpa
                .checked_add(len as u64)
                .is_some_and(|end| end <= EL1_DYNAMIC_METADATA_BASE + EL1_DYNAMIC_METADATA_SIZE)
    };
    let page_len = size_of::<ThreadLifecyclePage>();
    let control_len = size_of::<ThreadControlSlot>();
    let in_metadata_aperture =
        inside(lifecycle_page, page_len) && inside(control_slot, control_len);
    let mapped = |gpa: u64, len: usize| {
        in_metadata_aperture
            .then(|| backend.host_ptr(gpa, len))
            .flatten()
    };
    // SAFETY: a mapped, aligned retained control slot.
    let control_visible_tid = mapped(control_slot, control_len)
        .and_then(|ptr| unsafe { &*ptr.cast::<ThreadControlSlot>() }.visible_tid());
    let page_serves_ring = mapped(lifecycle_page, page_len).is_some_and(|ptr| {
        // SAFETY: a mapped, aligned retained lifecycle page.
        let page = unsafe { &*ptr.cast::<ThreadLifecyclePage>() };
        page.serves_threads() || page.serves_sigmask()
    });
    let portal_is_owner_wait_venue = get_el1_region_host_ptr() == region as usize
        && carrick_kernel::dispatch::carrier_loop::OwnerWaitVenue::published().is_ok();
    Ok(SoftRootPublication {
        task_tid,
        lifecycle_page,
        control_slot,
        in_metadata_aperture,
        control_visible_tid,
        page_serves_ring,
        portal_carrier: portal.carrier(),
        carrier: backend.carrier().raw(),
        portal_is_owner_wait_venue,
    })
}

/// Run a single-process AArch64 Linux ELF to exit on the native arm64 [`HostBlockRunner`].
pub fn run_single_process(
    config: &SoftSingleProcessConfig<'_>,
) -> Result<SoftProcessRun<HostBlockRunner>, String> {
    let executor =
        HostBlockRunner::new().map_err(|e| format!("HostBlockRunner::new failed: {e:?}"))?;
    run_single_process_with_executor(config, executor)
}

/// Run a single-process AArch64 Linux ELF to exit over an arbitrary [`ExecuteBlock`].
pub fn run_single_process_with_executor<X>(
    config: &SoftSingleProcessConfig<'_>,
    executor: X,
) -> Result<SoftProcessRun<X>, String>
where
    X: ExecuteBlock + Send + 'static,
    X::Error: core::fmt::Debug,
{
    run_single_process_with_executor_and_setup(config, executor, |_| Ok(()))
}

/// Run a single-process AArch64 Linux ELF to exit over an arbitrary [`ExecuteBlock`],
/// running `setup` after stage-2 and EL1 aperture publication and before the first step.
pub fn run_single_process_with_executor_and_setup<X, F>(
    config: &SoftSingleProcessConfig<'_>,
    executor: X,
    setup: F,
) -> Result<SoftProcessRun<X>, String>
where
    X: ExecuteBlock + Send + 'static,
    X::Error: core::fmt::Debug,
    F: FnOnce(&mut SoftAarch64Engine<X>) -> Result<(), String>,
{
    let carrier_lease = SoftCarrierLease::try_acquire().map_err(|e| e.to_string())?;
    let mut dispatcher = SyscallDispatcher::with_bridges(refusing_soft_bridges());
    if let Some(root_dir) = config.rootfs_dir {
        let rootfs = RootFs::from_immutable_host_dir(root_dir).map_err(|e| {
            format!(
                "RootFs::from_immutable_host_dir({}): {e}",
                root_dir.display()
            )
        })?;
        dispatcher.set_rootfs_layer(rootfs);
    }

    let argv = if config.argv.is_empty() {
        vec![config.executable_path.as_bytes().to_vec()]
    } else {
        config.argv.clone()
    };
    let proc_argv: Vec<String> = argv
        .iter()
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect();
    dispatcher.set_executable_identity(config.executable_path, proc_argv, config.envp.clone());

    let mut image = AddressSpace::load_elf_bytes_with_reader(config.elf_bytes, &|interp_path| {
        dispatcher.read_exec_file(interp_path)
    })
    .map_err(|e| format!("load ELF {}: {e}", config.executable_path))?
    .with_vdso_auxv(false)
    .without_auxv_hwcap(LinuxAarch64Hwcap::all() - GUEST_CPU_PROFILE.hwcap())
    .with_main_file_path(config.executable_path)
    .with_linux_initial_stack_execfn_page_size(
        &argv,
        &config.envp,
        config.executable_path.as_bytes(),
        GUEST_PAGE_BYTES,
    )
    .map_err(|e| format!("build initial stack: {e}"))?;

    let auxv_bytes = patch_stack_auxv_hwcap2(&mut image)?;
    let image = image
        .with_el0_trampoline()
        .and_then(|img| img.with_el1_vectors_mailbox_clock(true, true, El1IrqMode::Gic))
        .and_then(AddressSpace::with_identity_page)
        .and_then(AddressSpace::with_syscall_mailbox_arena)
        .and_then(AddressSpace::with_hvpatch_stage1_page_tables)
        .map_err(|e| format!("finalize soft AArch64 AddressSpace: {e}"))?;

    let root_ctx = dispatcher
        .capture_one_task_context()
        .map_err(|e| format!("capture root KernelContext: {e}"))?;
    dispatcher
        .publish_initial_image_state(
            proc_maps_from_address_space(&image),
            auxv_bytes,
            core_file_mappings_from_address_space(&image),
            boot_private_file_backings(&image),
        )
        .map_err(|e| format!("publish initial image state: {e}"))?;

    let ipc = host_window_backing(&dispatcher);
    let mut engine = SoftAarch64Vmm::bring_up_with_executor(
        &image,
        config.el1_elf_override,
        ipc.clone(),
        executor,
    )
    .map_err(|e| format!("SoftAarch64Vmm bring-up: {e}"))?;

    stamp_identity_page(&mut engine, &dispatcher, &root_ctx)
        .map_err(|e| format!("stamp identity page: {e}"))?;
    engine
        .set_guest_thread_id((1u64 << 32) | 1u64)
        .map_err(|e| format!("stamp guest thread id: {e}"))?;

    let mut aperture_scope = El1ApertureScope {
        el1_host_ptr: 0,
        lifecycle: None,
        zone: None,
        _lease: carrier_lease,
    };
    if let Some(el1_host_ptr) = carrick_hal::GuestVmBackend::host_ptr(
        engine.backend(),
        LINUX_EL1_KERNEL_BASE,
        LINUX_EL1_KERNEL_SIZE as usize,
    ) {
        let ptr = el1_host_ptr as usize;
        record_el1_region_host_ptr(ptr);
        aperture_scope.el1_host_ptr = ptr;
        if let Some(ipc_backing) = &ipc {
            // SAFETY: `engine` retains `ipc_backing` across the entire lifetime of `aperture_scope`.
            let window = unsafe {
                IpcWindow::new(
                    ipc_backing.directory_ptr() as usize,
                    ipc_backing.directory_len(),
                    ipc_backing.pool_ptr() as usize,
                    ipc_backing.pool_len(),
                )
            };
            record_ipc_window_host(window);
            if let Some(map) = ipc_table_map_host() {
                map.publish_window();
            }
        }
        let tid = root_ctx.thread().key().tid.raw();
        let file_table_id = root_ctx.resources().files().id().raw();
        // The root's PID as its own namespace sees it: EL1 admits the root
        // under this PID, and its control slot's TID must agree with it.
        let visible_pid = carrick_kernel::namespace::pid::ns_visible_task_pid(root_ctx.task())
            .ok_or_else(|| "soft root task has no namespace identity".to_owned())?;
        if let Some(one) = NonZeroU64::new(1) {
            publish_current_task(
                0,
                El1TaskId::from_linux_tid(tid),
                SnapshotGeneration::INITIAL,
                file_table_id,
                visible_pid,
                false,
                ContextGeneration::new(one),
            );
        }
        // SAFETY: `el1_host_ptr` points to the live `LINUX_EL1_KERNEL_SIZE` stage-2 window,
        // and `EL1_CURRENT_TASKS_OFFSET` is aligned to `CurrentTask` inside that window.
        let current_task = unsafe {
            &*((el1_host_ptr as usize + EL1_CURRENT_TASKS_OFFSET as usize) as *const CurrentTask)
        };
        current_task.mm.key.store(
            root_ctx.shared().mm().id().raw(),
            std::sync::atomic::Ordering::Relaxed,
        );
        current_task.mm.thread_generation.store(
            root_ctx.thread().key().serial.raw(),
            std::sync::atomic::Ordering::Release,
        );
        {
            // SAFETY: `el1_host_ptr` points to the live `LINUX_EL1_KERNEL_SIZE`
            // stage-2 window, and `EL1_MM_PORTAL_OFFSET` is aligned inside it.
            let portal =
                unsafe { &*((ptr + EL1_MM_PORTAL_OFFSET as usize) as *const MmPortalSlots) };
            // Owner-memory waits, and the root's transfer custody, authenticate
            // against this binding: it is the carrier's one identity, the one
            // its stage-2 core was minted with.
            if !portal.bind_carrier(engine.backend().carrier().raw()) {
                return Err("soft carrier MM portal is already bound".to_owned());
            }
            // Only the MM portal owner writes signal frames here, so EL1
            // accepts a caught handler only for an owner-admitted MM; the
            // root is admitted through the soft transfer custody (#2814).
            if !portal.publish_signal_frame_custody(SignalFrameCustody::AdmittedOwner) {
                return Err("soft carrier signal-frame custody is already published".to_owned());
            }
        }
        aperture_scope.lifecycle = Some(publish_root_lifecycle(&engine, &root_ctx)?);
        // EL1 admits the root against the zone's own PID namespace and
        // issuers: hand the kernel's births to them before the first entry,
        // as the HVF and x86 carriers bind theirs.
        let births = engine
            .vm()
            .birth_serial_source()
            .map_err(|e| format!("soft carrier birth source: {e}"))?;
        root_ctx
            .kernel()
            .bind_initial_birth_source(births)
            .map_err(|e| format!("bind the soft carrier birth source: {e}"))?;
    }

    dispatcher
        .activate_file_authority(root_ctx.resources().files())
        .map_err(|e| format!("activate file authority: {e:?}"))?;
    let wake_slot = Arc::new(SingleCarrierHandbackWait::for_current_thread());
    if aperture_scope.el1_host_ptr != 0 {
        register_handback_publisher(wake_slot.publisher());
        publish_file_table(&root_ctx);
    }

    // The dispatcher (and the kernel graph it holds) leaves before the
    // aperture: its file table withdraws its IPC binding from the mapped
    // region, on every path.
    let outcome = {
        let mut dispatcher = dispatcher;
        let zone = if aperture_scope.el1_host_ptr != 0 {
            SoftZone::start(&mut engine, &dispatcher, &root_ctx)
                .map(|zone| aperture_scope.zone = Some(zone))
        } else {
            Ok(())
        };
        drop(root_ctx);
        let run = zone.and_then(|()| setup(&mut engine)).and_then(|()| {
            drive_single_process_syscalls(
                &mut engine,
                &mut dispatcher,
                &wake_slot,
                aperture_scope.zone.as_mut(),
                config.max_syscalls,
            )
        });
        // The root's executor leaves its slot, and its space retires, before
        // the kernel graph does.
        let closed = aperture_scope
            .zone
            .take()
            .map_or(Ok(()), |mut zone| zone.close());
        run.and_then(|summary| closed.map(|()| summary))
    };
    drop(aperture_scope);
    let summary = outcome?;
    Ok(SoftProcessRun {
        exit_code: summary.exit_code,
        stdout: summary.stdout,
        stderr: summary.stderr,
        syscalls_dispatched: summary.syscalls_dispatched,
        reply_census: summary.reply_census,
        terminating_fault: summary.terminating_fault,
        counted_enosys: summary.counted_enosys,
        vmas: summary.vmas,
        frame_inventory: summary.frame_inventory,
        engine,
    })
}

/// Publish the root thread's lifecycle page and control slot on mailbox slot
/// 0 through the shared carrier lifecycle publisher, mapping each retained
/// slab into this carrier's EL1 dynamic metadata aperture, exactly as an HVF
/// executor does when it loads a task.
fn publish_root_lifecycle<X>(
    engine: &SoftAarch64Engine<X>,
    root: &carrick_kernel::kernel::KernelContext,
) -> Result<CarrierLifecycleMappings<SoftRetainedMetadata>, String>
where
    X: ExecuteBlock + Send + 'static,
    X::Error: core::fmt::Debug,
{
    let mappings = CarrierLifecycleMappings::new(engine.backend().retained_metadata());
    let control = root.thread().control_lease();
    if control.visible_tid().is_none() {
        let tid = carrick_kernel::namespace::pid::ns_visible_thread_tid(root.thread())
            .ok_or_else(|| "soft root thread has no namespace identity".to_owned())?;
        if !control.publish_visible_tid(tid) {
            return Err("soft root thread changed lifecycle identity".to_owned());
        }
    }
    mappings
        .publish(0, control)
        .map_err(|error| format!("soft root lifecycle publication failed: {error:?}"))?;
    Ok(mappings)
}

/// Drive an already-brought-up [`SoftAarch64Engine`] against `dispatcher` until
/// guest exit (`exit` / `exit_group`) or error.
pub fn drive_single_process_engine<X>(
    mut engine: SoftAarch64Engine<X>,
    dispatcher: &mut SyscallDispatcher,
    max_syscalls: usize,
) -> Result<SoftProcessRun<X>, String>
where
    X: ExecuteBlock + Send + 'static,
    X::Error: core::fmt::Debug,
{
    let _carrier_lease = SoftCarrierLease::try_acquire().map_err(|e| e.to_string())?;
    let wake_slot = Arc::new(SingleCarrierHandbackWait::for_current_thread());
    if get_el1_region_host_ptr() != 0 {
        register_handback_publisher(wake_slot.publisher());
    }
    let summary =
        drive_single_process_syscalls(&mut engine, dispatcher, &wake_slot, None, max_syscalls)?;
    Ok(SoftProcessRun {
        exit_code: summary.exit_code,
        stdout: summary.stdout,
        stderr: summary.stderr,
        syscalls_dispatched: summary.syscalls_dispatched,
        reply_census: summary.reply_census,
        terminating_fault: summary.terminating_fault,
        counted_enosys: summary.counted_enosys,
        vmas: summary.vmas,
        frame_inventory: summary.frame_inventory,
        engine,
    })
}

struct SingleProcessSummary {
    exit_code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    syscalls_dispatched: u64,
    reply_census: Hvc2ReplyCensus,
    terminating_fault: Option<SoftFaultTermination>,
    counted_enosys: Vec<(u64, &'static str, u64)>,
    vmas: Vec<VmaSummary>,
    frame_inventory: FrameInventorySnapshot,
}

fn drive_single_process_syscalls<X>(
    engine: &mut SoftAarch64Engine<X>,
    dispatcher: &mut SyscallDispatcher,
    wake_slot: &SingleCarrierHandbackWait,
    mut zone: Option<&mut SoftZone>,
    max_syscalls: usize,
) -> Result<SingleProcessSummary, String>
where
    X: ExecuteBlock + Send + 'static,
    X::Error: core::fmt::Debug,
{
    let reporter = CompatReporter::default();
    let mut refused_by_runner = std::collections::BTreeMap::<u64, u64>::new();
    let mut syscalls_dispatched = 0u64;
    let mut reply_census = Hvc2ReplyCensus::default();
    let mut syscall_turns = 0usize;
    // The frame inventory outlives the exiting task: hold the kernel so the
    // summary samples it after `exit_group` retires the task leader.
    let kernel = Arc::clone(
        dispatcher
            .capture_one_task_context()
            .map_err(|e| format!("capture KernelContext for frame inventory: {e}"))?
            .kernel(),
    );

    while syscall_turns < max_syscalls {
        let pre_ctx = dispatcher
            .capture_one_task_context()
            .map_err(|e| format!("capture KernelContext before run: {e}"))?;
        if let Some(signum) = default_signal_death(dispatcher, &pre_ctx)? {
            return Ok(finish_single_process_summary(
                engine,
                dispatcher,
                &kernel,
                reporter,
                &refused_by_runner,
                128 + signum,
                syscalls_dispatched,
                reply_census,
                None,
            ));
        }
        publish_file_table(&pre_ctx);
        let tid = pre_ctx.thread().key().tid.raw();
        let _ = revalidate_current_task(
            0,
            El1TaskId::from_linux_tid(tid),
            pre_ctx.resources().files().id().raw(),
        );

        let next = match zone.as_deref() {
            Some(zone) => {
                let next = zone.run_guest(pre_ctx.thread(), || engine.next_syscall());
                if zone.settle_exit()? == SoftZoneExit::IdleWithRootParked {
                    if !matches!(next, Ok(None)) {
                        return Err(format!(
                            "EL1's idle exit with the root parked surfaced as {next:?}"
                        ));
                    }
                    syscall_turns += 1;
                    zone.serve_idle_exit(engine, dispatcher)?;
                    continue;
                }
                next
            }
            None => engine.next_syscall(),
        };
        let mut raw = match next {
            Ok(Some(raw)) => {
                syscall_turns += 1;
                raw
            }
            Ok(None) => {
                syscall_turns += 1;
                continue;
            }
            Err(
                err @ TrapError::EL0Fault {
                    syndrome, elr, far, ..
                },
            ) => {
                let access = carrick_aarch64::esr::el0_fault_access(syndrome);
                let fault_kind = carrick_aarch64::esr::el0_fault_kind(syndrome);
                let (resolved, _owner_waits) = resolve_host_first_touch_with_owner_wait(
                    engine,
                    dispatcher,
                    zone.as_deref_mut()
                        .and_then(|zone| zone.participation.as_mut()),
                    &pre_ctx,
                    wake_slot,
                    far,
                    access,
                    fault_kind,
                )?;
                if resolved {
                    continue;
                }
                if let Some((signum, si_code, fault_addr)) =
                    carrick_aarch64::esr::lower_el0_fault(syndrome, elr, far)
                {
                    return Ok(finish_single_process_summary(
                        engine,
                        dispatcher,
                        &kernel,
                        reporter,
                        &refused_by_runner,
                        128 + signum,
                        syscalls_dispatched,
                        reply_census,
                        Some(SoftFaultTermination {
                            signum,
                            si_code,
                            fault_addr,
                            elr,
                            syndrome,
                        }),
                    ));
                }
                return Err(format!("engine next_syscall failed: {err}"));
            }
            // The in-ring root owner retired the process: its terminal
            // status is the run's result, as on the HVF executor.
            Err(TrapError::NativeRootExit { status }) => {
                let (exit_code, _) = carrick_kernel::run_result::native_terminal_exit(status)
                    .ok_or_else(|| {
                        format!("native root exit status {status:?} exceeds the result domain")
                    })?;
                return Ok(finish_single_process_summary(
                    engine,
                    dispatcher,
                    &kernel,
                    reporter,
                    &refused_by_runner,
                    exit_code,
                    syscalls_dispatched,
                    reply_census,
                    None,
                ));
            }
            Err(e) => return Err(format!("engine next_syscall failed: {e}")),
        };

        let served_boundary = settle_el1_boundary_for(0, dispatcher);
        match served_boundary {
            Some(carrick_el1_abi::ServedBoundary::Completed) => {
                syscalls_dispatched += 1;
                reply_census.ring_completed += 1;
                let completed_val = raw.args[0] as i64;
                engine
                    .complete_syscall(completed_val)
                    .map_err(|e| format!("complete EL1-served syscall: {e}"))?;
                continue;
            }
            Some(
                carrick_el1_abi::ServedBoundary::ReplayOriginal { x0 }
                | carrick_el1_abi::ServedBoundary::ForwardOriginal { x0 },
            ) => {
                let orig = get_orig_arg0(0);
                raw.args[0] = if orig != 0 { orig } else { x0 };
            }
            None => {}
        }

        let nr = raw.number.raw();
        if should_refuse_single_process_timer_or_signal_syscall(engine, raw.number, &raw.args) {
            syscalls_dispatched += 1;
            reply_census.runner_refused += 1;
            *refused_by_runner.entry(nr).or_default() += 1;
            engine
                .complete_syscall(carrick_abi::LINUX_ENOSYS.guest_retval())
                .map_err(|e| format!("complete_syscall({nr} refused ENOSYS): {e}"))?;
            continue;
        }

        let kernel_context = dispatcher
            .capture_one_task_context()
            .map_err(|e| format!("capture KernelContext for syscall {nr}: {e}"))?;
        let request = SyscallRequest::from_raw(raw);
        syscalls_dispatched += 1;

        // The root's executor dispatches under its own participation.
        let outcome = match zone
            .as_deref_mut()
            .and_then(|zone| zone.participation.as_mut())
        {
            Some(executor) => dispatcher.dispatch_with_mm_executor(
                executor,
                &kernel_context,
                request,
                &mut *engine,
                &reporter,
            ),
            None => dispatcher.dispatch(&kernel_context, request, &mut *engine, &reporter),
        }
        .map_err(|e| format!("dispatch syscall {nr} failed: {e}"))?;

        match outcome {
            DispatchOutcome::Returned { value } => {
                reply_census.kernel_dispatched += 1;
                engine
                    .complete_syscall(value)
                    .map_err(|e| format!("complete_syscall({}): {e}", raw.number.raw()))?;
            }
            DispatchOutcome::Errno { errno } => {
                reply_census.kernel_dispatched += 1;
                engine
                    .complete_syscall(errno.guest_retval())
                    .map_err(|e| format!("complete_syscall({} errno): {e}", raw.number.raw()))?;
            }
            DispatchOutcome::SchedulerYield => {
                reply_census.kernel_dispatched += 1;
                engine
                    .complete_syscall(0)
                    .map_err(|e| format!("complete_syscall(sched_yield): {e}"))?;
            }
            DispatchOutcome::SetMemoryModel { tso } => {
                engine
                    .set_memory_model(tso)
                    .map_err(|e| format!("set_memory_model: {e}"))?;
                reply_census.kernel_dispatched += 1;
                engine
                    .complete_syscall(0)
                    .map_err(|e| format!("complete_syscall(set_memory_model): {e}"))?;
            }
            DispatchOutcome::MapHostAlias {
                success_retval,
                transaction,
                va,
                ipa,
                len,
                payload,
                backing,
                prot,
                prot_none,
            } => {
                let alias_result = install_host_alias_with_inventory(
                    engine,
                    dispatcher,
                    zone.as_deref_mut()
                        .and_then(|zone| zone.participation.as_mut()),
                    &kernel_context,
                    transaction,
                    va,
                    ipa,
                    len,
                    &payload,
                    backing,
                    prot,
                    prot_none,
                    success_retval,
                )?;
                reply_census.kernel_dispatched += 1;
                engine
                    .complete_syscall(alias_result)
                    .map_err(|e| format!("complete_syscall(MapHostAlias): {e}"))?;
            }
            DispatchOutcome::Exit { code } | DispatchOutcome::ThreadExit { code } => {
                reply_census.kernel_dispatched += 1;
                return Ok(finish_single_process_summary(
                    engine,
                    dispatcher,
                    &kernel,
                    reporter,
                    &refused_by_runner,
                    code,
                    syscalls_dispatched,
                    reply_census,
                    None,
                ));
            }
            DispatchOutcome::SignalDeath { signum } => {
                reply_census.kernel_dispatched += 1;
                return Ok(finish_single_process_summary(
                    engine,
                    dispatcher,
                    &kernel,
                    reporter,
                    &refused_by_runner,
                    128 + signum,
                    syscalls_dispatched,
                    reply_census,
                    None,
                ));
            }
            other => {
                return Err(format!(
                    "unsupported single-process DispatchOutcome {other:?} on syscall {}",
                    raw.number.raw()
                ));
            }
        }
    }

    Err(format!(
        "single-process syscall budget ({max_syscalls}) exhausted after {syscalls_dispatched} dispatches"
    ))
}

/// Take the Linux default action of a kernel signal left deliverable at the
/// guest's return boundary (for example `SIGPIPE` from a write to a widowed
/// pipe). The runner refuses custom handlers, so the disposition is `SIG_DFL`:
/// default-ignore signals and `SIGCONT` (the process is never stopped) are
/// discarded, terminating ones end the process, and a stop signal, which has
/// no job control here, fails the run closed.
fn default_signal_death(
    dispatcher: &SyscallDispatcher,
    context: &carrick_kernel::kernel::KernelContext,
) -> Result<Option<i32>, String> {
    let tid = context.thread().registry_id();
    while let Some(signum) = dispatcher.take_deliverable_pending(context, tid) {
        if is_default_ignore_signal(signum) || signum == carrick_abi::LINUX_SIGCONT {
            continue;
        }
        if is_default_stop_signal(signum) {
            return Err(format!(
                "pending stop signal {signum} has no job control in the single-process soft runner"
            ));
        }
        return Ok(Some(signum));
    }
    Ok(None)
}

#[allow(clippy::too_many_arguments)]
fn finish_single_process_summary<X>(
    engine: &SoftAarch64Engine<X>,
    dispatcher: &mut SyscallDispatcher,
    kernel: &Kernel,
    reporter: CompatReporter,
    refused_by_runner: &std::collections::BTreeMap<u64, u64>,
    exit_code: i32,
    syscalls_dispatched: u64,
    reply_census: Hvc2ReplyCensus,
    terminating_fault: Option<SoftFaultTermination>,
) -> SingleProcessSummary
where
    X: ExecuteBlock + Send + 'static,
    X::Error: core::fmt::Debug,
{
    let frame_inventory = kernel.frame_inventory().snapshot();
    let vmas = dispatcher
        .vma_snapshot_source()
        .snapshot(Instant::now() + Duration::from_secs(1))
        .map_or_else(|_| Vec::new(), |snap| snap.vmas);
    dispatcher.cleanup_sysv_ipc_on_process_exit();
    let mut counted_enosys = sample_el1_counted_enosys(engine);
    let mut merge_count = |nr: u64, count: u64| {
        if let Some(existing) = counted_enosys.iter_mut().find(|(n, _, _)| *n == nr) {
            existing.2 = existing.2.saturating_add(count);
        } else {
            let name = lookup_aarch64(nr).map_or("unknown", |call| call.name);
            counted_enosys.push((nr, name, count));
        }
    };
    let report = reporter.finish();
    for entry in report
        .unhandled_syscalls
        .iter()
        .chain(&report.deferred_syscalls)
    {
        merge_count(entry.number, entry.count);
    }
    for (&nr, &count) in refused_by_runner {
        merge_count(nr, count);
    }
    counted_enosys.sort_by_key(|(nr, _, _)| *nr);
    SingleProcessSummary {
        exit_code,
        stdout: dispatcher.stdout(),
        stderr: dispatcher.stderr(),
        syscalls_dispatched,
        reply_census,
        terminating_fault,
        counted_enosys,
        vmas,
        frame_inventory,
    }
}
