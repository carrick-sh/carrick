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

use carrick_abi::{LinuxProtFlags, SigBlockMask, SigSet};
use carrick_el1_abi::{
    Counters, CurrentTask, EL1_COUNTERS_BASE, EL1_CURRENT_TASKS_OFFSET, El1TaskId, IpcWindow,
    SnapshotGeneration, clear_current_task_record, clear_el1_region_host_ptr_if,
    get_el1_region_host_ptr, ipc_table_map_host, record_el1_region_host_ptr,
    record_ipc_window_host,
};
use carrick_guest_arch::ContextGeneration;
use carrick_guest_mem::{GuestMemory, MappingSharing};
use carrick_hal::{
    GuestTimerBridge, HostSignalBridge, NO_PENDING_SIGNAL, PosixTimerSpec, SyscallTrap,
    ThreadedEngine, TimerDelivery, TimerSpecNs, TrapError,
};
use carrick_kernel::compat::CompatReporter;
use carrick_kernel::dispatch::{
    CarrierBridges, DispatchOutcome, SyscallDispatcher, SyscallRequest, boot_private_file_backings,
};
use carrick_kernel::el1_delegation::{
    get_orig_arg0, publish_current_task, recall_all_delegated, revalidate_current_task,
    settle_el1_boundary_for,
};
use carrick_kernel::kernel::VmaSummary;
use carrick_kernel::kernel::continuation::ipc::{host_window_backing, publish_file_table};
use carrick_kernel::kernel::exec_transaction::{
    core_file_mappings_from_address_space, proc_maps_from_address_space,
};
use carrick_kernel::kernel::identity_page::stamp_identity_page;
use carrick_mem::linux_abi::{
    LINUX_AT_HWCAP, LINUX_AT_HWCAP2, LINUX_AT_NULL, syscall::lookup_aarch64,
};
use carrick_mem::memory::{AddressSpace, El1IrqMode, LINUX_EL1_KERNEL_BASE, LINUX_EL1_KERNEL_SIZE};
use carrick_softcpu_aarch64::GUEST_CPU_PROFILE;
use carrick_softcpu_aarch64::dispatch::ExecuteBlock;
use carrick_vfs::rootfs::RootFs;

use crate::HostBlockRunner;
use crate::facade::{GUEST_PAGE_BYTES, SoftAarch64Engine, SoftAarch64Vmm};

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

/// Timer and signal syscalls refused with counted `ENOSYS` on the single-process
/// soft-CPU bring-up runner until `#2645` wires guest signal and timer delivery.
const fn is_refused_single_process_timer_or_signal_syscall(nr: u64) -> bool {
    matches!(
        nr,
        74 | 85..=87 | 102 | 103 | 107..=111 | 129..=139 | 240 | 408..=411 | 421 | 424
    )
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
/// completion boundary by whichever responder answered the mailbox.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Hvc2ReplyCensus {
    pub fixture_answers: u64,
    pub production_answers: u64,
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
    /// `(aarch64_nr, syscall_name, count)` refused with `ENOSYS` in EL1 ring or host dispatch.
    pub counted_enosys: Vec<(u64, &'static str, u64)>,
    pub vmas: Vec<VmaSummary>,
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
    _lease: SoftCarrierLease,
}

impl Drop for El1ApertureScope {
    fn drop(&mut self) {
        if self.el1_host_ptr != 0 {
            if get_el1_region_host_ptr() == self.el1_host_ptr {
                recall_all_delegated();
                clear_current_task_record(0);
                record_ipc_window_host(None);
            }
            let _ = clear_el1_region_host_ptr_if(self.el1_host_ptr);
        }
    }
}

/// Patch `AT_HWCAP` and `AT_HWCAP2` in the initial stack region to match
/// [`GUEST_CPU_PROFILE`] so glibc/musl IFUNC resolvers select only instructions
/// admitted by the soft AArch64 CPU profile, returning the updated auxv bytes.
fn patch_stack_auxv_hwcaps(image: &mut AddressSpace) -> Result<Vec<u8>, String> {
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
    let hwcap = GUEST_CPU_PROFILE.hwcap().bits();
    let hwcap2 = GUEST_CPU_PROFILE.hwcap2().bits();
    loop {
        let tag = read_u64_at(bytes, cursor)?;
        let val_off = cursor
            .checked_add(8)
            .ok_or_else(|| "initial stack auxv val offset overflow".to_owned())?;
        if tag == LINUX_AT_HWCAP {
            bytes[val_off..val_off + 8].copy_from_slice(&hwcap.to_le_bytes());
        } else if tag == LINUX_AT_HWCAP2 {
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

/// Sample counted `ENOSYS` refusals from `EL1_COUNTERS_BASE` (`refused` + `venue_refused`).
pub fn sample_el1_counted_enosys<X>(engine: &SoftAarch64Engine<X>) -> Vec<(u64, &'static str, u64)>
where
    X: ExecuteBlock + Send + 'static,
    X::Error: core::fmt::Debug,
{
    use carrick_aarch64::Aarch64Vmm as _;

    let ring_base = EL1_COUNTERS_BASE + offset_of!(Counters, refused) as u64;
    let venue_base = EL1_COUNTERS_BASE + offset_of!(Counters, venue_refused) as u64;
    let Ok(ring_bytes) = engine.backend().read_gpa(ring_base, 512 * 8) else {
        return Vec::new();
    };
    let Ok(venue_bytes) = engine.backend().read_gpa(venue_base, 512 * 8) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for nr in 0..512usize {
        let mut r = [0u8; 8];
        let mut v = [0u8; 8];
        r.copy_from_slice(&ring_bytes[nr * 8..nr * 8 + 8]);
        v.copy_from_slice(&venue_bytes[nr * 8..nr * 8 + 8]);
        let count = u64::from_le_bytes(r).saturating_add(u64::from_le_bytes(v));
        if count != 0 {
            let nr_u64 = nr as u64;
            let name = lookup_aarch64(nr_u64).map_or("unknown", |call| call.name);
            out.push((nr_u64, name, count));
        }
    }
    out
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
    .with_main_file_path(config.executable_path)
    .with_linux_initial_stack_execfn_page_size(
        &argv,
        &config.envp,
        config.executable_path.as_bytes(),
        GUEST_PAGE_BYTES,
    )
    .map_err(|e| format!("build initial stack: {e}"))?;

    let auxv_bytes = patch_stack_auxv_hwcaps(&mut image)?;
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
        if let Some(one) = NonZeroU64::new(1) {
            publish_current_task(
                0,
                El1TaskId::from_linux_tid(tid),
                SnapshotGeneration::INITIAL,
                file_table_id,
                1,
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
    }

    dispatcher
        .activate_file_authority(root_ctx.resources().files())
        .map_err(|e| format!("activate file authority: {e:?}"))?;
    if aperture_scope.el1_host_ptr != 0 {
        publish_file_table(&root_ctx);
    }
    drop(root_ctx);

    let outcome = {
        let mut dispatcher = dispatcher;
        setup(&mut engine).and_then(|()| {
            drive_single_process_syscalls(&mut engine, &mut dispatcher, config.max_syscalls)
        })
    };
    drop(aperture_scope);
    let summary = outcome?;
    Ok(SoftProcessRun {
        exit_code: summary.exit_code,
        stdout: summary.stdout,
        stderr: summary.stderr,
        syscalls_dispatched: summary.syscalls_dispatched,
        reply_census: summary.reply_census,
        counted_enosys: summary.counted_enosys,
        vmas: summary.vmas,
        engine,
    })
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
    let summary = drive_single_process_syscalls(&mut engine, dispatcher, max_syscalls)?;
    Ok(SoftProcessRun {
        exit_code: summary.exit_code,
        stdout: summary.stdout,
        stderr: summary.stderr,
        syscalls_dispatched: summary.syscalls_dispatched,
        reply_census: summary.reply_census,
        counted_enosys: summary.counted_enosys,
        vmas: summary.vmas,
        engine,
    })
}

struct SingleProcessSummary {
    exit_code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    syscalls_dispatched: u64,
    reply_census: Hvc2ReplyCensus,
    counted_enosys: Vec<(u64, &'static str, u64)>,
    vmas: Vec<VmaSummary>,
}

fn prot_allows_access(prot: u64, access: Option<carrick_mmu_core::aarch64::LeafAccess>) -> bool {
    use carrick_mmu_core::aarch64::LeafAccess;
    let flags = LinuxProtFlags::from_bits_truncate(prot);
    match access {
        // Any accessible stage-1 leaf in Carrick's lowering is readable.
        Some(LeafAccess::Read) => {
            flags.intersects(LinuxProtFlags::READ | LinuxProtFlags::WRITE | LinuxProtFlags::EXEC)
        }
        Some(LeafAccess::Write) => flags.contains(LinuxProtFlags::WRITE),
        Some(LeafAccess::Execute) => flags.contains(LinuxProtFlags::EXEC),
        None => false,
    }
}

fn try_resolve_single_process_first_touch<X>(
    engine: &mut SoftAarch64Engine<X>,
    dispatcher: &mut SyscallDispatcher,
    syndrome: u64,
    far: u64,
) -> Result<bool, String>
where
    X: ExecuteBlock + Send + 'static,
    X::Error: core::fmt::Debug,
{
    let Some(access) = carrick_aarch64::esr::el0_fault_access(syndrome) else {
        return Ok(false);
    };
    loop {
        let step = dispatcher
            .with_mm_executor_mutation(
                |disp,
                 mutation|
                 -> Result<
                    Result<bool, carrick_kernel::dispatch::mem::ReservationBusy>,
                    String,
                > {
                    let permit = mutation.host_alias_permit();
                    match disp.resident_fault_plan(&permit, far) {
                        Err(contended) => return Ok(Err(contended)),
                        Ok(Some(plan)) => {
                            let page = plan.page();
                            let prot = plan.prot();
                            if !prot_allows_access(prot, Some(access)) {
                                return Ok(Ok(false));
                            }
                            engine
                                .protect_range(page, GUEST_PAGE_BYTES as usize, prot)
                                .map_err(|e| {
                                    format!(
                                        "first-touch protect_range({page:#x}, prot={prot:#x}): {e}"
                                    )
                                })?;
                            disp.commit_resident_fault(plan);
                            return Ok(Ok(true));
                        }
                        Ok(None) => {}
                    }

                    if matches!(
                        access,
                        carrick_mmu_core::aarch64::LeafAccess::Read
                            | carrick_mmu_core::aarch64::LeafAccess::Write
                    ) && let Some(plan) = disp.mmap_growdown_fault_plan(&permit, far)
                    {
                        let rw = (LinuxProtFlags::READ | LinuxProtFlags::WRITE).bits();
                        engine
                            .protect_range(plan.start(), plan.len(), rw)
                            .map_err(|e| {
                                format!(
                                    "growdown protect_range({:#x}, len={:#x}): {e}",
                                    plan.start(),
                                    plan.len()
                                )
                            })?;
                        disp.commit_mmap_growdown(plan);
                        return Ok(Ok(true));
                    }

                    Ok(Ok(false))
                },
            )
            .map_err(|e| format!("MM executor mutation for first-touch fault: {e}"))??;
        match step {
            Ok(done) => return Ok(done),
            Err(_contended) => {
                // Release the MM mutation lease before yielding and rerunning.
                std::thread::yield_now();
            }
        }
    }
}

fn drive_single_process_syscalls<X>(
    engine: &mut SoftAarch64Engine<X>,
    dispatcher: &mut SyscallDispatcher,
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
    let max_first_touch_faults = max_syscalls.saturating_mul(16).max(65_536);
    let mut first_touch_faults = 0usize;
    let mut syscall_turns = 0usize;

    while syscall_turns < max_syscalls {
        let pre_ctx = dispatcher
            .capture_one_task_context()
            .map_err(|e| format!("capture KernelContext before run: {e}"))?;
        publish_file_table(&pre_ctx);
        let tid = pre_ctx.thread().key().tid.raw();
        let _ = revalidate_current_task(
            0,
            El1TaskId::from_linux_tid(tid),
            pre_ctx.resources().files().id().raw(),
        );

        let mut raw = match engine.next_syscall() {
            Ok(Some(raw)) => {
                syscall_turns += 1;
                raw
            }
            Ok(None) => {
                syscall_turns += 1;
                continue;
            }
            Err(err @ TrapError::EL0Fault { syndrome, far, .. }) => {
                if first_touch_faults < max_first_touch_faults
                    && try_resolve_single_process_first_touch(engine, dispatcher, syndrome, far)?
                {
                    first_touch_faults += 1;
                    continue;
                }
                return Err(format!("engine next_syscall failed: {err}"));
            }
            Err(e) => return Err(format!("engine next_syscall failed: {e}")),
        };

        let served_boundary = settle_el1_boundary_for(0, dispatcher);
        match served_boundary {
            Some(carrick_el1_abi::ServedBoundary::Completed) => {
                syscalls_dispatched += 1;
                reply_census.production_answers += 1;
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
        if is_refused_single_process_timer_or_signal_syscall(nr) {
            syscalls_dispatched += 1;
            reply_census.production_answers += 1;
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

        let outcome = dispatcher
            .dispatch(&kernel_context, request, &mut *engine, &reporter)
            .map_err(|e| format!("dispatch syscall {nr} failed: {e}"))?;

        match outcome {
            DispatchOutcome::Returned { value } => {
                reply_census.production_answers += 1;
                engine
                    .complete_syscall(value)
                    .map_err(|e| format!("complete_syscall({}): {e}", raw.number.raw()))?;
            }
            DispatchOutcome::Errno { errno } => {
                reply_census.production_answers += 1;
                engine
                    .complete_syscall(errno.guest_retval())
                    .map_err(|e| format!("complete_syscall({} errno): {e}", raw.number.raw()))?;
            }
            DispatchOutcome::SchedulerYield => {
                reply_census.production_answers += 1;
                engine
                    .complete_syscall(0)
                    .map_err(|e| format!("complete_syscall(sched_yield): {e}"))?;
            }
            DispatchOutcome::SetMemoryModel { tso } => {
                engine
                    .set_memory_model(tso)
                    .map_err(|e| format!("set_memory_model: {e}"))?;
                reply_census.production_answers += 1;
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
                let shared = backing.is_shared();
                let alias_result = dispatcher
                    .with_mm_executor_mutation(|disp, mutation| -> Result<i64, String> {
                        let permit = mutation.host_alias_permit();
                        let Some(install) = transaction.claim(&permit) else {
                            drop(backing);
                            return Ok(carrick_abi::LINUX_ENOMEM.guest_retval());
                        };
                        engine
                            .map_host_alias(va, ipa, len, &payload, backing)
                            .map_err(|e| {
                                format!("map_host_alias({:#x}, len={len:#x}): {e}", va.raw())
                            })?;
                        let len_usize = usize::try_from(len)
                            .map_err(|_| format!("host alias length {len:#x} exceeds usize"))?;
                        let prot_flags = LinuxProtFlags::from_bits_truncate(prot);
                        let exec = prot_flags.contains(LinuxProtFlags::EXEC);
                        if prot_none || exec {
                            engine
                                .protect_range(
                                    va.raw(),
                                    len_usize,
                                    if prot_none { 0 } else { prot },
                                )
                                .map_err(|e| format!("protect_range({:#x}): {e}", va.raw()))?;
                        }
                        engine.set_mapping_protection_and_sharing(
                            va.raw(),
                            len_usize,
                            prot_none,
                            !prot_flags.contains(LinuxProtFlags::WRITE),
                            if shared {
                                MappingSharing::Shared
                            } else {
                                MappingSharing::Private
                            },
                        );
                        if let Some((bus_start, bus_len)) = install.bus_fault_range() {
                            let bus_len_usize = usize::try_from(bus_len)
                                .map_err(|_| "bus fault length exceeds usize".to_owned())?;
                            engine
                                .protect_range(bus_start, bus_len_usize, 0)
                                .map_err(|e| format!("protect_range bus fault: {e}"))?;
                            engine.set_no_access(bus_start, bus_len_usize, true);
                        }
                        disp.commit_host_alias_install(install)
                            .map_err(|e| format!("commit_host_alias_install: {e:?}"))?;
                        Ok(success_retval)
                    })
                    .map_err(|e| format!("MM executor mutation for MapHostAlias: {e}"))??;
                reply_census.production_answers += 1;
                engine
                    .complete_syscall(alias_result)
                    .map_err(|e| format!("complete_syscall(MapHostAlias): {e}"))?;
            }
            DispatchOutcome::Exit { code } | DispatchOutcome::ThreadExit { code } => {
                reply_census.production_answers += 1;
                return Ok(finish_single_process_summary(
                    engine,
                    dispatcher,
                    reporter,
                    &refused_by_runner,
                    code,
                    syscalls_dispatched,
                    reply_census,
                ));
            }
            DispatchOutcome::SignalDeath { signum } => {
                reply_census.production_answers += 1;
                return Ok(finish_single_process_summary(
                    engine,
                    dispatcher,
                    reporter,
                    &refused_by_runner,
                    128 + signum,
                    syscalls_dispatched,
                    reply_census,
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

fn finish_single_process_summary<X>(
    engine: &SoftAarch64Engine<X>,
    dispatcher: &mut SyscallDispatcher,
    reporter: CompatReporter,
    refused_by_runner: &std::collections::BTreeMap<u64, u64>,
    exit_code: i32,
    syscalls_dispatched: u64,
    reply_census: Hvc2ReplyCensus,
) -> SingleProcessSummary
where
    X: ExecuteBlock + Send + 'static,
    X::Error: core::fmt::Debug,
{
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
        counted_enosys,
        vmas,
    }
}
