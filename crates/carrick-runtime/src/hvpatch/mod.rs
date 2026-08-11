//! HVF execution with static text patched to enter in-guest syscall islands.

#[cfg(all(
    feature = "platform-macos",
    target_os = "macos",
    target_arch = "aarch64"
))]
use std::path::{Path, PathBuf};

use crate::dispatch::SyscallDispatcher;
use crate::memory::{AddressSpace, AddressSpaceError};
#[cfg(all(
    feature = "platform-macos",
    target_os = "macos",
    target_arch = "aarch64"
))]
use crate::run_result::RunResult;
use crate::run_result::RuntimeError;
use carrick_hal::{SysReg, ThreadedEngine};
use carrick_mem::elf::SegmentPerms;
use info_page::{INFO_PAGE_BASE, InfoPage, info_page_bytes};
use island::passthrough_island_bytes;
use patcher::{ISLAND_STUB_SIZE, PatchError, PatchSite, patch_svc_zero};

mod asid;
mod bank_resources;
mod banked_mm;
mod info_page;
mod island;
mod patcher;

use bank_resources::BankResources;

#[derive(Clone, Debug)]
pub(crate) struct ProcessContext {
    resources: std::sync::Arc<BankResources>,
    binding: crate::kernel::KernelTaskBinding,
    mm_backend: std::sync::Arc<banked_mm::BankedMmBackend>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ChildExit {
    pid: crate::kernel::TaskId,
    status: i32,
}

impl ChildExit {
    pub(crate) const fn pid(self) -> crate::kernel::TaskId {
        self.pid
    }

    pub(crate) const fn status(self) -> i32 {
        self.status
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessThreadExit {
    Retired,
    LastThread,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WaitResult {
    Exited(ChildExit),
    StillRunning,
    NoChild,
}

impl ProcessContext {
    fn new(
        resources: std::sync::Arc<BankResources>,
        binding: crate::kernel::KernelTaskBinding,
        mm_backend: std::sync::Arc<banked_mm::BankedMmBackend>,
    ) -> Self {
        Self {
            resources,
            binding,
            mm_backend,
        }
    }

    pub(crate) fn pid(&self) -> i32 {
        self.binding.task_id().raw()
    }

    pub(crate) fn task_id(&self) -> crate::kernel::TaskId {
        self.binding.task_id()
    }

    pub(crate) fn task_key(&self) -> crate::kernel::TaskKey {
        self.binding.task_key()
    }

    pub(crate) fn task_binding(&self) -> crate::kernel::KernelTaskBinding {
        self.binding.clone()
    }

    pub(crate) fn kernel_graph(&self) -> &std::sync::Arc<crate::kernel::Kernel> {
        self.binding.kernel()
    }

    pub(crate) fn bank_resources(&self) -> &std::sync::Arc<BankResources> {
        &self.resources
    }

    pub(crate) fn context_for_linux_tid(
        &self,
        tid: crate::kernel::LinuxTid,
    ) -> Result<crate::kernel::KernelContext, crate::kernel::KernelError> {
        self.binding.capture(tid)
    }

    pub(crate) fn published_child_context(
        &self,
        context: &crate::kernel::KernelContext,
        mm_backend: std::sync::Arc<banked_mm::BankedMmBackend>,
    ) -> Self {
        Self::new(
            std::sync::Arc::clone(&self.resources),
            context.task_binding(),
            mm_backend,
        )
    }

    pub(crate) fn live_process_count(&self) -> usize {
        self.kernel_graph().registry().task_count()
    }

    pub(crate) fn mm_binding(&self) -> Option<crate::kernel::MmBinding> {
        Some(crate::kernel::MmBackend::binding(self.mm_backend.as_ref()))
    }

    pub(crate) fn syscall_trace_identity(&self) -> Option<(i32, u32)> {
        let identity = self.kernel_graph().task_identity(self.task_id()).ok()?;
        let binding = self.mm_binding()?;
        Some((identity.task_id.raw(), u32::from(binding.asid.raw())))
    }

    pub(crate) fn register_pidfd_watch(
        &self,
        target: i32,
        watch: &std::sync::Arc<crate::dispatch::fd_table::PidfdWatch>,
    ) -> Option<crate::kernel::TaskKey> {
        let target = crate::kernel::TaskId::from_abi_positive(target).ok()?;
        self.kernel_graph()
            .register_task_exit_subscriber(target, watch)
    }

    pub(crate) fn process_is_live(&self, target: crate::kernel::TaskKey) -> bool {
        self.kernel_graph().task_key_is_live(target)
    }

    pub(crate) fn is_child(&self) -> bool {
        self.kernel_graph()
            .task_identity(self.task_id())
            .is_ok_and(|identity| identity.parent.is_some())
    }

    pub(crate) fn trace_lifecycle(
        &self,
        phase: carrick_observability::probes::HvpatchGuestLifecyclePhase,
        tid: crate::thread::ThreadId,
        detail: i64,
    ) {
        let Ok(identity) = self.kernel_graph().task_identity(self.task_id()) else {
            tracing::warn!(
                pid = self.pid(),
                ?phase,
                "hvpatch lifecycle record disappeared"
            );
            return;
        };
        let Some(binding) = self.mm_binding() else {
            tracing::error!(pid = self.pid(), "hvpatch task has no mm backend");
            return;
        };
        let event = carrick_observability::probes::HvpatchGuestLifecycle::new(
            phase,
            identity.task_id.raw(),
            identity.parent.map_or(0, crate::kernel::TaskId::raw),
            tid.raw(),
            u32::from(binding.asid.raw()),
            detail,
        );
        match event {
            Ok(event) => crate::probes::hvpatch_guest_lifecycle(event),
            Err(error) => {
                tracing::error!(pid = self.pid(), %error, "invalid hvpatch lifecycle event")
            }
        }
        if let Some(bank) = self.resources.bank(self.task_key()) {
            let address_space = carrick_observability::probes::HvpatchGuestAddressSpace::new(
                self.pid(),
                u32::from(binding.asid.raw()),
                bank.base(),
                bank.size(),
                binding.ttbr0.raw(),
            );
            match address_space {
                Ok(event) => crate::probes::hvpatch_guest_address_space(event),
                Err(error) => {
                    tracing::error!(pid = self.pid(), %error, "invalid hvpatch address-space event")
                }
            }
        }
    }

    pub(crate) fn trace_fault(
        &self,
        syndrome: u64,
        elr: u64,
        far: u64,
        tid: crate::thread::ThreadId,
    ) {
        let Some(binding) = self.mm_binding() else {
            tracing::error!(pid = self.pid(), "hvpatch task has no mm backend");
            return;
        };
        let event = carrick_observability::probes::HvpatchGuestFault::new(
            syndrome,
            elr,
            far,
            self.pid(),
            tid.raw(),
            u32::from(binding.asid.raw()),
        );
        match event {
            Ok(event) => crate::probes::hvpatch_guest_fault(event),
            Err(error) => tracing::error!(pid = self.pid(), %error, "invalid hvpatch fault event"),
        }
    }

    pub(crate) fn prepare_exec(
        &self,
        tid: crate::kernel::LinuxTid,
    ) -> Result<crate::kernel::PreparedExec, String> {
        let context = self
            .context_for_linux_tid(tid)
            .map_err(|error| error.to_string())?;
        let backend: std::sync::Arc<dyn crate::kernel::MmBackend> = self.mm_backend.clone();
        self.kernel_graph()
            .prepare_exec_with_mm_backend(&context, backend, None)
            .map_err(|error| error.to_string())
    }

    pub(crate) fn commit_exec(
        &self,
        prepared: crate::kernel::PreparedExec,
        stage1_root: u64,
    ) -> Result<crate::kernel::KernelContext, String> {
        self.resources
            .publish_exec(self.task_key(), stage1_root)
            .map_err(|error| error.to_string())?;
        self.kernel_graph()
            .commit_exec(prepared, None)
            .map_err(|error| error.to_string())
    }

    pub(crate) fn record_process_exit_begin(&self, exit_code: i32, tid: crate::thread::ThreadId) {
        crate::event_ring::rec_hvpatch_process_exit_begin(self.pid(), tid.raw(), exit_code);
        self.trace_lifecycle(
            carrick_observability::probes::HvpatchGuestLifecyclePhase::ProcessExit,
            tid,
            i64::from(exit_code),
        );
    }

    /// Publish Linux lifecycle state before any irreversible backend teardown.
    /// Bank/ASID retirement is deliberately separate so the runtime can order
    /// output and fd finalization first, then publish the zombie/pidfd wake,
    /// then serialize backend retirement under the topology lock.
    pub(crate) fn publish_exit_status(
        &self,
        exit_code: i32,
    ) -> Result<Option<crate::kernel::TaskKey>, String> {
        self.kernel_graph()
            .exit_task_key_eventually(
                self.task_key(),
                crate::kernel::LinuxWaitStatus::from_wait_encoding((exit_code & 0xff) << 8),
                crate::kernel::TaskRusage::default(),
            )
            .map(|zombie| zombie.parent)
            .map_err(|error| error.to_string())
    }

    pub(crate) fn retire_address_space(
        &self,
        exit_code: i32,
        tid: crate::thread::ThreadId,
    ) -> Result<(), String> {
        let retired = self
            .resources
            .retire(self.task_key())
            .map_err(|error| error.to_string())?;
        self.resources
            .acknowledge_tlb_flush(retired)
            .map_err(|error| error.to_string())?;
        crate::event_ring::rec_hvpatch_process_exit_end(self.pid(), tid.raw(), exit_code);
        Ok(())
    }

    pub(crate) fn exit_thread(
        &self,
        tid: crate::kernel::LinuxTid,
    ) -> Result<ProcessThreadExit, crate::kernel::KernelOperationError> {
        let context = match self.context_for_linux_tid(tid) {
            Ok(context) => context,
            Err(crate::kernel::KernelError::UnknownThread(_)) => {
                // Exec replacement may already have retired this exact old
                // thread while its host loop is unwinding.
                return Ok(ProcessThreadExit::Retired);
            }
            Err(_) if !self.kernel_graph().task_is_live(self.task_id()) => {
                return Ok(ProcessThreadExit::Retired);
            }
            Err(_) => {
                return Err(crate::kernel::KernelOperationError::UnknownTask(
                    self.task_id(),
                ));
            }
        };
        loop {
            let observed = self.kernel_graph().reservation_epoch();
            match self.kernel_graph().exit_thread(&context, None) {
                Ok(_) => return Ok(ProcessThreadExit::Retired),
                Err(crate::kernel::KernelOperationError::TaskBusy(_)) => {
                    self.kernel_graph().wait_for_reservation_change(observed);
                }
                Err(crate::kernel::KernelOperationError::LastThreadRequiresTaskExit(_)) => {
                    return Ok(ProcessThreadExit::LastThread);
                }
                Err(crate::kernel::KernelOperationError::UnknownThread(_))
                    if !context.exact_thread_is_live() =>
                {
                    return Ok(ProcessThreadExit::Retired);
                }
                Err(crate::kernel::KernelOperationError::ParentExited)
                | Err(crate::kernel::KernelOperationError::UnknownTask(_))
                    if !self.kernel_graph().task_is_live(self.task_id()) =>
                {
                    return Ok(ProcessThreadExit::Retired);
                }
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) fn wait_child(
        &self,
        target: Option<i32>,
        _nohang: bool,
        nowait: bool,
    ) -> WaitResult {
        let target = target.and_then(|raw| crate::kernel::TaskId::from_abi_positive(raw).ok());
        let mode = if nowait {
            crate::kernel::WaitMode::Observe
        } else {
            crate::kernel::WaitMode::Consume
        };
        loop {
            let observed = self.kernel_graph().reservation_epoch();
            match self.kernel_graph().wait_child(self.task_id(), target, mode) {
                Ok(crate::kernel::WaitOutcome::Exited(zombie)) => {
                    break WaitResult::Exited(ChildExit {
                        pid: zombie.key.id,
                        status: zombie.status.raw(),
                    });
                }
                Ok(crate::kernel::WaitOutcome::StillRunning) => {
                    break WaitResult::StillRunning;
                }
                Ok(crate::kernel::WaitOutcome::NoChild) => {
                    break WaitResult::NoChild;
                }
                Err(crate::kernel::KernelOperationError::TaskBusy(_)) => {
                    self.kernel_graph().wait_for_reservation_change(observed);
                }
                Err(error) => {
                    tracing::error!(pid = self.pid(), %error, "authoritative child wait failed");
                    break WaitResult::NoChild;
                }
            }
        }
    }

    pub(crate) fn wait_child_key(
        &self,
        target: crate::kernel::TaskKey,
        nowait: bool,
    ) -> WaitResult {
        let mode = if nowait {
            crate::kernel::WaitMode::Observe
        } else {
            crate::kernel::WaitMode::Consume
        };
        loop {
            let observed = self.kernel_graph().reservation_epoch();
            match self
                .kernel_graph()
                .wait_child_key(self.task_id(), target, mode)
            {
                Ok(crate::kernel::WaitOutcome::Exited(zombie)) => {
                    break WaitResult::Exited(ChildExit {
                        pid: zombie.key.id,
                        status: zombie.status.raw(),
                    });
                }
                Ok(crate::kernel::WaitOutcome::StillRunning) => {
                    break WaitResult::StillRunning;
                }
                Ok(crate::kernel::WaitOutcome::NoChild) => {
                    break WaitResult::NoChild;
                }
                Err(crate::kernel::KernelOperationError::TaskBusy(_)) => {
                    self.kernel_graph().wait_for_reservation_change(observed);
                }
                Err(error) => {
                    tracing::error!(pid = self.pid(), %error, "authoritative pidfd child wait failed");
                    break WaitResult::NoChild;
                }
            }
        }
    }

    pub(crate) fn process_group(
        &self,
        target: Option<i32>,
    ) -> Result<i32, crate::linux_abi::LinuxErrno> {
        let target = target
            .map(crate::kernel::TaskId::from_abi_positive)
            .transpose()
            .map_err(|_| crate::linux_abi::LINUX_ESRCH)?
            .unwrap_or(self.task_id());
        self.kernel_graph()
            .task_identity(target)
            .map(|identity| identity.process_group.raw())
            .map_err(identity_operation_errno)
    }

    pub(crate) fn session_id(
        &self,
        target: Option<i32>,
    ) -> Result<i32, crate::linux_abi::LinuxErrno> {
        let target = target
            .map(crate::kernel::TaskId::from_abi_positive)
            .transpose()
            .map_err(|_| crate::linux_abi::LINUX_ESRCH)?
            .unwrap_or(self.task_id());
        self.kernel_graph()
            .task_identity(target)
            .map(|identity| identity.session.raw())
            .map_err(identity_operation_errno)
    }

    pub(crate) fn set_process_group(
        &self,
        target: Option<i32>,
        group: Option<i32>,
    ) -> Result<(), crate::linux_abi::LinuxErrno> {
        let target = target
            .map(crate::kernel::TaskId::from_abi_positive)
            .transpose()
            .map_err(|_| crate::linux_abi::LINUX_ESRCH)?;
        let group = group
            .map(crate::kernel::ProcessGroupId::from_abi_positive)
            .transpose()
            .map_err(|_| crate::linux_abi::LINUX_EINVAL)?;
        self.kernel_graph()
            .set_process_group(self.task_id(), target, group)
            .map_err(identity_operation_errno)
    }

    pub(crate) fn create_session(&self) -> Result<i32, crate::linux_abi::LinuxErrno> {
        self.kernel_graph()
            .create_session(self.task_id(), None)
            .map(crate::kernel::SessionId::raw)
            .map_err(identity_operation_errno)
    }
}

fn identity_operation_errno(
    error: crate::kernel::KernelOperationError,
) -> crate::linux_abi::LinuxErrno {
    match error {
        crate::kernel::KernelOperationError::UnknownTask(_) => crate::linux_abi::LINUX_ESRCH,
        crate::kernel::KernelOperationError::IdentityPermission
        | crate::kernel::KernelOperationError::ChildExeced(_) => crate::linux_abi::LINUX_EPERM,
        _ => crate::linux_abi::LINUX_EINVAL,
    }
}

/// Install the root in-process guest's nonzero ASID before its first entry.
/// All other backends return `None` and retain their existing register values.
pub(crate) fn initialize_root_process<E: ThreadedEngine>(
    engine: &mut E,
    dispatcher: &SyscallDispatcher,
) -> Result<Option<ProcessContext>, RuntimeError> {
    if dispatcher.execution_backend() != crate::page_profile::ExecutionBackend::HvPatch {
        return Ok(None);
    }
    const TTBR_ROOT_MASK: u64 = (1_u64 << 48) - 1;
    let stage1_root = engine.get_sys_reg(SysReg::Ttbr0).map_err(|error| {
        RuntimeError::Trap(crate::trap::TrapError::Hypervisor(error.to_string()))
    })? & TTBR_ROOT_MASK;
    let pid = i32::try_from(std::process::id()).map_err(|_| {
        RuntimeError::Configuration("host PID does not fit Linux task identity".to_owned())
    })?;
    let (table, mm_backend) = BankResources::new_root(stage1_root)
        .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
    let table = std::sync::Arc::new(table);
    let root_tid = crate::thread::ThreadId::from_guest_supplied_tid(pid);
    let bootstrap = crate::kernel::RootBootstrap::with_mm_backend(
        pid,
        root_tid,
        mm_backend.clone(),
        "hvpatch-root".to_owned(),
    )
    .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
    let (_kernel, root) = crate::kernel::Kernel::bootstrap_root(bootstrap)
        .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
    table
        .publish_root(root.task().key())
        .map_err(|error| RuntimeError::Configuration(error.to_string()))?;
    let context = ProcessContext::new(table, root.task_binding(), mm_backend);
    let binding = context.mm_binding().ok_or_else(|| {
        RuntimeError::Configuration("hvpatch root mm backend disappeared".to_owned())
    })?;
    engine.configure_process_asid(binding.asid.raw())?;
    debug_assert_eq!(
        binding.ttbr0.raw(),
        engine.get_sys_reg(SysReg::Ttbr0).unwrap_or(0)
    );
    context.trace_lifecycle(
        carrick_observability::probes::HvpatchGuestLifecyclePhase::Root,
        root_tid,
        0,
    );
    dispatcher.bind_hvpatch_process(context.clone());
    Ok(Some(context))
}

const PAGE_SIZE: u64 = 4096;
const STAGE2_PAGE_SIZE: u64 = crate::trap::HVF_PAGE_SIZE;
const SVC_ZERO: u32 = 0xd400_0001;

#[derive(Debug)]
struct PreparedImage {
    image: AddressSpace,
    manifest: Vec<PatchSite>,
    island_bases: Vec<u64>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PrepareError {
    #[error(transparent)]
    AddressSpace(#[from] AddressSpaceError),
    #[error(transparent)]
    Patch(#[from] PatchError),
    #[error("no free island page within B range of executable region 0x{start:x}..0x{end:x}")]
    NoIsland { start: u64, end: u64 },
    #[error("loaded executable region index {0} disappeared during hvpatch preparation")]
    MissingRegion(usize),
}

fn align_up_stage2(value: u64) -> Option<u64> {
    value
        .checked_add(STAGE2_PAGE_SIZE - 1)
        .map(|v| v & !(STAGE2_PAGE_SIZE - 1))
}

fn span_is_free(base: u64, size: u64, ranges: &[(u64, u64)]) -> bool {
    let Some(end) = base.checked_add(size) else {
        return false;
    };
    ranges
        .iter()
        .all(|&(occupied_start, occupied_end)| end <= occupied_start || base >= occupied_end)
}

fn find_island_base(
    region_start: u64,
    region_end: u64,
    svc_sites: &[u64],
    occupied: &[(u64, u64)],
) -> Result<u64, PrepareError> {
    let island_span = u64::try_from(svc_sites.len())
        .ok()
        .and_then(|count| count.checked_mul(ISLAND_STUB_SIZE))
        .and_then(align_up_stage2)
        .ok_or(PrepareError::NoIsland {
            start: region_start,
            end: region_end,
        })?;
    let branches_fit = |base: u64| {
        svc_sites.iter().enumerate().all(|(index, &site)| {
            let Some(stub) = u64::try_from(index)
                .ok()
                .and_then(|index| index.checked_mul(ISLAND_STUB_SIZE))
                .and_then(|offset| base.checked_add(offset))
            else {
                return false;
            };
            let Some(stub_return) = stub.checked_add(4) else {
                return false;
            };
            let Some(site_return) = site.checked_add(4) else {
                return false;
            };
            patcher::encode_b(site, stub).is_ok()
                && patcher::encode_b(stub_return, site_return).is_ok()
        })
    };
    let mut candidate = align_up_stage2(region_end).ok_or(PrepareError::NoIsland {
        start: region_start,
        end: region_end,
    })?;
    loop {
        if branches_fit(candidate) && span_is_free(candidate, island_span, occupied) {
            return Ok(candidate);
        }
        let Some(next) = candidate.checked_add(STAGE2_PAGE_SIZE) else {
            break;
        };
        candidate = next;
        if !branches_fit(candidate) {
            break;
        }
    }

    let Some(mut candidate) = region_start
        .checked_sub(STAGE2_PAGE_SIZE)
        .map(|v| v & !(STAGE2_PAGE_SIZE - 1))
    else {
        return Err(PrepareError::NoIsland {
            start: region_start,
            end: region_end,
        });
    };
    loop {
        if branches_fit(candidate) && span_is_free(candidate, island_span, occupied) {
            return Ok(candidate);
        }
        let Some(previous) = candidate.checked_sub(STAGE2_PAGE_SIZE) else {
            break;
        };
        candidate = previous;
        if !branches_fit(candidate) {
            break;
        }
    }
    Err(PrepareError::NoIsland {
        start: region_start,
        end: region_end,
    })
}

fn prepare_image(mut image: AddressSpace, info: InfoPage) -> Result<PreparedImage, PrepareError> {
    let mut occupied: Vec<(u64, u64)> = Vec::with_capacity(image.regions().len() + 1);
    for region in image.regions() {
        let end = align_up_stage2(region.end).ok_or(PrepareError::NoIsland {
            start: region.start,
            end: region.end,
        })?;
        occupied.push((region.start & !(STAGE2_PAGE_SIZE - 1), end));
    }
    occupied.push((INFO_PAGE_BASE, INFO_PAGE_BASE + STAGE2_PAGE_SIZE));

    let executable_regions: Vec<(usize, u64, u64, Vec<u64>)> = image
        .regions()
        .iter()
        .enumerate()
        .filter(|(_, region)| region.perms.execute)
        .filter_map(|(index, region)| {
            let sites: Vec<u64> = region
                .bytes()
                .chunks_exact(4)
                .enumerate()
                .filter_map(|(word_index, bytes)| {
                    let word = u32::from_le_bytes(bytes.try_into().ok()?);
                    (word == SVC_ZERO).then(|| region.start + (word_index as u64 * 4))
                })
                .collect();
            (!sites.is_empty()).then_some((index, region.start, region.end, sites))
        })
        .collect();

    let mut manifest = Vec::new();
    let mut islands = Vec::new();
    for (region_index, start, end, sites) in executable_regions {
        let island_base = find_island_base(start, end, &sites, &occupied)?;
        let region_bytes = image
            .region_bytes_mut(region_index)
            .ok_or(PrepareError::MissingRegion(region_index))?;
        let region_manifest = patch_svc_zero(region_bytes, start, island_base)?;
        let island_bytes = passthrough_island_bytes(&region_manifest)?;
        let island_len =
            u64::try_from(island_bytes.len()).map_err(|_| PatchError::AddressOverflow)?;
        let mapped_size =
            align_up_stage2(island_len).ok_or(PrepareError::NoIsland { start, end })?;
        occupied.push((island_base, island_base + mapped_size));
        manifest.extend(region_manifest);
        islands.push((island_base, island_bytes));
    }

    let rx = SegmentPerms {
        read: true,
        write: false,
        execute: true,
    };
    let island_bases: Vec<u64> = islands.iter().map(|(base, _)| *base).collect();
    for (island_base, island_bytes) in islands {
        image = image.with_region_bytes(island_base, rx, false, island_bytes)?;
    }
    let info_perms = SegmentPerms {
        read: true,
        write: true,
        execute: false,
    };
    image = image.with_region_bytes(INFO_PAGE_BASE, info_perms, false, info_page_bytes(info))?;

    Ok(PreparedImage {
        image,
        manifest,
        island_bases,
    })
}

/// Preserve the selected backend across `execve`: the mature HVF reload path
/// receives byte-identical guest text, while HvPatch replacement images are
/// patched before the runtime adds its own executable trampoline/vector pages.
pub(crate) fn prepare_exec_image_for_dispatcher(
    image: AddressSpace,
    dispatcher: &SyscallDispatcher,
) -> Result<AddressSpace, PrepareError> {
    if dispatcher.execution_backend() != crate::page_profile::ExecutionBackend::HvPatch {
        return Ok(image);
    }
    Ok(prepare_image(image, InfoPage::default())?.image)
}

#[cfg(all(
    feature = "platform-macos",
    target_os = "macos",
    target_arch = "aarch64"
))]
pub(crate) fn finish_hvpatch_image(
    image: AddressSpace,
    dispatcher: SyscallDispatcher,
    max_traps: usize,
    debug_state_path: Option<&PathBuf>,
) -> Result<RunResult, RuntimeError> {
    // Offline stack attribution needs the exact Carrick Mach-O identity on
    // every file/rootfs/raw-image path before any syscall-service probe can
    // fire. All dyld queries remain inside the USDT closure, so an untraced
    // launch pays only this disabled-probe call.
    crate::probes::host_image_base();
    let prepared = prepare_image(image, InfoPage::default()).map_err(|error| {
        RuntimeError::Unsupported(format!("hvpatch image preparation failed: {error}"))
    })?;
    let _patch_summary = (prepared.manifest.len(), prepared.island_bases.len());
    crate::runtime::finish_and_run_image(prepared.image, dispatcher, max_traps, debug_state_path)
}

#[cfg(all(
    feature = "platform-macos",
    target_os = "macos",
    target_arch = "aarch64"
))]
pub(crate) fn run_static_hvpatch<A, E>(
    path: &Path,
    dispatcher: SyscallDispatcher,
    argv: A,
    env: E,
    max_traps: usize,
    debug_state_path: Option<&PathBuf>,
) -> Result<RunResult, RuntimeError>
where
    A: IntoIterator<Item = String>,
    E: IntoIterator<Item = String>,
{
    let argv: Vec<String> = argv.into_iter().collect();
    let env: Vec<String> = env.into_iter().collect();
    let identity = argv.first().cloned().unwrap_or_else(|| {
        path.canonicalize()
            .unwrap_or_else(|_| path.to_path_buf())
            .to_string_lossy()
            .into_owned()
    });
    dispatcher.set_executable_identity(
        identity,
        argv.clone(),
        env.iter().map(|value| value.as_bytes().to_vec()).collect(),
    );
    let file = std::fs::read(path).map_err(AddressSpaceError::Io)?;
    let image = AddressSpace::load_elf_bytes_with_reader(&file, &|interpreter| {
        dispatcher
            .read_exec_file(interpreter)
            .or_else(|| std::fs::read(interpreter).ok())
    })?
    .with_vdso_auxv(crate::runtime::vdso_enabled_for_debug())
    .with_linux_initial_stack_page_size(argv, env, PAGE_SIZE)?;
    finish_hvpatch_image(image, dispatcher, max_traps, debug_state_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::AddressSpace;
    use carrick_mem::elf::SegmentPerms;
    use info_page::{INFO_PAGE_BASE, InfoPage};

    const RX: SegmentPerms = SegmentPerms {
        read: true,
        write: false,
        execute: true,
    };

    fn text(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    fn authoritative_root() -> (ProcessContext, crate::kernel::KernelContext) {
        let pid = 10_000;
        let (table, backend) = BankResources::new_root(0x4000).unwrap();
        let bootstrap = crate::kernel::RootBootstrap::with_mm_backend(
            pid,
            crate::thread::ThreadId::synthetic_for_tests(pid),
            backend.clone(),
            "adapter-root".to_owned(),
        )
        .unwrap();
        let (_kernel, root) = crate::kernel::Kernel::bootstrap_root(bootstrap).unwrap();
        let table = std::sync::Arc::new(table);
        table.publish_root(root.task().key()).unwrap();
        (
            ProcessContext::new(table, root.task_binding(), backend),
            root,
        )
    }

    fn finalize_test_child(process: &ProcessContext, exit_code: i32, tid: crate::thread::ThreadId) {
        process.record_process_exit_begin(exit_code, tid);
        let _ = process.publish_exit_status(exit_code).unwrap();
        process.retire_address_space(exit_code, tid).unwrap();
    }

    #[test]
    fn child_wait_retries_an_overlapping_exit_reservation() {
        let (parent, root) = authoritative_root();
        let prepared_mm = parent.bank_resources().prepare_child().unwrap();
        let child = parent
            .kernel_graph()
            .reserve_fork(
                &root,
                crate::kernel::ClonePlan::from_flags(carrick_abi::LinuxCloneFlags::empty())
                    .unwrap(),
                "wait-retry-child".to_owned(),
                None,
            )
            .unwrap()
            .prepare_with_mm_backend(
                prepared_mm.backend(),
                crate::thread::ThreadId::synthetic_for_tests(10_001),
            )
            .unwrap()
            .commit()
            .unwrap()
            .into_parts()
            .unwrap()
            .0;
        let child_key = child.task().key();
        let prepared_exit = parent
            .kernel_graph()
            .prepare_task_exit_key(
                child_key,
                crate::kernel::LinuxWaitStatus::from_wait_encoding(7 << 8),
                crate::kernel::TaskRusage::default(),
                None,
            )
            .unwrap();

        let waiting_parent = parent.clone();
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        let handle = std::thread::spawn(move || {
            result_tx
                .send(waiting_parent.wait_child(Some(child_key.id.raw()), true, false))
                .unwrap();
        });
        parent
            .kernel_graph()
            .wait_for_reservation_waiter_for_tests();
        assert!(matches!(
            result_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        prepared_exit.commit().unwrap();
        let WaitResult::Exited(exit) = result_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("reservation release wakes child wait")
        else {
            panic!("child wait did not observe the committed zombie");
        };
        handle.join().unwrap();
        assert_eq!(exit.pid(), child_key.id);
        assert_eq!(exit.status(), 7 << 8);
    }

    #[test]
    fn root_kernel_mm_keeps_the_exact_banked_backend() {
        let (process, root) = authoritative_root();
        let expected: std::sync::Arc<dyn crate::kernel::MmBackend> = process.mm_backend.clone();
        let mm = root.shared().mm();
        let actual = mm.backend().expect("root mm backend");

        assert!(
            std::sync::Arc::ptr_eq(actual, &expected),
            "root bootstrap must not replace the live banked backend with a snapshot"
        );
        assert_eq!(
            crate::kernel::MmBackend::binding(actual.as_ref()),
            process.mm_binding().unwrap()
        );
    }

    #[test]
    fn shared_mm_fork_keeps_kernel_mm_and_vfork_release_authoritative() {
        let (parent, root) = authoritative_root();
        let prepared_mm = parent.bank_resources().prepare_child().unwrap();
        let plan = crate::kernel::ClonePlan::from_flags(
            carrick_abi::LinuxCloneFlags::VM | carrick_abi::LinuxCloneFlags::VFORK,
        )
        .unwrap();
        let child_tid = crate::thread::ThreadId::synthetic_for_tests(10_001);
        let published = parent
            .kernel_graph()
            .reserve_fork(&root, plan, "shared-mm-child".to_owned(), None)
            .unwrap()
            .prepare_shared_mm(child_tid)
            .unwrap()
            .commit()
            .unwrap();
        let (child_context, wait) = published.into_parts().unwrap();
        let wait = wait.expect("vfork parent wait");
        assert!(std::sync::Arc::ptr_eq(
            &root.shared().mm(),
            &child_context.shared().mm()
        ));
        assert_eq!(wait.released_reason(), None);

        let backend = parent
            .bank_resources()
            .publish_child(child_context.task().key(), prepared_mm)
            .unwrap();
        let child = parent.published_child_context(&child_context, backend);
        finalize_test_child(&child, 0, child_tid);
        assert_eq!(
            wait.released_reason(),
            Some(crate::kernel::VforkReleaseReason::Exit)
        );
    }

    #[test]
    fn destructive_exec_releases_the_vfork_parent_gate() {
        let (parent, root) = authoritative_root();
        let prepared_mm = parent.bank_resources().prepare_child().unwrap();
        let stage1_root = prepared_mm.binding().stage1_root.gpa().raw();
        let child_tid = crate::thread::ThreadId::synthetic_for_tests(10_001);
        let published = parent
            .kernel_graph()
            .reserve_fork(
                &root,
                crate::kernel::ClonePlan::from_flags(
                    carrick_abi::LinuxCloneFlags::VM | carrick_abi::LinuxCloneFlags::VFORK,
                )
                .unwrap(),
                "vfork-exec-child".to_owned(),
                None,
            )
            .unwrap()
            .prepare_shared_mm(child_tid)
            .unwrap()
            .commit()
            .unwrap();
        let (child_context, wait) = published.into_parts().unwrap();
        let wait = wait.expect("vfork parent wait");
        let child_id = child_context.task().key().id;
        let backend = parent
            .bank_resources()
            .publish_child(child_context.task().key(), prepared_mm)
            .unwrap();
        let child = parent.published_child_context(&child_context, backend);

        let leader_tid = crate::kernel::LinuxTid::for_task_leader(child_id);
        let prepared_exec = child.prepare_exec(leader_tid).unwrap();
        let committed = child.commit_exec(prepared_exec, stage1_root).unwrap();
        assert_eq!(committed.thread().key().tid, leader_tid);
        assert_eq!(
            wait.released_reason(),
            Some(crate::kernel::VforkReleaseReason::Exec)
        );
        finalize_test_child(&child, 0, child_tid);
    }

    #[test]
    fn nonleader_exec_promotes_the_authoritative_hvpatch_survivor() {
        let (process, root) = authoritative_root();
        let sibling_registry_id = crate::thread::ThreadId::synthetic_for_tests(10_002);
        let sibling = process
            .kernel_graph()
            .reserve_thread_clone(
                &root,
                crate::kernel::ClonePlan::from_flags(
                    carrick_abi::LinuxCloneFlags::THREAD
                        | carrick_abi::LinuxCloneFlags::SIGHAND
                        | carrick_abi::LinuxCloneFlags::VM,
                )
                .unwrap(),
                None,
            )
            .unwrap()
            .prepare(sibling_registry_id)
            .unwrap()
            .commit()
            .unwrap()
            .start_thread()
            .unwrap();
        let sibling_tid = sibling.context().thread().key().tid;
        let stage1_root = process.mm_binding().unwrap().stage1_root.gpa().raw();

        let prepared = process.prepare_exec(sibling_tid).unwrap();
        let committed = process.commit_exec(prepared, stage1_root).unwrap();

        assert_eq!(
            committed.thread().key().tid,
            crate::kernel::LinuxTid::for_task_leader(process.task_id())
        );
        assert_eq!(committed.thread().registry_id(), sibling_registry_id);
        assert!(matches!(
            process.context_for_linux_tid(sibling_tid),
            Err(crate::kernel::KernelError::UnknownThread(_))
        ));
        assert_eq!(
            committed
                .shared()
                .mm()
                .backend()
                .map(|backend| crate::kernel::MmBackend::binding(backend.as_ref())),
            process.mm_binding()
        );
    }

    #[test]
    fn copied_mm_fork_keeps_the_prepared_banked_backend() {
        let (parent, root) = authoritative_root();
        let prepared_mm = parent.bank_resources().prepare_child().unwrap();
        let expected: std::sync::Arc<dyn crate::kernel::MmBackend> = prepared_mm.backend();
        let child = parent
            .kernel_graph()
            .reserve_fork(
                &root,
                crate::kernel::ClonePlan::from_flags(carrick_abi::LinuxCloneFlags::empty())
                    .unwrap(),
                "copied-mm-child".to_owned(),
                None,
            )
            .unwrap()
            .prepare_with_mm_backend(
                prepared_mm.backend(),
                crate::thread::ThreadId::synthetic_for_tests(10_001),
            )
            .unwrap()
            .commit()
            .unwrap()
            .into_parts()
            .unwrap()
            .0;
        let mm = child.shared().mm();
        assert!(std::sync::Arc::ptr_eq(
            mm.backend().expect("copied child mm backend"),
            &expected
        ));
    }

    #[test]
    fn process_adapter_publishes_and_retires_through_kernel_authority() {
        let (parent, root) = authoritative_root();
        let prepared_mm = parent.bank_resources().prepare_child().unwrap();
        let child_tid = crate::thread::ThreadId::synthetic_for_tests(10_001);
        let prepared = parent
            .kernel_graph()
            .reserve_fork(
                &root,
                crate::kernel::ClonePlan::from_flags(carrick_abi::LinuxCloneFlags::empty())
                    .unwrap(),
                "adapter-child".to_owned(),
                None,
            )
            .unwrap()
            .prepare_with_mm_backend(prepared_mm.backend(), child_tid)
            .unwrap();
        let published = prepared.commit().unwrap();
        let (child_context, wait) = published.into_parts().unwrap();
        assert!(wait.is_none());
        let child_id = child_context.task().key().id;
        let backend = parent
            .bank_resources()
            .publish_child(child_context.task().key(), prepared_mm)
            .unwrap();
        let child = parent.published_child_context(&child_context, backend);

        assert_eq!(parent.live_process_count(), 2);
        assert_eq!(child.process_group(None).unwrap(), parent.pid());
        assert!(matches!(
            parent.wait_child(Some(child.pid()), true, false),
            WaitResult::StillRunning
        ));

        finalize_test_child(&child, 23, child_tid);
        assert!(
            parent
                .bank_resources()
                .bank(child_context.task().key())
                .is_none()
        );
        let WaitResult::Exited(exit) = parent.wait_child(Some(child.pid()), true, false) else {
            panic!("kernel zombie was not visible through adapter wait");
        };
        assert_eq!(exit.pid(), child_id);
        assert_eq!(exit.status(), 23 << 8);
        assert_eq!(parent.live_process_count(), 1);
    }

    #[test]
    fn prepares_loaded_text_with_near_island_and_fixed_info_page() {
        let image = AddressSpace::from_segments(
            0x400000,
            [(0x400000, RX, text(&[0xd503_201f, 0xd400_0001]), 0x1000)],
        )
        .unwrap();

        let prepared = prepare_image(image, InfoPage::default()).expect("prepare hvpatch image");

        assert_eq!(prepared.manifest.len(), 1);
        assert_eq!(prepared.manifest[0].guest_va, 0x400004);
        assert_eq!(prepared.island_bases, vec![0x404000]);
        assert!(
            prepared
                .image
                .regions()
                .iter()
                .any(|r| r.start == INFO_PAGE_BASE)
        );
        let code = prepared
            .image
            .regions()
            .iter()
            .find(|r| r.start == 0x400000)
            .unwrap();
        assert_eq!(
            u32::from_le_bytes(code.bytes()[4..8].try_into().unwrap()),
            patcher::encode_b(0x400004, 0x404000).unwrap()
        );
    }

    #[test]
    fn assigns_a_near_island_to_each_distant_executable_region() {
        let image = AddressSpace::from_segments(
            0x400000,
            [
                (0x400000, RX, text(&[0xd400_0001]), 0x1000),
                (0x80_0000_0000, RX, text(&[0xd400_0001]), 0x1000),
            ],
        )
        .unwrap();

        let prepared = prepare_image(image, InfoPage::default()).expect("prepare two images");

        assert_eq!(prepared.manifest.len(), 2);
        assert_eq!(prepared.island_bases, vec![0x404000, 0x80_0000_4000]);
    }

    #[test]
    fn leaves_tpidr_el0_reads_unmodified() {
        let mrs_x0_tpidr_el0 = 0xd53b_d040;
        let image = AddressSpace::from_segments(
            0x400000,
            [(0x400000, RX, text(&[mrs_x0_tpidr_el0]), 0x1000)],
        )
        .unwrap();

        let prepared = prepare_image(image, InfoPage::default()).expect("prepare hvpatch image");
        let code = prepared.image.regions().first().unwrap();
        assert_eq!(
            u32::from_le_bytes(code.bytes()[0..4].try_into().unwrap()),
            mrs_x0_tpidr_el0
        );
        assert!(prepared.manifest.is_empty());
        assert!(prepared.island_bases.is_empty());
    }

    #[test]
    fn every_hvpatch_image_publishes_host_identity_before_preparation() {
        let source = include_str!("mod.rs");
        let function = source
            .split_once("pub(crate) fn finish_hvpatch_image")
            .expect("finish_hvpatch_image definition")
            .1
            .split_once("pub(crate) fn run_static_hvpatch")
            .expect("end of finish_hvpatch_image")
            .0;
        let publish_needle = ["crate::probes::", "host_image_base();"].concat();
        let publish = function
            .find(&publish_needle)
            .expect("hvpatch host-image publication");
        let guest_load = function
            .find("prepare_image(image")
            .expect("hvpatch preparation");

        assert!(
            publish < guest_load,
            "host identity must be available on every image path before service probes"
        );
    }

    #[test]
    fn exec_replacement_is_repatched_only_for_the_hvpatch_backend() {
        let make_image = || {
            AddressSpace::from_segments(0x400000, [(0x400000, RX, text(&[0xd400_0001]), 0x1000)])
                .unwrap()
        };

        let vmm_dispatcher = SyscallDispatcher::new();
        let vmm_image = prepare_exec_image_for_dispatcher(make_image(), &vmm_dispatcher)
            .expect("VMM exec image");
        assert_eq!(
            u32::from_le_bytes(vmm_image.regions()[0].bytes()[0..4].try_into().unwrap()),
            SVC_ZERO,
            "the mature VMM reload must remain byte-identical"
        );

        let mut hvpatch_dispatcher = SyscallDispatcher::new();
        hvpatch_dispatcher.set_execution_backend(crate::page_profile::ExecutionBackend::HvPatch);
        let hvpatch_image = prepare_exec_image_for_dispatcher(make_image(), &hvpatch_dispatcher)
            .expect("HvPatch exec image");
        assert_ne!(
            u32::from_le_bytes(hvpatch_image.regions()[0].bytes()[0..4].try_into().unwrap()),
            SVC_ZERO,
            "an HvPatch exec replacement must not silently fall back to VMM text"
        );
        assert!(
            hvpatch_image
                .regions()
                .iter()
                .any(|region| region.start == INFO_PAGE_BASE)
        );
    }
}
