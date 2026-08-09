//! HVF execution with static text patched to enter in-guest syscall islands.

use std::path::{Path, PathBuf};

use crate::dispatch::SyscallDispatcher;
use crate::memory::{AddressSpace, AddressSpaceError};
use crate::runtime::{RunResult, RuntimeError};
use carrick_hal::{SysReg, ThreadedEngine};
use carrick_mem::elf::SegmentPerms;
use info_page::{INFO_PAGE_BASE, InfoPage, info_page_bytes};
use island::passthrough_island_bytes;
use patcher::{ISLAND_STUB_SIZE, PatchError, PatchSite, patch_svc_zero};

mod asid;
mod info_page;
mod island;
mod patcher;
mod process_table;

pub(crate) use process_table::WaitResult;
use process_table::{GuestPid, ProcessTable};

/// Per-kernel binding to one Linux process inside the shared hvpatch VM.
/// Child kernels will carry the same table with a different `pid`.
#[derive(Clone, Debug)]
pub(crate) struct ProcessContext {
    table: std::sync::Arc<ProcessTable>,
    pid: GuestPid,
}

impl ProcessContext {
    pub(crate) fn pid(&self) -> i32 {
        self.pid.raw()
    }

    pub(crate) fn live_process_count(&self) -> usize {
        self.table.live_process_count()
    }

    /// Return the Linux process identity needed to bind a host service record
    /// to this multiplexed address space. A missing record means the process is
    /// already retired, so callers omit rather than forge diagnostic identity.
    pub(crate) fn syscall_trace_identity(&self) -> Option<(i32, u32)> {
        self.table
            .process(self.pid)
            .map(|process| (process.pid().raw(), u32::from(process.asid().raw())))
    }

    /// Register a readiness subscriber for a pidfd targeting this shared VM's
    /// guest process namespace. Returns false only when the pid is neither live
    /// nor a retained zombie.
    pub(crate) fn register_pidfd_watch(
        &self,
        target: i32,
        watch: &std::sync::Arc<crate::dispatch::fd_table::PidfdWatch>,
    ) -> bool {
        GuestPid::from_raw(target)
            .is_some_and(|target| self.table.register_pidfd_watch(target, watch))
    }

    pub(crate) fn process_is_live(&self, target: i32) -> bool {
        GuestPid::from_raw(target).is_some_and(|target| self.table.is_live(target))
    }

    pub(crate) fn allocate_thread_id(
        &self,
    ) -> Result<crate::thread::ThreadId, process_table::ProcessTableError> {
        self.table
            .allocate_task_id()
            .map(crate::thread::ThreadId::from_guest_supplied_tid)
    }

    pub(crate) fn is_child(&self) -> bool {
        self.table
            .process(self.pid)
            .is_some_and(|process| process.parent().is_some())
    }

    pub(crate) fn trace_lifecycle(
        &self,
        phase: carrick_observability::probes::HvpatchGuestLifecyclePhase,
        tid: crate::thread::ThreadId,
        detail: i64,
    ) {
        let Some(process) = self.table.process(self.pid) else {
            tracing::warn!(
                pid = self.pid.raw(),
                ?phase,
                "hvpatch lifecycle record disappeared"
            );
            return;
        };
        let ppid = process.parent().map_or(0, GuestPid::raw);
        let event = carrick_observability::probes::HvpatchGuestLifecycle::new(
            phase,
            process.pid().raw(),
            ppid,
            tid.raw(),
            u32::from(process.asid().raw()),
            detail,
        );
        match event {
            Ok(event) => crate::probes::hvpatch_guest_lifecycle(event),
            Err(error) => {
                tracing::error!(pid = self.pid.raw(), %error, "invalid hvpatch lifecycle event")
            }
        }
        if let Some(bank) = process.bank() {
            let address_space = carrick_observability::probes::HvpatchGuestAddressSpace::new(
                process.pid().raw(),
                u32::from(process.asid().raw()),
                bank.base(),
                bank.size(),
                process.ttbr0(),
            );
            match address_space {
                Ok(event) => crate::probes::hvpatch_guest_address_space(event),
                Err(error) => tracing::error!(
                    pid = self.pid.raw(),
                    %error,
                    "invalid hvpatch address-space event"
                ),
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
        let Some(process) = self.table.process(self.pid) else {
            tracing::warn!(
                pid = self.pid.raw(),
                "hvpatch fault process record disappeared"
            );
            return;
        };
        let event = carrick_observability::probes::HvpatchGuestFault::new(
            syndrome,
            elr,
            far,
            process.pid().raw(),
            tid.raw(),
            u32::from(process.asid().raw()),
        );
        match event {
            Ok(event) => crate::probes::hvpatch_guest_fault(event),
            Err(error) => {
                tracing::error!(pid = self.pid.raw(), %error, "invalid hvpatch fault event")
            }
        }
    }

    pub(crate) fn fork_child(
        &self,
    ) -> Result<(Self, process_table::GuestProcess), process_table::ProcessTableError> {
        let child = self.table.fork_process(self.pid)?;
        Ok((
            Self {
                table: std::sync::Arc::clone(&self.table),
                pid: child.pid(),
            },
            child,
        ))
    }

    pub(crate) fn discard_unstarted_child(&self) -> Result<(), process_table::ProcessTableError> {
        let retired = self.table.exit_process(self.pid)?;
        self.table.acknowledge_tlb_flush(retired)
    }

    pub(crate) fn publish_exit_code(
        &self,
        exit_code: i32,
        tid: crate::thread::ThreadId,
    ) -> Result<(), process_table::ProcessTableError> {
        crate::event_ring::rec_hvpatch_process_exit_begin(self.pid.raw(), tid.raw(), exit_code);
        self.trace_lifecycle(
            carrick_observability::probes::HvpatchGuestLifecyclePhase::ProcessExit,
            tid,
            i64::from(exit_code),
        );
        self.table.publish_exit(self.pid, (exit_code & 0xff) << 8)?;
        crate::event_ring::rec_hvpatch_process_exit_end(self.pid.raw(), tid.raw(), exit_code);
        Ok(())
    }

    pub(crate) fn wait_child(&self, target: Option<i32>, nohang: bool, nowait: bool) -> WaitResult {
        let target = target.and_then(GuestPid::from_raw);
        self.table.wait_child(self.pid, target, nohang, nowait)
    }

    pub(crate) fn process_group(
        &self,
        target: Option<i32>,
    ) -> Result<i32, crate::linux_abi::LinuxErrno> {
        self.table
            .process_group(self.pid, target.and_then(GuestPid::from_raw))
            .map(GuestPid::raw)
            .map_err(identity_operation_errno)
    }

    pub(crate) fn session_id(
        &self,
        target: Option<i32>,
    ) -> Result<i32, crate::linux_abi::LinuxErrno> {
        self.table
            .session_id(self.pid, target.and_then(GuestPid::from_raw))
            .map(GuestPid::raw)
            .map_err(identity_operation_errno)
    }

    pub(crate) fn set_process_group(
        &self,
        target: Option<i32>,
        group: Option<i32>,
    ) -> Result<(), crate::linux_abi::LinuxErrno> {
        self.table
            .set_process_group(
                self.pid,
                target.and_then(GuestPid::from_raw),
                group.and_then(GuestPid::from_raw),
            )
            .map_err(identity_operation_errno)
    }

    pub(crate) fn create_session(&self) -> Result<i32, crate::linux_abi::LinuxErrno> {
        self.table
            .create_session(self.pid)
            .map(GuestPid::raw)
            .map_err(identity_operation_errno)
    }
}

fn identity_operation_errno(
    error: process_table::ProcessTableError,
) -> crate::linux_abi::LinuxErrno {
    match error {
        process_table::ProcessTableError::UnknownProcess(_) => crate::linux_abi::LINUX_ESRCH,
        process_table::ProcessTableError::IdentityPermission => crate::linux_abi::LINUX_EPERM,
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
    let pid = GuestPid::root();
    let table = std::sync::Arc::new(
        ProcessTable::new_root(pid, stage1_root)
            .map_err(|error| RuntimeError::Configuration(error.to_string()))?,
    );
    let root = table.process(pid).ok_or_else(|| {
        RuntimeError::Configuration("hvpatch root process disappeared".to_owned())
    })?;
    engine.configure_process_asid(root.asid().raw())?;
    debug_assert_eq!(root.ttbr0(), engine.get_sys_reg(SysReg::Ttbr0).unwrap_or(0));
    let context = ProcessContext { table, pid };
    context.trace_lifecycle(
        carrick_observability::probes::HvpatchGuestLifecyclePhase::Root,
        crate::thread::ThreadId::from_guest_supplied_tid(pid.raw()),
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
