//! Strict reader for the HVPatch whole-carrier CPU attribution profile.
//!
//! Decomposes 100% of carrier CPU for one guest run into:
//!   - time in guest (`hv_vcpu_run`)
//!   - host syscall service (by class)
//!   - fault service (by fault class: first touch, COW, frame grant, stage-2)
//!   - EL1 mailbox/grant handling
//!   - executor scheduling/park/unpark
//!   - lock wait
//!
//! The D program emits an END aggregation. Its scalar `sample-population` is
//! authoritative only when every emitted stack count closes exactly to it, and
//! the capture fails closed on zero events or any lossy drop.

use std::collections::{BTreeMap, BTreeSet, HashMap, btree_map::Entry};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::trace_profile::ProfileCaptureStatus;

const PREFIX: &str = "HVPCARRIERATTR";
pub(crate) const PROGRAM_SHA256_PLACEHOLDER: &str =
    "/* CARRICK_HVPCARRIERCPUATTR_PROGRAM_SHA256 */";

/// The capture-bound placeholder slot, substituted by
/// `render_profile_capture_bound` when `--profile-bound-seconds` overrides
/// the shipped 90 s default for long workloads (e.g. `go build`).
pub(crate) const BOUND_PLACEHOLDER: &str = "/* CARRICK_HVPCARRIERCPUATTR_BOUND */";

/// Render the bundled template's immutable digest into the raw-stream header.
pub(crate) const MAX_INSTRUMENTATION_SHARE: f64 = 0.05;

pub(crate) fn render_profile_script(template: &str) -> Result<String> {
    let slots = template.match_indices(PROGRAM_SHA256_PLACEHOLDER).count();
    if slots != 1 {
        bail!(
            "{PREFIX} profile template must contain exactly one program-SHA-256 placeholder, found {slots}"
        );
    }
    Ok(template.replacen(PROGRAM_SHA256_PLACEHOLDER, &program_sha256(), 1))
}

pub(crate) fn program_sha256() -> String {
    format!(
        "{:x}",
        Sha256::digest(
            carrick_runtime::dtrace_consumer::BUNDLED_HVPATCH_CARRIER_CPU_ATTRIBUTION_D.as_bytes(),
        )
    )
}

/// The four distinct fault classes specified for carrier CPU attribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum FaultClass {
    FirstTouch,
    Cow,
    FrameGrant,
    Stage2,
}

impl FaultClass {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::FirstTouch => "first-touch",
            Self::Cow => "cow",
            Self::FrameGrant => "frame-grant",
            Self::Stage2 => "stage-2",
        }
    }
}

/// Primary attribution categories for carrier CPU.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "category", content = "detail", rename_all = "kebab-case")]
pub(crate) enum CpuCategory {
    GuestExecution,
    HostSyscall(String),
    /// Completion of a threaded syscall's return path
    /// (`HvfAarch64Vcpu::complete_syscall_return` and its callees): distinct
    /// from `HostSyscall` dispatch/service because it is carrier-side return
    /// bookkeeping, not the host call itself.
    SyscallReturn,
    FaultService(FaultClass),
    El1Mailbox,
    ExecutorScheduling,
    LockWait,
    Instrumentation,
    Other,
}

/// Find the carrick executable on the host to symbolize stack frames in-process.
pub(crate) fn find_carrick_binary() -> Option<PathBuf> {
    if let Ok(var) = std::env::var("CARRICK_BIN").or_else(|_| std::env::var("CARRICK_BINARY")) {
        let p = PathBuf::from(var);
        if p.exists() {
            return Some(p);
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if exe.file_name().and_then(|s| s.to_str()) == Some("carrick") && exe.exists() {
            return Some(exe);
        }
        let mut search_dirs = Vec::new();
        let mut curr = exe.parent();
        while let Some(dir) = curr {
            search_dirs.push(dir.to_path_buf());
            curr = dir.parent();
        }
        for dir in &search_dirs {
            let rel = dir.join("release/carrick");
            if rel.exists() {
                return Some(rel);
            }
        }
        for dir in &search_dirs {
            let deb = dir.join("debug/carrick");
            if deb.exists() {
                return Some(deb);
            }
            let direct = dir.join("carrick");
            if direct.is_file() && direct.exists() {
                return Some(direct);
            }
        }
    }

    for candidate in [
        "target/release/carrick",
        "target/debug/carrick",
        "../target/release/carrick",
        "../target/debug/carrick",
        "../../target/release/carrick",
        "../../target/debug/carrick",
    ] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return Some(p);
        }
    }

    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let p = dir.join("carrick");
            if p.exists() {
                return Some(p);
            }
        }
    }

    None
}

/// In-process Mach-O and ELF symbol table parser.
#[derive(Clone, Debug, Default)]
pub(crate) struct SymbolTable {
    symbols: Vec<(u64, String)>,
    text_vmaddr: u64,
}

impl SymbolTable {
    pub(crate) fn from_binary(path: &Path) -> Result<Self> {
        let buffer =
            fs::read(path).with_context(|| format!("read binary at {}", path.display()))?;
        Self::parse(&buffer)
    }

    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        match goblin::mach::Mach::parse(bytes) {
            Ok(goblin::mach::Mach::Binary(macho)) => Self::from_macho(&macho),
            Ok(goblin::mach::Mach::Fat(multi)) => {
                for entry in multi.into_iter().flatten() {
                    let goblin::mach::SingleArch::MachO(macho) = entry else {
                        continue;
                    };
                    if macho.header.cputype == goblin::mach::constants::cputype::CPU_TYPE_ARM64
                        || macho.header.cputype == goblin::mach::constants::cputype::CPU_TYPE_X86_64
                    {
                        return Self::from_macho(&macho);
                    }
                }
                for entry in multi.into_iter().flatten() {
                    let goblin::mach::SingleArch::MachO(macho) = entry else {
                        continue;
                    };
                    return Self::from_macho(&macho);
                }
                bail!("no usable architecture in fat Mach-O");
            }
            Err(_) => {
                if let Ok(elf) = goblin::elf::Elf::parse(bytes) {
                    return Self::from_elf(&elf);
                }
                bail!("binary is neither Mach-O nor ELF");
            }
        }
    }

    fn from_macho(macho: &goblin::mach::MachO) -> Result<Self> {
        let mut text_vmaddr = 0x100000000;
        for segment in &macho.segments {
            if matches!(segment.name(), Ok("__TEXT")) {
                text_vmaddr = segment.vmaddr;
                break;
            }
        }

        let mut symbols = Vec::new();
        for (name, nlist) in macho.symbols().flatten() {
            if nlist.is_undefined() || nlist.n_value == 0 {
                continue;
            }
            let clean_name = name.strip_prefix('_').unwrap_or(name);
            let demangled = format!("{:#}", rustc_demangle::demangle(clean_name));
            symbols.push((nlist.n_value, demangled));
        }

        symbols.sort_by_key(|(addr, _)| *addr);
        symbols.dedup_by_key(|(addr, _)| *addr);

        Ok(Self {
            symbols,
            text_vmaddr,
        })
    }

    fn from_elf(elf: &goblin::elf::Elf) -> Result<Self> {
        let mut symbols = Vec::new();
        for sym in &elf.syms {
            if sym.st_value == 0 {
                continue;
            }
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                let demangled = format!("{:#}", rustc_demangle::demangle(name));
                symbols.push((sym.st_value, demangled));
            }
        }
        symbols.sort_by_key(|(addr, _)| *addr);
        symbols.dedup_by_key(|(addr, _)| *addr);
        Ok(Self {
            symbols,
            text_vmaddr: 0,
        })
    }

    pub(crate) fn resolve(&self, text_base: u64, addr: u64) -> Option<String> {
        if self.symbols.is_empty() {
            return None;
        }

        let slide = text_base.saturating_sub(self.text_vmaddr);
        let file_vmaddr = if addr >= slide {
            addr - slide
        } else {
            return None;
        };

        let idx = match self.symbols.binary_search_by_key(&file_vmaddr, |(a, _)| *a) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };

        let (sym_addr, ref sym_name) = self.symbols[idx];
        let offset = file_vmaddr - sym_addr;
        if offset < 1024 * 1024 {
            Some(format!("{sym_name}+0x{offset:x} (in carrick)"))
        } else {
            None
        }
    }
}

/// In-process symbol resolution of hex addresses using binary symbol tables.
pub(crate) fn resolve_addresses(
    binary: &Path,
    text_base: &str,
    addresses: &[&str],
) -> HashMap<String, String> {
    let mut resolved = HashMap::new();
    if addresses.is_empty() {
        return resolved;
    }

    let Ok(sym_table) = SymbolTable::from_binary(binary) else {
        return resolved;
    };

    let base_num = u64::from_str_radix(text_base.trim_start_matches("0x"), 16).unwrap_or(0);
    if base_num == 0 {
        return resolved;
    }

    for addr_str in addresses {
        let trimmed = addr_str.trim();
        let Ok(addr_num) = u64::from_str_radix(trimmed.trim_start_matches("0x"), 16) else {
            continue;
        };
        if let Some(sym) = sym_table.resolve(base_num, addr_num) {
            resolved.insert(trimmed.to_owned(), sym);
        }
    }

    resolved
}

/// Classify a single frame string into an attribution category if it matches.
pub(crate) fn classify_frame(frame: &str) -> Option<CpuCategory> {
    // 1. Instrumentation: USDT probes, DTrace tracing hooks, and fasttrap probes
    if frame.contains("carrick_observability::probes")
        || frame.contains("probes::real::")
        || frame.contains("crate::probes::")
        || frame.contains("___dtrace_")
        || frame.contains("dtrace_probe")
        || frame.contains("dtrace_")
        || frame.contains("usdt::")
        || frame.contains("fasttrap")
    {
        return Some(CpuCategory::Instrumentation);
    }

    // 2. Lock wait / contention primitives
    if frame.contains("psynch_cvwait")
        || frame.contains("psynch_mutexwait")
        || frame.contains("__ulock_wait")
        || frame.contains("hw_lock_lock_contended")
        || frame.contains("lck_mtx_lock")
        || frame.contains("lck_rw_lock_shared")
        || frame.contains("RawMutex::lock_slow")
        || frame.contains("parking_lot::raw_mutex")
        || frame.contains("Condvar::wait")
        || frame.contains("wait_until_internal")
        || frame.contains("wait_timeout")
    {
        return Some(CpuCategory::LockWait);
    }

    // 3. Executor scheduling / park / unpark
    if frame.contains("idle_condvar")
        || frame.contains("park_spare")
        || frame.contains("RunQueue::")
        || frame.contains("Scheduler::")
        || frame.contains("take_row_bound")
        || frame.contains("run_worker")
        || frame.contains("mn_admit")
        || frame.contains("mn_reclaim")
        || frame.contains("executor_claim")
        || frame.contains("scheduler_wake")
        || frame.contains("lease_settle")
        || frame.contains("vtimer")
        || frame.contains("run_executor_loop")
        || frame.contains("executor_worker")
        || frame.contains("ExecutorRegistration")
        || frame.contains("destroy_raw_vcpu")
        || frame.contains("executor::")
        || frame.contains("::schedule")
    {
        return Some(CpuCategory::ExecutorScheduling);
    }

    // 4. Guest execution (hv_vcpu_run, vcpu execution loop)
    if frame.contains("hv_vcpu_run")
        || frame.contains("Vcpu::run")
        || frame.contains("HvfAarch64Vcpu::run")
        || frame.contains("HvfInner::run_to_exit")
        || frame.contains("run_to_exit")
        || frame.contains("timed_run")
        || frame.contains("run_until_syscall")
        || frame.contains("get_sys_reg")
    {
        return Some(CpuCategory::GuestExecution);
    }

    // 5. Fault service by fault class
    if frame.contains("commit_resident_frame_grant")
        || frame.contains("prepare_el1_frame_grant")
        || frame.contains("publish_el1_frame_grant_on_host")
        || frame.contains("resident_frame_grant_plan")
        || frame.contains("hvpatch_el1_frame_grant_plan")
        || frame.contains("handle_frame_grant")
    {
        return Some(CpuCategory::FaultService(FaultClass::FrameGrant));
    }
    if frame.contains("resolve_frame_cow_fault")
        || frame.contains("note_cow_resolution")
        || frame.contains("cow_engine")
        || frame.contains("Stage1CowFault")
        || frame.contains("frame_cow")
        || frame.contains("handle_cow_fault")
    {
        return Some(CpuCategory::FaultService(FaultClass::Cow));
    }
    if frame.contains("inventory_hv_vm_map_replay")
        || frame.contains("map_host_alias")
        || frame.contains("lookup_shared_alias")
        || frame.contains("global_frame_stage2")
        || frame.contains("stage2_alias_map")
        || frame.contains("hv_vm_map")
    {
        return Some(CpuCategory::FaultService(FaultClass::Stage2));
    }
    if frame.contains("commit_resident_fault")
        || frame.contains("resident_fault_plan")
        || frame.contains("apply_first_touch")
        || frame.contains("commit_mmap_growdown")
        || frame.contains("mmap_growdown_fault_plan")
        || frame.contains("resolve_stale_stage1_fault")
        || frame.contains("handle_user_abort")
        || frame.contains("arm_fast_fault")
        || frame.contains("vm_fault_internal")
        || frame.contains("vm_fault")
        || frame.contains("vcpu_fault")
        || frame.contains("handle_guest_page_fault")
    {
        return Some(CpuCategory::FaultService(FaultClass::FirstTouch));
    }

    // 6. EL1 Mailbox / grant request handling
    if frame.contains("claim_frame_grant_request")
        || frame.contains("complete_grant")
        || frame.contains("frame_grant_mailbox")
        || frame.contains("publish_frame_grant_refusal")
        || frame.contains("cancel_frame_grant_request")
        || frame.contains("hvf_syscall_transport")
        || frame.contains("handle_el1_mailbox")
    {
        return Some(CpuCategory::El1Mailbox);
    }

    // 7. Host syscall service by class
    if frame.contains("openat")
        || frame.contains("open_at_path")
        || frame.contains("sys_openat")
        || frame.contains("open_for_dispatch")
        || frame.contains("fs::open")
    {
        return Some(CpuCategory::HostSyscall("openat".to_owned()));
    }
    if frame.contains("sys_mmap")
        || frame.contains("handle_mmap")
        || frame.contains("mmap_pgoff")
        || frame.contains("dispatch::mem::mmap")
    {
        return Some(CpuCategory::HostSyscall("mmap".to_owned()));
    }
    if frame.contains("sys_munmap") || frame.contains("munmap") {
        return Some(CpuCategory::HostSyscall("munmap".to_owned()));
    }
    if frame.contains("sys_brk")
        || frame.contains("handle_brk")
        || frame.contains("dispatch::mem::brk")
    {
        return Some(CpuCategory::HostSyscall("brk".to_owned()));
    }
    if frame.contains("sys_write")
        || frame.contains("writev")
        || frame.contains("pwrite64")
        || frame.contains("::write::")
        || frame.contains("::write(")
        || frame.contains("dispatch::fs::write")
    {
        return Some(CpuCategory::HostSyscall("write".to_owned()));
    }
    if frame.contains("sys_read")
        || frame.contains("readv")
        || frame.contains("pread64")
        || frame.contains("::read::")
        || frame.contains("::read(")
        || frame.contains("dispatch::fs::read")
    {
        return Some(CpuCategory::HostSyscall("read".to_owned()));
    }
    if frame.contains("newfstatat")
        || frame.contains("sys_newfstatat")
        || frame.contains("fstat")
        || frame.contains("statx")
        || frame.contains("fs::stat")
    {
        return Some(CpuCategory::HostSyscall("newfstatat".to_owned()));
    }
    if frame.contains("sys_futex")
        || frame.contains("futex_route")
        || frame.contains("::futex")
        || frame.contains("dispatch::futex")
    {
        return Some(CpuCategory::HostSyscall("futex".to_owned()));
    }
    if frame.contains("sys_close")
        || frame.contains("close_dup")
        || frame.contains("::close::")
        || frame.contains("::close(")
        || frame.contains("dispatch::fs::close")
    {
        return Some(CpuCategory::HostSyscall("close".to_owned()));
    }
    if frame.contains("renameat")
        || frame.contains("sys_renameat")
        || frame.contains("rename_overlay_entry")
        || frame.contains("do_renameat")
    {
        return Some(CpuCategory::HostSyscall("renameat".to_owned()));
    }
    if frame.contains("unlinkat")
        || frame.contains("sys_unlinkat")
        || frame.contains("do_unlinkat")
        || frame.contains("remove_dir_all")
    {
        return Some(CpuCategory::HostSyscall("unlinkat".to_owned()));
    }
    if frame.contains("getdents64") || frame.contains("sys_getdents64") {
        return Some(CpuCategory::HostSyscall("getdents64".to_owned()));
    }
    if frame.contains("sys_execve") || frame.contains("execve") {
        return Some(CpuCategory::HostSyscall("execve".to_owned()));
    }
    if frame.contains("sys_clone")
        || frame.contains("clone_task")
        || frame.contains("dispatch::clone")
    {
        return Some(CpuCategory::HostSyscall("clone".to_owned()));
    }
    if frame.contains("pipe2")
        || frame.contains("sys_pipe2")
        || frame.contains("dispatch::fs::pipe")
    {
        return Some(CpuCategory::HostSyscall("pipe".to_owned()));
    }
    if frame.contains("sys_fcntl")
        || frame.contains("fcntl")
        || frame.contains("dispatch::fs::fcntl")
    {
        return Some(CpuCategory::HostSyscall("fcntl".to_owned()));
    }
    if frame.contains("sys_ppoll")
        || frame.contains("ppoll")
        || frame.contains("epoll_pwait")
        || frame.contains("epoll_ctl")
    {
        return Some(CpuCategory::HostSyscall("poll".to_owned()));
    }
    if frame.contains("sys_socket")
        || frame.contains("sys_bind")
        || frame.contains("sys_connect")
        || frame.contains("sys_sendto")
        || frame.contains("sys_recvfrom")
        || frame.contains("::socket::")
        || frame.contains("::socket(")
        || frame.contains("dispatch::net")
    {
        return Some(CpuCategory::HostSyscall("socket".to_owned()));
    }
    if frame.contains("complete_syscall_return") || frame.contains("complete_returned") {
        return Some(CpuCategory::SyscallReturn);
    }
    if frame.contains("service_outcome")
        || frame.contains("service_threaded_syscall")
        || frame.contains("redispatch_threaded_syscall")
        || frame.contains("dispatch_threaded")
        || frame.contains("dispatch_normalized")
        || frame.contains("SyscallDispatcher")
        || frame.contains("dispatch_syscall")
        || frame.contains("syscall_service")
        || frame.contains("next_syscall")
    {
        return Some(CpuCategory::HostSyscall("dispatch".to_owned()));
    }

    None
}

/// Classify a user stack (frames ordered from leaf to root) into one of the
/// attribution categories.
pub(crate) fn classify_stack(frames: &[&str]) -> CpuCategory {
    // Walk leaf-to-root and take the first matched category.
    for frame in frames {
        if let Some(category) = classify_frame(frame) {
            // When a thread is idle waiting in the scheduler's run queue, its leaf frame
            // is `wait_until_internal` or `psynch_cvwait` (LockWait). If an outer caller
            // on the stack is idle parking in the run queue, attribute to ExecutorScheduling
            // rather than lock contention.
            if category == CpuCategory::LockWait {
                let is_park = frames.iter().any(|f| {
                    f.contains("idle_condvar")
                        || f.contains("park_spare")
                        || f.contains("RunQueue::park_spare")
                });
                if is_park {
                    return CpuCategory::ExecutorScheduling;
                }
            }
            return category;
        }
    }

    CpuCategory::Other
}

/// Machine-readable summary of HVPatch carrier CPU attribution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct HvpatchCarrierCpuAttributionSummary {
    pub(crate) sample_population: u64,
    pub(crate) stack_population: u64,
    pub(crate) stack_count: u64,
    pub(crate) program_sha256: String,
    pub(crate) image_text_base: String,
    pub(crate) guest_execution_samples: u64,
    pub(crate) host_syscall_samples: u64,
    pub(crate) syscall_return_samples: u64,
    pub(crate) fault_service_samples: u64,
    pub(crate) el1_mailbox_samples: u64,
    pub(crate) executor_scheduling_samples: u64,
    pub(crate) lock_wait_samples: u64,
    pub(crate) instrumentation_samples: u64,
    pub(crate) other_samples: u64,
    pub(crate) syscall_classes: BTreeMap<String, u64>,
    pub(crate) fault_classes: BTreeMap<String, u64>,
    pub(crate) usdt_metrics: BTreeMap<String, u64>,
    #[serde(skip)]
    pub(crate) raw: String,
}

impl HvpatchCarrierCpuAttributionSummary {
    pub(crate) fn from_path(path: &Path, status: ProfileCaptureStatus) -> Result<Self> {
        let raw = fs::read_to_string(path).with_context(|| {
            format!("read HVPatch carrier attribution stream {}", path.display())
        })?;
        Self::from_raw(raw, status)
    }

    pub(crate) fn from_raw(raw: String, status: ProfileCaptureStatus) -> Result<Self> {
        require_lossless(status)?;

        let mut summary = None;
        let mut header = None;
        let mut population = None;
        let mut image_text_base = None;
        let mut section_seen = false;
        let mut stack_frames = Vec::new();
        let mut stack_count = 0_u64;
        let mut stack_population = 0_u64;
        let mut raw_stacks = Vec::new();

        let mut guest_execution_samples = 0_u64;
        let mut host_syscall_samples = 0_u64;
        let mut syscall_return_samples = 0_u64;
        let mut fault_service_samples = 0_u64;
        let mut el1_mailbox_samples = 0_u64;
        let mut executor_scheduling_samples = 0_u64;
        let mut lock_wait_samples = 0_u64;
        let mut instrumentation_samples = 0_u64;
        let mut other_samples = 0_u64;

        let mut syscall_classes = BTreeMap::new();
        let mut fault_classes = BTreeMap::new();
        let mut usdt_metrics = BTreeMap::new();

        for line in raw.lines() {
            if !section_seen {
                if line.is_empty() {
                    continue;
                }
                let record = Record::parse(line)?;
                match record.tag.as_str() {
                    "header" => {
                        record.exact_fields(&["program_sha256"])?;
                        if header
                            .replace(record.value("program_sha256")?.to_owned())
                            .is_some()
                        {
                            bail!("duplicate {PREFIX} header");
                        }
                    }
                    "summary" => {
                        if summary.replace(Summary::parse(&record)?).is_some() {
                            bail!("duplicate {PREFIX} summary");
                        }
                    }
                    "sample-population" => {
                        record.exact_fields(&["count"])?;
                        if population.replace(record.u64("count")?).is_some() {
                            bail!("duplicate {PREFIX} sample-population");
                        }
                    }
                    "image" => {
                        record.exact_fields(&["host_pid", "text_base", "slide"])?;
                        if image_text_base
                            .replace(record.value("text_base")?.to_owned())
                            .is_some()
                        {
                            bail!("duplicate {PREFIX} image");
                        }
                    }
                    "section=usdt-metrics" => {
                        record.exact_fields(&[])?;
                    }
                    "usdt" => {
                        record.exact_fields(&["metric", "count"])?;
                        let metric = record.value("metric")?.to_owned();
                        let count = record.u64("count")?;
                        usdt_metrics.insert(metric, count);
                    }
                    "section=user-stacks" => {
                        record.exact_fields(&[])?;
                        section_seen = true;
                    }
                    other => bail!("unknown {PREFIX} record tag {other:?}"),
                }
                continue;
            }

            if line.starts_with(PREFIX) {
                bail!("{PREFIX} record appears after the user-stacks section");
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if is_canonical_u64(trimmed) {
                if stack_frames.is_empty() {
                    bail!("{PREFIX} stack count has no preceding user-stack frames");
                }
                let count = parse_u64(trimmed, "stack count")?;
                if count == 0 {
                    bail!("{PREFIX} emitted a zero-count user stack");
                }
                stack_population = stack_population
                    .checked_add(count)
                    .ok_or_else(|| anyhow!("{PREFIX} stack count overflow"))?;
                stack_count = stack_count
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("{PREFIX} stack cardinality overflow"))?;
                raw_stacks.push((std::mem::take(&mut stack_frames), count));
            } else {
                stack_frames.push(trimmed.to_owned());
            }
        }

        let header = header.ok_or_else(|| anyhow!("{PREFIX} stream has no header"))?;
        if header != program_sha256() {
            bail!(
                "{PREFIX} header program_sha256 {header} does not name the bundled carrier attribution program ({})",
                program_sha256()
            );
        }
        let summary = summary.ok_or_else(|| anyhow!("{PREFIX} stream has no summary"))?;
        let sample_population =
            population.ok_or_else(|| anyhow!("{PREFIX} stream has no sample-population"))?;
        if !section_seen {
            bail!("{PREFIX} stream has no user-stacks section");
        }
        if !stack_frames.is_empty() {
            bail!("{PREFIX} user-stack aggregation ends without its count");
        }
        summary.validate()?;
        if sample_population == 0 || stack_count == 0 {
            bail!("{PREFIX} captured no user-stack population");
        }
        if stack_population != sample_population {
            bail!(
                "{PREFIX} stack-count closure failed: sample-population={sample_population}, user-stack-counts={stack_population}"
            );
        }

        let image_text_base = image_text_base
            .ok_or_else(|| anyhow!("{PREFIX} stream has no carrier image record"))?;

        // Batch resolve raw hex addresses if carrick binary and /usr/bin/atos are available.
        let mut sym_map = HashMap::new();
        let mut unique_addrs = BTreeSet::new();
        for (stack, _) in &raw_stacks {
            for frame in stack {
                let trimmed = frame.trim();
                if trimmed.starts_with("0x") {
                    unique_addrs.insert(trimmed);
                }
            }
        }
        if let Some(binary) = (!unique_addrs.is_empty())
            .then(find_carrick_binary)
            .flatten()
        {
            let addrs: Vec<&str> = unique_addrs.into_iter().collect();
            sym_map = resolve_addresses(&binary, &image_text_base, &addrs);
        }

        for (stack, count) in raw_stacks {
            let resolved_frames: Vec<&str> = stack
                .iter()
                .map(|f| {
                    let trimmed = f.trim();
                    sym_map.get(trimmed).map(String::as_str).unwrap_or(trimmed)
                })
                .collect();
            let category = classify_stack(&resolved_frames);
            match category {
                CpuCategory::GuestExecution => {
                    guest_execution_samples = guest_execution_samples
                        .checked_add(count)
                        .ok_or_else(|| anyhow!("guest execution overflow"))?;
                }
                CpuCategory::HostSyscall(class) => {
                    host_syscall_samples = host_syscall_samples
                        .checked_add(count)
                        .ok_or_else(|| anyhow!("host syscall overflow"))?;
                    *syscall_classes.entry(class).or_insert(0_u64) += count;
                }
                CpuCategory::SyscallReturn => {
                    syscall_return_samples = syscall_return_samples
                        .checked_add(count)
                        .ok_or_else(|| anyhow!("syscall return overflow"))?;
                }
                CpuCategory::FaultService(class) => {
                    fault_service_samples = fault_service_samples
                        .checked_add(count)
                        .ok_or_else(|| anyhow!("fault service overflow"))?;
                    *fault_classes
                        .entry(class.as_str().to_owned())
                        .or_insert(0_u64) += count;
                }
                CpuCategory::El1Mailbox => {
                    el1_mailbox_samples = el1_mailbox_samples
                        .checked_add(count)
                        .ok_or_else(|| anyhow!("el1 mailbox overflow"))?;
                }
                CpuCategory::ExecutorScheduling => {
                    executor_scheduling_samples = executor_scheduling_samples
                        .checked_add(count)
                        .ok_or_else(|| anyhow!("executor scheduling overflow"))?;
                }
                CpuCategory::LockWait => {
                    lock_wait_samples = lock_wait_samples
                        .checked_add(count)
                        .ok_or_else(|| anyhow!("lock wait overflow"))?;
                }
                CpuCategory::Instrumentation => {
                    instrumentation_samples = instrumentation_samples
                        .checked_add(count)
                        .ok_or_else(|| anyhow!("instrumentation overflow"))?;
                }
                CpuCategory::Other => {
                    other_samples = other_samples
                        .checked_add(count)
                        .ok_or_else(|| anyhow!("other samples overflow"))?;
                }
            }
        }

        if other_samples == sample_population && sample_population > 0 {
            bail!(
                "{PREFIX} attribution failed closed: 100% of samples ({sample_population}) across {stack_count} distinct stacks were unclassified 'other'; carrier symbols were unresolved or unclassified"
            );
        }

        let inst_share = share(instrumentation_samples, sample_population);
        if inst_share > MAX_INSTRUMENTATION_SHARE && sample_population > 0 {
            bail!(
                "{PREFIX} attribution failed closed: instrumentation samples ({instrumentation_samples} of {sample_population}, {:>4.1}%) exceeded maximum allowed threshold ({:>4.1}%); probe trampolines contaminated profile",
                inst_share * 100.0,
                MAX_INSTRUMENTATION_SHARE * 100.0,
            );
        }

        Ok(Self {
            sample_population,
            stack_population,
            stack_count,
            program_sha256: program_sha256(),
            image_text_base,
            guest_execution_samples,
            host_syscall_samples,
            syscall_return_samples,
            fault_service_samples,
            el1_mailbox_samples,
            executor_scheduling_samples,
            lock_wait_samples,
            instrumentation_samples,
            other_samples,
            syscall_classes,
            fault_classes,
            usdt_metrics,
            raw,
        })
    }

    pub(crate) fn guest_execution_share(&self) -> f64 {
        share(self.guest_execution_samples, self.sample_population)
    }

    pub(crate) fn host_syscall_share(&self) -> f64 {
        share(self.host_syscall_samples, self.sample_population)
    }

    pub(crate) fn syscall_return_share(&self) -> f64 {
        share(self.syscall_return_samples, self.sample_population)
    }

    pub(crate) fn fault_service_share(&self) -> f64 {
        share(self.fault_service_samples, self.sample_population)
    }

    pub(crate) fn el1_mailbox_share(&self) -> f64 {
        share(self.el1_mailbox_samples, self.sample_population)
    }

    pub(crate) fn executor_scheduling_share(&self) -> f64 {
        share(self.executor_scheduling_samples, self.sample_population)
    }

    pub(crate) fn lock_wait_share(&self) -> f64 {
        share(self.lock_wait_samples, self.sample_population)
    }

    pub(crate) fn instrumentation_share(&self) -> f64 {
        share(self.instrumentation_samples, self.sample_population)
    }

    pub(crate) fn other_share(&self) -> f64 {
        share(self.other_samples, self.sample_population)
    }

    pub(crate) fn render_human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "HVPatch carrier CPU attribution: total_samples={}, distinct_stacks={}, image_text_base={}\n",
            self.sample_population, self.stack_count, self.image_text_base
        ));
        out.push_str(&format!(
            "  guest_execution:     {:>8} ({:>5.1}%)\n",
            self.guest_execution_samples,
            self.guest_execution_share() * 100.0
        ));
        out.push_str(&format!(
            "  host_syscall:        {:>8} ({:>5.1}%)\n",
            self.host_syscall_samples,
            self.host_syscall_share() * 100.0
        ));
        for (class, count) in &self.syscall_classes {
            out.push_str(&format!(
                "    {:<18} {:>8} ({:>5.1}%)\n",
                class,
                count,
                share(*count, self.sample_population) * 100.0
            ));
        }
        out.push_str(&format!(
            "  syscall_return:      {:>8} ({:>5.1}%)\n",
            self.syscall_return_samples,
            self.syscall_return_share() * 100.0
        ));
        out.push_str(&format!(
            "  fault_service:       {:>8} ({:>5.1}%)\n",
            self.fault_service_samples,
            self.fault_service_share() * 100.0
        ));
        for (class, count) in &self.fault_classes {
            out.push_str(&format!(
                "    {:<18} {:>8} ({:>5.1}%)\n",
                class,
                count,
                share(*count, self.sample_population) * 100.0
            ));
        }
        out.push_str(&format!(
            "  el1_mailbox:         {:>8} ({:>5.1}%)\n",
            self.el1_mailbox_samples,
            self.el1_mailbox_share() * 100.0
        ));
        out.push_str(&format!(
            "  executor_scheduling: {:>8} ({:>5.1}%)\n",
            self.executor_scheduling_samples,
            self.executor_scheduling_share() * 100.0
        ));
        out.push_str(&format!(
            "  lock_wait:           {:>8} ({:>5.1}%)\n",
            self.lock_wait_samples,
            self.lock_wait_share() * 100.0
        ));
        out.push_str(&format!(
            "  instrumentation:     {:>8} ({:>5.1}%)\n",
            self.instrumentation_samples,
            self.instrumentation_share() * 100.0
        ));
        if self.other_samples > 0 {
            out.push_str(&format!(
                "  other:               {:>8} ({:>5.1}%)\n",
                self.other_samples,
                self.other_share() * 100.0
            ));
        }
        out.trim_end().to_owned()
    }
}

fn share(count: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        count as f64 / total as f64
    }
}

#[derive(Debug)]
struct Record {
    tag: String,
    fields: BTreeMap<String, String>,
}

impl Record {
    fn parse(line: &str) -> Result<Self> {
        let mut parts = line.split('|');
        if parts.next() != Some(PREFIX) {
            bail!("unknown {PREFIX} protocol prefix in {line:?}");
        }
        let tag = parts
            .next()
            .filter(|tag| !tag.is_empty())
            .ok_or_else(|| anyhow!("truncated {PREFIX} record"))?
            .to_owned();
        let mut fields = BTreeMap::new();
        for raw in parts {
            let (key, value) = raw
                .split_once('=')
                .ok_or_else(|| anyhow!("{PREFIX} field lacks '=': {raw:?}"))?;
            if key.is_empty() || value.is_empty() {
                bail!("{PREFIX} field has an empty key or value");
            }
            match fields.entry(key.to_owned()) {
                Entry::Vacant(slot) => {
                    slot.insert(value.to_owned());
                }
                Entry::Occupied(_) => bail!("duplicate {PREFIX} field {key:?}"),
            }
        }
        Ok(Self { tag, fields })
    }

    fn exact_fields(&self, expected: &[&str]) -> Result<()> {
        let actual = self
            .fields
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let expected = expected.iter().copied().collect::<BTreeSet<_>>();
        if actual != expected {
            bail!("{PREFIX} {:?} field contract mismatch", self.tag);
        }
        Ok(())
    }

    fn value(&self, field: &str) -> Result<&str> {
        self.fields
            .get(field)
            .map(String::as_str)
            .ok_or_else(|| anyhow!("{PREFIX} {:?} record lacks {field:?}", self.tag))
    }

    fn u64(&self, field: &str) -> Result<u64> {
        parse_u64(self.value(field)?, field)
    }
}

#[derive(Clone, Copy, Debug)]
struct Summary {
    root_exited: u64,
    bounded: u64,
    errors: u64,
    saw_sample: u64,
}

impl Summary {
    fn parse(record: &Record) -> Result<Self> {
        record.exact_fields(&["status", "root_exited", "bounded", "errors", "saw_sample"])?;
        if record.value("status")? != "ok" {
            bail!("{PREFIX} producer reported an error");
        }
        Ok(Self {
            root_exited: record.u64("root_exited")?,
            bounded: record.u64("bounded")?,
            errors: record.u64("errors")?,
            saw_sample: record.u64("saw_sample")?,
        })
    }

    fn validate(self) -> Result<()> {
        if self.root_exited != 1 || self.bounded != 0 || self.errors != 0 || self.saw_sample != 1 {
            bail!(
                "{PREFIX} producer summary is not a clean completed capture: root_exited={}, bounded={}, errors={}, saw_sample={}",
                self.root_exited,
                self.bounded,
                self.errors,
                self.saw_sample,
            );
        }
        Ok(())
    }
}

fn is_canonical_u64(value: &str) -> bool {
    value == "0" || (!value.starts_with('0') && value.bytes().all(|byte| byte.is_ascii_digit()))
}

fn parse_u64(value: &str, field: &str) -> Result<u64> {
    if !is_canonical_u64(value) {
        bail!("{PREFIX} {field} is not a canonical unsigned integer: {value:?}");
    }
    value
        .parse()
        .with_context(|| format!("invalid {PREFIX} {field}"))
}

fn require_lossless(status: ProfileCaptureStatus) -> Result<()> {
    if status != ProfileCaptureStatus::default() {
        bail!(
            "{PREFIX} capture is not lossless: principal={}, aggregation={}, dynamic={}, dynamic_rinse={}, dynamic_dirty={}, other={}, interrupted={}",
            status.principal_drops,
            status.aggregation_drops,
            status.dynamic_drops,
            status.dynamic_rinse_drops,
            status.dynamic_dirty_drops,
            status.other_drops,
            status.interrupted,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_stream() -> String {
        let p_sha = program_sha256();
        [
            &format!("HVPCARRIERATTR|header|program_sha256={p_sha}"),
            "HVPCARRIERATTR|image|host_pid=1234|text_base=0x100000000|slide=0x0",
            "HVPCARRIERATTR|summary|status=ok|root_exited=1|bounded=0|errors=0|saw_sample=1",
            "HVPCARRIERATTR|sample-population|count=100",
            "HVPCARRIERATTR|section=usdt-metrics",
            "HVPCARRIERATTR|usdt|metric=syscall-services|count=20",
            "HVPCARRIERATTR|usdt|metric=vcpu-faults|count=15",
            "HVPCARRIERATTR|usdt|metric=cow-events|count=5",
            "HVPCARRIERATTR|usdt|metric=frame-grants|count=4",
            "HVPCARRIERATTR|usdt|metric=stage2-aliases|count=3",
            "HVPCARRIERATTR|section=user-stacks",
            // Guest execution (hv_vcpu_run): 38 samples
            "              carrick`hv_vcpu_run+0x10",
            "              carrick`carrick_vmm_hvf::trap::HvfAarch64Vcpu::run_to_exit+0x120",
            "              38",
            "",
            // Host syscall: openat: 10 samples
            "              libsystem_kernel.dylib`__openat+0x8",
            "              carrick`carrick_kernel::dispatch::fs::openat+0x40",
            "              carrick`carrick_kernel::dispatch::SyscallDispatcher::dispatch+0x100",
            "              10",
            "",
            // Host syscall: mmap: 10 samples
            "              libsystem_kernel.dylib`__mmap+0x8",
            "              carrick`carrick_kernel::dispatch::mem::mmap+0x50",
            "              carrick`carrick_kernel::dispatch::SyscallDispatcher::dispatch+0x100",
            "              10",
            "",
            // Syscall return completion: 3 samples
            "              carrick`carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Vcpu::complete_syscall_return+0x10",
            "              carrick`carrick_runtime::vcpu_loop::ThreadRuntimeState::complete_returned+0x20",
            "              3",
            "",
            // Fault: first touch: 6 samples
            "              carrick`carrick_kernel::dispatch::mem::fault::commit_resident_fault+0x50",
            "              carrick`carrick_runtime::vcpu_loop::signal::resolve_mutating_fault+0x80",
            "              6",
            "",
            // Fault: COW: 4 samples
            "              carrick`carrick_vmm_hvf::trap::cow_engine::resolve_frame_cow_fault+0x30",
            "              carrick`carrick_vmm_hvf::trap::run_to_exit+0x100",
            "              4",
            "",
            // Fault: frame grant: 3 samples
            "              carrick`carrick_runtime::vcpu_loop::signal::commit_resident_frame_grant+0x40",
            "              carrick`carrick_runtime::vcpu_loop::signal::resolve_mutating_fault+0x80",
            "              3",
            "",
            // Fault: stage-2: 2 samples
            "              carrick`carrick_vmm_hvf::trap::inventory_hv_vm_map_replay+0x30",
            "              carrick`carrick_vmm_hvf::trap::run_to_exit+0x100",
            "              2",
            "",
            // EL1 mailbox: 5 samples
            "              carrick`carrick_runtime::vcpu_loop::signal::claim_frame_grant_request+0x20",
            "              carrick`carrick_runtime::vcpu_loop::signal::resolve_mutating_fault+0x80",
            "              5",
            "",
            // Executor scheduling: 8 samples
            "              carrick`carrick_kernel::kernel::scheduler::idle_condvar+0x10",
            "              carrick`carrick_kernel::kernel::scheduler::Scheduler::take+0x90",
            "              8",
            "",
            // Lock wait: 7 samples
            "              libsystem_kernel.dylib`__psynch_mutexwait+0x8",
            "              carrick`parking_lot::raw_mutex::RawMutex::lock_slow+0x40",
            "              carrick`carrick_kernel::dispatch::fs::openat+0x20",
            "              7",
            "",
            // Instrumentation: 2 samples
            "              carrick`carrick_observability::probes::real::hvpatch_executor_claim+0x10",
            "              2",
            "",
            // Other: 2 samples
            "              carrick`some_other_helper+0x10",
            "              2",
            "",
        ]
        .join("\n")
    }

    #[test]
    fn parse_valid_carrier_cpu_attribution_stream() {
        let stream = sample_stream();
        let summary =
            HvpatchCarrierCpuAttributionSummary::from_raw(stream, ProfileCaptureStatus::default())
                .expect("summary parse");

        assert_eq!(summary.sample_population, 100);
        assert_eq!(summary.stack_population, 100);
        assert_eq!(summary.stack_count, 13);
        assert_eq!(summary.guest_execution_samples, 38);
        assert_eq!(summary.host_syscall_samples, 20);
        assert_eq!(summary.syscall_return_samples, 3);
        assert_eq!(summary.fault_service_samples, 15);
        assert_eq!(summary.el1_mailbox_samples, 5);
        assert_eq!(summary.executor_scheduling_samples, 8);
        assert_eq!(summary.lock_wait_samples, 7);
        assert_eq!(summary.instrumentation_samples, 2);
        assert_eq!(summary.other_samples, 2);

        assert_eq!(summary.syscall_classes.get("openat"), Some(&10));
        assert_eq!(summary.syscall_classes.get("mmap"), Some(&10));

        assert_eq!(summary.fault_classes.get("first-touch"), Some(&6));
        assert_eq!(summary.fault_classes.get("cow"), Some(&4));
        assert_eq!(summary.fault_classes.get("frame-grant"), Some(&3));
        assert_eq!(summary.fault_classes.get("stage-2"), Some(&2));

        assert_eq!(summary.usdt_metrics.get("syscall-services"), Some(&20));
        assert_eq!(summary.usdt_metrics.get("vcpu-faults"), Some(&15));

        // Shares
        assert!((summary.guest_execution_share() - 0.38).abs() < 1e-6);
        assert!((summary.host_syscall_share() - 0.20).abs() < 1e-6);
        assert!((summary.syscall_return_share() - 0.03).abs() < 1e-6);
        assert!((summary.fault_service_share() - 0.15).abs() < 1e-6);
        assert!((summary.el1_mailbox_share() - 0.05).abs() < 1e-6);
        assert!((summary.executor_scheduling_share() - 0.08).abs() < 1e-6);
        assert!((summary.lock_wait_share() - 0.07).abs() < 1e-6);
        assert!((summary.instrumentation_share() - 0.02).abs() < 1e-6);
        assert!((summary.other_share() - 0.02).abs() < 1e-6);

        // Human output check
        let human = summary.render_human();
        assert!(human.contains("HVPatch carrier CPU attribution"));
        assert!(human.contains("guest_execution:"));
        assert!(human.contains("38 ( 38.0%)"));
        assert!(human.contains("host_syscall:"));
        assert!(human.contains("20 ( 20.0%)"));
        assert!(human.contains("openat"));
        assert!(human.contains("10 ( 10.0%)"));
        assert!(human.contains("syscall_return:"));
        assert!(human.contains("3 (  3.0%)"));
        assert!(human.contains("first-touch"));
        assert!(human.contains("6 (  6.0%)"));
        assert!(human.contains("instrumentation:"));
        assert!(human.contains("2 (  2.0%)"));
    }

    #[test]
    fn rejects_stack_population_closure_mismatch() {
        let stream = sample_stream().replace(
            "HVPCARRIERATTR|sample-population|count=100",
            "HVPCARRIERATTR|sample-population|count=99",
        );
        let err =
            HvpatchCarrierCpuAttributionSummary::from_raw(stream, ProfileCaptureStatus::default())
                .expect_err("closure mismatch");
        assert!(err.to_string().contains("stack-count closure failed"));
    }

    #[test]
    fn rejects_lossy_capture() {
        let stream = sample_stream();
        let status = ProfileCaptureStatus {
            aggregation_drops: 1,
            ..Default::default()
        };
        let err = HvpatchCarrierCpuAttributionSummary::from_raw(stream, status)
            .expect_err("lossy capture");
        assert!(err.to_string().contains("not lossless"));
    }

    #[test]
    fn rejects_corrupt_summary_status() {
        for corrupt in [
            sample_stream().replace("root_exited=1", "root_exited=0"),
            sample_stream().replace("bounded=0", "bounded=1"),
            sample_stream().replace("errors=0", "errors=1"),
            sample_stream().replace("saw_sample=1", "saw_sample=0"),
            sample_stream().replace(&program_sha256(), &"00".repeat(32)),
        ] {
            assert!(
                HvpatchCarrierCpuAttributionSummary::from_raw(
                    corrupt,
                    ProfileCaptureStatus::default(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_100_percent_other_attribution() {
        let p_sha = program_sha256();
        let stream = [
            &format!("HVPCARRIERATTR|header|program_sha256={p_sha}"),
            "HVPCARRIERATTR|image|host_pid=1234|text_base=0x100000000|slide=0x0",
            "HVPCARRIERATTR|summary|status=ok|root_exited=1|bounded=0|errors=0|saw_sample=1",
            "HVPCARRIERATTR|sample-population|count=10",
            "HVPCARRIERATTR|section=usdt-metrics",
            "HVPCARRIERATTR|section=user-stacks",
            "              0xdeadbeef",
            "              10",
            "",
        ]
        .join("\n");

        let err =
            HvpatchCarrierCpuAttributionSummary::from_raw(stream, ProfileCaptureStatus::default())
                .expect_err("should fail closed on 100% other");
        assert!(err.to_string().contains("attribution failed closed"));
        assert!(err.to_string().contains("100% of samples"));
    }

    #[test]
    fn classifies_real_captured_carrier_stacks() {
        // 1. Guest execution via run_to_exit / Vcpu::run
        let guest_stack = [
            "applevisor::vcpu::Vcpu::get_sys_reg::h3efe6a3aabef6ac0 (in carrick) (vcpu.rs:0)",
            "carrick_vmm_hvf::trap::HvfInner::run_to_exit::h86a02940b642697e (in carrick) (trap.rs:7474)",
            "carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Vcpu::run::h587b622a2811e9a5 (in carrick) (hvf_aarch64_engine.rs:595)",
            "carrick_host::guest_cpu::timed_run::hc43419832bcd8d25 (in carrick) (guest_cpu.rs:191)",
            "carrick_aarch64::engine::Aarch64EngineCore::next_syscall::h67df699a04747041 (in carrick) (engine.rs:2816)",
        ];
        assert_eq!(classify_stack(&guest_stack), CpuCategory::GuestExecution);

        // 2. Syscall return completion: deepest carrick frame is complete_syscall_return
        let return_comp_stack = [
            "carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Vcpu::complete_syscall_return::h4c2248377b9b7249 (in carrick) (hvf_aarch64_engine.rs:509)",
            "carrick_runtime::vcpu_loop::ThreadRuntimeState::complete_returned::h9234673c72a38347 (in carrick) (mod.rs:2017)",
            "carrick_runtime::vcpu_loop::binding::ProductionHvpatchLoopJob::service_outcome::h2f161280967cc2d2 (in carrick) (binding.rs:2698)",
            "carrick_runtime::vcpu_loop::binding::ProductionHvpatchLoopJob::poll_with_engine::h3929857070dd193c (in carrick) (binding.rs:4409)",
        ];
        assert_eq!(
            classify_stack(&return_comp_stack),
            CpuCategory::SyscallReturn
        );

        // 3. Syscall dispatch frame (outermost dispatcher when no deeper handler is active)
        let dispatch_stack = [
            "carrick_runtime::vcpu_loop::binding::ProductionHvpatchLoopJob::service_outcome::h2f161280967cc2d2 (in carrick) (binding.rs:2698)",
            "carrick_runtime::vcpu_loop::binding::ProductionHvpatchLoopJob::poll_with_engine::h3929857070dd193c (in carrick) (binding.rs:4409)",
        ];
        assert_eq!(
            classify_stack(&dispatch_stack),
            CpuCategory::HostSyscall("dispatch".to_owned())
        );

        // 4. Fault service: first-touch
        let fault_stack = [
            "carrick_vmm_hvf::trap::handle_guest_page_fault::h12345 (in carrick)",
            "carrick_vmm_hvf::trap::HvfInner::run_to_exit::h86a02940b642697e (in carrick) (trap.rs:7474)",
            "carrick_host::guest_cpu::timed_run::hc43419832bcd8d25 (in carrick) (guest_cpu.rs:191)",
        ];
        assert_eq!(
            classify_stack(&fault_stack),
            CpuCategory::FaultService(FaultClass::FirstTouch)
        );

        // 5. Fault service: COW via cow_engine
        let cow_stack = [
            "carrick_vmm_hvf::trap::task_mapping_index::TaskMappingIndex::candidates_for_ipa_range::h2efd4d1d13f0246b (in carrick) (task_mapping_index.rs:820)",
            "carrick_vmm_hvf::trap::cow_engine::HvfVmState::mapping_for_ipa_range::h9c28ca89f7489c5b (in carrick) (cow_engine.rs:5073)",
            "carrick_runtime::vcpu_loop::signal::resolve_mutating_fault::h944919999724912b (in carrick) (signal.rs:620)",
        ];
        assert_eq!(
            classify_stack(&cow_stack),
            CpuCategory::FaultService(FaultClass::Cow)
        );

        // 6. Fault service: frame grant
        let grant_stack = [
            "carrick_runtime::vcpu_loop::signal::prepare_el1_frame_grant::h12345 (in carrick)",
            "carrick_runtime::vcpu_loop::signal::resolve_mutating_fault::h944919999724912b (in carrick) (signal.rs:511)",
        ];
        assert_eq!(
            classify_stack(&grant_stack),
            CpuCategory::FaultService(FaultClass::FrameGrant)
        );

        // 7. Lock wait
        let lock_stack = [
            "0x18a8be50c",
            "parking_lot::condvar::Condvar::wait_until_internal::heb307538a997ec5d (in carrick) (condvar.rs:334)",
            "carrick_runtime::vcpu_loop::outcome::HvpatchLoopResult::wait_supervised::hbd45820ed4aba5a9 (in carrick) (outcome.rs:443)",
        ];
        assert_eq!(classify_stack(&lock_stack), CpuCategory::LockWait);

        // 8. Executor scheduling (park_spare overrides leaf condvar wait)
        let executor_stack = [
            "0x18a8be50c",
            "parking_lot::condvar::Condvar::wait_until_internal::heb307538a997ec5d (in carrick) (condvar.rs:334)",
            "carrick_kernel::kernel::scheduler::RunQueue::park_spare::h15abbc763e994f34 (in carrick) (scheduler.rs:2779)",
            "carrick_kernel::kernel::scheduler::Scheduler::try_take::h14837436f11fd1ad (in carrick) (scheduler.rs:4309)",
        ];
        assert_eq!(
            classify_stack(&executor_stack),
            CpuCategory::ExecutorScheduling
        );

        // 9. Instrumentation: probe frames must NEVER be classified as scheduling even if park_spare is on the stack
        let probe_executor_stack = [
            "carrick_observability::probes::real::hvpatch_executor_claim::h12345 (in carrick) (probes.rs:100)",
            "carrick_kernel::kernel::scheduler::RunQueue::park_spare::h15abbc763e994f34 (in carrick) (scheduler.rs:2779)",
            "carrick_kernel::kernel::scheduler::Scheduler::try_take::h14837436f11fd1ad (in carrick) (scheduler.rs:4309)",
        ];
        assert_eq!(
            classify_stack(&probe_executor_stack),
            CpuCategory::Instrumentation
        );

        // 10. Instrumentation: probe frames in fault/syscall hooks
        let probe_fault_stack = [
            "carrick_observability::probes::real::vcpu_fault::he21282493f7bc6e4 (in carrick) (probes.rs:4982)",
            "carrick_vmm_hvf::trap::HvfInner::run_to_exit::h86a02940b642697e (in carrick) (trap.rs:7474)",
            "carrick_host::guest_cpu::timed_run::hc43419832bcd8d25 (in carrick) (guest_cpu.rs:191)",
        ];
        assert_eq!(
            classify_stack(&probe_fault_stack),
            CpuCategory::Instrumentation
        );

        // 11. Host syscall: openat
        let openat_stack = [
            "0x18a8bc5a8",
            "carrick_vfs::fs_backend::host::HostFsBackend::openat_for_guest::ha8d23ac5de91a7df (in carrick) (host.rs:1811)",
            "carrick_kernel::dispatch::fs::open::FsView::open_at_path_string::h1dee222a19ff20b3 (in carrick) (open.rs:734)",
        ];
        assert_eq!(
            classify_stack(&openat_stack),
            CpuCategory::HostSyscall("openat".to_owned())
        );

        // 12. Host syscall: renameat
        let renameat_stack = [
            "0x18a8c8a00",
            "carrick_vfs::fs_backend::host::HostFsBackend::rename_overlay_entry_at::h1d6a45c47169bb32 (in carrick) (host.rs:5405)",
            "carrick_kernel::dispatch::fs::directory::FsView::do_renameat::h0e4b00408525f8f0 (in carrick) (directory.rs:403)",
        ];
        assert_eq!(
            classify_stack(&renameat_stack),
            CpuCategory::HostSyscall("renameat".to_owned())
        );
    }

    #[test]
    fn parse_real_python_trace_if_present() {
        let trace_path = [
            Path::new("target/cpa-python.trace"),
            Path::new("../../target/cpa-python.trace"),
        ]
        .into_iter()
        .find(|p| p.exists());
        let Some(trace_path) = trace_path else {
            return;
        };
        if find_carrick_binary().is_none() {
            return;
        }
        let summary = HvpatchCarrierCpuAttributionSummary::from_path(
            trace_path,
            ProfileCaptureStatus::default(),
        )
        .expect("parse real python trace");

        assert_eq!(summary.sample_population, 1601);
        assert_eq!(summary.stack_count, 158);
        assert!(
            summary.host_syscall_samples > 1400,
            "host syscall was {}",
            summary.host_syscall_samples
        );
        assert!(
            summary.other_share() < 0.05,
            "other share was {}",
            summary.other_share()
        );
        assert!(
            summary.instrumentation_share() <= MAX_INSTRUMENTATION_SHARE,
            "instrumentation share was {}",
            summary.instrumentation_share()
        );
    }

    #[test]
    fn rejects_excessive_instrumentation_overhead() {
        let p_sha = program_sha256();
        let stream = [
            &format!("HVPCARRIERATTR|header|program_sha256={p_sha}"),
            "HVPCARRIERATTR|image|host_pid=1234|text_base=0x100000000|slide=0x0",
            "HVPCARRIERATTR|summary|status=ok|root_exited=1|bounded=0|errors=0|saw_sample=1",
            "HVPCARRIERATTR|sample-population|count=100",
            "HVPCARRIERATTR|section=user-stacks",
            // Guest execution: 40 samples
            "              carrick`hv_vcpu_run+0x10",
            "              40",
            "",
            // Excessive instrumentation: 60 samples (60%)
            "              carrick`carrick_observability::probes::real::hvf_syscall_transport+0x10",
            "              60",
            "",
        ]
        .join("\n");

        let err =
            HvpatchCarrierCpuAttributionSummary::from_raw(stream, ProfileCaptureStatus::default())
                .unwrap_err();
        assert!(
            err.to_string().contains("instrumentation samples")
                && err
                    .to_string()
                    .contains("exceeded maximum allowed threshold"),
            "expected instrumentation threshold error, got: {err}"
        );
    }

    #[test]
    fn render_script_placeholder_substitution() {
        let template = format!(
            "dtrace:::BEGIN {{ printf(\"HVPCARRIERATTR|header|program_sha256={}\"); }}",
            PROGRAM_SHA256_PLACEHOLDER
        );
        let rendered = render_profile_script(&template).expect("render");
        assert!(rendered.contains(&program_sha256()));
        assert!(!rendered.contains(PROGRAM_SHA256_PLACEHOLDER));
    }
}
