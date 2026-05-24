use crate::dispatch::{Aarch64SyscallFrame, GuestMemory, MemoryError};
use crate::elf::SegmentPerms;
use crate::memory::AddressSpace;
use serde::Serialize;
use thiserror::Error;

pub const HVF_PAGE_SIZE: u64 = 0x4000;
pub const AARCH64_SVC_EXCEPTION_CLASS: u64 = 0x15;
pub const AARCH64_HVC_EXCEPTION_CLASS: u64 = 0x16;
const AARCH64_EXCEPTION_CLASS_SHIFT: u64 = 26;
const AARCH64_EXCEPTION_CLASS_MASK: u64 = 0x3f;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrapBackend {
    HypervisorFramework,
}

#[derive(Debug, Error)]
pub enum TrapError {
    #[error("Hypervisor.framework syscall trapping is only available on macOS/aarch64")]
    UnsupportedPlatform,
    #[error("Hypervisor.framework operation failed: {0}")]
    Hypervisor(String),
    #[error("guest mapping size {0} does not fit this host")]
    MappingTooLarge(u64),
    #[error("guest mapping at 0x{guest_start:x} with size {mapped_size} overflows")]
    MappingOverflow { guest_start: u64, mapped_size: u64 },
    #[error("Hypervisor.framework exited for an unexpected reason: {reason}")]
    UnexpectedExit { reason: String },
    #[error(
        "guest exception is not an AArch64 SVC trap: syndrome=0x{syndrome:x}, virtual_address=0x{virtual_address:x}, physical_address=0x{physical_address:x}"
    )]
    UnexpectedException {
        syndrome: u64,
        virtual_address: u64,
        physical_address: u64,
    },
    #[error("fork(2) failed: {0}")]
    ForkFailed(String),
    #[error(
        "hv_vm_map(host=0x{host_addr:x}, guest=0x{guest_start:x}, size={size}) failed in child: 0x{code:x}"
    )]
    ChildMapFailed {
        host_addr: u64,
        guest_start: u64,
        size: usize,
        code: u32,
    },
    /// An EL0 sync exception other than `svc #0` reached the EL1 vector
    /// trampoline (e.g. instruction abort at PC=0, data abort, undef).
    /// Surfaces the original syndrome/ELR/FAR so the runtime can map it
    /// to a Linux signal (typically SIGSEGV/SIGBUS/SIGILL).
    #[error(
        "EL0 fault not handled by trap path: esr=0x{syndrome:x} elr=0x{elr:x} far=0x{far:x} x16=0x{x16:x} x17=0x{x17:x} x29=0x{x29:x} x30=0x{x30:x} sp=0x{sp:x}"
    )]
    EL0Fault {
        syndrome: u64,
        elr: u64,
        far: u64,
        /// x16/x17 at the fault. For the PLT `ldr x17,[x16,#off]; br x17`
        /// "PROT_REA" wild-PC crash, x16 is the GOT address the guest computed
        /// (compare against the slot carrick's read sees) and x17 the value it
        /// loaded — distinguishes a wrong-address fault from wrong page content.
        x16: u64,
        x17: u64,
        /// x29(FP)/x30(LR)/SP_EL0 at the fault — a corrupt x30 with the PC
        /// faulting at that address means a `ret` to a clobbered return slot.
        x29: u64,
        x30: u64,
        sp: u64,
    },
}

/// Outcome of `HvfTrapEngine::fork`. The parent learns the child's PID;
/// the child returns and continues executing with a freshly-rebuilt HVF
/// VM that points at the same host buffers (Mach VM gives us COW for free).
#[derive(Debug)]
pub enum ForkOutcome {
    Parent { child_pid: i32 },
    Child,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TrapCapabilities {
    pub backend: TrapBackend,
    pub available_on_this_host: bool,
    pub implemented: bool,
}

pub fn hvf_capabilities() -> TrapCapabilities {
    TrapCapabilities {
        backend: TrapBackend::HypervisorFramework,
        available_on_this_host: cfg!(all(target_os = "macos", target_arch = "aarch64")),
        implemented: cfg!(all(target_os = "macos", target_arch = "aarch64")),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuestMappingPlan {
    /// The user-mode entry point (real `_start` of the loaded ELF, already
    /// rebased through any PIE bias). When `el0_trampoline_entry` is `None`
    /// this is also the vCPU's initial PC. When the trampoline is installed
    /// this becomes ELR_EL1 instead, and the vCPU starts at the trampoline.
    pub entry: u64,
    pub initial_stack_pointer: Option<u64>,
    /// Guest physical address of the EL0 entry trampoline page (a single
    /// `eret` instruction). When set, the trap engine starts the vCPU here
    /// in EL1h and uses `entry` as the post-`eret` PC in EL0t.
    pub el0_trampoline_entry: Option<u64>,
    /// Guest physical address to program into VBAR_EL1 so EL0 SVC traps are
    /// routed through the EL1 vector page (which forwards them via HVC).
    pub el1_vectors_base: Option<u64>,
    /// Guest physical address of the stage-1 identity page-table root.
    /// When set, the trap engine programs TTBR0_EL1 / TCR_EL1 / MAIR_EL1
    /// and enables stage-1 (`SCTLR_EL1.M=1`).
    pub stage1_page_tables_base: Option<u64>,
    pub mappings: Vec<GuestMapping>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuestMapping {
    pub guest_start: u64,
    pub mapped_size: u64,
    pub offset_in_mapping: u64,
    pub payload_size: u64,
    pub perms: SegmentPerms,
    #[serde(skip)]
    image: Vec<u8>,
}

impl GuestMappingPlan {
    pub fn from_address_space(address_space: &AddressSpace) -> Result<Self, TrapError> {
        let mut mappings = Vec::with_capacity(address_space.regions().len());
        for region in address_space.regions() {
            let guest_start = align_down(region.start, HVF_PAGE_SIZE);
            let guest_end = align_up(region.end, HVF_PAGE_SIZE)?;
            let mapped_size =
                guest_end
                    .checked_sub(guest_start)
                    .ok_or(TrapError::MappingOverflow {
                        guest_start,
                        mapped_size: 0,
                    })?;
            let mapped_len = usize::try_from(mapped_size)
                .map_err(|_| TrapError::MappingTooLarge(mapped_size))?;
            let offset_in_mapping = region.start - guest_start;

            // Keep only the payload bytes, not a full zero-padded copy of the
            // (potentially 512 MiB) mapping. hv_vm_allocate hands back lazily
            // zero-filled, HVF-managed memory, so we write just the payload at
            // its offset and let untouched pages fault in on demand. Building
            // and writing the whole region here is what pinned ~2 GiB resident
            // per guest process for mappings the guest never touches.
            let _ = mapped_len;
            let image = region.bytes().to_vec();

            mappings.push(GuestMapping {
                guest_start,
                mapped_size,
                offset_in_mapping,
                payload_size: region.bytes().len() as u64,
                perms: region.perms,
                image,
            });
        }

        Ok(Self {
            entry: address_space.entry(),
            initial_stack_pointer: address_space.initial_stack_pointer(),
            el0_trampoline_entry: address_space.el0_trampoline_entry(),
            el1_vectors_base: address_space.el1_vectors_base(),
            stage1_page_tables_base: address_space.stage1_page_tables_base(),
            mappings,
        })
    }
}

pub struct HvfTrapEngine {
    inner: std::mem::ManuallyDrop<HvfInner>,
}

// On Drop we deliberately do NOT run applevisor's Vcpu / VirtualMachine
// destructors. Once carrick has executed a single `fork(2)` inside the
// trap loop, applevisor's internal state is no longer consistent with
// HVF in either the parent or the child — Drop unwraps
// `hv_vcpu_destroy` and panics with "no VM or vCPU available". Since
// the carrick host process is exiting either way, we let the kernel
// reclaim the HVF VM / vCPU at process exit and skip the Rust-side
// teardown.
impl Drop for HvfTrapEngine {
    fn drop(&mut self) {
        // `ManuallyDrop::drop` is the only thing that would invoke
        // `HvfInner::Drop` (which in turn drops `applevisor::Vcpu` and
        // `VirtualMachineInstance`). Skipping it is the whole point.
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const GPR_TABLE: [applevisor::vcpu::Reg; 31] = [
    applevisor::vcpu::Reg::X0,
    applevisor::vcpu::Reg::X1,
    applevisor::vcpu::Reg::X2,
    applevisor::vcpu::Reg::X3,
    applevisor::vcpu::Reg::X4,
    applevisor::vcpu::Reg::X5,
    applevisor::vcpu::Reg::X6,
    applevisor::vcpu::Reg::X7,
    applevisor::vcpu::Reg::X8,
    applevisor::vcpu::Reg::X9,
    applevisor::vcpu::Reg::X10,
    applevisor::vcpu::Reg::X11,
    applevisor::vcpu::Reg::X12,
    applevisor::vcpu::Reg::X13,
    applevisor::vcpu::Reg::X14,
    applevisor::vcpu::Reg::X15,
    applevisor::vcpu::Reg::X16,
    applevisor::vcpu::Reg::X17,
    applevisor::vcpu::Reg::X18,
    applevisor::vcpu::Reg::X19,
    applevisor::vcpu::Reg::X20,
    applevisor::vcpu::Reg::X21,
    applevisor::vcpu::Reg::X22,
    applevisor::vcpu::Reg::X23,
    applevisor::vcpu::Reg::X24,
    applevisor::vcpu::Reg::X25,
    applevisor::vcpu::Reg::X26,
    applevisor::vcpu::Reg::X27,
    applevisor::vcpu::Reg::X28,
    applevisor::vcpu::Reg::X29,
    applevisor::vcpu::Reg::X30,
];

/// V0–V31 SIMD/FP registers, saved/restored across signal delivery alongside
/// the GPRs so a handler that uses SIMD (aarch64 `memcpy`/`memset`, the guest's
/// own handler body) cannot corrupt the interrupted thread's vector state.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
const SIMD_FP_TABLE: [applevisor::vcpu::SimdFpReg; 32] = {
    use applevisor_sys::hv_simd_fp_reg_t::*;
    [
        Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7, Q8, Q9, Q10, Q11, Q12, Q13, Q14, Q15, Q16, Q17, Q18, Q19,
        Q20, Q21, Q22, Q23, Q24, Q25, Q26, Q27, Q28, Q29, Q30, Q31,
    ]
};

/// Full-speed diagnostic counters (the dtrace consumer perturbs the
/// SIGURG-vs-futex race away, so observe with cheap atomics instead). Dumped at
/// process teardown when `CARRICK_KICK_STATS` is set.
pub static EL1_KICK_RESUMED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static INJECT_AT_EL1: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static KICK_PATH_INJECT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn dump_kick_stats() {
    if std::env::var_os("CARRICK_KICK_STATS").is_some() {
        use std::sync::atomic::Ordering;
        eprintln!(
            "[kick_stats pid={}] el1_kick_resumed={} kick_path_inject={} inject_at_el1={}",
            unsafe { libc::getpid() },
            EL1_KICK_RESUMED.load(Ordering::Relaxed),
            KICK_PATH_INJECT.load(Ordering::Relaxed),
            INJECT_AT_EL1.load(Ordering::Relaxed),
        );
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Default)]
struct MemoryProtections {
    no_access: parking_lot::RwLock<Vec<(u64, u64)>>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl MemoryProtections {
    fn from_ranges(ranges: Vec<(u64, u64)>) -> Self {
        Self {
            no_access: parking_lot::RwLock::new(ranges),
        }
    }

    fn snapshot(&self) -> Vec<(u64, u64)> {
        self.no_access.read().clone()
    }

    fn range_no_access(&self, address: u64, length: usize) -> bool {
        let end = address.saturating_add(length as u64);
        if end <= address {
            return false;
        }
        let ranges = self.no_access.read();
        let idx = ranges.partition_point(|&(_, e)| e <= address);
        ranges
            .get(idx)
            .is_some_and(|&(s, e)| address < e && s < end)
    }

    fn set_no_access(&self, address: u64, len: usize, no_access: bool) {
        let end = address.saturating_add(len as u64);
        if end <= address {
            return;
        }
        let mut ranges = self.no_access.write();
        if no_access {
            ranges.push((address, end));
            ranges.sort_by_key(|&(start, _)| start);
            let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
            for (start, end) in std::mem::take(&mut *ranges) {
                if let Some((_, last_end)) = merged.last_mut()
                    && start <= *last_end
                {
                    *last_end = (*last_end).max(end);
                    continue;
                }
                merged.push((start, end));
            }
            *ranges = merged;
            return;
        }
        let mut next = Vec::with_capacity(ranges.len());
        for (s, e) in std::mem::take(&mut *ranges) {
            if address <= s && end >= e {
                continue;
            }
            if end <= s || address >= e {
                next.push((s, e));
                continue;
            }
            if s < address {
                next.push((s, address));
            }
            if end < e {
                next.push((end, e));
            }
        }
        next.sort_by_key(|&(start, _)| start);
        *ranges = next;
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct HvfInner {
    _vm: applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
    vcpu: applevisor::vcpu::Vcpu,
    mappings: Vec<HvfMappedRegion>,
    /// The exception class of the most recent vCPU exit. We need to remember
    /// whether the trap came in via EL0 `svc` (`EC = 0x15`) or the EL1 vector
    /// stub's `hvc` (`EC = 0x16`) so `complete_syscall` knows whether to
    /// advance PC past the HVC before resuming.
    last_exit_class: u64,
    /// True iff this engine was produced by a `fork(2)` returning into a
    /// child. The runtime checks this when the guest exits and calls
    /// `_exit(2)` instead of running normal Rust drops — applevisor's
    /// Vcpu Drop unwraps `hv_vcpu_destroy` and panics in the
    /// post-fork child's HVF context (the new VM HVF tracks for the
    /// child got swapped in by `fork()`; ordering of `_vm` vs `vcpu`
    /// Drop trips a "no VM or vCPU available" assertion).
    is_forked_child: bool,
    /// Process-wide guest ranges currently mapped `PROT_NONE`.
    /// Thread siblings share this metadata so syscall-path memory access checks
    /// observe `mprotect(PROT_NONE)` changes made by any guest thread.
    protections: std::sync::Arc<MemoryProtections>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn replace_destroyed_hvf_inner(slot: &mut HvfInner, new_inner: HvfInner) {
    // The caller has already destroyed the raw HVF vCPU/VM handles behind
    // `slot`. Assigning normally would run applevisor destructors for those
    // stale wrappers; `ptr::write` is the single no-drop replacement point.
    unsafe {
        std::ptr::write(slot as *mut HvfInner, new_inner);
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
struct HvfMappedRegion {
    start: u64,
    end: u64,
    /// Host VA of the buffer backing this guest-physical mapping. We
    /// record this explicitly so the fork(2) path can re-issue
    /// `hv_vm_map` in the child against the same (COW'd) host pages
    /// without going through `applevisor::Memory::new` (which would
    /// allocate a fresh buffer).
    host_addr: *mut u8,
    /// Size of the mapping in bytes (matches the size HVF was given).
    size: usize,
    /// Stage-2 permissions used to map the region. Same value that
    /// `hvf_perms` returned; the child rebuilds the mapping with these
    /// exact permissions.
    perms: applevisor::memory::MemPerms,
    /// `Memory` owns the host allocation and the hv_vm_unmap that
    /// fires on Drop. In a freshly-forked CHILD we replace this with
    /// `None` (after `mem::forget` on the inherited inner) — the host
    /// pages stay alive via COW; the unmap would target the parent's
    /// HVF context which no longer exists in the child.
    memory: Option<applevisor::memory::Memory>,
    host_mapping: Option<crate::host_mapping::OwnedHostMapping>,
    /// True for a genuine guest `MAP_SHARED` file mapping (`map_shared_file`).
    /// Guest memory is host-`MAP_SHARED` for HVF coherence, so fork(2) does
    /// NOT COW-isolate it; the `fork` path takes an explicit private snapshot
    /// of every region EXCEPT these — a guest `MAP_SHARED` file mapping must
    /// stay shared across guest fork (POSIX), so parent and child keep mapping
    /// the SAME host buffer. (LTP's test framework relies on this: the test
    /// runs in a forked child that writes pass/fail counts to a `MAP_SHARED`
    /// results file the parent then reads.)
    guest_shared: bool,
}

/// Snapshot of vCPU register state captured before fork(2). The child
/// restores from this after rebuilding the HVF context so it resumes
/// exactly where the parent left off (post-clone syscall).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Clone)]
struct VcpuSnapshot {
    gprs: [u64; 31], // X0..X30
    pc: u64,
    cpsr: u64,
    sp_el0: u64,
    sctlr_el1: u64,
    tcr_el1: u64,
    ttbr0_el1: u64,
    mair_el1: u64,
    vbar_el1: u64,
    cpacr_el1: u64,
    spsr_el1: u64,
    elr_el1: u64,
    /// EL0 thread pointer. Set by musl during thread init via the asm
    /// `msr tpidr_el0, x?` and read back via `mrs x?, TPIDR_EL0`. If
    /// we don't restore it post-fork, the child's musl post-clone
    /// path computes thread-struct offsets relative to bogus zero
    /// and either writes to unmapped memory or loops indefinitely
    /// because the thread's tid never lands at the expected slot.
    tpidr_el0: u64,
    last_exit_class: u64,
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
struct HvfInner;

/// One mapping descriptor for a thread sibling: the guest-physical range,
/// the host VA backing it, its size, and the stage-2 perms. The sibling vCPU
/// lives in the same HVF VM as the parent, so the stage-2 entries are already
/// present; the descriptor only re-materialises local syscall-path metadata as
/// `HvfMappedRegion { memory: None }` (UNOWNED) so the sibling never
/// unmaps/frees buffers the main engine owns.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug, Clone, Copy)]
struct ThreadMappingDesc {
    start: u64,
    end: u64,
    host_addr: *mut u8,
    size: usize,
    perms: applevisor::memory::MemPerms,
    guest_shared: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ThreadMappingDesc {
    fn from_region(region: &HvfMappedRegion) -> Self {
        Self {
            start: region.start,
            end: region.end,
            host_addr: region.host_addr,
            size: region.size,
            perms: region.perms,
            guest_shared: region.guest_shared,
        }
    }

    fn into_unowned_region(self) -> HvfMappedRegion {
        HvfMappedRegion {
            start: self.start,
            end: self.end,
            host_addr: self.host_addr,
            size: self.size,
            perms: self.perms,
            memory: None,
            host_mapping: None,
            guest_shared: self.guest_shared,
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct ForkMappingDesc {
    start: u64,
    end: u64,
    host: ForkMappingHost,
    size: usize,
    perms: applevisor::memory::MemPerms,
    guest_shared: bool,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
enum ForkMappingHost {
    Borrowed(*mut u8),
    Owned(crate::host_mapping::OwnedHostMapping),
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl ForkMappingHost {
    fn ptr(&self) -> *mut u8 {
        match self {
            ForkMappingHost::Borrowed(ptr) => *ptr,
            ForkMappingHost::Owned(mapping) => mapping.as_ptr(),
        }
    }

    fn into_owned(self) -> Option<crate::host_mapping::OwnedHostMapping> {
        match self {
            ForkMappingHost::Borrowed(_) => None,
            ForkMappingHost::Owned(mapping) => Some(mapping),
        }
    }
}

/// Everything a freshly-spawned host thread needs to stand up its own vCPU
/// in the SHARED process VM and resume the cloned guest thread.
///
/// `vm` is a `vm.clone()` handle: the applevisor VM is Arc-refcounted, so
/// holding a clone keeps the single process VM alive and lets the new thread
/// call `vcpu_create()` against it (HVF requires vCPU create on the owning
/// thread). `mappings` are raw descriptors of the SAME host buffers the main
/// engine mapped; they are local syscall-path metadata only, because the
/// stage-2 entries live on the shared HVF VM, not on each vCPU.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub struct ThreadSpec {
    vm: applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
    mappings: Vec<ThreadMappingDesc>,
    protections: std::sync::Arc<MemoryProtections>,
    snapshot: VcpuSnapshot,
}

// SAFETY: `ThreadSpec` carries raw `*mut u8` host pointers (inside the
// mapping descriptors). Those pointers name buffers that are valid for the
// entire host process address space — they outlive every guest thread and
// are never reallocated for the life of the VM. The `VcpuSnapshot` is plain
// register data. The applevisor VM handle is itself `Send` (Arc-backed).
// Moving the spec to another thread to materialise a vCPU there is exactly
// the supported HVF pattern (create the vCPU on its owning thread), so the
// raw pointers crossing the thread boundary is sound.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
unsafe impl Send for ThreadSpec {}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub struct ThreadSpec;

impl HvfTrapEngine {
    pub fn new() -> Result<Self, TrapError> {
        if !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            return Err(TrapError::UnsupportedPlatform);
        }
        Self::new_platform()
    }

    pub fn backend(&self) -> TrapBackend {
        TrapBackend::HypervisorFramework
    }

    pub fn mapped_region_count(&self) -> usize {
        self.inner.mapped_region_count()
    }

    pub fn program_counter(&self) -> Result<u64, TrapError> {
        self.inner.program_counter()
    }

    /// A `Send`/`Sync` handle other threads can use to force this vCPU out of
    /// `hv_vcpu_run` (see [`crate::vcpu_kick`]). Published into the shared
    /// `VcpuKicker` when this thread starts running.
    pub fn vcpu_kick_handle(&self) -> crate::vcpu_kick::VcpuKickHandle {
        self.inner.vcpu_kick_handle()
    }

    pub fn map_address_space(
        &mut self,
        address_space: &AddressSpace,
    ) -> Result<GuestMappingPlan, TrapError> {
        let plan = GuestMappingPlan::from_address_space(address_space)?;
        self.map_plan(&plan)?;
        Ok(plan)
    }

    pub fn run_until_syscall(&mut self) -> Result<Option<Aarch64SyscallFrame>, TrapError> {
        self.inner.run_until_syscall()
    }

    pub fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError> {
        self.inner.complete_syscall(return_value)
    }

    /// Real macOS fork(2). The parent continues running its existing HVF
    /// context unchanged; the child returns with a freshly-rebuilt VM
    /// pointing at the same host buffers (COW via Mach VM), all sysregs
    /// and GPRs restored from a pre-fork snapshot, and `complete_syscall`
    /// not yet called for the clone — so the caller writes 0 (child) or
    /// the child's pid (parent) into x0 to satisfy the guest's
    /// expectations.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub fn fork(&mut self) -> Result<ForkOutcome, TrapError> {
        self.inner.fork()
    }

    /// Build a [`ThreadSpec`] for a thread-creating clone. Snapshots the
    /// parent vCPU, seeds the child registers (PC=post-svc, X0=0, SP_EL0=
    /// stack, TPIDR_EL0=tls), clones the shared VM handle, and copies the
    /// mapping descriptors so the new thread's vCPU sees the same guest
    /// memory. Does NOT touch the parent's HVF state otherwise — the parent
    /// keeps running its own vCPU.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub fn build_thread_spec(&self, stack: u64, tls: u64) -> Result<ThreadSpec, TrapError> {
        self.inner.build_thread_spec(stack, tls)
    }

    /// Materialise a thread sibling on the CURRENT host thread from a
    /// [`ThreadSpec`]: create a new vCPU in the shared VM, mirror the
    /// inherited mapping metadata (UNOWNED), and seed the child registers. The
    /// returned engine resumes the cloned guest thread on its next
    /// `next_syscall`. MUST be called on the host thread that will own the
    /// vCPU (HVF requires vCPU create+run+destroy on one thread).
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub fn from_thread_spec(spec: ThreadSpec) -> Result<Self, TrapError> {
        HvfInner::from_thread_spec(spec).map(|inner| Self {
            inner: std::mem::ManuallyDrop::new(inner),
        })
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub fn build_thread_spec(&self, _stack: u64, _tls: u64) -> Result<ThreadSpec, TrapError> {
        Err(TrapError::UnsupportedPlatform)
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub fn from_thread_spec(_spec: ThreadSpec) -> Result<Self, TrapError> {
        Err(TrapError::UnsupportedPlatform)
    }

    /// True iff this engine was produced by a successful `fork(2)`
    /// returning into the child. The runtime uses this to short-circuit
    /// host-side teardown when the guest exits (Rust drops on the
    /// rebuilt HVF state would otherwise panic in applevisor's Vcpu
    /// Drop). Always false on non-macOS/non-aarch64 builds.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub fn is_forked_child(&self) -> bool {
        self.inner.is_forked_child
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub fn is_forked_child(&self) -> bool {
        false
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub fn fork(&mut self) -> Result<ForkOutcome, TrapError> {
        Err(TrapError::UnsupportedPlatform)
    }

    /// Linux `execve(2)`: tear down the current HVF VM, build a fresh
    /// one, install the new address space, and reset the vCPU as if
    /// this engine had just been created with `map_address_space(new)`.
    ///
    /// On success there is no return value to write into x0 — execve
    /// does not return to the caller; the next `run_until_syscall`
    /// resumes at the new image's entry point.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub fn execve_into(&mut self, address_space: &AddressSpace) -> Result<(), TrapError> {
        self.inner.execve_into(address_space)
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub fn execve_into(&mut self, _: &AddressSpace) -> Result<(), TrapError> {
        Err(TrapError::UnsupportedPlatform)
    }

    /// Push a Carrick signal frame onto SP_EL0 and redirect the next
    /// vCPU resume to `handler(signum)`. Returns the address of the
    /// frame so a future debugger can correlate. See
    /// `SyscallTrap::inject_signal` for the semantics.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub fn inject_signal(
        &mut self,
        signum: i32,
        handler: u64,
        sa_restorer: u64,
        pending_syscall_retval: Option<i64>,
        interrupted_pc: Option<u64>,
        altstack: Option<(u64, u64)>,
        saved_sigmask: u64,
    ) -> Result<(), TrapError> {
        self.inner.inject_signal(
            signum,
            handler,
            sa_restorer,
            pending_syscall_retval,
            interrupted_pc,
            altstack,
            saved_sigmask,
        )
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub fn inject_signal(
        &mut self,
        _signum: i32,
        _handler: u64,
        _sa_restorer: u64,
        _pending_syscall_retval: Option<i64>,
        _interrupted_pc: Option<u64>,
        _altstack: Option<(u64, u64)>,
        _saved_sigmask: u64,
    ) -> Result<(), TrapError> {
        Err(TrapError::UnsupportedPlatform)
    }

    /// Pop the Carrick signal frame at SP_EL0 and restore the pre-
    /// signal register state. Used by `rt_sigreturn(2)`.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub fn restore_from_sigframe(&mut self) -> Result<u64, TrapError> {
        self.inner.restore_from_sigframe()
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub fn restore_from_sigframe(&mut self) -> Result<u64, TrapError> {
        Err(TrapError::UnsupportedPlatform)
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn new_platform() -> Result<Self, TrapError> {
        use applevisor::prelude::*;

        let max_ipa = VirtualMachineConfig::get_max_ipa_size().map_err(hvf_error)?;
        let mut config = VirtualMachineConfig::new();
        config.set_ipa_size(max_ipa).map_err(hvf_error)?;
        let vm = VirtualMachine::with_config(config).map_err(hvf_error)?;
        let vcpu = vm.vcpu_create().map_err(hvf_error)?;
        Ok(Self {
            inner: std::mem::ManuallyDrop::new(HvfInner {
                _vm: vm,
                vcpu,
                mappings: Vec::new(),
                last_exit_class: 0,
                is_forked_child: false,
                protections: std::sync::Arc::new(MemoryProtections::default()),
            }),
        })
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    fn new_platform() -> Result<Self, TrapError> {
        Err(TrapError::UnsupportedPlatform)
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn map_plan(&mut self, plan: &GuestMappingPlan) -> Result<(), TrapError> {
        use applevisor::prelude::*;

        for mapping in &plan.mappings {
            if std::env::var_os("CARRICK_TRACE_MAPS").is_some() {
                eprintln!(
                    "MAP guest_start=0x{:x} mapped_size=0x{:x} payload_size=0x{:x} perms=r{}w{}x{}",
                    mapping.guest_start,
                    mapping.mapped_size,
                    mapping.payload_size,
                    if mapping.perms.read { '+' } else { '-' },
                    if mapping.perms.write { '+' } else { '-' },
                    if mapping.perms.execute { '+' } else { '-' },
                );
            }
            let region = map_region_raw(mapping)?;
            self.inner.mappings.push(region);
        }

        // Start PC: if an EL0 entry trampoline is installed, the vCPU begins
        // at the trampoline page (in EL1h) and executes the single `eret`
        // there to drop into EL0t at the real user entry. Otherwise the vCPU
        // starts directly at the user entry (used by the existing EL1-only
        // unit tests).
        let initial_pc = plan.el0_trampoline_entry.unwrap_or(plan.entry);
        self.inner
            .vcpu
            .set_reg(Reg::PC, initial_pc)
            .map_err(hvf_error)?;
        // M[3:0]=0b0101 = EL1h (AArch64 EL1 using SP_EL1) + DAIF masked.
        // HVF reset CPSR is also EL1h; we set it explicitly so a re-entry
        // after a syscall trap doesn't depend on whatever HVF left in place.
        // The vCPU stays at EL1h until the trampoline `eret` swaps PSTATE
        // for the SPSR_EL1 value programmed below.
        const AARCH64_PSTATE_EL1H_DAIF_MASKED: u64 = 0x3c5;
        self.inner
            .vcpu
            .set_reg(Reg::CPSR, AARCH64_PSTATE_EL1H_DAIF_MASKED)
            .map_err(hvf_error)?;
        // When using the trampoline, stage SPSR_EL1 with "AArch64 EL0t, DAIF
        // masked" (M[3:0]=0b0000) and ELR_EL1 with the user-mode entry. The
        // `eret` at the trampoline page then transitions to EL0t with
        // PC=plan.entry, which is the state Linux user code expects so the
        // first `svc #0` raises a "lower EL using AArch64" synchronous
        // exception that HVF surfaces to the host.
        if let Some(_trampoline) = plan.el0_trampoline_entry {
            const AARCH64_PSTATE_EL0T_DAIF_MASKED: u64 = 0x3c0;
            self.inner
                .vcpu
                .set_sys_reg(SysReg::SPSR_EL1, AARCH64_PSTATE_EL0T_DAIF_MASKED)
                .map_err(hvf_error)?;
            self.inner
                .vcpu
                .set_sys_reg(SysReg::ELR_EL1, plan.entry)
                .map_err(hvf_error)?;
        }
        // Disable stage-1 MMU translation for the EL0/EL1 guest. Without this,
        // the vCPU's reset value of SCTLR_EL1 has .M=1, which makes every
        // instruction fetch translate through page tables we never built, and
        // the first fetch faults with FSC=Translation fault, level 3. With
        // .M=0 the guest sees stage-2 mappings directly. Bits C/I (caches) are
        // also cleared since we have no maintenance ops yet.
        // SCTLR_EL1 layout:
        //   bit  0 = M  (MMU enable)        — 0: stage-1 MMU off, identity
        //   bit  2 = C  (D-cache enable)    — 1: data accesses cacheable
        //   bit 12 = I  (I-cache enable)    — 1: instruction fetches cacheable
        //   bits 22..21 = SED/UCT etc. (default 0 is fine)
        //   bits 28..23 = RES1 (reserved-as-one); HVF accepts 0 for them.
        // We keep M=0 (no page tables) but set C=1 and I=1 so the memory we
        // use is treated as cacheable Normal memory. ARMv8-A defines
        // exclusive load/store on non-cacheable memory as UNPREDICTABLE,
        // and Apple HVF appears to abort externally rather than treat it as
        // implementation-defined; musl's `ldaxr` on first mutex acquire
        // depends on this.
        // If a stage-1 page-table region is installed, program TTBR0_EL1,
        // TCR_EL1 and MAIR_EL1 to point at our identity-mapping tables,
        // and set SCTLR_EL1.M = 1 so EL0/EL1 data accesses go through
        // the Normal-cacheable mapping. ARMv8-A treats data accesses as
        // Device-nGnRnE memory whenever stage-1 is disabled, and
        // `ldaxr`/`stlxr` on Device memory abort externally — which is
        // exactly the wall musl's pthread_mutex_lock hits otherwise.
        let mut sctlr_el1: u64 = (1 << 2) | (1 << 12); // C=1, I=1
        // Stage-1 MMU is on by default. The identity tables use AP=00 for
        // kernel pages (trampoline/vectors/PT) and AP=01+PXN=1 for user
        // pages, which is required on Apple Silicon because HVF starts
        // vCPUs with PSTATE.PAN=1 and FEAT_PAN3 turns any EL1 fetch from
        // an AP[1]=1 page into a permission fault. See
        // `stage1_identity_page_tables` in src/memory.rs.
        if let Some(pt_base) = plan.stage1_page_tables_base {
            // MAIR_EL1 slot 0 = Normal memory, Inner & Outer Write-Back
            // Cacheable, RW-allocate (0xFF). Slot 1..7 stay 0 (Device-
            // nGnRnE), unused for now.
            self.inner
                .vcpu
                .set_sys_reg(SysReg::MAIR_EL1, 0xFF)
                .map_err(hvf_error)?;
            // TCR_EL1:
            //   T0SZ = 24  (40-bit VA, start at L0)
            //   IRGN0 = 0b11 (Inner WB Cacheable)
            //   ORGN0 = 0b11 (Outer WB Cacheable)
            //   SH0   = 0b11 (Inner Shareable)
            //   TG0   = 0b00 (4K granule)
            //   EPD1  = 1    (disable TTBR1 walks)
            //   IPS   = 0b010 (40-bit IPA, max for M-series HVF)
            const T0SZ: u64 = 24;
            const TCR_EL1_BOOTSTRAP: u64 =
                T0SZ | (0b11 << 8) | (0b11 << 10) | (0b11 << 12) | (1 << 23) | (0b010 << 32);
            self.inner
                .vcpu
                .set_sys_reg(SysReg::TCR_EL1, TCR_EL1_BOOTSTRAP)
                .map_err(hvf_error)?;
            self.inner
                .vcpu
                .set_sys_reg(SysReg::TTBR0_EL1, pt_base)
                .map_err(hvf_error)?;
            // Enable stage-1 MMU (M=1) on top of the C=1, I=1 flags above.
            sctlr_el1 |= 1;
        }
        self.inner
            .vcpu
            .set_sys_reg(SysReg::SCTLR_EL1, sctlr_el1)
            .map_err(hvf_error)?;
        // Enable FP/SIMD for the guest. Without this, CPACR_EL1.FPEN defaults
        // to "trap at EL0", and musl's `memset` (which uses NEON `dup`/`stp`
        // instructions) faults on its very first call — the trap is misrouted
        // through our EL1 vector as if it were an SVC, the dispatcher sees
        // garbage syscall numbers, and the guest spins forever. FPEN=0b11
        // turns the trap off; the bottom two bits of each TRC* field are kept
        // at zero (trace unsupported, no SME).
        const CPACR_EL1_FPEN_NO_TRAP: u64 = 0x3 << 20;
        self.inner
            .vcpu
            .set_sys_reg(SysReg::CPACR_EL1, CPACR_EL1_FPEN_NO_TRAP)
            .map_err(hvf_error)?;
        // Route lower-EL synchronous exceptions (EL0 `svc #0`) through our
        // vector page. Without this, VBAR_EL1 defaults to 0 (or whatever
        // HVF leaves it at) and the SVC fetch faults on an unmapped page.
        if let Some(vectors_base) = plan.el1_vectors_base {
            self.inner
                .vcpu
                .set_sys_reg(SysReg::VBAR_EL1, vectors_base)
                .map_err(hvf_error)?;
        }
        if let Some(stack_pointer) = plan.initial_stack_pointer {
            // Running at EL1h, so seed both SP_EL1 (current SP) and SP_EL0
            // (in case anything ever drops back to EL0).
            self.inner
                .vcpu
                .set_sys_reg(SysReg::SP_EL1, stack_pointer)
                .map_err(hvf_error)?;
            self.inner
                .vcpu
                .set_sys_reg(SysReg::SP_EL0, stack_pointer)
                .map_err(hvf_error)?;
        }
        Ok(())
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    fn map_plan(&mut self, _: &GuestMappingPlan) -> Result<(), TrapError> {
        Err(TrapError::UnsupportedPlatform)
    }
}

/// Volatile byte copy out of guest-shared memory. Guest RAM is MAP_SHARED
/// and the guest vCPU can mutate it concurrently on another host thread; a
/// plain (non-volatile) read racing that write is UB in Rust's memory
/// model (the optimizer may assume the bytes are stable and tear/hoist/
/// elide the read). `read_volatile` per byte forbids that. This does NOT
/// make the data race semantically correct — the guest owns its own
/// synchronization — it only removes the language-level UB on the host side.
///
/// SAFETY: `src` must be valid for reads of `len` bytes and `dst` valid for
/// writes of `len` bytes; the two regions must not overlap.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[inline]
unsafe fn volatile_copy_from_guest(src: *const u8, dst: *mut u8, len: usize) {
    for i in 0..len {
        unsafe { dst.add(i).write(src.add(i).read_volatile()) };
    }
}

/// Volatile byte copy INTO guest-shared memory. See
/// [`volatile_copy_from_guest`] for why volatile is required.
///
/// SAFETY: `src` must be valid for reads of `len` bytes and `dst` valid for
/// writes of `len` bytes; the two regions must not overlap.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[inline]
unsafe fn volatile_copy_to_guest(src: *const u8, dst: *mut u8, len: usize) {
    for i in 0..len {
        unsafe { dst.add(i).write_volatile(src.add(i).read()) };
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfInner {
    fn mapped_region_count(&self) -> usize {
        self.mappings.len()
    }

    fn program_counter(&self) -> Result<u64, TrapError> {
        use applevisor::prelude::*;

        self.vcpu.get_reg(Reg::PC).map_err(hvf_error)
    }

    fn vcpu_kick_handle(&self) -> crate::vcpu_kick::VcpuKickHandle {
        crate::vcpu_kick::VcpuKickHandle::new(self.vcpu.get_handle())
    }

    fn run_until_syscall(&mut self) -> Result<Option<Aarch64SyscallFrame>, TrapError> {
        use applevisor::prelude::*;

        // Time the vCPU's guest execution: the wall time spent inside
        // hv_vcpu_run is the time this vCPU thread was on-CPU running guest
        // code (blocking guest syscalls trap OUT and wait in carrick host code,
        // so this is execution time, not idle). HVF guest cycles don't accrue
        // to the host thread's rusage, so getrusage/times/`/proc` source the
        // guest's user CPU time from this. (hv_vcpu_get_exec_time was measured
        // to under-report ~40× here, so it isn't used.) Accumulated lock-free
        // into this vCPU thread's slot; summed process-wide by `guest_cpu`.
        let exit = loop {
            let run_start = std::time::Instant::now();
            let run_result = self.vcpu.run();
            let run_ns = run_start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            crate::guest_cpu::add(run_ns);
            run_result.map_err(hvf_error)?;
            let exit = self.vcpu.get_exit_info();
            if exit.reason == ExitReason::CANCELED {
                // A cross-thread `hv_vcpus_exit` (crate::vcpu_kick) forced this
                // vCPU out of the guest so a pending signal can be delivered.
                //
                // But the kick can land while the vCPU is still inside carrick's
                // EL1 trap trampoline — a guest EL0 `svc`/fault is mid-flight,
                // between the vector entry (VBAR_EL1 = vectors_base, e.g. the
                // sync-from-EL0 entry at +0x400) and the HVC that traps out to
                // the host. PC there is an EL1 trampoline address, NOT a guest
                // userspace PC. Injecting a signal frame at it (the run loop
                // treats `None` as "deliver at current PC") overwrites the
                // in-flight exception and wedges the thread — reproduced as a
                // SIGURG storm corrupting a futex waiter (pc=vectors_base+0x404).
                //
                // Resume until the guest is back at EL0 so the trampoline
                // completes its HVC and the real syscall is serviced; the
                // pending signal is then delivered at that clean EL0 boundary.
                let cpsr = self.vcpu.get_reg(Reg::CPSR).map_err(hvf_error)?;
                let el = (cpsr >> 2) & 0b11;
                if el != 0 {
                    EL1_KICK_RESUMED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    crate::probes::kick_in_kernel(self.vcpu.get_reg(Reg::PC).unwrap_or(0), el as u32);
                    continue;
                }
                return Ok(None);
            }
            break exit;
        };
        if exit.reason != ExitReason::EXCEPTION {
            return Err(TrapError::UnexpectedExit {
                reason: format!("{:?}", exit.reason),
            });
        }

        let exception = exit.exception;
        if !is_aarch64_syscall_exception(exception.syndrome) {
            return Err(TrapError::UnexpectedException {
                syndrome: exception.syndrome,
                virtual_address: exception.virtual_address,
                physical_address: exception.physical_address,
            });
        }
        // EC=0x16 (HVC) only means our EL1 vector trampoline fired — it
        // catches ALL lower-EL synchronous exceptions, not just SVCs.
        // Look at ESR_EL1 to see what actually trapped to EL1; if it's
        // not an SVC, surface it as an unexpected-EL0-fault so the
        // runtime can deliver the right Linux signal instead of pretending
        // x8 is a syscall number.
        if is_aarch64_hvc_exception(exception.syndrome) {
            let underlying = self.vcpu.get_sys_reg(SysReg::ESR_EL1).map_err(hvf_error)?;
            if !is_aarch64_svc_exception(underlying) {
                let elr = self.vcpu.get_sys_reg(SysReg::ELR_EL1).unwrap_or(0);
                let far = self.vcpu.get_sys_reg(SysReg::FAR_EL1).unwrap_or(0);
                let x16 = self.vcpu.get_reg(Reg::X16).unwrap_or(0);
                let x17 = self.vcpu.get_reg(Reg::X17).unwrap_or(0);
                let x29 = self.vcpu.get_reg(Reg::X29).unwrap_or(0);
                let x30 = self.vcpu.get_reg(Reg::LR).unwrap_or(0);
                let sp = self.vcpu.get_sys_reg(SysReg::SP_EL0).unwrap_or(0);
                // Fire the fault probe so `carrick trace` can catch the exact
                // fault (and `--stack`-walk the guest) — fires only here, never
                // on the happy path, so it doesn't perturb the timing-sensitive
                // c>=20 race it's meant to diagnose.
                crate::probes::vcpu_fault(underlying, elr, far, x30, sp, unsafe { libc::getpid() });
                return Err(TrapError::EL0Fault {
                    syndrome: underlying,
                    elr,
                    far,
                    x16,
                    x17,
                    x29,
                    x30,
                    sp,
                });
            }
        }
        self.last_exit_class = aarch64_exception_class(exception.syndrome);

        if std::env::var_os("CARRICK_TRACE_REGS").is_some() {
            let pc = self.vcpu.get_reg(Reg::PC).map_err(hvf_error)?;
            let elr = self.vcpu.get_sys_reg(SysReg::ELR_EL1).map_err(hvf_error)?;
            let spsr = self.vcpu.get_sys_reg(SysReg::SPSR_EL1).map_err(hvf_error)?;
            let sp_el0 = self.vcpu.get_sys_reg(SysReg::SP_EL0).map_err(hvf_error)?;
            let far = self.vcpu.get_sys_reg(SysReg::FAR_EL1).map_err(hvf_error)?;
            let x0 = self.vcpu.get_reg(Reg::X0).map_err(hvf_error)?;
            let x1 = self.vcpu.get_reg(Reg::X1).map_err(hvf_error)?;
            let x2 = self.vcpu.get_reg(Reg::X2).map_err(hvf_error)?;
            let x3 = self.vcpu.get_reg(Reg::X3).map_err(hvf_error)?;
            let x4 = self.vcpu.get_reg(Reg::X4).map_err(hvf_error)?;
            let x5 = self.vcpu.get_reg(Reg::X5).map_err(hvf_error)?;
            let x8 = self.vcpu.get_reg(Reg::X8).map_err(hvf_error)?;
            let esr = self.vcpu.get_sys_reg(SysReg::ESR_EL1).map_err(hvf_error)?;
            eprintln!(
                "TRAP exit_va=0x{:x} exit_pa=0x{:x} esr_el1=0x{:x} (ec=0x{:02x}) pc=0x{:x} elr=0x{:x} sp=0x{:x} far=0x{:x} x8={} x0=0x{:x} x1=0x{:x}",
                exception.virtual_address,
                exception.physical_address,
                esr,
                (esr >> 26) & 0x3f,
                pc,
                elr,
                sp_el0,
                far,
                x8,
                x0,
                x1
            );
            let _ = (spsr, x2, x3, x4, x5);
        }

        let frame = Aarch64SyscallFrame {
            x0: self.vcpu.get_reg(Reg::X0).map_err(hvf_error)?,
            x1: self.vcpu.get_reg(Reg::X1).map_err(hvf_error)?,
            x2: self.vcpu.get_reg(Reg::X2).map_err(hvf_error)?,
            x3: self.vcpu.get_reg(Reg::X3).map_err(hvf_error)?,
            x4: self.vcpu.get_reg(Reg::X4).map_err(hvf_error)?,
            x5: self.vcpu.get_reg(Reg::X5).map_err(hvf_error)?,
            x8: self.vcpu.get_reg(Reg::X8).map_err(hvf_error)?,
        };
        // Guest EL0 PC at the trap. HVF sets ELR_EL1 to the
        // instruction-after-svc when it dispatches the synchronous
        // exception, so this is the address the guest will resume at
        // after `complete_syscall`.
        let guest_pc = self.vcpu.get_sys_reg(SysReg::ELR_EL1).unwrap_or(0);
        let lr = self.vcpu.get_reg(Reg::LR).unwrap_or(0);
        // FP (x29) + SP let guest_stack.d walk the guest call chain.
        let fp = self.vcpu.get_reg(Reg::X29).unwrap_or(0);
        let sp = self.vcpu.get_sys_reg(SysReg::SP_EL0).unwrap_or(0);
        // Guest+host bases of the region containing `sp`, so a DTrace
        // consumer can translate stack VAs and copyin frames (the two
        // bases individually fit in i64; a single offset would wrap).
        let (stack_guest_base, stack_host_base, stack_guest_end) = self
            .mappings
            .iter()
            .find(|m| sp >= m.start && sp < m.end)
            .map(|m| (m.start, m.host_addr as u64, m.end))
            .unwrap_or((0, 0, 0));
        crate::probes::vcpu_trap(&crate::compat::GuestRegs {
            pc: guest_pc,
            sp,
            fp,
            lr,
            x8: frame.x8,
            x0: frame.x0,
            stack_guest_base,
            stack_host_base,
            stack_guest_end,
        });
        Ok(Some(frame))
    }

    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError> {
        use applevisor::prelude::*;

        self.vcpu
            .set_reg(Reg::X0, return_value as u64)
            .map_err(hvf_error)?;
        if std::env::var_os("CARRICK_TRACE_REGS").is_some() {
            let pc = self.vcpu.get_reg(Reg::PC).map_err(hvf_error)?;
            let elr = self.vcpu.get_sys_reg(SysReg::ELR_EL1).map_err(hvf_error)?;
            eprintln!(
                "COMPLETE return=0x{:x} pc=0x{:x} elr_el1=0x{:x}",
                return_value, pc, elr
            );
        }
        Ok(())
    }

    /// True if `[address, address+length)` overlaps any PROT_NONE range. Used
    /// to fault syscall-path accesses to a guest PROT_NONE buffer (EFAULT).
    fn range_no_access(&self, address: u64, length: usize) -> bool {
        self.protections.range_no_access(address, length)
    }

    fn read_guest_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        if self.range_no_access(address, length) {
            return Err(MemoryError::OutOfBounds { address, length });
        }
        let Some(mapping) = self.mapping_for_range(address, length) else {
            return Err(MemoryError::OutOfBounds { address, length });
        };
        // Read directly out of the host buffer. Works for both
        // applevisor-owned mappings (the parent case) and raw mappings
        // we re-created in a forked child via hv_vm_map.
        let offset = (address - mapping.start) as usize;
        let mut bytes = vec![0u8; length];
        unsafe {
            volatile_copy_from_guest(mapping.host_addr.add(offset), bytes.as_mut_ptr(), length);
        }
        Ok(bytes)
    }

    /// Host VA of `address` iff it lives in a genuine `MAP_SHARED` file
    /// mapping (shared across carrick processes via a host MAP_SHARED of the
    /// real file). Used to back a cross-process futex with `__ulock`.
    fn shared_futex_host_addr(&self, address: u64) -> Option<usize> {
        let mapping = self.mapping_for_range(address, 4)?;
        if !mapping.guest_shared {
            return None;
        }
        let offset = (address - mapping.start) as usize;
        Some(unsafe { mapping.host_addr.add(offset) } as usize)
    }

    fn write_guest_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let length = bytes.len();
        if self.range_no_access(address, length) {
            return Err(MemoryError::OutOfBounds { address, length });
        }
        let Some(mapping) = self.mapping_for_range_mut(address, length) else {
            return Err(MemoryError::OutOfBounds { address, length });
        };
        let offset = (address - mapping.start) as usize;
        unsafe {
            volatile_copy_to_guest(bytes.as_ptr(), mapping.host_addr.add(offset), length);
        }
        Ok(())
    }

    /// Mark `[address, address+len)` PROT_NONE (`no_access=true`) or clear it.
    /// Clearing performs interval subtraction so an mprotect/mmap that re-enables
    /// part of a PROT_NONE region leaves only the still-protected remainder.
    fn set_no_access(&mut self, address: u64, len: usize, no_access: bool) {
        self.protections.set_no_access(address, len, no_access);
    }

    /// Back `[guest_addr, guest_addr+len)` with a real `MAP_SHARED` mmap of
    /// the host file `host_fd`, mapped into the guest IPA via `hv_vm_map`.
    /// Both the guest CPU (stage-2) and the dispatcher accessor
    /// (`read_guest_bytes`, via `host_addr`) then share the file's page
    /// cache → full MAP_SHARED coherence + persistence. Takes ownership of
    /// `host_fd` (closes it once mapped — the mapping outlives the fd).
    fn map_shared_file(
        &mut self,
        guest_addr: u64,
        len: usize,
        host_fd: i32,
        offset: u64,
    ) -> Result<(), MemoryError> {
        let host_mapping = crate::host_mapping::OwnedHostMapping::map_shared_file(
            len, host_fd, offset,
        )
        .map_err(|error| MemoryError::HostMap(format!("mmap(MAP_SHARED) failed: {error}")))?;
        let host = host_mapping.as_ptr();
        let len = host_mapping.len();
        let perms = hvf_perms(SegmentPerms {
            read: true,
            write: true,
            execute: false,
        });
        let perms_raw: u64 = u64::from(perms);
        let r = unsafe {
            applevisor_sys::hv_vm_map(host.cast::<std::ffi::c_void>(), guest_addr, len, perms_raw)
        };
        if r != 0 {
            return Err(MemoryError::HostMap(format!("hv_vm_map failed: 0x{r:x}")));
        }
        let guest_shared = host_mapping.guest_shared();
        self.mappings.push(HvfMappedRegion {
            start: guest_addr,
            end: guest_addr + len as u64,
            host_addr: host,
            size: len,
            perms,
            // We own the libc mmap (not an applevisor Memory). Torn down by
            // `unmap_shared_file`; on engine drop the VM tear-down releases
            // the stage-2 entries and the host pages leak only at exit.
            memory: None,
            host_mapping: Some(host_mapping),
            // A genuine guest MAP_SHARED file mapping: must stay shared across
            // fork (no private snapshot).
            guest_shared,
        });
        Ok(())
    }

    /// Like `map_shared_file` but anonymous: a host `MAP_SHARED|MAP_ANON`
    /// region mapped into the guest IPA, kept shared across fork. Used for a
    /// guest `MAP_SHARED|MAP_ANONYMOUS` mmap (cross-process futex / shared IPC).
    fn map_shared_anon(&mut self, guest_addr: u64, len: usize) -> Result<(), MemoryError> {
        let host_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            len,
            crate::host_mapping::HostMappingKind::SharedAnon,
        )
        .map_err(|error| {
            MemoryError::HostMap(format!("mmap(MAP_SHARED|MAP_ANON) failed: {error}"))
        })?;
        let host = host_mapping.as_ptr();
        let len = host_mapping.len();
        let perms = hvf_perms(SegmentPerms {
            read: true,
            write: true,
            execute: false,
        });
        let perms_raw: u64 = u64::from(perms);
        let r = unsafe {
            applevisor_sys::hv_vm_map(host.cast::<std::ffi::c_void>(), guest_addr, len, perms_raw)
        };
        if r != 0 {
            return Err(MemoryError::HostMap(format!("hv_vm_map failed: 0x{r:x}")));
        }
        let guest_shared = host_mapping.guest_shared();
        self.mappings.push(HvfMappedRegion {
            start: guest_addr,
            end: guest_addr + len as u64,
            host_addr: host,
            size: len,
            perms,
            memory: None,
            host_mapping: Some(host_mapping),
            // Genuine guest MAP_SHARED mapping — shared across fork, never
            // snapshotted, and a valid cross-process futex target.
            guest_shared,
        });
        Ok(())
    }

    fn unmap_shared_file(&mut self, guest_addr: u64, len: usize) -> Result<(), MemoryError> {
        if let Some(pos) = self
            .mappings
            .iter()
            .position(|m| m.start == guest_addr && m.memory.is_none() && m.size == len)
        {
            let m = self.mappings.remove(pos);
            let owns_host_mapping = m.host_mapping.is_some();
            unsafe {
                applevisor_sys::hv_vm_unmap(guest_addr, len);
                if !owns_host_mapping {
                    libc::munmap(m.host_addr.cast::<std::ffi::c_void>(), len);
                }
            }
            drop(m);
        }
        Ok(())
    }

    fn msync_shared_file(&mut self, guest_addr: u64, len: usize) -> Result<(), MemoryError> {
        if let Some(m) = self
            .mappings
            .iter()
            .find(|m| m.start == guest_addr && m.memory.is_none())
        {
            unsafe {
                libc::msync(
                    m.host_addr as *mut std::ffi::c_void,
                    len.min(m.size),
                    libc::MS_SYNC,
                );
            }
        }
        Ok(())
    }

    fn mapping_for_range(&self, address: u64, length: usize) -> Option<&HvfMappedRegion> {
        self.mappings
            .iter()
            .find(|mapping| mapping.contains_range(address, length))
    }

    fn mapping_for_range_mut(
        &mut self,
        address: u64,
        length: usize,
    ) -> Option<&mut HvfMappedRegion> {
        self.mappings
            .iter_mut()
            .find(|mapping| mapping.contains_range(address, length))
    }

    fn guest_range_is_writable(&self, address: u64, length: usize) -> bool {
        self.mapping_for_range(address, length).is_some() && !self.range_no_access(address, length)
    }

    /// Snapshot every register the trap engine ever writes. We restore
    /// from this in the forked child after the new vCPU is created.
    fn snapshot_vcpu(&self) -> Result<VcpuSnapshot, TrapError> {
        use applevisor::prelude::*;
        let mut gprs = [0u64; 31];
        for (i, reg) in GPR_TABLE.iter().enumerate() {
            gprs[i] = self.vcpu.get_reg(*reg).map_err(hvf_error)?;
        }
        Ok(VcpuSnapshot {
            gprs,
            pc: self.vcpu.get_reg(Reg::PC).map_err(hvf_error)?,
            cpsr: self.vcpu.get_reg(Reg::CPSR).map_err(hvf_error)?,
            sp_el0: self.vcpu.get_sys_reg(SysReg::SP_EL0).map_err(hvf_error)?,
            sctlr_el1: self
                .vcpu
                .get_sys_reg(SysReg::SCTLR_EL1)
                .map_err(hvf_error)?,
            tcr_el1: self.vcpu.get_sys_reg(SysReg::TCR_EL1).map_err(hvf_error)?,
            ttbr0_el1: self
                .vcpu
                .get_sys_reg(SysReg::TTBR0_EL1)
                .map_err(hvf_error)?,
            mair_el1: self.vcpu.get_sys_reg(SysReg::MAIR_EL1).map_err(hvf_error)?,
            vbar_el1: self.vcpu.get_sys_reg(SysReg::VBAR_EL1).map_err(hvf_error)?,
            cpacr_el1: self
                .vcpu
                .get_sys_reg(SysReg::CPACR_EL1)
                .map_err(hvf_error)?,
            spsr_el1: self.vcpu.get_sys_reg(SysReg::SPSR_EL1).map_err(hvf_error)?,
            elr_el1: self.vcpu.get_sys_reg(SysReg::ELR_EL1).map_err(hvf_error)?,
            tpidr_el0: self
                .vcpu
                .get_sys_reg(SysReg::TPIDR_EL0)
                .map_err(hvf_error)?,
            last_exit_class: self.last_exit_class,
        })
    }

    fn restore_vcpu(&mut self, snap: &VcpuSnapshot) -> Result<(), TrapError> {
        use applevisor::prelude::*;
        for (reg, value) in GPR_TABLE.iter().zip(snap.gprs.iter()) {
            self.vcpu.set_reg(*reg, *value).map_err(hvf_error)?;
        }
        self.vcpu.set_reg(Reg::PC, snap.pc).map_err(hvf_error)?;
        self.vcpu.set_reg(Reg::CPSR, snap.cpsr).map_err(hvf_error)?;
        self.vcpu
            .set_sys_reg(SysReg::SP_EL0, snap.sp_el0)
            .map_err(hvf_error)?;
        // Order matters: program TCR/MAIR/TTBR0 before flipping SCTLR.M.
        self.vcpu
            .set_sys_reg(SysReg::MAIR_EL1, snap.mair_el1)
            .map_err(hvf_error)?;
        self.vcpu
            .set_sys_reg(SysReg::TCR_EL1, snap.tcr_el1)
            .map_err(hvf_error)?;
        self.vcpu
            .set_sys_reg(SysReg::TTBR0_EL1, snap.ttbr0_el1)
            .map_err(hvf_error)?;
        self.vcpu
            .set_sys_reg(SysReg::CPACR_EL1, snap.cpacr_el1)
            .map_err(hvf_error)?;
        self.vcpu
            .set_sys_reg(SysReg::VBAR_EL1, snap.vbar_el1)
            .map_err(hvf_error)?;
        self.vcpu
            .set_sys_reg(SysReg::SPSR_EL1, snap.spsr_el1)
            .map_err(hvf_error)?;
        self.vcpu
            .set_sys_reg(SysReg::ELR_EL1, snap.elr_el1)
            .map_err(hvf_error)?;
        self.vcpu
            .set_sys_reg(SysReg::TPIDR_EL0, snap.tpidr_el0)
            .map_err(hvf_error)?;
        // Apply SCTLR last so the MMU enable lands with the new tables.
        self.vcpu
            .set_sys_reg(SysReg::SCTLR_EL1, snap.sctlr_el1)
            .map_err(hvf_error)?;
        self.last_exit_class = snap.last_exit_class;
        Ok(())
    }

    /// Synthesise a Linux signal delivery: push a Carrick sigframe onto
    /// SP_EL0, set x0 = signum, x30 = sa_restorer, and point ELR_EL1 at
    /// the user handler so the next `eret` from EL1 lands on the
    /// handler in EL0t. Returns Ok(()) on success; the runtime then
    /// resumes the vCPU.
    ///
    /// `pending_syscall_retval` is the value the dispatcher computed
    /// for the syscall that just trapped. If it's `Some`, x0 in the
    /// snapshotted frame is replaced by this retval so the handler-
    /// return path resumes the caller as if the syscall completed
    /// normally; if it's `None`, the current x0 is preserved (used for
    /// the rare case where a signal is delivered before the first
    /// syscall has run).
    fn inject_signal(
        &mut self,
        signum: i32,
        handler: u64,
        sa_restorer: u64,
        pending_syscall_retval: Option<i64>,
        interrupted_pc: Option<u64>,
        altstack: Option<(u64, u64)>,
        saved_sigmask: u64,
    ) -> Result<(), TrapError> {
        use applevisor::prelude::*;
        use zerocopy::IntoBytes;

        let mut frame = crate::linux_abi::CarrickSigframe::empty();
        frame.signum = signum as u32;
        for (i, reg) in GPR_TABLE.iter().enumerate() {
            frame.saved_x[i] = self.vcpu.get_reg(*reg).map_err(hvf_error)?;
        }
        // x0 was just overwritten by `complete_syscall` with the
        // syscall's retval. Snapshot that value (not the pre-syscall
        // arg0) so the handler-return path resumes with the right
        // retval visible.
        if let Some(retval) = pending_syscall_retval {
            frame.saved_x[0] = retval as u64;
        }
        // Resume address after the handler returns. On a syscall-boundary
        // injection HVF set ELR_EL1 to the instruction after the `svc`; on a
        // kick (CANCELED) exit there was no exception, so ELR_EL1 is stale and
        // the caller passes the live guest PC instead.
        frame.saved_pc = match interrupted_pc {
            Some(pc) => {
                KICK_PATH_INJECT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // Tripwire: a kick-path injection should never capture a PC in
                // carrick's EL1 vector page — run_until_syscall resumes those.
                if (0x20000..0x24000).contains(&pc) {
                    INJECT_AT_EL1.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                pc
            }
            None => self.vcpu.get_sys_reg(SysReg::ELR_EL1).map_err(hvf_error)?,
        };
        frame.saved_sp = self.vcpu.get_sys_reg(SysReg::SP_EL0).map_err(hvf_error)?;
        frame.saved_spsr = self.vcpu.get_sys_reg(SysReg::SPSR_EL1).map_err(hvf_error)?;

        let mut siginfo = crate::linux_abi::LinuxSiginfo::empty();
        siginfo.si_signo = signum;
        siginfo.si_code = crate::linux_abi::LINUX_SI_USER;
        frame.siginfo = siginfo;

        let mut mcontext = crate::linux_abi::LinuxSignalContext::empty();
        mcontext.regs = frame.saved_x;
        mcontext.sp = frame.saved_sp;
        mcontext.pc = frame.saved_pc;
        mcontext.pstate = frame.saved_spsr;
        // Save V0–V31 + FPSR/FPCR as a Linux fpsimd_context at the start of
        // sigcontext.__reserved, so the handler can't leak SIMD state into the
        // interrupted thread (aarch64 memcpy/memset use V registers) and so a
        // handler inspecting the ucontext sees real FP state.
        self.save_fpsimd_into(&mut mcontext)?;
        let mut ucontext = crate::linux_abi::LinuxUcontext::empty();
        ucontext.uc_sigmask = saved_sigmask;
        ucontext.uc_mcontext = mcontext;
        // When delivering on the alternate signal stack (SA_ONSTACK), the
        // ucontext's uc_stack describes that stack with SS_ONSTACK set, so a
        // handler querying sigaltstack(NULL, &old) sees it's running on it.
        if let Some((ss_sp, ss_size)) = altstack {
            ucontext.uc_stack = crate::linux_abi::LinuxSignalStack {
                ss_sp,
                ss_flags: crate::linux_abi::LINUX_SS_ONSTACK as i32,
                _pad0: 0,
                ss_size,
            };
        }
        frame.ucontext = ucontext;

        // Reserve space on the target stack, rounded down to 16-byte alignment
        // (AArch64 stack alignment requirement at function-call boundaries).
        // For SA_ONSTACK the frame is pushed from the TOP of the alt stack
        // (ss_sp + ss_size); otherwise from the interrupted SP_EL0. The alt
        // stack is what lets a handler run when the main stack is unusable
        // (LTP sigaltstack01 deliberately exercises that).
        let frame_bytes = frame.as_bytes();
        let new_sp = signal_frame_stack_pointer(frame.saved_sp, altstack, frame_bytes.len())?;
        if altstack.is_some() && !self.guest_range_is_writable(new_sp, frame_bytes.len()) {
            return Err(TrapError::Hypervisor(format!(
                "signal alt stack frame range is not mapped/writable: 0x{new_sp:x}+{}",
                frame_bytes.len()
            )));
        }

        // Write the frame into guest memory at the new SP.
        self.write_guest_bytes(new_sp, frame_bytes)
            .map_err(|e| TrapError::Hypervisor(format!("sigframe write failed: {e}")))?;

        // Adjust SP_EL0 to point past the freshly-written frame.
        self.vcpu
            .set_sys_reg(SysReg::SP_EL0, new_sp)
            .map_err(hvf_error)?;

        // First handler argument is the signum.
        self.vcpu
            .set_reg(Reg::X0, signum as u64)
            .map_err(hvf_error)?;
        // x1/x2 carry siginfo* / ucontext* on SA_SIGINFO. Handlers may inspect
        // or mutate the saved PC/SP before rt_sigreturn, so keep the embedded
        // Linux-shaped context authoritative.
        let siginfo_addr =
            new_sp + core::mem::offset_of!(crate::linux_abi::CarrickSigframe, siginfo) as u64;
        let ucontext_addr =
            new_sp + core::mem::offset_of!(crate::linux_abi::CarrickSigframe, ucontext) as u64;
        self.vcpu
            .set_reg(Reg::X1, siginfo_addr)
            .map_err(hvf_error)?;
        self.vcpu
            .set_reg(Reg::X2, ucontext_addr)
            .map_err(hvf_error)?;

        // LR = the restorer the handler `ret`s to, which must invoke
        // `rt_sigreturn(2)`. musl/x86-style libcs pass an explicit
        // `sa_restorer`; glibc on aarch64 passes 0 and relies on the kernel's
        // VDSO sigreturn trampoline (the aarch64 kernel ABI has no
        // sa_restorer). Use Carrick's fixed executable user trampoline rather
        // than writing code into the guest signal stack: stack-resident code is
        // vulnerable to I-cache coherency and frame-clobber timing at Go's
        // SIGURG preemption rate.
        let restorer = if sa_restorer != 0 {
            sa_restorer
        } else {
            crate::memory::LINUX_SIGRETURN_TRAMPOLINE_BASE
        };
        self.vcpu.set_reg(Reg::X30, restorer).map_err(hvf_error)?;
        crate::probes::signal_inject(signum, frame.saved_pc, new_sp, handler);

        // Redirect to the handler entry. On a syscall-boundary injection the
        // guest is mid-`eret` from the EL1 vector, so the resume PC is ELR_EL1
        // (previously "instruction after the SVC"); we steal it for the handler
        // and frame.saved_pc holds the original until rt_sigreturn. On a kick
        // (CANCELED) injection there is no pending eret — the vCPU resumes
        // directly at Reg::PC — so redirect PC instead and leave ELR_EL1 alone.
        // Either way the handler later returns via the rt_sigreturn `svc`, whose
        // completion restores ELR_EL1 = saved_pc and erets to it.
        if interrupted_pc.is_some() {
            self.vcpu.set_reg(Reg::PC, handler).map_err(hvf_error)?;
        } else {
            self.vcpu
                .set_sys_reg(SysReg::ELR_EL1, handler)
                .map_err(hvf_error)?;
        }

        // Preserve the SPSR_EL1 we snapshotted — we want to return to
        // EL0t with the same DAIF state, and the EL1 vector path
        // already set SPSR_EL1 to "EL0t, DAIF masked" when entering
        // this trap. Nothing to write here; SPSR_EL1 is already
        // correct for "return to EL0t".

        // Signal-injection trap: x8 sentinel marks "not a syscall",
        // x0 carries the signum. PC is the handler entry; FP/SP aren't
        // meaningful mid-injection so leave them 0.
        crate::probes::vcpu_trap(&crate::compat::GuestRegs {
            pc: handler,
            sp: 0,
            fp: 0,
            lr: 0,
            x8: 0xffff_ffff_ffff_ffff,
            x0: signum as u64,
            stack_guest_base: 0,
            stack_host_base: 0,
            stack_guest_end: 0,
        });
        Ok(())
    }

    /// Snapshot the guest V0–V31 + FPSR/FPCR into the Linux `fpsimd_context`
    /// at the start of `mcontext.__reserved`. Mirrors what the arm64 kernel
    /// writes at signal entry (`preserve_fpsimd_context`).
    fn save_fpsimd_into(
        &self,
        mcontext: &mut crate::linux_abi::LinuxSignalContext,
    ) -> Result<(), TrapError> {
        use applevisor::prelude::*;
        use zerocopy::IntoBytes;

        let mut fp = crate::linux_abi::LinuxFpsimdContext::empty();
        let mut vregs = [0u128; 32];
        for (i, reg) in SIMD_FP_TABLE.iter().enumerate() {
            vregs[i] = self.vcpu.get_simd_fp_reg(*reg).map_err(hvf_error)?;
        }
        fp.vregs = vregs;
        fp.fpsr = self.vcpu.get_reg(Reg::FPSR).map_err(hvf_error)? as u32;
        fp.fpcr = self.vcpu.get_reg(Reg::FPCR).map_err(hvf_error)? as u32;
        let bytes = fp.as_bytes();
        mcontext.__reserved[..bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    /// Restore V0–V31 + FPSR/FPCR from the `fpsimd_context` saved in
    /// `mcontext.__reserved`. A missing/!FPSIMD_MAGIC record is left alone
    /// (vector registers keep their current values rather than taking garbage).
    fn restore_fpsimd_from(
        &self,
        mcontext: &crate::linux_abi::LinuxSignalContext,
    ) -> Result<(), TrapError> {
        use applevisor::prelude::*;
        use zerocopy::FromBytes;

        let reserved = mcontext.__reserved;
        let size = core::mem::size_of::<crate::linux_abi::LinuxFpsimdContext>();
        let Ok(fp) = crate::linux_abi::LinuxFpsimdContext::read_from_bytes(&reserved[..size]) else {
            return Ok(());
        };
        if fp.magic != crate::linux_abi::LINUX_FPSIMD_MAGIC {
            return Ok(());
        }
        let vregs = fp.vregs;
        for (i, reg) in SIMD_FP_TABLE.iter().enumerate() {
            self.vcpu
                .set_simd_fp_reg(*reg, vregs[i])
                .map_err(hvf_error)?;
        }
        let (fpsr, fpcr) = (fp.fpsr, fp.fpcr);
        self.vcpu
            .set_reg(Reg::FPSR, u64::from(fpsr))
            .map_err(hvf_error)?;
        self.vcpu
            .set_reg(Reg::FPCR, u64::from(fpcr))
            .map_err(hvf_error)?;
        Ok(())
    }

    /// Pop the Carrick sigframe at SP_EL0 (placed there by
    /// `inject_signal`) and restore the pre-signal register state.
    fn restore_from_sigframe(&mut self) -> Result<u64, TrapError> {
        use applevisor::prelude::*;
        use zerocopy::FromBytes;

        let sp = self.vcpu.get_sys_reg(SysReg::SP_EL0).map_err(hvf_error)?;
        let frame_size = core::mem::size_of::<crate::linux_abi::CarrickSigframe>();
        let bytes = self
            .read_guest_bytes(sp, frame_size)
            .map_err(|e| TrapError::Hypervisor(format!("sigframe read failed: {e}")))?;
        let frame = crate::linux_abi::CarrickSigframe::read_from_bytes(&bytes)
            .map_err(|_| TrapError::Hypervisor("sigframe decode failed".to_string()))?;
        let magic = frame.magic;
        if magic != crate::linux_abi::CARRICK_SIGFRAME_MAGIC {
            return Err(TrapError::Hypervisor(format!(
                "rt_sigreturn: bad sigframe magic at SP_EL0=0x{sp:x}: 0x{magic:x}"
            )));
        }

        // `frame` is `#[repr(C, packed)]` so we cannot borrow individual
        // fields. Copy out the Linux ucontext first; SA_SIGINFO handlers may
        // mutate it before invoking rt_sigreturn.
        let ucontext = frame.ucontext;
        let restored_sigmask = ucontext.uc_sigmask;
        let mcontext = ucontext.uc_mcontext;
        let saved_x = mcontext.regs;
        for (reg, value) in GPR_TABLE.iter().zip(saved_x.iter()) {
            self.vcpu.set_reg(*reg, *value).map_err(hvf_error)?;
        }
        // Restore V0–V31 + FPSR/FPCR from the fpsimd_context the matching
        // inject_signal stored (a handler may have mutated it). Skip silently if
        // the record's magic is absent (older/foreign frame) — never restore
        // garbage over the vector registers.
        self.restore_fpsimd_from(&mcontext)?;
        let saved_pc = mcontext.pc;
        let saved_sp = mcontext.sp;
        let saved_spsr = mcontext.pstate;
        crate::probes::signal_restore(saved_pc, sp, magic);
        self.vcpu
            .set_sys_reg(SysReg::ELR_EL1, saved_pc)
            .map_err(hvf_error)?;
        self.vcpu
            .set_sys_reg(SysReg::SP_EL0, saved_sp)
            .map_err(hvf_error)?;
        self.vcpu
            .set_sys_reg(SysReg::SPSR_EL1, saved_spsr)
            .map_err(hvf_error)?;
        Ok(restored_sigmask)
    }

    fn fork(&mut self) -> Result<ForkOutcome, TrapError> {
        use applevisor::prelude::*;

        // Pre-fork: snapshot vCPU state and capture mapping descriptors.
        let snapshot = self.snapshot_vcpu()?;
        crate::probes::fork_pre(snapshot.pc, snapshot.elr_el1, snapshot.cpsr);
        let mapping_descs: Vec<ForkMappingDesc> = self
            .mappings
            .iter()
            .map(|m| ForkMappingDesc {
                start: m.start,
                end: m.end,
                host: ForkMappingHost::Borrowed(m.host_addr),
                size: m.size,
                perms: m.perms,
                guest_shared: m.guest_shared,
            })
            .collect();

        // Guest RAM is host-MAP_SHARED (HVF coherence), so fork(2) does NOT
        // COW-isolate it. Take a private snapshot of each PRIVATE region HERE,
        // pre-fork, while the guest vCPU is suspended (atomic, race-free); the
        // child re-maps these copies, the parent keeps its originals. Genuine
        // guest MAP_SHARED file mappings (`guest_shared`) are NOT snapshotted —
        // they must stay shared across fork (POSIX), so both sides keep mapping
        // the same host buffer. Built unconditionally because we don't yet know
        // which side we are; the parent drops its unused owned snapshots after
        // choosing `mapping_descs` below.
        let mut child_descs: Vec<ForkMappingDesc> = Vec::with_capacity(mapping_descs.len());
        for desc in &mapping_descs {
            let child_host = if desc.guest_shared {
                ForkMappingHost::Borrowed(desc.host.ptr()) // shared mapping: child maps the SAME buffer
            } else {
                ForkMappingHost::Owned(clone_region_for_child(desc.host.ptr(), desc.size)?)
            };
            child_descs.push(ForkMappingDesc {
                start: desc.start,
                end: desc.end,
                host: child_host,
                size: desc.size,
                perms: desc.perms,
                guest_shared: desc.guest_shared,
            });
        }

        // Tear down the parent's HVF context BEFORE forking. macOS's
        // HVF kernel state is not fork-safe: if a VM exists in the
        // parent at fork(2) time, the child inherits a "resource is
        // busy" state that prevents `hv_vm_create` from succeeding.
        // Both processes then rebuild a fresh VM from the snapshot.
        let inherited_vcpu_id = self.vcpu.id();
        let _ = unsafe { applevisor_sys::hv_vcpu_destroy(inherited_vcpu_id) };
        let _ = unsafe { applevisor_sys::hv_vm_destroy() };

        // Real fork. Caller is expected to have flushed any host-side
        // stdio buffers; for our JSON-at-end report flow this is fine.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(TrapError::ForkFailed(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        if pid == 0 {
            // The child has a new pid, but its inherited USDT DOF is
            // registered with the kernel under the PARENT's pid. Re-register
            // so DTrace's `carrick*` provider matches this child too —
            // otherwise forked guest processes (apt's http method, dpkg-deb's
            // tar subprocess) are invisible to `carrick trace`, which made
            // tracing forked failures unreliable.
            let _ = crate::probes::register_dtrace_probes();
        }
        // Both parent and child fall through to the rebuild path below.
        // The discriminator at the end of the function returns the
        // appropriate `ForkOutcome` based on `pid`.

        // ----- Symmetric rebuild path (parent AND child reach here) -----
        //
        // Build a fresh VM + vCPU. Both processes have just had their
        // HVF state torn down (parent did it pre-fork; child inherited
        // the now-empty state via fork). Each side independently
        // re-registers the inherited host buffers via raw `hv_vm_map`.
        let max_ipa = VirtualMachineConfig::get_max_ipa_size().map_err(hvf_error)?;
        let mut config = VirtualMachineConfig::new();
        config.set_ipa_size(max_ipa).map_err(hvf_error)?;
        let new_vm = VirtualMachine::with_config(config).map_err(hvf_error)?;
        let new_vcpu = new_vm.vcpu_create().map_err(hvf_error)?;

        // Overwrite *self with the new HvfInner WITHOUT running Drop on
        // the old contents. The old struct holds applevisor wrappers
        // around HVF handles that we already destroyed via the raw API
        // pre-fork; running their Drop now would unwrap NO_RESOURCES
        // and panic.
        //
        // `is_forked_child` is true only in the child process; the
        // parent kept its pre-fork host process identity, so its post-
        // fork cleanup still uses the normal path (which now also goes
        // through ManuallyDrop, so neither side runs the panicky
        // destructors).
        // Guest PROT_NONE ranges are part of the address space fork copies;
        // carry them into the rebuilt engine so the child keeps faulting on
        // them (it inherited the parent's mappings, perms and all).
        let inherited_protections =
            std::sync::Arc::new(MemoryProtections::from_ranges(self.protections.snapshot()));
        let new_inner = HvfInner {
            _vm: new_vm,
            vcpu: new_vcpu,
            mappings: Vec::with_capacity(mapping_descs.len()),
            last_exit_class: snapshot.last_exit_class,
            is_forked_child: pid == 0,
            protections: inherited_protections,
        };
        replace_destroyed_hvf_inner(self, new_inner);

        // Re-map each region using raw hv_vm_map. The PARENT re-maps its
        // original buffers; the CHILD maps the pre-fork private snapshots for
        // PRIVATE regions and the shared originals for guest-MAP_SHARED ones.
        // The unused set (the child's snapshot copies in the parent) drops here
        // when the parent chooses `mapping_descs`; the child moves its owned
        // snapshots into the rebuilt engine.
        let descs = if pid == 0 { child_descs } else { mapping_descs };
        for desc in descs {
            let host_addr = desc.host.ptr();
            let perms_raw: u64 = u64::from(desc.perms);
            let r = unsafe {
                applevisor_sys::hv_vm_map(
                    host_addr as *mut std::ffi::c_void,
                    desc.start,
                    desc.size,
                    perms_raw,
                )
            };
            if r != 0 {
                return Err(TrapError::ChildMapFailed {
                    host_addr: host_addr as u64,
                    guest_start: desc.start,
                    size: desc.size,
                    code: r as u32,
                });
            }
            self.mappings.push(HvfMappedRegion {
                start: desc.start,
                end: desc.end,
                host_addr,
                size: desc.size,
                perms: desc.perms,
                // No Memory object — the host buffer is either an inherited
                // shared mapping or a snapshot copy. Drop runs no HVF call for
                // this mapping; the engine's VM tear-down releases all stage-2
                // entries in one shot.
                memory: None,
                host_mapping: desc.host.into_owned(),
                guest_shared: desc.guest_shared,
            });
        }

        // Restore vCPU register state from the pre-fork snapshot. Both
        // parent and child resume inside the same `clone` syscall site;
        // the dispatcher will then write the appropriate retval into
        // X0 (child pid for parent, 0 for child).
        self.restore_vcpu(&snapshot)?;
        crate::probes::fork_post(pid, snapshot.pc, snapshot.elr_el1);
        if pid == 0 {
            Ok(ForkOutcome::Child)
        } else {
            Ok(ForkOutcome::Parent { child_pid: pid })
        }
    }

    /// Snapshot the parent + capture mapping descriptors for a thread
    /// sibling. The shared VM handle is cloned (Arc-refcounted) so the
    /// spawned thread can create its vCPU against it.
    fn build_thread_spec(&self, stack: u64, tls: u64) -> Result<ThreadSpec, TrapError> {
        let parent = self.snapshot_vcpu()?;
        let snapshot = seed_child_snapshot(&parent, stack, tls);
        let mappings: Vec<ThreadMappingDesc> = self
            .mappings
            .iter()
            .map(ThreadMappingDesc::from_region)
            .collect();
        Ok(ThreadSpec {
            vm: self._vm.clone(),
            mappings,
            protections: std::sync::Arc::clone(&self.protections),
            snapshot,
        })
    }

    /// Stand up the sibling vCPU on the current thread. Mirrors fork()'s
    /// rebuild path but KEEPS the shared VM (the spec's `vm` clone) instead
    /// of creating a new one, and marks every re-mapped region UNOWNED
    /// (`memory: None`) so this engine never unmaps the buffers the main
    /// engine owns. `is_forked_child` is set so the runtime/Drop use the
    /// no-teardown path (the vCPU and the VM-clone Arc leak until process
    /// exit, exactly like the forked-child pattern; no double-free).
    fn from_thread_spec(spec: ThreadSpec) -> Result<Self, TrapError> {
        let ThreadSpec {
            vm,
            mappings,
            protections,
            snapshot,
        } = spec;

        let vcpu = vm.vcpu_create().map_err(hvf_error)?;

        let mut inner = HvfInner {
            _vm: vm,
            vcpu,
            mappings: Vec::with_capacity(mappings.len()),
            last_exit_class: snapshot.last_exit_class,
            // Reuse the forked-child shutdown discipline: this engine's
            // vCPU was created on this thread and must not be torn down by
            // the panicky applevisor Drops; the VM clone just decrements
            // the Arc on process exit.
            is_forked_child: true,
            protections,
        };

        for mapping in mappings {
            // `hv_vm_map` is VM-global on Hypervisor.framework. The new vCPU is
            // created in the parent's VM clone, so the parent mappings are
            // already visible here; reissuing them for every sibling is at best
            // an already-mapped no-op and at worst map-table churn while other
            // vCPUs are running. Keep only local metadata used by syscall-path
            // guest-memory accessors.
            inner.mappings.push(mapping.into_unowned_region());
        }

        inner.restore_vcpu_thread_start(&snapshot)?;
        Ok(inner)
    }

    /// Seed a BRAND-NEW sibling vCPU so it enters EL0 at the child's resume
    /// PC. Unlike `restore_vcpu` (used by fork, whose vCPU had already done
    /// the boot trampoline `eret` into EL0 and merely resumes), a freshly
    /// created vCPU has never transitioned to EL0. We therefore start it at
    /// the EL0 trampoline page (in EL1h) with SPSR_EL1=EL0t and
    /// ELR_EL1=the child's EL0 PC, so the trampoline's single `eret` drops
    /// the vCPU into EL0 at exactly the post-clone instruction — mirroring
    /// `map_plan`'s initial-boot sequence but with thread-private PC/SP/TLS.
    fn restore_vcpu_thread_start(&mut self, snap: &VcpuSnapshot) -> Result<(), TrapError> {
        use applevisor::prelude::*;
        for (reg, value) in GPR_TABLE.iter().zip(snap.gprs.iter()) {
            self.vcpu.set_reg(*reg, *value).map_err(hvf_error)?;
        }
        // Start at the EL0 trampoline page in EL1h; the trampoline `eret`s
        // into EL0t at ELR_EL1 with SPSR_EL1's PSTATE.
        const AARCH64_PSTATE_EL1H_DAIF_MASKED: u64 = 0x3c5;
        const AARCH64_PSTATE_EL0T_DAIF_MASKED: u64 = 0x3c0;
        self.vcpu
            .set_reg(Reg::PC, crate::memory::LINUX_EL0_TRAMPOLINE_BASE)
            .map_err(hvf_error)?;
        self.vcpu
            .set_reg(Reg::CPSR, AARCH64_PSTATE_EL1H_DAIF_MASKED)
            .map_err(hvf_error)?;
        self.vcpu
            .set_sys_reg(SysReg::SPSR_EL1, AARCH64_PSTATE_EL0T_DAIF_MASKED)
            .map_err(hvf_error)?;
        // The child's EL0 resume PC (snap.pc == parent ELR_EL1 == post-svc).
        self.vcpu
            .set_sys_reg(SysReg::ELR_EL1, snap.pc)
            .map_err(hvf_error)?;
        self.vcpu
            .set_sys_reg(SysReg::SP_EL0, snap.sp_el0)
            .map_err(hvf_error)?;
        // Same translation regime as the parent (shared address space).
        self.vcpu
            .set_sys_reg(SysReg::MAIR_EL1, snap.mair_el1)
            .map_err(hvf_error)?;
        self.vcpu
            .set_sys_reg(SysReg::TCR_EL1, snap.tcr_el1)
            .map_err(hvf_error)?;
        self.vcpu
            .set_sys_reg(SysReg::TTBR0_EL1, snap.ttbr0_el1)
            .map_err(hvf_error)?;
        self.vcpu
            .set_sys_reg(SysReg::CPACR_EL1, snap.cpacr_el1)
            .map_err(hvf_error)?;
        self.vcpu
            .set_sys_reg(SysReg::VBAR_EL1, snap.vbar_el1)
            .map_err(hvf_error)?;
        self.vcpu
            .set_sys_reg(SysReg::TPIDR_EL0, snap.tpidr_el0)
            .map_err(hvf_error)?;
        // SP_EL1 for the brief EL1h trampoline window. The trampoline only
        // executes one `eret` and touches no stack, but give it a sane value
        // (the child's EL0 stack works; the trampoline never pushes).
        self.vcpu
            .set_sys_reg(SysReg::SP_EL1, snap.sp_el0)
            .map_err(hvf_error)?;
        // Enable the MMU last, identically to the parent.
        self.vcpu
            .set_sys_reg(SysReg::SCTLR_EL1, snap.sctlr_el1)
            .map_err(hvf_error)?;
        self.last_exit_class = snap.last_exit_class;
        Ok(())
    }

    /// Replace the engine's HVF state with a fresh VM that runs
    /// `address_space` from its entry point. Used for `execve(2)`.
    ///
    /// Sequence mirrors `fork()`'s rebuild path but takes a brand-new
    /// AddressSpace rather than a snapshot, and resets the vCPU to
    /// "initial process startup" (trampoline + new entry) rather than
    /// "resume mid-syscall".
    fn execve_into(&mut self, address_space: &AddressSpace) -> Result<(), TrapError> {
        use applevisor::prelude::*;

        // Build the mapping plan up front so any image errors surface
        // before we destroy the current HVF state.
        let plan = GuestMappingPlan::from_address_space(address_space)?;

        // Tear down the current HVF VM. Same dance as fork(): destroy
        // vCPU then VM via raw API (applevisor's Drop is bypassed by
        // the `ManuallyDrop` wrapper around `HvfInner`).
        let inherited_vcpu_id = self.vcpu.id();
        let _ = unsafe { applevisor_sys::hv_vcpu_destroy(inherited_vcpu_id) };
        let _ = unsafe { applevisor_sys::hv_vm_destroy() };

        // Create a fresh VM + vCPU.
        let max_ipa = VirtualMachineConfig::get_max_ipa_size().map_err(hvf_error)?;
        let mut config = VirtualMachineConfig::new();
        config.set_ipa_size(max_ipa).map_err(hvf_error)?;
        let new_vm = VirtualMachine::with_config(config).map_err(hvf_error)?;
        let new_vcpu = new_vm.vcpu_create().map_err(hvf_error)?;

        // Preserve `is_forked_child` across execve. A process that
        // descended from the original `carrick run` invocation should
        // keep using the `_exit`-without-JSON shutdown path even after
        // it execve's into a different image; otherwise every forked +
        // execve'd descendant prints its own JSON report to stdout
        // (interleaved with the parent's), making the user-visible
        // output unreadable.
        let was_forked_child = self.is_forked_child;
        // Replace inner in place WITHOUT Drop on the old.
        let new_inner = HvfInner {
            _vm: new_vm,
            vcpu: new_vcpu,
            mappings: Vec::new(),
            last_exit_class: 0,
            is_forked_child: was_forked_child,
            // execve replaces the address space; any prior PROT_NONE ranges are
            // gone. The new image starts with none until it mmaps them.
            protections: std::sync::Arc::new(MemoryProtections::default()),
        };
        replace_destroyed_hvf_inner(self, new_inner);

        // Apply the new mapping plan via the shared raw-mmap helper (same
        // backing as map_plan — see `map_region_raw` for why we avoid
        // applevisor `Memory`/`alloc_zeroed`).
        for mapping in &plan.mappings {
            self.mappings.push(map_region_raw(mapping)?);
        }

        // Initial vCPU state — same sequence as `map_address_space`.
        // Zero the GPRs first: Linux's execve contract says the new
        // program starts with all registers clear (x29/x30 are part
        // of the ABI calling convention but the kernel zeros them too)
        // except for SP and PC. Without this, musl's _start in the new
        // image inherits the previous process's x8 which can decode
        // as a bogus syscall number on the first svc.
        for reg in GPR_TABLE {
            self.vcpu.set_reg(reg, 0).map_err(hvf_error)?;
        }

        let initial_pc = plan.el0_trampoline_entry.unwrap_or(plan.entry);
        self.vcpu.set_reg(Reg::PC, initial_pc).map_err(hvf_error)?;
        const AARCH64_PSTATE_EL1H_DAIF_MASKED: u64 = 0x3c5;
        self.vcpu
            .set_reg(Reg::CPSR, AARCH64_PSTATE_EL1H_DAIF_MASKED)
            .map_err(hvf_error)?;
        if let Some(_trampoline) = plan.el0_trampoline_entry {
            const AARCH64_PSTATE_EL0T_DAIF_MASKED: u64 = 0x3c0;
            self.vcpu
                .set_sys_reg(SysReg::SPSR_EL1, AARCH64_PSTATE_EL0T_DAIF_MASKED)
                .map_err(hvf_error)?;
            self.vcpu
                .set_sys_reg(SysReg::ELR_EL1, plan.entry)
                .map_err(hvf_error)?;
        }
        let mut sctlr_el1: u64 = (1 << 2) | (1 << 12);
        if let Some(pt_base) = plan.stage1_page_tables_base {
            self.vcpu
                .set_sys_reg(SysReg::MAIR_EL1, 0xFF)
                .map_err(hvf_error)?;
            const T0SZ: u64 = 24;
            const TCR_EL1_BOOTSTRAP: u64 =
                T0SZ | (0b11 << 8) | (0b11 << 10) | (0b11 << 12) | (1 << 23) | (0b010 << 32);
            self.vcpu
                .set_sys_reg(SysReg::TCR_EL1, TCR_EL1_BOOTSTRAP)
                .map_err(hvf_error)?;
            self.vcpu
                .set_sys_reg(SysReg::TTBR0_EL1, pt_base)
                .map_err(hvf_error)?;
            sctlr_el1 |= 1;
        }
        self.vcpu
            .set_sys_reg(SysReg::SCTLR_EL1, sctlr_el1)
            .map_err(hvf_error)?;
        const CPACR_EL1_FPEN_NO_TRAP: u64 = 0x3 << 20;
        self.vcpu
            .set_sys_reg(SysReg::CPACR_EL1, CPACR_EL1_FPEN_NO_TRAP)
            .map_err(hvf_error)?;
        if let Some(vectors_base) = plan.el1_vectors_base {
            self.vcpu
                .set_sys_reg(SysReg::VBAR_EL1, vectors_base)
                .map_err(hvf_error)?;
        }
        if let Some(stack_pointer) = plan.initial_stack_pointer {
            self.vcpu
                .set_sys_reg(SysReg::SP_EL1, stack_pointer)
                .map_err(hvf_error)?;
            self.vcpu
                .set_sys_reg(SysReg::SP_EL0, stack_pointer)
                .map_err(hvf_error)?;
        }
        // execve resets TPIDR_EL0 — the new image's musl init will
        // call set_thread_area to initialise it.
        self.vcpu
            .set_sys_reg(SysReg::TPIDR_EL0, 0)
            .map_err(hvf_error)?;

        // Verify post-execve sysreg state through dtrace. If stage-1
        // isn't on or TTBR0 doesn't point at the new tables, the new
        // process will fault on the first LDAXR.
        let actual_sctlr = self.vcpu.get_sys_reg(SysReg::SCTLR_EL1).unwrap_or(0);
        let actual_ttbr0 = self.vcpu.get_sys_reg(SysReg::TTBR0_EL1).unwrap_or(0);
        let actual_mair = self.vcpu.get_sys_reg(SysReg::MAIR_EL1).unwrap_or(0);
        crate::probes::execve_sysregs(actual_sctlr, actual_ttbr0, actual_mair);
        Ok(())
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfMappedRegion {
    fn contains_range(&self, address: u64, length: usize) -> bool {
        let Ok(length) = u64::try_from(length) else {
            return false;
        };
        let Some(end) = address.checked_add(length) else {
            return false;
        };
        address >= self.start && end <= self.end
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
impl HvfInner {
    fn mapped_region_count(&self) -> usize {
        0
    }

    fn program_counter(&self) -> Result<u64, TrapError> {
        Err(TrapError::UnsupportedPlatform)
    }

    fn vcpu_kick_handle(&self) -> crate::vcpu_kick::VcpuKickHandle {
        crate::vcpu_kick::VcpuKickHandle::placeholder()
    }

    fn run_until_syscall(&mut self) -> Result<Option<Aarch64SyscallFrame>, TrapError> {
        Err(TrapError::UnsupportedPlatform)
    }

    fn complete_syscall(&mut self, _: i64) -> Result<(), TrapError> {
        Err(TrapError::UnsupportedPlatform)
    }

    fn read_guest_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        Err(MemoryError::OutOfBounds { address, length })
    }

    fn write_guest_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        Err(MemoryError::OutOfBounds {
            address,
            length: bytes.len(),
        })
    }
}

impl GuestMemory for HvfTrapEngine {
    fn read_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        self.inner.read_guest_bytes(address, length)
    }

    fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.inner.write_guest_bytes(address, bytes)
    }

    fn map_shared_file(
        &mut self,
        guest_addr: u64,
        len: usize,
        host_fd: i32,
        offset: u64,
    ) -> Result<(), MemoryError> {
        self.inner.map_shared_file(guest_addr, len, host_fd, offset)
    }

    fn map_shared_anon(&mut self, guest_addr: u64, len: usize) -> Result<(), MemoryError> {
        self.inner.map_shared_anon(guest_addr, len)
    }

    fn unmap_shared_file(&mut self, guest_addr: u64, len: usize) -> Result<(), MemoryError> {
        self.inner.unmap_shared_file(guest_addr, len)
    }

    fn msync_shared_file(&mut self, guest_addr: u64, len: usize) -> Result<(), MemoryError> {
        self.inner.msync_shared_file(guest_addr, len)
    }

    fn set_no_access(&mut self, address: u64, len: usize, no_access: bool) {
        self.inner.set_no_access(address, len, no_access);
    }

    fn shared_futex_host_addr(&self, address: u64) -> Option<usize> {
        self.inner.shared_futex_host_addr(address)
    }
}

pub fn aarch64_exception_class(syndrome: u64) -> u64 {
    (syndrome >> AARCH64_EXCEPTION_CLASS_SHIFT) & AARCH64_EXCEPTION_CLASS_MASK
}

pub fn is_aarch64_svc_exception(syndrome: u64) -> bool {
    aarch64_exception_class(syndrome) == AARCH64_SVC_EXCEPTION_CLASS
}

pub fn is_aarch64_hvc_exception(syndrome: u64) -> bool {
    aarch64_exception_class(syndrome) == AARCH64_HVC_EXCEPTION_CLASS
}

/// True for syscall-shaped traps that the host can dispatch identically:
/// EL0 `svc #0` (`EC = 0x15`) and our EL1 vector's `hvc #0` re-trap
/// (`EC = 0x16`). Both deliver the syscall ABI registers unchanged.
pub fn is_aarch64_syscall_exception(syndrome: u64) -> bool {
    is_aarch64_svc_exception(syndrome) || is_aarch64_hvc_exception(syndrome)
}

fn align_down(value: u64, alignment: u64) -> u64 {
    value / alignment * alignment
}

fn align_up(value: u64, alignment: u64) -> Result<u64, TrapError> {
    let remainder = value % alignment;
    if remainder == 0 {
        Ok(value)
    } else {
        value
            .checked_add(alignment - remainder)
            .ok_or(TrapError::MappingOverflow {
                guest_start: value,
                mapped_size: alignment,
            })
    }
}

/// Back one guest region with a raw `mmap(MAP_ANON)` buffer + `hv_vm_map`,
/// returning an UNOWNED [`HvfMappedRegion`] (`memory: None`).
///
/// We deliberately do NOT use applevisor's `Memory` (`vm.memory_create`), whose
/// `alloc_zeroed(Layout::from_size_align(size, 16 KiB))` produces a VM mapping
/// that macOS `fork(2)` is ~8x more expensive to COW than a clean anonymous
/// `mmap` — even though neither is resident (both ~6 MiB RSS). For carrick's
/// ~640 MiB of guest windows this was the dominant per-fork cost: 640 MiB
/// fork+wait measured 9.6 ms (applevisor) vs 1.1 ms (raw mmap). See
/// `examples/fork_alloc_bench.rs`. The host pages leak only at process exit,
/// matching the existing `ManuallyDrop<HvfInner>` discipline (applevisor
/// `Memory` Drop never ran either) and the `map_shared_file` raw path.
/// Allocate a fresh `MAP_SHARED` anon buffer and copy `src`'s RESIDENT pages
/// into it. Used by `HvfInner::fork` to take a private snapshot of guest-
/// PRIVATE memory: guest RAM is host-`MAP_SHARED` for HVF coherence (see
/// `map_region_raw`), so `fork(2)` does NOT COW-isolate it — without an
/// explicit copy a forked child and its parent would share, and corrupt, the
/// same pages. Called pre-fork while the guest vCPU is suspended (atomic, no
/// race). Only resident pages are copied (mincore-gated) so the snapshot is
/// sparse; on mincore failure we fall back to a full copy (correct, slower).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn clone_region_for_child(
    src: *mut u8,
    size: usize,
) -> Result<crate::host_mapping::OwnedHostMapping, TrapError> {
    let dst = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        size,
        crate::host_mapping::HostMappingKind::ChildPrivateSnapshot,
    )
    .map_err(|error| {
        TrapError::Hypervisor(format!(
            "fork child-snapshot mmap (size={size}) failed: {error}"
        ))
    })?;
    let dst_ptr = dst.as_ptr();
    let page = {
        let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if p <= 0 { 16 * 1024 } else { p as usize }
    };
    let n_pages = size.div_ceil(page);
    let mut resident = vec![0u8; n_pages];
    let rc = unsafe {
        libc::mincore(
            src as *mut libc::c_void,
            size,
            resident.as_mut_ptr() as *mut libc::c_char,
        )
    };
    if rc != 0 {
        unsafe { std::ptr::copy_nonoverlapping(src, dst_ptr, size) };
        return Ok(dst);
    }
    for (i, &flag) in resident.iter().enumerate() {
        if flag & 1 != 0 {
            let off = i * page;
            let len = page.min(size - off);
            unsafe { std::ptr::copy_nonoverlapping(src.add(off), dst_ptr.add(off), len) };
        }
    }
    Ok(dst)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn map_region_raw(mapping: &GuestMapping) -> Result<HvfMappedRegion, TrapError> {
    let size = usize::try_from(mapping.mapped_size)
        .map_err(|_| TrapError::MappingTooLarge(mapping.mapped_size))?;
    // MAP_SHARED, not MAP_PRIVATE: a MAP_PRIVATE anon page mapped into the
    // guest via hv_vm_map desyncs from the host buffer — the guest's own store
    // and a later guest load observe different memory (the "PROT_REA" wild-PC
    // crash: a dynamic binary's GOT slot that ld.so resolved reads back stale).
    // MAP_SHARED anon is HVF-coherent (same as `map_shared_file`). The cost:
    // fork(2) no longer COW-isolates these pages, so `HvfInner::fork` takes an
    // explicit private snapshot for the child (see `clone_region_for_child`).
    let host_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
        size,
        crate::host_mapping::HostMappingKind::PrivateAnon,
    )
    .map_err(|error| {
        TrapError::Hypervisor(format!("mmap guest region (size={size}) failed: {error}"))
    })?;
    let host = host_mapping.as_ptr();
    let size = host_mapping.len();
    // Copy the payload prefix into the freshly-zeroed region; the rest stays
    // zero (lazy). offset_in_mapping + image.len() <= mapped_size is guaranteed
    // by GuestMappingPlan::from_address_space.
    if !mapping.image.is_empty() {
        let off = usize::try_from(mapping.offset_in_mapping)
            .map_err(|_| TrapError::MappingTooLarge(mapping.offset_in_mapping))?;
        unsafe {
            std::ptr::copy_nonoverlapping(
                mapping.image.as_ptr(),
                host.add(off),
                mapping.image.len(),
            );
        }
    }
    let perms = hvf_perms(mapping.perms);
    let perms_raw: u64 = u64::from(perms);
    let r = unsafe {
        applevisor_sys::hv_vm_map(
            host.cast::<std::ffi::c_void>(),
            mapping.guest_start,
            size,
            perms_raw,
        )
    };
    if r != 0 {
        return Err(TrapError::Hypervisor(format!(
            "hv_vm_map(guest=0x{:x}, size={size}) failed: 0x{r:x}",
            mapping.guest_start
        )));
    }
    let end =
        mapping
            .guest_start
            .checked_add(mapping.mapped_size)
            .ok_or(TrapError::MappingOverflow {
                guest_start: mapping.guest_start,
                mapped_size: mapping.mapped_size,
            })?;
    let guest_shared = host_mapping.guest_shared();
    Ok(HvfMappedRegion {
        start: mapping.guest_start,
        end,
        host_addr: host,
        size,
        perms,
        memory: None,
        host_mapping: Some(host_mapping),
        // Private guest RAM (data/bss/heap/stack/MAP_PRIVATE): fork snapshots it.
        guest_shared,
    })
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn hvf_perms(perms: SegmentPerms) -> applevisor::memory::MemPerms {
    use applevisor::memory::MemPerms;

    // HVF stage-2 quirk on macOS 26 (Tahoe) / Apple Silicon: a stage-2
    // mapping created with `HV_MEMORY_READ | HV_MEMORY_WRITE` (no
    // `HV_MEMORY_EXEC`) fails to translate EL0 data accesses — the guest
    // takes a stage-2 translation fault (DFSC=0x05, "translation fault
    // level 1") even though the IPA falls inside the mapping and the
    // host-side `Memory::read`/`Memory::write` accessors succeed. The
    // ARM stage-2 attribute model has no per-EL data-access bit, so the
    // fault is HVF-specific behaviour rather than ARMv8 architectural.
    //
    // Empirically, escalating the stage-2 permission to
    // `ReadWriteExec` makes the fault go away. The guest still uses
    // stage-1 (`SCTLR_EL1.M=0` in the bootstrap), so the stage-2 X bit
    // is the only thing that controls instruction fetch from the
    // region; the guest is already executing without stage-1 enforcement
    // and the host process is single-tenant, so granting stage-2 X on
    // data/stack regions does not add a meaningful new attack surface.
    //
    // The escalation is gated on the original perms still being some
    // form of `Write` so we don't accidentally upgrade a `Read`-only or
    // `Exec`-only mapping: those translate fine as-is. This keeps the
    // workaround narrow.
    let escalated_perms = SegmentPerms {
        read: perms.read,
        write: perms.write,
        execute: perms.execute || perms.write,
    };

    match (
        escalated_perms.read,
        escalated_perms.write,
        escalated_perms.execute,
    ) {
        (false, false, false) => MemPerms::None,
        (true, false, false) => MemPerms::Read,
        (false, true, false) => MemPerms::Write,
        (false, false, true) => MemPerms::Exec,
        (true, true, false) => MemPerms::ReadWrite,
        (true, false, true) => MemPerms::ReadExec,
        (false, true, true) => MemPerms::WriteExec,
        (true, true, true) => MemPerms::ReadWriteExec,
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn hvf_error(error: applevisor::error::HypervisorError) -> TrapError {
    TrapError::Hypervisor(error.to_string())
}

/// Derive the register snapshot for a thread-creating clone's child vCPU
/// from the parent's snapshot taken at the clone svc. The child shares the
/// SAME guest address space (same TTBR0/SCTLR/MMU state) so all sysregs are
/// copied verbatim; only the thread-private state differs:
///   - PC / ELR_EL1 = parent's ELR_EL1 (the instruction after the clone svc).
///     `complete_syscall` doesn't re-advance PC because HVF already set
///     ELR_EL1 to post-svc when it took the trap, so the child resumes there.
///   - X0 = 0: clone(2) returns 0 in the new thread.
///   - SP_EL0 = `stack`: the child's stack pointer (clone's stack arg).
///   - TPIDR_EL0 = `tls` if non-zero (CLONE_SETTLS), else the parent's value.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn seed_child_snapshot(parent: &VcpuSnapshot, stack: u64, tls: u64) -> VcpuSnapshot {
    let mut child = parent.clone();
    child.pc = parent.elr_el1;
    child.gprs[0] = 0;
    child.sp_el0 = stack;
    if tls != 0 {
        child.tpidr_el0 = tls;
    }
    child
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn signal_frame_stack_pointer(
    saved_sp: u64,
    altstack: Option<(u64, u64)>,
    frame_len: usize,
) -> Result<u64, TrapError> {
    let frame_len = u64::try_from(frame_len)
        .map_err(|_| TrapError::Hypervisor("sigframe length does not fit u64".to_string()))?;
    let aligned_len = frame_len
        .checked_add(15)
        .map(|len| len & !15u64)
        .ok_or_else(|| TrapError::Hypervisor("sigframe length overflowed".to_string()))?;
    let stack_base = match altstack {
        Some((ss_sp, ss_size)) => ss_sp
            .checked_add(ss_size)
            .ok_or_else(|| TrapError::Hypervisor("signal alt stack top overflowed".to_string()))?,
        None => saved_sp,
    };
    stack_base
        .checked_sub(aligned_len)
        .map(|sp| sp & !15u64)
        .ok_or_else(|| TrapError::Hypervisor("sigframe push underflowed stack".to_string()))
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg(test)]
mod memory_protection_tests {
    use super::*;

    #[test]
    fn cloned_protection_metadata_shares_updates_across_thread_engines() {
        let protections = std::sync::Arc::new(MemoryProtections::default());
        let sibling = std::sync::Arc::clone(&protections);

        protections.set_no_access(0x4000, 0x2000, true);
        assert!(sibling.range_no_access(0x4fff, 1));

        sibling.set_no_access(0x5000, 0x1000, false);
        assert!(protections.range_no_access(0x4000, 1));
        assert!(protections.range_no_access(0x4fff, 1));
        assert!(!protections.range_no_access(0x5000, 1));
        assert!(!protections.range_no_access(0x6000 - 1, 1));
    }

    #[test]
    fn protection_ranges_are_sorted_coalesced_and_split_on_clear() {
        let protections = MemoryProtections::default();

        protections.set_no_access(0x3000, 0x1000, true);
        protections.set_no_access(0x1000, 0x1000, true);
        protections.set_no_access(0x2000, 0x1000, true);

        assert_eq!(protections.snapshot(), vec![(0x1000, 0x4000)]);
        assert!(protections.range_no_access(0x1800, 1));
        assert!(protections.range_no_access(0x3fff, 1));
        assert!(!protections.range_no_access(0x4000, 1));

        protections.set_no_access(0x2000, 0x800, false);

        assert_eq!(
            protections.snapshot(),
            vec![(0x1000, 0x2000), (0x2800, 0x4000)]
        );
        assert!(!protections.range_no_access(0x2000, 0x800));
        assert!(protections.range_no_access(0x2800, 1));
    }

    #[test]
    fn signal_frame_stack_pointer_uses_checked_altstack_bounds() {
        let sp = signal_frame_stack_pointer(0x8000, Some((0x4000, 0x2000)), 0x123).unwrap();
        assert_eq!(sp & 15, 0);
        assert!(sp >= 0x4000);
        assert!(sp < 0x6000);

        let err = signal_frame_stack_pointer(0x8000, Some((u64::MAX - 8, 16)), 0x100).unwrap_err();
        assert!(
            err.to_string().contains("alt stack top overflowed"),
            "unexpected error: {err}"
        );
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[cfg(test)]
mod thread_sibling_tests {
    use super::*;

    fn parent_snapshot() -> VcpuSnapshot {
        let mut gprs = [0u64; 31];
        // Distinct values so we can prove the rest of the GPRs are copied.
        for (i, slot) in gprs.iter_mut().enumerate() {
            *slot = 0xA000 + i as u64;
        }
        VcpuSnapshot {
            gprs,
            pc: 0x1234, // the SVC PC; NOT where the child should resume
            cpsr: 0x3c0,
            sp_el0: 0xF000_0000,
            sctlr_el1: 0x1005,
            tcr_el1: 0x2,
            ttbr0_el1: 0x40000,
            mair_el1: 0xff,
            vbar_el1: 0x80000,
            cpacr_el1: 0x300000,
            spsr_el1: 0x3c0,
            elr_el1: 0x5678, // post-syscall resume point (instruction after svc)
            tpidr_el0: 0xBEEF_0000,
            last_exit_class: AARCH64_HVC_EXCEPTION_CLASS,
        }
    }

    #[test]
    fn child_resumes_at_post_syscall_pc_with_x0_zero() {
        let parent = parent_snapshot();
        let child = seed_child_snapshot(&parent, /*stack=*/ 0x7_0000, /*tls=*/ 0x9_0000);
        // The child must resume at the instruction *after* the clone svc,
        // i.e. the parent's ELR_EL1 — mirroring complete_syscall, which
        // does not re-advance PC (HVF already set ELR to post-svc).
        assert_eq!(child.pc, parent.elr_el1);
        // pthread_create expects clone to return 0 in the new thread.
        assert_eq!(child.gprs[0], 0);
    }

    #[test]
    fn child_uses_clone_stack_and_tls() {
        let parent = parent_snapshot();
        let child = seed_child_snapshot(&parent, 0x7_0000, 0x9_0000);
        assert_eq!(child.sp_el0, 0x7_0000);
        assert_eq!(child.tpidr_el0, 0x9_0000);
    }

    #[test]
    fn child_keeps_parent_tls_when_clone_tls_is_zero() {
        let parent = parent_snapshot();
        let child = seed_child_snapshot(&parent, 0x7_0000, /*tls=*/ 0);
        assert_eq!(child.tpidr_el0, parent.tpidr_el0);
    }

    #[test]
    fn child_copies_all_other_gprs_and_sysregs() {
        let parent = parent_snapshot();
        let child = seed_child_snapshot(&parent, 0x7_0000, 0x9_0000);
        // X1..X30 carried verbatim.
        for i in 1..31 {
            assert_eq!(child.gprs[i], parent.gprs[i], "gpr {i}");
        }
        assert_eq!(child.sctlr_el1, parent.sctlr_el1);
        assert_eq!(child.ttbr0_el1, parent.ttbr0_el1);
        assert_eq!(child.tcr_el1, parent.tcr_el1);
        assert_eq!(child.mair_el1, parent.mair_el1);
        assert_eq!(child.vbar_el1, parent.vbar_el1);
        assert_eq!(child.cpacr_el1, parent.cpacr_el1);
        assert_eq!(child.spsr_el1, parent.spsr_el1);
        // ELR_EL1 must point at the post-syscall PC so the very first eret
        // out of EL1 (after we seed the vCPU) lands the child in EL0.
        assert_eq!(child.elr_el1, parent.elr_el1);
        assert_eq!(child.last_exit_class, parent.last_exit_class);
    }

    #[test]
    fn thread_mapping_descriptor_preserves_shared_mapping_metadata() {
        let region = HvfMappedRegion {
            start: 0x1000,
            end: 0x5000,
            host_addr: 0x7000usize as *mut u8,
            size: 0x4000,
            perms: applevisor::memory::MemPerms::ReadWrite,
            memory: None,
            host_mapping: None,
            guest_shared: true,
        };

        let copied = ThreadMappingDesc::from_region(&region).into_unowned_region();

        assert_eq!(copied.start, region.start);
        assert_eq!(copied.end, region.end);
        assert_eq!(copied.host_addr, region.host_addr);
        assert_eq!(copied.size, region.size);
        assert_eq!(copied.perms, region.perms);
        assert!(copied.memory.is_none());
        assert!(copied.host_mapping.is_none());
        assert!(copied.guest_shared);
    }
}
