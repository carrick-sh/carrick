//! Hypervisor.framework trap engine, guest register/memory access, signal
//! frames, and fork/exec address-space management.

// The hub types live in the leaf crate carrick-guest-mem (A2); import them from
// there, not via `crate::dispatch`, so trap.rs has NO dependency on the
// dispatcher — the last edge blocking a future carrick-hvf crate (A3).
use carrick_guest_mem::{Aarch64SyscallFrame, GuestMemory, MemoryError};
use crate::elf::SegmentPerms;
use crate::memory::AddressSpace;
use serde::Serialize;
use thiserror::Error;

mod sysreg;
use sysreg::*;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod memprot;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use memprot::MemoryProtections;

/// The trap-engine contract the runtime loop drives: run the vCPU until a
/// syscall trap, complete/inject/restore around guest syscalls and signals,
/// and fork/execve the guest address space. Implemented by [`HvfTrapEngine`]
/// here and by the runtime's `SplitView` adapter. Lives in carrick-hvf (with
/// `TrapError`/`ForkOutcome`) and is re-exported from carrick-runtime.
pub trait SyscallTrap {
    /// Run the vCPU until it traps. `Ok(Some(frame))` is a guest syscall;
    /// `Ok(None)` means the vCPU was forced out of the guest by a cross-thread
    /// kick (`hv_vcpus_exit`, [`crate::vcpu_kick`]) with no syscall pending —
    /// the loop should run signal delivery and resume. `Err` is a real fault.
    fn next_syscall(&mut self) -> Result<Option<Aarch64SyscallFrame>, TrapError>;
    /// The guest PC the vCPU is currently parked at. Used as the resume address
    /// when injecting a signal on a non-syscall (kick) exit, where `ELR_EL1`
    /// does not hold a meaningful return address.
    fn current_pc(&self) -> Result<u64, TrapError>;
    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError>;
    /// Real macOS fork. Returns the child pid in the parent, 0 in the
    /// child. After this returns, the trap engine in the child holds a
    /// freshly rebuilt HVF context pointing at the same COW'd guest
    /// memory; the runtime then writes the appropriate retval into the
    /// guest's x0 via `complete_syscall`.
    fn fork(&mut self) -> Result<ForkOutcome, TrapError>;
    /// `execve(2)` — tear down the current guest address space and
    /// re-initialise this engine with `new_image`. Does NOT advance
    /// past a syscall (execve has no successful return); the next
    /// `next_syscall` resumes at the new image's entry point.
    fn execve_into(&mut self, new_image: &AddressSpace) -> Result<(), TrapError>;
    fn is_forked_child(&self) -> bool {
        false
    }
    /// Inject a guest signal frame for `signum`. Writes a
    /// `CarrickSigframe` to SP_EL0, points the guest's x30 at
    /// `sa_restorer`, sets x0 to `signum`, and redirects the vCPU's
    /// next resumed PC (`ELR_EL1`) to the user handler. The pre-signal
    /// register state is preserved in the frame and recovered by
    /// `restore_from_sigframe` on `rt_sigreturn`.
    ///
    /// `pending_syscall_retval` is the retval the dispatcher computed
    /// for the syscall that was just trapped, since signals are
    /// delivered between `complete_syscall` and the next vCPU run we
    /// already wrote it into x0; the frame snapshots the post-retval
    /// state so the handler-return path picks up where the caller left
    /// off. Pass `None` when injecting outside a syscall completion
    /// (e.g. when raising at the top of the trap loop before the first
    /// syscall has run).
    /// `interrupted_pc` is `Some(pc)` when injecting on a non-syscall kick exit
    /// (the vCPU was mid-userspace; `pc` is where it should resume after the
    /// handler returns and is redirected via `Reg::PC` rather than `ELR_EL1`).
    /// `None` is the syscall-boundary case (resume via the post-svc `ELR_EL1`).
    /// `altstack` is `Some((ss_sp, ss_size))` when the handler was registered
    /// `SA_ONSTACK` and an alternate signal stack is installed — the frame is
    /// pushed onto that stack instead of the interrupted SP_EL0. `None` keeps
    /// the frame on the current stack.
    fn inject_signal(
        &mut self,
        signum: i32,
        handler: u64,
        sa_restorer: u64,
        pending_syscall_retval: Option<i64>,
        interrupted_pc: Option<u64>,
        altstack: Option<(u64, u64)>,
        saved_sigmask: u64,
        // Some((si_code, si_addr)) for a synchronous fault (SIGSEGV/SIGBUS),
        // None for a SI_USER-shaped delivery.
        fault_siginfo: Option<(i32, u64)>,
        // SA_RESTART: this handler interrupted a restartable syscall that
        // returned EINTR. Resume at the `svc` (not after it) with the original
        // arg0 restored, so the guest re-executes the syscall after the handler
        // returns. Valid only on the syscall-boundary path (`interrupted_pc`
        // is None); ignored otherwise.
        restart_syscall: bool,
    ) -> Result<(), TrapError>;
    /// The Linux syscall number of the most recently dispatched `svc`, used to
    /// decide whether an interrupted syscall is in the SA_RESTART-restartable
    /// set. `None` before the first syscall / on traps with no vCPU.
    fn last_syscall_nr(&self) -> Option<u64> {
        None
    }
    /// Restore vCPU state from the `CarrickSigframe` at SP_EL0. Called
    /// when the guest invokes `rt_sigreturn(2)`. Does NOT advance PC
    /// past the syscall the way `complete_syscall` does — the restored
    /// PC IS the next PC.
    fn restore_from_sigframe(&mut self) -> Result<u64, TrapError>;
    /// Toggle the vCPU's memory-ordering model (`prctl(PR_SET_MEM_MODEL, …)`).
    /// `tso == true` enables hardware x86_64 Total Store Ordering on this vCPU
    /// (`ACTLR_EL1.EnTSO`), required for Rosetta-translated guests; `false`
    /// restores AArch64's default weakly-ordered model. The default
    /// implementation is a no-op (non-HVF / test traps have no vCPU register).
    fn set_memory_model(&mut self, tso: bool) -> Result<(), TrapError> {
        let _ = tso;
        Ok(())
    }
    /// Back a dynamic high-VA mmap (`DispatchOutcome::MapHostAlias`): map host
    /// memory at `ipa` and build the VA→IPA stage-1 path. Default no-op error
    /// for non-HVF/test traps (they never emit the outcome).
    fn map_host_alias(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        payload: &[u8],
    ) -> Result<(), TrapError> {
        let _ = (va, ipa, len, payload);
        Err(TrapError::UnsupportedPlatform)
    }
}


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
    /// Guest VIRTUAL address the region is mapped at (also the key for
    /// software syscall-path memory access). Equals `ipa_start` for every
    /// region except Rosetta's high-VA alias.
    pub guest_start: u64,
    /// Intermediate physical address actually handed to `hv_vm_map`. Identity
    /// (== `guest_start`) for all regions but the Rosetta window, which is
    /// aliased to a low IPA (see `crate::memory::ipa_for_va`).
    pub ipa_start: u64,
    pub mapped_size: u64,
    pub offset_in_mapping: u64,
    pub payload_size: u64,
    pub perms: SegmentPerms,
    /// Host backing is `MAP_SHARED` (kept shared across fork). Mirrors
    /// `MemoryRegion::shared`.
    pub shared: bool,
    #[serde(skip)]
    image: Vec<u8>,
}

impl GuestMappingPlan {
    pub fn from_address_space(address_space: &AddressSpace) -> Result<Self, TrapError> {
        let mut mappings = Vec::with_capacity(address_space.regions().len());
        for region in address_space.regions() {
            let guest_start = align_down(region.start, HVF_PAGE_SIZE);
            // The IPA actually mapped — identity for everything except the
            // Rosetta high-VA window, which is aliased down to a low IPA.
            let ipa_start = align_down(crate::memory::ipa_for_va(region.start), HVF_PAGE_SIZE);
            // Back the FULL Rosetta window (2 MiB) so its page-table block has no
            // unbacked tail; other regions round their end up to a page.
            let guest_end = if crate::memory::is_rosetta_va(region.start) {
                crate::memory::LINUX_ROSETTA_VA_BASE + crate::memory::LINUX_ROSETTA_WINDOW_SIZE
            } else {
                align_up(region.end, HVF_PAGE_SIZE)?
            };
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
                ipa_start,
                mapped_size,
                offset_in_mapping,
                payload_size: region.bytes().len() as u64,
                perms: region.perms,
                shared: region.shared,
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

/// Process-wide handoff for multithreaded fork: the forking thread (parent),
/// after rebuilding its VM, publishes a clone here so quiesced sibling threads
/// recreate their vCPUs in the same (new) process VM.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
type SharedVm = applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn rebuilt_vm_cell() -> &'static parking_lot::Mutex<Option<SharedVm>> {
    static CELL: std::sync::OnceLock<parking_lot::Mutex<Option<SharedVm>>> =
        std::sync::OnceLock::new();
    CELL.get_or_init(|| parking_lot::Mutex::new(None))
}

/// Process-global count of live HVF vCPUs (created minus destroyed). Pure
/// diagnostic: reported in the fork__quiesce phase-2 probe so a `carrick trace`
/// shows exactly how many vCPUs are alive when the forker calls hv_vm_destroy.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub static VCPU_LIVE: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn vcpu_created() {
    VCPU_LIVE.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// Enable EL0 direct reads of `CNTVCT_EL0`/`CNTFRQ_EL0` (`CNTKCTL_EL1.EL0VCTEN |
/// EL0PCTEN`) on a freshly-created vCPU. Must run on EVERY vCPU — initial,
/// per-thread, fork/execve rebuild. If only some vCPUs have it, the others trap
/// CNTVCT and fall back to the host-`Instant` emulation, which is a DIFFERENT
/// clock basis (ns-since-process-start, not the hardware counter the vDSO
/// assumes). That skews the monotonic clock between Go's worker threads, so a
/// timer scheduled on one vCPU is checked against a wildly different time on
/// another and never fires — deadlocking `time.After`/timer tests with absurd
/// (e.g. "179h") waits. Best-effort.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn enable_el0_counter_access(vcpu_id: applevisor_sys::hv_vcpu_t) {
    const CNTKCTL_EL1: applevisor_sys::hv_sys_reg_t = applevisor_sys::hv_sys_reg_t::CNTKCTL_EL1;
    unsafe {
        let _ = applevisor_sys::hv_vcpu_set_sys_reg(vcpu_id, CNTKCTL_EL1, (1 << 1) | (1 << 0));
    }
}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn vcpu_destroyed() {
    VCPU_LIVE.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
thread_local! {
    /// Per-sibling vCPU snapshot held between `release_vcpu_for_fork` and
    /// `rebuild_vcpu_after_fork` (both run on the same thread, around the fork
    /// quiesce park).
    static FORK_VCPU_SNAPSHOT: std::cell::RefCell<Option<VcpuSnapshot>> =
        const { std::cell::RefCell::new(None) };

}

/// Clear the published fork VM (child path; the child is single-threaded).
pub fn clear_rebuilt_vm_for_fork() {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        *rebuilt_vm_cell().lock() = None;
    }
}

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

/// Write a 128-bit value into a guest SIMD&FP (V) register.
///
/// Apple's `hv_simd_fp_uchar16_t` is `__attribute__((ext_vector_type(16)))
/// uint8_t` — a 16-byte SIMD vector, which AAPCS64 passes BY VALUE in a vector
/// (V) register. The `applevisor-sys` binding (without the nightly-only
/// `simd-nightly` feature) mistypes the by-value `set` parameter as `u128`,
/// which Rust passes in a general-purpose register PAIR (x2/x3). The kernel
/// then reads the value from a V register and gets unrelated bytes — in
/// practice zeroes — so `hv_vcpu_set_simd_fp_reg` silently corrupts the target
/// register while returning `HV_SUCCESS`. (`get` is unaffected: it is
/// pointer-based, so there is no register-class mismatch.)
///
/// This broke signal delivery: `restore_from_sigframe` could not restore the
/// interrupted thread's V registers, so any signal taken while the guest was
/// mid-SIMD (aarch64 `memmove`/`memequal`, FP math) resumed with zeroed vector
/// state. Under Go that surfaced as the async-preemption (SIGURG) corruption —
/// e.g. runtime `TestUserArena/largeScalar` comparing a buffer whose bytes are
/// intact but whose compare loop returns the wrong answer.
///
/// Passing a 16-byte vector by value across `extern "C"` from Rust needs the
/// nightly `simd_ffi` feature, so we route through a tiny C shim
/// (`carrick_shim.c`) that takes the 16 bytes by pointer and reconstructs the
/// `hv_simd_fp_uchar16_t` for the kernel call — C gets the vector ABI right on
/// stable. Returns the raw `hv_return_t` (0 = `HV_SUCCESS`).
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn set_simd_fp_reg_v(vcpu_id: u64, reg: applevisor_sys::hv_simd_fp_reg_t, value: u128) -> i32 {
    unsafe extern "C" {
        fn carrick_set_simd_fp_reg(vcpu: u64, reg: u32, bytes: *const u8) -> i32;
    }
    // u128 -> 16 little-endian bytes, matching the byte order `get_simd_fp_reg`
    // produces, so save/restore round-trips as identity.
    let bytes = value.to_le_bytes();
    unsafe { carrick_set_simd_fp_reg(vcpu_id, reg as u32, bytes.as_ptr()) }
}

/// Which privilege level a vCPU was executing at when carrick observed it. The
/// Linux guest runs its own code at EL0; everything at EL1 is carrick's trap
/// trampoline (the VBAR_EL1 vector table + the HVC that exits to the host),
/// never guest code. Keeping the two straight is a load-bearing invariant: a PC
/// (or register snapshot) captured at EL1 belongs to *carrick*, and must NEVER
/// be treated as a guest resume PC — injecting a signal frame at an EL1 PC
/// overwrites an in-flight syscall. This is the systematic carrick-vs-guest
/// distinction; classify with `ExecLevel::from_pstate(CPSR)` at every point
/// that captures a live vCPU PC for guest use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecLevel {
    /// EL0 — genuine guest userspace. Its PC is a valid guest resume target.
    Guest,
    /// EL1+ — inside carrick's trap trampoline. Its PC is a carrick address.
    Kernel,
}

impl ExecLevel {
    /// Classify from PSTATE/SPSR. M[3:2] is the exception level (00 = EL0).
    pub fn from_pstate(pstate: u64) -> Self {
        if (pstate >> 2) & 0b11 == 0 {
            ExecLevel::Guest
        } else {
            ExecLevel::Kernel
        }
    }

    pub fn is_guest(self) -> bool {
        matches!(self, ExecLevel::Guest)
    }
}

/// Full-speed diagnostic counters (the dtrace consumer perturbs the
/// SIGURG-vs-futex race away, so observe with cheap atomics instead). Dumped at
/// process teardown when `CARRICK_KICK_STATS` is set.
pub static EL1_KICK_RESUMED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static INJECT_AT_EL1: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub static KICK_PATH_INJECT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Guest mmap-arena high-water mark (the dispatcher's `mmap_next`), published by
/// `handle_fork` just before forking. `clone_region_for_child` reads it to bound
/// the per-fork resident-page `mincore` scan of the 32 GiB arena window to the
/// used prefix `[LINUX_MMAP_BASE, this)` instead of scanning all 2M pages — the
/// dominant per-fork cost (a `mincore` over the full window measured ~470 ms).
/// `u64::MAX` (the default) means "unknown, scan the full region" so non-fork
/// callers and tests keep the original, always-correct behaviour.
pub static GUEST_ARENA_HIGH_WATER: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(u64::MAX);

/// Publish the arena high-water for the next fork's snapshot scan. Called by
/// `handle_fork` with `SyscallDispatcher::mmap_arena_high_water()`.
pub fn set_guest_arena_high_water(addr: u64) {
    GUEST_ARENA_HIGH_WATER.store(addr, std::sync::atomic::Ordering::SeqCst);
}

/// Whether to save/restore guest FP/SIMD across signal handlers (default on;
/// `CARRICK_NO_FPSIMD` disables it for differential measurement). Cached after
/// the first read so the signal hot path doesn't hit the environment.
pub fn fpsimd_save_enabled() -> bool {
    use std::sync::atomic::{AtomicU8, Ordering};
    static FLAG: AtomicU8 = AtomicU8::new(0);
    match FLAG.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let on = std::env::var_os("CARRICK_NO_FPSIMD").is_none();
            FLAG.store(if on { 1 } else { 2 }, Ordering::Relaxed);
            on
        }
    }
}

pub fn dump_kick_stats() {
    use std::sync::atomic::Ordering;
    let (el1, inject, at_el1) = (
        EL1_KICK_RESUMED.load(Ordering::Relaxed),
        KICK_PATH_INJECT.load(Ordering::Relaxed),
        INJECT_AT_EL1.load(Ordering::Relaxed),
    );
    // Surface the cumulative totals through one cheap USDT fire at exit, so a
    // trace can read them without the per-event `kick-in-kernel` probe cost.
    crate::probes::kick_stats(el1, inject, at_el1);
    if std::env::var_os("CARRICK_KICK_STATS").is_some() {
        eprintln!(
            "[kick_stats pid={}] el1_kick_resumed={el1} kick_path_inject={inject} inject_at_el1={at_el1}",
            unsafe { libc::getpid() },
        );
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
    /// Lazily-built editor over the EL1 stage-1 page-table image, used to give
    /// `mprotect`/`PROT_NONE`/`munmap` guest-visible semantics. Built from the
    /// page-table region's host backing on first edit; reset to `None` on
    /// fork/execve (fresh tables). SHARED across sibling vCPU threads (one HVF
    /// VM ⇒ one set of stage-1 tables): the mutex serializes edits so the
    /// spare-table allocator stays consistent, and `sync_to_host` orders the
    /// descriptor stores so a concurrent sibling hardware walk stays safe
    /// without quiescing.
    page_tables: std::sync::Arc<parking_lot::Mutex<Option<crate::page_table::PageTableManager>>>,
    /// The Linux syscall number (x8) and original arg0 (x0) of the most recent
    /// `svc` trap, captured before the dispatcher overwrites x0 with the retval.
    /// Used to restart an `EINTR`'d restartable syscall under SA_RESTART: the
    /// handler-injection path rewinds PC to the `svc` and restores this x0.
    last_syscall_nr: Option<u64>,
    last_syscall_orig_x0: u64,
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
    /// Guest VIRTUAL start (the syscall-path lookup key). Differs from `ipa`
    /// only for the Rosetta high-VA alias.
    start: u64,
    end: u64,
    /// IPA this region was `hv_vm_map`'d at — needed to re-map across fork(2).
    /// Identity (== `start`) for every region but the Rosetta window.
    ipa: u64,
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
    ///
    /// `#[allow(dead_code)]`: these are RAII ownership holders, kept alive for
    /// their `Drop` side effects (freeing host pages), not read. Every region
    /// is now built by `map_region_raw` with `memory: None` +
    /// `host_mapping: Some(..)`.
    #[allow(dead_code)]
    memory: Option<applevisor::memory::Memory>,
    #[allow(dead_code)]
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
    ipa: u64,
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
            ipa: region.ipa,
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
            ipa: self.ipa,
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
    ipa: u64,
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
    /// Shared stage-1 page-table editor (one VM ⇒ one set of tables; siblings
    /// share this so concurrent edits serialize through its mutex).
    page_tables: std::sync::Arc<parking_lot::Mutex<Option<crate::page_table::PageTableManager>>>,
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

    pub fn last_syscall_nr(&self) -> Option<u64> {
        self.inner.last_syscall_nr()
    }

    /// Toggle hardware x86_64 Total Store Ordering on this vCPU by setting or
    /// clearing `ACTLR_EL1.EnTSO` (bit index 1). Apple Rosetta-translated
    /// guests request this via `prctl(PR_SET_MEM_MODEL, PR_SET_MEM_MODEL_TSO)`
    /// so x86 atomics/ordering are honoured in hardware instead of needing
    /// expensive barrier emulation. `applevisor` only permits this single bit
    /// to be set via `ACTLR_EL1`. Per-vCPU: must run on the active vCPU thread.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub fn set_hardware_tso(&self, tso: bool) -> Result<(), TrapError> {
        use applevisor::prelude::*;
        const EN_TSO: u64 = 1 << 1;
        let actlr = self
            .inner
            .vcpu
            .get_sys_reg(SysReg::ACTLR_EL1)
            .map_err(hvf_error)?;
        let next = if tso { actlr | EN_TSO } else { actlr & !EN_TSO };
        self.inner
            .vcpu
            .set_sys_reg(SysReg::ACTLR_EL1, next)
            .map_err(hvf_error)?;
        Ok(())
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub fn set_hardware_tso(&self, _tso: bool) -> Result<(), TrapError> {
        Err(TrapError::UnsupportedPlatform)
    }

    /// Back a dynamic high-VA `mmap` (see `DispatchOutcome::MapHostAlias`).
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub fn map_host_alias(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        payload: &[u8],
    ) -> Result<(), TrapError> {
        self.inner.map_host_alias(va, ipa, len, payload)
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub fn map_host_alias(
        &mut self,
        _va: u64,
        _ipa: u64,
        _len: u64,
        _payload: &[u8],
    ) -> Result<(), TrapError> {
        Err(TrapError::UnsupportedPlatform)
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
        fault_siginfo: Option<(i32, u64)>,
        restart_syscall: bool,
    ) -> Result<(), TrapError> {
        self.inner.inject_signal(
            signum,
            handler,
            sa_restorer,
            pending_syscall_retval,
            interrupted_pc,
            altstack,
            saved_sigmask,
            fault_siginfo,
            restart_syscall,
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
        _fault_siginfo: Option<(i32, u64)>,
        _restart_syscall: bool,
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

    /// Multithreaded-fork sibling: snapshot + destroy this vCPU (storing the
    /// snapshot in a thread-local) so the forking thread can `hv_vm_destroy`.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub fn release_vcpu_for_fork(&mut self) -> Result<(), TrapError> {
        self.inner.release_vcpu_for_fork()
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub fn release_vcpu_for_fork(&mut self) -> Result<(), TrapError> {
        Err(TrapError::UnsupportedPlatform)
    }

    /// A sibling guest thread is exiting: destroy ITS OWN vCPU (only the owning
    /// thread may) so the slot is freed in the process-global VM. Without this,
    /// the no-op `Drop` leaks the vCPU live forever, and a later fork's
    /// `hv_vm_destroy` trips over the accumulated dead-thread vCPUs (HV_BUSY).
    /// Raw `hv_vcpu_destroy`, not applevisor's panicky wrapper.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub fn destroy_vcpu_on_thread_exit(&mut self) {
        let _ = unsafe { applevisor_sys::hv_vcpu_destroy(self.inner.vcpu.id()) };
        vcpu_destroyed();
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub fn destroy_vcpu_on_thread_exit(&mut self) {}

    /// Multithreaded-fork parent: publish the rebuilt VM for quiesced siblings.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub fn publish_vm_for_siblings(&self) {
        self.inner.publish_vm_for_siblings();
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub fn publish_vm_for_siblings(&self) {}

    /// Multithreaded-fork sibling: recreate this vCPU in the parent's rebuilt VM
    /// and restore the thread-local snapshot from `release_vcpu_for_fork`.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub fn rebuild_vcpu_after_fork(&mut self) -> Result<(), TrapError> {
        self.inner.rebuild_vcpu_after_fork()
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub fn rebuild_vcpu_after_fork(&mut self) -> Result<(), TrapError> {
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
        vcpu_created();
        enable_el0_counter_access(vcpu.id());
        Ok(Self {
            inner: std::mem::ManuallyDrop::new(HvfInner {
                _vm: vm,
                vcpu,
                mappings: Vec::new(),
                last_exit_class: 0,
                is_forked_child: false,
                protections: std::sync::Arc::new(MemoryProtections::default()),
                page_tables: std::sync::Arc::new(parking_lot::Mutex::new(None)),
                last_syscall_nr: None,
                last_syscall_orig_x0: 0,
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
            //   T0SZ = 16  (48-bit VA, start at L0) — wide enough to address
            //              Rosetta's fixed ET_EXEC load base at 2^47; existing
            //              low identity mappings are unaffected (same L0[0..1]).
            //   IRGN0 = 0b11 (Inner WB Cacheable)
            //   ORGN0 = 0b11 (Outer WB Cacheable)
            //   SH0   = 0b11 (Inner Shareable)
            //   TG0   = 0b00 (4K granule)
            //   EPD1  = 1    (disable TTBR1 walks)
            //   IPS   = 0b010 (40-bit IPA, max for M-series HVF — output stays
            //              ≤40 bits; high VAs are mapped down to a low IPA)
            const T0SZ: u64 = 16;
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
        // Allow EL0 to read the virtual (EL0VCTEN, bit 1) and physical
        // (EL0PCTEN, bit 0) counters directly without trapping to EL1. This is
        // the foundation for the vDSO fast clock path: `__kernel_clock_gettime`
        // reads CNTVCT_EL0 in userspace, so it must NOT vmexit. The
        // emulate_el0_sys64_read path stays as a fallback for any guest whose
        // read still traps. Harmless for guests that don't read the counter.
        const CNTKCTL_EL1_EL0_COUNTER_ACCESS: u64 = (1 << 1) | (1 << 0);
        self.inner
            .vcpu
            .set_sys_reg(SysReg::CNTKCTL_EL1, CNTKCTL_EL1_EL0_COUNTER_ACCESS)
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
        // Fill the vDSO vvar page so __kernel_clock_gettime can derive time from
        // CNTVCT_EL0 in userspace. Best-effort: if the page isn't mapped (a load
        // path without with_vdso) just skip — the guest falls back to syscalls.
        self.inner.populate_vdso_data_page();
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

    /// Run the EL1 stage-1 maintenance trampoline on THIS vCPU to flush the
    /// stale stage-1 TLB after the host edited page descriptors (the only way
    /// to make a descriptor change guest-observable; arm64 public HVF has no
    /// stage-2 TLBI). The caller must have quiesced sibling vCPUs. The
    /// trampoline touches no GPRs/SP and its closing `hvc #1` traps EL1→EL2, so
    /// EL1 register state is intact; we still save/restore the interrupted
    /// EL1-vector PC/CPSR/ELR_EL1/SPSR_EL1 defensively so the in-flight syscall
    /// resumes exactly as before.
    fn run_el1_maintenance(&mut self) -> Result<(), TrapError> {
        use applevisor::prelude::*;
        // M[3:0]=0b0101 EL1h (SP_EL1) + DAIF masked; same value boot uses to
        // run the EL0-entry trampoline at EL1.
        const AARCH64_PSTATE_EL1H_DAIF_MASKED: u64 = 0x3c5;

        let saved_pc = self.vcpu.get_reg(Reg::PC).map_err(hvf_error)?;
        let saved_cpsr = self.vcpu.get_reg(Reg::CPSR).map_err(hvf_error)?;
        let saved_elr = self.vcpu.get_sys_reg(SysReg::ELR_EL1).map_err(hvf_error)?;
        let saved_spsr = self.vcpu.get_sys_reg(SysReg::SPSR_EL1).map_err(hvf_error)?;

        self.vcpu
            .set_reg(Reg::PC, crate::memory::LINUX_EL1_MAINT_BASE)
            .map_err(hvf_error)?;
        self.vcpu
            .set_reg(Reg::CPSR, AARCH64_PSTATE_EL1H_DAIF_MASKED)
            .map_err(hvf_error)?;

        let result = loop {
            self.vcpu.run().map_err(hvf_error)?;
            let exit = self.vcpu.get_exit_info();
            match exit.reason {
                // A cross-thread kick landed mid-flush; the trampoline is tiny
                // and idempotent, so just resume it to completion.
                ExitReason::CANCELED => continue,
                ExitReason::EXCEPTION => {
                    if is_aarch64_hvc_maintenance(exit.exception.syndrome) {
                        break Ok(());
                    }
                    // Per spec: an ambiguous exit here means we cannot trust
                    // guest memory visibility — surface it rather than resume.
                    break Err(TrapError::UnexpectedException {
                        syndrome: exit.exception.syndrome,
                        virtual_address: exit.exception.virtual_address,
                        physical_address: exit.exception.physical_address,
                    });
                }
                _ => {
                    break Err(TrapError::UnexpectedExit {
                        reason: format!("{:?} during EL1 maintenance", exit.reason),
                    });
                }
            }
        };

        // Restore the interrupted EL1-vector state regardless of outcome.
        self.vcpu.set_reg(Reg::PC, saved_pc).map_err(hvf_error)?;
        self.vcpu
            .set_reg(Reg::CPSR, saved_cpsr)
            .map_err(hvf_error)?;
        self.vcpu
            .set_sys_reg(SysReg::ELR_EL1, saved_elr)
            .map_err(hvf_error)?;
        self.vcpu
            .set_sys_reg(SysReg::SPSR_EL1, saved_spsr)
            .map_err(hvf_error)?;
        result
    }

    /// Host VA of the page-table region's backing (offset 0 == base).
    fn pt_host_ptr(&self) -> Option<*mut u8> {
        self.mapping_for_range(crate::memory::LINUX_PAGE_TABLES_BASE, 8)
            .map(|m| m.host_addr)
    }

    /// Edit stage-1 descriptors under the shared manager lock, atomically sync
    /// the changed descriptors to the host backing (ordered so a concurrent
    /// sibling walk stays safe), then flush the stage-1 TLB via the EL1
    /// maintenance trampoline so this vCPU (and, inner-shareable, its siblings)
    /// observe the change.
    fn pt_edit_and_flush(
        &mut self,
        edit: impl FnOnce(
            &mut crate::page_table::PageTableManager,
        ) -> Result<bool, crate::page_table::PageTableError>,
    ) -> Result<(), MemoryError> {
        use crate::page_table::PageTableError;
        let host = self
            .pt_host_ptr()
            .ok_or_else(|| MemoryError::HostMap("page-table region not mapped".to_string()))?;
        let pt = std::sync::Arc::clone(&self.page_tables);
        let changed = {
            let mut guard = pt.lock();
            // Build from the live host backing on first edit (matches the boot
            // image; nothing else writes the tables before this). `get_or_insert_with`
            // returns the live manager whether it already existed or was just built,
            // so there is no Option to unwrap.
            let mgr = guard.get_or_insert_with(|| {
                let size = crate::memory::LINUX_PAGE_TABLES_SIZE as usize;
                let mut bytes = vec![0u8; size];
                unsafe { std::ptr::copy_nonoverlapping(host, bytes.as_mut_ptr(), size) };
                crate::page_table::PageTableManager::new(
                    bytes,
                    crate::memory::LINUX_PAGE_TABLES_BASE,
                )
            });
            // Coalescing reclaims spare sub-tables into the 58-page pool; without
            // it, sustained discontiguous mmap/munmap churn leaks them until
            // OutOfTables → ENOMEM (PROVEN: the pt-pool watermark climbed to
            // 55/58, free=0, then Go OOM'd in TestPageAllocAlloc). Coalesce is a
            // break-before-make table↔block flip plus a page free — unsafe only
            // if a sibling holds a stale walk-cache reference to the freed page.
            // PMR removes exactly that hazard: every multi-vCPU table edit pauses
            // ALL siblings out of guest and `tlbi vmalle1is`-broadcasts before
            // resuming them, so none holds a stale walk across the free OR a
            // later reuse. So coalesce is safe iff the edit is EXCLUSIVE —
            // single-vCPU, or PMR-protected (the pt pause is held right now). The
            // flag is historically named `multi_vcpu` but really means "unsafe to
            // coalesce". (The earlier note blaming coalesce for an alloc_table
            // use-after-free was a misattribution: that was the fork-manager
            // reset bug, present coalesce on AND off, since fixed.)
            let live_multi = VCPU_LIVE.load(std::sync::atomic::Ordering::SeqCst) > 1;
            let unsafe_to_coalesce =
                live_multi && !crate::fork_quiesce::pt_barrier().is_quiescing();
            mgr.set_multi_vcpu(unsafe_to_coalesce);
            let changed = edit(mgr).map_err(|e| match e {
                PageTableError::OutOfTables => {
                    MemoryError::HostMap("stage-1 page-table pool exhausted".to_string())
                }
                PageTableError::BadAddress => MemoryError::OutOfBounds {
                    address: 0,
                    length: 0,
                },
            })?;
            // Pool occupancy after the edit — a rising `in_use` toward capacity
            // is the leak; flat proves coalescing keeps it bounded.
            let (in_use, free_list, capacity) = mgr.pool_stats();
            crate::probes::pt_pool(in_use, free_list, capacity, i32::from(changed));
            if changed {
                // SAFETY: `host` backs the live page-table region for the whole
                // process lifetime; the manager only writes 8-byte-aligned
                // descriptor slots within it.
                unsafe { mgr.sync_to_host(host) };
            }
            changed
        };
        // Nothing changed (range already at the target protection): no host
        // write, no TLBI.
        if !changed {
            return Ok(());
        }
        self.run_el1_maintenance()
            .map_err(|e| MemoryError::HostMap(format!("stage-1 TLBI failed: {e}")))?;
        Ok(())
    }

    fn protect_range(&mut self, address: u64, len: usize, prot: u64) -> Result<(), MemoryError> {
        use crate::linux_abi::{LINUX_PROT_READ, LINUX_PROT_WRITE};
        self.pt_edit_and_flush(|mgr| {
            if prot & LINUX_PROT_WRITE != 0 {
                mgr.set_rw(address, len)
            } else if prot & LINUX_PROT_READ != 0 {
                mgr.set_readonly(address, len)
            } else {
                mgr.set_prot_none(address, len)
            }
        })
    }

    fn unmap_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.pt_edit_and_flush(|mgr| mgr.invalidate(address, len))
    }

    /// Back a dynamic high-VA `mmap`: `hv_vm_map` host-anon memory at the
    /// reserved low IPA, build the VA→IPA stage-1 path, and register the region
    /// for syscall-path access (keyed by the VA). RWX so a JIT (Rosetta) can
    /// both write and execute it; the guest may `mprotect` afterwards.
    fn map_host_alias(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        payload: &[u8],
    ) -> Result<(), TrapError> {
        let size = usize::try_from(len).map_err(|_| TrapError::MappingTooLarge(len))?;
        let host_mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
            size,
            crate::host_mapping::HostMappingKind::PrivateAnon,
        )
        .map_err(|e| TrapError::Hypervisor(format!("alias mmap (size={size}) failed: {e}")))?;
        let host = host_mapping.as_ptr();
        let size = host_mapping.len();
        // Seed the file content (empty for anon — the anon mapping is zeroed).
        if !payload.is_empty() {
            let n = payload.len().min(size);
            unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), host, n) };
        }
        let perms = hvf_perms(SegmentPerms {
            read: true,
            write: true,
            execute: true,
        });
        let r =
            unsafe { applevisor_sys::hv_vm_map(host.cast(), ipa, size, u64::from(perms)) };
        if r != 0 {
            return Err(TrapError::Hypervisor(format!(
                "hv_vm_map alias va=0x{va:x} ipa=0x{ipa:x} size={size} failed: 0x{r:x}"
            )));
        }
        // Build VA→IPA descriptors + TLBI so the guest's own accesses translate.
        self.pt_edit_and_flush(|mgr| mgr.map_aliased(va, ipa, len))
            .map_err(|e| TrapError::Hypervisor(format!("alias page-table build failed: {e}")))?;
        let guest_shared = host_mapping.guest_shared();
        self.mappings.push(HvfMappedRegion {
            start: va,
            ipa,
            end: va + size as u64,
            host_addr: host,
            size,
            perms,
            memory: None,
            host_mapping: Some(host_mapping),
            guest_shared,
        });
        Ok(())
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
                if !ExecLevel::from_pstate(cpsr).is_guest() {
                    EL1_KICK_RESUMED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    crate::probes::kick_in_kernel(
                        self.vcpu.get_reg(Reg::PC).unwrap_or(0),
                        ((cpsr >> 2) & 0b11) as u32,
                    );
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
                if self.emulate_el0_sys64_read(underlying)? {
                    return self.run_until_syscall();
                }
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
                // Decoded fault diagnostics for `carrick trace` (vcpu-fault-regs)
                // as SCALARS — the faulting instruction word + the base register
                // a load/store dereferenced and its value. So a script sees e.g.
                // `ldr x0,[x0,#8]` with x0=17 -> far=0x19, without an eprintln
                // rebuild. Scalars survive a fault that kills the process before
                // DTrace's action runs (a copyin-pointer probe would not). Built
                // only at the fault (never on the happy path); the host-side read
                // of the instruction word can't be done in D (guest VA != host).
                {
                    let insn = self
                        .read_guest_bytes(elr, 4)
                        .ok()
                        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64)
                        .unwrap_or(0);
                    let rn = ((insn >> 5) & 0x1f) as u32;
                    let xrn = self
                        .vcpu
                        .get_reg(GPR_TABLE[rn as usize])
                        .unwrap_or(0);
                    crate::probes::vcpu_fault_regs(underlying, elr, far, insn, rn, xrn);
                }
                // Walk the LIVE host page-table backing at the faulting VA so a
                // trace can tell whether the leaf PTE is invalid in memory (a
                // logic bug — a missing/lost validate) vs valid-but-stale-TLB (a
                // coherence bug). Reads exactly what the guest HW walker sees.
                if let Some(host) = self.pt_host_ptr() {
                    let size = crate::memory::LINUX_PAGE_TABLES_SIZE as usize;
                    // SAFETY: `host` backs the page-table region for the whole
                    // process; we read `size` bytes from it, no writes.
                    let bytes = unsafe { std::slice::from_raw_parts(host, size) };
                    let d = crate::page_table::walk_descriptors(
                        bytes,
                        crate::memory::LINUX_PAGE_TABLES_BASE,
                        far,
                    );
                    crate::probes::pt_fault_walk(far, d[0], d[1], d[2], d[3]);
                }
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
        // Snapshot the syscall number + original arg0 before the dispatcher
        // overwrites x0 with the retval, so an SA_RESTART handler that
        // interrupts this syscall can restart it (rewind PC to the `svc`,
        // restore this x0) instead of surfacing EINTR.
        self.last_syscall_nr = Some(frame.x8);
        self.last_syscall_orig_x0 = frame.x0;
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

    fn last_syscall_nr(&self) -> Option<u64> {
        self.last_syscall_nr
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

    fn emulate_el0_sys64_read(&mut self, esr: u64) -> Result<bool, TrapError> {
        use applevisor::prelude::*;

        let Some((rt, reg)) = decode_el0_sys64_read(esr) else {
            return Ok(false);
        };
        let value = match reg {
            El0SysRegRead::CntfrqEl0 => AARCH64_GUEST_COUNTER_HZ,
            El0SysRegRead::CntvctEl0 => guest_counter_ticks(),
        };
        if let Some(target) = GPR_TABLE.get(rt as usize) {
            self.vcpu.set_reg(*target, value).map_err(hvf_error)?;
        }
        let elr = self.vcpu.get_sys_reg(SysReg::ELR_EL1).map_err(hvf_error)?;
        self.vcpu
            .set_sys_reg(SysReg::ELR_EL1, elr.wrapping_add(4))
            .map_err(hvf_error)?;
        Ok(true)
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

    /// Host VA of `address` iff it lives in a host-`MAP_SHARED` guest region
    /// (the boot-mapped shared aperture; shared across carrick processes via
    /// the inherited MAP_SHARED backing). Used to back a cross-process futex
    /// with the public `os_sync_wait_on_address` API (see `crate::ulock`).
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

    /// Write the vDSO vvar data page: the counter frequency and the
    /// monotonic→realtime offset, so `__kernel_clock_gettime` can convert
    /// CNTVCT_EL0 to a timespec entirely in userspace. The guest reads the same
    /// counter we calibrate against (CNTKCTL_EL1.EL0VCTEN), so the rate is exact;
    /// monotonic durations depend only on the frequency. Best-effort: silently
    /// skips if the vvar page isn't mapped.
    fn populate_vdso_data_page(&mut self) {
        let (host_cntvct, freq) = host_counter();
        if freq == 0 {
            return;
        }
        // HVF leaves the guest virtual-counter offset (CNTVOFF_EL2) at 0, so the
        // guest's CNTVCT_EL0 reads the same virtual count carrick reads here. The
        // absolute base is immaterial for CLOCK_MONOTONIC (durations cancel it);
        // it only shifts the realtime offset by a constant if HVF ever changed it.
        let guest_cntvct = host_cntvct;
        let mono_ns = ((guest_cntvct as u128).saturating_mul(1_000_000_000) / freq as u128) as u64;
        let unix_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let realtime_off = unix_ns.wrapping_sub(mono_ns);

        let base = crate::vdso::LINUX_VVAR_BASE;
        let _ = self.write_guest_bytes(
            base + crate::vdso::VVAR_OFF_FREQ as u64,
            &freq.to_le_bytes(),
        );
        let _ = self.write_guest_bytes(
            base + crate::vdso::VVAR_OFF_REALTIME_OFF_NS as u64,
            &realtime_off.to_le_bytes(),
        );
        // seq stays 0 (even = stable); these aren't updated after boot.
    }

    /// Mark `[address, address+len)` PROT_NONE (`no_access=true`) or clear it.
    /// Clearing performs interval subtraction so an mprotect/mmap that re-enables
    /// part of a PROT_NONE region leaves only the still-protected remainder.
    fn set_no_access(&mut self, address: u64, len: usize, no_access: bool) {
        self.protections.set_no_access(address, len, no_access);
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

    /// Multithreaded fork — sibling side, step 1. Snapshot this vCPU and destroy
    /// it (raw `hv_vcpu_destroy`; only the owning thread may) so the forking
    /// thread can `hv_vm_destroy` before `libc::fork` (which fails HV_BUSY while
    /// any vCPU is alive). The wrapper is left stale until `rebuild_vcpu_after_fork`.
    fn release_vcpu_for_fork(&mut self) -> Result<(), TrapError> {
        let snap = self.snapshot_vcpu()?;
        FORK_VCPU_SNAPSHOT.with(|s| *s.borrow_mut() = Some(snap));
        let rc = unsafe { applevisor_sys::hv_vcpu_destroy(self.vcpu.id()) };
        vcpu_destroyed();
        // phase 3: a nonzero rc means this sibling FAILED to destroy its own
        // vCPU, so it stays live and the forker's hv_vm_destroy hits HV_BUSY.
        crate::probes::fork_quiesce(3, rc as i64, self.vcpu.id() as i64, unsafe {
            libc::getpid()
        });
        Ok(())
    }

    /// Multithreaded fork — forking thread (parent), after rebuilding its VM.
    /// Publish a clone of the new process VM so quiesced siblings can recreate
    /// their vCPUs in it.
    fn publish_vm_for_siblings(&self) {
        *rebuilt_vm_cell().lock() = Some(self._vm.clone());
    }

    /// Multithreaded fork — sibling side, step 2 (after the parent published the
    /// rebuilt VM and released the quiesce). Recreate this vCPU in the new VM
    /// and restore the pre-fork register state. Mappings are VM-global (the
    /// parent remapped them into the shared VM), so nothing to re-map here.
    fn rebuild_vcpu_after_fork(&mut self) -> Result<(), TrapError> {
        let snap = FORK_VCPU_SNAPSHOT
            .with(|s| s.borrow_mut().take())
            .ok_or_else(|| TrapError::Hypervisor("no fork vCPU snapshot for rebuild".into()))?;
        // Post-fork: recreate in the parent's rebuilt VM (published). On a
        // quiesce ABORT (timeout — no fork happened), nothing was published and
        // the existing VM is still live, so recreate the vCPU in it.
        let new_vm = rebuilt_vm_cell()
            .lock()
            .clone()
            .unwrap_or_else(|| self._vm.clone());
        let new_vcpu = new_vm.vcpu_create().map_err(hvf_error)?;
        vcpu_created();
        enable_el0_counter_access(new_vcpu.id());
        // Replace _vm and vcpu WITHOUT running applevisor's panicky Drop on the
        // old (already-destroyed) handles — mirror the fork/thread-sibling
        // leak-until-exit discipline.
        std::mem::forget(std::mem::replace(&mut self.vcpu, new_vcpu));
        std::mem::forget(std::mem::replace(&mut self._vm, new_vm));
        self.restore_vcpu(&snap)?;
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
        fault_siginfo: Option<(i32, u64)>,
        restart_syscall: bool,
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
        //
        // SA_RESTART (restart_syscall): the interrupted syscall returned EINTR
        // and its handler is restartable. Restore the ORIGINAL arg0 instead so
        // that, after rt_sigreturn rewinds PC to the `svc` (below), the guest
        // re-executes the syscall with its real arguments (x8=sysno is
        // untouched by complete_syscall; x1..x5 were never clobbered).
        if restart_syscall {
            frame.saved_x[0] = self.last_syscall_orig_x0;
        } else if let Some(retval) = pending_syscall_retval {
            frame.saved_x[0] = retval as u64;
        }
        // Resume address after the handler returns. On a syscall-boundary
        // injection HVF set ELR_EL1 to the instruction after the `svc`; on a
        // kick (CANCELED) exit there was no exception, so ELR_EL1 is stale and
        // the caller passes the live guest PC instead.
        frame.saved_pc = match interrupted_pc {
            Some(pc) => {
                KICK_PATH_INJECT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                // Invariant: a kick-path resume PC is genuine guest EL0 code,
                // never carrick's EL1 trampoline — `run_until_syscall` resumes
                // EL1-window kicks rather than reporting them. If this fires,
                // that guard regressed and we're about to corrupt an in-flight
                // syscall. Tripwire (release) + assert (debug).
                if crate::memory::is_carrick_el1_vector_va(pc) {
                    INJECT_AT_EL1.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    debug_assert!(
                        false,
                        "signal injection at EL1 trampoline PC 0x{pc:x} (carrick space, not guest)"
                    );
                }
                pc
            }
            None => self.vcpu.get_sys_reg(SysReg::ELR_EL1).map_err(hvf_error)?,
        };
        // SA_RESTART: rewind PC by one instruction (4 bytes) so it points back
        // at the `svc` rather than the instruction after it. After the handler
        // returns via rt_sigreturn the guest re-executes the syscall (the
        // kernel's ERESTARTSYS). Only valid on the syscall-boundary path
        // (caller guarantees restart_syscall ⇒ interrupted_pc is None).
        if restart_syscall {
            frame.saved_pc = frame.saved_pc.wrapping_sub(4);
        }
        frame.saved_sp = self.vcpu.get_sys_reg(SysReg::SP_EL0).map_err(hvf_error)?;
        // Snapshot the interrupted code's PSTATE (incl. NZCV condition flags),
        // restored verbatim by rt_sigreturn → eret. The correct source differs
        // by injection path:
        //   * syscall-boundary (interrupted_pc == None): the guest `svc` took a
        //     synchronous exception to EL1, so the hardware latched the EL0
        //     PSTATE into SPSR_EL1. CPSR now reads the EL1 trampoline's state.
        //     SPSR_EL1 is authoritative.
        //   * kick (interrupted_pc == Some): a cross-thread hv_vcpus_exit forced
        //     a CANCELED exit while the guest was live at EL0 — NO exception was
        //     taken, so SPSR_EL1 is stale (it holds whatever the *previous*
        //     syscall latched). The live EL0 PSTATE is in CPSR. Reading SPSR_EL1
        //     here resumes the preempted routine with stale NZCV — conditional
        //     branches go the wrong way (memory intact, computation wrong),
        //     which is exactly Go's async-preemption (SIGURG) corruption.
        frame.saved_spsr = match interrupted_pc {
            Some(_) => self.vcpu.get_reg(Reg::CPSR).map_err(hvf_error)?,
            None => self.vcpu.get_sys_reg(SysReg::SPSR_EL1).map_err(hvf_error)?,
        };

        let mut siginfo = crate::linux_abi::LinuxSiginfo::empty();
        siginfo.si_signo = signum;
        // A synchronous fault carries the kernel-style si_code (SEGV_MAPERR /
        // SEGV_ACCERR / BUS_ADRALN) and si_addr=faulting address, so a handler
        // (e.g. Go's runtime sigpanic) sees the real cause. Otherwise it's a
        // SI_USER-shaped delivery (tkill/sysmon preempt).
        match fault_siginfo {
            Some((si_code, si_addr)) => {
                siginfo.si_code = si_code;
                siginfo.si_addr = si_addr;
            }
            None => {
                siginfo.si_code = crate::linux_abi::LINUX_SI_USER;
            }
        }
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

        if !fpsimd_save_enabled() {
            return Ok(());
        }
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

        if !fpsimd_save_enabled() {
            return Ok(());
        }
        let reserved = mcontext.__reserved;
        let size = core::mem::size_of::<crate::linux_abi::LinuxFpsimdContext>();
        let Ok(fp) = crate::linux_abi::LinuxFpsimdContext::read_from_bytes(&reserved[..size])
        else {
            return Ok(());
        };
        if fp.magic != crate::linux_abi::LINUX_FPSIMD_MAGIC {
            return Ok(());
        }
        let vregs = fp.vregs;
        let vcpu_id = self.vcpu.id();
        for (i, reg) in SIMD_FP_TABLE.iter().enumerate() {
            // NB: route through the C shim, NOT applevisor's set_simd_fp_reg —
            // its u128 by-value param uses the wrong (GP) register class for
            // Apple's vector-typed API and silently zeroes the register. See
            // `set_simd_fp_reg_v`.
            let rc = set_simd_fp_reg_v(vcpu_id, *reg, vregs[i]);
            if rc != 0 {
                return Err(TrapError::Hypervisor(format!(
                    "hv_vcpu_set_simd_fp_reg(q{i}) failed: rc={rc:#x}"
                )));
            }
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
                ipa: m.ipa,
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
                ForkMappingHost::Owned(clone_region_for_child(desc.host.ptr(), desc.size, desc.start)?)
            };
            child_descs.push(ForkMappingDesc {
                start: desc.start,
                ipa: desc.ipa,
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
        vcpu_destroyed();
        let vm_destroy_rc = unsafe { applevisor_sys::hv_vm_destroy() };
        // phase 2: a nonzero rc means a vCPU was still live at teardown — the
        // HV_BUSY root cause (the rebuilt VM is then corrupt and sibling
        // vcpu_create fails). Traceable via `carrick trace` fork__quiesce.
        crate::probes::fork_quiesce(
            2,
            vm_destroy_rc as i64,
            VCPU_LIVE.load(std::sync::atomic::Ordering::SeqCst),
            unsafe { libc::getpid() },
        );

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
        vcpu_created();
        enable_el0_counter_access(new_vcpu.id());

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
        // In the parent, keep the exact shared protection table siblings
        // already use; otherwise post-fork mmap/mprotect changes split across
        // two Arcs and one thread can see a valid Go heap futex as PROT_NONE.
        // The child is single-threaded after fork, so it gets a private copy of
        // the parent's ranges at the fork point.
        let inherited_protections = if pid == 0 {
            std::sync::Arc::new(MemoryProtections::from_ranges(self.protections.snapshot()))
        } else {
            std::sync::Arc::clone(&self.protections)
        };
        // The stage-1 page-table manager must survive fork EXACTLY like
        // protections. The PARENT's tables and their host backing are unchanged
        // by fork, so it keeps the SAME shared manager — a fresh manager would
        // rebuild from the (live) backing with `next_free` reset to the first
        // spare, then re-hand-out table pages already in use, writing L3 entries
        // over a live L2 table (proven: the cross-test TestUserArenaNew SIGSEGV,
        // an L2 slot holding `USER_PAGE_FLAGS | <arena PA>`). The CHILD gets a
        // private backing copy, so it needs its OWN manager — but a CLONE of the
        // parent's state, not a reset, so its bump cursor matches that backing.
        let inherited_page_tables = if pid == 0 {
            let cloned = self.page_tables.lock().clone();
            std::sync::Arc::new(parking_lot::Mutex::new(cloned))
        } else {
            std::sync::Arc::clone(&self.page_tables)
        };
        let new_inner = HvfInner {
            _vm: new_vm,
            vcpu: new_vcpu,
            mappings: Vec::with_capacity(mapping_descs.len()),
            last_exit_class: snapshot.last_exit_class,
            is_forked_child: pid == 0,
            protections: inherited_protections,
            page_tables: inherited_page_tables,
            last_syscall_nr: None,
            last_syscall_orig_x0: 0,
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
                    desc.ipa,
                    desc.size,
                    perms_raw,
                )
            };
            if r != 0 {
                return Err(TrapError::ChildMapFailed {
                    host_addr: host_addr as u64,
                    guest_start: desc.ipa,
                    size: desc.size,
                    code: r as u32,
                });
            }
            self.mappings.push(HvfMappedRegion {
                start: desc.start,
                ipa: desc.ipa,
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
            page_tables: std::sync::Arc::clone(&self.page_tables),
            snapshot,
        })
    }

    /// Stand up the sibling vCPU on the current thread. Mirrors fork()'s
    /// rebuild path but KEEPS the shared VM (the spec's `vm` clone) instead
    /// of creating a new one, and marks every re-mapped region UNOWNED
    /// (`memory: None`) so this engine never unmaps the buffers the main
    /// engine owns. Thread siblings are not forked child processes: the
    /// runtime must keep normal process-wide signal/exit semantics for them.
    fn from_thread_spec(spec: ThreadSpec) -> Result<Self, TrapError> {
        let ThreadSpec {
            vm,
            mappings,
            protections,
            page_tables,
            snapshot,
        } = spec;

        // The spec captured `vm` at clone time. If a fork rebuilt the VM since
        // then (the spec's `vm` was destroyed), create the vCPU in the CURRENT
        // VM that the fork published instead — otherwise vcpu_create hits
        // HV_BUSY on a torn-down VM. Between forks the published cell holds the
        // live VM; with no fork yet it's empty and the spec's `vm` is current.
        // The caller holds `fork_quiesce::topology_lock()`, so this read can't
        // race a fork's republish.
        let vm = rebuilt_vm_cell().lock().clone().unwrap_or(vm);
        let vcpu = vm.vcpu_create().map_err(hvf_error)?;
        vcpu_created();
        enable_el0_counter_access(vcpu.id());

        let mut inner = HvfInner {
            _vm: vm,
            vcpu,
            mappings: Vec::with_capacity(mappings.len()),
            last_exit_class: snapshot.last_exit_class,
            is_forked_child: false,
            protections,
            page_tables,
            last_syscall_nr: None,
            last_syscall_orig_x0: 0,
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
        vcpu_destroyed();
        let _ = unsafe { applevisor_sys::hv_vm_destroy() };

        // Create a fresh VM + vCPU.
        let max_ipa = VirtualMachineConfig::get_max_ipa_size().map_err(hvf_error)?;
        let mut config = VirtualMachineConfig::new();
        config.set_ipa_size(max_ipa).map_err(hvf_error)?;
        let new_vm = VirtualMachine::with_config(config).map_err(hvf_error)?;
        let new_vcpu = new_vm.vcpu_create().map_err(hvf_error)?;
        vcpu_created();
        enable_el0_counter_access(new_vcpu.id());

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
            page_tables: std::sync::Arc::new(parking_lot::Mutex::new(None)),
            last_syscall_nr: None,
            last_syscall_orig_x0: 0,
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
            // 48-bit VA (see the matching comment in map_address_space).
            const T0SZ: u64 = 16;
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
        self.populate_vdso_data_page();
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

    fn last_syscall_nr(&self) -> Option<u64> {
        None
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

    fn set_no_access(&mut self, address: u64, len: usize, no_access: bool) {
        self.inner.set_no_access(address, len, no_access);
    }

    fn protect_range(&mut self, address: u64, len: usize, prot: u64) -> Result<(), MemoryError> {
        self.inner.protect_range(address, len, prot)
    }

    fn unmap_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.inner.unmap_range(address, len)
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

/// True for the EL1 stage-1 maintenance trampoline's `hvc #1` completion
/// marker. The HVC immediate is the low 16 bits of the syndrome ISS. Distinct
/// from the `hvc #0` syscall forward so the maintenance run loop and the
/// syscall trap path never confuse the two.
pub fn is_aarch64_hvc_maintenance(syndrome: u64) -> bool {
    is_aarch64_hvc_exception(syndrome) && (syndrome & 0xffff) == 1
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
    guest_start: u64,
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
    // Bound the residency scan to the region's used prefix. The 32 GiB mmap
    // arena is mapped once but the guest only bump-allocates a sliver from its
    // base; `mincore` over the full window walks all ~2M pages (~470 ms/fork —
    // the dominant cost of any subprocess-spawning guest). The dispatcher's
    // arena high-water (published into GUEST_ARENA_HIGH_WATER by handle_fork)
    // says the guest has only touched `[LINUX_MMAP_BASE, hw)`; pages past it are
    // untouched in the parent too, so the child's freshly-zeroed snapshot needs
    // no copy there. Other regions (heap, stack, trampolines) keep the full
    // scan. `u64::MAX` default ⇒ full scan (non-fork callers / tests).
    let scan_size = if guest_start == crate::memory::LINUX_MMAP_BASE {
        let hw = GUEST_ARENA_HIGH_WATER.load(std::sync::atomic::Ordering::SeqCst);
        hw.saturating_sub(guest_start).try_into().unwrap_or(size).min(size)
    } else {
        size
    };
    if scan_size == 0 {
        return Ok(dst); // nothing resident to copy; dst stays lazily zero
    }
    let n_pages = scan_size.div_ceil(page);
    let mut resident = vec![0u8; n_pages];
    let rc = unsafe {
        libc::mincore(
            src as *mut libc::c_void,
            scan_size,
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
    // The aperture region is host-MAP_SHARED so it stays shared across fork(2)
    // (never snapshotted); all other regions are private guest RAM.
    let kind = if mapping.shared {
        crate::host_mapping::HostMappingKind::SharedAnon
    } else {
        crate::host_mapping::HostMappingKind::PrivateAnon
    };
    let host_mapping =
        crate::host_mapping::OwnedHostMapping::map_shared_anon(size, kind).map_err(|error| {
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
    // Map at the IPA (identity for all but the Rosetta alias); the guest's
    // stage-1 page tables translate the VIRTUAL `guest_start` to this IPA.
    let r = unsafe {
        applevisor_sys::hv_vm_map(
            host.cast::<std::ffi::c_void>(),
            mapping.ipa_start,
            size,
            perms_raw,
        )
    };
    if r != 0 {
        return Err(TrapError::Hypervisor(format!(
            "hv_vm_map(ipa=0x{:x}, va=0x{:x}, size={size}) failed: 0x{r:x}",
            mapping.ipa_start, mapping.guest_start
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
        ipa: mapping.ipa_start,
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
    fn exec_level_classifies_el0_as_guest_el1_as_kernel() {
        // PSTATE M[3:0]: EL0t=0b0000, EL1t=0b0100, EL1h=0b0101.
        assert_eq!(ExecLevel::from_pstate(0b0000), ExecLevel::Guest);
        assert!(ExecLevel::from_pstate(0b0000).is_guest());
        // EL0t with DAIF/nzcv bits set high is still EL0 (only M[3:2] matter).
        assert_eq!(ExecLevel::from_pstate(0x6000_0000), ExecLevel::Guest);
        assert_eq!(ExecLevel::from_pstate(0b0100), ExecLevel::Kernel); // EL1t
        assert_eq!(ExecLevel::from_pstate(0b0101), ExecLevel::Kernel); // EL1h
        assert!(!ExecLevel::from_pstate(0b0101).is_guest());
    }

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
    fn decodes_el0_counter_register_traps() {
        let cntfrq = (AARCH64_SYS64_EXCEPTION_CLASS << AARCH64_EXCEPTION_CLASS_SHIFT)
            | AARCH64_SYS64_ISS_SYS_CNTFRQ
            | (1 << AARCH64_SYS64_ISS_RT_SHIFT);
        let cntvct = (AARCH64_SYS64_EXCEPTION_CLASS << AARCH64_EXCEPTION_CLASS_SHIFT)
            | AARCH64_SYS64_ISS_SYS_CNTVCT
            | (2 << AARCH64_SYS64_ISS_RT_SHIFT);

        assert_eq!(
            decode_el0_sys64_read(cntfrq),
            Some((1, El0SysRegRead::CntfrqEl0))
        );
        assert_eq!(
            decode_el0_sys64_read(cntvct),
            Some((2, El0SysRegRead::CntvctEl0))
        );
        assert_eq!(decode_el0_sys64_read(0), None);
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
            ipa: 0x1000,
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

impl SyscallTrap for HvfTrapEngine {
    fn fork(&mut self) -> Result<ForkOutcome, TrapError> {
        self.fork()
    }

    fn execve_into(&mut self, new_image: &AddressSpace) -> Result<(), TrapError> {
        self.execve_into(new_image)
    }

    fn is_forked_child(&self) -> bool {
        HvfTrapEngine::is_forked_child(self)
    }

    fn next_syscall(&mut self) -> Result<Option<Aarch64SyscallFrame>, TrapError> {
        self.run_until_syscall()
    }

    fn current_pc(&self) -> Result<u64, TrapError> {
        self.program_counter()
    }

    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError> {
        self.complete_syscall(return_value)
    }

    fn set_memory_model(&mut self, tso: bool) -> Result<(), TrapError> {
        self.set_hardware_tso(tso)
    }

    fn map_host_alias(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        payload: &[u8],
    ) -> Result<(), TrapError> {
        HvfTrapEngine::map_host_alias(self, va, ipa, len, payload)
    }

    fn inject_signal(
        &mut self,
        signum: i32,
        handler: u64,
        sa_restorer: u64,
        pending_syscall_retval: Option<i64>,
        interrupted_pc: Option<u64>,
        altstack: Option<(u64, u64)>,
        saved_sigmask: u64,
        fault_siginfo: Option<(i32, u64)>,
        restart_syscall: bool,
    ) -> Result<(), TrapError> {
        HvfTrapEngine::inject_signal(
            self,
            signum,
            handler,
            sa_restorer,
            pending_syscall_retval,
            interrupted_pc,
            altstack,
            saved_sigmask,
            fault_siginfo,
            restart_syscall,
        )
    }

    fn last_syscall_nr(&self) -> Option<u64> {
        self.last_syscall_nr()
    }

    fn restore_from_sigframe(&mut self) -> Result<u64, TrapError> {
        HvfTrapEngine::restore_from_sigframe(self)
    }
}

