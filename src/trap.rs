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
    #[error("hv_vm_map(host=0x{host_addr:x}, guest=0x{guest_start:x}, size={size}) failed in child: 0x{code:x}")]
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
    #[error("EL0 fault not handled by trap path: esr=0x{syndrome:x} elr=0x{elr:x} far=0x{far:x}")]
    EL0Fault {
        syndrome: u64,
        elr: u64,
        far: u64,
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
            let payload_offset = usize::try_from(offset_in_mapping)
                .map_err(|_| TrapError::MappingTooLarge(offset_in_mapping))?;

            let mut image = vec![0; mapped_len];
            image[payload_offset..payload_offset + region.bytes().len()]
                .copy_from_slice(region.bytes());

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

    pub fn map_address_space(
        &mut self,
        address_space: &AddressSpace,
    ) -> Result<GuestMappingPlan, TrapError> {
        let plan = GuestMappingPlan::from_address_space(address_space)?;
        self.map_plan(&plan)?;
        Ok(plan)
    }

    pub fn run_until_syscall(&mut self) -> Result<Aarch64SyscallFrame, TrapError> {
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
    ) -> Result<(), TrapError> {
        self.inner
            .inject_signal(signum, handler, sa_restorer, pending_syscall_retval)
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub fn inject_signal(
        &mut self,
        _signum: i32,
        _handler: u64,
        _sa_restorer: u64,
        _pending_syscall_retval: Option<i64>,
    ) -> Result<(), TrapError> {
        Err(TrapError::UnsupportedPlatform)
    }

    /// Pop the Carrick signal frame at SP_EL0 and restore the pre-
    /// signal register state. Used by `rt_sigreturn(2)`.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub fn restore_from_sigframe(&mut self) -> Result<(), TrapError> {
        self.inner.restore_from_sigframe()
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    pub fn restore_from_sigframe(&mut self) -> Result<(), TrapError> {
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
            let mut memory = self
                .inner
                ._vm
                .memory_create(
                    usize::try_from(mapping.mapped_size)
                        .map_err(|_| TrapError::MappingTooLarge(mapping.mapped_size))?,
                )
                .map_err(hvf_error)?;
            memory
                .map(mapping.guest_start, hvf_perms(mapping.perms))
                .map_err(hvf_error)?;
            memory
                .write(mapping.guest_start, &mapping.image)
                .map_err(hvf_error)?;
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
            let host_addr = memory.host_addr();
            let size = usize::try_from(mapping.mapped_size)
                .map_err(|_| TrapError::MappingTooLarge(mapping.mapped_size))?;
            let perms = hvf_perms(mapping.perms);
            self.inner.mappings.push(HvfMappedRegion {
                start: mapping.guest_start,
                end: mapping.guest_start.checked_add(mapping.mapped_size).ok_or(
                    TrapError::MappingOverflow {
                        guest_start: mapping.guest_start,
                        mapped_size: mapping.mapped_size,
                    },
                )?,
                host_addr,
                size,
                perms,
                memory: Some(memory),
            });
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

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfInner {
    fn mapped_region_count(&self) -> usize {
        self.mappings.len()
    }

    fn program_counter(&self) -> Result<u64, TrapError> {
        use applevisor::prelude::*;

        self.vcpu.get_reg(Reg::PC).map_err(hvf_error)
    }

    fn run_until_syscall(&mut self) -> Result<Aarch64SyscallFrame, TrapError> {
        use applevisor::prelude::*;

        self.vcpu.run().map_err(hvf_error)?;
        let exit = self.vcpu.get_exit_info();
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
            let underlying = self
                .vcpu
                .get_sys_reg(SysReg::ESR_EL1)
                .map_err(hvf_error)?;
            if !is_aarch64_svc_exception(underlying) {
                let elr = self
                    .vcpu
                    .get_sys_reg(SysReg::ELR_EL1)
                    .unwrap_or(0);
                let far = self
                    .vcpu
                    .get_sys_reg(SysReg::FAR_EL1)
                    .unwrap_or(0);
                return Err(TrapError::EL0Fault {
                    syndrome: underlying,
                    elr,
                    far,
                });
            }
        }
        self.last_exit_class = aarch64_exception_class(exception.syndrome);

        if std::env::var_os("CARRICK_TRACE_REGS").is_some() {
            let pc = self.vcpu.get_reg(Reg::PC).map_err(hvf_error)?;
            let elr = self
                .vcpu
                .get_sys_reg(SysReg::ELR_EL1)
                .map_err(hvf_error)?;
            let spsr = self
                .vcpu
                .get_sys_reg(SysReg::SPSR_EL1)
                .map_err(hvf_error)?;
            let sp_el0 = self
                .vcpu
                .get_sys_reg(SysReg::SP_EL0)
                .map_err(hvf_error)?;
            let far = self
                .vcpu
                .get_sys_reg(SysReg::FAR_EL1)
                .map_err(hvf_error)?;
            let x0 = self.vcpu.get_reg(Reg::X0).map_err(hvf_error)?;
            let x1 = self.vcpu.get_reg(Reg::X1).map_err(hvf_error)?;
            let x2 = self.vcpu.get_reg(Reg::X2).map_err(hvf_error)?;
            let x3 = self.vcpu.get_reg(Reg::X3).map_err(hvf_error)?;
            let x4 = self.vcpu.get_reg(Reg::X4).map_err(hvf_error)?;
            let x5 = self.vcpu.get_reg(Reg::X5).map_err(hvf_error)?;
            let x8 = self.vcpu.get_reg(Reg::X8).map_err(hvf_error)?;
            let esr = self
                .vcpu
                .get_sys_reg(SysReg::ESR_EL1)
                .map_err(hvf_error)?;
            eprintln!(
                "TRAP exit_va=0x{:x} exit_pa=0x{:x} esr_el1=0x{:x} (ec=0x{:02x}) pc=0x{:x} elr=0x{:x} sp=0x{:x} far=0x{:x} x8={} x0=0x{:x} x1=0x{:x}",
                exception.virtual_address, exception.physical_address, esr, (esr >> 26) & 0x3f, pc, elr, sp_el0, far, x8, x0, x1
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
        let guest_pc = self
            .vcpu
            .get_sys_reg(SysReg::ELR_EL1)
            .unwrap_or(0);
        let lr = self.vcpu.get_reg(Reg::LR).unwrap_or(0);
        // FP (x29) + SP let guest_stack.d walk the guest call chain.
        let fp = self.vcpu.get_reg(Reg::X29).unwrap_or(0);
        let sp = self.vcpu.get_sys_reg(SysReg::SP_EL0).unwrap_or(0);
        // Wrapping guest->host offset for the region containing `sp`,
        // so the stack walker can translate frame addresses directly.
        let stack_xlate = self
            .mappings
            .iter()
            .find(|m| sp >= m.start && sp < m.end)
            .map(|m| (m.host_addr as u64).wrapping_sub(m.start))
            .unwrap_or(0);
        crate::probes::vcpu_trap(&crate::compat::GuestRegs {
            pc: guest_pc,
            sp,
            fp,
            lr,
            x8: frame.x8,
            x0: frame.x0,
            stack_xlate,
        });
        Ok(frame)
    }

    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError> {
        use applevisor::prelude::*;

        self.vcpu
            .set_reg(Reg::X0, return_value as u64)
            .map_err(hvf_error)?;
        if std::env::var_os("CARRICK_TRACE_REGS").is_some() {
            let pc = self.vcpu.get_reg(Reg::PC).map_err(hvf_error)?;
            let elr = self
                .vcpu
                .get_sys_reg(SysReg::ELR_EL1)
                .map_err(hvf_error)?;
            eprintln!(
                "COMPLETE return=0x{:x} pc=0x{:x} elr_el1=0x{:x}",
                return_value, pc, elr
            );
        }
        Ok(())
    }

    fn read_guest_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        let Some(mapping) = self.mapping_for_range(address, length) else {
            return Err(MemoryError::OutOfBounds { address, length });
        };
        // Read directly out of the host buffer. Works for both
        // applevisor-owned mappings (the parent case) and raw mappings
        // we re-created in a forked child via hv_vm_map.
        let offset = (address - mapping.start) as usize;
        let mut bytes = vec![0u8; length];
        unsafe {
            std::ptr::copy_nonoverlapping(
                mapping.host_addr.add(offset),
                bytes.as_mut_ptr(),
                length,
            );
        }
        Ok(bytes)
    }

    fn write_guest_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let length = bytes.len();
        let Some(mapping) = self.mapping_for_range_mut(address, length) else {
            return Err(MemoryError::OutOfBounds { address, length });
        };
        let offset = (address - mapping.start) as usize;
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                mapping.host_addr.add(offset),
                length,
            );
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

    /// Snapshot every register the trap engine ever writes. We restore
    /// from this in the forked child after the new vCPU is created.
    fn snapshot_vcpu(&self) -> Result<VcpuSnapshot, TrapError> {
        use applevisor::prelude::*;
        const GPR_TABLE: [Reg; 31] = [
            Reg::X0, Reg::X1, Reg::X2, Reg::X3, Reg::X4, Reg::X5, Reg::X6,
            Reg::X7, Reg::X8, Reg::X9, Reg::X10, Reg::X11, Reg::X12,
            Reg::X13, Reg::X14, Reg::X15, Reg::X16, Reg::X17, Reg::X18,
            Reg::X19, Reg::X20, Reg::X21, Reg::X22, Reg::X23, Reg::X24,
            Reg::X25, Reg::X26, Reg::X27, Reg::X28, Reg::X29, Reg::X30,
        ];
        let mut gprs = [0u64; 31];
        for (i, reg) in GPR_TABLE.iter().enumerate() {
            gprs[i] = self.vcpu.get_reg(*reg).map_err(hvf_error)?;
        }
        Ok(VcpuSnapshot {
            gprs,
            pc: self.vcpu.get_reg(Reg::PC).map_err(hvf_error)?,
            cpsr: self.vcpu.get_reg(Reg::CPSR).map_err(hvf_error)?,
            sp_el0: self.vcpu.get_sys_reg(SysReg::SP_EL0).map_err(hvf_error)?,
            sctlr_el1: self.vcpu.get_sys_reg(SysReg::SCTLR_EL1).map_err(hvf_error)?,
            tcr_el1: self.vcpu.get_sys_reg(SysReg::TCR_EL1).map_err(hvf_error)?,
            ttbr0_el1: self.vcpu.get_sys_reg(SysReg::TTBR0_EL1).map_err(hvf_error)?,
            mair_el1: self.vcpu.get_sys_reg(SysReg::MAIR_EL1).map_err(hvf_error)?,
            vbar_el1: self.vcpu.get_sys_reg(SysReg::VBAR_EL1).map_err(hvf_error)?,
            cpacr_el1: self.vcpu.get_sys_reg(SysReg::CPACR_EL1).map_err(hvf_error)?,
            spsr_el1: self.vcpu.get_sys_reg(SysReg::SPSR_EL1).map_err(hvf_error)?,
            elr_el1: self.vcpu.get_sys_reg(SysReg::ELR_EL1).map_err(hvf_error)?,
            tpidr_el0: self.vcpu.get_sys_reg(SysReg::TPIDR_EL0).map_err(hvf_error)?,
            last_exit_class: self.last_exit_class,
        })
    }

    fn restore_vcpu(&mut self, snap: &VcpuSnapshot) -> Result<(), TrapError> {
        use applevisor::prelude::*;
        const GPR_TABLE: [Reg; 31] = [
            Reg::X0, Reg::X1, Reg::X2, Reg::X3, Reg::X4, Reg::X5, Reg::X6,
            Reg::X7, Reg::X8, Reg::X9, Reg::X10, Reg::X11, Reg::X12,
            Reg::X13, Reg::X14, Reg::X15, Reg::X16, Reg::X17, Reg::X18,
            Reg::X19, Reg::X20, Reg::X21, Reg::X22, Reg::X23, Reg::X24,
            Reg::X25, Reg::X26, Reg::X27, Reg::X28, Reg::X29, Reg::X30,
        ];
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
    ) -> Result<(), TrapError> {
        use applevisor::prelude::*;
        use zerocopy::IntoBytes;

        const GPR_TABLE: [Reg; 31] = [
            Reg::X0, Reg::X1, Reg::X2, Reg::X3, Reg::X4, Reg::X5, Reg::X6,
            Reg::X7, Reg::X8, Reg::X9, Reg::X10, Reg::X11, Reg::X12,
            Reg::X13, Reg::X14, Reg::X15, Reg::X16, Reg::X17, Reg::X18,
            Reg::X19, Reg::X20, Reg::X21, Reg::X22, Reg::X23, Reg::X24,
            Reg::X25, Reg::X26, Reg::X27, Reg::X28, Reg::X29, Reg::X30,
        ];

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
        frame.saved_pc = self.vcpu.get_sys_reg(SysReg::ELR_EL1).map_err(hvf_error)?;
        frame.saved_sp = self.vcpu.get_sys_reg(SysReg::SP_EL0).map_err(hvf_error)?;
        frame.saved_spsr = self
            .vcpu
            .get_sys_reg(SysReg::SPSR_EL1)
            .map_err(hvf_error)?;

        // Reserve space on SP_EL0, rounded down to 16-byte alignment
        // (AArch64 stack alignment requirement at function-call boundaries).
        let frame_bytes = frame.as_bytes();
        let frame_len = frame_bytes.len() as u64;
        let aligned_len = (frame_len + 15) & !15u64;
        let new_sp = frame
            .saved_sp
            .checked_sub(aligned_len)
            .ok_or_else(|| TrapError::Hypervisor("sigframe push underflowed SP_EL0".to_string()))?;
        let new_sp = new_sp & !15u64;

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
        // x1/x2 carry siginfo* / ucontext* on SA_SIGINFO. We don't
        // construct those (handler should not assume it was registered
        // with SA_SIGINFO since musl maps 1-arg handlers to non-
        // SA_SIGINFO entries by default), but zero them so a curious
        // handler doesn't dereference whatever was in those registers.
        self.vcpu.set_reg(Reg::X1, 0).map_err(hvf_error)?;
        self.vcpu.set_reg(Reg::X2, 0).map_err(hvf_error)?;

        // LR = sa_restorer. When the handler executes `ret`, control
        // lands at the restorer which is responsible for invoking
        // `rt_sigreturn(2)`. If sa_restorer is zero we fall back to
        // putting the rt_sigreturn syscall directly inline at the
        // frame's start of unused reserved area — but musl always
        // provides one, so we surface an error in the zero case for
        // now to keep the impl honest.
        if sa_restorer == 0 {
            return Err(TrapError::Hypervisor(
                "signal handler registered without sa_restorer; no vDSO trampoline available"
                    .to_string(),
            ));
        }
        self.vcpu.set_reg(Reg::X30, sa_restorer).map_err(hvf_error)?;

        // Redirect post-eret PC to the handler. ELR_EL1 was previously
        // "instruction after the SVC that just trapped"; we steal it
        // for the handler entry, and the saved value lives in
        // frame.saved_pc until rt_sigreturn restores it.
        self.vcpu
            .set_sys_reg(SysReg::ELR_EL1, handler)
            .map_err(hvf_error)?;

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
            stack_xlate: 0,
        });
        Ok(())
    }

    /// Pop the Carrick sigframe at SP_EL0 (placed there by
    /// `inject_signal`) and restore the pre-signal register state.
    fn restore_from_sigframe(&mut self) -> Result<(), TrapError> {
        use applevisor::prelude::*;
        use zerocopy::FromBytes;

        const GPR_TABLE: [Reg; 31] = [
            Reg::X0, Reg::X1, Reg::X2, Reg::X3, Reg::X4, Reg::X5, Reg::X6,
            Reg::X7, Reg::X8, Reg::X9, Reg::X10, Reg::X11, Reg::X12,
            Reg::X13, Reg::X14, Reg::X15, Reg::X16, Reg::X17, Reg::X18,
            Reg::X19, Reg::X20, Reg::X21, Reg::X22, Reg::X23, Reg::X24,
            Reg::X25, Reg::X26, Reg::X27, Reg::X28, Reg::X29, Reg::X30,
        ];

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
        // fields. Copy out the whole register array first.
        let saved_x = frame.saved_x;
        for (reg, value) in GPR_TABLE.iter().zip(saved_x.iter()) {
            self.vcpu.set_reg(*reg, *value).map_err(hvf_error)?;
        }
        let saved_pc = frame.saved_pc;
        let saved_sp = frame.saved_sp;
        let saved_spsr = frame.saved_spsr;
        self.vcpu
            .set_sys_reg(SysReg::ELR_EL1, saved_pc)
            .map_err(hvf_error)?;
        self.vcpu
            .set_sys_reg(SysReg::SP_EL0, saved_sp)
            .map_err(hvf_error)?;
        self.vcpu
            .set_sys_reg(SysReg::SPSR_EL1, saved_spsr)
            .map_err(hvf_error)?;
        Ok(())
    }

    fn fork(&mut self) -> Result<ForkOutcome, TrapError> {
        use applevisor::prelude::*;

        // Pre-fork: snapshot vCPU state and capture mapping descriptors.
        let snapshot = self.snapshot_vcpu()?;
        crate::probes::fork_pre(snapshot.pc, snapshot.elr_el1, snapshot.cpsr);
        let mapping_descs: Vec<(u64, u64, *mut u8, usize, MemPerms)> = self
            .mappings
            .iter()
            .map(|m| (m.start, m.end, m.host_addr, m.size, m.perms))
            .collect();

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
        let new_inner = HvfInner {
            _vm: new_vm,
            vcpu: new_vcpu,
            mappings: Vec::with_capacity(mapping_descs.len()),
            last_exit_class: snapshot.last_exit_class,
            is_forked_child: pid == 0,
        };
        unsafe {
            std::ptr::write(self as *mut HvfInner, new_inner);
        }

        // Re-map each region using raw hv_vm_map. The host buffer is
        // already valid in the child (COW); the new VM owns the new
        // stage-2 entries.
        for (start, end, host_addr, size, perms) in mapping_descs {
            let perms_raw: u64 = u64::from(perms);
            let r = unsafe {
                applevisor_sys::hv_vm_map(
                    host_addr as *mut std::ffi::c_void,
                    start,
                    size,
                    perms_raw,
                )
            };
            if r != 0 {
                return Err(TrapError::ChildMapFailed {
                    host_addr: host_addr as u64,
                    guest_start: start,
                    size,
                    code: r as u32,
                });
            }
            self.mappings.push(HvfMappedRegion {
                start,
                end,
                host_addr,
                size,
                perms,
                // No Memory object — the host buffer was inherited via
                // COW from the parent. Drop runs no HVF call for this
                // mapping; the child's VM tear-down on engine drop will
                // tear all stage-2 mappings down in one shot.
                memory: None,
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
        };
        unsafe {
            std::ptr::write(self as *mut HvfInner, new_inner);
        }

        // Apply the new mapping plan + initial vCPU state. We replicate
        // the body of HvfTrapEngine::map_address_space's HVF setup
        // sequence inline; refactoring out a shared function is the
        // next iteration once we have a third caller.
        for mapping in &plan.mappings {
            let mut memory = self
                ._vm
                .memory_create(
                    usize::try_from(mapping.mapped_size)
                        .map_err(|_| TrapError::MappingTooLarge(mapping.mapped_size))?,
                )
                .map_err(hvf_error)?;
            memory
                .map(mapping.guest_start, hvf_perms(mapping.perms))
                .map_err(hvf_error)?;
            memory
                .write(mapping.guest_start, &mapping.image)
                .map_err(hvf_error)?;
            let host_addr = memory.host_addr();
            let size = usize::try_from(mapping.mapped_size)
                .map_err(|_| TrapError::MappingTooLarge(mapping.mapped_size))?;
            let perms = hvf_perms(mapping.perms);
            self.mappings.push(HvfMappedRegion {
                start: mapping.guest_start,
                end: mapping.guest_start.checked_add(mapping.mapped_size).ok_or(
                    TrapError::MappingOverflow {
                        guest_start: mapping.guest_start,
                        mapped_size: mapping.mapped_size,
                    },
                )?,
                host_addr,
                size,
                perms,
                memory: Some(memory),
            });
        }

        // Initial vCPU state — same sequence as `map_address_space`.
        // Zero the GPRs first: Linux's execve contract says the new
        // program starts with all registers clear (x29/x30 are part
        // of the ABI calling convention but the kernel zeros them too)
        // except for SP and PC. Without this, musl's _start in the new
        // image inherits the previous process's x8 which can decode
        // as a bogus syscall number on the first svc.
        const GPRS: [Reg; 31] = [
            Reg::X0, Reg::X1, Reg::X2, Reg::X3, Reg::X4, Reg::X5, Reg::X6,
            Reg::X7, Reg::X8, Reg::X9, Reg::X10, Reg::X11, Reg::X12,
            Reg::X13, Reg::X14, Reg::X15, Reg::X16, Reg::X17, Reg::X18,
            Reg::X19, Reg::X20, Reg::X21, Reg::X22, Reg::X23, Reg::X24,
            Reg::X25, Reg::X26, Reg::X27, Reg::X28, Reg::X29, Reg::X30,
        ];
        for reg in GPRS {
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
        let actual_sctlr = self
            .vcpu
            .get_sys_reg(SysReg::SCTLR_EL1)
            .unwrap_or(0);
        let actual_ttbr0 = self
            .vcpu
            .get_sys_reg(SysReg::TTBR0_EL1)
            .unwrap_or(0);
        let actual_mair = self
            .vcpu
            .get_sys_reg(SysReg::MAIR_EL1)
            .unwrap_or(0);
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

    fn run_until_syscall(&mut self) -> Result<Aarch64SyscallFrame, TrapError> {
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
