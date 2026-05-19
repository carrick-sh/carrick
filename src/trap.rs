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
    inner: HvfInner,
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
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
struct HvfMappedRegion {
    start: u64,
    end: u64,
    memory: applevisor::memory::Memory,
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

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn new_platform() -> Result<Self, TrapError> {
        use applevisor::prelude::*;

        let max_ipa = VirtualMachineConfig::get_max_ipa_size().map_err(hvf_error)?;
        let mut config = VirtualMachineConfig::new();
        config.set_ipa_size(max_ipa).map_err(hvf_error)?;
        let vm = VirtualMachine::with_config(config).map_err(hvf_error)?;
        let vcpu = vm.vcpu_create().map_err(hvf_error)?;
        Ok(Self {
            inner: HvfInner {
                _vm: vm,
                vcpu,
                mappings: Vec::new(),
                last_exit_class: 0,
            },
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
            self.inner.mappings.push(HvfMappedRegion {
                start: mapping.guest_start,
                end: mapping.guest_start.checked_add(mapping.mapped_size).ok_or(
                    TrapError::MappingOverflow {
                        guest_start: mapping.guest_start,
                        mapped_size: mapping.mapped_size,
                    },
                )?,
                memory,
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

        Ok(Aarch64SyscallFrame {
            x0: self.vcpu.get_reg(Reg::X0).map_err(hvf_error)?,
            x1: self.vcpu.get_reg(Reg::X1).map_err(hvf_error)?,
            x2: self.vcpu.get_reg(Reg::X2).map_err(hvf_error)?,
            x3: self.vcpu.get_reg(Reg::X3).map_err(hvf_error)?,
            x4: self.vcpu.get_reg(Reg::X4).map_err(hvf_error)?,
            x5: self.vcpu.get_reg(Reg::X5).map_err(hvf_error)?,
            x8: self.vcpu.get_reg(Reg::X8).map_err(hvf_error)?,
        })
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
        let mut bytes = vec![0; length];
        mapping
            .memory
            .read(address, &mut bytes)
            .map_err(|_| MemoryError::OutOfBounds { address, length })?;
        Ok(bytes)
    }

    fn write_guest_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let length = bytes.len();
        let Some(mapping) = self.mapping_for_range_mut(address, length) else {
            return Err(MemoryError::OutOfBounds { address, length });
        };
        mapping
            .memory
            .write(address, bytes)
            .map_err(|_| MemoryError::OutOfBounds { address, length })
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
