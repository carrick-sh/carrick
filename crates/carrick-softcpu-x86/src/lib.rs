//! `carrick-softcpu-x86` — Level 0 + CPL0 same-ISA dynamic binary translator,
//! architectural MSR file, privileged instruction emulator, and VM-free `SoftMachine`
//! for x86_64 (`carrick-sh/carrick#578`).

#![cfg(target_arch = "x86_64")]

pub mod apic;
pub mod block;
pub mod cflow;
pub mod context;
pub mod cpu;
pub mod cpuid;
pub mod decode;
pub mod emit;
pub mod machine;
pub mod mmu;
pub mod msr;
pub mod privileged;

pub use apic::{
    ApicCluster, ApicNode, LAPIC_APR_OFFSET, LAPIC_DEFAULT_PHYS_BASE, LAPIC_DFR_OFFSET,
    LAPIC_EOI_OFFSET, LAPIC_ESR_ILLEGAL_REG_ADDRESS, LAPIC_ESR_OFFSET,
    LAPIC_ESR_RECEIVE_ILLEGAL_VECTOR, LAPIC_ESR_SEND_ILLEGAL_VECTOR, LAPIC_ICR_DELIVERY_FIXED,
    LAPIC_ICR_DELIVERY_LOWEST_PRIORITY, LAPIC_ICR_DELIVERY_MODE_MASK,
    LAPIC_ICR_DELIVERY_STATUS_PENDING, LAPIC_ICR_DEST_MODE_LOGICAL, LAPIC_ICR_HIGH_OFFSET,
    LAPIC_ICR_LEVEL_ASSERT, LAPIC_ICR_LOW_OFFSET, LAPIC_ICR_SHORTHAND_ALL_EXCLUDING_SELF,
    LAPIC_ICR_SHORTHAND_ALL_INCLUDING_SELF, LAPIC_ICR_SHORTHAND_MASK, LAPIC_ICR_SHORTHAND_NONE,
    LAPIC_ICR_SHORTHAND_SELF, LAPIC_ICR_SHORTHAND_SHIFT, LAPIC_ICR_TRIGGER_LEVEL, LAPIC_ID_OFFSET,
    LAPIC_IRR_BASE_OFFSET, LAPIC_ISR_BASE_OFFSET, LAPIC_LDR_OFFSET, LAPIC_LVT_CMCI_OFFSET,
    LAPIC_LVT_ERROR_OFFSET, LAPIC_LVT_LINT0_OFFSET, LAPIC_LVT_LINT1_OFFSET, LAPIC_LVT_MASKED,
    LAPIC_LVT_PMC_OFFSET, LAPIC_LVT_THERMAL_OFFSET, LAPIC_LVT_TIMER_MODE_MASK,
    LAPIC_LVT_TIMER_MODE_ONESHOT, LAPIC_LVT_TIMER_MODE_PERIODIC, LAPIC_LVT_TIMER_MODE_SHIFT,
    LAPIC_LVT_TIMER_MODE_TSC_DEADLINE, LAPIC_LVT_TIMER_OFFSET, LAPIC_MIN_VALID_VECTOR,
    LAPIC_MMIO_SIZE, LAPIC_PPR_OFFSET, LAPIC_RRD_OFFSET, LAPIC_SVR_ENABLE, LAPIC_SVR_OFFSET,
    LAPIC_SVR_RESET, LAPIC_TIMER_CCR_OFFSET, LAPIC_TIMER_DCR_OFFSET, LAPIC_TIMER_ICR_OFFSET,
    LAPIC_TMR_BASE_OFFSET, LAPIC_TPR_OFFSET, LAPIC_VERSION_DEFAULT, LAPIC_VERSION_OFFSET,
    LapicTimerMode, LocalApic, ManualTscClock, MonotonicTscClock, TscClock,
};
pub use block::{BlockExit, BlockFetchFault, MAX_INSN_BYTES, PlannedBlock, plan_block_from_memory};
pub use cflow::{compute_effective_va, eval_cc, resolve_cflow};
pub use context::{
    AdmitRefused, DescriptorTablePtr, FxsaveArea, HostAccess, SoftCpuContext, SoftSegment,
    X86Exception, X86ExceptionVector, reg,
};
pub use cpu::{JitCodeBuffer, RunningContext, RunningCpu, SoftCpu, SoftCpuExit, SoftCpuNewError};
pub use cpuid::{Cpl0CpuidView, CpuidRegs, DEFAULT_TSC_HZ, GuestCpuidView, Level0CpuidView};
pub use decode::{CflowKind, DecodedInsn, InsnClass, SensitiveOp, classify, gpr_index};
pub use emit::{EmitError, EmittedBlock, JitStage, emit_block};
pub use machine::{SoftMachine, SoftMachineExit};
pub use mmu::{
    Access, AuthenticatedDescriptorWords, AuthenticatedGpa, Cpl, CpuAccessMode, DescriptorRefusal,
    DomainCompletion, ExtentEditError, ExtentRecord, ExtentTable, FrameGpa, GuestVa, HostVa,
    InventoryTerminal, LinearPlacement, LiveDescriptorWords, LookupAdmission, MmioHoles,
    OwnerGeneration, PF_ERR_INSTR, PF_ERR_PRESENT, PF_ERR_RSVD, PF_ERR_USER, PF_ERR_WRITE,
    PageFaultErrorCode, PageFaultInfo, PendingRetirement, Reclaimed, RetiredIdentity, Retirement,
    RetirementWaitError, RootGpa, SOFT_TLB_BITS, SOFT_TLB_ENTRIES, SOFT_TLB_INDEX_MASK,
    SOFT_TLB_INVALID_TAG, SOFT_TLB_OFFSET_MASK, SOFT_TLB_PAGE_MASK, SOFT_TLB_PAGE_SHIFT,
    SOFT_TLB_PAGE_SIZE, SOFT_TLB_TAG_AC_BIT, SOFT_TLB_TAG_CPL3_BIT, SoftAccessKind,
    SoftCpuException, SoftMemoryFault, SoftMmuMemory, SoftPageFault, SoftRequester, SoftSeatError,
    SoftTlb, SoftTlbEntry, SoftTlbPlane, SoftTlbStats, SoftTranslationError, SoftVcpuSeat,
    SoftWalker, Stage1Gpa, WalkOutcome, cpu_access_mode, is_canonical_va, read_guest_bytes,
    tlb_tag_mode_bits, translate_va, translate_with_frame, write_guest_bytes,
};
pub use msr::{
    DEFAULT_IA32_APIC_BASE, DEFAULT_IA32_PAT, EFER_LMA, EFER_LME, EFER_NXE, EFER_SCE,
    EFER_VALID_MASK, MSR_IA32_APIC_BASE, MSR_IA32_CSTAR, MSR_IA32_EFER, MSR_IA32_FMASK,
    MSR_IA32_FS_BASE, MSR_IA32_GS_BASE, MSR_IA32_KERNEL_GS_BASE, MSR_IA32_LSTAR,
    MSR_IA32_MISC_ENABLE, MSR_IA32_PAT, MSR_IA32_SFMASK, MSR_IA32_STAR, MSR_IA32_TSC,
    MSR_IA32_TSC_DEADLINE, MsrCapabilities, MsrError, MsrFile, MsrIndex, MsrWriteEffects,
};
