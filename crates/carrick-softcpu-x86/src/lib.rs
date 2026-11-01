//! `carrick-softcpu-x86` — Level 0 + CPL0 same-ISA dynamic binary translator,
//! architectural MSR file, privileged instruction emulator, and VM-free `SoftMachine`
//! for x86_64 (`carrick-sh/carrick#578`).

#![cfg(target_arch = "x86_64")]

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

pub use block::{BlockExit, BlockFetchFault, MAX_INSN_BYTES, PlannedBlock, plan_block_from_memory};
pub use cflow::{compute_effective_va, eval_cc, resolve_cflow};
pub use context::{
    AdmitRefused, DescriptorTablePtr, FxsaveArea, HostAccess, InvalidInterruptVector,
    SoftCpuContext, SoftSegment, X86Exception, X86ExceptionVector, reg,
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
    SoftCpuException, SoftMmuMemory, SoftPageFault, SoftRequester, SoftSeatError, SoftTlb,
    SoftTlbEntry, SoftTlbPlane, SoftTlbStats, SoftTranslationError, SoftVcpuSeat, SoftWalker,
    Stage1Gpa, WalkOutcome, cpu_access_mode, is_canonical_va, read_guest_bytes, tlb_tag_mode_bits,
    translate_va, translate_with_frame, write_guest_bytes,
};
pub use msr::{
    DEFAULT_IA32_APIC_BASE, DEFAULT_IA32_PAT, EFER_LMA, EFER_LME, EFER_NXE, EFER_SCE,
    EFER_VALID_MASK, MSR_IA32_APIC_BASE, MSR_IA32_CSTAR, MSR_IA32_EFER, MSR_IA32_FMASK,
    MSR_IA32_FS_BASE, MSR_IA32_GS_BASE, MSR_IA32_KERNEL_GS_BASE, MSR_IA32_LSTAR,
    MSR_IA32_MISC_ENABLE, MSR_IA32_PAT, MSR_IA32_SFMASK, MSR_IA32_STAR, MSR_IA32_TSC,
    MSR_IA32_TSC_DEADLINE, MsrCapabilities, MsrError, MsrFile, MsrIndex, MsrWriteEffects,
};
