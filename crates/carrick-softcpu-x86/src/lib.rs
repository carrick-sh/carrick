//! `carrick-softcpu-x86` — Level 0 same-ISA copy-through dynamic binary translator
//! for x86_64 user mode (`carrick-sh/carrick#578`, slice 1b `#581`).

#![cfg(target_arch = "x86_64")]

pub mod block;
pub mod cflow;
pub mod context;
pub mod cpu;
pub mod decode;
pub mod emit;
pub mod mmu;

pub use block::{BlockExit, BlockFetchFault, MAX_INSN_BYTES, PlannedBlock, plan_block_from_memory};
pub use cflow::{compute_effective_va, eval_cc, resolve_cflow};
pub use context::{FxsaveArea, SoftCpuContext, X86Exception, X86ExceptionVector, reg};
pub use cpu::{JitCodeBuffer, SoftCpu, SoftCpuExit};
pub use decode::{CflowKind, DecodedInsn, InsnClass, SensitiveOp, classify, gpr_index};
pub use emit::{EmitError, EmittedBlock, JitStage, emit_block};
pub use mmu::{
    Access, AuthenticatedDescriptorWords, AuthenticatedGpa, Cpl, CpuAccessMode, DescriptorRefusal,
    ExtentRecord, ExtentTable, FrameGpa, GuestVa, HostVa, LinearPlacement, LiveDescriptorWords,
    MmioHoles, OwnerGeneration, PF_ERR_INSTR, PF_ERR_PRESENT, PF_ERR_RSVD, PF_ERR_USER,
    PF_ERR_WRITE, PageFaultErrorCode, PageFaultInfo, RootGpa, SOFT_TLB_BITS, SOFT_TLB_ENTRIES,
    SOFT_TLB_INDEX_MASK, SOFT_TLB_INVALID_TAG, SOFT_TLB_OFFSET_MASK, SOFT_TLB_PAGE_MASK,
    SOFT_TLB_PAGE_SHIFT, SOFT_TLB_PAGE_SIZE, SOFT_TLB_TAG_AC_BIT, SOFT_TLB_TAG_CPL3_BIT,
    SoftAccessKind, SoftCpuException, SoftMmuMemory, SoftPageFault, SoftTlb, SoftTlbEntry,
    SoftTlbPlane, SoftTlbStats, SoftTranslationError, SoftWalker, Stage1Gpa, WalkOutcome,
    cpu_access_mode, is_canonical_va, read_guest_bytes, tlb_tag_mode_bits, translate_va,
    translate_with_frame, write_guest_bytes,
};
