//! Variable-length x86_64 basic-block planner for `carrick-softcpu-x86`.

use iced_x86::{Decoder, DecoderError, DecoderOptions, Instruction};

use crate::context::SoftCpuContext;
use crate::decode::{CflowKind, DecodedInsn, InsnClass, SensitiveOp, classify};
use crate::mmu::{
    SOFT_TLB_OFFSET_MASK, SOFT_TLB_PAGE_MASK, SOFT_TLB_PAGE_SIZE, SoftAccessKind, SoftMmuMemory,
    SoftPageFault, is_canonical_va, translate_with_frame,
};

/// Architectural x86_64 instruction maximum length in bytes.
pub const MAX_INSN_BYTES: usize = 15;

/// Reason a basic block terminates.
#[derive(Clone, Debug)]
pub enum BlockExit {
    Syscall {
        va: u64,
        resume: u64,
    },
    ControlFlow {
        va: u64,
        kind: CflowKind,
        raw: Instruction,
    },
    Sensitive {
        va: u64,
        resume: u64,
        op: SensitiveOp,
        raw: Instruction,
    },
    Continue {
        target: u64,
    },
    InvalidOpcode {
        va: u64,
    },
}

impl BlockExit {
    #[must_use]
    pub const fn va(&self) -> u64 {
        match *self {
            Self::Syscall { va, .. }
            | Self::ControlFlow { va, .. }
            | Self::Sensitive { va, .. }
            | Self::InvalidOpcode { va } => va,
            Self::Continue { target } => target,
        }
    }
}

/// Fault encountered while fetching the entry instruction of a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockFetchFault {
    GeneralProtection { rip: u64, error_code: u32 },
    PageFault { rip: u64, fault: SoftPageFault },
}

/// Planned basic block ready for [`crate::emit::emit_block`].
#[derive(Clone, Debug)]
pub struct PlannedBlock {
    pub start: u64,
    pub end: u64,
    pub insns: Vec<DecodedInsn>,
    pub insn_bytes: Vec<[u8; MAX_INSN_BYTES]>,
    pub exit: BlockExit,
}

/// Fetch one instruction at `va` through `mem`, reading into the next 4 KiB page
/// ONLY if the instruction encoding actually straddles the page boundary.
fn fetch_one_insn<M: SoftMmuMemory>(
    va: u64,
    ctx: &mut SoftCpuContext,
    mem: &mut M,
) -> Result<(DecodedInsn, [u8; MAX_INSN_BYTES]), BlockFetchFault> {
    if !is_canonical_va(va) {
        return Err(BlockFetchFault::GeneralProtection {
            rip: va,
            error_code: 0,
        });
    }

    let page_off = (va & SOFT_TLB_OFFSET_MASK) as usize;
    let first_chunk = (SOFT_TLB_PAGE_SIZE as usize - page_off).min(MAX_INSN_BYTES);
    let mut buf = [0u8; MAX_INSN_BYTES];
    let (first_ptr, first_frame) = translate_with_frame(ctx, mem, va, SoftAccessKind::Execute)
        .map_err(|fault| BlockFetchFault::PageFault { rip: va, fault })?;
    let _ = mem.mark_code_page(first_frame, &mut [&mut ctx.tlb]);
    // SAFETY: `first_ptr` has at least `first_chunk` valid bytes within its 4 KiB page.
    unsafe { std::ptr::copy_nonoverlapping(first_ptr, buf.as_mut_ptr(), first_chunk) };

    let mut total_fetched = first_chunk;
    if first_chunk < MAX_INSN_BYTES {
        let mut probe_dec = Decoder::with_ip(64, &buf[..first_chunk], va, DecoderOptions::NONE);
        let _ = probe_dec.decode();
        if probe_dec.last_error() == DecoderError::NoMoreBytes {
            let next_page_va = (va & SOFT_TLB_PAGE_MASK).wrapping_add(SOFT_TLB_PAGE_SIZE);
            if !is_canonical_va(next_page_va) {
                return Err(BlockFetchFault::GeneralProtection {
                    rip: va,
                    error_code: 0,
                });
            }
            let (second_ptr, second_frame) =
                translate_with_frame(ctx, mem, next_page_va, SoftAccessKind::Execute)
                    .map_err(|fault| BlockFetchFault::PageFault { rip: va, fault })?;
            let _ = mem.mark_code_page(second_frame, &mut [&mut ctx.tlb]);
            let dst = buf[first_chunk..].as_mut_ptr();
            // SAFETY: `second_ptr` and `dst` each have `MAX_INSN_BYTES - first_chunk` valid bytes.
            unsafe { std::ptr::copy_nonoverlapping(second_ptr, dst, MAX_INSN_BYTES - first_chunk) };
            total_fetched = MAX_INSN_BYTES;
        }
    }

    let decoded = classify(&buf[..total_fetched], va).unwrap_or(DecodedInsn {
        va,
        len: 1,
        class: InsnClass::InvalidOpcode,
        raw: Instruction::default(),
        rip_relative_target: None,
        fs_relative: false,
        gs_relative: false,
    });
    Ok((decoded, buf))
}

/// Plan one basic block starting at `entry_va` over `ctx` and `mem`.
pub fn plan_block_from_memory<M: SoftMmuMemory>(
    entry_va: u64,
    max_insns: usize,
    max_span: usize,
    ctx: &mut SoftCpuContext,
    mem: &mut M,
) -> Result<PlannedBlock, BlockFetchFault> {
    let (max_insns, max_span) = (max_insns.max(1), max_span.max(MAX_INSN_BYTES));
    let (mut insns, mut insn_bytes, mut cursor) = (Vec::new(), Vec::new(), entry_va);

    let exit = loop {
        if insns.len() >= max_insns {
            break BlockExit::Continue { target: cursor };
        }
        let (decoded, raw_bytes) = match fetch_one_insn(cursor, ctx, mem) {
            Ok(pair) => pair,
            Err(fault) if insns.is_empty() => return Err(fault),
            Err(_) => break BlockExit::Continue { target: cursor },
        };
        let next_va = cursor.wrapping_add(decoded.len as u64);
        if !insns.is_empty() && (next_va.wrapping_sub(entry_va) as usize) > max_span {
            break BlockExit::Continue { target: cursor };
        }
        let (va, raw) = (decoded.va, decoded.raw);
        match decoded.class {
            InsnClass::Body => {
                insns.push(decoded);
                insn_bytes.push(raw_bytes);
                cursor = next_va;
            }
            InsnClass::Syscall => {
                break BlockExit::Syscall {
                    va,
                    resume: next_va,
                };
            }
            InsnClass::ControlFlow(kind) => break BlockExit::ControlFlow { va, kind, raw },
            InsnClass::Sensitive(op) => {
                break BlockExit::Sensitive {
                    va,
                    resume: next_va,
                    op,
                    raw,
                };
            }
            InsnClass::InvalidOpcode => break BlockExit::InvalidOpcode { va },
        }
    };

    Ok(PlannedBlock {
        start: entry_va,
        end: cursor,
        insns,
        insn_bytes,
        exit,
    })
}
