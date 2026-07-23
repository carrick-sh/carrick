//! x86_64 basic-block planner: turns a run of guest bytes into a
//! straight-line [`X86Block`] ending at the first syscall, control-flow, or
//! sensitive instruction (or a page/instruction-count limit).
//!
//! The AArch64 lane's `block::plan_with_reader` does the same over fixed
//! 4-byte words; here every step advances by the decoder-reported
//! instruction length ([`classify`] returns it), because x86 is
//! variable-length. Like the AArch64 planner this is a PURE function over a
//! byte reader, so it is fully unit-testable with no guest memory or JIT.

use std::convert::Infallible;

use crate::decode::{X86DecodeError, X86InstClass, X86SensitiveKind, classify};

/// One planned guest instruction: its VA, byte length, and class. The
/// emitter copies `Copy`-class instructions verbatim from guest memory using
/// `va`/`len`; the block's single non-`Copy` instruction is described by the
/// [`X86Exit`] instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlannedInst {
    pub va: u64,
    pub len: u8,
    pub class: X86InstClass,
    /// Whether this instruction touches FPU/vector state (see
    /// [`X86Block::uses_fpu`]).
    pub uses_fpu: bool,
}

/// Why a block ended and what the translator must do at its boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X86Exit {
    /// A `syscall`/`int 0x80` gate. The emitter stashes `resume` (the VA of
    /// the following instruction) and exits to Rust, which services the
    /// Linux syscall and re-enters at `resume`.
    Syscall { va: u64, resume: u64, int80: bool },
    /// A control-flow instruction ended the block. The vertical slice lowers
    /// this to an indirect exit that returns the runtime-computed next RIP;
    /// direct-branch chaining is a later fast path.
    ControlFlow { va: u64, len: u8 },
    /// A sensitive non-syscall instruction (rdtsc/cpuid/fsgsbase/fs-gs
    /// access). Serviced by the sensitive exit path; `kind` selects the
    /// handler.
    Sensitive {
        va: u64,
        len: u8,
        kind: X86SensitiveKind,
    },
    /// An undecodable/privileged/unsupported instruction. Fail-closed: the
    /// translator refuses the block rather than emitting wrong code.
    Unsupported { va: u64 },
    /// The block hit a structural limit (page boundary or instruction count)
    /// with no terminator; execution continues by translating `target`.
    Continue { target: u64, limit: BlockLimit },
}

impl X86Exit {
    /// Guest VA of the instruction (or continuation point) this exit sits at.
    pub const fn va(self) -> u64 {
        match self {
            Self::Syscall { va, .. }
            | Self::ControlFlow { va, .. }
            | Self::Sensitive { va, .. }
            | Self::Unsupported { va } => va,
            Self::Continue { target, .. } => target,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockLimit {
    PageBoundary,
    InstructionLimit,
    /// The next instruction could not be fetched. A nonempty prefix remains
    /// executable; replanning at `target` will surface the typed fetch fault at
    /// the architecturally correct instruction boundary.
    FetchBoundary,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X86Block {
    pub start: u64,
    /// One past the last planned byte (the terminator's VA for a terminating
    /// exit, or the continuation target for a `Continue`).
    pub end: u64,
    pub instructions: Vec<PlannedInst>,
    pub exit: X86Exit,
    /// Whether any emitted (copy-through) instruction in this block touches
    /// SSE/AVX/x87/MMX state. When false the gateway can skip the
    /// `fxsave`/`fxrstor` of the 512-byte FPU area around the block — the
    /// common case in integer code. Most terminators do not touch xstate, but
    /// an omitted XRSTOR terminator must force a save so Rust emulation sees
    /// the authoritative pre-instruction guest state.
    pub uses_fpu: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum X86BlockError {
    #[error("x86 block planner: guest VA overflow at 0x{va:x}")]
    VaOverflow { va: u64 },
    #[error("x86 block planner: page size must be a nonzero power of two, got {page_size}")]
    BadPageSize { page_size: u64 },
    #[error("x86 block planner: decode failed: {0}")]
    Decode(#[from] X86DecodeError),
}

/// A planner failure that retains a typed instruction-fetch error instead of
/// collapsing an inaccessible guest address into an empty byte vector.
#[derive(Debug, PartialEq, Eq)]
pub enum X86BlockPlanError<E> {
    Block(X86BlockError),
    Read { va: u64, error: E },
}

impl<E> From<X86BlockError> for X86BlockPlanError<E> {
    fn from(error: X86BlockError) -> Self {
        Self::Block(error)
    }
}

impl<E: std::fmt::Display> std::fmt::Display for X86BlockPlanError<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Block(error) => error.fmt(formatter),
            Self::Read { va, error } => {
                write!(
                    formatter,
                    "x86 block planner: instruction fetch at 0x{va:x} failed: {error}"
                )
            }
        }
    }
}

impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for X86BlockPlanError<E> {}

fn page_end(start: u64, page_size: u64) -> Result<u64, X86BlockError> {
    if page_size == 0 || !page_size.is_power_of_two() {
        return Err(X86BlockError::BadPageSize { page_size });
    }
    (start & !(page_size - 1))
        .checked_add(page_size)
        .ok_or(X86BlockError::VaOverflow { va: start })
}

/// Plan a block starting at guest VA `start`. `read` yields the instruction
/// bytes at a VA — it must return at least the full instruction (up to the
/// x86 max of 15 bytes), or a slice ending at the page boundary if that comes
/// first (the planner then treats a partial tail as a page-limit
/// continuation, not a truncation error). `max_instructions` caps block
/// length; `page_size` bounds the block to a single guest page so
/// generation/invalidation stays page-granular (mirrors the AArch64 lane).
pub fn plan_block(
    start: u64,
    max_instructions: usize,
    page_size: u64,
    mut read: impl FnMut(u64) -> Vec<u8>,
) -> Result<X86Block, X86BlockError> {
    match plan_block_with_reader(start, max_instructions, page_size, |va| {
        Ok::<_, Infallible>(read(va))
    }) {
        Ok(block) => Ok(block),
        Err(X86BlockPlanError::Block(error)) => Err(error),
        Err(X86BlockPlanError::Read { error, .. }) => match error {},
    }
}

/// Typed-reader form of [`plan_block`]. A fetch failure at the first
/// instruction is returned to the caller. If a block already has an executable
/// prefix, the planner ends that prefix at a [`BlockLimit::FetchBoundary`]; the
/// caller executes it before replanning the faulting instruction.
pub fn plan_block_with_reader<E>(
    start: u64,
    max_instructions: usize,
    page_size: u64,
    mut read: impl FnMut(u64) -> Result<Vec<u8>, E>,
) -> Result<X86Block, X86BlockPlanError<E>> {
    let limit = page_end(start, page_size)?;
    let mut va = start;
    let mut instructions = Vec::new();

    loop {
        if instructions.len() >= max_instructions {
            return Ok(continue_block(
                start,
                va,
                BlockLimit::InstructionLimit,
                instructions,
            ));
        }
        if va >= limit {
            return Ok(continue_block(
                start,
                va,
                BlockLimit::PageBoundary,
                instructions,
            ));
        }

        let bytes = match read(va) {
            Ok(bytes) => bytes,
            Err(error) if instructions.is_empty() => {
                return Err(X86BlockPlanError::Read { va, error });
            }
            Err(_) => {
                return Ok(continue_block(
                    start,
                    va,
                    BlockLimit::FetchBoundary,
                    instructions,
                ));
            }
        };
        match classify(&bytes, va) {
            Ok(c) => {
                let next = va
                    .checked_add(c.len as u64)
                    .ok_or(X86BlockError::VaOverflow { va })?;
                // An instruction that would cross the page boundary belongs to
                // the next page's generation; stop before it — UNLESS it is the
                // block's first instruction, which must always be included so a
                // block never makes zero progress. A first instruction that
                // spans the boundary spans an INTERNAL page boundary (code does
                // not span a segment's end), so the bytes are contiguous; an
                // empty `Continue{target: start}` block would otherwise let a
                // caller that chains blocks emit an infinite self-jump.
                if next > limit && !instructions.is_empty() {
                    return Ok(continue_block(
                        start,
                        va,
                        BlockLimit::PageBoundary,
                        instructions,
                    ));
                }
                match c.class {
                    X86InstClass::Copy => {
                        instructions.push(PlannedInst {
                            va,
                            len: c.len,
                            class: c.class,
                            uses_fpu: c.uses_fpu,
                        });
                        va = next;
                    }
                    X86InstClass::Sensitive(X86SensitiveKind::Syscall) => {
                        return Ok(terminate(
                            start,
                            next,
                            instructions,
                            X86Exit::Syscall {
                                va,
                                resume: next,
                                int80: false,
                            },
                        ));
                    }
                    X86InstClass::Sensitive(X86SensitiveKind::Int80) => {
                        return Ok(terminate(
                            start,
                            next,
                            instructions,
                            X86Exit::Syscall {
                                va,
                                resume: next,
                                int80: true,
                            },
                        ));
                    }
                    X86InstClass::Sensitive(kind) => {
                        return Ok(terminate(
                            start,
                            next,
                            instructions,
                            X86Exit::Sensitive {
                                va,
                                len: c.len,
                                kind,
                            },
                        ));
                    }
                    X86InstClass::ControlFlow => {
                        return Ok(terminate(
                            start,
                            next,
                            instructions,
                            X86Exit::ControlFlow { va, len: c.len },
                        ));
                    }
                    X86InstClass::Unsupported => {
                        return Ok(terminate(
                            start,
                            va,
                            instructions,
                            X86Exit::Unsupported { va },
                        ));
                    }
                }
            }
            // Not enough bytes before the page boundary: continue at the next
            // page rather than failing (the caller re-plans with that page
            // faulted in). A genuine mid-page truncation cannot occur because
            // `read` supplies up to 15 bytes.
            Err(X86DecodeError::Truncated { .. }) if va < limit => {
                return Ok(continue_block(
                    start,
                    va,
                    BlockLimit::PageBoundary,
                    instructions,
                ));
            }
            Err(error) => return Err(X86BlockError::from(error).into()),
        }
    }
}

fn terminate(start: u64, end: u64, instructions: Vec<PlannedInst>, exit: X86Exit) -> X86Block {
    let uses_fpu = instructions.iter().any(|i| i.uses_fpu)
        || matches!(
            exit,
            X86Exit::Sensitive {
                kind: X86SensitiveKind::XstateSave(_)
                    | X86SensitiveKind::XstateRestore(_)
                    | X86SensitiveKind::FxState(_)
                    | X86SensitiveKind::LegacyX87(_)
                    | X86SensitiveKind::X87Wait,
                ..
            }
        );
    X86Block {
        start,
        end,
        instructions,
        exit,
        uses_fpu,
    }
}

/// A structural (`Continue`) block: the whole planned run is the body, and
/// execution continues by translating `target`.
fn continue_block(
    start: u64,
    target: u64,
    limit: BlockLimit,
    instructions: Vec<PlannedInst>,
) -> X86Block {
    let uses_fpu = instructions.iter().any(|i| i.uses_fpu);
    X86Block {
        start,
        end: target,
        instructions,
        exit: X86Exit::Continue { target, limit },
        uses_fpu,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: u64 = 4096;
    const BASE: u64 = 0x40_0000;

    /// A reader over one contiguous byte image based at `BASE`.
    fn image_reader(image: &'static [u8]) -> impl FnMut(u64) -> Vec<u8> {
        move |va: u64| {
            let off = (va - BASE) as usize;
            if off >= image.len() {
                return Vec::new();
            }
            let end = (off + 15).min(image.len());
            image[off..end].to_vec()
        }
    }

    #[test]
    fn straight_line_ends_at_syscall() {
        // mov edi,1 (bf 01 00 00 00); mov eax,60 (b8 3c 00 00 00); syscall (0f 05)
        static IMG: &[u8] = &[
            0xbf, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05,
        ];
        let block = plan_block(BASE, 256, PAGE, image_reader(IMG)).expect("plan");
        assert_eq!(block.instructions.len(), 2, "two copy insts before syscall");
        assert!(
            block
                .instructions
                .iter()
                .all(|i| i.class == X86InstClass::Copy)
        );
        assert_eq!(
            block.exit,
            X86Exit::Syscall {
                va: BASE + 10,
                resume: BASE + 12,
                int80: false,
            }
        );
        assert_eq!(block.end, BASE + 12);
    }

    #[test]
    fn control_flow_terminates_block() {
        // nop (90); jmp +0 (eb 00)
        static IMG: &[u8] = &[0x90, 0xeb, 0x00];
        let block = plan_block(BASE, 256, PAGE, image_reader(IMG)).expect("plan");
        assert_eq!(block.instructions.len(), 1);
        assert_eq!(
            block.exit,
            X86Exit::ControlFlow {
                va: BASE + 1,
                len: 2
            }
        );
    }

    #[test]
    fn int80_is_a_syscall_exit() {
        // int 0x80 (cd 80)
        static IMG: &[u8] = &[0xcd, 0x80];
        let block = plan_block(BASE, 256, PAGE, image_reader(IMG)).expect("plan");
        assert!(block.instructions.is_empty());
        assert_eq!(
            block.exit,
            X86Exit::Syscall {
                va: BASE,
                resume: BASE + 2,
                int80: true,
            }
        );
    }

    #[test]
    fn sensitive_nonsyscall_terminates() {
        // rdtsc (0f 31)
        static IMG: &[u8] = &[0x0f, 0x31];
        let block = plan_block(BASE, 256, PAGE, image_reader(IMG)).expect("plan");
        assert_eq!(
            block.exit,
            X86Exit::Sensitive {
                va: BASE,
                len: 2,
                kind: X86SensitiveKind::Rdtsc {
                    with_processor_id: false
                },
            }
        );
        assert!(
            !block.uses_fpu,
            "non-XRSTOR sensitive instructions retain the existing save policy"
        );
    }

    #[test]
    fn all_xsave_forms_end_as_typed_sensitive_blocks_with_authoritative_state() {
        for (image, len, kind) in [
            (
                &[0x0f, 0xae, 0x64, 0x24, 0x40][..],
                5,
                crate::decode::X86XstateSaveKind::Xsave,
            ),
            (
                &[0x48, 0x0f, 0xae, 0x64, 0x24, 0x40][..],
                6,
                crate::decode::X86XstateSaveKind::Xsave64,
            ),
            (
                &[0x0f, 0xae, 0x74, 0x24, 0x40][..],
                5,
                crate::decode::X86XstateSaveKind::Xsaveopt,
            ),
            (
                &[0x48, 0x0f, 0xae, 0x74, 0x24, 0x40][..],
                6,
                crate::decode::X86XstateSaveKind::Xsaveopt64,
            ),
            (
                &[0x0f, 0xc7, 0x64, 0x24, 0x40][..],
                5,
                crate::decode::X86XstateSaveKind::Xsavec,
            ),
            (
                &[0x48, 0x0f, 0xc7, 0x64, 0x24, 0x40][..],
                6,
                crate::decode::X86XstateSaveKind::Xsavec64,
            ),
        ] {
            let block = plan_block(BASE, 256, PAGE, |va| {
                usize::try_from(va - BASE)
                    .ok()
                    .and_then(|offset| image.get(offset..))
                    .map(<[u8]>::to_vec)
                    .unwrap_or_default()
            })
            .expect("plan XSAVE");
            assert!(block.instructions.is_empty());
            assert!(block.uses_fpu, "XSAVE needs the authoritative guest image");
            assert_eq!(
                block.exit,
                X86Exit::Sensitive {
                    va: BASE,
                    len,
                    kind: X86SensitiveKind::XstateSave(kind),
                }
            );
        }
    }

    #[test]
    fn exact_rsp_xrstor_and_xrstor64_end_as_typed_sensitive_blocks() {
        for (image, len, kind) in [
            (
                &[0x0f, 0xae, 0x6c, 0x24, 0x40][..],
                5,
                crate::decode::X86XstateRestoreKind::Xrstor,
            ),
            (
                &[0x48, 0x0f, 0xae, 0x6c, 0x24, 0x40][..],
                6,
                crate::decode::X86XstateRestoreKind::Xrstor64,
            ),
        ] {
            let block = plan_block(BASE, 256, PAGE, |va| {
                usize::try_from(va - BASE)
                    .ok()
                    .and_then(|offset| image.get(offset..))
                    .map(<[u8]>::to_vec)
                    .unwrap_or_default()
            })
            .expect("plan XRSTOR");
            assert!(block.instructions.is_empty());
            assert!(
                block.uses_fpu,
                "the gateway must capture authoritative pre-XRSTOR guest xstate"
            );
            assert_eq!(
                block.exit,
                X86Exit::Sensitive {
                    va: BASE,
                    len,
                    kind: X86SensitiveKind::XstateRestore(kind),
                }
            );
        }
    }

    #[test]
    fn instruction_limit_yields_continue() {
        // three nops, cap at 2
        static IMG: &[u8] = &[0x90, 0x90, 0x90];
        let block = plan_block(BASE, 2, PAGE, image_reader(IMG)).expect("plan");
        assert_eq!(block.instructions.len(), 2);
        assert_eq!(
            block.exit,
            X86Exit::Continue {
                target: BASE + 2,
                limit: BlockLimit::InstructionLimit,
            }
        );
    }

    #[test]
    fn instruction_straddling_page_boundary_stops_before_it() {
        // Place a 5-byte mov so it would cross a page end: start 3 bytes before.
        static IMG: &[u8] = &[0xbf, 0x01, 0x00, 0x00, 0x00];
        // A tiny page so BASE+3 is 2 bytes from the boundary; the 5-byte insn
        // at BASE+... let's use a 8-byte page window aligned so the mov crosses.
        let page: u64 = 8;
        let start = BASE + 5; // BASE..BASE+8 is one page; instr at +5 is 5 bytes -> crosses +8
        let reader = |va: u64| {
            let off = (va - BASE) as usize;
            if off >= IMG.len() {
                return Vec::new();
            }
            IMG[off..].to_vec()
        };
        let block = plan_block(start, 256, page, reader).expect("plan");
        assert!(block.instructions.is_empty());
        assert!(matches!(
            block.exit,
            X86Exit::Continue {
                limit: BlockLimit::PageBoundary,
                ..
            }
        ));
    }

    #[test]
    fn first_instruction_spanning_a_page_is_included_not_dropped() {
        // A 5-byte `mov edi, 1` at BASE+6 spans the 8-byte page boundary at
        // BASE+8. As the block's FIRST instruction it must be INCLUDED (the
        // bytes are contiguous within a segment), then the block continues past
        // it — a plan must never make zero progress, which would let a chaining
        // caller emit an infinite self-jump.
        static IMG: &[u8] = &[
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // 6 nops
            0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1 at offset 6
            0x90,
        ];
        let page: u64 = 8;
        let start = BASE + 6;
        let reader = |va: u64| {
            let off = (va - BASE) as usize;
            IMG.get(off..).map(|s| s.to_vec()).unwrap_or_default()
        };
        let block = plan_block(start, 256, page, reader).expect("plan");
        assert_eq!(
            block.instructions.len(),
            1,
            "the spanning first insn is kept"
        );
        assert_eq!(block.instructions[0].va, start);
        assert_eq!(block.instructions[0].len, 5);
        assert_eq!(
            block.exit,
            X86Exit::Continue {
                target: BASE + 11,
                limit: BlockLimit::PageBoundary,
            }
        );
    }

    #[test]
    fn typed_reader_retains_first_instruction_fetch_fault() {
        let error = plan_block_with_reader(BASE, 256, PAGE, |_va| {
            Err::<Vec<u8>, _>("mapped executable backing fault")
        })
        .expect_err("first instruction fetch must remain typed");
        assert_eq!(
            error,
            X86BlockPlanError::Read {
                va: BASE,
                error: "mapped executable backing fault",
            }
        );
    }

    #[test]
    fn typed_reader_executes_prefix_before_replanning_fault_boundary() {
        let block = plan_block_with_reader(BASE, 256, PAGE, |va| {
            if va == BASE {
                Ok(vec![0x90])
            } else {
                Err("next instruction is inaccessible")
            }
        })
        .expect("a valid prefix remains executable");
        assert_eq!(block.instructions.len(), 1);
        assert_eq!(
            block.exit,
            X86Exit::Continue {
                target: BASE + 1,
                limit: BlockLimit::FetchBoundary,
            }
        );
    }

    #[test]
    fn unsupported_instruction_fails_closed_as_exit() {
        // hlt (f4)
        static IMG: &[u8] = &[0x90, 0xf4];
        let block = plan_block(BASE, 256, PAGE, image_reader(IMG)).expect("plan");
        assert_eq!(block.instructions.len(), 1, "the leading nop copies");
        assert_eq!(block.exit, X86Exit::Unsupported { va: BASE + 1 });
    }
}
