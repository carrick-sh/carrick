#![allow(dead_code)] // Block publication is wired into DSR execution in Task 5.

use carrick_guest_mem::GuestVa;

use super::super::NativeMappedMemory;
use super::decode;
use super::types::{
    BiasedExclusiveScratch, CodeGeneration, DirectExit, DirectKind, DsrError, DsrScratchGpr,
    ExclusiveFusionDisposition, ExclusiveFusionRejection, ExclusiveFusionSite, ExclusiveRegionExit,
    IndirectExit, InstAction, MemoryAccess, MemoryBase, SensitiveExit, SensitiveKind,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PlannedInst {
    pub(super) guest: GuestVa,
    pub(super) action: InstAction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BlockLimit {
    PageBoundary,
    InstructionLimit,
    /// The block was split just before a fusible exclusive region so the
    /// exclusive load starts a fresh, self-contained fused block. Compilers
    /// emit the CAS/RMW argument setup (address, expected, new value) BEFORE
    /// the exclusive load, so the load is almost always reached mid-block; this
    /// split is what lets it become a block start and fuse (see
    /// `plan_with_reader`).
    ExclusiveRegionSplit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PlannedExit {
    Continue {
        target: GuestVa,
        limit: BlockLimit,
    },
    Syscall {
        guest: GuestVa,
        resume: GuestVa,
    },
    Sensitive {
        guest: GuestVa,
        word: u32,
        exit: SensitiveExit,
        fusion: Option<ExclusiveFusionSite>,
    },
    /// A fused exclusive region terminating the block (see
    /// `analyze_exclusive_region`). Direct mode produces this today; biased
    /// mode records eligibility on a `Sensitive` fallback until its emitter
    /// support is enabled.
    ExclusiveRegion {
        guest: GuestVa,
        word: u32,
        exit: ExclusiveRegionExit,
        fusion: ExclusiveFusionSite,
    },
    Direct {
        guest: GuestVa,
        word: u32,
        exit: DirectExit,
    },
    Indirect {
        guest: GuestVa,
        word: u32,
        exit: IndirectExit,
    },
    Unsupported {
        guest: GuestVa,
        word: u32,
        op: bad64::Op,
    },
    VirtualizedX18 {
        guest: GuestVa,
        word: u32,
        op: bad64::Op,
    },
    VirtualizedX28 {
        guest: GuestVa,
        word: u32,
        op: bad64::Op,
    },
}

impl PlannedExit {
    pub(super) const fn guest_pc(self) -> GuestVa {
        match self {
            Self::Continue { target, .. } => target,
            Self::Syscall { guest, .. }
            | Self::Sensitive { guest, .. }
            | Self::ExclusiveRegion { guest, .. }
            | Self::Direct { guest, .. }
            | Self::Indirect { guest, .. }
            | Self::Unsupported { guest, .. }
            | Self::VirtualizedX18 { guest, .. }
            | Self::VirtualizedX28 { guest, .. } => guest,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BlockPlan {
    pub(super) start: GuestVa,
    pub(super) end: GuestVa,
    pub(super) generation: CodeGeneration,
    pub(super) instructions: Vec<PlannedInst>,
    pub(super) exit: PlannedExit,
}

fn checked_next(pc: GuestVa) -> Result<GuestVa, DsrError> {
    pc.raw()
        .checked_add(4)
        .map(GuestVa)
        .ok_or(DsrError::PcOverflow { pc: pc.raw() })
}

fn page_end(start: GuestVa, page_size: u64) -> Result<GuestVa, DsrError> {
    if page_size == 0 || !page_size.is_power_of_two() {
        return Err(DsrError::BlockPolicy(format!(
            "DSR block page size must be a nonzero power of two, got {page_size}"
        )));
    }
    let page_start = start.raw() & !(page_size - 1);
    page_start
        .checked_add(page_size)
        .map(GuestVa)
        .ok_or(DsrError::PcOverflow { pc: start.raw() })
}

fn plan_with_reader(
    start: GuestVa,
    generation: CodeGeneration,
    max_instructions: usize,
    page_size: u64,
    fusion_policy: ExclusiveFusionPolicy,
    mut read: impl FnMut(GuestVa) -> Result<u32, DsrError>,
) -> Result<BlockPlan, DsrError> {
    if max_instructions == 0 {
        return Err(DsrError::BlockPolicy(
            "DSR block instruction limit must be nonzero".to_string(),
        ));
    }
    if !start.raw().is_multiple_of(4) {
        return Err(DsrError::BlockPolicy(format!(
            "DSR block start is not instruction aligned: 0x{:x}",
            start.raw()
        )));
    }

    let boundary = page_end(start, page_size)?;
    let mut pc = start;
    let mut instructions = Vec::new();
    loop {
        let word = read(pc)?;
        let action = decode::classify(word, pc)?;
        let next = checked_next(pc)?;
        // Analyze exclusive-region fusion. A fused region must be a
        // self-contained block whose retry edge re-enters the exclusive load
        // with no instruction (and, critically, no block prologue / context
        // store) between the load and the store. So the load must be the
        // block's FIRST instruction:
        //   - if it already is (`instructions.is_empty()`), emit the fused
        //     region as this block;
        //   - if the region is fusible but the load is reached mid-block
        //     (compilers load the CAS/RMW operands before the exclusive load,
        //     so this is the common case), END this block just before the load
        //     with a `Continue`, so the next translation starts AT the load and
        //     fuses. Without this split the load would never be a block start
        //     in the uncontended case (the retry edge that targets it is not
        //     taken), and would never fuse.
        // Biased execution remains disabled, but the shared analysis records
        // why every exclusive site did or did not qualify.
        let mut exclusive_fusion = None;
        if let InstAction::Sensitive(SensitiveExit {
            kind: SensitiveKind::Exclusive(load_word),
            ..
        }) = action
        {
            match analyze_exclusive_region(pc, load_word, fusion_policy, boundary, &mut read)? {
                ExclusiveRegionAnalysis::Candidate {
                    instructions: region_instructions,
                    exit: region_exit,
                    biased_scratch,
                } => {
                    let disposition = match fusion_policy {
                        ExclusiveFusionPolicy::Direct => {
                            Some(ExclusiveFusionDisposition::FusedDirect)
                        }
                        ExclusiveFusionPolicy::BiasedEnabled if biased_scratch.is_some() => {
                            Some(ExclusiveFusionDisposition::FusedBiased)
                        }
                        ExclusiveFusionPolicy::BiasedDisabled if biased_scratch.is_some() => None,
                        ExclusiveFusionPolicy::BiasedDisabled
                        | ExclusiveFusionPolicy::BiasedEnabled => {
                            exclusive_fusion = Some(ExclusiveFusionSite {
                                guest: pc,
                                word: load_word,
                                disposition: ExclusiveFusionDisposition::Rejected(
                                    ExclusiveFusionRejection::BiasedNoSafeScratch,
                                ),
                                biased_scratch: None,
                            });
                            None
                        }
                    };
                    if let Some(disposition) = disposition {
                        let fusion = ExclusiveFusionSite {
                            guest: pc,
                            word: load_word,
                            disposition,
                            biased_scratch,
                        };
                        if instructions.is_empty() {
                            return Ok(BlockPlan {
                                start,
                                end: region_exit.end,
                                generation,
                                instructions: region_instructions,
                                exit: PlannedExit::ExclusiveRegion {
                                    guest: pc,
                                    word: load_word,
                                    exit: region_exit,
                                    fusion,
                                },
                            });
                        }
                        return Ok(BlockPlan {
                            start,
                            end: pc,
                            generation,
                            instructions,
                            exit: PlannedExit::Continue {
                                target: pc,
                                limit: BlockLimit::ExclusiveRegionSplit,
                            },
                        });
                    }
                    if exclusive_fusion.is_none() {
                        exclusive_fusion = Some(ExclusiveFusionSite {
                            guest: pc,
                            word: load_word,
                            disposition: ExclusiveFusionDisposition::EligibleBackendDisabled,
                            biased_scratch,
                        });
                    }
                }
                ExclusiveRegionAnalysis::Rejected(rejection) => {
                    exclusive_fusion = Some(ExclusiveFusionSite {
                        guest: pc,
                        word: load_word,
                        disposition: ExclusiveFusionDisposition::Rejected(rejection),
                        biased_scratch: None,
                    });
                }
            }
        }
        let exit = match action {
            InstAction::Copy(_)
            | InstAction::Memory(_)
            | InstAction::PcRelative(_)
            | InstAction::VirtualizedX18 { .. }
            | InstAction::VirtualizedX28 { .. }
            | InstAction::VirtualizedX18X28ReadOnly { .. }
            | InstAction::VirtualizedX18WriteX28Read { .. } => {
                instructions.push(PlannedInst { guest: pc, action });
                if next == boundary {
                    Some(PlannedExit::Continue {
                        target: next,
                        limit: BlockLimit::PageBoundary,
                    })
                } else if instructions.len() == max_instructions {
                    Some(PlannedExit::Continue {
                        target: next,
                        limit: BlockLimit::InstructionLimit,
                    })
                } else {
                    None
                }
            }
            InstAction::Syscall { resume } => Some(PlannedExit::Syscall { guest: pc, resume }),
            InstAction::Sensitive(exit) => Some(PlannedExit::Sensitive {
                guest: pc,
                word,
                exit,
                fusion: exclusive_fusion,
            }),
            // `decode::classify` never returns this today -- recognising a
            // fused region needs the multi-instruction lookahead only the
            // planner (not per-instruction decode) can do, via
            // `analyze_exclusive_region`. This arm keeps `InstAction`
            // exhaustively matched even though per-instruction decode cannot
            // construct a multi-instruction region.
            InstAction::ExclusiveRegion(exit) => Some(PlannedExit::ExclusiveRegion {
                guest: pc,
                word,
                exit,
                fusion: ExclusiveFusionSite {
                    guest: pc,
                    word,
                    disposition: ExclusiveFusionDisposition::Rejected(
                        ExclusiveFusionRejection::AnalysisUnavailable,
                    ),
                    biased_scratch: None,
                },
            }),
            InstAction::Direct(exit) => Some(PlannedExit::Direct {
                guest: pc,
                word,
                exit,
            }),
            InstAction::Indirect(exit) => Some(PlannedExit::Indirect {
                guest: pc,
                word,
                exit,
            }),
            InstAction::Unsupported { word, op } => Some(PlannedExit::Unsupported {
                guest: pc,
                word,
                op,
            }),
        };
        if let Some(exit) = exit {
            return Ok(BlockPlan {
                start,
                end: next,
                generation,
                instructions,
                exit,
            });
        }
        pc = next;
    }
}

pub(super) fn plan_block(
    memory: &NativeMappedMemory,
    start: GuestVa,
    generation: CodeGeneration,
    max_instructions: usize,
) -> Result<BlockPlan, DsrError> {
    // Direct mode keeps its existing fused execution. Biased mode shares the
    // recognizer and records a scratch plan, but remains on the trap-and-emulate
    // path until the biased emitter is enabled.
    let fusion_policy = match memory.address_mode() {
        super::super::address::NativeAddressMode::Direct => ExclusiveFusionPolicy::Direct,
        super::super::address::NativeAddressMode::Biased { .. } => {
            ExclusiveFusionPolicy::BiasedDisabled
        }
    };
    plan_with_reader(
        start,
        generation,
        max_instructions,
        memory.linux_page_size,
        fusion_policy,
        |pc| {
            memory
                .read_u32(pc.raw())
                .map_err(|error| DsrError::MemoryRead {
                    pc: pc.raw(),
                    detail: error.to_string(),
                })
        },
    )
}

/// Bounded lookahead window (in instructions, load included) for exclusive-
/// region fusion. Real AArch64 CAS/RMW retry loops emitted by compilers keep
/// only a handful of instructions between the exclusive load and its
/// matching store. An unbounded forward scan at decode time would let a
/// corrupted or adversarial instruction stream turn block planning into an
/// unbounded decode loop, so this is a small, hard cap -- a decode-time-DoS
/// guard, not a tuning knob.
const EXCLUSIVE_REGION_SCAN_LIMIT: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
enum ExclusiveRegionAnalysis {
    Candidate {
        instructions: Vec<PlannedInst>,
        exit: ExclusiveRegionExit,
        biased_scratch: Option<BiasedExclusiveScratch>,
    },
    Rejected(ExclusiveFusionRejection),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExclusiveFusionPolicy {
    Direct,
    BiasedDisabled,
    BiasedEnabled,
}

fn biased_exclusive_scratch(
    instructions: &[PlannedInst],
    retry_pc: GuestVa,
    retry_word: u32,
) -> Option<BiasedExclusiveScratch> {
    let mut selected = Vec::with_capacity(2);
    for index in (9_u32..=17)
        .rev()
        .chain((0_u32..=8).rev())
        .chain([30, 29, 27])
    {
        let used = instructions.iter().any(|inst| match inst.action {
            InstAction::Copy(word) => {
                decode::copied_instruction_mentions_gpr(word, inst.guest, index).unwrap_or(true)
            }
            InstAction::Memory(MemoryAccess { word, .. }) => {
                decode::decoded_operands_mention_gpr(word, inst.guest, index)
            }
            _ => true,
        }) || decode::decoded_operands_mention_gpr(retry_word, retry_pc, index);
        if !used {
            selected.push(DsrScratchGpr::new(index)?);
        }
        if selected.len() == 2 {
            return Some(BiasedExclusiveScratch {
                address: selected[0],
                bias: selected[1],
            });
        }
    }
    None
}

/// Attempt to fuse the exclusive load at `start` (which must already be
/// known to decode to an LDXR/LDAXR-family instruction; `load_word` is that
/// decoded word) with its matching exclusive store into a single translated
/// region, via a bounded forward scan.
///
/// Returns a typed rejection unless ALL of the following hold. Direct mode
/// fuses candidates; biased mode records the result while keeping the
/// sensitive trap path until its emitter support is enabled.
///   - the load's addressing base is a plain guest GPR, not x18/x28 (those
///     are carrick's own reserved/virtualized registers, not guest-visible
///     under this DSR).
///   - a matching exclusive store -- same base register, also not x18/x28
///     -- is found within `EXCLUSIVE_REGION_SCAN_LIMIT` instructions.
///   - every instruction between the load and the store is a plain
///     data-processing op (`InstAction::Copy`), except for at most one
///     conditional branch (the CAS loop's compare-failure exit edge) whose
///     target is not the load's own PC.
///   - the store is immediately followed by exactly one conditional branch
///     targeting the load's PC (the loop's retry edge). This closes the
///     region.
///   - nothing in the region crosses the containing page boundary.
///   - nothing in the region is a syscall, another sensitive access
///     (tpidr/ctr/dczid/dc/ic, or another exclusive access), a PC-relative
///     instruction, an indirect branch, an unconditional branch, an
///     ordinary (non-exclusive) memory access, or an access that touches
///     carrick's virtualized x18/x28 registers. Beyond the CAS-loop-shape
///     checks above, these follow from the same hazard: the ARM ARM only
///     guarantees forward progress for an exclusive pair that contains no
///     other explicit memory access, and ordinary loads/stores, x18/x28
///     virtualization spills, and PC-relative literal loads are all memory
///     accesses.
///
/// Decode and read failures remain errors for direct execution. Biased
/// measurement converts them to `AnalysisUnavailable` so the existing
/// sensitive fallback stays usable.
fn analyze_exclusive_region(
    start: GuestVa,
    load_word: u32,
    policy: ExclusiveFusionPolicy,
    boundary: GuestVa,
    mut read: impl FnMut(GuestVa) -> Result<u32, DsrError>,
) -> Result<ExclusiveRegionAnalysis, DsrError> {
    let analysis = (|| -> Result<ExclusiveRegionAnalysis, DsrError> {
        let Some((decode::ExclusiveKind::Load, load_memory)) =
            decode::classify_exclusive(load_word, start)?
        else {
            return Ok(ExclusiveRegionAnalysis::Rejected(
                ExclusiveFusionRejection::NotLoad,
            ));
        };
        if matches!(
            load_memory.base,
            MemoryBase::VirtualX18 | MemoryBase::VirtualX28
        ) {
            return Ok(ExclusiveRegionAnalysis::Rejected(
                ExclusiveFusionRejection::VirtualizedBase,
            ));
        }
        // The load's transfer register must not be x18/x28 either. native16k keeps
        // the guest's x18/x28 in a spill slot (physical x18/x28 are carrick's own
        // reserved registers), so emitting the exclusive verbatim would read/write
        // the wrong register. The base is already excluded above; this covers the
        // data register. When it is virtualized, keep the trap path -- the emulator
        // reads the spill slots correctly.
        if decode::decoded_operands_mention_x18(load_word, start)
            || decode::decoded_operands_mention_x28(load_word, start)
        {
            return Ok(ExclusiveRegionAnalysis::Rejected(
                ExclusiveFusionRejection::VirtualizedOperand,
            ));
        }

        let load_shape = decode::exclusive_shape(load_memory.op);
        let mut instructions = vec![PlannedInst {
            guest: start,
            action: InstAction::Memory(load_memory),
        }];
        let mut scratch_instructions = instructions.clone();
        let mut pc = checked_next(start)?;
        let mut found_exit_branch = false;
        let mut early_exit_word: Option<u32> = None;
        let mut store: Option<(GuestVa, u32)> = None;

        for _ in 1..EXCLUSIVE_REGION_SCAN_LIMIT {
            if pc == boundary {
                return Ok(ExclusiveRegionAnalysis::Rejected(
                    ExclusiveFusionRejection::PageBoundary,
                ));
            }
            let word = read(pc)?;
            if let Some((kind, memory)) = decode::classify_exclusive(word, pc)? {
                // The store must match the load's base register (checked
                // below) AND its access width/family: a byte-width load can
                // only pair with a byte-width store, and a pair-form load
                // (LDXP/LDAXP) only with a pair-form store (STXP/STLXP).
                // `MemoryClass::Exclusive` collapses all 16 exclusive
                // load/store opcodes into one class, so without this the base
                // check alone would accept e.g. `ldaxr w0,[x1]` fused with a
                // same-base `stxrb`, or a single-register load fused with a
                // pair-form store -- both would emit width/family-inconsistent
                // native code once a later task lowers this fusion. If either
                // op's shape can't be determined, `zip` makes this `None`,
                // i.e. not matching: conservative is correct.
                let shape_matches = load_shape
                    .zip(decode::exclusive_shape(memory.op))
                    .is_some_and(|(load, store)| load == store);
                // bad64 collapses the W- and X-form single-register exclusives onto
                // one `Op`/shape, so `ldxr w`+`stxr x` share a shape. Re-derive the
                // exact access width from the raw size field (bits [31:30]) and
                // require an exact match on top of the shape check; a width- or
                // sign-mismatched pair must NOT fuse -- verbatim native emission of
                // such a pair would tear the guest's atomic.
                let width_matches = (load_word >> 30) == (word >> 30);
                // The store's transfer/status registers must likewise avoid x18/x28
                // (see the load check above).
                let store_uses_reserved = decode::decoded_operands_mention_x18(word, pc)
                    || decode::decoded_operands_mention_x28(word, pc);
                if store_uses_reserved {
                    return Ok(ExclusiveRegionAnalysis::Rejected(
                        ExclusiveFusionRejection::VirtualizedOperand,
                    ));
                }
                let is_matching_store = kind == decode::ExclusiveKind::Store
                    && memory.base == load_memory.base
                    && !matches!(memory.base, MemoryBase::VirtualX18 | MemoryBase::VirtualX28)
                    && shape_matches
                    && width_matches;
                if !is_matching_store {
                    // Another exclusive access (a second load, or a store to a
                    // different address) inside the region: not the canonical
                    // shape. Fall back to the trap path.
                    return Ok(ExclusiveRegionAnalysis::Rejected(
                        ExclusiveFusionRejection::MismatchedStore,
                    ));
                }
                let store_instruction = PlannedInst {
                    guest: pc,
                    action: InstAction::Memory(memory),
                };
                instructions.push(store_instruction);
                scratch_instructions.push(store_instruction);
                store = Some((pc, word));
                break;
            }
            let action = decode::classify(word, pc)?;
            match action {
                InstAction::Copy(_) => {
                    let instruction = PlannedInst { guest: pc, action };
                    instructions.push(instruction);
                    scratch_instructions.push(instruction);
                }
                InstAction::Direct(exit) => {
                    if decode::decoded_operands_mention_x18(word, pc)
                        || decode::decoded_operands_mention_x28(word, pc)
                    {
                        return Ok(ExclusiveRegionAnalysis::Rejected(
                            ExclusiveFusionRejection::VirtualizedOperand,
                        ));
                    }
                    if found_exit_branch
                        || exit.target == start
                        || matches!(exit.kind, DirectKind::Branch | DirectKind::Call)
                    {
                        return Ok(ExclusiveRegionAnalysis::Rejected(
                            ExclusiveFusionRejection::UnsupportedControlFlow,
                        ));
                    }
                    found_exit_branch = true;
                    // The raw word is dropped from `InstAction::Direct`; capture it
                    // so the emitter can re-encode the early-exit edge verbatim.
                    early_exit_word = Some(word);
                    instructions.push(PlannedInst { guest: pc, action });
                    // `InstAction::Direct` drops its encoding. Preserve the
                    // same decoded word in the scratch-only view so register
                    // selection can still account for branch operands.
                    scratch_instructions.push(PlannedInst {
                        guest: pc,
                        action: InstAction::Copy(word),
                    });
                }
                // Everything else (an ordinary memory access, a PC-relative
                // instruction, an indirect branch, a syscall, another sensitive
                // access, or an x18/x28-virtualized instruction) either leaves
                // the region's control flow in an unrecognised shape or is
                // itself a memory access that would break the exclusive pair's
                // forward-progress guarantee. Fall back to the trap path.
                InstAction::Memory(_)
                | InstAction::Sensitive(_)
                | InstAction::Syscall { .. }
                | InstAction::VirtualizedX18 { .. }
                | InstAction::VirtualizedX28 { .. }
                | InstAction::VirtualizedX18X28ReadOnly { .. }
                | InstAction::VirtualizedX18WriteX28Read { .. } => {
                    return Ok(ExclusiveRegionAnalysis::Rejected(
                        ExclusiveFusionRejection::UnsupportedBodyMemoryOrSensitive,
                    ));
                }
                InstAction::PcRelative(_)
                | InstAction::Indirect(_)
                | InstAction::ExclusiveRegion(_)
                | InstAction::Unsupported { .. } => {
                    return Ok(ExclusiveRegionAnalysis::Rejected(
                        ExclusiveFusionRejection::UnsupportedControlFlow,
                    ));
                }
            }
            pc = checked_next(pc)?;
        }

        let Some((store_pc, store_word)) = store else {
            return Ok(ExclusiveRegionAnalysis::Rejected(
                ExclusiveFusionRejection::ScanLimitOrNoStore,
            ));
        };
        let retry_pc = checked_next(store_pc)?;
        if retry_pc == boundary {
            return Ok(ExclusiveRegionAnalysis::Rejected(
                ExclusiveFusionRejection::PageBoundary,
            ));
        }
        let retry_word = read(retry_pc)?;
        if decode::classify_exclusive(retry_word, retry_pc)?.is_some() {
            return Ok(ExclusiveRegionAnalysis::Rejected(
                ExclusiveFusionRejection::InvalidRetryEdge,
            ));
        }
        let InstAction::Direct(retry_exit) = decode::classify(retry_word, retry_pc)? else {
            return Ok(ExclusiveRegionAnalysis::Rejected(
                ExclusiveFusionRejection::InvalidRetryEdge,
            ));
        };
        if decode::decoded_operands_mention_x18(retry_word, retry_pc)
            || decode::decoded_operands_mention_x28(retry_word, retry_pc)
        {
            return Ok(ExclusiveRegionAnalysis::Rejected(
                ExclusiveFusionRejection::VirtualizedOperand,
            ));
        }
        if retry_exit.target != start
            || matches!(retry_exit.kind, DirectKind::Branch | DirectKind::Call)
        {
            return Ok(ExclusiveRegionAnalysis::Rejected(
                ExclusiveFusionRejection::InvalidRetryEdge,
            ));
        }

        let end = checked_next(retry_pc)?;
        let biased_scratch = biased_exclusive_scratch(&scratch_instructions, retry_pc, retry_word);
        Ok(ExclusiveRegionAnalysis::Candidate {
            instructions,
            exit: ExclusiveRegionExit {
                start,
                end,
                retry_edge: start,
                load_word,
                store_word,
                retry_word,
                early_exit_word,
                fallback: SensitiveExit {
                    kind: SensitiveKind::Exclusive(load_word),
                    register: None,
                    resume: checked_next(start)?,
                },
            },
            biased_scratch,
        })
    })();
    match (policy, analysis) {
        (ExclusiveFusionPolicy::Direct, result) => result,
        (_, Ok(result)) => Ok(result),
        (_, Err(_)) => Ok(ExclusiveRegionAnalysis::Rejected(
            ExclusiveFusionRejection::AnalysisUnavailable,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_words(
        words: &[u32],
        start: GuestVa,
        page_size: u64,
        max_instructions: usize,
    ) -> (BlockPlan, usize) {
        let mut reads = 0;
        let plan = plan_with_reader(
            start,
            CodeGeneration::INITIAL,
            max_instructions,
            page_size,
            ExclusiveFusionPolicy::BiasedDisabled,
            |pc| {
                reads += 1;
                let offset = usize::try_from((pc.raw() - start.raw()) / 4)
                    .map_err(|_| DsrError::BlockPolicy("test offset overflow".to_string()))?;
                words
                    .get(offset)
                    .copied()
                    .ok_or_else(|| DsrError::MemoryRead {
                        pc: pc.raw(),
                        detail: "test region exhausted".to_string(),
                    })
            },
        )
        .expect("plan test block");
        (plan, reads)
    }

    #[test]
    fn dsr_block_stops_before_early_syscall() {
        let start = GuestVa(0x4000);
        let (plan, reads) = plan_words(&[0xd503_201f, 0xd400_0001, 0xd400_0001], start, 0x1000, 16);
        assert_eq!(reads, 2);
        assert_eq!(plan.instructions.len(), 1);
        assert_eq!(plan.instructions[0].guest, start);
        assert_eq!(plan.end, GuestVa(0x4008));
        assert!(matches!(
            plan.exit,
            PlannedExit::Syscall {
                guest: GuestVa(0x4004),
                resume: GuestVa(0x4008)
            }
        ));
    }

    #[test]
    fn dsr_block_does_not_decode_constant_pool_after_branch() {
        let start = GuestVa(0x5000);
        let data_equal_to_svc = 0xd400_0001;
        let words = [0xd503_201f, 0x1400_0002, data_equal_to_svc];
        let (plan, reads) = plan_words(&words, start, 0x1000, 16);
        assert_eq!(reads, 2);
        assert_eq!(plan.instructions.len(), 1);
        assert!(matches!(plan.exit, PlannedExit::Direct { .. }));
        assert_eq!(words[2], data_equal_to_svc);
    }

    #[test]
    fn dsr_block_stops_at_page_boundary() {
        let start = GuestVa(0x5ffc);
        let (plan, reads) = plan_words(&[0xd503_201f, 0xd400_0001], start, 0x1000, 16);
        assert_eq!(reads, 1);
        assert_eq!(plan.instructions.len(), 1);
        assert!(matches!(
            plan.exit,
            PlannedExit::Continue {
                target: GuestVa(0x6000),
                limit: BlockLimit::PageBoundary
            }
        ));
    }

    #[test]
    fn dsr_block_stops_at_configured_instruction_limit() {
        let start = GuestVa(0x7000);
        let (plan, reads) = plan_words(&[0xd503_201f, 0xd503_201f], start, 0x1000, 1);
        assert_eq!(reads, 1);
        assert!(matches!(
            plan.exit,
            PlannedExit::Continue {
                limit: BlockLimit::InstructionLimit,
                ..
            }
        ));
    }

    #[test]
    fn dsr_block_retains_memory_actions_in_the_instruction_stream() {
        let start = GuestVa(0x8000);
        let (plan, reads) = plan_words(&[0xf940_0020], start, 0x1000, 1);
        assert_eq!(reads, 1);
        assert!(matches!(
            plan.instructions.as_slice(),
            [PlannedInst {
                action: InstAction::Memory(_),
                ..
            }]
        ));
        assert!(matches!(
            plan.exit,
            PlannedExit::Continue {
                limit: BlockLimit::InstructionLimit,
                ..
            }
        ));
    }

    #[test]
    fn dsr_block_retains_unsupported_virtualized_memory_actions() {
        let start = GuestVa(0x9000);
        let (plan, reads) = plan_words(&[0xa452_48af], start, 0x1000, 1);
        assert_eq!(reads, 1);
        assert!(matches!(
            plan.instructions.as_slice(),
            [PlannedInst {
                action: InstAction::Memory(memory),
                ..
            }] if memory.class == super::super::types::MemoryClass::Unsupported
                && memory.virtualization
                    == super::super::types::MemoryVirtualization::X18
        ));
    }

    mod exclusive_region_fusion {
        use super::*;

        // ldaxr w0, [x1]
        const LDAXR_W0_X1: u32 = 0x885f_fc20;
        // cmp w0, w2
        const CMP_W0_W2: u32 = 0x6b02_001f;
        // stlxr w3, w4, [x1]
        const STLXR_W3_W4_X1: u32 = 0x8803_fc24;
        // stxrb w3, w4, [x1] -- SAME base register as LDAXR_W0_X1, but a
        // BYTE-width store (a width mismatch against the word-width load).
        // Verified against bad64-sys's own encoding corpus
        // (disassembler/test_cases.txt: "STXRB_SR32_ldstexclr
        // size=00|001000|o2=0|L=0|o1=0|Rs=xxxxx|o0=0|Rt2=(1)(1)(1)(1)(1)|Rn=xxxxx|Rt=xxxxx",
        // cross-checked bit-for-bit against its `08007439 stxrb w0, w25,
        // [x1]` fixture).
        const STXRB_W3_W4_X1: u32 = 0x0803_7c24;
        // stxp w3, w4, w5, [x1] -- SAME base register as LDAXR_W0_X1, but the
        // PAIR-form store family (a family mismatch against the
        // single-register load). Verified the same way against
        // "STXP_SP32_ldstexclp 1|sz=x|001000|o2=0|L=0|o1=1|Rs=xxxxx|o0=0|Rt2=xxxxx|Rn=xxxxx|Rt=xxxxx"
        // and its `88201069 stxp w0, w9, w4, [x3]` fixture.
        const STXP_W3_W4_W5_X1: u32 = 0x8823_1424;
        // svc #0
        const SVC0: u32 = 0xd400_0001;
        // mrs x0, tpidr_el0
        const MRS_TPIDR: u32 = 0xd53b_d040;
        // chkfeat x16 -- explicitly accepted by the DSR decoder because bad64
        // predates FEAT_CHK and cannot decode this fixed encoding.
        const CHKFEAT_X16: u32 = 0xd503_251f;
        // Pointer-authentication HINT aliases with architecturally implicit
        // GPRs. bad64 decodes these ops but reports no explicit operands.
        const AUTIA1716: u32 = 0xd503_219f;
        const PACIASP: u32 = 0xd503_233f;
        const XPACLRI: u32 = 0xd503_20ff;
        // Pointer-authenticated indirect control flow. These words were
        // assembled with GNU binutils 2.45 for `.arch armv8.3-a`.
        const BLRAA_X16_X11: u32 = 0xd73f_0a0b;
        const BLRAAZ_X16: u32 = 0xd63f_0a1f;
        const BLRAB_X16_X11: u32 = 0xd73f_0e0b;
        const BLRABZ_X16: u32 = 0xd63f_0e1f;
        const BRAA_X16_X11: u32 = 0xd71f_0a0b;
        const BRAAZ_X16: u32 = 0xd61f_0a1f;
        const BRAB_X16_X11: u32 = 0xd71f_0e0b;
        const BRABZ_X16: u32 = 0xd61f_0e1f;
        const RETAA: u32 = 0xd65f_0bff;
        const RETAB: u32 = 0xd65f_0fff;
        const ERETAA: u32 = 0xd69f_0bff;
        const ERETAB: u32 = 0xd69f_0fff;
        // ldr x0, [x1] -- an ordinary (non-exclusive) memory access.
        const LDR_X0_X1: u32 = 0xf940_0020;
        const COND_NE: u32 = 1;

        /// Encode `b.<cond> target` at `pc`. Verified against the real
        /// `b.ne` word cited by the exclusive-access diagnosis
        /// (`.superpowers/sdd/exclusive-diagnosis.md`): encoding a
        /// compare-failure branch 3 instructions ahead with `cond=NE`
        /// reproduces its exact `0x54000061`.
        fn encode_b_cond(pc: GuestVa, target: GuestVa, cond: u32) -> u32 {
            let offset = (target.raw() as i64 - pc.raw() as i64) / 4;
            let imm19 = (offset as u32) & 0x7_ffff;
            0x5400_0000 | (imm19 << 5) | cond
        }

        /// Encode `cbnz w<rt>, target` at `pc`. Verified the same way: a
        /// retry branch 4 instructions back with `rt=3` reproduces the
        /// diagnosis's exact `0x35ffff83`.
        fn encode_cbnz_w(pc: GuestVa, target: GuestVa, rt: u32) -> u32 {
            let offset = (target.raw() as i64 - pc.raw() as i64) / 4;
            let imm19 = (offset as u32) & 0x7_ffff;
            0x3500_0000 | (imm19 << 5) | rt
        }

        fn encode_cmp_w(left: u32, right: u32) -> u32 {
            0x6b00_001f | (right << 16) | (left << 5)
        }

        /// Replace the encoded base register (bits [9:5], uniform across the
        /// LDXR/STXR/LDAXR/STLXR single-register family) of an exclusive
        /// access word.
        fn with_base_register(word: u32, index: u32) -> u32 {
            (word & !(0x1f << 5)) | (index << 5)
        }

        fn exclusive_region_words(
            words: &[u32],
            start: GuestVa,
            load_word: u32,
            policy: ExclusiveFusionPolicy,
            page_size: u64,
        ) -> Result<ExclusiveRegionAnalysis, DsrError> {
            let boundary = page_end(start, page_size)?;
            analyze_exclusive_region(start, load_word, policy, boundary, |pc| {
                let offset = usize::try_from((pc.raw() - start.raw()) / 4)
                    .map_err(|_| DsrError::BlockPolicy("test offset overflow".to_string()))?;
                words
                    .get(offset)
                    .copied()
                    .ok_or_else(|| DsrError::MemoryRead {
                        pc: pc.raw(),
                        detail: "test region exhausted".to_string(),
                    })
            })
        }

        /// The canonical shape from the diagnosis:
        /// `ldaxr/cmp/b.ne/stlxr/cbnz`. This is the positive case: it must
        /// plan as ONE block whose instruction list contains the load, the
        /// compare, the branch, and the store -- not a zero-instruction
        /// sensitive exit.
        #[test]
        fn fuses_a_cas_retry_loop_into_one_block() {
            let start = GuestVa(0x4000);
            let branch_pc = GuestVa(0x4008);
            let retry_pc = GuestVa(0x4010);
            let out_pc = GuestVa(0x4014);
            let words = [
                LDAXR_W0_X1,
                CMP_W0_W2,
                encode_b_cond(branch_pc, out_pc, COND_NE),
                STLXR_W3_W4_X1,
                encode_cbnz_w(retry_pc, start, 3),
                SVC0,
            ];
            assert_eq!(words[2], 0x5400_0061, "b.ne encoding matches the diagnosis");
            assert_eq!(words[4], 0x35ff_ff83, "cbnz encoding matches the diagnosis");

            let analysis = exclusive_region_words(
                &words,
                start,
                LDAXR_W0_X1,
                ExclusiveFusionPolicy::Direct,
                0x1000,
            )
            .expect("scan must not error");
            let ExclusiveRegionAnalysis::Candidate {
                instructions,
                exit,
                biased_scratch,
            } = analysis
            else {
                panic!("canonical CAS loop must be a candidate: {analysis:?}");
            };

            assert_eq!(exit.start, start);
            assert_eq!(exit.end, out_pc);
            assert_eq!(instructions.len(), 4, "load, compare, branch, store");
            assert!(biased_scratch.is_some());
            assert!(matches!(
                instructions[0],
                PlannedInst {
                    guest: GuestVa(0x4000),
                    action: InstAction::Memory(memory),
                } if memory.class == super::super::super::types::MemoryClass::Exclusive
            ));
            assert!(matches!(
                instructions[1],
                PlannedInst {
                    guest: GuestVa(0x4004),
                    action: InstAction::Copy(CMP_W0_W2),
                }
            ));
            assert!(matches!(
                instructions[2],
                PlannedInst {
                    guest: GuestVa(0x4008),
                    action: InstAction::Direct(_),
                }
            ));
            assert!(matches!(
                instructions[3],
                PlannedInst {
                    guest: GuestVa(0x400c),
                    action: InstAction::Memory(memory),
                } if memory.class == super::super::super::types::MemoryClass::Exclusive
            ));
            assert_eq!(exit.retry_edge, start);
            assert_eq!(exit.load_word, LDAXR_W0_X1);
            assert_eq!(exit.store_word, STLXR_W3_W4_X1);
            assert_eq!(
                exit.fallback,
                SensitiveExit {
                    kind: SensitiveKind::Exclusive(LDAXR_W0_X1),
                    register: None,
                    resume: GuestVa(0x4004),
                }
            );
        }

        #[test]
        fn biased_analysis_returns_the_structural_candidate() {
            let start = GuestVa(0x4000);
            let words = [
                LDAXR_W0_X1,
                CMP_W0_W2,
                STLXR_W3_W4_X1,
                encode_cbnz_w(GuestVa(0x400c), start, 3),
            ];
            let analysis = exclusive_region_words(
                &words,
                start,
                LDAXR_W0_X1,
                ExclusiveFusionPolicy::BiasedDisabled,
                0x1000,
            )
            .expect("scan must not error");
            assert!(matches!(
                analysis,
                ExclusiveRegionAnalysis::Candidate {
                    biased_scratch: Some(_),
                    ..
                }
            ));
        }

        #[test]
        fn direct_analysis_preserves_reader_errors() {
            let start = GuestVa(0x4000);
            let boundary = page_end(start, 0x1000).expect("page boundary");
            let analysis = analyze_exclusive_region(
                start,
                LDAXR_W0_X1,
                ExclusiveFusionPolicy::Direct,
                boundary,
                |pc| {
                    Err(DsrError::MemoryRead {
                        pc: pc.raw(),
                        detail: "injected read failure".to_string(),
                    })
                },
            );
            assert!(matches!(
                analysis,
                Err(DsrError::MemoryRead { pc: 0x4004, .. })
            ));
        }

        #[test]
        fn biased_analysis_types_reader_errors_as_unavailable() {
            let start = GuestVa(0x4000);
            let boundary = page_end(start, 0x1000).expect("page boundary");
            let analysis = analyze_exclusive_region(
                start,
                LDAXR_W0_X1,
                ExclusiveFusionPolicy::BiasedDisabled,
                boundary,
                |pc| {
                    Err(DsrError::MemoryRead {
                        pc: pc.raw(),
                        detail: "injected read failure".to_string(),
                    })
                },
            )
            .expect("biased measurement must preserve the sensitive fallback");
            assert_eq!(
                analysis,
                ExclusiveRegionAnalysis::Rejected(ExclusiveFusionRejection::AnalysisUnavailable)
            );
        }

        #[test]
        fn falls_back_when_no_matching_store_is_found_in_the_scan_window() {
            let start = GuestVa(0x4000);
            let mut words = vec![LDAXR_W0_X1];
            words.extend(std::iter::repeat_n(
                CMP_W0_W2,
                EXCLUSIVE_REGION_SCAN_LIMIT + 4,
            ));
            let analysis = exclusive_region_words(
                &words,
                start,
                LDAXR_W0_X1,
                ExclusiveFusionPolicy::Direct,
                0x1_0000,
            )
            .expect("scan must not error");
            assert_eq!(
                analysis,
                ExclusiveRegionAnalysis::Rejected(ExclusiveFusionRejection::ScanLimitOrNoStore)
            );
        }

        #[test]
        fn falls_back_when_the_region_crosses_a_page_boundary() {
            let start = GuestVa(0x4ff8);
            let words = [
                LDAXR_W0_X1,
                STLXR_W3_W4_X1,
                encode_cbnz_w(GuestVa(0x5000), start, 3),
            ];
            let analysis = exclusive_region_words(
                &words,
                start,
                LDAXR_W0_X1,
                ExclusiveFusionPolicy::Direct,
                0x1000,
            )
            .expect("scan must not error");
            assert_eq!(
                analysis,
                ExclusiveRegionAnalysis::Rejected(ExclusiveFusionRejection::PageBoundary)
            );
        }

        #[test]
        fn falls_back_on_unsupported_control_flow_inside_the_region() {
            let start = GuestVa(0x4000);
            let words = [
                LDAXR_W0_X1,
                0x1400_0001,
                STLXR_W3_W4_X1,
                encode_cbnz_w(GuestVa(0x400c), start, 3),
            ];
            let analysis = exclusive_region_words(
                &words,
                start,
                LDAXR_W0_X1,
                ExclusiveFusionPolicy::Direct,
                0x1000,
            )
            .expect("scan must not error");
            assert_eq!(
                analysis,
                ExclusiveRegionAnalysis::Rejected(ExclusiveFusionRejection::UnsupportedControlFlow)
            );
        }

        #[test]
        fn falls_back_on_a_syscall_inside_the_region() {
            let start = GuestVa(0x4000);
            let words = [
                LDAXR_W0_X1,
                SVC0,
                STLXR_W3_W4_X1,
                encode_cbnz_w(GuestVa(0x400c), start, 3),
            ];
            let analysis = exclusive_region_words(
                &words,
                start,
                LDAXR_W0_X1,
                ExclusiveFusionPolicy::Direct,
                0x1000,
            )
            .expect("scan must not error");
            assert_eq!(
                analysis,
                ExclusiveRegionAnalysis::Rejected(
                    ExclusiveFusionRejection::UnsupportedBodyMemoryOrSensitive
                )
            );
        }

        #[test]
        fn falls_back_on_another_sensitive_op_inside_the_region() {
            let start = GuestVa(0x4000);
            let words = [
                LDAXR_W0_X1,
                MRS_TPIDR,
                STLXR_W3_W4_X1,
                encode_cbnz_w(GuestVa(0x400c), start, 3),
            ];
            let analysis = exclusive_region_words(
                &words,
                start,
                LDAXR_W0_X1,
                ExclusiveFusionPolicy::Direct,
                0x1000,
            )
            .expect("scan must not error");
            assert_eq!(
                analysis,
                ExclusiveRegionAnalysis::Rejected(
                    ExclusiveFusionRejection::UnsupportedBodyMemoryOrSensitive
                )
            );
        }

        #[test]
        fn falls_back_on_another_exclusive_load_inside_the_region() {
            let start = GuestVa(0x4000);
            let words = [
                LDAXR_W0_X1,
                LDAXR_W0_X1,
                STLXR_W3_W4_X1,
                encode_cbnz_w(GuestVa(0x400c), start, 3),
            ];
            let analysis = exclusive_region_words(
                &words,
                start,
                LDAXR_W0_X1,
                ExclusiveFusionPolicy::Direct,
                0x1000,
            )
            .expect("scan must not error");
            assert_eq!(
                analysis,
                ExclusiveRegionAnalysis::Rejected(ExclusiveFusionRejection::MismatchedStore)
            );
        }

        #[test]
        fn falls_back_on_an_ordinary_memory_access_inside_the_region() {
            let start = GuestVa(0x4000);
            let words = [
                LDAXR_W0_X1,
                LDR_X0_X1,
                STLXR_W3_W4_X1,
                encode_cbnz_w(GuestVa(0x400c), start, 3),
            ];
            let analysis = exclusive_region_words(
                &words,
                start,
                LDAXR_W0_X1,
                ExclusiveFusionPolicy::Direct,
                0x1000,
            )
            .expect("scan must not error");
            assert_eq!(
                analysis,
                ExclusiveRegionAnalysis::Rejected(
                    ExclusiveFusionRejection::UnsupportedBodyMemoryOrSensitive
                )
            );
        }

        #[test]
        fn falls_back_when_the_trailing_branch_is_not_the_retry_edge() {
            let start = GuestVa(0x4000);
            let branch_pc = GuestVa(0x4008);
            let retry_pc = GuestVa(0x4010);
            let out_pc = GuestVa(0x4014);
            let wrong_target = GuestVa(0x9000);
            let words = [
                LDAXR_W0_X1,
                CMP_W0_W2,
                encode_b_cond(branch_pc, out_pc, COND_NE),
                STLXR_W3_W4_X1,
                // A branch out of the region that is not the recognised
                // retry edge (it does not target the load's PC).
                encode_cbnz_w(retry_pc, wrong_target, 3),
                SVC0,
            ];
            let analysis = exclusive_region_words(
                &words,
                start,
                LDAXR_W0_X1,
                ExclusiveFusionPolicy::Direct,
                0x1000,
            )
            .expect("scan must not error");
            assert_eq!(
                analysis,
                ExclusiveRegionAnalysis::Rejected(ExclusiveFusionRejection::InvalidRetryEdge)
            );
        }

        #[test]
        fn falls_back_for_an_x18_based_load_address() {
            let start = GuestVa(0x4000);
            let load_word = with_base_register(LDAXR_W0_X1, 18);
            let store_word = with_base_register(STLXR_W3_W4_X1, 18);
            let words = [
                load_word,
                CMP_W0_W2,
                store_word,
                encode_cbnz_w(GuestVa(0x400c), start, 3),
            ];
            let analysis = exclusive_region_words(
                &words,
                start,
                load_word,
                ExclusiveFusionPolicy::Direct,
                0x1000,
            )
            .expect("scan must not error");
            assert_eq!(
                analysis,
                ExclusiveRegionAnalysis::Rejected(ExclusiveFusionRejection::VirtualizedBase)
            );
        }

        #[test]
        fn falls_back_for_an_x28_based_load_address() {
            let start = GuestVa(0x4000);
            let load_word = with_base_register(LDAXR_W0_X1, 28);
            let store_word = with_base_register(STLXR_W3_W4_X1, 28);
            let words = [
                load_word,
                CMP_W0_W2,
                store_word,
                encode_cbnz_w(GuestVa(0x400c), start, 3),
            ];
            let analysis = exclusive_region_words(
                &words,
                start,
                load_word,
                ExclusiveFusionPolicy::Direct,
                0x1000,
            )
            .expect("scan must not error");
            assert_eq!(
                analysis,
                ExclusiveRegionAnalysis::Rejected(ExclusiveFusionRejection::VirtualizedBase)
            );
        }

        /// The false-fusible class this closes: a single-register exclusive
        /// load (`ldaxr w0, [x1]`) paired with a same-base store of a
        /// DIFFERENT access width (`stxrb w3, w4, [x1]`). Before requiring
        /// width agreement, `is_matching_store` only compared `kind` and
        /// `base`, so this wrongly fused.
        #[test]
        fn falls_back_on_a_width_mismatched_store_inside_the_region() {
            let start = GuestVa(0x4000);
            let words = [
                LDAXR_W0_X1,
                STXRB_W3_W4_X1,
                encode_cbnz_w(GuestVa(0x4008), start, 3),
            ];
            let analysis = exclusive_region_words(
                &words,
                start,
                LDAXR_W0_X1,
                ExclusiveFusionPolicy::Direct,
                0x1000,
            )
            .expect("scan must not error");
            assert_eq!(
                analysis,
                ExclusiveRegionAnalysis::Rejected(ExclusiveFusionRejection::MismatchedStore)
            );
        }

        /// The other false-fusible class this closes: a single-register
        /// exclusive load paired with a same-base PAIR-form store (`stxp w3,
        /// w4, w5, [x1]`). Before requiring family agreement, a pair-form
        /// store passed the old `kind == Store && base == load_base` check
        /// just like a single-register one would.
        #[test]
        fn falls_back_on_a_pair_form_store_inside_the_region() {
            let start = GuestVa(0x4000);
            let words = [
                LDAXR_W0_X1,
                STXP_W3_W4_W5_X1,
                encode_cbnz_w(GuestVa(0x4008), start, 3),
            ];
            let analysis = exclusive_region_words(
                &words,
                start,
                LDAXR_W0_X1,
                ExclusiveFusionPolicy::Direct,
                0x1000,
            )
            .expect("scan must not error");
            assert_eq!(
                analysis,
                ExclusiveRegionAnalysis::Rejected(ExclusiveFusionRejection::MismatchedStore)
            );
        }

        /// Minor: a store to a genuinely different (non-x18/x28) base
        /// register than the load must still not fuse -- the pre-existing
        /// base-register check, left intact by adding the width/family
        /// check above.
        #[test]
        fn falls_back_for_a_store_to_a_different_base_register() {
            let start = GuestVa(0x4000);
            let store_word = with_base_register(STLXR_W3_W4_X1, 2);
            let words = [
                LDAXR_W0_X1,
                store_word,
                encode_cbnz_w(GuestVa(0x4008), start, 3),
            ];
            let analysis = exclusive_region_words(
                &words,
                start,
                LDAXR_W0_X1,
                ExclusiveFusionPolicy::Direct,
                0x1000,
            )
            .expect("scan must not error");
            assert_eq!(
                analysis,
                ExclusiveRegionAnalysis::Rejected(ExclusiveFusionRejection::MismatchedStore)
            );
        }

        /// Replace the encoded transfer register (Rt, bits [4:0]) of a
        /// single-register exclusive access word.
        fn with_data_register(word: u32, index: u32) -> u32 {
            (word & !0x1f) | index
        }

        /// The width gate the reviewer flagged: bad64 collapses the W- and
        /// X-form single-register exclusives onto one `Op`/shape, so
        /// `ldaxr w0,[x1]` (32-bit) and a same-base `stlxr x3,x4,[x1]` (64-bit)
        /// share a shape and base -- only re-deriving the raw size field
        /// (bits [31:30]) rejects the pairing. A verbatim native emission of
        /// such a mismatched pair would tear the guest atomic, so it must NOT
        /// fuse.
        #[test]
        fn falls_back_on_a_word_load_with_a_doubleword_store() {
            let start = GuestVa(0x4000);
            // stlxr x3, x4, [x1] -- 64-bit form (size bits [31:30] = 0b11),
            // versus the word-width (0b10) load. Same Op/shape and base as
            // STLXR_W3_W4_X1.
            let stlxr_x3_x4_x1 = STLXR_W3_W4_X1 | 0x4000_0000;
            assert_eq!(stlxr_x3_x4_x1, 0xc803_fc24);
            let words = [
                LDAXR_W0_X1,
                stlxr_x3_x4_x1,
                encode_cbnz_w(GuestVa(0x4008), start, 3),
            ];
            let analysis = exclusive_region_words(
                &words,
                start,
                LDAXR_W0_X1,
                ExclusiveFusionPolicy::Direct,
                0x1000,
            )
            .expect("scan must not error");
            assert_eq!(
                analysis,
                ExclusiveRegionAnalysis::Rejected(ExclusiveFusionRejection::MismatchedStore)
            );
        }

        /// The load's transfer register must not be x18/x28: native16k keeps the
        /// guest's x18/x28 in a spill slot, so a verbatim `ldaxr w18,[x1]` would
        /// clobber carrick's reserved physical x18. Keep the trap path.
        #[test]
        fn falls_back_when_the_load_targets_a_reserved_register() {
            let start = GuestVa(0x4000);
            let load_word = with_data_register(LDAXR_W0_X1, 18);
            let words = [
                load_word,
                STLXR_W3_W4_X1,
                encode_cbnz_w(GuestVa(0x4008), start, 3),
            ];
            let analysis = exclusive_region_words(
                &words,
                start,
                load_word,
                ExclusiveFusionPolicy::Direct,
                0x1000,
            )
            .expect("scan must not error");
            assert_eq!(
                analysis,
                ExclusiveRegionAnalysis::Rejected(ExclusiveFusionRejection::VirtualizedOperand)
            );
        }

        /// The store's data/status registers must likewise avoid x18/x28.
        #[test]
        fn falls_back_when_the_store_uses_a_reserved_register() {
            let start = GuestVa(0x4000);
            let store_word = with_data_register(STLXR_W3_W4_X1, 28);
            let words = [
                LDAXR_W0_X1,
                store_word,
                encode_cbnz_w(GuestVa(0x4008), start, 3),
            ];
            let analysis = exclusive_region_words(
                &words,
                start,
                LDAXR_W0_X1,
                ExclusiveFusionPolicy::Direct,
                0x1000,
            )
            .expect("scan must not error");
            assert_eq!(
                analysis,
                ExclusiveRegionAnalysis::Rejected(ExclusiveFusionRejection::VirtualizedOperand)
            );
        }

        /// A retry branch testing x18/x28 would need a native spill to evaluate
        /// (a memory access in the reservation window), so it must not fuse.
        #[test]
        fn falls_back_when_the_retry_branch_uses_a_reserved_register() {
            let start = GuestVa(0x4000);
            // cbnz w18, top -- the retry branch tests carrick's reserved x18.
            let retry = encode_cbnz_w(GuestVa(0x4008), start, 18);
            let words = [LDAXR_W0_X1, STLXR_W3_W4_X1, retry];
            let analysis = exclusive_region_words(
                &words,
                start,
                LDAXR_W0_X1,
                ExclusiveFusionPolicy::Direct,
                0x1000,
            )
            .expect("scan must not error");
            assert_eq!(
                analysis,
                ExclusiveRegionAnalysis::Rejected(ExclusiveFusionRejection::VirtualizedOperand)
            );
        }

        /// Plan the block via the PRODUCTION planner (`plan_with_reader`), the
        /// exact path `plan_block` drives, to exercise the wiring: a block that
        /// starts at a fusible exclusive load produces an `ExclusiveRegion`
        /// exit, not a zero-instruction `Sensitive` one.
        fn plan_via_production(
            words: &[u32],
            start: GuestVa,
            policy: ExclusiveFusionPolicy,
            page_size: u64,
        ) -> BlockPlan {
            plan_with_reader(
                start,
                CodeGeneration::INITIAL,
                256,
                page_size,
                policy,
                |pc| {
                    let offset = usize::try_from((pc.raw() - start.raw()) / 4)
                        .map_err(|_| DsrError::BlockPolicy("test offset overflow".to_string()))?;
                    words
                        .get(offset)
                        .copied()
                        .ok_or_else(|| DsrError::MemoryRead {
                            pc: pc.raw(),
                            detail: "test region exhausted".to_string(),
                        })
                },
            )
            .expect("plan production block")
        }

        fn canonical_cas(start: GuestVa) -> [u32; 6] {
            let branch_pc = GuestVa(start.raw() + 8);
            let retry_pc = GuestVa(start.raw() + 16);
            let out_pc = GuestVa(start.raw() + 20);
            [
                LDAXR_W0_X1,
                CMP_W0_W2,
                encode_b_cond(branch_pc, out_pc, COND_NE),
                STLXR_W3_W4_X1,
                encode_cbnz_w(retry_pc, start, 3),
                SVC0,
            ]
        }

        #[test]
        fn production_planner_fuses_a_leading_exclusive_region_when_allowed() {
            let start = GuestVa(0x4000);
            let plan = plan_via_production(
                &canonical_cas(start),
                start,
                ExclusiveFusionPolicy::Direct,
                0x1000,
            );
            match plan.exit {
                PlannedExit::ExclusiveRegion {
                    guest,
                    exit,
                    fusion,
                    ..
                } => {
                    assert_eq!(guest, start);
                    assert_eq!(fusion.disposition, ExclusiveFusionDisposition::FusedDirect);
                    assert_eq!(exit.start, start);
                    assert_eq!(exit.end, GuestVa(0x4014));
                    assert_eq!(exit.store_word, STLXR_W3_W4_X1);
                    assert_eq!(exit.retry_word, encode_cbnz_w(GuestVa(0x4010), start, 3));
                    assert_eq!(
                        exit.early_exit_word,
                        Some(encode_b_cond(GuestVa(0x4008), GuestVa(0x4014), COND_NE))
                    );
                }
                other => panic!("expected fused ExclusiveRegion, got {other:?}"),
            }
        }

        #[test]
        fn production_planner_keeps_the_trap_path_when_fusion_is_disallowed() {
            let start = GuestVa(0x4000);
            // Biased (linux4k) mode records fusion analysis but leaves the
            // exclusive load as a zero-instruction Sensitive exit.
            let plan = plan_via_production(
                &canonical_cas(start),
                start,
                ExclusiveFusionPolicy::BiasedDisabled,
                0x1000,
            );
            assert!(plan.instructions.is_empty());
            assert!(matches!(
                plan.exit,
                PlannedExit::Sensitive {
                    guest: GuestVa(0x4000),
                    fusion: Some(_),
                    ..
                }
            ));
        }

        #[test]
        fn biased_planner_reports_canonical_region_as_eligible_but_disabled() {
            let start = GuestVa(0x4000);
            let plan = plan_via_production(
                &canonical_cas(start),
                start,
                ExclusiveFusionPolicy::BiasedDisabled,
                0x1000,
            );
            assert!(plan.instructions.is_empty());
            assert!(matches!(
                plan.exit,
                PlannedExit::Sensitive {
                    fusion: Some(ExclusiveFusionSite {
                        disposition: ExclusiveFusionDisposition::EligibleBackendDisabled,
                        biased_scratch: Some(_),
                        ..
                    }),
                    ..
                }
            ));
        }

        #[test]
        fn biased_scratch_accounts_for_explicitly_modeled_chkfeat_x16() {
            let start = GuestVa(0x4000);
            let retry_pc = GuestVa(0x400c);
            let words = [
                LDAXR_W0_X1,
                CHKFEAT_X16,
                STLXR_W3_W4_X1,
                encode_cbnz_w(retry_pc, start, 3),
            ];
            let plan =
                plan_via_production(&words, start, ExclusiveFusionPolicy::BiasedDisabled, 0x1000);
            let PlannedExit::Sensitive {
                fusion:
                    Some(ExclusiveFusionSite {
                        disposition: ExclusiveFusionDisposition::EligibleBackendDisabled,
                        biased_scratch: Some(scratch),
                        ..
                    }),
                ..
            } = plan.exit
            else {
                panic!("expected an eligible biased fallback, got {:?}", plan.exit);
            };
            assert_eq!(scratch.address.index(), 17);
            assert_eq!(scratch.bias.index(), 15, "x16 is an operand of chkfeat");
        }

        fn assert_implicit_copy_fails_closed(word: u32) {
            let decoded = bad64::decode(word, 0x4004).expect("decode implicit-register copy");
            assert!(
                decoded.operands().is_empty(),
                "test requires an incomplete bad64 operand model: {decoded:?}"
            );

            let start = GuestVa(0x4000);
            let words = [
                LDAXR_W0_X1,
                word,
                STLXR_W3_W4_X1,
                encode_cbnz_w(GuestVa(0x400c), start, 3),
            ];
            let biased =
                plan_via_production(&words, start, ExclusiveFusionPolicy::BiasedDisabled, 0x1000);
            assert!(matches!(
                biased.exit,
                PlannedExit::Sensitive {
                    fusion: Some(ExclusiveFusionSite {
                        disposition: ExclusiveFusionDisposition::Rejected(
                            ExclusiveFusionRejection::BiasedNoSafeScratch
                        ),
                        biased_scratch: None,
                        ..
                    }),
                    ..
                }
            ));

            let direct = plan_via_production(&words, start, ExclusiveFusionPolicy::Direct, 0x1000);
            assert!(matches!(
                direct.exit,
                PlannedExit::ExclusiveRegion {
                    fusion: ExclusiveFusionSite {
                        disposition: ExclusiveFusionDisposition::FusedDirect,
                        ..
                    },
                    ..
                }
            ));
        }

        #[test]
        fn biased_scratch_fails_closed_for_autia1716_implicit_pair() {
            assert_implicit_copy_fails_closed(AUTIA1716);
        }

        #[test]
        fn biased_scratch_fails_closed_for_implicit_lr_copies() {
            for word in [PACIASP, XPACLRI] {
                assert_implicit_copy_fails_closed(word);
            }
        }

        fn assert_authenticated_control_flow_rejected(word: u32) {
            let start = GuestVa(0x4000);
            let words = [
                LDAXR_W0_X1,
                word,
                STLXR_W3_W4_X1,
                encode_cbnz_w(GuestVa(0x400c), start, 3),
            ];
            let analysis = exclusive_region_words(
                &words,
                start,
                LDAXR_W0_X1,
                ExclusiveFusionPolicy::Direct,
                0x1000,
            )
            .expect("scan authenticated control flow");
            assert_eq!(
                analysis,
                ExclusiveRegionAnalysis::Rejected(ExclusiveFusionRejection::UnsupportedControlFlow),
                "word=0x{word:08x}"
            );
        }

        #[test]
        fn blraa_is_rejected_as_unsupported_control_flow() {
            assert_authenticated_control_flow_rejected(BLRAA_X16_X11);
        }

        #[test]
        fn authenticated_branch_call_and_return_families_are_control_flow() {
            for word in [
                BLRAAZ_X16,
                BLRAB_X16_X11,
                BLRABZ_X16,
                BRAA_X16_X11,
                BRAAZ_X16,
                BRAB_X16_X11,
                BRABZ_X16,
                RETAA,
                RETAB,
                ERETAA,
                ERETAB,
            ] {
                assert_authenticated_control_flow_rejected(word);
            }
        }

        #[test]
        fn exclusive_store_is_a_typed_non_entry_site() {
            let start = GuestVa(0x4000);
            let words = [STLXR_W3_W4_X1, SVC0];
            let plan =
                plan_via_production(&words, start, ExclusiveFusionPolicy::BiasedDisabled, 0x1000);
            assert!(matches!(
                plan.exit,
                PlannedExit::Sensitive {
                    fusion: Some(ExclusiveFusionSite {
                        disposition: ExclusiveFusionDisposition::Rejected(
                            ExclusiveFusionRejection::NotLoad
                        ),
                        ..
                    }),
                    ..
                }
            ));
        }

        #[test]
        fn biased_planner_rejects_a_register_saturated_candidate() {
            let start = GuestVa(0x4000);
            let scratch_order = [
                17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 30, 29, 27,
            ];
            let mut words = vec![LDAXR_W0_X1];
            words.extend(
                scratch_order
                    .chunks(2)
                    .map(|pair| encode_cmp_w(pair[0], pair.get(1).copied().unwrap_or(pair[0]))),
            );
            words.push(STLXR_W3_W4_X1);
            let retry_pc = GuestVa(start.raw() + words.len() as u64 * 4);
            words.push(encode_cbnz_w(retry_pc, start, 3));

            let biased =
                plan_via_production(&words, start, ExclusiveFusionPolicy::BiasedDisabled, 0x1000);
            assert!(matches!(
                biased.exit,
                PlannedExit::Sensitive {
                    fusion: Some(ExclusiveFusionSite {
                        disposition: ExclusiveFusionDisposition::Rejected(
                            ExclusiveFusionRejection::BiasedNoSafeScratch
                        ),
                        biased_scratch: None,
                        ..
                    }),
                    ..
                }
            ));

            let direct = plan_via_production(&words, start, ExclusiveFusionPolicy::Direct, 0x1000);
            assert!(matches!(
                direct.exit,
                PlannedExit::ExclusiveRegion {
                    fusion: ExclusiveFusionSite {
                        disposition: ExclusiveFusionDisposition::FusedDirect,
                        biased_scratch: None,
                        ..
                    },
                    ..
                }
            ));
        }

        #[test]
        fn scratch_register_rejects_sp() {
            assert_eq!(DsrScratchGpr::new(30).map(DsrScratchGpr::index), Some(30));
            assert_eq!(DsrScratchGpr::new(31), None);
        }

        #[test]
        fn production_planner_splits_before_a_mid_block_fusible_load() {
            let start = GuestVa(0x4000);
            let load_pc = GuestVa(0x4004);
            // A NOP precedes the CAS loop, so the exclusive load is NOT the
            // block's first instruction (this is the common shape: compilers
            // load the CAS operands before the exclusive load). The block must
            // END just before the load with a Continue, so the load starts a
            // fresh, fusible block.
            let nop = 0xd503_201f;
            let mut words = vec![nop];
            words.extend_from_slice(&canonical_cas(load_pc));
            let plan = plan_via_production(&words, start, ExclusiveFusionPolicy::Direct, 0x1000);
            assert_eq!(plan.instructions.len(), 1, "only the leading NOP");
            assert!(matches!(
                plan.exit,
                PlannedExit::Continue {
                    target: GuestVa(0x4004),
                    limit: BlockLimit::ExclusiveRegionSplit,
                }
            ));

            // Translating from the load PC (the split target) now fuses, because
            // the load is the block's first instruction.
            let load_plan = plan_via_production(
                &canonical_cas(load_pc),
                load_pc,
                ExclusiveFusionPolicy::Direct,
                0x1000,
            );
            assert!(matches!(
                load_plan.exit,
                PlannedExit::ExclusiveRegion {
                    guest: GuestVa(0x4004),
                    ..
                }
            ));
        }

        #[test]
        fn production_planner_does_not_split_before_a_non_fusible_mid_block_load() {
            let start = GuestVa(0x4000);
            // A NOP, then an exclusive load whose store is width-mismatched
            // (not fusible). The load must stay a Sensitive (trap) exit -- no
            // split -- so the non-fused trap path is unchanged.
            let nop = 0xd503_201f;
            let load = LDAXR_W0_X1;
            let bad_store = STLXR_W3_W4_X1 | 0x4000_0000; // 64-bit store vs 32-bit load
            let words = [
                nop,
                load,
                bad_store,
                encode_cbnz_w(GuestVa(0x400c), GuestVa(0x4004), 3),
            ];
            let plan = plan_via_production(&words, start, ExclusiveFusionPolicy::Direct, 0x1000);
            assert!(matches!(
                plan.exit,
                PlannedExit::Sensitive {
                    guest: GuestVa(0x4004),
                    ..
                }
            ));
        }
    }
}
