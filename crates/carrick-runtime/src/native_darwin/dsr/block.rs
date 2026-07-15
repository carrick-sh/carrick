#![allow(dead_code)] // Block publication is wired into DSR execution in Task 5.

use carrick_guest_mem::GuestVa;

use super::super::NativeMappedMemory;
use super::decode;
use super::types::{
    CodeGeneration, DirectExit, DirectKind, DsrError, ExclusiveRegionExit, IndirectExit,
    InstAction, MemoryBase, SensitiveExit, SensitiveKind,
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
    },
    /// A fused exclusive region terminating the block (see
    /// `try_fuse_exclusive_region`). Not yet produced by `plan_block`
    /// (Task 1 keeps `plan_block`'s output identical to today's
    /// `PlannedExit::Sensitive` behavior); Task 2 wires this in and teaches
    /// the emitter to lower it to native code instead of a gateway trap.
    ExclusiveRegion {
        guest: GuestVa,
        word: u32,
        exit: ExclusiveRegionExit,
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
    allow_fusion: bool,
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
        // Attempt exclusive-region fusion. A fused region must be a
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
        // When the region is not provably fusible, or `allow_fusion` is off,
        // fall through to today's `Sensitive` exit unchanged
        // (`try_fuse_exclusive_region` gates every hazard and returns `None`
        // when in any doubt).
        if allow_fusion {
            if let InstAction::Sensitive(SensitiveExit {
                kind: SensitiveKind::Exclusive(load_word),
                ..
            }) = action
            {
                if let Some((region_instructions, region_exit)) =
                    try_fuse_exclusive_region(pc, load_word, allow_fusion, boundary, &mut read)?
                {
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
            }),
            // `decode::classify` never returns this today -- recognising a
            // fused region needs the multi-instruction lookahead only the
            // planner (not per-instruction decode) can do, via
            // `try_fuse_exclusive_region`. This arm exists so `InstAction`
            // stays exhaustively matched here, and so it is already correct
            // for Task 2, which wires the recogniser into this loop.
            InstAction::ExclusiveRegion(exit) => Some(PlannedExit::ExclusiveRegion {
                guest: pc,
                word,
                exit,
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
    // Exclusive-region fusion emits the load/store verbatim, which is only sound
    // in Direct (native16k) addressing. Biased (linux4k) mode needs a scratch
    // base-register spill -- itself a memory access inside the reservation
    // window -- so it keeps the trap-and-emulate path (see the emitter's
    // biased tripwire and `try_fuse_exclusive_region`).
    let allow_fusion = matches!(
        memory.address_mode(),
        super::super::address::NativeAddressMode::Direct
    );
    plan_with_reader(
        start,
        generation,
        max_instructions,
        memory.linux_page_size,
        allow_fusion,
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

/// Attempt to fuse the exclusive load at `start` (which must already be
/// known to decode to an LDXR/LDAXR-family instruction; `load_word` is that
/// decoded word) with its matching exclusive store into a single translated
/// region, via a bounded forward scan.
///
/// Returns `Ok(None)` -- "not provably fusible; the caller must produce
/// today's `PlannedExit::Sensitive` unchanged" -- unless ALL of the
/// following hold:
///   - `allow_fusion` is set. The caller must gate this on the block's
///     address mode: fusion is Direct-mode (native16k/unbiased) only.
///     Biased (linux4k) mode needs a scratch-register spill to materialize
///     the host base, and that spill is itself a memory access between the
///     exclusive pair, which would violate the forward-progress hazard
///     below -- so biased mode keeps the trap path unconditionally.
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
/// When in doubt this always returns `Ok(None)`: a missed fusion opportunity
/// costs a gateway round-trip (today's status quo, unchanged); a wrongly
/// accepted one risks a torn or livelocked guest atomic.
fn try_fuse_exclusive_region(
    start: GuestVa,
    load_word: u32,
    allow_fusion: bool,
    boundary: GuestVa,
    mut read: impl FnMut(GuestVa) -> Result<u32, DsrError>,
) -> Result<Option<(Vec<PlannedInst>, ExclusiveRegionExit)>, DsrError> {
    if !allow_fusion {
        return Ok(None);
    }
    let Some((decode::ExclusiveKind::Load, load_memory)) =
        decode::classify_exclusive(load_word, start)?
    else {
        return Ok(None);
    };
    if matches!(
        load_memory.base,
        MemoryBase::VirtualX18 | MemoryBase::VirtualX28
    ) {
        return Ok(None);
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
        return Ok(None);
    }

    let load_shape = decode::exclusive_shape(load_memory.op);
    let mut instructions = vec![PlannedInst {
        guest: start,
        action: InstAction::Memory(load_memory),
    }];
    let mut pc = checked_next(start)?;
    let mut found_exit_branch = false;
    let mut early_exit_word: Option<u32> = None;
    let mut store: Option<(GuestVa, u32)> = None;

    for _ in 1..EXCLUSIVE_REGION_SCAN_LIMIT {
        if pc == boundary {
            return Ok(None);
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
            let is_matching_store = kind == decode::ExclusiveKind::Store
                && memory.base == load_memory.base
                && !matches!(memory.base, MemoryBase::VirtualX18 | MemoryBase::VirtualX28)
                && shape_matches
                && width_matches
                && !store_uses_reserved;
            if !is_matching_store {
                // Another exclusive access (a second load, or a store to a
                // different address) inside the region: not the canonical
                // shape. Fall back to the trap path.
                return Ok(None);
            }
            instructions.push(PlannedInst {
                guest: pc,
                action: InstAction::Memory(memory),
            });
            store = Some((pc, word));
            break;
        }
        let action = decode::classify(word, pc)?;
        match action {
            InstAction::Copy(_) => {
                instructions.push(PlannedInst { guest: pc, action });
            }
            InstAction::Direct(exit) => {
                if found_exit_branch
                    || exit.target == start
                    || matches!(exit.kind, DirectKind::Branch | DirectKind::Call)
                    // A branch testing x18/x28 would need the guest register
                    // spilled into a scratch to evaluate natively -- another
                    // memory access inside the reservation window. Keep the
                    // trap path.
                    || decode::decoded_operands_mention_x18(word, pc)
                    || decode::decoded_operands_mention_x28(word, pc)
                {
                    return Ok(None);
                }
                found_exit_branch = true;
                // The raw word is dropped from `InstAction::Direct`; capture it
                // so the emitter can re-encode the early-exit edge verbatim.
                early_exit_word = Some(word);
                instructions.push(PlannedInst { guest: pc, action });
            }
            // Everything else (an ordinary memory access, a PC-relative
            // instruction, an indirect branch, a syscall, another sensitive
            // access, or an x18/x28-virtualized instruction) either leaves
            // the region's control flow in an unrecognised shape or is
            // itself a memory access that would break the exclusive pair's
            // forward-progress guarantee. Fall back to the trap path.
            _ => return Ok(None),
        }
        pc = checked_next(pc)?;
    }

    let Some((store_pc, store_word)) = store else {
        return Ok(None);
    };
    let retry_pc = checked_next(store_pc)?;
    if retry_pc == boundary {
        return Ok(None);
    }
    let retry_word = read(retry_pc)?;
    if decode::classify_exclusive(retry_word, retry_pc)?.is_some() {
        return Ok(None);
    }
    let InstAction::Direct(retry_exit) = decode::classify(retry_word, retry_pc)? else {
        return Ok(None);
    };
    if retry_exit.target != start
        || matches!(retry_exit.kind, DirectKind::Branch | DirectKind::Call)
        // As with the early-exit branch: a retry branch testing x18/x28 would
        // need a spill to evaluate natively. Keep the trap path.
        || decode::decoded_operands_mention_x18(retry_word, retry_pc)
        || decode::decoded_operands_mention_x28(retry_word, retry_pc)
    {
        return Ok(None);
    }

    let end = checked_next(retry_pc)?;
    Ok(Some((
        instructions,
        ExclusiveRegionExit {
            start,
            end,
            retry_edge: start,
            load_word,
            store_word,
            retry_word,
            early_exit_word,
        },
    )))
}

/// Plan a fused exclusive region as a single `BlockPlan`, using
/// `try_fuse_exclusive_region`'s bounded scan. This is the recogniser's
/// block-shaped entry point: Task 2 wires it into `plan_with_reader`'s
/// `InstAction::Sensitive(SensitiveExit { kind: SensitiveKind::Exclusive(word),
/// .. })` arm (guarded on the block's address mode) so a fusible region
/// becomes the real `plan_block` output instead of falling through to
/// `PlannedExit::Sensitive`. It is not wired in yet: `plan_block` above is
/// unchanged, so guest behavior is unchanged by this task -- see this
/// module's tests for the recogniser exercised directly.
fn plan_exclusive_region_with_reader(
    start: GuestVa,
    generation: CodeGeneration,
    load_word: u32,
    allow_fusion: bool,
    page_size: u64,
    read: impl FnMut(GuestVa) -> Result<u32, DsrError>,
) -> Result<Option<BlockPlan>, DsrError> {
    let boundary = page_end(start, page_size)?;
    let Some((instructions, exit)) =
        try_fuse_exclusive_region(start, load_word, allow_fusion, boundary, read)?
    else {
        return Ok(None);
    };
    Ok(Some(BlockPlan {
        start,
        end: exit.end,
        generation,
        instructions,
        exit: PlannedExit::ExclusiveRegion {
            guest: start,
            word: load_word,
            exit,
        },
    }))
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
            false,
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
            allow_fusion: bool,
            page_size: u64,
        ) -> Result<Option<BlockPlan>, DsrError> {
            plan_exclusive_region_with_reader(
                start,
                CodeGeneration::INITIAL,
                load_word,
                allow_fusion,
                page_size,
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

            let plan = exclusive_region_words(&words, start, LDAXR_W0_X1, true, 0x1000)
                .expect("scan must not error")
                .expect("canonical CAS loop must fuse");

            assert_eq!(plan.start, start);
            assert_eq!(plan.end, out_pc);
            assert_eq!(plan.instructions.len(), 4, "load, compare, branch, store");
            assert!(matches!(
                plan.instructions[0],
                PlannedInst {
                    guest: GuestVa(0x4000),
                    action: InstAction::Memory(memory),
                } if memory.class == super::super::super::types::MemoryClass::Exclusive
            ));
            assert!(matches!(
                plan.instructions[1],
                PlannedInst {
                    guest: GuestVa(0x4004),
                    action: InstAction::Copy(CMP_W0_W2),
                }
            ));
            assert!(matches!(
                plan.instructions[2],
                PlannedInst {
                    guest: GuestVa(0x4008),
                    action: InstAction::Direct(_),
                }
            ));
            assert!(matches!(
                plan.instructions[3],
                PlannedInst {
                    guest: GuestVa(0x400c),
                    action: InstAction::Memory(memory),
                } if memory.class == super::super::super::types::MemoryClass::Exclusive
            ));
            match plan.exit {
                PlannedExit::ExclusiveRegion { guest, word, exit } => {
                    assert_eq!(guest, start);
                    assert_eq!(word, LDAXR_W0_X1);
                    assert_eq!(exit.start, start);
                    assert_eq!(exit.end, out_pc);
                    assert_eq!(exit.retry_edge, start);
                    assert_eq!(exit.load_word, LDAXR_W0_X1);
                    assert_eq!(exit.store_word, STLXR_W3_W4_X1);
                }
                other => panic!("expected ExclusiveRegion exit, got {other:?}"),
            }
        }

        #[test]
        fn falls_back_when_fusion_is_not_allowed_in_this_address_mode() {
            let start = GuestVa(0x4000);
            let words = [
                LDAXR_W0_X1,
                CMP_W0_W2,
                STLXR_W3_W4_X1,
                encode_cbnz_w(GuestVa(0x400c), start, 3),
            ];
            let plan = exclusive_region_words(&words, start, LDAXR_W0_X1, false, 0x1000)
                .expect("scan must not error");
            assert!(plan.is_none());
        }

        #[test]
        fn falls_back_when_no_matching_store_is_found_in_the_scan_window() {
            let start = GuestVa(0x4000);
            let mut words = vec![LDAXR_W0_X1];
            words.extend(std::iter::repeat_n(
                CMP_W0_W2,
                EXCLUSIVE_REGION_SCAN_LIMIT + 4,
            ));
            let plan = exclusive_region_words(&words, start, LDAXR_W0_X1, true, 0x1_0000)
                .expect("scan must not error");
            assert!(plan.is_none());
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
            let plan = exclusive_region_words(&words, start, LDAXR_W0_X1, true, 0x1000)
                .expect("scan must not error");
            assert!(plan.is_none());
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
            let plan = exclusive_region_words(&words, start, LDAXR_W0_X1, true, 0x1000)
                .expect("scan must not error");
            assert!(plan.is_none());
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
            let plan = exclusive_region_words(&words, start, LDAXR_W0_X1, true, 0x1000)
                .expect("scan must not error");
            assert!(plan.is_none());
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
            let plan = exclusive_region_words(&words, start, LDAXR_W0_X1, true, 0x1000)
                .expect("scan must not error");
            assert!(plan.is_none());
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
            let plan = exclusive_region_words(&words, start, LDAXR_W0_X1, true, 0x1000)
                .expect("scan must not error");
            assert!(plan.is_none());
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
            let plan = exclusive_region_words(&words, start, load_word, true, 0x1000)
                .expect("scan must not error");
            assert!(plan.is_none());
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
            let plan = exclusive_region_words(&words, start, load_word, true, 0x1000)
                .expect("scan must not error");
            assert!(plan.is_none());
        }

        // The next two tests assert `Option::is_none()` from the recogniser
        // directly rather than the eventual `PlannedExit::Sensitive` a real
        // block plan would fall back to: that fallback is guaranteed by
        // `decode::classify` being unmodified by this fix (`classify` still
        // unconditionally converts every `MemoryClass::Exclusive` access to
        // `InstAction::Sensitive`, independent of this recogniser, and is
        // covered by its own pre-existing tests) plus the unwired-recogniser
        // comment on `plan_block` above -- a `None` here can only ever
        // become `PlannedExit::Sensitive`, never a wrong fusion.

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
            let plan = exclusive_region_words(&words, start, LDAXR_W0_X1, true, 0x1000)
                .expect("scan must not error");
            assert!(plan.is_none());
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
            let plan = exclusive_region_words(&words, start, LDAXR_W0_X1, true, 0x1000)
                .expect("scan must not error");
            assert!(plan.is_none());
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
            let plan = exclusive_region_words(&words, start, LDAXR_W0_X1, true, 0x1000)
                .expect("scan must not error");
            assert!(plan.is_none());
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
            let plan = exclusive_region_words(&words, start, LDAXR_W0_X1, true, 0x1000)
                .expect("scan must not error");
            assert!(plan.is_none());
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
            let plan = exclusive_region_words(&words, start, load_word, true, 0x1000)
                .expect("scan must not error");
            assert!(plan.is_none());
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
            let plan = exclusive_region_words(&words, start, LDAXR_W0_X1, true, 0x1000)
                .expect("scan must not error");
            assert!(plan.is_none());
        }

        /// A retry branch testing x18/x28 would need a native spill to evaluate
        /// (a memory access in the reservation window), so it must not fuse.
        #[test]
        fn falls_back_when_the_retry_branch_uses_a_reserved_register() {
            let start = GuestVa(0x4000);
            // cbnz w18, top -- the retry branch tests carrick's reserved x18.
            let retry = encode_cbnz_w(GuestVa(0x4008), start, 18);
            let words = [LDAXR_W0_X1, STLXR_W3_W4_X1, retry];
            let plan = exclusive_region_words(&words, start, LDAXR_W0_X1, true, 0x1000)
                .expect("scan must not error");
            assert!(plan.is_none());
        }

        /// Plan the block via the PRODUCTION planner (`plan_with_reader`), the
        /// exact path `plan_block` drives, to exercise the wiring: a block that
        /// starts at a fusible exclusive load produces an `ExclusiveRegion`
        /// exit, not a zero-instruction `Sensitive` one.
        fn plan_via_production(
            words: &[u32],
            start: GuestVa,
            allow_fusion: bool,
            page_size: u64,
        ) -> BlockPlan {
            plan_with_reader(
                start,
                CodeGeneration::INITIAL,
                256,
                page_size,
                allow_fusion,
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
            let plan = plan_via_production(&canonical_cas(start), start, true, 0x1000);
            match plan.exit {
                PlannedExit::ExclusiveRegion { guest, exit, .. } => {
                    assert_eq!(guest, start);
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
            // Biased (linux4k) mode passes `allow_fusion = false`; the exclusive
            // load must remain a zero-instruction Sensitive exit (the trap path,
            // and the biased tripwire's precondition).
            let plan = plan_via_production(&canonical_cas(start), start, false, 0x1000);
            assert!(plan.instructions.is_empty());
            assert!(matches!(
                plan.exit,
                PlannedExit::Sensitive {
                    guest: GuestVa(0x4000),
                    ..
                }
            ));
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
            let plan = plan_via_production(&words, start, true, 0x1000);
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
            let load_plan = plan_via_production(&canonical_cas(load_pc), load_pc, true, 0x1000);
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
            let plan = plan_via_production(&words, start, true, 0x1000);
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
