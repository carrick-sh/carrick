#![allow(dead_code)] // Block publication is wired into DSR execution in Task 5.

use carrick_guest_mem::GuestVa;

use super::super::NativeMappedMemory;
use super::decode;
use super::types::{CodeGeneration, DirectExit, DsrError, IndirectExit, InstAction, SensitiveExit};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PlannedInst {
    pub(super) guest: GuestVa,
    pub(super) action: InstAction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BlockLimit {
    PageBoundary,
    InstructionLimit,
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
}

impl PlannedExit {
    pub(super) const fn guest_pc(self) -> GuestVa {
        match self {
            Self::Continue { target, .. } => target,
            Self::Syscall { guest, .. }
            | Self::Sensitive { guest, .. }
            | Self::Direct { guest, .. }
            | Self::Indirect { guest, .. }
            | Self::Unsupported { guest, .. } => guest,
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
        let exit = match action {
            InstAction::Copy(_) | InstAction::PcRelative(_) => {
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
    plan_with_reader(
        start,
        generation,
        max_instructions,
        memory.linux_page_size,
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
}
