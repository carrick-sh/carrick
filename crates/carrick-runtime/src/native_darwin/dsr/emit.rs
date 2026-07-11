#![allow(dead_code)] // Emitted blocks enter the context gateway in Task 5.

use std::collections::BTreeMap;

use carrick_guest_mem::GuestVa;
use dynasmrt::{DynasmApi, VecAssembler, aarch64::Aarch64Relocation};

use super::block::{BlockPlan, PlannedExit};
use super::cache::{PublishedCode, TranslationCache};
use super::types::{CacheOffset, CacheVa, DsrError, InstAction};

const BRK_DSR_CONTINUE: u32 = 0xd43a_0020;
const BRK_DSR_SYSCALL: u32 = 0xd43a_0040;
const BRK_DSR_SENSITIVE: u32 = 0xd43a_0060;
const BRK_DSR_UNSUPPORTED: u32 = 0xd43a_0080;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PcMapEntry {
    pub(super) guest: GuestVa,
    pub(super) cache: CacheOffset,
}

#[derive(Debug)]
pub(super) struct InstructionMap {
    entries: Vec<PcMapEntry>,
    forward: BTreeMap<GuestVa, CacheOffset>,
    inverse: BTreeMap<CacheOffset, GuestVa>,
}

impl InstructionMap {
    fn new(entries: Vec<PcMapEntry>) -> Result<Self, DsrError> {
        let mut forward = BTreeMap::new();
        let mut inverse = BTreeMap::new();
        for entry in &entries {
            if forward.insert(entry.guest, entry.cache).is_some() {
                return Err(DsrError::CachePolicy(format!(
                    "duplicate guest PC in DSR instruction map: 0x{:x}",
                    entry.guest.raw()
                )));
            }
            if inverse.insert(entry.cache, entry.guest).is_some() {
                return Err(DsrError::CachePolicy(format!(
                    "duplicate cache offset in DSR instruction map: {}",
                    entry.cache.get()
                )));
            }
        }
        Ok(Self {
            entries,
            forward,
            inverse,
        })
    }

    pub(super) fn entries(&self) -> &[PcMapEntry] {
        &self.entries
    }

    pub(super) fn cache_for_guest(&self, guest: GuestVa) -> Option<CacheOffset> {
        self.forward.get(&guest).copied()
    }

    pub(super) fn guest_for_cache(&self, cache: CacheOffset) -> Option<GuestVa> {
        self.inverse.get(&cache).copied()
    }
}

pub(super) struct EmittedBlock {
    code: PublishedCode,
    map: InstructionMap,
}

impl EmittedBlock {
    pub(super) const fn entry(&self) -> CacheVa {
        self.code.entry()
    }

    pub(super) const fn len(&self) -> usize {
        self.code.len()
    }

    pub(super) const fn map(&self) -> &InstructionMap {
        &self.map
    }
}

fn unsupported_action(
    plan: &BlockPlan,
    guest_pc: GuestVa,
    word: u32,
    class: &'static str,
) -> DsrError {
    let op = bad64::decode(word, guest_pc.raw())
        .map(|instruction| instruction.op())
        .unwrap_or(bad64::Op::UDF);
    DsrError::UnsupportedBlockAction {
        block_start: plan.start.raw(),
        generation: plan.generation.get(),
        guest_pc: guest_pc.raw(),
        word,
        op,
        class,
    }
}

fn exit_word(plan: &BlockPlan) -> Result<u32, DsrError> {
    match plan.exit {
        PlannedExit::Continue { .. } => Ok(BRK_DSR_CONTINUE),
        PlannedExit::Syscall { .. } => Ok(BRK_DSR_SYSCALL),
        PlannedExit::Sensitive { .. } => Ok(BRK_DSR_SENSITIVE),
        PlannedExit::Unsupported { .. } => Ok(BRK_DSR_UNSUPPORTED),
        PlannedExit::Direct { guest, word, .. } => {
            Err(unsupported_action(plan, guest, word, "direct exit"))
        }
        PlannedExit::Indirect { guest, word, .. } => {
            Err(unsupported_action(plan, guest, word, "indirect exit"))
        }
    }
}

pub(super) fn emit_block(
    cache: &mut TranslationCache,
    plan: &BlockPlan,
) -> Result<EmittedBlock, DsrError> {
    let mut assembler = VecAssembler::<Aarch64Relocation>::new(0);
    let mut entries = Vec::with_capacity(plan.instructions.len() + 1);
    for instruction in &plan.instructions {
        let word = match instruction.action {
            InstAction::Copy(word) => word,
            InstAction::PcRelative(relative) => {
                return Err(unsupported_action(
                    plan,
                    instruction.guest,
                    relative.word,
                    "PC-relative instruction",
                ));
            }
            InstAction::Direct(_) => {
                return Err(unsupported_action(
                    plan,
                    instruction.guest,
                    0,
                    "direct action",
                ));
            }
            InstAction::Indirect(_) => {
                return Err(unsupported_action(
                    plan,
                    instruction.guest,
                    0,
                    "indirect action",
                ));
            }
            InstAction::Syscall { .. }
            | InstAction::Sensitive(_)
            | InstAction::Unsupported { .. } => {
                return Err(DsrError::BlockPolicy(format!(
                    "terminator appeared in DSR copy stream at guest PC 0x{:x}",
                    instruction.guest.raw()
                )));
            }
        };
        let offset = u32::try_from(assembler.offset().0)
            .map_err(|_| DsrError::CachePolicy("emitted block exceeds u32 offsets".to_string()))?;
        entries.push(PcMapEntry {
            guest: instruction.guest,
            cache: CacheOffset::published(offset),
        });
        assembler.push_u32(word);
    }

    let exit_offset = u32::try_from(assembler.offset().0)
        .map_err(|_| DsrError::CachePolicy("emitted block exceeds u32 offsets".to_string()))?;
    entries.push(PcMapEntry {
        guest: plan.exit.guest_pc(),
        cache: CacheOffset::published(exit_offset),
    });
    assembler.push_u32(exit_word(plan)?);
    let bytes = assembler
        .finalize()
        .map_err(|error| DsrError::Assembler(error.to_string()))?;
    if !bytes.len().is_multiple_of(4) {
        return Err(DsrError::CachePolicy(format!(
            "dynasm emitted a non-instruction byte count: {}",
            bytes.len()
        )));
    }
    let words = bytes
        .chunks_exact(4)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .collect::<Vec<_>>();
    let map = InstructionMap::new(entries)?;
    let mut writer = cache.begin_write(bytes.len())?;
    writer.write_words(&words)?;
    let code = writer.publish()?;
    Ok(EmittedBlock { code, map })
}

#[cfg(test)]
mod tests {
    use super::super::block::{BlockLimit, PlannedInst};
    use super::super::types::{
        CodeGeneration, DirectExit, DirectKind, IndirectExit, IndirectKind, PcRelativeInst,
        PcRelativeKind,
    };
    use super::*;

    fn copy_plan() -> BlockPlan {
        BlockPlan {
            start: GuestVa(0x4000),
            end: GuestVa(0x400c),
            generation: CodeGeneration::INITIAL,
            instructions: vec![
                PlannedInst {
                    guest: GuestVa(0x4000),
                    action: InstAction::Copy(0xd503_201f),
                },
                PlannedInst {
                    guest: GuestVa(0x4004),
                    action: InstAction::Copy(0x9100_0400),
                },
            ],
            exit: PlannedExit::Syscall {
                guest: GuestVa(0x4008),
                resume: GuestVa(0x400c),
            },
        }
    }

    #[test]
    fn dsr_emit_copy_only_block_decodes_back_with_exact_maps() {
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate translation cache");
        let emitted = emit_block(&mut cache, &copy_plan()).expect("emit copy-only block");
        assert_eq!(emitted.len(), 12);
        let original_words = [0xd503_201f, 0x9100_0400];
        let expected_ops = [bad64::Op::NOP, bad64::Op::ADD, bad64::Op::BRK];
        for (index, expected_op) in expected_ops.into_iter().enumerate() {
            let offset = index * 4;
            let pointer = (emitted.entry().host().raw() + offset) as *const u32;
            let word = unsafe { std::ptr::read_unaligned(pointer) };
            let decoded = bad64::decode(word, emitted.entry().host().raw() as u64 + offset as u64)
                .expect("decode emitted instruction");
            assert_eq!(decoded.op(), expected_op);
            if let Some(original_word) = original_words.get(index) {
                let original = bad64::decode(*original_word, 0x4000 + offset as u64)
                    .expect("decode original instruction");
                assert_eq!(decoded.operands(), original.operands());
            }
        }

        let expected_guests = [GuestVa(0x4000), GuestVa(0x4004), GuestVa(0x4008)];
        assert_eq!(emitted.map().entries().len(), expected_guests.len());
        for (index, guest) in expected_guests.into_iter().enumerate() {
            let offset = CacheOffset::published((index * 4) as u32);
            assert_eq!(
                emitted.map().entries()[index],
                PcMapEntry {
                    guest,
                    cache: offset
                }
            );
            assert_eq!(emitted.map().cache_for_guest(guest), Some(offset));
            assert_eq!(emitted.map().guest_for_cache(offset), Some(guest));
            assert_eq!(emitted.map().entries()[index].cache.get() % 4, 0);
        }
    }

    #[test]
    fn dsr_emit_rejects_pc_relative_copy_subset() {
        let mut plan = copy_plan();
        plan.instructions[0].action = InstAction::PcRelative(PcRelativeInst {
            kind: PcRelativeKind::Adr,
            target: GuestVa(0x5000),
            destination: Some(bad64::Reg::X0),
            word: 0x1000_8000,
        });
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate translation cache");
        let error = match emit_block(&mut cache, &plan) {
            Ok(_) => panic!("PC-relative instruction should not emit in Task 4"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            DsrError::UnsupportedBlockAction {
                class: "PC-relative instruction",
                ..
            }
        ));
    }

    #[test]
    fn dsr_emit_rejects_direct_and_indirect_exits() {
        let cases = [
            (
                PlannedExit::Direct {
                    guest: GuestVa(0x4008),
                    word: 0x1400_0002,
                    exit: DirectExit {
                        kind: DirectKind::Branch,
                        target: GuestVa(0x4010),
                        resume: GuestVa(0x400c),
                        condition: None,
                        register: None,
                        bit: None,
                    },
                },
                "direct exit",
            ),
            (
                PlannedExit::Indirect {
                    guest: GuestVa(0x4008),
                    word: 0xd61f_0000,
                    exit: IndirectExit {
                        kind: IndirectKind::Branch,
                        register: bad64::Reg::X0,
                        resume: GuestVa(0x400c),
                    },
                },
                "indirect exit",
            ),
        ];
        for (exit, expected_class) in cases {
            let mut plan = copy_plan();
            plan.exit = exit;
            let mut cache = TranslationCache::new(16 * 1024).expect("allocate translation cache");
            let error = match emit_block(&mut cache, &plan) {
                Ok(_) => panic!("{expected_class} should not emit in Task 4"),
                Err(error) => error,
            };
            assert!(matches!(
                error,
                DsrError::UnsupportedBlockAction { class, .. } if class == expected_class
            ));
        }
    }

    #[test]
    fn dsr_emit_continue_exit_is_typed_and_decodable() {
        let mut plan = copy_plan();
        plan.instructions.truncate(1);
        plan.end = GuestVa(0x4004);
        plan.exit = PlannedExit::Continue {
            target: GuestVa(0x4004),
            limit: BlockLimit::InstructionLimit,
        };
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate translation cache");
        let emitted = emit_block(&mut cache, &plan).expect("emit bounded block");
        let exit =
            unsafe { std::ptr::read_unaligned((emitted.entry().host().raw() + 4) as *const u32) };
        assert_eq!(exit, BRK_DSR_CONTINUE);
        assert_eq!(
            emitted.map().guest_for_cache(CacheOffset::published(4)),
            Some(GuestVa(0x4004))
        );
    }
}
