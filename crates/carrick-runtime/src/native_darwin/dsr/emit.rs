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
            forward.entry(entry.guest).or_insert(entry.cache);
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
    direct_links: Vec<DirectLink>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DirectLink {
    pub(super) slot: CacheOffset,
    pub(super) target: GuestVa,
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

    pub(super) fn direct_links(&self) -> &[DirectLink] {
        &self.direct_links
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
        PlannedExit::VirtualizedX18 { guest, word, .. } => Err(unsupported_action(
            plan,
            guest,
            word,
            "virtualized x18 instruction",
        )),
        PlannedExit::Direct { guest, word, .. } => {
            Err(unsupported_action(plan, guest, word, "direct exit"))
        }
        PlannedExit::Indirect { guest, word, .. } => {
            Err(unsupported_action(plan, guest, word, "indirect exit"))
        }
    }
}

fn current_offset(assembler: &VecAssembler<Aarch64Relocation>) -> Result<CacheOffset, DsrError> {
    u32::try_from(assembler.offset().0)
        .map(CacheOffset::published)
        .map_err(|_| DsrError::CachePolicy("emitted block exceeds u32 offsets".to_string()))
}

fn map_next(
    assembler: &VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    guest: GuestVa,
) -> Result<(), DsrError> {
    entries.push(PcMapEntry {
        guest,
        cache: current_offset(assembler)?,
    });
    Ok(())
}

fn emit_mov_u64(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    guest: GuestVa,
    register: u32,
    value: u64,
) -> Result<(), DsrError> {
    for halfword in 0..4_u32 {
        map_next(assembler, entries, guest)?;
        let immediate = ((value >> (halfword * 16)) & 0xffff) as u32;
        let base = if halfword == 0 {
            0xd280_0000
        } else {
            0xf280_0000
        };
        assembler.push_u32(base | (halfword << 21) | (immediate << 5) | register);
    }
    Ok(())
}

fn emit_word(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    guest: GuestVa,
    word: u32,
) -> Result<(), DsrError> {
    map_next(assembler, entries, guest)?;
    assembler.push_u32(word);
    Ok(())
}

fn gpr_index(register: bad64::Reg) -> Option<u32> {
    let raw = register as u32;
    let first = bad64::Reg::X0 as u32;
    let last = bad64::Reg::X30 as u32;
    (first..=last).contains(&raw).then_some(raw - first)
}

fn emit_pc_relative_address(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    plan: &BlockPlan,
    guest: GuestVa,
    relative: super::types::PcRelativeInst,
) -> Result<(), DsrError> {
    let destination = relative.destination.ok_or_else(|| {
        unsupported_action(
            plan,
            guest,
            relative.word,
            "PC-relative instruction without destination",
        )
    })?;
    let register = gpr_index(destination).ok_or_else(|| {
        unsupported_action(
            plan,
            guest,
            relative.word,
            "PC-relative non-GPR destination",
        )
    })?;
    if register == 18 {
        map_next(assembler, entries, guest)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; str x17, [x18, #136]
        );
        emit_mov_u64(assembler, entries, guest, 17, relative.target.raw())?;
        map_next(assembler, entries, guest)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; str x17, [x18, #144]
            ; ldr x17, [x18, #136]
        );
    } else {
        emit_mov_u64(assembler, entries, guest, register, relative.target.raw())?;
    }
    Ok(())
}

fn emit_literal_with_x17_scratch(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    guest: GuestVa,
    target: GuestVa,
    memory_word: u32,
) -> Result<(), DsrError> {
    emit_word(assembler, entries, guest, 0xf900_4651)?; // str x17, [x18, #136]
    emit_mov_u64(assembler, entries, guest, 17, target.raw())?;
    emit_word(assembler, entries, guest, memory_word)?;
    emit_word(assembler, entries, guest, 0xf940_4651)?; // ldr x17, [x18, #136]
    Ok(())
}

fn emit_pc_relative_literal(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    plan: &BlockPlan,
    guest: GuestVa,
    relative: super::types::PcRelativeInst,
) -> Result<(), DsrError> {
    let opc = relative.word >> 30;
    let vector = (relative.word >> 26) & 1 != 0;
    let destination = relative.word & 0x1f;
    if relative.kind == super::types::PcRelativeKind::LiteralPrefetch {
        let word = 0xf980_0000 | (17 << 5) | destination;
        return emit_literal_with_x17_scratch(assembler, entries, guest, relative.target, word);
    }

    if vector {
        let base = match opc {
            0 => 0xbd40_0000, // ldr St, [Xn]
            1 => 0xfd40_0000, // ldr Dt, [Xn]
            2 => 0x3dc0_0000, // ldr Qt, [Xn]
            _ => {
                return Err(unsupported_action(
                    plan,
                    guest,
                    relative.word,
                    "reserved SIMD literal load",
                ));
            }
        };
        let word = base | (17 << 5) | destination;
        return emit_literal_with_x17_scratch(assembler, entries, guest, relative.target, word);
    }

    let base = match opc {
        0 => 0xb940_0000, // ldr Wt, [Xn]
        1 => 0xf940_0000, // ldr Xt, [Xn]
        2 => 0xb980_0000, // ldrsw Xt, [Xn]
        _ => {
            return Err(unsupported_action(
                plan,
                guest,
                relative.word,
                "reserved integer literal load",
            ));
        }
    };

    if destination == 18 {
        emit_word(assembler, entries, guest, 0xf900_4651)?;
        emit_mov_u64(assembler, entries, guest, 17, relative.target.raw())?;
        emit_word(assembler, entries, guest, base | (17 << 5) | 17)?;
        emit_word(assembler, entries, guest, 0xf900_4a51)?; // str x17, [x18, #144]
        emit_word(assembler, entries, guest, 0xf940_4651)?;
    } else if destination == 31 {
        emit_literal_with_x17_scratch(
            assembler,
            entries,
            guest,
            relative.target,
            base | (17 << 5) | destination,
        )?;
    } else {
        emit_mov_u64(
            assembler,
            entries,
            guest,
            destination,
            relative.target.raw(),
        )?;
        emit_word(
            assembler,
            entries,
            guest,
            base | (destination << 5) | destination,
        )?;
    }
    Ok(())
}

fn emit_gateway_exit(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    guest: GuestVa,
    target: GuestVa,
    source: Option<GuestVa>,
    status: u32,
    gateway: u64,
) -> Result<(), DsrError> {
    emit_mov_u64(assembler, entries, guest, 17, target.raw())?;
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x17, [x18, #1080]
    );
    if let Some(source) = source {
        emit_mov_u64(assembler, entries, guest, 17, source.raw())?;
        map_next(assembler, entries, guest)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; str x17, [x18, #1088]
        );
    }
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; mov w17, status
        ; str w17, [x18, #1096]
    );
    emit_mov_u64(assembler, entries, guest, 17, gateway)?;
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; br x17
    );
    Ok(())
}

fn relocated_direct_word(word: u32, exit: super::types::DirectExit) -> Result<u32, DsrError> {
    let immediate = 2_u32;
    let mut relocated = match exit.kind {
        super::types::DirectKind::Conditional | super::types::DirectKind::CompareZero { .. } => {
            (word & !0x00ff_ffe0) | (immediate << 5)
        }
        super::types::DirectKind::TestBit { .. } => (word & !0x0007_ffe0) | (immediate << 5),
        _ => {
            return Err(DsrError::BlockPolicy(format!(
                "cannot relocate non-conditional direct word 0x{word:08x}"
            )));
        }
    };
    if matches!(exit.register, Some(bad64::Reg::X18 | bad64::Reg::W18)) {
        relocated = (relocated & !0x1f) | 17;
    }
    Ok(relocated)
}

fn emit_indirect_exit(
    assembler: &mut VecAssembler<Aarch64Relocation>,
    entries: &mut Vec<PcMapEntry>,
    plan: &BlockPlan,
    guest: GuestVa,
    exit: super::types::IndirectExit,
) -> Result<(), DsrError> {
    let register = gpr_index(exit.register)
        .ok_or_else(|| unsupported_action(plan, guest, 0, "indirect exit with non-GPR target"))?;
    if register == 18 {
        map_next(assembler, entries, guest)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; ldr x17, [x18, #144]
        );
    } else if register != 17 {
        emit_word(
            assembler,
            entries,
            guest,
            0xaa00_03f1 | (register << 16), // mov x17, xN
        )?;
    }
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x17, [x18, #1080]
    );
    let link = (exit.kind == super::types::IndirectKind::Call).then_some(exit.resume);
    if let Some(link) = link {
        emit_mov_u64(assembler, entries, guest, 30, link.raw())?;
    }
    emit_mov_u64(assembler, entries, guest, 17, guest.raw())?;
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; str x17, [x18, #1088]
    );
    if let Some(link) = link {
        emit_mov_u64(assembler, entries, guest, 17, link.raw())?;
        map_next(assembler, entries, guest)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; str x17, [x18, #1104]
            ; mov w17, #1
            ; str w17, [x18, #1112]
        );
    } else {
        map_next(assembler, entries, guest)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; str wzr, [x18, #1112]
        );
    }
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; mov w17, #3
        ; str w17, [x18, #1096]
    );
    emit_mov_u64(
        assembler,
        entries,
        guest,
        17,
        super::gateway::indirect_exit_address(),
    )?;
    map_next(assembler, entries, guest)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; br x17
    );
    Ok(())
}

pub(super) fn emit_block(
    cache: &mut TranslationCache,
    plan: &BlockPlan,
) -> Result<EmittedBlock, DsrError> {
    let mut assembler = VecAssembler::<Aarch64Relocation>::new(0);
    let mut entries = Vec::with_capacity(plan.instructions.len() + 8);
    let mut direct_links = Vec::new();
    map_next(&assembler, &mut entries, plan.start)?;
    dynasmrt::dynasm!(assembler
        ; .arch aarch64
        ; ldr x17, [x18, #136]
    );
    for instruction in &plan.instructions {
        let word = match instruction.action {
            InstAction::Copy(word) => word,
            InstAction::VirtualizedX18 { word, .. } => {
                return Err(unsupported_action(
                    plan,
                    instruction.guest,
                    word,
                    "virtualized x18 instruction",
                ));
            }
            InstAction::PcRelative(relative)
                if matches!(
                    relative.kind,
                    super::types::PcRelativeKind::Adr | super::types::PcRelativeKind::Adrp
                ) =>
            {
                emit_pc_relative_address(
                    &mut assembler,
                    &mut entries,
                    plan,
                    instruction.guest,
                    relative,
                )?;
                continue;
            }
            InstAction::PcRelative(relative) => {
                emit_pc_relative_literal(
                    &mut assembler,
                    &mut entries,
                    plan,
                    instruction.guest,
                    relative,
                )?;
                continue;
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
        map_next(&assembler, &mut entries, instruction.guest)?;
        assembler.push_u32(word);
    }

    let exit_guest = plan.exit.guest_pc();
    if let PlannedExit::Syscall { resume, .. } = plan.exit {
        map_next(&assembler, &mut entries, exit_guest)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; str x17, [x18, #136]
        );
        emit_gateway_exit(
            &mut assembler,
            &mut entries,
            exit_guest,
            resume,
            None,
            1,
            super::gateway::syscall_exit_address(),
        )?;
    } else if let PlannedExit::Direct { word, exit, .. } = plan.exit {
        map_next(&assembler, &mut entries, exit_guest)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; str x17, [x18, #136]
        );
        if exit.kind == super::types::DirectKind::Call {
            emit_mov_u64(
                &mut assembler,
                &mut entries,
                exit_guest,
                30,
                exit.resume.raw(),
            )?;
        }
        if matches!(
            exit.kind,
            super::types::DirectKind::Branch | super::types::DirectKind::Call
        ) {
            let slot = current_offset(&assembler)?;
            direct_links.push(DirectLink {
                slot,
                target: exit.target,
            });
            emit_word(&mut assembler, &mut entries, exit_guest, 0x1400_0001)?;
            emit_gateway_exit(
                &mut assembler,
                &mut entries,
                exit_guest,
                exit.target,
                Some(exit_guest),
                2,
                super::gateway::direct_exit_address(),
            )?;
        } else {
            if matches!(exit.register, Some(bad64::Reg::X18 | bad64::Reg::W18)) {
                map_next(&assembler, &mut entries, exit_guest)?;
                dynasmrt::dynasm!(assembler
                    ; .arch aarch64
                    ; ldr x17, [x18, #144]
                );
            }
            emit_word(
                &mut assembler,
                &mut entries,
                exit_guest,
                relocated_direct_word(word, exit)?,
            )?;
            let fall_slot = current_offset(&assembler)?;
            direct_links.push(DirectLink {
                slot: fall_slot,
                target: exit.resume,
            });
            emit_word(&mut assembler, &mut entries, exit_guest, 0x1400_0002)?;
            let taken_slot = current_offset(&assembler)?;
            direct_links.push(DirectLink {
                slot: taken_slot,
                target: exit.target,
            });
            emit_word(&mut assembler, &mut entries, exit_guest, 0x1400_0012)?;
            emit_gateway_exit(
                &mut assembler,
                &mut entries,
                exit_guest,
                exit.resume,
                Some(exit_guest),
                2,
                super::gateway::direct_exit_address(),
            )?;
            emit_gateway_exit(
                &mut assembler,
                &mut entries,
                exit_guest,
                exit.target,
                Some(exit_guest),
                2,
                super::gateway::direct_exit_address(),
            )?;
        }
    } else if let PlannedExit::Indirect { exit, .. } = plan.exit {
        map_next(&assembler, &mut entries, exit_guest)?;
        dynasmrt::dynasm!(assembler
            ; .arch aarch64
            ; str x17, [x18, #136]
        );
        emit_indirect_exit(&mut assembler, &mut entries, plan, exit_guest, exit)?;
    } else {
        map_next(&assembler, &mut entries, exit_guest)?;
        assembler.push_u32(exit_word(plan)?);
    }
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
    Ok(EmittedBlock {
        code,
        map,
        direct_links,
    })
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
        assert_eq!(emitted.len(), 64);
        let original_words = [0xd503_201f, 0x9100_0400];
        let entry_word =
            unsafe { std::ptr::read_unaligned(emitted.entry().host().raw() as *const u32) };
        assert_eq!(
            bad64::decode(entry_word, emitted.entry().host().raw() as u64)
                .expect("decode entry restore")
                .op(),
            bad64::Op::LDR
        );
        for (index, original_word) in original_words.into_iter().enumerate() {
            let offset = (index + 1) * 4;
            let pointer = (emitted.entry().host().raw() + offset) as *const u32;
            let word = unsafe { std::ptr::read_unaligned(pointer) };
            let decoded = bad64::decode(word, emitted.entry().host().raw() as u64 + offset as u64)
                .expect("decode emitted instruction");
            let original = bad64::decode(original_word, 0x4000 + index as u64 * 4)
                .expect("decode original instruction");
            assert_eq!(decoded.op(), original.op());
            assert_eq!(decoded.operands(), original.operands());
        }

        assert_eq!(
            emitted.map().cache_for_guest(GuestVa(0x4000)),
            Some(CacheOffset::published(0))
        );
        assert_eq!(
            emitted.map().guest_for_cache(CacheOffset::published(4)),
            Some(GuestVa(0x4000))
        );
        assert_eq!(
            emitted.map().cache_for_guest(GuestVa(0x4004)),
            Some(CacheOffset::published(8))
        );
        for entry in emitted.map().entries() {
            assert_eq!(entry.cache.get() % 4, 0);
            assert_eq!(
                emitted.map().guest_for_cache(entry.cache),
                Some(entry.guest)
            );
        }
    }

    #[test]
    fn dsr_emit_relocates_pc_relative_address_subset() {
        let mut plan = copy_plan();
        plan.instructions[0].action = InstAction::PcRelative(PcRelativeInst {
            kind: PcRelativeKind::Adr,
            target: GuestVa(0x5000),
            destination: Some(bad64::Reg::X0),
            word: 0x1000_8000,
        });
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate translation cache");
        let emitted = emit_block(&mut cache, &plan).expect("emit relocated ADR");
        assert!(emitted.len() > 36);
    }

    #[test]
    fn dsr_emit_direct_link_and_indirect_resolver_exit() {
        let mut direct = copy_plan();
        direct.exit = PlannedExit::Direct {
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
        };
        let mut cache = TranslationCache::new(16 * 1024).expect("allocate translation cache");
        let emitted = emit_block(&mut cache, &direct).expect("emit direct link");
        assert_eq!(emitted.direct_links().len(), 1);
        assert_eq!(emitted.direct_links()[0].target, GuestVa(0x4010));

        let mut indirect = copy_plan();
        indirect.exit = PlannedExit::Indirect {
            guest: GuestVa(0x4008),
            word: 0xd61f_0000,
            exit: IndirectExit {
                kind: IndirectKind::Branch,
                register: bad64::Reg::X0,
                resume: GuestVa(0x400c),
            },
        };
        let emitted = emit_block(&mut cache, &indirect).expect("emit indirect resolver exit");
        assert!(emitted.direct_links().is_empty());
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
            unsafe { std::ptr::read_unaligned((emitted.entry().host().raw() + 8) as *const u32) };
        assert_eq!(exit, BRK_DSR_CONTINUE);
        assert_eq!(
            emitted.map().guest_for_cache(CacheOffset::published(8)),
            Some(GuestVa(0x4004))
        );
    }
}
