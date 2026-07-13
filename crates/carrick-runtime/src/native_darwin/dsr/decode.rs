#![allow(dead_code)] // Classification is wired into block formation in Task 4.

use bad64::{Imm, Op, Operand, Reg, SysReg};
use carrick_guest_mem::GuestVa;

use super::types::{
    DirectExit, DirectKind, DsrError, IndirectExit, IndirectKind, InstAction, MemoryAccess,
    MemoryBase, MemoryClass, MemoryVirtualization, MemoryWriteback, PcRelativeInst, PcRelativeKind,
    SensitiveExit, SensitiveKind,
};

fn resume_pc(pc: GuestVa) -> Result<GuestVa, DsrError> {
    pc.raw()
        .checked_add(4)
        .map(GuestVa)
        .ok_or(DsrError::PcOverflow { pc: pc.raw() })
}

fn immediate_value(imm: Imm) -> u64 {
    match imm {
        Imm::Signed(value) => value as u64,
        Imm::Unsigned(value) => value,
    }
}

fn label(operands: &[Operand]) -> Option<GuestVa> {
    operands.iter().find_map(|operand| match operand {
        Operand::Label(imm) => Some(GuestVa(immediate_value(*imm))),
        _ => None,
    })
}

fn first_reg(operands: &[Operand]) -> Option<Reg> {
    operands.iter().find_map(|operand| match operand {
        Operand::Reg { reg, .. } => Some(*reg),
        _ => None,
    })
}

fn condition(operands: &[Operand]) -> Option<bad64::Condition> {
    operands.iter().find_map(|operand| match operand {
        Operand::Cond(condition) => Some(*condition),
        _ => None,
    })
}

fn branch_condition(op: Op) -> Option<bad64::Condition> {
    use bad64::Condition;
    match op {
        Op::B_EQ => Some(Condition::EQ),
        Op::B_NE => Some(Condition::NE),
        Op::B_CS => Some(Condition::CS),
        Op::B_CC => Some(Condition::CC),
        Op::B_MI => Some(Condition::MI),
        Op::B_PL => Some(Condition::PL),
        Op::B_VS => Some(Condition::VS),
        Op::B_VC => Some(Condition::VC),
        Op::B_HI => Some(Condition::HI),
        Op::B_LS => Some(Condition::LS),
        Op::B_GE => Some(Condition::GE),
        Op::B_LT => Some(Condition::LT),
        Op::B_GT => Some(Condition::GT),
        Op::B_LE => Some(Condition::LE),
        Op::B_AL => Some(Condition::AL),
        Op::B_NV => Some(Condition::NV),
        _ => None,
    }
}

fn immediate_u8(operands: &[Operand]) -> Option<u8> {
    operands.iter().find_map(|operand| match operand {
        Operand::Imm32 { imm, .. } | Operand::Imm64 { imm, .. } => {
            u8::try_from(immediate_value(*imm)).ok()
        }
        _ => None,
    })
}

fn malformed(pc: GuestVa, word: u32, op: Op) -> DsrError {
    DsrError::Malformed {
        pc: pc.raw(),
        word,
        op,
    }
}

fn register_matches_gpr(register: Reg, index: u32) -> bool {
    let raw = register as u32;
    raw == bad64::Reg::X0 as u32 + index || raw == bad64::Reg::W0 as u32 + index
}

fn operand_mentions_gpr(operand: &Operand, index: u32) -> bool {
    match operand {
        Operand::ShiftReg { reg, .. }
        | Operand::QualReg { reg, .. }
        | Operand::Reg { reg, .. }
        | Operand::MemReg(reg)
        | Operand::MemOffset { reg, .. }
        | Operand::MemPreIdx { reg, .. }
        | Operand::MemPostIdxImm { reg, .. }
        | Operand::AccumArray { reg, .. } => register_matches_gpr(*reg, index),
        Operand::MultiReg { regs, .. } => regs
            .iter()
            .flatten()
            .copied()
            .any(|register| register_matches_gpr(register, index)),
        Operand::MemPostIdxReg(regs)
        | Operand::MemExt { regs, .. }
        | Operand::IndexedElement { regs, .. } => regs
            .iter()
            .copied()
            .any(|register| register_matches_gpr(register, index)),
        Operand::SmeTile { reg, .. } => reg.is_some_and(|reg| register_matches_gpr(reg, index)),
        Operand::Imm32 { .. }
        | Operand::Imm64 { .. }
        | Operand::FImm32(_)
        | Operand::SysReg(_)
        | Operand::Label(_)
        | Operand::ImplSpec { .. }
        | Operand::Cond(_)
        | Operand::Name(_)
        | Operand::StrImm { .. } => false,
    }
}

fn operand_mentions_gpr_outside_memory_base(operand: &Operand, index: u32) -> bool {
    match operand {
        Operand::MemReg(_)
        | Operand::MemOffset { .. }
        | Operand::MemPreIdx { .. }
        | Operand::MemPostIdxImm { .. } => false,
        Operand::MemPostIdxReg(regs) | Operand::MemExt { regs, .. } => {
            register_matches_gpr(regs[1], index)
        }
        _ => operand_mentions_gpr(operand, index),
    }
}

fn base_register(operands: &[Operand]) -> Option<(Reg, MemoryWriteback)> {
    operands.iter().find_map(|operand| match operand {
        Operand::MemReg(reg) | Operand::MemOffset { reg, .. } => {
            Some((*reg, MemoryWriteback::None))
        }
        Operand::MemExt { regs, .. } => Some((regs[0], MemoryWriteback::None)),
        Operand::MemPreIdx { reg, .. } => Some((*reg, MemoryWriteback::PreIndex)),
        Operand::MemPostIdxImm { reg, .. } => Some((*reg, MemoryWriteback::PostIndex)),
        Operand::MemPostIdxReg(regs) => Some((regs[0], MemoryWriteback::PostIndex)),
        _ => None,
    })
}

fn encoded_base_index(register: Reg) -> Option<u32> {
    let raw = register as u32;
    let first_x = Reg::X0 as u32;
    let last_x = Reg::X30 as u32;
    if (first_x..=last_x).contains(&raw) {
        Some(raw - first_x)
    } else if register == Reg::SP {
        Some(31)
    } else {
        None
    }
}

fn memory_base(
    pc: GuestVa,
    word: u32,
    op: Op,
    operands: &[Operand],
) -> Result<MemoryBase, DsrError> {
    if let Some(target) = label(operands) {
        return Ok(MemoryBase::Literal(target));
    }
    let (register, _) = base_register(operands).ok_or_else(|| malformed(pc, word, op))?;
    let encoded = (word >> 5) & 0x1f;
    if encoded_base_index(register) != Some(encoded) {
        return Err(malformed(pc, word, op));
    }
    if register_matches_gpr(register, 18) {
        Ok(MemoryBase::VirtualX18)
    } else if register_matches_gpr(register, 28) {
        Ok(MemoryBase::VirtualX28)
    } else {
        Ok(MemoryBase::Register(register))
    }
}

fn is_standard_simd_register(register: Reg) -> bool {
    let raw = register as u32;
    [
        (Reg::V0 as u32, Reg::V31 as u32),
        (Reg::B0 as u32, Reg::B31 as u32),
        (Reg::H0 as u32, Reg::H31 as u32),
        (Reg::S0 as u32, Reg::S31 as u32),
        (Reg::D0 as u32, Reg::D31 as u32),
        (Reg::Q0 as u32, Reg::Q31 as u32),
    ]
    .iter()
    .any(|(first, last)| (*first..=*last).contains(&raw))
}

fn has_standard_simd_transfer(operands: &[Operand]) -> bool {
    operands.iter().any(|operand| match operand {
        Operand::Reg { reg, .. } => is_standard_simd_register(*reg),
        Operand::MultiReg { regs, .. } => regs
            .iter()
            .flatten()
            .copied()
            .any(is_standard_simd_register),
        _ => false,
    })
}

fn is_scalable_or_matrix_register(register: Reg) -> bool {
    register.is_sve() || register.is_pred() || register == Reg::ZT0
}

fn has_scalable_or_matrix_shape(operands: &[Operand]) -> bool {
    operands.iter().any(|operand| match operand {
        Operand::ShiftReg { reg, .. }
        | Operand::QualReg { reg, .. }
        | Operand::Reg { reg, .. }
        | Operand::MemReg(reg) => is_scalable_or_matrix_register(*reg),
        Operand::MultiReg { regs, .. } => regs
            .iter()
            .flatten()
            .copied()
            .any(is_scalable_or_matrix_register),
        Operand::MemOffset {
            reg,
            mul_vl,
            arrspec,
            ..
        } => *mul_vl || arrspec.is_some() || is_scalable_or_matrix_register(*reg),
        Operand::MemExt { regs, arrspec, .. } => {
            arrspec.is_some() || regs.iter().copied().any(is_scalable_or_matrix_register)
        }
        Operand::MemPostIdxReg(regs) | Operand::IndexedElement { regs, .. } => {
            regs.iter().copied().any(is_scalable_or_matrix_register)
        }
        Operand::MemPreIdx { reg, .. } | Operand::MemPostIdxImm { reg, .. } => {
            is_scalable_or_matrix_register(*reg)
        }
        Operand::SmeTile { .. } | Operand::AccumArray { .. } => true,
        Operand::Imm32 { .. }
        | Operand::Imm64 { .. }
        | Operand::FImm32(_)
        | Operand::SysReg(_)
        | Operand::Label(_)
        | Operand::ImplSpec { .. }
        | Operand::Cond(_)
        | Operand::Name(_)
        | Operand::StrImm { .. } => false,
    })
}

fn memory_class(op: Op, operands: &[Operand]) -> Option<MemoryClass> {
    if has_scalable_or_matrix_shape(operands) && has_memory_operand(operands) {
        return Some(MemoryClass::Unsupported);
    }
    if label(operands).is_some() {
        return matches!(op, Op::LDR | Op::LDRSW | Op::PRFM).then_some(MemoryClass::Literal);
    }
    match op {
        Op::LDP | Op::LDNP | Op::LDPSW | Op::STP | Op::STNP => Some(MemoryClass::Pair),
        Op::LDAXP
        | Op::LDAXR
        | Op::LDAXRB
        | Op::LDAXRH
        | Op::LDXP
        | Op::LDXR
        | Op::LDXRB
        | Op::LDXRH
        | Op::STLXP
        | Op::STLXR
        | Op::STLXRB
        | Op::STLXRH
        | Op::STXP
        | Op::STXR
        | Op::STXRB
        | Op::STXRH => Some(MemoryClass::Exclusive),
        Op::CAS
        | Op::CASA
        | Op::CASAB
        | Op::CASAH
        | Op::CASAL
        | Op::CASALB
        | Op::CASALH
        | Op::CASB
        | Op::CASH
        | Op::CASL
        | Op::CASLB
        | Op::CASLH
        | Op::CASP
        | Op::CASPA
        | Op::CASPAL
        | Op::CASPL
        | Op::LDADD
        | Op::LDADDA
        | Op::LDADDAB
        | Op::LDADDAH
        | Op::LDADDAL
        | Op::LDADDALB
        | Op::LDADDALH
        | Op::LDADDB
        | Op::LDADDH
        | Op::LDADDL
        | Op::LDADDLB
        | Op::LDADDLH
        | Op::LDAR
        | Op::LDARB
        | Op::LDARH
        | Op::LDAPR
        | Op::LDAPRB
        | Op::LDAPRH
        | Op::LDCLR
        | Op::LDCLRA
        | Op::LDCLRAB
        | Op::LDCLRAH
        | Op::LDCLRAL
        | Op::LDCLRALB
        | Op::LDCLRALH
        | Op::LDCLRB
        | Op::LDCLRH
        | Op::LDCLRL
        | Op::LDCLRLB
        | Op::LDCLRLH
        | Op::LDEOR
        | Op::LDEORA
        | Op::LDEORAB
        | Op::LDEORAH
        | Op::LDEORAL
        | Op::LDEORALB
        | Op::LDEORALH
        | Op::LDEORB
        | Op::LDEORH
        | Op::LDEORL
        | Op::LDEORLB
        | Op::LDEORLH
        | Op::LDSET
        | Op::LDSETA
        | Op::LDSETAB
        | Op::LDSETAH
        | Op::LDSETAL
        | Op::LDSETALB
        | Op::LDSETALH
        | Op::LDSETB
        | Op::LDSETH
        | Op::LDSETL
        | Op::LDSETLB
        | Op::LDSETLH
        | Op::LDSMAX
        | Op::LDSMAXA
        | Op::LDSMAXAB
        | Op::LDSMAXAH
        | Op::LDSMAXAL
        | Op::LDSMAXALB
        | Op::LDSMAXALH
        | Op::LDSMAXB
        | Op::LDSMAXH
        | Op::LDSMAXL
        | Op::LDSMAXLB
        | Op::LDSMAXLH
        | Op::LDSMIN
        | Op::LDSMINA
        | Op::LDSMINAB
        | Op::LDSMINAH
        | Op::LDSMINAL
        | Op::LDSMINALB
        | Op::LDSMINALH
        | Op::LDSMINB
        | Op::LDSMINH
        | Op::LDSMINL
        | Op::LDSMINLB
        | Op::LDSMINLH
        | Op::LDUMAX
        | Op::LDUMAXA
        | Op::LDUMAXAB
        | Op::LDUMAXAH
        | Op::LDUMAXAL
        | Op::LDUMAXALB
        | Op::LDUMAXALH
        | Op::LDUMAXB
        | Op::LDUMAXH
        | Op::LDUMAXL
        | Op::LDUMAXLB
        | Op::LDUMAXLH
        | Op::LDUMIN
        | Op::LDUMINA
        | Op::LDUMINAB
        | Op::LDUMINAH
        | Op::LDUMINAL
        | Op::LDUMINALB
        | Op::LDUMINALH
        | Op::LDUMINB
        | Op::LDUMINH
        | Op::LDUMINL
        | Op::LDUMINLB
        | Op::LDUMINLH
        | Op::STLLR
        | Op::STLLRB
        | Op::STLLRH
        | Op::STLR
        | Op::STLRB
        | Op::STLRH
        | Op::STADD
        | Op::STADDB
        | Op::STADDH
        | Op::STADDL
        | Op::STADDLB
        | Op::STADDLH
        | Op::STCLR
        | Op::STCLRB
        | Op::STCLRH
        | Op::STCLRL
        | Op::STCLRLB
        | Op::STCLRLH
        | Op::STEOR
        | Op::STEORB
        | Op::STEORH
        | Op::STEORL
        | Op::STEORLB
        | Op::STEORLH
        | Op::STSET
        | Op::STSETB
        | Op::STSETH
        | Op::STSETL
        | Op::STSETLB
        | Op::STSETLH
        | Op::STSMAX
        | Op::STSMAXB
        | Op::STSMAXH
        | Op::STSMAXL
        | Op::STSMAXLB
        | Op::STSMAXLH
        | Op::STSMIN
        | Op::STSMINB
        | Op::STSMINH
        | Op::STSMINL
        | Op::STSMINLB
        | Op::STSMINLH
        | Op::STUMAX
        | Op::STUMAXB
        | Op::STUMAXH
        | Op::STUMAXL
        | Op::STUMAXLB
        | Op::STUMAXLH
        | Op::STUMIN
        | Op::STUMINB
        | Op::STUMINH
        | Op::STUMINL
        | Op::STUMINLB
        | Op::STUMINLH
        | Op::SWP
        | Op::SWPA
        | Op::SWPAB
        | Op::SWPAH
        | Op::SWPAL
        | Op::SWPALB
        | Op::SWPALH
        | Op::SWPB
        | Op::SWPH
        | Op::SWPL
        | Op::SWPLB
        | Op::SWPLH => Some(MemoryClass::Atomic),
        Op::LD1
        | Op::LD1R
        | Op::LD2
        | Op::LD2R
        | Op::LD3
        | Op::LD3R
        | Op::LD4
        | Op::LD4R
        | Op::ST1
        | Op::ST2
        | Op::ST3
        | Op::ST4 => Some(MemoryClass::Simd),
        Op::LDAPUR
        | Op::LDAPURB
        | Op::LDAPURH
        | Op::LDAPURSB
        | Op::LDAPURSH
        | Op::LDAPURSW
        | Op::LDR
        | Op::LDRB
        | Op::LDRH
        | Op::LDRSB
        | Op::LDRSH
        | Op::LDRSW
        | Op::LDTR
        | Op::LDTRB
        | Op::LDTRH
        | Op::LDTRSB
        | Op::LDTRSH
        | Op::LDTRSW
        | Op::LDUR
        | Op::LDURB
        | Op::LDURH
        | Op::LDURSB
        | Op::LDURSH
        | Op::LDURSW
        | Op::PRFM
        | Op::PRFUM
        | Op::STLUR
        | Op::STLURB
        | Op::STLURH
        | Op::STR
        | Op::STRB
        | Op::STRH
        | Op::STTR
        | Op::STTRB
        | Op::STTRH
        | Op::STUR
        | Op::STURB
        | Op::STURH => Some(if has_standard_simd_transfer(operands) {
            MemoryClass::Simd
        } else {
            MemoryClass::Scalar
        }),
        _ => None,
    }
}

fn has_memory_operand(operands: &[Operand]) -> bool {
    operands.iter().any(|operand| {
        matches!(
            operand,
            Operand::MemReg(_)
                | Operand::MemOffset { .. }
                | Operand::MemPreIdx { .. }
                | Operand::MemPostIdxImm { .. }
                | Operand::MemPostIdxReg(_)
                | Operand::MemExt { .. }
        )
    })
}

fn classify_memory(
    pc: GuestVa,
    word: u32,
    op: Op,
    operands: &[Operand],
) -> Result<Option<MemoryAccess>, DsrError> {
    let class = match memory_class(op, operands) {
        Some(class) => class,
        None if has_memory_operand(operands) => MemoryClass::Unsupported,
        None => return Ok(None),
    };
    let base = memory_base(pc, word, op, operands)?;
    let writeback = base_register(operands)
        .map(|(_, writeback)| writeback)
        .unwrap_or(MemoryWriteback::None);
    Ok(Some(MemoryAccess {
        word,
        op,
        base,
        writeback,
        class,
        virtualization: MemoryVirtualization::None,
    }))
}

pub(super) fn decoded_operands_mention_x18(word: u32, pc: GuestVa) -> bool {
    decoded_operands_mention_gpr(word, pc, 18)
}

pub(super) fn decoded_operands_mention_x28(word: u32, pc: GuestVa) -> bool {
    decoded_operands_mention_gpr(word, pc, 28)
}

pub(super) fn decoded_operands_mention_gpr(word: u32, pc: GuestVa, index: u32) -> bool {
    bad64::decode(word, pc.raw()).is_ok_and(|instruction| {
        instruction
            .operands()
            .iter()
            .any(|operand| operand_mentions_gpr(operand, index))
    })
}

fn direct(
    pc: GuestVa,
    word: u32,
    op: Op,
    kind: DirectKind,
    operands: &[Operand],
) -> Result<InstAction, DsrError> {
    Ok(InstAction::Direct(DirectExit {
        kind,
        target: label(operands).ok_or_else(|| malformed(pc, word, op))?,
        resume: resume_pc(pc)?,
        condition: condition(operands),
        register: first_reg(operands),
        bit: immediate_u8(operands),
    }))
}

fn indirect(
    pc: GuestVa,
    word: u32,
    op: Op,
    kind: IndirectKind,
    operands: &[Operand],
) -> Result<InstAction, DsrError> {
    Ok(InstAction::Indirect(IndirectExit {
        kind,
        register: first_reg(operands).ok_or_else(|| malformed(pc, word, op))?,
        resume: resume_pc(pc)?,
    }))
}

fn pc_relative(
    pc: GuestVa,
    word: u32,
    op: Op,
    kind: PcRelativeKind,
    operands: &[Operand],
) -> Result<InstAction, DsrError> {
    Ok(InstAction::PcRelative(PcRelativeInst {
        kind,
        target: label(operands).ok_or_else(|| malformed(pc, word, op))?,
        destination: first_reg(operands),
        word,
    }))
}

fn sensitive(
    pc: GuestVa,
    kind: SensitiveKind,
    register: Option<Reg>,
) -> Result<InstAction, DsrError> {
    Ok(InstAction::Sensitive(SensitiveExit {
        kind,
        register,
        resume: resume_pc(pc)?,
    }))
}

pub(super) fn classify(word: u32, pc: GuestVa) -> Result<InstAction, DsrError> {
    // FEAT_CHK's fixed `chkfeat x16` encoding is also architecturally a HINT
    // on implementations without the extension. bad64 0.12 predates this
    // Armv8.9 alias and rejects the otherwise copy-safe instruction. x16 is an
    // ordinary guest register while translated code is running, so native
    // execution preserves both the implemented and HINT behaviors.
    if word == 0xd503_251f {
        return Ok(InstAction::Copy(word));
    }
    let instruction = bad64::decode(word, pc.raw()).map_err(|error| DsrError::Decode {
        pc: pc.raw(),
        word,
        detail: format!("{error:?}"),
    })?;
    let op = instruction.op();
    let operands = instruction.operands();
    let mentions_x18 = operands
        .iter()
        .any(|operand| operand_mentions_gpr(operand, 18));
    let mentions_x28 = operands
        .iter()
        .any(|operand| operand_mentions_gpr(operand, 28));
    let mentions_x18_outside_base = operands
        .iter()
        .any(|operand| operand_mentions_gpr_outside_memory_base(operand, 18));
    let mentions_x28_outside_base = operands
        .iter()
        .any(|operand| operand_mentions_gpr_outside_memory_base(operand, 28));

    let virtualized = || {
        if mentions_x18 && mentions_x28 {
            let writes_x18_from_x28 = matches!(
                operands,
                [
                    Operand::Reg { reg: destination, .. },
                    Operand::Reg { reg: source, .. },
                    ..
                ] if register_matches_gpr(*destination, 18)
                    && register_matches_gpr(*source, 28)
            );
            let loads_x18_from_x28 = matches!(
                (op, operands),
                (
                    Op::LDR,
                    [
                        Operand::Reg { reg: destination, .. },
                        Operand::MemOffset { reg: base, .. }
                    ]
                ) if register_matches_gpr(*destination, 18)
                    && register_matches_gpr(*base, 28)
            ) || matches!(
                (op, operands),
                (
                    Op::LDP,
                    [
                        Operand::Reg { .. },
                        Operand::Reg { reg: destination, .. },
                        Operand::MemOffset { reg: base, .. }
                    ]
                ) if register_matches_gpr(*destination, 18)
                    && register_matches_gpr(*base, 28)
            );
            if (matches!(op, Op::ADD | Op::SUB) && writes_x18_from_x28) || loads_x18_from_x28 {
                InstAction::VirtualizedX18WriteX28Read { word, op }
            } else if matches!(
                (op, operands),
                (
                    Op::STP,
                    [
                        Operand::Reg { .. },
                        Operand::Reg { .. },
                        Operand::MemOffset { .. }
                    ]
                ) | (Op::STR, [Operand::Reg { .. }, Operand::MemOffset { .. }])
            ) {
                // Offset-form stores only read their data registers and base;
                // unlike pre/post-index forms they cannot update guest x28.
                InstAction::VirtualizedX18X28ReadOnly { word, op }
            } else {
                InstAction::Unsupported { word, op }
            }
        } else if mentions_x18 {
            InstAction::VirtualizedX18 { word, op }
        } else if mentions_x28 {
            InstAction::VirtualizedX28 { word, op }
        } else {
            InstAction::Copy(word)
        }
    };

    if let Some(mut memory) = classify_memory(pc, word, op, operands)? {
        if memory.class != MemoryClass::Literal
            && (mentions_x18_outside_base || mentions_x28_outside_base)
        {
            let action = virtualized();
            memory.virtualization = match action {
                InstAction::VirtualizedX18 { .. } => MemoryVirtualization::X18,
                InstAction::VirtualizedX28 { .. } => MemoryVirtualization::X28,
                InstAction::VirtualizedX18X28ReadOnly { .. } => {
                    MemoryVirtualization::X18X28ReadOnly
                }
                InstAction::VirtualizedX18WriteX28Read { .. } => {
                    MemoryVirtualization::X18WriteX28Read
                }
                InstAction::Unsupported { .. } => MemoryVirtualization::Unsupported,
                _ => MemoryVirtualization::None,
            };
            return Ok(InstAction::Memory(memory));
        }
        return Ok(InstAction::Memory(memory));
    }
    if let Some(condition) = branch_condition(op) {
        let mut action = direct(pc, word, op, DirectKind::Conditional, operands)?;
        if let InstAction::Direct(exit) = &mut action {
            exit.condition = Some(condition);
        }
        return Ok(action);
    }

    match op {
        Op::SVC if word == 0xd400_0001 => Ok(InstAction::Syscall {
            resume: resume_pc(pc)?,
        }),
        Op::SVC => Ok(InstAction::Unsupported { word, op }),
        Op::B => direct(pc, word, op, DirectKind::Branch, operands),
        Op::BL => direct(pc, word, op, DirectKind::Call, operands),
        Op::CBZ => direct(
            pc,
            word,
            op,
            DirectKind::CompareZero { nonzero: false },
            operands,
        ),
        Op::CBNZ => direct(
            pc,
            word,
            op,
            DirectKind::CompareZero { nonzero: true },
            operands,
        ),
        Op::TBZ => direct(
            pc,
            word,
            op,
            DirectKind::TestBit { nonzero: false },
            operands,
        ),
        Op::TBNZ => direct(
            pc,
            word,
            op,
            DirectKind::TestBit { nonzero: true },
            operands,
        ),
        Op::BR => indirect(pc, word, op, IndirectKind::Branch, operands),
        Op::BLR => indirect(pc, word, op, IndirectKind::Call, operands),
        Op::RET => Ok(InstAction::Indirect(IndirectExit {
            kind: IndirectKind::Return,
            register: first_reg(operands).unwrap_or(Reg::X30),
            resume: resume_pc(pc)?,
        })),
        Op::ADR => pc_relative(pc, word, op, PcRelativeKind::Adr, operands),
        Op::ADRP => pc_relative(pc, word, op, PcRelativeKind::Adrp, operands),
        Op::MRS => match operands {
            [Operand::Reg { reg, .. }, Operand::SysReg(SysReg::TPIDR_EL0)] => {
                sensitive(pc, SensitiveKind::ReadTpidr, Some(*reg))
            }
            [Operand::Reg { reg, .. }, Operand::SysReg(SysReg::CTR_EL0)] => {
                sensitive(pc, SensitiveKind::ReadCtr, Some(*reg))
            }
            [Operand::Reg { reg, .. }, Operand::SysReg(SysReg::DCZID_EL0)] => {
                sensitive(pc, SensitiveKind::ReadDczid, Some(*reg))
            }
            [
                Operand::Reg { .. },
                Operand::SysReg(SysReg::CNTVCT_EL0 | SysReg::CNTFRQ_EL0),
            ] => {
                // Native16k executes these host-readable EL0 registers
                // directly. Keeping them in-cache is also essential for the
                // guest vDSO and timing-heavy workloads.
                Ok(virtualized())
            }
            [Operand::Reg { .. }, Operand::SysReg(SysReg::NZCV)] => Ok(virtualized()),
            [
                Operand::Reg { .. },
                Operand::SysReg(SysReg::FPCR | SysReg::FPSR),
            ] => Ok(virtualized()),
            _ => Ok(InstAction::Unsupported { word, op }),
        },
        Op::MSR => match operands {
            [Operand::SysReg(SysReg::TPIDR_EL0), Operand::Reg { reg, .. }] => {
                sensitive(pc, SensitiveKind::WriteTpidr, Some(*reg))
            }
            [Operand::SysReg(SysReg::NZCV), Operand::Reg { .. }] => Ok(virtualized()),
            [
                Operand::SysReg(SysReg::FPCR | SysReg::FPSR),
                Operand::Reg { .. },
            ] => Ok(virtualized()),
            _ => Ok(InstAction::Unsupported { word, op }),
        },
        Op::DC if (word & !0x1f) == 0xd50b_7420 => {
            sensitive(pc, SensitiveKind::DcZva, first_reg(operands))
        }
        Op::DC if (word & !0x1f) == 0xd50b_7b20 => {
            sensitive(pc, SensitiveKind::DcCvau, first_reg(operands))
        }
        Op::IC if (word & !0x1f) == 0xd50b_7520 => {
            sensitive(pc, SensitiveKind::IcIvau, first_reg(operands))
        }
        Op::DC | Op::IC | Op::HVC | Op::SMC | Op::ERET => Ok(InstAction::Unsupported { word, op }),
        _ => Ok(virtualized()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_darwin::dsr::types::{
        MemoryBase, MemoryClass, MemoryVirtualization, MemoryWriteback,
    };

    const PC: GuestVa = GuestVa(0x4000);

    #[test]
    fn classifies_memory_operands_for_biased_lowering() {
        let cases = [
            (0xf940_0020, MemoryClass::Scalar, MemoryWriteback::None),
            (0xf81f_0ffe, MemoryClass::Scalar, MemoryWriteback::PreIndex),
            (0xa8c1_7bfd, MemoryClass::Pair, MemoryWriteback::PostIndex),
            (0x3dc0_0020, MemoryClass::Simd, MemoryWriteback::None),
            (0xc85f_7c20, MemoryClass::Exclusive, MemoryWriteback::None),
            (0xf8e1_0022, MemoryClass::Atomic, MemoryWriteback::None),
            (0x5800_0040, MemoryClass::Literal, MemoryWriteback::None),
            // Standard Advanced SIMD post-index register form.
            (0x4cc2_7020, MemoryClass::Simd, MemoryWriteback::PostIndex),
            // Standard scalar register-offset form (`MemExt` in bad64).
            (0xf862_6820, MemoryClass::Scalar, MemoryWriteback::None),
        ];
        for (word, class, writeback) in cases {
            let InstAction::Memory(memory) = classify(word, PC).expect("classify memory") else {
                panic!("0x{word:08x} was not classified as memory");
            };
            assert_eq!(memory.class, class, "word=0x{word:08x}");
            assert_eq!(memory.writeback, writeback, "word=0x{word:08x}");
        }
    }

    #[test]
    fn memory_base_retains_virtual_register_metadata() {
        assert!(matches!(
            classify(0xf940_0240, PC), // ldr x0, [x18]
            Ok(InstAction::Memory(memory)) if memory.base == MemoryBase::VirtualX18
        ));
        assert!(matches!(
            classify(0xf940_0380, PC), // ldr x0, [x28]
            Ok(InstAction::Memory(memory)) if memory.base == MemoryBase::VirtualX28
        ));
    }

    #[test]
    fn audited_bad64_memory_operand_shapes_are_stable() {
        type OperandShape = fn(&Operand) -> bool;
        let cases: &[(u32, OperandShape)] = &[
            // bad64 0.12 normalizes this zero-offset exclusive form to
            // `MemOffset`, rather than `MemReg`.
            (0xc85f_7c20, |operand| {
                matches!(operand, Operand::MemOffset { .. })
            }),
            (0xf940_0020, |operand| {
                matches!(operand, Operand::MemOffset { .. })
            }),
            (0xf81f_0ffe, |operand| {
                matches!(operand, Operand::MemPreIdx { .. })
            }),
            (0xa8c1_7bfd, |operand| {
                matches!(operand, Operand::MemPostIdxImm { .. })
            }),
            (0x4cc2_7020, |operand| {
                matches!(operand, Operand::MemPostIdxReg(_))
            }),
            (0xf862_6820, |operand| {
                matches!(operand, Operand::MemExt { .. })
            }),
            (0x5800_0040, |operand| matches!(operand, Operand::Label(_))),
        ];
        for (word, expected) in cases {
            let instruction = bad64::decode(*word, PC.raw()).expect("decode audited memory word");
            assert!(
                instruction.operands().iter().any(expected),
                "unexpected operands for 0x{word:08x}: {instruction:?}"
            );
        }
    }

    #[test]
    fn non_base_virtual_registers_keep_virtualization_precedence() {
        assert!(matches!(
            classify(0xf940_0012, PC), // ldr x18, [x0]
            Ok(InstAction::Memory(memory))
                if memory.virtualization == MemoryVirtualization::X18
        ));
        assert!(matches!(
            classify(0xf940_0392, PC), // ldr x18, [x28]
            Ok(InstAction::Memory(memory))
                if memory.virtualization == MemoryVirtualization::X18WriteX28Read
        ));
        assert!(matches!(
            classify(0x7940_0e52, PC), // ldrh w18, [x18, #6]
            Ok(InstAction::Memory(memory))
                if memory.virtualization == MemoryVirtualization::X18
        ));
        assert!(matches!(
            classify(0x5800_0052, PC), // ldr x18, 0x4008
            Ok(InstAction::Memory(memory))
                if memory.class == MemoryClass::Literal
                    && memory.base == MemoryBase::Literal(GuestVa(0x4008))
        ));
    }

    #[test]
    fn memory_operand_base_must_match_encoded_rn() {
        let operands = [
            Operand::Reg {
                reg: Reg::X0,
                arrspec: None,
            },
            Operand::MemOffset {
                reg: Reg::X2,
                offset: Imm::Signed(0),
                mul_vl: false,
                arrspec: None,
            },
        ];
        assert!(matches!(
            classify_memory(PC, 0xf940_0020, Op::LDR, &operands),
            Err(DsrError::Malformed { .. })
        ));

        let invalid_base = [
            Operand::Reg {
                reg: Reg::X0,
                arrspec: None,
            },
            Operand::MemReg(Reg::Q1),
        ];
        assert!(matches!(
            classify_memory(PC, 0xf940_0020, Op::LDR, &invalid_base),
            Err(DsrError::Malformed { .. })
        ));
    }

    #[test]
    fn unaudited_memory_family_remains_typed_for_direct_passthrough() {
        let operands = [Operand::MemOffset {
            reg: Reg::X1,
            offset: Imm::Signed(0),
            mul_vl: false,
            arrspec: None,
        }];
        let memory = classify_memory(PC, 0x0000_0020, Op::ADD, &operands)
            .expect("validate synthetic memory operand")
            .expect("retain unaudited memory family");
        assert_eq!(memory.class, MemoryClass::Unsupported);
        assert_eq!(memory.base, MemoryBase::Register(Reg::X1));
    }

    fn assert_unsupported_memory(word: u32) {
        let instruction = bad64::decode(word, PC.raw()).expect("decode unsupported fixture");
        let InstAction::Memory(memory) = classify(word, PC).expect("classify unsupported memory")
        else {
            panic!("0x{word:08x} was not retained as typed memory: {instruction}");
        };
        assert_eq!(
            memory.class,
            MemoryClass::Unsupported,
            "0x{word:08x}: {instruction:?}"
        );
    }

    #[test]
    fn sve_memory_is_not_standard_simd_or_scalar() {
        let word = 0x8598_5f6f;
        let instruction = bad64::decode(word, PC.raw()).expect("decode SVE fixture");
        assert!(matches!(
            instruction.operands(),
            [
                Operand::Reg { reg: Reg::Z15, .. },
                Operand::MemOffset {
                    reg: Reg::X27,
                    mul_vl: true,
                    ..
                }
            ]
        ));
        assert_unsupported_memory(word);
    }

    #[test]
    fn sme_memory_is_not_standard_simd_or_scalar() {
        // bad64 exposes the ZA slice as `AccumArray` and the address as
        // `MemOffset { mul_vl: true, .. }`.
        let word = 0xe100_004d;
        let instruction = bad64::decode(word, PC.raw()).expect("decode SME fixture");
        assert!(matches!(
            instruction.operands(),
            [
                Operand::AccumArray { .. },
                Operand::MemOffset {
                    reg: Reg::X2,
                    mul_vl: true,
                    ..
                }
            ]
        ));
        assert_unsupported_memory(word);
    }

    #[test]
    fn unsupported_memory_retains_non_base_virtualization() {
        let cases = [
            (0xa452_48af, Reg::X18, MemoryVirtualization::X18),
            (0xa45c_48af, Reg::X28, MemoryVirtualization::X28),
        ];
        for (word, index, virtualization) in cases {
            let instruction =
                bad64::decode(word, PC.raw()).expect("decode SVE virtual-index fixture");
            assert!(instruction.operands().iter().any(|operand| matches!(
                operand,
                Operand::MemExt { regs: [Reg::X5, observed], .. } if *observed == index
            )));
            let InstAction::Memory(memory) =
                classify(word, PC).expect("classify SVE virtual-index memory")
            else {
                panic!("0x{word:08x} lost typed memory identity: {instruction}");
            };
            assert_eq!(memory.class, MemoryClass::Unsupported);
            assert_eq!(memory.virtualization, virtualization);
        }
    }
}
