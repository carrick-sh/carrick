#![allow(dead_code)] // Classification is wired into block formation in Task 4.

use bad64::{Imm, Op, Operand, Reg, SysReg};
use carrick_guest_mem::GuestVa;

use super::types::{
    DirectExit, DirectKind, DsrError, IndirectExit, IndirectKind, InstAction, PcRelativeInst,
    PcRelativeKind, SensitiveExit, SensitiveKind,
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
        Op::LDR | Op::LDRSW if label(operands).is_some() => {
            pc_relative(pc, word, op, PcRelativeKind::LiteralLoad, operands)
        }
        Op::PRFM if label(operands).is_some() => {
            pc_relative(pc, word, op, PcRelativeKind::LiteralPrefetch, operands)
        }
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
