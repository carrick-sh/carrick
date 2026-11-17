//! Typed decoding entry point. Unimplemented and reserved leaves fail shut.
use crate::Decoded;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Instruction {
    Unallocated,
    CensusGap(Decoded),
    Hint(Hint),
    Arithmetic(Arithmetic),
}

/// Arm ARM DDI0487G.a C6.2.92 HINT, C6.2.204 NOP, C6.2.354 YIELD,
/// C6.2.348 WFE, C6.2.350 WFI, C6.2.238 SEV, C6.2.239 SEVL;
/// encoding index C4.1.3, Hints. Extension hints are deliberately unsupported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hint {
    Nop,
    Yield,
    Wfe,
    Wfi,
    Sev,
    Sevl,
}

pub fn decode_instruction(word: u32) -> Instruction {
    let hint = match word {
        0xd503201f => Some(Hint::Nop),
        0xd503203f => Some(Hint::Yield),
        0xd503205f => Some(Hint::Wfe),
        0xd503207f => Some(Hint::Wfi),
        0xd503209f => Some(Hint::Sev),
        0xd50320bf => Some(Hint::Sevl),
        _ => None,
    };
    if let Some(hint) = hint {
        return Instruction::Hint(hint);
    }

    if let Some(a) = arithmetic(word) {
        return Instruction::Arithmetic(a);
    }
    crate::decode(word).map_or(Instruction::Unallocated, Instruction::CensusGap)
}

/// Register index 0..30. Architectural register 31 is represented separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gpr(u8);
impl Gpr {
    pub const fn number(self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperandRegister {
    Gpr(Gpr),
    Sp,
    Zr,
}
impl OperandRegister {
    fn field(bits: u32, sp: bool) -> Self {
        match bits & 31 {
            31 if sp => Self::Sp,
            31 => Self::Zr,
            n => Self::Gpr(Gpr(n as u8)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShiftAmount(u8);
impl ShiftAmount {
    pub const fn value(self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Extend {
    Uxtb,
    Uxth,
    Uxtw,
    Uxtx,
    Sxtb,
    Sxth,
    Sxtw,
    Sxtx,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddSubtract {
    Add,
    Subtract,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddImmediate {
    encoded: u16,
    shift: ShiftAmount,
}
impl AddImmediate {
    pub const fn encoded(self) -> u16 {
        self.encoded
    }
    pub const fn shift(self) -> ShiftAmount {
        self.shift
    }
    pub const fn value(self) -> u64 {
        (self.encoded as u64) << self.shift.0
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithmeticOperand {
    Immediate(AddImmediate),
    Shifted {
        rm: OperandRegister,
        shift: crate::Shift,
        amount: ShiftAmount,
    },
    Extended {
        rm: OperandRegister,
        extend: Extend,
        amount: ShiftAmount,
    },
    WithCarry {
        rm: OperandRegister,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arithmetic {
    pub width: crate::Width,
    pub op: AddSubtract,
    pub set_flags: bool,
    pub rd: OperandRegister,
    pub rn: OperandRegister,
    pub operand: ArithmeticOperand,
}

/// DDI0487G.a C6.2.4 ADD / C6.2.8 ADDS / C6.2.313 SUB /
/// C6.2.319 SUBS (immediate); C4.1.2 Add/subtract (immediate).
fn arithmetic_immediate(w: u32) -> Option<ArithmeticOperand> {
    (w & 0x1f800000 == 0x11000000).then_some(ArithmeticOperand::Immediate(AddImmediate {
        encoded: ((w >> 10) & 4095) as u16,
        shift: ShiftAmount(if w & (1 << 22) != 0 { 12 } else { 0 }),
    }))
}

/// DDI0487G.a C6.2.5 ADD / C6.2.9 ADDS / C6.2.314 SUB /
/// C6.2.320 SUBS (shifted register); C4.1.5 Add/subtract (shifted register).
fn arithmetic_shifted(w: u32) -> Option<ArithmeticOperand> {
    if w & 0x1f200000 != 0x0b000000 || (w >> 31 == 0 && w & 0x8000 != 0) {
        return None;
    }
    let shift = match (w >> 22) & 3 {
        0 => crate::Shift::Lsl,
        1 => crate::Shift::Lsr,
        2 => crate::Shift::Asr,
        _ => return None,
    };
    Some(ArithmeticOperand::Shifted {
        rm: OperandRegister::field(w >> 16, false),
        shift,
        amount: ShiftAmount(((w >> 10) & 63) as u8),
    })
}

/// DDI0487G.a C6.2.3 ADD / C6.2.7 ADDS / C6.2.312 SUB /
/// C6.2.318 SUBS (extended register); C4.1.5 Add/subtract (extended register).
fn arithmetic_extended(w: u32) -> Option<ArithmeticOperand> {
    if w & 0x1fe00000 != 0x0b200000 || (w >> 10) & 7 > 4 {
        return None;
    }
    let extend = match (w >> 13) & 7 {
        0 => Extend::Uxtb,
        1 => Extend::Uxth,
        2 => Extend::Uxtw,
        3 => Extend::Uxtx,
        4 => Extend::Sxtb,
        5 => Extend::Sxth,
        6 => Extend::Sxtw,
        _ => Extend::Sxtx,
    };
    Some(ArithmeticOperand::Extended {
        rm: OperandRegister::field(w >> 16, false),
        extend,
        amount: ShiftAmount(((w >> 10) & 7) as u8),
    })
}

/// DDI0487G.a C6.2.1 ADC, C6.2.2 ADCS, C6.2.231 SBC, C6.2.232 SBCS;
/// C4.1.5 Add/subtract (with carry). All three registers use ZR, never SP.
fn arithmetic_carry(w: u32) -> Option<ArithmeticOperand> {
    (w & 0x1fe0fc00 == 0x1a000000).then_some(ArithmeticOperand::WithCarry {
        rm: OperandRegister::field(w >> 16, false),
    })
}

fn arithmetic(w: u32) -> Option<Arithmetic> {
    let operand = arithmetic_immediate(w)
        .or_else(|| arithmetic_shifted(w))
        .or_else(|| arithmetic_extended(w))
        .or_else(|| arithmetic_carry(w))?;
    let uses_sp = matches!(
        operand,
        ArithmeticOperand::Immediate(_) | ArithmeticOperand::Extended { .. }
    );
    let set_flags = w & (1 << 29) != 0;
    Some(Arithmetic {
        width: if w >> 31 != 0 {
            crate::Width::X64
        } else {
            crate::Width::W32
        },
        op: if w & (1 << 30) != 0 {
            AddSubtract::Subtract
        } else {
            AddSubtract::Add
        },
        set_flags,
        rd: OperandRegister::field(w, uses_sp && !set_flags),
        rn: OperandRegister::field(w >> 5, uses_sp),
        operand,
    })
}
