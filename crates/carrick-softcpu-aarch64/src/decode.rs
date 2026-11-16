//! Hand-written leaves from Arm ARM DDI0487, A64 encoding index.
//! This is decoding only: no instruction is executed on the host.

/// Architectural general-purpose register number; 31 denotes ZR here, not SP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Register(u8);
impl Register {
    pub const fn number(self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Immediate16(u16);
impl Immediate16 {
    pub const fn value(self) -> u16 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExclusiveOption(u8);
impl ExclusiveOption {
    pub const fn value(self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Width {
    W32,
    X64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shift {
    Lsl,
    Lsr,
    Asr,
    Ror,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unary {
    Rbit,
    Rev16,
    Rev32,
    Rev64,
    Clz,
    Cls,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Translation {
    S1E1R,
    S1E1W,
    S1E0R,
    S1E0W,
    S1E2R,
    S1E2W,
    S12E1R,
    S12E1W,
    S12E0R,
    S12E0W,
    S1E3R,
    S1E3W,
    S1E1Rp,
    S1E1Wp,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlbOperation {
    Vae1,
    Vale1,
    Aside1,
    Vaae1,
    Vaale1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shareability {
    InnerShareable,
    NonShareable,
}

/// Operands of the supported leaves. Other existing census classes have no
/// operand decoder yet and return None from `decode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decoded {
    VariableShift {
        width: Width,
        op: Shift,
        rm: Register,
        rn: Register,
        rd: Register,
    },
    OneSource {
        width: Width,
        op: Unary,
        rn: Register,
        rd: Register,
    },
    Breakpoint {
        immediate: Immediate16,
    },
    ClearExclusive {
        option: ExclusiveOption,
    },
    AddressTranslate {
        op: Translation,
        xt: Register,
    },
    TlbInvalidate {
        op: TlbOperation,
        scope: Shareability,
        xt: Register,
    },
}

/// Arm ARM DDI0487, "A64 instruction set encoding", Data-processing
/// (2 source), Data-processing (1 source), Exception generation (BRK),
/// System instructions (CLREX), and "A64 system instructions for address
/// translation" / "A64 system instructions for TLB maintenance" tables.
/// Only the baseline AT forms plus FEAT_PAN2 RP/WP and the EL1 VA/ASID
/// TLBI forms listed here are admitted; extension and reserved leaves fail shut.
pub fn decode(w: u32) -> Option<Decoded> {
    let rd = Register((w & 31) as u8);
    let rn = Register(((w >> 5) & 31) as u8);
    let width = if w >> 31 == 0 { Width::W32 } else { Width::X64 };
    // sf is variable; S and opcode2 are fixed zero. Bits 15:10 select
    // LSLV/LSRV/ASRV/RORV; all other two-source opcodes are outside this leaf.
    if w & 0x7fe0f000 == 0x1ac02000 {
        let op = match (w >> 10) & 3 {
            0 => Shift::Lsl,
            1 => Shift::Lsr,
            2 => Shift::Asr,
            _ => Shift::Ror,
        };
        return Some(Decoded::VariableShift {
            width,
            op,
            rm: Register(((w >> 16) & 31) as u8),
            rn,
            rd,
        });
    }
    // opcode2 (20:16) and S must be zero. REV64 is unallocated at sf=0;
    // opcode=2 denotes REV W at sf=0 and REV32 X at sf=1.
    if w & 0x7ffffc00 >= 0x5ac00000 && w & 0x7ffffc00 <= 0x5ac01400 {
        let op = match (w >> 10) & 63 {
            0 => Unary::Rbit,
            1 => Unary::Rev16,
            2 => Unary::Rev32,
            3 if width == Width::X64 => Unary::Rev64,
            4 => Unary::Clz,
            5 => Unary::Cls,
            _ => return None,
        };
        return Some(Decoded::OneSource { width, op, rn, rd });
    }
    if w & 0xffe0001f == 0xd4200000 {
        return Some(Decoded::Breakpoint {
            immediate: Immediate16(((w >> 5) & 0xffff) as u16),
        });
    }
    if w & 0xfffff0ff == 0xd503305f {
        return Some(Decoded::ClearExclusive {
            option: ExclusiveOption(((w >> 8) & 15) as u8),
        });
    }
    // SYS: fixed L=0, op0=01, CRn=7; explicitly enumerate allocated AT
    // op1:CRm:op2 tuples instead of treating all SYS as translations.
    if w & 0xfff8f000 == 0xd5087000 {
        let op = match ((w >> 16) & 7, (w >> 8) & 15, (w >> 5) & 7) {
            (0, 8, 0) => Translation::S1E1R,
            (0, 8, 1) => Translation::S1E1W,
            (0, 8, 2) => Translation::S1E0R,
            (0, 8, 3) => Translation::S1E0W,
            (4, 8, 0) => Translation::S1E2R,
            (4, 8, 1) => Translation::S1E2W,
            (4, 8, 4) => Translation::S12E1R,
            (4, 8, 5) => Translation::S12E1W,
            (4, 8, 6) => Translation::S12E0R,
            (4, 8, 7) => Translation::S12E0W,
            (6, 8, 0) => Translation::S1E3R,
            (6, 8, 1) => Translation::S1E3W,
            (0, 9, 0) => Translation::S1E1Rp,
            (0, 9, 1) => Translation::S1E1Wp,
            _ => return None,
        };
        return Some(Decoded::AddressTranslate { op, xt: rd });
    }
    // SYS op1=0 CRn=8. CRm=3/7 selects IS/local; op2=4/6 are
    // unallocated, and VMALLE1 (op2=0) stays in the existing census class.
    if w & 0xfffff000 == 0xd5088000 {
        let scope = match (w >> 8) & 15 {
            3 => Shareability::InnerShareable,
            7 => Shareability::NonShareable,
            _ => return None,
        };
        let op = match (w >> 5) & 7 {
            1 => TlbOperation::Vae1,
            2 => TlbOperation::Aside1,
            3 => TlbOperation::Vaae1,
            5 => TlbOperation::Vale1,
            7 => TlbOperation::Vaale1,
            _ => return None,
        };
        return Some(Decoded::TlbInvalidate { op, scope, xt: rd });
    }
    None
}
