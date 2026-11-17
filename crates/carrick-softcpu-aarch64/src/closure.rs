//! Remaining baseline leaves, hand-written from Arm ARM DDI0487G.a.
use crate::Instruction;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarrierKind {
    Dsb,
    Dmb,
    Isb,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarrierDomain {
    OuterShareable,
    NonShareable,
    InnerShareable,
    FullSystem,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarrierAccess {
    Reads,
    Writes,
    All,
}
/// DDI0487G.a C6.2.80 DMB, C6.2.82 DSB, C6.2.97 ISB;
/// C4.1.3 encoding index, Barriers. Reserved options deliberately fail shut,
/// including the reserved options architecturally executed as full-system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Barrier {
    pub kind: BarrierKind,
    pub domain: BarrierDomain,
    pub access: BarrierAccess,
    pub option: crate::ExclusiveOption,
}
fn barrier(w: u32) -> Option<Instruction> {
    let kind = match w & 0xfffff0ff {
        0xd503309f => BarrierKind::Dsb,
        0xd50330bf => BarrierKind::Dmb,
        0xd50330df if w == 0xd5033fdf => BarrierKind::Isb,
        _ => return None,
    };
    let option = ((w >> 8) & 15) as u8;
    let access = match option & 3 {
        1 => BarrierAccess::Reads,
        2 => BarrierAccess::Writes,
        3 => BarrierAccess::All,
        _ => return None,
    };
    let domain = match option >> 2 {
        0 => BarrierDomain::OuterShareable,
        1 => BarrierDomain::NonShareable,
        2 => BarrierDomain::InnerShareable,
        _ => BarrierDomain::FullSystem,
    };
    Some(Instruction::Barrier(Barrier {
        kind,
        domain,
        access,
        option: crate::ExclusiveOption::from_option(option),
    }))
}

/// Architectural system-register identity. The original census fields remain
/// available through `encoding`; names never discard or alias that identity.
/// DDI0487G.a C6.2.194 MRS, C6.2.196 MSR (register), C4.1.3
/// System register move; D13 AArch64 System Register Descriptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedSystemRegister {
    Ttbr0El1,
    Ttbr1El1,
    SpEl0,
    TpidrEl0,
    TpidrroEl0,
    ContextidrEl1,
    Fpcr,
    Fpsr,
    Daif,
    Pan,
    ParEl1,
    CntfrqEl0,
    CntvctEl0,
    CntvCtlEl0,
    CntvCvalEl0,
    MpidrEl1,
    IccIar1El1,
    IccEoir1El1,
    IccSgi1rEl1,
    Unnamed(crate::SystemRegister),
}
impl NamedSystemRegister {
    pub fn from_encoding(r: crate::SystemRegister) -> Self {
        match (r.op0, r.op1, r.crn, r.crm, r.op2) {
            (3, 0, 2, 0, 0) => Self::Ttbr0El1,
            (3, 0, 2, 0, 1) => Self::Ttbr1El1,
            (3, 0, 4, 1, 0) => Self::SpEl0,
            (3, 3, 13, 0, 2) => Self::TpidrEl0,
            (3, 3, 13, 0, 3) => Self::TpidrroEl0,
            (3, 0, 13, 0, 1) => Self::ContextidrEl1,
            (3, 3, 4, 4, 0) => Self::Fpcr,
            (3, 3, 4, 4, 1) => Self::Fpsr,
            (3, 3, 4, 2, 1) => Self::Daif,
            (3, 0, 4, 2, 3) => Self::Pan,
            (3, 0, 7, 4, 0) => Self::ParEl1,
            (3, 3, 14, 0, 0) => Self::CntfrqEl0,
            (3, 3, 14, 0, 2) => Self::CntvctEl0,
            (3, 3, 14, 3, 1) => Self::CntvCtlEl0,
            (3, 3, 14, 3, 2) => Self::CntvCvalEl0,
            (3, 0, 0, 0, 5) => Self::MpidrEl1,
            (3, 0, 12, 12, 0) => Self::IccIar1El1,
            (3, 0, 12, 12, 1) => Self::IccEoir1El1,
            (3, 0, 12, 11, 5) => Self::IccSgi1rEl1,
            _ => Self::Unnamed(r),
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemDirection {
    Read,
    Write,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemAccess {
    pub direction: SystemDirection,
    pub encoding: crate::SystemRegister,
    pub register: NamedSystemRegister,
    pub rt: crate::OperandRegister,
}
/// DDI0487G.a C6.2.195 MSR (immediate); C4.1.3 PSTATE encoding index.
/// Feature-dependent fields are decoded, without asserting execution support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PstateField {
    SpSel,
    DaifSet,
    DaifClr,
    Pan,
    Uao,
    Dit,
    Ssbs,
    Tco,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PstateImmediate {
    pub field: PstateField,
    pub immediate: u8,
}
fn system(w: u32) -> Option<Instruction> {
    if w & 0xffd00000 == 0xd5100000 {
        let encoding = crate::SystemRegister::from_word(w);
        return Some(Instruction::SystemAccess(SystemAccess {
            direction: if w & (1 << 21) != 0 {
                SystemDirection::Read
            } else {
                SystemDirection::Write
            },
            register: NamedSystemRegister::from_encoding(encoding),
            encoding,
            rt: crate::OperandRegister::field(w, false),
        }));
    }
    if w & 0xfff8f01f != 0xd500401f {
        return None;
    }
    let field = match ((w >> 16) & 7, (w >> 5) & 7) {
        (0, 3) => PstateField::Uao,
        (0, 4) => PstateField::Pan,
        (0, 5) => PstateField::SpSel,
        (3, 1) => PstateField::Ssbs,
        (3, 2) => PstateField::Dit,
        (3, 4) => PstateField::Tco,
        (3, 6) => PstateField::DaifSet,
        (3, 7) => PstateField::DaifClr,
        _ => return None,
    };
    Some(Instruction::PstateImmediate(PstateImmediate {
        field,
        immediate: ((w >> 8) & 15) as u8,
    }))
}
pub(crate) fn decode(w: u32) -> Option<Instruction> {
    barrier(w).or_else(|| system(w))
}
