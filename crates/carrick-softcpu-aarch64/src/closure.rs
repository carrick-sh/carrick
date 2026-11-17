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
pub(crate) fn decode(w: u32) -> Option<Instruction> {
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
