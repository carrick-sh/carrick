//! Typed decoding entry point. Unimplemented and reserved leaves fail shut.
use crate::Decoded;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Instruction {
    Unallocated,
    CensusGap(Decoded),
    Hint(Hint),
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

    crate::decode(word).map_or(Instruction::Unallocated, Instruction::CensusGap)
}
