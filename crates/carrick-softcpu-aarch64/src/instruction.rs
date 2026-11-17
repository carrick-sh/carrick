//! Typed decoding entry point. Unimplemented and reserved leaves fail shut.
use crate::Decoded;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Instruction {
    Unallocated,
    CensusGap(Decoded),
}

pub fn decode_instruction(word: u32) -> Instruction {
    crate::decode(word).map_or(Instruction::Unallocated, Instruction::CensusGap)
}
