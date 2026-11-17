//! Loader leaves, hand-written from the Arm ARM DDI0487G.a PDF.
use crate::Instruction;

pub(crate) fn decode(word: u32) -> Option<Instruction> {
    // C6.2.87 ERET. C6.2.88 ERETAA/ERETAB require pointer authentication;
    // the production loader does not emit them, so they remain Unallocated.
    (word == 0xd69f03e0).then_some(Instruction::Eret)
}
