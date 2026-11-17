//! Loader leaves, hand-written from the Arm ARM DDI0487G.a PDF.
use crate::{Instruction, MemorySize, OperandRegister};

/// Arm ARM DDI0487G.a C6.2.99–101 LDADD byte, halfword, word and doubleword.
/// `acquire` retains the encoded A bit; effective acquisition also needs Rt != ZR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtomicAdd {
    pub size: MemorySize,
    pub acquire: bool,
    pub release: bool,
    pub source: OperandRegister,
    pub destination: OperandRegister,
    pub base: OperandRegister,
}
impl AtomicAdd {
    pub fn acquires(self) -> bool {
        self.acquire && self.destination != OperandRegister::Zr
    }
}

pub(crate) fn decode(word: u32) -> Option<Instruction> {
    // C6.2.87 ERET. C6.2.88 ERETAA/ERETAB require pointer authentication;
    // the production loader does not emit them, so they remain Unallocated.
    if word & 0x3f20fc00 == 0x38200000 {
        return Some(Instruction::AtomicAdd(AtomicAdd {
            size: match word >> 30 {
                0 => MemorySize::Byte,
                1 => MemorySize::Half,
                2 => MemorySize::Word,
                _ => MemorySize::Double,
            },
            acquire: word & (1 << 23) != 0,
            release: word & (1 << 22) != 0,
            source: OperandRegister::field(word >> 16, false),
            destination: OperandRegister::field(word, false),
            base: OperandRegister::field(word >> 5, true),
        }));
    }
    (word == 0xd69f03e0).then_some(Instruction::Eret)
}
