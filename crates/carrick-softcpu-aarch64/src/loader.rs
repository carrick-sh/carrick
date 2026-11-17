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
    if word & 0xfff80000 == 0xd5080000 {
        let op1 = ((word >> 16) & 7) as u8;
        let crn = ((word >> 12) & 15) as u8;
        let crm = ((word >> 8) & 15) as u8;
        let op2 = ((word >> 5) & 7) as u8;
        if let Some(operation) = TlbiOperation::from_fields(op1, crn, crm, op2) {
            return Some(Instruction::SystemOperation(SystemOperation {
                operation, op1, crn, crm, op2,
                rt: OperandRegister::field(word, false),
            }));
        }
    }
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

/// Arm ARM DDI0487G.a C6.2.332 TLBI and C6.2.330 SYS.
/// Exact SYS fields are retained, including Rt for operandless aliases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemOperation {
    pub operation: TlbiOperation,
    pub op1: u8,
    pub crn: u8,
    pub crm: u8,
    pub op2: u8,
    pub rt: OperandRegister,
}

macro_rules! tlbi_operations {
    ($($name:ident = ($op1:literal, $crm:literal, $op2:literal)),* $(,)?) => {
        /// Arm ARM DDI0487G.a C6.2.332, pp. C6-1470–1472.
        /// Includes FEAT_TLBIOS and FEAT_TLBIRANGE names, without claiming execution support.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum TlbiOperation { $($name),* }
        impl TlbiOperation {
            pub fn from_fields(op1: u8, crn: u8, crm: u8, op2: u8) -> Option<Self> {
                if crn != 8 { return None; }
                Some(match (op1, crm, op2) {
                    $(($op1, $crm, $op2) => Self::$name,)*
                    _ => return None,
                })
            }
        }
    };
}
tlbi_operations! {
    Vmalle1is = (0,3,0), Vae1is = (0,3,1), Aside1is = (0,3,2),
    Vaae1is = (0,3,3), Vale1is = (0,3,5), Vaale1is = (0,3,7),
    Vmalle1 = (0,7,0), Vae1 = (0,7,1), Aside1 = (0,7,2),
    Vaae1 = (0,7,3), Vale1 = (0,7,5), Vaale1 = (0,7,7),
    Ipas2e1is = (4,0,1), Ipas2le1is = (4,0,5),
    Alle2is = (4,3,0), Vae2is = (4,3,1), Alle1is = (4,3,4),
    Vale2is = (4,3,5), Vmalls12e1is = (4,3,6),
    Ipas2e1 = (4,4,1), Ipas2le1 = (4,4,5),
    Alle2 = (4,7,0), Vae2 = (4,7,1), Alle1 = (4,7,4),
    Vale2 = (4,7,5), Vmalls12e1 = (4,7,6),
    Alle3is = (6,3,0), Vae3is = (6,3,1), Vale3is = (6,3,5),
    Alle3 = (6,7,0), Vae3 = (6,7,1), Vale3 = (6,7,5),
    Vmalle1os = (0,1,0), Vae1os = (0,1,1), Aside1os = (0,1,2),
    Vaae1os = (0,1,3), Vale1os = (0,1,5), Vaale1os = (0,1,7),
    Alle2os = (4,1,0), Vae2os = (4,1,1), Alle1os = (4,1,4),
    Vale2os = (4,1,5), Vmalls12e1os = (4,1,6),
    Ipas2e1os = (4,4,0), Ipas2le1os = (4,4,4),
    Alle3os = (6,1,0), Vae3os = (6,1,1), Vale3os = (6,1,5),
    Rvae1is = (0,2,1), Rvaae1is = (0,2,3), Rvale1is = (0,2,5), Rvaale1is = (0,2,7),
    Rvae1os = (0,5,1), Rvaae1os = (0,5,3), Rvale1os = (0,5,5), Rvaale1os = (0,5,7),
    Rvae1 = (0,6,1), Rvaae1 = (0,6,3), Rvale1 = (0,6,5), Rvaale1 = (0,6,7),
    Ripas2e1is = (4,0,2), Ripas2le1is = (4,0,6),
    Rvae2is = (4,2,1), Rvale2is = (4,2,5),
    Ripas2e1 = (4,4,2), Ripas2e1os = (4,4,3),
    Ripas2le1 = (4,4,6), Ripas2le1os = (4,4,7),
    Rvae2os = (4,5,1), Rvale2os = (4,5,5),
    Rvae2 = (4,6,1), Rvale2 = (4,6,5),
    Rvae3is = (6,2,1), Rvale3is = (6,2,5),
    Rvae3os = (6,5,1), Rvale3os = (6,5,5),
    Rvae3 = (6,6,1), Rvale3 = (6,6,5),
}
