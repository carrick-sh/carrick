//! The AArch64 VMSAv8-64 stage-1 walk for the EL1&0 translation regime, as
//! a [`Stage1Walker`]: the one architectural CPU walk the soft CPU uses.
//!
//! Authority: Arm ARM DDI0487G.a D5.2 (translation regime, input range,
//! TTBR selection, start level), D5.3 (VMSAv8-64 long descriptors), D5.4
//! (AP, APTable, PXN/UXN, PXNTable/UXNTable, WXN, PAN, UAO and the
//! unprivileged LDTR/STTR access class), D5.8.2-3 (fault levels and
//! priority), D13.2.120 TCR_EL1 and D13.2.116 SCTLR_EL1. No other
//! implementation was consulted.
//!
//! The descriptor encoding constants are the ones this module tree already
//! defines for the production editors (`super::VALID`, `TYPE_*`, `AP_*`,
//! `ACCESS_FLAG`, `NON_GLOBAL`, `UXN`, `PA_MASK_*`): there is one ARM
//! descriptor format in this crate, and this walk decodes it through
//! [`DescriptorFormat::decode`]. Owner and editor walks keep their own
//! software-state policy; they never decide CPU permissions.
//!
//! Profile (admitted by [`Aarch64Regime::new`]; anything else is a typed
//! [`UnsupportedRegime`], never a silent reinterpretation): 4 KiB granule
//! on both ranges, T0SZ/T1SZ in 16..=39, IPS up to 48 bits, software
//! access-flag management (HA=HD=0, so AF=0 faults), no hierarchical
//! permission disables (HPD), no TBID/E0PD/NFD/TCMA/DS/HWU features.
//! FEAT_PAN and FEAT_UAO are implemented; FEAT_PAN3 is not, so
//! SCTLR_EL1.EPAN is RES0 and ignored. Contiguous hints are kept in the
//! leaf and never widen its span.

use carrick_guest_arch::{FrameGpa, GuestVa};

use super::{
    ACCESS_FLAG, AP_EL0_ACCESS, AP_READ_ONLY, NON_GLOBAL, PA_MASK_1GIB, PA_MASK_2MIB, PA_MASK_4KIB,
    PA_MASK_TABLE, TYPE_BITS, TYPE_BLOCK, TYPE_TABLE_OR_PAGE, UXN, VALID,
};
use crate::live_descriptor_words::LiveDescriptorWords;
use crate::stage1::{LeafAccess, LeafSpan, Stage1Leaf, Stage1Walker, WalkError};

/// D5.3.3 block/page PXN, bit 53.
const PXN: u64 = 1 << 53;
/// D5.3.3 contiguous hint, bit 52.
const CONTIGUOUS: u64 = 1 << 52;
/// D5.3.3 AttrIndx[2:0], bits 4:2.
const ATTR_INDEX_SHIFT: u32 = 2;
/// D5.3.3 next-level table attributes (HPD=0): PXNTable 59, UXNTable 60,
/// APTable[0] 61 (no EL0 access), APTable[1] 62 (no write at any EL).
const PXN_TABLE: u64 = 1 << 59;
const UXN_TABLE: u64 = 1 << 60;
const AP_TABLE_NO_EL0: u64 = 1 << 61;
const AP_TABLE_READ_ONLY: u64 = 1 << 62;
/// TTBR BADDR without the start-table alignment: bits 47:1 (bit 0 is CnP).
const TTBR_BADDR: u64 = 0x0000_ffff_ffff_fffe;

/// D13.2.120 TCR_EL1 fields used by this profile.
mod tcr {
    pub const T0SZ_SHIFT: u32 = 0;
    pub const EPD0: u64 = 1 << 7;
    pub const TG0_SHIFT: u32 = 14;
    pub const T1SZ_SHIFT: u32 = 16;
    pub const A1: u64 = 1 << 22;
    pub const EPD1: u64 = 1 << 23;
    pub const TG1_SHIFT: u32 = 30;
    pub const IPS_SHIFT: u32 = 32;
    pub const AS: u64 = 1 << 36;
    pub const TBI0: u64 = 1 << 37;
    pub const TBI1: u64 = 1 << 38;
    pub const HA: u64 = 1 << 39;
    pub const HD: u64 = 1 << 40;
    pub const HPD0: u64 = 1 << 41;
    pub const HPD1: u64 = 1 << 42;
    /// HWU059..HWU162, bits 50:43.
    pub const HWU: u64 = 0xff << 43;
    pub const TBID0: u64 = 1 << 51;
    pub const TBID1: u64 = 1 << 52;
    pub const NFD0: u64 = 1 << 53;
    pub const NFD1: u64 = 1 << 54;
    pub const E0PD0: u64 = 1 << 55;
    pub const E0PD1: u64 = 1 << 56;
    pub const TCMA0: u64 = 1 << 57;
    pub const TCMA1: u64 = 1 << 58;
    pub const DS: u64 = 1 << 59;
    /// TG0 = 0b00 selects the 4 KiB granule.
    pub const TG0_4K: u64 = 0b00;
    /// TG1 = 0b10 selects the 4 KiB granule (a different encoding from TG0).
    pub const TG1_4K: u64 = 0b10;
}

/// D13.2.116 SCTLR_EL1.WXN, bit 19.
const SCTLR_WXN: u64 = 1 << 19;

/// The smallest and largest TnSZ this 4 KiB profile admits: a 48-bit input
/// without FEAT_LVA, down to a 25-bit input without FEAT_TTST.
const MIN_TNSZ: u8 = 16;
const MAX_TNSZ: u8 = 39;

/// A translation-table level of the 4 KiB granule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Aarch64Level {
    L0 = 0,
    L1 = 1,
    L2 = 2,
    L3 = 3,
}

impl Aarch64Level {
    const ALL: [Self; 4] = [Self::L0, Self::L1, Self::L2, Self::L3];

    /// The lowest input-address bit this level's index resolves.
    pub const fn shift(self) -> u32 {
        12 + 9 * (3 - self as u32)
    }

    const fn next(self) -> Option<Self> {
        match self {
            Self::L0 => Some(Self::L1),
            Self::L1 => Some(Self::L2),
            Self::L2 => Some(Self::L3),
            Self::L3 => None,
        }
    }
}

/// One decoded VMSAv8-64 4 KiB-granule descriptor (D5.3.1-3): the single
/// format decode of this crate's architectural walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorFormat {
    /// Bit 0 clear, or a reserved encoding (an L0 block, an L3 type 01).
    Invalid,
    /// A next-level table at L0..=L2.
    Table { next: u64 },
    /// An L1 or L2 block, or an L3 page: output base and size.
    Leaf { base: u64, bytes: u64 },
}

impl DescriptorFormat {
    pub const fn decode(level: Aarch64Level, descriptor: u64) -> Self {
        if descriptor & VALID == 0 {
            return Self::Invalid;
        }
        let kind = descriptor & TYPE_BITS;
        match (level, kind) {
            (Aarch64Level::L3, TYPE_TABLE_OR_PAGE) => Self::Leaf {
                base: descriptor & PA_MASK_4KIB,
                bytes: 1 << 12,
            },
            (Aarch64Level::L3, _) => Self::Invalid,
            (_, TYPE_TABLE_OR_PAGE) => Self::Table {
                next: descriptor & PA_MASK_TABLE,
            },
            (Aarch64Level::L1, TYPE_BLOCK) => Self::Leaf {
                base: descriptor & PA_MASK_1GIB,
                bytes: 1 << 30,
            },
            (Aarch64Level::L2, TYPE_BLOCK) => Self::Leaf {
                base: descriptor & PA_MASK_2MIB,
                bytes: 1 << 21,
            },
            // An L0 block needs a feature (LPA2) this profile lacks.
            _ => Self::Invalid,
        }
    }
}

/// The exception level an access executes at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aarch64El {
    El0,
    El1,
}

/// The instruction class of a data access: an ordinary load/store, or an
/// unprivileged LDTR*/STTR* (D5.4.2-3), which at EL1 with PSTATE.UAO=0 is
/// checked with EL0 permissions (and so is not subject to PAN).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aarch64AccessClass {
    Ordinary,
    Unprivileged,
}

/// Why a TCR_EL1 configuration is outside the admitted profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedRegime {
    /// TG0 or TG1 selects a 16 KiB or 64 KiB granule (`upper` = TTBR1 range).
    Granule { upper: bool, encoding: u8 },
    /// T0SZ or T1SZ outside 16..=39.
    InputSize { upper: bool, tnsz: u8 },
    /// IPS selects 52 bits or a reserved encoding.
    OutputSize { ips: u8 },
    /// A TCR_EL1 feature bit this profile does not implement is set.
    Feature { bits: u64 },
}

/// The VA range a translation uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaRange {
    /// TTBR0_EL1: the lower range.
    Lower,
    /// TTBR1_EL1: the upper range.
    Upper,
}

/// An admitted EL1&0 stage-1 translation regime: TCR_EL1, TTBR0_EL1,
/// TTBR1_EL1 and SCTLR_EL1 as programmed. Construct with [`Self::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aarch64Regime {
    tcr: u64,
    ttbr0: u64,
    ttbr1: u64,
    sctlr: u64,
}

const fn field(value: u64, shift: u32, width: u32) -> u64 {
    (value >> shift) & ((1 << width) - 1)
}

/// TCR_EL1 bits of features this profile does not implement.
const TCR_UNIMPLEMENTED: u64 = tcr::HA
    | tcr::HD
    | tcr::HPD0
    | tcr::HPD1
    | tcr::HWU
    | tcr::TBID0
    | tcr::TBID1
    | tcr::NFD0
    | tcr::NFD1
    | tcr::E0PD0
    | tcr::E0PD1
    | tcr::TCMA0
    | tcr::TCMA1
    | tcr::DS;

impl Aarch64Regime {
    /// Admit a register configuration, or say exactly which part of it this
    /// profile does not implement.
    pub const fn new(
        tcr: u64,
        ttbr0: u64,
        ttbr1: u64,
        sctlr: u64,
    ) -> Result<Self, UnsupportedRegime> {
        if tcr & TCR_UNIMPLEMENTED != 0 {
            return Err(UnsupportedRegime::Feature {
                bits: tcr & TCR_UNIMPLEMENTED,
            });
        }
        let tg0 = field(tcr, tcr::TG0_SHIFT, 2);
        if tg0 != tcr::TG0_4K {
            return Err(UnsupportedRegime::Granule {
                upper: false,
                encoding: tg0 as u8,
            });
        }
        let tg1 = field(tcr, tcr::TG1_SHIFT, 2);
        if tg1 != tcr::TG1_4K {
            return Err(UnsupportedRegime::Granule {
                upper: true,
                encoding: tg1 as u8,
            });
        }
        let t0sz = field(tcr, tcr::T0SZ_SHIFT, 6) as u8;
        if t0sz < MIN_TNSZ || t0sz > MAX_TNSZ {
            return Err(UnsupportedRegime::InputSize {
                upper: false,
                tnsz: t0sz,
            });
        }
        let t1sz = field(tcr, tcr::T1SZ_SHIFT, 6) as u8;
        if t1sz < MIN_TNSZ || t1sz > MAX_TNSZ {
            return Err(UnsupportedRegime::InputSize {
                upper: true,
                tnsz: t1sz,
            });
        }
        let ips = field(tcr, tcr::IPS_SHIFT, 3) as u8;
        if ips > 0b101 {
            return Err(UnsupportedRegime::OutputSize { ips });
        }
        Ok(Self {
            tcr,
            ttbr0,
            ttbr1,
            sctlr,
        })
    }

    pub const fn tcr(&self) -> u64 {
        self.tcr
    }
    pub const fn ttbr0(&self) -> u64 {
        self.ttbr0
    }
    pub const fn ttbr1(&self) -> u64 {
        self.ttbr1
    }
    pub const fn sctlr(&self) -> u64 {
        self.sctlr
    }

    /// The current ASID (D13.2.120, D13.2.131-132): TCR.A1 selects TTBR1's
    /// ASID, and with TCR.AS=0 only its low 8 bits count.
    pub const fn asid(&self) -> u16 {
        let ttbr = if self.tcr & tcr::A1 != 0 {
            self.ttbr1
        } else {
            self.ttbr0
        };
        let asid = (ttbr >> 48) as u16;
        if self.tcr & tcr::AS != 0 {
            asid
        } else {
            asid & 0xff
        }
    }

    /// The physical output size in bits from TCR.IPS (D13.2.120).
    pub const fn output_bits(&self) -> u32 {
        match field(self.tcr, tcr::IPS_SHIFT, 3) {
            0b000 => 32,
            0b001 => 36,
            0b010 => 40,
            0b011 => 42,
            0b100 => 44,
            _ => 48,
        }
    }

    /// TTBR, TnSZ and EPD of one range.
    const fn range_config(&self, range: VaRange) -> (u64, u8, bool) {
        match range {
            VaRange::Lower => (
                self.ttbr0,
                field(self.tcr, tcr::T0SZ_SHIFT, 6) as u8,
                self.tcr & tcr::EPD0 != 0,
            ),
            VaRange::Upper => (
                self.ttbr1,
                field(self.tcr, tcr::T1SZ_SHIFT, 6) as u8,
                self.tcr & tcr::EPD1 != 0,
            ),
        }
    }

    /// The range `va` selects and whether its top byte is ignored (D5.1.4
    /// AddrTop: TBI is chosen by bit 55; with TBI the range bit is 55,
    /// otherwise 63).
    pub const fn select(&self, va: u64) -> (VaRange, bool) {
        let tbi = if va & (1 << 55) != 0 {
            self.tcr & tcr::TBI1 != 0
        } else {
            self.tcr & tcr::TBI0 != 0
        };
        let top = if tbi { 55 } else { 63 };
        let range = if va & (1 << top) != 0 {
            VaRange::Upper
        } else {
            VaRange::Lower
        };
        (range, tbi)
    }
}

/// Everything one access's walk depends on: the regime registers and the
/// PSTATE/instruction facts that select its permission check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aarch64WalkContext {
    pub regime: Aarch64Regime,
    pub el: Aarch64El,
    /// PSTATE.PAN.
    pub pan: bool,
    /// PSTATE.UAO.
    pub uao: bool,
    pub class: Aarch64AccessClass,
}

impl Aarch64WalkContext {
    /// Whether a data access is checked with EL0 permissions (D5.4.3): at
    /// EL0, or an unprivileged LDTR/STTR at EL1 with PSTATE.UAO clear.
    pub const fn checks_as_el0(&self) -> bool {
        match self.el {
            Aarch64El::El0 => true,
            Aarch64El::El1 => matches!(self.class, Aarch64AccessClass::Unprivileged) && !self.uao,
        }
    }
}

/// A stage-1 fault's status class (D13.2.37 DFSC/IFSC).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aarch64FaultKind {
    /// Output or table address above TCR.IPS (FSC 0b0000LL).
    AddressSize,
    /// Out-of-range input, disabled walk, invalid or reserved descriptor
    /// (FSC 0b0001LL).
    Translation,
    /// AF=0 with hardware AF management off (FSC 0b0010LL).
    AccessFlag,
    /// AP, APTable, PXN/UXN, XNTable, WXN or PAN denied (FSC 0b0011LL).
    Permission,
}

/// The exact architectural record of one stage-1 fault: what the exception
/// builder needs for ESR_EL1 (class, level, direction) and FAR_EL1 (the
/// faulting virtual address as the access presented it, tag included).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aarch64Fault {
    pub kind: Aarch64FaultKind,
    pub level: Aarch64Level,
    pub va: GuestVa,
    pub access: LeafAccess,
}

impl Aarch64Fault {
    /// The DFSC/IFSC value (D13.2.37): class base plus level.
    pub const fn status_code(&self) -> u8 {
        let base = match self.kind {
            Aarch64FaultKind::AddressSize => 0x00,
            Aarch64FaultKind::Translation => 0x04,
            Aarch64FaultKind::AccessFlag => 0x08,
            Aarch64FaultKind::Permission => 0x0c,
        };
        base + self.level as u8
    }
}

/// A translated leaf: output, span and the decoded attributes a caller
/// caches or authenticates. Permissions are not part of it: a cache tags
/// an entry by the permission class it was filled for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aarch64Leaf {
    output: FrameGpa,
    span: LeafSpan,
    level: Aarch64Level,
    descriptor: u64,
    range: VaRange,
    asid: u16,
}

impl Aarch64Leaf {
    pub const fn level(&self) -> Aarch64Level {
        self.level
    }
    /// The leaf descriptor exactly as loaded.
    pub const fn descriptor(&self) -> u64 {
        self.descriptor
    }
    pub const fn range(&self) -> VaRange {
        self.range
    }
    /// nG clear: the translation is global, valid for every ASID.
    pub const fn global(&self) -> bool {
        self.descriptor & NON_GLOBAL == 0
    }
    /// The ASID current at the walk (meaningful when not [`Self::global`]).
    pub const fn asid(&self) -> u16 {
        self.asid
    }
    /// MAIR_EL1 attribute index (AttrIndx[2:0]).
    pub const fn attr_index(&self) -> u8 {
        ((self.descriptor >> ATTR_INDEX_SHIFT) & 0b111) as u8
    }
    /// The contiguous hint; never used to widen [`Stage1Leaf::span`].
    pub const fn contiguous_hint(&self) -> bool {
        self.descriptor & CONTIGUOUS != 0
    }
}

impl Stage1Leaf for Aarch64Leaf {
    fn output(&self) -> FrameGpa {
        self.output
    }
    fn span(&self) -> LeafSpan {
        self.span
    }
}

/// The AArch64 EL1&0 stage-1 walker. Stateless: a walk depends only on the
/// [`Aarch64WalkContext`] and the descriptor words.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Aarch64Walker;

/// The hierarchical restrictions a walk accumulated down to its leaf.
#[derive(Clone, Copy, Default)]
struct TableRestrictions {
    no_el0: bool,
    read_only: bool,
    pxn: bool,
    uxn: bool,
}

/// D5.4.4-6: one leaf's access permission with table restrictions folded
/// in.
fn permits(
    context: &Aarch64WalkContext,
    descriptor: u64,
    table: TableRestrictions,
    access: LeafAccess,
) -> bool {
    let el0_access = descriptor & AP_EL0_ACCESS != 0 && !table.no_el0;
    let read_only = descriptor & AP_READ_ONLY != 0 || table.read_only;
    let el0_writable = el0_access && !read_only;
    let el1_writable = !read_only;
    let wxn = context.regime.sctlr & SCTLR_WXN != 0;
    match access {
        LeafAccess::Execute => match context.el {
            // EL0 execution needs no EL0 data permission (execute-only).
            Aarch64El::El0 => !(descriptor & UXN != 0 || table.uxn || (wxn && el0_writable)),
            // EL0-writable memory is never privileged-executable.
            Aarch64El::El1 => {
                !(descriptor & PXN != 0 || table.pxn || el0_writable || (wxn && el1_writable))
            }
        },
        LeafAccess::Read | LeafAccess::Write => {
            let write = access == LeafAccess::Write;
            if context.checks_as_el0() {
                el0_access && (!write || el0_writable)
            } else {
                // PAN (D5.4.2): a privileged data access to EL0-accessible
                // memory faults. LDTR/STTR with UAO=0 never reach here.
                !(context.pan && el0_access) && (!write || el1_writable)
            }
        }
    }
}

impl Stage1Walker for Aarch64Walker {
    type Context = Aarch64WalkContext;
    type Fault = Aarch64Fault;
    type Leaf = Aarch64Leaf;

    fn walk<D: LiveDescriptorWords + ?Sized>(
        &self,
        words: &D,
        context: &Aarch64WalkContext,
        va: GuestVa,
        access: LeafAccess,
    ) -> Result<Aarch64Leaf, WalkError<Aarch64Fault>> {
        let fault = |kind, level| {
            WalkError::Fault(Aarch64Fault {
                kind,
                level,
                va,
                access,
            })
        };
        let regime = &context.regime;
        // RED WITNESS STUB: no architectural walk yet.
        if regime.tcr() != u64::MAX {
            return Err(fault(Aarch64FaultKind::Translation, Aarch64Level::L0));
        }
        let raw = va.raw();
        let (range, tbi) = regime.select(raw);
        let (ttbr, tnsz, disabled) = regime.range_config(range);
        let input_bits = 64 - u32::from(tnsz);
        // Every bit from AddrTop down to the input size must equal the range
        // bit. A failed range check or a disabled walk is a level-0
        // translation fault (D5.2.6, D5.8.2).
        let top = if tbi { 55 } else { 63 };
        let width = top + 1 - input_bits;
        let checked = (raw >> input_bits) & ((1u64 << width) - 1);
        let expected = match range {
            VaRange::Lower => 0,
            VaRange::Upper => (1u64 << width) - 1,
        };
        if checked != expected || disabled {
            return Err(fault(Aarch64FaultKind::Translation, Aarch64Level::L0));
        }
        // D5.2.6: levels resolve 9 input bits each above the 12-bit page
        // offset; the start table holds the remainder.
        let levels = (input_bits - 12).div_ceil(9);
        let start = Aarch64Level::ALL[(4 - levels) as usize];
        let start_bits = input_bits - start.shift();
        let output_limit = 1u64 << context.regime.output_bits();
        // The start table is 2^(start_bits + 3) bytes and aligned to it.
        let mut table = ttbr & TTBR_BADDR & !((1u64 << (start_bits + 3)) - 1);
        if table >= output_limit {
            return Err(fault(Aarch64FaultKind::AddressSize, Aarch64Level::L0));
        }
        let mut restrictions = TableRestrictions::default();
        let mut level = start;
        loop {
            let index_bits = if level == start { start_bits } else { 9 };
            let index = (raw >> level.shift()) & ((1u64 << index_bits) - 1);
            let descriptor = words.load(table + index * 8).map_err(WalkError::Refusal)?;
            match DescriptorFormat::decode(level, descriptor) {
                DescriptorFormat::Invalid => {
                    return Err(fault(Aarch64FaultKind::Translation, level));
                }
                DescriptorFormat::Table { next } => {
                    if next >= output_limit {
                        return Err(fault(Aarch64FaultKind::AddressSize, level));
                    }
                    restrictions.pxn |= descriptor & PXN_TABLE != 0;
                    restrictions.uxn |= descriptor & UXN_TABLE != 0;
                    restrictions.no_el0 |= descriptor & AP_TABLE_NO_EL0 != 0;
                    restrictions.read_only |= descriptor & AP_TABLE_READ_ONLY != 0;
                    table = next;
                    // L3 never decodes as a table.
                    let Some(next_level) = level.next() else {
                        return Err(fault(Aarch64FaultKind::Translation, level));
                    };
                    level = next_level;
                }
                DescriptorFormat::Leaf { base, bytes } => {
                    if base >= output_limit {
                        return Err(fault(Aarch64FaultKind::AddressSize, level));
                    }
                    if descriptor & ACCESS_FLAG == 0 {
                        return Err(fault(Aarch64FaultKind::AccessFlag, level));
                    }
                    if !permits(context, descriptor, restrictions, access) {
                        return Err(fault(Aarch64FaultKind::Permission, level));
                    }
                    let Some(span) = LeafSpan::new(FrameGpa::new(base), bytes) else {
                        return Err(fault(Aarch64FaultKind::Translation, level));
                    };
                    return Ok(Aarch64Leaf {
                        output: FrameGpa::new(base | (raw & (bytes - 1))),
                        span,
                        level,
                        descriptor,
                        range,
                        asid: regime.asid(),
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
