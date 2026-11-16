//! Conservative, hand-authored A64 instruction census, not a decoder or CPU.
//! Source: Arm ARM DDI0487, A64 instruction set encoding, "Index by
//! encoding" (Data Processing -- Immediate/Register, Loads and Stores,
//! Branches, Exception Generating and System, Data Processing -- SIMD/FP).
//! No machine-readable collateral or third-party decoder tables are used.
//! Recognized subsets are deliberately narrow; extensions not checked here
//! remain Unknown. Membership does not imply that execution is implemented.
#![no_std]
#![forbid(unsafe_code)]

/// MRS/MSR encoding fields, preserving the architectural namespace exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SystemRegister {
    pub op0: u8,
    pub op1: u8,
    pub crn: u8,
    pub crm: u8,
    pub op2: u8,
}
impl SystemRegister {
    fn from_word(w: u32) -> Self {
        Self {
            op0: ((w >> 19) & 3) as u8,
            op1: ((w >> 16) & 7) as u8,
            crn: ((w >> 12) & 15) as u8,
            crm: ((w >> 8) & 15) as u8,
            op2: ((w >> 5) & 7) as u8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum A64Class {
    Unknown,
    Arithmetic,
    Logical,
    Bitfield,
    MoveWide,
    Multiply,
    Divide,
    ConditionalSelect,
    ConditionalCompare,
    Address,
    Literal,
    Branch,
    Call,
    Return,
    ScalarLoadStore,
    PairLoadStore,
    AcquireRelease,
    Exclusive,
    LseAtomic,
    Barrier,
    Svc,
    Hvc,
    Mrs(SystemRegister),
    Msr(SystemRegister),
    Pstate,
    Eret,
    Tlbi,
    Dc,
    Ic,
    Wfi,
    Wfe,
    Sev,
    Hint,
    SimdFpLoadStore,
    SimdFpCompute,
}

/// Classify only encoding leaves whose reserved fields are checked below.
/// Each block cites the named encoding-index subgroup in DDI0487's
/// "A64 instruction set encoding"; these are architectural encoding masks,
/// not tables transcribed from another implementation.
pub fn classify(w: u32) -> A64Class {
    use A64Class::{
        AcquireRelease, Address, Arithmetic, Barrier, Bitfield, Branch, Call, ConditionalCompare,
        ConditionalSelect, Dc, Divide, Eret, Exclusive, Hint, Hvc, Ic, Literal, Logical, LseAtomic,
        MoveWide, Mrs, Msr, Multiply, PairLoadStore, Pstate, Return, ScalarLoadStore, Sev,
        SimdFpCompute, SimdFpLoadStore, Svc, Tlbi, Unknown, Wfe, Wfi,
    };
    // Branches, Exception Generating and System: exception generation,
    // unconditional branch (register/immediate), compare/test/conditional.
    if w & 0xffe0001f == 0xd4000001 {
        return Svc;
    }
    if w & 0xffe0001f == 0xd4000002 {
        return Hvc;
    }
    if w == 0xd69f03e0 {
        return Eret;
    }
    match w & 0xfffffc1f {
        0xd61f0000 => return Branch,
        0xd63f0000 => return Call,
        0xd65f0000 => return Return,
        _ => {}
    }
    if w & 0x7c000000 == 0x14000000 {
        return if w >> 31 == 0 { Branch } else { Call };
    }
    if w & 0xff000010 == 0x54000000 || w & 0x7e000000 == 0x34000000 || w & 0x7e000000 == 0x36000000
    {
        return Branch;
    }
    // System: exact architectural hints and barriers, system register move.
    match w {
        0xd503201f => return Hint,
        0xd503205f => return Wfe,
        0xd503207f => return Wfi,
        0xd503209f | 0xd50320bf => return Sev,
        0xd503203f => return Hint,
        _ => {}
    }
    let barrier = w & 0xfffff0ff;
    if (barrier == 0xd503309f || barrier == 0xd50330bf)
        && matches!((w >> 8) & 15, 1..=3 | 5..=7 | 9..=11 | 13..=15)
        || w == 0xd5033fdf
    {
        return Barrier;
    }
    if w & 0xffd00000 == 0xd5100000 {
        let reg = SystemRegister::from_word(w);
        return if w & (1 << 21) != 0 {
            Mrs(reg)
        } else {
            Msr(reg)
        };
    }
    // MSR (immediate), DAIFSet/DAIFClr only.
    if matches!(w & 0xfffff0ff, 0xd50340df | 0xd50340ff) {
        return Pstate;
    }
    // SYS: bounded EL1 maintenance operations actually used by the carrier.
    // Unknown SYS/SYSL operations are never promoted to maintenance classes.
    if matches!(w, 0xd508831f | 0xd508871f)
        || matches!(w & 0xffffffe0, 0xd5088340 | 0xd5088350 | 0xd5088320)
    {
        return Tlbi;
    }
    if matches!(
        w & 0xffffffe0,
        0xd50b7420 | 0xd50b7a20 | 0xd50b7b20 | 0xd50b7e20
    ) {
        return Dc;
    }
    if w == 0xd508751f || w == 0xd508711f || w & 0xffffffe0 == 0xd50b7520 {
        return Ic;
    }
    // Data Processing -- Immediate: PC-relative, add/subtract, move wide,
    // bitfield/extract, logical immediate (reject reserved bitmask lengths).
    if w & 0x1f000000 == 0x10000000 {
        return Address;
    }
    if w & 0x1f800000 == 0x11000000 {
        return Arithmetic;
    }
    if w & 0x1f800000 == 0x12800000 && (w >> 29) & 3 != 1 && (w >> 31 != 0 || (w >> 21) & 3 < 2) {
        return MoveWide;
    }
    if w & 0x1f800000 == 0x13000000
        && (w >> 29) & 3 != 3
        && (w >> 22) & 1 == w >> 31
        && (w >> 31 != 0 || w & 0x00208000 == 0)
    {
        return Bitfield;
    }
    if w & 0x7fa00000 == 0x13800000 && (w >> 22) & 1 == w >> 31 && (w >> 31 != 0 || w & 0x8000 == 0)
    {
        return Bitfield;
    }
    if w & 0x1f800000 == 0x12000000 {
        let n = (w >> 22) & 1;
        let imms = (w >> 10) & 63;
        let length_bits = (n << 6) | ((!imms) & 63);
        if length_bits >= 2 && (w >> 31 != 0 || n == 0) {
            let len = 31 - length_bits.leading_zeros();
            if imms & ((1 << len) - 1) != (1 << len) - 1 {
                return Logical;
            }
        }
    }
    // Data Processing -- Register: shifted/extended add, logical shifted,
    // carry, conditional compare/select, multiply, two-source divide.
    if w & 0x1f200000 == 0x0b000000 && (w >> 22) & 3 != 3 && (w >> 31 != 0 || w & 0x8000 == 0) {
        return Arithmetic;
    }
    if w & 0x1fe00000 == 0x0b200000 && (w >> 10) & 7 <= 4 {
        return Arithmetic;
    }
    if w & 0x1fe0fc00 == 0x1a000000 {
        return Arithmetic;
    }
    if w & 0x1f000000 == 0x0a000000 && (w >> 31 != 0 || w & 0x8000 == 0) {
        return Logical;
    }
    if w & 0x3fe00800 == 0x1a800000 {
        return ConditionalSelect;
    }
    if w & 0x3fe00410 == 0x3a400000 {
        return ConditionalCompare;
    }
    if w & 0x7fe0f800 == 0x1ac00800 {
        return Divide;
    }
    if w & 0x7fe00000 == 0x1b000000 {
        return Multiply;
    }
    if matches!(w & 0xffe00000, 0x9b200000 | 0x9ba00000)
        || matches!(w & 0xffe0fc00, 0x9b407c00 | 0x9bc07c00)
    {
        return Multiply;
    }
    // Loads and Stores: literal, pair, unsigned offset, unscaled/pre/post,
    // register offset. Reject reserved opc/size combinations before grouping.
    let v = w & (1 << 26) != 0;
    let size = w >> 30;
    let opc = (w >> 22) & 3;
    let valid_scalar = opc < 2 || (opc == 2 && size < 3) || (opc == 3 && size < 2);
    if w & 0x3b000000 == 0x18000000 && (w >> 30 != 3 || !v) {
        return if v { SimdFpLoadStore } else { Literal };
    }
    if w & 0x3a000000 == 0x28000000
        && (if v {
            size < 3
        } else {
            size == 0 || size == 2 || (size == 1 && w & (1 << 22) != 0 && (w >> 23) & 3 != 0)
        })
    {
        return if v { SimdFpLoadStore } else { PairLoadStore };
    }
    let valid_mem = if v {
        opc < 2 || size == 0
    } else {
        valid_scalar
    };
    if valid_mem
        && (w & 0x3b000000 == 0x39000000
            || (w & 0x3b200000 == 0x38000000 && (!v || (w >> 10) & 3 != 2))
            || (w & 0x3b200c00 == 0x38200800 && matches!((w >> 13) & 7, 2 | 3 | 6 | 7)))
    {
        return if v { SimdFpLoadStore } else { ScalarLoadStore };
    }
    // Exclusive/acquire-release: single register base encodings only.
    if w & 0x3fa07c00 == 0x08807c00 && (w >> 16) & 31 == 31 {
        return AcquireRelease;
    }
    if w & 0x3fa07c00 == 0x08007c00 && (w & (1 << 22) == 0 || (w >> 16) & 31 == 31) {
        return Exclusive;
    }
    // Atomic memory operations: LDADD..LDUMIN and SWP, excluding reserved opcodes.
    if w & 0x3f200c00 == 0x38200000 && (w >> 12) & 15 <= 8 {
        return LseAtomic;
    }
    // SIMD/FP: scalar floating-point two-source arithmetic, single/double.
    // Wider NEON families intentionally remain Unknown until individually checked.
    if w & 0xff200c00 == 0x1e200800 && (w >> 22) & 3 < 2 && (w >> 12) & 15 <= 8 {
        return SimdFpCompute;
    }
    Unknown
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::{A64Class, SystemRegister, classify};
    #[test]
    fn reserved_span_fails_closed() {
        let words = [0xd503201f, 0xffff_ffff];
        let unknown: std::vec::Vec<_> = words
            .into_iter()
            .enumerate()
            .filter(|(_, word)| classify(*word) == A64Class::Unknown)
            .collect();
        assert_eq!(unknown, [(1, 0xffff_ffff)]);
    }
    #[test]
    fn independently_reserved_encodings() {
        for word in [
            0,
            0xffff_ffff,
            0x91800000,
            0x52c00000,
            0x93000000,
            0x1200fc00,
            0x0bc00000,
            0x0a008000,
            0x9ac00000,
            0xd5033cdf,
            0x7c000800,
            0x68400000,
            0x3e202800,
        ] {
            assert_eq!(classify(word), A64Class::Unknown, "{word:08x}");
        }
    }
    #[test]
    fn known_words() {
        use A64Class::{
            AcquireRelease, Address, Arithmetic, Barrier, Bitfield, Branch, Call,
            ConditionalCompare, ConditionalSelect, Dc, Divide, Eret, Exclusive, Hint, Hvc, Ic,
            Literal, Logical, LseAtomic, MoveWide, Mrs, Msr, Multiply, PairLoadStore, Pstate,
            Return, ScalarLoadStore, Sev, SimdFpCompute, SimdFpLoadStore, Svc, Tlbi, Wfe, Wfi,
        };
        for (word, class) in [
            (0x91000400, Arithmetic),
            (0xaa0103e0, Logical),
            (0xd340fc00, Bitfield),
            (0xd2800020, MoveWide),
            (0x9b017c00, Multiply),
            (0x9ac10800, Divide),
            (0x9a810000, ConditionalSelect),
            (0xfa410000, ConditionalCompare),
            (0x90000000, Address),
            (0x58000000, Literal),
            (0x14000000, Branch),
            (0x94000000, Call),
            (0xd65f03c0, Return),
            (0xf9400000, ScalarLoadStore),
            (0xf8408400, ScalarLoadStore), // ldr x0, [x0], #8
            (0xf8008c00, ScalarLoadStore), // str x0, [x0, #8]!
            (0xd61f0000, Branch),
            (0xd63f0000, Call),
            (0x54000000, Branch),
            (0x34000000, Branch),
            (0x36000000, Branch),
            (0xa9bf7bfd, PairLoadStore),
            (0xc8dffc00, AcquireRelease),
            (0xc85f7c00, Exclusive),
            (0xf8200020, LseAtomic),
            (0xd5033f9f, Barrier),
            (0xd4000001, Svc),
            (0xd4000022, Hvc),
            (0xd69f03e0, Eret),
            (0xd508831f, Tlbi),
            (0xd50b7b20, Dc),
            (0xd50b7520, Ic),
            (0xd503207f, Wfi),
            (0xd503205f, Wfe),
            (0xd503209f, Sev),
            (0xd503201f, Hint),
            (0x3dc00000, SimdFpLoadStore),
            (0x1e602800, SimdFpCompute),
            (0xd5034fdf, Pstate),
        ] {
            assert_eq!(classify(word), class, "{word:08x}");
        }
        let reg = SystemRegister {
            op0: 3,
            op1: 0,
            crn: 2,
            crm: 0,
            op2: 0,
        };
        assert_eq!(classify(0xd5382000), Mrs(reg));
        assert_eq!(classify(0xd5182000), Msr(reg));
    }
}
