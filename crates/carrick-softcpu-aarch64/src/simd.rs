//! Arm ARM DDI0487 C4.1: register-only Scalar Floating-Point and
//! Advanced SIMD processing. Admit allocated leaves and their operand
//! constraints before handing any word to the native emitter.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimdCompute {
    FloatingPoint,
    AdvancedSimd,
}

pub(crate) fn decode(word: u32) -> Option<SimdCompute> {
    if scalar_fp(word) {
        return Some(SimdCompute::FloatingPoint);
    }
    vector_simd(word).then_some(SimdCompute::AdvancedSimd)
}

fn scalar_fp(word: u32) -> bool {
    // The integer conversions repurpose M as sf. The other scalar groups
    // require M=0. All baseline forms have S=0 and bit 30 clear.
    if word & 0x7e00_0000 != 0x1e00_0000 {
        return false;
    }
    let ftype = (word >> 22) & 3;
    let sf = word >> 31;
    let rmode_opcode = (word >> 16) & 31;
    if word & 0x0120_fc00 == 0x0020_0000 {
        // Floating-point <-> integer, including FMOV between register banks.
        return match (ftype, rmode_opcode) {
            (0 | 1, 0..=5 | 8 | 9 | 16 | 17 | 24 | 25) => true,
            (0 | 1, 6 | 7) => sf == ftype,
            (2, 14 | 15) => sf == 1, // FMOV upper D lane
            _ => false,
        };
    }
    if word & 0x0120_0000 == 0 {
        // Floating-point <-> fixed-point. W forms require scale<5> = 1.
        return ftype <= 1
            && matches!(rmode_opcode, 2 | 3 | 24 | 25)
            && (sf == 1 || word & (1 << 15) != 0);
    }
    if sf != 0 {
        return false;
    }
    if word & 0x0100_0000 != 0 {
        return ftype <= 1; // fused three-source arithmetic
    }
    if word & 0x7c00 == 0x4000 {
        let opcode = (word >> 15) & 63;
        // Half-precision conversion is baseline FEAT_FP, unlike FP16
        // arithmetic. Same-precision FCVT and FP16/BF16/FRINTTS leaves fail.
        return matches!(
            (ftype, opcode),
            (0 | 1, 0..=3 | 7..=12 | 14 | 15) | (0, 5) | (1, 4) | (3, 4 | 5)
        );
    }
    if ftype > 1 {
        return false;
    }
    match word & 0xc00 {
        0x400 | 0xc00 => true,                         // FCCMP, FCCMPE and FCSEL
        0x800 => (word >> 12) & 15 <= 8,               // two-source arithmetic
        _ if word & 0xfc00 == 0x2000 => word & 7 == 0, // FCMP / FCMPE
        _ => word & 0x13e0 == 0x1000,                  // FMOV immediate
    }
}

fn vector_simd(word: u32) -> bool {
    let q = (word >> 30) & 1;
    let u = (word >> 29) & 1;
    let size = (word >> 22) & 3;
    match word & 0x9f20_0400 {
        // Advanced SIMD three same. Size is an integer arrangement or an
        // FP opcode high bit and precision bit depending on the leaf.
        0x0e20_0400 => vector_three_same(q, u, size, (word >> 11) & 31),
        0x0e20_0000 => match word & 0x001e_0c00 {
            0x0000_0800 => vector_misc(q, u, size, (word >> 12) & 31),
            0x0010_0800 => vector_reduction(q, u, size, (word >> 12) & 31),
            _ if word & 0xc00 == 0 => vector_three_different(u, size, (word >> 12) & 15),
            _ => false,
        },
        0x0e00_0000 if u == 0 && word & 0x8000 == 0 => {
            match word & 0x0c00 {
                0 => size == 0, // TBL/TBX, any table length
                0x800 => !matches!((word >> 12) & 7, 0 | 4) && (q == 1 || size < 3),
                _ => false,
            }
        }
        0x0e00_0000 if u == 1 => {
            // EXT: Q=0 reserves imm4[3].
            size == 0 && word & 0x8000 == 0 && (q == 1 || word & 0x4000 == 0)
        }
        0x0e00_0400 if size == 0 && word & 0x8000 == 0 => vector_copy(q, u, word),
        0x1e00_0400 if q == 1 && u == 0 && size == 0 && word & 0xf800 == 0 => {
            // DUP (element) to scalar. The source lane is independent of Q.
            ((word >> 16) & 31).trailing_zeros() < 4
        }
        0x0f00_0400 if word & 0x00f8_0000 == 0 => {
            // Modified immediate; o2=1 requires FP16.
            word & 0x800 == 0 && (q == 1 || u == 0 || (word >> 12) & 15 != 15)
        }
        0x1e20_0400 if q == 1 => scalar_three_same(u, size, (word >> 11) & 31),
        0x1e20_0000 if q == 1 => match word & 0x001e_0c00 {
            0x0000_0800 => scalar_misc(u, size, (word >> 12) & 31),
            0x0010_0800 => {
                let opcode = (word >> 12) & 31;
                matches!(
                    (u, size, opcode),
                    (0, 3, 27) | (1, _, 12 | 15) | (1, 0 | 1, 13)
                )
            }
            _ => {
                word & 0xc00 == 0
                    && u == 0
                    && matches!(size, 1 | 2)
                    && matches!((word >> 12) & 15, 9 | 11 | 13)
            }
        },
        0x0f00_0400 | 0x0f20_0400 | 0x1f00_0400 | 0x1f20_0400
            if word & 0x8000_0000 == 0 && word & (1 << 23) == 0 =>
        {
            let scalar = word & (1 << 28) != 0;
            (!scalar || q == 1) && simd_shift(q, u, scalar, (word >> 19) & 15, (word >> 11) & 31)
        }
        0x0f00_0000 | 0x0f20_0000 | 0x1f00_0000 | 0x1f20_0000 => {
            let scalar = word & (1 << 28) != 0;
            (!scalar || q == 1) && simd_indexed(word, q, u, size, scalar)
        }
        _ => false,
    }
}

fn vector_copy(q: u32, u: u32, word: u32) -> bool {
    let size = ((word >> 16) & 31).trailing_zeros();
    let imm4 = (word >> 11) & 15;
    if size > 3 {
        return false;
    }
    match (u, imm4) {
        (0, 0 | 1) => q == 1 || size < 3,            // DUP
        (0, 3) | (1, _) => q == 1,                   // INS
        (0, 5) => size < 2 || (q == 1 && size == 2), // SMOV
        (0, 7) => (q == 1) == (size == 3),           // UMOV
        _ => false,
    }
}

fn vector_three_same(q: u32, u: u32, size: u32, opcode: u32) -> bool {
    match opcode {
        // Logical ops use size as an opcode extension.
        3 => true,
        1 | 5..=11 | 16 | 17 => q == 1 || size < 3,
        0 | 2 | 4 | 12..=15 | 18 | 20 | 21 => size < 3,
        19 if u == 1 => size == 0, // PMUL
        19 => size < 3,            // MUL
        22 => matches!(size, 1 | 2),
        23 => u == 0 && (q == 1 || size < 3),
        _ if q == 0 && size & 1 != 0 => false, // no double-precision 1D form
        24 | 26 | 30 => true,
        25 => u == 0,
        27 => size < 2,
        28 => u == 1 || size < 2,
        29 => u == 1,
        31 => u == 0 || size < 2,
        _ => false,
    }
}

fn vector_three_different(u: u32, size: u32, opcode: u32) -> bool {
    match (u, opcode) {
        (0, 9 | 11 | 13) => matches!(size, 1 | 2),
        (0, 14) => size == 0, // PMULL of bytes; 64-bit polynomial requires FEAT_PMULL
        (0, 0..=13) | (1, 0..=8 | 10 | 12) => size < 3,
        _ => false,
    }
}

fn vector_misc(q: u32, u: u32, size: u32, opcode: u32) -> bool {
    match (u, opcode) {
        (0, 0) => size < 3,      // REV64
        (1, 0) => size < 2,      // REV32
        (0, 1 | 5) => size == 0, // REV16, CNT
        (1, 5) => size <= 1,     // NOT, RBIT
        (_, 2 | 4 | 6 | 18 | 20) | (1, 19) => size < 3,
        (_, 3 | 7..=9 | 11) | (0, 10) => q == 1 || size < 3,
        (0, 22 | 23) => size <= 1, // FCVTN, FCVTL
        (1, 22) => size == 1,      // FCVTXN
        (0, 12..=15) | (1, 12 | 13 | 15) => size >= 2 && (q == 1 || size == 2),
        (_, 25..=27 | 29) | (0, 24) => q == 1 || size & 1 == 0,
        (1, 24) => size < 2 && (q == 1 || size == 0),
        (_, 28) => size == 0 || (size == 1 && q == 1) || size == 2, // FCVT{A}, URECPE/URSQRTE (only 32-bit)
        (1, 31) => size >= 2 && (q == 1 || size == 2),
        _ => false,
    }
}

fn vector_reduction(q: u32, u: u32, size: u32, opcode: u32) -> bool {
    match (u, opcode) {
        (_, 3 | 10 | 26) | (0, 27) => size < 3 && (q == 1 || size < 2),
        (1, 12 | 15) => q == 1 && size & 1 == 0,
        _ => false,
    }
}

fn scalar_three_same(u: u32, size: u32, opcode: u32) -> bool {
    match (u, opcode) {
        (_, 1 | 5 | 9 | 11) => true,
        (_, 6..=8 | 10 | 16 | 17) => size == 3,
        (_, 22) => matches!(size, 1 | 2),
        (0, 27 | 28) => size < 2,
        (0, 31) | (1, 28 | 29) => true,
        (1, 26) => size >= 2,
        _ => false,
    }
}

fn scalar_misc(u: u32, size: u32, opcode: u32) -> bool {
    match (u, opcode) {
        (_, 3 | 7) => true,
        (_, 8 | 9 | 11) | (0, 10) => size == 3,
        (0, 12..=14 | 31) | (1, 12 | 13) => size >= 2,
        (1, 18) | (_, 20) => size < 3,
        (1, 22) => size == 1,
        (_, 26 | 27 | 29) => true,
        (_, 28) => size < 2,
        _ => false,
    }
}

fn simd_shift(q: u32, u: u32, scalar: bool, immh: u32, opcode: u32) -> bool {
    if immh == 0 {
        return false;
    }
    let double = immh >= 8;
    let full_lane = if scalar { double } else { q == 1 || !double };
    match (u, opcode) {
        (_, 0 | 2 | 4 | 6 | 10) | (1, 8) => full_lane,
        (_, 14) | (1, 12) => scalar || full_lane,
        (_, 18 | 19) | (1, 16 | 17) => !double,
        (0, 16 | 17) | (_, 20) => !scalar && !double,
        (_, 28 | 31) => immh >= 4 && (scalar || full_lane),
        _ => false,
    }
}

fn simd_indexed(word: u32, q: u32, u: u32, size: u32, scalar: bool) -> bool {
    let opcode = (word >> 12) & 15;
    let l = word & (1 << 21) != 0;
    match (u, opcode) {
        (0, 1 | 5 | 9) | (1, 9) => size == 2 || (size == 3 && q == 1 && !l),
        (0, 3 | 7 | 11..=13) => matches!(size, 1 | 2),
        (0, 2 | 6 | 8 | 10) | (1, 0 | 2 | 4 | 6 | 10) => !scalar && matches!(size, 1 | 2),
        _ => false,
    }
}
