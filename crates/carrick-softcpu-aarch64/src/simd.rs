//! Arm ARM DDI0487 C4.1: register-only Scalar Floating-Point and
//! Advanced SIMD processing. Admit allocated leaves and their operand
//! constraints before handing any word to the native emitter.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimdCompute {
    FloatingPoint,
    AdvancedSimd,
}

pub(crate) fn decode(word: u32) -> Option<SimdCompute> {
    scalar_fp(word).then_some(SimdCompute::FloatingPoint)
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
