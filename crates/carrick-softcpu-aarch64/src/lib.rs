//! Conservative, hand-authored A64 instruction census and partial operand decoder, not a CPU.
//! Source: Arm ARM DDI0487, A64 instruction set encoding, "Index by
//! encoding" (Data Processing -- Immediate/Register, Loads and Stores,
//! Branches, Exception Generating and System, Data Processing -- SIMD/FP).
//! No machine-readable collateral or third-party decoder tables are used.
//! Recognized subsets are deliberately narrow; extensions not checked here
//! remain Unknown. Membership does not imply that execution is implemented.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod closure {
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
    fn barrier(w: u32) -> Option<Instruction> {
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

    /// Architectural system-register identity. The original census fields remain
    /// available through `encoding`; names never discard or alias that identity.
    /// DDI0487G.a C6.2.194 MRS, C6.2.196 MSR (register), C4.1.3
    /// System register move; D13 AArch64 System Register Descriptions.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum NamedSystemRegister {
        /// DDI0487G.a D13.2.135 TTBR0_EL1.
        Ttbr0El1,
        /// DDI0487G.a D13.2.138 TTBR1_EL1.
        Ttbr1El1,
        /// DDI0487G.a C5.2.11 SP_EL0.
        SpEl0,
        /// DDI0487G.a D13.2.130 TPIDR_EL0.
        TpidrEl0,
        /// DDI0487G.a D13.2.134 TPIDRRO_EL0.
        TpidrroEl0,
        /// DDI0487G.a D13.2.28 CONTEXTIDR_EL1.
        ContextidrEl1,
        /// DDI0487G.a C5.2.7 FPCR.
        Fpcr,
        /// DDI0487G.a C5.2.8 FPSR.
        Fpsr,
        /// DDI0487G.a C5.2.2 DAIF.
        Daif,
        /// DDI0487G.a C5.2.10 PAN.
        Pan,
        /// DDI0487G.a D13.2.103 PAR_EL1.
        ParEl1,
        /// DDI0487G.a D13.8.1 CNTFRQ_EL0.
        CntfrqEl0,
        /// DDI0487G.a D13.8.29 CNTVCT_EL0.
        CntvctEl0,
        /// DDI0487G.a D13.8.25 CNTV_CTL_EL0.
        CntvCtlEl0,
        /// DDI0487G.a D13.8.26 CNTV_CVAL_EL0.
        CntvCvalEl0,
        /// DDI0487G.a D13.2.99 MPIDR_EL1.
        MpidrEl1,
        /// DDI0487G.a D12.3 Table D12-2, system-register encodings (GIC register space).
        IccIar1El1,
        /// DDI0487G.a D12.3 Table D12-2, system-register encodings (GIC register space).
        IccEoir1El1,
        /// DDI0487G.a D12.3 Table D12-2, system-register encodings (GIC register space).
        IccSgi1rEl1,
        Unnamed(crate::SystemRegister),
    }
    impl NamedSystemRegister {
        pub fn from_encoding(r: crate::SystemRegister) -> Self {
            match (r.op0, r.op1, r.crn, r.crm, r.op2) {
                (3, 0, 2, 0, 0) => Self::Ttbr0El1,
                (3, 0, 2, 0, 1) => Self::Ttbr1El1,
                (3, 0, 4, 1, 0) => Self::SpEl0,
                (3, 3, 13, 0, 2) => Self::TpidrEl0,
                (3, 3, 13, 0, 3) => Self::TpidrroEl0,
                (3, 0, 13, 0, 1) => Self::ContextidrEl1,
                (3, 3, 4, 4, 0) => Self::Fpcr,
                (3, 3, 4, 4, 1) => Self::Fpsr,
                (3, 3, 4, 2, 1) => Self::Daif,
                (3, 0, 4, 2, 3) => Self::Pan,
                (3, 0, 7, 4, 0) => Self::ParEl1,
                (3, 3, 14, 0, 0) => Self::CntfrqEl0,
                (3, 3, 14, 0, 2) => Self::CntvctEl0,
                (3, 3, 14, 3, 1) => Self::CntvCtlEl0,
                (3, 3, 14, 3, 2) => Self::CntvCvalEl0,
                (3, 0, 0, 0, 5) => Self::MpidrEl1,
                (3, 0, 12, 12, 0) => Self::IccIar1El1,
                (3, 0, 12, 12, 1) => Self::IccEoir1El1,
                (3, 0, 12, 11, 5) => Self::IccSgi1rEl1,
                _ => Self::Unnamed(r),
            }
        }
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SystemDirection {
        Read,
        Write,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SystemAccess {
        pub direction: SystemDirection,
        pub encoding: crate::SystemRegister,
        pub register: NamedSystemRegister,
        pub rt: crate::OperandRegister,
    }
    /// DDI0487G.a C6.2.195 MSR (immediate); C4.1.3 PSTATE encoding index.
    /// Feature-dependent fields are decoded, without asserting execution support.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PstateField {
        SpSel,
        DaifSet,
        DaifClr,
        Pan,
        Uao,
        Dit,
        Ssbs,
        Tco,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PstateImmediate {
        pub field: PstateField,
        pub immediate: u8,
    }
    fn system(w: u32) -> Option<Instruction> {
        if w & 0xffd00000 == 0xd5100000 {
            let encoding = crate::SystemRegister::from_word(w);
            return Some(Instruction::SystemAccess(SystemAccess {
                direction: if w & (1 << 21) != 0 {
                    SystemDirection::Read
                } else {
                    SystemDirection::Write
                },
                register: NamedSystemRegister::from_encoding(encoding),
                encoding,
                rt: crate::OperandRegister::field(w, false),
            }));
        }
        if w & 0xfff8f01f != 0xd500401f {
            return None;
        }
        let field = match ((w >> 16) & 7, (w >> 5) & 7) {
            (0, 3) => PstateField::Uao,
            (0, 4) => PstateField::Pan,
            (0, 5) => PstateField::SpSel,
            (3, 1) => PstateField::Ssbs,
            (3, 2) => PstateField::Dit,
            (3, 4) => PstateField::Tco,
            (3, 6) => PstateField::DaifSet,
            (3, 7) => PstateField::DaifClr,
            _ => return None,
        };
        Some(Instruction::PstateImmediate(PstateImmediate {
            field,
            immediate: ((w >> 8) & 15) as u8,
        }))
    }
    pub(crate) fn decode(w: u32) -> Option<Instruction> {
        barrier(w)
            .or_else(|| system(w))
            .or_else(|| exception(w))
            .or_else(|| extract(w))
    }

    /// DDI0487G.a C6.2.38 BRK, C6.2.76–78 DCPS1/2/3, C6.2.93 HLT,
    /// C6.2.94 HVC, C6.2.241 SMC, C6.2.321 SVC;
    /// C4.1.3 Exception generation encoding index, pp. C4-286–287.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ExceptionKind {
        Svc,
        Hvc,
        Smc,
        Brk,
        Hlt,
        Dcps1,
        Dcps2,
        Dcps3,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ExceptionGeneration {
        pub kind: ExceptionKind,
        pub immediate: u16,
    }
    fn exception(w: u32) -> Option<Instruction> {
        let kind = match w & 0xffe0001f {
            0xd4000001 => ExceptionKind::Svc,
            0xd4000002 => ExceptionKind::Hvc,
            0xd4000003 => ExceptionKind::Smc,
            0xd4200000 => ExceptionKind::Brk,
            0xd4400000 => ExceptionKind::Hlt,
            0xd4a00001 => ExceptionKind::Dcps1,
            0xd4a00002 => ExceptionKind::Dcps2,
            0xd4a00003 => ExceptionKind::Dcps3,
            _ => return None,
        };
        Some(Instruction::ExceptionGeneration(ExceptionGeneration {
            kind,
            immediate: ((w >> 5) & 0xffff) as u16,
        }))
    }

    /// DDI0487G.a C6.2.90 EXTR; C4.1.2 Extract encoding index.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Extract {
        pub width: crate::Width,
        pub rm: crate::OperandRegister,
        pub rn: crate::OperandRegister,
        pub rd: crate::OperandRegister,
        pub lsb: u8,
    }
    fn extract(w: u32) -> Option<Instruction> {
        if w & 0x7fa00000 != 0x13800000
            || (w >> 22) & 1 != w >> 31
            || (w >> 31 == 0 && w & 0x8000 != 0)
        {
            return None;
        }
        Some(Instruction::Extract(Extract {
            width: if w >> 31 == 0 {
                crate::Width::W32
            } else {
                crate::Width::X64
            },
            rm: crate::OperandRegister::field(w >> 16, false),
            rn: crate::OperandRegister::field(w >> 5, false),
            rd: crate::OperandRegister::field(w, false),
            lsb: ((w >> 10) & 63) as u8,
        }))
    }
}
pub use closure::{
    Barrier, BarrierAccess, BarrierDomain, BarrierKind, ExceptionGeneration, ExceptionKind,
    Extract, NamedSystemRegister, PstateField, PstateImmediate, SystemAccess, SystemDirection,
};

mod decode {
    //! Hand-written leaves from Arm ARM DDI0487, A64 encoding index.
    //! This is decoding only: no instruction is executed on the host.

    /// Architectural general-purpose register number; 31 denotes ZR here, not SP.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Register(u8);
    impl Register {
        pub const fn number(self) -> u8 {
            self.0
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Immediate16(u16);
    impl Immediate16 {
        /// Preserve a complete architectural 16-bit immediate field.
        pub const fn new(value: u16) -> Self {
            Self(value)
        }
        pub const fn value(self) -> u16 {
            self.0
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ExclusiveOption(u8);
    impl ExclusiveOption {
        pub(crate) const fn from_option(value: u8) -> Self {
            Self(value)
        }
        pub const fn value(self) -> u8 {
            self.0
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Width {
        W32,
        X64,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Shift {
        Lsl,
        Lsr,
        Asr,
        Ror,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Unary {
        Rbit,
        Rev16,
        Rev32,
        Rev64,
        Clz,
        Cls,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Translation {
        S1E1R,
        S1E1W,
        S1E0R,
        S1E0W,
        S1E2R,
        S1E2W,
        S12E1R,
        S12E1W,
        S12E0R,
        S12E0W,
        S1E3R,
        S1E3W,
        S1E1Rp,
        S1E1Wp,
    }
    /// Operands of the supported leaves. Other existing census classes have no
    /// operand decoder yet and return None from `decode`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Decoded {
        VariableShift {
            width: Width,
            op: Shift,
            rm: Register,
            rn: Register,
            rd: Register,
        },
        OneSource {
            width: Width,
            op: Unary,
            rn: Register,
            rd: Register,
        },
        Breakpoint {
            immediate: Immediate16,
        },
        ClearExclusive {
            option: ExclusiveOption,
        },
        AddressTranslate {
            op: Translation,
            xt: Register,
        },
    }

    /// Arm ARM DDI0487G.a, "A64 instruction set encoding", Data-processing
    /// (2 source), pp. C4-329–330; Data-processing (1 source), pp. C4-330–331;
    /// Exception generation (BRK), pp. C4-286–287; Barriers (CLREX), p. C4-289; and "A64 system instructions for address
    /// translation" tables.
    /// Only baseline AT forms plus FEAT_PAN2 RP/WP are admitted here;
    /// TLBI uses loader::decode exclusively.
    pub fn decode(w: u32) -> Option<Decoded> {
        let rd = Register((w & 31) as u8);
        let rn = Register(((w >> 5) & 31) as u8);
        let width = if w >> 31 == 0 { Width::W32 } else { Width::X64 };
        // sf and Rm are variable; S is fixed zero. Bits 15:10 select
        // LSLV/LSRV/ASRV/RORV; all other two-source opcodes are outside this leaf.
        if w & 0x7fe0f000 == 0x1ac02000 {
            let op = match (w >> 10) & 3 {
                0 => Shift::Lsl,
                1 => Shift::Lsr,
                2 => Shift::Asr,
                _ => Shift::Ror,
            };
            return Some(Decoded::VariableShift {
                width,
                op,
                rm: Register(((w >> 16) & 31) as u8),
                rn,
                rd,
            });
        }
        // opcode2 (20:16) and S must be zero. REV64 is unallocated at sf=0;
        // opcode=2 denotes REV W at sf=0 and REV32 X at sf=1.
        if w & 0x7fff0000 == 0x5ac00000 {
            let op = match (w >> 10) & 63 {
                0 => Unary::Rbit,
                1 => Unary::Rev16,
                2 => Unary::Rev32,
                3 if width == Width::X64 => Unary::Rev64,
                4 => Unary::Clz,
                5 => Unary::Cls,
                _ => return None,
            };
            return Some(Decoded::OneSource { width, op, rn, rd });
        }
        if w & 0xffe0001f == 0xd4200000 {
            return Some(Decoded::Breakpoint {
                immediate: Immediate16(((w >> 5) & 0xffff) as u16),
            });
        }
        if w & 0xfffff0ff == 0xd503305f {
            return Some(Decoded::ClearExclusive {
                option: ExclusiveOption(((w >> 8) & 15) as u8),
            });
        }
        // SYS: fixed L=0, op0=01, CRn=7; explicitly enumerate allocated AT
        // op1:CRm:op2 tuples instead of treating all SYS as translations.
        if w & 0xfff8f000 == 0xd5087000 {
            let op = match ((w >> 16) & 7, (w >> 8) & 15, (w >> 5) & 7) {
                (0, 8, 0) => Translation::S1E1R,
                (0, 8, 1) => Translation::S1E1W,
                (0, 8, 2) => Translation::S1E0R,
                (0, 8, 3) => Translation::S1E0W,
                (4, 8, 0) => Translation::S1E2R,
                (4, 8, 1) => Translation::S1E2W,
                (4, 8, 4) => Translation::S12E1R,
                (4, 8, 5) => Translation::S12E1W,
                (4, 8, 6) => Translation::S12E0R,
                (4, 8, 7) => Translation::S12E0W,
                (6, 8, 0) => Translation::S1E3R,
                (6, 8, 1) => Translation::S1E3W,
                (0, 9, 0) => Translation::S1E1Rp,
                (0, 9, 1) => Translation::S1E1Wp,
                _ => return None,
            };
            return Some(Decoded::AddressTranslate { op, xt: rd });
        }
        None
    }
}
pub use decode::{
    Decoded, ExclusiveOption, Immediate16, Register, Shift, Translation, Unary, Width, decode,
};

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
    VariableShift,
    CountLeadingBits,
    ReverseBits,
    Breakpoint,
    ClearExclusive,
    AddressTranslate,
    TlbInvalidate,
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
    if let Some(decoded) = decode(w) {
        return match decoded {
            Decoded::VariableShift { .. } => A64Class::VariableShift,
            Decoded::OneSource {
                op: Unary::Clz | Unary::Cls,
                ..
            } => A64Class::CountLeadingBits,
            Decoded::OneSource { .. } => A64Class::ReverseBits,
            Decoded::Breakpoint { .. } => A64Class::Breakpoint,
            Decoded::ClearExclusive { .. } => A64Class::ClearExclusive,
            Decoded::AddressTranslate { .. } => A64Class::AddressTranslate,
        };
    }
    // Preserve the original census bucket for the 320 EL1 VA/ASID words,
    // using the one typed TLBI decoder (C6.2.332).
    if let Some(Instruction::SystemOperation(op)) = loader::decode(w)
        && matches!(
            op.operation,
            TlbiOperation::Vae1is
                | TlbiOperation::Aside1is
                | TlbiOperation::Vaae1is
                | TlbiOperation::Vale1is
                | TlbiOperation::Vaale1is
                | TlbiOperation::Vae1
                | TlbiOperation::Aside1
                | TlbiOperation::Vaae1
                | TlbiOperation::Vale1
                | TlbiOperation::Vaale1
        )
    {
        return A64Class::TlbInvalidate;
    }
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
    if matches!(w, 0xd508831f | 0xd508871f) {
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

mod loader {
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
                    operation,
                    op1,
                    crn,
                    crm,
                    op2,
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

    /// Arm ARM DDI0487G.a C6.2.332 TLBI and C6.2.328 SYS.
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

    /// Arm ARM DDI0487G.a C6.2.332, pp. C6-1470–1472.
    /// Includes FEAT_TLBIOS and FEAT_TLBIRANGE without claiming execution support.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TlbiOperation {
        Vmalle1is,
        Vae1is,
        Aside1is,
        Vaae1is,
        Vale1is,
        Vaale1is,
        Vmalle1,
        Vae1,
        Aside1,
        Vaae1,
        Vale1,
        Vaale1,
        Ipas2e1is,
        Ipas2le1is,
        Alle2is,
        Vae2is,
        Alle1is,
        Vale2is,
        Vmalls12e1is,
        Ipas2e1,
        Ipas2le1,
        Alle2,
        Vae2,
        Alle1,
        Vale2,
        Vmalls12e1,
        Alle3is,
        Vae3is,
        Vale3is,
        Alle3,
        Vae3,
        Vale3,
        Vmalle1os,
        Vae1os,
        Aside1os,
        Vaae1os,
        Vale1os,
        Vaale1os,
        Alle2os,
        Vae2os,
        Alle1os,
        Vale2os,
        Vmalls12e1os,
        Ipas2e1os,
        Ipas2le1os,
        Alle3os,
        Vae3os,
        Vale3os,
        Rvae1is,
        Rvaae1is,
        Rvale1is,
        Rvaale1is,
        Rvae1os,
        Rvaae1os,
        Rvale1os,
        Rvaale1os,
        Rvae1,
        Rvaae1,
        Rvale1,
        Rvaale1,
        Ripas2e1is,
        Ripas2le1is,
        Rvae2is,
        Rvale2is,
        Ripas2e1,
        Ripas2e1os,
        Ripas2le1,
        Ripas2le1os,
        Rvae2os,
        Rvale2os,
        Rvae2,
        Rvale2,
        Rvae3is,
        Rvale3is,
        Rvae3os,
        Rvale3os,
        Rvae3,
        Rvale3,
    }
    impl TlbiOperation {
        pub fn from_fields(op1: u8, crn: u8, crm: u8, op2: u8) -> Option<Self> {
            if crn != 8 {
                return None;
            }
            Some(match (op1, crm, op2) {
                (0, 3, 0) => Self::Vmalle1is,
                (0, 3, 1) => Self::Vae1is,
                (0, 3, 2) => Self::Aside1is,
                (0, 3, 3) => Self::Vaae1is,
                (0, 3, 5) => Self::Vale1is,
                (0, 3, 7) => Self::Vaale1is,
                (0, 7, 0) => Self::Vmalle1,
                (0, 7, 1) => Self::Vae1,
                (0, 7, 2) => Self::Aside1,
                (0, 7, 3) => Self::Vaae1,
                (0, 7, 5) => Self::Vale1,
                (0, 7, 7) => Self::Vaale1,
                (4, 0, 1) => Self::Ipas2e1is,
                (4, 0, 5) => Self::Ipas2le1is,
                (4, 3, 0) => Self::Alle2is,
                (4, 3, 1) => Self::Vae2is,
                (4, 3, 4) => Self::Alle1is,
                (4, 3, 5) => Self::Vale2is,
                (4, 3, 6) => Self::Vmalls12e1is,
                (4, 4, 1) => Self::Ipas2e1,
                (4, 4, 5) => Self::Ipas2le1,
                (4, 7, 0) => Self::Alle2,
                (4, 7, 1) => Self::Vae2,
                (4, 7, 4) => Self::Alle1,
                (4, 7, 5) => Self::Vale2,
                (4, 7, 6) => Self::Vmalls12e1,
                (6, 3, 0) => Self::Alle3is,
                (6, 3, 1) => Self::Vae3is,
                (6, 3, 5) => Self::Vale3is,
                (6, 7, 0) => Self::Alle3,
                (6, 7, 1) => Self::Vae3,
                (6, 7, 5) => Self::Vale3,
                (0, 1, 0) => Self::Vmalle1os,
                (0, 1, 1) => Self::Vae1os,
                (0, 1, 2) => Self::Aside1os,
                (0, 1, 3) => Self::Vaae1os,
                (0, 1, 5) => Self::Vale1os,
                (0, 1, 7) => Self::Vaale1os,
                (4, 1, 0) => Self::Alle2os,
                (4, 1, 1) => Self::Vae2os,
                (4, 1, 4) => Self::Alle1os,
                (4, 1, 5) => Self::Vale2os,
                (4, 1, 6) => Self::Vmalls12e1os,
                (4, 4, 0) => Self::Ipas2e1os,
                (4, 4, 4) => Self::Ipas2le1os,
                (6, 1, 0) => Self::Alle3os,
                (6, 1, 1) => Self::Vae3os,
                (6, 1, 5) => Self::Vale3os,
                (0, 2, 1) => Self::Rvae1is,
                (0, 2, 3) => Self::Rvaae1is,
                (0, 2, 5) => Self::Rvale1is,
                (0, 2, 7) => Self::Rvaale1is,
                (0, 5, 1) => Self::Rvae1os,
                (0, 5, 3) => Self::Rvaae1os,
                (0, 5, 5) => Self::Rvale1os,
                (0, 5, 7) => Self::Rvaale1os,
                (0, 6, 1) => Self::Rvae1,
                (0, 6, 3) => Self::Rvaae1,
                (0, 6, 5) => Self::Rvale1,
                (0, 6, 7) => Self::Rvaale1,
                (4, 0, 2) => Self::Ripas2e1is,
                (4, 0, 6) => Self::Ripas2le1is,
                (4, 2, 1) => Self::Rvae2is,
                (4, 2, 5) => Self::Rvale2is,
                (4, 4, 2) => Self::Ripas2e1,
                (4, 4, 3) => Self::Ripas2e1os,
                (4, 4, 6) => Self::Ripas2le1,
                (4, 4, 7) => Self::Ripas2le1os,
                (4, 5, 1) => Self::Rvae2os,
                (4, 5, 5) => Self::Rvale2os,
                (4, 6, 1) => Self::Rvae2,
                (4, 6, 5) => Self::Rvale2,
                (6, 2, 1) => Self::Rvae3is,
                (6, 2, 5) => Self::Rvale3is,
                (6, 5, 1) => Self::Rvae3os,
                (6, 5, 5) => Self::Rvale3os,
                (6, 6, 1) => Self::Rvae3,
                (6, 6, 5) => Self::Rvale3,
                _ => return None,
            })
        }
    }
}
pub use loader::{AtomicAdd, SystemOperation, TlbiOperation};

mod instruction {
    //! Typed decoding entry point. Unimplemented and reserved leaves fail shut.
    use crate::Decoded;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Instruction {
        Unallocated,
        /// Arm ARM DDI0487G.a C6.2.87 ERET (no pointer authentication).
        Eret,
        AtomicAdd(crate::AtomicAdd),
        SystemOperation(crate::SystemOperation),
        Barrier(crate::Barrier),
        ExceptionGeneration(crate::ExceptionGeneration),
        SystemAccess(crate::SystemAccess),
        PstateImmediate(crate::PstateImmediate),
        CensusGap(Decoded),
        Hint(Hint),
        Arithmetic(Arithmetic),
        Branch(Branch),
        ScalarMemory(ScalarMemory),
        UnprivilegedMemory(ScalarMemory),
        Extract(crate::Extract),
        PairMemory(PairMemory),
        Logical(Logical),
        MoveWide(MoveWide),
        Bitfield(Bitfield),
        Address(Address),
        Multiply(Multiply),
        Divide(Divide),
        AtomicTransfer(AtomicTransfer),
        ConditionalSelect(ConditionalSelect),
        ConditionalCompare(ConditionalCompare),
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
        if let Some(instruction) = crate::loader::decode(word) {
            return instruction;
        }
        if let Some(instruction) = crate::closure::decode(word) {
            return instruction;
        }
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

        if let Some(a) = arithmetic(word) {
            return Instruction::Arithmetic(a);
        }
        if let Some(b) = branch(word) {
            return Instruction::Branch(b);
        }
        if let Some(m) = scalar_memory(word).or_else(|| literal_memory(word)) {
            return if word & 0x3f200c00 == 0x38000800 {
                Instruction::UnprivilegedMemory(m)
            } else {
                Instruction::ScalarMemory(m)
            };
        }
        if let Some(m) = pair_memory(word) {
            return Instruction::PairMemory(m);
        }
        if let Some(l) = logical(word) {
            return Instruction::Logical(l);
        }
        if let Some(m) = move_wide(word) {
            return Instruction::MoveWide(m);
        }
        if let Some(b) = bitfield(word) {
            return Instruction::Bitfield(b);
        }
        if let Some(a) = address(word) {
            return Instruction::Address(a);
        }
        if let Some(c) = conditional_select(word) {
            return Instruction::ConditionalSelect(c);
        }
        if let Some(c) = conditional_compare(word) {
            return Instruction::ConditionalCompare(c);
        }
        if let Some(m) = multiply(word) {
            return Instruction::Multiply(m);
        }
        if let Some(d) = divide(word) {
            return Instruction::Divide(d);
        }
        if let Some(a) = atomic_transfer(word) {
            return Instruction::AtomicTransfer(a);
        }
        crate::decode(word).map_or(Instruction::Unallocated, Instruction::CensusGap)
    }

    /// Transfer size in bytes (including the SIMD 128-bit form).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum MemorySize {
        Byte,
        Half,
        Word,
        Double,
        Quad,
    }
    impl MemorySize {
        pub const fn bytes(self) -> u8 {
            match self {
                Self::Byte => 1,
                Self::Half => 2,
                Self::Word => 4,
                Self::Double => 8,
                Self::Quad => 16,
            }
        }
        fn scale(scale: u32) -> Option<Self> {
            Some(match scale {
                0 => Self::Byte,
                1 => Self::Half,
                2 => Self::Word,
                3 => Self::Double,
                4 => Self::Quad,
                _ => return None,
            })
        }
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct VectorRegister(u8);
    impl VectorRegister {
        pub const fn number(self) -> u8 {
            self.0
        }
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum MemoryRegister {
        Integer {
            register: OperandRegister,
            width: crate::Width,
        },
        Vector(VectorRegister),
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum MemoryOperation {
        Store,
        Load,
        LoadSigned,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum MemoryIndex {
        Offset,
        Pre,
        Post,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MemoryOffset(i32);
    impl MemoryOffset {
        pub const fn bytes(self) -> i32 {
            self.0
        }
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum MemoryAddress {
        Immediate {
            base: OperandRegister,
            offset: MemoryOffset,
            index: MemoryIndex,
            unscaled: bool,
        },
        Register {
            base: OperandRegister,
            offset: OperandRegister,
            extend: Extend,
            scaled: bool,
        },
        Literal(PcOffset),
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ScalarMemory {
        pub operation: MemoryOperation,
        pub size: MemorySize,
        pub register: MemoryRegister,
        pub address: MemoryAddress,
    }

    /// DDI0487G.a C6.2.132/134 LDR, C6.2.136–146 LDRB/H/SB/SH/SW,
    /// C6.2.168–173 LDUR/B/H/SB/SH/SW, C6.2.278–283 STR/B/H;
    /// C7.2.191/193/194 LDR/LDUR and C7.2.331/332 STR (SIMD&FP).
    /// Encoding index C4.1.4, pp. C4-312–317, C4-325–327:
    /// unscaled, pre/post-indexed, register offset, unsigned immediate.
    /// C6.2.156–161 LDTR/B/H/SB/SH/SW, C6.2.293–295 STTR/B/H;
    /// C4.1.4 Load/store register (unprivileged) encoding index.
    /// Unprivileged forms share the offset decode and have a distinct Instruction.
    /// Prefetch forms are deliberately unsupported.
    fn scalar_memory(w: u32) -> Option<ScalarMemory> {
        if w & 0x3b000000 != 0x39000000 && w & 0x3b000000 != 0x38000000 {
            return None;
        }
        let size = w >> 30;
        let opc = (w >> 22) & 3;
        let vector = w & (1 << 26) != 0;
        let scale = if vector {
            size | ((opc >> 1) << 2)
        } else {
            size
        };
        let size = MemorySize::scale(scale)?;
        let operation = if vector || opc < 2 {
            if opc & 1 != 0 {
                MemoryOperation::Load
            } else {
                MemoryOperation::Store
            }
        } else {
            if scale == 3 || (scale == 2 && opc == 3) {
                return None;
            }
            MemoryOperation::LoadSigned
        };
        let register = if vector {
            MemoryRegister::Vector(VectorRegister((w & 31) as u8))
        } else {
            MemoryRegister::Integer {
                register: OperandRegister::field(w, false),
                width: if (opc == 2) || scale == 3 {
                    crate::Width::X64
                } else {
                    crate::Width::W32
                },
            }
        };
        let base = OperandRegister::field(w >> 5, true);
        let address = if w & (1 << 24) != 0 {
            MemoryAddress::Immediate {
                base,
                offset: MemoryOffset((((w >> 10) & 4095) << scale) as i32),
                index: MemoryIndex::Offset,
                unscaled: false,
            }
        } else if w & (1 << 21) != 0 {
            if w & 0xc00 != 0x800 {
                return None;
            }
            let extend = match (w >> 13) & 7 {
                2 => Extend::Uxtw,
                3 => Extend::Uxtx,
                6 => Extend::Sxtw,
                7 => Extend::Sxtx,
                _ => return None,
            };
            MemoryAddress::Register {
                base,
                offset: OperandRegister::field(w >> 16, false),
                extend,
                scaled: w & 0x1000 != 0,
            }
        } else {
            let index = match (w >> 10) & 3 {
                0 => MemoryIndex::Offset,
                2 if !vector => MemoryIndex::Offset,
                1 => MemoryIndex::Post,
                3 => MemoryIndex::Pre,
                _ => return None,
            };
            MemoryAddress::Immediate {
                base,
                offset: MemoryOffset(((w << 11) as i32) >> 23),
                index,
                unscaled: index == MemoryIndex::Offset,
            }
        };
        Some(ScalarMemory {
            operation,
            size,
            register,
            address,
        })
    }

    /// DDI0487G.a C6.2.133 LDR (literal), C6.2.145 LDRSW (literal),
    /// C7.2.192 LDR (literal, SIMD&FP); C4.1.4 Load register (literal), C4-309.
    fn literal_memory(w: u32) -> Option<ScalarMemory> {
        if w & 0x3b000000 != 0x18000000 {
            return None;
        }
        let opc = w >> 30;
        if opc == 3 {
            return None;
        }
        let vector = w & (1 << 26) != 0;
        let size = MemorySize::scale(if vector {
            opc + 2
        } else if opc == 1 {
            3
        } else {
            2
        })?;
        Some(ScalarMemory {
            operation: if !vector && opc == 2 {
                MemoryOperation::LoadSigned
            } else {
                MemoryOperation::Load
            },
            size,
            register: if vector {
                MemoryRegister::Vector(VectorRegister((w & 31) as u8))
            } else {
                MemoryRegister::Integer {
                    register: OperandRegister::field(w, false),
                    width: if opc == 0 {
                        crate::Width::W32
                    } else {
                        crate::Width::X64
                    },
                }
            },
            address: MemoryAddress::Literal(PcOffset((((w << 8) as i32) >> 13) as i64 * 4)),
        })
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PairMemory {
        pub operation: MemoryOperation,
        pub size: MemorySize,
        pub first: MemoryRegister,
        pub second: MemoryRegister,
        pub base: OperandRegister,
        pub offset: MemoryOffset,
        pub index: MemoryIndex,
        pub non_temporal: bool,
    }

    /// DDI0487G.a C6.2.129–131 LDNP/LDP/LDPSW, C6.2.276/277 STNP/STP;
    /// C7.2.189/190 LDNP/LDP and C7.2.329/330 STNP/STP (SIMD&FP).
    /// Encoding index C4.1.4, Load/store no-allocate pair and register pair,
    /// offset/pre/post-indexed, pp. C4-309–312. MTE STGP is unsupported.
    fn pair_memory(w: u32) -> Option<PairMemory> {
        if w & 0x3a000000 != 0x28000000 {
            return None;
        }
        let opc = w >> 30;
        let vector = w & (1 << 26) != 0;
        let load = w & (1 << 22) != 0;
        let mode = (w >> 23) & 3;
        if opc == 3 || (!vector && opc == 1 && (!load || mode == 0)) {
            return None;
        }
        let scale = if vector { opc + 2 } else { 2 + (opc >> 1) };
        let register = |bits| {
            if vector {
                MemoryRegister::Vector(VectorRegister((bits & 31) as u8))
            } else {
                MemoryRegister::Integer {
                    register: OperandRegister::field(bits, false),
                    width: if opc == 0 {
                        crate::Width::W32
                    } else {
                        crate::Width::X64
                    },
                }
            }
        };
        Some(PairMemory {
            operation: if !load {
                MemoryOperation::Store
            } else if !vector && opc == 1 {
                MemoryOperation::LoadSigned
            } else {
                MemoryOperation::Load
            },
            size: MemorySize::scale(scale)?,
            first: register(w),
            second: register(w >> 10),
            base: OperandRegister::field(w >> 5, true),
            offset: MemoryOffset((((w << 10) as i32) >> 25) << scale),
            index: match mode {
                1 => MemoryIndex::Post,
                3 => MemoryIndex::Pre,
                _ => MemoryIndex::Offset,
            },
            non_temporal: mode == 0,
        })
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum LogicalOperation {
        And,
        Orr,
        Eor,
        Ands,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct LogicalImmediate(u64);
    impl LogicalImmediate {
        pub const fn value(self) -> u64 {
            self.0
        }
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum LogicalOperand {
        Immediate(LogicalImmediate),
        Shifted {
            rm: OperandRegister,
            shift: crate::Shift,
            amount: ShiftAmount,
            invert: bool,
        },
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Logical {
        pub width: crate::Width,
        pub operation: LogicalOperation,
        pub rd: OperandRegister,
        pub rn: OperandRegister,
        pub operand: LogicalOperand,
    }
    /// DDI0487G.a C6.2.12/14 AND/ANDS, C6.2.85 EOR, C6.2.206 ORR (immediate);
    /// C4.1.2 Logical (immediate), C4-282–283; J1 DecodeBitMasks, J1-7953–7954.
    /// Derive the element length, reject reserved all-ones, rotate and replicate.
    fn logical_immediate(w: u32) -> Option<LogicalOperand> {
        if w & 0x1f800000 != 0x12000000 {
            return None;
        }
        let n = (w >> 22) & 1;
        if w >> 31 == 0 && n != 0 {
            return None;
        }
        let s = (w >> 10) & 63;
        let combined = (n << 6) | ((!s) & 63);
        if combined < 2 {
            return None;
        }
        let length = 31 - combined.leading_zeros();
        let size = 1u32 << length;
        let levels = size - 1;
        let s = s & levels;
        if s == levels {
            return None;
        }
        let r = (w >> 16) & levels;
        let ones = (1u64 << (s + 1)) - 1;
        let element_mask = u64::MAX >> (64 - size);
        let element = if r == 0 {
            ones
        } else {
            (ones >> r | ones << (size - r)) & element_mask
        };
        let width = if w >> 31 == 0 { 32 } else { 64 };
        let mut mask = 0;
        let mut position = 0;
        while position < width {
            mask |= element << position;
            position += size;
        }
        Some(LogicalOperand::Immediate(LogicalImmediate(mask)))
    }
    /// DDI0487G.a C6.2.13/15 AND/ANDS, C6.2.31/32 BIC/BICS,
    /// C6.2.84/86 EON/EOR, C6.2.205/207 ORN/ORR (shifted register);
    /// C4.1.5 Logical (shifted register), C4-332.
    fn logical_shifted(w: u32) -> Option<LogicalOperand> {
        if w & 0x1f000000 != 0x0a000000 || (w >> 31 == 0 && w & 0x8000 != 0) {
            return None;
        }
        Some(LogicalOperand::Shifted {
            rm: OperandRegister::field(w >> 16, false),
            shift: match (w >> 22) & 3 {
                0 => crate::Shift::Lsl,
                1 => crate::Shift::Lsr,
                2 => crate::Shift::Asr,
                _ => crate::Shift::Ror,
            },
            amount: ShiftAmount(((w >> 10) & 63) as u8),
            invert: w & (1 << 21) != 0,
        })
    }
    fn logical(w: u32) -> Option<Logical> {
        let operand = logical_immediate(w).or_else(|| logical_shifted(w))?;
        let operation = match (w >> 29) & 3 {
            0 => LogicalOperation::And,
            1 => LogicalOperation::Orr,
            2 => LogicalOperation::Eor,
            _ => LogicalOperation::Ands,
        };
        Some(Logical {
            width: if w >> 31 == 0 {
                crate::Width::W32
            } else {
                crate::Width::X64
            },
            operation,
            rd: OperandRegister::field(
                w,
                matches!(operand, LogicalOperand::Immediate(_))
                    && operation != LogicalOperation::Ands,
            ),
            rn: OperandRegister::field(w >> 5, false),
            operand,
        })
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum MoveWideOperation {
        Not,
        Zero,
        Keep,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MoveWide {
        pub operation: MoveWideOperation,
        pub width: crate::Width,
        pub rd: OperandRegister,
        pub immediate: u16,
        pub shift: ShiftAmount,
    }
    /// DDI0487G.a C6.2.191 MOVK, C6.2.192 MOVN, C6.2.193 MOVZ;
    /// C4.1.2 Move wide (immediate), C4-283–284.
    fn move_wide(w: u32) -> Option<MoveWide> {
        if w & 0x1f800000 != 0x12800000 || (w >> 31 == 0 && w & (1 << 22) != 0) {
            return None;
        }
        let operation = match (w >> 29) & 3 {
            0 => MoveWideOperation::Not,
            2 => MoveWideOperation::Zero,
            3 => MoveWideOperation::Keep,
            _ => return None,
        };
        Some(MoveWide {
            operation,
            width: if w >> 31 == 0 {
                crate::Width::W32
            } else {
                crate::Width::X64
            },
            rd: OperandRegister::field(w, false),
            immediate: ((w >> 5) & 65535) as u16,
            shift: ShiftAmount((((w >> 21) & 3) * 16) as u8),
        })
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum BitfieldOperation {
        Signed,
        Merge,
        Unsigned,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Bitfield {
        pub operation: BitfieldOperation,
        pub width: crate::Width,
        pub rd: OperandRegister,
        pub rn: OperandRegister,
        pub rotate: ShiftAmount,
        pub last: ShiftAmount,
    }
    /// DDI0487G.a C6.2.29 BFM, C6.2.234 SBFM, C6.2.337 UBFM;
    /// C4.1.2 Bitfield, C4-284. Preserve immr/imms for wraparound inserts.
    fn bitfield(w: u32) -> Option<Bitfield> {
        if w & 0x1f800000 != 0x13000000 {
            return None;
        }
        let sf = w >> 31;
        if ((w >> 22) & 1) != sf || (sf == 0 && w & 0x208000 != 0) {
            return None;
        }
        let operation = match (w >> 29) & 3 {
            0 => BitfieldOperation::Signed,
            1 => BitfieldOperation::Merge,
            2 => BitfieldOperation::Unsigned,
            _ => return None,
        };
        Some(Bitfield {
            operation,
            width: if sf == 0 {
                crate::Width::W32
            } else {
                crate::Width::X64
            },
            rd: OperandRegister::field(w, false),
            rn: OperandRegister::field(w >> 5, false),
            rotate: ShiftAmount(((w >> 16) & 63) as u8),
            last: ShiftAmount(((w >> 10) & 63) as u8),
        })
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum AddressBase {
        Pc,
        Page,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Address {
        pub base: AddressBase,
        pub rd: OperandRegister,
        pub offset: PcOffset,
    }
    /// DDI0487G.a C6.2.10 ADR, C6.2.11 ADRP;
    /// C4.1.2 PC-rel. addressing, C4-281. ADRP aligns PC before adding offset.
    fn address(w: u32) -> Option<Address> {
        if w & 0x1f000000 != 0x10000000 {
            return None;
        }
        let page = w >> 31 != 0;
        let imm = ((w >> 5) & 0x7ffff) << 2 | ((w >> 29) & 3);
        let offset = ((imm << 11) as i32 >> 11) as i64;
        Some(Address {
            base: if page {
                AddressBase::Page
            } else {
                AddressBase::Pc
            },
            rd: OperandRegister::field(w, false),
            offset: PcOffset(if page { offset << 12 } else { offset }),
        })
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum SelectOperation {
        Select,
        Increment,
        Invert,
        Negate,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ConditionalSelect {
        pub width: crate::Width,
        pub operation: SelectOperation,
        pub rd: OperandRegister,
        pub rn: OperandRegister,
        pub rm: OperandRegister,
        pub condition: Condition,
    }
    /// DDI0487G.a C6.2.69 CSEL, C6.2.72–74 CSINC/CSINV/CSNEG;
    /// C4.1.5 Conditional select, C4-336–337.
    fn conditional_select(w: u32) -> Option<ConditionalSelect> {
        if w & 0x3fe00800 != 0x1a800000 {
            return None;
        }
        Some(ConditionalSelect {
            width: if w >> 31 == 0 {
                crate::Width::W32
            } else {
                crate::Width::X64
            },
            operation: match ((w >> 29) & 2) | ((w >> 10) & 1) {
                0 => SelectOperation::Select,
                1 => SelectOperation::Increment,
                2 => SelectOperation::Invert,
                _ => SelectOperation::Negate,
            },
            rd: OperandRegister::field(w, false),
            rn: OperandRegister::field(w >> 5, false),
            rm: OperandRegister::field(w >> 16, false),
            condition: Condition::field(w >> 12),
        })
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CompareImmediate(u8);
    impl CompareImmediate {
        pub const fn value(self) -> u8 {
            self.0
        }
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Nzcv(u8);
    impl Nzcv {
        pub const fn bits(self) -> u8 {
            self.0
        }
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum CompareOperand {
        Register(OperandRegister),
        Immediate(CompareImmediate),
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ConditionalCompare {
        pub width: crate::Width,
        pub operation: AddSubtract,
        pub rn: OperandRegister,
        pub operand: CompareOperand,
        pub condition: Condition,
        pub otherwise: Nzcv,
    }
    /// DDI0487G.a C6.2.46–49 CCMN/CCMP (immediate/register);
    /// C4.1.5 Conditional compare (register/immediate), C4-335–336.
    fn conditional_compare(w: u32) -> Option<ConditionalCompare> {
        if w & 0x3fe00410 != 0x3a400000 {
            return None;
        }
        Some(ConditionalCompare {
            width: if w >> 31 == 0 {
                crate::Width::W32
            } else {
                crate::Width::X64
            },
            operation: if w & (1 << 30) == 0 {
                AddSubtract::Add
            } else {
                AddSubtract::Subtract
            },
            rn: OperandRegister::field(w >> 5, false),
            operand: if w & 0x800 == 0 {
                CompareOperand::Register(OperandRegister::field(w >> 16, false))
            } else {
                CompareOperand::Immediate(CompareImmediate(((w >> 16) & 31) as u8))
            },
            condition: Condition::field(w >> 12),
            otherwise: Nzcv((w & 15) as u8),
        })
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum MultiplyKind {
        SameWidth,
        SignedLong,
        UnsignedLong,
        SignedHigh,
        UnsignedHigh,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Multiply {
        pub kind: MultiplyKind,
        pub width: crate::Width,
        pub subtract: bool,
        pub rd: OperandRegister,
        pub rn: OperandRegister,
        pub rm: OperandRegister,
        pub accumulator: Option<OperandRegister>,
    }
    /// DDI0487G.a C6.2.184/197 MADD/MSUB, C6.2.240/243 SMADDL/SMSUBL,
    /// C6.2.341/343 UMADDL/UMSUBL, C6.2.244/344 SMULH/UMULH;
    /// C4.1.5 Data-processing (3 source), C4-337–338.
    fn multiply(w: u32) -> Option<Multiply> {
        if w & 0x7f000000 != 0x1b000000 {
            return None;
        }
        let sf = w >> 31;
        let kind = match (w >> 21) & 7 {
            0 => MultiplyKind::SameWidth,
            1 if sf == 1 => MultiplyKind::SignedLong,
            5 if sf == 1 => MultiplyKind::UnsignedLong,
            2 if sf == 1 => MultiplyKind::SignedHigh,
            6 if sf == 1 => MultiplyKind::UnsignedHigh,
            _ => return None,
        };
        let high = matches!(kind, MultiplyKind::SignedHigh | MultiplyKind::UnsignedHigh);
        // The high-half form does not consume an accumulator. Accept the
        // canonical all-ones Ra field; noncanonical constrained bits fail shut.
        if high && w & 0xfc00 != 0x7c00 {
            return None;
        }
        Some(Multiply {
            kind,
            width: if sf == 0 {
                crate::Width::W32
            } else {
                crate::Width::X64
            },
            subtract: w & 0x8000 != 0,
            rd: OperandRegister::field(w, false),
            rn: OperandRegister::field(w >> 5, false),
            rm: OperandRegister::field(w >> 16, false),
            accumulator: if high {
                None
            } else {
                Some(OperandRegister::field(w >> 10, false))
            },
        })
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Divide {
        pub width: crate::Width,
        pub signed: bool,
        pub rd: OperandRegister,
        pub rn: OperandRegister,
        pub rm: OperandRegister,
    }
    /// DDI0487G.a C6.2.236 SDIV, C6.2.340 UDIV;
    /// C4.1.5 Data-processing (2 source), C4-328–330.
    fn divide(w: u32) -> Option<Divide> {
        if w & 0x7fe0f800 != 0x1ac00800 {
            return None;
        }
        Some(Divide {
            width: if w >> 31 == 0 {
                crate::Width::W32
            } else {
                crate::Width::X64
            },
            signed: w & 0x400 != 0,
            rd: OperandRegister::field(w, false),
            rn: OperandRegister::field(w >> 5, false),
            rm: OperandRegister::field(w >> 16, false),
        })
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum AtomicTransferKind {
        LoadAcquire,
        StoreRelease,
        LoadExclusive {
            acquire: bool,
        },
        StoreExclusive {
            release: bool,
            status: OperandRegister,
        },
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AtomicTransfer {
        pub kind: AtomicTransferKind,
        pub size: MemorySize,
        pub first: OperandRegister,
        pub second: Option<OperandRegister>,
        pub base: OperandRegister,
    }
    /// DDI0487G.a C6.2.111–117 LDAR/B/H, LDAXP/LDAXR/B/H;
    /// C6.2.174–177 LDXP/LDXR/B/H; C6.2.266–268 STLR/B/H;
    /// C6.2.272–275 STLXP/STLXR/B/H; C6.2.305–308 STXP/STXR/B/H.
    /// C4.1.4 Load/store exclusive, C4-306–308.
    /// LSE CAS/CASP and limited-ordering extensions remain unsupported.
    fn atomic_transfer(w: u32) -> Option<AtomicTransfer> {
        if w & 0x3f000000 != 0x08000000 {
            return None;
        }
        let size = w >> 30;
        let ordinary = w & (1 << 23) != 0;
        let load = w & (1 << 22) != 0;
        let pair = w & (1 << 21) != 0;
        let ordered = w & (1 << 15) != 0;
        let rs = (w >> 16) & 31;
        let rt2 = (w >> 10) & 31;
        if (!pair && rt2 != 31) || (load && rs != 31) {
            return None;
        }
        let kind = if ordinary {
            if pair || !ordered || rs != 31 {
                return None;
            }
            if load {
                AtomicTransferKind::LoadAcquire
            } else {
                AtomicTransferKind::StoreRelease
            }
        } else {
            if pair && size < 2 {
                return None;
            }
            if load {
                AtomicTransferKind::LoadExclusive { acquire: ordered }
            } else {
                AtomicTransferKind::StoreExclusive {
                    release: ordered,
                    status: OperandRegister::field(rs, false),
                }
            }
        };
        Some(AtomicTransfer {
            kind,
            size: MemorySize::scale(size)?,
            first: OperandRegister::field(w, false),
            second: if pair {
                Some(OperandRegister::field(rt2, false))
            } else {
                None
            },
            base: OperandRegister::field(w >> 5, true),
        })
    }

    /// Register index 0..30. Architectural register 31 is represented separately.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Gpr(u8);
    impl Gpr {
        /// X0..X30; register 31 is SP or ZR by context, never a `Gpr`.
        pub const fn new(number: u8) -> Option<Self> {
            if number < 31 {
                Some(Self(number))
            } else {
                None
            }
        }
        pub const fn number(self) -> u8 {
            self.0
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum OperandRegister {
        Gpr(Gpr),
        Sp,
        Zr,
    }
    impl OperandRegister {
        pub(crate) fn field(bits: u32, sp: bool) -> Self {
            match bits & 31 {
                31 if sp => Self::Sp,
                31 => Self::Zr,
                n => Self::Gpr(Gpr(n as u8)),
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ShiftAmount(u8);
    impl ShiftAmount {
        pub const fn value(self) -> u8 {
            self.0
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Extend {
        Uxtb,
        Uxth,
        Uxtw,
        Uxtx,
        Sxtb,
        Sxth,
        Sxtw,
        Sxtx,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum AddSubtract {
        Add,
        Subtract,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AddImmediate {
        encoded: u16,
        shift: ShiftAmount,
    }
    impl AddImmediate {
        pub const fn encoded(self) -> u16 {
            self.encoded
        }
        pub const fn shift(self) -> ShiftAmount {
            self.shift
        }
        pub const fn value(self) -> u64 {
            (self.encoded as u64) << self.shift.0
        }
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ArithmeticOperand {
        Immediate(AddImmediate),
        Shifted {
            rm: OperandRegister,
            shift: crate::Shift,
            amount: ShiftAmount,
        },
        Extended {
            rm: OperandRegister,
            extend: Extend,
            amount: ShiftAmount,
        },
        WithCarry {
            rm: OperandRegister,
        },
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Arithmetic {
        pub width: crate::Width,
        pub op: AddSubtract,
        pub set_flags: bool,
        pub rd: OperandRegister,
        pub rn: OperandRegister,
        pub operand: ArithmeticOperand,
    }

    /// DDI0487G.a C6.2.4 ADD / C6.2.8 ADDS / C6.2.313 SUB /
    /// C6.2.319 SUBS (immediate); C4.1.2 Add/subtract (immediate).
    fn arithmetic_immediate(w: u32) -> Option<ArithmeticOperand> {
        (w & 0x1f800000 == 0x11000000).then_some(ArithmeticOperand::Immediate(AddImmediate {
            encoded: ((w >> 10) & 4095) as u16,
            shift: ShiftAmount(if w & (1 << 22) != 0 { 12 } else { 0 }),
        }))
    }

    /// DDI0487G.a C6.2.5 ADD / C6.2.9 ADDS / C6.2.314 SUB /
    /// C6.2.320 SUBS (shifted register); C4.1.5 Add/subtract (shifted register).
    fn arithmetic_shifted(w: u32) -> Option<ArithmeticOperand> {
        if w & 0x1f200000 != 0x0b000000 || (w >> 31 == 0 && w & 0x8000 != 0) {
            return None;
        }
        let shift = match (w >> 22) & 3 {
            0 => crate::Shift::Lsl,
            1 => crate::Shift::Lsr,
            2 => crate::Shift::Asr,
            _ => return None,
        };
        Some(ArithmeticOperand::Shifted {
            rm: OperandRegister::field(w >> 16, false),
            shift,
            amount: ShiftAmount(((w >> 10) & 63) as u8),
        })
    }

    /// DDI0487G.a C6.2.3 ADD / C6.2.7 ADDS / C6.2.312 SUB /
    /// C6.2.318 SUBS (extended register); C4.1.5 Add/subtract (extended register).
    fn arithmetic_extended(w: u32) -> Option<ArithmeticOperand> {
        if w & 0x1fe00000 != 0x0b200000 || (w >> 10) & 7 > 4 {
            return None;
        }
        let extend = match (w >> 13) & 7 {
            0 => Extend::Uxtb,
            1 => Extend::Uxth,
            2 => Extend::Uxtw,
            3 => Extend::Uxtx,
            4 => Extend::Sxtb,
            5 => Extend::Sxth,
            6 => Extend::Sxtw,
            _ => Extend::Sxtx,
        };
        Some(ArithmeticOperand::Extended {
            rm: OperandRegister::field(w >> 16, false),
            extend,
            amount: ShiftAmount(((w >> 10) & 7) as u8),
        })
    }

    /// DDI0487G.a C6.2.1 ADC, C6.2.2 ADCS, C6.2.231 SBC, C6.2.232 SBCS;
    /// C4.1.5 Add/subtract (with carry). All three registers use ZR, never SP.
    fn arithmetic_carry(w: u32) -> Option<ArithmeticOperand> {
        (w & 0x1fe0fc00 == 0x1a000000).then_some(ArithmeticOperand::WithCarry {
            rm: OperandRegister::field(w >> 16, false),
        })
    }

    fn arithmetic(w: u32) -> Option<Arithmetic> {
        let operand = arithmetic_immediate(w)
            .or_else(|| arithmetic_shifted(w))
            .or_else(|| arithmetic_extended(w))
            .or_else(|| arithmetic_carry(w))?;
        let uses_sp = matches!(
            operand,
            ArithmeticOperand::Immediate(_) | ArithmeticOperand::Extended { .. }
        );
        let set_flags = w & (1 << 29) != 0;
        Some(Arithmetic {
            width: if w >> 31 != 0 {
                crate::Width::X64
            } else {
                crate::Width::W32
            },
            op: if w & (1 << 30) != 0 {
                AddSubtract::Subtract
            } else {
                AddSubtract::Add
            },
            set_flags,
            rd: OperandRegister::field(w, uses_sp && !set_flags),
            rn: OperandRegister::field(w >> 5, uses_sp),
            operand,
        })
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PcOffset(i64);
    impl PcOffset {
        pub const fn bytes(self) -> i64 {
            self.0
        }
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Condition {
        Eq,
        Ne,
        Cs,
        Cc,
        Mi,
        Pl,
        Vs,
        Vc,
        Hi,
        Ls,
        Ge,
        Lt,
        Gt,
        Le,
        Al,
        Nv,
    }
    impl Condition {
        fn field(w: u32) -> Self {
            match w & 15 {
                0 => Self::Eq,
                1 => Self::Ne,
                2 => Self::Cs,
                3 => Self::Cc,
                4 => Self::Mi,
                5 => Self::Pl,
                6 => Self::Vs,
                7 => Self::Vc,
                8 => Self::Hi,
                9 => Self::Ls,
                10 => Self::Ge,
                11 => Self::Lt,
                12 => Self::Gt,
                13 => Self::Le,
                14 => Self::Al,
                _ => Self::Nv,
            }
        }
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum RegisterBranch {
        Jump,
        Call,
        Return,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Branch {
        Immediate {
            link: bool,
            offset: PcOffset,
        },
        Conditional {
            condition: Condition,
            offset: PcOffset,
        },
        Compare {
            width: crate::Width,
            nonzero: bool,
            rt: OperandRegister,
            offset: PcOffset,
        },
        Test {
            bit: ShiftAmount,
            nonzero: bool,
            rt: OperandRegister,
            offset: PcOffset,
        },
        Register {
            op: RegisterBranch,
            rn: OperandRegister,
        },
    }

    fn signed_offset(field: u32, bits: u32) -> PcOffset {
        PcOffset(((i64::from(field) << (64 - bits)) >> (64 - bits)) << 2)
    }

    /// DDI0487G.a C6.2.26 B, C6.2.33 BL; C4.1.3 Unconditional branch (immediate).
    fn branch_immediate(w: u32) -> Option<Branch> {
        (w & 0x7c000000 == 0x14000000).then_some(Branch::Immediate {
            link: w >> 31 != 0,
            offset: signed_offset(w & 0x03ffffff, 26),
        })
    }
    /// DDI0487G.a C6.2.25 B.cond; C4.1.3 Conditional branch (immediate).
    fn branch_conditional(w: u32) -> Option<Branch> {
        (w & 0xff000010 == 0x54000000).then_some(Branch::Conditional {
            condition: Condition::field(w),
            offset: signed_offset((w >> 5) & 0x7ffff, 19),
        })
    }
    /// DDI0487G.a C6.2.44 CBNZ, C6.2.45 CBZ;
    /// C4.1.3 Compare and branch (immediate).
    fn branch_compare(w: u32) -> Option<Branch> {
        (w & 0x7e000000 == 0x34000000).then_some(Branch::Compare {
            width: if w >> 31 == 0 {
                crate::Width::W32
            } else {
                crate::Width::X64
            },
            nonzero: w & (1 << 24) != 0,
            rt: OperandRegister::field(w, false),
            offset: signed_offset((w >> 5) & 0x7ffff, 19),
        })
    }
    /// DDI0487G.a C6.2.330 TBNZ, C6.2.331 TBZ;
    /// C4.1.3 Test and branch (immediate). Bit 31 is `bit_pos[5]`, not sf.
    fn branch_test(w: u32) -> Option<Branch> {
        (w & 0x7e000000 == 0x36000000).then_some(Branch::Test {
            bit: ShiftAmount((((w >> 26) & 32) | ((w >> 19) & 31)) as u8),
            nonzero: w & (1 << 24) != 0,
            rt: OperandRegister::field(w, false),
            offset: signed_offset((w >> 5) & 0x3fff, 14),
        })
    }
    /// DDI0487G.a C6.2.36 BR, C6.2.34 BLR, C6.2.220 RET;
    /// C4.1.3 Unconditional branch (register). Authentication extensions fail shut.
    fn branch_register(w: u32) -> Option<Branch> {
        let op = match w & 0xfffffc1f {
            0xd61f0000 => RegisterBranch::Jump,
            0xd63f0000 => RegisterBranch::Call,
            0xd65f0000 => RegisterBranch::Return,
            _ => return None,
        };
        Some(Branch::Register {
            op,
            rn: OperandRegister::field(w >> 5, false),
        })
    }
    fn branch(w: u32) -> Option<Branch> {
        branch_immediate(w)
            .or_else(|| branch_conditional(w))
            .or_else(|| branch_compare(w))
            .or_else(|| branch_test(w))
            .or_else(|| branch_register(w))
    }
}
pub use instruction::{
    AddImmediate, AddSubtract, Address, AddressBase, Arithmetic, ArithmeticOperand, AtomicTransfer,
    AtomicTransferKind, Bitfield, BitfieldOperation, Branch, CompareImmediate, CompareOperand,
    Condition, ConditionalCompare, ConditionalSelect, Divide, Extend, Gpr, Hint, Instruction,
    Logical, LogicalImmediate, LogicalOperand, LogicalOperation, MemoryAddress, MemoryIndex,
    MemoryOffset, MemoryOperation, MemoryRegister, MemorySize, MoveWide, MoveWideOperation,
    Multiply, MultiplyKind, Nzcv, OperandRegister, PairMemory, PcOffset, RegisterBranch,
    ScalarMemory, SelectOperation, ShiftAmount, VectorRegister, decode_instruction,
};

pub mod dispatch;
pub mod exception;
pub mod handler;
pub mod mmu;
pub mod state;
pub mod translate;
