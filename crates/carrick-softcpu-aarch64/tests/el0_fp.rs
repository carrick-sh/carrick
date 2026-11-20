//! Arm ARM DDI0487 C4.1, Data Processing — SIMD and Floating Point.
use carrick_softcpu_aarch64::{
    state::ProgramCounter,
    translate::{CopyKind, ExitReason, GuestInstruction, InstructionClass},
};

#[test]
fn scalar_fp_is_copied_only_for_allocated_single_and_double_encodings() {
    for (name, word) in [
        ("fadd d0, d0, d0", 0x1e60_2800),
        ("fcvt s0, d0", 0x1e62_4000),
        ("fcmp d0, #0.0", 0x1e60_2008),
        ("fmadd d0, d0, d0, d0", 0x1f40_0000),
        ("fcvtzs x0, d0", 0x9e78_0000),
    ] {
        assert_eq!(
            GuestInstruction::decode(ProgramCounter(0), word).class(),
            InstructionClass::Copy(CopyKind::Verbatim),
            "{name}"
        );
    }
    for word in [0x1ee0_2800, 0x1ea0_2800, 0x1e60_2018 | 1, 0x1e60_9800] {
        assert_eq!(
            GuestInstruction::decode(ProgramCounter(0), word).class(),
            InstructionClass::Exit(ExitReason::Undefined),
            "{word:08x}"
        );
    }
}

#[test]
fn vector_integer_fp_permute_and_table_admit_only_allocated_forms() {
    for (name, word) in [
        ("add v0.16b, v0.16b, v1.16b", 0x4e21_8400),
        ("fadd v0.2d, v0.2d, v1.2d", 0x4e61_d400),
        ("zip1 v0.16b, v0.16b, v1.16b", 0x4e01_3800),
        ("tbl v0.16b, {v0.16b}, v1.16b", 0x4e01_0000),
    ] {
        assert_eq!(
            GuestInstruction::decode(ProgramCounter(0), word).class(),
            InstructionClass::Copy(CopyKind::Verbatim),
            "{name}"
        );
    }
    for word in [0x0e61_d400, 0x0ec1_3800, 0x4e41_0000, 0x4e28_4800] {
        assert_eq!(
            GuestInstruction::decode(ProgramCounter(0), word).class(),
            InstructionClass::Exit(ExitReason::Undefined),
            "{word:08x}"
        );
    }
}

#[test]
fn el0_static_census_admits_baseline_families_and_rejects_extensions() {
    use InstructionClass::{Copy, Exit};
    for (name, word, expected) in [
        ("chkfeat x16", 0xd503_251f, Copy(CopyKind::NoOperation)),
        ("fadd d0, d0, d1", 0x1e61_2800, Copy(CopyKind::Verbatim)),
        (
            "add v0.16b, v0.16b, v1.16b",
            0x4e21_8400,
            Copy(CopyKind::Verbatim),
        ),
        ("ld1 {v0.16b}, [x0]", 0x4c40_7000, Exit(ExitReason::Memory)),
        ("ldr q0, [x0]", 0x3dc0_0000, Exit(ExitReason::Memory)),
        (
            "prfm pldl1keep, [x0]",
            0xf980_0000,
            Exit(ExitReason::Memory),
        ),
        ("ldxr x0, [x1]", 0xc85f_7c20, Exit(ExitReason::Memory)),
        ("stlxr w2, x0, [x1]", 0xc802_fc20, Exit(ExitReason::Memory)),
        (
            "crc32x w2, w0, x1",
            0x9ac1_4c02,
            Exit(ExitReason::RegisterCompute),
        ),
        ("extr x0, x0, x1, #1", 0x93c1_0400, Copy(CopyKind::Verbatim)),
        ("clz x0, x0", 0xdac0_1000, Copy(CopyKind::Verbatim)),
        (
            "isb",
            0xd503_3fdf,
            Exit(ExitReason::InstructionSynchronization),
        ),
        (
            "mrs x0, nzcv",
            0xd53b_4200,
            Exit(ExitReason::SystemRegister),
        ),
        ("ptrue p0.b", 0x2518_e3e0, Exit(ExitReason::Undefined)),
        (
            "aese v0.16b, v0.16b",
            0x4e28_4800,
            Exit(ExitReason::Undefined),
        ),
        (
            "ldadd x0, x0, [x1]",
            0xf820_0020,
            Exit(ExitReason::Undefined),
        ),
        (
            "casa x0, x1, [x2]",
            0xc8e0_7c41,
            Exit(ExitReason::Undefined),
        ),
        (
            "cpyfp [x3]!, [x1]!, x2!",
            0x1901_0443,
            Exit(ExitReason::Undefined),
        ),
    ] {
        assert_eq!(
            GuestInstruction::decode_el0(ProgramCounter(0x1000), word).class(),
            expected,
            "{name} ({word:08x})",
        );
    }
}
