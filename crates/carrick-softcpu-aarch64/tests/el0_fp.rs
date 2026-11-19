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
