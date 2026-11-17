use carrick_softcpu_aarch64::{Instruction, decode_instruction};

#[test]
fn baseline_hints_are_typed() {
    for word in [
        0xd503201f, 0xd503203f, 0xd503205f, 0xd503207f, 0xd503209f, 0xd50320bf,
    ] {
        assert_ne!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}

#[test]
fn unsupported_hint_extensions_fail_shut() {
    for word in [0xd50320df, 0xd50320ff, 0xd503211f, 0xd503241f, 0xd503201e] {
        assert_eq!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}

#[test]
fn arithmetic_forms_are_typed() {
    for word in [
        0x910007ff, 0xb10007ff, 0xd1400420, 0xf1400420, 0x8b020020, 0x6b827c3f, 0x8b2243ff,
        0xeb22d3ff, 0x9a020020, 0xfa020020,
    ] {
        assert_ne!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}

#[test]
fn arithmetic_reserved_fields_fail_shut() {
    for word in [0x91800000, 0x0bc00000, 0x0b008000, 0x8b201400, 0x9a000400] {
        assert_eq!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}

#[test]
fn branch_forms_are_typed() {
    for word in [
        0x14000000, 0x97ffffff, 0x54ffffe0, 0x3400003f, 0xb5ffffe0, 0x36000020, 0xb7ffffe0,
        0xd61f03e0, 0xd63f0020, 0xd65f03c0,
    ] {
        assert_ne!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}

#[test]
fn branch_fixed_fields_fail_shut() {
    for word in [0x54000010, 0xd61f0001, 0xd63f0400, 0xd65f0800] {
        assert_eq!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}
