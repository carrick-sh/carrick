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

#[test]
fn logical_forms_have_typed_operands() {
    for word in [0x92401c20, 0x12001c20, 0xaa020020, 0x8a220020, 0xea420420] {
        assert_ne!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}

#[test]
fn logical_reserved_masks_and_shifts_fail_shut() {
    for word in [0x12400000, 0x9240fc00, 0x9200fc00, 0x0a008000] {
        assert_eq!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}

#[test]
fn logical_masks_rotate_and_replicate() {
    use carrick_softcpu_aarch64::LogicalOperand;
    for (word, mask) in [
        (0x92401c20, 255),
        (0x320083ff, 0x10001),
        (0x320107ff, 0x80000001),
    ] {
        let Instruction::Logical(l) = decode_instruction(word) else {
            panic!("missing logical")
        };
        let LogicalOperand::Immediate(i) = l.operand else {
            panic!("missing immediate")
        };
        assert_eq!(i.value(), mask);
    }
}

#[test]
fn move_wide_forms_have_typed_operands() {
    for word in [0xd2800020, 0x92800020, 0xf2e24680, 0x52a24680] {
        assert_ne!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}

#[test]
fn move_wide_retains_halfword_and_reserved_selectors() {
    use carrick_softcpu_aarch64::MoveWideOperation;
    let Instruction::MoveWide(m) = decode_instruction(0xf2e24680) else {
        panic!("missing move-wide")
    };
    assert_eq!(m.operation, MoveWideOperation::Keep);
    assert_eq!(m.immediate, 0x1234);
    assert_eq!(m.shift.value(), 48);
    for word in [0x72c00000, 0x32800000, 0x52e00000] {
        assert_eq!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}

#[test]
fn bitfield_and_address_forms_have_typed_operands() {
    for word in [
        0x93401c20, 0xb3401c20, 0xd3401c20, 0x13001c20, 0x10000020, 0x90000020,
    ] {
        assert_ne!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}

#[test]
fn bitfield_reserved_fields_fail_shut() {
    for word in [0x93000000, 0x13400000, 0x13200000, 0x13008000, 0xf3400000] {
        assert_eq!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}

#[test]
fn conditional_forms_have_typed_operands() {
    for word in [
        0x9a820020, 0x9a820420, 0xda820020, 0xda820420, 0xfa420020, 0xba420820,
    ] {
        assert_ne!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}

#[test]
fn conditional_reserved_bits_fail_shut() {
    for word in [0xba820020, 0x9a820820, 0xda420020, 0xfa420430, 0xfa420420] {
        assert_eq!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}

#[test]
fn multiply_divide_forms_have_typed_operands() {
    for word in [
        0x9b020c20, 0x9b028c20, 0x9b220c20, 0x9ba20c20, 0x9b427c20, 0x9bc27c20, 0x9ac20c20,
        0x1ac20820,
    ] {
        assert_ne!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}

#[test]
fn multiply_reserved_combinations_fail_shut() {
    for word in [0x1b220c20, 0x9b628c20, 0x9b42fc20, 0x9bc20020, 0x3b020c20] {
        assert_eq!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}
