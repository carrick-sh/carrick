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
