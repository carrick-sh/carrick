use carrick_softcpu_aarch64::{decode_instruction, Instruction};

#[test]
fn eret_loader_red_witness() {
    assert_ne!(decode_instruction(0xd69f03e0), Instruction::Unallocated);
}

#[test]
fn ldadd_loader_red_witness() {
    assert_ne!(decode_instruction(0xf8f1021f), Instruction::Unallocated);
}

#[test]
fn tlbi_loader_red_witness() {
    assert_ne!(decode_instruction(0xd508831f), Instruction::Unallocated);
}
