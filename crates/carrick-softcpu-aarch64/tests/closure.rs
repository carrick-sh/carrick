use carrick_softcpu_aarch64::*;

#[test]
fn barrier_closure_red_witness() {
    for word in [0xd5033f9f, 0xd5033bbf, 0xd5033fdf] {
        assert_ne!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}

#[test]
fn system_closure_red_witness() {
    for word in [0xd5382000, 0xd5182000, 0xd5034fdf, 0xd50041bf] {
        assert_ne!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}

#[test]
fn exception_closure_red_witness() {
    for word in [0xd4000001, 0xd4000022, 0xd4000003, 0xd4400000] {
        assert_ne!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}

#[test]
fn transfer_extract_closure_red_witness() {
    for word in [0xf8400800, 0xf8000800, 0x93c10020] {
        assert_ne!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}
