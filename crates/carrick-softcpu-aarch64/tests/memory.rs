use carrick_softcpu_aarch64::{Instruction, decode_instruction};

#[test]
fn scalar_memory_forms_are_typed() {
    for word in [
        0xf9400820, // ldr x0, [x1, #16]
        0xf8408420, // ldr x0, [x1], #8
        0xf8008c20, // str x0, [x1, #8]!
        0x38dff020, // ldursb w0, [x1, #-1]
        0xf8627820, // ldr x0, [x1, x2, lsl #3]
        0x58000040, // ldr x0, pc+8
        0x3dc00420, // ldr q0, [x1, #16]
    ] {
        assert_ne!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}
