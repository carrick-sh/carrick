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

#[test]
fn scalar_reserved_neighbours_fail_shut() {
    for word in [0xf9c00000, 0xb9c00000, 0x7dc00000, 0xdc000000, 0xf8620820] {
        assert_eq!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}

#[test]
fn scalar_literal_offset_does_not_include_rt() {
    use carrick_softcpu_aarch64::{
        MemoryAddress, MemoryIndex, MemoryOperation, MemoryRegister, MemorySize, Width,
    };
    for rt in 0..32 {
        let Instruction::ScalarMemory(m) = decode_instruction(0x58ffffe0 | rt) else {
            panic!("literal missing")
        };
        let MemoryAddress::Literal(offset) = m.address else {
            panic!("wrong addressing")
        };
        assert_eq!(offset.bytes(), -4);
    }
    let Instruction::ScalarMemory(m) = decode_instruction(0x38dff020) else {
        panic!("signed load missing")
    };
    assert_eq!(m.operation, MemoryOperation::LoadSigned);
    assert_eq!(m.size, MemorySize::Byte);
    assert!(matches!(
        m.register,
        MemoryRegister::Integer {
            width: Width::W32,
            ..
        }
    ));
    let MemoryAddress::Immediate {
        offset,
        index,
        unscaled,
        ..
    } = m.address
    else {
        panic!("wrong addressing")
    };
    assert_eq!(offset.bytes(), -1);
    assert_eq!(index, MemoryIndex::Offset);
    assert!(unscaled);
}

#[test]
fn pair_memory_forms_are_typed() {
    for word in [
        0xa9bf7bfd, 0xa8c17bfd, 0xa9400440, 0x69400440, 0x28400440, 0xad400440,
    ] {
        assert_ne!(
            decode_instruction(word),
            Instruction::Unallocated,
            "{word:08x}"
        );
    }
}
