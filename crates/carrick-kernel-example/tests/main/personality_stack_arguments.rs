//! Unit tests for personality-driven architectural entry decode and stack pointer handling.
//!
//! Acceptance criteria:
//! - During PersonalityAbi::decode, a personality decodes from the architectural snapshot and user stack pointer.
//! - Fault handling respects memory protection and unmapped addresses, returning EntryDecodeError::Fault (never a panic).
//! - Unsupported ABIs return EntryDecodeError::UnsupportedAbi.
//! - PersonalityAbi::encode_return writes the result word to the frame.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use carrick_core::personality::{
    CallContext, CallOrdinal, EntryDecodeError, PersonalityAbi, UserStackOffset,
};
use carrick_guest_arch::{Arch, GuestIsa, NativeAbi, NativeReturnWord, UserVa};
use carrick_kernel_example::ExamplePersonality;
use carrick_kernel_example::personality::{ExampleCall, ExampleEntryBackend};

#[test]
fn test_personality_decode_x86_snapshot() {
    let personality = ExamplePersonality::new();
    let mut backend = ExampleEntryBackend::new();

    // Map a valid stack page.
    let stack_va = 0x1000_8000u64;
    backend.map_page(stack_va, true /* readable */);
    backend.write_u64(stack_va, 70);
    backend.write_u64(stack_va + 8, 80);

    let frame = backend.create_frame(
        42,                       // syscall ordinal
        [10, 20, 30, 40, 50, 60], // arguments 1-6 in registers
        stack_va,                 // user stack pointer
    );

    let mut arch = Arch::new(backend);
    let mut cx = CallContext::new(&mut arch, &frame);

    let decoded: ExampleCall = personality
        .decode(&mut cx)
        .expect("decode should succeed for valid stack");

    assert_eq!(decoded.ordinal, CallOrdinal::from_raw(42));
    assert_eq!(decoded.args, [10, 20, 30, 40, 50, 60, 70, 80]);
    assert_eq!(decoded.stack, UserVa::new(stack_va));
}

#[test]
fn test_personality_decode_aarch64_snapshot() {
    let personality = ExamplePersonality::new();
    let mut backend = ExampleEntryBackend::new().with_isa(GuestIsa::Aarch64, NativeAbi::Aarch64El0);

    // Map a valid stack page.
    let stack_va = 0x2000_8000u64;
    backend.map_page(stack_va, true /* readable */);
    backend.write_u64(stack_va, 7);
    backend.write_u64(stack_va + 8, 8);

    let frame = backend.create_frame(
        93,                 // syscall ordinal (exit on AArch64)
        [1, 2, 3, 4, 5, 6], // arguments 1-6 in registers x0..x5
        stack_va,           // user stack pointer
    );

    let mut arch = Arch::new(backend);
    let mut cx = CallContext::new(&mut arch, &frame);

    let decoded: ExampleCall = personality
        .decode(&mut cx)
        .expect("decode should succeed for valid AArch64 snapshot");

    assert_eq!(decoded.ordinal, CallOrdinal::from_raw(93));
    assert_eq!(decoded.args, [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(decoded.stack, UserVa::new(stack_va));
}

#[test]
fn test_personality_decode_unmapped_stack_returns_fault() {
    let personality = ExamplePersonality::new();
    let backend = ExampleEntryBackend::new();

    // User stack pointer points to an unmapped address.
    let unmapped_stack_va = 0xdead_beef_0000u64;
    let frame = backend.create_frame(42, [1, 2, 3, 4, 5, 6], unmapped_stack_va);

    let mut arch = Arch::new(backend);
    let mut cx = CallContext::new(&mut arch, &frame);

    let result = personality.decode(&mut cx);
    assert_eq!(
        result,
        Err(EntryDecodeError::Fault),
        "unmapped stack must yield EntryDecodeError::Fault, never panic"
    );
}

#[test]
fn test_personality_decode_protected_stack_returns_fault() {
    let personality = ExamplePersonality::new();
    let mut backend = ExampleEntryBackend::new();

    // Map a page without read permission (protected).
    let protected_stack_va = 0x1000_9000u64;
    backend.map_page(protected_stack_va, false /* readable */);

    let frame = backend.create_frame(42, [1, 2, 3, 4, 5, 6], protected_stack_va);

    let mut arch = Arch::new(backend);
    let mut cx = CallContext::new(&mut arch, &frame);

    let result = personality.decode(&mut cx);
    assert_eq!(
        result,
        Err(EntryDecodeError::Fault),
        "protected stack must yield EntryDecodeError::Fault, never panic"
    );
}

#[test]
fn test_personality_decode_unsupported_abi_returns_unsupported() {
    let personality = ExamplePersonality::new();
    // Mismatched ISA and ABI: x86_64 ISA with Aarch64El0 ABI
    let mut backend = ExampleEntryBackend::new().with_isa(GuestIsa::X86_64, NativeAbi::Aarch64El0);
    let stack_va = 0x1000_8000u64;
    backend.map_page(stack_va, true);

    let frame = backend.create_frame(42, [1, 2, 3, 4, 5, 6], stack_va);
    let mut arch = Arch::new(backend);
    let mut cx = CallContext::new(&mut arch, &frame);

    let result = personality.decode(&mut cx);
    assert_eq!(result, Err(EntryDecodeError::UnsupportedAbi));
}

#[test]
fn test_personality_encode_return() {
    let personality = ExamplePersonality::new();
    let backend = ExampleEntryBackend::new();
    let mut frame = backend.create_frame(42, [1, 2, 3, 4, 5, 6], 0x7fff_0000);

    PersonalityAbi::<Arch<ExampleEntryBackend>>::encode_return(
        &personality,
        NativeReturnWord(0xfeed_face_cafe_babe),
        &mut frame,
    )
    .expect("encode_return must succeed");
    assert_eq!(frame.result, 0xfeed_face_cafe_babe);
}

#[test]
fn test_entry_decode_error_variants_and_user_stack_offset() {
    let offset = UserStackOffset::new(16);
    assert_eq!(offset.raw(), 16);

    let busy = EntryDecodeError::Busy;
    let unbound = EntryDecodeError::Unbound;
    assert_ne!(busy, unbound);
    assert!(format!("{}", busy).contains("carrier"));
    assert!(format!("{}", unbound).contains("unbound"));
}

#[test]
fn test_personality_decode_stack_copy_boundary_without_overread() {
    let mut backend = ExampleEntryBackend::new();
    let page_base = 0x1000_5000u64;
    // Map only page_base, leaving page_base + 0x1000 unmapped.
    backend.map_page(page_base, true /* readable */);

    // Place 4 bytes at the very end of the page (offset 4092..4096).
    backend.write_bytes(page_base + 4092, &[0xaa, 0xbb, 0xcc, 0xdd]);

    // Stack pointer points 4 bytes before the end of the mapped page.
    let frame = backend.create_frame(1, [0; 6], page_base + 4092);
    let mut arch = Arch::new(backend);
    let mut cx = CallContext::new(&mut arch, &frame);

    // Copying 4 bytes must succeed because they are within the mapped page,
    // and must not over-read into the unmapped next page.
    let mut buf = [0u8; 4];
    cx.user()
        .copy_in(UserVa::new(page_base + 4092), &mut buf)
        .expect("copy within mapped boundary must succeed without over-reading");
    assert_eq!(buf, [0xaa, 0xbb, 0xcc, 0xdd]);

    // Attempting to copy 5 bytes crosses into the unmapped page and must fault.
    let mut buf5 = [0u8; 5];
    let err = cx.user().copy_in(UserVa::new(page_base + 4092), &mut buf5);
    assert_eq!(err, Err(carrick_core::personality::ServiceError::Fault));
}
