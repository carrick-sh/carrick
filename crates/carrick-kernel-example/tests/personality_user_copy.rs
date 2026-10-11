//! Red-first unit tests for personality-facing bounded user copy-in/copy-out.
//!
//! Acceptance criteria (carrick issue #209):
//! - Multi-page copy-in across page boundaries.
//! - Copy-out to a writable page.
//! - Copy-out to a read-only page refused with ServiceError::AccessDenied.
//! - Unmapped page gives a typed fault (ServiceError::Fault).
//! - Range overflow refused with ServiceError::RangeOverflow.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use carrick_core::personality::{CallContext, ServiceError};
use carrick_guest_arch::{Arch, CopyProgress, GuestLen, UserRange, UserVa};
use carrick_kernel_example::personality::ExampleEntryBackend;

#[test]
fn test_personality_multi_page_copy_in() {
    let mut backend = ExampleEntryBackend::new();
    let page1 = 0x2000_0000u64;
    let page2 = 0x2000_1000u64;
    let page3 = 0x2000_2000u64;

    backend.map_page_with_perms(page1, true /* readable */, false /* writable */);
    backend.map_page_with_perms(page2, true, false);
    backend.map_page_with_perms(page3, true, false);

    // Write a repeating test pattern of 6000 bytes starting at page1 + 2048.
    // This spans through page1 (2048 bytes), all of page2 (4096 bytes), and into page3.
    let start_va = page1 + 2048;
    let total_len = 6000usize;
    let mut expected = vec![0u8; total_len];
    for (i, byte) in expected.iter_mut().enumerate() {
        *byte = ((i * 7 + 13) & 0xff) as u8;
    }
    backend.write_bytes(start_va, &expected);

    let frame = backend.create_frame(1, [0; 6], 0x7000_0000);
    let mut arch = Arch::new(backend);
    let mut cx = CallContext::new(&mut arch, &frame);

    let range = UserRange::checked(UserVa::new(start_va), GuestLen::new(total_len as u64))
        .expect("valid user range");
    let mut dst = vec![0u8; total_len];

    let progress: CopyProgress = cx
        .user()
        .copy_in(range, &mut dst)
        .expect("multi-page copy-in must succeed");

    assert_eq!(progress.completed, GuestLen::new(total_len as u64));
    assert_eq!(progress.remaining, GuestLen::new(0));
    assert_eq!(dst, expected);
}

#[test]
fn test_personality_copy_out_to_writable_page() {
    let mut backend = ExampleEntryBackend::new();
    let page_va = 0x3000_0000u64;
    backend.map_page_with_perms(page_va, true /* readable */, true /* writable */);

    let frame = backend.create_frame(1, [0; 6], 0x7000_0000);
    let mut arch = Arch::new(backend);
    let mut cx = CallContext::new(&mut arch, &frame);

    let write_va = page_va + 512;
    let payload = [0xa5u8; 1024];
    let range = UserRange::checked(UserVa::new(write_va), GuestLen::new(payload.len() as u64))
        .expect("valid user range");

    let progress: CopyProgress = cx
        .user()
        .copy_out(range, &payload)
        .expect("copy-out to writable page must succeed");

    assert_eq!(progress.completed, GuestLen::new(payload.len() as u64));
    assert_eq!(progress.remaining, GuestLen::new(0));

    // Verify written data by reading back via copy_in
    let mut read_back = [0u8; 1024];
    let in_progress = cx
        .user()
        .copy_in(range, &mut read_back)
        .expect("read-back of written page must succeed");
    assert_eq!(in_progress.completed, GuestLen::new(payload.len() as u64));
    assert_eq!(read_back, payload);
}

#[test]
fn test_personality_copy_out_to_read_only_page_refused() {
    let mut backend = ExampleEntryBackend::new();
    let page_va = 0x4000_0000u64;
    // Map as readable only, NOT writable.
    backend.map_page_with_perms(page_va, true /* readable */, false /* writable */);

    let frame = backend.create_frame(1, [0; 6], 0x7000_0000);
    let mut arch = Arch::new(backend);
    let mut cx = CallContext::new(&mut arch, &frame);

    let payload = [0x55u8; 128];
    let range = UserRange::checked(UserVa::new(page_va), GuestLen::new(payload.len() as u64))
        .expect("valid user range");

    let err = cx
        .user()
        .copy_out(range, &payload)
        .expect_err("copy-out to read-only page must be refused");

    assert_eq!(
        err,
        ServiceError::AccessDenied,
        "write to read-only page must yield ServiceError::AccessDenied"
    );
}

#[test]
fn test_personality_unmapped_page_gives_typed_fault() {
    let backend = ExampleEntryBackend::new();
    let unmapped_va = 0x5000_0000u64;

    let frame = backend.create_frame(1, [0; 6], 0x7000_0000);
    let mut arch = Arch::new(backend);
    let mut cx = CallContext::new(&mut arch, &frame);

    let mut in_buf = [0u8; 64];
    let in_range =
        UserRange::checked(UserVa::new(unmapped_va), GuestLen::new(64)).expect("valid user range");

    let in_err = cx
        .user()
        .copy_in(in_range, &mut in_buf)
        .expect_err("copy-in from unmapped page must fault");
    assert_eq!(
        in_err,
        ServiceError::Fault,
        "unmapped copy-in must yield ServiceError::Fault"
    );

    let out_buf = [0x77u8; 64];
    let out_range =
        UserRange::checked(UserVa::new(unmapped_va), GuestLen::new(64)).expect("valid user range");
    let out_err = cx
        .user()
        .copy_out(out_range, &out_buf)
        .expect_err("copy-out to unmapped page must fault");
    assert_eq!(
        out_err,
        ServiceError::Fault,
        "unmapped copy-out must yield ServiceError::Fault"
    );
}

#[test]
fn test_personality_range_overflow_refused() {
    let backend = ExampleEntryBackend::new();
    let frame = backend.create_frame(1, [0; 6], 0x7000_0000);
    let mut arch = Arch::new(backend);
    let mut cx = CallContext::new(&mut arch, &frame);

    // Test 1: UserVa arithmetic wrapping u64 max
    assert!(
        UserRange::checked(UserVa::new(u64::MAX - 10), GuestLen::new(20)).is_none(),
        "UserRange::checked must reject arithmetic overflow"
    );

    // Test 2: Address in upper half (>= USER_CEILING 0x0000_8000_0000_0000)
    let upper_half_va = UserVa::new(0x0000_8000_0000_0000);
    let upper_range =
        UserRange::checked(upper_half_va, GuestLen::new(64)).expect("checked addition succeeds");
    let mut buf = [0u8; 64];

    let in_err = cx
        .user()
        .copy_in(upper_range, &mut buf)
        .expect_err("upper-half access must be refused");
    assert_eq!(
        in_err,
        ServiceError::RangeOverflow,
        "address >= USER_CEILING must yield ServiceError::RangeOverflow"
    );

    let out_buf = [0x33u8; 64];
    let out_err = cx
        .user()
        .copy_out(upper_range, &out_buf)
        .expect_err("upper-half write must be refused");
    assert_eq!(
        out_err,
        ServiceError::RangeOverflow,
        "address >= USER_CEILING must yield ServiceError::RangeOverflow"
    );

    // Test 3: Slice length mismatch against UserRange
    let valid_range = UserRange::checked(UserVa::new(0x1000_0000), GuestLen::new(64)).unwrap();
    let mut short_buf = [0u8; 32];
    let mismatch_err = cx
        .user()
        .copy_in(valid_range, &mut short_buf)
        .expect_err("length mismatch must be refused");
    assert_eq!(mismatch_err, ServiceError::RangeOverflow);
}
