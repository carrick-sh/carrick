//! Real KVM proof that production CPL0 dispatches a Linux lifecycle call
//! inside the shared family before its only semantic host exit.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::expect_used)]

use carrick_mem::x86_initial_image::prepare_static_x86_elf;
use carrick_vmm_kvm::cpl0_boot::Cpl0Carrier;

fn tiny_elf(code: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 0xb0 + code.len()];
    let file_size = bytes.len() as u64;
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4..7].copy_from_slice(&[2, 1, 1]);
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86_64
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x0040_00b0_u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    bytes[68..72].copy_from_slice(&5u32.to_le_bytes()); // PF_R|X
    bytes[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&file_size.to_le_bytes());
    bytes[104..112].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[112..120].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[0xb0..].copy_from_slice(code);
    bytes
}

#[test]
fn production_sigprocmask_uses_shared_lifecycle_family() {
    let code = [
        // NULL set and oldset need no guest memory or host resource. The old
        // CommonFamilies lifecycle path still forwarded this valid call.
        0x31, 0xf6, // xor esi,esi: no new set
        0x31, 0xff, // xor edi,edi: SIG_BLOCK
        0x31, 0xd2, // xor edx,edx: no old set
        0x49, 0xc7, 0xc2, 0x08, 0x00, 0x00, 0x00, // mov r10,8
        0xb8, 0x0e, 0x00, 0x00, 0x00, // mov eax,14: rt_sigprocmask
        0x0f, 0x05, // syscall
        0x48, 0x85, 0xc0, // test rax,rax
        0xbf, 0x07, 0x00, 0x00, 0x00, // mov edi,7: success exit
        0x74, 0x05, // jz exit_group
        0xbf, 0x09, 0x00, 0x00, 0x00, // mov edi,9: failure exit
        0xb8, 0xe7, 0x00, 0x00, 0x00, // mov eax,231: exit_group
        0x0f, 0x05, 0x0f, 0x0b, // syscall; ud2
    ];
    let elf = tiny_elf(&code);
    let image = prepare_static_x86_elf(&elf).expect("static x86 ELF");
    let extent =
        Cpl0Carrier::initial_extent_bytes_for(&image, &[], &[]).expect("bounded initial extent");
    let mut carrier = Cpl0Carrier::boot_production(extent).expect("production KVM image");
    carrier
        .load_guest_mm(&image, &[], &[])
        .expect("initial guest MM");
    let (status, semantic_host_exits) = carrier
        .run_initial_process(4, |_, _| -1)
        .expect("shared lifecycle call and exit");
    assert_eq!(status, 7);
    assert_eq!(semantic_host_exits, 1); // only exit_group reaches the host
}
