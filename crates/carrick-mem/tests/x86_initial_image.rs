//! VM-free contract for the static x86 ELF's exact load description.
use carrick_mem::x86_initial_image::prepare_static_x86_elf;

fn tiny_static_elf() -> Vec<u8> {
    let mut bytes = vec![0; 0x2003];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4..7].copy_from_slice(&[2, 1, 1]);
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
    // RX header + text segment; the ELF program header table is mapped.
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
    bytes[68..72].copy_from_slice(&5u32.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&0x1010u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&0x1010u64.to_le_bytes());
    bytes[112..120].copy_from_slice(&0x1000u64.to_le_bytes());
    // RW data with an initialized prefix and a page of zero-filled BSS.
    bytes[120..124].copy_from_slice(&1u32.to_le_bytes());
    bytes[124..128].copy_from_slice(&6u32.to_le_bytes());
    bytes[128..136].copy_from_slice(&0x2000u64.to_le_bytes());
    bytes[136..144].copy_from_slice(&0x402000u64.to_le_bytes());
    bytes[152..160].copy_from_slice(&3u64.to_le_bytes());
    bytes[160..168].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[168..176].copy_from_slice(&0x1000u64.to_le_bytes());
    // mov eax,231; mov edi,7; syscall; ud2.
    bytes[0x1000..0x100f].copy_from_slice(&[
        0xb8, 0xe7, 0, 0, 0, 0xbf, 7, 0, 0, 0, 0x0f, 0x05, 0x0f, 0x0b, 0x90,
    ]);
    bytes[0x2000..].copy_from_slice(b"hi\n");
    bytes
}

#[test]
fn static_x86_image_reuses_elf_plan_without_host_mm_edits() {
    let elf = tiny_static_elf();
    let image = prepare_static_x86_elf(&elf).expect("static x86 ELF");
    assert_eq!(image.entry, 0x401000);
    assert_eq!((image.phdr, image.phent, image.phnum), (0x400040, 56, 2));
    let text = image.regions.iter().find(|r| r.start == 0x400000).unwrap();
    assert!(text.perms.read && text.perms.execute && !text.perms.write);
    assert_eq!(
        &text.file_bytes[0x1000..0x100c],
        &[0xb8, 0xe7, 0, 0, 0, 0xbf, 7, 0, 0, 0, 0x0f, 0x05]
    );
    let data = image.regions.iter().find(|r| r.start == 0x402000).unwrap();
    assert!(data.perms.read && data.perms.write && !data.perms.execute);
    assert_eq!(data.file_bytes, b"hi\n");
    assert_eq!(data.end - data.start, 4096);
}
