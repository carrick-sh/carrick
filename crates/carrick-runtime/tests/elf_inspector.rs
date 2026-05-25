use carrick_runtime::elf::{ElfClass, ElfEndianness, Machine, SegmentPerms, inspect_elf, plan_elf_load};

#[test]
fn inspects_minimal_aarch64_linux_elf() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hello");
    std::fs::write(&path, minimal_aarch64_elf()).unwrap();

    let elf = inspect_elf(&path).unwrap();

    assert_eq!(elf.class, ElfClass::Elf64);
    assert_eq!(elf.endianness, ElfEndianness::Little);
    assert_eq!(elf.machine, Machine::Aarch64);
    assert_eq!(elf.entry, 0x400000);
    assert!(elf.interpreter.is_none());
}

#[test]
fn rejects_non_elf_input() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("not-elf");
    std::fs::write(&path, b"#!/bin/sh\n").unwrap();

    let err = inspect_elf(&path).unwrap_err();

    assert!(err.to_string().contains("not an ELF binary"));
}

#[test]
fn creates_load_plan_for_pt_load_segments() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hello");
    std::fs::write(&path, minimal_aarch64_elf_with_load_segment()).unwrap();

    let plan = plan_elf_load(&path).unwrap();

    assert_eq!(plan.entry, 0x400000);
    assert_eq!(plan.segments.len(), 1);
    assert_eq!(plan.segments[0].file_offset, 0x1000);
    assert_eq!(plan.segments[0].virtual_address, 0x400000);
    assert_eq!(plan.segments[0].file_size, 4);
    assert_eq!(plan.segments[0].memory_size, 0x1000);
    assert_eq!(
        plan.segments[0].perms,
        SegmentPerms {
            read: true,
            write: false,
            execute: true
        }
    );
}

#[test]
fn load_plan_derives_linux_auxv_program_header_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hello");
    std::fs::write(&path, minimal_aarch64_elf_with_mapped_headers()).unwrap();

    let plan = plan_elf_load(&path).unwrap();

    assert_eq!(plan.program_header_address, Some(0x400040));
    assert_eq!(plan.program_header_entry_size, 56);
    assert_eq!(plan.program_header_count, 1);
}

fn minimal_aarch64_elf() -> Vec<u8> {
    let mut elf = vec![0_u8; 64];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2; // ELFCLASS64
    elf[5] = 1; // ELFDATA2LSB
    elf[6] = 1; // EV_CURRENT
    elf[7] = 0; // ELFOSABI_SYSV, what Linux toolchains normally use.
    elf[16..18].copy_from_slice(&2_u16.to_le_bytes()); // ET_EXEC
    elf[18..20].copy_from_slice(&183_u16.to_le_bytes()); // EM_AARCH64
    elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
    elf[24..32].copy_from_slice(&0x400000_u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
    elf
}

fn minimal_aarch64_elf_with_mapped_headers() -> Vec<u8> {
    let mut elf = minimal_aarch64_elf_with_load_segment();
    let len = elf.len() as u64;
    let ph = 64;
    elf[ph + 8..ph + 16].copy_from_slice(&0_u64.to_le_bytes());
    elf[ph + 16..ph + 24].copy_from_slice(&0x400000_u64.to_le_bytes());
    elf[ph + 32..ph + 40].copy_from_slice(&len.to_le_bytes());
    elf[ph + 40..ph + 48].copy_from_slice(&len.to_le_bytes());
    elf
}

fn minimal_aarch64_elf_with_load_segment() -> Vec<u8> {
    let mut elf = vec![0_u8; 0x1004];
    elf[0..64].copy_from_slice(&minimal_aarch64_elf());
    elf[32..40].copy_from_slice(&64_u64.to_le_bytes()); // e_phoff
    elf[56..58].copy_from_slice(&1_u16.to_le_bytes()); // e_phnum

    let ph = 64;
    elf[ph..ph + 4].copy_from_slice(&1_u32.to_le_bytes()); // PT_LOAD
    elf[ph + 4..ph + 8].copy_from_slice(&5_u32.to_le_bytes()); // PF_R | PF_X
    elf[ph + 8..ph + 16].copy_from_slice(&0x1000_u64.to_le_bytes());
    elf[ph + 16..ph + 24].copy_from_slice(&0x400000_u64.to_le_bytes());
    elf[ph + 32..ph + 40].copy_from_slice(&4_u64.to_le_bytes());
    elf[ph + 40..ph + 48].copy_from_slice(&0x1000_u64.to_le_bytes());
    elf[ph + 48..ph + 56].copy_from_slice(&0x1000_u64.to_le_bytes());
    elf[0x1000..0x1004].copy_from_slice(b"\x1f\x20\x03\xd5");
    elf
}
