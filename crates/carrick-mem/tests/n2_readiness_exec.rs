//! N2 readiness row 11, L5: Linux image preparation, before MM publication.
//!
//! Authority: System V ABI, Program Header (PT_LOAD / PT_INTERP), and
//! execve(2)'s executable-format requirement:
//! https://www.sco.com/developers/gabi/latest/ch5.pheader.html
//! https://man7.org/linux/man-pages/man2/execve.2.html
//!
//! These invoke the existing production parser, not a replacement parser.
//! They do not establish EL1 venue, owner Exec rollback, or a work budget.
//! N1 owner Exec and the driver's shared parser export are still dependencies.

#![allow(clippy::expect_used)]

use carrick_mem::elf::{ElfType, inspect_elf_bytes, plan_elf_load_bytes_for};
use goblin::elf::{
    header::{EM_AARCH64, ET_EXEC, ET_REL},
    program_header::{PF_R, PF_X, PT_INTERP, PT_LOAD},
};

const PHOFF: usize = 64;
const PHENT: usize = 56;
const PAYLOAD: usize = 0x1000;
const ENTRY: u64 = 0x40_0000;

/// A bounded, sectionless ELF64 fixture. No guest or host mapping is created.
fn executable(interpreter: Option<&[u8]>) -> Vec<u8> {
    let mut bytes = vec![0; PAYLOAD + 4];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
    bytes[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
    bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&ENTRY.to_le_bytes());
    bytes[32..40].copy_from_slice(&(PHOFF as u64).to_le_bytes());
    bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&(PHENT as u16).to_le_bytes());
    let phnum: u16 = if interpreter.is_some() { 2 } else { 1 };
    bytes[56..58].copy_from_slice(&phnum.to_le_bytes());

    let load = if let Some(path) = interpreter {
        let offset = PHOFF + 2 * PHENT;
        bytes[PHOFF..PHOFF + 4].copy_from_slice(&PT_INTERP.to_le_bytes());
        bytes[PHOFF + 8..PHOFF + 16].copy_from_slice(&(offset as u64).to_le_bytes());
        bytes[PHOFF + 32..PHOFF + 40].copy_from_slice(&(path.len() as u64).to_le_bytes());
        bytes[offset..offset + path.len()].copy_from_slice(path);
        PHOFF + PHENT
    } else {
        PHOFF
    };
    bytes[load..load + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
    bytes[load + 4..load + 8].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
    bytes[load + 8..load + 16].copy_from_slice(&(PAYLOAD as u64).to_le_bytes());
    bytes[load + 16..load + 24].copy_from_slice(&ENTRY.to_le_bytes());
    bytes[load + 32..load + 40].copy_from_slice(&4_u64.to_le_bytes());
    bytes[load + 40..load + 48].copy_from_slice(&0x1000_u64.to_le_bytes());
    bytes[load + 48..load + 56].copy_from_slice(&0x1000_u64.to_le_bytes());
    bytes[PAYLOAD..].copy_from_slice(&0xd65f_03c0_u32.to_le_bytes()); // AArch64 ret
    bytes
}

#[test]
fn relocatable_elf_cannot_prepare_an_exec_image() {
    let mut bytes = executable(None);
    let valid = plan_elf_load_bytes_for(&bytes, EM_AARCH64).expect("valid executable control");
    assert_eq!(valid.entry, ENTRY);
    assert_eq!(valid.segments.len(), 1);
    bytes[16..18].copy_from_slice(&ET_REL.to_le_bytes());
    assert_eq!(
        inspect_elf_bytes(&bytes)
            .expect("relocatable inspection")
            .e_type,
        ElfType::Other(ET_REL)
    );

    let result = plan_elf_load_bytes_for(&bytes, EM_AARCH64);
    assert!(
        result.is_err(),
        "row 11: ET_REL produced an exec load plan: {result:?}"
    );
}

#[test]
fn oversized_load_file_cannot_prepare_an_exec_image() {
    let mut bytes = executable(None);
    let valid = plan_elf_load_bytes_for(&bytes, EM_AARCH64).expect("valid executable control");
    assert_eq!(valid.segments[0].file_size, 4);
    // Change only p_memsz. All four file bytes remain present in the fixture.
    bytes[PHOFF + 40..PHOFF + 48].copy_from_slice(&3_u64.to_le_bytes());
    assert!(inspect_elf_bytes(&bytes).is_err());

    let result = plan_elf_load_bytes_for(&bytes, EM_AARCH64);
    assert!(
        result.is_err(),
        "row 11: p_filesz > p_memsz produced a load plan: {result:?}"
    );
}

#[test]
fn unterminated_interp_cannot_select_a_different_interpreter() {
    let mut bytes = executable(Some(b"/ld.so\0"));
    let valid = plan_elf_load_bytes_for(&bytes, EM_AARCH64).expect("valid interpreter control");
    assert_eq!(valid.interpreter.as_deref(), Some("/ld.so"));
    // Leave the NUL in the file, but outside the declared PT_INTERP extent.
    // A parser must not read the following byte to repair a malformed extent.
    bytes[PHOFF + 32..PHOFF + 40].copy_from_slice(&6_u64.to_le_bytes());
    assert!(inspect_elf_bytes(&bytes).is_err());

    let result = plan_elf_load_bytes_for(&bytes, EM_AARCH64);
    assert!(
        result.is_err(),
        "row 11: unterminated PT_INTERP produced a load plan: {result:?}"
    );
}
