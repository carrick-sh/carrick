// Test code: helpers are plain `fn`s (not `#[test]`/`#[cfg(test)]`), so clippy's
// allow-unwrap-in-tests heuristic does not exempt them. The no-panic gate targets
// production code, so allow unwrap/expect across this integration test file.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use carrick::dispatch::{GuestMemory, SyscallDispatcher, SyscallRequest};
use carrick::elf::SegmentPerms;
use carrick::linux_abi::{
    LINUX_AT_BASE, LINUX_AT_ENTRY, LINUX_AT_NULL, LINUX_AT_PAGESZ, LINUX_AT_PHDR, LINUX_AT_PHENT,
    LINUX_AT_PHNUM, LinuxAuxvEntry,
};
use carrick::memory::{AddressSpace, LINUX_HEAP_BASE, LINUX_INTERPRETER_BASE, LINUX_MMAP_BASE};
use carrick::rootfs::{LayerSource, RootFs};
use zerocopy::{FromBytes, IntoBytes};

use carrick::compat::{CompatReporter, SyscallArgs};

#[test]
fn loads_static_linux_fixture_into_guest_address_space() {
    build_fixture();
    let artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-hello";
    let image = AddressSpace::load_elf(artifact).unwrap();

    assert!(image.entry() >= image.regions()[0].start);
    assert!(image.regions().iter().any(|region| region.perms.execute));
    assert!(image.find_bytes(b"hello from carrick\n").is_some());

    let bytes = std::fs::read(artifact).unwrap();
    let image = AddressSpace::load_elf_bytes(&bytes).unwrap();
    assert!(image.find_bytes(b"hello from carrick\n").is_some());
}

#[test]
fn zero_fills_memory_past_file_backing() {
    let image = AddressSpace::from_segments(
        0x1000,
        [(
            0x1000,
            SegmentPerms {
                read: true,
                write: true,
                execute: false,
            },
            b"abc".to_vec(),
            8,
        )],
    )
    .unwrap();

    assert_eq!(image.read_bytes(0x1000, 8).unwrap(), b"abc\0\0\0\0\0");
}

#[test]
fn builds_linux_initial_stack_with_argv_envp_and_auxv() {
    let image = AddressSpace::from_segments(
        0x1000,
        [(
            0x1000,
            SegmentPerms {
                read: true,
                write: false,
                execute: true,
            },
            vec![0xd4, 0x20, 0x00, 0x00],
            4,
        )],
    )
    .unwrap()
    .with_linux_initial_stack(
        ["/bin/cat-motd".to_owned(), "/etc/motd".to_owned()],
        ["PATH=/bin".to_owned()],
    )
    .unwrap();

    let sp = image.initial_stack_pointer().unwrap();
    assert_eq!(sp % 16, 0);
    assert_eq!(read_u64(&image, sp), 2);

    let argv0 = read_u64(&image, sp + 8);
    let argv1 = read_u64(&image, sp + 16);
    assert_eq!(read_c_string(&image, argv0), "/bin/cat-motd");
    assert_eq!(read_c_string(&image, argv1), "/etc/motd");
    assert_eq!(read_u64(&image, sp + 24), 0);

    let env0 = read_u64(&image, sp + 32);
    assert_eq!(read_c_string(&image, env0), "PATH=/bin");
    assert_eq!(read_u64(&image, sp + 40), 0);
    assert_eq!(read_u64(&image, sp + 48), 0);
    assert_eq!(read_u64(&image, sp + 56), 0);
}

#[test]
fn loaded_elf_initial_stack_includes_linux_auxv() {
    build_fixture();
    let artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-hello";
    let image = AddressSpace::load_elf(artifact)
        .unwrap()
        .with_linux_initial_stack([artifact.to_owned()], std::iter::empty::<String>())
        .unwrap();
    let sp = image.initial_stack_pointer().unwrap();
    let auxv = read_auxv(&image, sp + 32);

    assert!(auxv.contains(&(LINUX_AT_ENTRY, image.entry())));
    assert!(
        auxv.iter()
            .any(|(tag, value)| *tag == LINUX_AT_PHDR && *value != 0)
    );
    assert!(auxv.contains(&(LINUX_AT_PHENT, 56)));
    assert!(
        auxv.iter()
            .any(|(tag, value)| *tag == LINUX_AT_PHNUM && *value > 0)
    );
    assert!(auxv.contains(&(LINUX_AT_PAGESZ, 4096)));
    assert_eq!(auxv.last(), Some(&(LINUX_AT_NULL, 0)));
}

#[test]
fn load_elf_from_rootfs_maps_pt_interp_at_base_and_sets_at_base() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([
        ("bin/app", dynamic_aarch64_elf("/lib/ld-linux-aarch64.so.1")),
        ("lib/ld-linux-aarch64.so.1", interpreter_aarch64_elf()),
    ]))])
    .unwrap();

    let image = AddressSpace::load_elf_from_rootfs("/bin/app", &rootfs)
        .unwrap()
        .with_linux_initial_stack(["/bin/app".to_owned()], std::iter::empty::<String>())
        .unwrap();
    let sp = image.initial_stack_pointer().unwrap();
    let auxv = read_auxv(&image, sp + 32);

    assert_eq!(image.entry(), LINUX_INTERPRETER_BASE + 0x120);
    assert!(image.read_bytes(0x400120, 4).is_ok());
    assert!(image.read_bytes(LINUX_INTERPRETER_BASE + 0x120, 4).is_ok());
    assert!(image.read_bytes(LINUX_HEAP_BASE, 1).is_ok());
    assert!(image.read_bytes(LINUX_MMAP_BASE, 1).is_ok());
    assert!(auxv.contains(&(LINUX_AT_ENTRY, 0x400120)));
    assert!(auxv.contains(&(LINUX_AT_BASE, LINUX_INTERPRETER_BASE)));
}

#[test]
fn dispatcher_can_write_from_loaded_guest_memory() {
    let mut image = AddressSpace::from_segments(
        0x1000,
        [(
            0x4000,
            SegmentPerms {
                read: true,
                write: false,
                execute: false,
            },
            b"hello".to_vec(),
            5,
        )],
    )
    .unwrap();
    let mut reporter = CompatReporter::default();
    let mut dispatcher = SyscallDispatcher::new();

    dispatcher
        .dispatch(
            SyscallRequest::new(64, SyscallArgs::from([1, 0x4000, 5, 0, 0, 0])),
            &mut image,
            &mut reporter,
        )
        .unwrap();

    assert_eq!(dispatcher.stdout(), b"hello");
}

#[test]
fn rejects_overlapping_regions() {
    let err = AddressSpace::from_segments(
        0x1000,
        [
            (
                0x1000,
                SegmentPerms {
                    read: true,
                    write: false,
                    execute: false,
                },
                vec![1, 2, 3],
                3,
            ),
            (
                0x1002,
                SegmentPerms {
                    read: true,
                    write: false,
                    execute: false,
                },
                vec![4, 5, 6],
                3,
            ),
        ],
    )
    .unwrap_err();

    assert!(err.to_string().contains("overlaps"));
}

fn read_u64(image: &AddressSpace, address: u64) -> u64 {
    let bytes: [u8; 8] = image.read_bytes(address, 8).unwrap().try_into().unwrap();
    u64::from_le_bytes(bytes)
}

fn read_c_string(image: &AddressSpace, address: u64) -> String {
    let mut bytes = Vec::new();
    let mut cursor = address;
    loop {
        let byte = image.read_bytes(cursor, 1).unwrap()[0];
        if byte == 0 {
            return String::from_utf8(bytes).unwrap();
        }
        bytes.push(byte);
        cursor += 1;
    }
}

fn read_auxv(image: &AddressSpace, address: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut cursor = address;
    loop {
        let entry = read_auxv_entry(image, cursor);
        let tag = entry.tag();
        let value = entry.value();
        out.push((tag, value));
        if tag == LINUX_AT_NULL {
            return out;
        }
        cursor += core::mem::size_of::<LinuxAuxvEntry>() as u64;
    }
}

fn read_auxv_entry(image: &AddressSpace, address: u64) -> LinuxAuxvEntry {
    let bytes = image
        .read_bytes(address, core::mem::size_of::<LinuxAuxvEntry>())
        .unwrap();
    LinuxAuxvEntry::read_from_bytes(&bytes).unwrap()
}

fn build_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn dynamic_aarch64_elf(interpreter: &str) -> Vec<u8> {
    let mut elf = aarch64_elf_header(0x400120, 2, ET_EXEC);
    let interp_offset = 0x100;
    let code_offset = 0x120;
    let code = 0xd4200000_u32.to_le_bytes();

    write_program_header(
        &mut elf,
        0,
        ProgramHeader {
            p_type: PT_LOAD,
            p_flags: PF_R | PF_X,
            p_offset: 0,
            p_vaddr: 0x400000,
            p_filesz: 0x124,
            p_memsz: 0x124,
            p_align: 0x1000,
        },
    );
    write_program_header(
        &mut elf,
        1,
        ProgramHeader {
            p_type: PT_INTERP,
            p_flags: PF_R,
            p_offset: interp_offset as u64,
            p_vaddr: 0x400100,
            p_filesz: interpreter.len() as u64 + 1,
            p_memsz: interpreter.len() as u64 + 1,
            p_align: 1,
        },
    );

    elf[interp_offset..interp_offset + interpreter.len()].copy_from_slice(interpreter.as_bytes());
    elf[interp_offset + interpreter.len()] = 0;
    elf[code_offset..code_offset + code.len()].copy_from_slice(&code);
    elf
}

fn interpreter_aarch64_elf() -> Vec<u8> {
    let mut elf = aarch64_elf_header(0x120, 1, ET_DYN);
    let code_offset = 0x120;
    let code = 0xd4200000_u32.to_le_bytes();
    write_program_header(
        &mut elf,
        0,
        ProgramHeader {
            p_type: PT_LOAD,
            p_flags: PF_R | PF_X,
            p_offset: 0,
            p_vaddr: 0,
            p_filesz: 0x124,
            p_memsz: 0x124,
            p_align: 0x1000,
        },
    );
    elf[code_offset..code_offset + code.len()].copy_from_slice(&code);
    elf
}

fn aarch64_elf_header(entry: u64, phnum: u16, elf_type: u16) -> Vec<u8> {
    let mut elf = vec![0_u8; 0x124];
    let header = Elf64Header {
        e_ident: elf64_ident(),
        e_type: elf_type,
        e_machine: EM_AARCH64,
        e_version: 1,
        e_entry: entry,
        e_phoff: ELF64_HEADER_SIZE as u64,
        e_shoff: 0,
        e_flags: 0,
        e_ehsize: ELF64_HEADER_SIZE as u16,
        e_phentsize: ELF64_PROGRAM_HEADER_SIZE as u16,
        e_phnum: phnum,
        e_shentsize: 0,
        e_shnum: 0,
        e_shstrndx: 0,
    };
    elf[..ELF64_HEADER_SIZE].copy_from_slice(header.as_bytes());
    elf
}

struct ProgramHeader {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

fn write_program_header(elf: &mut [u8], index: usize, header: ProgramHeader) {
    let ph = ELF64_HEADER_SIZE + index * ELF64_PROGRAM_HEADER_SIZE;
    let packed = Elf64ProgramHeader {
        p_type: header.p_type,
        p_flags: header.p_flags,
        p_offset: header.p_offset,
        p_vaddr: header.p_vaddr,
        p_paddr: header.p_vaddr,
        p_filesz: header.p_filesz,
        p_memsz: header.p_memsz,
        p_align: header.p_align,
    };
    elf[ph..ph + ELF64_PROGRAM_HEADER_SIZE].copy_from_slice(packed.as_bytes());
}

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_AARCH64: u16 = 183;
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PF_X: u32 = 1;
const PF_R: u32 = 4;
const ELF64_HEADER_SIZE: usize = core::mem::size_of::<Elf64Header>();
const ELF64_PROGRAM_HEADER_SIZE: usize = core::mem::size_of::<Elf64ProgramHeader>();

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, zerocopy::IntoBytes, zerocopy::Immutable)]
struct Elf64Header {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, zerocopy::IntoBytes, zerocopy::Immutable)]
struct Elf64ProgramHeader {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

fn elf64_ident() -> [u8; 16] {
    let mut ident = [0; 16];
    ident[0..4].copy_from_slice(b"\x7fELF");
    ident[4] = 2;
    ident[5] = 1;
    ident[6] = 1;
    ident
}

fn gzip_tar<const N: usize>(files: [(&str, Vec<u8>); N]) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for (path, contents) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            builder
                .append_data(&mut header, path, contents.as_slice())
                .unwrap();
        }
        builder.finish().unwrap();
    }

    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut encoder, &tar_bytes).unwrap();
    encoder.finish().unwrap()
}
