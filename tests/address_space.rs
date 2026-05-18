use carrick::dispatch::{GuestMemory, SyscallDispatcher, SyscallRequest};
use carrick::elf::SegmentPerms;
use carrick::linux_abi::{
    LINUX_AT_ENTRY, LINUX_AT_NULL, LINUX_AT_PAGESZ, LINUX_AT_PHDR, LINUX_AT_PHENT, LINUX_AT_PHNUM,
};
use carrick::memory::AddressSpace;

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
        let tag = read_u64(image, cursor);
        let value = read_u64(image, cursor + 8);
        out.push((tag, value));
        if tag == LINUX_AT_NULL {
            return out;
        }
        cursor += 16;
    }
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
