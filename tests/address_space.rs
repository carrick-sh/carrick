use carrick::dispatch::{GuestMemory, SyscallDispatcher, SyscallRequest};
use carrick::elf::SegmentPerms;
use carrick::memory::AddressSpace;

use carrick::compat::{CompatReporter, SyscallArgs};

#[test]
fn loads_static_linux_fixture_into_guest_address_space() {
    build_fixture();
    let image = AddressSpace::load_elf(
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-hello",
    )
    .unwrap();

    assert!(image.entry() >= image.regions()[0].start);
    assert!(image.regions().iter().any(|region| region.perms.execute));
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
