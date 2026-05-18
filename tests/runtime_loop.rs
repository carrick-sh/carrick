use std::collections::VecDeque;
use std::process::Command;

use carrick::dispatch::{Aarch64SyscallFrame, GuestMemory, LinearMemory, SyscallDispatcher};
use carrick::memory::AddressSpace;
use carrick::rootfs::{LayerSource, RootFs};
use carrick::runtime::{
    RuntimeError, SyscallTrap, run_syscall_loop, run_syscall_loop_with_dispatcher,
};
use carrick::trap::TrapError;
use flate2::Compression;
use flate2::write::GzEncoder;
use std::io::Write;

const HELLO: &[u8] = b"hello from carrick\n";

#[test]
fn runtime_loop_dispatches_static_elf_write_and_exit() {
    build_linux_fixture();
    let mut image = AddressSpace::load_elf(
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-hello",
    )
    .unwrap();
    let message = image.find_bytes(HELLO).unwrap();
    let mut trap = ScriptedTrap::new([
        Aarch64SyscallFrame {
            x0: 1,
            x1: message,
            x2: HELLO.len() as u64,
            x3: 0,
            x4: 0,
            x5: 0,
            x8: 64,
        },
        Aarch64SyscallFrame {
            x0: 0,
            x1: 0,
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
            x8: 93,
        },
    ]);

    let result = run_syscall_loop(&mut image, &mut trap, 8).unwrap();

    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout, HELLO);
    assert!(result.stderr.is_empty());
    assert_eq!(result.traps, 2);
    assert_eq!(trap.return_values, [HELLO.len() as i64]);
    assert!(result.report.unhandled_syscalls.is_empty());
}

#[test]
fn runtime_loop_stops_when_guest_never_exits() {
    let mut memory = LinearMemory::new(0x4000, b"x".to_vec());
    let mut trap = ScriptedTrap::new([Aarch64SyscallFrame {
        x0: 1,
        x1: 0x4000,
        x2: 1,
        x3: 0,
        x4: 0,
        x5: 0,
        x8: 64,
    }]);

    let err = run_syscall_loop(&mut memory, &mut trap, 0).unwrap_err();

    assert!(matches!(
        err,
        RuntimeError::TrapLimitExceeded { max_traps: 0 }
    ));
}

#[test]
fn runtime_loop_can_cat_a_rootfs_file() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x300]);
    memory.write_bytes(0x4000, b"/etc/motd\0").unwrap();
    let mut trap = ScriptedTrap::new([
        Aarch64SyscallFrame {
            x0: (-100_i64) as u64,
            x1: 0x4000,
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
            x8: 56,
        },
        Aarch64SyscallFrame {
            x0: 3,
            x1: 0x4100,
            x2: 64,
            x3: 0,
            x4: 0,
            x5: 0,
            x8: 63,
        },
        Aarch64SyscallFrame {
            x0: 1,
            x1: 0x4100,
            x2: 18,
            x3: 0,
            x4: 0,
            x5: 0,
            x8: 64,
        },
        Aarch64SyscallFrame {
            x0: 3,
            x1: 0,
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
            x8: 57,
        },
        Aarch64SyscallFrame {
            x0: 0,
            x1: 0,
            x2: 0,
            x3: 0,
            x4: 0,
            x5: 0,
            x8: 93,
        },
    ]);

    let result = run_syscall_loop_with_dispatcher(
        &mut memory,
        &mut trap,
        SyscallDispatcher::with_rootfs(rootfs),
        8,
    )
    .unwrap();

    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout, b"rootfs says hello\n");
    assert_eq!(result.traps, 5);
    assert_eq!(trap.return_values, [3, 18, 18, 0]);
    assert!(result.report.unhandled_syscalls.is_empty());
}

struct ScriptedTrap {
    frames: VecDeque<Aarch64SyscallFrame>,
    return_values: Vec<i64>,
}

impl ScriptedTrap {
    fn new(frames: impl IntoIterator<Item = Aarch64SyscallFrame>) -> Self {
        Self {
            frames: frames.into_iter().collect(),
            return_values: Vec::new(),
        }
    }
}

impl SyscallTrap for ScriptedTrap {
    fn next_syscall(&mut self) -> Result<Aarch64SyscallFrame, TrapError> {
        self.frames
            .pop_front()
            .ok_or_else(|| TrapError::Hypervisor("scripted trap stream exhausted".to_owned()))
    }

    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError> {
        self.return_values.push(return_value);
        Ok(())
    }
}

fn build_linux_fixture() {
    let status = Command::new("scripts/build-linux-fixtures.sh")
        .status()
        .unwrap();
    assert!(status.success());
}

fn gzip_tar<const N: usize>(files: [(&str, &[u8]); N]) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for (path, contents) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, contents).unwrap();
        }
        builder.finish().unwrap();
    }

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}
