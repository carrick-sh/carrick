// Test code: helpers are plain `fn`s (not `#[test]`/`#[cfg(test)]`), so clippy's
// allow-unwrap-in-tests heuristic does not exempt them. The no-panic gate targets
// production code, so allow unwrap/expect across this integration test file.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::VecDeque;
use std::process::Command;

use carrick_runtime::dispatch::{Aarch64SyscallFrame, GuestMemory, LinearMemory, SyscallDispatcher};
use carrick_runtime::memory::AddressSpace;
use carrick_runtime::rootfs::{LayerSource, RootFs};
use carrick_runtime::runtime::{SyscallTrap, run_syscall_loop, run_syscall_loop_with_dispatcher};
use carrick_runtime::trap::TrapError;
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

    let result = run_syscall_loop(&mut memory, &mut trap, 0).unwrap();

    assert!(result.trap_limit_hit);
    assert_eq!(result.exit_code, -1);
    assert_eq!(result.traps, 0);
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

#[test]
fn runtime_loop_can_list_a_rootfs_directory() {
    let rootfs = RootFs::from_layers([LayerSource::TarGz(gzip_tar([(
        "etc/motd",
        b"rootfs says hello\n".as_slice(),
    )]))])
    .unwrap();
    let mut memory = LinearMemory::new(0x4000, vec![0; 0x400]);
    memory.write_bytes(0x4000, b"/etc\0").unwrap();
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
            x2: 0x100,
            x3: 0,
            x4: 0,
            x5: 0,
            x8: 61,
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
    assert_eq!(result.traps, 4);
    assert_eq!(trap.return_values[0], 3);
    assert!(trap.return_values[1] > 0);
    assert_eq!(trap.return_values[2], 0);
    assert!(
        memory
            .read_bytes(0x4100, trap.return_values[1] as usize)
            .unwrap()[..]
            .windows(4)
            .any(|window| window == b"motd")
    );
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
    fn next_syscall(&mut self) -> Result<Option<Aarch64SyscallFrame>, TrapError> {
        self.frames
            .pop_front()
            .map(Some)
            .ok_or_else(|| TrapError::Hypervisor("scripted trap stream exhausted".to_owned()))
    }

    fn current_pc(&self) -> Result<u64, TrapError> {
        Ok(0)
    }

    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError> {
        self.return_values.push(return_value);
        Ok(())
    }

    fn fork(&mut self) -> Result<carrick_runtime::trap::ForkOutcome, TrapError> {
        Err(TrapError::Hypervisor(
            "scripted trap does not implement fork".to_owned(),
        ))
    }

    fn execve_into(&mut self, _: &carrick_runtime::memory::AddressSpace) -> Result<(), TrapError> {
        Err(TrapError::Hypervisor(
            "scripted trap does not implement execve".to_owned(),
        ))
    }

    fn inject_signal(
        &mut self,
        _signum: i32,
        _handler: u64,
        _sa_restorer: u64,
        _pending_syscall_retval: Option<i64>,
        _interrupted_pc: Option<u64>,
        _altstack: Option<(u64, u64)>,
        _saved_sigmask: u64,
        _fault_siginfo: Option<(i32, u64)>,
    ) -> Result<(), TrapError> {
        Err(TrapError::Hypervisor(
            "scripted trap does not implement inject_signal".to_owned(),
        ))
    }

    fn restore_from_sigframe(&mut self) -> Result<u64, TrapError> {
        Err(TrapError::Hypervisor(
            "scripted trap does not implement restore_from_sigframe".to_owned(),
        ))
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
