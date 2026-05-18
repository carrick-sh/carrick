use std::collections::VecDeque;
use std::process::Command;

use carrick::dispatch::{Aarch64SyscallFrame, LinearMemory};
use carrick::memory::AddressSpace;
use carrick::runtime::{RuntimeError, SyscallTrap, run_syscall_loop};
use carrick::trap::TrapError;

const HELLO: &[u8] = b"hello from carrick\n";

#[test]
fn runtime_loop_dispatches_static_elf_write_and_exit() {
    build_linux_fixture();
    let image = AddressSpace::load_elf(
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

    let result = run_syscall_loop(&image, &mut trap, 8).unwrap();

    assert_eq!(result.exit_code, 0);
    assert_eq!(result.stdout, HELLO);
    assert!(result.stderr.is_empty());
    assert_eq!(result.traps, 2);
    assert_eq!(trap.return_values, [HELLO.len() as i64]);
    assert!(result.report.unhandled_syscalls.is_empty());
}

#[test]
fn runtime_loop_stops_when_guest_never_exits() {
    let memory = LinearMemory::new(0x4000, b"x".to_vec());
    let mut trap = ScriptedTrap::new([Aarch64SyscallFrame {
        x0: 1,
        x1: 0x4000,
        x2: 1,
        x3: 0,
        x4: 0,
        x5: 0,
        x8: 64,
    }]);

    let err = run_syscall_loop(&memory, &mut trap, 0).unwrap_err();

    assert!(matches!(
        err,
        RuntimeError::TrapLimitExceeded { max_traps: 0 }
    ));
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
