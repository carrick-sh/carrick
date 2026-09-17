//! Syscall constructor helpers.

use carrick_abi::syscall::nr;
use carrick_abi::{CanonicalNr, LINUX_SIGCHLD};

use crate::operand::{Expect, Operand, Syscall};

fn call(label: &'static str, nr: CanonicalNr, args: [Operand; 6]) -> Syscall {
    Syscall {
        label,
        nr,
        args,
        saves: Vec::new(),
        expect: Expect::Any,
    }
}

/// `pipe2(2)`: allocates an 8-byte buffer for the two fds at arg 0.
pub fn pipe2(flags: i32) -> Syscall {
    call(
        "pipe2",
        nr::PIPE2,
        [
            Operand::Out(8),
            (flags as i64).into(),
            0.into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `clone(2)` with `SIGCHLD`: issues a fork.
pub fn fork() -> Syscall {
    call(
        "fork",
        nr::CLONE,
        [
            (LINUX_SIGCHLD as i64).into(),
            0.into(),
            0.into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `read(2)`: allocates an `Out(len)` buffer at arg 1.
pub fn read(fd: impl Into<Operand>, len: usize) -> Syscall {
    call(
        "read",
        nr::READ,
        [
            fd.into(),
            Operand::Out(len),
            (len as i64).into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `write(2)`: puts `data` into guest memory at arg 1.
pub fn write(fd: impl Into<Operand>, data: &[u8]) -> Syscall {
    call(
        "write",
        nr::WRITE,
        [
            fd.into(),
            Operand::Bytes(data.to_vec()),
            (data.len() as i64).into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `close(2)`.
pub fn close(fd: impl Into<Operand>) -> Syscall {
    call(
        "close",
        nr::CLOSE,
        [fd.into(), 0.into(), 0.into(), 0.into(), 0.into(), 0.into()],
    )
}

/// `wait4(2)`: allocates a 4-byte `Out(4)` status buffer at arg 1.
pub fn wait4(pid: impl Into<Operand>, options: i32) -> Syscall {
    call(
        "wait4",
        nr::WAIT4,
        [
            pid.into(),
            Operand::Out(4),
            (options as i64).into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `exit_group(2)`: terminates the task group.
pub fn exit_group(code: i32) -> Syscall {
    call(
        "exit_group",
        nr::EXIT_GROUP,
        [
            (code as i64).into(),
            0.into(),
            0.into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `getpid(2)`.
pub fn getpid() -> Syscall {
    call(
        "getpid",
        nr::GETPID,
        [0.into(), 0.into(), 0.into(), 0.into(), 0.into(), 0.into()],
    )
}

/// `getppid(2)`.
pub fn getppid() -> Syscall {
    call(
        "getppid",
        nr::GETPPID,
        [0.into(), 0.into(), 0.into(), 0.into(), 0.into(), 0.into()],
    )
}
