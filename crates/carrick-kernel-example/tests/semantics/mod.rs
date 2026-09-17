//! Shared helpers, constructor functions, and decoders for the semantics suite.

pub use carrick_abi::syscall::nr;
pub use carrick_abi::*;
pub use carrick_kernel_example::{
    ExampleError, Expect, Operand, Output, RunReport, Save, ScriptedBackend, Step, Syscall,
    await_parked, in_out, last_child, slot, sys,
};

pub const LINUX_O_NONBLOCK: i32 = 0x800; // 2048
pub const LINUX_F_GETFL: i32 = 3;
pub const LINUX_F_SETFL: i32 = 4;
pub const LINUX_F_SETPIPE_SZ: i32 = 1031;
pub const LINUX_F_GETPIPE_SZ: i32 = 1032;
pub const LINUX_FIONREAD: u64 = 0x541B;

pub const LINUX_PR_SET_CHILD_SUBREAPER: i32 = 36;
pub const LINUX_PR_GET_CHILD_SUBREAPER: i32 = 37;

pub const LINUX_P_ALL: i32 = 0;
pub const LINUX_P_PID: i32 = 1;
pub const LINUX_P_PGID: i32 = 2;
pub const LINUX_P_PIDFD: i32 = 3;

pub const LINUX_WNOHANG: i32 = 1;
pub const LINUX_WSTOPPED: i32 = 2;
pub const LINUX_WEXITED: i32 = 4;
pub const LINUX_WCONTINUED: i32 = 8;
pub const LINUX_WNOWAIT: i32 = 0x0100_0000;

pub fn run(script: Vec<Step>) -> RunReport {
    ScriptedBackend::new()
        .run_root(script)
        .expect("backend ran")
}

/// Decode the exit status word from the first output captured for `label`.
pub fn wait_status(run: &RunReport, label: &str) -> i32 {
    i32::from_le_bytes(run.output(label)[0..4].try_into().unwrap())
}

/// `WEXITSTATUS(s)` per `man 2 wait4` (bits 8..16).
pub fn wexitstatus(s: i32) -> i32 {
    (s >> 8) & 0xff
}

/// `WTERMSIG(s)` per `man 2 wait4` (bits 0..7).
pub fn wtermsig(s: i32) -> i32 {
    s & 0x7f
}

/// `WIFEXITED(s)` per `man 2 wait4`.
pub fn wifexited(s: i32) -> bool {
    (s & 0x7f) == 0
}

/// `WIFSIGNALED(s)` per `man 2 wait4`.
pub fn wifsignaled(s: i32) -> bool {
    (((s & 0x7f) + 1) as i8 >> 1) > 0
}

/// Standard pipe helper saving read end to slot 0 and write end to slot 1.
pub fn pipe() -> Step {
    pipe_to_slots(0, 1)
}

/// Pipe helper saving read end to `read_slot` and write end to `write_slot`.
pub fn pipe_to_slots(read_slot: usize, write_slot: usize) -> Step {
    Step::Sys(
        sys::pipe2(0)
            .ret(0)
            .save_out_i32(0, 0, read_slot)
            .save_out_i32(0, 1, write_slot),
    )
}

/// Generic syscall builder.
pub fn call(
    label: &'static str,
    nr: carrick_abi::CanonicalNr,
    args: [carrick_kernel_example::Operand; 6],
) -> Syscall {
    Syscall::new(label, nr, args)
}

/// `waitid(2)`: allocates a 128-byte `Out(128)` buffer for `siginfo_t` at arg 2.
pub fn waitid(
    idtype: impl Into<carrick_kernel_example::Operand>,
    id: impl Into<carrick_kernel_example::Operand>,
    options: i32,
) -> Syscall {
    waitid_labeled("waitid", idtype, id, options)
}

/// `waitid(2)` with a custom diagnostic label.
pub fn waitid_labeled(
    label: &'static str,
    idtype: impl Into<carrick_kernel_example::Operand>,
    id: impl Into<carrick_kernel_example::Operand>,
    options: i32,
) -> Syscall {
    call(
        label,
        nr::WAITID,
        [
            idtype.into(),
            id.into(),
            carrick_kernel_example::Operand::Out(128),
            (options as i64).into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `wait4(2)` with a custom diagnostic label and 4-byte `wstatus` buffer at arg 1.
pub fn wait4_labeled(
    label: &'static str,
    pid: impl Into<carrick_kernel_example::Operand>,
    options: i32,
) -> Syscall {
    call(
        label,
        nr::WAIT4,
        [
            pid.into(),
            carrick_kernel_example::Operand::Out(4),
            (options as i64).into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `prctl(2)`: operations on a process.
pub fn prctl(option: i32, arg2: impl Into<carrick_kernel_example::Operand>) -> Syscall {
    call(
        "prctl",
        nr::PRCTL,
        [
            (option as i64).into(),
            arg2.into(),
            0.into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `setpgid(2)`: set process group ID.
pub fn setpgid(
    pid: impl Into<carrick_kernel_example::Operand>,
    pgid: impl Into<carrick_kernel_example::Operand>,
) -> Syscall {
    call(
        "setpgid",
        nr::SETPGID,
        [
            pid.into(),
            pgid.into(),
            0.into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `getpgid(2)`: get process group ID.
pub fn getpgid(pid: impl Into<carrick_kernel_example::Operand>) -> Syscall {
    call(
        "getpgid",
        nr::GETPGID,
        [pid.into(), 0.into(), 0.into(), 0.into(), 0.into(), 0.into()],
    )
}

/// `getpgrp(2)`: get process group ID of calling process.
pub fn getpgrp() -> Syscall {
    getpgid(0)
}

/// `setsid(2)`: create a new session and set process group ID.
pub fn setsid() -> Syscall {
    call(
        "setsid",
        nr::SETSID,
        [0.into(), 0.into(), 0.into(), 0.into(), 0.into(), 0.into()],
    )
}

/// `getsid(2)`: get session ID.
pub fn getsid(pid: impl Into<carrick_kernel_example::Operand>) -> Syscall {
    call(
        "getsid",
        nr::GETSID,
        [pid.into(), 0.into(), 0.into(), 0.into(), 0.into(), 0.into()],
    )
}

/// `fcntl(2)`: manipulate file descriptor.
pub fn fcntl(
    fd: impl Into<carrick_kernel_example::Operand>,
    cmd: i32,
    arg: impl Into<carrick_kernel_example::Operand>,
) -> Syscall {
    call(
        "fcntl",
        nr::FCNTL,
        [
            fd.into(),
            (cmd as i64).into(),
            arg.into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `fcntl(fd, F_SETFL, flags)`.
pub fn fcntl_setfl(fd: impl Into<carrick_kernel_example::Operand>, flags: i32) -> Syscall {
    fcntl(fd, LINUX_F_SETFL, flags)
}

/// `fcntl(fd, F_GETPIPE_SZ, 0)`.
pub fn fcntl_getpipe_sz(fd: impl Into<carrick_kernel_example::Operand>) -> Syscall {
    fcntl(fd, LINUX_F_GETPIPE_SZ, 0)
}

/// `ioctl(2)`: control device / descriptor.
pub fn ioctl(
    fd: impl Into<carrick_kernel_example::Operand>,
    request: u64,
    arg: impl Into<carrick_kernel_example::Operand>,
) -> Syscall {
    call(
        "ioctl",
        nr::IOCTL,
        [
            fd.into(),
            (request as i64).into(),
            arg.into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `ioctl(fd, FIONREAD, &mut bytes_ready)` with a custom diagnostic label.
pub fn ioctl_fionread_labeled(
    label: &'static str,
    fd: impl Into<carrick_kernel_example::Operand>,
) -> Syscall {
    call(
        label,
        nr::IOCTL,
        [
            fd.into(),
            (LINUX_FIONREAD as i64).into(),
            carrick_kernel_example::Operand::Out(4),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `ioctl(fd, FIONREAD, &mut bytes_ready)`.
pub fn ioctl_fionread(fd: impl Into<carrick_kernel_example::Operand>) -> Syscall {
    ioctl_fionread_labeled("ioctl_fionread", fd)
}

/// `dup3(2)`: duplicate a file descriptor.
pub fn dup3(
    oldfd: impl Into<carrick_kernel_example::Operand>,
    newfd: impl Into<carrick_kernel_example::Operand>,
    flags: i32,
) -> Syscall {
    call(
        "dup3",
        nr::DUP3,
        [
            oldfd.into(),
            newfd.into(),
            (flags as i64).into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}
