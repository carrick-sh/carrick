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

pub use carrick_kernel_example::sys::{
    dup3, fcntl, fcntl_getpipe_sz, fcntl_setfl, fcntl_setpipe_sz, getpgid, getpgrp, getsid, ioctl,
    ioctl_fionread, ioctl_fionread_labeled, prctl, setpgid, setsid, wait4_labeled, waitid,
    waitid_labeled,
};

/// Generic syscall builder for case-specific diagnostic labels.
pub fn call(label: &'static str, nr: carrick_abi::CanonicalNr, args: [Operand; 6]) -> Syscall {
    Syscall::new(label, nr, args)
}
