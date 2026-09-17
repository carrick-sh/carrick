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

/// `pselect6(2)` with a timespec timeout and optional sigmask.
pub fn pselect6(
    nfds: i32,
    readfds: impl Into<Operand>,
    writefds: impl Into<Operand>,
    exceptfds: impl Into<Operand>,
    timeout: impl Into<Operand>,
    sigmask: impl Into<Operand>,
) -> Syscall {
    call(
        "pselect6",
        nr::PSELECT6,
        [
            (nfds as i64).into(),
            readfds.into(),
            writefds.into(),
            exceptfds.into(),
            timeout.into(),
            sigmask.into(),
        ],
    )
}

/// `kill(2)`: send signal `sig` to process `pid`.
pub fn kill(pid: impl Into<Operand>, sig: i32) -> Syscall {
    call(
        "kill",
        nr::KILL,
        [
            pid.into(),
            (sig as i64).into(),
            0.into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `tgkill(2)`: send signal `sig` to thread `tid` in thread group `tgid`.
pub fn tgkill(tgid: impl Into<Operand>, tid: impl Into<Operand>, sig: i32) -> Syscall {
    call(
        "tgkill",
        nr::TGKILL,
        [
            tgid.into(),
            tid.into(),
            (sig as i64).into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `rt_sigprocmask(2)`: examine and change blocked signals.
pub fn rt_sigprocmask(
    how: i32,
    set: impl Into<Operand>,
    oldset: impl Into<Operand>,
    sigsetsize: usize,
) -> Syscall {
    call(
        "rt_sigprocmask",
        nr::RT_SIGPROCMASK,
        [
            (how as i64).into(),
            set.into(),
            oldset.into(),
            (sigsetsize as i64).into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `rt_sigprocmask(SIG_BLOCK, mask, NULL, 8)` helper.
pub fn rt_sigprocmask_block(mask: u64) -> Syscall {
    let bytes = mask.to_le_bytes();
    rt_sigprocmask(carrick_abi::LINUX_SIG_BLOCK as i32, bytes.as_slice(), 0, 8)
}

/// `rt_sigaction(2)`: examine and change a signal action.
pub fn rt_sigaction(
    signum: i32,
    act: impl Into<Operand>,
    oldact: impl Into<Operand>,
    sigsetsize: usize,
) -> Syscall {
    call(
        "rt_sigaction",
        nr::RT_SIGACTION,
        [
            (signum as i64).into(),
            act.into(),
            oldact.into(),
            (sigsetsize as i64).into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `rt_sigaction(signum, &SIG_IGN, NULL, 8)` helper.
pub fn rt_sigaction_ign(signum: i32) -> Syscall {
    let mut act = [0u8; 32];
    act[0..8].copy_from_slice(&carrick_abi::LINUX_SIG_IGN.to_le_bytes());
    rt_sigaction(signum, &act[..], 0, 8)
}

/// `rt_sigaction(signum, &SIG_DFL, NULL, 8)` helper.
pub fn rt_sigaction_dfl(signum: i32) -> Syscall {
    let mut act = [0u8; 32];
    act[0..8].copy_from_slice(&carrick_abi::LINUX_SIG_DFL.to_le_bytes());
    rt_sigaction(signum, &act[..], 0, 8)
}

/// `rt_sigtimedwait(2)`: synchronously wait for queued signals.
pub fn rt_sigtimedwait(
    set: impl Into<Operand>,
    info: impl Into<Operand>,
    timeout: impl Into<Operand>,
    sigsetsize: usize,
) -> Syscall {
    call(
        "rt_sigtimedwait",
        nr::RT_SIGTIMEDWAIT,
        [
            set.into(),
            info.into(),
            timeout.into(),
            (sigsetsize as i64).into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `rt_sigtimedwait(mask, &siginfo, NULL, 8)` helper.
pub fn rt_sigtimedwait_siginfo(mask: u64) -> Syscall {
    let bytes = mask.to_le_bytes();
    rt_sigtimedwait(bytes.as_slice(), Operand::Out(128), 0, 8)
}

/// `signalfd4(2)`: create a file descriptor for accepting signals.
pub fn signalfd4(
    fd: impl Into<Operand>,
    mask: impl Into<Operand>,
    sizemask: usize,
    flags: i32,
) -> Syscall {
    call(
        "signalfd4",
        nr::SIGNALFD4,
        [
            fd.into(),
            mask.into(),
            (sizemask as i64).into(),
            (flags as i64).into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `nanosleep(2)`: high-resolution sleep.
pub fn nanosleep(req: impl Into<Operand>, rem: impl Into<Operand>) -> Syscall {
    call(
        "nanosleep",
        nr::NANOSLEEP,
        [
            req.into(),
            rem.into(),
            0.into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `nanosleep` for `ms` milliseconds helper.
pub fn nanosleep_ms(ms: u64) -> Syscall {
    let sec = (ms / 1000) as i64;
    let nsec = ((ms % 1000) * 1_000_000) as i64;
    let mut req = [0u8; 16];
    req[0..8].copy_from_slice(&sec.to_le_bytes());
    req[8..16].copy_from_slice(&nsec.to_le_bytes());
    nanosleep(&req[..], Operand::Out(16))
}

/// `clock_nanosleep(2)`: high-resolution sleep with a specified clock.
pub fn clock_nanosleep(
    clockid: i32,
    flags: i32,
    req: impl Into<Operand>,
    rem: impl Into<Operand>,
) -> Syscall {
    call(
        "clock_nanosleep",
        nr::CLOCK_NANOSLEEP,
        [
            (clockid as i64).into(),
            (flags as i64).into(),
            req.into(),
            rem.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `clock_nanosleep` for `ms` milliseconds helper.
pub fn clock_nanosleep_ms(clockid: i32, flags: i32, ms: u64) -> Syscall {
    let sec = (ms / 1000) as i64;
    let nsec = ((ms % 1000) * 1_000_000) as i64;
    let mut req = [0u8; 16];
    req[0..8].copy_from_slice(&sec.to_le_bytes());
    req[8..16].copy_from_slice(&nsec.to_le_bytes());
    clock_nanosleep(clockid, flags, &req[..], Operand::Out(16))
}

/// `timerfd_create(2)`: create a timer that delivers timer expiration notifications via a file descriptor.
pub fn timerfd_create(clockid: i32, flags: i32) -> Syscall {
    call(
        "timerfd_create",
        nr::TIMERFD_CREATE,
        [
            (clockid as i64).into(),
            (flags as i64).into(),
            0.into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `timerfd_settime(2)`: arm/disarm a timerfd timer.
pub fn timerfd_settime(
    fd: impl Into<Operand>,
    flags: i32,
    new_value: impl Into<Operand>,
    old_value: impl Into<Operand>,
) -> Syscall {
    call(
        "timerfd_settime",
        nr::TIMERFD_SETTIME,
        [
            fd.into(),
            (flags as i64).into(),
            new_value.into(),
            old_value.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `timerfd_settime` for a one-shot `ms` milliseconds expiration helper.
pub fn timerfd_settime_ms(
    fd: impl Into<Operand>,
    flags: i32,
    ms: u64,
    interval_ms: u64,
) -> Syscall {
    let sec = (ms / 1000) as i64;
    let nsec = ((ms % 1000) * 1_000_000) as i64;
    let mut spec = [0u8; 32];
    spec[..8].copy_from_slice(&((interval_ms / 1000) as i64).to_le_bytes());
    spec[8..16].copy_from_slice(&(((interval_ms % 1000) * 1_000_000) as i64).to_le_bytes());
    spec[16..24].copy_from_slice(&sec.to_le_bytes());
    spec[24..32].copy_from_slice(&nsec.to_le_bytes());
    timerfd_settime(fd, flags, &spec[..], 0)
}

/// `timerfd_gettime(2)`: inspect current timer setting.
pub fn timerfd_gettime(fd: impl Into<Operand>, curr_value: impl Into<Operand>) -> Syscall {
    call(
        "timerfd_gettime",
        nr::TIMERFD_GETTIME,
        [
            fd.into(),
            curr_value.into(),
            0.into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}
