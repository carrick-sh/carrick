//! Syscall constructor helpers.

use carrick_abi::syscall::nr;
use carrick_abi::{
    CanonicalNr, LINUX_AF_UNIX, LINUX_CMSGHDR_LEN, LINUX_EPOLL_CTL_ADD, LINUX_EPOLL_CTL_DEL,
    LINUX_EPOLL_CTL_MOD, LINUX_SCM_RIGHTS, LINUX_SIGCHLD, LINUX_SO_PEERCRED, LINUX_SOCK_STREAM,
    LINUX_SOL_SOCKET, LINUX_UCRED_SIZE,
};

use crate::operand::{Expect, Layout, Operand, RelocWidth, Syscall};

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

/// `dup(2)`: duplicate an open file descriptor.
pub fn dup(oldfd: impl Into<Operand>) -> Syscall {
    call(
        "dup",
        nr::DUP,
        [
            oldfd.into(),
            0.into(),
            0.into(),
            0.into(),
            0.into(),
            0.into(),
        ],
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

/// `socketpair(2)`: creates a pair of connected sockets.
pub fn socketpair(domain: i32, type_: i32, protocol: i32) -> Syscall {
    call(
        "socketpair",
        nr::SOCKETPAIR,
        [
            (domain as i64).into(),
            (type_ as i64).into(),
            (protocol as i64).into(),
            Operand::Out(8),
            0.into(),
            0.into(),
        ],
    )
}

/// `socketpair(AF_UNIX, SOCK_STREAM, 0)` helper.
pub fn socketpair_stream() -> Syscall {
    socketpair(LINUX_AF_UNIX, LINUX_SOCK_STREAM, 0)
}

/// `sendmsg(2)`: send a message on a socket using a `msghdr` layout.
pub fn sendmsg(fd: impl Into<Operand>, msg: impl Into<Operand>, flags: i32) -> Syscall {
    call(
        "sendmsg",
        nr::SENDMSG,
        [
            fd.into(),
            msg.into(),
            (flags as i64).into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `sendmsg(2)` passing file descriptors via `SCM_RIGHTS`.
pub fn sendmsg_fds(fd: impl Into<Operand>, fds: &[Operand], data: &[u8], flags: i32) -> Syscall {
    let iov_data = Operand::Bytes(data.to_vec());
    let iov_layout = Layout::new(16)
        .with_reloc(0, RelocWidth::U64, iov_data)
        .with_u64(8, data.len() as u64);
    let cmsg_data_len = fds.len() * 4;
    let cmsg_len = LINUX_CMSGHDR_LEN + cmsg_data_len;
    let mut cmsg = Layout::new(cmsg_len)
        .with_u64(0, cmsg_len as u64)
        .with_i32(8, LINUX_SOL_SOCKET)
        .with_i32(12, LINUX_SCM_RIGHTS);
    for (i, fd_op) in fds.iter().enumerate() {
        cmsg = cmsg.with_reloc(16 + i * 4, RelocWidth::I32, fd_op.clone());
    }
    let msghdr = Layout::new(56)
        .with_reloc(16, RelocWidth::U64, iov_layout)
        .with_u64(24, 1)
        .with_reloc(32, RelocWidth::U64, cmsg)
        .with_u64(40, cmsg_len as u64);
    sendmsg(fd, msghdr, flags)
}

/// `sendto(2)`: send a message on a socket.
pub fn sendto(fd: impl Into<Operand>, data: &[u8], flags: i32) -> Syscall {
    call(
        "sendto",
        nr::SENDTO,
        [
            fd.into(),
            Operand::Bytes(data.to_vec()),
            (data.len() as i64).into(),
            (flags as i64).into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `recvmsg(2)`: receive a message from a socket using a `msghdr` layout.
pub fn recvmsg(fd: impl Into<Operand>, msg: impl Into<Operand>, flags: i32) -> Syscall {
    call(
        "recvmsg",
        nr::RECVMSG,
        [
            fd.into(),
            msg.into(),
            (flags as i64).into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `recvmsg(2)` helper for receiving stream data and optional control messages.
pub fn recvmsg_stream(
    fd: impl Into<Operand>,
    iov_len: usize,
    control_len: usize,
    flags: i32,
) -> Syscall {
    let iov_buf = Operand::TaggedOut("iov", iov_len);
    let iov_layout = Layout::new(16)
        .with_reloc(0, RelocWidth::U64, iov_buf)
        .with_u64(8, iov_len as u64);
    let mut msghdr = Layout::new(56)
        .with_reloc(16, RelocWidth::U64, iov_layout)
        .with_u64(24, 1)
        .with_capture(true)
        .with_tag("msghdr");
    if control_len > 0 {
        let control_buf = Operand::TaggedOut("control", control_len);
        msghdr = msghdr
            .with_reloc(32, RelocWidth::U64, control_buf)
            .with_u64(40, control_len as u64);
    }
    recvmsg(fd, msghdr, flags)
}

/// `recvfrom(2)`: receive a message from a socket.
pub fn recvfrom(fd: impl Into<Operand>, len: usize, flags: i32) -> Syscall {
    call(
        "recvfrom",
        nr::RECVFROM,
        [
            fd.into(),
            Operand::Out(len),
            (len as i64).into(),
            (flags as i64).into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `setsockopt(2)`: set socket options.
pub fn setsockopt(
    fd: impl Into<Operand>,
    level: i32,
    optname: i32,
    optval: impl Into<Operand>,
    optlen: usize,
) -> Syscall {
    call(
        "setsockopt",
        nr::SETSOCKOPT,
        [
            fd.into(),
            (level as i64).into(),
            (optname as i64).into(),
            optval.into(),
            (optlen as i64).into(),
            0.into(),
        ],
    )
}

/// `setsockopt` with a 4-byte `i32` value helper.
pub fn setsockopt_int(fd: impl Into<Operand>, level: i32, optname: i32, val: i32) -> Syscall {
    setsockopt(fd, level, optname, val.to_le_bytes().as_slice(), 4)
}

/// `getsockopt(2)`: get socket options.
pub fn getsockopt(fd: impl Into<Operand>, level: i32, optname: i32, optlen: usize) -> Syscall {
    call(
        "getsockopt",
        nr::GETSOCKOPT,
        [
            fd.into(),
            (level as i64).into(),
            (optname as i64).into(),
            Operand::TaggedOut("optval", optlen),
            Operand::TaggedInOut("optlen", (optlen as u32).to_le_bytes().to_vec()),
            0.into(),
        ],
    )
}

/// `getsockopt(SOL_SOCKET, SO_PEERCRED)` helper.
pub fn getsockopt_so_peercred(fd: impl Into<Operand>) -> Syscall {
    getsockopt(fd, LINUX_SOL_SOCKET, LINUX_SO_PEERCRED, LINUX_UCRED_SIZE)
}

/// `shutdown(2)`: shut down part of a full-duplex connection.
pub fn shutdown(fd: impl Into<Operand>, how: i32) -> Syscall {
    call(
        "shutdown",
        nr::SHUTDOWN,
        [
            fd.into(),
            (how as i64).into(),
            0.into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `epoll_create1(2)`: open an epoll file descriptor.
pub fn epoll_create1(flags: i32) -> Syscall {
    call(
        "epoll_create1",
        nr::EPOLL_CREATE1,
        [
            (flags as i64).into(),
            0.into(),
            0.into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `epoll_ctl(2)`: control interface for an epoll file descriptor.
pub fn epoll_ctl(
    epfd: impl Into<Operand>,
    op: u64,
    fd: impl Into<Operand>,
    event: impl Into<Operand>,
) -> Syscall {
    call(
        "epoll_ctl",
        nr::EPOLL_CTL,
        [
            epfd.into(),
            (op as i64).into(),
            fd.into(),
            event.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `epoll_event` layout builder.
pub fn epoll_event(events: u32, data: impl Into<Operand>) -> Layout {
    Layout::new(16)
        .with_u32(0, events)
        .with_reloc(8, RelocWidth::U64, data)
}

/// `epoll_ctl(EPOLL_CTL_ADD)` helper.
pub fn epoll_ctl_add(
    epfd: impl Into<Operand>,
    fd: impl Into<Operand>,
    events: u32,
    data: impl Into<Operand>,
) -> Syscall {
    epoll_ctl(epfd, LINUX_EPOLL_CTL_ADD, fd, epoll_event(events, data))
}

/// `epoll_ctl(EPOLL_CTL_MOD)` helper.
pub fn epoll_ctl_mod(
    epfd: impl Into<Operand>,
    fd: impl Into<Operand>,
    events: u32,
    data: impl Into<Operand>,
) -> Syscall {
    epoll_ctl(epfd, LINUX_EPOLL_CTL_MOD, fd, epoll_event(events, data))
}

/// `epoll_ctl(EPOLL_CTL_DEL)` helper.
pub fn epoll_ctl_del(epfd: impl Into<Operand>, fd: impl Into<Operand>) -> Syscall {
    epoll_ctl(epfd, LINUX_EPOLL_CTL_DEL, fd, 0)
}

/// `epoll_pwait(2)`: wait for an I/O event on an epoll file descriptor.
pub fn epoll_pwait(
    epfd: impl Into<Operand>,
    maxevents: usize,
    timeout_ms: i32,
    sigmask: impl Into<Operand>,
) -> Syscall {
    call(
        "epoll_pwait",
        nr::EPOLL_PWAIT,
        [
            epfd.into(),
            Operand::TaggedOut("events", maxevents * 16),
            (maxevents as i64).into(),
            (timeout_ms as i64).into(),
            sigmask.into(),
            0.into(),
        ],
    )
}

/// `pidfd_open(2)`: obtain a file descriptor that refers to a process.
pub fn pidfd_open(pid: impl Into<Operand>, flags: u32) -> Syscall {
    call(
        "pidfd_open",
        nr::PIDFD_OPEN,
        [
            pid.into(),
            (flags as i64).into(),
            0.into(),
            0.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `pidfd_send_signal(2)`: send a signal to a process specified by a file descriptor.
pub fn pidfd_send_signal(
    pidfd: impl Into<Operand>,
    sig: i32,
    info: impl Into<Operand>,
    flags: u32,
) -> Syscall {
    call(
        "pidfd_send_signal",
        nr::PIDFD_SEND_SIGNAL,
        [
            pidfd.into(),
            (sig as i64).into(),
            info.into(),
            (flags as i64).into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `pollfd` layout builder.
pub fn pollfd(fd: impl Into<Operand>, events: i16) -> Layout {
    Layout::new(8)
        .with_reloc(0, RelocWidth::I32, fd)
        .with_i16(4, events)
        .with_i16(6, 0)
        .with_capture(true)
        .with_tag("pollfd")
}

/// `ppoll(2)`: wait for some event on a file descriptor.
pub fn ppoll(
    fds: impl Into<Operand>,
    nfds: usize,
    timeout: impl Into<Operand>,
    sigmask: impl Into<Operand>,
) -> Syscall {
    call(
        "ppoll",
        nr::PPOLL,
        [
            fds.into(),
            (nfds as i64).into(),
            timeout.into(),
            sigmask.into(),
            0.into(),
            0.into(),
        ],
    )
}

/// `ppoll` for a single file descriptor helper.
pub fn ppoll_one(fd: impl Into<Operand>, events: i16, timeout_ms: Option<u64>) -> Syscall {
    let pfd = pollfd(fd, events);
    let tmo: Operand = match timeout_ms {
        None => 0.into(),
        Some(ms) => {
            let sec = (ms / 1000) as u64;
            let nsec = ((ms % 1000) * 1_000_000) as u64;
            let mut b = [0u8; 16];
            b[0..8].copy_from_slice(&sec.to_le_bytes());
            b[8..16].copy_from_slice(&nsec.to_le_bytes());
            b.to_vec().into()
        }
    };
    ppoll(pfd, 1, tmo, 0)
}

/// `waitid(2)`: wait for process state change.
pub fn waitid(idtype: i32, id: impl Into<Operand>, options: i32) -> Syscall {
    call(
        "waitid",
        nr::WAITID,
        [
            (idtype as i64).into(),
            id.into(),
            Operand::TaggedOut("siginfo", 128),
            (options as i64).into(),
            0.into(),
            0.into(),
        ],
    )
}
