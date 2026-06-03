//! Session-leader supervisor for `carrick run -t` / `carrick shell`.
//!
//! # Why a separate process at all
//!
//! An interactive guest shell expects to do job control — `setsid`, become a
//! session leader, own a controlling tty, and `tcsetpgrp` the foreground job.
//! For that to work with **real** macOS `tcsetpgrp`/`wait4`/SIGTTOU semantics
//! (rather than a carrick emulation), the guest runtime must run in its own
//! process group under a session whose leader owns the controlling pty. carrick
//! builds that boundary by forking, **before** the HVF VM exists, into a
//! supervisor that owns the pty + the byte relay and a child that becomes the
//! guest runtime in a fresh process group.
//!
//! # The three-process structure
//!
//! [`fork_interactive_session`] forks twice, yielding three processes:
//!
//! 1. **Launcher** — the original `carrick` process. It may already be a
//!    process-group leader (when started from an interactive shell), in which
//!    case `setsid()` would `EPERM`. So it forks a fresh non-leader and just
//!    waits on it ([`InteractiveParentKind::Launcher`]), propagating its exit
//!    code. It also holds the "life" pipe whose close tells the supervisor the
//!    launcher is gone.
//! 2. **Supervisor** — the forked non-leader. It `setsid()`s (becoming a session
//!    leader), `TIOCSCTTY`s the pty slave as its controlling tty, forks the
//!    runtime child, sets that child's pgrp as the tty foreground, and then runs
//!    the byte relay ([`PtyRelay`]) until the child exits
//!    ([`InteractiveParentKind::Supervisor`]). There is **one supervisor per
//!    interactive run** — this is not a shared daemon (same no-daemon principle
//!    as [`namespace::supervisor`](crate::namespace::supervisor)).
//! 3. **Runtime child** — the carrick guest runtime
//!    ([`InteractiveChild`]). It `setpgid`s into its own group and, after a
//!    ready/ack handshake with the supervisor (so the supervisor has set the
//!    foreground pgrp before any guest code runs), continues into the HVF loop
//!    with the pty slave as fds 0/1/2.
//!
//! # Window-size relay across the session boundary
//!
//! The supervisor lives in a *new* session, so it no longer shares the original
//! terminal's SIGWINCH. A small winsize-watcher helper ([`WinsizeWatcher`])
//! stays in the launcher's session, catches resizes, and forwards the new
//! `winsize` over a pipe that the [`PtyRelay`] watches as an out-of-band fd (see
//! `start_with_pair_and_winsize` in [`pty_relay`](crate::pty_relay)).
//!
//! All fds shared across these forks are relocated above the guest's stdio range
//! (`relocate_internal_fd` / `dup_relocated`) so the guest never collides with
//! carrick's own controlling fds, and every error path here `_exit`s or returns
//! before any guest `Drop` could double-close an inherited fd.

use crate::dispatch::SyscallDispatcher;
use crate::pty_relay::{PtyPair, PtyRelay};
use std::io;
use std::os::unix::io::RawFd;

pub enum SupervisorFork {
    Parent(InteractiveParent),
    Child(InteractiveChild),
}

pub struct InteractiveParent {
    kind: InteractiveParentKind,
}

enum InteractiveParentKind {
    Launcher {
        supervisor_pid: libc::pid_t,
        life_w: RawFd,
    },
    Supervisor {
        child_pid: libc::pid_t,
        pair: Option<PtyPair>,
        real_in: RawFd,
        real_out: RawFd,
        launcher_life_r: RawFd,
        winsize_r: RawFd,
        winsize_pid: libc::pid_t,
        initial_winsize: Option<libc::winsize>,
        ready_r: RawFd,
        ack_w: RawFd,
    },
}

struct SupervisorResources {
    child_pid: libc::pid_t,
    pair: Option<PtyPair>,
    real_in: RawFd,
    real_out: RawFd,
    launcher_life_r: RawFd,
    winsize_r: RawFd,
    winsize_pid: libc::pid_t,
    initial_winsize: Option<libc::winsize>,
    ready_r: RawFd,
    ack_w: RawFd,
}

struct WinsizeWatcher {
    pid: libc::pid_t,
    read_fd: RawFd,
}

pub struct InteractiveChild {
    slave_fd: RawFd,
    slave_name: String,
    ready_w: RawFd,
    ack_r: RawFd,
}

/// Create the interactive session boundary and fork the runtime child.
///
/// Parent side: session leader + controlling pty + relay owner. Child side:
/// Carrick runtime, placed in its own process group.
pub fn fork_interactive_session() -> io::Result<SupervisorFork> {
    fork_launcher_supervisor()
}

fn fork_launcher_supervisor() -> io::Result<SupervisorFork> {
    let (life_r, life_w) = sync_pipe()?;
    // First fork a dedicated supervisor. A process launched by an interactive
    // host shell is often already a process-group leader, in which case
    // setsid() would fail with EPERM. The forked supervisor child is not a
    // pgrp leader, so it can reliably create the pty session.
    let supervisor_pid = unsafe { libc::fork() };
    if supervisor_pid < 0 {
        unsafe {
            libc::close(life_r);
            libc::close(life_w);
        }
        return Err(io::Error::last_os_error());
    }
    if supervisor_pid > 0 {
        unsafe { libc::close(life_r) };
        crate::probes::supervisor_fork(supervisor_pid);
        return Ok(SupervisorFork::Parent(InteractiveParent {
            kind: InteractiveParentKind::Launcher {
                supervisor_pid,
                life_w,
            },
        }));
    }
    unsafe { libc::close(life_w) };
    fork_runtime_under_current_process(life_r)
}

fn fork_runtime_under_current_process(launcher_life_r: RawFd) -> io::Result<SupervisorFork> {
    let initial_winsize = read_winsize(0);
    let winsize = spawn_winsize_watcher(0)?;
    let real_in = dup_relocated(0)?;
    let real_out = dup_relocated(1)?;
    let mut pair = PtyPair::allocate()?;
    pair.master_fd = crate::host_signal::relocate_internal_fd(pair.master_fd);

    if unsafe { libc::setsid() } < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::ioctl(pair.slave_fd, libc::TIOCSCTTY as libc::c_ulong, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }

    let (ready_r, ready_w) = sync_pipe()?;
    let (ack_r, ack_w) = sync_pipe()?;

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }

    if pid == 0 {
        unsafe {
            libc::close(ready_r);
            libc::close(ack_w);
            libc::close(real_in);
            libc::close(real_out);
            libc::close(pair.master_fd);
            libc::close(winsize.read_fd);
            libc::close(launcher_life_r);
        }
        if unsafe { libc::setpgid(0, 0) } < 0 {
            unsafe { libc::_exit(126) };
        }
        crate::probes::supervisor_child_ready(unsafe { libc::getpid() });
        write_one(ready_w)?;
        read_one(ack_r)?;
        Ok(SupervisorFork::Child(InteractiveChild {
            slave_fd: pair.slave_fd,
            slave_name: pair.slave_name,
            ready_w,
            ack_r,
        }))
    } else {
        unsafe {
            libc::close(ready_w);
            libc::close(ack_r);
        }
        crate::probes::supervisor_fork(pid);
        Ok(SupervisorFork::Parent(InteractiveParent {
            kind: InteractiveParentKind::Supervisor {
                child_pid: pid,
                pair: Some(pair),
                real_in,
                real_out,
                launcher_life_r,
                winsize_r: winsize.read_fd,
                winsize_pid: winsize.pid,
                initial_winsize,
                ready_r,
                ack_w,
            },
        }))
    }
}

impl InteractiveParent {
    pub fn relay_and_wait(self) -> io::Result<i32> {
        match self.kind {
            InteractiveParentKind::Launcher {
                supervisor_pid,
                life_w,
            } => {
                let status = wait_for_child(supervisor_pid);
                unsafe { libc::close(life_w) };
                status.map(wait_status_to_exit_code)
            }
            InteractiveParentKind::Supervisor {
                child_pid,
                pair,
                real_in,
                real_out,
                launcher_life_r,
                winsize_r,
                winsize_pid,
                initial_winsize,
                ready_r,
                ack_w,
            } => {
                let resources = SupervisorResources {
                    child_pid,
                    pair,
                    real_in,
                    real_out,
                    launcher_life_r,
                    winsize_r,
                    winsize_pid,
                    initial_winsize,
                    ready_r,
                    ack_w,
                };
                relay_and_wait_in_supervisor(resources)
            }
        }
    }
}

fn relay_and_wait_in_supervisor(mut resources: SupervisorResources) -> io::Result<i32> {
    read_one(resources.ready_r)?;
    unsafe { libc::close(resources.ready_r) };

    // Close the parent/child race even though the child already setpgid'd
    // before signalling readiness.
    unsafe {
        libc::setpgid(resources.child_pid, resources.child_pid);
    }

    let slave_fd = resources
        .pair
        .as_ref()
        .map(|p| p.slave_fd)
        .ok_or_else(|| io::Error::other("interactive pty already consumed"))?;
    let fg_rc = unsafe { libc::tcsetpgrp(slave_fd, resources.child_pid) };
    let fg_errno = if fg_rc < 0 {
        io::Error::last_os_error().raw_os_error().unwrap_or(0)
    } else {
        0
    };
    crate::probes::supervisor_foreground_pgrp(resources.child_pid, fg_errno);
    if fg_rc < 0 {
        return Err(io::Error::last_os_error());
    }

    if let Some(ws) = resources.initial_winsize
        && let Some(pair) = resources.pair.as_ref()
    {
        crate::pty_relay::apply_winsize(pair.slave_fd, &ws);
    }

    let relay = match PtyRelay::start_with_pair_and_winsize(
        resources
            .pair
            .take()
            .ok_or_else(|| io::Error::other("interactive pty missing"))?,
        resources.real_in,
        resources.real_out,
        resources.winsize_r,
    ) {
        Ok(relay) => relay,
        Err(e) => {
            unsafe { libc::close(resources.ack_w) };
            unsafe { libc::close(resources.launcher_life_r) };
            stop_winsize_watcher(resources.winsize_pid);
            return Err(e);
        }
    };
    write_one(resources.ack_w)?;
    unsafe { libc::close(resources.ack_w) };

    let status = match wait_for_runtime_child(resources.child_pid, resources.launcher_life_r) {
        Ok(status) => status,
        Err(e) => {
            relay.stop();
            unsafe { libc::close(resources.launcher_life_r) };
            stop_winsize_watcher(resources.winsize_pid);
            return Err(e);
        }
    };
    crate::probes::supervisor_child_exit(resources.child_pid, status);
    relay.stop();
    unsafe { libc::close(resources.launcher_life_r) };
    stop_winsize_watcher(resources.winsize_pid);
    Ok(wait_status_to_exit_code(status))
}

fn wait_for_child(pid: libc::pid_t) -> io::Result<i32> {
    let mut status = 0;
    loop {
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r >= 0 {
            return Ok(status);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

fn wait_for_runtime_child(pid: libc::pid_t, launcher_life_r: RawFd) -> io::Result<i32> {
    let mut status = 0;
    let mut terminating = false;
    let mut polls_after_term = 0;
    loop {
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if r == pid {
            return Ok(status);
        }
        if r < 0 {
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
            continue;
        }

        let mut pfd = libc::pollfd {
            fd: launcher_life_r,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        let n = unsafe { libc::poll(&mut pfd, 1, 250) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
            continue;
        }

        if !terminating && n > 0 && pfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
            terminate_runtime_pgrp(pid, libc::SIGHUP);
            terminate_runtime_pgrp(pid, libc::SIGTERM);
            terminate_runtime_pgrp(pid, libc::SIGCONT);
            terminating = true;
            continue;
        }

        if terminating {
            polls_after_term += 1;
            if polls_after_term == 8 {
                terminate_runtime_pgrp(pid, libc::SIGKILL);
            }
        }
    }
}

fn terminate_runtime_pgrp(pgid: libc::pid_t, signal: libc::c_int) {
    unsafe {
        libc::kill(-pgid, signal);
    }
}

impl InteractiveChild {
    pub fn adopt_stdio(self, dispatcher: &mut SyscallDispatcher) -> io::Result<()> {
        unsafe {
            libc::close(self.ready_w);
            libc::close(self.ack_r);
            if libc::dup2(self.slave_fd, 0) < 0
                || libc::dup2(self.slave_fd, 1) < 0
                || libc::dup2(self.slave_fd, 2) < 0
            {
                return Err(io::Error::last_os_error());
            }
            if self.slave_fd > 2 {
                libc::close(self.slave_fd);
            }
        }
        dispatcher.set_stream_stdio(true);
        dispatcher.register_controlling_pty(self.slave_name);
        crate::host_signal::reset_after_supervisor_fork();
        Ok(())
    }
}

fn dup_relocated(fd: RawFd) -> io::Result<RawFd> {
    let duped = unsafe { libc::dup(fd) };
    if duped < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(crate::host_signal::relocate_internal_fd(duped))
}

fn sync_pipe() -> io::Result<(RawFd, RawFd)> {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let read_fd = crate::host_signal::relocate_internal_fd(fds[0]);
    let write_fd = crate::host_signal::relocate_internal_fd(fds[1]);
    for fd in [read_fd, write_fd] {
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags >= 0 {
                libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
            }
        }
    }
    Ok((read_fd, write_fd))
}

fn spawn_winsize_watcher(source_fd: RawFd) -> io::Result<WinsizeWatcher> {
    let (read_fd, write_fd) = sync_pipe()?;
    set_nonblocking(read_fd);
    set_nonblocking(write_fd);
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        unsafe { libc::close(read_fd) };
        winsize_watcher_loop(source_fd, write_fd);
    }
    unsafe { libc::close(write_fd) };
    Ok(WinsizeWatcher { pid, read_fd })
}

fn winsize_watcher_loop(source_fd: RawFd, write_fd: RawFd) -> ! {
    let mut last: Option<libc::winsize> = None;
    loop {
        if let Some(ws) = read_winsize(source_fd) {
            let changed = last.as_ref().is_none_or(|prev| {
                prev.ws_row != ws.ws_row
                    || prev.ws_col != ws.ws_col
                    || prev.ws_xpixel != ws.ws_xpixel
                    || prev.ws_ypixel != ws.ws_ypixel
            });
            if changed {
                let ptr = &ws as *const libc::winsize as *const libc::c_void;
                let len = std::mem::size_of::<libc::winsize>();
                let n = unsafe { libc::write(write_fd, ptr, len) };
                if n < 0 {
                    unsafe { libc::_exit(0) };
                }
                last = Some(ws);
            }
        }
        unsafe { libc::usleep(250_000) };
    }
}

fn read_winsize(fd: RawFd) -> Option<libc::winsize> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0
        && ws.ws_row != 0
        && ws.ws_col != 0
    {
        Some(ws)
    } else {
        None
    }
}

fn set_nonblocking(fd: RawFd) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}

fn stop_winsize_watcher(pid: libc::pid_t) {
    let mut status = 0;
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    loop {
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r >= 0 {
            return;
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return;
        }
    }
}

#[doc(hidden)]
pub fn sync_pipe_for_test() -> io::Result<(RawFd, RawFd)> {
    sync_pipe()
}

fn write_one(fd: RawFd) -> io::Result<()> {
    let byte = [1u8; 1];
    loop {
        let n = unsafe { libc::write(fd, byte.as_ptr().cast(), 1) };
        if n == 1 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

fn read_one(fd: RawFd) -> io::Result<()> {
    let mut byte = [0u8; 1];
    loop {
        let n = unsafe { libc::read(fd, byte.as_mut_ptr().cast(), 1) };
        if n == 1 {
            return Ok(());
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "supervisor sync pipe closed",
            ));
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

fn wait_status_to_exit_code(status: i32) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        1
    }
}
