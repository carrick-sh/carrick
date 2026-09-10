//! Conformance probe: POSIX job control, controlling TTY background read/write,
//! and orphaned process groups.
//!
//! Linux semantics (man 7 credentials, man 4 tty_ioctl, POSIX.1-2017):
//! 1. TOSTOP is clear by default on a controlling TTY: background writes
//!    succeed without signal.
//! 2. Background reads on a controlling TTY deliver SIGTTIN to the process
//!    group by default, stopping the process.
//! 3. If SIGTTIN is ignored (or blocked), a background read on the controlling
//!    TTY fails immediately with EIO without sending a signal.
//! 4. A background process reading from a non-TTY descriptor (e.g. a pipe, as
//!    in Go's exec.Command("cat") with Setpgid) must never receive SIGTTIN.
//! 5. If the background process group is orphaned (no member has a parent in
//!    the same session and a different process group), a background read on
//!    the controlling TTY fails with EIO and no signal is sent. The controlling
//!    session leader remains alive so the failure is strictly process-group
//!    orphaning, not controlling TTY hangup/deallocation.
//! 6. A background process reading from a pipe dup2'd onto fd 0 must never
//!    receive SIGTTIN.
//!
//! Output format:
//! Pure deterministic key=value pairs recording numeric syscall return codes,
//! errnos, stop signals, wait status, and child retirement.

use std::ffi::CString;
use std::mem::MaybeUninit;
use std::time::{Duration, Instant};

use conformance_probes::report;

const PR_SET_CHILD_SUBREAPER: libc::c_int = 36;
const TIOCGPTN: libc::c_ulong = 0x80045430;
const TIOCSPTLCK: libc::c_ulong = 0x40045431;
const TIOCSCTTY: libc::c_ulong = 0x540E;
const SYS_PIDFD_OPEN: libc::c_long = 434;

const OP_TIMEOUT_MS: libc::c_int = 2000;

#[inline]
unsafe fn errno() -> i32 {
    *libc::__errno_location()
}

#[inline]
unsafe fn close_pipe(fds: [libc::c_int; 2]) {
    libc::close(fds[0]);
    libc::close(fds[1]);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChildPid(libc::pid_t);

impl ChildPid {
    #[inline]
    fn from_raw(pid: libc::pid_t) -> Option<Self> {
        if pid > 0 {
            Some(Self(pid))
        } else {
            None
        }
    }

    #[inline]
    fn raw(&self) -> libc::pid_t {
        self.0
    }

    #[inline]
    unsafe fn kill(&self, sig: libc::c_int) -> libc::c_int {
        libc::kill(self.0, sig)
    }
}

unsafe fn open_pty_pair() -> Option<(libc::c_int, libc::c_int)> {
    let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
    if master < 0 {
        return None;
    }

    let mut ptn: libc::c_uint = 0;
    if libc::ioctl(master, TIOCGPTN as _, &mut ptn) != 0 {
        libc::close(master);
        return None;
    }

    let lock: libc::c_int = 0;
    if libc::ioctl(master, TIOCSPTLCK as _, &lock) != 0 {
        libc::close(master);
        return None;
    }

    let slave_path = CString::new(format!("/dev/pts/{ptn}")).ok()?;
    let slave = libc::open(
        slave_path.as_ptr(),
        libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
    );
    if slave < 0 {
        libc::close(master);
        return None;
    }

    Some((master, slave))
}

unsafe fn create_pipe() -> Option<[libc::c_int; 2]> {
    let mut fds = [0i32; 2];
    if libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
        return None;
    }
    Some(fds)
}

unsafe fn pidfd_open(pid: libc::pid_t) -> libc::c_int {
    libc::syscall(SYS_PIDFD_OPEN, pid, 0) as libc::c_int
}

unsafe fn poll_read_ready(fd: libc::c_int, timeout_ms: libc::c_int) -> bool {
    if fd < 0 {
        return false;
    }
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let r = libc::poll(&mut pfd, 1, timeout_ms);
    r > 0 && (pfd.revents & (libc::POLLIN | libc::POLLHUP)) != 0
}

unsafe fn poll_write_ready(fd: libc::c_int, timeout_ms: libc::c_int) -> bool {
    if fd < 0 {
        return false;
    }
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLOUT,
        revents: 0,
    };
    let r = libc::poll(&mut pfd, 1, timeout_ms);
    r > 0 && (pfd.revents & libc::POLLOUT) != 0
}

unsafe fn read_exact_timeout(fd: libc::c_int, buf: &mut [u8], timeout_ms: libc::c_int) -> bool {
    if fd < 0 {
        return false;
    }
    let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
    let mut off = 0;
    while off < buf.len() {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        let remaining_ms = (deadline - now).as_millis().max(1) as libc::c_int;
        if !poll_read_ready(fd, remaining_ms) {
            return false;
        }
        let n = libc::read(fd, buf[off..].as_mut_ptr().cast(), buf.len() - off);
        if n > 0 {
            off += n as usize;
        } else if n == 0 {
            return false;
        } else if errno() != libc::EINTR {
            return false;
        }
    }
    true
}

unsafe fn write_all_timeout(fd: libc::c_int, buf: &[u8], timeout_ms: libc::c_int) -> bool {
    if fd < 0 {
        return false;
    }
    let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
    let mut off = 0;
    while off < buf.len() {
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        let remaining_ms = (deadline - now).as_millis().max(1) as libc::c_int;
        if !poll_write_ready(fd, remaining_ms) {
            return false;
        }
        let n = libc::write(fd, buf[off..].as_ptr().cast(), buf.len() - off);
        if n > 0 {
            off += n as usize;
        } else if n < 0 {
            if errno() != libc::EINTR {
                return false;
            }
        } else {
            return false;
        }
    }
    true
}

#[derive(Debug, Clone, Copy)]
struct ChildExit {
    reaped: bool,
    exit_code: libc::c_int,
    term_sig: libc::c_int,
}

impl Default for ChildExit {
    fn default() -> Self {
        Self {
            reaped: false,
            exit_code: -1,
            term_sig: -1,
        }
    }
}

unsafe fn reap_child_bounded(child: Option<ChildPid>, timeout_ms: libc::c_int) -> ChildExit {
    let Some(child) = child else {
        return ChildExit::default();
    };
    let pid = child.raw();
    let mut status: libc::c_int = -1;
    let mut reaped = false;

    // Phase 1: Wait for voluntary termination up to timeout_ms with WNOHANG
    let phase1_deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
    let pidfd = pidfd_open(pid);

    while Instant::now() < phase1_deadline {
        let mut cur_status = 0i32;
        let r = libc::waitpid(pid, &mut cur_status, libc::WNOHANG);
        if r == pid {
            status = cur_status;
            reaped = true;
            break;
        }
        if r < 0 && errno() != libc::EINTR {
            break;
        }

        if pidfd >= 0 {
            let now = Instant::now();
            let remaining = phase1_deadline.saturating_duration_since(now);
            let slice_ms = (remaining.as_millis() as libc::c_int).min(10).max(1);
            let _ = poll_read_ready(pidfd, slice_ms);
        } else {
            libc::usleep(2_000);
        }
    }

    if pidfd >= 0 {
        libc::close(pidfd);
    }

    // Phase 2: If voluntary wait exceeded deadline, send SIGKILL and wait up to timeout_ms with WNOHANG
    if !reaped {
        child.kill(libc::SIGKILL);
        let phase2_deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        while Instant::now() < phase2_deadline {
            let mut cur_status = 0i32;
            let r = libc::waitpid(pid, &mut cur_status, libc::WNOHANG);
            if r == pid {
                status = cur_status;
                reaped = true;
                break;
            }
            if r < 0 && errno() != libc::EINTR {
                break;
            }
            libc::usleep(2_000);
        }
    }

    if reaped {
        ChildExit {
            reaped: true,
            exit_code: if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                -1
            },
            term_sig: if libc::WIFSIGNALED(status) {
                libc::WTERMSIG(status)
            } else {
                -1
            },
        }
    } else {
        ChildExit::default()
    }
}

#[derive(Debug, Clone, Copy)]
struct StopResult {
    stopped: bool,
    stopsig: libc::c_int,
    si_code: libc::c_int,
}

impl Default for StopResult {
    fn default() -> Self {
        Self {
            stopped: false,
            stopsig: -1,
            si_code: -1,
        }
    }
}

unsafe fn wait_stopped_bounded(child: Option<ChildPid>, timeout_ms: libc::c_int) -> StopResult {
    let Some(child) = child else {
        return StopResult::default();
    };
    let pid = child.raw();
    let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
    let mut info: libc::siginfo_t = MaybeUninit::zeroed().assume_init();
    let mut stopped = false;

    while Instant::now() < deadline {
        info = MaybeUninit::zeroed().assume_init();
        let r = libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WSTOPPED | libc::WNOHANG,
        );
        if r == 0 && info.si_pid() == pid {
            stopped = true;
            break;
        }
        if r < 0 && errno() != libc::EINTR {
            break;
        }
        libc::usleep(2_000);
    }

    if stopped {
        StopResult {
            stopped: true,
            stopsig: info.si_status(),
            si_code: info.si_code,
        }
    } else {
        StopResult::default()
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ProbeResults {
    // Subject 1: bg write
    bg_write_rc: i64,
    bg_write_errno: i32,
    bg_write_child_reaped: bool,
    bg_write_child_exit_status: i32,

    // Subject 2: bg read stopped by SIGTTIN
    bg_read_stopped: bool,
    bg_read_stop_signal: i32,
    bg_read_stop_code: i32,
    bg_read_child_reaped: bool,
    bg_read_child_term_signal: i32,

    // Subject 3: bg read with SIGTTIN ignored
    bg_read_ign_rc: i64,
    bg_read_ign_errno: i32,
    bg_read_ign_child_reaped: bool,
    bg_read_ign_child_exit_status: i32,

    // Subject 4: bg pipe read
    bg_pipe_read_rc: i64,
    bg_pipe_read_errno: i32,
    bg_pipe_read_payload_matches: bool,
    bg_pipe_read_child_reaped: bool,
    bg_pipe_read_child_exit_status: i32,

    // Subject 5: bg orphan tty read
    bg_read_orphan_rc: i64,
    bg_read_orphan_errno: i32,
    orphan_worker_pid: i32,

    // Subject 6: bg dup2 pipe read onto fd 0
    bg_dup2_pipe_read_rc: i64,
    bg_dup2_pipe_read_errno: i32,
    bg_dup2_pipe_read_payload_matches: bool,
    bg_dup2_pipe_child_reaped: bool,
    bg_dup2_pipe_child_exit_status: i32,
}

impl Default for ProbeResults {
    fn default() -> Self {
        Self {
            bg_write_rc: -1,
            bg_write_errno: -1,
            bg_write_child_reaped: false,
            bg_write_child_exit_status: -1,

            bg_read_stopped: false,
            bg_read_stop_signal: -1,
            bg_read_stop_code: -1,
            bg_read_child_reaped: false,
            bg_read_child_term_signal: -1,

            bg_read_ign_rc: -1,
            bg_read_ign_errno: -1,
            bg_read_ign_child_reaped: false,
            bg_read_ign_child_exit_status: -1,

            bg_pipe_read_rc: -1,
            bg_pipe_read_errno: -1,
            bg_pipe_read_payload_matches: false,
            bg_pipe_read_child_reaped: false,
            bg_pipe_read_child_exit_status: -1,

            bg_read_orphan_rc: -1,
            bg_read_orphan_errno: -1,
            orphan_worker_pid: -1,

            bg_dup2_pipe_read_rc: -1,
            bg_dup2_pipe_read_errno: -1,
            bg_dup2_pipe_read_payload_matches: false,
            bg_dup2_pipe_child_reaped: false,
            bg_dup2_pipe_child_exit_status: -1,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct OpOutcome {
    rc: i64,
    err: i32,
    matched: bool,
}

impl Default for OpOutcome {
    fn default() -> Self {
        Self {
            rc: -1,
            err: -1,
            matched: false,
        }
    }
}

unsafe fn run_session_leader(
    slave: libc::c_int,
    results_pipe_w: libc::c_int,
    mut orphan_pid_pipe_w: libc::c_int,
) {
    let sid = libc::setsid();
    if sid < 0 {
        if orphan_pid_pipe_w >= 0 {
            libc::close(orphan_pid_pipe_w);
        }
        libc::close(results_pipe_w);
        libc::close(slave);
        libc::_exit(101);
    }
    let ct = libc::ioctl(slave, TIOCSCTTY as _, 0);
    if ct != 0 {
        if orphan_pid_pipe_w >= 0 {
            libc::close(orphan_pid_pipe_w);
        }
        libc::close(results_pipe_w);
        libc::close(slave);
        libc::_exit(102);
    }

    let mut res = ProbeResults::default();

    // -------------------------------------------------------------------------
    // 1. Background write on controlling TTY
    // -------------------------------------------------------------------------
    if let Some(s1_pipe) = create_pipe() {
        let child1 = libc::fork();
        if child1 == 0 {
            libc::close(s1_pipe[0]);
            if orphan_pid_pipe_w >= 0 {
                libc::close(orphan_pid_pipe_w);
            }
            libc::close(results_pipe_w);
            libc::setpgid(0, 0);
            let msg = b"line\n";
            let written = libc::write(slave, msg.as_ptr().cast(), msg.len());
            let err = if written < 0 { errno() } else { 0 };
            let outcome = OpOutcome {
                rc: written as i64,
                err,
                matched: written == msg.len() as isize,
            };
            let bytes = std::slice::from_raw_parts(
                &outcome as *const OpOutcome as *const u8,
                std::mem::size_of::<OpOutcome>(),
            );
            let _ = write_all_timeout(s1_pipe[1], bytes, OP_TIMEOUT_MS);
            libc::close(s1_pipe[1]);
            libc::close(slave);
            libc::_exit(0);
        }
        libc::close(s1_pipe[1]);

        if child1 > 0 {
            let mut outcome1 = OpOutcome::default();
            let bytes1 = std::slice::from_raw_parts_mut(
                &mut outcome1 as *mut OpOutcome as *mut u8,
                std::mem::size_of::<OpOutcome>(),
            );
            let _ = read_exact_timeout(s1_pipe[0], bytes1, OP_TIMEOUT_MS);
            let child1_pid = ChildPid::from_raw(child1);
            let exit1 = reap_child_bounded(child1_pid, OP_TIMEOUT_MS);
            res.bg_write_rc = outcome1.rc;
            res.bg_write_errno = outcome1.err;
            res.bg_write_child_reaped = exit1.reaped;
            res.bg_write_child_exit_status = exit1.exit_code;
        }
        libc::close(s1_pipe[0]);
    }

    // -------------------------------------------------------------------------
    // 2. Background read on controlling TTY delivers SIGTTIN and stops
    // -------------------------------------------------------------------------
    if let Some(ready_pipe) = create_pipe() {
        let child2 = libc::fork();
        if child2 == 0 {
            libc::close(ready_pipe[0]);
            if orphan_pid_pipe_w >= 0 {
                libc::close(orphan_pid_pipe_w);
            }
            libc::close(results_pipe_w);
            libc::setpgid(0, 0);
            let _ = write_all_timeout(ready_pipe[1], &[1u8], OP_TIMEOUT_MS);
            libc::close(ready_pipe[1]);
            let mut buf = [0u8; 1];
            libc::read(slave, buf.as_mut_ptr().cast(), 1);
            libc::close(slave);
            libc::_exit(0);
        }
        libc::close(ready_pipe[1]);

        if child2 > 0 {
            let child2_pid = ChildPid::from_raw(child2);
            let mut ready_buf = [0u8; 1];
            let _ = read_exact_timeout(ready_pipe[0], &mut ready_buf, OP_TIMEOUT_MS);

            let stop2 = wait_stopped_bounded(child2_pid, OP_TIMEOUT_MS);
            if let Some(c) = child2_pid {
                c.kill(libc::SIGKILL);
            }
            let exit2 = reap_child_bounded(child2_pid, OP_TIMEOUT_MS);

            res.bg_read_stopped = stop2.stopped;
            res.bg_read_stop_signal = stop2.stopsig;
            res.bg_read_stop_code = stop2.si_code;
            res.bg_read_child_reaped = exit2.reaped;
            res.bg_read_child_term_signal = exit2.term_sig;
        }
        libc::close(ready_pipe[0]);
    }

    // -------------------------------------------------------------------------
    // 3. Background read with SIGTTIN ignored returns EIO
    // -------------------------------------------------------------------------
    if let Some(s3_pipe) = create_pipe() {
        let child3 = libc::fork();
        if child3 == 0 {
            libc::close(s3_pipe[0]);
            if orphan_pid_pipe_w >= 0 {
                libc::close(orphan_pid_pipe_w);
            }
            libc::close(results_pipe_w);
            libc::signal(libc::SIGTTIN, libc::SIG_IGN);
            libc::setpgid(0, 0);
            let mut buf = [0u8; 1];
            let r = libc::read(slave, buf.as_mut_ptr().cast(), 1);
            let err = if r < 0 { errno() } else { 0 };
            let outcome = OpOutcome {
                rc: r as i64,
                err,
                matched: false,
            };
            let bytes = std::slice::from_raw_parts(
                &outcome as *const OpOutcome as *const u8,
                std::mem::size_of::<OpOutcome>(),
            );
            let _ = write_all_timeout(s3_pipe[1], bytes, OP_TIMEOUT_MS);
            libc::close(s3_pipe[1]);
            libc::close(slave);
            libc::_exit(0);
        }
        libc::close(s3_pipe[1]);

        if child3 > 0 {
            let mut outcome3 = OpOutcome::default();
            let bytes3 = std::slice::from_raw_parts_mut(
                &mut outcome3 as *mut OpOutcome as *mut u8,
                std::mem::size_of::<OpOutcome>(),
            );
            let _ = read_exact_timeout(s3_pipe[0], bytes3, OP_TIMEOUT_MS);
            let child3_pid = ChildPid::from_raw(child3);
            let exit3 = reap_child_bounded(child3_pid, OP_TIMEOUT_MS);
            res.bg_read_ign_rc = outcome3.rc;
            res.bg_read_ign_errno = outcome3.err;
            res.bg_read_ign_child_reaped = exit3.reaped;
            res.bg_read_ign_child_exit_status = exit3.exit_code;
        }
        libc::close(s3_pipe[0]);
    }

    // -------------------------------------------------------------------------
    // 4. Background read on a pipe does NOT receive SIGTTIN and succeeds
    // -------------------------------------------------------------------------
    let p4_data = create_pipe();
    let p4_s4 = create_pipe();
    match (p4_data, p4_s4) {
        (Some(pipefd), Some(s4_pipe)) => {
            let child4 = libc::fork();
            if child4 == 0 {
                libc::close(pipefd[1]);
                libc::close(s4_pipe[0]);
                if orphan_pid_pipe_w >= 0 {
                    libc::close(orphan_pid_pipe_w);
                }
                libc::close(results_pipe_w);
                libc::setpgid(0, 0);
                let mut buf = [0u8; 5];
                let mut n = 0isize;
                while (n as usize) < buf.len() {
                    let r = libc::read(
                        pipefd[0],
                        buf[n as usize..].as_mut_ptr().cast(),
                        buf.len() - n as usize,
                    );
                    if r > 0 {
                        n += r;
                    } else if r == 0 {
                        break;
                    } else if errno() != libc::EINTR {
                        n = -1;
                        break;
                    }
                }
                let err = if n < 0 { errno() } else { 0 };
                libc::close(pipefd[0]);
                let outcome = OpOutcome {
                    rc: n as i64,
                    err,
                    matched: n == 5 && &buf == b"hello",
                };
                let bytes = std::slice::from_raw_parts(
                    &outcome as *const OpOutcome as *const u8,
                    std::mem::size_of::<OpOutcome>(),
                );
                let _ = write_all_timeout(s4_pipe[1], bytes, OP_TIMEOUT_MS);
                libc::close(s4_pipe[1]);
                libc::close(slave);
                libc::_exit(0);
            }
            libc::close(pipefd[0]);
            libc::close(s4_pipe[1]);

            if child4 > 0 {
                let _ = write_all_timeout(pipefd[1], b"hello", OP_TIMEOUT_MS);
                libc::close(pipefd[1]);

                let mut outcome4 = OpOutcome::default();
                let bytes4 = std::slice::from_raw_parts_mut(
                    &mut outcome4 as *mut OpOutcome as *mut u8,
                    std::mem::size_of::<OpOutcome>(),
                );
                let _ = read_exact_timeout(s4_pipe[0], bytes4, OP_TIMEOUT_MS);
                libc::close(s4_pipe[0]);

                let child4_pid = ChildPid::from_raw(child4);
                let exit4 = reap_child_bounded(child4_pid, OP_TIMEOUT_MS);
                res.bg_pipe_read_rc = outcome4.rc;
                res.bg_pipe_read_errno = outcome4.err;
                res.bg_pipe_read_payload_matches = outcome4.matched;
                res.bg_pipe_read_child_reaped = exit4.reaped;
                res.bg_pipe_read_child_exit_status = exit4.exit_code;
            } else {
                libc::close(pipefd[1]);
                libc::close(s4_pipe[0]);
            }
        }
        (Some(p), None) => {
            close_pipe(p);
        }
        (None, Some(p)) => {
            close_pipe(p);
        }
        (None, None) => {}
    }

    // -------------------------------------------------------------------------
    // 5. Orphaned background process group read returns EIO
    // -------------------------------------------------------------------------
    // Reduce the intended orphan condition with the controlling session leader
    // kept alive: an intermediary parent in the same session exits, orphaning
    // a separate background group, while the tty owner remains alive.
    let p_interm = create_pipe();
    let p_worker = create_pipe();
    let p_proceed = create_pipe();
    let p_result = create_pipe();

    if let (
        Some(interm_pipe),
        Some(worker_pid_pipe),
        Some(proceed_pipe),
        Some(orphan_result_pipe),
    ) = (p_interm, p_worker, p_proceed, p_result)
    {
        let interm_parent = libc::fork();
        if interm_parent == 0 {
            if orphan_pid_pipe_w >= 0 {
                libc::close(orphan_pid_pipe_w);
            }
            libc::close(results_pipe_w);
            libc::close(worker_pid_pipe[0]);
            libc::close(proceed_pipe[1]);
            libc::close(orphan_result_pipe[0]);

            let orphan_worker = libc::fork();
            if orphan_worker == 0 {
                libc::close(interm_pipe[0]);
                libc::close(worker_pid_pipe[1]);

                // Establish separate background process group in this session
                libc::setpgid(0, 0);

                let my_pid = libc::getpid();
                let _ = write_all_timeout(interm_pipe[1], &my_pid.to_ne_bytes(), OP_TIMEOUT_MS);
                libc::close(interm_pipe[1]);

                // Wait until intermediary parent exits and is reaped
                let mut proceed_byte = [0u8; 1];
                let _ = read_exact_timeout(proceed_pipe[0], &mut proceed_byte, OP_TIMEOUT_MS);
                libc::close(proceed_pipe[0]);

                // Attempt background read on controlling terminal from orphaned group
                let mut buf = [0u8; 1];
                let r = libc::read(slave, buf.as_mut_ptr().cast(), 1);
                let err = if r < 0 { errno() } else { 0 };
                let outcome = OpOutcome {
                    rc: r as i64,
                    err,
                    matched: false,
                };
                let bytes = std::slice::from_raw_parts(
                    &outcome as *const OpOutcome as *const u8,
                    std::mem::size_of::<OpOutcome>(),
                );
                let _ = write_all_timeout(orphan_result_pipe[1], bytes, OP_TIMEOUT_MS);
                libc::close(orphan_result_pipe[1]);
                libc::close(slave);
                libc::_exit(0);
            }

            libc::close(interm_pipe[1]);
            libc::close(proceed_pipe[0]);
            libc::close(orphan_result_pipe[1]);

            if orphan_worker > 0 {
                let mut w_pid_bytes = [0u8; 4];
                let _ = read_exact_timeout(interm_pipe[0], &mut w_pid_bytes, OP_TIMEOUT_MS);
                libc::close(interm_pipe[0]);

                let _ = write_all_timeout(worker_pid_pipe[1], &w_pid_bytes, OP_TIMEOUT_MS);
                libc::close(worker_pid_pipe[1]);
            } else {
                libc::close(interm_pipe[0]);
                libc::close(worker_pid_pipe[1]);
            }

            libc::close(slave);
            // Intermediary parent exits now, orphaning orphan_worker's process group
            libc::_exit(0);
        }

        libc::close(interm_pipe[0]);
        libc::close(interm_pipe[1]);
        libc::close(worker_pid_pipe[1]);
        libc::close(proceed_pipe[0]);
        libc::close(orphan_result_pipe[1]);

        if interm_parent > 0 {
            let mut w_pid_bytes = [0u8; 4];
            let got_pid = read_exact_timeout(worker_pid_pipe[0], &mut w_pid_bytes, OP_TIMEOUT_MS);
            libc::close(worker_pid_pipe[0]);

            if got_pid {
                let worker_pid = i32::from_ne_bytes(w_pid_bytes);

                // Hand off worker PID early to main process
                if orphan_pid_pipe_w >= 0 {
                    let _ = write_all_timeout(orphan_pid_pipe_w, &w_pid_bytes, OP_TIMEOUT_MS);
                    libc::close(orphan_pid_pipe_w);
                    orphan_pid_pipe_w = -1;
                }

                // Reap the intermediary parent in this session
                let interm_pid = ChildPid::from_raw(interm_parent);
                let _ = reap_child_bounded(interm_pid, OP_TIMEOUT_MS);

                // Signal orphan_worker to proceed with background read
                let _ = write_all_timeout(proceed_pipe[1], &[1u8], OP_TIMEOUT_MS);
                libc::close(proceed_pipe[1]);

                // Read orphan worker's numeric syscall outcome
                let mut outcome5 = OpOutcome::default();
                let bytes5 = std::slice::from_raw_parts_mut(
                    &mut outcome5 as *mut OpOutcome as *mut u8,
                    std::mem::size_of::<OpOutcome>(),
                );
                let _ = read_exact_timeout(orphan_result_pipe[0], bytes5, OP_TIMEOUT_MS);
                libc::close(orphan_result_pipe[0]);

                res.bg_read_orphan_rc = outcome5.rc;
                res.bg_read_orphan_errno = outcome5.err;
                res.orphan_worker_pid = worker_pid;
            } else {
                if orphan_pid_pipe_w >= 0 {
                    libc::close(orphan_pid_pipe_w);
                    orphan_pid_pipe_w = -1;
                }
                libc::close(proceed_pipe[1]);
                libc::close(orphan_result_pipe[0]);
                let interm_pid = ChildPid::from_raw(interm_parent);
                let _ = reap_child_bounded(interm_pid, OP_TIMEOUT_MS);
            }
        } else {
            if orphan_pid_pipe_w >= 0 {
                libc::close(orphan_pid_pipe_w);
                orphan_pid_pipe_w = -1;
            }
            libc::close(worker_pid_pipe[0]);
            libc::close(proceed_pipe[1]);
            libc::close(orphan_result_pipe[0]);
        }
    } else {
        if orphan_pid_pipe_w >= 0 {
            libc::close(orphan_pid_pipe_w);
            orphan_pid_pipe_w = -1;
        }
        if let Some(p) = p_interm {
            close_pipe(p);
        }
        if let Some(p) = p_worker {
            close_pipe(p);
        }
        if let Some(p) = p_proceed {
            close_pipe(p);
        }
        if let Some(p) = p_result {
            close_pipe(p);
        }
    }

    // -------------------------------------------------------------------------
    // 6. Background pipe read with pipe dup2'd onto fd 0
    // -------------------------------------------------------------------------
    let p6_stdio = create_pipe();
    let p6_s6 = create_pipe();
    match (p6_stdio, p6_s6) {
        (Some(pipefd_stdio), Some(s6_pipe)) => {
            let child6 = libc::fork();
            if child6 == 0 {
                if orphan_pid_pipe_w >= 0 {
                    libc::close(orphan_pid_pipe_w);
                }
                libc::close(results_pipe_w);
                libc::close(pipefd_stdio[1]);
                libc::close(s6_pipe[0]);
                libc::dup2(pipefd_stdio[0], 0);
                libc::close(pipefd_stdio[0]);
                libc::setpgid(0, 0);

                let mut buf = [0u8; 4];
                let mut n = 0isize;
                while (n as usize) < buf.len() {
                    let r = libc::read(
                        0,
                        buf[n as usize..].as_mut_ptr().cast(),
                        buf.len() - n as usize,
                    );
                    if r > 0 {
                        n += r;
                    } else if r == 0 {
                        break;
                    } else if errno() != libc::EINTR {
                        n = -1;
                        break;
                    }
                }
                let err = if n < 0 { errno() } else { 0 };
                let outcome = OpOutcome {
                    rc: n as i64,
                    err,
                    matched: n == 4 && &buf == b"pipe",
                };
                let bytes = std::slice::from_raw_parts(
                    &outcome as *const OpOutcome as *const u8,
                    std::mem::size_of::<OpOutcome>(),
                );
                let _ = write_all_timeout(s6_pipe[1], bytes, OP_TIMEOUT_MS);
                libc::close(s6_pipe[1]);
                libc::close(slave);
                libc::_exit(0);
            }
            libc::close(pipefd_stdio[0]);
            libc::close(s6_pipe[1]);

            if child6 > 0 {
                let _ = write_all_timeout(pipefd_stdio[1], b"pipe", OP_TIMEOUT_MS);
                libc::close(pipefd_stdio[1]);

                let mut outcome6 = OpOutcome::default();
                let bytes6 = std::slice::from_raw_parts_mut(
                    &mut outcome6 as *mut OpOutcome as *mut u8,
                    std::mem::size_of::<OpOutcome>(),
                );
                let _ = read_exact_timeout(s6_pipe[0], bytes6, OP_TIMEOUT_MS);
                libc::close(s6_pipe[0]);

                let child6_pid = ChildPid::from_raw(child6);
                let exit6 = reap_child_bounded(child6_pid, OP_TIMEOUT_MS);
                res.bg_dup2_pipe_read_rc = outcome6.rc;
                res.bg_dup2_pipe_read_errno = outcome6.err;
                res.bg_dup2_pipe_read_payload_matches = outcome6.matched;
                res.bg_dup2_pipe_child_reaped = exit6.reaped;
                res.bg_dup2_pipe_child_exit_status = exit6.exit_code;
            } else {
                libc::close(pipefd_stdio[1]);
                libc::close(s6_pipe[0]);
            }
        }
        (Some(p), None) => {
            close_pipe(p);
        }
        (None, Some(p)) => {
            close_pipe(p);
        }
        (None, None) => {}
    }

    if orphan_pid_pipe_w >= 0 {
        libc::close(orphan_pid_pipe_w);
    }

    // Send collected probe results to main process
    let result_bytes = std::slice::from_raw_parts(
        &res as *const ProbeResults as *const u8,
        std::mem::size_of::<ProbeResults>(),
    );
    let _ = write_all_timeout(results_pipe_w, result_bytes, OP_TIMEOUT_MS);
    libc::close(results_pipe_w);
    libc::close(slave);
    libc::_exit(0);
}

fn main() {
    unsafe {
        // Overall probe safety backstop
        libc::alarm(20);

        // Subreaper ensures orphaned descendants reparent to root process
        libc::prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);

        let Some((master, slave)) = open_pty_pair() else {
            report!(pty_setup_ok = false);
            return;
        };

        let Some(results_pipe) = create_pipe() else {
            libc::close(master);
            libc::close(slave);
            report!(pipe_setup_ok = false);
            return;
        };

        let Some(orphan_pid_pipe) = create_pipe() else {
            libc::close(master);
            libc::close(slave);
            close_pipe(results_pipe);
            report!(pipe_setup_ok = false);
            return;
        };

        let leader = libc::fork();
        if leader < 0 {
            libc::close(master);
            libc::close(slave);
            close_pipe(results_pipe);
            close_pipe(orphan_pid_pipe);
            report!(leader_fork_ok = false);
            return;
        }

        if leader == 0 {
            libc::close(master);
            libc::close(results_pipe[0]);
            libc::close(orphan_pid_pipe[0]);
            run_session_leader(slave, results_pipe[1], orphan_pid_pipe[1]);
        }

        libc::close(slave);
        libc::close(results_pipe[1]);
        libc::close(orphan_pid_pipe[1]);

        // Receive orphan worker PID early from session leader
        let mut orphan_pid_bytes = [0u8; 4];
        let got_orphan_pid =
            read_exact_timeout(orphan_pid_pipe[0], &mut orphan_pid_bytes, OP_TIMEOUT_MS * 4);
        libc::close(orphan_pid_pipe[0]);
        let orphan_worker_pid = if got_orphan_pid {
            ChildPid::from_raw(i32::from_ne_bytes(orphan_pid_bytes))
        } else {
            None
        };

        let mut res = ProbeResults::default();
        let res_bytes = std::slice::from_raw_parts_mut(
            &mut res as *mut ProbeResults as *mut u8,
            std::mem::size_of::<ProbeResults>(),
        );
        let _ = read_exact_timeout(results_pipe[0], res_bytes, OP_TIMEOUT_MS * 6);
        libc::close(results_pipe[0]);

        // Reap orphan worker reparented to root subreaper
        let orphan_child = orphan_worker_pid.or_else(|| ChildPid::from_raw(res.orphan_worker_pid));
        let orphan_exit = reap_child_bounded(orphan_child, OP_TIMEOUT_MS);

        // Reap session leader
        let leader_exit = reap_child_bounded(ChildPid::from_raw(leader), OP_TIMEOUT_MS);

        libc::close(master);
        libc::alarm(0);

        // -------------------------------------------------------------------------
        // Report all numeric syscall observations and descendant lifecycles
        // -------------------------------------------------------------------------
        report!(
            bg_write_rc = res.bg_write_rc,
            bg_write_errno = res.bg_write_errno,
            bg_write_child_reaped = res.bg_write_child_reaped,
            bg_write_child_exit_status = res.bg_write_child_exit_status,
            bg_read_stopped = res.bg_read_stopped,
            bg_read_stop_signal = res.bg_read_stop_signal,
            bg_read_stop_code = res.bg_read_stop_code,
            bg_read_child_reaped = res.bg_read_child_reaped,
            bg_read_child_term_signal = res.bg_read_child_term_signal,
            bg_read_ign_rc = res.bg_read_ign_rc,
            bg_read_ign_errno = res.bg_read_ign_errno,
            bg_read_ign_child_reaped = res.bg_read_ign_child_reaped,
            bg_read_ign_child_exit_status = res.bg_read_ign_child_exit_status,
            bg_pipe_read_rc = res.bg_pipe_read_rc,
            bg_pipe_read_errno = res.bg_pipe_read_errno,
            bg_pipe_read_payload_matches = res.bg_pipe_read_payload_matches,
            bg_pipe_read_child_reaped = res.bg_pipe_read_child_reaped,
            bg_pipe_read_child_exit_status = res.bg_pipe_read_child_exit_status,
            bg_read_orphan_rc = res.bg_read_orphan_rc,
            bg_read_orphan_errno = res.bg_read_orphan_errno,
            bg_read_orphan_child_reaped = orphan_exit.reaped,
            bg_read_orphan_child_exit_status = orphan_exit.exit_code,
            bg_dup2_pipe_read_rc = res.bg_dup2_pipe_read_rc,
            bg_dup2_pipe_read_errno = res.bg_dup2_pipe_read_errno,
            bg_dup2_pipe_read_payload_matches = res.bg_dup2_pipe_read_payload_matches,
            bg_dup2_pipe_child_reaped = res.bg_dup2_pipe_child_reaped,
            bg_dup2_pipe_child_exit_status = res.bg_dup2_pipe_child_exit_status,
            session_leader_reaped = leader_exit.reaped,
            session_leader_exit_status = leader_exit.exit_code,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_child_pid_from_raw_positive_only() {
        assert_eq!(ChildPid::from_raw(-1), None);
        assert_eq!(ChildPid::from_raw(0), None);
        assert_eq!(ChildPid::from_raw(-42), None);
        assert_eq!(ChildPid::from_raw(1), Some(ChildPid(1)));
        assert_eq!(ChildPid::from_raw(1234), Some(ChildPid(1234)));
    }

    #[test]
    fn test_injected_fork_failure_simulation_does_not_signal_or_hang() {
        let simulated_failed_fork: libc::pid_t = -1;
        let child = ChildPid::from_raw(simulated_failed_fork);
        assert!(child.is_none());

        unsafe {
            // Assert that passing None / failed fork result returns safely without issuing signals
            let stop = wait_stopped_bounded(child, 50);
            assert!(!stop.stopped);
            assert_eq!(stop.stopsig, -1);
            assert_eq!(stop.si_code, -1);

            let exit = reap_child_bounded(child, 50);
            assert!(!exit.reaped);
            assert_eq!(exit.exit_code, -1);
            assert_eq!(exit.term_sig, -1);
        }
    }

    #[test]
    fn test_reap_child_bounded_normal_exit() {
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0);
            if pid == 0 {
                libc::_exit(42);
            }
            let exit = reap_child_bounded(ChildPid::from_raw(pid), 1000);
            assert!(exit.reaped);
            assert_eq!(exit.exit_code, 42);
            assert_eq!(exit.term_sig, -1);
        }
    }

    #[test]
    fn test_reap_child_bounded_withheld_exit_times_out_and_kills() {
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0);
            if pid == 0 {
                loop {
                    libc::pause();
                }
            }
            // Phase 1 times out in 50ms, Phase 2 kills with SIGKILL and reaps
            let exit = reap_child_bounded(ChildPid::from_raw(pid), 50);
            assert!(exit.reaped);
            assert_eq!(exit.exit_code, -1);
            assert_eq!(exit.term_sig, libc::SIGKILL);
        }
    }

    #[test]
    fn test_wait_stopped_bounded_success() {
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0);
            if pid == 0 {
                libc::raise(libc::SIGSTOP);
                libc::_exit(0);
            }
            let child = ChildPid::from_raw(pid);
            let stop = wait_stopped_bounded(child, 1000);
            assert!(stop.stopped);
            assert_eq!(stop.stopsig, libc::SIGSTOP);
            if let Some(c) = child {
                c.kill(libc::SIGKILL);
            }
            let _ = reap_child_bounded(child, 1000);
        }
    }

    #[test]
    fn test_wait_stopped_bounded_timeout_when_child_does_not_stop() {
        unsafe {
            let pid = libc::fork();
            assert!(pid >= 0);
            if pid == 0 {
                loop {
                    libc::pause();
                }
            }
            let child = ChildPid::from_raw(pid);
            let stop = wait_stopped_bounded(child, 50);
            assert!(!stop.stopped);
            assert_eq!(stop.stopsig, -1);
            assert_eq!(stop.si_code, -1);
            if let Some(c) = child {
                c.kill(libc::SIGKILL);
            }
            let _ = reap_child_bounded(child, 1000);
        }
    }

    #[test]
    fn test_pipe_read_timeout_on_blocked_empty_pipe() {
        unsafe {
            let (r, w) = conformance_probes::pipe2();
            let mut buf = [0u8; 4];
            let start = Instant::now();
            let ok = read_exact_timeout(r, &mut buf, 50);
            let elapsed = start.elapsed();
            assert!(!ok);
            assert!(elapsed >= Duration::from_millis(40));
            assert!(elapsed < Duration::from_millis(500));
            libc::close(r);
            libc::close(w);
        }
    }

    #[test]
    fn test_pipe_transfer_bounded_success() {
        unsafe {
            let (r, w) = conformance_probes::pipe2();
            let ok_w = write_all_timeout(w, b"ping", 500);
            assert!(ok_w);
            let mut buf = [0u8; 4];
            let ok_r = read_exact_timeout(r, &mut buf, 500);
            assert!(ok_r);
            assert_eq!(&buf, b"ping");
            libc::close(r);
            libc::close(w);
        }
    }
}
