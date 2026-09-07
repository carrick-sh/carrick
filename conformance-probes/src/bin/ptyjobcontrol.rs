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
//! 4. If the background process group is orphaned (no member has a parent in
//!    the same session and a different process group), a background read on
//!    the controlling TTY fails with EIO and no signal is sent.
//! 5. A background process reading from a non-TTY descriptor (e.g. a pipe, as
//!    in Go's exec.Command("cat") with Setpgid) must never receive SIGTTIN.
//! 6. A background process reading from a pipe dup2'd onto fd 0 must never
//!    receive SIGTTIN.
//!
//! Expected Linux output:
//! bg_write_poll_ready=true
//! bg_write_exit_code=0
//! bg_read_stopped=true
//! bg_read_stopsig=21
//! bg_read_ign_errno_eio=true
//! bg_pipe_read_ok=true
//! bg_read_orphan_errno_eio=true
//! bg_dup2_pipe_read_ok=true

use std::ffi::CString;
use std::mem::MaybeUninit;

const TIOCGPTN: libc::c_ulong = 0x80045430;
const TIOCSPTLCK: libc::c_ulong = 0x40045431;
const TIOCSCTTY: libc::c_ulong = 0x540E;
const SYS_PIDFD_OPEN: libc::c_long = 434;

unsafe fn open_pty_pair() -> (libc::c_int, libc::c_int) {
    let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC);
    assert!(master >= 0, "posix_openpt failed");

    let mut ptn: libc::c_uint = 0;
    assert_eq!(libc::ioctl(master, TIOCGPTN as _, &mut ptn), 0);

    let lock: libc::c_int = 0;
    assert_eq!(libc::ioctl(master, TIOCSPTLCK as _, &lock), 0);

    let slave_path = CString::new(format!("/dev/pts/{ptn}")).unwrap();
    let slave = libc::open(
        slave_path.as_ptr(),
        libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
    );
    assert!(slave >= 0, "open slave failed");
    (master, slave)
}

unsafe fn pidfd_open(pid: libc::pid_t) -> libc::c_int {
    libc::syscall(SYS_PIDFD_OPEN, pid, 0) as libc::c_int
}

unsafe fn poll_pidfd(pidfd: libc::c_int, timeout_ms: libc::c_int) -> bool {
    let mut pfd = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    let r = libc::poll(&mut pfd, 1, timeout_ms);
    r > 0 && (pfd.revents & (libc::POLLIN | libc::POLLHUP)) != 0
}

fn main() {
    unsafe {
        let (master, slave) = open_pty_pair();

        // Pipe for orphan worker to report its result to parent
        let mut result_pipe = [0i32; 2];
        assert_eq!(libc::pipe(result_pipe.as_mut_ptr()), 0);

        // Session leader process: creates a new session and acquires slave as controlling tty
        let leader = libc::fork();
        assert!(leader >= 0);
        if leader == 0 {
            libc::close(result_pipe[0]);

            let sid = libc::setsid();
            assert!(sid >= 0, "setsid failed");
            let ct = libc::ioctl(slave, TIOCSCTTY as _, 0);
            assert_eq!(ct, 0, "TIOCSCTTY failed");

            // 1. Background write on controlling tty
            let child1 = libc::fork();
            assert!(child1 >= 0);
            if child1 == 0 {
                libc::setpgid(0, 0);
                let msg = b"line\n";
                let written = libc::write(slave, msg.as_ptr().cast(), msg.len());
                let code = if written == msg.len() as isize { 0 } else { 1 };
                libc::_exit(code);
            }

            let pidfd1 = pidfd_open(child1);
            let ready1 = if pidfd1 >= 0 {
                poll_pidfd(pidfd1, 5000)
            } else {
                false
            };
            let mut info1: libc::siginfo_t = MaybeUninit::zeroed().assume_init();
            let waited1 = libc::waitid(
                libc::P_PID,
                child1 as libc::id_t,
                &mut info1,
                libc::WEXITED,
            );
            let exit1 = if waited1 == 0 { info1.si_status() } else { -1 };
            println!("bg_write_poll_ready={ready1}");
            println!("bg_write_exit_code={exit1}");
            if pidfd1 >= 0 {
                libc::close(pidfd1);
            }

            // 2. Background read on controlling tty delivers SIGTTIN and stops
            let child2 = libc::fork();
            assert!(child2 >= 0);
            if child2 == 0 {
                libc::setpgid(0, 0);
                let mut buf = [0u8; 1];
                libc::read(slave, buf.as_mut_ptr().cast(), 1);
                libc::_exit(0);
            }

            let pidfd2 = pidfd_open(child2);
            let mut info2: libc::siginfo_t = MaybeUninit::zeroed().assume_init();
            let waited2 = libc::waitid(
                libc::P_PID,
                child2 as libc::id_t,
                &mut info2,
                libc::WSTOPPED,
            );
            let stopped2 = waited2 == 0 && info2.si_code == 5; // CLD_STOPPED = 5
            let stopsig2 = if stopped2 { info2.si_status() } else { 0 };
            println!("bg_read_stopped={stopped2}");
            println!("bg_read_stopsig={stopsig2}");
            libc::kill(child2, libc::SIGKILL);
            libc::waitid(
                libc::P_PID,
                child2 as libc::id_t,
                &mut info2,
                libc::WEXITED,
            );
            if pidfd2 >= 0 {
                libc::close(pidfd2);
            }

            // 3. Background read with SIGTTIN ignored returns EIO
            let child3 = libc::fork();
            assert!(child3 >= 0);
            if child3 == 0 {
                libc::signal(libc::SIGTTIN, libc::SIG_IGN);
                libc::setpgid(0, 0);
                let mut buf = [0u8; 1];
                let r = libc::read(slave, buf.as_mut_ptr().cast(), 1);
                let err = *libc::__errno_location();
                let code = if r == -1 && err == libc::EIO { 0 } else { 1 };
                libc::_exit(code);
            }

            let pidfd3 = pidfd_open(child3);
            let _ = if pidfd3 >= 0 { poll_pidfd(pidfd3, 5000) } else { false };
            let mut info3: libc::siginfo_t = MaybeUninit::zeroed().assume_init();
            let waited3 = libc::waitid(
                libc::P_PID,
                child3 as libc::id_t,
                &mut info3,
                libc::WEXITED,
            );
            let ok3 = waited3 == 0 && info3.si_status() == 0;
            println!("bg_read_ign_errno_eio={ok3}");
            if pidfd3 >= 0 {
                libc::close(pidfd3);
            }

            // 5. Background read on a pipe does NOT receive SIGTTIN and succeeds
            let mut pipefd = [0i32; 2];
            assert_eq!(libc::pipe(pipefd.as_mut_ptr()), 0);
            let child5 = libc::fork();
            assert!(child5 >= 0);
            if child5 == 0 {
                libc::close(pipefd[1]);
                libc::setpgid(0, 0);
                let mut buf = [0u8; 5];
                let n = libc::read(pipefd[0], buf.as_mut_ptr().cast(), 5);
                let code = if n == 5 && &buf == b"hello" { 0 } else { 1 };
                libc::_exit(code);
            }
            libc::close(pipefd[0]);
            libc::write(pipefd[1], b"hello".as_ptr().cast(), 5);
            libc::close(pipefd[1]);

            let pidfd5 = pidfd_open(child5);
            let _ = if pidfd5 >= 0 { poll_pidfd(pidfd5, 5000) } else { false };
            let mut info5: libc::siginfo_t = MaybeUninit::zeroed().assume_init();
            let waited5 = libc::waitid(
                libc::P_PID,
                child5 as libc::id_t,
                &mut info5,
                libc::WEXITED,
            );
            let ok5 = waited5 == 0 && info5.si_status() == 0;
            println!("bg_pipe_read_ok={ok5}");
            if pidfd5 >= 0 {
                libc::close(pidfd5);
            }

            // 4. Orphaned background process group read returns EIO:
            // Fork worker child in this session. When leader exits, worker's session leader is gone,
            // so worker's process group becomes orphaned.
            let mut exit_pipe = [0i32; 2];
            assert_eq!(libc::pipe(exit_pipe.as_mut_ptr()), 0);
            let orphan_worker = libc::fork();
            assert!(orphan_worker >= 0);
            if orphan_worker == 0 {
                libc::close(exit_pipe[1]);
                libc::setpgid(0, 0);

                // Wait for EOF on exit_pipe (which happens when leader exits)
                let mut eof_buf = [0u8; 1];
                let _ = libc::read(exit_pipe[0], eof_buf.as_mut_ptr().cast(), 1);
                libc::close(exit_pipe[0]);

                let mut buf = [0u8; 1];
                let r = libc::read(slave, buf.as_mut_ptr().cast(), 1);
                let err = *libc::__errno_location();
                let success: u8 = if r == -1 && err == libc::EIO { 1 } else { 0 };
                libc::write(result_pipe[1], &success as *const u8 as *const libc::c_void, 1);
                libc::close(result_pipe[1]);
                libc::_exit(0);
            }

            libc::close(exit_pipe[0]);
            // Leader exits now, orphaning the worker process group.
            // When leader exits, exit_pipe[1] is closed.
            libc::_exit(0);
        }

        libc::close(result_pipe[1]);

        // Parent waits for session leader to exit
        let mut leader_info: libc::siginfo_t = MaybeUninit::zeroed().assume_init();
        libc::waitid(
            libc::P_PID,
            leader as libc::id_t,
            &mut leader_info,
            libc::WEXITED,
        );

        // Read orphan worker's result
        let mut orphan_success = [0u8; 1];
        let n = libc::read(result_pipe[0], orphan_success.as_mut_ptr().cast(), 1);
        libc::close(result_pipe[0]);
        let ok4 = n == 1 && orphan_success[0] == 1;
        println!("bg_read_orphan_errno_eio={ok4}");

        // Wait for orphan worker (reparented to root/parent)
        let mut worker_info: libc::siginfo_t = MaybeUninit::zeroed().assume_init();
        libc::waitid(libc::P_ALL, 0, &mut worker_info, libc::WEXITED);

        // 6. Background pipe read with pipe dup2'd onto fd 0 (Go TestSetpgid pattern)
        let mut pipefd_stdio = [0i32; 2];
        assert_eq!(libc::pipe(pipefd_stdio.as_mut_ptr()), 0);
        let child6 = libc::fork();
        assert!(child6 >= 0);
        if child6 == 0 {
            libc::dup2(pipefd_stdio[0], 0);
            libc::close(pipefd_stdio[0]);
            libc::close(pipefd_stdio[1]);
            libc::setpgid(0, 0);
            let mut buf = [0u8; 4];
            let n = libc::read(0, buf.as_mut_ptr().cast(), 4);
            let code = if n == 4 && &buf == b"pipe" { 0 } else { 1 };
            libc::_exit(code);
        }
        libc::close(pipefd_stdio[0]);
        libc::write(pipefd_stdio[1], b"pipe".as_ptr().cast(), 4);
        libc::close(pipefd_stdio[1]);

        let pidfd6 = pidfd_open(child6);
        let _ = if pidfd6 >= 0 { poll_pidfd(pidfd6, 5000) } else { false };
        let mut info6: libc::siginfo_t = MaybeUninit::zeroed().assume_init();
        let waited6 = libc::waitid(
            libc::P_PID,
            child6 as libc::id_t,
            &mut info6,
            libc::WEXITED,
        );
        let ok6 = waited6 == 0 && info6.si_status() == 0;
        println!("bg_dup2_pipe_read_ok={ok6}");
        if pidfd6 >= 0 {
            libc::close(pidfd6);
        }

        libc::close(master);
        libc::close(slave);
    }
}
