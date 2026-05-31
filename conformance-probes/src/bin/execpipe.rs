//! fork+exec stdout pipe inheritance probe.
//!
//! Mirrors the child-process shape used by Node/libuv: create a CLOEXEC pipe,
//! fork, dup the write end onto stdout (dup2 must clear FD_CLOEXEC on fd 1),
//! close the original pipe fds, exec a shell that writes to stdout, and have
//! the parent read the bytes then EOF. A wrong fd lifetime shows up as EPIPE in
//! the exec'd child or as no bytes/EOF in the parent.

use conformance_probes::{errno, report};
use std::ffi::CString;
use std::time::{Duration, Instant};

fn main() {
    unsafe {
        let mut pipefd = [0i32; 2];
        if libc::pipe2(pipefd.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
            report!(pipe_setup_ok = false);
            return;
        }
        report!(pipe_setup_ok = true);

        let pid = libc::fork();
        if pid == 0 {
            libc::close(pipefd[0]);
            if libc::dup2(pipefd[1], libc::STDOUT_FILENO) != libc::STDOUT_FILENO {
                libc::_exit(101);
            }
            let fd_flags = libc::fcntl(libc::STDOUT_FILENO, libc::F_GETFD);
            if fd_flags < 0 || (fd_flags & libc::FD_CLOEXEC) != 0 {
                libc::_exit(102);
            }
            libc::close(pipefd[1]);

            let sh = CString::new("/bin/sh").unwrap();
            let arg0 = CString::new("sh").unwrap();
            let argc = CString::new("-c").unwrap();
            let script = CString::new("printf %s child-ok").unwrap();
            let argv = [
                arg0.as_ptr(),
                argc.as_ptr(),
                script.as_ptr(),
                core::ptr::null(),
            ];
            let envp = [core::ptr::null()];
            libc::execve(sh.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(127);
        }
        if pid < 0 {
            let er = errno();
            libc::close(pipefd[0]);
            libc::close(pipefd[1]);
            println!("fork_errno={er}");
            return;
        }

        libc::close(pipefd[1]);
        let flags = libc::fcntl(pipefd[0], libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(pipefd[0], libc::F_SETFL, flags | libc::O_NONBLOCK);
        }

        let deadline = Instant::now() + Duration::from_secs(3);
        let mut out = Vec::new();
        let mut saw_eof = false;
        let mut read_errno = 0;
        while Instant::now() < deadline {
            let mut buf = [0u8; 64];
            let n = libc::read(pipefd[0], buf.as_mut_ptr() as *mut libc::c_void, buf.len());
            if n > 0 {
                out.extend_from_slice(&buf[..n as usize]);
                continue;
            }
            if n == 0 {
                saw_eof = true;
                break;
            }
            let er = errno();
            if er == libc::EAGAIN || er == libc::EWOULDBLOCK {
                let mut status = 0;
                let waited = libc::waitpid(pid, &mut status, libc::WNOHANG);
                if waited == pid {
                    continue;
                }
                libc::usleep(10_000);
                continue;
            }
            read_errno = er;
            break;
        }
        libc::close(pipefd[0]);

        let mut status = 0;
        while libc::waitpid(pid, &mut status, 0) < 0 && errno() == libc::EINTR {}
        let exited = libc::WIFEXITED(status);
        let code = if exited { libc::WEXITSTATUS(status) } else { -1 };

        report!(
            child_exited_zero = exited && code == 0,
            child_exit_code = code,
            parent_read_child_ok = out == b"child-ok",
            parent_read_eof = saw_eof,
            parent_read_errno = read_errno,
        );
    }
}
