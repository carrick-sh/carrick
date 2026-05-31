//! Guest-visible F_GETFL status/access modes for anonymous pipe and socket fds.
//!
//! Carrick keeps host-backed fds nonblocking internally, but Linux guests must
//! see only the flags they requested. Child-process stdio setup depends on this:
//! pipe read ends report O_RDONLY, pipe write ends report O_WRONLY, socketpair
//! endpoints report O_RDWR, and SOCK_CLOEXEC alone must not imply O_NONBLOCK.

use conformance_probes::{errno, report};

fn main() {
    unsafe {
        let mut pipefd = [0i32; 2];
        let pipe_ok = libc::pipe2(pipefd.as_mut_ptr(), libc::O_CLOEXEC) == 0;
        if !pipe_ok {
            report!(pipe_ok = false, pipe_errno = errno());
            return;
        }

        let pipe_read_flags = libc::fcntl(pipefd[0], libc::F_GETFL);
        let pipe_write_flags = libc::fcntl(pipefd[1], libc::F_GETFL);
        libc::close(pipefd[0]);
        libc::close(pipefd[1]);

        let mut sv = [0i32; 2];
        let socket_ok = libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            sv.as_mut_ptr(),
        ) == 0;
        if !socket_ok {
            report!(pipe_ok = true, socket_ok = false, socket_errno = errno());
            return;
        }
        let sock0_flags = libc::fcntl(sv[0], libc::F_GETFL);
        let sock1_flags = libc::fcntl(sv[1], libc::F_GETFL);
        libc::close(sv[0]);
        libc::close(sv[1]);

        report!(
            pipe_ok = true,
            pipe_read_rdonly = (pipe_read_flags & libc::O_ACCMODE) == libc::O_RDONLY,
            pipe_write_wronly = (pipe_write_flags & libc::O_ACCMODE) == libc::O_WRONLY,
            pipe_cloexec_not_nonblock = (pipe_read_flags & libc::O_NONBLOCK) == 0
                && (pipe_write_flags & libc::O_NONBLOCK) == 0,
            socket_ok = true,
            socket0_rdwr = (sock0_flags & libc::O_ACCMODE) == libc::O_RDWR,
            socket1_rdwr = (sock1_flags & libc::O_ACCMODE) == libc::O_RDWR,
            sock_cloexec_not_nonblock = (sock0_flags & libc::O_NONBLOCK) == 0
                && (sock1_flags & libc::O_NONBLOCK) == 0,
        );
    }
}
