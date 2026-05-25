//! Non-interactive invariants for the `run -t` session supervisor.
//!
//! The full behavior is covered by the ignored pty-driven tests in
//! `interactive_tty.rs`; these tests pin the fork-safety mechanics that must be
//! true before the interactive runtime starts.

#[test]
fn supervisor_sync_pipe_fds_are_high_and_cloexec() {
    let (read_fd, write_fd) =
        carrick_runtime::interactive_supervisor::sync_pipe_for_test().expect("sync pipe");

    assert!(
        read_fd >= 16 * 1024,
        "read end should be outside the guest-visible fd range, got {read_fd}"
    );
    assert!(
        write_fd >= 16 * 1024,
        "write end should be outside the guest-visible fd range, got {write_fd}"
    );

    for fd in [read_fd, write_fd] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0, "F_GETFD failed for {fd}");
        assert_ne!(
            flags & libc::FD_CLOEXEC,
            0,
            "supervisor fd {fd} must be CLOEXEC"
        );
        unsafe { libc::close(fd) };
    }
}
