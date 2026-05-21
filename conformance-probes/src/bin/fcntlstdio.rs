//! fcntl-on-stdio probe. Exercises fcntl(F_GETFL/F_SETFL/F_GETFD/F_SETFD) on
//! the three bare standard fds (0, 1, 2) and prints one labelled boolean per
//! observation. This locks the regression where `fcntl(0, F_SETFL, O_NONBLOCK)`
//! returned EBADF on carrick — the dpkg child set stdin non-blocking, got
//! EBADF, and _exit(100)'d, breaking `apt install`.
//!
//! IMPORTANT: stdio under the harness may be a pipe/tty/file, which differs
//! between carrick and Docker — so we assert ONLY the fcntl RETURN semantics
//! (success vs EBADF), which are identical on real Linux regardless of the
//! underlying object. We never print fd numbers, flag values, or content.

fn main() {
    for fd in [0i32, 1, 2] {
        // F_GETFL must succeed (>= 0). Real Linux never returns EBADF for an
        // open standard fd.
        let getfl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        println!("getfl_fd{fd}_ok={}", getfl >= 0);

        // F_SETFL O_NONBLOCK must return 0 (NOT EBADF). THIS is the regression.
        let setfl = unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
        println!("setfl_nonblock_fd{fd}_ok={}", setfl == 0);

        // F_GETFD must succeed (>= 0).
        let getfd = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        println!("getfd_fd{fd}_ok={}", getfd >= 0);

        // F_SETFD FD_CLOEXEC must return 0; then F_GETFD must reflect the bit.
        let setfd = unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        let getfd2 = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        let reflected = getfd2 >= 0 && (getfd2 & libc::FD_CLOEXEC) != 0;
        println!("setfd_fd{fd}_ok={}", setfd == 0 && reflected);
    }

    // NEGATIVE control: an obviously-bogus fd must fail with EBADF.
    let bad = unsafe { libc::fcntl(999, libc::F_SETFL, libc::O_NONBLOCK) };
    println!(
        "setfl_badfd_ebadf={}",
        bad == -1 && errno() == libc::EBADF
    );
}

/// Current errno value.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}
