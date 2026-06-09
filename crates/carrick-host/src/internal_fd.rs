//! Relocate carrick-internal file descriptors above a high floor.
//!
//! carrick opens a number of host fds for its own bookkeeping (the signal-pump
//! self-pipe, eventfd readiness pipes, the kqueue/epoll multiplexer fd, …).
//! Those fds must NOT sit at low numbers where they could alias a host fd that
//! a guest is handed under `--fs host` (the guest fd table maps low fd numbers
//! to host fds; an internal carrick fd squatting on e.g. fd 5 would collide).
//!
//! The mechanism is pure POSIX — `F_DUPFD_CLOEXEC` to dup the fd to the lowest
//! free number `>= floor`, then close the original — so it compiles and behaves
//! identically on Linux and macOS/FreeBSD. It was originally homed in the
//! macOS-only `carrick-bsd` crate (alongside the kqueue wrapper that first used
//! it); it lives here in the neutral `carrick-host` crate so the KVM/Linux
//! backend gets the real implementation instead of an identity stub, and
//! `carrick-bsd` re-exports it (keeping HVF's public path stable).

use std::sync::atomic::{AtomicU8, Ordering};

/// The floor carrick relocates internal fds above. 16 KiB clears every plausible
/// guest fd-table range while staying well under a raised `RLIMIT_NOFILE`.
pub const HOST_INTERNAL_FD_MIN: i32 = 16 * 1024;
/// Fallback floor for hosts whose `RLIMIT_NOFILE` cannot reach the preferred
/// range (CI runners with a low fd cap). Still clears the guest fd range.
const HOST_INTERNAL_FD_MIN_FALLBACK: i32 = 2048;
const HOST_INTERNAL_FD_TARGET: libc::rlim_t = (HOST_INTERNAL_FD_MIN as libc::rlim_t) + 16;
static NOFILE_RAISE_ATTEMPTED: AtomicU8 = AtomicU8::new(0);

fn ensure_internal_fd_range() {
    if NOFILE_RAISE_ATTEMPTED
        .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }

    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) } != 0 {
        return;
    }
    let mut limit = unsafe { limit.assume_init() };
    if limit.rlim_cur >= HOST_INTERNAL_FD_TARGET {
        return;
    }
    let desired = if limit.rlim_max == libc::RLIM_INFINITY {
        HOST_INTERNAL_FD_TARGET
    } else {
        HOST_INTERNAL_FD_TARGET.min(limit.rlim_max)
    };
    if desired > limit.rlim_cur {
        limit.rlim_cur = desired;
        unsafe {
            libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
        }
    }
}

/// Dup `fd` to the lowest free number at or above [`HOST_INTERNAL_FD_MIN`]
/// (with `CLOEXEC` set), returning the new fd. The original `fd` is left open.
/// Returns `None` if even the fallback floor cannot be reached.
pub fn duplicate_internal_fd(fd: i32) -> Option<i32> {
    ensure_internal_fd_range();
    // Prefer the high internal range. On a host whose RLIMIT_NOFILE cannot reach
    // it, `F_DUPFD_CLOEXEC` returns EMFILE for every fd >= HOST_INTERNAL_FD_MIN;
    // fall back to a lower floor that still clears the guest fd range, so carrick
    // keeps working (and CI runners with a low fd cap stay green) instead of
    // failing every internal-pipe allocation.
    for floor in [HOST_INTERNAL_FD_MIN, HOST_INTERNAL_FD_MIN_FALLBACK] {
        let duped = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, floor) };
        if duped >= 0 {
            return Some(duped);
        }
    }
    None
}

/// Move `fd` into the internal range and close the original, returning the new
/// fd. If the dup fails (no fd available even at the fallback floor) the
/// original `fd` is returned UNCHANGED (and left open) — never closed without a
/// replacement.
pub fn relocate_internal_fd(fd: i32) -> i32 {
    let Some(duped) = duplicate_internal_fd(fd) else {
        return fd;
    };
    unsafe { libc::close(fd) };
    duped
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `relocate_internal_fd` moves a low fd above the floor and closes the
    /// original.
    #[test]
    fn relocate_moves_above_floor_and_closes_original() {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe failed");
        let [read_end, write_end] = fds;
        // The read end starts at a low fd number (typically < 16).
        assert!(
            read_end < HOST_INTERNAL_FD_MIN,
            "fresh pipe fd unexpectedly high: {read_end}"
        );

        let relocated = relocate_internal_fd(read_end);
        assert!(
            relocated >= HOST_INTERNAL_FD_MIN || relocated >= 2048,
            "relocated fd {relocated} below both floors"
        );
        // The original fd number was closed: re-fcntl on it must fail EBADF.
        let getfl = unsafe { libc::fcntl(read_end, libc::F_GETFD) };
        assert_eq!(getfl, -1, "original fd {read_end} should be closed");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
        // The relocated fd is still a live read end: it carries CLOEXEC.
        let flags = unsafe { libc::fcntl(relocated, libc::F_GETFD) };
        assert!(flags >= 0, "relocated fd {relocated} not open");
        assert_ne!(flags & libc::FD_CLOEXEC, 0, "CLOEXEC not set on relocated fd");

        unsafe {
            libc::close(relocated);
            libc::close(write_end);
        }
    }

    /// `duplicate_internal_fd` returns a NEW fd above the floor while leaving the
    /// original open (the non-closing variant).
    #[test]
    fn duplicate_returns_new_high_fd_leaving_original_open() {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe failed");
        let [read_end, write_end] = fds;

        let duped = duplicate_internal_fd(read_end).expect("duplicate_internal_fd failed");
        assert_ne!(duped, read_end, "dup returned the same fd number");
        assert!(
            duped >= HOST_INTERNAL_FD_MIN || duped >= 2048,
            "duped fd {duped} below both floors"
        );
        // The ORIGINAL stays open (duplicate, unlike relocate, does not close it).
        let orig_flags = unsafe { libc::fcntl(read_end, libc::F_GETFD) };
        assert!(orig_flags >= 0, "original fd {read_end} should still be open");

        unsafe {
            libc::close(duped);
            libc::close(read_end);
            libc::close(write_end);
        }
    }
}
