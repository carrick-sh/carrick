//! Thin safe wrapper around Darwin/FreeBSD `kqueue`/`kevent`.

use std::os::fd::RawFd;

/// Darwin's exceptional-condition filter. The `libc` crate version (0.2.186)
/// does not expose this SDK constant for Darwin.
///
/// **IMPORTANT platform difference:** On Darwin, `-15` is `EVFILT_EXCEPT` (OOB
/// socket events). On FreeBSD, `-15` is `EVFILT_JAILDESC` (jail-descriptor
/// events) — an entirely different filter. FreeBSD has **no** `EVFILT_EXCEPT`
/// equivalent; OOB socket readiness is not exposed through kqueue on FreeBSD.
/// The FreeBSD constant is therefore a positive sentinel (`i16::MAX`) that can
/// never match any real kqueue filter (all real filters are negative), so the
/// `Kevent::oob` constructor compiles on FreeBSD but kevent(2) rejects it with
/// `EINVAL`, which callers propagate as "OOB unsupported".
#[cfg(target_os = "macos")]
pub const EVFILT_EXCEPT: i16 = -15;
/// FreeBSD has no `EVFILT_EXCEPT`. Use a positive sentinel that can never match
/// a real kqueue filter (all filters are negative ints) so an accidental
/// registration returns EINVAL rather than silently matching EVFILT_JAILDESC.
#[cfg(target_os = "freebsd")]
pub const EVFILT_EXCEPT: i16 = i16::MAX;

/// `EVFILT_EXCEPT` hint for socket out-of-band data (Darwin only).
///
/// On Darwin, registering `EVFILT_EXCEPT` with `NOTE_OOB` delivers OOB/urgent
/// data readiness. On FreeBSD this feature does not exist; `NOTE_OOB` is
/// defined as `0` so it is a no-op fflags addition (consistent with
/// `NOTE_EXITSTATUS` on FreeBSD).
#[cfg(target_os = "macos")]
pub const NOTE_OOB: u32 = 0x0000_0002;
/// FreeBSD has no `EVFILT_EXCEPT`/`NOTE_OOB`; defined as 0 (no-op fflags).
#[cfg(target_os = "freebsd")]
pub const NOTE_OOB: u32 = 0;
/// macOS `EVFILT_PROC` fflag that requests the exit status be delivered in
/// `data`. FreeBSD has no such fflag — but its `NOTE_EXIT` already delivers the
/// wait-status in `data` UNCONDITIONALLY — so we define this as 0 (a no-op
/// fflags addition) purely to keep the shared arming code compiling. Note the
/// consequence: on FreeBSD `proc_exit_status` (which reads `data`) returns the
/// REAL status, not 0.
#[cfg(target_os = "macos")]
pub use libc::NOTE_EXITSTATUS;
#[cfg(target_os = "freebsd")]
pub const NOTE_EXITSTATUS: u32 = 0;

// Internal-fd relocation is platform-neutral POSIX (F_DUPFD_CLOEXEC above a
// high floor, then close the original); it now lives in the neutral
// `carrick-host` crate so the KVM/Linux backend shares the real impl. Re-export
// it here so this crate's public path (and HVF's via carrick_host_bsd) is unchanged.
pub use carrick_host::internal_fd::{duplicate_internal_fd, relocate_internal_fd};

/// RAII owner for a Darwin/FreeBSD kqueue fd.
#[derive(Debug)]
pub struct Kqueue {
    fd: RawFd,
}

impl Kqueue {
    pub fn new_internal() -> Option<Self> {
        let raw = unsafe { libc::kqueue() };
        if raw < 0 {
            return None;
        }
        let fd = relocate_internal_fd(raw);
        Some(Self { fd })
    }

    pub fn raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Test/diagnostic hook: close the kqueue fd now and forget it, so a later
    /// `kevent` on this wrapper returns EBADF (modelling the fork-storm race in
    /// which an internal fd is closed out from under a blocked waiter) without a
    /// double-close of a possibly-reused fd number when the wrapper is dropped.
    /// Returns the fd that was closed (or -1). Not for production use.
    #[doc(hidden)]
    pub fn debug_close_and_invalidate(&mut self) -> RawFd {
        let fd = self.fd;
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
        self.fd = -1;
        fd
    }

    pub fn apply(&self, changes: &[Kevent]) -> Result<(), i32> {
        let rc = unsafe {
            libc::kevent(
                self.fd,
                changes.as_ptr().cast::<libc::kevent>(),
                changes.len() as libc::c_int,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };
        if rc < 0 {
            Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
        } else {
            Ok(())
        }
    }

    pub fn wait(
        &self,
        changes: &[Kevent],
        events: &mut [Kevent],
        timeout: Option<&libc::timespec>,
    ) -> Result<usize, i32> {
        let changes_ptr = if changes.is_empty() {
            std::ptr::null()
        } else {
            changes.as_ptr().cast::<libc::kevent>()
        };
        let timeout_ptr = timeout.map_or(std::ptr::null(), |timeout| timeout as *const _);
        let n = unsafe {
            libc::kevent(
                self.fd,
                changes_ptr,
                changes.len() as libc::c_int,
                events.as_mut_ptr().cast::<libc::kevent>(),
                events.len() as libc::c_int,
                timeout_ptr,
            )
        };
        if n < 0 {
            Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
        } else {
            Ok(n as usize)
        }
    }
}

impl Drop for Kqueue {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

/// Opaque wrapper around Darwin's `struct kevent` so call sites do not build
/// raw `libc::kevent` values themselves.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Kevent(libc::kevent);

impl Kevent {
    pub fn empty() -> Self {
        Self(libc::kevent {
            ident: 0,
            filter: 0,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
            #[cfg(target_os = "freebsd")]
            ext: [0; 4],
        })
    }

    pub fn read(fd: RawFd, flags: u16) -> Self {
        Self::new(fd as usize, libc::EVFILT_READ, flags, 0)
    }

    pub fn write(fd: RawFd, flags: u16) -> Self {
        Self::new(fd as usize, libc::EVFILT_WRITE, flags, 0)
    }

    pub fn oob(fd: RawFd, flags: u16) -> Self {
        Self::new(fd as usize, EVFILT_EXCEPT, flags, NOTE_OOB)
    }

    /// Watch process `pid` for exit. The kqueue becomes read-ready (and a
    /// `kevent` returns this event) when the process terminates — the macOS
    /// kernel's native process-lifecycle tracking that backs a guest pidfd.
    /// One-shot: fires once on exit.
    ///
    /// Armed with `NOTE_EXITSTATUS` as well as `NOTE_EXIT` so the returned
    /// event's `data` field carries the exit status
    /// ([`proc_exit_status`](Self::proc_exit_status)). Under plain `NOTE_EXIT`
    /// macOS leaves `data` at 0; the NsSupervisor needs the real status to
    /// harvest a namespace member's exit code before launchd reaps the host
    /// zombie (after which `waitpid` is ECHILD). Detection-only callers
    /// ([`proc_exit_ident`](Self::proc_exit_ident)) are unaffected by the extra
    /// fflag.
    pub fn proc_exit(pid: i32) -> Self {
        Self::new(
            pid as usize,
            libc::EVFILT_PROC,
            libc::EV_ADD | libc::EV_ONESHOT,
            libc::NOTE_EXIT | NOTE_EXITSTATUS,
        )
    }

    /// Delete a previously-added `EVFILT_PROC`/`NOTE_EXIT` watch for `pid`.
    /// `proc_exit` is `EV_ONESHOT` (auto-removed once it fires), so this is only
    /// needed to drop a watch whose wait was interrupted before the exit fired.
    pub fn proc_exit_delete(pid: i32) -> Self {
        Self::new(pid as usize, libc::EVFILT_PROC, libc::EV_DELETE, 0)
    }

    /// Stash a small integer (a guest fd) in `udata` so a returned event maps
    /// straight back to its guest fd without a reverse lookup. Used by the
    /// epoll-backing kqueue (`dispatch::net`).
    pub fn with_udata(mut self, udata: i32) -> Self {
        self.0.udata = udata as isize as *mut libc::c_void;
        self
    }

    pub fn with_udata_u64(mut self, udata: u64) -> Self {
        self.0.udata = udata as *mut libc::c_void;
        self
    }

    /// The kqueue filter (`EVFILT_READ`/`EVFILT_WRITE`/`EVFILT_USER`/…).
    pub fn filter(self) -> i16 {
        self.0.filter
    }

    /// The event flags (`EV_EOF`, `EV_ERROR`, …) on a returned event.
    pub fn flags(self) -> u16 {
        self.0.flags
    }

    /// The filter-specific flags (`fflags`) — for `EV_EOF` this carries the
    /// socket/pipe error code, which maps to `EPOLLERR`.
    pub fn fflags(self) -> u32 {
        self.0.fflags
    }

    pub fn data(self) -> i64 {
        // macOS: `data` is `isize`; FreeBSD: `data` is `i64`. Cast only when needed.
        #[cfg(target_os = "macos")]
        return self.0.data as i64;
        #[cfg(not(target_os = "macos"))]
        return self.0.data;
    }

    /// The integer previously stashed via [`with_udata`](Self::with_udata) (the
    /// guest fd).
    pub fn udata_i32(self) -> i32 {
        self.0.udata as isize as i32
    }

    pub fn udata_u64(self) -> u64 {
        self.0.udata as u64
    }

    pub fn user(ident: usize, flags: u16) -> Self {
        Self::new(ident, libc::EVFILT_USER, flags, 0)
    }

    /// If this returned event is an `EVFILT_PROC`/`NOTE_EXIT` firing (a watched
    /// process exited), the pid that exited; else `None`. The signal pump uses
    /// this to map a child exit back to the forking guest tid and publish
    /// SIGCHLD. An `EV_ERROR` event (e.g. the pid was already gone) also carries
    /// `EVFILT_PROC`, so the caller treats both as "the child is now reapable".
    pub fn proc_exit_ident(self) -> Option<i32> {
        if self.0.filter == libc::EVFILT_PROC {
            Some(self.0.ident as i32)
        } else {
            None
        }
    }

    /// For a returned `EVFILT_PROC`/`NOTE_EXIT` event, the exited process's
    /// status in `waitpid(2)` out-parameter format (macOS carries it in the
    /// `data` field, NOTE_EXITSTATUS). Used by the NsSupervisor to harvest a
    /// namespace member's exit status at death — before launchd reaps the
    /// host zombie, after which `waitpid` from any other process is ECHILD.
    pub fn proc_exit_status(self) -> i32 {
        self.0.data as i32
    }

    /// One-shot or periodic timer. `interval_ns` is the period in nanoseconds
    /// (`NOTE_NSECONDS`); pass `EV_ADD | EV_ONESHOT` for a single fire or
    /// `EV_ADD` for a repeating timer, and `EV_DELETE` (with `interval_ns` 0)
    /// to disarm. The `ident` lives in the EVFILT_TIMER namespace, distinct
    /// from EVFILT_READ fds and EVFILT_USER idents.
    pub fn timer(ident: usize, flags: u16, interval_ns: i64) -> Self {
        let mut ev = Self::new(ident, libc::EVFILT_TIMER, flags, libc::NOTE_NSECONDS);
        // macOS: data is `isize`; FreeBSD: data is `i64`.
        #[cfg(target_os = "macos")]
        {
            ev.0.data = interval_ns as isize;
        }
        #[cfg(target_os = "freebsd")]
        {
            ev.0.data = interval_ns;
        }
        ev
    }

    fn trigger_user(ident: usize) -> Self {
        Self::new(ident, libc::EVFILT_USER, 0, libc::NOTE_TRIGGER)
    }

    /// Watch a vnode (open fd) for the given `NOTE_*` changes — the backing for
    /// inotify watches. `EV_CLEAR` so each `kevent` returns only the changes
    /// since the last read (edge-triggered, like inotify's event drain).
    pub fn vnode(fd: RawFd, note: u32) -> Self {
        Self::new(
            fd as usize,
            libc::EVFILT_VNODE,
            libc::EV_ADD | libc::EV_CLEAR,
            note,
        )
    }

    /// Remove a previously-added `EVFILT_VNODE` watch for `fd`.
    pub fn vnode_delete(fd: RawFd) -> Self {
        Self::new(fd as usize, libc::EVFILT_VNODE, libc::EV_DELETE, 0)
    }

    /// The fd a returned `EVFILT_VNODE` event refers to (its `ident`).
    pub fn vnode_ident(self) -> RawFd {
        self.0.ident as RawFd
    }

    fn new(ident: usize, filter: i16, flags: u16, fflags: u32) -> Self {
        Self(libc::kevent {
            ident,
            filter,
            flags,
            fflags,
            data: 0,
            udata: std::ptr::null_mut(),
            #[cfg(target_os = "freebsd")]
            ext: [0; 4],
        })
    }

    pub fn is_read_for_fd(self, fd: RawFd) -> bool {
        self.0.ident as RawFd == fd && self.0.filter == libc::EVFILT_READ
    }

    pub fn is_read(self) -> bool {
        self.0.filter == libc::EVFILT_READ
    }

    /// If this event is an EVFILT_TIMER firing, its timer ident; else `None`.
    pub fn timer_ident(self) -> Option<usize> {
        if self.0.filter == libc::EVFILT_TIMER {
            Some(self.0.ident)
        } else {
            None
        }
    }

    #[cfg(test)]
    pub fn is_user(self, ident: usize) -> bool {
        self.0.ident == ident && self.0.filter == libc::EVFILT_USER
    }

    /// Return the raw filter value of this event. Used in tests only.
    #[cfg(test)]
    pub fn raw_filter(self) -> i16 {
        self.0.filter
    }
}

pub fn trigger_user(kq: RawFd, ident: usize) -> Result<(), i32> {
    let trigger = Kevent::trigger_user(ident);
    let rc = unsafe {
        libc::kevent(
            kq,
            std::ptr::from_ref(&trigger).cast::<libc::kevent>(),
            1,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    };
    if rc < 0 {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    } else {
        Ok(())
    }
}

/// Apply kevent changes to a kqueue identified by raw fd (no RAII owner).
/// Used to register/disarm timers on the signal pump's published kqueue from
/// a different thread, mirroring `trigger_user`.
pub fn apply_changes(kq: RawFd, changes: &[Kevent]) -> Result<(), i32> {
    let rc = unsafe {
        libc::kevent(
            kq,
            changes.as_ptr().cast::<libc::kevent>(),
            changes.len() as libc::c_int,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    };
    if rc < 0 {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kqueue_closes_fd_on_drop() {
        let mut observed_close = false;
        for _ in 0..128 {
            let kqueue = Kqueue::new_internal().expect("kqueue should open");
            let fd = kqueue.raw_fd();
            assert!(
                unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0,
                "fd must be live while the Kqueue is held"
            );
            drop(kqueue);
            if unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1 {
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EBADF),
                    "a closed fd must report EBADF"
                );
                observed_close = true;
                break;
            }
        }
        assert!(
            observed_close,
            "Kqueue::drop never closed its fd: F_GETFD never read back EBADF in 128 attempts"
        );
    }

    #[test]
    fn user_trigger_wakes_registered_kqueue() {
        let kqueue = Kqueue::new_internal().expect("kqueue should open");
        kqueue
            .apply(&[Kevent::user(0, libc::EV_ADD | libc::EV_CLEAR)])
            .expect("register user event");
        trigger_user(kqueue.raw_fd(), 0).expect("trigger user event");

        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let mut out = [Kevent::empty()];
        let n = kqueue
            .wait(&[], &mut out, Some(&timeout))
            .expect("wait user event");
        assert_eq!(n, 1);
        assert!(out[0].is_user(0));
    }

    #[test]
    fn oneshot_timer_fires_and_reports_ident() {
        let kqueue = Kqueue::new_internal().expect("kqueue should open");
        let ident = 0xC1_0000usize;
        kqueue
            .apply(&[Kevent::timer(
                ident,
                libc::EV_ADD | libc::EV_ONESHOT,
                1_000_000,
            )])
            .expect("register timer");

        let timeout = libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };
        let mut out = [Kevent::empty()];
        let n = kqueue
            .wait(&[], &mut out, Some(&timeout))
            .expect("wait timer");
        assert_eq!(n, 1);
        assert_eq!(out[0].timer_ident(), Some(ident));
    }
}

/// FreeBSD-specific tests: verify EVFILT_EXCEPT/NOTE_OOB constants are
/// host-correct and do NOT collide with FreeBSD's real filter assignments.
#[cfg(all(test, target_os = "freebsd"))]
mod freebsd_kqueue_tests {
    use super::*;

    /// On FreeBSD, `-15` is `EVFILT_JAILDESC` — a completely different filter
    /// from Darwin's `EVFILT_EXCEPT`. Our sentinel (`i16::MAX`) must never
    /// equal `EVFILT_JAILDESC` so that an accidental OOB registration returns
    /// `EINVAL` rather than silently arming a jail-descriptor watch.
    #[test]
    fn evfilt_except_sentinel_does_not_collide_with_jaildesc() {
        // FreeBSD EVFILT_JAILDESC = -15 (from /usr/include/sys/event.h).
        const EVFILT_JAILDESC: i16 = -15;
        assert_ne!(
            EVFILT_EXCEPT, EVFILT_JAILDESC,
            "EVFILT_EXCEPT sentinel must not collide with FreeBSD EVFILT_JAILDESC (-15)"
        );
        // Sentinel must be positive so it can never match any real filter
        // (all real kqueue filters are negative integers).
        assert!(
            EVFILT_EXCEPT > 0,
            "FreeBSD EVFILT_EXCEPT sentinel must be positive (all real filters are negative)"
        );
    }

    /// Registering EVFILT_EXCEPT on FreeBSD must return an error (EINVAL or
    /// ENOTSUP) — not silently succeed as a EVFILT_JAILDESC watch.
    #[test]
    fn oob_kevent_register_returns_error_on_freebsd() {
        let kq = Kqueue::new_internal().expect("kqueue should open");
        // Create a real TCP socket so the fd is valid.
        let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        assert!(sock >= 0, "socket creation failed");
        let result = kq.apply(&[Kevent::oob(sock, libc::EV_ADD)]);
        unsafe { libc::close(sock) };
        assert!(
            result.is_err(),
            "registering EVFILT_EXCEPT (sentinel) on FreeBSD must fail; \
             got Ok — sentinel may have accidentally matched a real filter"
        );
    }
}
