//! Thin safe wrapper around Darwin kqueue/kevent operations used by waits,
//! epoll emulation, timers, and signal pumping.

use std::os::fd::RawFd;

/// RAII owner for a Darwin kqueue fd.
#[derive(Debug)]
pub(crate) struct Kqueue {
    fd: RawFd,
}

impl Kqueue {
    pub(crate) fn new_internal() -> Option<Self> {
        let raw = unsafe { libc::kqueue() };
        if raw < 0 {
            return None;
        }
        Some(Self {
            fd: crate::host_signal::relocate_internal_fd(raw),
        })
    }

    pub(crate) fn raw_fd(&self) -> RawFd {
        self.fd
    }

    pub(crate) fn apply(&self, changes: &[Kevent]) -> Result<(), i32> {
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

    pub(crate) fn wait(
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
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Opaque wrapper around Darwin's `struct kevent` so call sites do not build
/// raw `libc::kevent` values themselves.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub(crate) struct Kevent(libc::kevent);

impl Kevent {
    pub(crate) fn empty() -> Self {
        Self(libc::kevent {
            ident: 0,
            filter: 0,
            flags: 0,
            fflags: 0,
            data: 0,
            udata: std::ptr::null_mut(),
        })
    }

    pub(crate) fn read(fd: RawFd, flags: u16) -> Self {
        Self::new(fd as usize, libc::EVFILT_READ, flags, 0)
    }

    pub(crate) fn write(fd: RawFd, flags: u16) -> Self {
        Self::new(fd as usize, libc::EVFILT_WRITE, flags, 0)
    }

    /// Watch process `pid` for exit. The kqueue becomes read-ready (and a
    /// `kevent` returns this event) when the process terminates — the macOS
    /// kernel's native process-lifecycle tracking that backs a guest pidfd.
    /// One-shot: fires once on exit.
    pub(crate) fn proc_exit(pid: i32) -> Self {
        Self::new(
            pid as usize,
            libc::EVFILT_PROC,
            (libc::EV_ADD | libc::EV_ONESHOT) as u16,
            libc::NOTE_EXIT,
        )
    }

    /// Delete a previously-added `EVFILT_PROC`/`NOTE_EXIT` watch for `pid`.
    /// `proc_exit` is `EV_ONESHOT` (auto-removed once it fires), so this is only
    /// needed to drop a watch whose wait was interrupted before the exit fired.
    pub(crate) fn proc_exit_delete(pid: i32) -> Self {
        Self::new(pid as usize, libc::EVFILT_PROC, libc::EV_DELETE as u16, 0)
    }

    /// Stash a small integer (a guest fd) in `udata` so a returned event maps
    /// straight back to its guest fd without a reverse lookup. Used by the
    /// epoll-backing kqueue (`dispatch::net`).
    pub(crate) fn with_udata(mut self, udata: i32) -> Self {
        self.0.udata = udata as isize as *mut libc::c_void;
        self
    }

    /// The kqueue filter (`EVFILT_READ`/`EVFILT_WRITE`/`EVFILT_USER`/…).
    pub(crate) fn filter(self) -> i16 {
        self.0.filter
    }

    /// The event flags (`EV_EOF`, `EV_ERROR`, …) on a returned event.
    pub(crate) fn flags(self) -> u16 {
        self.0.flags
    }

    /// The filter-specific flags (`fflags`) — for `EV_EOF` this carries the
    /// socket/pipe error code, which maps to `EPOLLERR`.
    pub(crate) fn fflags(self) -> u32 {
        self.0.fflags
    }

    /// The integer previously stashed via [`with_udata`] (the guest fd).
    pub(crate) fn udata_i32(self) -> i32 {
        self.0.udata as isize as i32
    }

    pub(crate) fn user(ident: usize, flags: u16) -> Self {
        Self::new(ident, libc::EVFILT_USER, flags, 0)
    }

    /// One-shot or periodic timer. `interval_ns` is the period in nanoseconds
    /// (`NOTE_NSECONDS`); pass `EV_ADD | EV_ONESHOT` for a single fire or
    /// `EV_ADD` for a repeating timer, and `EV_DELETE` (with `interval_ns` 0)
    /// to disarm. The `ident` lives in the EVFILT_TIMER namespace, distinct
    /// from EVFILT_READ fds and EVFILT_USER idents.
    pub(crate) fn timer(ident: usize, flags: u16, interval_ns: i64) -> Self {
        let mut ev = Self::new(ident, libc::EVFILT_TIMER, flags, libc::NOTE_NSECONDS);
        ev.0.data = interval_ns as isize;
        ev
    }

    fn trigger_user(ident: usize) -> Self {
        Self::new(ident, libc::EVFILT_USER, 0, libc::NOTE_TRIGGER)
    }

    fn new(ident: usize, filter: i16, flags: u16, fflags: u32) -> Self {
        Self(libc::kevent {
            ident,
            filter,
            flags,
            fflags,
            data: 0,
            udata: std::ptr::null_mut(),
        })
    }

    pub(crate) fn is_read_for_fd(self, fd: RawFd) -> bool {
        self.0.ident as RawFd == fd && self.0.filter == libc::EVFILT_READ
    }

    pub(crate) fn is_read(self) -> bool {
        self.0.filter == libc::EVFILT_READ
    }

    /// If this event is an EVFILT_TIMER firing, its timer ident; else `None`.
    pub(crate) fn timer_ident(self) -> Option<usize> {
        if self.0.filter == libc::EVFILT_TIMER {
            Some(self.0.ident)
        } else {
            None
        }
    }

    #[cfg(test)]
    pub(crate) fn is_user(self, ident: usize) -> bool {
        self.0.ident == ident && self.0.filter == libc::EVFILT_USER
    }
}

pub(crate) fn trigger_user(kq: RawFd, ident: usize) -> Result<(), i32> {
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
pub(crate) fn apply_changes(kq: RawFd, changes: &[Kevent]) -> Result<(), i32> {
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
        let fd = {
            let kqueue = Kqueue::new_internal().expect("kqueue should open");
            let fd = kqueue.raw_fd();
            assert!(unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0);
            fd
        };

        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
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
        // 1ms one-shot timer.
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
