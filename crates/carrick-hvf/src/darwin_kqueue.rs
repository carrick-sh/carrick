//! Thin safe wrapper around Darwin `kqueue`/`kevent`.
//!
//! THEORY OF OPERATION
//!
//! `kqueue` is the one host primitive that unifies almost every "wait for
//! something" in the carrick concurrency cluster, because it watches fd
//! readiness, process exit, timers, vnode changes, and a user-triggered wake
//! source through ONE blocking call — which is exactly what lets a guest thread
//! park on a guest fd AND its signal self-pipe AND a fork-quiesce wake at the
//! same time. The Linux features layered on top all reduce to a [`Kevent`]
//! filter:
//!
//!   * `EVFILT_READ`/`EVFILT_WRITE`/`EVFILT_EXCEPT` — blocking-I/O waits
//!     ([`crate::io_wait`]) and epoll emulation. `with_udata` stashes the guest
//!     fd so a returned event maps straight back without a reverse lookup.
//!   * `EVFILT_PROC`/`NOTE_EXIT` — a guest child's exit, the macOS-native
//!     process-lifecycle tracking that backs both pidfd and SIGCHLD delivery.
//!     `proc_exit` additionally arms `NOTE_EXITSTATUS` so the event's `data`
//!     carries the exit status, which the namespace supervisor harvests before
//!     launchd reaps the host zombie (after which `waitpid` is ECHILD).
//!   * `EVFILT_TIMER` — `setitimer`/POSIX-timer expiry on the signal pump's
//!     kqueue ([`crate::itimer`]).
//!   * `EVFILT_USER` (`NOTE_TRIGGER`) — an explicit cross-thread wake of the
//!     signal pump; the async-signal-safe path uses the self-pipe instead, since
//!     `kevent` is not async-signal-safe.
//!   * `EVFILT_VNODE` — the backing for inotify watches.
//!
//! INVARIANT — EDGE vs LEVEL is a correctness choice, not a tuning knob. Wake
//! pipes and vnode/user watches are registered `EV_CLEAR` (edge-triggered) on
//! purpose to avoid duplicate wake-byte delivery before userspace drains them.
//! EOF is still special: after userspace reads `0`, Darwin can deliver the EOF
//! edge again, so [`crate::io_wait`] deletes dead wake-pipe filters and falls
//! back to bounded polling instead of busy-spinning a vCPU at 100%.
//!
//! The wrapper is deliberately thin: [`Kqueue`] is just an RAII fd owner, and
//! [`Kevent`] is `#[repr(transparent)]` over `libc::kevent` so call sites never
//! hand-build a raw `kevent`. The `EVFILT_EXCEPT`/`NOTE_OOB` constants are
//! defined here because the pinned `libc` version doesn't expose them.

use std::os::fd::RawFd;

/// Darwin's exceptional-condition filter. The `libc` crate version used here
/// does not expose this SDK constant.
pub const EVFILT_EXCEPT: i16 = -15;
/// `EVFILT_EXCEPT` hint for socket out-of-band data.
pub const NOTE_OOB: u32 = 0x0000_0002;

/// RAII owner for a Darwin kqueue fd.
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
        let fd = crate::host_signal::relocate_internal_fd(raw);
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
            libc::NOTE_EXIT | libc::NOTE_EXITSTATUS,
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

    /// The integer previously stashed via [`with_udata`](Self::with_udata) (the
    /// guest fd).
    pub fn udata_i32(self) -> i32 {
        self.0.udata as isize as i32
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
        ev.0.data = interval_ns as isize;
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
        // `Kqueue::drop` must close its fd. Asserting that the freed fd *number*
        // reads back EBADF after a single drop is racy under the parallel test
        // harness: the moment Drop closes the fd, another test thread can reuse
        // that number for a fresh descriptor, so F_GETFD nondeterministically
        // reads back as a live, unrelated fd (observed: == FD_CLOEXEC from a
        // sibling's new CLOEXEC fd). Inspecting the bare number is therefore racy
        // to read and unsafe to close/dup2 (it might clobber the sibling).
        //
        // But that reuse can only happen *because* Drop freed the number — so
        // retry until we observe an iteration where it is still free and reads
        // back EBADF. A correct Drop reaches that within a try or two; a Drop that
        // failed to close would read back its own live kqueue on every attempt and
        // never reach EBADF, failing the bounded loop. Only ever *reads* the fd.
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
            // The freed number was reused before we looked; retry with a fresh one.
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
