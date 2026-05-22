//! Per-thread blocking-I/O wait built on macOS `kqueue`.
//!
//! A guest thread that issues a blocking syscall (recv/accept/ppoll/…) must
//! wait WITHOUT holding the big kernel lock — otherwise it starves every
//! sibling vCPU thread (the GIL/server-worker starvation). The runtime drops
//! the lock and parks the vCPU thread here, in `kevent()`, on:
//!
//!   * `EVFILT_READ` / `EVFILT_WRITE` for the host fd(s) it's waiting on, and
//!   * `EVFILT_READ` on the process-wide self-pipe (see `host_signal`), whose
//!     write end the signal handler pokes so a pending guest signal wakes the
//!     wait PROMPTLY — no 50ms poll, and no reliance on `SA_RESTART`/EINTR
//!     (a queue event, not a Unix signal).
//!
//! Each thread owns its own `kqueue` (a kqueue is NOT shared and is NOT
//! inherited across fork — `host_signal::reinit_after_fork` + a fresh waiter
//! handle that). On non-macOS targets (the type-check-only stubs) this degrades
//! to a bounded `poll` loop.

use std::os::fd::RawFd;
use std::time::{Duration, Instant};

/// Result of a blocking-I/O wait.
pub enum WaitResult {
    /// One of the watched fds is ready — the runtime re-dispatches the syscall.
    Ready,
    /// The guest timeout elapsed with no fd ready.
    TimedOut,
    /// A signal became pending — the runtime delivers it (syscall → EINTR).
    Interrupted,
}

/// A per-thread kqueue + its registration of the self-pipe wake channel.
pub struct ThreadWaiter {
    kq: RawFd,
    /// The self-pipe read fd this waiter registered, or `-1` if unavailable.
    pipe_read: RawFd,
}

impl ThreadWaiter {
    #[cfg(target_os = "macos")]
    pub fn new() -> Self {
        let kq = unsafe { libc::kqueue() };
        let pipe_read = crate::host_signal::pending_pipe_read_fd();
        if kq >= 0 && pipe_read >= 0 {
            // Persistent EVFILT_READ on the self-pipe: any byte the signal
            // handler writes wakes this thread's kevent() immediately.
            let change = ev(pipe_read, libc::EVFILT_READ, libc::EV_ADD);
            unsafe {
                libc::kevent(kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null());
            }
        }
        Self { kq, pipe_read }
    }

    #[cfg(not(target_os = "macos"))]
    pub fn new() -> Self {
        Self { kq: -1, pipe_read: -1 }
    }

    /// Block until one of `fds` (host fds, with `libc::POLL*` event masks) is
    /// ready, `timeout` elapses, or a signal becomes pending. The kernel lock
    /// MUST NOT be held by the caller. `fds` may be empty (a pure sleep).
    pub fn wait(&self, fds: &[(i32, i16)], timeout: Option<Duration>) -> WaitResult {
        // A signal that arrived just before we parked must not be missed.
        if crate::host_signal::has_pending() {
            return WaitResult::Interrupted;
        }
        #[cfg(target_os = "macos")]
        {
            if self.kq >= 0 {
                return self.wait_kqueue(fds, timeout);
            }
        }
        self.fallback_poll(fds, timeout)
    }

    #[cfg(target_os = "macos")]
    fn wait_kqueue(&self, fds: &[(i32, i16)], timeout: Option<Duration>) -> WaitResult {
        let deadline = timeout.map(|d| Instant::now() + d);
        let mut changes: Vec<libc::kevent> = Vec::with_capacity(fds.len() * 2);
        for &(fd, events) in fds {
            if events & libc::POLLIN != 0 {
                changes.push(ev(fd, libc::EVFILT_READ, libc::EV_ADD));
            }
            if events & libc::POLLOUT != 0 {
                changes.push(ev(fd, libc::EVFILT_WRITE, libc::EV_ADD));
            }
        }
        let cap = (changes.len() + 1).max(1);
        let mut events_out: Vec<libc::kevent> = vec![zeroed_kevent(); cap];

        let result = loop {
            let ts = match deadline {
                Some(dl) => {
                    let now = Instant::now();
                    if now >= dl {
                        break WaitResult::TimedOut;
                    }
                    Some(duration_to_timespec(dl - now))
                }
                // No deadline: the self-pipe wakes us on a signal, so block
                // indefinitely. Without the pipe, cap at 50ms to re-check.
                None if self.pipe_read >= 0 => None,
                None => Some(libc::timespec { tv_sec: 0, tv_nsec: 50_000_000 }),
            };
            let ts_ptr = ts.as_ref().map_or(std::ptr::null(), |t| t as *const _);
            let n = unsafe {
                libc::kevent(
                    self.kq,
                    if changes.is_empty() { std::ptr::null() } else { changes.as_ptr() },
                    changes.len() as libc::c_int,
                    events_out.as_mut_ptr(),
                    events_out.len() as libc::c_int,
                    ts_ptr,
                )
            };
            changes.clear(); // registrations persist; only re-add once.

            if n < 0 {
                // EINTR (a signal raced in) — re-check the pending flag.
                if crate::host_signal::has_pending() {
                    break WaitResult::Interrupted;
                }
                continue;
            }
            let mut fd_ready = false;
            let mut pipe_woke = false;
            for e in &events_out[..n as usize] {
                if e.ident as RawFd == self.pipe_read && e.filter == libc::EVFILT_READ {
                    pipe_woke = true;
                } else {
                    // A real fd event, OR an EV_ERROR on a bad fd: either way,
                    // let the re-dispatched op observe the true state/errno.
                    fd_ready = true;
                }
            }
            if fd_ready {
                break WaitResult::Ready;
            }
            if pipe_woke {
                crate::host_signal::drain_pending_pipe();
            }
            if crate::host_signal::has_pending() {
                break WaitResult::Interrupted;
            }
            // Spurious wake or fallback slice elapsed — re-park (the deadline
            // is re-checked at the top of the loop).
        };

        self.clear_fd_registrations(fds);
        result
    }

    /// Remove the per-wait fd filters so they don't accumulate on the long-lived
    /// kqueue. ENOENT (already gone) is fine.
    #[cfg(target_os = "macos")]
    fn clear_fd_registrations(&self, fds: &[(i32, i16)]) {
        if fds.is_empty() {
            return;
        }
        let mut deletes: Vec<libc::kevent> = Vec::with_capacity(fds.len() * 2);
        for &(fd, events) in fds {
            if events & libc::POLLIN != 0 {
                deletes.push(ev(fd, libc::EVFILT_READ, libc::EV_DELETE));
            }
            if events & libc::POLLOUT != 0 {
                deletes.push(ev(fd, libc::EVFILT_WRITE, libc::EV_DELETE));
            }
        }
        let zero = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe {
            libc::kevent(
                self.kq,
                deletes.as_ptr(),
                deletes.len() as libc::c_int,
                std::ptr::null_mut(),
                0,
                &zero,
            );
        }
    }

    /// Bounded poll loop used when kqueue is unavailable (non-macOS stubs, or a
    /// `kqueue()` failure). 50ms signal-recheck slices, matching the pre-kqueue
    /// behaviour. fd-readiness still wakes promptly (poll blocks until ready).
    fn fallback_poll(&self, fds: &[(i32, i16)], timeout: Option<Duration>) -> WaitResult {
        const SLICE_MS: i32 = 50;
        let deadline = timeout.map(|d| Instant::now() + d);
        let mut pollfds: Vec<libc::pollfd> = fds
            .iter()
            .map(|&(fd, events)| libc::pollfd { fd, events, revents: 0 })
            .collect();
        loop {
            if crate::host_signal::has_pending() {
                return WaitResult::Interrupted;
            }
            let slice_ms = match deadline {
                Some(dl) => {
                    let now = Instant::now();
                    if now >= dl {
                        return WaitResult::TimedOut;
                    }
                    (dl - now).as_millis().min(SLICE_MS as u128) as i32
                }
                None => SLICE_MS,
            };
            let n = unsafe {
                libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, slice_ms)
            };
            if n > 0 {
                return WaitResult::Ready;
            }
        }
    }
}

impl Drop for ThreadWaiter {
    fn drop(&mut self) {
        if self.kq >= 0 {
            unsafe { libc::close(self.kq) };
        }
    }
}

#[cfg(target_os = "macos")]
fn ev(fd: i32, filter: i16, flags: u16) -> libc::kevent {
    libc::kevent {
        ident: fd as usize,
        filter,
        flags,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    }
}

#[cfg(target_os = "macos")]
fn zeroed_kevent() -> libc::kevent {
    libc::kevent {
        ident: 0,
        filter: 0,
        flags: 0,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    }
}

#[cfg(target_os = "macos")]
fn duration_to_timespec(d: Duration) -> libc::timespec {
    libc::timespec {
        tv_sec: d.as_secs() as libc::time_t,
        tv_nsec: d.subsec_nanos() as libc::c_long,
    }
}
