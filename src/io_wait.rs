//! Per-thread blocking-I/O wait built on macOS `kqueue`.
//!
//! A guest thread that issues a blocking syscall (recv/accept/ppoll/…) must
//! wait WITHOUT holding the dispatcher lock — otherwise it starves every
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

#[cfg(target_os = "macos")]
use crate::darwin_kqueue::{Kevent, Kqueue};

/// Result of a blocking-I/O wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitResult {
    /// One of the watched fds is ready — the runtime re-dispatches the syscall.
    Ready,
    /// The guest timeout elapsed with no fd ready.
    TimedOut,
    /// A signal became pending — the runtime delivers it (syscall → EINTR).
    Interrupted,
}

struct PinnedWaitFd {
    fd: RawFd,
    owned: bool,
}

impl Drop for PinnedWaitFd {
    fn drop(&mut self) {
        if self.owned {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

struct PinnedWaitFds {
    wait_fds: Vec<(RawFd, i16)>,
    _pinned: Vec<PinnedWaitFd>,
}

impl PinnedWaitFds {
    fn new(fds: &[(RawFd, i16)]) -> Self {
        let mut wait_fds = Vec::with_capacity(fds.len());
        let mut pinned = Vec::with_capacity(fds.len());
        for &(fd, events) in fds {
            let duped = unsafe { libc::dup(fd) };
            let (wait_fd, owned) = if duped >= 0 {
                (duped, true)
            } else {
                (fd, false)
            };
            wait_fds.push((wait_fd, events));
            pinned.push(PinnedWaitFd { fd: wait_fd, owned });
        }
        Self {
            wait_fds,
            _pinned: pinned,
        }
    }

    fn as_wait_fds(&self) -> &[(RawFd, i16)] {
        &self.wait_fds
    }
}

/// A per-thread kqueue + its registration of the self-pipe wake channel.
pub struct ThreadWaiter {
    #[cfg(target_os = "macos")]
    kq: Option<Kqueue>,
    /// Process-wide self-pipe read fd for process-directed signals, or `-1`.
    process_pipe_read: RawFd,
    /// Per-thread wake pipe for thread-directed signals.
    thread_wake: Option<crate::host_signal::ThreadWakePipe>,
    /// The guest tid this waiter runs for, so a pending signal targeted at a
    /// *sibling* thread doesn't spuriously interrupt this thread's blocking
    /// syscall (which would surface a wrong EINTR). Process-directed signals
    /// still interrupt any thread.
    tid: crate::thread::ThreadId,
}

impl ThreadWaiter {
    #[cfg(target_os = "macos")]
    pub fn new(tid: crate::thread::ThreadId) -> Self {
        let kq = Kqueue::new_internal();
        let process_pipe_read = crate::host_signal::pending_pipe_read_fd();
        let thread_wake = crate::host_signal::register_thread_waiter(tid);
        if let Some(kq) = kq.as_ref()
        {
            let mut changes = Vec::with_capacity(2);
            if process_pipe_read >= 0 {
                // Persistent EVFILT_READ on the process self-pipe: any byte the
                // async signal handler writes wakes waiters immediately.
                changes.push(Kevent::read(process_pipe_read, libc::EV_ADD));
            }
            if let Some(thread_wake) = thread_wake.as_ref() {
                // Thread-directed signals use a private pipe so siblings cannot
                // drain the target's wake before its kqueue observes it.
                changes.push(Kevent::read(thread_wake.read_fd(), libc::EV_ADD));
            }
            if !changes.is_empty() {
                let _ = kq.apply(&changes);
            }
        }
        Self {
            kq,
            process_pipe_read,
            thread_wake,
            tid,
        }
    }

    #[cfg(not(target_os = "macos"))]
    pub fn new(tid: crate::thread::ThreadId) -> Self {
        Self {
            process_pipe_read: -1,
            thread_wake: None,
            tid,
        }
    }

    /// Block until one of `fds` (host fds, with `libc::POLL*` event masks) is
    /// ready, `timeout` elapses, or a signal becomes pending. The dispatcher lock
    /// MUST NOT be held by the caller. `fds` may be empty (a pure sleep).
    ///
    /// `block_mask` is the set of signals (bit `signum-1`) the caller's syscall
    /// temporarily blocks (an `epoll_pwait`/`ppoll`/`pselect6` sigmask); a signal
    /// blocked by it does not interrupt the wait (it stays pending for delivery
    /// after the syscall, per the persistent mask). `0` = no extra blocking.
    pub fn wait(
        &self,
        fds: &[(i32, i16)],
        timeout: Option<Duration>,
        block_mask: u64,
    ) -> WaitResult {
        let fd0 = fds.first().map_or(-1, |(fd, _)| *fd);
        let events0 = fds.first().map_or(0, |(_, events)| i32::from(*events));
        let fd1 = fds.get(1).map_or(-1, |(fd, _)| *fd);
        crate::probes::io_wait_begin(
            self.tid,
            fds.len() as i32,
            timeout
                .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
                .unwrap_or(-1),
            fd0,
            events0,
            fd1,
        );
        // A signal that arrived just before we parked must not be missed
        // (unless it's blocked by this wait's sigmask).
        if crate::host_signal::has_unblocked_pending_for(self.tid, block_mask) {
            crate::probes::io_wait_end(
                self.tid,
                wait_result_code(WaitResult::Interrupted),
                fds.len() as i32,
                fd0,
                fd1,
                fds.get(2).map_or(-1, |(fd, _)| *fd),
            );
            return WaitResult::Interrupted;
        }
        let pinned_fds = PinnedWaitFds::new(fds);
        let wait_fds = pinned_fds.as_wait_fds();
        let result;
        #[cfg(target_os = "macos")]
        {
            if let Some(kq) = self.kq.as_ref() {
                result = self.wait_kqueue(kq, wait_fds, timeout, block_mask);
                crate::probes::io_wait_end(
                    self.tid,
                    wait_result_code(result),
                    fds.len() as i32,
                    fd0,
                    fd1,
                    fds.get(2).map_or(-1, |(fd, _)| *fd),
                );
                return result;
            }
        }
        result = self.fallback_poll(wait_fds, timeout, block_mask);
        crate::probes::io_wait_end(
            self.tid,
            wait_result_code(result),
            fds.len() as i32,
            fd0,
            fd1,
            fds.get(2).map_or(-1, |(fd, _)| *fd),
        );
        result
    }

    /// Block using `poll(2)` instead of the per-thread kqueue. This is used for
    /// kqueue fds themselves: poll observes kqueue readability without draining
    /// the queued events.
    pub fn wait_poll(
        &self,
        fds: &[(i32, i16)],
        timeout: Option<Duration>,
        block_mask: u64,
    ) -> WaitResult {
        let fd0 = fds.first().map_or(-1, |(fd, _)| *fd);
        let events0 = fds.first().map_or(0, |(_, events)| i32::from(*events));
        let fd1 = fds.get(1).map_or(-1, |(fd, _)| *fd);
        crate::probes::io_wait_begin(
            self.tid,
            fds.len() as i32,
            timeout
                .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
                .unwrap_or(-1),
            fd0,
            events0,
            fd1,
        );
        if crate::host_signal::has_unblocked_pending_for(self.tid, block_mask) {
            crate::probes::io_wait_end(
                self.tid,
                wait_result_code(WaitResult::Interrupted),
                fds.len() as i32,
                fd0,
                fd1,
                fds.get(2).map_or(-1, |(fd, _)| *fd),
            );
            return WaitResult::Interrupted;
        }
        let pinned_fds = PinnedWaitFds::new(fds);
        let result = self.poll_with_signal(pinned_fds.as_wait_fds(), timeout, block_mask);
        crate::probes::io_wait_end(
            self.tid,
            wait_result_code(result),
            fds.len() as i32,
            fd0,
            fd1,
            fds.get(2).map_or(-1, |(fd, _)| *fd),
        );
        result
    }

    #[cfg(target_os = "macos")]
    fn wait_kqueue(
        &self,
        kq: &Kqueue,
        fds: &[(i32, i16)],
        timeout: Option<Duration>,
        block_mask: u64,
    ) -> WaitResult {
        let deadline = timeout.map(|d| Instant::now() + d);
        let mut changes: Vec<Kevent> = Vec::with_capacity(fds.len() * 2);
        for &(fd, events) in fds {
            if events & libc::POLLIN != 0 {
                changes.push(Kevent::read(fd, libc::EV_ADD));
            }
            if events & libc::POLLOUT != 0 {
                changes.push(Kevent::write(fd, libc::EV_ADD));
            }
        }
        let cap = (changes.len() + self.signal_pipe_count()).max(1);
        let mut events_out: Vec<Kevent> = vec![Kevent::empty(); cap];

        let result = loop {
            let ts = match deadline {
                Some(dl) => {
                    let now = Instant::now();
                    if now >= dl {
                        break WaitResult::TimedOut;
                    }
                    Some(duration_to_timespec(dl - now))
                }
                // No deadline: a signal pipe wakes us on a signal, so block
                // indefinitely. Without the pipe, cap at 50ms to re-check.
                None if self.has_signal_pipe() => None,
                None => Some(libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 50_000_000,
                }),
            };
            let n = kq.wait(&changes, &mut events_out, ts.as_ref());
            changes.clear(); // registrations persist; only re-add once.

            let n = match n {
                Ok(n) => n,
                Err(_) => {
                    // EINTR (a signal raced in) — re-check the pending flag.
                    if crate::host_signal::has_unblocked_pending_for(self.tid, block_mask) {
                        break WaitResult::Interrupted;
                    }
                    continue;
                }
            };
            let mut fd_ready = false;
            let mut process_pipe_woke = false;
            let mut thread_pipe_woke = false;
            for e in &events_out[..n] {
                if e.is_read_for_fd(self.process_pipe_read) {
                    process_pipe_woke = true;
                } else if self
                    .thread_wake
                    .as_ref()
                    .is_some_and(|thread_wake| e.is_read_for_fd(thread_wake.read_fd()))
                {
                    thread_pipe_woke = true;
                } else {
                    // A real fd event, OR an EV_ERROR on a bad fd: either way,
                    // let the re-dispatched op observe the true state/errno.
                    fd_ready = true;
                }
            }
            if fd_ready {
                break WaitResult::Ready;
            }
            if process_pipe_woke {
                crate::host_signal::drain_pending_pipe();
            }
            if thread_pipe_woke
                && let Some(thread_wake) = self.thread_wake.as_ref()
            {
                thread_wake.drain();
            }
            if crate::host_signal::has_unblocked_pending_for(self.tid, block_mask) {
                break WaitResult::Interrupted;
            }
            // Spurious wake or fallback slice elapsed — re-park (the deadline
            // is re-checked at the top of the loop).
        };

        self.clear_fd_registrations(kq, fds);
        result
    }

    /// Remove the per-wait fd filters so they don't accumulate on the long-lived
    /// kqueue. ENOENT (already gone) is fine.
    #[cfg(target_os = "macos")]
    fn clear_fd_registrations(&self, kq: &Kqueue, fds: &[(i32, i16)]) {
        if fds.is_empty() {
            return;
        }
        let mut deletes: Vec<Kevent> = Vec::with_capacity(fds.len() * 2);
        for &(fd, events) in fds {
            if events & libc::POLLIN != 0 {
                deletes.push(Kevent::read(fd, libc::EV_DELETE));
            }
            if events & libc::POLLOUT != 0 {
                deletes.push(Kevent::write(fd, libc::EV_DELETE));
            }
        }
        let zero = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let _ = kq.wait(&deletes, &mut [], Some(&zero));
    }

    /// Bounded poll loop used when kqueue is unavailable (non-macOS stubs, or a
    /// `kqueue()` failure). 50ms signal-recheck slices, matching the pre-kqueue
    /// behaviour. fd-readiness still wakes promptly (poll blocks until ready).
    fn fallback_poll(
        &self,
        fds: &[(i32, i16)],
        timeout: Option<Duration>,
        block_mask: u64,
    ) -> WaitResult {
        self.poll_with_signal(fds, timeout, block_mask)
    }

    fn poll_with_signal(
        &self,
        fds: &[(i32, i16)],
        timeout: Option<Duration>,
        block_mask: u64,
    ) -> WaitResult {
        const SLICE_MS: i32 = 50;
        let deadline = timeout.map(|d| Instant::now() + d);
        let mut pollfds: Vec<libc::pollfd> = fds
            .iter()
            .map(|&(fd, events)| libc::pollfd {
                fd,
                events,
                revents: 0,
            })
            .collect();
        let process_signal_index = if self.process_pipe_read >= 0 {
            let index = pollfds.len();
            pollfds.push(libc::pollfd {
                fd: self.process_pipe_read,
                events: libc::POLLIN,
                revents: 0,
            });
            Some(index)
        } else {
            None
        };
        let thread_signal_index = self.thread_wake.as_ref().map(|thread_wake| {
            let index = pollfds.len();
            pollfds.push(libc::pollfd {
                fd: thread_wake.read_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
            index
        });
        loop {
            if crate::host_signal::has_unblocked_pending_for(self.tid, block_mask) {
                return WaitResult::Interrupted;
            }
            for pfd in &mut pollfds {
                pfd.revents = 0;
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
                libc::poll(
                    pollfds.as_mut_ptr(),
                    pollfds.len() as libc::nfds_t,
                    slice_ms,
                )
            };
            if n > 0 {
                if pollfds[..fds.len()].iter().any(|pfd| pfd.revents != 0) {
                    return WaitResult::Ready;
                }
                if process_signal_index
                    .and_then(|index| pollfds.get(index))
                    .is_some_and(|pfd| pfd.revents != 0)
                {
                    crate::host_signal::drain_pending_pipe();
                }
                if thread_signal_index
                    .and_then(|index| pollfds.get(index))
                    .is_some_and(|pfd| pfd.revents != 0)
                    && let Some(thread_wake) = self.thread_wake.as_ref()
                {
                    thread_wake.drain();
                }
                if crate::host_signal::has_unblocked_pending_for(self.tid, block_mask) {
                    return WaitResult::Interrupted;
                }
            } else if n < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error();
                if errno == Some(libc::EINTR)
                    && crate::host_signal::has_unblocked_pending_for(self.tid, block_mask)
                {
                    return WaitResult::Interrupted;
                }
            }
        }
    }

    fn has_signal_pipe(&self) -> bool {
        self.process_pipe_read >= 0 || self.thread_wake.is_some()
    }

    fn signal_pipe_count(&self) -> usize {
        usize::from(self.process_pipe_read >= 0) + usize::from(self.thread_wake.is_some())
    }
}

fn wait_result_code(result: WaitResult) -> i32 {
    match result {
        WaitResult::Ready => 0,
        WaitResult::TimedOut => 1,
        WaitResult::Interrupted => 2,
    }
}

#[cfg(target_os = "macos")]
fn duration_to_timespec(d: Duration) -> libc::timespec {
    libc::timespec {
        tv_sec: d.as_secs() as libc::time_t,
        tv_nsec: d.subsec_nanos() as libc::c_long,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn pinned_wait_fd_survives_original_close() {
        let mut fds = [-1, -1];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let pinned = super::PinnedWaitFds::new(&[(fds[0], libc::POLLIN)]);
        assert_eq!(unsafe { libc::close(fds[0]) }, 0);
        assert_eq!(unsafe { libc::write(fds[1], b"x".as_ptr().cast(), 1) }, 1);

        let mut pollfd = libc::pollfd {
            fd: pinned.as_wait_fds()[0].0,
            events: pinned.as_wait_fds()[0].1,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut pollfd, 1, 0) }, 1);
        assert_ne!(pollfd.revents & libc::POLLIN, 0);
        assert_eq!(unsafe { libc::close(fds[1]) }, 0);
    }
}
