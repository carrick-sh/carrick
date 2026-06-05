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
use std::sync::atomic::{AtomicBool, Ordering};
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
    /// Could not pin (dup) a watched fd — host fd table exhausted. Carries the
    /// LINUX errno to surface to the guest (LINUX_EMFILE / LINUX_ENFILE).
    Errno(i32),
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
    /// Pin (dup) every watched fd so a sibling thread's close()+open() cannot
    /// silently re-target the parked wait at a different file. FAIL-CLOSED: on
    /// ANY dup() failure (host fd table exhausted) return Err with a LINUX
    /// errno — never fall back to parking on the raw, unowned guest fd (the
    /// exact fd-reuse race this dup is meant to prevent). The partially-duped
    /// set is dropped via PinnedWaitFd::Drop (RAII rollback).
    fn new(fds: &[(RawFd, i16)]) -> Result<Self, i32> {
        let mut wait_fds = Vec::with_capacity(fds.len());
        let mut pinned = Vec::with_capacity(fds.len());
        for &(fd, events) in fds {
            let duped = unsafe { libc::dup(fd) };
            if duped < 0 {
                // Read errno IMMEDIATELY (before any other libc call clobbers it).
                let host = std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EMFILE);
                let linux_errno = match host {
                    libc::ENFILE => crate::linux_abi::LINUX_ENFILE,
                    _ => crate::linux_abi::LINUX_EMFILE,
                };
                return Err(linux_errno); // partial `pinned` drops here → closes already-duped fds
            }
            wait_fds.push((duped, events));
            pinned.push(PinnedWaitFd {
                fd: duped,
                owned: true,
            });
        }
        Ok(Self {
            wait_fds,
            _pinned: pinned,
        })
    }

    fn as_wait_fds(&self) -> &[(RawFd, i16)] {
        &self.wait_fds
    }
}

/// Outcome of `wait_proc_exit`'s kqueue fast path.
#[cfg(target_os = "macos")]
enum ProcExitWait {
    /// The wait resolved (child exited, signal pending, or fork quiesce began).
    Done(WaitResult),
    /// `kevent` reported the kqueue fd itself is invalid (EBADF) — it was closed
    /// out from under us by the fork-storm internal-fd churn. Retrying the same
    /// kqueue can only EBADF forever, so the caller polls the child directly.
    KqueueDead,
}

#[cfg(target_os = "macos")]
fn child_status_ready(pid: i32) -> bool {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
        )
    };
    if rc == 0 {
        // si_pid != 0 means the child has exited. WNOWAIT leaves it reapable
        // for the caller's re-dispatched wait4/waitid.
        info.si_pid != 0
    } else {
        // Already reaped (or never ours). Report ready so the caller surfaces
        // the real status/ECHILD exactly as it would without this backstop.
        std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
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
    /// True once this waiter observes EOF/error on an internal wake pipe. Its
    /// kqueue registration can no longer provide reliable signal wakeups; use
    /// bounded poll slices instead.
    wake_pipe_dead: AtomicBool,
    /// The guest tid this waiter runs for, so a pending signal targeted at a
    /// *sibling* thread doesn't spuriously interrupt this thread's blocking
    /// syscall (which would surface a wrong EINTR). Process-directed signals
    /// still interrupt any thread.
    tid: crate::thread::ThreadId,
    /// Created by a freshly forked child before it has performed any blocking
    /// syscall. It keeps process-directed signal wakeups via the process
    /// self-pipe, but skips the per-thread kqueue/wake-pipe until the child
    /// actually needs to park.
    deferred_full_init: bool,
}

/// kqueue registration for a WAKE pipe (the process-directed self-pipe and the
/// per-thread wake channel). These are edge-triggered (`EV_CLEAR`) to avoid
/// duplicate delivery before the waiter drains a wake byte. EOF is still
/// special: after a drain reads `0`, Darwin can re-deliver the EOF edge, so the
/// wait path must delete that registration and fall back to bounded polling.
#[cfg(target_os = "macos")]
fn wake_pipe_read_kevent(fd: RawFd) -> Kevent {
    Kevent::read(fd, libc::EV_ADD | libc::EV_CLEAR)
}

#[cfg(target_os = "macos")]
fn delete_wake_pipe_registration(kq: &Kqueue, fd: RawFd) {
    let _ = kq.apply(&[Kevent::read(fd, libc::EV_DELETE)]);
}

#[cfg(target_os = "macos")]
fn drain_wake_pipe_registration(kq: &Kqueue, fd: RawFd) -> crate::host_signal::DrainResult {
    let result = crate::host_signal::drain_fd(fd);
    if result == crate::host_signal::DrainResult::Dead {
        delete_wake_pipe_registration(kq, fd);
    }
    result
}

impl ThreadWaiter {
    #[cfg(target_os = "macos")]
    pub fn new(tid: crate::thread::ThreadId) -> Self {
        let kq = Kqueue::new_internal();
        let process_pipe_read = crate::host_signal::pending_pipe_read_fd();
        let thread_wake = crate::host_signal::register_thread_waiter(tid);
        if let Some(kq) = kq.as_ref() {
            let mut changes = Vec::with_capacity(2);
            if process_pipe_read >= 0 {
                // Persistent EVFILT_READ on the process self-pipe: any byte the
                // async signal handler writes wakes waiters immediately. Edge-
                // triggered (see wake_pipe_read_kevent) so a closed-write-end
                // (EOF) pipe can't busy-spin the wait loop.
                changes.push(wake_pipe_read_kevent(process_pipe_read));
            }
            if let Some(thread_wake) = thread_wake.as_ref() {
                // Thread-directed signals use a private pipe so siblings cannot
                // drain the target's wake before its kqueue observes it.
                changes.push(wake_pipe_read_kevent(thread_wake.read_fd()));
            }
            if !changes.is_empty() {
                let _ = kq.apply(&changes);
            }
        }
        Self {
            kq,
            process_pipe_read,
            thread_wake,
            wake_pipe_dead: AtomicBool::new(false),
            tid,
            deferred_full_init: false,
        }
    }

    #[cfg(not(target_os = "macos"))]
    pub fn new(tid: crate::thread::ThreadId) -> Self {
        Self {
            process_pipe_read: -1,
            thread_wake: None,
            wake_pipe_dead: AtomicBool::new(false),
            tid,
            deferred_full_init: false,
        }
    }

    pub fn process_only(tid: crate::thread::ThreadId) -> Self {
        Self {
            #[cfg(target_os = "macos")]
            kq: None,
            process_pipe_read: crate::host_signal::pending_pipe_read_fd(),
            thread_wake: None,
            wake_pipe_dead: AtomicBool::new(false),
            tid,
            deferred_full_init: true,
        }
    }

    pub fn ensure_full(&mut self) {
        if self.deferred_full_init {
            *self = Self::new(self.tid);
        }
    }

    fn has_dead_wake_pipe(&self) -> bool {
        self.wake_pipe_dead.load(Ordering::SeqCst)
    }

    fn mark_dead_wake_pipe(&self) {
        self.wake_pipe_dead.store(true, Ordering::SeqCst);
    }

    #[cfg(target_os = "macos")]
    fn drain_process_wake_pipe(&self, kq: &Kqueue) -> crate::host_signal::DrainResult {
        if self.process_pipe_read < 0 {
            return crate::host_signal::DrainResult::Dead;
        }
        let result = drain_wake_pipe_registration(kq, self.process_pipe_read);
        if result == crate::host_signal::DrainResult::Dead {
            self.mark_dead_wake_pipe();
        }
        result
    }

    #[cfg(target_os = "macos")]
    fn drain_thread_wake_pipe(&self, kq: &Kqueue) -> crate::host_signal::DrainResult {
        let Some(thread_wake) = self.thread_wake.as_ref() else {
            return crate::host_signal::DrainResult::Dead;
        };
        let result = drain_wake_pipe_registration(kq, thread_wake.read_fd());
        if result == crate::host_signal::DrainResult::Dead {
            self.mark_dead_wake_pipe();
        }
        result
    }

    /// Test/diagnostic hook: close the per-thread kqueue's fd and invalidate the
    /// wrapper, so the next `kevent` returns EBADF. Models the fork-storm race in
    /// which an internal fd is closed out from under a blocked `wait_proc_exit`.
    /// Returns the fd that was closed (or -1). Not for production use.
    #[doc(hidden)]
    #[cfg(target_os = "macos")]
    pub fn debug_close_kqueue(&mut self) -> RawFd {
        self.kq
            .as_mut()
            .map_or(-1, |kq| kq.debug_close_and_invalidate())
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
        if crate::host_signal::has_unblocked_pending_for(self.tid, block_mask)
            || crate::fork_quiesce::is_quiescing()
        {
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
        let pinned_fds = match PinnedWaitFds::new(fds) {
            Ok(p) => p,
            Err(errno) => {
                crate::probes::io_wait_end(
                    self.tid,
                    wait_result_code(WaitResult::Errno(errno)),
                    fds.len() as i32,
                    fd0,
                    fd1,
                    fds.get(2).map_or(-1, |(fd, _)| *fd),
                );
                return WaitResult::Errno(errno);
            }
        };
        let wait_fds = pinned_fds.as_wait_fds();
        let result;
        #[cfg(target_os = "macos")]
        {
            if !self.has_dead_wake_pipe()
                && let Some(kq) = self.kq.as_ref()
            {
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
        if crate::host_signal::has_unblocked_pending_for(self.tid, block_mask)
            || crate::fork_quiesce::is_quiescing()
        {
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
        let pinned_fds = match PinnedWaitFds::new(fds) {
            Ok(p) => p,
            Err(errno) => {
                crate::probes::io_wait_end(
                    self.tid,
                    wait_result_code(WaitResult::Errno(errno)),
                    fds.len() as i32,
                    fd0,
                    fd1,
                    fds.get(2).map_or(-1, |(fd, _)| *fd),
                );
                return WaitResult::Errno(errno);
            }
        };
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

    /// Block until process `pid` exits, a signal becomes pending, or a fork
    /// quiesce begins. Used by a blocking `waitid(P_PID)`: the child's exit is
    /// observed via the per-thread kqueue's `EVFILT_PROC`/`NOTE_EXIT` (macOS's
    /// native process-lifecycle tracking) so the thread parks in `kevent()` —
    /// interruptible by the self-pipe poke — instead of an uninterruptible
    /// `libc::waitid`. The runtime re-dispatches the waitid on `Ready` to reap.
    #[cfg(target_os = "macos")]
    pub fn wait_proc_exit(&self, pid: i32, block_mask: u64) -> WaitResult {
        if crate::host_signal::has_unblocked_pending_for(self.tid, block_mask)
            || crate::fork_quiesce::is_quiescing()
        {
            return WaitResult::Interrupted;
        }
        // Fork/wait storms commonly reach this point after the child has already
        // become reapable. Peek before arming EVFILT_PROC so the hot path avoids
        // add/delete kqueue bookkeeping for every immediate-exit child.
        if child_status_ready(pid) {
            return WaitResult::Ready;
        }
        // Fast path: park in kevent() on the per-thread kqueue's EVFILT_PROC.
        if !self.has_dead_wake_pipe()
            && let Some(kq) = self.kq.as_ref()
        {
            match self.wait_proc_exit_kqueue(kq, pid, block_mask) {
                ProcExitWait::Done(result) => return result,
                // The kqueue fd was closed out from under us; abandon it and poll
                // the child directly so the guest's wait4 still completes instead
                // of busy-spinning on EBADF forever (the apt fork-storm hang).
                ProcExitWait::KqueueDead => {}
            }
        }
        self.wait_proc_exit_fallback(pid, block_mask)
    }

    /// Park in `kevent()` on the long-lived per-thread kqueue until `pid` exits,
    /// a signal becomes pending, or a fork quiesce begins. Returns `KqueueDead`
    /// (without touching the kqueue further) if `kevent` reports the kqueue fd
    /// itself is invalid — the caller then falls back to a direct poll.
    #[cfg(target_os = "macos")]
    fn wait_proc_exit_kqueue(&self, kq: &Kqueue, pid: i32, block_mask: u64) -> ProcExitWait {
        let mut changes = vec![Kevent::proc_exit(pid)];
        let cap = (1 + self.signal_pipe_count()).max(1);
        let mut events_out: Vec<Kevent> = vec![Kevent::empty(); cap];
        let mut wake_pipe_dead = false;
        let result = loop {
            // Bound the wait even when a signal pipe exists. A freshly forked
            // child can race signal-pump/self-pipe reinitialisation; the kqueue
            // event is still the fast path, but this retry guarantees a pending
            // guest signal is observed instead of losing the wake edge forever.
            let ts = Some(libc::timespec {
                tv_sec: 0,
                tv_nsec: 50_000_000,
            });
            let n = match kq.wait(&changes, &mut events_out, ts.as_ref()) {
                Ok(n) => n,
                Err(e) => {
                    if crate::host_signal::has_unblocked_pending_for(self.tid, block_mask)
                        || crate::fork_quiesce::is_quiescing()
                    {
                        break WaitResult::Interrupted;
                    }
                    // EINTR: a signal raced into kevent — retry. Any other error
                    // (EBADF: the kqueue fd was closed; EINVAL/EFAULT: unusable)
                    // cannot be cured by retrying the same kqueue, so report it
                    // dead and let the caller poll rather than spin.
                    if e == libc::EINTR {
                        changes.clear();
                        continue;
                    }
                    return ProcExitWait::KqueueDead;
                }
            };
            changes.clear(); // registration persists; only add once.
            let mut proc_woke = false;
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
                    // The EVFILT_PROC/NOTE_EXIT event (or an EV_ERROR because the
                    // pid was already gone) — either way the child is now
                    // reapable, so re-dispatch the waitid.
                    proc_woke = true;
                }
            }
            if proc_woke {
                break WaitResult::Ready;
            }
            if process_pipe_woke {
                if self.drain_process_wake_pipe(kq) == crate::host_signal::DrainResult::Dead {
                    wake_pipe_dead = true;
                    break WaitResult::Interrupted;
                }
            }
            if thread_pipe_woke
                && self.drain_thread_wake_pipe(kq) == crate::host_signal::DrainResult::Dead
            {
                wake_pipe_dead = true;
                break WaitResult::Interrupted;
            }
            // Backstop poll (mirrors `wait_proc_exit_fallback`). `EVFILT_PROC`/
            // `NOTE_EXIT` is the fast wake, but it is lost if the child exits in
            // the window between the guest's `wait4` WNOHANG pre-check (child
            // still alive) and our registration of the proc watch: the child is
            // already a zombie when the knote arms, so its exit edge is in the
            // past and may not fire. Re-poll the child directly so a missed edge
            // can never strand the parent. `WNOWAIT` peeks and leaves the zombie
            // for the caller's re-dispatched `wait4` to reap.
            if child_status_ready(pid) {
                break WaitResult::Ready;
            }
            if crate::host_signal::has_unblocked_pending_for(self.tid, block_mask)
                || crate::fork_quiesce::is_quiescing()
            {
                break WaitResult::Interrupted;
            }
        };
        // Drop the one-shot proc watch if it didn't fire (interrupted wait), so
        // it can't accumulate on the long-lived kqueue. ENOENT is fine.
        let zero = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let _ = kq.wait(&[Kevent::proc_exit_delete(pid)], &mut [], Some(&zero));
        if wake_pipe_dead {
            ProcExitWait::KqueueDead
        } else {
            ProcExitWait::Done(result)
        }
    }

    /// Bounded fallback for `wait_proc_exit` when the per-thread kqueue is
    /// unusable (its fd was closed out from under us, or it never existed). Polls
    /// the child's exit with `waitid(WNOHANG | WNOWAIT)` — `WNOWAIT` leaves the
    /// child reapable, so the caller's re-dispatched `waitid` still reaps it —
    /// between 50 ms signal-recheck slices parked on the signal pipes. Returns
    /// `Ready` when the child is reapable, `Interrupted` on a pending signal or
    /// fork quiesce. Not a busy spin: each idle slice sleeps in `poll()`.
    #[cfg(target_os = "macos")]
    fn wait_proc_exit_fallback(&self, pid: i32, block_mask: u64) -> WaitResult {
        loop {
            if crate::host_signal::has_unblocked_pending_for(self.tid, block_mask)
                || crate::fork_quiesce::is_quiescing()
            {
                return WaitResult::Interrupted;
            }
            if child_status_ready(pid) {
                return WaitResult::Ready;
            }
            // Still running: park briefly on the signal pipes (interruptible),
            // then re-poll. The empty fd list means poll_with_signal returns only
            // Interrupted (pending signal) or TimedOut (slice elapsed).
            if let WaitResult::Interrupted =
                self.poll_with_signal(&[], Some(Duration::from_millis(50)), block_mask)
            {
                return WaitResult::Interrupted;
            }
        }
    }

    /// Non-macOS stub: no kqueue, so report interrupted and let the caller
    /// fall back to a bounded retry.
    #[cfg(not(target_os = "macos"))]
    pub fn wait_proc_exit(&self, _pid: i32, _block_mask: u64) -> WaitResult {
        WaitResult::Interrupted
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
                // Bound the wait even when a signal pipe exists. The kqueue
                // event is still the fast path, but a freshly forked child
                // can race signal-pump/self-pipe reinitialisation and lose a
                // wake edge forever (this is the exact bug d97a47a fixed for
                // wait4; ppoll(0,0,NULL,...) — which musl uses for pause() on
                // aarch64 — needs the same 50 ms retry to guarantee a pending
                // guest signal is observed).
                None => Some(libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 50_000_000,
                }),
            };
            let n = kq.wait(&changes, &mut events_out, ts.as_ref());
            changes.clear(); // registrations persist; only re-add once.

            let n = match n {
                Ok(n) => n,
                Err(e) => {
                    if crate::host_signal::has_unblocked_pending_for(self.tid, block_mask)
                        || crate::fork_quiesce::is_quiescing()
                    {
                        break WaitResult::Interrupted;
                    }
                    // EINTR (a signal raced in) — re-check the pending flag and
                    // retry. Any other error means the kqueue fd is unusable
                    // (EBADF: closed out from under us by the fork-storm
                    // internal-fd churn), which retrying can only repeat forever;
                    // abandon it and poll(2) the watched fds directly instead.
                    if e == libc::EINTR {
                        continue;
                    }
                    return self.fallback_poll(fds, timeout, block_mask);
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
                if self.drain_process_wake_pipe(kq) == crate::host_signal::DrainResult::Dead {
                    self.clear_fd_registrations(kq, fds);
                    return self.fallback_poll(fds, remaining_timeout(deadline), block_mask);
                }
            }
            if thread_pipe_woke
                && self.drain_thread_wake_pipe(kq) == crate::host_signal::DrainResult::Dead
            {
                self.clear_fd_registrations(kq, fds);
                return self.fallback_poll(fds, remaining_timeout(deadline), block_mask);
            }
            if crate::host_signal::has_unblocked_pending_for(self.tid, block_mask)
                || crate::fork_quiesce::is_quiescing()
            {
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
        let include_signal_pipes = !self.has_dead_wake_pipe();
        let process_signal_index = if include_signal_pipes && self.process_pipe_read >= 0 {
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
        let thread_signal_index = if include_signal_pipes {
            self.thread_wake.as_ref().map(|thread_wake| {
                let index = pollfds.len();
                pollfds.push(libc::pollfd {
                    fd: thread_wake.read_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                });
                index
            })
        } else {
            None
        };
        loop {
            if crate::host_signal::has_unblocked_pending_for(self.tid, block_mask)
                || crate::fork_quiesce::is_quiescing()
            {
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
                    if crate::host_signal::drain_fd(self.process_pipe_read)
                        == crate::host_signal::DrainResult::Dead
                    {
                        self.mark_dead_wake_pipe();
                        if let Some(index) = process_signal_index
                            && let Some(pfd) = pollfds.get_mut(index)
                        {
                            pfd.fd = -1;
                            pfd.events = 0;
                        }
                        if let Some(index) = thread_signal_index
                            && let Some(pfd) = pollfds.get_mut(index)
                        {
                            pfd.fd = -1;
                            pfd.events = 0;
                        }
                    }
                }
                if thread_signal_index
                    .and_then(|index| pollfds.get(index))
                    .is_some_and(|pfd| pfd.revents != 0)
                    && let Some(thread_wake) = self.thread_wake.as_ref()
                {
                    if thread_wake.drain() == crate::host_signal::DrainResult::Dead {
                        self.mark_dead_wake_pipe();
                        if let Some(index) = process_signal_index
                            && let Some(pfd) = pollfds.get_mut(index)
                        {
                            pfd.fd = -1;
                            pfd.events = 0;
                        }
                        if let Some(index) = thread_signal_index
                            && let Some(pfd) = pollfds.get_mut(index)
                        {
                            pfd.fd = -1;
                            pfd.events = 0;
                        }
                    }
                }
                if crate::host_signal::has_unblocked_pending_for(self.tid, block_mask)
                    || crate::fork_quiesce::is_quiescing()
                {
                    return WaitResult::Interrupted;
                }
            } else if n < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error();
                if errno == Some(libc::EINTR)
                    && (crate::host_signal::has_unblocked_pending_for(self.tid, block_mask)
                        || crate::fork_quiesce::is_quiescing())
                {
                    return WaitResult::Interrupted;
                }
            }
        }
    }

    fn signal_pipe_count(&self) -> usize {
        if self.has_dead_wake_pipe() {
            return 0;
        }
        usize::from(self.process_pipe_read >= 0) + usize::from(self.thread_wake.is_some())
    }
}

fn wait_result_code(result: WaitResult) -> i32 {
    match result {
        WaitResult::Ready => 0,
        WaitResult::TimedOut => 1,
        WaitResult::Interrupted => 2,
        // Trace-only code (io_wait_end USDT); any stable value is fine.
        WaitResult::Errno(_) => 3,
    }
}

#[cfg(target_os = "macos")]
fn duration_to_timespec(d: Duration) -> libc::timespec {
    libc::timespec {
        tv_sec: d.as_secs() as libc::time_t,
        tv_nsec: d.subsec_nanos() as libc::c_long,
    }
}

#[cfg(target_os = "macos")]
fn remaining_timeout(deadline: Option<Instant>) -> Option<Duration> {
    deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn pinned_wait_fd_survives_original_close() {
        let mut fds = [-1, -1];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let pinned = super::PinnedWaitFds::new(&[(fds[0], libc::POLLIN)])
            .expect("dup should succeed in test");
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

    #[test]
    fn pinned_wait_fds_errors_on_bad_fd() {
        // dup() of a closed/invalid fd fails (EBADF) deterministically, no
        // rlimit perturbation. new() must return Err, not park on the raw fd.
        let bad = 100_000; // not an open fd in the test process
        assert!(super::PinnedWaitFds::new(&[(bad, libc::POLLIN)]).is_err());
    }

    /// A wake pipe whose write end is closed (EOF) must not re-fire its
    /// EVFILT_READ forever after the wait loop drains it. Darwin can deliver
    /// EOF again even for an `EV_CLEAR` registration once userspace reads `0`,
    /// so the waiter must delete the read filter and fall back to bounded poll
    /// slices.
    #[cfg(target_os = "macos")]
    #[test]
    fn wake_pipe_at_eof_does_not_refire() {
        use crate::darwin_kqueue::{Kevent, Kqueue};
        let kq = Kqueue::new_internal().expect("kqueue");
        let mut fds = [-1, -1];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (r, w) = (fds[0], fds[1]);
        // Close the write end: the read end is now at permanent EOF (data == 0).
        assert_eq!(unsafe { libc::close(w) }, 0);
        kq.apply(&[super::wake_pipe_read_kevent(r)]).expect("apply");

        let zero = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let mut out = [Kevent::empty(); 4];
        // The EOF edge is delivered once (a watcher must still learn of it).
        let n1 = kq.wait(&[], &mut out, Some(&zero)).expect("wait1");
        assert!(n1 >= 1, "EOF should be delivered at least once; n1={n1}");
        assert_eq!(
            super::drain_wake_pipe_registration(&kq, r),
            crate::host_signal::DrainResult::Dead
        );
        // No new write occurred: a SECOND wait must be quiet after the waiter
        // drains the EOF edge. A refire here models the busy-spin trace:
        // kevent -> read(EOF) -> kevent -> read(EOF) forever.
        let n2 = kq.wait(&[], &mut out, Some(&zero)).expect("wait2");
        assert_eq!(unsafe { libc::close(r) }, 0);
        assert_eq!(
            n2, 0,
            "wake pipe at EOF re-fired EVFILT_READ -> wait_kqueue busy-spins (n1={n1} n2={n2})"
        );
    }
}
