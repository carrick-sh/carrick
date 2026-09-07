//! Carrick kernel wait set and readiness publication.
//!
//! Provides the Carrick-owned [`WaitSet`] and [`WaitQueue`] primitives for `ppoll`,
//! `poll`, `select`, and `pselect6`. Host kqueues/descriptors are wake sources
//! only, never the readiness authority.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};

use crate::dispatch::fd_table::{HostFdRef, make_readiness_pipe};

/// An enrolled waiter's reference in a [`WaitQueue`].
///
/// When dropped, this automatically unregisters the waiter from the target queue.
#[derive(Debug)]
pub struct WaitEnrollment {
    token: u64,
    queue: Weak<WaitQueueInner>,
}

impl WaitEnrollment {
    /// Disarm / unregister immediately rather than waiting for drop.
    pub fn unregister(self) {
        drop(self);
    }
}

impl Drop for WaitEnrollment {
    fn drop(&mut self) {
        if let Some(queue) = self.queue.upgrade() {
            let mut waiters = queue.waiters.lock();
            waiters.remove(&self.token);
        }
    }
}

#[derive(Debug, Default)]
struct WaitQueueInner {
    waiters: Mutex<BTreeMap<u64, Weak<WaitSetInner>>>,
    next_token: AtomicU64,
}

/// A wait queue embedded in any Carrick-owned kernel object (pipe, eventfd, timerfd, etc.).
///
/// Waiters enroll interest via [`WaitQueue::enroll`]. When the object's readiness changes,
/// [`WaitQueue::wake_all`] notifies all active waiters.
#[derive(Debug, Clone)]
pub struct WaitQueue {
    inner: Arc<WaitQueueInner>,
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl WaitQueue {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(WaitQueueInner {
                waiters: Mutex::new(BTreeMap::new()),
                next_token: AtomicU64::new(1),
            }),
        }
    }

    /// Enroll a waiter with this wait queue.
    /// Returns an RAII [`WaitEnrollment`]. Dropping the enrollment unregisters the waiter.
    pub fn enroll(&self, wait_set: &WaitSet) -> WaitEnrollment {
        let token = self.inner.next_token.fetch_add(1, Ordering::Relaxed);
        let mut waiters = self.inner.waiters.lock();
        waiters.insert(token, Arc::downgrade(&wait_set.inner));
        WaitEnrollment {
            token,
            queue: Arc::downgrade(&self.inner),
        }
    }

    /// Wake all active waiters enrolled in this queue.
    pub fn wake_all(&self) {
        let mut waiters = self.inner.waiters.lock();
        waiters.retain(|_, weak| {
            if let Some(waiter) = weak.upgrade() {
                waiter.wake();
                true
            } else {
                false // prune dead weak references
            }
        });
    }

    /// Return the count of active waiters (primarily for unit tests).
    pub fn waiter_count(&self) -> usize {
        let mut waiters = self.inner.waiters.lock();
        waiters.retain(|_, weak| weak.strong_count() > 0);
        waiters.len()
    }
}

/// Outcome of a [`WaitSet::wait`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitSetOutcome {
    Woken,
    Timeout,
    Interrupted,
}

#[derive(Debug)]
pub struct WaitSetInner {
    notified: AtomicBool,
    lock: Mutex<()>,
    condvar: Condvar,
    wake_pipe: Option<(HostFdRef, HostFdRef)>,
}

impl WaitSetInner {
    pub fn wake(&self) {
        self.notified.store(true, Ordering::SeqCst);
        {
            let _guard = self.lock.lock();
            self.condvar.notify_all();
        }
        if let Some((_, write_fd)) = &self.wake_pipe {
            let _ = unsafe { libc::write(write_fd.raw(), [1u8].as_ptr() as *const _, 1) };
        }
    }
}

/// A kernel wait set representing a thread waiting on a collection of descriptors.
#[derive(Debug, Clone)]
pub struct WaitSet {
    inner: Arc<WaitSetInner>,
}

impl Default for WaitSet {
    fn default() -> Self {
        Self::new()
    }
}

impl WaitSet {
    /// Create a pure in-memory wait set.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(WaitSetInner {
                notified: AtomicBool::new(false),
                lock: Mutex::new(()),
                condvar: Condvar::new(),
                wake_pipe: None,
            }),
        }
    }

    /// Create a wait set equipped with a host wake pipe for multiplexing host descriptors.
    pub fn with_wake_pipe() -> Self {
        let wake_pipe = make_readiness_pipe();
        Self {
            inner: Arc::new(WaitSetInner {
                notified: AtomicBool::new(false),
                lock: Mutex::new(()),
                condvar: Condvar::new(),
                wake_pipe,
            }),
        }
    }

    /// Wake this wait set immediately.
    pub fn wake(&self) {
        self.inner.wake();
    }

    /// Enroll this wait set with a [`WaitQueue`].
    pub fn enroll(&self, queue: &WaitQueue) -> WaitEnrollment {
        queue.enroll(self)
    }

    /// Wait for a notification, timeout, or signal interruption.
    ///
    /// - If `host_fds` is provided, waits on host descriptors concurrently via `libc::poll`.
    /// - Closes the lost-wake race window by checking whether a wake occurred prior to sleeping.
    /// - Arithmetic uses monotonic time to prevent drift and never counts slices.
    pub fn wait(
        &self,
        host_fds: &[(i32, i16)],
        timeout: Option<Duration>,
        is_interrupted: impl Fn() -> bool,
    ) -> WaitSetOutcome {
        if is_interrupted() {
            return WaitSetOutcome::Interrupted;
        }

        // Check if already notified before sleeping (closes race window!)
        if self.inner.notified.swap(false, Ordering::SeqCst) {
            self.drain_wake_pipe();
            return WaitSetOutcome::Woken;
        }

        if host_fds.is_empty() && self.inner.wake_pipe.is_none() {
            // Pure in-memory condvar path
            let mut guard = self.inner.lock.lock();
            match timeout {
                None => {
                    while !self.inner.notified.load(Ordering::SeqCst) {
                        if is_interrupted() {
                            return WaitSetOutcome::Interrupted;
                        }
                        self.inner.condvar.wait(&mut guard);
                    }
                    self.inner.notified.store(false, Ordering::SeqCst);
                    WaitSetOutcome::Woken
                }
                Some(duration) => {
                    let deadline = Instant::now() + duration;
                    loop {
                        if is_interrupted() {
                            return WaitSetOutcome::Interrupted;
                        }
                        if self.inner.notified.swap(false, Ordering::SeqCst) {
                            return WaitSetOutcome::Woken;
                        }
                        let now = Instant::now();
                        if now >= deadline {
                            return WaitSetOutcome::Timeout;
                        }
                        let remaining = deadline - now;
                        let result = self.inner.condvar.wait_for(&mut guard, remaining);
                        if self.inner.notified.swap(false, Ordering::SeqCst) {
                            return WaitSetOutcome::Woken;
                        }
                        if result.timed_out() || Instant::now() >= deadline {
                            return WaitSetOutcome::Timeout;
                        }
                    }
                }
            }
        } else {
            self.wait_host_poll(host_fds, timeout, is_interrupted)
        }
    }

    fn wait_host_poll(
        &self,
        host_fds: &[(i32, i16)],
        timeout: Option<Duration>,
        is_interrupted: impl Fn() -> bool,
    ) -> WaitSetOutcome {
        let wake_read_fd = self.inner.wake_pipe.as_ref().map(|(r, _)| r.raw());
        let mut pollfds: Vec<libc::pollfd> = host_fds
            .iter()
            .map(|(fd, events)| libc::pollfd {
                fd: *fd,
                events: *events,
                revents: 0,
            })
            .collect();
        if let Some(rfd) = wake_read_fd {
            pollfds.push(libc::pollfd {
                fd: rfd,
                events: libc::POLLIN,
                revents: 0,
            });
        }

        let start = Instant::now();
        loop {
            if is_interrupted() {
                return WaitSetOutcome::Interrupted;
            }
            if self.inner.notified.swap(false, Ordering::SeqCst) {
                self.drain_wake_pipe();
                return WaitSetOutcome::Woken;
            }

            let timeout_ms = match timeout {
                None => -1,
                Some(dur) => {
                    let elapsed = start.elapsed();
                    if elapsed >= dur {
                        return WaitSetOutcome::Timeout;
                    }
                    let remaining = dur - elapsed;
                    i32::try_from(remaining.as_millis().max(1)).unwrap_or(i32::MAX)
                }
            };

            for p in &mut pollfds {
                p.revents = 0;
            }

            let rc = unsafe {
                libc::poll(
                    pollfds.as_mut_ptr(),
                    pollfds.len() as libc::nfds_t,
                    timeout_ms,
                )
            };

            if rc > 0 {
                if let Some(rfd) = wake_read_fd {
                    if let Some(wp) = pollfds.iter().find(|p| p.fd == rfd) {
                        if wp.revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0 {
                            self.drain_wake_pipe();
                        }
                    }
                }
                self.inner.notified.store(false, Ordering::SeqCst);
                return WaitSetOutcome::Woken;
            } else if rc == 0 {
                return WaitSetOutcome::Timeout;
            } else {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    if is_interrupted() {
                        return WaitSetOutcome::Interrupted;
                    }
                    // Spurious host signal, loop and re-evaluate.
                } else {
                    return WaitSetOutcome::Woken;
                }
            }
        }
    }

    fn drain_wake_pipe(&self) {
        if let Some((read_fd, _)) = &self.inner.wake_pipe {
            let mut buf = [0u8; 64];
            while unsafe { libc::read(read_fd.raw(), buf.as_mut_ptr() as *mut _, buf.len()) } > 0 {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn enrollment_drop_unregisters() {
        let queue = WaitQueue::new();
        let wait_set = WaitSet::new();
        let enrollment = queue.enroll(&wait_set);
        assert_eq!(queue.waiter_count(), 1);
        drop(enrollment);
        assert_eq!(queue.waiter_count(), 0);
    }

    #[test]
    fn lost_wake_ready_before_sleep_does_not_hang() {
        let queue = WaitQueue::new();
        let wait_set = WaitSet::new();
        let _enrollment = queue.enroll(&wait_set);
        // Wake queue BEFORE waiting
        queue.wake_all();
        // Wait must return Woken immediately without blocking
        let outcome = wait_set.wait(&[], Some(Duration::from_secs(5)), || false);
        assert_eq!(outcome, WaitSetOutcome::Woken);
    }

    #[test]
    fn deadline_arithmetic() {
        let wait_set = WaitSet::new();
        let t0 = Instant::now();
        let outcome = wait_set.wait(&[], Some(Duration::from_millis(30)), || false);
        let elapsed = t0.elapsed();
        assert_eq!(outcome, WaitSetOutcome::Timeout);
        assert!(
            elapsed >= Duration::from_millis(28) && elapsed <= Duration::from_millis(45),
            "expected ~30ms, got {:?}",
            elapsed
        );
    }

    #[test]
    fn wake_wakes_waiter() {
        let queue = WaitQueue::new();
        let wait_set = WaitSet::new();
        let _enrollment = queue.enroll(&wait_set);

        let ws_clone = wait_set.clone();
        let waiter_handle =
            thread::spawn(move || ws_clone.wait(&[], Some(Duration::from_secs(5)), || false));

        thread::sleep(Duration::from_millis(20));
        queue.wake_all();

        let outcome = waiter_handle.join().expect("join waiter");
        assert_eq!(outcome, WaitSetOutcome::Woken);
    }

    #[test]
    fn wake_pipe_host_poll_integration() {
        let wait_set = WaitSet::with_wake_pipe();
        let mut fds = [-1i32; 2];
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0);

        let ws_clone = wait_set.clone();
        let host_rd = fds[0];
        let host_wr = fds[1];

        let waiter = thread::spawn(move || {
            ws_clone.wait(
                &[(host_rd, libc::POLLIN)],
                Some(Duration::from_secs(5)),
                || false,
            )
        });

        thread::sleep(Duration::from_millis(20));
        let n = unsafe { libc::write(host_wr, [1u8].as_ptr() as *const _, 1) };
        assert_eq!(n, 1);

        let outcome = waiter.join().expect("join waiter");
        assert_eq!(outcome, WaitSetOutcome::Woken);

        unsafe {
            libc::close(host_rd);
            libc::close(host_wr);
        }
    }
}
