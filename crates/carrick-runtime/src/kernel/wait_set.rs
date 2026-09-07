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

/// A persistent wake pipe owned by an executor host thread.
///
/// Allocated once per host thread (via thread-local storage) and reused across syscalls,
/// avoiding any per-syscall host file descriptor allocation.
#[derive(Debug)]
pub struct ExecutorWakePipe {
    read_fd: HostFdRef,
    write_fd: HostFdRef,
}

impl ExecutorWakePipe {
    /// Create a new executor wake pipe with non-blocking, cloexec descriptors.
    pub fn new() -> Option<Self> {
        make_readiness_pipe().map(|(read_fd, write_fd)| Self { read_fd, write_fd })
    }

    /// The host read descriptor to include in `libc::poll`.
    pub fn read_fd(&self) -> i32 {
        self.read_fd.raw()
    }

    /// The host write descriptor used to wake a waiting thread.
    pub fn write_fd(&self) -> i32 {
        self.write_fd.raw()
    }

    /// Wake any thread blocked on this pipe by writing a single byte.
    pub fn wake(&self) {
        let byte = 1u8;
        loop {
            let rc = unsafe {
                libc::write(
                    self.write_fd.raw(),
                    &byte as *const _ as *const libc::c_void,
                    1,
                )
            };
            if rc >= 0 {
                break;
            }
            let err = std::io::Error::last_os_error().raw_os_error();
            if err == Some(libc::EINTR) {
                continue;
            }
            // EAGAIN / EWOULDBLOCK: pipe is full, reader will wake regardless.
            break;
        }
    }

    /// Drain all pending bytes from the pipe so it does not report readiness immediately.
    pub fn drain(&self) {
        let mut buf = [0u8; 128];
        loop {
            let rc = unsafe {
                libc::read(
                    self.read_fd.raw(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if rc > 0 {
                continue;
            }
            if rc < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break;
        }
    }
}

thread_local! {
    static CURRENT_EXECUTOR_WAKE_PIPE: Option<Arc<ExecutorWakePipe>> = ExecutorWakePipe::new().map(Arc::new);
}

/// Retrieve or initialize the thread-local [`ExecutorWakePipe`] for the calling host thread.
pub fn current_executor_wake_pipe() -> Option<Arc<ExecutorWakePipe>> {
    CURRENT_EXECUTOR_WAKE_PIPE.with(|cell| cell.clone())
}

#[derive(Debug)]
pub struct WaitSetInner {
    notified: AtomicBool,
    lock: Mutex<()>,
    condvar: Condvar,
    wake_pipe: Option<Arc<ExecutorWakePipe>>,
}

impl WaitSetInner {
    pub fn wake(&self) {
        self.notified.store(true, Ordering::SeqCst);
        {
            let _guard = self.lock.lock();
            self.condvar.notify_all();
        }
        if let Some(pipe) = &self.wake_pipe {
            pipe.wake();
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

    /// Create a wait set equipped with an explicit executor wake pipe.
    pub fn with_executor_pipe(pipe: Option<Arc<ExecutorWakePipe>>) -> Self {
        if let Some(p) = &pipe {
            p.drain();
        }
        Self {
            inner: Arc::new(WaitSetInner {
                notified: AtomicBool::new(false),
                lock: Mutex::new(()),
                condvar: Condvar::new(),
                wake_pipe: pipe,
            }),
        }
    }

    /// Create a wait set equipped with the calling thread's cached [`ExecutorWakePipe`].
    pub fn for_current_executor() -> Self {
        Self::with_executor_pipe(current_executor_wake_pipe())
    }

    /// Legacy / compatibility constructor: aliases [`Self::for_current_executor`].
    pub fn with_wake_pipe() -> Self {
        Self::for_current_executor()
    }

    /// Wake this wait set immediately.
    pub fn wake(&self) {
        self.inner.wake();
    }

    /// Enroll this wait set with a [`WaitQueue`].
    pub fn enroll(&self, queue: &WaitQueue) -> WaitEnrollment {
        queue.enroll(self)
    }

    /// Enroll a task's wake notifications with this wait set.
    /// When the task is woken (e.g. by a signal), this wait set is notified.
    pub fn enroll_task(
        &self,
        task: &crate::kernel::Task,
    ) -> crate::kernel::objects::TaskWakeSubscription {
        let ws = self.clone();
        loop {
            let observed = task.wake_generation();
            let callback: std::sync::Arc<dyn Fn(u64) + Send + Sync + 'static> = {
                let ws = ws.clone();
                std::sync::Arc::new(move |_| {
                    ws.wake();
                })
            };
            match task.subscribe_wake(observed, callback) {
                crate::kernel::objects::TaskWakeEnrollment::Ready(_) => {
                    self.wake();
                }
                crate::kernel::objects::TaskWakeEnrollment::Subscribed(sub) => {
                    return sub;
                }
            }
        }
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
            if is_interrupted() {
                return WaitSetOutcome::Interrupted;
            }
            return WaitSetOutcome::Woken;
        }

        let outcome = if host_fds.is_empty() && self.inner.wake_pipe.is_none() {
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
                    if is_interrupted() {
                        WaitSetOutcome::Interrupted
                    } else {
                        WaitSetOutcome::Woken
                    }
                }
                Some(duration) => {
                    let deadline = Instant::now() + duration;
                    loop {
                        if is_interrupted() {
                            break WaitSetOutcome::Interrupted;
                        }
                        if self.inner.notified.swap(false, Ordering::SeqCst) {
                            if is_interrupted() {
                                break WaitSetOutcome::Interrupted;
                            }
                            break WaitSetOutcome::Woken;
                        }
                        let now = Instant::now();
                        if now >= deadline {
                            break WaitSetOutcome::Timeout;
                        }
                        let remaining = deadline - now;
                        let result = self.inner.condvar.wait_for(&mut guard, remaining);
                        if self.inner.notified.swap(false, Ordering::SeqCst) {
                            if is_interrupted() {
                                break WaitSetOutcome::Interrupted;
                            }
                            break WaitSetOutcome::Woken;
                        }
                        if result.timed_out() || Instant::now() >= deadline {
                            break WaitSetOutcome::Timeout;
                        }
                    }
                }
            }
        } else {
            self.wait_host_poll(host_fds, timeout, is_interrupted)
        };
        self.drain_wake_pipe();
        outcome
    }

    fn wait_host_poll(
        &self,
        host_fds: &[(i32, i16)],
        timeout: Option<Duration>,
        is_interrupted: impl Fn() -> bool,
    ) -> WaitSetOutcome {
        let wake_read_fd = self.inner.wake_pipe.as_ref().map(|p| p.read_fd());
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
                if is_interrupted() {
                    return WaitSetOutcome::Interrupted;
                }
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
                            if is_interrupted() {
                                self.inner.notified.store(false, Ordering::SeqCst);
                                return WaitSetOutcome::Interrupted;
                            }
                        }
                    }
                }
                self.inner.notified.store(false, Ordering::SeqCst);
                if is_interrupted() {
                    return WaitSetOutcome::Interrupted;
                }
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
        if let Some(pipe) = &self.inner.wake_pipe {
            pipe.drain();
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
