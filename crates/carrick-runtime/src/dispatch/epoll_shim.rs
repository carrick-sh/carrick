//! In-memory epoll readiness-wake registry, split out of dispatch/mod.rs
//! (WS-F3). Tracks live epoll-instance kqueue fds so an in-memory readiness
//! change (eventfd/pipe/timerfd) can wake every epoll_wait blocked on one
//! (the fix for Go's netpollBreak lost-wakeup / high-P netpoller stall).
use super::*;

/// Live epoll-instance kqueue fds, so an in-memory readiness change
/// (eventfd/pipe/timerfd) can wake every `epoll_wait` blocked on one. Go's
/// `netpollBreak` writes an eventfd to wake the poller; that fd isn't host-backed,
/// so without this the blocked io_wait on the instance kqueue never sees it → a
/// lost wakeup → the c>=32 netpoller stall (all Ps idle until the 5s deadline).
static EPOLL_INMEM_KQUEUES: Mutex<Vec<i32>> = Mutex::new(Vec::new());

pub(crate) fn register_epoll_kqueue(fd: i32) {
    EPOLL_INMEM_KQUEUES.lock().push(fd);
}

pub(crate) fn unregister_epoll_kqueue(fd: i32) {
    EPOLL_INMEM_KQUEUES.lock().retain(|&f| f != fd);
}

/// Wake every epoll instance (via its `EVFILT_USER(0)`) so a thread blocked in
/// `epoll_wait` re-checks in-memory fd readiness. Call when an eventfd/pipe/
/// timerfd becomes readable. A coarse broadcast — a spurious wake just makes the
/// poller recompute and find nothing, which is harmless.
pub(crate) fn notify_inmem_epoll() {
    for &fd in EPOLL_INMEM_KQUEUES.lock().iter() {
        let _ = crate::darwin_kqueue::trigger_user(fd, 0);
    }
}
