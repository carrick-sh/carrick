//! In-memory epoll readiness-wake registry, split out of dispatch/mod.rs
//! (WS-F3). Tracks live epoll-instance kqueue fds so an in-memory readiness
//! change (eventfd/pipe/timerfd) can wake every epoll_wait blocked on one
//! (the fix for Go's netpollBreak lost-wakeup / high-P netpoller stall).
use super::*;

/// Live epoll-instance user-wake fds, so an in-memory readiness change
/// (eventfd/pipe/timerfd) can wake every `epoll_wait` blocked on one. Go's
/// `netpollBreak` writes an eventfd to wake the poller; that fd isn't host-backed,
/// so without this the blocked io_wait on the instance kqueue never sees it → a
/// lost wakeup → the c>=32 netpoller stall (all Ps idle until the 5s deadline).
///
/// The fd stored is each instance's [`EpollKqueue::wake_fd`]: the kqueue fd on
/// macOS (EVFILT_USER(0) rides it) or the user-wake `eventfd` on Linux (a
/// separate fd that, written, makes the epoll `poll_fd` readable).
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
///
/// The registry holds each instance's `wake_fd` (cached by `EpollKqueue`). On
/// macOS that is the kqueue fd, whose `register_user(0)` armed the
/// `EVFILT_USER(0)` channel; firing it is exactly what
/// `KqueueMultiplexer::trigger_user` does, so we drive the same underlying
/// `carrick_host_bsd::kqueue::trigger_user` on it. On Linux that is the user-wake
/// `eventfd`; writing its 8-byte counter makes the epoll `poll_fd` readable and
/// pops the parked waiter (reaching the instance's mux without threading a
/// handle through the registry).
pub(crate) fn notify_inmem_epoll() {
    for &fd in EPOLL_INMEM_KQUEUES.lock().iter() {
        #[cfg(any(feature = "platform-macos", feature = "platform-freebsd"))]
        let _ = carrick_host_bsd::kqueue::trigger_user(fd, 0);
        #[cfg(feature = "platform-linux")]
        carrick_linux::epoll_mux::trigger_user_eventfd(fd);
        #[cfg(not(any(
            feature = "platform-macos",
            feature = "platform-linux",
            feature = "platform-freebsd"
        )))]
        let _ = fd;
    }
}
