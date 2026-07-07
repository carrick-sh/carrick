//! In-memory epoll readiness-wake registry, split out of dispatch/mod.rs
//! (WS-F3). Tracks live epoll-instance kqueue fds so an in-memory readiness
//! change (eventfd/pipe/timerfd) can wake every epoll_wait blocked on one
//! (the fix for Go's netpollBreak lost-wakeup / high-P netpoller stall).
use super::*;

pub(crate) type EpollWakeRegistry = std::sync::Arc<Mutex<Vec<i32>>>;

/// Create an epoll wake registry owned by one dispatcher/process state.
pub(crate) fn new_epoll_wake_registry() -> EpollWakeRegistry {
    std::sync::Arc::new(Mutex::new(Vec::new()))
}

/// Live epoll-instance user-wake fds, so an in-memory readiness change
/// (eventfd/pipe/timerfd) can wake every `epoll_wait` blocked on one. Go's
/// `netpollBreak` writes an eventfd to wake the poller; that fd isn't host-backed,
/// so without this the blocked io_wait on the instance kqueue never sees it → a
/// lost wakeup → the c>=32 netpoller stall (all Ps idle until the 5s deadline).
///
/// The fd stored is each instance's [`EpollKqueue::wake_fd`]: the kqueue fd on
/// macOS (EVFILT_USER(0) rides it) or the user-wake `eventfd` on Linux (a
/// separate fd that, written, makes the epoll `poll_fd` readable).
pub(crate) fn register_epoll_kqueue(registry: &EpollWakeRegistry, fd: i32) {
    registry.lock().push(fd);
}

pub(crate) fn unregister_epoll_kqueue(registry: &EpollWakeRegistry, fd: i32) {
    registry.lock().retain(|&f| f != fd);
}

/// Drop the parent process's in-memory epoll wake-fd registry in a fork child.
/// The real epoll/kqueue descriptors are inherited through the fd table, but
/// this registry is process-local bookkeeping. Keeping the parent's wake fd
/// numbers after fork can pulse unrelated descriptors if the child closes and
/// reuses those numbers before any fresh epoll instance registers itself.
pub(crate) fn after_fork_child(registry: &EpollWakeRegistry) {
    registry.lock().clear();
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
pub(crate) fn notify_inmem_epoll(registry: &EpollWakeRegistry) {
    for &fd in registry.lock().iter() {
        crate::event_mux::trigger_user_wake_fd(fd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registered_fds(registry: &EpollWakeRegistry) -> Vec<i32> {
        registry.lock().clone()
    }

    #[test]
    fn fork_child_reset_clears_inherited_wake_registry() {
        let registry = new_epoll_wake_registry();
        register_epoll_kqueue(&registry, 41);
        register_epoll_kqueue(&registry, 42);

        after_fork_child(&registry);

        assert!(
            registered_fds(&registry).is_empty(),
            "fork child must not retain parent epoll wake fds"
        );
    }
}
