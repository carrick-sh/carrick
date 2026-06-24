//! Backend selection for the readiness multiplexer (Part C).
//!
//! Hands the runtime a boxed [`EventMultiplexer`]
//! implementation appropriate for the host platform: kqueue-backed on macOS and
//! FreeBSD/NetBSD (the same `carrick_host_bsd::KqueueMultiplexer`, whose `to_note`/`from_note`
//! helpers already carry FreeBSD cfg gates), epoll-backed on Linux. The dispatch
//! path (`dispatch/net.rs`) drives readiness exclusively through this trait so the
//! backend choice lives in exactly one place.

use carrick_hal::error::OsError;
use carrick_hal::event::EventMultiplexer;
use std::os::fd::RawFd;

/// Fire the user-wake channel on an epoll instance's cached wake fd — the
/// host-specific half of [`crate::dispatch::epoll_shim::notify_inmem_epoll`].
/// The fd is the value `EpollKqueue::wake_fd` caches: the kqueue fd on the
/// BSD/macOS lanes (whose `EVFILT_USER(0)` is pulsed by `kqueue::trigger_user`)
/// or the user-wake `eventfd` on Linux (whose 8-byte counter is written by
/// `trigger_user_eventfd`, making the epoll `poll_fd` readable). Co-located with
/// [`make_event_multiplexer`] so the host event-backend choice lives in exactly
/// one place; the dispatch-layer caller stays host-agnostic.
pub fn trigger_user_wake_fd(wake_fd: RawFd) {
    #[cfg(any(
        feature = "platform-macos",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ))]
    let _ = carrick_host_bsd::kqueue::trigger_user(wake_fd, 0);
    #[cfg(feature = "platform-linux")]
    carrick_host_linux::epoll_mux::trigger_user_eventfd(wake_fd);
    #[cfg(not(any(
        feature = "platform-macos",
        feature = "platform-linux",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    )))]
    let _ = wake_fd;
}

/// Construct the platform readiness multiplexer.
pub fn make_event_multiplexer() -> Result<Box<dyn EventMultiplexer>, OsError> {
    #[cfg(feature = "platform-macos")]
    {
        Ok(Box::new(carrick_host_bsd::KqueueMultiplexer::new()?))
    }
    #[cfg(feature = "platform-linux")]
    {
        Ok(Box::new(carrick_host_linux::EpollMultiplexer::new()?))
    }
    // BSD VMM hosts share the macOS kqueue multiplexer: `carrick_bsd` includes
    // FreeBSD and NetBSD, so the same `KqueueMultiplexer` compiles and runs here.
    // The `platform-*` features are mutually exclusive, so positive predicates
    // suffice (no `not(platform-macos)` disambiguation needed).
    #[cfg(any(feature = "platform-freebsd", feature = "platform-netbsd"))]
    {
        Ok(Box::new(carrick_host_bsd::KqueueMultiplexer::new()?))
    }
    #[cfg(not(any(
        feature = "platform-macos",
        feature = "platform-linux",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    )))]
    {
        Err(OsError::from_raw(libc::ENOSYS))
    }
}
