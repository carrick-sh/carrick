//! Backend selection for the readiness multiplexer (Part C).
//!
//! Hands the runtime a boxed [`EventMultiplexer`](carrick_hal::event::EventMultiplexer)
//! implementation appropriate for the host platform: kqueue-backed on macOS and
//! FreeBSD (the same `carrick_host_bsd::KqueueMultiplexer`, whose `to_note`/`from_note`
//! helpers already carry FreeBSD cfg gates), epoll-backed on Linux. The dispatch
//! path (`dispatch/net.rs`) drives readiness exclusively through this trait so the
//! backend choice lives in exactly one place.

use carrick_hal::error::OsError;
use carrick_hal::event::EventMultiplexer;

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
    // FreeBSD shares the macOS kqueue multiplexer: `carrick_bsd` is gated
    // `cfg(any(macos, freebsd))`, so the same `KqueueMultiplexer` compiles and
    // runs here. Without this arm a platform-freebsd runtime falls through to
    // ENOSYS at multiplexer construction (every guest process dies at startup).
    // The `platform-*` features are mutually exclusive, so positive predicates
    // suffice (no `not(platform-macos)` disambiguation needed).
    #[cfg(feature = "platform-freebsd")]
    {
        Ok(Box::new(carrick_host_bsd::KqueueMultiplexer::new()?))
    }
    #[cfg(not(any(
        feature = "platform-macos",
        feature = "platform-linux",
        feature = "platform-freebsd"
    )))]
    {
        Err(OsError::from_raw(libc::ENOSYS))
    }
}
