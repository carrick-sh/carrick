//! Backend selection for the readiness multiplexer (Part C).
//!
//! Hands the runtime a boxed [`EventMultiplexer`](carrick_hal::event::EventMultiplexer)
//! implementation appropriate for the host platform: kqueue-backed on macOS/BSD,
//! a future epoll-backed multiplexer on Linux. The epoll dispatch path
//! (`dispatch/net.rs`) drives readiness exclusively through this trait so the
//! backend choice lives in exactly one place.

use carrick_hal::error::OsError;
use carrick_hal::event::EventMultiplexer;

/// Construct the platform readiness multiplexer.
pub fn make_event_multiplexer() -> Result<Box<dyn EventMultiplexer>, OsError> {
    #[cfg(feature = "platform-macos")]
    {
        Ok(Box::new(carrick_bsd::KqueueMultiplexer::new()?))
    }
    #[cfg(all(not(feature = "platform-macos"), feature = "platform-linux"))]
    {
        todo!("Linux EpollMultiplexer — Part C Phase 2")
    }
    #[cfg(not(any(feature = "platform-macos", feature = "platform-linux")))]
    {
        Err(OsError::from_raw(libc::ENOSYS))
    }
}
