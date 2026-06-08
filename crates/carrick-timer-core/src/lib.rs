//! Platform-NEUTRAL interval/POSIX timer-slot bookkeeping + guest-CPU-due math,
//! shared by every backend. Delivery (kqueue EVFILT_TIMER vs the wall-clock
//! fallback thread) is the backend's concern; this crate owns the slot state,
//! `cpu_timer_decision`, and the shared fallback-thread timing loop body
//! (`run_fallback`). The thread spawn and the actual fire action (publish a
//! signal + kick) stay per-backend.
//!
//! The two timer families live in submodules ([`itimer`] for `setitimer`'s
//! REAL/VIRTUAL/PROF interval timers, [`posix`] for the `timer_create` family)
//! because both expose an `arm`/`clear`; a backend re-exports each into its own
//! `itimer` / `posix_timer` wrapper module via `pub use ...::itimer::*` /
//! `pub use ...::posix::*`.

pub mod itimer;
pub mod posix;
