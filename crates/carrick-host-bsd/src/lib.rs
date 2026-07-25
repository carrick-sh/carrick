//! BSD-family host-primitive implementations of the `carrick-hal` traits.
//!
//! Gated `cfg(carrick_bsd_family)` (emitted by `build.rs` for macOS / FreeBSD /
//! NetBSD / OpenBSD / DragonFly — all the kqueue + BSD-numbered hosts). This
//! crate holds the BSD-family implementations lifted out of `carrick-runtime`:
//! the errno translation, the kqueue multiplexer, and the one BSD `SIGNUM_XLATE`
//! signal-number table (`signum`). A new BSD host
//! is a one-line addition to `build.rs`, not a per-arm `cfg` audit — only the
//! actual kernel-call divergence (`__ulock`/`_umtx_op`/`__futex`) stays a
//! per-host arm, and that is pushed behind `carrick-host`.
#![cfg(carrick_bsd_family)]

pub mod errno;
pub use errno::bsd_to_linux_errno;

pub mod kqueue;
pub use kqueue::{Kevent, Kqueue, duplicate_internal_fd, relocate_internal_fd};
pub mod multiplexer;
pub use multiplexer::KqueueMultiplexer;

/// The one BSD-family `linux <-> host` signal-number translation table (shared
/// by the HVF/macOS and bhyve/FreeBSD backends; previously triplicated).
pub mod signum;

/// The BSD **native (no-VMM) lane's** `HostSignalGlue` — the `ActiveGlue` a
/// FreeBSD/NetBSD build with no VMM crate (i.e. aarch64) resolves to. Empty on
/// macOS, whose native lane runs under the HVF crate's own glue.
pub mod native_glue;
