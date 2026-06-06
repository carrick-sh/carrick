//! `carrick-portable` — a thin per-OS portability shim for the raw `libc`
//! symbols that differ (or are absent) across carrick's host platforms.
//!
//! carrick's runtime was written against macOS/Darwin `libc`. Many call sites
//! use BSD-only constants (`EV_*`/`NOTE_*` kqueue flags, `TCP_NOPUSH`, …), the
//! BSD errno accessor (`*libc::__error()`), or BSD-named equivalents of Linux
//! constants (`CLOCK_UPTIME_RAW`, `AF_LINK`). This crate re-exports each under a
//! single stable name resolved per `cfg(target_os)`, so the runtime can write
//! `carrick_portable::EV_ADD` once instead of cfg-gating every call site.
//!
//! Three flavors:
//!   * **alias** — a real equivalent exists on the other OS (e.g. Darwin
//!     `CLOCK_UPTIME_RAW` ↔ Linux `CLOCK_MONOTONIC_RAW`); re-exported natively.
//!   * **stub** — no equivalent (kqueue is BSD-only); on Linux these are typed
//!     placeholder values so macOS-shaped event-loop code COMPILES. They are
//!     **not functional on Linux** — the Linux event loop uses epoll via the
//!     HAL `EventMultiplexer` (full-Linux-backend spec, Phase C). Anything that
//!     reaches a stub at runtime on Linux is a bug to be fixed by that migration.
//!   * **fn** — an accessor that differs (`errno()`).
//!
//! A semgrep rule (`.semgrep/portability.yaml`) forbids new direct `libc::<X>`
//! uses for the symbols below, so the port doesn't regress.

/// Portable `termios` flag word. Darwin `tcflag_t` is `c_ulong` (u64); Linux's
/// is `c_uint` (u32). Use this for `c_iflag`/`c_oflag`/`c_cflag`/`c_lflag` bit
/// constants so the bitwise math matches the live `termios` fields on each OS.
pub type TcFlag = libc::tcflag_t;

/// Current thread errno. Darwin/BSD use `__error()`, Linux `__errno_location()`.
#[inline]
pub fn errno() -> i32 {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    // SAFETY: `__error()` returns a valid per-thread pointer for the caller.
    {
        unsafe { *libc::__error() }
    }
    #[cfg(target_os = "linux")]
    // SAFETY: `__errno_location()` returns a valid per-thread pointer.
    {
        unsafe { *libc::__errno_location() }
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "linux"
    )))]
    {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }
}

/// Set the current thread errno (inverse of [`errno`]). Used where carrick
/// synthesizes a host errno before mapping it to a Linux errno.
#[inline]
pub fn set_errno(value: i32) {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    // SAFETY: `__error()` returns a valid per-thread pointer for the caller.
    unsafe {
        *libc::__error() = value;
    }
    #[cfg(target_os = "linux")]
    // SAFETY: `__errno_location()` returns a valid per-thread pointer.
    unsafe {
        *libc::__errno_location() = value;
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "linux"
    )))]
    {
        let _ = value;
    }
}

/// Re-export a constant that has a real (possibly differently-named) equivalent
/// on non-macOS: `port_alias!(PORTNAME => macos_libc_name, other_libc_name)`.
macro_rules! port_alias {
    ($name:ident => $mac:ident, $other:ident) => {
        #[cfg(target_os = "macos")]
        pub use libc::$mac as $name;
        #[cfg(not(target_os = "macos"))]
        pub use libc::$other as $name;
    };
}

// Darwin name -> Linux equivalent. Re-exported as the Darwin name so call sites
// keep reading naturally; the value is the platform-native libc constant.
port_alias!(CLOCK_UPTIME_RAW => CLOCK_UPTIME_RAW, CLOCK_MONOTONIC_RAW);
port_alias!(TCP_NOPUSH => TCP_NOPUSH, TCP_CORK);
port_alias!(TCP_KEEPALIVE => TCP_KEEPALIVE, TCP_KEEPIDLE);
port_alias!(AF_LINK => AF_LINK, AF_PACKET);

/// kqueue flag/filter/fflag constants. BSD-only; on Linux these are typed
/// placeholders (see the module doc) carrying the canonical BSD numeric value.
macro_rules! port_kqueue {
    ($ty:ty: $($name:ident = $val:expr),+ $(,)?) => {
        $(
            #[cfg(target_os = "macos")]
            pub use libc::$name;
            #[cfg(not(target_os = "macos"))]
            pub const $name: $ty = $val;
        )+
    };
}

// kevent.flags (EV_*) are u16, kevent.filter (EVFILT_*) i16, kevent.fflags
// (NOTE_*) u32. Linux placeholder values are the canonical 4.4BSD numbers.
port_kqueue!(u16:
    EV_ADD = 0x0001,
    EV_DELETE = 0x0002,
    EV_ENABLE = 0x0004,
    EV_ONESHOT = 0x0010,
    EV_CLEAR = 0x0020,
    EV_ERROR = 0x4000,
    EV_EOF = 0x8000,
);
port_kqueue!(i16:
    EVFILT_READ = -1,
    EVFILT_WRITE = -2,
);
port_kqueue!(u32:
    NOTE_DELETE = 0x0000_0001,
    NOTE_WRITE = 0x0000_0002,
    NOTE_EXTEND = 0x0000_0004,
    NOTE_ATTRIB = 0x0000_0008,
    NOTE_RENAME = 0x0000_0020,
);
