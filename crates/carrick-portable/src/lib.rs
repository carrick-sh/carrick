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

// ---- extended attributes ----
// Darwin's f*xattr take a trailing `position` (resource-fork offset, always 0
// for the xattrs carrick uses) that Linux lacks; the `flags`/`options` arg also
// shifts position. These wrappers expose the common (Linux-shaped) signature.

/// `fsetxattr` with the portable `(fd, name, value, size, flags)` shape.
///
/// # Safety
/// `name` is a valid C string; `value` is readable for `size` bytes.
#[inline]
pub unsafe fn fsetxattr(
    fd: i32,
    name: *const libc::c_char,
    value: *const libc::c_void,
    size: usize,
    flags: libc::c_int,
) -> libc::c_int {
    #[cfg(target_os = "macos")]
    {
        unsafe { libc::fsetxattr(fd, name, value, size, 0, flags) }
    }
    #[cfg(not(target_os = "macos"))]
    {
        unsafe { libc::fsetxattr(fd, name, value, size, flags) }
    }
}

/// `fgetxattr` with the portable `(fd, name, value, size)` shape.
///
/// # Safety
/// `name` is a valid C string; `value` is writable for `size` bytes.
#[inline]
pub unsafe fn fgetxattr(
    fd: i32,
    name: *const libc::c_char,
    value: *mut libc::c_void,
    size: usize,
) -> isize {
    #[cfg(target_os = "macos")]
    {
        unsafe { libc::fgetxattr(fd, name, value, size, 0, 0) }
    }
    #[cfg(not(target_os = "macos"))]
    {
        unsafe { libc::fgetxattr(fd, name, value, size) }
    }
}

/// `flistxattr` with the portable `(fd, list, size)` shape.
///
/// # Safety
/// `list` is writable for `size` bytes (or null with size 0).
#[inline]
pub unsafe fn flistxattr(fd: i32, list: *mut libc::c_char, size: usize) -> isize {
    #[cfg(target_os = "macos")]
    {
        unsafe { libc::flistxattr(fd, list, size, 0) }
    }
    #[cfg(not(target_os = "macos"))]
    {
        unsafe { libc::flistxattr(fd, list, size) }
    }
}

/// `fremovexattr` with the portable `(fd, name)` shape.
///
/// # Safety
/// `name` is a valid C string.
#[inline]
pub unsafe fn fremovexattr(fd: i32, name: *const libc::c_char) -> libc::c_int {
    #[cfg(target_os = "macos")]
    {
        unsafe { libc::fremovexattr(fd, name, 0) }
    }
    #[cfg(not(target_os = "macos"))]
    {
        unsafe { libc::fremovexattr(fd, name) }
    }
}

/// Zero-copy regular-file → socket transfer. Returns bytes sent, or `-errno`.
/// Darwin: `sendfile(file, sock, off, *len_in_out, hdtr, flags)`. Linux:
/// `sendfile(out_sock, in_file, *off, count)` — note the swapped fd order.
///
/// # Safety
/// `file_fd`/`sock_fd` are live fds owned by the caller.
#[inline]
pub unsafe fn sendfile_to_socket(file_fd: i32, sock_fd: i32, offset: i64, count: usize) -> isize {
    #[cfg(target_os = "macos")]
    {
        let mut len: libc::off_t = count as libc::off_t;
        // Darwin sendfile returns 0 on success (bytes in `len`) or -1 (errno set).
        // Normalize to the Linux shape: bytes on success, -1 (errno set) on error,
        // so callers can recover the errno from the thread-local.
        let rc = unsafe {
            libc::sendfile(
                file_fd,
                sock_fd,
                offset as libc::off_t,
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc == 0 { len as isize } else { rc as isize }
    }
    #[cfg(target_os = "linux")]
    {
        let mut off = offset as libc::off_t;
        unsafe { libc::sendfile(sock_fd, file_fd, &mut off, count) }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (file_fd, sock_fd, offset, count);
        -libc::ENOSYS as isize
    }
}

/// Peer credentials `(pid, uid, gid)` of a connected `AF_UNIX` `host_fd`,
/// best-effort (`0` where unavailable). Linux exposes them in one call via
/// `SO_PEERCRED` -> `struct ucred`; Darwin has no single equivalent, so we read
/// `LOCAL_PEERCRED` (uid + primary gid via `xucred`) and `LOCAL_PEERPID` (pid).
/// Used to synthesize the `SO_PEERCRED`/`SCM_CREDENTIALS` the guest expects.
pub fn peer_ucred(host_fd: i32) -> (u32, u32, u32) {
    #[cfg(target_os = "linux")]
    {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: cred/len are valid out-params for getsockopt on a socket fd.
        let rc = unsafe {
            libc::getsockopt(
                host_fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        };
        if rc == 0 {
            (cred.pid as u32, cred.uid, cred.gid)
        } else {
            (0, 0, 0)
        }
    }
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    {
        let mut xucred: libc::xucred = unsafe { std::mem::zeroed() };
        let mut xlen = std::mem::size_of::<libc::xucred>() as libc::socklen_t;
        // SAFETY: xucred/xlen are valid out-params for getsockopt on a socket fd.
        let (uid, gid) = if unsafe {
            libc::getsockopt(
                host_fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERCRED,
                (&mut xucred as *mut libc::xucred).cast(),
                &mut xlen,
            )
        } == 0
        {
            (
                xucred.cr_uid,
                xucred.cr_groups.first().copied().unwrap_or(0),
            )
        } else {
            (0, 0)
        };
        let mut peer_pid: libc::pid_t = 0;
        let mut plen = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        // SAFETY: peer_pid/plen are valid out-params for getsockopt.
        let pid = if unsafe {
            libc::getsockopt(
                host_fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                (&mut peer_pid as *mut libc::pid_t).cast(),
                &mut plen,
            )
        } == 0
        {
            peer_pid as u32
        } else {
            0
        };
        (pid, uid, gid)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd"
    )))]
    {
        let _ = host_fd;
        (0, 0, 0)
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

// Host `ptrace(2)` request constants (Darwin `PT_*` ↔ Linux `PTRACE_*`). Used
// to drive the *host* ptrace when emulating the guest's ptrace; the request
// type also differs (Darwin `c_int` vs Linux `c_uint`), which the native
// re-export resolves automatically.
port_alias!(PT_TRACE_ME => PT_TRACE_ME, PTRACE_TRACEME);
port_alias!(PT_CONTINUE => PT_CONTINUE, PTRACE_CONT);
port_alias!(PT_KILL => PT_KILL, PTRACE_KILL);
port_alias!(PT_DETACH => PT_DETACH, PTRACE_DETACH);

/// `siginfo_t` field accessors. Darwin exposes `si_pid`/`si_uid`/`si_status` as
/// plain fields; the `libc` crate exposes them as *methods* on Linux (the
/// fields live in an anonymous union). These read-only accessors paper over
/// that so call sites read `carrick_portable::si_pid(&info)` on both.
macro_rules! siginfo_accessor {
    ($name:ident -> $ty:ty) => {
        #[inline]
        pub fn $name(info: &libc::siginfo_t) -> $ty {
            #[cfg(target_os = "macos")]
            {
                info.$name
            }
            #[cfg(not(target_os = "macos"))]
            // SAFETY: these read POSIX-defined members of the siginfo union;
            // libc marks the accessor `unsafe` only because it reads a union.
            {
                unsafe { info.$name() }
            }
        }
    };
}
siginfo_accessor!(si_pid -> libc::pid_t);
siginfo_accessor!(si_uid -> libc::uid_t);
siginfo_accessor!(si_status -> libc::c_int);

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
