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

/// Current thread errno. Darwin/FreeBSD use `__error()`, NetBSD `__errno()`,
/// Linux `__errno_location()`.
#[inline]
pub fn errno() -> i32 {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    // SAFETY: `__error()` returns a valid per-thread pointer for the caller.
    {
        unsafe { *libc::__error() }
    }
    #[cfg(target_os = "netbsd")]
    // SAFETY: `__errno()` returns a valid per-thread pointer for the caller.
    {
        unsafe { *libc::__errno() }
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
        target_os = "netbsd",
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
    #[cfg(target_os = "netbsd")]
    // SAFETY: `__errno()` returns a valid per-thread pointer for the caller.
    unsafe {
        *libc::__errno() = value;
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
        target_os = "netbsd",
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

/// On FreeBSD, parse a Linux-style xattr name (`"user.foo"`, `"system.foo"`, …)
/// into a `(namespace, attr_name)` pair for the `extattr_*_fd` API.
/// Unmapped prefixes fall back to `EXTATTR_NAMESPACE_USER`.
#[cfg(target_os = "freebsd")]
fn freebsd_xattr_ns(name: &std::ffi::CStr) -> (libc::c_int, std::ffi::CString) {
    let bytes = name.to_bytes();
    for (prefix, ns) in [
        (&b"user."[..], libc::EXTATTR_NAMESPACE_USER as libc::c_int),
        (
            &b"system."[..],
            libc::EXTATTR_NAMESPACE_SYSTEM as libc::c_int,
        ),
        (
            &b"trusted."[..],
            libc::EXTATTR_NAMESPACE_SYSTEM as libc::c_int,
        ),
        (
            &b"security."[..],
            libc::EXTATTR_NAMESPACE_SYSTEM as libc::c_int,
        ),
    ] {
        if let Some(rest) = bytes.strip_prefix(prefix) {
            return (ns, std::ffi::CString::new(rest).unwrap_or_default());
        }
    }
    (
        libc::EXTATTR_NAMESPACE_USER as libc::c_int,
        std::ffi::CString::new(bytes).unwrap_or_default(),
    )
}

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
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::fsetxattr(fd, name, value, size, flags) }
    }
    #[cfg(target_os = "freebsd")]
    {
        // extattr_set_fd has no flags parameter; xattr flags are ignored on FreeBSD.
        let _ = flags;
        let (ns, attr) = freebsd_xattr_ns(unsafe { std::ffi::CStr::from_ptr(name) });
        let rc = unsafe { libc::extattr_set_fd(fd, ns, attr.as_ptr(), value, size) };
        if rc >= 0 { 0 } else { -1 }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "freebsd")))]
    {
        let _ = (fd, name, value, size, flags);
        -libc::ENOSYS
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
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::fgetxattr(fd, name, value, size) }
    }
    #[cfg(target_os = "freebsd")]
    {
        let (ns, attr) = freebsd_xattr_ns(unsafe { std::ffi::CStr::from_ptr(name) });
        unsafe { libc::extattr_get_fd(fd, ns, attr.as_ptr(), value, size) }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "freebsd")))]
    {
        let _ = (fd, name, value, size);
        -libc::ENOSYS as isize
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
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::flistxattr(fd, list, size) }
    }
    #[cfg(target_os = "freebsd")]
    {
        // FreeBSD extattr_list_fd returns per-namespace `[u8 len][name bytes]` entries
        // (no NUL terminator on each entry). Merge USER+SYSTEM namespaces and re-emit
        // Linux-style NUL-terminated `"prefix.name\0"` entries.
        let mut out: Vec<u8> = Vec::new();
        for (ns, prefix) in [
            (libc::EXTATTR_NAMESPACE_USER as libc::c_int, &b"user."[..]),
            (
                libc::EXTATTR_NAMESPACE_SYSTEM as libc::c_int,
                &b"system."[..],
            ),
        ] {
            let need = unsafe { libc::extattr_list_fd(fd, ns, std::ptr::null_mut(), 0) };
            if need <= 0 {
                continue;
            }
            let mut raw = vec![0u8; need as usize];
            let got = unsafe { libc::extattr_list_fd(fd, ns, raw.as_mut_ptr().cast(), raw.len()) };
            if got <= 0 {
                continue;
            }
            let raw = &raw[..got as usize];
            let mut i = 0usize;
            while i < raw.len() {
                let nlen = raw[i] as usize;
                i += 1;
                if i + nlen > raw.len() {
                    break;
                }
                out.extend_from_slice(prefix);
                out.extend_from_slice(&raw[i..i + nlen]);
                out.push(0);
                i += nlen;
            }
        }
        if size == 0 {
            return out.len() as isize;
        }
        if out.len() > size {
            set_errno(libc::ERANGE);
            return -1;
        }
        unsafe { std::ptr::copy_nonoverlapping(out.as_ptr(), list.cast::<u8>(), out.len()) };
        out.len() as isize
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "freebsd")))]
    {
        let _ = (fd, list, size);
        -libc::ENOSYS as isize
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
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::fremovexattr(fd, name) }
    }
    #[cfg(target_os = "freebsd")]
    {
        let (ns, attr) = freebsd_xattr_ns(unsafe { std::ffi::CStr::from_ptr(name) });
        let rc = unsafe { libc::extattr_delete_fd(fd, ns, attr.as_ptr()) };
        if rc >= 0 { 0 } else { -1 }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "freebsd")))]
    {
        let _ = (fd, name);
        -libc::ENOSYS
    }
}

// ---- path-based extended attributes ----
// Linux exposes path-based `{l,}{get,set}xattr`; macOS folds no-follow into a
// `XATTR_NOFOLLOW` option on `{get,set}xattr`; FreeBSD uses `extattr_*_file`
// (follow) / `extattr_*_link` (no-follow). These wrappers expose the common
// Linux-shaped signature so call sites stay cfg-free.

/// Linux xattr flags, portable. FreeBSD `extattr` has no create/replace flags;
/// the FreeBSD shims accept and ignore them (matching the fd-based shims).
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const XATTR_CREATE: libc::c_int = libc::XATTR_CREATE;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub const XATTR_REPLACE: libc::c_int = libc::XATTR_REPLACE;
#[cfg(target_os = "linux")]
pub const XATTR_CREATE: libc::c_int = libc::XATTR_CREATE;
#[cfg(target_os = "linux")]
pub const XATTR_REPLACE: libc::c_int = libc::XATTR_REPLACE;
#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "linux")))]
pub const XATTR_CREATE: libc::c_int = 1;
#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "linux")))]
pub const XATTR_REPLACE: libc::c_int = 2;

/// Path-based `getxattr` (follow symlinks), portable `(path, name, value, size)`.
///
/// # Safety
/// `path`/`name` are valid C strings; `value` is writable for `size` bytes.
#[inline]
pub unsafe fn getxattr(
    path: *const libc::c_char,
    name: *const libc::c_char,
    value: *mut libc::c_void,
    size: usize,
) -> isize {
    #[cfg(target_os = "macos")]
    {
        unsafe { libc::getxattr(path, name, value, size, 0, 0) }
    }
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::getxattr(path, name, value, size) }
    }
    #[cfg(target_os = "freebsd")]
    {
        let (ns, attr) = freebsd_xattr_ns(unsafe { std::ffi::CStr::from_ptr(name) });
        unsafe { libc::extattr_get_file(path, ns, attr.as_ptr(), value, size) }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "freebsd")))]
    {
        let _ = (path, name, value, size);
        -libc::ENOSYS as isize
    }
}

/// Path-based `lgetxattr` (no-follow), portable `(path, name, value, size)`.
///
/// # Safety
/// As [`getxattr`].
#[inline]
pub unsafe fn lgetxattr(
    path: *const libc::c_char,
    name: *const libc::c_char,
    value: *mut libc::c_void,
    size: usize,
) -> isize {
    #[cfg(target_os = "macos")]
    {
        unsafe { libc::getxattr(path, name, value, size, 0, libc::XATTR_NOFOLLOW) }
    }
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::lgetxattr(path, name, value, size) }
    }
    #[cfg(target_os = "freebsd")]
    {
        let (ns, attr) = freebsd_xattr_ns(unsafe { std::ffi::CStr::from_ptr(name) });
        unsafe { libc::extattr_get_link(path, ns, attr.as_ptr(), value, size) }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "freebsd")))]
    {
        let _ = (path, name, value, size);
        -libc::ENOSYS as isize
    }
}

/// Path-based `setxattr` (follow symlinks), portable `(path, name, value, size, flags)`.
///
/// # Safety
/// `path`/`name` are valid C strings; `value` is readable for `size` bytes.
#[inline]
pub unsafe fn setxattr(
    path: *const libc::c_char,
    name: *const libc::c_char,
    value: *const libc::c_void,
    size: usize,
    flags: libc::c_int,
) -> libc::c_int {
    #[cfg(target_os = "macos")]
    {
        unsafe { libc::setxattr(path, name, value, size, 0, flags) }
    }
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::setxattr(path, name, value, size, flags) }
    }
    #[cfg(target_os = "freebsd")]
    {
        // extattr_set_file has no flags parameter; xattr flags are ignored on FreeBSD.
        let _ = flags;
        let (ns, attr) = freebsd_xattr_ns(unsafe { std::ffi::CStr::from_ptr(name) });
        let rc = unsafe { libc::extattr_set_file(path, ns, attr.as_ptr(), value, size) };
        if rc >= 0 { 0 } else { -1 }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "freebsd")))]
    {
        let _ = (path, name, value, size, flags);
        -libc::ENOSYS
    }
}

/// Path-based `lsetxattr` (no-follow), portable `(path, name, value, size, flags)`.
///
/// # Safety
/// As [`setxattr`].
#[inline]
pub unsafe fn lsetxattr(
    path: *const libc::c_char,
    name: *const libc::c_char,
    value: *const libc::c_void,
    size: usize,
    flags: libc::c_int,
) -> libc::c_int {
    #[cfg(target_os = "macos")]
    {
        unsafe { libc::setxattr(path, name, value, size, 0, flags | libc::XATTR_NOFOLLOW) }
    }
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::lsetxattr(path, name, value, size, flags) }
    }
    #[cfg(target_os = "freebsd")]
    {
        let _ = flags;
        let (ns, attr) = freebsd_xattr_ns(unsafe { std::ffi::CStr::from_ptr(name) });
        let rc = unsafe { libc::extattr_set_link(path, ns, attr.as_ptr(), value, size) };
        if rc >= 0 { 0 } else { -1 }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "freebsd")))]
    {
        let _ = (path, name, value, size, flags);
        -libc::ENOSYS
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
    #[cfg(target_os = "freebsd")]
    {
        let mut sbytes: libc::off_t = 0;
        // FreeBSD sendfile(2): sendfile(fd, s, offset, nbytes, hdtr, *sbytes, flags)
        // fd=source file, s=socket — note the arg order is opposite to Linux.
        // Returns 0 on success with bytes written in *sbytes; -1 on error (errno set).
        // SAFETY: file_fd/sock_fd are live caller-owned fds; sbytes is a valid out-param.
        let rc = unsafe {
            libc::sendfile(
                file_fd,
                sock_fd,
                offset as libc::off_t,
                count,
                std::ptr::null_mut(),
                &mut sbytes,
                0,
            )
        };
        if rc == 0 {
            sbytes as isize
        } else {
            rc as isize
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "freebsd")))]
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
    #[cfg(any(target_os = "macos", target_os = "ios"))]
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
    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: uid/gid are valid out-params for getpeereid on a socket fd.
        // FreeBSD/NetBSD have no peer-pid API; report pid as 0.
        let rc = unsafe { libc::getpeereid(host_fd, &mut uid, &mut gid) };
        if rc == 0 {
            (0, uid as u32, gid as u32)
        } else {
            (0, 0, 0)
        }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd"
    )))]
    {
        let _ = host_fd;
        (0, 0, 0)
    }
}

/// Re-export a constant that has a real (possibly differently-named) equivalent
/// on every platform. Two-way form: `port_alias!(NAME => bsd_name, linux_name)`
/// uses `bsd_name` on the BSD family (macOS, FreeBSD, NetBSD — for constants all
/// three share under the same libc name) and `linux_name` everywhere else.
/// Three-way form: `port_alias!(NAME => mac_name, freebsd_name, linux_name)` for
/// constants where macOS and FreeBSD use different libc names; here NetBSD takes
/// the `linux_name` arm by default — when NetBSD needs a *different* name, add an
/// explicit `netbsd =` clause: `port_alias!(NAME => mac, freebsd, linux, netbsd = nb)`.
///
/// NetBSD is a BSD, so it shares most constants with the `bsd_name` position
/// (e.g. `PT_*`); the explicit-`netbsd` form covers the deltas (e.g. NetBSD has
/// no `CLOCK_*_RAW`, so `CLOCK_UPTIME_RAW` maps to `CLOCK_MONOTONIC`).
macro_rules! port_alias {
    // BSD family (macOS + FreeBSD + NetBSD) share the same name; Linux differs.
    ($name:ident => $bsd:ident, $other:ident) => {
        #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd"))]
        pub use libc::$bsd as $name;
        #[cfg(not(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd")))]
        pub use libc::$other as $name;
    };
    // macOS / FreeBSD / (Linux + NetBSD) each take a distinct name.
    ($name:ident => $mac:ident, $bsd:ident, $linux:ident) => {
        #[cfg(target_os = "freebsd")]
        pub use libc::$bsd as $name;
        #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
        pub use libc::$linux as $name;
        #[cfg(target_os = "macos")]
        pub use libc::$mac as $name;
    };
    // As the three-way form, but with an explicit NetBSD name distinct from all
    // three (NetBSD does not take the Linux arm).
    ($name:ident => $mac:ident, $bsd:ident, $linux:ident, netbsd = $nb:ident) => {
        #[cfg(target_os = "freebsd")]
        pub use libc::$bsd as $name;
        #[cfg(not(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd")))]
        pub use libc::$linux as $name;
        #[cfg(target_os = "macos")]
        pub use libc::$mac as $name;
        #[cfg(target_os = "netbsd")]
        pub use libc::$nb as $name;
    };
}

// Darwin name -> Linux equivalent. Re-exported as the Darwin name so call sites
// keep reading naturally; the value is the platform-native libc constant.
//
// CLOCK_UPTIME_RAW: macOS=CLOCK_UPTIME_RAW, FreeBSD=CLOCK_UPTIME_PRECISE
//   (both measure unhalted wall time; PRECISE is the highest-res FreeBSD clock);
//   NetBSD has no CLOCK_*_RAW/UPTIME clock, so map to CLOCK_MONOTONIC.
// TCP_KEEPALIVE: macOS name; FreeBSD/Linux/NetBSD all use TCP_KEEPIDLE (NetBSD
//   has no TCP_KEEPALIVE, so it correctly takes the `linux` = TCP_KEEPIDLE arm).
port_alias!(CLOCK_UPTIME_RAW => CLOCK_UPTIME_RAW, CLOCK_UPTIME_PRECISE, CLOCK_MONOTONIC_RAW, netbsd = CLOCK_MONOTONIC);
port_alias!(TCP_KEEPALIVE => TCP_KEEPALIVE, TCP_KEEPIDLE, TCP_KEEPIDLE);
port_alias!(AF_LINK => AF_LINK, AF_PACKET);

// TCP_NOPUSH: macOS/FreeBSD name; Linux uses TCP_CORK. NetBSD's libc bindings
// (libc 0.2.x) do NOT export TCP_NOPUSH even though <netinet/tcp.h> defines it,
// so supply the header value directly.
//   NetBSD /usr/include/netinet/tcp.h: `#define TCP_NOPUSH 4`
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub use libc::TCP_NOPUSH;
#[cfg(target_os = "netbsd")]
pub const TCP_NOPUSH: libc::c_int = 4;
#[cfg(not(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd")))]
pub use libc::TCP_CORK as TCP_NOPUSH;

// Host `ptrace(2)` request constants (Darwin `PT_*` ↔ Linux `PTRACE_*`). NetBSD
// is a BSD and shares the `PT_*` names (libc `netbsdlike` module), so it takes
// the `bsd` arm of the two-way form. Used to drive the *host* ptrace when
// emulating the guest's ptrace; the request type also differs (Darwin `c_int`
// vs Linux `c_uint`), which the native re-export resolves automatically.
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
/// On macOS and FreeBSD the real `libc` constant is re-exported; on Linux a
/// typed placeholder carrying the canonical 4.4BSD numeric value is used.
macro_rules! port_kqueue {
    ($ty:ty: $($name:ident = $val:expr),+ $(,)?) => {
        $(
            #[cfg(any(target_os = "macos", target_os = "freebsd"))]
            pub use libc::$name;
            #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
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

#[cfg(all(test, target_os = "freebsd"))]
mod freebsd_const_tests {
    #[test]
    fn port_kqueue_uses_real_freebsd_values() {
        assert_eq!(super::EV_CLEAR, libc::EV_CLEAR);
        assert_eq!(super::EVFILT_READ, libc::EVFILT_READ);
        assert_eq!(super::NOTE_WRITE, libc::NOTE_WRITE);
    }

    #[test]
    fn siginfo_accessor_reads_fields_on_freebsd() {
        let info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(super::si_pid(&info), 0);
        assert_eq!(super::si_uid(&info), 0);
        assert_eq!(super::si_status(&info), 0);
    }

    #[test]
    fn sendfile_to_socket_transfers_on_freebsd() {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        let mut tmp = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open("/tmp/carrick_sendfile_test.bin")
            .unwrap();
        tmp.write_all(b"hello-sendfile").unwrap();
        tmp.flush().unwrap();
        let mut sv = [0 as libc::c_int; 2];
        assert_eq!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) },
            0
        );
        let n = unsafe { super::sendfile_to_socket(tmp.as_raw_fd(), sv[0], 0, 14) };
        assert!(n > 0, "sendfile_to_socket returned {n}, expected > 0");
        let mut buf = [0u8; 14];
        let got = unsafe { libc::read(sv[1], buf.as_mut_ptr() as *mut libc::c_void, 14) };
        assert!(got > 0, "socket read returned {got}");
        unsafe {
            libc::close(sv[0]);
            libc::close(sv[1]);
        }
    }
}

#[cfg(all(test, target_os = "freebsd"))]
mod freebsd_xattr_tests {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;

    #[test]
    fn user_namespace_xattr_round_trip() {
        let f = std::fs::File::create("/tmp/carrick_xattr_test.bin").unwrap();
        let fd = f.as_raw_fd();
        let name = CString::new("user.carrick.test").unwrap();
        let val = b"42";
        let rc = unsafe { super::fsetxattr(fd, name.as_ptr(), val.as_ptr().cast(), val.len(), 0) };
        assert!(rc >= 0, "fsetxattr failed: {rc}");
        let mut buf = [0u8; 16];
        let got =
            unsafe { super::fgetxattr(fd, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        assert_eq!(got, 2, "fgetxattr len");
        assert_eq!(&buf[..2], b"42");
        let mut list = [0u8; 256];
        let ln = unsafe { super::flistxattr(fd, list.as_mut_ptr().cast(), list.len()) };
        assert!(ln > 0, "flistxattr len {ln}");
        assert!(
            list[..ln as usize]
                .split(|&b| b == 0)
                .any(|e| e == b"user.carrick.test"),
            "list missing entry: {:?}",
            &list[..ln as usize]
        );
        let rm = unsafe { super::fremovexattr(fd, name.as_ptr()) };
        assert!(rm >= 0, "fremovexattr failed: {rm}");
    }

    #[test]
    fn path_namespace_xattr_round_trip() {
        let path = "/tmp/carrick_path_xattr_test.bin";
        std::fs::write(path, b"hi").unwrap();
        let cpath = CString::new(path).unwrap();
        let name = CString::new("user.carrick.ptest").unwrap();
        let val = 0x1122_3344u32.to_le_bytes();
        let rc = unsafe {
            super::setxattr(
                cpath.as_ptr(),
                name.as_ptr(),
                val.as_ptr().cast(),
                val.len(),
                0,
            )
        };
        assert_eq!(rc, 0, "setxattr failed: errno {}", super::errno());
        let mut out = [0u8; 4];
        let n = unsafe {
            super::getxattr(
                cpath.as_ptr(),
                name.as_ptr(),
                out.as_mut_ptr().cast(),
                out.len(),
            )
        };
        assert_eq!(n, 4, "getxattr len");
        assert_eq!(out, val);
        // no-follow variant on a regular (non-symlink) file behaves identically.
        let ln = unsafe {
            super::lsetxattr(
                cpath.as_ptr(),
                name.as_ptr(),
                val.as_ptr().cast(),
                val.len(),
                0,
            )
        };
        assert_eq!(ln, 0, "lsetxattr failed: errno {}", super::errno());
    }
}
