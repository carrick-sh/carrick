//! Socket-syscall probe. Exercises socketpair/socket/bind/listen/connect/
//! accept/getsockname/setsockopt/getsockopt across several address families
//! and prints one labelled line per observation. The conformance harness runs
//! this identical static binary under carrick and real Linux and diffs line by
//! line — a divergent line names the exact failing syscall.
//!
//! Deterministic only: no fd numbers, ports, addresses, pids, or timestamps.
//! Fallible calls are reported as `=ERR:<errno>`. Where a family may legally
//! differ (AF_INET6, AF_NETLINK) the errno is printed verbatim so the diff
//! documents the carrick-vs-Linux gap rather than masking it.

use std::ffi::CString;
use std::mem;

const SOCK_PATH_BIND: &str = "/tmp/net_bind.sock";
const SOCK_PATH_LISTEN: &str = "/tmp/net_listen.sock";

fn main() {
    socketpair_roundtrip();
    socket_inet();
    socket_inet6();
    socket_netlink();
    unix_bind_getsockname();
    unix_loopback();
    so_reuseaddr_roundtrip();
    so_type_unix();
}

/// socketpair(AF_UNIX, SOCK_STREAM): write "hi" into one end, read from the
/// other; print the recovered bytes and overall success.
fn socketpair_roundtrip() {
    let mut sv = [0i32; 2];
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
    if rc != 0 {
        println!("socketpair=ERR:{}", errno());
        return;
    }
    let (a, b) = (sv[0], sv[1]);
    let msg = b"hi";
    let w = unsafe { libc::write(a, msg.as_ptr() as *const _, msg.len()) };
    let mut buf = [0u8; 8];
    let n = unsafe { libc::read(b, buf.as_mut_ptr() as *mut _, buf.len()) };
    println!("socketpair_bytes={}", show(&buf[..n.max(0) as usize]));
    println!("socketpair_ok={}", rc == 0 && w == 2 && n == 2);
    unsafe {
        libc::close(a);
        libc::close(b);
    }
}

/// socket(AF_INET, SOCK_STREAM, 0): report whether a valid (>=0) fd came back.
fn socket_inet() {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        println!("socket_inet=ERR:{}", errno());
    } else {
        println!("socket_inet_ok={}", fd >= 0);
        unsafe { libc::close(fd) };
    }
}

/// socket(AF_INET6, SOCK_STREAM, 0): print success-boolean or the errno
/// (AF_INET6 may be EAFNOSUPPORT under carrick).
fn socket_inet6() {
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        println!("socket_inet6=ERR:{}", errno());
    } else {
        println!("socket_inet6_ok={}", fd >= 0);
        unsafe { libc::close(fd) };
    }
}

/// socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE): Linux succeeds, carrick may
/// EAFNOSUPPORT — print the outcome so the diff documents the gap.
fn socket_netlink() {
    const NETLINK_ROUTE: i32 = 0;
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };
    if fd < 0 {
        println!("socket_netlink=ERR:{}", errno());
    } else {
        println!("socket_netlink_ok={}", fd >= 0);
        unsafe { libc::close(fd) };
    }
}

/// bind an AF_UNIX socket to a fixed /tmp path, getsockname, and report whether
/// the family returned is AF_UNIX.
fn unix_bind_getsockname() {
    unlink(SOCK_PATH_BIND);
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        println!("unix_bind=ERR:{}", errno());
        return;
    }
    let addr = unix_addr(SOCK_PATH_BIND);
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        println!("unix_bind=ERR:{}", errno());
        unsafe { libc::close(fd) };
        unlink(SOCK_PATH_BIND);
        return;
    }
    let mut got: libc::sockaddr_un = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    let grc = unsafe {
        libc::getsockname(fd, &mut got as *mut _ as *mut libc::sockaddr, &mut len)
    };
    if grc != 0 {
        println!("unix_getsockname=ERR:{}", errno());
    } else {
        println!(
            "unix_getsockname_is_unix={}",
            got.sun_family as i32 == libc::AF_UNIX
        );
    }
    unsafe { libc::close(fd) };
    unlink(SOCK_PATH_BIND);
}

/// AF_UNIX stream loopback in a single process via a nonblocking listener:
/// bind+listen, connect a second socket, accept, send "ping", recv it back.
fn unix_loopback() {
    unlink(SOCK_PATH_LISTEN);
    let srv = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if srv < 0 {
        println!("unix_loopback=ERR:{}", errno());
        return;
    }
    let addr = unix_addr(SOCK_PATH_LISTEN);
    let addr_len = mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
    let brc = unsafe {
        libc::bind(srv, &addr as *const _ as *const libc::sockaddr, addr_len)
    };
    if brc != 0 {
        println!("unix_loopback=ERR:{}", errno());
        unsafe { libc::close(srv) };
        unlink(SOCK_PATH_LISTEN);
        return;
    }
    let lrc = unsafe { libc::listen(srv, 1) };
    println!("unix_listen_rc={}", lrc);

    // Make the listening socket nonblocking so accept() does not wedge the
    // single-threaded process before connect() runs.
    let fl = unsafe { libc::fcntl(srv, libc::F_GETFL) };
    unsafe { libc::fcntl(srv, libc::F_SETFL, fl | libc::O_NONBLOCK) };

    let cli = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if cli < 0 {
        println!("unix_connect=ERR:{}", errno());
        unsafe { libc::close(srv) };
        unlink(SOCK_PATH_LISTEN);
        return;
    }
    let crc = unsafe {
        libc::connect(cli, &addr as *const _ as *const libc::sockaddr, addr_len)
    };
    println!("unix_connect_ok={}", crc == 0);

    // accept() may need a couple of tries under nonblocking semantics.
    let mut accepted = -1i32;
    for _ in 0..1000 {
        let a = unsafe { libc::accept(srv, std::ptr::null_mut(), std::ptr::null_mut()) };
        if a >= 0 {
            accepted = a;
            break;
        }
        let e = errno();
        if e != libc::EAGAIN && e != libc::EWOULDBLOCK {
            break;
        }
    }
    if accepted < 0 {
        println!("unix_accept=ERR:{}", errno());
        unsafe {
            libc::close(cli);
            libc::close(srv);
        }
        unlink(SOCK_PATH_LISTEN);
        return;
    }

    let msg = b"ping";
    unsafe { libc::write(cli, msg.as_ptr() as *const _, msg.len()) };
    let mut buf = [0u8; 8];
    let n = unsafe { libc::read(accepted, buf.as_mut_ptr() as *mut _, buf.len()) };
    println!("unix_loopback_bytes={}", show(&buf[..n.max(0) as usize]));

    unsafe {
        libc::close(accepted);
        libc::close(cli);
        libc::close(srv);
    }
    unlink(SOCK_PATH_LISTEN);
}

/// setsockopt(SO_REUSEADDR=1) then getsockopt(SO_REUSEADDR) on an AF_INET
/// socket; print the value read back (normalized to 0/1).
fn so_reuseaddr_roundtrip() {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        println!("so_reuseaddr=ERR:{}", errno());
        return;
    }
    let one: libc::c_int = 1;
    let src = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if src != 0 {
        println!("so_reuseaddr=ERR:{}", errno());
        unsafe { libc::close(fd) };
        return;
    }
    let mut val: libc::c_int = 0;
    let mut len = mem::size_of::<libc::c_int>() as libc::socklen_t;
    let grc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &mut val as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if grc != 0 {
        println!("so_reuseaddr=ERR:{}", errno());
    } else {
        println!("so_reuseaddr_value={}", (val != 0) as i32);
    }
    unsafe { libc::close(fd) };
}

/// getsockopt(SO_TYPE) on a fresh AF_UNIX stream socket; print whether it
/// reports SOCK_STREAM.
fn so_type_unix() {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        println!("so_type=ERR:{}", errno());
        return;
    }
    let mut val: libc::c_int = -1;
    let mut len = mem::size_of::<libc::c_int>() as libc::socklen_t;
    let grc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut val as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if grc != 0 {
        println!("so_type=ERR:{}", errno());
    } else {
        println!("so_type_is_stream={}", val == libc::SOCK_STREAM);
    }
    unsafe { libc::close(fd) };
}

/// Build a sockaddr_un for a filesystem-path AF_UNIX socket.
fn unix_addr(path: &str) -> libc::sockaddr_un {
    let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let bytes = path.as_bytes();
    // Leave room for the trailing NUL; path is a fixed short literal.
    let cap = addr.sun_path.len() - 1;
    let n = bytes.len().min(cap);
    for i in 0..n {
        addr.sun_path[i] = bytes[i] as libc::c_char;
    }
    addr
}

/// Remove a path, ignoring errors (best-effort pre-bind cleanup).
fn unlink(path: &str) {
    if let Ok(c) = CString::new(path) {
        unsafe { libc::unlink(c.as_ptr()) };
    }
}

/// Current errno value.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

/// Render bytes as a deterministic single-line token: newlines -> '|', other
/// non-printable bytes -> \xHH, printable ASCII verbatim.
fn show(bytes: &[u8]) -> String {
    let mut s = String::new();
    for &b in bytes {
        match b {
            b'\n' => s.push('|'),
            0x20..=0x7e => s.push(b as char),
            _ => s.push_str(&format!("\\x{:02x}", b)),
        }
    }
    s
}
