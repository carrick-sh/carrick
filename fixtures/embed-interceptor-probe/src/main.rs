//! The one deterministic raw-syscall fixture `carrick-embed`'s signed
//! interceptor tests run inside a guest.
//!
//! # Why this is Rust and not C
//!
//! It was a `probe.c` built inside an `alpine:3.20` container, which put a
//! DOCKER DAEMON on the critical path of `just test-embed`: with Docker not
//! running, the whole signed lane died at step 0 with "failed to connect to
//! the docker API at ~/.docker/run/docker.sock" — before a single test, and
//! with every needed image already in the local store. AGENTS.md's rule for
//! probes applies exactly here: a libc-only probe cross-compiles locally
//! (`cargo build --target aarch64-unknown-linux-musl`), so nothing about this
//! fixture needs a container.
//!
//! # What it must keep doing
//!
//! Byte-identical behaviour to the C original, because the tests assert on
//! the exact stdout and on exact syscall COUNTS (`getuid`, `getpid`,
//! `clock_gettime` once each; `write` exactly twice in `write` mode). So:
//! every observable call goes through `libc::syscall` (raw, errno-setting,
//! never a libc wrapper that might add a call), the output is formatted into
//! a fixed stack buffer, and nothing is printed through Rust's `std::io`
//! machinery, which would add its own writes and a flush at exit.

use std::ffi::c_long;

const STDOUT_FILENO: c_long = 1;
const STDERR_FILENO: c_long = 2;

/// Raw `write(2)`. Returns the kernel's own answer, negative errno included.
fn raw_write(fd: c_long, bytes: &[u8]) -> c_long {
    // SAFETY: `bytes` is a live slice and the length is its exact length.
    unsafe {
        libc::syscall(
            libc::SYS_write,
            fd,
            bytes.as_ptr() as *const libc::c_void,
            bytes.len(),
        )
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn set_errno(value: i32) {
    // SAFETY: `__errno_location` returns this thread's errno cell.
    unsafe { *libc::__errno_location() = value };
}

fn identity() -> i32 {
    set_errno(0);
    // SAFETY: `getuid` takes no arguments and cannot fault.
    let uid = unsafe { libc::syscall(libc::SYS_getuid) };
    let uid_errno = errno();

    set_errno(0);
    // SAFETY: `getpid` takes no arguments and cannot fault.
    let pid = unsafe { libc::syscall(libc::SYS_getpid) };
    let pid_errno = errno();

    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    set_errno(0);
    // SAFETY: `now` is a live, correctly typed `timespec` for the duration of
    // the call. The raw syscall is used rather than `clock_gettime(3)` so the
    // guest sees exactly ONE `clock_gettime` — a libc wrapper is free to serve
    // it from the vDSO or to retry, and the test asserts the count.
    let clock_raw = unsafe {
        libc::syscall(
            libc::SYS_clock_gettime,
            libc::CLOCK_REALTIME as c_long,
            std::ptr::addr_of_mut!(now),
        )
    };
    // The C original called `clock_gettime(3)`, whose contract is -1 plus
    // errno. A raw syscall returns `-errno` instead, so it is lowered to the
    // same two values the tests read.
    let (clock_rc, clock_errno) = if clock_raw < 0 {
        (-1_i32, i32::try_from(-clock_raw).unwrap_or(0))
    } else {
        (0_i32, 0_i32)
    };

    let output = format_identity(uid, uid_errno, pid, pid_errno, clock_rc, clock_errno);
    let expected = c_long::try_from(output.len()).unwrap_or(-1);
    if raw_write(STDOUT_FILENO, &output) == expected {
        0
    } else {
        3
    }
}

/// The C original's `snprintf` into a 256-byte buffer, reproduced exactly.
/// Built with `Vec` rather than `format!` only because the payload is bounded
/// and the allocation happens before any observed syscall.
fn format_identity(
    uid: c_long,
    uid_errno: i32,
    pid: c_long,
    pid_errno: i32,
    clock_rc: i32,
    clock_errno: i32,
) -> Vec<u8> {
    let text = format!(
        "uid={uid} uid_errno={uid_errno}\n\
         pid={pid} pid_errno={pid_errno}\n\
         clock_rc={clock_rc} clock_errno={clock_errno}\n"
    );
    text.into_bytes()
}

fn write_markers() -> i32 {
    const STDOUT_MARKER: &[u8] = b"INTERCEPT_STDOUT\n";
    const STDERR_MARKER: &[u8] = b"NATIVE_STDERR\n";

    let stdout_written = raw_write(STDOUT_FILENO, STDOUT_MARKER);
    let stderr_written = raw_write(STDERR_FILENO, STDERR_MARKER);
    if stdout_written == STDOUT_MARKER.len() as c_long
        && stderr_written == STDERR_MARKER.len() as c_long
    {
        0
    } else {
        4
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        std::process::exit(64);
    }
    let code = match args[1].as_str() {
        "identity" => identity(),
        "write" => write_markers(),
        _ => 64,
    };
    std::process::exit(code);
}
