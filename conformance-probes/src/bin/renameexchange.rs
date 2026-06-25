//! renameat2(RENAME_EXCHANGE) probe. RENAME_EXCHANGE atomically swaps two
//! existing paths (both must exist; no file is created or removed). carrick
//! previously lacked the RENAME_EXCHANGE flag path (it fell through to a plain
//! rename, clobbering the target instead of swapping). This probe pins the swap
//! semantics plus the two error contracts: a missing exchange target → ENOENT,
//! and RENAME_EXCHANGE|RENAME_NOREPLACE (a nonsensical combination) → EINVAL.
//! The harness diffs carrick vs Linux line by line.
//!
//! Deterministic: booleans + the swapped file CONTENTS (fixed strings), never
//! sizes-as-numbers/inodes/times.

use std::ffi::CString;

// renameat2 raw syscall: the libc wrapper hides the flags arg on some musl
// bindings, so issue it directly. SYS_renameat2 is per-arch in the libc crate.
const RENAME_NOREPLACE: libc::c_uint = 1;
const RENAME_EXCHANGE: libc::c_uint = 2;

fn renameat2(oldp: &str, newp: &str, flags: libc::c_uint) -> libc::c_long {
    let (Ok(o), Ok(n)) = (CString::new(oldp), CString::new(newp)) else {
        return -1;
    };
    unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            o.as_ptr(),
            libc::AT_FDCWD,
            n.as_ptr(),
            flags,
        )
    }
}

fn main() {
    // Empty run-elf rootfs: create /tmp first (Docker's exists → EEXIST,
    // ignored).
    mkdir("/tmp", 0o777);

    // /tmp/a holds "AAAA" (4 bytes), /tmp/b holds "BB" (2 bytes) — distinct
    // contents AND sizes so a swap is unambiguous.
    if !write_file("/tmp/a", b"AAAA") || !write_file("/tmp/b", b"BB") {
        println!("seed=ERR:{}", errno());
        return;
    }

    // Atomic exchange of two existing files → 0.
    let r = renameat2("/tmp/a", "/tmp/b", RENAME_EXCHANGE);
    println!("exchange_ok={}", r == 0);

    // After the swap, /tmp/a holds the old /tmp/b content ("BB") and vice versa.
    println!("a_now={}", read_file("/tmp/a"));
    println!("b_now={}", read_file("/tmp/b"));

    // RENAME_EXCHANGE with a non-existent target → -1 / ENOENT (both operands
    // must exist). /tmp/missing was never created.
    let rm = renameat2("/tmp/a", "/tmp/missing", RENAME_EXCHANGE);
    println!("missing_enoent={}", rm == -1 && errno() == libc::ENOENT);

    // RENAME_EXCHANGE|RENAME_NOREPLACE is an illegal flag combination →
    // -1 / EINVAL (validated before any filesystem work).
    let rn = renameat2("/tmp/a", "/tmp/b", RENAME_EXCHANGE | RENAME_NOREPLACE);
    println!("noreplace_einval={}", rn == -1 && errno() == libc::EINVAL);
}

/// Truncate-create `path` and write `data`; returns true on success.
fn write_file(path: &str, data: &[u8]) -> bool {
    let Ok(c) = CString::new(path) else {
        return false;
    };
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        )
    };
    if fd < 0 {
        return false;
    }
    let n = unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, data.len()) };
    unsafe { libc::close(fd) };
    n == data.len() as isize
}

/// Read `path` and return its content as a String, or "ERR:<errno>" on failure.
/// Bounded read into a fixed buffer (contents here are tiny and fixed).
fn read_file(path: &str) -> String {
    let Ok(c) = CString::new(path) else {
        return "ERR:cstring".to_string();
    };
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return format!("ERR:{}", errno());
    }
    let mut buf = [0u8; 64];
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    unsafe { libc::close(fd) };
    if n < 0 {
        return format!("ERR:{}", errno());
    }
    String::from_utf8_lossy(&buf[..n as usize]).to_string()
}

/// mkdir(2); failures (e.g. EEXIST) are ignored.
fn mkdir(path: &str, mode: libc::mode_t) {
    if let Ok(c) = CString::new(path) {
        unsafe {
            libc::mkdir(c.as_ptr(), mode);
        }
    }
}

/// Current errno value.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}
