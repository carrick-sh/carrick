//! fstatat(2) flag-validation probe. The flags argument to newfstatat accepts
//! only a small set of bits (AT_EMPTY_PATH, AT_NO_AUTOMOUNT, AT_SYMLINK_NOFOLLOW);
//! any other bit is rejected with EINVAL *before* the stat is attempted.
//! carrick previously ignored unknown flag bits and stat()'d anyway, so an
//! invalid-flags call succeeded where Linux returns -1/EINVAL. This probe pins
//! both halves: garbage flags → EINVAL, flags==0 on an existing file → success.
//! The harness diffs carrick vs Linux line by line.
//!
//! Deterministic: two booleans only (never sizes/inodes/times).

use std::ffi::CString;

fn main() {
    // The run-elf rootfs is empty; create /tmp first (Docker's already exists →
    // mkdir EEXIST, ignored).
    mkdir("/tmp", 0o777);

    let path = "/tmp/p";
    if !seed_file(path) {
        println!("seed=ERR:{}", errno());
        return;
    }

    let Ok(c) = CString::new(path) else {
        println!("cstring=ERR");
        return;
    };

    // Invalid flag bits (9999 contains bits outside the AT_* whitelist) →
    // -1 / EINVAL, regardless of whether the path exists.
    let mut st1: libc::stat = unsafe { std::mem::zeroed() };
    let r1 = unsafe { libc::fstatat(libc::AT_FDCWD, c.as_ptr(), &mut st1, 9999) };
    println!("badflags_einval={}", r1 == -1 && errno() == libc::EINVAL);

    // flags == 0 on the existing regular file → success (rc 0), reporting a
    // regular-file type so a "succeeded but stat'd garbage" bug is also caught.
    let mut st2: libc::stat = unsafe { std::mem::zeroed() };
    let r2 = unsafe { libc::fstatat(libc::AT_FDCWD, c.as_ptr(), &mut st2, 0) };
    let is_reg = (st2.st_mode & libc::S_IFMT) == libc::S_IFREG;
    println!("goodflags_ok={}", r2 == 0 && is_reg);
}

/// Create `path` as an empty regular file; returns true on success.
fn seed_file(path: &str) -> bool {
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
    unsafe { libc::close(fd) };
    true
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
