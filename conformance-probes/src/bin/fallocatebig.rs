//! fallocate(2) range-overflow probe. Linux validates offset+len before
//! touching the file: if the requested range would exceed the maximum file
//! size (offset+len overflows the signed 64-bit byte count), fallocate fails
//! with EFBIG and the file is untouched. carrick previously computed the end
//! offset without the overflow check and either succeeded or faulted on the
//! wrap. This probe pins the EFBIG contract and a normal allocation as the
//! control. The harness diffs carrick vs Linux line by line.
//!
//! Deterministic: two booleans only (never sizes/addresses/times).

use std::ffi::CString;

fn main() {
    // Empty run-elf rootfs: create /tmp first (Docker's exists → EEXIST,
    // ignored).
    mkdir("/tmp", 0o777);

    let path = "/tmp/falloc";
    let Ok(c) = CString::new(path) else {
        println!("cstring=ERR");
        return;
    };
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        )
    };
    if fd < 0 {
        println!("open=ERR:{}", errno());
        return;
    }

    // offset + len overflows i64 (off_t): (i64::MAX - 4096) + 8192 wraps past
    // i64::MAX → Linux rejects with -1 / EFBIG before any allocation.
    let off: libc::off_t = i64::MAX - 4096;
    let len: libc::off_t = 8192;
    let r1 = unsafe { libc::fallocate(fd, 0, off, len) };
    println!("overflow_efbig={}", r1 == -1 && errno() == libc::EFBIG);

    // Control: a normal in-range allocation (mode 0, offset 0, len 4096) → 0.
    let r2 = unsafe { libc::fallocate(fd, 0, 0, 4096) };
    println!("normal_ok={}", r2 == 0);

    unsafe { libc::close(fd) };
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
