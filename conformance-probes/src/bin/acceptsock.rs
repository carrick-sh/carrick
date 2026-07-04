//! Socket accept edge case from LTP accept03.
//!
//! The probe pins the Linux contract that accept(2) on an O_PATH fd fails
//! EBADF, not ENOTSOCK.
//!
//! Output is deterministic booleans only.

use conformance_probes::report;
use std::ffi::CString;

const O_PATH: i32 = 0o10000000;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

fn cstr(path: &str) -> CString {
    CString::new(path).unwrap()
}

unsafe fn seed_file(path: &str) {
    let c = cstr(path);
    let fd = libc::open(
        c.as_ptr(),
        libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
        0o644,
    );
    if fd >= 0 {
        libc::close(fd);
    }
}

unsafe fn accept_opath_ebadf() -> bool {
    libc::mkdir(cstr("/tmp").as_ptr(), 0o777);
    let path = "/tmp/acceptsock-opath";
    seed_file(path);
    let fd = libc::open(cstr(path).as_ptr(), O_PATH | libc::O_RDONLY);
    if fd < 0 {
        return false;
    }
    let rc = libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut());
    let ok = rc == -1 && errno() == libc::EBADF;
    libc::close(fd);
    libc::unlink(cstr(path).as_ptr());
    ok
}

fn main() {
    unsafe {
        report!(accept_opath_ebadf = accept_opath_ebadf(),);
    }
}
