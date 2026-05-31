//! open("")/openat(AT_FDCWD,"") must return ENOENT (no AT_EMPTY_PATH on open).
//! carrick's resolver used to treat "" as the dirfd's directory and succeed;
//! test_ctypes' libc.open(b"",0) expects -1/ENOENT. Deterministic booleans.
use std::ffi::CString;
fn main() {
    let empty = CString::new("").unwrap();
    let fd = unsafe { libc::open(empty.as_ptr(), libc::O_RDONLY) };
    let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    println!("open_empty_fails={}", fd < 0);
    println!("open_empty_enoent={}", fd < 0 && e == libc::ENOENT);
    // openat(AT_FDCWD, "") — same.
    let fd2 = unsafe { libc::openat(libc::AT_FDCWD, empty.as_ptr(), libc::O_RDONLY) };
    let e2 = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    println!("openat_empty_enoent={}", fd2 < 0 && e2 == libc::ENOENT);
    // a NON-empty valid open still works (guard against over-broad rejection).
    let dev = CString::new("/dev/null").unwrap();
    let fd3 = unsafe { libc::open(dev.as_ptr(), libc::O_RDONLY) };
    println!("nonempty_open_ok={}", fd3 >= 0);
    if fd3 >= 0 { unsafe { libc::close(fd3); } }
}
