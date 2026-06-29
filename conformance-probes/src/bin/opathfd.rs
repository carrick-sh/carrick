//! O_PATH file-descriptor semantics probe. An fd opened with O_PATH is a bare
//! reference to the filesystem object: it can be passed to *at() calls and
//! fstat()'d, but it is NOT open for I/O — read/write/fchmod/fchown/fgetxattr
//! against it must fail with EBADF. carrick previously treated an O_PATH fd as
//! an ordinary descriptor (it routed through the normal open path and lost the
//! O_PATH restriction), so reads/writes succeeded where Linux rejects them.
//! This probe pins the exact Linux contract; the harness diffs carrick vs Linux
//! line by line.
//!
//! Deterministic: booleans only (each op's -1/EBADF outcome, plus fstat OK).
//! Never raw addresses, fds, inodes, or sizes.

use std::ffi::CString;

// O_PATH is not exposed by musl's libc bindings on every target; use the raw
// AArch64 Linux value (shared with x86_64). open(O_PATH|O_RDONLY) yields the
// restricted descriptor.
const O_PATH: i32 = 0o10000000;

fn main() {
    // The run-elf rootfs is empty; create /tmp before touching files under it
    // (Docker's /tmp already exists → mkdir reports EEXIST, which we ignore).
    mkdir("/tmp", 0o777);

    let path = "/tmp/opathtarget";

    // Seed a normal regular file with one byte so an I/O attempt has something
    // to (not) read. Done with an ordinary O_RDWR|O_CREAT open, then closed.
    if !seed_file(path) {
        println!("seed=ERR:{}", errno());
        return;
    }

    // Re-open O_PATH. This is the descriptor under test.
    let Ok(c) = CString::new(path) else {
        println!("opath_open=ERR:cstring");
        return;
    };
    let fd = unsafe { libc::open(c.as_ptr(), O_PATH | libc::O_RDONLY) };
    if fd < 0 {
        println!("opath_open=ERR:{}", errno());
        return;
    }

    // read() on an O_PATH fd → -1 / EBADF.
    let mut buf = [0u8; 16];
    let r = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    println!("read_ebadf={}", r == -1 && errno() == libc::EBADF);

    // write() → -1 / EBADF.
    let w = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, 1) };
    println!("write_ebadf={}", w == -1 && errno() == libc::EBADF);

    // fchmod() → -1 / EBADF.
    let fc = unsafe { libc::fchmod(fd, 0o600) };
    println!("fchmod_ebadf={}", fc == -1 && errno() == libc::EBADF);

    // fchown() → -1 / EBADF (chown to -1/-1 == no-op IDs, still rejected for
    // O_PATH before any ownership check runs).
    let fo = unsafe { libc::fchown(fd, u32::MAX, u32::MAX) };
    println!("fchown_ebadf={}", fo == -1 && errno() == libc::EBADF);

    // fgetxattr() → -1 / EBADF (the fd has no I/O access; xattr query is denied
    // the same way). Query a name that doesn't exist; EBADF must win over
    // ENODATA because the descriptor itself is the failure.
    let Ok(name) = CString::new("user.carrick.absent") else {
        println!("fgetxattr_ebadf=ERR:cstring");
        return;
    };
    let mut xbuf = [0u8; 16];
    let xr = unsafe {
        libc::fgetxattr(
            fd,
            name.as_ptr(),
            xbuf.as_mut_ptr() as *mut libc::c_void,
            xbuf.len(),
        )
    };
    println!("fgetxattr_ebadf={}", xr == -1 && errno() == libc::EBADF);

    // fstat() is the ONE I/O-less query O_PATH explicitly permits → must
    // succeed (rc 0) and report the regular-file type.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let sr = unsafe { libc::fstat(fd, &mut st) };
    let is_reg = (st.st_mode & libc::S_IFMT) == libc::S_IFREG;
    println!("fstat_ok={}", sr == 0 && is_reg);

    unsafe { libc::close(fd) };
}

/// Create `path` as a regular file with a single byte of content; returns true
/// on success.
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
    let one = [0u8; 1];
    let _ = unsafe { libc::write(fd, one.as_ptr() as *const libc::c_void, 1) };
    unsafe { libc::close(fd) };
    true
}

/// mkdir(2); failures (e.g. EEXIST) are ignored by the caller.
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
