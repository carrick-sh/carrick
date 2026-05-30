//! Non-UTF-8 (undecodable) PATHNAME round-trip probe.
//!
//! Linux pathnames are opaque BYTE strings: any byte except `/` (0x2F) and NUL
//! is legal in a filename. A program (CPython via PEP 383 surrogateescape, or
//! any C program with a raw `char*`) can create `b"/tmp/cr_\xff\xfe_x"` and the
//! kernel stores those bytes verbatim; a later `open`/`stat`/`getdents` by the
//! SAME bytes round-trips. carrick used to read guest paths as a Rust `String`
//! and rejected non-UTF-8 with EINVAL, so `open(b"...\xff...")` errored where
//! Linux succeeds. This probe pins the round-trip.
//!
//! Deterministic only: BOOLEANS and the small written byte count — never an
//! inode/dev/timestamp (those differ across machines/runs). All names are
//! UNIQUE per kind so concurrent runs can't collide.

use std::ffi::CString;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

/// A NUL-terminated C path from raw bytes (path bytes never contain NUL).
fn cpath(bytes: &[u8]) -> CString {
    CString::new(bytes).expect("path has no interior NUL")
}

fn main() {
    // The undecodable leaf: a valid-UTF-8 dir + a filename with raw 0xff/0xfe
    // bytes that are NOT valid UTF-8 on their own.
    let path: &[u8] = b"/tmp/cr_nonutf8_\xff\xfe_probe";
    let dir: &[u8] = b"/tmp";
    let cp = cpath(path);

    // Fresh start.
    unsafe { libc::unlink(cp.as_ptr()) };

    // -- open(O_CREAT|O_WRONLY) + write -------------------------------------
    let payload = b"hi";
    let fd = unsafe {
        libc::open(
            cp.as_ptr(),
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
            0o644 as libc::c_uint,
        )
    };
    if fd < 0 {
        // The whole point: this MUST succeed on Linux. Emit the verdict so a
        // divergent line names the failure precisely.
        println!("open_create=ERR:{}", errno());
        println!("write_ok=false");
        println!("fstat_ok=false");
        println!("reopen_ok=false");
        println!("read_roundtrip=false");
        println!("listdir_has_name=false");
        return;
    }
    println!("open_create_ok=true");

    let wrote = unsafe { libc::write(fd, payload.as_ptr() as *const _, payload.len()) };
    println!("write_ok={}", wrote == payload.len() as isize);

    // fstat the just-created fd: it must be a regular file of size 2.
    let mut fst: libc::stat = unsafe { std::mem::zeroed() };
    let frc = unsafe { libc::fstat(fd, &mut fst) };
    println!(
        "fstat_ok={}",
        frc == 0
            && (fst.st_mode & libc::S_IFMT) == libc::S_IFREG
            && fst.st_size == payload.len() as libc::off_t
    );
    unsafe { libc::close(fd) };

    // -- reopen by the SAME bytes (O_RDONLY) + read back --------------------
    let rfd = unsafe { libc::open(cp.as_ptr(), libc::O_RDONLY) };
    println!("reopen_ok={}", rfd >= 0);
    if rfd >= 0 {
        let mut buf = [0u8; 8];
        let n = unsafe { libc::read(rfd, buf.as_mut_ptr() as *mut _, buf.len()) };
        println!(
            "read_roundtrip={}",
            n == payload.len() as isize && &buf[..payload.len()] == payload
        );
        unsafe { libc::close(rfd) };
    } else {
        println!("read_roundtrip=false");
    }

    // -- path-stat (newfstatat) by the same bytes ---------------------------
    let mut pst: libc::stat = unsafe { std::mem::zeroed() };
    let prc = unsafe { libc::stat(cp.as_ptr(), &mut pst) };
    println!(
        "pathstat_ok={}",
        prc == 0 && pst.st_size == payload.len() as libc::off_t
    );

    // -- getdents on /tmp must list the EXACT undecodable name back ---------
    // We enumerate via getdents64 directly so the raw d_name bytes are compared
    // (opendir/readdir would also work but this is byte-exact and dep-free).
    let leaf: &[u8] = b"cr_nonutf8_\xff\xfe_probe";
    println!("listdir_has_name={}", dir_has_name(dir, leaf));

    // -- unlink by the same bytes removes it (then it's gone) ---------------
    let urc = unsafe { libc::unlink(cp.as_ptr()) };
    let after = unsafe { libc::access(cp.as_ptr(), libc::F_OK) };
    println!("unlink_then_gone={}", urc == 0 && after != 0);
}

/// Enumerate `dir` via getdents64 and report whether any entry's raw name
/// bytes equal `want`.
fn dir_has_name(dir: &[u8], want: &[u8]) -> bool {
    let cd = cpath(dir);
    let dfd = unsafe { libc::open(cd.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    if dfd < 0 {
        return false;
    }
    let mut found = false;
    let mut buf = [0u8; 16384];
    loop {
        let n = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                dfd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if n <= 0 {
            break;
        }
        let mut off = 0usize;
        let n = n as usize;
        while off < n {
            // struct linux_dirent64 { u64 d_ino; i64 d_off; u16 d_reclen;
            //   u8 d_type; char d_name[]; }  -> name starts at byte 19.
            let reclen = u16::from_ne_bytes([buf[off + 16], buf[off + 17]]) as usize;
            let name_start = off + 19;
            // name is NUL-terminated within the record.
            let mut end = name_start;
            while end < off + reclen && buf[end] != 0 {
                end += 1;
            }
            if &buf[name_start..end] == want {
                found = true;
            }
            off += reclen;
        }
    }
    unsafe { libc::close(dfd) };
    found
}
