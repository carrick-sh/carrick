//! F_GETLK on a region with NO conflicting lock leaves the caller's struct
//! UNCHANGED except `l_type = F_UNLCK` — in particular `l_pid` keeps the value
//! the caller passed (LTP fcntl05 pre-sets l_pid = getpid() and asserts it
//! survives). carrick previously rewrote the whole struct from the macOS flock
//! result, zeroing l_pid. Deterministic booleans, diffed line-exact vs Linux.

use conformance_probes::errno;

fn main() {
    unsafe {
        libc::mkdir(b"/tmp\0".as_ptr() as *const _, 0o777);
        let path = b"/tmp/flk\0".as_ptr() as *const libc::c_char;
        let fd = libc::open(path, libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644);
        println!("open_ok={}", fd >= 0);

        let mut fl: libc::flock = std::mem::zeroed();
        fl.l_type = libc::F_WRLCK as i16;
        fl.l_whence = libc::SEEK_SET as i16;
        fl.l_start = 0;
        fl.l_len = 0;
        // Sentinel values the kernel must leave untouched on a no-conflict
        // F_GETLK (only l_type changes to F_UNLCK).
        fl.l_pid = 0x7777;
        let rc = libc::fcntl(fd, libc::F_GETLK, &mut fl);
        println!("getlk_ok={}", rc == 0);
        println!("getlk_type_unlck={}", fl.l_type == libc::F_UNLCK as i16);
        println!("getlk_lpid_preserved={}", fl.l_pid == 0x7777);
        println!("getlk_whence_preserved={}", fl.l_whence == libc::SEEK_SET as i16);

        let _ = errno;
        libc::close(fd);
        libc::unlink(path);
    }
}
