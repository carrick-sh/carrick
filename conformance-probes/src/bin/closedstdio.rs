//! closed-stdio probe. Mirrors CPython's startup contract when a standard fd is
//! CLOSED before the program runs (test_cmd_line.test_no_std* run python with
//! fd 0/1/2 closed via subprocess preexec_fn; the interpreter detects the
//! closed stream and sets sys.stdin/out/err = None).
//!
//! We close fd 0 (the harness feeds the probe over stdin, but the bytes are
//! already buffered by the time `main` runs, so closing fd 0 is safe and keeps
//! fd 1 free for our own output). We then assert, as BOOLEANS only, that every
//! operation on the now-closed fd behaves like a genuinely closed descriptor —
//! EBADF, not the "implicit open host stdio stream" carrick used to fake — AND
//! that reopening /dev/null over the freed fd number lands at fd 0 and reports
//! a CHARACTER DEVICE (S_IFCHR), exactly as Linux does. No fd numbers, modes,
//! addresses, or content are printed — only the relationships that are
//! identical on real Linux regardless of the harness's stdio object.

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

fn main() {
    // Close fd 0. On real Linux this frees descriptor 0 entirely.
    let closed = unsafe { libc::close(0) };
    println!("close0_ok={}", closed == 0);

    // fstat(0): EBADF.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let fst = unsafe { libc::fstat(0, &mut st) };
    println!("fstat0_ebadf={}", fst == -1 && errno() == libc::EBADF);

    // fcntl(0, F_GETFL): EBADF (CPython uses this to size up each std fd).
    let getfl = unsafe { libc::fcntl(0, libc::F_GETFL) };
    println!("getfl0_ebadf={}", getfl == -1 && errno() == libc::EBADF);

    // fcntl(0, F_GETFD): EBADF.
    let getfd = unsafe { libc::fcntl(0, libc::F_GETFD) };
    println!("getfd0_ebadf={}", getfd == -1 && errno() == libc::EBADF);

    // isatty(0): false, errno EBADF (closed fd is never a tty).
    let tty = unsafe { libc::isatty(0) };
    println!("isatty0_false={}", tty == 0);

    // dup(0): EBADF.
    let duped = unsafe { libc::dup(0) };
    println!("dup0_ebadf={}", duped == -1 && errno() == libc::EBADF);
    if duped >= 0 {
        unsafe { libc::close(duped) };
    }

    // lseek(0): EBADF (a closed fd, NOT an unseekable-but-open ESPIPE).
    let off = unsafe { libc::lseek(0, 0, libc::SEEK_CUR) };
    println!("lseek0_ebadf={}", off == -1 && errno() == libc::EBADF);

    // read(0): EBADF.
    let mut buf = [0u8; 1];
    let nread = unsafe { libc::read(0, buf.as_mut_ptr() as *mut libc::c_void, 1) };
    println!("read0_ebadf={}", nread == -1 && errno() == libc::EBADF);

    // Reopen /dev/null: the lowest free fd is the freed 0, so it MUST land on 0
    // (this is what lets CPython reopen a closed std stream to /dev/null).
    let devnull = b"/dev/null\0";
    let nfd = unsafe { libc::open(devnull.as_ptr() as *const libc::c_char, libc::O_RDWR) };
    println!("devnull_reuses_fd0={}", nfd == 0);

    // The reopened /dev/null fstat's as a CHARACTER DEVICE on Linux (S_IFCHR) —
    // NOT a FIFO. CPython's init_sys_streams mis-detects a FIFO here and aborts.
    if nfd >= 0 {
        let mut st2: libc::stat = unsafe { std::mem::zeroed() };
        let ok = unsafe { libc::fstat(nfd, &mut st2) } == 0;
        let is_chr = ok && (st2.st_mode & libc::S_IFMT) == libc::S_IFCHR;
        println!("devnull_is_chardev={is_chr}");
        unsafe { libc::close(nfd) };
    } else {
        println!("devnull_is_chardev=false");
    }
}
