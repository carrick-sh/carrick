//! splice(2) probe. Moves bytes from a pipe to a file and from a pipe to a
//! pipe, asserting the return count and the bytes actually moved. Prints one
//! labelled line per observation. The conformance harness runs this identical
//! static binary under carrick and real Linux and diffs line by line — a
//! divergent line names the exact failing behavior.
//!
//! Deterministic only: no fd numbers, addresses, pids, or timestamps. Booleans,
//! byte counts, and read-back content (rendered single-line) only.

use std::ffi::CString;

fn main() {
    splice_pipe_to_file();
    splice_pipe_to_pipe();
}

/// Write "splice-bytes!" to a pipe, then splice() from the pipe read-end into a
/// regular file. Assert the splice return count equals the byte count and the
/// file contents match.
fn splice_pipe_to_file() {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), 0) } != 0 {
        println!("splice_f_pipe=ERR:{}", errno());
        return;
    }
    let (rd, wr) = (fds[0], fds[1]);

    let payload = b"splice-bytes!";
    let w = unsafe { libc::write(wr, payload.as_ptr() as *const _, payload.len()) };
    if w != payload.len() as isize {
        println!("splice_f_write=ERR:{}", errno());
        unsafe { libc::close(rd); libc::close(wr) };
        return;
    }
    // Close the write-end so the pipe has a bounded amount of data.
    unsafe { libc::close(wr) };

    let fd = open("/tmp/splice_out", libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644);
    if fd < 0 {
        println!("splice_f_open=ERR:{}", errno());
        unsafe { libc::close(rd) };
        return;
    }

    // splice from pipe (no in-offset) to file (no out-offset, uses file offset).
    let n = unsafe {
        libc::splice(
            rd,
            std::ptr::null_mut(),
            fd,
            std::ptr::null_mut(),
            payload.len(),
            0,
        )
    };
    if n < 0 {
        println!("splice_pipe_to_file_count=ERR:{}", errno());
    } else {
        println!("splice_pipe_to_file_count={}", n);
    }

    // Read the file back and confirm the bytes match.
    unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    let mut buf = [0u8; 64];
    let r = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
    let got = &buf[..r.max(0) as usize];
    println!("splice_pipe_to_file_match={}", got == payload);

    unsafe { libc::close(fd); libc::close(rd) };
}

/// Write "p2p-data" to pipe A, splice() A→B, then read it out of pipe B.
fn splice_pipe_to_pipe() {
    let mut a = [0i32; 2];
    let mut b = [0i32; 2];
    if unsafe { libc::pipe2(a.as_mut_ptr(), 0) } != 0
        || unsafe { libc::pipe2(b.as_mut_ptr(), 0) } != 0
    {
        println!("splice_pp_pipe=ERR:{}", errno());
        return;
    }
    let (a_rd, a_wr) = (a[0], a[1]);
    let (b_rd, b_wr) = (b[0], b[1]);

    let payload = b"p2p-data";
    unsafe { libc::write(a_wr, payload.as_ptr() as *const _, payload.len()) };
    unsafe { libc::close(a_wr) };

    let n = unsafe {
        libc::splice(
            a_rd,
            std::ptr::null_mut(),
            b_wr,
            std::ptr::null_mut(),
            payload.len(),
            0,
        )
    };
    if n < 0 {
        println!("splice_pipe_to_pipe_count=ERR:{}", errno());
    } else {
        println!("splice_pipe_to_pipe_count={}", n);
    }

    let mut buf = [0u8; 64];
    let r = unsafe { libc::read(b_rd, buf.as_mut_ptr() as *mut _, buf.len()) };
    let got = &buf[..r.max(0) as usize];
    println!("splice_pipe_to_pipe_match={}", got == payload);

    unsafe {
        libc::close(a_rd);
        libc::close(b_rd);
        libc::close(b_wr);
    }
}

/// Open helper returning the raw fd (or -1 on error).
fn open(path: &str, flags: i32, mode: u32) -> i32 {
    let c = CString::new(path).unwrap();
    unsafe { libc::open(c.as_ptr(), flags, mode as libc::c_uint) }
}

/// Current errno value.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}
