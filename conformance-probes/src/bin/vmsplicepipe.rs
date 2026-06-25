//! vmsplice(2) probe. Moves bytes from user memory INTO a pipe (write end) and
//! FROM a pipe into user memory (read end), asserting the return count and the
//! bytes actually moved. The conformance harness runs this identical static
//! binary under carrick and real Linux and diffs line by line — a divergent line
//! names the exact failing behavior. This isolates the vmsplice data path from
//! the LTP framework/fork-tree/checkpoint noise.
//!
//! Deterministic only: no fd numbers, addresses, pids, or timestamps. Booleans
//! and byte counts only.

fn main() {
    vmsplice_user_to_pipe();
    vmsplice_pipe_to_user();
}

/// Gather "vmsplice-data!" from user memory into a pipe write-end, then read it
/// back out of the read-end. Assert the count and the bytes match.
fn vmsplice_user_to_pipe() {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), 0) } != 0 {
        println!("vms_u2p_pipe=ERR:{}", errno());
        return;
    }
    let (rd, wr) = (fds[0], fds[1]);

    let payload = b"vmsplice-data!";
    let iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let n = unsafe { libc::vmsplice(wr, &iov, 1, 0) };
    if n < 0 {
        println!("vms_u2p_count=ERR:{}", errno());
    } else {
        println!("vms_u2p_count={}", n);
    }
    unsafe { libc::close(wr) };

    let mut buf = [0u8; 64];
    let r = unsafe { libc::read(rd, buf.as_mut_ptr() as *mut _, buf.len()) };
    let got = &buf[..r.max(0) as usize];
    println!("vms_u2p_match={}", got == payload);

    unsafe { libc::close(rd) };
}

/// Write "p2u-bytes" into a pipe, then vmsplice it FROM the read-end into user
/// memory. Assert the count and the extracted bytes match.
fn vmsplice_pipe_to_user() {
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), 0) } != 0 {
        println!("vms_p2u_pipe=ERR:{}", errno());
        return;
    }
    let (rd, wr) = (fds[0], fds[1]);

    let payload = b"p2u-bytes";
    unsafe { libc::write(wr, payload.as_ptr() as *const _, payload.len()) };
    unsafe { libc::close(wr) };

    let mut buf = [0u8; 64];
    let iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let n = unsafe { libc::vmsplice(rd, &iov, 1, 0) };
    if n < 0 {
        println!("vms_p2u_count=ERR:{}", errno());
    } else {
        println!("vms_p2u_count={}", n);
    }
    let got = &buf[..n.max(0) as usize];
    println!("vms_p2u_match={}", got == payload);

    unsafe { libc::close(rd) };
}

/// Current errno value.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}
