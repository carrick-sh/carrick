//! writev(2) is atomic across iovecs: a single writev whose total exceeds the
//! socket send buffer writes as much as fits and returns that PARTIAL byte
//! count (> 0). It must NOT return EAGAIN after the first iovec(s) were written.
//!
//! Carrick looped per-iovec with a single-buffer write: iovec[0] wrote a partial
//! count, the loop continued to iovec[1] which hit EAGAIN, and carrick returned
//! that EAGAIN — discarding every byte already written. libuv then re-sent from
//! offset 0 forever, so no uv_write ever completed and heavy bidirectional IPC
//! deadlocked (ipc_heavy_traffic_deadlock_bug: bw stuck at 0).
//!
//!  * writev_big_returns_partial: writev of 3x1MB on a fresh non-blocking
//!    socketpair returns a positive partial count (what fit in the send
//!    buffer), not -1/EAGAIN.

fn main() {
    unsafe { run() }
}

unsafe fn run() {
    let mut sv = [0i32; 2];
    if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) != 0 {
        println!("setup=false socketpair");
        return;
    }
    let fl = libc::fcntl(sv[0], libc::F_GETFL);
    libc::fcntl(sv[0], libc::F_SETFL, fl | libc::O_NONBLOCK);

    // 3 MiB total across 3 iovecs — far larger than any default AF_UNIX send
    // buffer, so the write is necessarily partial.
    const MB: usize = 1024 * 1024;
    let buf = libc::malloc(3 * MB) as *mut u8;
    if buf.is_null() {
        println!("setup=false malloc");
        return;
    }
    libc::memset(buf as *mut libc::c_void, 42, 3 * MB);
    let iov = [
        libc::iovec {
            iov_base: buf as *mut _,
            iov_len: MB,
        },
        libc::iovec {
            iov_base: buf.add(MB) as *mut _,
            iov_len: MB,
        },
        libc::iovec {
            iov_base: buf.add(2 * MB) as *mut _,
            iov_len: MB,
        },
    ];
    let ret = libc::writev(sv[0], iov.as_ptr(), 3);
    let e = if ret < 0 {
        *libc::__errno_location()
    } else {
        0
    };
    // The exact partial byte count is NOT comparable across kernels (the AF_UNIX
    // send-buffer size differs), so only assert the invariant: a positive
    // partial, never EAGAIN. errno is only meaningful on the (wrong) -1 path.
    let writev_big_returns_partial = ret > 0;
    let _ = e;

    println!("writev_big_returns_partial={writev_big_returns_partial}");

    libc::free(buf as *mut libc::c_void);
    libc::close(sv[0]);
    libc::close(sv[1]);
}
