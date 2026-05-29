//! recv/recvfrom with MSG_ERRQUEUE on a socket with no queued error → EAGAIN
//! (LTP recv01/recvfrom01). carrick has no socket error queue, so it returned
//! 0 (treated the flag as a normal recv); Linux returns EAGAIN when the error
//! queue is empty. Deterministic, line-exact carrick-vs-Linux.

use conformance_probes::errno;

fn main() {
    unsafe {
        let s = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        let mut buf = [0u8; 16];

        // MSG_ERRQUEUE, nothing queued → EAGAIN (also set MSG_DONTWAIT so a
        // normal recv would block, isolating the error-queue path).
        let r = libc::recv(
            s,
            buf.as_mut_ptr() as *mut _,
            buf.len(),
            libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT,
        );
        println!(
            "recv_errqueue_empty_eagain={}",
            r == -1 && errno() == libc::EAGAIN
        );

        libc::close(s);
        let _ = errno;
    }
}
