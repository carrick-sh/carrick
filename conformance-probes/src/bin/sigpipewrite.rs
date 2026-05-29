//! SIGPIPE on a broken-pipe write (LTP write05): writing to a pipe whose read
//! end is closed returns EPIPE AND raises SIGPIPE on the writer — a handler
//! runs exactly once; when SIGPIPE is SIG_IGN the write still returns EPIPE but
//! no handler runs. carrick returned EPIPE without raising SIGPIPE.
//! Deterministic, line-exact carrick-vs-Linux.

use conformance_probes::errno;
use std::sync::atomic::{AtomicU32, Ordering};

static HITS: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_pipe(_sig: i32) {
    HITS.fetch_add(1, Ordering::SeqCst);
}

fn main() {
    unsafe {
        let buf = [0u8; 4];

        // --- caught SIGPIPE: write to a broken pipe → EPIPE + handler once ---
        let mut fds = [0i32; 2];
        libc::pipe(fds.as_mut_ptr());
        libc::close(fds[0]); // close read end → broken pipe
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_pipe as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGPIPE, &sa, std::ptr::null_mut());
        HITS.store(0, Ordering::SeqCst);
        let r = libc::write(fds[1], buf.as_ptr() as *const _, 4);
        println!(
            "write_broken_pipe_epipe={}",
            r == -1 && errno() == libc::EPIPE
        );
        println!("sigpipe_delivered_once={}", HITS.load(Ordering::SeqCst) == 1);
        libc::close(fds[1]);

        // --- ignored SIGPIPE: still EPIPE, but no handler runs ---
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        let mut fds2 = [0i32; 2];
        libc::pipe(fds2.as_mut_ptr());
        libc::close(fds2[0]);
        HITS.store(0, Ordering::SeqCst);
        let r2 = libc::write(fds2[1], buf.as_ptr() as *const _, 4);
        println!(
            "ignored_still_epipe={}",
            r2 == -1 && errno() == libc::EPIPE
        );
        println!("ignored_no_handler={}", HITS.load(Ordering::SeqCst) == 0);
        libc::close(fds2[1]);

        let _ = errno;
    }
}
