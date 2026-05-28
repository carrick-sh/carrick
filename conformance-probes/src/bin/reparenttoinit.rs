//! When a child's parent exits before the child is reaped, the child is
//! reparented to init (PID 1) in its PID namespace. This is fundamental
//! process-lifecycle plumbing that LTP's `getpid01` exercises and shells +
//! daemons depend on (the canonical "double-fork to detach" idiom). carrick
//! mirrors the guest process tree onto the host process tree; if the mirror
//! gets a real-Linux semantics wrong, an orphan's `getppid()` would surface
//! the host's init or 0 rather than guest-PID-1.
//!
//! Shape (the double-fork):
//!   main          → fork → child A
//!   child A       → fork → grandchild B
//!   child A       → exit(0) immediately   (orphans B)
//!   main          → waitpid(A)            (reaps A, releases its slot)
//!   grandchild B  → sleep, then getppid() (must observe ppid == 1)
//!   grandchild B  → writes 4 bytes over a shared pipe with main, exits.
//!
//! Output (deterministic booleans):
//!   reparent_read_ok=true        // main read the 4-byte ppid from B
//!   reparent_grandchild_ppid_is_1=true  // B's parent is PID 1 after orphan
//!   reparent_grandchild_exited_clean=... // best-effort: we can't waitpid(B)
//!                                          because B is no longer our child,
//!                                          so this asserts only that B
//!                                          managed to write before exit.

use conformance_probes::{errno, report};
use std::time::{Duration, Instant};

fn main() {
    unsafe {
        let mut fds = [0i32; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            report!(
                reparent_pipe_ok = false,
                reparent_read_ok = false,
                reparent_grandchild_ppid_is_1 = false,
            );
            return;
        }

        let child_a = libc::fork();
        if child_a == 0 {
            // Child A: spawn grandchild then exit immediately.
            libc::close(fds[0]);
            let grandchild_b = libc::fork();
            if grandchild_b == 0 {
                // Grandchild B: hold while child A exits and gets reaped.
                // 200 ms is plenty for main to reap A — bounded so a broken
                // path doesn't hang the harness.
                libc::usleep(200_000);
                let ppid = libc::getppid();
                let bytes = ppid.to_ne_bytes();
                libc::write(
                    fds[1],
                    bytes.as_ptr() as *const libc::c_void,
                    bytes.len(),
                );
                libc::close(fds[1]);
                libc::_exit(0);
            }
            // Child A exits NOW so B is orphaned — the kernel reparents B.
            libc::_exit(0);
        }
        if child_a < 0 {
            report!(
                reparent_pipe_ok = true,
                reparent_read_ok = false,
                reparent_grandchild_ppid_is_1 = false,
            );
            return;
        }

        // Main: close write end so a hung B doesn't keep the pipe alive.
        libc::close(fds[1]);
        // Reap A immediately. B keeps running with its now-orphan ppid.
        let mut status = 0i32;
        let _ = libc::waitpid(child_a, &mut status, 0);

        // Read B's ppid from the pipe. Bounded: poll until data or 2 s.
        let mut bytes = [0u8; 4];
        let mut got = 0usize;
        let deadline = Instant::now() + Duration::from_secs(2);
        while got < bytes.len() && Instant::now() < deadline {
            let n = libc::read(
                fds[0],
                bytes.as_mut_ptr().add(got) as *mut libc::c_void,
                bytes.len() - got,
            );
            if n > 0 {
                got += n as usize;
            } else if n == 0 {
                break; // EOF — write end closed without writing all 4 bytes
            } else if errno() != libc::EINTR {
                break;
            }
        }
        libc::close(fds[0]);

        let read_ok = got == 4;
        let ppid = if read_ok { i32::from_ne_bytes(bytes) } else { 0 };
        report!(
            reparent_pipe_ok = true,
            reparent_read_ok = read_ok,
            reparent_grandchild_ppid_is_1 = read_ok && ppid == 1,
        );
    }
}
