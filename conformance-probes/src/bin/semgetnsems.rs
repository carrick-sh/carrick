//! semget caps nsems at the Linux SEMMSL (default 32000): a request with
//! nsems > SEMMSL → EINVAL (LTP semget02); a normal small set succeeds. carrick
//! forwarded straight to macOS semget, which returns ENOSPC for the over-large
//! request (its SEMMSL is far smaller). Deterministic booleans, line-exact vs
//! Linux.

use conformance_probes::errno;

fn main() {
    unsafe {
        // nsems past the Linux limit → EINVAL (not ENOSPC).
        let r1 = libc::semget(libc::IPC_PRIVATE, 32001, libc::IPC_CREAT | 0o600);
        println!(
            "semget_nsems_too_large_einval={}",
            r1 == -1 && errno() == libc::EINVAL
        );

        // a minimal private set succeeds; clean it up.
        let id = libc::semget(libc::IPC_PRIVATE, 1, libc::IPC_CREAT | 0o600);
        println!("semget_small_ok={}", id >= 0);
        if id >= 0 {
            libc::semctl(id, 0, libc::IPC_RMID);
        }

        let _ = errno;
    }
}
