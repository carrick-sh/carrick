//! setfsuid/setfsgid filesystem-id model (LTP setfsuid01/03, setfsgid01/02).
//! carrick returned a fixed euid/egid and tracked no fsuid/fsgid; the syscalls
//! must return the PREVIOUS fs-id and update it (when privileged, or when the
//! arg already matches one of r/e/s/fs id). `(uid_t)-1` is a pure query.
//! Deterministic booleans, line-exact carrick-vs-Linux. Runs privileged (root
//! in docker / guest-root under run-elf) so every set is permitted — the
//! non-root permitted-vs-denied legs are gated by the LTP tests (they drop to
//! nobody).

use conformance_probes::errno;

fn main() {
    unsafe {
        // fsuid starts == euid (0). setfsuid returns the previous fsuid.
        let p0 = libc::setfsuid(1000);
        println!("setfsuid_prev_is_euid0={}", p0 == 0);
        // (uid_t)-1 → query: returns the current fsuid (now 1000), no change.
        let q = libc::setfsuid(u32::MAX);
        println!("setfsuid_query_is_1000={}", q == 1000);
        // next set returns the prior value (1000).
        let p1 = libc::setfsuid(2000);
        println!("setfsuid_prev_is_1000={}", p1 == 1000);

        // fsgid mirrors fsuid.
        let g0 = libc::setfsgid(1000);
        println!("setfsgid_prev_is_egid0={}", g0 == 0);
        let gq = libc::setfsgid(u32::MAX);
        println!("setfsgid_query_is_1000={}", gq == 1000);
        let g1 = libc::setfsgid(2000);
        println!("setfsgid_prev_is_1000={}", g1 == 1000);

        let _ = errno;
    }
}
