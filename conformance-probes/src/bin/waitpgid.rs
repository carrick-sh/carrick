//! waitpid(2) error edges (LTP waitpid04): waiting on an invalid process group
//! (pid < -1 that resolves to no group, e.g. INT_MIN) → ESRCH; invalid options
//! → EINVAL; no children → ECHILD. carrick forwarded pid<-1 to the host, which
//! surfaces EINVAL for the bad pgid — remapped to ESRCH. Deterministic,
//! line-exact carrick-vs-Linux.

use conformance_probes::errno;

fn main() {
    unsafe {
        // pid < -1 naming a nonexistent process group → ESRCH.
        let r1 = libc::waitpid(i32::MIN, std::ptr::null_mut(), 0);
        println!("waitpid_intmin_esrch={}", r1 == -1 && errno() == libc::ESRCH);

        // invalid options → EINVAL.
        let r2 = libc::waitpid(-1, std::ptr::null_mut(), -1);
        println!("waitpid_badflags_einval={}", r2 == -1 && errno() == libc::EINVAL);

        // no children → ECHILD.
        let r3 = libc::waitpid(-1, std::ptr::null_mut(), 0);
        println!("waitpid_nochild_echild={}", r3 == -1 && errno() == libc::ECHILD);

        let _ = errno;
    }
}
