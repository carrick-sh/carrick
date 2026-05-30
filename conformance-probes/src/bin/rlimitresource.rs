//! prlimit64/getrlimit reject an invalid resource (>= RLIM_NLIMITS = 16) with
//! EINVAL (LTP getrlimit02 invalid-resource-type case); a valid resource (0..15)
//! succeeds. carrick previously treated unknown resources as RLIM_INFINITY and
//! returned success. Uses the raw syscall so musl's wrapper can't pre-validate.
//! Deterministic booleans, diffed line-exact carrick-vs-Linux.

use conformance_probes::errno;

fn main() {
    unsafe {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let p = &mut rl as *mut _ as i64;

        // resource 99 (far past RLIM_NLIMITS) → EINVAL.
        let r1 = libc::syscall(libc::SYS_prlimit64, 0i64, 99i64, 0i64, p);
        println!(
            "prlimit_bad_resource_einval={}",
            r1 == -1 && errno() == libc::EINVAL
        );

        // boundary: resource 16 == RLIM_NLIMITS → EINVAL (15 is the last valid).
        let r2 = libc::syscall(libc::SYS_prlimit64, 0i64, 16i64, 0i64, p);
        println!(
            "prlimit_resource16_einval={}",
            r2 == -1 && errno() == libc::EINVAL
        );

        // valid resource RLIMIT_NOFILE (7) → success.
        let r3 = libc::syscall(libc::SYS_prlimit64, 0i64, 7i64, 0i64, p);
        println!("prlimit_nofile_ok={}", r3 == 0);

        // The pid arg selects the target process. pid 0 names the caller and
        // succeeds; a pid that does not exist is ESRCH. carrick previously
        // IGNORED the pid and treated everything as self → wrongly succeeded
        // (CPython test_resource.test_prlimit). RLIMIT_AS (9) is read-only here.
        const RLIMIT_AS: i64 = 9;

        // pid 0 (self) → success.
        let r4 = libc::syscall(libc::SYS_prlimit64, 0i64, RLIMIT_AS, 0i64, p);
        println!("prlimit_self_ok={}", r4 == 0);

        // pid -1 → ESRCH (never a real task).
        let r5 = libc::syscall(libc::SYS_prlimit64, -1i64, RLIMIT_AS, 0i64, p);
        println!(
            "prlimit_pid_neg1_esrch={}",
            r5 == -1 && errno() == libc::ESRCH
        );

        // pid 999999 (huge, almost certainly nonexistent) → ESRCH.
        let r6 = libc::syscall(libc::SYS_prlimit64, 999999i64, RLIMIT_AS, 0i64, p);
        println!(
            "prlimit_pid_999999_esrch={}",
            r6 == -1 && errno() == libc::ESRCH
        );

        let _ = errno;
    }
}
