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

        let _ = errno;
    }
}
