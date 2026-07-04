//! `clock_nanosleep(2)` rejects CPU-time clocks.
//!
//! Linux allows `clock_gettime` on static and dynamic CPU clocks, but sleeping
//! against a CPU-time clock is unsupported. LTP `clock_nanosleep01` exercises
//! the raw syscall path and expects `-1/EOPNOTSUPP` for `CLOCK_THREAD_CPUTIME_ID`.

use conformance_probes::{errno, report};

fn raw_clock_nanosleep(clock_id: libc::clockid_t) -> (libc::c_long, i32) {
    let req = libc::timespec {
        tv_sec: 0,
        tv_nsec: 500_000_000,
    };
    let mut rem = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_clock_nanosleep,
            clock_id,
            0,
            &req as *const libc::timespec,
            &mut rem as *mut libc::timespec,
        )
    };
    (rc, errno())
}

fn main() {
    let (thread_rc, thread_errno) = raw_clock_nanosleep(libc::CLOCK_THREAD_CPUTIME_ID);
    report!(thread_cputime_raw_eopnotsupp =
        thread_rc == -1 && thread_errno == libc::EOPNOTSUPP);
}
