//! select/pselect6 must reject a negative `nfds` with EINVAL *before* the
//! empty-fd-set + NULL-timeout path — otherwise `pselect6(-1, NULL, NULL,
//! NULL, NULL, mask)` blocks forever (the LTP pselect02 case-2 hang that the
//! tst_test watchdog SIGALRM-kills → TBROK). Linux validates `nfds < 0` first.
//! Deterministic booleans, diffed line-exact carrick-vs-Linux.

use conformance_probes::errno;

fn main() {
    unsafe {
        // The exact pselect02 case-2 shape: negative nfds, all sets NULL, NULL
        // timeout, NULL sigmask. Must return EINVAL immediately, never block.
        let rc = libc::syscall(
            libc::SYS_pselect6,
            -1i64, // nfds (sign-extended to u64::MAX)
            0i64,  // readfds = NULL
            0i64,  // writefds = NULL
            0i64,  // exceptfds = NULL
            0i64,  // timeout = NULL (block forever, if not for the nfds check)
            0i64,  // sigmask pack = NULL
        );
        println!(
            "pselect6_neg_nfds_einval={}",
            rc == -1 && errno() == libc::EINVAL
        );

        // Same via a non-NULL (but empty) read set + a real timeout: still
        // EINVAL (nfds is validated ahead of the sets/timeout).
        let mut rset: libc::fd_set = std::mem::zeroed();
        libc::FD_ZERO(&mut rset);
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let rc2 = libc::syscall(
            libc::SYS_pselect6,
            -5i64,
            &mut rset as *mut _ as i64,
            0i64,
            0i64,
            &mut ts as *mut _ as i64,
            0i64,
        );
        println!(
            "pselect6_neg_nfds_with_set_einval={}",
            rc2 == -1 && errno() == libc::EINVAL
        );

        // Sanity: a valid empty select with a zero timeout returns 0 (timeout),
        // proving the fix didn't turn legitimate empty waits into errors.
        let mut ts0 = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let rc3 = libc::syscall(libc::SYS_pselect6, 0i64, 0i64, 0i64, 0i64, &mut ts0 as *mut _ as i64, 0i64);
        println!("pselect6_zero_nfds_returns_0={}", rc3 == 0);
    }
}
