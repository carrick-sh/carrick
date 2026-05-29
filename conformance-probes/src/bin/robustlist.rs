//! set_robust_list / get_robust_list errno conformance (LTP set_robust_list01,
//! get_robust_list01). Both syscalls were ENOSYS/no-op on carrick; the LTP
//! tests TCONF'd or failed their EINVAL edge. carrick has no robust-futex
//! death cleanup, so the head is not retained — these assertions cover only
//! the ABI errno/return contract, which is what the tests check.
//!
//!   set_robust_list: len != sizeof(struct robust_list_head) → EINVAL; ==24 → 0.
//!   get_robust_list: NULL head/len ptr → EFAULT; a nonexistent pid → ESRCH;
//!   self → 0.
//!
//! Deterministic booleans, diffed line-exact carrick-vs-Linux. NOTE: the
//! "another live task → EPERM" leg is NOT probed here — under the harness's
//! bare `docker run alpine /probe` the probe IS pid 1, so get_robust_list(1)
//! targets itself and succeeds, while under carrick pid 1 is launchd (EPERM).
//! That divergence is a probe-environment artifact, not a carrick bug; LTP
//! get_robust_list01 (where the test process is not pid 1) gates the EPERM leg.

use conformance_probes::errno;

fn main() {
    unsafe {
        // --- set_robust_list ---
        let mut head = [0u8; 24];
        let r_bad = libc::syscall(libc::SYS_set_robust_list, head.as_mut_ptr(), -1i64);
        println!(
            "set_robust_list_badlen_einval={}",
            r_bad == -1 && errno() == libc::EINVAL
        );
        let r_ok = libc::syscall(libc::SYS_set_robust_list, head.as_mut_ptr(), 24i64);
        println!("set_robust_list_ok={}", r_ok == 0);

        // --- get_robust_list ---
        let mut hp: u64 = 0; // head output slot (a robust_list_head*)
        let mut lp: libc::size_t = 0; // len output slot

        let e_null_len = libc::syscall(
            libc::SYS_get_robust_list,
            0i64,
            &mut hp as *mut u64,
            core::ptr::null_mut::<libc::size_t>(),
        );
        println!(
            "get_robust_list_null_len_efault={}",
            e_null_len == -1 && errno() == libc::EFAULT
        );

        let e_null_head = libc::syscall(
            libc::SYS_get_robust_list,
            0i64,
            core::ptr::null_mut::<u64>(),
            &mut lp as *mut libc::size_t,
        );
        println!(
            "get_robust_list_null_head_efault={}",
            e_null_head == -1 && errno() == libc::EFAULT
        );

        // A pid that cannot exist (just under i32::MAX) → ESRCH.
        let e_unused = libc::syscall(
            libc::SYS_get_robust_list,
            0x7FFF_FFF0i64,
            &mut hp as *mut u64,
            &mut lp as *mut libc::size_t,
        );
        println!(
            "get_robust_list_unused_esrch={}",
            e_unused == -1 && errno() == libc::ESRCH
        );

        // Self (pid 0) with valid pointers → success.
        let e_self = libc::syscall(
            libc::SYS_get_robust_list,
            0i64,
            &mut hp as *mut u64,
            &mut lp as *mut libc::size_t,
        );
        println!("get_robust_list_self_ok={}", e_self == 0);

        let _ = errno;
    }
}
