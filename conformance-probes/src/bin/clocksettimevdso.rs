//! Conformance probe: `clock_settime(CLOCK_REALTIME)` moves the guest wall
//! clock, and both the direct syscall and the `__kernel_clock_gettime` vDSO
//! fast path in every thread and forked child must immediately reflect the
//! updated time.
//!
//! Deterministic only: prints booleans and errnos, never absolute timestamps.

use std::mem::MaybeUninit;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn raw_clock_gettime(clk: libc::clockid_t) -> (i32, libc::timespec) {
    let mut ts = MaybeUninit::<libc::timespec>::uninit();
    let rc = unsafe {
        libc::syscall(
            libc::SYS_clock_gettime,
            clk as libc::c_long,
            ts.as_mut_ptr(),
        ) as i32
    };
    let ts = if rc == 0 {
        unsafe { ts.assume_init() }
    } else {
        libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }
    };
    (rc, ts)
}

fn libc_clock_gettime(clk: libc::clockid_t) -> (i32, libc::timespec) {
    let mut ts = MaybeUninit::<libc::timespec>::uninit();
    let rc = unsafe { libc::clock_gettime(clk, ts.as_mut_ptr()) };
    let ts = if rc == 0 {
        unsafe { ts.assume_init() }
    } else {
        libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        }
    };
    (rc, ts)
}

fn libc_gettimeofday() -> (i32, libc::timeval) {
    let mut tv = MaybeUninit::<libc::timeval>::uninit();
    let rc = unsafe { libc::gettimeofday(tv.as_mut_ptr(), std::ptr::null_mut()) };
    let tv = if rc == 0 {
        unsafe { tv.assume_init() }
    } else {
        libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        }
    };
    (rc, tv)
}

fn main() {
    // 1. CLOCK_MONOTONIC cannot be set -> EINVAL.
    {
        let ts = libc::timespec {
            tv_sec: 1000,
            tv_nsec: 0,
        };
        let rc = unsafe { libc::clock_settime(libc::CLOCK_MONOTONIC, &ts) };
        println!(
            "clock_settime_monotonic rc={} errno={}",
            rc,
            if rc == -1 { errno() } else { 0 }
        );
    }

    // 2. Read initial REALTIME via both syscall and vDSO (libc).
    let (rc_raw_0, ts_raw_0) = raw_clock_gettime(libc::CLOCK_REALTIME);
    let (rc_vdso_0, ts_vdso_0) = libc_clock_gettime(libc::CLOCK_REALTIME);
    let (rc_gtod_0, tv_gtod_0) = libc_gettimeofday();

    println!(
        "initial_reads rc_raw={} rc_vdso={} rc_gtod={}",
        rc_raw_0, rc_vdso_0, rc_gtod_0
    );

    // 3. Shift REALTIME forward by +3600 seconds.
    let shift_sec: libc::time_t = 3600;
    let target_sec = ts_raw_0.tv_sec + shift_sec;
    let set_ts = libc::timespec {
        tv_sec: target_sec,
        tv_nsec: ts_raw_0.tv_nsec,
    };
    let set_rc = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &set_ts) };
    println!(
        "clock_settime_realtime rc={} errno={}",
        set_rc,
        if set_rc == -1 { errno() } else { 0 }
    );

    // 4. Verify shifted time on both raw syscall and vDSO / gettimeofday.
    let (rc_raw_1, ts_raw_1) = raw_clock_gettime(libc::CLOCK_REALTIME);
    let (rc_vdso_1, ts_vdso_1) = libc_clock_gettime(libc::CLOCK_REALTIME);
    let (rc_gtod_1, tv_gtod_1) = libc_gettimeofday();

    let raw_shifted = rc_raw_1 == 0 && ts_raw_1.tv_sec >= target_sec && ts_raw_1.tv_sec <= target_sec + 60;
    let vdso_shifted = rc_vdso_1 == 0 && ts_vdso_1.tv_sec >= target_sec && ts_vdso_1.tv_sec <= target_sec + 60;
    let gtod_shifted = rc_gtod_1 == 0 && tv_gtod_1.tv_sec >= target_sec && tv_gtod_1.tv_sec <= target_sec + 60;
    println!(
        "parent_shifted raw_shifted={} vdso_shifted={} gtod_shifted={}",
        raw_shifted, vdso_shifted, gtod_shifted
    );

    // 5. Fork child and verify child's vDSO and raw syscall see shifted time.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        println!("fork_failed errno={}", errno());
    } else if pid == 0 {
        // Child
        let (rc_raw_c, ts_raw_c) = raw_clock_gettime(libc::CLOCK_REALTIME);
        let (rc_vdso_c, ts_vdso_c) = libc_clock_gettime(libc::CLOCK_REALTIME);
        let child_raw_shifted = rc_raw_c == 0 && ts_raw_c.tv_sec >= target_sec && ts_raw_c.tv_sec <= target_sec + 60;
        let child_vdso_shifted = rc_vdso_c == 0 && ts_vdso_c.tv_sec >= target_sec && ts_vdso_c.tv_sec <= target_sec + 60;
        println!(
            "child_shifted raw_shifted={} vdso_shifted={}",
            child_raw_shifted, child_vdso_shifted
        );
        unsafe { libc::_exit(0) };
    } else {
        // Parent: wait for child.
        let mut status = 0;
        let wait_rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        println!(
            "child_wait wait_rc_ok={} exit_ok={}",
            wait_rc == pid,
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
        );
    }

    // 6. Restore time by shifting back.
    let restore_ts = libc::timespec {
        tv_sec: ts_raw_0.tv_sec + 1,
        tv_nsec: ts_raw_0.tv_nsec,
    };
    let restore_rc = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &restore_ts) };
    println!(
        "clock_settime_restore rc={} errno={}",
        restore_rc,
        if restore_rc == -1 { errno() } else { 0 }
    );
}
