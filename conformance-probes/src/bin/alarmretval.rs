//! alarm(2) return-value semantics (LTP alarm02/03/05/06/07): alarm returns
//! the number of seconds REMAINING on any previously scheduled alarm (0 when
//! none), and alarm(0) cancels. Large seconds values (INT_MAX) must round-trip
//! through the shared ITIMER_REAL slot without truncation or a phantom
//! "previous" alarm appearing in a fresh process.

fn main() {
    unsafe {
        let r0 = libc::alarm(300);
        let r1 = libc::alarm(0);
        let big = (u32::MAX / 4) as libc::c_uint;
        let r2 = libc::alarm(big);
        let r3 = libc::alarm(0);
        println!("fresh_alarm_returns_zero={}", r0 == 0);
        println!("cancel_returns_remaining={}", r1 == 300);
        println!("big_alarm_returns_zero={}", r2 == 0);
        println!("big_cancel_exact={}", r3 == big);
    }
    setitimer_roundtrip();
}

// Raw setitimer round-trip — glibc implements alarm() via setitimer, so the
// old-value writeback is what LTP alarm02 actually exercises under glibc.
fn setitimer_roundtrip() {
    unsafe {
        let arm = libc::itimerval {
            it_interval: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            it_value: libc::timeval {
                tv_sec: 2147483647,
                tv_usec: 0,
            },
        };
        let rc0 = libc::setitimer(libc::ITIMER_REAL, &arm, std::ptr::null_mut());
        let mut old: libc::itimerval = std::mem::zeroed();
        let disarm: libc::itimerval = std::mem::zeroed();
        let rc1 = libc::setitimer(libc::ITIMER_REAL, &disarm, &mut old);
        println!("setitimer_arm_ok={}", rc0 == 0);
        println!("setitimer_disarm_ok={}", rc1 == 0);
        println!(
            "old_value_sec_intmax={}",
            (2147483645..=2147483647).contains(&old.it_value.tv_sec)
        );
        println!(
            "old_value_usec_range={}",
            (0..1_000_000).contains(&old.it_value.tv_usec)
        );
    }
}
