//! CPU usage belongs to a reaped guest child and becomes the parent's children usage.
use std::mem::zeroed;

unsafe fn cpu_ns() -> i64 {
    let mut now: libc::timespec = zeroed();
    assert_eq!(
        libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, &mut now),
        0
    );
    now.tv_sec * 1_000_000_000 + now.tv_nsec
}

fn main() {
    unsafe {
        // Bound the wait and CPU burn even when accounting is broken.
        libc::alarm(5);
        let mut before: libc::rusage = zeroed();
        assert_eq!(libc::getrusage(libc::RUSAGE_CHILDREN, &mut before), 0);
        let child = libc::fork();
        assert!(child >= 0);
        if child == 0 {
            libc::alarm(5);
            let start = cpu_ns();
            let mut value = 1_u64;
            while cpu_ns() - start < 50_000_000 {
                for _ in 0..10_000 {
                    value =
                        std::hint::black_box(value.wrapping_mul(1664525).wrapping_add(1013904223));
                }
            }
            libc::_exit(0);
        }
        let mut status = 0;
        let mut usage: libc::rusage = zeroed();
        assert_eq!(libc::wait4(child, &mut status, 0, &mut usage), child);
        assert_eq!(status, 0);
        let mut after: libc::rusage = zeroed();
        assert_eq!(libc::getrusage(libc::RUSAGE_CHILDREN, &mut after), 0);
        println!(
            "wait4_utime_positive={}",
            usage.ru_utime.tv_sec > 0 || usage.ru_utime.tv_usec > 0
        );
        println!(
            "children_utime_positive_after_reap={}",
            after.ru_utime.tv_sec > 0 || after.ru_utime.tv_usec > 0
        );
        println!(
            "children_zero_before_reap={}",
            before.ru_utime.tv_sec == 0
                && before.ru_utime.tv_usec == 0
                && before.ru_stime.tv_sec == 0
                && before.ru_stime.tv_usec == 0
        );
    }
}
