//! Time / clock probe. Exercises clock_gettime/clock_getres/nanosleep/
//! clock_nanosleep/gettimeofday/times/getrusage/time syscalls and prints one
//! labelled line per observation. The conformance harness runs this identical
//! static binary under carrick and real Linux and diffs line by line — a
//! divergent line names the exact failing syscall.
//!
//! Deterministic only: NEVER print actual times, dates, durations, or tick
//! values — they vary per run. Print only relationships, booleans, and errnos
//! so the output is byte-identical across two runs on the same machine.

use std::mem::MaybeUninit;

fn main() {
    // clock_gettime for several clocks: rc==0 and tv_sec>0 (boolean each).
    for (name, id) in [
        ("realtime", libc::CLOCK_REALTIME),
        ("monotonic", libc::CLOCK_MONOTONIC),
        ("boottime", libc::CLOCK_BOOTTIME),
        ("process_cputime", libc::CLOCK_PROCESS_CPUTIME_ID),
    ] {
        let mut ts = MaybeUninit::<libc::timespec>::uninit();
        let rc = unsafe { libc::clock_gettime(id, ts.as_mut_ptr()) };
        if rc != 0 {
            println!("clock_gettime_{}=ERR:{}", name, errno());
        } else {
            let ts = unsafe { ts.assume_init() };
            println!("clock_gettime_{} rc={} sec_positive={}", name, rc, ts.tv_sec > 0);
        }
    }

    // Two successive CLOCK_MONOTONIC reads are non-decreasing (boolean).
    {
        let mut a = MaybeUninit::<libc::timespec>::uninit();
        let mut b = MaybeUninit::<libc::timespec>::uninit();
        let r1 = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, a.as_mut_ptr()) };
        let r2 = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, b.as_mut_ptr()) };
        if r1 != 0 || r2 != 0 {
            println!("clock_monotonic_nondecreasing=ERR:{}", errno());
        } else {
            let a = unsafe { a.assume_init() };
            let b = unsafe { b.assume_init() };
            let nondecreasing = (b.tv_sec, b.tv_nsec) >= (a.tv_sec, a.tv_nsec);
            println!("clock_monotonic_nondecreasing={}", nondecreasing);
        }
    }

    // CLOCK_BOOTTIME >= CLOCK_MONOTONIC: BOOTTIME counts suspend time on top of
    // MONOTONIC, so it is never behind. (Read MONOTONIC first so any elapsed
    // time during the two calls only helps the >= hold.) This invariant holds
    // on Linux and on carrick (which sources MONOTONIC from CLOCK_UPTIME_RAW
    // and BOOTTIME from the sleep-inclusive host CLOCK_MONOTONIC).
    {
        let mut m = MaybeUninit::<libc::timespec>::uninit();
        let mut bt = MaybeUninit::<libc::timespec>::uninit();
        let r1 = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, m.as_mut_ptr()) };
        let r2 = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, bt.as_mut_ptr()) };
        if r1 != 0 || r2 != 0 {
            println!("clock_boottime_ge_monotonic=ERR:{}", errno());
        } else {
            let m = unsafe { m.assume_init() };
            let bt = unsafe { bt.assume_init() };
            let ge = (bt.tv_sec, bt.tv_nsec) >= (m.tv_sec, m.tv_nsec);
            println!("clock_boottime_ge_monotonic={ge}");
        }
    }

    // clock_getres for REALTIME/MONOTONIC: res > 0 and <= 1 second (booleans).
    for (name, id) in [
        ("realtime", libc::CLOCK_REALTIME),
        ("monotonic", libc::CLOCK_MONOTONIC),
    ] {
        let mut res = MaybeUninit::<libc::timespec>::uninit();
        let rc = unsafe { libc::clock_getres(id, res.as_mut_ptr()) };
        if rc != 0 {
            println!("clock_getres_{}=ERR:{}", name, errno());
        } else {
            let res = unsafe { res.assume_init() };
            let positive = res.tv_sec > 0 || res.tv_nsec > 0;
            let at_most_one_sec = res.tv_sec < 1 || (res.tv_sec == 1 && res.tv_nsec == 0);
            println!(
                "clock_getres_{} positive={} le_one_sec={}",
                name, positive, at_most_one_sec
            );
        }
    }

    // nanosleep 1ms: rc==0 and returned without EINTR (boolean). No elapsed.
    {
        let req = libc::timespec { tv_sec: 0, tv_nsec: 1_000_000 };
        let mut rem = MaybeUninit::<libc::timespec>::uninit();
        let rc = unsafe { libc::nanosleep(&req, rem.as_mut_ptr()) };
        if rc != 0 {
            let e = errno();
            println!("nanosleep rc=-1 errno={} no_eintr={}", e, e != libc::EINTR);
        } else {
            println!("nanosleep rc={} no_eintr=true", rc);
        }
    }

    // clock_nanosleep(CLOCK_MONOTONIC, 0, 1ms): print rc.
    {
        let req = libc::timespec { tv_sec: 0, tv_nsec: 1_000_000 };
        let rc = unsafe {
            libc::clock_nanosleep(libc::CLOCK_MONOTONIC, 0, &req, std::ptr::null_mut())
        };
        // clock_nanosleep returns the error number directly (0 on success).
        println!("clock_nanosleep rc={}", rc);
    }

    // gettimeofday: rc and tv_sec>0 (boolean).
    {
        let mut tv = MaybeUninit::<libc::timeval>::uninit();
        let rc = unsafe { libc::gettimeofday(tv.as_mut_ptr(), std::ptr::null_mut()) };
        if rc != 0 {
            println!("gettimeofday=ERR:{}", errno());
        } else {
            let tv = unsafe { tv.assume_init() };
            println!("gettimeofday rc={} sec_positive={}", rc, tv.tv_sec > 0);
        }
    }

    // times(): rc>=0 (boolean). Do NOT print tick values.
    {
        let mut buf = MaybeUninit::<libc::tms>::uninit();
        let rc = unsafe { libc::times(buf.as_mut_ptr()) };
        if rc == -1 {
            println!("times=ERR:{}", errno());
        } else {
            println!("times rc_nonneg={}", rc >= 0);
        }
    }

    // getrusage(RUSAGE_SELF): rc==0 and ru_maxrss >= 0 (boolean). No values.
    {
        let mut ru = MaybeUninit::<libc::rusage>::uninit();
        let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, ru.as_mut_ptr()) };
        if rc != 0 {
            println!("getrusage=ERR:{}", errno());
        } else {
            let ru = unsafe { ru.assume_init() };
            println!("getrusage rc={} maxrss_nonneg={}", rc, ru.ru_maxrss >= 0);
        }
    }

    // time(NULL): result > 1_700_000_000 (fixed past epoch; deterministic).
    {
        let t = unsafe { libc::time(std::ptr::null_mut()) };
        if t == -1 {
            println!("time=ERR:{}", errno());
        } else {
            println!("time_after_2023={}", t > 1_700_000_000);
        }
    }
}

/// Current errno value.
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}
