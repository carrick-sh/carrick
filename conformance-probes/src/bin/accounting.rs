//! CPU-time + memory accounting probe. After burning a measurable amount of
//! CPU, a correct kernel reports non-zero usage through getrusage(2), times(2),
//! /proc/self/statm and /proc/self/status. carrick now sources these from the
//! Darwin kernel (proc_pid_rusage / task_info / thread_info) instead of
//! emitting zeros.
//!
//! Deterministic-by-design: absolute times/sizes vary per machine and are
//! NEVER printed. Each observation is reduced to a boolean ("> 0 after doing
//! work", "monotonic non-decreasing", "self-consistent") that holds on any
//! correct system.

/// Burn a FIXED amount of user CPU (no wall-clock dependency — the clock is
/// part of what we're testing). `iters` is sized so the accrued user time
/// clears times(2)'s 10 ms tick granularity on both Docker and carrick.
/// Volatile accumulation defeats dead-code elimination. (Pure arithmetic only:
/// a large random-access memory loop is fine on Linux but pathologically slow
/// under carrick's fault-per-access guest memory, which would measure the
/// emulator rather than the syscall.)
fn burn_cpu(iters: u64) -> u64 {
    let mut acc: u64 = 1;
    for _ in 0..iters {
        acc = acc.wrapping_mul(6364136223846793005).wrapping_add(1);
        acc ^= acc >> 17;
    }
    acc
}

fn rusage_cpu_us(who: libc::c_int) -> Option<(u64, u64)> {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(who, &mut ru) } != 0 {
        return None;
    }
    let us = |t: libc::timeval| t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64;
    Some((us(ru.ru_utime), us(ru.ru_stime)))
}

fn main() {
    std::hint::black_box(burn_cpu(80_000_000));

    // getrusage(RUSAGE_SELF): user+system CPU time must be > 0 after the burn,
    // and ru_maxrss must be > 0.
    {
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
        let cpu = rusage_cpu_us(libc::RUSAGE_SELF).unwrap_or((0, 0));
        println!("getrusage_self_ok={}", rc == 0);
        println!("getrusage_self_cpu_pos={}", cpu.0 + cpu.1 > 0);
        println!("getrusage_self_maxrss_pos={}", ru.ru_maxrss > 0);
    }

    // getrusage(RUSAGE_THREAD): this thread did the work, so its CPU > 0.
    {
        let cpu = rusage_cpu_us(libc::RUSAGE_THREAD).unwrap_or((0, 0));
        println!("getrusage_thread_cpu_pos={}", cpu.0 + cpu.1 > 0);
    }

    // times(2): tms_utime+tms_stime > 0, and a second sampling after more work
    // is monotonic non-decreasing.
    {
        let mut t1: libc::tms = unsafe { std::mem::zeroed() };
        let r1 = unsafe { libc::times(&mut t1) };
        std::hint::black_box(burn_cpu(40_000_000));
        let mut t2: libc::tms = unsafe { std::mem::zeroed() };
        let r2 = unsafe { libc::times(&mut t2) };
        println!("times_ok={}", r1 != -1 && r2 != -1);
        println!("times_cpu_pos={}", t2.tms_utime + t2.tms_stime > 0);
        println!(
            "times_monotonic={}",
            t2.tms_utime >= t1.tms_utime && t2.tms_stime >= t1.tms_stime
        );
    }

    // /proc/self/statm: size (vsize) and resident (RSS) in pages, both > 0.
    {
        let s = std::fs::read_to_string("/proc/self/statm").unwrap_or_default();
        let fields: Vec<u64> = s
            .split_whitespace()
            .filter_map(|f| f.parse().ok())
            .collect();
        let size = fields.first().copied().unwrap_or(0);
        let resident = fields.get(1).copied().unwrap_or(0);
        println!("statm_size_pos={}", size > 0);
        println!("statm_resident_pos={}", resident > 0);
        println!("statm_resident_le_size={}", resident <= size);
    }

    // /proc/self/status: VmSize and VmRSS in kB, both > 0, RSS <= Size.
    {
        let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let kb = |key: &str| -> u64 {
            s.lines()
                .find(|l| l.starts_with(key))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
                .unwrap_or(0)
        };
        let vmsize = kb("VmSize:");
        let vmrss = kb("VmRSS:");
        println!("status_vmsize_pos={}", vmsize > 0);
        println!("status_vmrss_pos={}", vmrss > 0);
        println!("status_vmrss_le_vmsize={}", vmrss <= vmsize);
    }
}
