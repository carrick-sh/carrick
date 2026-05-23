//! CPU-count / affinity consistency probe. The Go runtime sizes `GOMAXPROCS`
//! from the bit count returned by `sched_getaffinity`, `nproc` reads the same,
//! and OpenMP/`sysconf(_SC_NPROCESSORS_ONLN)` agree with it on real Linux. A
//! machine with N CPUs reports N consistently across `sched_getaffinity`,
//! `/proc/cpuinfo`, `/proc/stat`, `/sys/devices/system/cpu/online`, and
//! `sysconf` — and `getcpu` returns a CPU index inside that range.
//!
//! Deterministic & machine-independent: the Docker LinuxKit VM and the host
//! Mac have DIFFERENT CPU counts, so the raw number is never printed. Instead
//! every surface is reduced to its agreement with `sched_getaffinity` (an
//! internal-consistency invariant that holds on any correct system whatever N
//! is), plus relationships (`>= 1`, `in range`). carrick must satisfy the same
//! invariants real Linux does.

use std::fs;

fn main() {
    // Source of truth for "how many CPUs does this task see": the set returned
    // by sched_getaffinity, counted via CPU_COUNT. Go counts exactly this.
    let affinity = affinity_count();
    println!("affinity_ge_1={}", affinity >= 1);

    // Differential signal that carrick reports the host's ACTUAL core count,
    // not a hardcoded 1: on a multicore host both Docker and carrick see >1
    // (true == true); on a uniprocessor both see 1 (false == false). Either
    // way they must AGREE — a carrick that hardcodes 1 on a multicore host
    // produces false != true and the harness flags it.
    println!("affinity_gt_1={}", affinity > 1);

    // sysconf(_SC_NPROCESSORS_ONLN): musl derives this from sched_getaffinity,
    // glibc from /sys — either way it must equal the affinity count.
    let onln = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    println!("sysconf_onln_eq_affinity={}", onln == affinity as i64);

    // _SC_NPROCESSORS_CONF (configured) >= online, and >= 1.
    let conf = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_CONF) };
    println!("sysconf_conf_ge_onln={}", conf >= onln && conf >= 1);

    // /proc/cpuinfo: one "processor\t:" block per logical CPU.
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let cpuinfo_n = cpuinfo
        .lines()
        .filter(|l| l.starts_with("processor"))
        .count();
    println!("cpuinfo_eq_affinity={}", cpuinfo_n == affinity);

    // /proc/stat: one "cpuN " line per CPU (in addition to the aggregate "cpu "
    // line). Count lines whose first token is "cpu" immediately followed by a
    // digit.
    let stat = fs::read_to_string("/proc/stat").unwrap_or_default();
    let stat_n = stat
        .lines()
        .filter(|l| {
            l.strip_prefix("cpu")
                .and_then(|r| r.chars().next())
                .is_some_and(|c| c.is_ascii_digit())
        })
        .count();
    println!("procstat_percpu_eq_affinity={}", stat_n == affinity);

    // /sys/devices/system/cpu/online: a range list like "0-9" (or "0" for a
    // single CPU). Its cardinality must equal the affinity count.
    let online = fs::read_to_string("/sys/devices/system/cpu/online").unwrap_or_default();
    let online_n = count_cpu_list(online.trim());
    println!("sysonline_eq_affinity={}", online_n == affinity);

    // getcpu(2): the returned CPU index must be a valid online CPU, i.e. in
    // [0, affinity). The specific index varies run-to-run so is not printed.
    let mut cpu: libc::c_uint = u32::MAX;
    let mut node: libc::c_uint = u32::MAX;
    let rc = unsafe {
        libc::syscall(
            libc::SYS_getcpu,
            &mut cpu as *mut libc::c_uint,
            &mut node as *mut libc::c_uint,
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    println!("getcpu_ok={}", rc == 0);
    println!("getcpu_in_range={}", rc == 0 && (cpu as usize) < affinity);

    // sched_setaffinity(2): setting the affinity to the CURRENT full set must
    // succeed and be observable on read-back (the mask is unchanged). This is
    // the path taskset/numactl/Go's debug paths exercise; carrick honours the
    // requested mask even though Apple Silicon scheduling is advisory.
    {
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let got = unsafe {
            libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set)
        };
        let set_rc = unsafe {
            libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set)
        };
        println!("setaffinity_full_ok={}", got == 0 && set_rc == 0);
        // Read back: still the same count.
        let mut set2: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let got2 = unsafe {
            libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set2)
        };
        let back = unsafe { libc::CPU_COUNT(&set2) } as usize;
        println!("setaffinity_full_roundtrip={}", got2 == 0 && back == affinity);
    }

    // sched_setaffinity with an EMPTY mask is rejected with EINVAL on Linux
    // (a task must be allowed to run on at least one CPU).
    {
        let empty: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &empty)
        };
        let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        println!("setaffinity_empty_einval={}", rc == -1 && err == libc::EINVAL);
    }
}

/// Count CPUs reported by `sched_getaffinity` for the calling task.
fn affinity_count() -> usize {
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let rc =
        unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) };
    if rc != 0 {
        return 0;
    }
    unsafe { libc::CPU_COUNT(&set) as usize }
}

/// Cardinality of a Linux CPU range list such as "0-9", "0", or "0-3,8-9".
fn count_cpu_list(s: &str) -> usize {
    if s.is_empty() {
        return 0;
    }
    let mut total = 0usize;
    for part in s.split(',') {
        if let Some((lo, hi)) = part.split_once('-') {
            if let (Ok(lo), Ok(hi)) = (lo.parse::<usize>(), hi.parse::<usize>()) {
                if hi >= lo {
                    total += hi - lo + 1;
                }
            }
        } else if part.parse::<usize>().is_ok() {
            total += 1;
        }
    }
    total
}
