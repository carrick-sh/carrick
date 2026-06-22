//! CPU-count / affinity consistency probe. The Go runtime sizes `GOMAXPROCS`
//! from the bit count returned by `sched_getaffinity`, `nproc` reads the same,
//! and OpenMP/`sysconf(_SC_NPROCESSORS_ONLN)` track CPU availability.
//!
//! Two DISTINCT quantities exist on Linux and must NOT be conflated. The ONLINE
//! TOPOLOGY — `/proc/cpuinfo`, `/proc/stat` per-cpu lines, and
//! `/sys/devices/system/cpu/online` — all report the same physical/online CPU
//! count and AGREE WITH EACH OTHER. The task AFFINITY set —
//! `sched_getaffinity`/`CPU_COUNT` — is what a cpuset cgroup (a `docker run
//! --cpuset-cpus`, Kubernetes, or an outer LXC container) can restrict to a
//! SUBSET of the online set. In a cpuset-restricted container the two differ
//! (e.g. cpuinfo=16, affinity=4), so the earlier `cpuinfo == affinity`
//! assertions were not actually machine-independent — they held only where
//! nothing restricts the cpuset, and diverged from real Linux under a
//! restriction (the x86_64-lane DIFF this fixes).
//!
//! The genuinely universal invariants this asserts: the three online-topology
//! surfaces agree with each other (and are >= 1); the affinity set is non-empty
//! and a subset of the online topology; `getcpu` returns an index inside the
//! online topology; `_SC_NPROCESSORS_CONF >= _SC_NPROCESSORS_ONLN >= 1`, and
//! ONLN lies in `[affinity, online]` (musl derives ONLN from affinity, glibc
//! from /sys — either way it sits between the two); a full-mask setaffinity
//! roundtrips; an empty mask is rejected EINVAL. Raw counts are never printed
//! (the oracle VM and the host differ in N); every line is a relationship, so it
//! diffs byte-exact carrick-vs-Linux on any host.

use std::fs;

fn main() {
    // Affinity set: the CPUs this task may run on (cpuset-restricted subset of
    // the online topology). Go counts exactly this for GOMAXPROCS.
    let affinity = affinity_count();
    println!("affinity_ge_1={}", affinity >= 1);

    // Differential signal that carrick reports the host's ACTUAL core count, not
    // a hardcoded 1: on a multicore host both Docker and carrick see an online
    // topology > 1. Anchored on the online topology (not affinity) so a
    // cpuset-restricted oracle still agrees with carrick.
    let online_n = online_topology();
    println!("online_gt_1={}", online_n > 1);

    // The three online-topology surfaces must agree with EACH OTHER and be >= 1.
    let cpuinfo_n = fs::read_to_string("/proc/cpuinfo")
        .unwrap_or_default()
        .lines()
        .filter(|l| l.starts_with("processor"))
        .count();
    let stat_n = fs::read_to_string("/proc/stat")
        .unwrap_or_default()
        .lines()
        .filter(|l| {
            l.strip_prefix("cpu")
                .and_then(|r| r.chars().next())
                .is_some_and(|c| c.is_ascii_digit())
        })
        .count();
    println!(
        "topology_surfaces_agree={}",
        online_n >= 1 && cpuinfo_n == online_n && stat_n == online_n
    );

    // Affinity is a non-empty SUBSET of the online topology (cpuset may shrink it
    // but never grow it past the online set).
    println!(
        "affinity_subset_of_online={}",
        affinity >= 1 && affinity <= online_n
    );

    // sysconf: CONF (configured) >= ONLN >= 1; and ONLN sits between the affinity
    // count and the online topology (musl → affinity, glibc → /sys online).
    let onln = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) } as usize;
    let conf = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_CONF) } as usize;
    println!("sysconf_conf_ge_onln_ge_1={}", conf >= onln && onln >= 1);
    println!(
        "sysconf_onln_in_affinity_online_range={}",
        onln >= affinity && onln <= online_n
    );

    // getcpu(2): the returned CPU index must be a valid online CPU, i.e. in
    // [0, online_topology). The specific index varies run-to-run so is not printed.
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
    println!("getcpu_in_range={}", rc == 0 && (cpu as usize) < online_n);

    // sched_setaffinity(2): setting the affinity to the CURRENT full set must
    // succeed and be observable on read-back (the mask is unchanged). This is
    // the path taskset/numactl/Go's debug paths exercise; carrick honours the
    // requested mask even though Apple Silicon scheduling is advisory.
    {
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let got =
            unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) };
        let set_rc =
            unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) };
        println!("setaffinity_full_ok={}", got == 0 && set_rc == 0);
        // Read back: still the same count.
        let mut set2: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let got2 = unsafe {
            libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set2)
        };
        let back = unsafe { libc::CPU_COUNT(&set2) } as usize;
        println!(
            "setaffinity_full_roundtrip={}",
            got2 == 0 && back == affinity
        );
    }

    // sched_setaffinity with an EMPTY mask is rejected with EINVAL on Linux
    // (a task must be allowed to run on at least one CPU).
    {
        let empty: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let rc =
            unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &empty) };
        let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        println!(
            "setaffinity_empty_einval={}",
            rc == -1 && err == libc::EINVAL
        );
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

/// The ONLINE CPU topology cardinality, read from
/// `/sys/devices/system/cpu/online` (a range list like "0-15"). This is the
/// physical/online count, NOT the cpuset-restricted affinity set.
fn online_topology() -> usize {
    let online = fs::read_to_string("/sys/devices/system/cpu/online").unwrap_or_default();
    count_cpu_list(online.trim())
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
