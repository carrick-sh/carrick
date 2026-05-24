//! System-wide host facts that are invariant for the life of the process and
//! shared by every guest thread — chiefly the Linux-visible CPU count. These
//! back the Linux surfaces that report "how many CPUs does this machine have"
//! (`sched_getaffinity`, `getcpu`, `/proc/cpuinfo`, `/proc/stat`,
//! `/sys/devices/system/cpu/*`, `/proc/<pid>/status` `Cpus_allowed`). Following
//! the project's "Darwin kernel as source of truth" principle, the count comes
//! from host kernel `sysctl` state rather than a hardcoded 1. On Apple Silicon,
//! prefer the performance-cluster logical count (`hw.perflevel0.logicalcpu`)
//! over total logical CPUs: Carrick runs one host HVF vCPU thread per guest
//! thread and does not yet provide a guest CPU scheduler, so exposing the
//! conservative vCPU capacity is a safer Linux affinity surface than
//! advertising every hardware thread. `CARRICK_EXPOSED_CPUS` can override this
//! for differential runs.
//!
//! The value cannot change while we run (macOS does not hot-unplug logical
//! CPUs from a live process's perspective), so it is read once and cached.

use std::sync::OnceLock;

static LOGICAL_CPUS: OnceLock<usize> = OnceLock::new();

/// Number of logical CPUs Carrick exposes to Linux guests, clamped to `[1, 1024]`.
///
/// 1024 is the number of CPUs a default Linux `cpu_set_t` (128 bytes) can
/// represent; clamping there keeps every bitmask surface within the ABI's
/// fixed-size buffers without truncation surprises. The query is Darwin-backed
/// where available, with `available_parallelism` as the final fallback so the
/// function is always defined.
pub fn logical_cpu_count() -> usize {
    *LOGICAL_CPUS.get_or_init(|| query_logical_cpus().clamp(1, 1024))
}

#[cfg(target_os = "macos")]
fn query_logical_cpus() -> usize {
    if let Some(n) = env_exposed_cpus() {
        return n;
    }
    let host_logical = sysctl_u32("hw.logicalcpu")
        .filter(|n| *n >= 1)
        .or_else(|| sysctl_u32("hw.ncpu").filter(|n| *n >= 1))
        .map(|n| n as usize);
    let performance_logical = sysctl_u32("hw.perflevel0.logicalcpu")
        .filter(|n| *n >= 1)
        .map(|n| n as usize);
    select_exposed_cpu_count(
        performance_logical,
        host_logical,
        available_parallelism_count(),
    )
}

#[cfg(not(target_os = "macos"))]
fn query_logical_cpus() -> usize {
    if let Some(n) = env_exposed_cpus() {
        return n;
    }
    available_parallelism_count()
}

fn available_parallelism_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

fn env_exposed_cpus() -> Option<usize> {
    let raw = std::env::var("CARRICK_EXPOSED_CPUS").ok()?;
    raw.parse::<usize>().ok().filter(|n| *n >= 1)
}

fn select_exposed_cpu_count(
    performance_logical: Option<usize>,
    host_logical: Option<usize>,
    fallback: usize,
) -> usize {
    match (performance_logical, host_logical) {
        (Some(perf), Some(host)) => perf.min(host).max(1),
        (Some(perf), None) => perf.max(1),
        (None, Some(host)) => host.max(1),
        (None, None) => fallback.max(1),
    }
}

/// Read an integer `sysctl` by name into a `u32`. `None` on any failure.
#[cfg(target_os = "macos")]
fn sysctl_u32(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut value: u32 = 0;
    let mut len = std::mem::size_of::<u32>();
    // SAFETY: `sysctlbyname` writes at most `len` bytes into `value`; we pass a
    // matching size and a valid pointer. `name` is a NUL-terminated C string.
    let rc = unsafe {
        libc::sysctlbyname(
            cname.as_ptr(),
            &mut value as *mut u32 as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc == 0 && len == std::mem::size_of::<u32>() {
        Some(value)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_cpu_count_is_sane() {
        let n = logical_cpu_count();
        assert!((1..=1024).contains(&n), "cpu count {n} out of range");
    }

    #[test]
    fn logical_cpu_count_is_cached_stable() {
        // Two reads must agree (OnceLock); also guards against the clamp
        // accidentally producing 0.
        assert_eq!(logical_cpu_count(), logical_cpu_count());
        assert!(logical_cpu_count() >= 1);
    }

    #[test]
    fn exposed_cpu_selection_prefers_performance_level_when_present() {
        assert_eq!(select_exposed_cpu_count(Some(4), Some(10), 10), 4);
        assert_eq!(select_exposed_cpu_count(Some(12), Some(10), 10), 10);
    }

    #[test]
    fn exposed_cpu_selection_falls_back_without_performance_level() {
        assert_eq!(select_exposed_cpu_count(None, Some(10), 4), 10);
        assert_eq!(select_exposed_cpu_count(None, None, 6), 6);
        assert_eq!(select_exposed_cpu_count(Some(0), Some(0), 0), 1);
    }
}
