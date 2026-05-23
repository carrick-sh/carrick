//! System-wide host facts that are invariant for the life of the process and
//! shared by every guest thread — chiefly the logical CPU count. These back the
//! Linux surfaces that report "how many CPUs does this machine have"
//! (`sched_getaffinity`, `getcpu`, `/proc/cpuinfo`, `/proc/stat`,
//! `/sys/devices/system/cpu/*`, `/proc/<pid>/status` `Cpus_allowed`). Following
//! the project's "Darwin kernel as source of truth" principle, the count comes
//! from the host kernel via `sysctl hw.logicalcpu` rather than a hardcoded 1,
//! so the Go runtime's `GOMAXPROCS` (which counts the bits returned by
//! `sched_getaffinity`), `nproc`, and OpenMP see the real parallelism available.
//!
//! The value cannot change while we run (macOS does not hot-unplug logical
//! CPUs from a live process's perspective), so it is read once and cached.

use std::sync::OnceLock;

static LOGICAL_CPUS: OnceLock<usize> = OnceLock::new();

/// Number of logical CPUs the host kernel reports, clamped to `[1, 1024]`.
///
/// 1024 is the number of CPUs a default Linux `cpu_set_t` (128 bytes) can
/// represent; clamping there keeps every bitmask surface within the ABI's
/// fixed-size buffers without truncation surprises. The query is
/// `sysctl hw.logicalcpu` (the count usable by threads, which is what Linux's
/// "online CPUs" means), with `hw.ncpu` and `available_parallelism` as
/// fallbacks so the function is always defined.
pub fn logical_cpu_count() -> usize {
    *LOGICAL_CPUS.get_or_init(|| query_logical_cpus().clamp(1, 1024))
}

#[cfg(target_os = "macos")]
fn query_logical_cpus() -> usize {
    for name in ["hw.logicalcpu", "hw.ncpu"] {
        if let Some(n) = sysctl_u32(name).filter(|n| *n >= 1) {
            return n as usize;
        }
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

#[cfg(not(target_os = "macos"))]
fn query_logical_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
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
}
