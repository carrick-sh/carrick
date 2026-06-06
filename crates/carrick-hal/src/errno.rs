//! Host→Linux errno translation seam.
//!
//! The single hook every host-syscall error site funnels through. The macOS/
//! FreeBSD table (driven off `libc::E*`, not numeric equality) lands in
//! `carrick-bsd::bsd_to_linux_errno`; Linux is identity. Until carrick-bsd is
//! wired (later section), the macOS arm calls the local fallback below so the
//! leaf crate carries no platform dependency.

/// Translate a host errno into its Linux equivalent.
#[cfg(target_os = "linux")]
pub fn host_to_linux_errno(host: i32) -> i32 {
    // Linux host: identity.
    host
}

/// Translate a host errno into its Linux equivalent. The BSD table is owned by
/// `carrick-bsd` and routed in when that crate is wired; until then this is a
/// passthrough placeholder so the signature is fixed and the crate stays a leaf.
#[cfg(not(target_os = "linux"))]
pub fn host_to_linux_errno(host: i32) -> i32 {
    host
}
