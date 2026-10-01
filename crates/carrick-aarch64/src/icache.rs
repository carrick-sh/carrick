//! Instruction-cache maintenance by host address for guest frames.

/// Invalidate the instruction cache for `[host, host + len)`, the host
/// mapping of guest backing (macOS `sys_icache_invalidate`). AArch64
/// instruction caches are physically tagged for this purpose (PoU
/// invalidation by address reaches every view of the physical lines), so
/// invalidating through the host mapping also drops lines the guest fetched
/// through its own translation.
///
/// # Safety
/// `[host, host + len)` must be mapped in the calling process.
#[cfg(target_os = "macos")]
pub unsafe fn invalidate_host_range(host: *mut u8, len: usize) {
    unsafe extern "C" {
        fn sys_icache_invalidate(start: *mut core::ffi::c_void, len: usize);
    }
    // SAFETY: forwarded from the caller.
    unsafe { sys_icache_invalidate(host.cast(), len) };
}
