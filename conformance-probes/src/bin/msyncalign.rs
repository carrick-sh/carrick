//! `msync(2)` requires a page-aligned start address; a non-page-aligned addr is
//! EINVAL on Linux. CPython's `mmap.flush(offset, size)` maps straight onto
//! `msync(data + offset, size, MS_SYNC)`, so `flush(1, n)` must raise OSError —
//! `test_mmap.test_flush_return_value` asserts exactly that on Linux.
//!
//! carrick's msync handler accepted any address (it looked up the mapping by
//! base and wrote back, ignoring sub-page misalignment), so `flush(1, n)`
//! silently succeeded. INVARIANT: msync with a non-page-aligned address returns
//! EINVAL; with an aligned address it succeeds.

use conformance_probes::report;

fn main() {
    unsafe {
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let len = page * 2;
        let p = libc::mmap(
            core::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if p == libc::MAP_FAILED {
            report!(mmap_ok = false);
            return;
        }

        // Aligned address → success.
        let aligned_rc = libc::msync(p, page, libc::MS_SYNC);

        // Non-page-aligned address (p + 1) → EINVAL, exactly like flush(1, n).
        let unaligned = (p as *mut u8).add(1).cast::<libc::c_void>();
        let unaligned_rc = libc::msync(unaligned, page, libc::MS_SYNC);
        let unaligned_errno = conformance_probes::errno();

        libc::munmap(p, len);

        report!(
            aligned_msync_ok = aligned_rc == 0,
            unaligned_msync_fails = unaligned_rc == -1,
            unaligned_errno_is_einval = unaligned_errno == libc::EINVAL,
        );
    }
}
