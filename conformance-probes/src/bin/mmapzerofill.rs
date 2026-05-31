//! `mmap(MAP_ANONYMOUS)` must ALWAYS return zero-filled pages — even when the
//! returned range reuses address space a prior `munmap` reclaimed. carrick's
//! anon-mmap arena is a bump allocator that skips the zero-fill on the bump path
//! because it assumes `[mmap_next, ...)` is pristine guest RAM. `munmap` of the
//! TOP allocation LOWERS `mmap_next` back over pages the guest already dirtied;
//! a later bump allocation then handed those STALE bytes back instead of zeros.
//!
//! Real Linux always zeros anonymous pages. The CPython test_subprocess SEGV
//! (pymalloc built objects on 'x'-filled stderr-buffer pages it got back from a
//! post-munmap mmap, then dereferenced a 0x7878787878787878 pointer) was exactly
//! this. INVARIANT: after fill+munmap+remap, the remapped region reads as zero.

use conformance_probes::report;

const LEN: usize = 4 * 1024 * 1024; // 4 MiB — large enough to be its own arena
// region and exercise the bump-then-reclaim
// path rather than a small-object pool.

/// Map LEN anon bytes, fill with 0xNN, then unmap. Returns the mapping address
/// (so the caller can confirm reuse) or 0 on failure.
unsafe fn map_fill_unmap(fill: u8) -> usize {
    let p = libc::mmap(
        core::ptr::null_mut(),
        LEN,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if p == libc::MAP_FAILED {
        return 0;
    }
    core::ptr::write_bytes(p as *mut u8, fill, LEN);
    if libc::munmap(p, LEN) != 0 {
        return 0;
    }
    p as usize
}

fn main() {
    unsafe {
        // First mapping: fill with 'x' (0x78) and unmap. This dirties the arena
        // pages and (on carrick) lowers the bump cursor back over them.
        let first = map_fill_unmap(0x78);

        // Second mapping of the same size: a fresh anonymous mapping. Linux
        // guarantees it is zero-filled; the bug returned the stale 'x' bytes.
        let p = libc::mmap(
            core::ptr::null_mut(),
            LEN,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        let mapped_ok = p != libc::MAP_FAILED;

        // Scan the whole second mapping: every byte MUST be zero.
        let mut all_zero = mapped_ok;
        let mut saw_stale_x = false;
        if mapped_ok {
            let s = core::slice::from_raw_parts(p as *const u8, LEN);
            for &b in s {
                if b != 0 {
                    all_zero = false;
                    if b == 0x78 {
                        saw_stale_x = true;
                    }
                    break;
                }
            }
            // Reuse confirmation is incidental (allocators may or may not reuse);
            // the load-bearing invariant is the zero-fill, asserted above.
            let _reused_same_addr = first != 0 && (p as usize) == first;
            libc::munmap(p, LEN);
        }

        report!(
            second_mmap_ok = mapped_ok,
            anon_mmap_is_zero_filled = all_zero,
            no_stale_bytes_leaked = !saw_stale_x,
        );
    }
}
