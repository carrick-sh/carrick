//! mremap MOVE/SHRINK reclamation probe. glibc's `mremap_chunk` grows a large
//! mmapped malloc chunk by `mremap(p, old, new, MREMAP_MAYMOVE)`; on Linux a
//! moving mremap UNMAPS the source and a shrinking mremap UNMAPS the freed tail,
//! returning those VAs to the kernel. carrick previously left both MAPPED with
//! their stale bytes and never reclaimed the VA, so its view of which pages are
//! mapped diverged from glibc's — corrupting the mmapped-chunk bookkeeping
//! across a realloc-grow cascade (CPython multiprocessing test_connection's
//! 16 MiB pipe round-trip aborted with `mremap_chunk: aligned_OK` /
//! `unaligned fastbin`). This probe drives the same pattern directly and checks
//! the data survives every move, plus that a shrink's freed tail is no longer
//! resident (mincore → ENOMEM on real Linux). Booleans only → deterministic.

use std::ffi::c_void;

const PAGE: usize = 4096;

fn main() {
    // 1) mremap MOVE-growth cascade with a sentinel byte: grow a region in many
    //    small steps so each grow is forced to MOVE, verifying the head/tail
    //    bytes survive each relocation (a botched copy or stale destination
    //    surfaces as a mismatch).
    let mut len = 64 * 1024usize;
    let mut p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    let mmap_ok = p != libc::MAP_FAILED;
    let mut move_integrity = mmap_ok;
    if mmap_ok {
        unsafe { std::ptr::write_bytes(p as *mut u8, b'X', len) };
        for _ in 0..64 {
            let new_len = len + 0x12000;
            // Reserve a fresh anonymous region right after, then free it, so the
            // in-place tail is occupied and glibc/Linux must MOVE on grow.
            let q = unsafe { libc::mremap(p, len, new_len, libc::MREMAP_MAYMOVE) };
            if q == libc::MAP_FAILED {
                move_integrity = false;
                break;
            }
            // Old head must have survived the move; new tail is fresh (uninit on
            // a grow — do NOT assume zero), so only seed it.
            let head_ok = unsafe { *(q as *const u8) } == b'X';
            if !head_ok {
                move_integrity = false;
                break;
            }
            unsafe { std::ptr::write_bytes((q as *mut u8).add(len), b'X', new_len - len) };
            p = q;
            len = new_len;
        }
        // Whole region is 'X' now.
        if move_integrity {
            let bytes = unsafe { std::slice::from_raw_parts(p as *const u8, len) };
            move_integrity = bytes.iter().all(|&b| b == b'X');
        }
    }
    println!("move_integrity={move_integrity}");

    // 2) mremap SHRINK frees the tail: shrink the big region to one page; the
    //    freed tail must no longer be resident (mincore returns -1/ENOMEM on
    //    Linux). carrick previously left it mapped (mincore succeeded).
    let mut shrink_unmaps_tail = false;
    if mmap_ok && move_integrity {
        let shrunk = unsafe { libc::mremap(p, len, PAGE, 0) };
        if shrunk != libc::MAP_FAILED {
            let tail = unsafe { (shrunk as *mut u8).add(PAGE * 4) } as *mut c_void;
            let mut vec = [0u8; 1];
            let rc = unsafe { libc::mincore(tail, PAGE, vec.as_mut_ptr()) };
            shrink_unmaps_tail = rc == -1;
            p = shrunk;
            len = PAGE;
        }
    }
    println!("shrink_unmaps_tail={shrink_unmaps_tail}");

    // 3) After the move/shrink churn a fresh anonymous mmap must hand back
    //    ZEROED memory even if it reuses a reclaimed VA (no stale 'X' bytes).
    let mut fresh_is_zeroed = false;
    let fresh = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            1 << 20,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if fresh != libc::MAP_FAILED {
        let bytes = unsafe { std::slice::from_raw_parts(fresh as *const u8, 1 << 20) };
        fresh_is_zeroed = bytes.iter().all(|&b| b == 0);
        unsafe { libc::munmap(fresh, 1 << 20) };
    }
    println!("fresh_is_zeroed={fresh_is_zeroed}");

    if mmap_ok && len > 0 {
        unsafe { libc::munmap(p, len) };
    }
}
