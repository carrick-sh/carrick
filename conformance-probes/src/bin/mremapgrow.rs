//! mremap in-place grow over reclaimed, 4KiB-split-invalidated arena pages.
//!
//! Reproduces the CPython `test_compile` segfault: carrick's mremap "grow in
//! place" fast path (old_end == arena high-water) bumped the allocator top but
//! never RE-VALIDATED the freshly-grown tail's stage-1 leaves. When that tail
//! lands on pages whose leaves were SPLIT to 4 KiB and INVALIDATED by a prior
//! munmap/mprotect (then reclaimed via the high-water roll-back), the guest
//! takes a level-3 translation fault on first write to the grown region —
//! SIGSEGV — where Linux just succeeds. (CPython's obmalloc reallocs an arena
//! buffer in place; the 10k-line compile grew the buffer onto invalidated
//! pages.)
//!
//! Deterministic, allocator-independent trigger: reserve one big window so the
//! whole region is at the arena high-water, then carve R2 (the tail) at the TOP
//! of it with MAP_FIXED, mprotect(PROT_NONE) scattered single pages of R2 to
//! force a 4 KiB split + INVALID leaves IN PLACE, munmap R2 (rolls the
//! high-water back, leaving those split leaves invalid), then mremap-grow R1 (at
//! the bottom of the window) in place so its new tail covers exactly R2's
//! reclaimed, still-invalid pages. Touch every page of the grown R1.
//!
//! Deterministic: booleans only. A faulting page kills the process before the
//! result prints — that absence IS the failure under a broken carrick.

use std::ptr;

const PAGE: usize = 4096;

fn touch_all(p: *mut u8, len: usize) -> bool {
    let mut off = 0usize;
    while off < len {
        unsafe {
            ptr::write_volatile(
                p.add(off) as *mut u64,
                0xA5A5_0000_u64 | (off as u64 & 0xffff),
            );
        }
        off += PAGE;
    }
    off = 0;
    let mut ok = true;
    while off < len {
        unsafe {
            if ptr::read_volatile(p.add(off) as *const u64)
                != (0xA5A5_0000_u64 | (off as u64 & 0xffff))
            {
                ok = false;
            }
        }
        off += PAGE;
    }
    ok
}

fn main() {
    let r1_len = 4 * PAGE;
    let r2_len = 60 * PAGE;
    let win = r1_len + r2_len;

    // Reserve the whole window in one shot (PROT_NONE) so it sits at the arena
    // high-water and we own the exact VA range; then MAP_FIXED-carve R1 and R2.
    let win_base = unsafe {
        libc::mmap(
            ptr::null_mut(),
            win,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    let win_ok = win_base != libc::MAP_FAILED;
    if !win_ok {
        println!("win_ok=false");
        return;
    }

    // R1 = bottom of window, RW.
    let r1 = unsafe {
        libc::mmap(
            win_base,
            r1_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1,
            0,
        )
    };
    let r1_ok = r1 == win_base;
    if r1_ok {
        unsafe { ptr::write_volatile(r1 as *mut u64, 0x1234_5678) };
    }

    // R2 = top of window (immediately above R1), RW.
    let r2_addr = unsafe { (win_base as *mut u8).add(r1_len) as *mut libc::c_void };
    let r2 = unsafe {
        libc::mmap(
            r2_addr,
            r2_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1,
            0,
        )
    };
    let r2_ok = r2 == r2_addr;

    // Split + INVALIDATE R2's leaves at 4 KiB granularity (scattered single
    // pages, unaligned), then free R2 so the high-water rolls back to R1_end.
    if r2_ok {
        let mut i = 1usize;
        while i < 60 {
            unsafe {
                libc::mprotect(
                    (r2 as *mut u8).add(i * PAGE) as *mut libc::c_void,
                    PAGE,
                    libc::PROT_NONE,
                );
            }
            i += 2;
        }
        unsafe { libc::munmap(r2, r2_len) };
    }

    // Grow R1 in place into R2's reclaimed range. old_end(R1) == high-water, so
    // carrick takes the in-place fast path; the new tail covers R2's invalid
    // pages. A broken carrick faults here on the first write in touch_all.
    let np = unsafe { libc::mremap(r1, r1_len, win, libc::MREMAP_MAYMOVE) };
    let mremap_ok = np != libc::MAP_FAILED;
    let in_place = mremap_ok && np == r1;

    let preserved = mremap_ok && unsafe { ptr::read_volatile(np as *const u64) } == 0x1234_5678;
    let tail_usable = mremap_ok && touch_all(np as *mut u8, win);

    println!("win_ok={win_ok}");
    println!("r1_ok={r1_ok}");
    println!("r2_ok={r2_ok}");
    println!("mremap_ok={mremap_ok}");
    println!("in_place={in_place}");
    println!("preserved={preserved}");
    println!("tail_usable={tail_usable}");
}
