//! Minimal reducer for the bhyve/x86 "stale window after munmap" corruption.
//!
//! Hypothesis: the bhyve backend never removes a VA→GPA *window* on `munmap`
//! (it only clears the leaf via `protect_range(0)`). A later `mmap` that reuses
//! the same VA therefore resolves to the stale window's old GPA — returning the
//! OLD bytes instead of a fresh zero-filled page. On a real kernel (and on the
//! KVM/HVF host-mmap backends) a reused anon VA is always zero-filled.
//!
//! Test: map an anon region, stamp it 0xAB, munmap it, then map again at the
//! SAME VA with MAP_FIXED (forcing reuse). A correct kernel yields 0x00; the
//! stale window bug yields 0xAB.
//!
//! IMPORTANT: this probe deliberately avoids the heap and stdio (`println!`,
//! `report!`) because the very bug under test corrupts/zeroes heap-backed output
//! buffers. It signals purely via a raw `write(2)` of a `.rodata` string and the
//! process EXIT CODE, both of which are heap- and stdio-free:
//!   exit 0  + "mmapreuse=CLEAN\n"  -> reused VA was correctly zero-filled
//!   exit 42 + "mmapreuse=STALE\n"  -> reused VA returned stale (non-zero) bytes
//!   exit 43 + "mmapreuse=ERR\n"    -> mmap/munmap setup failed

use std::os::raw::c_void;

const LEN: usize = 256 * 1024; // 64 pages — exercises demand-commit across pages

fn emit(s: &'static str) {
    unsafe {
        libc::write(1, s.as_ptr() as *const c_void, s.len());
    }
}

fn main() {
    let code = unsafe { run() };
    unsafe { libc::_exit(code) };
}

unsafe fn run() -> i32 {
    // 1) First mapping — kernel picks the address.
    let a = libc::mmap(
        std::ptr::null_mut(),
        LEN,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if a == libc::MAP_FAILED {
        emit("mmapreuse=ERR\n");
        return 43;
    }
    // Stamp every byte with a non-zero sentinel.
    std::ptr::write_bytes(a as *mut u8, 0xAB, LEN);

    // 2) Free it.
    if libc::munmap(a, LEN) != 0 {
        emit("mmapreuse=ERR\n");
        return 43;
    }

    // 3) Remap at the SAME address with MAP_FIXED, forcing VA reuse.
    let b = libc::mmap(
        a,
        LEN,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
        -1,
        0,
    );
    if b == libc::MAP_FAILED {
        emit("mmapreuse=ERR\n");
        return 43;
    }

    // 4) A fresh anon page MUST read back as zero. Scan every page.
    let mut off = 0usize;
    let mut stale = false;
    while off < LEN {
        if *((b as *const u8).add(off)) != 0 {
            stale = true;
            break;
        }
        off += 4096;
    }

    if stale {
        emit("mmapreuse=STALE\n");
        42
    } else {
        emit("mmapreuse=CLEAN\n");
        0
    }
}
