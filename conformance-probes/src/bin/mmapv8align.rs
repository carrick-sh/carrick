//! V8-style mmap alignment and MADV_DONTFORK probe.
//!
//! Node/V8 reserves slightly more memory than it needs, rounds the returned
//! base up to an alignment boundary, asks the kernel not to inherit the mapping
//! across fork (`MADV_DONTFORK`), then `munmap`s the prefix/suffix. The syscall
//! contract is simple: mmap must never report a low 32-bit sentinel-like value
//! as success, MADV_DONTFORK is an accepted advisory hint, and the unmaps around
//! the aligned allocation must succeed.

use conformance_probes::report;
use core::arch::asm;
use std::ffi::c_void;

const SYS_MUNMAP: u64 = 215;
const SYS_MMAP: u64 = 222;
const SYS_MADVISE: u64 = 233;
const PAGE: usize = 4096;
const SIZE: usize = 0x40000;
const ALIGNMENT: usize = 0x40000;
const REQUEST_SIZE: usize = SIZE + (ALIGNMENT - PAGE);
const MADV_DONTFORK: i32 = 10;

fn align_up(value: usize, alignment: usize) -> usize {
    value.div_ceil(alignment) * alignment
}

unsafe fn syscall3(number: u64, arg0: u64, arg1: u64, arg2: u64) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "svc #0",
            inlateout("x0") arg0 as i64 => ret,
            in("x1") arg1,
            in("x2") arg2,
            in("x8") number,
            clobber_abi("C"),
            options(nostack)
        );
    }
    ret
}

unsafe fn syscall6(
    number: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> i64 {
    let ret: i64;
    unsafe {
        asm!(
            "svc #0",
            inlateout("x0") arg0 as i64 => ret,
            in("x1") arg1,
            in("x2") arg2,
            in("x3") arg3,
            in("x4") arg4,
            in("x5") arg5,
            in("x8") number,
            clobber_abi("C"),
            options(nostack)
        );
    }
    ret
}

fn main() {
    let mut mmap_ok = true;
    let mut no_low32_success = true;
    let mut madv_dontfork_accepted = true;
    let mut prefix_suffix_unmap_ok = true;

    for i in 0..64usize {
        let hint = ((0x2000_0000usize + i * 0x1f00_0000usize) & 0x3fff_fff000usize)
            as *mut c_void;
        let ptr = unsafe {
            syscall6(
                SYS_MMAP,
                hint as u64,
                REQUEST_SIZE as u64,
                (libc::PROT_READ | libc::PROT_WRITE) as u64,
                (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
                (-1_i64) as u64,
                0,
            )
        };
        if ptr < 0 {
            mmap_ok = false;
            continue;
        }
        let base = ptr as usize;
        if base == 0xffff_ffff {
            no_low32_success = false;
        }

        if unsafe { syscall3(SYS_MADVISE, ptr as u64, REQUEST_SIZE as u64, MADV_DONTFORK as u64) }
            != 0
        {
            madv_dontfork_accepted = false;
        }

        let aligned = align_up(base, ALIGNMENT);
        if aligned != base {
            let prefix = aligned - base;
            if unsafe { syscall3(SYS_MUNMAP, ptr as u64, prefix as u64, 0) } != 0 {
                prefix_suffix_unmap_ok = false;
            }
        }
        let remaining = REQUEST_SIZE - (aligned - base);
        if remaining != SIZE {
            let suffix = remaining - SIZE;
            let suffix_ptr = (aligned + SIZE) as *mut c_void;
            if unsafe { syscall3(SYS_MUNMAP, suffix_ptr as u64, suffix as u64, 0) } != 0 {
                prefix_suffix_unmap_ok = false;
            }
        }
        if unsafe { syscall3(SYS_MUNMAP, aligned as u64, SIZE as u64, 0) } != 0 {
            prefix_suffix_unmap_ok = false;
        }
    }

    report!(
        mmap_ok = mmap_ok,
        no_low32_success = no_low32_success,
        madv_dontfork_accepted = madv_dontfork_accepted,
        prefix_suffix_unmap_ok = prefix_suffix_unmap_ok,
    );
}
