//! mincore edge errno probe. Linux distinguishes an invalid residency-vector
//! pointer (EFAULT) from an address range that is not fully mapped (ENOMEM).
//! Carrick's handler used to check only the first and last page of the input
//! range and then blindly report success, which let mapped-hole ranges pass.

use conformance_probes::{errno, report};
use std::ffi::c_void;

const PAGE: usize = 4096;

fn mincore_errno(addr: *mut c_void, len: usize, vec: *mut u8) -> i32 {
    unsafe {
        let rc = libc::mincore(addr, len, vec);
        if rc == 0 { 0 } else { errno() }
    }
}

fn main() {
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    let invalid_vec_errno = if p == libc::MAP_FAILED {
        -1
    } else {
        mincore_errno(p, PAGE, std::ptr::null_mut())
    };
    if p != libc::MAP_FAILED {
        unsafe {
            libc::munmap(p, PAGE);
        }
    }

    let q = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            PAGE * 3,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    let hole_errno = if q == libc::MAP_FAILED {
        -1
    } else {
        unsafe {
            libc::munmap((q as *mut u8).add(PAGE) as *mut c_void, PAGE);
        }
        let mut vec = [0u8; 3];
        let err = mincore_errno(q, PAGE * 3, vec.as_mut_ptr());
        unsafe {
            libc::munmap(q, PAGE);
            libc::munmap((q as *mut u8).add(PAGE * 2) as *mut c_void, PAGE);
        }
        err
    };

    report!(
        invalid_vec_errno = invalid_vec_errno,
        hole_errno = hole_errno,
    );
}
