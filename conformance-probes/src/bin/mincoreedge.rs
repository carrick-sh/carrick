//! mincore edge errno probe. Linux distinguishes an invalid residency-vector
//! pointer (EFAULT) from an address range that is not fully mapped (ENOMEM).
//! Carrick's handler used to check only the first and last page of the input
//! range and then blindly report success, which let mapped-hole ranges pass.

use conformance_probes::{errno, report};
use std::ffi::c_void;

fn linux_page_size() -> Option<usize> {
    let raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(raw)
        .ok()
        .filter(|page| page.is_power_of_two() && *page <= usize::MAX / 3)
}

fn mincore_errno(addr: *mut c_void, len: usize, vec: *mut u8) -> i32 {
    unsafe {
        let rc = libc::mincore(addr, len, vec);
        if rc == 0 { 0 } else { errno() }
    }
}

fn main() {
    let Some(page_size) = linux_page_size() else {
        report!(invalid_vec_errno = -1, hole_errno = -1);
        return;
    };
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    let invalid_vec_errno = if p == libc::MAP_FAILED {
        -1
    } else {
        mincore_errno(p, page_size, std::ptr::null_mut())
    };
    if p != libc::MAP_FAILED {
        unsafe {
            libc::munmap(p, page_size);
        }
    }

    let q = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page_size * 3,
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
            libc::munmap((q as *mut u8).add(page_size) as *mut c_void, page_size);
        }
        let mut vec = [0u8; 3];
        let err = mincore_errno(q, page_size * 3, vec.as_mut_ptr());
        unsafe {
            libc::munmap(q, page_size);
            libc::munmap((q as *mut u8).add(page_size * 2) as *mut c_void, page_size);
        }
        err
    };

    report!(
        invalid_vec_errno = invalid_vec_errno,
        hole_errno = hole_errno,
    );
}
