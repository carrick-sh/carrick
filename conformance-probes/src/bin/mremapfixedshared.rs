//! `mremap(MREMAP_MAYMOVE|MREMAP_FIXED)` of one page inside a `MAP_SHARED`
//! file mapping to a fixed destination inside the same mapping.
//!
//! Stands in for LTP `mremap06` (the vma_merge pgoff reproducer), which
//! TBROKs at its first mremap under carrick.
//!
//! Invariants encoded, all boolean:
//!
//!   * The fixed move of page 1 onto page 3 of a four-page shared file
//!     mapping succeeds and returns the destination address.
//!   * The moved page still shows page 1's file content at the destination
//!     (a shared mapping keeps its file offset when moved).
//!   * A write through the moved page reaches the file at page 1's offset.
//!   * Moving it back with the same flags succeeds.
//!
//! Deterministic output: booleans only.

use conformance_probes::{errno, report};
use std::ffi::CString;

const PAGE: usize = 4096;

fn main() {
    unsafe {
        let path = CString::new("/tmp/mremapfixedshared.dat").unwrap();
        let fd = libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644);
        assert!(fd >= 0, "open errno {}", errno());
        assert_eq!(libc::ftruncate(fd, (4 * PAGE) as libc::off_t), 0);
        let mut page = vec![0u8; PAGE];
        for i in 0..4 {
            page.fill(0x10 + i as u8);
            assert_eq!(libc::pwrite(fd, page.as_ptr().cast(), PAGE, (i * PAGE) as libc::off_t), PAGE as isize);
        }
        let buf = libc::mmap(
            std::ptr::null_mut(),
            4 * PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        ) as *mut u8;
        assert!(buf as isize != -1, "mmap errno {}", errno());

        let dest = buf.add(3 * PAGE);
        let moved = libc::mremap(
            buf.add(PAGE) as *mut libc::c_void,
            PAGE,
            PAGE,
            libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED,
            dest as *mut libc::c_void,
        );
        let fixed_move_ok = moved == dest as *mut libc::c_void;
        let moved_page_keeps_offset = fixed_move_ok && *dest == 0x11;
        let mut write_reaches_file = false;
        let mut move_back_ok = false;
        if fixed_move_ok {
            *dest = 0x77;
            assert_eq!(libc::msync(dest as *mut libc::c_void, PAGE, libc::MS_SYNC), 0);
            let mut b = [0u8; 1];
            libc::pread(fd, b.as_mut_ptr().cast(), 1, PAGE as libc::off_t);
            write_reaches_file = b[0] == 0x77;
            let back = libc::mremap(
                dest as *mut libc::c_void,
                PAGE,
                PAGE,
                libc::MREMAP_MAYMOVE | libc::MREMAP_FIXED,
                buf.add(PAGE) as *mut libc::c_void,
            );
            move_back_ok = back == buf.add(PAGE) as *mut libc::c_void;
        }
        report!(
            fixed_move_within_shared_mapping_ok = fixed_move_ok,
            moved_page_keeps_file_offset = moved_page_keeps_offset,
            write_through_moved_page_reaches_file = write_reaches_file,
            move_back_ok = move_back_ok,
        );
        libc::close(fd);
        libc::unlink(path.as_ptr());
    }
}
