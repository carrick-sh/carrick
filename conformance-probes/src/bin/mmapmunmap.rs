//! mmap/munmap errno + behavioral conformance (LTP mmap08, munmap01, munmap02):
//!  - mmap() on a closed fd for a file mapping fails with EBADF (carrick gave
//!    EINVAL); LTP mmap08.
//!  - munmap() of a validly-mapped region (MAP_SHARED file, then MAP_PRIVATE
//!    file) returns success — carrick treated the MAP_SHARED file mapping (a
//!    high-VA alias) as out-of-range and returned EINVAL; LTP munmap01/02.
//! Deterministic booleans, diffed line-exact carrick-vs-Linux. Needs `--fs
//! host` so the MAP_SHARED file leg engages the real host page cache.

use conformance_probes::errno;

fn main() {
    unsafe {
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        libc::mkdir(b"/tmp\0".as_ptr() as *const _, 0o777);
        let path = b"/tmp/mm\0".as_ptr() as *const libc::c_char;

        // --- mmap08: a file mapping on a CLOSED fd → EBADF (not EINVAL).
        // mmap08 leaves page_sz==0, so length is 0: Linux's ksys_mmap_pgoff
        // does fget(fd) (→ EBADF) BEFORE do_mmap's len==0 (→ EINVAL), so the
        // bad fd wins. carrick validated length first → wrongly gave EINVAL.
        let bad = {
            let fd = libc::open(path, libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644);
            libc::ftruncate(fd, page as i64);
            libc::close(fd); // fd is now an invalid descriptor
            fd
        };
        let a = libc::mmap(
            core::ptr::null_mut(),
            0, // mmap08: page_sz never initialised
            libc::PROT_WRITE,
            libc::MAP_FILE | libc::MAP_SHARED,
            bad,
            0,
        );
        println!("mmap_badfd_len0_fails={}", a == libc::MAP_FAILED);
        println!(
            "mmap_badfd_len0_ebadf={}",
            a == libc::MAP_FAILED && errno() == libc::EBADF
        );

        // ordering check: a VALID fd with length 0 → EINVAL (fd ok, do_mmap
        // rejects the zero length). Confirms EBADF is fd-specific, not blanket.
        let vfd = libc::open(path, libc::O_RDWR | libc::O_CREAT, 0o644);
        libc::ftruncate(vfd, page as i64);
        let z = libc::mmap(
            core::ptr::null_mut(),
            0,
            libc::PROT_WRITE,
            libc::MAP_FILE | libc::MAP_SHARED,
            vfd,
            0,
        );
        println!(
            "mmap_validfd_len0_einval={}",
            z == libc::MAP_FAILED && errno() == libc::EINVAL
        );
        libc::close(vfd);

        // --- munmap01: MAP_SHARED file mapping, unmap the whole region → ok ---
        let fd = libc::open(path, libc::O_RDWR | libc::O_CREAT, 0o644);
        libc::ftruncate(fd, page as i64);
        let s = libc::mmap(
            core::ptr::null_mut(),
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        );
        println!("mmap_shared_ok={}", s != libc::MAP_FAILED);
        let u1 = if s != libc::MAP_FAILED {
            libc::munmap(s, page)
        } else {
            -1
        };
        println!("munmap_shared_ok={}", u1 == 0);

        // --- munmap02: MAP_PRIVATE file mapping, unmap → ok ---
        let p = libc::mmap(
            core::ptr::null_mut(),
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE,
            fd,
            0,
        );
        println!("mmap_private_ok={}", p != libc::MAP_FAILED);
        let u2 = if p != libc::MAP_FAILED {
            libc::munmap(p, page)
        } else {
            -1
        };
        println!("munmap_private_ok={}", u2 == 0);

        // munmap of an unaligned address → EINVAL (oracle-agreed edge kept intact)
        let u3 = libc::munmap((page + 1) as *mut libc::c_void, page);
        println!("munmap_unaligned_einval={}", u3 == -1 && errno() == libc::EINVAL);

        libc::close(fd);
        let _ = errno;
    }
}
