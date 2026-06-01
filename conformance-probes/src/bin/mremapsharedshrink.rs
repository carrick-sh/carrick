//! `mremap` must shrink a MAP_SHARED mapping (file-backed OR anonymous) in
//! place. CPython's `mmap.resize(smaller)` does exactly this:
//! `test_mmap.test_basic` resizes a MAP_SHARED FILE mapping down and
//! `test_resize_past_pos` resizes a MAP_SHARED ANONYMOUS `mmap.mmap(-1, n)`
//! down. The test only tolerates success or SystemError — never the OSError
//! (EINVAL) carrick used to raise.
//!
//! carrick backs a MAP_SHARED file mmap with a high-VA host alias and a
//! MAP_SHARED anonymous mmap with a shared-aperture region; neither lives in the
//! mmap arena, so mremap's arena range-check rejected both with EINVAL. A
//! resize-DOWN keeps the backing at its address with a smaller logical size and
//! must just succeed. (Distinct from `mremapshrink`, which covers the arena
//! MAP_PRIVATE|ANON path and additionally asserts the freed tail is unmapped.)
//!
//! INVARIANT: shrinking either MAP_SHARED mapping via mremap returns a valid
//! address whose surviving prefix is still readable.

use conformance_probes::report;

fn main() {
    unsafe {
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let big = page * 2;

        // (a) MAP_SHARED file mapping, shrunk to one page.
        let path = c"/tmp/mremapsharedshrink.bin";
        let fd = libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        let buf = vec![b'Z'; big];
        let _ = libc::write(fd, buf.as_ptr().cast(), big);
        let fp = libc::mmap(
            core::ptr::null_mut(),
            big,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        );
        let mut file_shrink_ok = false;
        let mut file_prefix_ok = false;
        if fp != libc::MAP_FAILED {
            let r = libc::mremap(fp, big, page, libc::MREMAP_MAYMOVE);
            file_shrink_ok = r != libc::MAP_FAILED;
            if file_shrink_ok {
                file_prefix_ok = *(r as *const u8) == b'Z';
                libc::munmap(r, page);
            } else {
                libc::munmap(fp, big);
            }
        }
        libc::close(fd);

        // (b) MAP_SHARED anonymous mapping, shrunk to one page.
        let ap = libc::mmap(
            core::ptr::null_mut(),
            big,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        let mut anon_shrink_ok = false;
        let mut anon_prefix_ok = false;
        if ap != libc::MAP_FAILED {
            *(ap as *mut u8) = 0x5a;
            let r = libc::mremap(ap, big, page, libc::MREMAP_MAYMOVE);
            anon_shrink_ok = r != libc::MAP_FAILED;
            if anon_shrink_ok {
                anon_prefix_ok = *(r as *const u8) == 0x5a;
                libc::munmap(r, page);
            } else {
                libc::munmap(ap, big);
            }
        }

        report!(
            file_shrink_ok = file_shrink_ok,
            file_prefix_readable = file_prefix_ok,
            anon_shared_shrink_ok = anon_shrink_ok,
            anon_prefix_readable = anon_prefix_ok,
        );
    }
}
