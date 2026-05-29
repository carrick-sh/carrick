//! MAP_FIXED|MAP_PRIVATE must be genuinely private. A child that MAP_FIXED-
//! replaces a shared page with a private mapping and writes to it must NOT
//! affect the parent. carrick accepts MAP_FIXED at any page-aligned address and
//! its syscall write path goes through to the existing backing without honoring
//! MAP_PRIVATE/placement (write_guest_bytes ignores perms; next_mmap_address
//! trusts the address — mem.rs:81), so a child's "private" write can corrupt
//! the parent's shared page. Run under `--fs host`. Cross-fork sentinel.

use conformance_probes::report;

fn main() {
    unsafe {
        let len = 4096;
        let p = libc::mmap(
            core::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if p == libc::MAP_FAILED {
            report!(setup_ok = false);
            return;
        }
        let cell = p as *mut u8;
        *cell = 0xAA; // parent sentinel into the (fork-shared) page

        let mut fds = [0i32; 2];
        libc::pipe(fds.as_mut_ptr());
        let pid = libc::fork();
        if pid == 0 {
            // Replace the mapping at p with a PRIVATE anon page, then write.
            let q = libc::mmap(
                p,
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            let fixed_ok = q == p;
            if fixed_ok {
                *(p as *mut u8) = 0xBB;
            }
            let b = [fixed_ok as u8];
            libc::write(fds[1], b.as_ptr() as *const libc::c_void, 1);
            libc::_exit(0);
        }
        libc::close(fds[1]);
        let mut b = [0u8; 1];
        libc::read(fds[0], b.as_mut_ptr() as *mut libc::c_void, 1);
        let mut st = 0;
        while libc::wait4(pid, &mut st, 0, core::ptr::null_mut()) < 0 {}
        let parent_val = *cell;
        report!(
            setup_ok = true,
            child_map_fixed_ok = b[0] != 0,
            // Linux: true (child's private write stayed in the child).
            parent_value_preserved = parent_val == 0xAA,
            // carrick (bug): true (child write leaked through to the parent).
            parent_clobbered_by_child = parent_val == 0xBB,
        );
    }
}
