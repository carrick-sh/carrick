//! Read-side handlers eagerly allocate `vec![0u8; guest_count]` BEFORE bounding
//! the count (no MAX_RW_COUNT clamp; only sendfile caps — dispatch/mod.rs:3665,
//! net.rs:2323, proc.rs:1488, fs.rs:3148). A single read with a huge count
//! makes carrick attempt a terabyte-scale host allocation; the allocator's
//! failure path is handle_alloc_error -> abort(), tearing down the whole
//! runtime. Linux caps the transfer at MAX_RW_COUNT and returns a short count.
//!
//! Crash-class: the read runs in a forked child so the parent can observe how
//! the child terminated (clean short read vs killed). The pipe has 4 bytes, so
//! Linux returns 4 regardless of the absurd count.

use conformance_probes::{errno, reap, report};

// Returns (rc, errno). Linux EFAULTs (the 1<<46 count overflows the user
// address-space range that read's access_ok checks); fixed carrick short-reads
// the 4 available bytes. The INVARIANT is that the runtime SURVIVES either way —
// pre-fix carrick aborted on the eager vec![0u8; 1<<46].
unsafe fn read_huge_from_pipe() -> (i64, i32) {
    let mut fds = [0i32; 2];
    if libc::pipe(fds.as_mut_ptr()) != 0 {
        return (-2, 0);
    }
    let data = b"data";
    libc::write(fds[1], data.as_ptr() as *const libc::c_void, data.len());
    libc::close(fds[1]);
    let mut buf = [0u8; 16];
    let r = libc::read(fds[0], buf.as_mut_ptr() as *mut libc::c_void, 1usize << 46);
    let e = if r < 0 { errno() } else { 0 };
    libc::close(fds[0]);
    (r as i64, e)
}

fn main() {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            let (r, e) = read_huge_from_pipe();
            // A short read (>=0) or EFAULT both mean the runtime handled it
            // without aborting. pre-fix carrick is killed before reaching here.
            let handled = r >= 0 || e == libc::EFAULT;
            libc::_exit(if handled { 0 } else { 2 });
        }
        let (_, status) = reap(pid);
        report!(
            runtime_survived_huge_read = libc::WIFEXITED(status),
            child_not_killed = !libc::WIFSIGNALED(status),
            child_handled_cleanly = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        );
    }
}
