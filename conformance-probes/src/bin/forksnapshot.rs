//! fork(2) must snapshot private guest memory.
//!
//! The child blocks until the parent mutates a stack slot after fork. Linux
//! fork gives the child the pre-fork value; a shared guest-RAM implementation
//! leaks the parent's later write into the child.

use conformance_probes::{pipe2, reap, report};

unsafe fn child_observes_after_parent_write(slot: *mut i32, parent_value: i32) -> Option<i32> {
    let (ready_r, ready_w) = pipe2();
    let (result_r, result_w) = pipe2();
    let pid = libc::fork();
    if pid == 0 {
        libc::close(ready_w);
        libc::close(result_r);
        let mut byte = 0u8;
        let _ = libc::read(ready_r, (&mut byte as *mut u8).cast(), 1);
        let observed = core::ptr::read_volatile(slot);
        let _ = libc::write(
            result_w,
            (&observed as *const i32).cast(),
            core::mem::size_of::<i32>(),
        );
        libc::_exit(0);
    }

    libc::close(ready_r);
    libc::close(result_w);
    core::ptr::write_volatile(slot, parent_value);
    let byte = 1u8;
    let _ = libc::write(ready_w, (&byte as *const u8).cast(), 1);
    libc::close(ready_w);

    let mut observed = 0i32;
    let got = libc::read(
        result_r,
        (&mut observed as *mut i32).cast(),
        core::mem::size_of::<i32>(),
    );
    let (_, status) = reap(pid);
    (got == core::mem::size_of::<i32>() as isize
        && libc::WIFEXITED(status)
        && libc::WEXITSTATUS(status) == 0)
        .then_some(observed)
}

fn main() {
    unsafe {
        let mut slot = 1i32;
        let stack_observed = child_observes_after_parent_write(&mut slot, 2);

        let page = libc::mmap(
            core::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        ) as *mut i32;
        let mmap_observed = if page == libc::MAP_FAILED.cast() {
            None
        } else {
            core::ptr::write_volatile(page, 1);
            let observed = child_observes_after_parent_write(page, 2);
            let _ = libc::munmap(page.cast(), 4096);
            observed
        };

        report!(
            fork_private_stack_snapshot = stack_observed == Some(1),
            fork_private_mmap_snapshot = mmap_observed == Some(1),
        );
    }
}
