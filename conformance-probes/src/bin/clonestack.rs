//! Fork-like `clone(2)` with an explicit CHILD STACK (LTP clone01/06/07): the
//! kernel starts the child at the same PC with SP = the caller-supplied stack,
//! and libc's `__clone` stub pops the child function off that NEW stack. carrick
//! ran the child on the PARENT's stack (the clone stack arg was only honored on
//! the vfork path), so the stub's child leg dereferenced parent frames and
//! crashed — the LTP parent then saw ECHILD/garbage exits.

extern "C" fn child_main(_arg: *mut libc::c_void) -> i32 {
    42
}

fn main() {
    unsafe {
        let len = 256 * 1024;
        let stack = libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        );
        if stack == libc::MAP_FAILED {
            println!("stack_mmap_ok=false");
            return;
        }
        // Stack grows down: pass the TOP (aligned).
        let top = (stack as usize + len) & !0xf;
        let pid = libc::clone(
            child_main,
            top as *mut libc::c_void,
            libc::SIGCHLD,
            std::ptr::null_mut(),
        );
        println!("clone_ok={}", pid > 0);
        let mut status = 0;
        let reaped = libc::waitpid(pid, &mut status, 0);
        println!("wait_ok={}", reaped == pid);
        println!(
            "child_exit_42={}",
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 42
        );
    }
}
