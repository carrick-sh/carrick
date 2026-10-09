//! Dynamic glibc startup, file-backed mappings, fork and bounded wait witness.
#![no_std]
#![no_main]

#[link(name = "c")]
unsafe extern "C" {}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: terminate this fixture; no shared runtime state needs unwinding.
    unsafe { libc::_exit(99) }
}

#[unsafe(no_mangle)]
pub extern "C" fn main() -> libc::c_int {
    // SAFETY: all pointers below address live, correctly aligned local storage;
    // the child performs only close and _exit after fork.
    unsafe {
        let mut ends = [-1; 2];
        if libc::pipe(ends.as_mut_ptr()) != 0 {
            return 81;
        }
        let child = libc::fork();
        if child < 0 {
            return 82;
        }
        if child == 0 {
            libc::close(ends[0]);
            libc::_exit(23);
        }
        libc::close(ends[1]);
        let mut ready = libc::pollfd {
            fd: ends[0],
            events: libc::POLLIN,
            revents: 0,
        };
        // Exit closes the child writer; never perform an unbounded guest wait.
        if libc::poll(&mut ready, 1, 5000) != 1 || ready.revents & libc::POLLHUP == 0 {
            return 83;
        }
        libc::close(ends[0]);
        let mut status = 0;
        if libc::waitpid(child, &mut status, libc::WNOHANG) != child {
            return 84;
        }
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 23 {
            return 85;
        }
        let output = b"glibc fork wait 23\n";
        let mut stdout = libc::pollfd {
            fd: 1,
            events: libc::POLLOUT,
            revents: 0,
        };
        if libc::poll(&mut stdout, 1, 5000) != 1 || stdout.revents & libc::POLLOUT == 0 {
            return 86;
        }
        if libc::write(1, output.as_ptr().cast(), output.len()) != output.len() as isize {
            return 87;
        }
        0
    }
}
