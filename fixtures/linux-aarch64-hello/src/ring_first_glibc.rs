//! Dynamic glibc startup and optional fork with bounded descriptor waits.
#![no_std]
#![no_main]

#[link(name = "c")]
unsafe extern "C" {}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: terminate this fixture; no shared runtime state needs unwinding.
    unsafe { libc::_exit(99) }
}

fn loader_only() -> libc::c_int {
    // SAFETY: each pointer addresses live local storage; all descriptor waits
    // are bounded and no child process is created in this mode.
    unsafe {
        let mut time: libc::timespec = core::mem::zeroed();
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) != 0 || libc::getpid() <= 0 {
            return 71;
        }
        let fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return 72;
        }
        let mut byte = 0u8;
        if libc::read(fd, (&mut byte as *mut u8).cast(), 1) != 0 || libc::close(fd) != 0 {
            return 73;
        }
        let uid = libc::syscall(libc::SYS_getuid);
        let output: &[u8] = if uid == -1 && *libc::__errno_location() == libc::ENOSYS {
            b"glibc loader strict\n"
        } else if uid >= 0 {
            b"glibc loader forward\n"
        } else {
            return 74;
        };
        let mut stdout = libc::pollfd {
            fd: 1,
            events: libc::POLLOUT,
            revents: 0,
        };
        if libc::poll(&mut stdout, 1, 5000) != 1 || stdout.revents & libc::POLLOUT == 0 {
            return 75;
        }
        if libc::write(1, output.as_ptr().cast(), output.len()) != output.len() as isize {
            return 76;
        }
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn main(argc: libc::c_int, argv: *const *const libc::c_char) -> libc::c_int {
    // SAFETY: the GNU CRT provides argc live NUL-terminated argv strings.
    if argc == 2 && unsafe { libc::strcmp(*argv.add(1), c"--loader-only".as_ptr()) } == 0 {
        return loader_only();
    }
    // SAFETY: all pointers below address live, correctly aligned local storage;
    // the child performs only close and _exit after fork.
    unsafe {
        let mut mask: libc::sigset_t = core::mem::zeroed();
        if libc::sigemptyset(&mut mask) != 0
            || libc::sigaddset(&mut mask, libc::SIGCHLD) != 0
            || libc::sigprocmask(libc::SIG_BLOCK, &mask, core::ptr::null_mut()) != 0
        {
            return 81;
        }
        let signal_fd = libc::signalfd(-1, &mask, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
        if signal_fd < 0 {
            return 82;
        }
        let child = libc::fork();
        if child < 0 {
            return 83;
        }
        if child == 0 {
            libc::close(signal_fd);
            libc::_exit(23);
        }
        let mut ready = libc::pollfd {
            fd: signal_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SIGCHLD reports child state, unlike pipe EOF (which only proves fd
        // closure). No unbounded wait and no wait-until-ready retry loop.
        if libc::poll(&mut ready, 1, 5000) != 1 || ready.revents & libc::POLLIN == 0 {
            return 84;
        }
        let mut event: libc::signalfd_siginfo = core::mem::zeroed();
        if libc::read(
            signal_fd,
            (&mut event as *mut libc::signalfd_siginfo).cast(),
            core::mem::size_of_val(&event),
        ) != core::mem::size_of_val(&event) as isize
            || event.ssi_signo != libc::SIGCHLD as u32
            || event.ssi_pid != child as u32
        {
            return 85;
        }
        libc::close(signal_fd);
        let mut status = 0;
        if libc::waitpid(child, &mut status, libc::WNOHANG) != child {
            return 86;
        }
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 23 {
            return 87;
        }
        let output = b"glibc fork wait 23\n";
        let mut stdout = libc::pollfd {
            fd: 1,
            events: libc::POLLOUT,
            revents: 0,
        };
        if libc::poll(&mut stdout, 1, 5000) != 1 || stdout.revents & libc::POLLOUT == 0 {
            return 88;
        }
        if libc::write(1, output.as_ptr().cast(), output.len()) != output.len() as isize {
            return 89;
        }
        0
    }
}
