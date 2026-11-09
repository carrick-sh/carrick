//! Fork child writes through an inherited regular-file descriptor whose source
//! buffer stops being readable part-way (#1954, PR #1935).
//! Linux authority: write(2) and writev(2) return the bytes transferred before
//! the first unreadable source byte, and EFAULT only when nothing transferred.
//! The parent opens four host-backed destination files under `/out` BEFORE a
//! real `fork`; the child (a ring-owned native task under Carrick) writes:
//!   1. `write` of 0x100001 bytes starting 16 initialized bytes before an
//!      unmapped page: returns 16, the file holds `0123456789abcdef`;
//!   2. `writev` of `hello` then a vector starting in the unmapped page:
//!      returns 5, the file holds `hello`;
//!   3. `write` from the unmapped page itself: -1/EFAULT (14), file empty;
//!   4. `write` of 4096 bytes from a never-touched PROT_READ anonymous page:
//!      returns 4096, the file holds 4096 zero bytes.
//!
//! The child is bounded by `alarm`; the parent's wait is bounded by `alarm`
//! with a non-restarting handler and kills the child on expiry. A SIGSEGV in
//! the child is reported as `child_signal=11`, never accepted.
use conformance_probes::{errno, report};

const FILES: [&std::ffi::CStr; 4] = [
    c"/out/prefix_write",
    c"/out/prefix_writev",
    c"/out/unreadable_write",
    c"/out/untouched_write",
];
const PREFIX: &[u8; 16] = b"0123456789abcdef";
const UNTOUCHED_COUNT: usize = 4096;

extern "C" fn on_alarm(_signal: libc::c_int) {}

fn outcome(ret: isize) -> (isize, i32) {
    (ret, if ret < 0 { errno() } else { 0 })
}

/// Runs in the fork child; never returns.
unsafe fn child(fds: [libc::c_int; 4]) -> ! {
    libc::alarm(10);
    let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
    // Map the untouched page first: any mapping made after the `munmap` below
    // may be placed in the hole and make it readable again.
    let untouched = libc::mmap(
        std::ptr::null_mut(),
        page,
        libc::PROT_READ,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if untouched == libc::MAP_FAILED {
        libc::_exit(4);
    }
    let pair = libc::mmap(
        std::ptr::null_mut(),
        2 * page,
        libc::PROT_READ | libc::PROT_WRITE,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    if pair == libc::MAP_FAILED {
        libc::_exit(2);
    }
    let base = pair.cast::<u8>();
    let hole = base.add(page);
    let prefix = hole.sub(PREFIX.len());
    std::ptr::copy_nonoverlapping(PREFIX.as_ptr(), prefix, PREFIX.len());
    if libc::munmap(hole.cast(), page) != 0 {
        libc::_exit(3);
    }
    // No allocation or mapping happens between here and the last write.

    let write = outcome(libc::write(fds[0], prefix.cast(), 0x100001));
    let iov = [
        libc::iovec {
            iov_base: b"hello".as_ptr() as *mut libc::c_void,
            iov_len: 5,
        },
        libc::iovec {
            iov_base: hole.cast(),
            iov_len: page,
        },
    ];
    let writev = outcome(libc::writev(fds[1], iov.as_ptr(), 2));
    let unreadable = outcome(libc::write(fds[2], hole.cast(), PREFIX.len()));
    let zero = outcome(libc::write(fds[3], untouched.cast(), UNTOUCHED_COUNT));

    report!(
        prefix_write_ret = write.0,
        prefix_write_errno = write.1,
        prefix_writev_ret = writev.0,
        prefix_writev_errno = writev.1,
        unreadable_write_ret = unreadable.0,
        unreadable_write_errno = unreadable.1,
        untouched_write_ret = zero.0,
        untouched_write_errno = zero.1
    );
    use std::io::Write;
    let flushed = std::io::stdout().flush().is_ok();
    libc::_exit(if flushed { 0 } else { 5 });
}

fn main() {
    unsafe {
        let mut fds = [-1; 4];
        for (fd, path) in fds.iter_mut().zip(FILES) {
            *fd = libc::open(
                path.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
                0o644,
            );
            if *fd < 0 {
                println!("open_errno={}", errno());
                std::process::exit(1);
            }
        }

        let pid = libc::fork();
        if pid == 0 {
            child(fds);
        }
        if pid < 0 {
            println!("fork_errno={}", errno());
            std::process::exit(1);
        }

        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = on_alarm as extern "C" fn(libc::c_int) as usize;
        action.sa_flags = 0;
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(libc::SIGALRM, &action, std::ptr::null_mut());
        libc::alarm(20);
        let mut status = 0;
        let mut timed_out = false;
        let mut reaped = libc::waitpid(pid, &mut status, 0);
        if reaped < 0 && errno() == libc::EINTR {
            timed_out = true;
            libc::kill(pid, libc::SIGKILL);
            reaped = libc::waitpid(pid, &mut status, 0);
        }
        libc::alarm(0);
        let exited = reaped == pid && libc::WIFEXITED(status);
        let signalled = reaped == pid && libc::WIFSIGNALED(status);
        report!(
            child_exit = if exited {
                libc::WEXITSTATUS(status).to_string()
            } else {
                "none".to_owned()
            },
            child_signal = if signalled {
                libc::WTERMSIG(status).to_string()
            } else {
                "none".to_owned()
            },
            child_timeout = timed_out
        );

        for (fd, name) in fds.iter().zip([
            "prefix_write_size",
            "prefix_writev_size",
            "unreadable_write_size",
            "untouched_write_size",
        ]) {
            let mut st: libc::stat = std::mem::zeroed();
            let size = if libc::fstat(*fd, &mut st) == 0 {
                st.st_size.to_string()
            } else {
                format!("fstat_errno_{}", errno())
            };
            println!("{name}={size}");
            libc::close(*fd);
        }
    }
}
