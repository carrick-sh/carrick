//! A `/proc/<pid>` directory fd is a valid pidfd for `pidfd_send_signal(2)`:
//! Linux lets `open("/proc/<pid>", O_DIRECTORY)` produce an fd usable to send a
//! signal to that process. CPython's PidfdSignalTest.test_pidfd_send_signal
//! relies on it: open /proc/<getpid()>, then pidfd_send_signal(fd, SIGINT) to
//! self, expecting the SIGINT handler (KeyboardInterrupt) to run.
//!
//!  * pidfd0_ebadf:          pidfd_send_signal(0, SIGINT) fails with EBADF
//!                           (fd 0 is stdin, not a pidfd) — NOT ENOSYS.
//!  * procpid_dir_open_ok:   open("/proc/<getpid()>", O_DIRECTORY) succeeds.
//!  * pidfd_self_sigint_ok:  pidfd_send_signal(that fd, SIGINT) delivers SIGINT
//!                           to self (the installed handler runs).

use conformance_probes::report;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const SYS_PIDFD_SEND_SIGNAL: libc::c_long = 424;

static GOT_SIGINT: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigint(_sig: libc::c_int) {
    GOT_SIGINT.store(true, Ordering::Release);
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn main() {
    unsafe {
        // (1) pidfd_send_signal on a non-pidfd fd (stdin) -> EBADF.
        let r0 = libc::syscall(SYS_PIDFD_SEND_SIGNAL, 0, libc::SIGINT, 0, 0);
        let pidfd0_ebadf = r0 == -1 && errno() == libc::EBADF;

        // Catch SIGINT so a successful self-delivery is observable (and does not
        // terminate the probe).
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_sigint as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());

        // (2) open /proc/<self> as a directory — the pidfd.
        let pid = libc::getpid();
        let path = std::ffi::CString::new(format!("/proc/{pid}")).unwrap();
        let fd = libc::open(path.as_ptr(), libc::O_DIRECTORY);
        let procpid_dir_open_ok = fd >= 0;

        // (3) send SIGINT to self via the /proc/<pid> pidfd.
        let mut pidfd_self_sigint_ok = false;
        if fd >= 0 {
            let rs = libc::syscall(
                SYS_PIDFD_SEND_SIGNAL,
                fd as libc::c_long,
                libc::SIGINT,
                0,
                0,
            );
            if rs == 0 {
                let deadline = Instant::now() + Duration::from_secs(2);
                while !GOT_SIGINT.load(Ordering::Acquire) && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(5));
                }
                pidfd_self_sigint_ok = GOT_SIGINT.load(Ordering::Acquire);
            }
            libc::close(fd);
        }

        report!(
            pidfd0_ebadf = pidfd0_ebadf,
            procpid_dir_open_ok = procpid_dir_open_ok,
            pidfd_self_sigint_ok = pidfd_self_sigint_ok
        );
    }
}
