//! BSD host signal translation collision probe.
//!
//! Linux SIGSTKFLT(16) and SIGPWR(30) have no BSD host carrier: BSD 16 is
//! SIGURG and BSD 30 is SIGUSR1. A BSD-backed carrick lane must therefore
//! deliver them through Carrick's explicit signal path, not by raw host signal
//! identity. Linux SIGIO(29) is the countercheck: it does have a BSD carrier
//! (host SIGIO/SIGPOLL 23), while host SIGINFO(29) is Carrick-internal.

use conformance_probes::report;
use std::sync::atomic::{AtomicUsize, Ordering};

const SIGSTKFLT: i32 = 16;
const SIGPWR: i32 = 30;
const SIGIO_LINUX: i32 = 29;

static GOT_STKFLT: AtomicUsize = AtomicUsize::new(0);
static GOT_PWR: AtomicUsize = AtomicUsize::new(0);
static GOT_IO: AtomicUsize = AtomicUsize::new(0);

extern "C" fn on_stkflt(_sig: i32) {
    GOT_STKFLT.fetch_add(1, Ordering::SeqCst);
}

extern "C" fn on_pwr(_sig: i32) {
    GOT_PWR.fetch_add(1, Ordering::SeqCst);
}

extern "C" fn on_io(_sig: i32) {
    GOT_IO.fetch_add(1, Ordering::SeqCst);
}

unsafe fn install(signum: i32, handler: extern "C" fn(i32)) -> bool {
    let mut sa: libc::sigaction = core::mem::zeroed();
    sa.sa_sigaction = handler as usize;
    sa.sa_flags = 0;
    libc::sigemptyset(&mut sa.sa_mask);
    libc::sigaction(signum, &sa, core::ptr::null_mut()) == 0
}

fn child_main(ready_fd: i32) -> ! {
    unsafe {
        let installed = install(SIGSTKFLT, on_stkflt)
            && install(SIGPWR, on_pwr)
            && install(SIGIO_LINUX, on_io);
        let byte = [installed as u8];
        let _ = libc::write(ready_fd, byte.as_ptr().cast(), 1);
        libc::close(ready_fd);
        if !installed {
            libc::_exit(2);
        }

        libc::alarm(5);
        while GOT_STKFLT.load(Ordering::SeqCst) == 0
            || GOT_PWR.load(Ordering::SeqCst) == 0
            || GOT_IO.load(Ordering::SeqCst) == 0
        {
            libc::pause();
        }
        libc::_exit(0);
    }
}

fn main() {
    unsafe {
        let mut pipefd = [0; 2];
        if libc::pipe(pipefd.as_mut_ptr()) != 0 {
            report!(setup_pipe_ok = false);
            return;
        }

        let child = libc::fork();
        if child < 0 {
            report!(fork_ok = false);
            return;
        }
        if child == 0 {
            libc::close(pipefd[0]);
            child_main(pipefd[1]);
        }

        libc::close(pipefd[1]);
        let mut ready = [0u8; 1];
        let ready_read = libc::read(pipefd[0], ready.as_mut_ptr().cast(), 1);
        libc::close(pipefd[0]);

        let child_ready = ready_read == 1 && ready[0] == 1;
        let kill_stkflt = if child_ready {
            libc::kill(child, SIGSTKFLT) == 0
        } else {
            false
        };
        let kill_pwr = if child_ready {
            libc::kill(child, SIGPWR) == 0
        } else {
            false
        };
        let kill_io = if child_ready {
            libc::kill(child, SIGIO_LINUX) == 0
        } else {
            false
        };

        let mut status = 0;
        let waited = libc::waitpid(child, &mut status, 0) == child;
        report!(
            child_handlers_installed = child_ready,
            kill_sigstkflt_ok = kill_stkflt,
            kill_sigpwr_ok = kill_pwr,
            kill_sigio_ok = kill_io,
            child_waited = waited,
            child_exited_zero = waited && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        );
    }
}
