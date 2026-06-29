//! Reducer for the CPython `test_signal.WakeupSignalTests.test_pending` hang.
//!
//! The test blocks SIGUSR1+SIGUSR2, raises both (now pending+blocked), then
//! `pthread_sigmask(SIG_UNBLOCK)`s them. CPython's `set_wakeup_fd` installs a C
//! signal handler that, on EACH delivery, `write()`s the signum byte to a
//! non-blocking pipe; the test then reads the pipe and expects exactly the two
//! signums. Under carrick the child spun (1M syscall traps).
//!
//! A counting C handler with NO syscall delivers each-once correctly, so the
//! trigger is the HANDLER MAKING A SYSCALL (the wakeup-fd `write`). This reducer
//! mirrors that: the handler `write()`s its signum to a non-blocking pipe. If
//! carrick re-delivers a pending signal while servicing the handler's syscall
//! (its pending bit not cleared on entry), the handler loops — visible as >2
//! bytes in the pipe (or the guest itself spinning to the trap limit).

use std::os::raw::c_void;
use std::sync::atomic::{AtomicI32, Ordering};

static WFD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn wakeup_handler(signum: i32) {
    let fd = WFD.load(Ordering::SeqCst);
    if fd >= 0 {
        let b = [signum as u8; 1];
        unsafe {
            libc::write(fd, b.as_ptr() as *const c_void, 1);
        }
    }
}

fn emit(s: &str) {
    unsafe {
        libc::write(1, s.as_ptr() as *const c_void, s.len());
    }
}

fn main() {
    unsafe {
        // Non-blocking pipe — the "wakeup fd".
        let mut pfd = [0i32; 2];
        if libc::pipe(pfd.as_mut_ptr()) != 0 {
            emit("sigunblockpending=ERR pipe\n");
            libc::_exit(72);
        }
        let (rfd, wfd) = (pfd[0], pfd[1]);
        let fl = libc::fcntl(wfd, libc::F_GETFL, 0);
        libc::fcntl(wfd, libc::F_SETFL, fl | libc::O_NONBLOCK);
        WFD.store(wfd, Ordering::SeqCst);

        // Wakeup-fd-style handlers (do a write syscall on delivery).
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = wakeup_handler as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGUSR2, &sa, std::ptr::null_mut());

        // Block both, raise each once (pending), then unblock — Linux delivers
        // each exactly once, so the pipe ends up with exactly two bytes {10,12}.
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGUSR1);
        libc::sigaddset(&mut set, libc::SIGUSR2);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        libc::raise(libc::SIGUSR1);
        libc::raise(libc::SIGUSR2);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());

        // Drain the pipe (non-blocking). A correct kernel yields exactly 2 bytes;
        // a re-delivery loop yields many (or the guest already hit the trap limit
        // and never reached here).
        let mut buf = [0u8; 256];
        let n = libc::read(rfd, buf.as_mut_ptr() as *mut c_void, buf.len());
        let got = if n > 0 { n as usize } else { 0 };

        if got == 2 {
            emit("sigunblockpending=OK two-bytes\n");
            libc::_exit(0);
        } else if got > 2 {
            emit("sigunblockpending=REDELIVER-LOOP\n");
            libc::_exit(70);
        } else {
            emit("sigunblockpending=BAD too-few\n");
            libc::_exit(71);
        }
    }
}
