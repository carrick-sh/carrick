//! Cross-process signal probe. A child sends SIGUSR1 to its parent, which has
//! a handler installed; the parent must RUN that handler (not die from the
//! signal's default action). This is exactly LTP's tst_test heartbeat
//! (`kill(getppid(), SIGUSR1)`). Linux and macOS use DIFFERENT numbers for
//! SIGUSR1 (10 vs 30), so carrick must translate signums on both the send
//! (libc::kill) and receive (host handler -> guest delivery) sides.
//!
//! Deterministic: prints only booleans.

use std::sync::atomic::{AtomicI32, Ordering};

static GOT: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_usr1(_sig: libc::c_int) {
    GOT.store(1, Ordering::SeqCst);
}

fn main() {
    // Install a SIGUSR1 handler in the parent.
    unsafe {
        let mut act: libc::sigaction = std::mem::zeroed();
        act.sa_sigaction = on_usr1 as usize;
        libc::sigemptyset(&mut act.sa_mask);
        act.sa_flags = 0;
        libc::sigaction(libc::SIGUSR1, &act, std::ptr::null_mut());
    }

    // Sync pipe: child waits until parent is ready, then signals.
    let mut ready = [0i32; 2];
    let mut done = [0i32; 2];
    unsafe {
        libc::pipe(ready.as_mut_ptr());
        libc::pipe(done.as_mut_ptr());
    }

    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // Child: wait for parent-ready, then SIGUSR1 the parent.
        unsafe {
            libc::close(ready[1]);
            libc::close(done[0]);
            let mut b = [0u8; 1];
            libc::read(ready[0], b.as_mut_ptr() as *mut libc::c_void, 1);
            libc::kill(libc::getppid(), libc::SIGUSR1);
            // Tell the parent we've sent it.
            libc::write(done[1], b.as_ptr() as *const libc::c_void, 1);
            libc::_exit(0);
        }
    }

    unsafe {
        libc::close(ready[0]);
        libc::close(done[1]);
        // Tell child we're ready, then block until it reports it sent the sig.
        let b = [1u8; 1];
        libc::write(ready[1], b.as_ptr() as *const libc::c_void, 1);
        let mut rb = [0u8; 1];
        libc::read(done[0], rb.as_mut_ptr() as *mut libc::c_void, 1);
        // Give delivery a beat (handler runs asynchronously).
        let ts = libc::timespec { tv_sec: 0, tv_nsec: 50_000_000 };
        libc::nanosleep(&ts, std::ptr::null_mut());
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
    }

    println!("xsignal handler_ran={}", GOT.load(Ordering::SeqCst) == 1);
}
