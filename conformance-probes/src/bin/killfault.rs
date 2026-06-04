//! Cross-process delivery of an IGNORED synchronous-fault signal (LTP kill12's
//! inner loop). For each of SIGILL/SIGTRAP/SIGABRT/SIGBUS/SIGFPE/SIGSEGV, a
//! forked child sets that signal to SIG_IGN plus a SIGCHLD handler that exits 1,
//! signals ready, then waits. The parent sends the fault signal (the child must
//! IGNORE it — it is SIG_IGN) followed by SIGCHLD (the child's handler exits 1).
//! On real Linux every child exits normally with code 1; the fault signal is
//! discarded by the guest's SIG_IGN disposition.
//!
//! carrick must NOT translate the parent's cross-process kill into a real host
//! fault (host SIGILL etc. at SIG_DFL → the child dies core-dumped, WIFSIGNALED).
//! The host disposition for fault signals is shared with genuine guest faults,
//! so SIG_IGN cannot be mirrored to the host; the signal must instead be routed
//! through the in-guest delivery path that honours the guest disposition.
//! Deterministic: prints `ignored=<n>/6 correct=<0|1>`.
use std::sync::atomic::{AtomicI32, Ordering};

static SAW_CHLD: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_chld(_s: libc::c_int) {
    // The child's SIGCHLD handler: mirror kill12 — exit with status 1.
    SAW_CHLD.store(1, Ordering::SeqCst);
    unsafe { libc::_exit(1) };
}

fn run_one(sig: libc::c_int) -> bool {
    unsafe {
        let mut ready = [0i32; 2];
        libc::pipe(ready.as_mut_ptr());
        let pid = libc::fork();
        if pid == 0 {
            // CHILD: SIGCHLD -> exit(1); test signal -> ignore.
            let mut chld: libc::sigaction = std::mem::zeroed();
            chld.sa_sigaction = on_chld as usize;
            libc::sigemptyset(&mut chld.sa_mask);
            libc::sigaction(libc::SIGCHLD, &chld, std::ptr::null_mut());

            let mut ign: libc::sigaction = std::mem::zeroed();
            ign.sa_sigaction = libc::SIG_IGN;
            libc::sigemptyset(&mut ign.sa_mask);
            libc::sigaction(sig, &ign, std::ptr::null_mut());

            libc::write(ready[1], b"r".as_ptr() as *const libc::c_void, 1);
            // Wait to be killed by SIGCHLD; bound it so a broken probe exits.
            let mut i = 0;
            while i < 3000 {
                libc::usleep(1000);
                i += 1;
            }
            libc::_exit(0); // never reached on real Linux
        }
        // PARENT: wait for the child's readiness, then send fault sig + SIGCHLD.
        let mut b = [0u8; 1];
        libc::read(ready[0], b.as_mut_ptr() as *mut libc::c_void, 1);
        libc::usleep(50_000);
        libc::kill(pid, sig); // child must IGNORE this (SIG_IGN)
        libc::usleep(50_000);
        libc::kill(pid, libc::SIGCHLD); // child's handler exits 1
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
        // Correct iff the child exited normally with code 1 (fault sig ignored),
        // NOT terminated by a signal.
        libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 1
    }
}

fn main() {
    let sigs = [
        libc::SIGILL,
        libc::SIGTRAP,
        libc::SIGABRT,
        libc::SIGBUS,
        libc::SIGFPE,
        libc::SIGSEGV,
    ];
    let mut ok = 0;
    for &s in &sigs {
        if run_one(s) {
            ok += 1;
        }
    }
    println!("ignored={}/6 correct={}", ok, (ok == sigs.len()) as i32);
}
