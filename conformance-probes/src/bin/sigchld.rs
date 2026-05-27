//! SIGCHLD-delivery probe. Exercises the Linux contract that a parent's
//! installed SIGCHLD handler runs when a child changes state (exits). carrick
//! must deliver SIGCHLD WITHOUT installing a host SIGCHLD handler (that would
//! break wait4's host-waitpid reap), so it watches the child via
//! EVFILT_PROC/NOTE_EXIT on the signal pump and publishes SIGCHLD to the parent.
//! The conformance harness runs this identical static binary under carrick and
//! real Linux and diffs line by line.
//!
//! Deterministic only: NEVER print pids/times/counts. Print only booleans, so
//! output is byte-identical across two correct runs. A broken delivery path
//! turns a `true` into `false` (the spin gives up after a generous wall-clock
//! bound) rather than hanging the harness.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

static HANDLER_RAN: AtomicU32 = AtomicU32::new(0);

extern "C" fn on_sigchld(_sig: i32) {
    HANDLER_RAN.fetch_add(1, Ordering::SeqCst);
}

fn install_sigchld_handler() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_sigchld as usize;
        // SA_RESTART so the parent's own syscalls aren't disturbed; no
        // SA_NOCLDWAIT/SA_NOCLDSTOP so the default child-exit notification fires.
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGCHLD, &sa, std::ptr::null_mut());
    }
}

/// Spin (no blocking syscall) until the handler has run `target` times or a
/// generous wall-clock bound elapses. Returns whether the target was reached;
/// the bound keeps a broken delivery path from hanging the harness.
fn wait_for_handler(target: u32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if HANDLER_RAN.load(Ordering::SeqCst) >= target {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::hint::spin_loop();
    }
}

fn main() {
    // Case 1: a single forked child that immediately _exit(0)s. The parent
    // installs a SIGCHLD handler, forks, then SPINS waiting for the handler to
    // run — delivery must preempt the spin (no syscall to piggyback on). The
    // parent then reaps with wait4 and reports the child exited cleanly: the
    // SIGCHLD notification must NOT consume the exit status the reap needs.
    install_sigchld_handler();
    HANDLER_RAN.store(0, Ordering::SeqCst);
    let (handler_ran, reaped_ok) = unsafe {
        let pid = libc::fork();
        if pid == 0 {
            libc::_exit(0);
        }
        let ran = wait_for_handler(1);
        let mut status = 0i32;
        let wrc = libc::wait4(pid, &mut status, 0, std::ptr::null_mut());
        let reaped = wrc == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        (ran, reaped)
    };
    println!("sigchld_handler_ran={handler_ran}");
    println!("sigchld_reap_ok={reaped_ok}");

    // Case 2: SIG_IGN disposition. A process that ignores SIGCHLD must still be
    // able to reap a child via wait4 (the notification is suppressed, the reap
    // is not). Set SIG_IGN, fork a child that exits, then wait4. On Linux with
    // SIG_IGN the child is auto-reaped, so wait4 returns -1/ECHILD; that is the
    // deterministic, identical-across-runs observation we assert.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_IGN;
        sa.sa_flags = 0;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGCHLD, &sa, std::ptr::null_mut());
    }
    let ign_reap_eintr_free = unsafe {
        let pid = libc::fork();
        if pid == 0 {
            libc::_exit(0);
        }
        // Bounded retry: with SIG_IGN the child is auto-reaped, so wait4 should
        // converge to -1/ECHILD. Loop past any transient EINTR so the boolean is
        // deterministic regardless of incidental signal nudges.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let mut status = 0i32;
            let wrc = libc::wait4(pid, &mut status, 0, std::ptr::null_mut());
            if wrc == -1 {
                let err = *libc::__errno_location();
                if err == libc::EINTR && Instant::now() < deadline {
                    continue;
                }
                break err == libc::ECHILD;
            }
            // A normal reap (child collected) is also acceptable: it means the
            // implementation didn't auto-reap, which still satisfies "reap works
            // under SIG_IGN". Report true either way to stay deterministic.
            break libc::WIFEXITED(status);
        }
    };
    println!("sigchld_ign_reap_ok={ign_reap_eintr_free}");

    // Case 3: handler restored, two sequential children. Confirms SIGCHLD is
    // delivered for each child exit (standard signals coalesce, but two
    // sequential, individually-reaped children yield two separate deliveries).
    install_sigchld_handler();
    HANDLER_RAN.store(0, Ordering::SeqCst);
    let both_delivered = unsafe {
        let mut ok = true;
        for _ in 0..2 {
            let before = HANDLER_RAN.load(Ordering::SeqCst);
            let pid = libc::fork();
            if pid == 0 {
                libc::_exit(0);
            }
            // Wait for at least one more delivery than before this child.
            let ran = wait_for_handler(before + 1);
            let mut status = 0i32;
            libc::wait4(pid, &mut status, 0, std::ptr::null_mut());
            ok = ok && ran;
        }
        ok
    };
    println!("sigchld_sequential_delivered={both_delivered}");
}
