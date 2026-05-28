//! Signal mask + pending-set semantics across fork(2). Three Linux invariants
//! that no other probe covers (signals.rs never forks):
//!   * a forked child INHERITS the parent's blocked signal mask;
//!   * the child's set of PENDING signals is EMPTY (fork clears pending);
//!   * the parent's own pending signal SURVIVES the fork.
//! The parent blocks SIGUSR1, raises it (pending), then forks; the child
//! reports its mask/pending state back over a pipe. Deterministic booleans;
//! the child exits promptly so the parent's reap can't hang.

use std::os::fd::RawFd;

unsafe fn blocked(sig: i32) -> bool {
    let mut cur: libc::sigset_t = std::mem::zeroed();
    libc::sigprocmask(libc::SIG_SETMASK, std::ptr::null(), &mut cur);
    libc::sigismember(&cur, sig) == 1
}

unsafe fn is_pending(sig: i32) -> bool {
    let mut p: libc::sigset_t = std::mem::zeroed();
    libc::sigpending(&mut p);
    libc::sigismember(&p, sig) == 1
}

fn main() {
    unsafe {
        // Block SIGUSR1 process-wide, then raise it so it sits pending.
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGUSR1);
        libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        libc::raise(libc::SIGUSR1);
        let parent_pending_before = is_pending(libc::SIGUSR1);

        let mut fds: [RawFd; 2] = [0; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            println!("setup=false");
            return;
        }

        let pid = libc::fork();
        if pid == 0 {
            // Child: mask must be inherited (SIGUSR1 still blocked), but the
            // pending SIGUSR1 must NOT have carried over (fork clears pending).
            let mask_inherited = blocked(libc::SIGUSR1);
            let pending_cleared = !is_pending(libc::SIGUSR1);
            let byte = [(mask_inherited as u8) | ((pending_cleared as u8) << 1)];
            libc::write(fds[1], byte.as_ptr() as *const libc::c_void, 1);
            libc::_exit(0);
        }

        libc::close(fds[1]);
        let mut b = [0u8; 1];
        let _ = libc::read(fds[0], b.as_mut_ptr() as *mut libc::c_void, 1);
        let mut st = 0;
        while libc::wait4(pid, &mut st, 0, std::ptr::null_mut()) < 0 {}
        let parent_pending_after = is_pending(libc::SIGUSR1);

        println!("child_inherits_blocked_mask={}", b[0] & 1 != 0);
        println!("child_pending_cleared_on_fork={}", b[0] & 2 != 0);
        println!(
            "parent_pending_survives_fork={}",
            parent_pending_before && parent_pending_after
        );
    }
}
