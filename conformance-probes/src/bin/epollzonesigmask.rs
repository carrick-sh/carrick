//! epoll_pwait with a non-NULL signal mask over an in-zone (eventfd) set:
//! the mask is installed for exactly the duration of the wait.
//!
//! Contract `kernel.el1.epoll-zone`; authority `man 2 epoll_pwait` ("the
//! signal mask ... is atomically replaced for the duration of the call, then
//! restored"), `man 7 signal`.
//!
//! Invariants encoded (errno numbers, booleans):
//!   * a signal blocked in the thread mask but pending before the call is
//!     delivered by a wait whose sigmask unblocks it: rc=-1, errno=4, the
//!     handler ran, and afterwards the thread mask blocks it again;
//!   * a signal unblocked in the thread mask but blocked by the call's
//!     sigmask and sent during the wait does not interrupt it: the 300 ms
//!     wait times out (rc=0, not EINTR), and the handler runs as the call
//!     returns and restores the thread mask (it has run by the time the
//!     next statement executes);
//!   * a ready member is reported by epoll_pwait with a mask, like
//!     epoll_wait;
//!   * a sigsetsize other than 8 is EINVAL.
//! Every wait is bounded; the sender is a forked child (100 ms delay).

use conformance_probes::{
    block_signal, errno, install_handler, is_blocked, reap, report, unblock_signal,
};
use std::sync::atomic::{AtomicBool, Ordering};

const IN: u32 = 0x001;
static RAN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_usr1(_: i32) {
    RAN.store(true, Ordering::SeqCst);
}

unsafe fn mask_with(sig: Option<i32>) -> libc::sigset_t {
    let mut set: libc::sigset_t = std::mem::zeroed();
    libc::sigemptyset(&mut set);
    if let Some(sig) = sig {
        libc::sigaddset(&mut set, sig);
    }
    set
}

fn main() {
    unsafe {
        assert!(install_handler(libc::SIGUSR1, on_usr1, 0));
        let efd = libc::eventfd(0, libc::EFD_NONBLOCK);
        let ep = libc::epoll_create1(0);
        let mut ev = libc::epoll_event {
            events: IN,
            u64: 77,
        };
        assert_eq!(libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, efd, &mut ev), 0);
        let mut out = [libc::epoll_event { events: 0, u64: 0 }; 2];

        // (1) pending + blocked, the call's mask unblocks it.
        assert!(block_signal(libc::SIGUSR1));
        RAN.store(false, Ordering::SeqCst);
        libc::raise(libc::SIGUSR1);
        let open = mask_with(None);
        let n = libc::epoll_pwait(ep, out.as_mut_ptr(), 2, 1000, &open);
        let e = if n < 0 { errno() } else { 0 };
        report!(
            unblock_pending_rc = n,
            unblock_pending_errno = e,
            unblock_pending_handler_ran = RAN.load(Ordering::SeqCst),
            unblock_pending_mask_restored = is_blocked(libc::SIGUSR1)
        );

        // (2) unblocked thread mask, the call's mask blocks it.
        assert!(unblock_signal(libc::SIGUSR1));
        RAN.store(false, Ordering::SeqCst);
        let blocked = mask_with(Some(libc::SIGUSR1));
        let parent = libc::getpid();
        let child = libc::fork();
        if child == 0 {
            libc::usleep(100_000);
            libc::kill(parent, libc::SIGUSR1);
            libc::_exit(0);
        }
        let n = libc::epoll_pwait(ep, out.as_mut_ptr(), 2, 300, &blocked);
        let e = if n < 0 { errno() } else { 0 };
        let ran_by_return = RAN.load(Ordering::SeqCst);
        reap(child);
        report!(
            blocked_during_rc = n,
            blocked_during_errno = e,
            blocked_handler_ran_by_return = ran_by_return,
            blocked_mask_restored = !is_blocked(libc::SIGUSR1)
        );

        // (3) a ready member is reported through epoll_pwait with a mask.
        let one = 1u64;
        libc::write(efd, (&one as *const u64).cast(), 8);
        let n = libc::epoll_pwait(ep, out.as_mut_ptr(), 2, 1000, &blocked);
        report!(
            ready_rc = n,
            ready_data = if n == 1 { out[0].u64 } else { 0 }
        );

        // (4) a sigsetsize other than sizeof(kernel sigset_t) is EINVAL.
        let rc = libc::syscall(
            libc::SYS_epoll_pwait,
            ep,
            out.as_mut_ptr(),
            2,
            0,
            &blocked as *const libc::sigset_t,
            4usize,
        );
        report!(bad_sigsetsize_rc = rc, bad_sigsetsize_errno = errno());

        libc::close(ep);
        libc::close(efd);
    }
}
