//! A signal that arrives while a thread is blocked in epoll_wait on an
//! in-zone (eventfd) set interrupts the wait with EINTR, with and without
//! SA_RESTART, whether it is sent by another process or by a sibling thread.
//!
//! Contract `kernel.el1.epoll-zone`; authority `man 2 epoll_wait` (EINTR),
//! `man 7 signal` ("never restarted after being interrupted by a signal
//! handler": epoll_wait, epoll_pwait).
//!
//! Invariants encoded (errno numbers, not names):
//!   * `<case>_rc=-1`, `<case>_errno=4`, `<case>_handler_ran=true`;
//!   * after the interruption the same set still delivers a later post.
//! The blocked wait has a 5 s timeout: a signal that never interrupts it
//! prints rc=0 rather than hanging. Sender delays are 100 ms.

use conformance_probes::{errno, install_handler, reap, report};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::Duration;

const IN: u32 = 0x001;
static RAN: AtomicBool = AtomicBool::new(false);
static WAITER_TID: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_usr1(_: i32) {
    RAN.store(true, Ordering::SeqCst);
}

unsafe fn set() -> (i32, i32) {
    let efd = libc::eventfd(0, libc::EFD_NONBLOCK);
    let ep = libc::epoll_create1(0);
    let mut ev = libc::epoll_event { events: IN, u64: 9 };
    assert_eq!(libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, efd, &mut ev), 0);
    (efd, ep)
}

unsafe fn blocked_wait(ep: i32) -> (i32, i32) {
    let mut out = [libc::epoll_event { events: 0, u64: 0 }; 2];
    let n = libc::epoll_wait(ep, out.as_mut_ptr(), 2, 5000);
    (n, if n < 0 { errno() } else { 0 })
}

unsafe fn still_delivers(efd: i32, ep: i32) -> bool {
    let one = 1u64;
    libc::write(efd, (&one as *const u64).cast(), 8);
    let mut out = [libc::epoll_event { events: 0, u64: 0 }; 2];
    libc::epoll_wait(ep, out.as_mut_ptr(), 2, 5000) == 1 && out[0].u64 == 9
}

/// A forked child signals the parent after 100 ms.
unsafe fn from_process(flags: i32) -> (i32, i32, bool, bool) {
    assert!(install_handler(libc::SIGUSR1, on_usr1, flags));
    RAN.store(false, Ordering::SeqCst);
    let (efd, ep) = set();
    let parent = libc::getpid();
    let child = libc::fork();
    if child == 0 {
        libc::usleep(100_000);
        libc::kill(parent, libc::SIGUSR1);
        libc::_exit(0);
    }
    let (n, e) = blocked_wait(ep);
    let ran = RAN.load(Ordering::SeqCst);
    reap(child);
    let after = still_delivers(efd, ep);
    libc::close(ep);
    libc::close(efd);
    (n, e, ran, after)
}

/// A sibling thread signals the waiting thread (tgkill) after 100 ms.
unsafe fn from_thread() -> (i32, i32, bool, bool) {
    assert!(install_handler(libc::SIGUSR1, on_usr1, 0));
    RAN.store(false, Ordering::SeqCst);
    let (efd, ep) = set();
    WAITER_TID.store(libc::syscall(libc::SYS_gettid) as i32, Ordering::SeqCst);
    let pid = libc::getpid();
    let sender = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        unsafe {
            libc::syscall(
                libc::SYS_tgkill,
                pid,
                WAITER_TID.load(Ordering::SeqCst),
                libc::SIGUSR1,
            )
        };
    });
    let (n, e) = blocked_wait(ep);
    let ran = RAN.load(Ordering::SeqCst);
    let _ = sender.join();
    let after = still_delivers(efd, ep);
    libc::close(ep);
    libc::close(efd);
    (n, e, ran, after)
}

fn main() {
    unsafe {
        let (n, e, ran, after) = from_process(0);
        report!(
            process_rc = n,
            process_errno = e,
            process_handler_ran = ran,
            process_after_delivers = after
        );
        let (n, e, ran, after) = from_process(libc::SA_RESTART);
        report!(
            restart_rc = n,
            restart_errno = e,
            restart_handler_ran = ran,
            restart_after_delivers = after
        );
        let (n, e, ran, after) = from_thread();
        report!(
            thread_rc = n,
            thread_errno = e,
            thread_handler_ran = ran,
            thread_after_delivers = after
        );
    }
}
