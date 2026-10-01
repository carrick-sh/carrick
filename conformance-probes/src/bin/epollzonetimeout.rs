//! epoll_wait timeouts (0, finite, infinite) and argument errors over an
//! in-zone (eventfd) set.
//!
//! Contract `kernel.el1.epoll-zone`; authority `man 2 epoll_wait`.
//!
//! Invariants encoded:
//!   * timeout 0 on a set with nothing ready returns 0 at once;
//!   * a finite timeout with no writer returns 0 after no less than the
//!     requested time on CLOCK_MONOTONIC (elapsed >= 100 ms for a 100 ms
//!     timeout, and well under the 5 s bound);
//!   * an empty epoll (no members) honours a finite timeout the same way;
//!   * a finite (2 s) wait whose member another thread makes ready after
//!     about 50 ms returns that one event early, not at its timeout;
//!   * timeout -1 blocks until a member becomes ready (a thread posts after
//!     about 50 ms) and returns that one event;
//!   * errnos: maxevents 0 is EINVAL, a closed epfd is EBADF, a non-epoll
//!     epfd is EINVAL, an unmapped events buffer is EFAULT once an event is
//!     ready.
//! The infinite wait is bounded by a 5 s ITIMER_REAL whose handler does not
//! restart: a lost wake prints rc=-1 errno=4 instead of hanging.

use conformance_probes::{arm_alarm_ms, disarm_alarm, errno, install_handler, report};
use std::time::Duration;

const IN: u32 = 0x001;

extern "C" fn on_alarm(_: i32) {}

/// CLOCK_MONOTONIC now (the clock epoll_wait(2) measures its timeout on).
fn monotonic() -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid timespec out-pointer.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime");
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

/// One epoll_wait: (rc, errno, first event's data, elapsed).
unsafe fn wait(ep: i32, timeout: i32) -> (i32, i32, u64, Duration) {
    let mut out = [libc::epoll_event { events: 0, u64: 0 }; 4];
    let t0 = monotonic();
    let n = libc::epoll_wait(ep, out.as_mut_ptr(), 4, timeout);
    let e = if n < 0 { errno() } else { 0 };
    let data = if n >= 1 { out[0].u64 } else { 0 };
    (n, e, data, monotonic().saturating_sub(t0))
}

/// A thread that writes 1 to eventfd `efd` after `ms`.
fn post_after(efd: i32, ms: u64) -> std::thread::JoinHandle<bool> {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(ms));
        let one = 1u64;
        // SAFETY: an 8-byte value for an eventfd write.
        unsafe { libc::write(efd, (&one as *const u64).cast(), 8) == 8 }
    })
}

fn main() {
    unsafe {
        assert!(install_handler(libc::SIGALRM, on_alarm, 0), "SIGALRM");
        let efd = libc::eventfd(0, libc::EFD_NONBLOCK);
        let ep = libc::epoll_create1(0);
        let mut ev = libc::epoll_event {
            events: IN,
            u64: 42,
        };
        assert_eq!(libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, efd, &mut ev), 0);

        let (n, _, _, t) = wait(ep, 0);
        report!(zero_rc = n, zero_prompt = t < Duration::from_secs(1));

        let (n, _, _, t) = wait(ep, 100);
        report!(
            finite_rc = n,
            finite_waited = t >= Duration::from_millis(100),
            finite_bounded = t < Duration::from_secs(4)
        );

        let empty = libc::epoll_create1(0);
        let (n, _, _, t) = wait(empty, 100);
        report!(
            empty_set_rc = n,
            empty_set_waited = t >= Duration::from_millis(100)
        );

        // A finite wait woken mid-wait by another thread's write.
        let poster = post_after(efd, 50);
        arm_alarm_ms(5000);
        let (n, e, data, t) = wait(ep, 2000);
        disarm_alarm();
        let posted = poster.join().unwrap_or(false);
        report!(
            finite_woken_rc = n,
            finite_woken_errno = e,
            finite_woken_data = data,
            finite_woken_early = t < Duration::from_millis(1500),
            finite_woken_posted = posted
        );
        let mut drained = 0u64;
        let read = libc::read(efd, (&mut drained as *mut u64).cast(), 8);
        report!(finite_woken_drained = read == 8 && drained == 1);

        let poster = post_after(efd, 50);
        arm_alarm_ms(5000);
        let mut out = [libc::epoll_event { events: 0, u64: 0 }; 4];
        let n = libc::epoll_wait(ep, out.as_mut_ptr(), 4, -1);
        let e = if n < 0 { errno() } else { 0 };
        disarm_alarm();
        let posted = poster.join().unwrap_or(false);
        report!(
            infinite_rc = n,
            infinite_errno = e,
            infinite_data = if n == 1 { out[0].u64 } else { 0 },
            infinite_posted = posted
        );

        // Argument errors (an event is ready, so ordering cannot hide them).
        let rc = libc::epoll_wait(ep, out.as_mut_ptr(), 0, 0);
        report!(maxevents_zero_rc = rc, maxevents_zero_errno = errno());
        let rc = libc::epoll_wait(ep, out.as_mut_ptr(), -1, 0);
        report!(
            maxevents_negative_rc = rc,
            maxevents_negative_errno = errno()
        );
        let rc = libc::epoll_wait(efd, out.as_mut_ptr(), 4, 0);
        report!(not_epoll_rc = rc, not_epoll_errno = errno());
        let rc = libc::epoll_wait(
            ep,
            8usize as *mut libc::epoll_event, // never mapped
            4,
            0,
        );
        report!(bad_buffer_rc = rc, bad_buffer_errno = errno());
        libc::close(empty);
        let rc = libc::epoll_wait(empty, out.as_mut_ptr(), 4, 0);
        report!(closed_epfd_rc = rc, closed_epfd_errno = errno());

        libc::close(ep);
        libc::close(efd);
    }
}
