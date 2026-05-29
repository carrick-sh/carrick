//! epoll overflow-queue keying bug.
//!
//! carrick stores overflow-deferred ready events in a `pending_ready`
//! VecDeque<LinuxEpollEvent> that carries only (events, _pad, data) — it LOSES
//! the originating guest fd (dispatch/net.rs:1264-1278). `EPOLL_CTL_DEL`/`MOD`
//! then purge that queue with `pending_ready.retain(|e| e.data != fd as u64)`
//! (dispatch/net/support.rs:106-111). When the guest registered the fd with an
//! `event.data.u64` TOKEN that is not equal to the fd number — the normal case
//! (epoll data is a user cookie / pointer, not the fd) — the retain never
//! matches, so a queued event for a DELETED fd SURVIVES and is handed to the
//! next epoll_wait. Linux keys interest strictly by fd: after EPOLL_CTL_DEL the
//! fd can never produce another event.
//!
//! Trigger: register TWO ready fds, each with data != fd, then
//! epoll_pwait(maxevents=1). One event is returned, the OTHER overflows into
//! pending_ready (carrick splits the surplus at net.rs:1272-1278; acc is a
//! HashMap keyed by guest fd, value (events, token)). We don't know which fd
//! overflowed, so we DEL BOTH fds. After DEL of all interest, Linux's next
//! epoll_pwait MUST return 0. carrick (pre-fix) drains the stale pending_ready
//! entry first (net.rs:1067-1077) and returns it (>=1).
//!
//! Deterministic booleans only — no fds/addresses/times/sizes. Every wait is
//! bounded to <=200 ms so a broken path prints `false`, never hangs. The probe
//! ALWAYS prints the same four keys (setup failure -> all false) so the
//! line-for-line diff is stable regardless of which path is taken.

use conformance_probes::report;

const EPOLLIN: u32 = 0x001;

// Tokens deliberately unequal to any small fd number, so the buggy
// `data != fd` retain leaves the overflowed entry in place.
const TOKEN_A: u64 = 0xAAAA_0000_0000_0001;
const TOKEN_B: u64 = 0xBBBB_0000_0000_0002;

fn main() {
    unsafe { run() }
}

unsafe fn run() {
    // Default-false results so a setup failure still prints the full key set.
    let mut setup_ok = false;
    let mut first_returned_one = false;
    let mut first_data_is_token = false;
    let mut no_stale_event_after_del = false;

    // Two pipes; the read ends are the epoll targets, both made readable.
    let mut p1 = [0i32; 2];
    let mut p2 = [0i32; 2];
    if libc::pipe(p1.as_mut_ptr()) == 0 && libc::pipe(p2.as_mut_ptr()) == 0 {
        let rd_a = p1[0];
        let rd_b = p2[0];

        let epfd = libc::epoll_create1(0);
        if epfd >= 0 {
            // Register both read ends with TOKEN data (data.u64 != fd).
            let mut ev_a = libc::epoll_event { events: EPOLLIN, u64: TOKEN_A };
            let mut ev_b = libc::epoll_event { events: EPOLLIN, u64: TOKEN_B };
            let add_a = libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, rd_a, &mut ev_a);
            let add_b = libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, rd_b, &mut ev_b);

            // Make BOTH ready before the wait so the wait sees two ready fds.
            libc::write(p1[1], b"x".as_ptr().cast(), 1);
            libc::write(p2[1], b"y".as_ptr().cast(), 1);

            // maxevents=1: exactly one event is returned, the other is deferred
            // into carrick's pending_ready overflow queue.
            let mut out1 = [libc::epoll_event { events: 0, u64: 0 }; 1];
            let n1 = libc::epoll_pwait(epfd, out1.as_mut_ptr(), 1, 200, std::ptr::null());
            first_returned_one = n1 == 1;
            // The returned event must carry a TOKEN, never a raw fd number.
            first_data_is_token =
                n1 == 1 && (out1[0].u64 == TOKEN_A || out1[0].u64 == TOKEN_B);

            // DEL BOTH fds: Linux interest set is now empty regardless of which
            // fd overflowed. A correct runtime purges any deferred event too.
            let del_a =
                libc::epoll_ctl(epfd, libc::EPOLL_CTL_DEL, rd_a, std::ptr::null_mut());
            let del_b =
                libc::epoll_ctl(epfd, libc::EPOLL_CTL_DEL, rd_b, std::ptr::null_mut());

            setup_ok = add_a == 0 && add_b == 0 && del_a == 0 && del_b == 0;

            // Second wait: with no registered fds, Linux returns 0 (timeout).
            // carrick pre-fix returns the stale overflow event (>=1).
            let mut out2 = [libc::epoll_event { events: 0, u64: 0 }; 4];
            let n2 = libc::epoll_pwait(epfd, out2.as_mut_ptr(), 4, 200, std::ptr::null());
            no_stale_event_after_del = n2 == 0;

            libc::close(epfd);
        }
        libc::close(p1[0]);
        libc::close(p1[1]);
        libc::close(p2[0]);
        libc::close(p2[1]);
    }

    report!(
        setup_ok = setup_ok,
        first_returned_one = first_returned_one,
        first_data_is_token = first_data_is_token,
        // THE INVARIANT: after deleting every fd the next wait delivers nothing.
        // Linux: true (n2 == 0). pre-fix carrick: false (stale event delivered).
        no_stale_event_after_del = no_stale_event_after_del,
    );
}