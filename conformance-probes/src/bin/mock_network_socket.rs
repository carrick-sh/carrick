//! Conformance probe for in-memory and mock network socket semantics:
//! - File description flags (`F_GETFL`, `F_SETFL`, `O_NONBLOCK`).
//! - Errno behavior on non-blocking reads (`EAGAIN`) and invalid operations.
//! - Readiness via `select`, `poll`, and `epoll` with `EPOLLET` (edge-triggered).
//! - Partial I/O chunking across multiple reads.
//! - `shutdown(SHUT_WR)` half-close and EOF propagation.
//! - `SIGPIPE` / `EPIPE` when writing to a closed/broken peer.
//! - Descriptor duplication (`dup`), independent closes, and resource lifetime.

use conformance_probes::{errno, report};
use std::mem::MaybeUninit;

const EPOLLET: u32 = 0x8000_0000;
const LINUX_EAGAIN: i32 = 11;
const LINUX_EPIPE: i32 = 32;

#[cfg(target_os = "linux")]
use libc::{epoll_create1, epoll_ctl, epoll_event, epoll_wait, EPOLLIN, EPOLL_CTL_ADD};

#[cfg(not(target_os = "linux"))]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct epoll_event {
    pub events: u32,
    pub u64: u64,
}

#[cfg(not(target_os = "linux"))]
const EPOLLIN: u32 = 1;
#[cfg(not(target_os = "linux"))]
const EPOLL_CTL_ADD: i32 = 1;

#[cfg(not(target_os = "linux"))]
unsafe fn epoll_create1(_flags: i32) -> i32 {
    -1
}
#[cfg(not(target_os = "linux"))]
unsafe fn epoll_ctl(_epfd: i32, _op: i32, _fd: i32, _event: *mut epoll_event) -> i32 {
    -1
}
#[cfg(not(target_os = "linux"))]
unsafe fn epoll_wait(_epfd: i32, _events: *mut epoll_event, _maxevents: i32, _timeout: i32) -> i32 {
    -1
}

fn main() {
    unsafe {
        // 1. Socket creation and fd flags (O_NONBLOCK)
        let sock = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        let sock_created = sock >= 0;
        let initial_flags = libc::fcntl(sock, libc::F_GETFL, 0);
        let setfl_rc = libc::fcntl(sock, libc::F_SETFL, initial_flags | libc::O_NONBLOCK);
        let updated_flags = libc::fcntl(sock, libc::F_GETFL, 0);
        let nonblock_set = setfl_rc == 0 && (updated_flags & libc::O_NONBLOCK) != 0;
        libc::close(sock);

        // 2. Connected socket pair for semantic tests
        let mut pair = [0i32; 2];
        let pair_rc = libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr());
        let socketpair_ok = pair_rc == 0;
        let (s1, s2) = (pair[0], pair[1]);

        // Make both non-blocking
        let f1 = libc::fcntl(s1, libc::F_GETFL, 0);
        libc::fcntl(s1, libc::F_SETFL, f1 | libc::O_NONBLOCK);
        let f2 = libc::fcntl(s2, libc::F_GETFL, 0);
        libc::fcntl(s2, libc::F_SETFL, f2 | libc::O_NONBLOCK);

        // 3. Non-blocking read on empty socket returns EAGAIN
        let mut dummy = [0u8; 16];
        let empty_read_rc = libc::read(s2, dummy.as_mut_ptr() as *mut _, dummy.len());
        let read_eagain = empty_read_rc == -1 && errno() == LINUX_EAGAIN;

        // 4. Partial I/O & multi-chunk writes
        let msg = b"HELLO_MOCK_NET";
        let write_rc = libc::write(s1, msg.as_ptr() as *const _, msg.len());
        let full_write_ok = write_rc == msg.len() as isize;

        // 5. Readiness via select and poll
        let mut rset: libc::fd_set = MaybeUninit::zeroed().assume_init();
        libc::FD_ZERO(&mut rset);
        libc::FD_SET(s2, &mut rset);
        let mut tv = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        let select_rc = libc::select(
            s2 + 1,
            &mut rset,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut tv,
        );
        let select_readable = select_rc == 1 && libc::FD_ISSET(s2, &rset);

        let mut pfd = libc::pollfd {
            fd: s2,
            events: libc::POLLIN,
            revents: 0,
        };
        let poll_rc = libc::poll(&mut pfd as *mut _, 1, 1000);
        let poll_readable = poll_rc == 1 && (pfd.revents & libc::POLLIN) != 0;

        // 6. Edge-triggered epoll (EPOLLET)
        let epfd = epoll_create1(0);
        let mut ev = epoll_event {
            events: (EPOLLIN as u32) | EPOLLET,
            u64: s2 as u64,
        };
        let ctl_rc = epoll_ctl(epfd, EPOLL_CTL_ADD, s2, &mut ev);
        let epoll_add_ok = ctl_rc == 0;

        let mut out_events = [epoll_event { events: 0, u64: 0 }; 4];
        let epoll_wait1 = epoll_wait(epfd, out_events.as_mut_ptr(), 4, 1000);
        let epoll_edge1 = epoll_wait1 == 1 && (out_events[0].events & EPOLLIN as u32) != 0;

        // Read 5 bytes (partial)
        let mut chunk1 = [0u8; 5];
        let read_chunk1 = libc::read(s2, chunk1.as_mut_ptr() as *mut _, 5);
        let partial_read_ok = read_chunk1 == 5 && &chunk1 == b"HELLO";

        // Second epoll_wait without new writes: under EPOLLET it must NOT fire (timeout returns 0)
        let epoll_wait2 = epoll_wait(epfd, out_events.as_mut_ptr(), 4, 10);
        let epollet_no_spurious_edge = epoll_wait2 == 0;

        // Read the remaining bytes
        let mut chunk2 = [0u8; 9];
        let read_chunk2 = libc::read(s2, chunk2.as_mut_ptr() as *mut _, 9);
        let full_drain_ok = read_chunk2 == 9 && &chunk2 == b"_MOCK_NET";

        libc::close(epfd);

        // 7. dup / close sharing
        let s1_dup = libc::dup(s1);
        let dup_ok = s1_dup >= 0 && s1_dup != s1;
        libc::close(s1); // Close original s1, s1_dup should still be valid writer

        let test_payload = b"DUP_TEST";
        let dup_write = libc::write(s1_dup, test_payload.as_ptr() as *const _, test_payload.len());
        let dup_write_ok = dup_write == test_payload.len() as isize;

        let mut dup_read_buf = [0u8; 8];
        let dup_read = libc::read(s2, dup_read_buf.as_mut_ptr() as *mut _, 8);
        let dup_read_ok = dup_read == 8 && &dup_read_buf == test_payload;

        // 8. shutdown(SHUT_WR) and half-close EOF
        let shut_rc = libc::shutdown(s1_dup, libc::SHUT_WR);
        let shutdown_ok = shut_rc == 0;

        // Writing after shutdown write end returns EPIPE
        let post_shut_write = libc::send(
            s1_dup,
            b"FAIL".as_ptr() as *const _,
            4,
            libc::MSG_NOSIGNAL,
        );
        let shut_write_epipe = post_shut_write == -1 && errno() == LINUX_EPIPE;

        // Reader on s2 receives EOF (0)
        let mut eof_buf = [0u8; 4];
        let eof_read = libc::read(s2, eof_buf.as_mut_ptr() as *mut _, 4);
        let eof_received = eof_read == 0;

        libc::close(s1_dup);
        libc::close(s2);

        report!(
            sock_created = sock_created,
            nonblock_set = nonblock_set,
            socketpair_ok = socketpair_ok,
            read_eagain = read_eagain,
            full_write_ok = full_write_ok,
            select_readable = select_readable,
            poll_readable = poll_readable,
            epoll_add_ok = epoll_add_ok,
            epoll_edge1 = epoll_edge1,
            partial_read_ok = partial_read_ok,
            epollet_no_spurious_edge = epollet_no_spurious_edge,
            full_drain_ok = full_drain_ok,
            dup_ok = dup_ok,
            dup_write_ok = dup_write_ok,
            dup_read_ok = dup_read_ok,
            shutdown_ok = shutdown_ok,
            shut_write_epipe = shut_write_epipe,
            eof_received = eof_received,
        );
    }
}
