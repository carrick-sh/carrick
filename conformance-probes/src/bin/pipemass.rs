//! A guest `pipe(2)` costs the guest two descriptors and nothing on the host
//! until someone polls it. This is LTP `pipe06`'s shape — open pipes until
//! `EMFILE` — bounded to a fixed soft `RLIMIT_NOFILE` so the count is
//! lane-independent, then followed by the operations that a runtime paying
//! host resources per guest pipe gets wrong:
//!
//! - the pipe count must be exactly what the soft limit allows (two fds per
//!   pipe, one slot left over), and the failing call must report `EMFILE`;
//! - the single remaining slot must still open a REGULAR file;
//! - the last pipe must be pollable and carry a byte end to end;
//! - once that pipe is closed, its slots must still open a SOCKET — the one
//!   object here that is host-backed under every lane. A runtime that spends
//!   host descriptors on every guest pipe has exhausted its own process's
//!   table long before the guest's, and that `socket` fails `EMFILE` against
//!   a guest limit that still has room.
//!
//! Linux allocates a pipe's pages on first write, so 100k idle pipes cost a
//! few hundred bytes each; `pipe06` creates 524k of them in ~1.6 s.

const SOFT_NOFILE: libc::rlim_t = 200_000;

fn main() {
    unsafe {
        // Keep the hard limit as it is; only the soft ceiling matters here.
        let mut current: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut current) != 0 {
            println!("getrlimit=errno{}", *libc::__errno_location());
            return;
        }
        let limit = libc::rlimit {
            rlim_cur: SOFT_NOFILE,
            rlim_max: current.rlim_max,
        };
        if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
            println!("setrlimit=errno{}", *libc::__errno_location());
            return;
        }
        println!("soft_nofile={SOFT_NOFILE}");

        let mut pipes: Vec<[libc::c_int; 2]> = Vec::with_capacity(SOFT_NOFILE as usize / 2);
        let mut fds = [-1; 2];
        let fail_errno = loop {
            if libc::pipe(fds.as_mut_ptr()) != 0 {
                break *libc::__errno_location();
            }
            pipes.push(fds);
        };
        let opened = pipes.len() * 2;
        let highest = pipes.last().map_or(-1, |p| p[0].max(p[1]));
        println!(
            "pipes={} fds_opened={opened} highest_fd={highest} fail={}",
            pipes.len(),
            if fail_errno == libc::EMFILE {
                "EMFILE".to_string()
            } else {
                format!("errno{fail_errno}")
            }
        );

        // One descriptor slot remains: a regular file must still open.
        let path = c"/tmp/pipemass";
        let file = libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        );
        if file < 0 {
            println!("open_last_slot=errno{}", *libc::__errno_location());
        } else {
            println!("open_last_slot=ok fd_is_last={}", file == SOFT_NOFILE as libc::c_int - 1);
            libc::close(file);
        }
        libc::unlink(path.as_ptr());

        // The last pipe is a real pipe: writable, then readable, one byte.
        if let Some(last) = pipes.last() {
            let mut out = libc::pollfd {
                fd: last[1],
                events: libc::POLLOUT,
                revents: 0,
            };
            let rc = libc::poll(&mut out, 1, 1000);
            println!("last_writable poll={rc} pollout={}", out.revents & libc::POLLOUT != 0);
            let w = libc::write(last[1], b"z".as_ptr().cast(), 1);
            let mut inp = libc::pollfd {
                fd: last[0],
                events: libc::POLLIN,
                revents: 0,
            };
            let rc = libc::poll(&mut inp, 1, 1000);
            let mut byte = 0u8;
            let r = libc::read(last[0], (&mut byte as *mut u8).cast(), 1);
            println!(
                "last_roundtrip write={w} poll={rc} pollin={} read={r} byte={}",
                inp.revents & libc::POLLIN != 0,
                byte as char
            );
        }

        // Free the last pipe's two slots; a host-backed socket must land in
        // the lower one.
        if let Some(last) = pipes.pop() {
            libc::close(last[0]);
            libc::close(last[1]);
            let sock = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            if sock < 0 {
                println!("socket_in_freed_slot=errno{}", *libc::__errno_location());
            } else {
                println!(
                    "socket_in_freed_slot=ok fd_reuses_slot={}",
                    sock == last[0].min(last[1])
                );
                libc::close(sock);
            }
        }

        for p in &pipes {
            libc::close(p[0]);
            libc::close(p[1]);
        }
        println!("closed={}", pipes.len() + 1);
    }
}
