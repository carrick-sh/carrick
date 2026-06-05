//! MANY edge-triggered pipe read-ends in ONE epoll, many child writers exiting
//! concurrently — the faithful `cmd/go`/`cgo` fan-out shape (it spawns several
//! compiler children at once, each on its own output pipe, all watched by one
//! netpoll epoll instance). A single LOST EOF edge among the fan-out leaves the
//! netpoller parked forever = the `go build <cgo>` / `TestCoroCgoCallback` hang.
//!
//! Each pipe j's read-end is registered `EPOLLIN|EPOLLOUT|EPOLLRDHUP|EPOLLET`
//! (Go's mask). Each child owns exactly ONE write end (it closes every other
//! pipe's write end, mimicking dup-to-stdout + O_CLOEXEC), writes a byte, then
//! exits at a staggered delay so the EOF edges land while the parent is parked
//! in `epoll_wait` and overlap with each other. The parent collects ready fds,
//! drains each to EOF, and counts how many of N reached EOF.
//!
//! INVARIANT: all N read-ends reach EOF (every writer-close edge is delivered).
//! Deterministic: prints the EOF count as `N/N`. Every wait is bounded so a lost
//! edge prints a short count instead of hanging.

use conformance_probes::report;

const EPOLLET: u32 = 0x8000_0000;
const N: usize = 8;

fn main() {
    unsafe {
        let mut rd = [0i32; N];
        let mut wr = [0i32; N];
        for i in 0..N {
            let mut fds = [0i32; 2];
            if libc::pipe(fds.as_mut_ptr()) != 0 {
                report!(pipe_ok = false);
                return;
            }
            rd[i] = fds[0];
            wr[i] = fds[1];
            let fl = libc::fcntl(rd[i], libc::F_GETFL, 0);
            libc::fcntl(rd[i], libc::F_SETFL, fl | libc::O_NONBLOCK);
        }

        let ep = libc::epoll_create1(0);
        let mask = libc::EPOLLIN as u32 | libc::EPOLLOUT as u32 | libc::EPOLLRDHUP as u32 | EPOLLET;
        for i in 0..N {
            let mut ev = libc::epoll_event {
                events: mask,
                u64: rd[i] as u64,
            };
            libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, rd[i], &mut ev);
        }

        for i in 0..N {
            let pid = libc::fork();
            if pid == 0 {
                // Child i owns wr[i] only — close every read end and every other
                // write end (mimics dup-to-stdout + O_CLOEXEC on the rest).
                libc::close(ep);
                for j in 0..N {
                    libc::close(rd[j]);
                    if j != i {
                        libc::close(wr[j]);
                    }
                }
                libc::write(wr[i], b"x".as_ptr().cast(), 1);
                // Staggered exit so EOF edges arrive while the parent is parked
                // and overlap with one another.
                libc::usleep((100_000 + i as u32 * 40_000) as libc::useconds_t);
                libc::_exit(0);
            }
        }

        // Parent: drop ALL its write-end copies so each pipe's sole remaining
        // writer is its child — otherwise no read end ever reaches EOF.
        for i in 0..N {
            libc::close(wr[i]);
        }

        // Collect EOFs: wake on edges, drain each ready fd; an fd that reads 0 is
        // at EOF. Count distinct fds that reached EOF, bounded.
        let mut eof = [false; N];
        let mut eof_count = 0usize;
        let mut out = [libc::epoll_event { events: 0, u64: 0 }; (N + 4)];
        let mut buf = [0u8; 64];
        // At most a few hundred ms of staggered exits; cap total waits.
        for _ in 0..60 {
            if eof_count == N {
                break;
            }
            let n = libc::epoll_wait(ep, out.as_mut_ptr(), out.len() as i32, 1000);
            if n <= 0 {
                continue;
            }
            for ev in out.iter().take(n as usize) {
                let fd = ev.u64 as i32;
                let idx = rd.iter().position(|&x| x == fd);
                let Some(idx) = idx else { continue };
                if eof[idx] {
                    continue;
                }
                // Drain; read()==0 means EOF (last writer closed).
                loop {
                    let r = libc::read(fd, buf.as_mut_ptr().cast(), buf.len());
                    if r == 0 {
                        eof[idx] = true;
                        eof_count += 1;
                        break;
                    } else if r < 0 {
                        break; // EAGAIN: not yet at EOF, wait for the next edge
                    }
                }
            }
        }

        for i in 0..N {
            libc::close(rd[i]);
            let mut st = 0i32;
            libc::wait(&mut st);
            let _ = i;
        }
        libc::close(ep);

        // Single deterministic line: how many of N reached EOF.
        let summary = format!("{eof_count}/{N}");
        report!(eofs_delivered = summary);
    }
}
