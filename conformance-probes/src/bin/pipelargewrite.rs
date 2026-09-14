//! A single blocking `write(2)` of a >64 KiB buffer through a pipe must arrive
//! at the reader BYTE-FOR-BYTE, in order, exactly once — Linux delivers the
//! stream verbatim.
//!
//! Regression e33f8973 ("match Linux epoll edge cases") added pipe-capacity
//! write accounting to carrick's host-pipe write loop. When a blocking pipe
//! filled mid-write (after partial progress, `offset > 0`), the `room == 0`
//! branch returned `would_block_outcome`, which re-dispatched the guest
//! `write(2)` FROM OFFSET 0 on wake — re-sending the already-delivered prefix.
//! Any >64 KiB blocking-pipe stream was duplicated past the first 64 KiB, e.g.
//! dpkg's decompressed `data.tar` got a corrupt header ("invalid tar header
//! size field") and `apt-get install` exited 100.
//!
//! This probe forks a writer child that does ONE `write()` of 256 KiB of a
//! known 4-byte little-endian counter pattern (word[i] == i) — a period-65536
//! pattern so a 16384-word (64 KiB) duplication cannot alias into a match. The
//! parent reads exactly 256 KiB back and asserts every word is at its expected
//! index. Pre-fix carrick re-sends words 0.. at read position 16384 (expected
//! 16384, got 0) → mismatch; post-fix the stream is intact.
//!
//!  * pipe_large_write_intact: 256 KiB read back byte-for-byte identical, in
//!    order, with no duplicated prefix.

use conformance_probes::{reap, report};

const LEN: usize = 256 * 1024; // > LINUX pipe capacity (64 KiB): forces multiple fills
const WORDS: usize = LEN / 4;

fn writev_bad_tail(first_len: usize, second_len: usize) -> (i64, usize, bool) {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return (-1, 0, false);
    }
    let [rd, wr] = fds;
    let writer = std::thread::spawn(move || {
        let first = vec![0x5a_u8; first_len];
        let second = vec![0x6b_u8; second_len];
        let vectors = [
            libc::iovec {
                iov_base: first.as_ptr() as *mut _,
                iov_len: first.len(),
            },
            libc::iovec {
                iov_base: second.as_ptr() as *mut _,
                iov_len: second.len(),
            },
            libc::iovec {
                iov_base: 1usize as *mut _,
                iov_len: 1,
            },
        ];
        let value = unsafe { libc::writev(wr, vectors.as_ptr(), vectors.len() as i32) };
        let value = if value < 0 {
            -(unsafe { *libc::__errno_location() } as i64)
        } else {
            value as i64
        };
        unsafe { libc::close(wr) };
        value
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut received = Vec::new();
    while std::time::Instant::now() < deadline {
        let mut pollfd = libc::pollfd {
            fd: rd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pollfd, 1, 100) };
        if ready < 0 {
            break;
        }
        if ready == 0 {
            continue;
        }
        let mut chunk = [0u8; 8192];
        let count = unsafe { libc::read(rd, chunk.as_mut_ptr().cast(), chunk.len()) };
        if count <= 0 {
            break;
        }
        received.extend_from_slice(&chunk[..count as usize]);
        if received.len() > first_len + second_len {
            break;
        }
    }
    unsafe { libc::close(rd) };
    let value = writer.join().unwrap_or(-1);
    let intact = received.len() <= first_len + second_len
        && received[..received.len().min(first_len)]
            .iter()
            .all(|byte| *byte == 0x5a)
        && received
            .get(first_len..)
            .unwrap_or_default()
            .iter()
            .all(|byte| *byte == 0x6b);
    (value, received.len(), intact)
}

fn closed_writer_keeps_inflight_endpoint() -> bool {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return false;
    }
    let [rd, wr] = fds;
    let writer = std::thread::spawn(move || {
        let payload = vec![0x5a_u8; LEN];
        // Another thread closes the numeric fd after this operation starts.
        // Linux retains the in-flight write's open file description.
        unsafe { libc::write(wr, payload.as_ptr().cast(), payload.len()) }
    });
    let mut pollfd = libc::pollfd {
        fd: rd,
        events: libc::POLLIN,
        revents: 0,
    };
    let started = unsafe { libc::poll(&mut pollfd, 1, 5000) } > 0;
    unsafe { libc::close(wr) };
    let mut received = vec![0u8; LEN];
    let mut offset = 0;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while started && offset < LEN {
        if std::time::Instant::now() >= deadline {
            break;
        }
        pollfd.revents = 0;
        let ready = unsafe { libc::poll(&mut pollfd, 1, 100) };
        if ready < 0 {
            break;
        }
        if ready == 0 {
            continue;
        }
        let count = unsafe { libc::read(rd, received[offset..].as_mut_ptr().cast(), LEN - offset) };
        if count <= 0 {
            break;
        }
        offset += count as usize;
    }
    unsafe { libc::close(rd) };
    let written = writer.join().unwrap_or(-1);
    started && written == LEN as isize && offset == LEN && received.iter().all(|b| *b == 0x5a)
}

/// All producers reach the barrier before filling independent pipes. The
/// reader then sleeps briefly, so blocked writes must release executor capacity
/// for it to resume. A host-thread wait inside a guest write can otherwise
/// occupy every bound executor even though the reader is runnable.
fn concurrent_writer_progress() -> bool {
    const WRITERS: usize = 32;
    let mut pipes: Vec<[i32; 2]> = Vec::with_capacity(WRITERS);
    for _ in 0..WRITERS {
        let mut fds = [-1; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            for [rd, wr] in pipes {
                unsafe {
                    libc::close(rd);
                    libc::close(wr);
                }
            }
            return false;
        }
        pipes.push(fds);
    }
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(WRITERS + 1));
    let payload: std::sync::Arc<Vec<u8>> = std::sync::Arc::new(
        (0..WORDS)
            .flat_map(|word| (word as u32).to_le_bytes())
            .collect(),
    );
    let mut writers = Vec::with_capacity(WRITERS);
    for &[_rd, wr] in &pipes {
        let barrier = std::sync::Arc::clone(&barrier);
        let payload = std::sync::Arc::clone(&payload);
        writers.push(std::thread::spawn(move || {
            barrier.wait();
            // No signal is sent during this operation. Linux completes the
            // blocking write; a continuation must preserve its original count.
            let written = unsafe { libc::write(wr, payload.as_ptr().cast(), payload.len()) };
            unsafe { libc::close(wr) };
            written == LEN as isize
        }));
    }
    barrier.wait();
    std::thread::sleep(std::time::Duration::from_millis(100));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut intact = true;
    for &[rd, _wr] in &pipes {
        let mut received = vec![0u8; LEN];
        let mut offset = 0;
        while intact && offset < LEN {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                intact = false;
                break;
            }
            let mut pollfd = libc::pollfd {
                fd: rd,
                events: libc::POLLIN,
                revents: 0,
            };
            let ready =
                unsafe { libc::poll(&mut pollfd, 1, remaining.as_millis().min(100) as i32) };
            if ready < 0 {
                intact = false;
                break;
            }
            if ready == 0 {
                continue;
            }
            let count =
                unsafe { libc::read(rd, received[offset..].as_mut_ptr().cast(), LEN - offset) };
            if count <= 0 {
                intact = false;
                break;
            }
            offset += count as usize;
        }
        intact &= offset == LEN && received.as_slice() == payload.as_slice();
        // Closing every reader also releases blocked writers on a failure.
        unsafe { libc::close(rd) };
    }
    for writer in writers {
        intact &= writer.join().unwrap_or(false);
    }
    intact
}

fn main() {
    unsafe {
        // The writer must see EPIPE (not die) if the reader closes early after
        // detecting corruption, so it can exit cleanly instead of wedging.
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);

        let mut fds = [0i32; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            report!(pipe_large_write_intact = false);
            return;
        }
        let (rd, wr) = (fds[0], fds[1]);

        // Known pattern: word[i] == i, so any re-sent 0.. prefix misaligns.
        let mut buf = vec![0u8; LEN];
        for i in 0..WORDS {
            buf[i * 4..i * 4 + 4].copy_from_slice(&(i as u32).to_le_bytes());
        }

        let pid = libc::fork();
        if pid == 0 {
            // Writer child: one big blocking write, then exit silently.
            libc::close(rd);
            let mut off = 0usize;
            while off < LEN {
                let n = libc::write(wr, buf[off..].as_ptr() as *const libc::c_void, LEN - off);
                if n <= 0 {
                    break; // reader closed (EPIPE) or error — nothing more to do
                }
                off += n as usize;
            }
            libc::close(wr);
            libc::_exit(0);
        }

        // Reader parent: pull exactly LEN bytes and verify order + identity.
        libc::close(wr);
        let mut recv = vec![0u8; LEN];
        let mut got = 0usize;
        let mut intact = true;
        while got < LEN {
            let n = libc::read(rd, recv[got..].as_mut_ptr() as *mut libc::c_void, LEN - got);
            if n <= 0 {
                intact = false; // short stream / EOF before LEN → corruption
                break;
            }
            got += n as usize;
        }
        if intact {
            for i in 0..WORDS {
                let w = u32::from_le_bytes([
                    recv[i * 4],
                    recv[i * 4 + 1],
                    recv[i * 4 + 2],
                    recv[i * 4 + 3],
                ]);
                if w != i as u32 {
                    intact = false;
                    break;
                }
            }
        }

        libc::close(rd); // break the writer if it is still looping (RED path)
        let _ = reap(pid);

        report!(pipe_large_write_intact = intact);
        let (value, bytes, intact) = writev_bad_tail(LEN, 32);
        report!(pipe_writev_bad_tail_return = value);
        report!(pipe_writev_bad_tail_bytes = bytes);
        report!(pipe_writev_bad_tail_prefix_intact = intact);
        let (value, bytes, intact) = writev_bad_tail(LEN, 4096);
        report!(pipe_writev_page_tail_return = value);
        report!(pipe_writev_page_tail_bytes = bytes);
        report!(pipe_writev_page_tail_prefix_intact = intact);
        let (value, bytes, intact) = writev_bad_tail(LEN, 65536);
        report!(pipe_writev_capacity_tail_return = value);
        report!(pipe_writev_capacity_tail_bytes = bytes);
        report!(pipe_writev_capacity_tail_prefix_intact = intact);
        for (name, first, second) in [
            ("unaligned_before", LEN - 1, 4096),
            ("unaligned_after", LEN + 1, 4096),
            ("page_plus_one", LEN, 4097),
            ("current_partial_page", LEN + 1, 32),
        ] {
            let (value, bytes, intact) = writev_bad_tail(first, second);
            println!("pipe_writev_{name}_return={value}");
            println!("pipe_writev_{name}_bytes={bytes}");
            println!("pipe_writev_{name}_prefix_intact={intact}");
        }
        report!(pipe_closed_writer_inflight_endpoint = closed_writer_keeps_inflight_endpoint());
        report!(pipe_concurrent_writers_progress = concurrent_writer_progress());
    }
}
