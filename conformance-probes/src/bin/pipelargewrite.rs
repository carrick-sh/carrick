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
    }
}
