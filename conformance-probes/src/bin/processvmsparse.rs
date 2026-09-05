//! `process_vm_readv` across a remote buffer whose pages are only partly
//! resident.
//!
//! Stands in for LTP `process_vm_readv03`'s large case (8 local iovecs,
//! 131072 bytes), which returned 18368 with no errno under carrick.
//!
//! Invariants encoded, all boolean:
//!
//!   * A 128 KiB anonymous buffer in the child with only its first and its
//!     twentieth page written is read by the parent in one call through
//!     eight 16 KiB local iovecs: the call returns the full length.
//!   * The two written pages read back with their patterns and an untouched
//!     page reads back as zeros (Linux reads a never-touched anonymous page
//!     as the zero page; it does not stop there).
//!   * The same buffer read through four 32 KiB remote iovecs and eight
//!     16 KiB local iovecs also returns the full length.
//!
//! Deterministic output: booleans only.

use conformance_probes::{errno, report};

const PAGE: usize = 4096;
const LEN: usize = 128 * 1024;

unsafe fn remote_read(pid: libc::pid_t, remote_base: usize, remote_chunks: usize) -> isize {
    let mut local_buf = vec![0xEEu8; LEN];
    let local: Vec<libc::iovec> = (0..8)
        .map(|i| libc::iovec {
            iov_base: local_buf.as_mut_ptr().add(i * (LEN / 8)) as *mut libc::c_void,
            iov_len: LEN / 8,
        })
        .collect();
    let remote: Vec<libc::iovec> = (0..remote_chunks)
        .map(|i| libc::iovec {
            iov_base: (remote_base + i * (LEN / remote_chunks)) as *mut libc::c_void,
            iov_len: LEN / remote_chunks,
        })
        .collect();
    let n = libc::process_vm_readv(pid, local.as_ptr(), 8, remote.as_ptr(), remote_chunks as u64, 0);
    if n == LEN as isize {
        // Stash the checks in the return code's sign bits via globals instead
        // of printing numerals: keep the probe boolean.
        CHECK_FIRST = local_buf[0] == 0xAB;
        CHECK_MID = local_buf[20 * PAGE] == 0xCD;
        CHECK_ZERO = local_buf[10 * PAGE] == 0 && local_buf[31 * PAGE + 100] == 0;
    }
    n
}

static mut CHECK_FIRST: bool = false;
static mut CHECK_MID: bool = false;
static mut CHECK_ZERO: bool = false;

fn main() {
    unsafe {
        let mut pfd = [0i32; 2];
        assert_eq!(libc::pipe(pfd.as_mut_ptr()), 0);
        let pid = libc::fork();
        assert!(pid >= 0);
        if pid == 0 {
            libc::close(pfd[0]);
            let p = libc::mmap(
                std::ptr::null_mut(),
                LEN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            ) as *mut u8;
            assert!(p as isize != -1);
            *p = 0xAB;
            *p.add(20 * PAGE) = 0xCD;
            let addr = p as usize;
            libc::write(pfd[1], &addr as *const usize as *const libc::c_void, 8);
            libc::close(pfd[1]);
            libc::pause();
            libc::_exit(0);
        }
        libc::close(pfd[1]);
        let mut addr = 0usize;
        let got = libc::read(pfd[0], &mut addr as *mut usize as *mut libc::c_void, 8);
        assert_eq!(got, 8);

        let n1 = remote_read(pid, addr, 1);
        let one_remote_full_length = n1 == LEN as isize;
        let (first, mid, zero) = (CHECK_FIRST, CHECK_MID, CHECK_ZERO);
        let n2 = remote_read(pid, addr, 4);
        let four_remote_full_length = n2 == LEN as isize;
        let read_errno_zero_on_short = n1 == LEN as isize || errno() != 0;

        report!(
            one_remote_iov_full_length = one_remote_full_length,
            written_first_page_preserved = first,
            written_middle_page_preserved = mid,
            untouched_pages_read_as_zero = zero,
            four_remote_iovs_full_length = four_remote_full_length,
            short_read_carries_errno = read_errno_zero_on_short,
        );
        libc::kill(pid, libc::SIGKILL);
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
    }
}
