//! `/proc/<pid>/mem` must never hand back the READER's own memory labelled as
//! another process's.
//!
//! carrick serves `/proc/<pid>/mem` by treating the file offset as a guest
//! virtual address and reading it out of the CALLER's address space. The path
//! predicate accepted any all-digit pid, so `/proc/<peer>/mem` returned the
//! reader's bytes at that address — plausible garbage presented as the target's,
//! with nothing to indicate the read had failed. Silent wrong data is worse than
//! an error: a debugger or test gets an answer it cannot distinguish from truth.
//!
//! The probe writes one marker into a page, forks a child that overwrites its
//! (now private, post-COW) copy with a DIFFERENT marker, and reads the child's
//! `/proc/<child>/mem` at that address.
//!
//!  * peer_mem_returned_reader_bytes: the reader's own marker came back as the
//!    peer's memory. MUST be false — this is the lie. Linux either returns the
//!    child's bytes or fails; it never substitutes the caller's.
//!  * dead_pid_mem_open: `/proc/<never-allocated>/mem` opens. MUST be false;
//!    Linux is ENOENT because the process directory does not exist.
//!  * self_mem_reads_own_marker / self_numeric_mem_reads_own_marker: the
//!    reader's OWN mem still works, by `self` alias and by its own pid spelled
//!    numerically. The numeric form is what a tightened predicate breaks first.
//!
//! Deliberately NOT asserted: whether the peer read SUCCEEDS. Linux permits it
//! for a ptrace-eligible target, and carrick cannot address a non-current
//! HVPatch `mm` at all, so that capability gap is tracked separately rather
//! than encoded as a permanently-red line here.

use conformance_probes::report;
use std::ffi::CString;

const READER_MARK: &[u8; 8] = b"READERAA";
const PEER_MARK: &[u8; 8] = b"PEERBBBB";

/// The 8 bytes at guest VA `va` as seen through `path`, via the `lseek`+`read`
/// idiom `/proc/<pid>/mem` is addressed with. `None` if the open or read fails.
fn read_marker_at(path: &str, va: u64) -> Option<[u8; 8]> {
    let c = CString::new(path).ok()?;
    unsafe {
        let fd = libc::open(c.as_ptr(), libc::O_RDONLY);
        if fd < 0 {
            return None;
        }
        let mut got = [0u8; 8];
        libc::lseek(fd, va as libc::off_t, libc::SEEK_SET);
        let n = libc::read(fd, got.as_mut_ptr().cast(), got.len());
        libc::close(fd);
        (n == got.len() as isize).then_some(got)
    }
}

fn main() {
    unsafe {
        let len = 4096;
        let buf = libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        assert!(buf != libc::MAP_FAILED, "probe needs an anonymous page");
        std::ptr::copy_nonoverlapping(READER_MARK.as_ptr(), buf as *mut u8, READER_MARK.len());
        let va = buf as u64;

        // The child must signal that its overwrite has landed before the parent
        // reads, or a slow child turns the assertion into a race.
        let mut ready: [libc::c_int; 2] = [0; 2];
        assert!(libc::pipe(ready.as_mut_ptr()) == 0, "probe needs a pipe");

        let child = libc::fork();
        if child == 0 {
            libc::close(ready[0]);
            // COW-breaks the page, so parent and child now hold DIFFERENT bytes
            // at the same virtual address — which is exactly what distinguishes
            // "read the peer" from "read myself".
            std::ptr::copy_nonoverlapping(PEER_MARK.as_ptr(), buf as *mut u8, PEER_MARK.len());
            libc::write(ready[1], b"1".as_ptr().cast(), 1);
            libc::close(ready[1]);
            libc::sleep(30);
            libc::_exit(0);
        }
        assert!(child > 0, "probe requires a forked peer");
        libc::close(ready[1]);
        let mut ack = [0u8; 1];
        libc::read(ready[0], ack.as_mut_ptr().cast(), 1);
        libc::close(ready[0]);

        // `lseek` + `read`, NOT `pread`: that is the idiom every debugger uses
        // and the one carrick's `SyntheticFile` read arm special-cases. Measured
        // live, `pread` on the same fd returned 0 under carrick while
        // `lseek`+`read` returned the reader's marker, so a `pread`-only probe
        // would have reported this bug as absent.
        let peer_path = CString::new(format!("/proc/{child}/mem")).unwrap();
        let mut got = [0u8; 8];
        let mut peer_mem_returned_reader_bytes = false;
        let fd = libc::open(peer_path.as_ptr(), libc::O_RDONLY);
        if fd >= 0 {
            libc::lseek(fd, va as libc::off_t, libc::SEEK_SET);
            let n = libc::read(fd, got.as_mut_ptr().cast(), got.len());
            if n == got.len() as isize {
                peer_mem_returned_reader_bytes = &got == READER_MARK;
            }
            libc::close(fd);
        }

        // The reader's OWN mem must keep working, by alias and by its own pid
        // spelled numerically — the numeric form is what a tightened predicate
        // would break first, so it is asserted, not assumed.
        let own = libc::getpid();
        let self_mem_reads_own_marker = read_marker_at("/proc/self/mem", va) == Some(*READER_MARK);
        let self_numeric_mem_reads_own_marker =
            read_marker_at(&format!("/proc/{own}/mem"), va) == Some(*READER_MARK);

        let dead = CString::new("/proc/424242/mem").unwrap();
        let dead_fd = libc::open(dead.as_ptr(), libc::O_RDONLY);
        let dead_pid_mem_open = dead_fd >= 0;
        if dead_fd >= 0 {
            libc::close(dead_fd);
        }

        libc::kill(child, libc::SIGKILL);
        let mut status = 0;
        libc::waitpid(child, &mut status, 0);

        report!(
            peer_mem_returned_reader_bytes = peer_mem_returned_reader_bytes,
            dead_pid_mem_open = dead_pid_mem_open,
            self_mem_reads_own_marker = self_mem_reads_own_marker,
            self_numeric_mem_reads_own_marker = self_numeric_mem_reads_own_marker
        );
    }
}
