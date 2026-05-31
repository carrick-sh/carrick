//! Anonymous-temp-file writes from a thread, plus atime stability across a
//! directory enumeration — the two carrick gaps behind CPython `test_mailbox`
//! (`tempfile.TemporaryFile` round-trips + `mailbox.Maildir.clean`).
//!
//! 1. **O_TMPFILE / memfd_create writes work on the threaded path.** carrick's
//!    multithreaded run-loop (`dispatch_threaded`) gated `write(2)` behind a
//!    per-fd allowlist that only covered host-fd / pipe / socket / eventfd
//!    descriptors — an in-memory anonymous file (O_TMPFILE, memfd_create) fell
//!    through to the "unhandled syscall → ENOSYS" dead-end, so a worker thread
//!    writing a `tempfile.TemporaryFile` got `OSError: [Errno 38] Function not
//!    implemented` even though `read`/`lseek`/`writev` all worked on the same
//!    fd. The write is done from a SPAWNED THREAD so the guest is genuinely
//!    multithreaded (single-threaded guests never hit the gate). We then seek
//!    to 0 and read the bytes back: a faithful anonymous file round-trips.
//!
//! 2. **utime'd atime survives a getdents enumeration.** On a strict-atime
//!    APFS scratch, carrick read each file's guest-mode xattr (every stat) and
//!    its size (every directory read) by `open()`ing the file — which bumped
//!    the access time to "now", silently undoing a guest
//!    `utimensat(path, {past_atime, ...})`. We set atime far in the past,
//!    enumerate the parent directory (opendir/readdir → getdents), then
//!    re-stat: the atime must still be the past value, NOT "now".
//!
//! Pure booleans; bounded; no raw times/pids/addrs cross the diff boundary.

use conformance_probes::report;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

const O_TMPFILE: i32 = 0o20000000 | 0o200000; // __O_TMPFILE | O_DIRECTORY
const MEMFD_CLOEXEC: u32 = 0x0001;
const PAYLOAD: &[u8] = b"carrick anon tempfile payload\n";

/// Write PAYLOAD to `fd`, rewind, read it back; return the bytes read.
unsafe fn roundtrip(fd: i32) -> Vec<u8> {
    let w = libc::write(fd, PAYLOAD.as_ptr() as *const libc::c_void, PAYLOAD.len());
    if w != PAYLOAD.len() as isize {
        return Vec::new();
    }
    if libc::lseek(fd, 0, libc::SEEK_SET) != 0 {
        return Vec::new();
    }
    let mut buf = vec![0u8; PAYLOAD.len()];
    let r = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
    if r < 0 {
        return Vec::new();
    }
    buf.truncate(r as usize);
    buf
}

fn main() {
    unsafe {
        libc::mkdir(b"/tmp\0".as_ptr() as *const libc::c_char, 0o777);

        // --- (1) anonymous-file writes from a worker thread ---------------
        // memfd_create: anonymous in-memory file. carrick models this (and
        // O_TMPFILE) as the same in-kernel `OpenDescription::File` shape that
        // CPython's `tempfile.TemporaryFile` lands on. memfd is the portable
        // probe: O_TMPFILE support is FILESYSTEM-DEPENDENT (the Docker oracle's
        // /tmp overlayfs rejects it with EINVAL, so a guest tempfile falls back
        // to mkstemp+unlink there) — asserting on O_TMPFILE-on-/tmp would diff
        // on an environment capability, not on carrick's write emulation. We
        // still open O_TMPFILE and feed it through the same round-trip when the
        // fs supports it, but only `memfd_*` is reported.
        let tmpfile_fd = libc::open(
            b"/tmp\0".as_ptr() as *const libc::c_char,
            libc::O_RDWR | O_TMPFILE,
            0o600,
        );
        let memfd = libc::memfd_create(
            b"carrick-probe\0".as_ptr() as *const libc::c_char,
            MEMFD_CLOEXEC,
        );

        // Hand the fds to a spawned thread so the guest is genuinely
        // multithreaded and the writes traverse the threaded dispatcher (where
        // the write-to-in-memory-File gap lived — a single-threaded guest never
        // hits it).
        let memfd_match = Arc::new(AtomicI64::new(-1));
        let mm = memfd_match.clone();
        let h = std::thread::spawn(move || unsafe {
            if tmpfile_fd >= 0 {
                // Exercise the same path when available; result not reported.
                let _ = roundtrip(tmpfile_fd);
            }
            if memfd >= 0 {
                mm.store((roundtrip(memfd) == PAYLOAD) as i64, Ordering::SeqCst);
            } else {
                mm.store(0, Ordering::SeqCst);
            }
        });
        let _ = h.join();
        if tmpfile_fd >= 0 {
            libc::close(tmpfile_fd);
        }
        if memfd >= 0 {
            libc::close(memfd);
        }

        report!(
            memfd_open_ok = memfd >= 0,
            memfd_thread_roundtrip = memfd_match.load(Ordering::SeqCst) == 1,
        );

        // --- (2) utime'd atime survives a directory enumeration -----------
        let dir = b"/tmp/carrick_atime_dir\0";
        libc::mkdir(dir.as_ptr() as *const libc::c_char, 0o755);
        let file = b"/tmp/carrick_atime_dir/foo\0";
        let fd = libc::open(
            file.as_ptr() as *const libc::c_char,
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        let mut atime_setup = false;
        let mut atime_survives = false;
        if fd >= 0 {
            libc::write(fd, b"@".as_ptr() as *const libc::c_void, 1);
            // Current mtime (preserve it) + an atime ~36h in the past.
            let mut st: libc::stat = std::mem::zeroed();
            libc::fstat(fd, &mut st);
            libc::close(fd);
            let now = libc::time(std::ptr::null_mut());
            let past_atime = now - 200_000; // > clean()'s 129600s cutoff
            let times = [
                libc::timespec {
                    tv_sec: past_atime as libc::time_t,
                    tv_nsec: 0,
                },
                libc::timespec {
                    tv_sec: st.st_mtime,
                    tv_nsec: 0,
                },
            ];
            let rc = libc::utimensat(
                libc::AT_FDCWD,
                file.as_ptr() as *const libc::c_char,
                times.as_ptr(),
                0,
            );
            // Right after utime: atime is the past value we set.
            let mut s1: libc::stat = std::mem::zeroed();
            libc::stat(file.as_ptr() as *const libc::c_char, &mut s1);
            atime_setup = rc == 0 && (s1.st_atime - past_atime).abs() <= 2;

            // Enumerate the directory (opendir/readdir → getdents), exactly
            // what mailbox.Maildir.clean does before its getatime sweep.
            let d = libc::opendir(dir.as_ptr() as *const libc::c_char);
            if !d.is_null() {
                loop {
                    let e = libc::readdir(d);
                    if e.is_null() {
                        break;
                    }
                }
                libc::closedir(d);
            }

            // Re-stat: the atime must STILL be the past value (not "now").
            let mut s2: libc::stat = std::mem::zeroed();
            libc::stat(file.as_ptr() as *const libc::c_char, &mut s2);
            atime_survives = (s2.st_atime - past_atime).abs() <= 2;
        }

        report!(
            atime_set_in_past = atime_setup,
            atime_survives_readdir = atime_survives,
        );

        libc::unlink(file.as_ptr() as *const libc::c_char);
        libc::rmdir(dir.as_ptr() as *const libc::c_char);
    }
}
