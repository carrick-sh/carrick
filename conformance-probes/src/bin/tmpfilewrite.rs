//! O_TMPFILE write roundtrip on the MULTI-THREADED dispatch path.
//!
//! `open(dir, O_RDWR|O_TMPFILE)` yields an unnamed, writable regular inode.
//! carrick models it as an in-memory `OpenDescription::File`. On the
//! single-threaded run-loop a write(2) to that fd works, but the multithreaded
//! shared dispatcher's `write_shared_supported()` whitelist excluded the
//! in-memory `File` kind, so write(2) fell through to ENOSYS — but ONLY once
//! the guest had become multithreaded. `tempfile.TemporaryFile()` (which uses
//! O_TMPFILE) therefore failed under threaded CPython, surfacing as 58 ERRORs
//! in test_csv (every test that wrote through a TemporaryFile).
//!
//! To exercise the threaded path deterministically, this probe spawns a helper
//! thread FIRST (forcing carrick onto its multithreaded run-loop), then on the
//! main thread does the O_TMPFILE write/seek/read roundtrip and prints the
//! relationships (never the bytes/sizes themselves as raw values — just the
//! booleans: did open succeed, did write report the full length, did the
//! readback equal what we wrote). Diffed line-exact carrick-vs-Linux.
//!
//! O_TMPFILE on aarch64 Linux is `__O_TMPFILE (0o20000000) | O_DIRECTORY
//! (0o40000)`; defined locally because the libc crate doesn't expose it on
//! every target.

use std::sync::mpsc;
use std::thread;

const O_TMPFILE: i32 = 0o20_000_000 | 0o40_000; // __O_TMPFILE | O_DIRECTORY

fn main() {
    // Become multithreaded before the syscall under test: this is what routes
    // the subsequent write(2) through carrick's `dispatch_threaded` path.
    let (tx, rx) = mpsc::channel::<()>();
    let handle = thread::spawn(move || {
        // Block until the main thread is done, so the process is genuinely
        // multithreaded across the whole roundtrip.
        let _ = rx.recv();
    });

    let payload = b"carrick-o-tmpfile-roundtrip";

    let (open_ok, write_full, readback_matches) = unsafe {
        let fd = libc::open(
            b"/tmp\0".as_ptr() as *const _,
            libc::O_RDWR | O_TMPFILE,
            0o600,
        );
        if fd < 0 {
            (false, false, false)
        } else {
            let n = libc::write(fd, payload.as_ptr() as *const libc::c_void, payload.len());
            let write_full = n == payload.len() as isize;

            let _ = libc::lseek(fd, 0, libc::SEEK_SET);
            let mut buf = [0u8; 64];
            let r = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
            let readback_matches =
                r == payload.len() as isize && buf[..payload.len()] == payload[..];

            libc::close(fd);
            (true, write_full, readback_matches)
        }
    };

    println!("o_tmpfile_open_ok={open_ok}");
    println!("o_tmpfile_write_full={write_full}");
    println!("o_tmpfile_readback_matches={readback_matches}");

    let _ = tx.send(());
    let _ = handle.join();
}
