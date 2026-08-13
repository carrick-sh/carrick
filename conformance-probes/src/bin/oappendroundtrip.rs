//! `O_APPEND` must survive an `F_GETFL` → `F_SETFL` round trip, and an append
//! write must land at end-of-file rather than at the current offset.
//!
//! This is the exact sequence Go's runtime performs on every file it opens.
//! `os.OpenFile` calls `syscall.SetNonblock`, which is a read-modify-write:
//!
//! ```text
//! flag = fcntl(fd, F_GETFL, 0);
//! fcntl(fd, F_SETFL, flag &^ O_NONBLOCK);
//! ```
//!
//! If `F_GETFL` under-reports the status flags, the guest writes the
//! under-reported word straight back and the missing flag is destroyed for the
//! lifetime of the open file description. Nothing in the sequence looks wrong
//! from the guest's side, which is why it is invisible to a probe that only
//! checks a freshly opened fd.
//!
//! carrick shipped exactly that bug: `F_GETFL` on a host-backed description
//! overlaid the mutable bits from the HOST fd, but carrick never opens an
//! overlay file with `O_APPEND` (`FsBackend::open_raw_fd` has no append
//! parameter), so the flag read back as absent. `cmd/go` opens archives with
//! `O_WRONLY|O_APPEND`; losing the flag sent the archive's member header to
//! offset 0 instead of end-of-file, so the `!<arch>\n` magic never appeared and
//! a cold `go build` failed with "not the start of an archive file".
//!
//! `fsetfl` does not catch this: it opens WITHOUT `O_APPEND` and never asserts
//! that an existing status flag survives being read and written back.

use conformance_probes::{errno, report};

fn main() {
    unsafe {
        // run-elf's rootfs is empty; /tmp may not exist. Ignore EEXIST.
        libc::mkdir(b"/tmp\0".as_ptr() as *const libc::c_char, 0o777);
        let path = b"/tmp/oappend_probe\0".as_ptr() as *const libc::c_char;

        // Seed the file with a known prefix, the way an archive writer lays
        // down a magic before appending members.
        let seed = libc::open(path, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o644);
        if seed < 0 {
            report!(setup_open_ok = false, open_errno = errno());
            return;
        }
        libc::write(seed, b"HEAD".as_ptr() as *const libc::c_void, 4);
        libc::close(seed);

        // Reopen for append, exactly as `os.OpenFile(path, O_WRONLY|O_APPEND, 0)`.
        let fd = libc::open(path, libc::O_WRONLY | libc::O_APPEND);
        if fd < 0 {
            report!(setup_open_ok = false, open_errno = errno());
            return;
        }

        // Linux: F_GETFL reports the O_APPEND the file was opened with.
        let before = libc::fcntl(fd, libc::F_GETFL);
        let append_reported_before = (before & libc::O_APPEND) != 0;

        // The Go read-modify-write. Clearing O_NONBLOCK must not disturb
        // O_APPEND — and if F_GETFL under-reported it, this is where it dies.
        let setfl_rc = libc::fcntl(fd, libc::F_SETFL, before & !libc::O_NONBLOCK);
        let after = libc::fcntl(fd, libc::F_GETFL);
        let append_survives_roundtrip = (after & libc::O_APPEND) != 0;

        // The behavioural half: an append write goes to end-of-file even when
        // the offset says otherwise, so the seeded prefix is preserved.
        libc::lseek(fd, 0, libc::SEEK_SET);
        libc::write(fd, b"TAIL".as_ptr() as *const libc::c_void, 4);
        libc::close(fd);

        let mut buffer = [0_u8; 16];
        let verify = libc::open(path, libc::O_RDONLY);
        let read_len = if verify < 0 {
            -1
        } else {
            let n = libc::read(verify, buffer.as_mut_ptr() as *mut libc::c_void, 16);
            libc::close(verify);
            n as i64
        };
        let contents = &buffer[..read_len.max(0) as usize];

        report!(
            setup_open_ok = true,
            setfl_rc_zero = setfl_rc == 0,
            // Linux: true. The open flag is visible to F_GETFL.
            append_reported_before = append_reported_before,
            // Linux: true. Reading the flags and writing them back is lossless.
            append_survives_roundtrip = append_survives_roundtrip,
            // Linux: "HEADTAIL" — the append ignored the lseek to 0 and the
            // seeded prefix survived. On the bug: "TAIL" (prefix overwritten).
            appended_after_seek_zero = contents == b"HEADTAIL",
            total_len_eight = read_len == 8,
        );
    }
}
