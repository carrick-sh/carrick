//! read() positioned at/after EOF must return 0 on Linux and NEVER fault the
//! process. carrick's in-memory File/SyntheticFile read path slices
//! `&contents[*offset..]` with no bound check (dispatch/fs.rs:3043), and lseek
//! happily stores an offset past EOF (fs.rs:2857-2872), so `lseek` past EOF
//! then `read` is a Rust slice-index-out-of-bounds panic that aborts the
//! carrick host process.
//!
//! This triggers ONLY for in-memory File/SyntheticFile, so run it under
//! `--fs memory` (a regular file is then an in-memory File). Under `--fs host`
//! a regular file is a HostFile (libc::read on a real fd, returns 0 at EOF) and
//! the bug does NOT trigger — which is itself a useful datum.
//!
//! Direct (non-forked) so that under carrick the abort is visible as a missing
//! stdout line + panic, and under Linux the single deterministic line prints.

use conformance_probes::{errno, report};

fn main() {
    unsafe {
        libc::mkdir(b"/tmp\0".as_ptr() as *const libc::c_char, 0o777);
        let path = b"/tmp/rpe\0".as_ptr() as *const libc::c_char;

        let wfd = libc::open(path, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o644);
        if wfd < 0 {
            report!(setup_ok = false, setup_errno = errno());
            return;
        }
        let msg = b"hello";
        libc::write(wfd, msg.as_ptr() as *const libc::c_void, msg.len());
        libc::close(wfd);

        let fd = libc::open(path, libc::O_RDONLY);
        if fd < 0 {
            report!(setup_ok = false, setup_errno = errno());
            return;
        }
        // Seek far past EOF (file is 5 bytes), then read.
        libc::lseek(fd, 1 << 20, libc::SEEK_SET);
        let mut buf = [0u8; 16];
        let r = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
        // Linux: r == 0 (EOF). carrick (--fs memory): aborts before reaching here.
        report!(
            read_past_eof_rc = r,
            read_past_eof_errno = if r < 0 { errno() } else { 0 },
        );
        libc::close(fd);
    }
}
