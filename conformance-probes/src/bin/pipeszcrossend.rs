//! `F_SETPIPE_SZ` on ONE end of a pipe must be visible to `F_GETPIPE_SZ` on the
//! OTHER end — Linux has a single shared pipe buffer, so capacity is a property
//! of the pipe, not of the individual fd. CPython test_subprocess.test_pipesizes
//! sets the size on the WRITE ends of the subprocess pipes and then reads it
//! back on the stdout/stderr READ ends, expecting the set value.
//!
//! Carrick stored pipe_capacity per-OpenDescription, so each end of pipe(2)
//! tracked its own value — a set on the write end left the read end at the
//! default. (The existing fcntlpipesz probe only set/get on a SINGLE end, so it
//! missed this.)
//!
//!  * crossend_eq: F_SETPIPE_SZ(write_end, want) then F_GETPIPE_SZ(read_end)
//!    returns `want`.

use conformance_probes::report;

const F_SETPIPE_SZ: i32 = 1031;
const F_GETPIPE_SZ: i32 = 1032;

fn main() {
    unsafe {
        let mut fds = [0i32; 2];
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            report!(crossend_eq = false);
            return;
        }
        let (rd, wr) = (fds[0], fds[1]);

        let default_sz = libc::fcntl(wr, F_GETPIPE_SZ);
        // default/2 is page-aligned (default is a power-of-two ≥ 64 KiB), so the
        // kernel rounds it to exactly itself — a clean round-trip.
        let want = if default_sz >= 8192 {
            default_sz / 2
        } else {
            4096
        };

        // Set on the WRITE end.
        let set_rc = libc::fcntl(wr, F_SETPIPE_SZ, want);
        // Read back on the READ end — must reflect the shared pipe's new size.
        let read_get = libc::fcntl(rd, F_GETPIPE_SZ);

        report!(crossend_eq = (set_rc == want && read_get == want));

        libc::close(rd);
        libc::close(wr);
    }
}
