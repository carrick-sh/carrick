//! A guest may raise its soft RLIMIT_NOFILE (setrlimit) and then open more than
//! the default 1024 file descriptors. libuv's watcher_cross_stop calls
//! TEST_FILE_LIMIT(~2532) then opens 2500 UDP sockets.
//!
//! Carrick hardcoded the fd cap at 1024 and getrlimit returned a fixed 1024,
//! ignoring the guest's setrlimit — so the 1025th fd got EMFILE. (It also never
//! raised its own host RLIMIT_NOFILE, so even a higher guest limit couldn't be
//! backed by host fds.)
//!
//!  * rlimit_nofile_raised: after setrlimit(NOFILE, soft=1600), getrlimit
//!    reflects 1600 AND opening 1500 fds (well past the old 1024 cap) all
//!    succeed with no EMFILE.

use conformance_probes::report;

const TARGET_SOFT: u64 = 1600;
const OPEN_COUNT: usize = 1500;

fn main() {
    unsafe {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) != 0 {
            report!(setup_ok = false);
            return;
        }
        // Raise the soft limit (keep the hard limit).
        rl.rlim_cur = TARGET_SOFT;
        let set_rc = libc::setrlimit(libc::RLIMIT_NOFILE, &rl);

        let mut after = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::getrlimit(libc::RLIMIT_NOFILE, &mut after);

        // Open many fds, well past the old hardcoded 1024 cap.
        let mut opened = 0usize;
        let mut fds = Vec::with_capacity(OPEN_COUNT);
        let mut last_errno = 0;
        for _ in 0..OPEN_COUNT {
            let fd = libc::open(
                b"/dev/null\0".as_ptr() as *const libc::c_char,
                libc::O_RDONLY,
            );
            if fd < 0 {
                last_errno = *libc::__errno_location();
                break;
            }
            fds.push(fd);
            opened += 1;
        }
        for fd in &fds {
            libc::close(*fd);
        }
        eprintln!(
            "set_rc={set_rc} soft_after={} opened={opened}/{OPEN_COUNT} last_errno={last_errno}",
            after.rlim_cur
        );
        report!(rlimit_nofile_raised = after.rlim_cur >= TARGET_SOFT && opened == OPEN_COUNT);
    }
}
