//! A child must be able to join its PARENT's existing process group:
//! setpgid(0, getpgrp()) succeeds. CPython's posix_spawn(setpgroup=os.getpgrp())
//! (test_posix.test_setpgroup) does exactly this in the pre-exec child; if it
//! fails, glibc aborts the spawn and the child exits 127.
//!
//! Under carrick's PID namespace, getpgrp() returned the HOST pgid (the
//! launching shell's group) instead of the ns-pgid (1), so setpgid(0, <that>)
//! failed (the host pid behind ns-pgid 1 wasn't a group leader).
//!
//!  * child_joins_parent_group: a forked child's setpgid(0, parent_getpgrp())
//!    returns 0 (the child then exits 0; the parent confirms exit code 0).

use conformance_probes::report;

fn main() {
    unsafe {
        let pgrp = libc::getpgrp();
        let pid = libc::fork();
        if pid == 0 {
            // Join the parent's process group, exactly like posix_spawn setpgroup.
            let rc = libc::setpgid(0, pgrp);
            libc::_exit(if rc == 0 { 0 } else { 1 });
        }
        let mut status = 0i32;
        libc::waitpid(pid, &mut status, 0);
        let joined = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        report!(child_joins_parent_group = joined);
    }
}
