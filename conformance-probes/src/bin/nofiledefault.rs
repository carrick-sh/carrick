//! Default RLIMIT_NOFILE shape. LTP fcntl12 is sensitive to Docker's large
//! default soft limit; Carrick must expose the same initial cap.

use conformance_probes::report;

fn main() {
    unsafe {
        let mut rl: libc::rlimit = std::mem::zeroed();
        let rc = libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl);
        if rc != 0 {
            report!(getrlimit_ok = false);
            return;
        }
        report!(
            getrlimit_ok = true,
            nofile_soft = rl.rlim_cur,
            nofile_hard = rl.rlim_max,
        );
    }
}
