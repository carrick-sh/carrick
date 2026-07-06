//! Fork/exit churn that exercises the atomic vCPU-permit release paths.
//!
//! Each round forks N children that immediately `_exit(0)`; the parent reaps all
//! N before the next round; repeat M rounds. Every child is a fresh guest process
//! that acquires a vCPU-admission permit at VM/vCPU create and must release it on
//! exit. Under `CARRICK_HVF_ATOMIC_PERMIT=1` the child's cooperative
//! `process_exit_cleanup` frees its permit slot on its own thread BEFORE `_exit`,
//! so the shared slot table returns to baseline promptly instead of lingering at
//! budget until the root reaper backstop sweeps it (the churn window that timed
//! out the node suites in 3b). The occupancy assertion itself lives in the
//! host-side unit test (`cooperative_release_*` in `carrick-vmm-hvf::trap`), which
//! can read the in-process slot table; this probe is the reproducible WORKLOAD
//! for the gate (Task 5) and produces a deterministic line-diff against Linux.

use conformance_probes::report;

const ROUNDS: i32 = 8;
const CHILDREN_PER_ROUND: i32 = 6;

fn main() {
    unsafe {
        let mut forked_all = true;
        let mut reaped_all = true;
        let mut all_exit_zero = true;

        for _round in 0..ROUNDS {
            let mut kids = [0i32; CHILDREN_PER_ROUND as usize];
            for kid in kids.iter_mut() {
                match libc::fork() {
                    -1 => {
                        forked_all = false;
                        *kid = -1;
                    }
                    0 => {
                        // Fresh guest child: acquired a permit at VM/vCPU create;
                        // exit at once so the cooperative release path runs.
                        libc::_exit(0);
                    }
                    pid => {
                        *kid = pid;
                    }
                }
            }

            for &pid in kids.iter() {
                if pid <= 0 {
                    continue;
                }
                let mut status: libc::c_int = 0;
                if libc::waitpid(pid, &mut status, 0) != pid {
                    reaped_all = false;
                    continue;
                }
                if !(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0) {
                    all_exit_zero = false;
                }
            }
        }

        report!(
            forked_all = forked_all,
            reaped_all = reaped_all,
            all_exit_zero = all_exit_zero,
        );
    }
}
