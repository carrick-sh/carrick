//! Idle-churn witness for the MT VM lease: a TWO-threaded process where BOTH
//! threads sit in one long `nanosleep` (the WaitOnSleep slicing arm, both
//! RELEASE-SAFE). Under the slice-tick lease WITHOUT skip-resume, the parked
//! process resumes + re-parks its vCPU on every stretched tick (2s→4s→8s ≈
//! 4-6 rebuilds in 20 s). WITH skip-resume, an idle TimedOut tick re-arms the
//! wait with the vCPU still parked: expect ≤2 hv_vm_create for the whole run
//! (initial boot + the final-wake rebuild). Measured externally via dtrace on
//! hv_vm_create — the probe itself reports only a deterministic boolean.

use conformance_probes::report;

fn main() {
    let t = std::thread::spawn(|| unsafe {
        let ts = libc::timespec {
            tv_sec: 20,
            tv_nsec: 0,
        };
        libc::nanosleep(&ts, std::ptr::null_mut());
    });
    unsafe {
        let ts = libc::timespec {
            tv_sec: 20,
            tv_nsec: 0,
        };
        libc::nanosleep(&ts, std::ptr::null_mut());
    }
    let joined = t.join().is_ok();
    report!(slept_both = joined);
}
