//! `/proc/self/status` must report the process's real signal dispositions in
//! its `SigIgn` (ignored) and `SigCgt` (caught/handled) bitmask lines, not a
//! hardcoded zero. CPython's test_subprocess.test_restore_signals compares the
//! `SigIgn` line of two children (restore_signals False vs True) and requires
//! them to DIFFER — impossible if carrick always renders SigIgn=0.
//!
//!  * sigign_has_usr1: after sigaction(SIGUSR1, SIG_IGN), the SigIgn mask has
//!    the SIGUSR1 bit (1 << (10-1)).
//!  * sigcgt_has_usr2: after installing a real SIGUSR2 handler, the SigCgt mask
//!    has the SIGUSR2 bit (1 << (12-1)).

use conformance_probes::report;
use std::io::Read;

extern "C" fn handler(_sig: libc::c_int) {}

fn status_mask(field: &str) -> u64 {
    let mut s = String::new();
    if std::fs::File::open("/proc/self/status")
        .and_then(|mut f| f.read_to_string(&mut s))
        .is_err()
    {
        return 0;
    }
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            // e.g. "SigIgn:\t0000000000001000"
            let hex = rest.trim_start_matches(':').trim();
            return u64::from_str_radix(hex, 16).unwrap_or(0);
        }
    }
    0
}

fn main() {
    unsafe {
        // Ignore SIGUSR1.
        let mut ign: libc::sigaction = std::mem::zeroed();
        ign.sa_sigaction = libc::SIG_IGN;
        libc::sigemptyset(&mut ign.sa_mask);
        libc::sigaction(libc::SIGUSR1, &ign, std::ptr::null_mut());

        // Install a real handler for SIGUSR2.
        let mut cgt: libc::sigaction = std::mem::zeroed();
        cgt.sa_sigaction = handler as usize;
        libc::sigemptyset(&mut cgt.sa_mask);
        cgt.sa_flags = 0;
        libc::sigaction(libc::SIGUSR2, &cgt, std::ptr::null_mut());

        let sig_ign = status_mask("SigIgn");
        let sig_cgt = status_mask("SigCgt");
        let usr1_bit = 1u64 << (libc::SIGUSR1 as u64 - 1);
        let usr2_bit = 1u64 << (libc::SIGUSR2 as u64 - 1);

        report!(
            sigign_has_usr1 = (sig_ign & usr1_bit != 0),
            sigcgt_has_usr2 = (sig_cgt & usr2_bit != 0)
        );
    }
}
