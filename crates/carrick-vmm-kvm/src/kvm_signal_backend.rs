//! KVM's [`HostSignalGlue`] — the ~15-line backend seam the shared host-signal
//! driver (`carrick_signal_core::host_glue` + `carrick_hal::signal_pump`) is
//! generic over. This is the ENTIRE KVM host-signal footprint now: the routed +
//! nudge + pump handlers, the disposition install mask, the daemon-thread pump,
//! and the fork/execve lifecycle all live in the shared crates and inherit these
//! six methods. KVM is identity (Linux host == guest signum), so the translation
//! methods are no-ops and the shared code monomorphizes to exactly the old
//! `kvm_disposition`/`kvm_xsig`/`kvm_signal_pump` bodies.
//!
//! The irreducible vCPU KICK ("EINTR `KVM_RUN`") is a SEPARATE seam
//! (`carrick_hal::VcpuKick`, impl in [`crate::kvm_kicker`]); only the kick's
//! SIGNAL NUMBER is named here, to derive the xsig nudge and exclude it from
//! disposition mirroring.

use carrick_signal_core::HostSignalGlue;

/// Zero-sized marker carrying KVM's host-signal policy.
pub struct KvmGlue;

impl HostSignalGlue for KvmGlue {
    fn kick_signal() -> i32 {
        // The same number the vCPU kick installs (see `kvm_kicker::kick_signal`).
        libc::SIGRTMIN()
    }

    fn host_to_linux(s: i32) -> i32 {
        s // Linux host: host signum == guest signum.
    }

    fn linux_to_host(s: i32) -> i32 {
        s
    }

    /// Signals KVM already CLAIMS for its own mechanisms (so the disposition mirror
    /// leaves them alone): the four pumped process signals, the SIGCHLD reaper,
    /// SIGPIPE (carrick-cli owns a process-wide SIG_IGN), and the kick + xsig nudge.
    /// This is the old `kvm_disposition::is_kvm_claimed` body verbatim.
    fn is_claimed(s: i32) -> bool {
        if matches!(
            s,
            libc::SIGHUP | libc::SIGINT | libc::SIGQUIT | libc::SIGTERM
        ) {
            return true;
        }
        if s == libc::SIGCHLD {
            return true;
        }
        if s == libc::SIGPIPE {
            return true;
        }
        let rtmin = libc::SIGRTMIN();
        s == rtmin || s == rtmin + 1
    }

    fn poke() {
        carrick_hal::signal_pump::poke();
    }

    fn install_kick_handler() {
        crate::kvm_kicker::install_kvm_kick_handler();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kvm_glue_claims_and_translation() {
        assert_eq!(KvmGlue::nudge_signum(), libc::SIGRTMIN() + 1);
        assert_eq!(KvmGlue::host_to_linux(10), 10); // identity
        assert_eq!(KvmGlue::linux_to_host(10), 10);
        for s in [libc::SIGHUP, libc::SIGINT, libc::SIGQUIT, libc::SIGTERM] {
            assert!(KvmGlue::is_claimed(s), "pumped {s} claimed");
        }
        assert!(KvmGlue::is_claimed(libc::SIGCHLD));
        assert!(KvmGlue::is_claimed(libc::SIGPIPE));
        assert!(KvmGlue::is_claimed(libc::SIGRTMIN()));
        assert!(KvmGlue::is_claimed(libc::SIGRTMIN() + 1));
        // Standard catchable signals are NOT claimed.
        for s in [10, 12, 14] {
            assert!(!KvmGlue::is_claimed(s));
        }
    }
}
