//! Launch-time container syscall-deny policy — carrick's model of Docker's
//! default seccomp profile.
//!
//! # Theory of operation
//!
//! `docker run` installs a seccomp profile at container launch, before the
//! entrypoint runs. Syscalls the profile denies fail with a configured errno
//! (EPERM) *at the syscall-entry seam*, without ever reaching a kernel
//! handler; the filter is inherited by every fork/exec descendant of the
//! container init. This module models exactly that shape as launch-time
//! configuration: a `syscall -> errno` deny table consulted at carrick's
//! dispatch-entry seam (`dispatch_inner` / `dispatch_threaded`, next to the
//! guest-installed seccomp precheck), before any handler runs.
//!
//! Recorded maintainer ruling (2026-07-10): Linux keyring syscalls are
//! available to unprivileged processes; Docker's EPERM comes from its
//! launch-time policy. carrick must NOT edit absent keyring handlers to
//! return EPERM (probe-shaped policy fabrication) — handlers keep their
//! honest ENOSYS when this layer is off, and the layer is plain launch
//! configuration when it is on, exactly where Docker's seccomp sits.
//!
//! # Inheritance
//!
//! The policy lives as a plain field on `SyscallDispatcher`. carrick's guest
//! `fork` is a host `fork` (the child inherits the dispatcher via the memory
//! copy) and guest `execve` replaces the image in-process (the dispatcher
//! object survives), so the table is per-process-tree inherited across
//! fork/exec — the same lifetime as a Linux seccomp filter, with no
//! per-backend wiring.
//!
//! # Table provenance (differential, 2026-07-11)
//!
//! Every entry is derived from Docker's public default-profile documentation
//! AND observed differentially on Docker 29.6.1 (builtin seccomp profile,
//! `docker.io/library/ubuntu:24.04`, linux/arm64, musl + gnu byte-identical
//! — the `keydeny` conformance probe):
//!
//! * default profile: `add_key`/`request_key`/`keyctl` all return
//!   ret=-1, errno=1 (EPERM);
//! * `--security-opt seccomp=unconfined`: `add_key` and `keyctl` SUCCEED
//!   unprivileged (key serials returned); `request_key` fails ENOKEY (126)
//!   for a genuinely-absent key — proving the EPERM is Docker's launch-time
//!   policy, not a kernel permission check.
//!
//! The table is deliberately minimal: model only what is verified, extend
//! entry-by-entry with the same evidence bar (Docker's profile JSON is NOT
//! copied wholesale).

use crate::linux_abi::LinuxErrno;
use carrick_abi::LINUX_EPERM;

/// Canonical (asm-generic/aarch64) syscall numbers for the deny table. The
/// dispatcher normalizes x86_64 guests onto canonical numbers before dispatch,
/// so one canonical-keyed table covers every lane.
const SYS_ADD_KEY: u64 = 217;
const SYS_REQUEST_KEY: u64 = 218;
const SYS_KEYCTL: u64 = 219;

/// Identity syscalls the EL1 fast-path shim may answer without a dispatch
/// (getpid/getppid/getuid/geteuid/getgid/getegid/gettid). A policy that denied
/// any of these could be bypassed by the shim, so `SyscallDispatcher::
/// identity_fast_path_enabled` disables the shim in that case. The Docker
/// default model never denies these; the guard keeps a future table honest
/// without costing the common case its fast path.
pub(crate) const IDENTITY_FAST_PATH_SYSCALLS: &[u64] = &[172, 173, 174, 175, 176, 177, 178];

/// A launch-time syscall-deny table (canonical syscall number -> errno),
/// consulted at the dispatch-entry seam before any handler. See the module
/// docs for provenance and inheritance semantics.
#[derive(Debug, Clone)]
pub(crate) struct ContainerPolicy {
    /// Sorted by syscall number (binary-searchable; the table is tiny today
    /// but the invariant keeps growth cheap).
    deny: Vec<(u64, LinuxErrno)>,
}

impl ContainerPolicy {
    /// The carrick model of Docker's default seccomp profile. Entries carry
    /// their differential evidence in the module docs; keep the two in sync.
    pub(crate) fn docker_default_model() -> Self {
        Self::from_entries(vec![
            // Keyring syscalls: EPERM under Docker's default profile, succeed
            // unprivileged when unconfined (observed 2026-07-11, module docs).
            (SYS_ADD_KEY, LINUX_EPERM),
            (SYS_REQUEST_KEY, LINUX_EPERM),
            (SYS_KEYCTL, LINUX_EPERM),
        ])
    }

    fn from_entries(mut deny: Vec<(u64, LinuxErrno)>) -> Self {
        deny.sort_by_key(|(nr, _)| *nr);
        deny.dedup_by_key(|(nr, _)| *nr);
        Self { deny }
    }

    /// The errno this policy denies `canonical_nr` with, or `None` when the
    /// syscall passes through to its handler untouched.
    pub(crate) fn denied_errno(&self, canonical_nr: u64) -> Option<LinuxErrno> {
        self.deny
            .binary_search_by_key(&canonical_nr, |(nr, _)| *nr)
            .ok()
            .map(|i| self.deny[i].1)
    }

    /// Whether the policy denies any syscall in `nrs` (the identity fast-path
    /// guard).
    pub(crate) fn denies_any(&self, nrs: &[u64]) -> bool {
        nrs.iter().any(|nr| self.denied_errno(*nr).is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn docker_default_model_denies_keyring_family_with_eperm() {
        let policy = ContainerPolicy::docker_default_model();
        for nr in [SYS_ADD_KEY, SYS_REQUEST_KEY, SYS_KEYCTL] {
            assert_eq!(
                policy.denied_errno(nr),
                Some(LINUX_EPERM),
                "syscall {nr} must be policy-denied EPERM (Docker default profile model)"
            );
        }
    }

    #[test]
    fn docker_default_model_passes_unlisted_syscalls_through() {
        let policy = ContainerPolicy::docker_default_model();
        // Neighbors and common syscalls must pass through untouched — the
        // model is a targeted deny table, not a broad filter.
        for nr in [
            0, 63, 64, 93, 172, 216, 220, // …clone
            435,
        ] {
            assert_eq!(
                policy.denied_errno(nr),
                None,
                "syscall {nr} must NOT be policy-denied"
            );
        }
    }

    #[test]
    fn docker_default_model_never_denies_identity_fast_path() {
        // Guards the EL1-shim fast path: the Docker default model must never
        // intersect the identity set (a deny there would be shim-bypassable,
        // and identity_fast_path_enabled would have to turn the shim off).
        let policy = ContainerPolicy::docker_default_model();
        assert!(!policy.denies_any(IDENTITY_FAST_PATH_SYSCALLS));
    }

    #[test]
    fn entries_are_sorted_and_deduped_for_lookup() {
        let policy = ContainerPolicy::from_entries(vec![
            (300, LINUX_EPERM),
            (100, LinuxErrno::new(38)),
            (300, LinuxErrno::new(13)), // dup: first-sorted wins after dedup
        ]);
        assert_eq!(policy.denied_errno(100), Some(LinuxErrno::new(38)));
        assert!(policy.denied_errno(200).is_none());
        assert!(policy.denied_errno(300).is_some());
    }
}
