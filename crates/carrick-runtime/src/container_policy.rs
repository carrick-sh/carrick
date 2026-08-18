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
//! launch-time policy. carrick must NOT edit its keyring handlers to return
//! EPERM (probe-shaped policy fabrication) — the handlers answer with real
//! keyring semantics when this layer is off, and the layer is plain launch
//! configuration when it is on, exactly where Docker's seccomp sits.
//!
//! That ruling predated the keyring subsystem itself. It still holds, and the
//! separation is now load-bearing in BOTH directions: `crate::keyring` really
//! does implement `add_key`/`request_key`/`keyctl`, so this table is the only
//! thing that makes a default `carrick run` reproduce Docker's EPERM, and the
//! handlers must never learn about it.
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
//! `perf_event_open` (2026-08-18, same method, LTP arm64 image): default
//! profile answers EPERM for every event type (LTP perf_event_open01 TFAILs
//! "EPERM ... failed unexpectedly" on its FIRST case); unconfined, the same
//! call reaches the kernel and answers honestly (ENOENT for hardware events
//! inside the VM, working fds for software events). The EPERM is Docker's
//! launch policy, so it belongs HERE — the dispatch handler keeps its honest
//! implementation when the layer is off.
//!
//! The table is deliberately minimal: model only what is verified, extend
//! entry-by-entry with the same evidence bar (Docker's profile JSON is NOT
//! copied wholesale).
//!
//! # `clone3(2)` entry provenance (differential, 2026-08-18)
//!
//! Docker's default profile answers `clone3` with **ENOSYS** rather than
//! EPERM — deliberately, so a guest libc falls back to `clone` instead of
//! failing. Observed on `localhost:5050/cpython-test:3.12.13`, linux/arm64,
//! same caps: default profile `clone3(NULL, 0)` -> ENOSYS;
//! `--security-opt seccomp=unconfined` -> EINVAL (the kernel validating the
//! NULL args). carrick answered EINVAL, i.e. it behaved like an unconfined
//! host and ran clone3 paths the oracle never reaches (LTP clone301 TCONFs
//! on the oracle for exactly this reason).
//!
//! # `unshare(2)`/`setns(2)` entry provenance (differential, 2026-08-18)
//!
//! Docker's default profile denies both unless the container holds
//! `CAP_SYS_ADMIN`. Observed on `localhost:5050/cpython-test:3.12.13`,
//! linux/arm64, IDENTICAL default caps on both sides:
//!
//! * default profile: `unshare(CLONE_NEWUTS)` EPERM, `unshare(CLONE_FILES)`
//!   EPERM, `setns(-1, 0)` EPERM;
//! * `--security-opt seccomp=unconfined`: `unshare(CLONE_FILES)` SUCCEEDS,
//!   `setns(-1, 0)` fails EBADF (the kernel validates the fd), while
//!   `unshare(CLONE_NEWUTS)` still fails EPERM.
//!
//! The first two flips prove the confined EPERM is the launch-time profile,
//! not a kernel check — the deny-before-validation shape this table models.
//! The third is a genuine kernel capability check, so the `unshare` HANDLER
//! enforces `CAP_SYS_ADMIN` for namespace flags independently of this layer
//! (the keyring ruling's two-sided separation).
//!
//! # `bpf(2)` entry provenance (differential, 2026-08-18)
//!
//! Docker's default profile allows `bpf` only when the container holds
//! `CAP_SYS_ADMIN`; the default cap set does not, so under plain `docker run`
//! every `bpf()` call answers EPERM. Observed on the native arm64 LTP oracle
//! image (`localhost:5050/ltp:arm64`, linuxkit 7.0.12):
//!
//! * default profile: all eight LTP bpf suites TCONF at their first
//!   `BPF_MAP_CREATE` with EPERM (`bpf_common.c:40`);
//! * `--security-opt seccomp=unconfined`, SAME default caps: all eight run
//!   their full assertion bodies (bpf_map01 7/7 TPASS, …) — and the oracle
//!   kernel reports `unprivileged_bpf_disabled=0` — proving the EPERM is
//!   Docker's launch-time policy, not a kernel capability check.
//!
//! Per the 2026-07-10 ruling above, `crate::dispatch::bpf` therefore
//! implements real map/prog-load semantics and never learns about this
//! entry.

use crate::linux_abi::LinuxErrno;
use carrick_abi::{LINUX_ENOSYS, LINUX_EPERM};

/// Canonical (asm-generic/aarch64) syscall numbers for the deny table. The
/// dispatcher normalizes x86_64 guests onto canonical numbers before dispatch,
/// so one canonical-keyed table covers every lane.
const SYS_ADD_KEY: u64 = 217;
const SYS_REQUEST_KEY: u64 = 218;
const SYS_KEYCTL: u64 = 219;
const SYS_PERF_EVENT_OPEN: u64 = 241;
const SYS_BPF: u64 = 280;
const SYS_UNSHARE: u64 = 97;
const SYS_CLONE3: u64 = 435;
const SYS_SETNS: u64 = 268;

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
            // perf_event_open: EPERM under Docker's default profile; honest
            // handler behavior when unconfined (observed 2026-08-18, module
            // docs).
            (SYS_PERF_EVENT_OPEN, LINUX_EPERM),
            // bpf(2): EPERM under Docker's default profile (gated on
            // CAP_SYS_ADMIN, which the default cap set lacks); succeeds
            // unprivileged when unconfined (observed 2026-08-18, module docs).
            (SYS_BPF, LINUX_EPERM),
            // `unshare`/`setns`: denied by the default profile unless the
            // container holds CAP_SYS_ADMIN (see the provenance note above).
            (SYS_UNSHARE, LINUX_EPERM),
            (SYS_SETNS, LINUX_EPERM),
            // `clone3`: denied with ENOSYS (not EPERM) so a guest libc takes
            // its documented `clone` fallback, exactly as it does in Docker.
            (SYS_CLONE3, LINUX_ENOSYS),
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
    fn docker_default_model_denies_keyring_family_perf_and_bpf_with_eperm() {
        let policy = ContainerPolicy::docker_default_model();
        for nr in [
            SYS_ADD_KEY,
            SYS_REQUEST_KEY,
            SYS_KEYCTL,
            SYS_PERF_EVENT_OPEN,
            SYS_BPF,
        ] {
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
        // NB: 435 (clone3) IS denied now (ENOSYS, matching Docker's profile —
        // see the clone3 provenance note), so it moved out of this list; 220
        // (clone) stays here because Docker denies only its namespace-flag
        // shapes, which this nr-keyed table does not express.
        for nr in [0, 63, 64, 93, 172, 216, 220] {
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
