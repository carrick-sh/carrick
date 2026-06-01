//! Process-global namespace + capability state.
//!
//! User namespace membership and the capability set are **per-process**
//! attributes that are read from two very different places: the syscall
//! dispatcher (`capget`/`capset`/`unshare`, `is_privileged`) and the free
//! `/proc` synthesis functions in `vfs/proc.rs` (which have no handle to the
//! dispatcher). A process-global store reachable from both — inherited at fork
//! via the address-space copy, exactly like the `NICE_VALUE` static in
//! `creds.rs` and the `cred_ipc` publish pattern — is the natural home.
//!
//! This is the Phase 1 storage for the *current* process's user namespace.
//! Cross-process sharing of namespace objects (the file-backed registry of
//! design §4.5) and the PID-namespace hot state (the `MAP_SHARED` region of
//! [`super::pid`]) are separate; this module only holds what a single process
//! needs to answer "what uid_map/caps do I present?".

use std::sync::OnceLock;

use parking_lot::Mutex;

use super::pid::PidNs;
use super::user::UserNs;
use super::{FIRST_DYNAMIC_NS, INITIAL_PID_NS, INITIAL_USER_NS, NsId};

/// The Docker default bounded capability set, observed on
/// `docker run debian:stable` (design §1.2, §4.4). carrick reports this in
/// `/proc/self/status` so capability-probing tools see a coherent non-zero set
/// instead of the all-zero set that makes them refuse to proceed.
pub const DOCKER_DEFAULT_CAPS: u64 = 0x0000_0000_a804_25fb;

/// The highest capability number carrick models (`CAP_LAST_CAP`,
/// `capabilities(7)`; mirrors `LINUX_CAP_LAST_CAP`). A full set is all bits
/// `0..=CAP_LAST_CAP`.
pub const CAP_LAST_CAP: u32 = 40;

/// A full capability set over the modeled range — what the creator of a fresh
/// user namespace holds within it (design §4.1, §4.4).
pub const FULL_CAPS: u64 = if CAP_LAST_CAP >= 63 {
    u64::MAX
} else {
    (1u64 << (CAP_LAST_CAP + 1)) - 1
};

/// The five capability sets Linux exposes in `/proc/[pid]/status` and through
/// `capget`/`capset` (`capabilities(7)`). Modeled, not enforced — carrick is
/// the kernel and does not modulate DAC the way Linux caps do; the point is a
/// coherent story for tools that *query* capabilities (design §4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilitySet {
    pub effective: u64,
    pub permitted: u64,
    pub inheritable: u64,
    pub bounding: u64,
    pub ambient: u64,
}

impl CapabilitySet {
    /// The default container set (effective=permitted=bounding = Docker
    /// default; inheritable/ambient empty), matching observed `docker run`.
    pub fn docker_default() -> Self {
        Self {
            effective: DOCKER_DEFAULT_CAPS,
            permitted: DOCKER_DEFAULT_CAPS,
            inheritable: 0,
            bounding: DOCKER_DEFAULT_CAPS,
            ambient: 0,
        }
    }

    /// A full set — granted to the creator of a fresh user namespace.
    pub fn full() -> Self {
        Self {
            effective: FULL_CAPS,
            permitted: FULL_CAPS,
            inheritable: 0,
            bounding: FULL_CAPS,
            ambient: 0,
        }
    }

    /// The five `Cap*` lines of `/proc/[pid]/status`, in the kernel's order and
    /// format (lowercase hex, 16-wide zero-padded). Must match Linux
    /// byte-for-byte for the conformance diff (design §4.4).
    pub fn status_lines(&self) -> String {
        format!(
            "CapInh:\t{:016x}\n\
             CapPrm:\t{:016x}\n\
             CapEff:\t{:016x}\n\
             CapBnd:\t{:016x}\n\
             CapAmb:\t{:016x}\n",
            self.inheritable, self.permitted, self.effective, self.bounding, self.ambient
        )
    }
}

/// The per-process namespace + capability state.
struct ProcessNs {
    /// This process's current user namespace. Starts as the identity initial ns
    /// (uid 0 → host uid 0), so the common `docker run` case is unchanged.
    user: UserNs,
    /// This process's current PID namespace descriptor. The hot translation
    /// lives in [`super::pid`]'s shared region; this is identity + lineage.
    pidns: PidNs,
    /// The modeled capability set (Docker default until a fresh userns grants
    /// a full set).
    caps: CapabilitySet,
    /// `unshare(CLONE_NEWPID)` arms this; the next `fork` consumes it and makes
    /// the child the init of a fresh pid ns (design §5.5). Phase 4.
    pending_newpid: bool,
    /// Monotonic allocator for namespace ids created *by this process*
    /// (`unshare`/`clone(CLONE_NEW*)`). Starts after the initial-ns ids.
    next_ns_id: NsId,
}

impl ProcessNs {
    fn new() -> Self {
        Self {
            user: UserNs::initial(INITIAL_USER_NS),
            pidns: PidNs::initial(INITIAL_PID_NS),
            caps: CapabilitySet::docker_default(),
            pending_newpid: false,
            next_ns_id: FIRST_DYNAMIC_NS,
        }
    }
}

/// The process-global store. `OnceLock`-initialized on first access; the
/// initialized value is inherited by fork descendants (address-space copy), so
/// a child sees the parent's `current_userns`/caps at fork time and may diverge
/// afterward — exactly the per-process semantic Linux gives.
fn store() -> &'static Mutex<ProcessNs> {
    static STORE: OnceLock<Mutex<ProcessNs>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(ProcessNs::new()))
}

/// Run `f` with a shared reference to the current user namespace.
pub fn with_user<R>(f: impl FnOnce(&UserNs) -> R) -> R {
    f(&store().lock().user)
}

/// Run `f` with a mutable reference to the current user namespace.
pub fn with_user_mut<R>(f: impl FnOnce(&mut UserNs) -> R) -> R {
    f(&mut store().lock().user)
}

/// The current user namespace id.
pub fn current_user_ns() -> NsId {
    store().lock().user.id
}

/// The current PID namespace descriptor.
pub fn current_pid_ns() -> PidNs {
    store().lock().pidns
}

/// Set the current PID namespace descriptor (launch placement, §5.2).
pub fn set_current_pid_ns(ns: PidNs) {
    store().lock().pidns = ns;
}

/// The modeled capability set.
pub fn caps() -> CapabilitySet {
    store().lock().caps
}

/// Replace the modeled capability set (`capset` accept-and-record, §4.4).
pub fn set_caps(caps: CapabilitySet) {
    store().lock().caps = caps;
}

/// The five `Cap*` lines for `/proc/[pid]/status`.
pub fn cap_status_lines() -> String {
    store().lock().caps.status_lines()
}

/// `prctl(PR_CAPBSET_READ, cap)` — is `cap` in the bounding set?
pub fn capbset_read(cap: u32) -> bool {
    if cap > 63 {
        return false;
    }
    store().lock().caps.bounding & (1u64 << cap) != 0
}

/// `prctl(PR_CAPBSET_DROP, cap)` — clear `cap` from the bounding set
/// (accept-and-record; §4.4).
pub fn capbset_drop(cap: u32) {
    if cap > 63 {
        return;
    }
    store().lock().caps.bounding &= !(1u64 << cap);
}

/// Is the current process privileged for *map-writing* purposes in its current
/// user namespace? True if it holds `CAP_SETUID`/`CAP_SETGID` (modeled), i.e.
/// it is uid 0 with the default set, or it created a fresh userns (full caps).
/// This is the gate the `/proc/[pid]/uid_map` writer consults (design §4.3).
pub fn is_map_write_privileged() -> bool {
    let c = store().lock().caps;
    const CAP_SETGID: u64 = 1 << 6;
    const CAP_SETUID: u64 = 1 << 7;
    c.effective & (CAP_SETUID | CAP_SETGID) == (CAP_SETUID | CAP_SETGID)
}

/// `unshare(CLONE_NEWUSER)` (and the `clone(CLONE_NEWUSER)` child path):
/// allocate a fresh user namespace for the caller, parented at the current one,
/// and grant a full capability set within it (design §4.1, §4.6). Returns the
/// new namespace id.
pub fn unshare_user_ns() -> NsId {
    let mut g = store().lock();
    let parent = g.user.id;
    let id = g.next_ns_id;
    g.next_ns_id += 1;
    g.user = UserNs::fresh(id, parent);
    g.caps = CapabilitySet::full();
    id
}

/// Arm the pending-NEWPID flag (`unshare(CLONE_NEWPID)`; consumed at the next
/// fork — design §5.5). Phase 4.
pub fn arm_pending_newpid() {
    store().lock().pending_newpid = true;
}

/// Consume the pending-NEWPID flag, returning whether it was set.
pub fn take_pending_newpid() -> bool {
    let mut g = store().lock();
    std::mem::take(&mut g.pending_newpid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_caps_covers_modeled_range() {
        // CAP_LAST_CAP=40 → bits 0..=40 set.
        assert_eq!(FULL_CAPS, (1u64 << 41) - 1);
        assert!(FULL_CAPS & (1 << 40) != 0);
        assert!(FULL_CAPS & (1 << 41) == 0);
    }

    #[test]
    fn docker_default_status_lines_match_observed() {
        let s = CapabilitySet::docker_default();
        let text = s.status_lines();
        assert!(text.contains("CapEff:\t00000000a80425fb\n"));
        assert!(text.contains("CapBnd:\t00000000a80425fb\n"));
        assert!(text.contains("CapPrm:\t00000000a80425fb\n"));
        assert!(text.contains("CapInh:\t0000000000000000\n"));
        assert!(text.contains("CapAmb:\t0000000000000000\n"));
        // Order: Inh, Prm, Eff, Bnd, Amb (kernel order).
        let inh = text.find("CapInh").unwrap();
        let prm = text.find("CapPrm").unwrap();
        let eff = text.find("CapEff").unwrap();
        let bnd = text.find("CapBnd").unwrap();
        let amb = text.find("CapAmb").unwrap();
        assert!(inh < prm && prm < eff && eff < bnd && bnd < amb);
    }

    #[test]
    fn docker_default_has_setuid_setgid() {
        // The map-write privilege gate depends on these bits being present in
        // the default set (so a default container root can write arbitrary
        // maps, matching docker-run).
        let c = CapabilitySet::docker_default();
        assert!(c.effective & (1 << 6) != 0, "CAP_SETGID");
        assert!(c.effective & (1 << 7) != 0, "CAP_SETUID");
    }

    #[test]
    fn full_caps_is_map_write_privileged() {
        let c = CapabilitySet::full();
        assert!(c.effective & (1 << 6) != 0);
        assert!(c.effective & (1 << 7) != 0);
    }
}
