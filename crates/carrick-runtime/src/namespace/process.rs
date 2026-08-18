//! Per-process capability sets and user-namespace view — the *types*. The
//! storage is [`crate::kernel::Task`].
//!
//! User-namespace membership and the five capability sets are **per-process**
//! attributes (`capabilities(7)`, `user_namespaces(7)`): a `PR_CAPBSET_DROP`
//! or a `uid_map` write by one process is invisible to every other process,
//! and a `fork` child starts from a copy that diverges freely afterwards.
//!
//! This module used to hold them in a `static OnceLock<Mutex<ProcessNs>>`,
//! which was correct under the retired 1:1 host-process-per-guest-process
//! backends: a guest `fork` was a host `fork`, so the address-space copy gave
//! every guest process its own copy of the static for free. **Under HVPatch
//! every Linux process is a thread of ONE Darwin carrier**, so that static was
//! a single cell shared by every guest process at once — one guest's capbset
//! drop silently removed the capability from every other guest, monotonically
//! and irreversibly, and one guest's `unshare(CLONE_NEWUSER)` + `uid_map`
//! write appeared in every other guest's `/proc/self/uid_map`.
//!
//! The state therefore lives on the task, next to [`crate::kernel::Task`]'s
//! `oom_score_adj` and `keyrings` and for exactly the same reason. Namespace
//! *ids* are the deliberate exception — see [`alloc_ns_id`].
//!
//! Cross-process sharing of namespace objects (the file-backed registry of
//! design §4.5) and the PID-namespace hot state (the `MAP_SHARED` region of
//! [`super::pid`]) remain separate.

use std::sync::atomic::{AtomicU32, Ordering};

use super::user::UserNs;
use super::{FIRST_DYNAMIC_NS, NsId};

/// The Docker default bounded capability set, observed on
/// `docker run debian:stable` (design §1.2, §4.4). carrick reports this in
/// `/proc/self/status` so capability-probing tools see a coherent non-zero set
/// instead of the all-zero set that makes them refuse to proceed.
pub const DOCKER_DEFAULT_CAPS: u64 = 0x0000_0000_a804_25fb;

/// The highest capability number carrick models (`CAP_LAST_CAP`,
/// `capabilities(7)`; mirrors `LINUX_CAP_LAST_CAP`). A full set is all bits
/// `0..=CAP_LAST_CAP`.
pub const CAP_LAST_CAP: u32 = 40;
pub const CAP_CHOWN: u32 = 0;
pub const CAP_DAC_OVERRIDE: u32 = 1;
pub const CAP_DAC_READ_SEARCH: u32 = 2;
pub const CAP_FOWNER: u32 = 3;
pub const CAP_FSETID: u32 = 4;
pub const CAP_SETPCAP: u32 = 8;
pub const CAP_LINUX_IMMUTABLE: u32 = 9;
pub const CAP_NET_RAW: u32 = 13;
pub const CAP_SYS_PTRACE: u32 = 19;
pub const CAP_SYS_ADMIN: u32 = 21;
pub const CAP_SYS_NICE: u32 = 23;
pub const CAP_MKNOD: u32 = 27;
pub const CAP_MAC_OVERRIDE: u32 = 32;
pub const CAP_WAKE_ALARM: u32 = 35;

/// The file-related capabilities `fsuid` transitions raise and lower in the
/// EFFECTIVE set (capabilities(7), "Effect of user ID changes" rule 3).
pub const FS_CAPABILITIES: u64 = (1 << CAP_CHOWN)
    | (1 << CAP_DAC_OVERRIDE)
    | (1 << CAP_DAC_READ_SEARCH)
    | (1 << CAP_FOWNER)
    | (1 << CAP_FSETID)
    | (1 << CAP_LINUX_IMMUTABLE)
    | (1 << CAP_MKNOD)
    | (1 << CAP_MAC_OVERRIDE);
pub const CAP_SYS_RESOURCE: u32 = 24;

/// Resolve a docker `--cap-add` name (no `CAP_` prefix, case-insensitive) to
/// its capability number. Only the capabilities carrick actually models are
/// listed; an unknown name yields `None` so the caller can refuse loudly
/// rather than silently granting nothing.
pub fn capability_by_name(name: &str) -> Option<u32> {
    let name = name
        .trim()
        .trim_start_matches("CAP_")
        .trim_start_matches("cap_");
    Some(match name.to_ascii_uppercase().as_str() {
        "CHOWN" => CAP_CHOWN,
        "DAC_OVERRIDE" => CAP_DAC_OVERRIDE,
        "DAC_READ_SEARCH" => CAP_DAC_READ_SEARCH,
        "FOWNER" => CAP_FOWNER,
        "FSETID" => CAP_FSETID,
        "SETPCAP" => CAP_SETPCAP,
        "LINUX_IMMUTABLE" => CAP_LINUX_IMMUTABLE,
        "NET_RAW" => CAP_NET_RAW,
        "SYS_ADMIN" => CAP_SYS_ADMIN,
        "SYS_PTRACE" => CAP_SYS_PTRACE,
        "SYS_NICE" => CAP_SYS_NICE,
        "SYS_RESOURCE" => CAP_SYS_RESOURCE,
        "MKNOD" => CAP_MKNOD,
        "MAC_OVERRIDE" => CAP_MAC_OVERRIDE,
        "WAKE_ALARM" => CAP_WAKE_ALARM,
        _ => return None,
    })
}

/// The bit mask for a set of docker `--cap-add` names, plus the names that
/// were not recognised.
pub fn capability_mask_for_names(names: &[String]) -> (u64, Vec<String>) {
    let mut mask = 0_u64;
    let mut unknown = Vec::new();
    for name in names {
        match capability_by_name(name) {
            Some(cap) => mask |= 1_u64 << cap,
            None => unknown.push(name.clone()),
        }
    }
    (mask, unknown)
}

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
        // `--cap-add` raises the effective/permitted/bounding sets exactly as
        // docker does; the grant is a launch-time constant (see
        // `grant_launch_capabilities`).
        let caps = DOCKER_DEFAULT_CAPS | launch_granted_capabilities();
        Self {
            effective: caps,
            permitted: caps,
            inheritable: 0,
            bounding: caps,
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

/// A process's capability sets plus its user-namespace view — the pair that
/// `unshare(CLONE_NEWUSER)` replaces together, and the pair that a `fork`
/// child inherits as a copy.
///
/// The authority is one mutex on [`crate::kernel::Task`]; the `/proc`
/// synthesis layer receives a snapshot of this on its render context, the same
/// way it receives `oom_score_adj`.
#[derive(Clone, Debug)]
pub struct ProcessCredsNs {
    /// The modeled capability set — the Docker default until a fresh user
    /// namespace grants a full set within it.
    pub caps: CapabilitySet,
    /// This process's user namespace. Starts as the identity initial ns
    /// (uid 0 → host uid 0), so the common `docker run` case is unchanged.
    pub user: UserNs,
}

/// Capabilities granted at launch by `--cap-add`, ORed into the container
/// default set every process starts from. A launch-time constant: written
/// once before the guest boots and read-only thereafter, exactly like the
/// container syscall policy it travels with.
static LAUNCH_GRANTED_CAPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Record the launch-time `--cap-add` grant. Called once, before boot.
pub fn grant_launch_capabilities(mask: u64) {
    LAUNCH_GRANTED_CAPS.store(mask, std::sync::atomic::Ordering::Release);
}

/// The launch-time grant, for the container default set.
pub fn launch_granted_capabilities() -> u64 {
    LAUNCH_GRANTED_CAPS.load(std::sync::atomic::Ordering::Acquire)
}

impl Default for ProcessCredsNs {
    fn default() -> Self {
        Self {
            caps: CapabilitySet::docker_default(),
            user: UserNs::initial(super::INITIAL_USER_NS),
        }
    }
}

/// Bit `cap` of a 64-bit capability mask, or `None` for an out-of-range
/// capability number. Every accessor below funnels through this so an
/// out-of-range `prctl` argument can never shift past the width of the mask.
fn cap_bit(cap: u32) -> Option<u64> {
    (cap <= 63).then(|| 1u64 << cap)
}

impl CapabilitySet {
    /// `prctl(PR_CAPBSET_READ, cap)` — is `cap` in the bounding set?
    pub fn capbset_read(&self, cap: u32) -> bool {
        cap_bit(cap).is_some_and(|bit| self.bounding & bit != 0)
    }

    /// `prctl(PR_CAPBSET_DROP, cap)` — clear `cap` from the bounding set
    /// (accept-and-record; §4.4). Irreversible for this process, and per
    /// `capabilities(7)` visible to nobody else.
    pub fn capbset_drop(&mut self, cap: u32) {
        if let Some(bit) = cap_bit(cap) {
            self.bounding &= !bit;
        }
    }

    /// Is `cap` in the effective set?
    pub fn has_effective(&self, cap: u32) -> bool {
        cap_bit(cap).is_some_and(|bit| self.effective & bit != 0)
    }

    /// `PR_CAP_AMBIENT_IS_SET`.
    pub fn ambient_is_set(&self, cap: u32) -> bool {
        cap_bit(cap).is_some_and(|bit| self.ambient & bit != 0)
    }

    /// `PR_CAP_AMBIENT_LOWER`.
    pub fn ambient_lower(&mut self, cap: u32) {
        if let Some(bit) = cap_bit(cap) {
            self.ambient &= !bit;
        }
    }

    /// `PR_CAP_AMBIENT_CLEAR_ALL`.
    pub fn ambient_clear_all(&mut self) {
        self.ambient = 0;
    }

    /// `PR_CAP_AMBIENT_RAISE`. Per `capabilities(7)` a capability may enter the
    /// ambient set only while it is in BOTH the permitted and the inheritable
    /// set; otherwise the raise fails (EPERM at the caller).
    pub fn ambient_raise(&mut self, cap: u32) -> bool {
        let Some(bit) = cap_bit(cap) else {
            return false;
        };
        if self.permitted & bit == 0 || self.inheritable & bit == 0 {
            return false;
        }
        self.ambient |= bit;
        true
    }

    /// Is this set privileged for *map-writing* purposes in its user
    /// namespace? True if it holds `CAP_SETUID`/`CAP_SETGID` (modeled), i.e.
    /// it is uid 0 with the default set, or it created a fresh userns (full
    /// caps). This is the gate the `/proc/[pid]/uid_map` writer consults
    /// (design §4.3).
    pub fn is_map_write_privileged(&self) -> bool {
        const CAP_SETGID: u64 = 1 << 6;
        const CAP_SETUID: u64 = 1 << 7;
        self.effective & (CAP_SETUID | CAP_SETGID) == (CAP_SETUID | CAP_SETGID)
    }
}

/// Monotonic allocator for namespace ids, scoped to the whole VM carrier.
///
/// This is the deliberate exception to "per-process state lives on the task".
/// A namespace id is an IDENTITY, not a per-process view of one: Linux exposes
/// it as an nsfs inode number that is unique kernel-wide, and two namespaces
/// are the same namespace exactly when their ids match. A per-task allocator
/// would hand the same id to two processes that unshared independently,
/// aliasing two distinct namespaces into one — the opposite of the isolation
/// this module exists to provide. Carrier-wide monotonic allocation is what
/// keeps ids unique, so a shared counter is correct here.
pub fn alloc_ns_id() -> NsId {
    static NEXT_NS_ID: AtomicU32 = AtomicU32::new(FIRST_DYNAMIC_NS);
    NEXT_NS_ID.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_caps_covers_modeled_range() {
        // CAP_LAST_CAP=40 → bits 0..=40 set.
        assert_eq!(FULL_CAPS, (1u64 << 41) - 1);
        const { assert!(FULL_CAPS & (1 << 40) != 0) };
        const { assert!(FULL_CAPS & (1 << 41) == 0) };
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
    fn docker_default_excludes_sys_resource() {
        let bit = 1u64 << CAP_SYS_RESOURCE;
        assert_eq!(CapabilitySet::docker_default().effective & bit, 0);
        assert_ne!(CapabilitySet::full().effective & bit, 0);
    }

    #[test]
    fn docker_default_excludes_sys_ptrace() {
        // userfaultfd(2)'s container-policy EPERM depends on the default set
        // LACKING CAP_SYS_PTRACE (the oracle's Docker seccomp gate; LTP
        // userfaultfd01/02/06 TCONF).
        let bit = 1u64 << CAP_SYS_PTRACE;
        assert_eq!(CapabilitySet::docker_default().effective & bit, 0);
        assert_ne!(CapabilitySet::full().effective & bit, 0);
    }

    #[test]
    fn full_caps_is_map_write_privileged() {
        let c = CapabilitySet::full();
        assert!(c.effective & (1 << 6) != 0);
        assert!(c.effective & (1 << 7) != 0);
    }
}
