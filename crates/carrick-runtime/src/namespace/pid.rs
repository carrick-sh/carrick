//! PID namespace translation: a host-pid ↔ ns-pid table backed by a
//! `MAP_SHARED|MAP_ANON` region so it is coherent across `fork` (design §3.3,
//! §5.2, §5.6).
//!
//! The region is allocated **before the first guest fork** (mirroring
//! `carrick_host::guest_cpu::init_child_table`) and inherited by every
//! descendant: all processes map the same physical pages, so a
//! `fetch_add`/`compare_exchange` on an `AtomicU32` in one process is visible to
//! all others (Apple-Silicon hardware atomics operate on physical addresses).
//!
//! Only the *initial* root PID namespace is modeled by the global region for
//! now — the common `docker run` case (one fresh pid ns whose init is pid 1).
//! Nested guest-created namespaces (Phase 4) extend this; the slot model already
//! carries enough to distinguish them by `init_host_pid` if needed later.
//!
//! NOTE: the translation/shared-region API below is wired into the fork path,
//! `getpid`/`getppid`, `wait4`/`kill`, and `/proc` in Phase 2. Until then the
//! items are unused; the module-level `allow(dead_code)` is removed once Phase 2
//! lands.
#![allow(dead_code)]

use std::sync::atomic::{AtomicI32, AtomicPtr, AtomicU8, AtomicU32, Ordering};

use super::NsId;

/// Member is alive and (so far as we know) parented within the namespace.
pub const MEMBER_ALIVE: u8 = 0;
/// Member's namespace-parent died; `getppid` should report ns-pid 1 (design
/// §3.6). Set by the NsSupervisor.
pub const MEMBER_ORPHANED: u8 = 1;
/// Member has exited; `exit_status` holds the `waitpid`-format status harvested
/// from `NOTE_EXITSTATUS` (design §3.4).
pub const MEMBER_DEAD: u8 = 2;

/// Number of member slots in the shared table. Container process trees are tens
/// to low hundreds of members; 1024 is comfortable headroom (design §3.3).
pub const MEMBER_SLOTS: usize = 1024;

/// ns-pid 1 — the namespace init (`pid_namespaces(7)`).
pub const NS_INIT_PID: u32 = 1;

/// One member of a PID namespace. All fields are atomic so they can be read and
/// written cross-process through the shared mapping. `host_pid == 0` marks a
/// free slot.
#[repr(C)]
pub struct MemberSlot {
    pub host_pid: AtomicU32,
    pub ns_pid: AtomicU32,
    pub parent_host_pid: AtomicU32,
    pub flags: AtomicU8,
    pub exit_status: AtomicI32,
}

impl MemberSlot {
    const fn empty() -> Self {
        Self {
            host_pid: AtomicU32::new(0),
            ns_pid: AtomicU32::new(0),
            parent_host_pid: AtomicU32::new(0),
            flags: AtomicU8::new(MEMBER_ALIVE),
            exit_status: AtomicI32::new(0),
        }
    }
}

/// The shared region. Laid out `#[repr(C)]` so its layout is identical in every
/// process mapping the page.
#[repr(C)]
pub struct NsSharedRegion {
    /// Monotonic ns-pid allocator. Seeded at 2 (pid 1 is pre-assigned to the
    /// init before the first fork), so the first forked child gets ns-pid 2.
    pub next_pid: AtomicU32,
    /// The init's host pid (ns-pid 1). 0 until launch placement sets it.
    pub init_host_pid: AtomicU32,
    pub members: [MemberSlot; MEMBER_SLOTS],
}

/// Global pointer to the shared region, inherited across fork (the child's
/// static still points at the same physical pages). Null until [`init`].
static REGION: AtomicPtr<NsSharedRegion> = AtomicPtr::new(std::ptr::null_mut());

/// Allocate the shared region with `mmap(MAP_SHARED|MAP_ANON)` and publish it.
/// Must be called **once, before the first guest fork** (design §3.3). Returns
/// `Err` (never panics — the no-panic lint forbids it) if the mapping fails;
/// the caller should fall back to identity (non-namespaced) behavior.
///
/// `init_host_pid` is the root guest's host pid (ns-pid 1). Idempotent: a second
/// call returns the existing region.
pub fn init(init_host_pid: u32) -> Result<(), ()> {
    if !REGION.load(Ordering::Acquire).is_null() {
        return Ok(());
    }
    let size = std::mem::size_of::<NsSharedRegion>();
    // SAFETY: a standard anonymous shared mapping; size is the exact struct
    // size; the kernel zero-initializes the pages (so every AtomicU32 starts 0).
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(());
    }
    let region = ptr.cast::<NsSharedRegion>();
    // The pages are zeroed; set the two fields with non-zero initial values.
    // SAFETY: `region` is a valid, writable mapping of exactly this struct.
    unsafe {
        (*region).next_pid.store(2, Ordering::Relaxed);
        (*region)
            .init_host_pid
            .store(init_host_pid, Ordering::Relaxed);
        // Pre-register the init as ns-pid 1 in slot 0.
        let init_slot = &(*region).members[0];
        init_slot.ns_pid.store(NS_INIT_PID, Ordering::Relaxed);
        init_slot.parent_host_pid.store(0, Ordering::Relaxed);
        init_slot.flags.store(MEMBER_ALIVE, Ordering::Relaxed);
        // Publish host_pid last so a concurrent reader never sees a half-filled
        // slot (Release pairs with the Acquire scan in `host_to_ns`).
        init_slot.host_pid.store(init_host_pid, Ordering::Release);
    }
    REGION.store(region, Ordering::Release);
    Ok(())
}

/// Borrow the shared region, or `None` if namespaces are not enabled for this
/// run (identity behavior — `getpid` returns the host pid).
pub fn region() -> Option<&'static NsSharedRegion> {
    let ptr = REGION.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        // SAFETY: once published the region lives for the whole process; the
        // mapping is never unmapped while the process runs.
        Some(unsafe { &*ptr })
    }
}

impl NsSharedRegion {
    /// Allocate the next ns-pid (lock-free, monotonic, never recycled — gaps are
    /// harmless, design §8).
    pub fn alloc_ns_pid(&self) -> u32 {
        self.next_pid.fetch_add(1, Ordering::SeqCst)
    }

    /// The init's host pid (ns-pid 1), or 0 if unset.
    pub fn init_host_pid(&self) -> u32 {
        self.init_host_pid.load(Ordering::Acquire)
    }

    /// Claim a free slot for a new member. Returns the slot index, or `None` if
    /// the table is full (the caller degrades gracefully — never panics).
    pub fn register(&self, host_pid: u32, ns_pid: u32, parent_host_pid: u32) -> Option<usize> {
        for (i, slot) in self.members.iter().enumerate() {
            if slot
                .host_pid
                .compare_exchange(0, host_pid, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                slot.ns_pid.store(ns_pid, Ordering::Relaxed);
                slot.parent_host_pid
                    .store(parent_host_pid, Ordering::Relaxed);
                slot.exit_status.store(0, Ordering::Relaxed);
                // flags Release-published so a reader that sees host_pid also
                // sees ALIVE (it was set when the slot was last freed/zeroed).
                slot.flags.store(MEMBER_ALIVE, Ordering::Release);
                return Some(i);
            }
        }
        None
    }

    /// Translate a host pid to its ns-pid in this namespace, or `None` if the
    /// host pid is not a member (caller decides the fallback — e.g. 0 for a
    /// parent outside the ns).
    pub fn host_to_ns(&self, host_pid: u32) -> Option<u32> {
        for slot in &self.members {
            if slot.host_pid.load(Ordering::Acquire) == host_pid {
                return Some(slot.ns_pid.load(Ordering::Acquire));
            }
        }
        None
    }

    /// Translate an ns-pid to its host pid, or `None` if the ns-pid names no
    /// member (caller maps to `ESRCH`).
    pub fn ns_to_host(&self, ns_pid: u32) -> Option<u32> {
        for slot in &self.members {
            if slot.host_pid.load(Ordering::Acquire) != 0
                && slot.ns_pid.load(Ordering::Acquire) == ns_pid
            {
                return Some(slot.host_pid.load(Ordering::Acquire));
            }
        }
        None
    }

    /// Find the slot index for a host pid, if registered.
    pub fn slot_of(&self, host_pid: u32) -> Option<usize> {
        self.members
            .iter()
            .position(|s| s.host_pid.load(Ordering::Acquire) == host_pid)
    }

    /// The member's flags, or `None` if not registered.
    pub fn flags_of(&self, host_pid: u32) -> Option<u8> {
        self.slot_of(host_pid)
            .map(|i| self.members[i].flags.load(Ordering::Acquire))
    }

    /// Mark every live member whose ns-parent is `dead_host_pid` as orphaned
    /// (design §3.6 step 3). Called by the NsSupervisor on a parent's death.
    pub fn mark_children_orphaned(&self, dead_host_pid: u32) {
        for slot in &self.members {
            if slot.host_pid.load(Ordering::Acquire) != 0
                && slot.parent_host_pid.load(Ordering::Acquire) == dead_host_pid
                && slot.flags.load(Ordering::Acquire) == MEMBER_ALIVE
            {
                slot.flags.store(MEMBER_ORPHANED, Ordering::Release);
            }
        }
    }

    /// Record a member's death and its exit status (design §3.4).
    pub fn mark_dead(&self, host_pid: u32, exit_status: i32) {
        if let Some(i) = self.slot_of(host_pid) {
            self.members[i]
                .exit_status
                .store(exit_status, Ordering::Relaxed);
            self.members[i].flags.store(MEMBER_DEAD, Ordering::Release);
        }
    }
}

/// A PID namespace descriptor — the per-process attribute (inherited at fork via
/// address-space copy) naming which ns the process lives in. The mutable
/// translation lives in the shared region; this is just identity + lineage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PidNs {
    pub id: NsId,
    pub parent: Option<NsId>,
    /// 0 = the initial/host ns (identity map, ns_pid == host_pid).
    pub level: u32,
}

impl PidNs {
    /// The initial (host) namespace — identity translation.
    pub fn initial(id: NsId) -> Self {
        Self {
            id,
            parent: None,
            level: 0,
        }
    }

    /// A fresh child namespace at `level`.
    pub fn fresh(id: NsId, parent: NsId, level: u32) -> Self {
        Self {
            id,
            parent: Some(parent),
            level,
        }
    }

    /// `true` for the initial/host namespace (no translation).
    pub fn is_initial(&self) -> bool {
        self.level == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests run in a single process (mmap MAP_SHARED|MAP_ANON works
    // in-process); fork-coherence is validated by the conformance probes under
    // the signed build. They are gated to run serially via a fresh region per
    // test would be ideal, but the region is a process-global; so each test
    // uses the global region after init and asserts on its own pids.

    #[test]
    fn pidns_descriptors() {
        let init = PidNs::initial(1);
        assert!(init.is_initial());
        let child = PidNs::fresh(2, 1, 1);
        assert!(!child.is_initial());
        assert_eq!(child.parent, Some(1));
        assert_eq!(child.level, 1);
    }

    #[test]
    fn shared_region_alloc_register_translate() {
        // Use a locally-mmap'd region (not the global) so this test is
        // independent of init() ordering with other tests.
        let size = std::mem::size_of::<NsSharedRegion>();
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert_ne!(ptr, libc::MAP_FAILED);
        let region: &NsSharedRegion = unsafe { &*ptr.cast::<NsSharedRegion>() };
        region.next_pid.store(2, Ordering::Relaxed);
        region.init_host_pid.store(100, Ordering::Relaxed);
        // pre-register init as ns-pid 1
        assert_eq!(region.register(100, NS_INIT_PID, 0), Some(0));

        // a forked child host pid 200, ns-parent 100
        let ns_pid = region.alloc_ns_pid();
        assert_eq!(ns_pid, 2);
        assert!(region.register(200, ns_pid, 100).is_some());

        assert_eq!(region.host_to_ns(100), Some(1));
        assert_eq!(region.host_to_ns(200), Some(2));
        assert_eq!(region.host_to_ns(999), None);
        assert_eq!(region.ns_to_host(1), Some(100));
        assert_eq!(region.ns_to_host(2), Some(200));
        assert_eq!(region.ns_to_host(42), None);

        // orphan the child by killing its parent (100)
        region.mark_children_orphaned(100);
        assert_eq!(region.flags_of(200), Some(MEMBER_ORPHANED));

        // mark the child dead
        region.mark_dead(200, 0);
        assert_eq!(region.flags_of(200), Some(MEMBER_DEAD));

        unsafe {
            libc::munmap(ptr, size);
        }
    }
}
