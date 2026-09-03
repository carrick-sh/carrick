//! PID namespace translation: a host-pid ↔ ns-pid table over the carrier's
//! kernel-arena process section (design §3.3, §5.2, §5.6).
//!
//! One record table serves every container in the carrier; each PID namespace
//! owns one [`NsSharedRegion`], which claims a numbering slot in the arena
//! (`carrick_kernel::pidns`) and tags its member records with its namespace
//! id. There is no process-global region: a task reaches its namespace through
//! its `Container` (`Task::pid_ns_region`), the free functions below resolve
//! the CALLING task's region from the active dispatch context, and callers
//! outside a dispatch scope that still hold the exact task pass it explicitly
//! (`*_for(context, ..)`). Retiring (or dropping) a container's region retires
//! its members and returns the slot for the next container.
//!
//! Only the container's root PID namespace is modeled; nested guest-created
//! namespaces (Phase 4) extend the same slot model.
#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, Weak};

use carrick_kernel::arena::{ArenaError, KernelArena};
use carrick_kernel::domains::{HostPid, ProcessGeneration};
use carrick_kernel::pidns::{PID_NAMESPACE_SLOTS, PidNamespaceRef, PidNamespaceSlot};
use carrick_kernel::process::{
    FLAG_ALIVE, FLAG_DEAD, FLAG_ORPHANED, PROCESS_RECORDS, ProcessRecord, ProcessRecordRef,
    ProcessRecordTransitionAction, ProcessRecordTransitionError, ProcessSection, REGISTERING,
};
#[cfg(test)]
use carrick_kernel::process::{VirtualPtraceControl, VirtualPtraceState};

use super::NsId;

/// Member is alive and (so far as we know) parented within the namespace.
pub const MEMBER_ALIVE: u32 = FLAG_ALIVE;
/// Member's namespace-parent died; `getppid` should report ns-pid 1 (design
/// §3.6). Set from the Carrick kernel graph.
pub const MEMBER_ORPHANED: u32 = FLAG_ORPHANED;
/// Member has exited; `exit_status` holds the harvested bare exit code (the
/// multiplexer's `PollEvent::exit_status`: WEXITSTATUS, or 128+signal for a
/// signal death) so the ns-init can report it for an orphaned grandchild (§3.4).
pub const MEMBER_DEAD: u32 = FLAG_DEAD;

/// Number of process records in the shared namespace table.
pub const MEMBER_SLOTS: usize = PROCESS_RECORDS;

/// ns-pid 1 — the namespace init (`pid_namespaces(7)`).
pub const NS_INIT_PID: u32 = 1;

/// Sentinel used while a process is filling a slot. Readers must treat it as
/// unpublished; the real host pid is release-stored only after the rest of the
/// slot is initialized.
pub const HOST_PID_REGISTERING: u32 = REGISTERING;
/// Sentinel used while namespace adoption or process retirement owns the
/// transition of a shared process record. Readers must treat it as unpublished.
pub(crate) const NS_PID_REGISTERING: u32 = REGISTERING;
const RUN_STATE_KIND_TID: u64 = 1 << 40;

pub type MemberSlot = ProcessRecord;

/// One PID namespace's view of the carrier's process table: the arena's
/// shared record section plus this namespace's own numbering slot.
///
/// OWNED, not global. A container allocates one at launch and holds it in an
/// `Arc`; every task in the container reaches it through its `Container`
/// (`Task::pid_ns_region`), never through a static. Container teardown calls
/// [`NsSharedRegion::retire`] to retire the namespace's member tags and
/// release the slot for reuse; dropping the last `Arc` does the same as a
/// safety net if nobody retired explicitly.
pub struct NsSharedRegion {
    arena: &'static KernelArena,
    section: &'static ProcessSection,
    /// This namespace's numbering words. Borrowed for `'static` because the
    /// arena mapping is process-lifetime and the slot cannot be reclaimed
    /// while this owner holds `claim` (release needs the exact reference).
    ns: &'static PidNamespaceSlot,
    claim: PidNamespaceRef,
    /// Set by whichever of `retire`/`Drop` released the slot first, so the
    /// other is a no-op and a reused slot is never released twice.
    released: AtomicBool,
    /// One Linux PID/TID number domain per namespace. Allocation is
    /// monotonic; dropping a preparation burns its number but publishes no
    /// membership, which is both Linux-compatible and rollback-safe.
    next_identity: AtomicU32,
    /// Serializes exact-claim validation with retirement. Once a stale holder
    /// acquires this lock, it must still prove `claim` names the live arena
    /// owner before reading or mutating either the slot or member records.
    lifecycle: Mutex<()>,
}

#[derive(Debug)]
pub(crate) struct PreparedNamespaceIdentity {
    region: Arc<NsSharedRegion>,
    internal_id: u32,
    visible_id: u32,
    parent_internal_id: u32,
    active: Option<Arc<AtomicBool>>,
}

#[derive(Clone, Debug)]
pub(crate) struct PreparedNamespaceIdentityView {
    internal_id: u32,
    visible_id: u32,
    active: Weak<AtomicBool>,
}

impl PreparedNamespaceIdentityView {
    pub(crate) fn visible_for(&self, internal_id: u32) -> Option<u32> {
        (self.internal_id == internal_id
            && self
                .active
                .upgrade()
                .is_some_and(|active| active.load(Ordering::Acquire)))
        .then_some(self.visible_id)
    }
}

impl PreparedNamespaceIdentity {
    pub(crate) const fn visible_id(&self) -> u32 {
        self.visible_id
    }

    pub(crate) fn view(&self) -> Option<PreparedNamespaceIdentityView> {
        Some(PreparedNamespaceIdentityView {
            internal_id: self.internal_id,
            visible_id: self.visible_id,
            active: Arc::downgrade(self.active.as_ref()?),
        })
    }

    pub(crate) fn commit(self) -> bool {
        let committed = self
            .region
            .register(self.internal_id, self.visible_id, self.parent_internal_id)
            .is_some();
        if let Some(active) = self.active.as_ref() {
            active.store(false, Ordering::Release);
        }
        committed
    }
}

impl Drop for PreparedNamespaceIdentity {
    fn drop(&mut self) {
        if let Some(active) = self.active.as_ref() {
            active.store(false, Ordering::Release);
        }
    }
}

impl std::fmt::Debug for NsSharedRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NsSharedRegion")
            .field("ns_id", &self.ns_id())
            .field("slot", &self.claim.index)
            .field("init_host_pid", &self.init_host_pid())
            .finish()
    }
}

impl NsSharedRegion {
    /// Claim a fresh PID namespace in `arena`. The namespace id comes from the
    /// carrier-wide allocator, so record tags are unambiguous across
    /// containers. Fails loudly when the arena's slot table is full.
    pub fn allocate(arena: &'static KernelArena) -> Result<Arc<Self>, ArenaError> {
        // The carrier-wide id counter starting at FIRST_DYNAMIC_NS (2) reaches
        // 0 only after wrapping u32: report that as the same exhaustion.
        let ns_id = std::num::NonZeroU32::new(super::process::alloc_ns_id()).ok_or(
            ArenaError::Exhausted {
                section: "pid_namespaces",
                capacity: PID_NAMESPACE_SLOTS,
            },
        )?;
        let layout = arena.layout();
        let (claim, ns) = layout
            .pid_namespaces
            .claim(ns_id, arena.allocate_generation())?;
        Ok(Arc::new(Self {
            arena,
            section: &layout.processes,
            ns,
            claim,
            released: AtomicBool::new(false),
            next_identity: AtomicU32::new(NS_INIT_PID + 1),
            lifecycle: Mutex::new(()),
        }))
    }

    fn claim_is_live(&self) -> bool {
        !self.released.load(Ordering::Acquire)
            && self
                .arena
                .layout()
                .pid_namespaces
                .slot(self.claim)
                .is_some()
    }

    pub(crate) fn reserve_init_identity(
        self: &Arc<Self>,
        internal_id: u32,
    ) -> Option<PreparedNamespaceIdentity> {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !self.claim_is_live() || self.init_host_pid_locked() != 0 {
            return None;
        }
        Some(PreparedNamespaceIdentity {
            region: Arc::clone(self),
            internal_id,
            visible_id: NS_INIT_PID,
            parent_internal_id: 0,
            active: Some(Arc::new(AtomicBool::new(true))),
        })
    }

    pub(crate) fn reserve_identity(
        self: &Arc<Self>,
        internal_id: u32,
        parent_internal_id: u32,
    ) -> Option<PreparedNamespaceIdentity> {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !self.claim_is_live() {
            return None;
        }
        let visible_id = self
            .next_identity
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                (current < i32::MAX as u32).then_some(current + 1)
            })
            .ok()?;
        Some(PreparedNamespaceIdentity {
            region: Arc::clone(self),
            internal_id,
            visible_id,
            parent_internal_id,
            active: None,
        })
    }

    /// This namespace's id — the `pid:[N]` inode and the member record tag.
    pub fn ns_id(&self) -> NsId {
        self.claim.ns_id.get()
    }

    /// Record `init_host_pid` as the namespace init (ns-pid 1) and pre-register
    /// it as the first member. The init's host process-group/session are
    /// captured so ns-pgid 1 ↔ that group (`host_to_ns_pgid`).
    pub fn set_init(&self, init_host_pid: u32) {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !self.claim_is_live()
            || self
                .register_locked(init_host_pid, NS_INIT_PID, 0)
                .is_none()
        {
            return;
        }
        self.ns
            .init_host_pid
            .store(init_host_pid, Ordering::Relaxed);
        let init_host_pgid = unsafe { libc::getpgrp() };
        if init_host_pgid > 0 {
            self.ns
                .init_host_pgid
                .store(init_host_pgid as u32, Ordering::Relaxed);
        }
        let init_host_sid = unsafe { libc::getsid(0) };
        if init_host_sid > 0 {
            self.ns
                .init_host_sid
                .store(init_host_sid as u32, Ordering::Relaxed);
        }
    }

    /// Register a Carrick-kernel init whose task, process-group, and session
    /// identities share one carrier-global number. Unlike [`Self::set_init`],
    /// this never consults the host process group/session: multiple container
    /// roots coexist inside the same host carrier.
    pub(crate) fn set_kernel_init(&self, internal_task_id: u32) -> bool {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !self.claim_is_live()
            || self
                .register_locked(internal_task_id, NS_INIT_PID, 0)
                .is_none()
        {
            return false;
        }
        self.ns
            .init_host_pid
            .store(internal_task_id, Ordering::Release);
        self.ns
            .init_host_pgid
            .store(internal_task_id, Ordering::Release);
        self.ns
            .init_host_sid
            .store(internal_task_id, Ordering::Release);
        true
    }

    pub(crate) fn rollback_kernel_init(&self, internal_task_id: u32) {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !self.claim_is_live() {
            return;
        }
        if self.ns.init_host_pid.load(Ordering::Acquire) == internal_task_id {
            self.ns.init_host_pid.store(0, Ordering::Release);
            self.ns.init_host_pgid.store(0, Ordering::Release);
            self.ns.init_host_sid.store(0, Ordering::Release);
        }
        self.unregister_reaped_locked(internal_task_id);
    }

    /// Container teardown: retire every member this namespace still tags and
    /// release its arena slot NOW, without waiting for the last `Arc` (a
    /// reaped task's `Container` handle may outlive the teardown by a beat).
    /// `true` if this call released the slot; `false` if it was already
    /// released. Consumed by `carrier::retire_container` (Task 23).
    pub(crate) fn retire(self: Arc<Self>) -> bool {
        self.release_slot()
    }

    fn release_slot(&self) -> bool {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.released.load(Ordering::Acquire) {
            return false;
        }
        self.retire_members();
        if !self.arena.layout().pid_namespaces.release(self.claim) {
            return false;
        }
        self.released.store(true, Ordering::Release);
        true
    }

    /// Strip this namespace's identity from every record it tagged and release
    /// the ones nothing else owns, so a later namespace reusing the slot can
    /// never inherit stale members. A record whose transition is owned
    /// elsewhere at this instant keeps a tag no live namespace will ever equal.
    fn retire_members(&self) {
        let ns_id = self.ns_id();
        for (index, record) in self.section.records.iter().enumerate() {
            if record.pid_ns.load(Ordering::Acquire) != ns_id {
                continue;
            }
            if !record.try_claim_transition() {
                continue;
            }
            let host_pid = record.host_pid.load(Ordering::Acquire);
            let generation = record.generation.load(Ordering::Acquire);
            let still_ours = record.pid_ns.load(Ordering::Acquire) == ns_id;
            if still_ours {
                record.ns_pid.store(0, Ordering::Release);
                record.pid_ns.store(0, Ordering::Release);
                record.exec_generation.store(0, Ordering::Release);
                record.exit_status.store(0, Ordering::Relaxed);
                record
                    .flags
                    .fetch_and(!(MEMBER_DEAD | MEMBER_ORPHANED), Ordering::AcqRel);
            }
            record.release_transition();
            // A record no run-state owner still holds is this namespace's to
            // return; a live task's record (nonzero run-state word) stays for
            // `run_state::clear_guest_process`.
            if still_ours && generation != 0 && record.run_state.load(Ordering::Acquire) == 0 {
                let _ = self.section.release_if_namespace_unowned(
                    ProcessRecordRef {
                        index,
                        generation: ProcessGeneration::new(generation),
                    },
                    HostPid::new(host_pid),
                );
            }
        }
    }
}

impl Drop for NsSharedRegion {
    fn drop(&mut self) {
        // Safety net only: `retire` is the intended release.
        let _ = self.release_slot();
    }
}

/// The CALLING task's PID namespace region, or `None` when no guest syscall
/// is in flight on this thread or the task's container shares the host pid
/// namespace (`--pid host`). Every translation below is then the identity.
pub fn region() -> Option<Arc<NsSharedRegion>> {
    crate::dispatch::resources::with_active_context(region_for).flatten()
}

/// The PID namespace region of the exact task `context` names. For callers
/// outside a dispatch scope that still hold the task — signal delivery, exec
/// commit — never a thread- or process-derived surrogate.
pub fn region_for(context: &crate::kernel::KernelContext) -> Option<Arc<NsSharedRegion>> {
    context.task().pid_ns_region()
}

/// `true` if the calling task is in a private PID namespace. When false, every
/// translation below is the identity (the guest pid IS the host pid) so
/// `run-elf` and `--pid host` runs are unchanged.
pub fn enabled() -> bool {
    region().is_some()
}

/// Translate a host pid to the pid the current ns sees. Identity when
/// namespaces are off. A host pid that is not a registered member translates
/// to `0` — matching `getppid()` of a process whose parent is outside the ns
/// (`pid_namespaces(7)`).
pub fn host_to_ns_or_self(host_pid: u32) -> u32 {
    match region() {
        Some(r) => r.host_to_ns(host_pid).unwrap_or(0),
        None => host_pid,
    }
}

/// Translate a host pid to the pid the current ns sees. Identity when
/// namespaces are off. Unlike [`host_to_ns_or_self`], this preserves the
/// "not a namespace member" distinction for wait/reap paths, where returning
/// pid 0 would be a bogus successful `waitpid(-1)` result.
pub fn host_to_ns(host_pid: u32) -> Option<u32> {
    match region() {
        Some(r) => r.host_to_ns(host_pid),
        None => Some(host_pid),
    }
}

/// Translate a host pgid/sid to the value the ns should report. If the group/
/// session leader is a namespace member, report its ns-pid; otherwise keep the
/// host value (a pgid/sid is always positive, so unlike a parent pid it must
/// NOT collapse to 0 — Phase 2 keeps non-member groups host-level, §6.6).
/// Identity when namespaces are off.
pub fn host_to_ns_pgid(host_pgid: u32) -> u32 {
    match region() {
        Some(r) => {
            // The init's host group is ns-pgid 1 (Docker-style pid-1=pgid-1),
            // even though its host pgid is the launching shell's (a non-member).
            let init_pgid = r.init_host_pgid();
            if init_pgid != 0 && host_pgid == init_pgid {
                return NS_INIT_PID;
            }
            let init_sid = r.init_host_sid();
            if init_sid != 0 && host_pgid == init_sid {
                return NS_INIT_PID;
            }
            r.host_to_ns(host_pgid).unwrap_or(host_pgid)
        }
        None => host_pgid,
    }
}

/// Translate an ns-pgid the guest supplied (e.g. `setpgid`/`kill(-pgid)`) to the
/// host pgid to operate on. ns-pgid 1 is the init's group → its real host pgid
/// (the existing group the init is in, so a child can JOIN it). Other ns-pgids
/// name a guest group leader, whose ns-pid == ns-pgid → its host pid (== its
/// host pgid, since it's a leader). Identity when namespaces are off.
pub fn ns_to_host_pgid(ns_pgid: u32) -> Option<u32> {
    match region() {
        Some(r) => {
            if ns_pgid == NS_INIT_PID {
                let init_pgid = r.init_host_pgid();
                if init_pgid != 0 {
                    return Some(init_pgid);
                }
            }
            r.ns_to_host(ns_pgid)
        }
        None => Some(ns_pgid),
    }
}

/// Refresh the special ns-pgid 1 ↔ host-pgid mapping after the namespace init
/// successfully changes its host process group.
pub fn refresh_init_host_pgid() {
    let Some(region) = region() else { return };
    if self_ns_pid() != NS_INIT_PID {
        return;
    }
    let pgid = unsafe { libc::getpgrp() };
    if pgid > 0 {
        region.set_init_host_pgid(pgid as u32);
    }
}

/// Translate an ns-pid the guest supplied back to the host pid to operate on.
/// Identity when namespaces are off. Returns `None` (→ `ESRCH`) for an ns-pid
/// that names no member.
/// A positive pid exactly as the GUEST names it, translated into the kernel
/// task-id number the graph indexes by.
///
/// The guest names processes in its pid namespace (`fork` returns ns pids,
/// `getpid` reports them), while the kernel graph is keyed by task id; the two
/// numbering domains drift apart the moment a container exists. `None` means
/// the number names nothing in the guest's namespace (ESRCH/ECHILD at the
/// caller's discretion). Identity when namespaces are off.
pub fn guest_pid_to_kernel(pid: i32) -> Option<i32> {
    let raw = u32::try_from(pid).ok().filter(|raw| *raw != 0)?;
    let host = ns_to_host_or_self(raw)?;
    i32::try_from(host).ok()
}

/// Resolve a guest-visible thread id through the exact caller's PID
/// namespace. A missing mapping never falls back to the carrier-global numeric
/// id: that can alias another process or a thread the caller's namespace cannot
/// name.
pub(crate) fn guest_tid_to_kernel_for(
    context: &crate::kernel::KernelContext,
    tid: i32,
) -> Option<i32> {
    let raw = u32::try_from(tid).ok().filter(|raw| *raw != 0)?;
    ns_to_kernel_for(context, raw).and_then(|internal| i32::try_from(internal).ok())
}

pub fn ns_to_host_or_self(ns_pid: u32) -> Option<u32> {
    match region() {
        Some(r) => r.ns_to_host(ns_pid),
        None => Some(ns_pid),
    }
}

/// The CALLING Linux process's own pid — what `getpid(2)` reports.
///
/// The first question this asks is "who is calling?", and only carrick's kernel
/// can answer it. Under HVPatch every logical Linux process is a thread of ONE
/// VM carrier, so the host-pid derivation below describes the carrier and is
/// identical for all of them: the pid-namespace region holds exactly one
/// registration, the carrier's, mapped to ns-pid 1, so this function returned
/// **1 for every guest process**. Everything built on it inherited that —
/// `NsPid::names_self()` said yes to pid 1 from any process (so a child's
/// `capset(hdr{pid:1})` mutated the child instead of failing EPERM),
/// `readlink("/proc/self")` resolved to "1" for everyone, and `/proc/<own
/// pid>/…` was ENOENT for any process that was not the init.
///
/// The dispatch boundary installs the calling task for exactly this class of
/// question (see `dispatch::resources::with_active_context`), so the kernel
/// graph answers whenever a guest syscall is in flight. Outside any dispatch
/// scope there is no calling Linux process to describe — runtime-internal
/// callers, and the unit suite — and the carrier's host-pid derivation is then
/// the honest answer rather than a wrong one.
pub fn self_ns_pid() -> u32 {
    if let Some(pid) = crate::dispatch::resources::with_active_context(|context| {
        let task_id = u32::try_from(context.task().key().id.raw()).unwrap_or(0);
        // SELF's pid — never zero. See `ns_self_pid_for`.
        ns_self_pid_for(context, task_id)
    }) {
        return pid;
    }
    let host = std::process::id();
    // `host_to_ns_or_self` returns 0 for a host pid that isn't mapped in the
    // namespace region — correct for a FOREIGN pid (invisible across the pid-ns
    // boundary), but the current process ALWAYS has a real pid, so self falls
    // back to it rather than the invalid 0. (This also keeps the unit suite
    // order-independent: a sibling test may have seeded the process-global
    // region without registering this test process's host pid.)
    match region() {
        Some(r) => r.host_to_ns(host).unwrap_or(host),
        None => host,
    }
}

/// The CALLING Linux process's parent pid — the value `getppid()` returns and
/// `/proc/self/status` shows as `PPid:`.
///
/// Same authority and same reason as [`self_ns_pid`]: the host `getppid()` names
/// the carrier's Darwin parent (usually a shell or CLI launcher), which is one
/// value shared by every guest process and is not a guest pid at all. The kernel
/// graph also observes reparenting, which a fork-time snapshot cannot: an orphan
/// whose parent exited must report its new reaper. A caller with no parent in
/// the graph is the namespace init, whose `PPid` is 0 (`pid_namespaces(7)`).
pub fn self_ns_ppid() -> u32 {
    if let Some(ppid) = crate::dispatch::resources::with_active_context(|context| {
        context
            .kernel()
            .process_identity(context.task().key().id)
            .map(|identity| {
                identity
                    .parent
                    .and_then(|parent| {
                        let parent_raw = u32::try_from(parent.raw()).ok()?;
                        Some(host_to_ns_or_self_for(context, parent_raw))
                    })
                    .unwrap_or(0)
            })
    })
    .flatten()
    {
        return ppid;
    }
    if !enabled() {
        // SAFETY: getppid is always safe.
        return unsafe { libc::getppid() } as u32;
    }
    let self_host = std::process::id();
    if self_ns_pid() == NS_INIT_PID {
        return 0;
    }
    if let Some(parent) = crate::guest_cpu::adopted_parent_for_self() {
        return region()
            .and_then(|r| r.host_to_ns(parent))
            .unwrap_or(NS_INIT_PID);
    }
    // Explicit orphan flag retained for compatibility with process-table
    // readers; the kernel graph is the authority for new logical tasks.
    if is_orphaned(self_host) {
        return NS_INIT_PID;
    }
    if let Some(parent) = ns_ppid_for_host(self_host) {
        return parent;
    }
    let host_ppid = unsafe { libc::getppid() } as u32;
    match region().and_then(|r| r.host_to_ns(host_ppid)) {
        // Parent is a live namespace member: report its ns-pid.
        Some(ns) => ns,
        // Parent is NOT a member of this namespace. Two cases collapse here and
        // both match Linux (pid_namespaces(7)): the macOS kernel reparented us
        // to launchd because our ns-parent died — so we are an orphan and
        // reparent to the ns-init (ns-pid 1). (A process whose parent is
        // genuinely outside the ns would read 0, but carrick's container tree
        // has no such case below the init: every member descends from pid 1,
        // so a non-member host ppid always means "parent died" → 1.) This makes
        // reparenting correct even before the carrier publishes the orphan flag.
        None => NS_INIT_PID,
    }
}

/// Namespace-visible parent pid for a registered host pid, derived from the
/// fork-time parent recorded in the shared namespace table. This is more stable
/// than `libc::getppid()` because Carrick guest processes are logical tasks in
/// one carrier and therefore do not have a corresponding host parent topology.
pub fn ns_ppid_for_host(host_pid: u32) -> Option<u32> {
    region()?.ns_ppid_for_host(host_pid)
}

/// Publish that the ns-init has installed (or cleared) a handler for `signum`.
/// Called from rt_sigaction when the caller is the ns-init (ns-pid 1). Lets the
/// kill path enforce pid-1 protection without cross-process handler-table
/// visibility (§5.4). No-op when ns is off or signum out of range.
pub fn set_init_handler(signum: i32, installed: bool) {
    let Some(r) = region() else { return };
    // Standard sigset_t convention (bit `signum-1`) via SigSet. This word
    // briefly used the raw bit=signum convention — the execve ignored-mask
    // off-by-one class the typed-domains semgrep gate now rejects. SigSet
    // also lifts the old 1..=63 cap (a shift-overflow guard, not semantics)
    // to the full 1..=64 signal range; out-of-range signums are a no-op.
    let bits = carrick_abi::SigSet::EMPTY.with(signum).raw();
    if bits == 0 {
        return;
    }
    r.set_init_handler_bits(bits, installed);
}

/// Whether the ns-init has a handler installed for `signum`.
pub fn init_handles(signum: i32) -> bool {
    match region() {
        Some(r) => carrick_abi::SigSet::from_raw(r.init_handler_bits()).contains(signum),
        _ => false,
    }
}

/// Whether `signum` is a signal pid-1 is protected from when UNHANDLED, i.e. a
/// default-lethal signal that is NOT the always-unblockable SIGKILL/SIGSTOP
/// (those always act on pid 1). Used by the kill path to apply pid-1 semantics
/// even on the non-namespaced OCI path where `region()` is absent but the guest
/// still presents itself AS the container init (bootstrap pid 1): a default-
/// lethal, unhandled signal pid-1 sends to ITSELF is dropped, matching Linux
/// (init never gets the default action for an unhandled signal). The caller
/// supplies the "is there a handler" check (the dispatcher's own handler table).
pub fn is_init_protected_default_signal(signum: i32) -> bool {
    if signum == 9 || signum == 19 {
        return false;
    }
    is_default_lethal(signum)
}

/// The signals whose default action terminates the process and which pid-1 is
/// protected from when unhandled (`pid_namespaces(7)`: pid 1 only gets signals
/// it has a handler for, plus the always-unblockable SIGKILL/SIGSTOP which are
/// NOT in this set). Linux signal numbers.
fn is_default_lethal(signum: i32) -> bool {
    // SIGHUP(1) SIGINT(2) SIGQUIT(3) SIGILL(4) SIGABRT(6) SIGFPE(8) SIGUSR1(10)
    // SIGSEGV(11) SIGUSR2(12) SIGPIPE(13) SIGALRM(14) SIGTERM(15) SIGBUS(7)
    // SIGTRAP(5) SIGSYS(31) SIGVTALRM(26) SIGPROF(27) SIGXCPU(24) SIGXFSZ(25)
    // SIGSTKFLT(16) SIGIO(29) SIGPWR(30). SIGCHLD/SIGURG/SIGWINCH/SIGCONT have a
    // non-lethal default (ignore/continue) and are not "lethal". SIGKILL(9) and
    // SIGSTOP(19) are handled by the caller (never dropped for pid 1).
    matches!(
        signum,
        1 | 2
            | 3
            | 4
            | 5
            | 6
            | 7
            | 8
            | 10
            | 11
            | 12
            | 13
            | 14
            | 15
            | 16
            | 24
            | 25
            | 26
            | 27
            | 29
            | 30
            | 31
    )
}

/// Whether a signal `signum` sent (by an in-ns member) to host pid `target`
/// must be DROPPED because `target` is the ns-init and the init has no handler
/// for a default-lethal signal (`pid_namespaces(7)`, §5.4). SIGKILL/SIGSTOP are
/// never dropped. Returns false when ns is off, the target isn't the init, or
/// the init handles the signal. The signal is dropped silently (the kill still
/// returns success — Linux behavior).
pub fn should_drop_signal_to_init(target_host_pid: u32, signum: i32) -> bool {
    let Some(r) = region() else { return false };
    if r.init_host_pid() != target_host_pid {
        return false;
    }
    // SIGKILL(9)/SIGSTOP(19) always act on pid 1 from within the ns (Linux
    // delivers these regardless of handler — they can't be caught/ignored).
    if signum == 9 || signum == 19 {
        return false;
    }
    // Only default-lethal signals are dropped; a non-lethal-default signal
    // (SIGCHLD etc.) is harmless to deliver. Drop iff lethal-default AND the
    // init installed no handler.
    is_default_lethal(signum) && !init_handles(signum)
}

/// Whether the namespace record marks `host_pid`'s parent as dead, so its
/// `getppid()` should report ns-pid 1 (the ns-init) per `pid_namespaces(7)`
/// reparent-to-init semantics (§3.6).
pub fn is_orphaned(host_pid: u32) -> bool {
    region()
        .and_then(|r| r.flags_of(host_pid))
        .map(|f| f & MEMBER_ORPHANED != 0)
        .unwrap_or(false)
}

/// Forget a namespace member after its terminal wait consumed the zombie.
///
/// A dead-but-unreaped child must stay in the table so `wait4(ns_pid)` can still
/// translate to the host pid. Once the wait succeeds, Linux removes the zombie
/// from the process table; Carrick can likewise free the fixed-size member slot
/// for later fork storms while keeping ns-pids monotonic and never recycled.
pub fn unregister_reaped(host_pid: u32) {
    if let Some(r) = region() {
        r.unregister_reaped(host_pid);
    }
}

/// Mark the member `context` names as having crossed an `execve(2)` point of
/// no return. Linux uses this to reject a parent changing the process group of
/// its child after the child has executed a new program. Exec commit runs
/// outside the dispatch scope, so the region comes from the exact task.
pub fn mark_self_execed_for(context: &crate::kernel::KernelContext) {
    let Some(r) = region_for(context) else { return };
    let Ok(internal) = u32::try_from(context.task().key().id.raw()) else {
        std::process::abort();
    };
    r.mark_execed(internal);
}

/// [`host_to_ns_or_self`] for a caller outside the dispatch scope that holds
/// the exact task (signal delivery in the vCPU loop).
/// Translate a host pid for `context`'s namespace, or `0` when it is not a
/// member.
///
/// The zero is deliberate and matches `pid_namespaces(7)`: a process whose
/// PARENT lives outside the namespace sees `getppid() == 0`. That is what
/// `self_ns_ppid` needs.
///
/// It is NOT what a process's OWN pid needs — `getpid()` never returns 0 on
/// Linux — so callers asking "what is my pid here?" must use
/// [`ns_self_pid_for`] instead. Reporting a missing translation as 0 through
/// this function was how a container's init came to report `getpid=0` while
/// synthetic `/proc/self/status` correctly said `Pid: 1`.
pub fn host_to_ns_or_self_for(context: &crate::kernel::KernelContext, host_pid: u32) -> u32 {
    match region_for(context) {
        Some(r) => r.host_to_ns(host_pid).unwrap_or(0),
        None => host_pid,
    }
}

/// Translate one carrier-global kernel identity through the exact caller's
/// container PID namespace. A missing member stays invisible rather than
/// falling back to a raw ID that may name another container's task.
pub(crate) fn kernel_to_ns_for(
    context: &crate::kernel::KernelContext,
    internal_id: u32,
) -> Option<u32> {
    match region_for(context) {
        Some(region) => region.host_to_ns(internal_id),
        None => Some(internal_id),
    }
}

pub(crate) fn ns_to_kernel_for(
    context: &crate::kernel::KernelContext,
    namespace_id: u32,
) -> Option<u32> {
    match region_for(context) {
        Some(region) => region.ns_to_host(namespace_id),
        None => Some(namespace_id),
    }
}

/// Resolve a guest process-group id through the caller's container-scoped
/// process-group records. Unlike PID membership, this authority remains live
/// after the group leader is reaped while another member survives.
pub(crate) fn ns_to_process_group_for(
    context: &crate::kernel::KernelContext,
    namespace_id: u32,
) -> Option<crate::kernel::ProcessGroupId> {
    context
        .kernel()
        .registry()
        .process_group_from_namespace(context.container().id(), namespace_id)
}

/// Render an internal process-group key in the caller's container namespace.
pub(crate) fn process_group_to_ns_for(
    context: &crate::kernel::KernelContext,
    group: crate::kernel::ProcessGroupId,
) -> Option<u32> {
    context
        .kernel()
        .registry()
        .process_group_to_namespace(context.container().id(), group)
}

/// Resolve a guest session id through the caller's container-scoped session
/// records. Kept typed even though current Linux SID-taking syscalls name a
/// process, so future surfaces cannot accidentally fall back to PID lifetime.
pub(crate) fn ns_to_session_for(
    context: &crate::kernel::KernelContext,
    namespace_id: u32,
) -> Option<crate::kernel::SessionId> {
    context
        .kernel()
        .registry()
        .session_from_namespace(context.container().id(), namespace_id)
}

/// Render an internal session key in the caller's container namespace.
pub(crate) fn session_to_ns_for(
    context: &crate::kernel::KernelContext,
    session: crate::kernel::SessionId,
) -> Option<u32> {
    context
        .kernel()
        .registry()
        .session_to_namespace(context.container().id(), session)
}

/// The pid `host_pid` sees for ITSELF in `context`'s namespace — never zero.
///
/// A miss means the task is not registered in the region, not that its
/// ns-local pid is 0. `getpid()` never returns 0 on Linux, and this value
/// reaches the guest both through the trapped handler and through the EL1
/// identity page's no-exit fast path, so a zero here is a pid no process can
/// have. When no namespace is installed, the internal id is already visible.
pub fn ns_self_pid_for(context: &crate::kernel::KernelContext, host_pid: u32) -> u32 {
    try_ns_self_pid_for(context, host_pid).unwrap_or_else(|| {
        tracing::error!(
            internal_id = host_pid,
            container = context.container().id().raw(),
            "live task is missing its namespace-local identity"
        );
        std::process::abort();
    })
}

pub(crate) fn try_ns_self_pid_for(
    context: &crate::kernel::KernelContext,
    host_pid: u32,
) -> Option<u32> {
    if let Some(pid) = context.provisional_namespace_pid_for(host_pid) {
        return Some(pid);
    }
    match region_for(context) {
        Some(r) => r.host_to_ns(host_pid),
        None => Some(host_pid),
    }
}

/// Whether `target_ns_pid` names a direct child of the current process that has
/// successfully execed. Identity mode has no namespace table, so this predicate
/// is only authoritative for namespace-enabled container runs.
pub fn is_execed_child_of_current(target_ns_pid: u32) -> bool {
    let Some(r) = region() else { return false };
    let Some(target_host_pid) = r.ns_to_host(target_ns_pid) else {
        return false;
    };
    r.is_execed_child_of(target_host_pid, std::process::id())
}

impl NsSharedRegion {
    /// The init's host pid (ns-pid 1), or 0 if unset.
    pub fn init_host_pid(&self) -> u32 {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !self.claim_is_live() {
            return 0;
        }
        self.init_host_pid_locked()
    }

    fn init_host_pid_locked(&self) -> u32 {
        self.ns.init_host_pid.load(Ordering::Acquire)
    }

    fn init_host_pgid(&self) -> u32 {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.claim_is_live() {
            self.ns.init_host_pgid.load(Ordering::Acquire)
        } else {
            0
        }
    }

    fn init_host_sid(&self) -> u32 {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.claim_is_live() {
            self.ns.init_host_sid.load(Ordering::Acquire)
        } else {
            0
        }
    }

    fn set_init_host_pgid(&self, pgid: u32) {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.claim_is_live() {
            self.ns.init_host_pgid.store(pgid, Ordering::Release);
        }
    }

    fn set_init_handler_bits(&self, bits: u64, installed: bool) {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !self.claim_is_live() {
            return;
        }
        if installed {
            self.ns.init_sig_handlers.fetch_or(bits, Ordering::Release);
        } else {
            self.ns
                .init_sig_handlers
                .fetch_and(!bits, Ordering::Release);
        }
    }

    fn init_handler_bits(&self) -> u64 {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.claim_is_live() {
            self.ns.init_sig_handlers.load(Ordering::Acquire)
        } else {
            0
        }
    }

    /// Claim or reuse a process record for a namespace member. Returns the
    /// record index, or `None` if the process section is full.
    pub fn register(&self, host_pid: u32, ns_pid: u32, parent_host_pid: u32) -> Option<usize> {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !self.claim_is_live() {
            return None;
        }
        self.register_locked(host_pid, ns_pid, parent_host_pid)
    }

    fn register_locked(&self, host_pid: u32, ns_pid: u32, parent_host_pid: u32) -> Option<usize> {
        let transition_deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            if let Some(i) = self.slot_of_locked(host_pid) {
                return Some(i);
            }
            // A task belongs to exactly one PID namespace: a host pid that is
            // already a member elsewhere is refused, not waited for.
            if self.is_member_elsewhere(host_pid) {
                return None;
            }
            if let Some((i, record)) = self.reusable_record_for(host_pid) {
                fill_member(record, self.ns_id(), ns_pid, parent_host_pid);
                return Some(i);
            }
            // A matching record whose transition is owned by registration or
            // retirement is not a free-slot verdict. Retry until it either
            // publishes namespace identity or unpublishes its host key; falling
            // through here would create a duplicate member for one host pid.
            if !self.has_process_record_for(host_pid) {
                break;
            }
            if std::time::Instant::now() >= transition_deadline {
                return None;
            }
            std::thread::yield_now();
        }
        let generation = self.arena.allocate_generation();
        let ns_id = self.ns_id();
        let claimed = self
            .section
            .claim(Some(HostPid::new(host_pid)), generation, |record| {
                fill_member(record, ns_id, ns_pid, parent_host_pid);
            })
            .ok()?;
        Some(claimed.index)
    }

    /// Translate a host pid to its ns-pid in this namespace, or `None` if the
    /// host pid is not a member (caller decides the fallback — e.g. 0 for a
    /// parent outside the ns).
    pub fn host_to_ns(&self, host_pid: u32) -> Option<u32> {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !self.claim_is_live() {
            return None;
        }
        if host_pid == 0 || host_pid == HOST_PID_REGISTERING {
            return None;
        }
        for record in self.member_records() {
            if record.host_pid.load(Ordering::Acquire) == host_pid {
                return Some(record.ns_pid.load(Ordering::Acquire));
            }
        }
        None
    }

    /// Translate an ns-pid to its host pid, or `None` if the ns-pid names no
    /// member (caller maps to `ESRCH`).
    pub fn ns_to_host(&self, ns_pid: u32) -> Option<u32> {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !self.claim_is_live() {
            return None;
        }
        for record in self.member_records() {
            if record.ns_pid.load(Ordering::Acquire) == ns_pid {
                return Some(record.host_pid.load(Ordering::Acquire));
            }
        }
        None
    }

    /// Find the slot index for a host pid, if registered.
    pub fn slot_of(&self, host_pid: u32) -> Option<usize> {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.slot_of_locked(host_pid)
    }

    fn slot_of_locked(&self, host_pid: u32) -> Option<usize> {
        if !self.claim_is_live() {
            return None;
        }
        if host_pid == 0 || host_pid == HOST_PID_REGISTERING {
            return None;
        }
        let ns_id = self.ns_id();
        self.section.records.iter().position(|s| {
            let ns_pid = s.ns_pid.load(Ordering::Acquire);
            s.host_pid.load(Ordering::Acquire) == host_pid
                && ns_pid != 0
                && ns_pid != NS_PID_REGISTERING
                && s.pid_ns.load(Ordering::Acquire) == ns_id
        })
    }

    /// Whether `host_pid` is a published member of a DIFFERENT namespace.
    fn is_member_elsewhere(&self, host_pid: u32) -> bool {
        let ns_id = self.ns_id();
        self.section.records.iter().any(|s| {
            let ns_pid = s.ns_pid.load(Ordering::Acquire);
            let tag = s.pid_ns.load(Ordering::Acquire);
            s.host_pid.load(Ordering::Acquire) == host_pid
                && ns_pid != 0
                && ns_pid != NS_PID_REGISTERING
                && tag != 0
                && tag != ns_id
        })
    }

    /// The member's flags, or `None` if not registered.
    pub fn flags_of(&self, host_pid: u32) -> Option<u32> {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.slot_of_locked(host_pid)
            .map(|i| self.section.records[i].flags.load(Ordering::Acquire))
    }

    /// The host pid recorded as this member's namespace parent at fork time.
    pub fn parent_host_pid_of(&self, host_pid: u32) -> Option<u32> {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.slot_of_locked(host_pid).map(|i| {
            self.section.records[i]
                .parent_host_pid
                .load(Ordering::Acquire)
        })
    }

    /// Whether the member has successfully executed a new image since fork.
    pub fn execed_of(&self, host_pid: u32) -> Option<bool> {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.slot_of_locked(host_pid).map(|i| {
            self.section.records[i]
                .exec_generation
                .load(Ordering::Acquire)
                != 0
        })
    }

    /// Mark a registered member as having crossed an exec point of no return.
    pub fn mark_execed(&self, host_pid: u32) {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(i) = self.slot_of_locked(host_pid) {
            let record = &self.section.records[i];
            let _ = record.exec_generation.fetch_add(1, Ordering::AcqRel);
        }
    }

    /// Whether `host_pid` is a direct child of `parent_host_pid` and has
    /// successfully executed a new image.
    pub fn is_execed_child_of(&self, host_pid: u32, parent_host_pid: u32) -> bool {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(i) = self.slot_of_locked(host_pid) else {
            return false;
        };
        self.section.records[i]
            .parent_host_pid
            .load(Ordering::Acquire)
            == parent_host_pid
            && self.section.records[i]
                .exec_generation
                .load(Ordering::Acquire)
                != 0
    }

    /// Translate a member's recorded parent to the pid its namespace sees.
    pub fn ns_ppid_for_host(&self, host_pid: u32) -> Option<u32> {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !self.claim_is_live() {
            return None;
        }
        let i = self.slot_of_locked(host_pid)?;
        let ns_pid = self.section.records[i].ns_pid.load(Ordering::Acquire);
        if ns_pid == NS_INIT_PID {
            return Some(0);
        }
        if self.section.records[i].flags.load(Ordering::Acquire) & MEMBER_ORPHANED != 0 {
            return Some(NS_INIT_PID);
        }
        let parent = self.section.records[i]
            .parent_host_pid
            .load(Ordering::Acquire);
        if parent == 0 {
            return Some(0);
        }
        Some(
            self.slot_of_locked(parent)
                .map(|parent_i| {
                    self.section.records[parent_i]
                        .ns_pid
                        .load(Ordering::Acquire)
                })
                .unwrap_or(NS_INIT_PID),
        )
    }

    /// Mark every live member whose ns-parent is `dead_host_pid` as orphaned
    /// (design §3.6 step 3).
    pub fn mark_children_orphaned(&self, dead_host_pid: u32) {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !self.claim_is_live() {
            return;
        }
        for slot in self.member_records() {
            let host_pid = slot.host_pid.load(Ordering::Acquire);
            if host_pid != 0
                && host_pid != HOST_PID_REGISTERING
                && slot.parent_host_pid.load(Ordering::Acquire) == dead_host_pid
                && slot.flags.load(Ordering::Acquire) & MEMBER_DEAD == 0
            {
                slot.flags.fetch_or(MEMBER_ORPHANED, Ordering::AcqRel);
            }
        }
    }

    /// Record a member's death and its exit status (design §3.4).
    pub fn mark_dead(&self, host_pid: u32, exit_status: i32) {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(i) = self.slot_of_locked(host_pid) {
            self.section.records[i]
                .exit_status
                .store(exit_status as u32 as u64, Ordering::Relaxed);
            self.section.records[i]
                .flags
                .fetch_or(MEMBER_DEAD, Ordering::AcqRel);
        }
    }

    /// Release namespace membership for `host_pid` after the guest has reaped
    /// it. The process section is generation-checked, so a stale release cannot
    /// clear a reused record.
    pub fn unregister_reaped(&self, host_pid: u32) -> bool {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !self.claim_is_live() {
            return false;
        }
        self.unregister_reaped_locked(host_pid)
    }

    fn unregister_reaped_locked(&self, host_pid: u32) -> bool {
        let Some(i) = self.slot_of_locked(host_pid) else {
            return false;
        };
        let record = &self.section.records[i];
        let generation = record.generation.load(Ordering::Acquire);
        if generation != 0 {
            return self.unregister_reaped_ref(
                host_pid,
                ProcessRecordRef {
                    index: i,
                    generation: ProcessGeneration::new(generation),
                },
            );
        }
        if record.try_claim_transition() {
            let ns_pid = record.ns_pid.load(Ordering::Acquire);
            let still_member = record.host_pid.load(Ordering::Acquire) == host_pid
                && ns_pid != 0
                && ns_pid != NS_PID_REGISTERING;
            if still_member {
                record.ns_pid.store(0, Ordering::Release);
                record.pid_ns.store(0, Ordering::Release);
                record.exec_generation.store(0, Ordering::Release);
                record.flags.fetch_and(!MEMBER_DEAD, Ordering::AcqRel);
                record.flags.fetch_and(!MEMBER_ORPHANED, Ordering::AcqRel);
                record.exit_status.store(0, Ordering::Relaxed);
            }
            record.release_transition();
            return still_member;
        }
        false
    }

    fn unregister_reaped_ref(&self, host_pid: u32, record_ref: ProcessRecordRef) -> bool {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            match self
                .section
                .with_record_transition(record_ref, HostPid::new(host_pid), |_| {
                    ((), ProcessRecordTransitionAction::Retire)
                }) {
                Ok(_) | Err(ProcessRecordTransitionError::Stale) => return true,
                Err(ProcessRecordTransitionError::Busy) if std::time::Instant::now() < deadline => {
                    std::thread::yield_now();
                }
                Err(ProcessRecordTransitionError::Busy) => return false,
            }
        }
    }

    /// Release records whose owner host pid is FULLY gone (no live process and
    /// no zombie — `is_gone` is a `kill(pid, 0) == ESRCH`
    /// re-check, the same liveness discipline as the vCPU-permit reaper's
    /// backstop) and whose exit no live guest waiter can still consume.
    ///
    /// This is the legacy host-process leak backstop for fork children that are
    /// never waited on (SIGCHLD set to SIG_IGN, or the parent exited without a
    /// subreaper reap): their terminal reap never runs `unregister_reaped`, so
    /// only a liveness sweep can return those records to the section before it
    /// exhausts. Records that still carry a consumable exit — a published
    /// adopted exit status (`exit_ready`), or a harvested §3.4 status on a
    /// dead ns member — are kept while their waiter (the recorded parent, or
    /// the ns-init for an orphan) is alive.
    ///
    /// A zombie still answers `kill(pid, 0)` with success, so a dead-but-
    /// unreaped child whose live parent can still `wait4` it is naturally
    /// kept until that terminal reap (or the parent's own death) happens.
    /// Returns the number of records released.
    pub fn sweep_dead_owner_records(&self, is_gone: &dyn Fn(u32) -> bool) -> usize {
        let _guard = self
            .lifecycle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !self.claim_is_live() {
            return 0;
        }
        let init = self.init_host_pid_locked();
        let mut released = 0;
        for (index, record) in self.section.records.iter().enumerate() {
            let host_pid = record.host_pid.load(Ordering::Acquire);
            if host_pid == 0 || host_pid == HOST_PID_REGISTERING || host_pid == init {
                continue;
            }
            let ns_pid = record.ns_pid.load(Ordering::Acquire);
            if ns_pid == NS_PID_REGISTERING || record.transition_claimed() {
                continue;
            }
            // Another namespace's member is that namespace's to reclaim.
            if ns_pid != 0 && record.pid_ns.load(Ordering::Acquire) != self.ns_id() {
                continue;
            }
            // Run-state TID entries carry thread ids, not process pids; the
            // liveness predicate is meaningless for them and they are owned
            // by the run-state table.
            if record.run_state.load(Ordering::Acquire) & RUN_STATE_KIND_TID != 0 {
                continue;
            }
            // ...and under HVPatch the same is true of PROCESS entries. A Linux
            // process is a task in the carrier with no host process of its own,
            // so `host_pid` here is a GUEST pid: `kill(pid, 0)` names an
            // unrelated host process or none at all, answers ESRCH, and this
            // sweep then released the record of a LIVE guest process. That is
            // how a parked guest came to read `R` forever in
            // `/proc/<pid>/stat` — its published `Blocked` was swept moments
            // after it landed, so the renderer fell back to the host/ns
            // derivation (989 diverging rows on `ltp-futex_cmp_requeue01`
            // alone, since LTP's `TST_PROCESS_STATE_WAIT` polls that character
            // with no timeout).
            //
            // These records are released at guest task exit instead
            // (`run_state::clear_guest_process`), which is the only authority
            // that knows a carrier task is finished.
            //
            // Skipping such a record OUTRIGHT was the first attempt and was
            // wrong in the other direction: this sweep is also the namespace
            // subsystem's reclamation path, and `run_state::claim_record`
            // stamps the owner flag onto ADOPTED member records, so dead
            // members would stop being reclaimed altogether.
            //
            // A guest-task record needs a different liveness AUTHORITY, not a
            // different verdict, and the guest's own lifecycle maintains one:
            // `run_state::clear_guest_process` zeroes the run-state word when
            // the task leader exits. A live word means alive; a cleared word
            // means gone and the record is reclaimable exactly as before.
            let owner_is_guest_task = record.flags.load(Ordering::Acquire)
                & carrick_kernel::process::FLAG_OWNER_GUEST_TASK
                != 0;
            if owner_is_guest_task && record.run_state.load(Ordering::Acquire) != 0 {
                continue;
            }
            let generation = record.generation.load(Ordering::Acquire);
            if generation == 0 {
                continue;
            }
            if !is_gone(host_pid) || Self::awaiting_guest_reap(record, is_gone, init) {
                continue;
            }
            // Generation-checked release: a concurrent reuse of this slot
            // (new generation) makes the release a no-op.
            let record_ref = ProcessRecordRef {
                index,
                generation: ProcessGeneration::new(generation),
            };
            let did_release = if ns_pid == 0 {
                self.section
                    .release_if_namespace_unowned(record_ref, HostPid::new(host_pid))
            } else {
                self.section.release(record_ref)
            };
            released += usize::from(did_release);
        }
        released
    }

    /// Whether a gone owner's record still carries an exit some LIVE guest
    /// process can consume through `wait4` (see `sweep_dead_owner_records`).
    fn awaiting_guest_reap(
        record: &ProcessRecord,
        is_gone: &dyn Fn(u32) -> bool,
        init_host_pid: u32,
    ) -> bool {
        let flags = record.flags.load(Ordering::Acquire);
        let consumable = record.exit_ready.load(Ordering::Acquire) != 0
            || (record.ns_pid.load(Ordering::Acquire) != 0 && flags & MEMBER_DEAD != 0);
        if !consumable {
            return false;
        }
        let waiter = if flags & MEMBER_ORPHANED != 0 {
            init_host_pid
        } else {
            record.parent_host_pid.load(Ordering::Acquire)
        };
        waiter != 0 && !is_gone(waiter)
    }

    fn member_records(&self) -> impl Iterator<Item = &ProcessRecord> {
        let ns_id = self.ns_id();
        self.section.records.iter().filter(move |record| {
            let host_pid = record.host_pid.load(Ordering::Acquire);
            let ns_pid = record.ns_pid.load(Ordering::Acquire);
            host_pid != 0
                && host_pid != HOST_PID_REGISTERING
                && ns_pid != 0
                && ns_pid != NS_PID_REGISTERING
                && record.pid_ns.load(Ordering::Acquire) == ns_id
        })
    }

    fn reusable_record_for(&self, host_pid: u32) -> Option<(usize, &ProcessRecord)> {
        if host_pid == 0 || host_pid == HOST_PID_REGISTERING {
            return None;
        }
        self.section
            .records
            .iter()
            .enumerate()
            .find_map(|(index, record)| {
                if record.host_pid.load(Ordering::Acquire) != host_pid
                    || record.generation.load(Ordering::Acquire) == 0
                    || record.run_state.load(Ordering::Acquire) & RUN_STATE_KIND_TID != 0
                    || !record.try_claim_transition()
                {
                    return None;
                }
                let still_reusable = record.host_pid.load(Ordering::Acquire) == host_pid
                    && record.generation.load(Ordering::Acquire) != 0
                    && record.ns_pid.load(Ordering::Acquire) == 0
                    && record.run_state.load(Ordering::Acquire) & RUN_STATE_KIND_TID == 0;
                if still_reusable {
                    record.ns_pid.store(NS_PID_REGISTERING, Ordering::Release);
                    Some((index, record))
                } else {
                    record.release_transition();
                    None
                }
            })
    }

    fn has_process_record_for(&self, host_pid: u32) -> bool {
        self.section.records.iter().any(|record| {
            record.host_pid.load(Ordering::Acquire) == host_pid
                && record.generation.load(Ordering::Acquire) != 0
                && record.run_state.load(Ordering::Acquire) & RUN_STATE_KIND_TID == 0
        })
    }
}

fn fill_member(record: &ProcessRecord, ns_id: NsId, ns_pid: u32, parent_host_pid: u32) {
    record
        .parent_host_pid
        .store(parent_host_pid, Ordering::Relaxed);
    record.pid_ns.store(ns_id, Ordering::Relaxed);
    record.exec_generation.store(0, Ordering::Relaxed);
    record.exit_status.store(0, Ordering::Relaxed);
    // Namespace registration may attach to the process record prepared before
    // fork. Preserve its generation-scoped ptrace control and stop sequence;
    // resetting either would invalidate a live stop or let an old token regain
    // authority. Claiming a genuinely new process record resets those fields.
    // The remaining wait state is namespace-owned and must start clean.
    record.exit_ready.store(0, Ordering::Relaxed);
    record.guest_ns.store(0, Ordering::Relaxed);
    record.subreaper_pid.store(0, Ordering::Relaxed);
    record
        .flags
        .fetch_and(!carrick_kernel::process::FLAG_ADOPTED, Ordering::AcqRel);
    record.flags.fetch_or(MEMBER_ALIVE, Ordering::AcqRel);
    record.flags.fetch_and(!MEMBER_ORPHANED, Ordering::AcqRel);
    record.flags.fetch_and(!MEMBER_DEAD, Ordering::AcqRel);
    // Publish namespace identity last. For a reused run-state record the
    // sentinel is the ownership claim that excludes concurrent retirement;
    // for a new record host_pid itself remains unpublished until this closure
    // returns. Either way readers cannot observe partially initialized member
    // metadata.
    record.ns_pid.store(ns_pid, Ordering::Release);
    record.release_transition();
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
    fn fill_member_preserves_generation_scoped_ptrace_state() {
        // Attaching namespace identity to a pre-fork process record must clear
        // namespace wait bookkeeping without invalidating a ptrace stop that
        // already belongs to this exact record generation.
        let region = test_region();
        let section = region.section;
        let pid = 0x51F1_0001u32;
        let generation = ProcessGeneration::new(41);
        let r = match section.claim(Some(HostPid::new(pid)), generation, |record| {
            record.subreaper_pid.store(999, Ordering::Relaxed);
            record
                .ptrace_stop_signal
                .store((996u64 << 32) | 19, Ordering::Relaxed);
            record.ptrace_control.store(
                VirtualPtraceControl::traced(998, generation, VirtualPtraceState::StopReported)
                    .expect("valid traced control")
                    .raw(),
                Ordering::Relaxed,
            );
            record.exit_ready.store(1, Ordering::Relaxed);
            record.guest_ns.store(123_456, Ordering::Relaxed);
            record
                .flags
                .store(carrick_kernel::process::FLAG_ADOPTED, Ordering::Relaxed);
        }) {
            Ok(r) => r,
            Err(err) => unreachable!("claim: {err:?}"),
        };
        let record = &section.records[r.index];

        fill_member(record, region.ns_id(), 42, 998);

        assert_eq!(record.exit_ready.load(Ordering::Acquire), 0);
        assert_eq!(record.guest_ns.load(Ordering::Acquire), 0);
        assert_eq!(record.subreaper_pid.load(Ordering::Acquire), 0);
        assert_eq!(record.parent_host_pid.load(Ordering::Acquire), 998);
        assert_eq!(
            record.ptrace_stop_signal.load(Ordering::Acquire),
            (996u64 << 32) | 19
        );
        assert_eq!(
            record.ptrace_control.load(Ordering::Acquire),
            VirtualPtraceControl::traced(998, generation, VirtualPtraceState::StopReported)
                .expect("valid traced control")
                .raw()
        );
        assert_eq!(
            record.flags.load(Ordering::Acquire) & carrick_kernel::process::FLAG_ADOPTED,
            0,
            "stale ADOPTED flag must not survive member reuse"
        );
        section.release(r);
    }

    #[test]
    fn reusable_record_claim_has_single_winner() {
        let region = test_region();
        let section = region.section;
        let pid = 0x51F1_0002u32;
        let generation = ProcessGeneration::new(42);
        let claimed = section
            .claim(Some(HostPid::new(pid)), generation, |_| {})
            .expect("claim reusable process record");

        let (_, record) = region
            .reusable_record_for(pid)
            .expect("first namespace adoption must claim the reusable record");
        assert_eq!(
            record.ns_pid.load(Ordering::Acquire),
            REGISTERING,
            "the winning adopter must exclude a concurrent adopter or retirement"
        );
        assert!(
            region.reusable_record_for(pid).is_none(),
            "only one transition may own a reusable process record"
        );

        record.ns_pid.store(0, Ordering::Release);
        record.release_transition();
        section.release(claimed);
    }

    #[test]
    fn public_register_waits_for_in_progress_adoption_instead_of_duplicating() {
        let region = test_region();
        let section = region.section;
        let pid = 0x51F1_0003u32;
        let generation = ProcessGeneration::new(43);
        let claimed = section
            .claim(Some(HostPid::new(pid)), generation, |_| {})
            .expect("claim reusable process record");
        let record = &section.records[claimed.index];
        assert!(record.try_claim_transition());
        record.ns_pid.store(NS_PID_REGISTERING, Ordering::Release);

        let (tx, rx) = std::sync::mpsc::channel();
        let registrar = Arc::clone(&region);
        let join = std::thread::spawn(move || {
            tx.send(registrar.register(pid, 43, 998)).unwrap();
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(25))
                .is_err(),
            "a losing registrar must wait, not publish a duplicate record"
        );

        // Publication now carries the namespace tag: `slot_of` only sees a
        // record tagged with this region's id, so an untagged publish would
        // leave the waiting registrar spinning to its deadline.
        record.pid_ns.store(region.ns_id(), Ordering::Relaxed);
        record.ns_pid.store(42, Ordering::Release);
        record.release_transition();
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(1))
                .expect("waiting registrar completes after publication"),
            Some(claimed.index)
        );
        join.join().unwrap();
        assert_eq!(
            section
                .records
                .iter()
                .filter(|candidate| {
                    candidate.host_pid.load(Ordering::Acquire) == pid
                        && candidate.ns_pid.load(Ordering::Acquire) != 0
                })
                .count(),
            1
        );
        section.release(claimed);
    }

    #[test]
    fn sweep_preserves_record_owned_by_namespace_transition() {
        let region = test_region();
        let section = region.section;
        let pid = 0x51F1_0004u32;
        let generation = ProcessGeneration::new(44);
        let claimed = section
            .claim(Some(HostPid::new(pid)), generation, |record| {
                record.flags.fetch_or(
                    carrick_kernel::process::FLAG_OWNER_GUEST_TASK,
                    Ordering::Relaxed,
                );
            })
            .expect("claim process record for transition sweep test");
        let record = &section.records[claimed.index];
        assert!(record.try_claim_transition());
        record.ns_pid.store(NS_PID_REGISTERING, Ordering::Release);

        assert_eq!(region.sweep_dead_owner_records(&|_| true), 0);
        assert_eq!(record.host_pid.load(Ordering::Acquire), pid);
        assert_eq!(record.generation.load(Ordering::Acquire), generation.raw());

        record.ns_pid.store(42, Ordering::Release);
        record.release_transition();
        section.release(claimed);
    }

    #[test]
    fn unregister_reaped_waits_for_member_publication_transition() {
        let region = test_region();
        let section = region.section;
        let pid = 0x51F1_0005u32;
        let generation = ProcessGeneration::new(45);
        let ns_id = region.ns_id();
        let claimed = section
            .claim(Some(HostPid::new(pid)), generation, |record| {
                record.pid_ns.store(ns_id, Ordering::Relaxed);
                record.ns_pid.store(42, Ordering::Release);
                record.flags.fetch_or(MEMBER_DEAD, Ordering::Relaxed);
            })
            .expect("claim reaped namespace member");
        let record = &section.records[claimed.index];
        assert!(record.try_claim_transition());

        let (tx, rx) = std::sync::mpsc::channel();
        let reaper = Arc::clone(&region);
        let join = std::thread::spawn(move || {
            tx.send(reaper.unregister_reaped(pid)).unwrap();
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(25))
                .is_err(),
            "reap must not report success while member publication owns the record"
        );

        record.release_transition();
        assert!(
            rx.recv_timeout(std::time::Duration::from_secs(1))
                .expect("reap completes after publication unlock")
        );
        join.join().unwrap();
        assert!(section.find(HostPid::new(pid)).is_none());
    }

    #[test]
    fn unregister_stale_ref_cannot_release_same_numeric_pid_reuse() {
        let region = test_region();
        let section = region.section;
        let pid = 0x51F1_0006u32;
        let old = section
            .claim(
                Some(HostPid::new(pid)),
                ProcessGeneration::new(46),
                |record| record.ns_pid.store(42, Ordering::Release),
            )
            .expect("claim old namespace member");
        assert!(section.release(old));
        let new = section
            .claim(
                Some(HostPid::new(pid)),
                ProcessGeneration::new(47),
                |record| record.ns_pid.store(43, Ordering::Release),
            )
            .expect("claim same-numeric-pid replacement member");

        assert!(region.unregister_reaped_ref(pid, old));
        let replacement = &section.records[new.index];
        assert_eq!(replacement.generation.load(Ordering::Acquire), 47);
        assert_eq!(replacement.host_pid.load(Ordering::Acquire), pid);
        assert_eq!(replacement.ns_pid.load(Ordering::Acquire), 43);
        assert!(section.release(new));
    }

    fn test_arena() -> &'static KernelArena {
        Box::leak(Box::new(KernelArena::create().expect("create test arena")))
    }

    fn test_region() -> Arc<NsSharedRegion> {
        NsSharedRegion::allocate(test_arena()).expect("claim test namespace")
    }

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
        let region = test_region();
        region.ns.init_host_pid.store(100, Ordering::Relaxed);
        // pre-register init as ns-pid 1
        assert_eq!(region.register(100, NS_INIT_PID, 0), Some(0));

        // a forked child host pid 200, ns-parent 100
        assert!(region.register(200, 2, 100).is_some());

        assert_eq!(region.host_to_ns(100), Some(1));
        assert_eq!(region.host_to_ns(200), Some(2));
        assert_eq!(region.host_to_ns(999), None);
        assert_eq!(region.ns_to_host(1), Some(100));
        assert_eq!(region.ns_to_host(2), Some(200));
        assert_eq!(region.ns_to_host(42), None);
        assert_eq!(region.parent_host_pid_of(200), Some(100));
        assert_eq!(region.ns_ppid_for_host(100), Some(0));
        assert_eq!(region.ns_ppid_for_host(200), Some(1));
        assert_eq!(region.ns_ppid_for_host(999), None);
        assert_eq!(region.execed_of(200), Some(false));
        assert!(!region.is_execed_child_of(200, 100));
        region.mark_execed(200);
        assert_eq!(region.execed_of(200), Some(true));
        assert!(region.is_execed_child_of(200, 100));
        assert!(!region.is_execed_child_of(200, 999));

        // orphan the child by killing its parent (100)
        region.mark_children_orphaned(100);
        assert_ne!(region.flags_of(200).unwrap_or(0) & MEMBER_ORPHANED, 0);
        assert_eq!(region.ns_ppid_for_host(200), Some(1));

        // mark the child dead
        region.mark_dead(200, 0);
        assert_ne!(region.flags_of(200).unwrap_or(0) & MEMBER_DEAD, 0);
    }

    #[test]
    fn in_progress_registration_slot_is_not_visible() {
        let region = test_region();
        let slot = &region.section.records[0];
        assert!(
            slot.host_pid
                .compare_exchange(0, HOST_PID_REGISTERING, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        );
        slot.pid_ns.store(region.ns_id(), Ordering::Relaxed);
        slot.ns_pid.store(2, Ordering::Relaxed);
        slot.parent_host_pid.store(100, Ordering::Relaxed);
        slot.flags.store(MEMBER_ALIVE, Ordering::Relaxed);

        assert_eq!(region.host_to_ns(200), None);
        assert_eq!(region.ns_to_host(2), None);
        assert_eq!(region.slot_of(HOST_PID_REGISTERING), None);

        slot.host_pid.store(200, Ordering::Release);
        assert_eq!(region.host_to_ns(200), Some(2));
        assert_eq!(region.ns_to_host(2), Some(200));
    }

    #[test]
    fn sweep_releases_records_of_gone_owners_with_no_live_waiter() {
        // The leak this closes: a fork child that is never waited on (parent
        // exited without a subreaper reap) keeps its record forever; 4096 of
        // them exhaust the section. Once the owner host pid is FULLY gone (no
        // process, no zombie — the launchd reap already happened) and no live
        // guest waiter can still consume its exit, the compatibility sweep must
        // release the record.
        let region = test_region();
        region.ns.init_host_pid.store(100, Ordering::Relaxed);
        assert_eq!(region.register(100, NS_INIT_PID, 0), Some(0));

        // A namespace member whose parent (300) is itself gone.
        assert!(region.register(300, 2, 100).is_some());
        assert!(region.register(301, 3, 300).is_some());
        // A plain child-table record (no ns membership).
        let generation = ProcessGeneration::new(77);
        region
            .section
            .claim(Some(HostPid::new(400)), generation, |record| {
                record.parent_host_pid.store(300, Ordering::Relaxed);
                record.flags.store(MEMBER_ALIVE, Ordering::Relaxed);
            })
            .expect("claim child-table record");

        let gone = |pid: u32| pid == 300 || pid == 301 || pid == 400;
        let released = region.sweep_dead_owner_records(&gone);

        assert_eq!(released, 3, "all three gone-owner records are released");
        assert_eq!(region.host_to_ns(300), None);
        assert_eq!(region.host_to_ns(301), None);
        assert!(region.section.find(HostPid::new(400)).is_none());
        // The live init is untouched.
        assert_eq!(region.host_to_ns(100), Some(NS_INIT_PID));
    }

    #[test]
    fn sweep_keeps_records_awaiting_a_live_guest_reap() {
        let region = test_region();
        region.ns.init_host_pid.store(100, Ordering::Relaxed);
        assert_eq!(region.register(100, NS_INIT_PID, 0), Some(0));

        // An adopted child published its exit status for a LIVE subreaper
        // (parent 100): the record is the subreaper's only way to wait4 it
        // after launchd took the host zombie — it must survive the sweep.
        assert!(region.register(500, 2, 100).is_some());
        let i = region.slot_of(500).expect("member slot");
        region.section.records[i]
            .exit_ready
            .store(1, Ordering::Release);

        // An orphaned, dead ns member with a harvested exit status (§3.4):
        // the live ns-init may still reap it.
        assert!(region.register(501, 3, 999).is_some());
        region.mark_children_orphaned(999);
        region.mark_dead(501, 7);

        let gone = |pid: u32| pid == 500 || pid == 501 || pid == 999;
        let released = region.sweep_dead_owner_records(&gone);

        assert_eq!(released, 0, "records awaiting a live guest reap are kept");
        assert_eq!(region.host_to_ns(500), Some(2));
        assert_eq!(region.host_to_ns(501), Some(3));

        // Once the waiters are gone too, both records are releasable.
        let all_gone = |pid: u32| pid != 0;
        let released = region.sweep_dead_owner_records(&all_gone);
        assert_eq!(released, 2, "gone waiters make the records releasable");
    }

    #[test]
    fn sweep_skips_live_owners_and_tid_entries() {
        let region = test_region();
        region.ns.init_host_pid.store(100, Ordering::Relaxed);
        assert_eq!(region.register(100, NS_INIT_PID, 0), Some(0));
        assert!(region.register(600, 2, 100).is_some());

        // A run-state TID entry can carry a thread id in host_pid; the
        // liveness predicate is meaningless for it and it is owned by the
        // run-state table, not the process sweep.
        let generation = ProcessGeneration::new(88);
        region
            .section
            .claim(Some(HostPid::new(601)), generation, |record| {
                record
                    .run_state
                    .store(RUN_STATE_KIND_TID, Ordering::Relaxed);
            })
            .expect("claim tid record");

        let gone = |pid: u32| pid == 601;
        let released = region.sweep_dead_owner_records(&gone);

        assert_eq!(released, 0, "live owners and TID entries are untouched");
        assert_eq!(region.host_to_ns(600), Some(2));
        assert!(region.section.find(HostPid::new(601)).is_some());
    }

    #[test]
    fn reaped_member_slot_can_be_reused_without_recycling_ns_pid() {
        let region = test_region();

        let first_ns = 2;
        assert_eq!(region.register(200, first_ns, 100), Some(0));
        region.mark_execed(200);
        assert_eq!(region.execed_of(200), Some(true));
        region.mark_dead(200, 0);
        assert_eq!(region.ns_to_host(first_ns), Some(200));

        assert!(region.unregister_reaped(200));
        assert_eq!(region.ns_to_host(first_ns), None);
        assert_eq!(region.host_to_ns(200), None);

        let second_ns = 3;
        assert_eq!(region.register(201, second_ns, 100), Some(0));
        assert_eq!(region.ns_to_host(second_ns), Some(201));
        assert_eq!(region.execed_of(201), Some(false));
        assert_eq!(region.ns_to_host(first_ns), None);
    }

    #[test]
    fn two_regions_in_one_arena_are_disjoint_and_pid_1_names_each_own_init() {
        let arena = test_arena();
        let a = NsSharedRegion::allocate(arena).expect("claim namespace a");
        let b = NsSharedRegion::allocate(arena).expect("claim namespace b");
        assert_ne!(a.ns_id(), b.ns_id());
        assert_ne!(a.claim.index, b.claim.index);

        a.set_init(4100);
        b.set_init(4200);
        assert_eq!(a.ns_to_host(NS_INIT_PID), Some(4100));
        assert_eq!(b.ns_to_host(NS_INIT_PID), Some(4200));
        assert_eq!(a.host_to_ns(4200), None, "b's init is not a member of a");
        assert_eq!(b.host_to_ns(4100), None, "a's init is not a member of b");

        let (a_child, b_child) = (2, 2);
        assert!(a.register(4101, a_child, 4100).is_some());
        assert_eq!(a.host_to_ns(4101), Some(2));
        assert_eq!(a.ns_ppid_for_host(4101), Some(NS_INIT_PID));
        assert_eq!(b.host_to_ns(4101), None, "a's child is invisible in b");
        assert_eq!(b.ns_to_host(2), None, "ns-pid 2 is unassigned in b");
        assert_eq!(
            b.register(4101, b_child, 4200),
            None,
            "a task belongs to exactly one pid namespace"
        );
    }

    #[test]
    fn dropping_a_region_releases_its_slot_and_members_for_reuse() {
        let arena = test_arena();
        let a = NsSharedRegion::allocate(arena).expect("claim namespace a");
        let b = NsSharedRegion::allocate(arena).expect("claim namespace b");
        let a_claim = a.claim;
        let a_ns_id = a.ns_id();
        let section = a.section;
        a.set_init(4100);
        assert!(a.register(4101, 2, 4100).is_some());
        assert_eq!(arena.layout().pid_namespaces.claimed(), 2);

        drop(a);

        assert!(
            arena.layout().pid_namespaces.slot(a_claim).is_none(),
            "drop released the namespace slot"
        );
        assert_eq!(arena.layout().pid_namespaces.claimed(), 1);
        assert!(
            section
                .records
                .iter()
                .all(|record| record.pid_ns.load(Ordering::Acquire) != a_ns_id),
            "no record still carries the dropped namespace's tag"
        );
        assert!(
            section.find(HostPid::new(4101)).is_none(),
            "untagged member record released"
        );

        let c = NsSharedRegion::allocate(arena).expect("claim namespace c");
        assert_eq!(c.claim.index, a_claim.index, "the released slot is reused");
        assert_ne!(c.claim.index, b.claim.index);
        assert_ne!(c.ns_id(), a_ns_id);
        assert_eq!(c.ns_to_host(NS_INIT_PID), None, "c starts with no init");
        assert_eq!(c.host_to_ns(4101), None, "a's members were retired on drop");
        assert_eq!(b.ns_to_host(NS_INIT_PID), None, "b was never touched");
    }

    #[test]
    fn explicit_retire_releases_once_and_drop_is_then_a_no_op() {
        let arena = test_arena();
        let a = NsSharedRegion::allocate(arena).expect("claim namespace a");
        let a_claim = a.claim;
        let a_ns_id = a.ns_id();
        let section = a.section;
        a.set_init(4100);
        assert!(a.register(4101, 2, 4100).is_some());
        // A second holder, as a live task's `Container` would be at teardown.
        let holder = Arc::clone(&a);

        assert!(a.retire(), "the first retire releases the slot");
        assert!(
            arena.layout().pid_namespaces.slot(a_claim).is_none(),
            "retire released the namespace slot while another Arc is still held"
        );
        assert!(
            section
                .records
                .iter()
                .all(|record| record.pid_ns.load(Ordering::Acquire) != a_ns_id),
            "retire retired the members"
        );
        assert!(
            !Arc::clone(&holder).retire(),
            "a second retire reports nothing to release"
        );

        let c = NsSharedRegion::allocate(arena).expect("claim namespace c");
        assert_eq!(c.claim.index, a_claim.index, "the retired slot is reused");
        drop(holder);
        assert!(
            arena.layout().pid_namespaces.slot(c.claim).is_some(),
            "dropping the last Arc of a retired region does not free c's slot"
        );
    }

    #[test]
    fn failed_slot_release_does_not_falsely_mark_the_region_released() {
        let arena = test_arena();
        let region = NsSharedRegion::allocate(arena).expect("claim namespace");
        assert!(arena.layout().pid_namespaces.release(region.claim));

        assert!(!Arc::clone(&region).retire());
        assert!(
            !region.released.load(Ordering::Acquire),
            "a failed arena release must remain retryable and visible as incomplete"
        );
    }

    #[test]
    fn stale_holder_cannot_read_or_mutate_a_reused_namespace_slot() {
        let arena = test_arena();
        let original = NsSharedRegion::allocate(arena).expect("claim original namespace");
        let stale = Arc::clone(&original);
        let reused_index = original.claim.index;
        assert!(original.set_kernel_init(4_100));
        assert!(original.retire());

        let successor = NsSharedRegion::allocate(arena).expect("reuse retired namespace slot");
        assert_eq!(successor.claim.index, reused_index);
        assert!(successor.set_kernel_init(4_200));

        assert_eq!(stale.init_host_pid(), 0, "stale read must fail closed");
        assert_eq!(stale.host_to_ns(4_200), None);
        assert_eq!(stale.ns_to_host(NS_INIT_PID), None);
        assert_eq!(stale.register(4_201, 2, 4_200), None);
        stale.mark_dead(4_200, 19);
        stale.mark_children_orphaned(4_200);
        stale.mark_execed(4_200);
        assert_eq!(successor.host_to_ns(4_200), Some(NS_INIT_PID));
        assert_eq!(successor.host_to_ns(4_201), None);
        assert_eq!(successor.flags_of(4_200), Some(MEMBER_ALIVE));
        assert_eq!(successor.execed_of(4_200), Some(false));
    }
}
