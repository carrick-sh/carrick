//! Thread identity pool and thread ledger — stage L1 of the EL1 born-in-zone
//! thread lifecycle (`docs/superpowers/plans/2026-09-30-el1-thread-lifecycle.md`).
//!
//! The kernel graph stays the only authority for thread identity. Identities
//! are issued ahead of use into a per-task [`ThreadIdentityPool`] (a reserved
//! Linux tid, its PID-namespace visible id and an `RLIMIT_NPROC` uid credit);
//! every clone — whichever lane serves it — claims one entry. Credentials,
//! signal mask, affinity and the `ClonePlan` are NOT part of an entry: they are
//! bound when the claimed entry is prepared for publication.
//!
//! [`ThreadLedger`] is the registry-side half. It owns
//!
//! - the births recorded before publication, which [`ThreadLedger::settle`]
//!   publishes through the same `publish_reserved` body the host clone uses —
//!   and `Registry::settled` runs `settle` before it hands out the task graph,
//!   so no membership reader can observe a thread group without them;
//! - the `RLIMIT_NPROC` credits of claimed-but-unpublished clones, so the
//!   limit is exact for threads: published threads, claimed entries and born
//!   entries all count, and unclaimed pool credits are revoked by CAS under
//!   pressure rather than refusing a clone that Linux admits.
//!
//! `CARRICK_THREAD_POOL=0` keeps no standing entries: a clone finds the pool
//! empty and reserves its one entry at clone time, through the same code.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use carrick_abi::NsUid;
use parking_lot::Mutex;

use super::core::{Kernel, KernelContext, RegistryState, TaskRecord};
use super::ids::LinuxTid;
use super::objects::{TaskRef, ThreadKey};
use super::operations::KernelOperationError;
use super::operations::thread::{PreparedThreadClone, PublicationLane};
use super::registry::{RegistryLock, ThreadReservation};
use crate::namespace::pid::PreparedNamespaceIdentity;

/// Standing entries per multi-threaded task when the pool is on. Four covers
/// the common libc/Go worker fan-out without reserving a visible gap in the
/// tid space for a single-threaded process: a pool is primed only after the
/// task's first thread clone.
pub const DEFAULT_THREAD_POOL_DEPTH: usize = 4;

/// `CARRICK_THREAD_POOL=0` (exactly) turns the standing reserve off.
fn pool_depth_from_env() -> usize {
    static DEPTH: OnceLock<usize> = OnceLock::new();
    *DEPTH.get_or_init(|| match std::env::var("CARRICK_THREAD_POOL") {
        Ok(value) if value == "0" => 0,
        _ => DEFAULT_THREAD_POOL_DEPTH,
    })
}

/// Lifecycle of one standing pool entry. `Born` and `Published` are carried
/// by the typed owners a claim moves into (`ThreadCloneReservation` →
/// `PreparedThreadClone` → a ledger birth → a registry thread claim), so the
/// atomic only arbitrates the one race the pool itself has: a claimer and a
/// revoker competing for an unclaimed entry.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryState {
    Reserved = 0,
    Claimed = 1,
    Revoked = 2,
}

/// The exact kernel-issued identity of a thread: a reserved tid and serial
/// that adoption must retain, plus the prepared visible id in a PID namespace.
#[derive(Debug)]
pub(crate) struct ThreadIdentity {
    pub(crate) key: ThreadKey,
    pub(crate) reservation: ThreadReservation,
    pub(crate) pid_identity: Option<PreparedNamespaceIdentity>,
}

impl ThreadIdentity {
    /// Reserve a fresh identity for a thread of `task`.
    fn reserve(kernel: &Kernel, task: &TaskRef) -> Result<Self, KernelOperationError> {
        let (tid, reservation) = kernel.ids().reserve_thread()?;
        let pid_identity = match task.pid_ns_region() {
            Some(region) => {
                let internal = u32::try_from(tid.raw())
                    .map_err(|_| KernelOperationError::PidNamespaceMembership(task.key().id))?;
                let parent_id = u32::try_from(task.key().id.raw())
                    .map_err(|_| KernelOperationError::PidNamespaceMembership(task.key().id))?;
                Some(
                    region
                        .reserve_identity(internal, parent_id)
                        .ok_or(KernelOperationError::PidNamespaceMembership(task.key().id))?,
                )
            }
            None => None,
        };
        Ok(Self {
            key: ThreadKey {
                tid,
                serial: kernel.object_ids().thread_serial()?,
            },
            reservation,
            pid_identity,
        })
    }
}

#[derive(Debug)]
struct PooledThreadIdentity {
    state: AtomicU8,
    /// The real uid this entry's `RLIMIT_NPROC` credit is charged to.
    credit: NsUid,
    identity: ThreadIdentity,
}

impl PooledThreadIdentity {
    fn transition(&self, from: EntryState, to: EntryState) -> bool {
        self.state
            .compare_exchange(from as u8, to as u8, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

/// One task's standing thread identities. It lives in the task's registry
/// record, so a task that leaves the live set drops its pool — and every
/// reserved tid in it — with the record; no exit path has to remember it.
#[derive(Debug, Default)]
pub(crate) struct ThreadIdentityPool {
    entries: Mutex<VecDeque<PooledThreadIdentity>>,
}

impl ThreadIdentityPool {
    /// Claim the oldest standing entry. FIFO keeps successive thread tids
    /// ascending exactly as a clone-time reservation would issue them.
    fn claim(&self) -> Option<ThreadIdentity> {
        let mut entries = self.entries.lock();
        while let Some(entry) = entries.pop_front() {
            if entry.transition(EntryState::Reserved, EntryState::Claimed) {
                return Some(entry.identity);
            }
            // Revoked: dropping it releases its tid.
        }
        None
    }

    fn len(&self) -> usize {
        self.entries.lock().len()
    }

    fn credits(&self, uid: Option<NsUid>) -> usize {
        self.entries
            .lock()
            .iter()
            .filter(|entry| {
                entry.state.load(Ordering::Acquire) == EntryState::Reserved as u8
                    && uid.is_none_or(|uid| entry.credit == uid)
            })
            .count()
    }

    /// Revoke every unclaimed credit charged to `uid`; returns how many.
    fn revoke(&self, uid: NsUid) -> usize {
        let mut entries = self.entries.lock();
        let revoked = entries
            .iter()
            .filter(|entry| {
                entry.credit == uid && entry.transition(EntryState::Reserved, EntryState::Revoked)
            })
            .count();
        entries.retain(|entry| entry.state.load(Ordering::Acquire) == EntryState::Reserved as u8);
        revoked
    }

    fn push(&self, credit: NsUid, identity: ThreadIdentity) {
        self.entries.lock().push_back(PooledThreadIdentity {
            state: AtomicU8::new(EntryState::Reserved as u8),
            credit,
            identity,
        });
    }

    /// Tids currently standing in this pool (diagnostics and tests).
    fn tids(&self) -> Vec<LinuxTid> {
        self.entries
            .lock()
            .iter()
            .map(|entry| entry.identity.key.tid)
            .collect()
    }
}

type InFlightCounts = Arc<Mutex<BTreeMap<NsUid, usize>>>;

/// One claimed-or-born clone's `RLIMIT_NPROC` charge. It is released when the
/// thread publishes (under the registry write lock, in the same critical
/// section that inserts the thread claim that takes over the count) or when
/// the clone fails and the owner drops.
#[derive(Debug)]
pub(crate) struct NprocCredit {
    uid: NsUid,
    counts: InFlightCounts,
}

impl Drop for NprocCredit {
    fn drop(&mut self) {
        let mut counts = self.counts.lock();
        if let Some(count) = counts.get_mut(&self.uid) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.uid);
            }
        }
    }
}

/// A pool entry a clone has claimed, with its `RLIMIT_NPROC` charge.
#[derive(Debug)]
pub(crate) struct ClaimedThreadIdentity {
    pub(crate) identity: ThreadIdentity,
    pub(crate) credit: NprocCredit,
}

/// Registry-side thread lifecycle ledger. See the module documentation.
#[derive(Debug)]
pub struct ThreadLedger {
    depth: AtomicUsize,
    /// Births recorded but not yet settled. Incremented under `births`,
    /// decremented only after the births are published, so a reader that
    /// loads zero knows every earlier birth is in the graph.
    pending: AtomicUsize,
    births: Mutex<Vec<PreparedThreadClone>>,
    /// Serializes settlement: a reader that sees `pending > 0` waits here for
    /// the settler that took the births to finish publishing them.
    settling: Mutex<()>,
    in_flight: InFlightCounts,
}

impl Default for ThreadLedger {
    fn default() -> Self {
        Self::new(pool_depth_from_env())
    }
}

impl ThreadLedger {
    pub(crate) fn new(depth: usize) -> Self {
        Self {
            depth: AtomicUsize::new(depth),
            pending: AtomicUsize::new(0),
            births: Mutex::new(Vec::new()),
            settling: Mutex::new(()),
            in_flight: Arc::default(),
        }
    }

    /// Standing entries a multi-threaded task keeps.
    pub fn pool_depth(&self) -> usize {
        self.depth.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn set_pool_depth_for_test(&self, depth: usize) {
        self.depth.store(depth, Ordering::Relaxed);
    }

    /// Births recorded and not yet settled.
    pub fn pending_births(&self) -> usize {
        self.pending.load(Ordering::Acquire)
    }

    /// Record a thread that exists before its publication. The next
    /// `Registry::settled` publishes it through `publish_reserved`.
    pub(in crate::kernel) fn record_birth(&self, prepared: PreparedThreadClone) {
        let mut births = self.births.lock();
        births.push(prepared);
        self.pending.fetch_add(1, Ordering::AcqRel);
    }

    /// Publish every recorded birth. With nothing pending this is one load.
    pub(super) fn settle(&self, lock: &RegistryLock) {
        if self.pending.load(Ordering::Acquire) == 0 {
            return;
        }
        let settling = self.settling.lock();
        let births = std::mem::take(&mut *self.births.lock());
        if births.is_empty() {
            return;
        }
        let count = births.len();
        let mut published = Vec::with_capacity(count);
        {
            let mut state = lock.write();
            for birth in births {
                // A birth whose task left the live set before settlement is
                // dropped, which cancels it; there is nothing to publish into.
                if let Ok(publication) = birth.publish_reserved(&mut state, PublicationLane::Settle)
                {
                    published.push(publication);
                }
            }
        }
        self.pending.fetch_sub(count, Ordering::AcqRel);
        drop(settling);
        // After-lock work runs with neither the registry lock nor the settle
        // gate held: reservation-change subscribers read the registry.
        // Dropping the published clone opens its start gate — a birth has
        // already happened, so publication has nothing left to wait for; the
        // lane that runs it adopts it from the registry by `ThreadKey`.
        for publication in published {
            drop(publication.finish());
        }
    }

    /// Claim an identity for a clone by `parent` and charge its
    /// `RLIMIT_NPROC` credit. The caller holds the registry read lock taken
    /// through a settled view and has validated `record` as the parent task.
    pub(in crate::kernel) fn claim(
        &self,
        kernel: &Kernel,
        state: &RegistryState,
        record: &TaskRecord,
        parent: &KernelContext,
    ) -> Result<ClaimedThreadIdentity, KernelOperationError> {
        // Take the entry before admission so its own unclaimed credit is not
        // counted against it.
        let claimed = record.thread_pool.claim();
        let credit = self.admit_thread(state, parent)?;
        let identity = match claimed {
            Some(identity) => identity,
            None => ThreadIdentity::reserve(kernel, &record.task)?,
        };
        Ok(ClaimedThreadIdentity { identity, credit })
    }

    /// Bring `task`'s pool back to depth after a publication. Each new entry
    /// carries a credit for `uid`; the pool stops filling rather than hold a
    /// credit the uid's limit cannot cover.
    pub(in crate::kernel) fn replenish(
        &self,
        kernel: &Kernel,
        state: &RegistryState,
        publisher: &KernelContext,
    ) {
        let depth = self.pool_depth();
        if depth == 0 {
            return;
        }
        let Some(record) = state.tasks.get(&publisher.task().key().id) else {
            return;
        };
        if record.task.key() != publisher.task().key()
            || !record.task.container().accepts_new_tasks()
        {
            return;
        }
        let uid = publisher.resources.credentials().ruid();
        let limit = nproc_limit(publisher);
        while record.thread_pool.len() < depth {
            if let Some(limit) = limit {
                let in_flight = self.in_flight.lock();
                if nproc_count(state, &in_flight, uid, limit).is_some_and(|count| count >= limit) {
                    return;
                }
            }
            let Ok(identity) = ThreadIdentity::reserve(kernel, &record.task) else {
                return;
            };
            record.thread_pool.push(uid, identity);
        }
    }

    /// `RLIMIT_NPROC` admission for one thread clone; see [`nproc_verdict`].
    fn admit_thread(
        &self,
        state: &RegistryState,
        caller: &KernelContext,
    ) -> Result<NprocCredit, KernelOperationError> {
        let uid = caller.resources.credentials().ruid();
        let mut in_flight = self.in_flight.lock();
        if let Some(limit) = nproc_limit(caller) {
            nproc_verdict(state, &in_flight, uid, limit)?;
        }
        *in_flight.entry(uid).or_default() += 1;
        drop(in_flight);
        Ok(NprocCredit {
            uid,
            counts: Arc::clone(&self.in_flight),
        })
    }

    /// `RLIMIT_NPROC` admission for a fork, which publishes under the
    /// registry write lock and so needs no in-flight credit of its own.
    pub(in crate::kernel) fn admit_fork(
        &self,
        state: &RegistryState,
        caller: &KernelContext,
    ) -> Result<(), KernelOperationError> {
        let Some(limit) = nproc_limit(caller) else {
            return Ok(());
        };
        let in_flight = self.in_flight.lock();
        nproc_verdict(
            state,
            &in_flight,
            caller.resources.credentials().ruid(),
            limit,
        )
    }

    /// Claimed or born clones charged to `uid` that have not published.
    pub fn in_flight_threads(&self, uid: NsUid) -> usize {
        self.in_flight.lock().get(&uid).copied().unwrap_or(0)
    }
}

/// The soft `RLIMIT_NPROC` that binds `caller`, or `None` when the caller is
/// exempt.
///
/// setrlimit(2), `RLIMIT_NPROC`: a limit on the number of extant processes —
/// on Linux, threads — for the caller's REAL user ID; while the count is
/// greater than or equal to the limit, fork(2) fails with `EAGAIN` (clone(2)
/// documents the same `EAGAIN` for thread creation, "too many processes are
/// already running; see fork(2)"). The limit is not enforced for a caller
/// with `CAP_SYS_ADMIN` or `CAP_SYS_RESOURCE`, or with real user ID 0 — the
/// root exemption was also measured against the native-arm64 Docker oracle on
/// 2026-08-26 (default capability set, no `CAP_SYS_ADMIN`/`CAP_SYS_RESOURCE`,
/// soft limit 3: twelve live children, no `EAGAIN`).
fn nproc_limit(caller: &KernelContext) -> Option<usize> {
    if caller.resources.credentials().ruid() == NsUid::ROOT {
        return None;
    }
    let limit = caller
        .task()
        .rlimit(carrick_abi::LinuxResource::Nproc)
        .rlim_cur;
    if limit == carrick_abi::LINUX_RLIM_INFINITY {
        return None;
    }
    let caps = caller.task().caps();
    if caps.has_effective(crate::namespace::process::CAP_SYS_ADMIN)
        || caps.has_effective(crate::namespace::process::CAP_SYS_RESOURCE)
    {
        return None;
    }
    Some(usize::try_from(limit).unwrap_or(usize::MAX))
}

/// Threads charged to `uid`: published thread claims whose thread's real uid
/// is `uid`, claimed and born clones, and unclaimed pool credits. `None`
/// means the whole graph holds fewer than `limit` threads, so no uid can be at
/// the limit and no per-thread credentials were read.
fn nproc_count(
    state: &RegistryState,
    in_flight: &BTreeMap<NsUid, usize>,
    uid: NsUid,
    limit: usize,
) -> Option<usize> {
    let total = state
        .tasks
        .values()
        .map(|record| record.thread_claims.len() + record.thread_pool.credits(None))
        .sum::<usize>()
        + in_flight.values().sum::<usize>();
    if total < limit {
        return None;
    }
    Some(published_threads(state, uid) + claimed(in_flight, uid) + pooled_credits(state, uid))
}

fn published_threads(state: &RegistryState, uid: NsUid) -> usize {
    state
        .tasks
        .values()
        .flat_map(|record| {
            record
                .thread_claims
                .keys()
                .filter_map(|tid| record.task.thread(*tid))
        })
        .filter(|thread| thread.resources().credentials().ruid() == uid)
        .count()
}

fn claimed(in_flight: &BTreeMap<NsUid, usize>, uid: NsUid) -> usize {
    in_flight.get(&uid).copied().unwrap_or(0)
}

fn pooled_credits(state: &RegistryState, uid: NsUid) -> usize {
    state
        .tasks
        .values()
        .map(|record| record.thread_pool.credits(Some(uid)))
        .sum()
}

/// Exact `RLIMIT_NPROC` verdict for one new thread of `uid`. The caller holds
/// the registry lock (read or write) and the in-flight map, so publications
/// and competing admissions cannot interleave. Unclaimed pool credits are
/// promises, not threads: at the limit they are revoked (by CAS, so a
/// concurrent claimer either wins its entry first or loses it) before a
/// clone is refused.
fn nproc_verdict(
    state: &RegistryState,
    in_flight: &BTreeMap<NsUid, usize>,
    uid: NsUid,
    limit: usize,
) -> Result<(), KernelOperationError> {
    let Some(count) = nproc_count(state, in_flight, uid, limit) else {
        return Ok(());
    };
    if count < limit {
        return Ok(());
    }
    let revoked: usize = state
        .tasks
        .values()
        .map(|record| record.thread_pool.revoke(uid))
        .sum();
    let count = count - revoked;
    if count < limit {
        return Ok(());
    }
    Err(KernelOperationError::ProcessLimitExceeded {
        uid,
        count,
        limit: u64::try_from(limit).unwrap_or(u64::MAX),
    })
}

impl Kernel {
    /// Settle thread births before resolving a host-entry context. The
    /// empty-ledger path is one atomic load; membership readers use the
    /// same settlement body through the registry's settled view.
    pub fn settle_thread_ledger(&self) {
        let _ = self.registry().settled();
    }

    /// Tids standing in `task`'s identity pool (diagnostics and tests).
    pub fn standing_thread_identities(&self, task: super::ids::TaskId) -> Vec<LinuxTid> {
        self.registry()
            .settled()
            .read()
            .tasks
            .get(&task)
            .map(|record| record.thread_pool.tids())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::Arc;

    use carrick_abi::{LinuxCloneFlags, LinuxResource, LinuxRlimit, NsGid, NsUid};
    use carrick_hal::ThreadId;

    use crate::kernel::clone_plan::ClonePlan;
    use crate::kernel::core::KernelContext;
    use crate::kernel::objects::LinuxWaitStatus;
    use crate::kernel::operations::KernelOperationError;
    use crate::kernel::operations::tests::bootstrap;

    const USER: NsUid = NsUid::new(1000);

    fn thread_plan() -> ClonePlan {
        ClonePlan::from_flags(
            LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
        )
        .expect("thread plan")
    }

    fn fork_plan() -> ClonePlan {
        ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan")
    }

    #[test]
    fn lifecycle_host_boundary_settles_births_before_context_in_two_processes() {
        let (kernel, root) = bootstrap(9_650);
        let peer = kernel
            .fork_task(
                &root,
                fork_plan(),
                ThreadId::synthetic_for_tests(9_651),
                "boundary-observer".into(),
                None,
            )
            .unwrap();
        let mut births = Vec::new();
        for (index, parent) in [&root, &peer].into_iter().enumerate() {
            let prepared = kernel
                .reserve_thread_clone(parent, thread_plan(), None)
                .unwrap()
                .prepare(ThreadId::synthetic_for_tests(9_652 + index as i32))
                .unwrap();
            let tid = prepared.tid();
            let key = prepared.record_birth();
            births.push((parent.task().clone(), tid, key));
        }
        // Reserving the peer's birth observes membership and settles the
        // first birth; the last birth remains pending at host entry.
        assert_eq!(kernel.registry().thread_ledger().pending_births(), 1);
        // No region or boundary flags are necessary: thread settlement is
        // owed on every host entry, even an ordinary forwarded syscall.
        crate::el1_delegation::settle_el1_boundary(usize::MAX, &kernel);
        for (task, tid, _) in &births {
            // Read the actual task before a context/membership lookup can
            // hide missing boundary settlement by settling it itself.
            assert!(
                task.thread(*tid).is_some(),
                "boundary left a birth invisible"
            );
        }
        for (task, tid, key) in births {
            assert_eq!(
                kernel.context(task.key().id, tid).unwrap().thread().key(),
                key
            );
        }
        assert_eq!(kernel.registry().thread_ledger().pending_births(), 0);
    }

    #[test]
    fn lifecycle_control_backing_excludes_host_objects_in_two_processes() {
        let (kernel, root) = bootstrap(9_620);
        let peer = kernel
            .fork_task(
                &root,
                fork_plan(),
                ThreadId::synthetic_for_tests(9_621),
                "peer".into(),
                None,
            )
            .unwrap();
        for context in [&root, &peer] {
            let thread = context.thread();
            let object = std::ptr::from_ref(thread.as_ref()).addr();
            let slot = std::ptr::from_ref(thread.control_slot()).addr();
            assert!(
                !(object..object + std::mem::size_of_val(thread.as_ref())).contains(&slot),
                "EL1 control backing must not expose the host Thread object's pointers and locks"
            );
        }
        let first = root.thread().control_lease();
        let second = peer.thread().control_lease();
        assert_eq!(first.backing_base(), second.backing_base());
        assert_ne!(first.slot_address(), second.slot_address());
        assert_ne!(
            first.lifecycle().page_address(),
            second.lifecycle().page_address()
        );
        first.lifecycle().close();
        assert_eq!(
            root.thread().control_lease().lifecycle().gate(),
            carrick_el1_abi::GateState::Closed
        );
        assert_eq!(
            peer.thread().control_lease().lifecycle().gate(),
            carrick_el1_abi::GateState::Open
        );
        first.init_blocked(carrick_el1_abi::BlockedMask(0x400));
        assert_eq!(root.thread().blocked_mask().raw(), 0x400);
        assert_eq!(peer.thread().blocked_mask(), carrick_abi::SigSet::EMPTY);
        let kernel_lifetime = Arc::downgrade(&kernel);
        let first_task = Arc::downgrade(root.task());
        let second_task = Arc::downgrade(peer.task());
        drop(root);
        drop(peer);
        drop(kernel);
        assert!(kernel_lifetime.upgrade().is_none());
        assert!(first_task.upgrade().is_none());
        assert!(second_task.upgrade().is_none());
        assert_eq!(first.blocked().0, 0x400);
        assert_eq!(second.blocked().0, 0);
    }

    #[test]
    fn lifecycle_control_authority_survives_equal_keys_in_two_live_kernels() {
        let (_first_kernel, first) = bootstrap(9_640);
        let (_second_kernel, second) = bootstrap(9_640);
        let first_slot = first.thread().control_lease();
        let second_slot = second.thread().control_lease();
        assert_eq!(first_slot.identity(), second_slot.identity());
        assert!(first.task().owns_thread_control(&first_slot));
        assert!(second.task().owns_thread_control(&second_slot));
        assert!(!first.task().owns_thread_control(&second_slot));
        assert!(!second.task().owns_thread_control(&first_slot));
        assert_ne!(
            first_slot.lifecycle().backing_base(),
            second_slot.lifecycle().backing_base()
        );
    }

    #[test]
    fn lifecycle_adoption_retains_born_control_in_two_processes() {
        let (kernel, root) = bootstrap(9_630);
        let peer = kernel
            .fork_task(
                &root,
                fork_plan(),
                ThreadId::synthetic_for_tests(9_631),
                "peer".into(),
                None,
            )
            .unwrap();
        for (index, parent) in [&root, &peer].into_iter().enumerate() {
            let claim = kernel
                .reserve_thread_clone(parent, thread_plan(), None)
                .unwrap();
            let born = claim.control_lease();
            assert_eq!(
                born.lifecycle().backing_base(),
                parent.thread().control_lease().lifecycle().backing_base()
            );
            let mask = carrick_el1_abi::BlockedMask(1 << (10 + index));
            let stack = carrick_el1_abi::AltStack {
                sp: 0x40000,
                size: 0x10000,
                flags: 0,
            };
            // EL1 has run setup before the thread's first forwarded call.
            born.init_blocked(mask);
            born.write_altstack(stack);
            born.set_robust_list(0x1230, 24);
            let child = claim
                .prepare(ThreadId::synthetic_for_tests(9_632 + index as i32))
                .unwrap()
                .commit()
                .unwrap()
                .into_context()
                .unwrap();
            let adopted = child.thread().control_lease();
            assert_eq!(
                adopted.slot_address(),
                born.slot_address(),
                "adoption copied control storage"
            );
            assert_eq!(
                adopted.identity(),
                (parent.task().key(), child.thread().key())
            );
            assert_eq!(child.thread().blocked_mask().raw(), mask.0);
            assert_eq!(adopted.read_altstack(), stack);
            assert_eq!(adopted.robust_list(), (0x1230, 24));
        }
    }

    #[test]
    fn lifecycle_identity_precedes_adoption_in_two_processes() {
        let (kernel, root) = bootstrap(9_600);
        kernel.registry().thread_ledger().set_pool_depth_for_test(0);
        let peer = kernel
            .fork_task(
                &root,
                fork_plan(),
                ThreadId::synthetic_for_tests(9_601),
                "peer".into(),
                None,
            )
            .unwrap();
        let first = kernel
            .reserve_thread_clone(&root, thread_plan(), None)
            .unwrap();
        let second = kernel
            .reserve_thread_clone(&peer, thread_plan(), None)
            .unwrap();
        let reserved_first = first.key();
        let reserved_second = second.key();
        // Adoption may run in the reverse order of births. It must consume
        // identities already issued at reservation, not mint their serials.
        let second = second
            .prepare(ThreadId::synthetic_for_tests(9_603))
            .unwrap();
        let first = first.prepare(ThreadId::synthetic_for_tests(9_602)).unwrap();
        let first_key = first.prepared_execution_identity().1;
        let second_key = second.prepared_execution_identity().1;
        assert_eq!(first_key, reserved_first);
        assert_eq!(second_key, reserved_second);
        assert!(
            first_key.serial.raw() < second_key.serial.raw(),
            "identity was assigned at adoption: {first_key:?} {second_key:?}"
        );
        let first = first.commit().unwrap().into_context().unwrap();
        let second = second.commit().unwrap().into_context().unwrap();
        assert_eq!(first.thread().key(), first_key);
        assert_eq!(second.thread().key(), second_key);
        assert_eq!(first.task().key(), root.task().key());
        assert_eq!(second.task().key(), peer.task().key());
    }

    #[test]
    fn lifecycle_clone_seed_is_bound_at_claim_in_two_processes() {
        let (kernel, root) = bootstrap(9_610);
        kernel.registry().thread_ledger().set_pool_depth_for_test(0);
        let peer = kernel
            .fork_task(
                &root,
                fork_plan(),
                ThreadId::synthetic_for_tests(9_611),
                "peer".into(),
                None,
            )
            .unwrap();
        for (index, parent) in [&root, &peer].into_iter().enumerate() {
            let mask = carrick_abi::SigSet::from_raw(1 << (10 + index));
            let affinity = carrick_hal::CpuAffinity::from_words(&[1 << index]);
            parent.thread().store_blocked(mask);
            parent.thread().set_affinity(affinity);
            let claim = kernel
                .reserve_thread_clone(parent, thread_plan(), None)
                .unwrap();
            parent.thread().store_blocked(carrick_abi::SigSet::EMPTY);
            parent
                .thread()
                .set_affinity(carrick_hal::CpuAffinity::from_words(&[4]));
            let child = claim
                .prepare(ThreadId::synthetic_for_tests(9_612 + index as i32))
                .unwrap()
                .commit()
                .unwrap()
                .into_context()
                .unwrap();
            assert_eq!(
                child.thread().blocked_mask(),
                mask,
                "clone must inherit the claim-time mask"
            );
            assert_eq!(
                child.thread().affinity(),
                affinity,
                "clone must inherit the claim-time affinity"
            );
            assert_eq!(parent.thread().blocked_mask(), carrick_abi::SigSet::EMPTY);
        }
    }

    /// Drop `root` to real uid 1000 under a soft `RLIMIT_NPROC` of `soft`,
    /// with the default (Docker) capability set: no `CAP_SYS_ADMIN`, no
    /// `CAP_SYS_RESOURCE`.
    fn unprivileged(
        kernel: &std::sync::Arc<crate::kernel::Kernel>,
        root: &KernelContext,
        soft: u64,
    ) -> KernelContext {
        let user = kernel
            .update_credentials(root, |credentials| {
                credentials.seed_identity(USER, NsGid::new(1000));
            })
            .expect("seed unprivileged credentials");
        user.task()
            .replace_rlimit(LinuxResource::Nproc, |_| {
                Ok::<_, Infallible>(LinuxRlimit::new(soft, 8_192))
            })
            .expect("set RLIMIT_NPROC");
        user
    }

    fn is_nproc_refusal(
        result: &Result<KernelContext, KernelOperationError>,
        count: usize,
    ) -> bool {
        matches!(
            result,
            Err(KernelOperationError::ProcessLimitExceeded { uid, count: c, .. })
                if *uid == USER && *c == count
        )
    }

    /// setrlimit(2): `RLIMIT_NPROC` limits the threads of the caller's real
    /// uid; at `count >= limit` clone(2) fails with `EAGAIN`. Thread clones
    /// were not gated at all before the ledger (red: the second clone
    /// published a third thread).
    #[test]
    fn thread_clone_enforces_rlimit_nproc_per_real_uid() {
        let (kernel, root) = bootstrap(9_500);
        kernel.registry().thread_ledger().set_pool_depth_for_test(0);
        let user = unprivileged(&kernel, &root, 2);
        let sibling = kernel
            .clone_thread(
                &user,
                thread_plan(),
                ThreadId::synthetic_for_tests(9_501),
                None,
            )
            .expect("one live thread under a limit of two admits a clone");
        let refused = kernel.clone_thread(
            &user,
            thread_plan(),
            ThreadId::synthetic_for_tests(9_502),
            None,
        );
        assert!(is_nproc_refusal(&refused, 2), "{refused:?}");
        assert_eq!(user.task().threads().len(), 2);
        drop(sibling);
    }

    /// Claimed-but-unpublished clones hold their uid credit, so two clones
    /// racing at the limit cannot both win; a dropped claim returns it.
    #[test]
    fn in_flight_thread_clones_count_against_rlimit_nproc() {
        let (kernel, root) = bootstrap(9_510);
        kernel.registry().thread_ledger().set_pool_depth_for_test(0);
        let user = unprivileged(&kernel, &root, 3);
        let first = kernel
            .reserve_thread_clone(&user, thread_plan(), None)
            .expect("first claim");
        let second = kernel
            .reserve_thread_clone(&user, thread_plan(), None)
            .expect("second claim");
        assert_eq!(kernel.registry().thread_ledger().in_flight_threads(USER), 2);
        assert!(matches!(
            kernel.reserve_thread_clone(&user, thread_plan(), None),
            Err(KernelOperationError::ProcessLimitExceeded {
                count: 3,
                limit: 3,
                ..
            })
        ));
        drop(first);
        assert_eq!(kernel.registry().thread_ledger().in_flight_threads(USER), 1);
        let third = kernel
            .reserve_thread_clone(&user, thread_plan(), None)
            .expect("a returned credit admits the next claim");
        // Publication moves the charge from the ledger to the thread claim.
        let published = second
            .prepare(ThreadId::synthetic_for_tests(9_511))
            .expect("prepare")
            .commit()
            .expect("publish");
        assert_eq!(kernel.registry().thread_ledger().in_flight_threads(USER), 1);
        assert!(matches!(
            kernel.reserve_thread_clone(&user, thread_plan(), None),
            Err(KernelOperationError::ProcessLimitExceeded { count: 3, .. })
        ));
        drop(published);
        drop(third);
    }

    /// Real uid 0 and `CAP_SYS_ADMIN`/`CAP_SYS_RESOURCE` are exempt.
    #[test]
    fn root_and_capabilities_are_exempt_from_thread_rlimit_nproc() {
        let (kernel, root) = bootstrap(9_520);
        root.task()
            .replace_rlimit(LinuxResource::Nproc, |_| {
                Ok::<_, Infallible>(LinuxRlimit::new(1, 8_192))
            })
            .expect("set RLIMIT_NPROC");
        let root_sibling = kernel
            .clone_thread(
                &root,
                thread_plan(),
                ThreadId::synthetic_for_tests(9_521),
                None,
            )
            .expect("real uid 0 is exempt");
        let user = unprivileged(&kernel, &root, 1);
        assert!(is_nproc_refusal(
            &kernel.clone_thread(
                &user,
                thread_plan(),
                ThreadId::synthetic_for_tests(9_522),
                None
            ),
            // Both live threads carry uid 1000 now: credentials are per
            // thread and the update above re-credentialed the caller only,
            // so the root sibling still counts as uid 0.
            1,
        ));
        user.task().with_caps(|caps| {
            caps.effective |= 1u64 << crate::namespace::process::CAP_SYS_RESOURCE;
        });
        let exempt = kernel
            .clone_thread(
                &user,
                thread_plan(),
                ThreadId::synthetic_for_tests(9_523),
                None,
            )
            .expect("CAP_SYS_RESOURCE is exempt");
        drop((root_sibling, exempt));
    }

    /// Unclaimed pool credits are promises, not threads: a fork or clone at
    /// the limit revokes them (CAS) instead of being refused, and the pool
    /// stops filling rather than hold a credit the limit cannot cover.
    #[test]
    fn standing_pool_credits_are_revoked_under_pressure() {
        let (kernel, root) = bootstrap(9_530);
        kernel.registry().thread_ledger().set_pool_depth_for_test(4);
        let user = unprivileged(&kernel, &root, 3);
        let sibling = kernel
            .clone_thread(
                &user,
                thread_plan(),
                ThreadId::synthetic_for_tests(9_531),
                None,
            )
            .expect("first clone");
        // Two published threads + one credit reach the limit of three.
        let standing = kernel.standing_thread_identities(user.task().key().id);
        assert_eq!(standing.len(), 1, "{standing:?}");
        let child = kernel
            .fork_task(
                &user,
                fork_plan(),
                ThreadId::synthetic_for_tests(9_532),
                "pressure".to_owned(),
                None,
            )
            .expect("the fork revokes the unclaimed credit instead of failing");
        assert!(
            kernel
                .standing_thread_identities(user.task().key().id)
                .is_empty()
        );
        assert!(is_nproc_refusal(
            &kernel.clone_thread(
                &sibling,
                thread_plan(),
                ThreadId::synthetic_for_tests(9_533),
                None
            ),
            3,
        ));
        drop(child);
    }

    /// A tid is never issued twice while it is reserved: a standing entry
    /// is not handed to a fork, and an exited-but-unreaped thread's number
    /// stays claimed until its last context drains. FIFO claims keep a
    /// task's successive thread tids ascending.
    #[test]
    fn pooled_and_retired_tids_are_not_reused_before_reaping() {
        let (kernel, root) = bootstrap(9_540);
        kernel.registry().thread_ledger().set_pool_depth_for_test(4);
        let first = kernel
            .clone_thread(
                &root,
                thread_plan(),
                ThreadId::synthetic_for_tests(9_541),
                None,
            )
            .expect("first clone");
        let first_tid = first.thread().key().tid;
        let standing = kernel.standing_thread_identities(root.task().key().id);
        assert_eq!(standing.len(), 4);
        kernel.exit_thread(&first, None).expect("exit first thread");
        let child = kernel
            .fork_task(
                &root,
                fork_plan(),
                ThreadId::synthetic_for_tests(9_542),
                "fork-after-pool".to_owned(),
                None,
            )
            .expect("fork");
        let child_tid = crate::kernel::ids::LinuxTid::for_task_leader(child.task().key().id);
        assert!(!standing.contains(&child_tid));
        assert_ne!(child_tid, first_tid);
        let root = kernel
            .context(root.task().key().id, root.thread().key().tid)
            .expect("refresh root");
        let second = kernel
            .clone_thread(
                &root,
                thread_plan(),
                ThreadId::synthetic_for_tests(9_543),
                None,
            )
            .expect("second clone");
        assert_eq!(second.thread().key().tid, standing[0]);
        let refilled = kernel.standing_thread_identities(root.task().key().id);
        assert!(
            !refilled.contains(&first_tid),
            "retired tid reissued: {refilled:?}"
        );
        assert!(!refilled.contains(&child_tid));
        assert!(kernel.ids().is_reserved_number(first_tid.raw()));
        drop(first);
        kernel.sweep_retired_threads();
        assert!(!kernel.ids().is_reserved_number(first_tid.raw()));
        drop((second, child));
    }

    /// The pool is owned by the task's registry record: whole-process exit
    /// releases every standing tid with it.
    #[test]
    fn task_exit_releases_standing_pool_identities() {
        let (kernel, root) = bootstrap(9_550);
        kernel.registry().thread_ledger().set_pool_depth_for_test(4);
        let child = kernel
            .fork_task(
                &root,
                fork_plan(),
                ThreadId::synthetic_for_tests(9_551),
                "pool-owner".to_owned(),
                None,
            )
            .expect("fork");
        let sibling = kernel
            .clone_thread(
                &child,
                thread_plan(),
                ThreadId::synthetic_for_tests(9_552),
                None,
            )
            .expect("clone");
        let standing = kernel.standing_thread_identities(child.task().key().id);
        assert_eq!(standing.len(), 4);
        assert!(
            standing
                .iter()
                .all(|tid| kernel.ids().is_reserved_number(tid.raw()))
        );
        kernel
            .exit_task_key_eventually(child.task().key(), LinuxWaitStatus::from_wait_encoding(0))
            .expect("exit child");
        assert!(
            standing
                .iter()
                .all(|tid| !kernel.ids().is_reserved_number(tid.raw()))
        );
        drop((sibling, child));
    }

    /// `CARRICK_THREAD_POOL=0`: no standing entries; each clone reserves its
    /// one entry at clone time through the same claim.
    #[test]
    fn pool_depth_zero_reserves_one_entry_at_clone_time() {
        let (kernel, root) = bootstrap(9_560);
        kernel.registry().thread_ledger().set_pool_depth_for_test(0);
        let first = kernel
            .clone_thread(
                &root,
                thread_plan(),
                ThreadId::synthetic_for_tests(9_561),
                None,
            )
            .expect("first clone");
        let second = kernel
            .clone_thread(
                &root,
                thread_plan(),
                ThreadId::synthetic_for_tests(9_562),
                None,
            )
            .expect("second clone");
        assert!(
            kernel
                .standing_thread_identities(root.task().key().id)
                .is_empty()
        );
        assert_eq!(
            second.thread().key().tid.raw(),
            first.thread().key().tid.raw() + 1
        );
        drop((first, second));
    }

    /// A membership read settles recorded births first: the thread is
    /// invisible in the raw task graph until a settled view is taken, and
    /// every membership reader takes one.
    #[test]
    fn membership_read_settles_recorded_births() {
        let (kernel, root) = bootstrap(9_570);
        let prepared = kernel
            .reserve_thread_clone(&root, thread_plan(), None)
            .expect("claim")
            .prepare(ThreadId::synthetic_for_tests(9_571))
            .expect("prepare");
        let tid = prepared.tid();
        let key = prepared.record_birth();
        assert_eq!(kernel.registry().thread_ledger().pending_births(), 1);
        assert!(root.task().thread(tid).is_none());
        assert_eq!(
            kernel.live_task_for_thread(None, tid),
            Some(root.task().key().id)
        );
        assert_eq!(kernel.registry().thread_ledger().pending_births(), 0);
        assert!(root.task().thread(tid).is_some());
        assert!(kernel.exact_thread_for_scheduler(key).is_some());
    }

    /// A second live process resolves the thread-directed signal target of a
    /// thread born in another process, both by tid alone (`kill`/`tkill`)
    /// and with the tgid (`tgkill`).
    #[test]
    fn second_process_resolves_signal_target_of_born_thread() {
        let (kernel, root) = bootstrap(9_580);
        let other = kernel
            .fork_task(
                &root,
                fork_plan(),
                ThreadId::synthetic_for_tests(9_581),
                "observer".to_owned(),
                None,
            )
            .expect("second process");
        let root = kernel
            .context(root.task().key().id, root.thread().key().tid)
            .expect("refresh root");
        let prepared = kernel
            .reserve_thread_clone(&root, thread_plan(), None)
            .expect("claim")
            .prepare(ThreadId::synthetic_for_tests(9_582))
            .expect("prepare");
        let tid = prepared.tid();
        let key = prepared.record_birth();
        let observed = other.kernel().live_keys_for_thread(None, tid);
        assert_eq!(observed, Some((root.task().key(), key)));
        assert_eq!(
            other
                .kernel()
                .live_task_for_thread(Some(root.task().key().id), tid),
            Some(root.task().key().id)
        );
        assert_eq!(
            other
                .kernel()
                .live_task_for_thread(Some(other.task().key().id), tid),
            None
        );
    }
}
