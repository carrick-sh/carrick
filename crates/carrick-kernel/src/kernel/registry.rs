use std::collections::BTreeMap;
use std::num::NonZeroI32;
use std::sync::Arc;

use parking_lot::{Mutex, RwLock, RwLockReadGuard, RwLockWriteGuard};

use super::core::RegistryState;
use super::thread_ledger::ThreadLedger;

use super::ids::{LinuxTid, ProcessGroupId, SessionId, TaskId};

/// Shared Linux PID namespace allocator. Task IDs, thread IDs, process-group
/// IDs, and session IDs all claim numbers from this one collision domain.
#[derive(Clone, Debug)]
pub struct IdRegistry {
    state: Arc<Mutex<NamespaceState>>,
}

impl Default for IdRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl IdRegistry {
    pub fn new() -> Self {
        Self::with_range(1, i32::MAX, 1)
    }

    /// Start a registry around the already-running root task. The returned
    /// claim must live until the root task has been reaped.
    pub fn with_root(root: TaskId) -> Result<(Self, TaskClaim), IdError> {
        let next = root.raw().checked_add(1).unwrap_or(1);
        let registry = Self::with_range(1, i32::MAX, next);
        let reservation = TaskReservation(registry.reserve_exact(root.raw(), ClaimKind::Task)?);
        Ok((registry, reservation.commit()))
    }

    pub fn reserve_task(&self) -> Result<(TaskId, TaskReservation), IdError> {
        let reservation = self.reserve_next(ClaimKind::Task)?;
        let id = TaskId::from_registry_allocation(reservation.raw);
        Ok((id, TaskReservation(reservation)))
    }

    pub fn reserve_thread(&self) -> Result<(LinuxTid, ThreadReservation), IdError> {
        let reservation = self.reserve_next(ClaimKind::Thread)?;
        let id = LinuxTid::from_registry_allocation(reservation.raw);
        Ok((id, ThreadReservation(reservation)))
    }

    /// Reserve an externally established task ID, such as the bootstrap TGID.
    pub fn reserve_exact_task(&self, task: TaskId) -> Result<TaskReservation, IdError> {
        self.reserve_exact(task.raw(), ClaimKind::Task)
            .map(TaskReservation)
    }

    /// Claim the leader thread role on an already-reserved task/TGID number.
    pub fn claim_task_leader_thread(&self, task: TaskId) -> Result<ThreadClaim, IdError> {
        self.claim_related(task.raw(), ClaimKind::Thread)
            .map(ThreadClaim)
    }

    /// Keep a process-group number alive independently of its leader task.
    pub fn claim_process_group(&self, group: ProcessGroupId) -> Result<ProcessGroupClaim, IdError> {
        self.claim_related(group.raw(), ClaimKind::ProcessGroup)
            .map(ProcessGroupClaim)
    }

    /// Keep a session number alive independently of its leader task.
    pub fn claim_session(&self, session: SessionId) -> Result<SessionClaim, IdError> {
        self.claim_related(session.raw(), ClaimKind::Session)
            .map(SessionClaim)
    }

    pub fn is_reserved_number(&self, raw: i32) -> bool {
        self.state.lock().claims.contains_key(&raw)
    }

    pub fn counts(&self) -> IdRegistryCounts {
        let state = self.state.lock();
        state
            .claims
            .values()
            .fold(IdRegistryCounts::default(), |mut counts, claim| {
                counts.reserved_numbers += 1;
                counts.task_claims += claim.tasks as usize;
                counts.thread_claims += claim.threads as usize;
                counts.process_group_claims += claim.process_groups as usize;
                counts.session_claims += claim.sessions as usize;
                counts
            })
    }

    fn reserve_next(&self, kind: ClaimKind) -> Result<ReservationToken, IdError> {
        let mut state = self.state.lock();
        let start = state.next;
        loop {
            let candidate = state.next;
            state.advance();
            if !state.claims.contains_key(&candidate) {
                let Some(candidate) = NonZeroI32::new(candidate) else {
                    return Err(IdError::OutOfRange(candidate));
                };
                let incremented = state
                    .claims
                    .entry(candidate.get())
                    .or_default()
                    .increment(kind);
                if !incremented {
                    return Err(IdError::ClaimCountExhausted(candidate.get()));
                }
                return Ok(ReservationToken::new(
                    Arc::clone(&self.state),
                    candidate,
                    kind,
                ));
            }
            if state.next == start {
                return Err(IdError::Exhausted);
            }
        }
    }

    fn reserve_exact(&self, raw: i32, kind: ClaimKind) -> Result<ReservationToken, IdError> {
        let mut state = self.state.lock();
        if raw < state.first || raw > state.last {
            return Err(IdError::OutOfRange(raw));
        }
        if state.claims.contains_key(&raw) {
            return Err(IdError::AlreadyReserved(raw));
        }
        let Some(raw) = NonZeroI32::new(raw) else {
            return Err(IdError::OutOfRange(raw));
        };
        if !state.claims.entry(raw.get()).or_default().increment(kind) {
            return Err(IdError::ClaimCountExhausted(raw.get()));
        }
        Ok(ReservationToken::new(Arc::clone(&self.state), raw, kind))
    }

    fn claim_related(&self, raw: i32, kind: ClaimKind) -> Result<ClaimToken, IdError> {
        let mut state = self.state.lock();
        let Some(nonzero) = NonZeroI32::new(raw) else {
            return Err(IdError::OutOfRange(raw));
        };
        let Some(claims) = state.claims.get_mut(&raw) else {
            return Err(IdError::UnknownNamespaceId(raw));
        };
        if !claims.increment(kind) {
            return Err(IdError::ClaimCountExhausted(raw));
        }
        Ok(ClaimToken::new(Arc::clone(&self.state), nonzero, kind))
    }

    fn with_range(first: i32, last: i32, next: i32) -> Self {
        assert!(first > 0);
        assert!(last >= first);
        assert!((first..=last).contains(&next));
        Self {
            state: Arc::new(Mutex::new(NamespaceState {
                first,
                last,
                next,
                claims: BTreeMap::new(),
            })),
        }
    }

    #[cfg(test)]
    fn with_range_for_tests(first: i32, last: i32) -> Self {
        Self::with_range(first, last, first)
    }

    #[cfg(test)]
    pub(crate) fn set_next_for_tests(&self, raw: i32) {
        let mut state = self.state.lock();
        assert!((state.first..=state.last).contains(&raw));
        state.next = raw;
    }
}

#[derive(Debug)]
struct NamespaceState {
    first: i32,
    last: i32,
    next: i32,
    claims: BTreeMap<i32, ClaimCounts>,
}

impl NamespaceState {
    fn advance(&mut self) {
        self.next = if self.next == self.last {
            self.first
        } else {
            self.next + 1
        };
    }

    fn release(&mut self, raw: NonZeroI32, kind: ClaimKind) {
        let key = raw.get();
        let remove = {
            let Some(claims) = self.claims.get_mut(&key) else {
                debug_assert!(false, "live identity token lost its registry claim");
                return;
            };
            if !claims.decrement(kind) {
                debug_assert!(false, "identity claim reference count underflow");
                return;
            }
            claims.is_empty()
        };
        if remove {
            self.claims.remove(&key);
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum ClaimKind {
    Task,
    Thread,
    ProcessGroup,
    Session,
}

#[derive(Debug, Default)]
struct ClaimCounts {
    tasks: u32,
    threads: u32,
    process_groups: u32,
    sessions: u32,
}

impl ClaimCounts {
    fn counter(&mut self, kind: ClaimKind) -> &mut u32 {
        match kind {
            ClaimKind::Task => &mut self.tasks,
            ClaimKind::Thread => &mut self.threads,
            ClaimKind::ProcessGroup => &mut self.process_groups,
            ClaimKind::Session => &mut self.sessions,
        }
    }

    fn increment(&mut self, kind: ClaimKind) -> bool {
        let counter = self.counter(kind);
        let Some(next) = counter.checked_add(1) else {
            return false;
        };
        *counter = next;
        true
    }

    fn decrement(&mut self, kind: ClaimKind) -> bool {
        let counter = self.counter(kind);
        let Some(next) = counter.checked_sub(1) else {
            return false;
        };
        *counter = next;
        true
    }

    fn is_empty(&self) -> bool {
        self.tasks == 0 && self.threads == 0 && self.process_groups == 0 && self.sessions == 0
    }
}

#[derive(Debug)]
struct ReservationToken {
    state: Arc<Mutex<NamespaceState>>,
    raw: NonZeroI32,
    kind: ClaimKind,
    active: bool,
}

impl ReservationToken {
    fn new(state: Arc<Mutex<NamespaceState>>, raw: NonZeroI32, kind: ClaimKind) -> Self {
        Self {
            state,
            raw,
            kind,
            active: true,
        }
    }

    fn commit(mut self) -> ClaimToken {
        self.active = false;
        ClaimToken::new(Arc::clone(&self.state), self.raw, self.kind)
    }
}

impl Drop for ReservationToken {
    fn drop(&mut self) {
        if self.active {
            self.state.lock().release(self.raw, self.kind);
        }
    }
}

#[derive(Debug)]
struct ClaimToken {
    state: Arc<Mutex<NamespaceState>>,
    raw: NonZeroI32,
    kind: ClaimKind,
    active: bool,
}

impl ClaimToken {
    fn new(state: Arc<Mutex<NamespaceState>>, raw: NonZeroI32, kind: ClaimKind) -> Self {
        Self {
            state,
            raw,
            kind,
            active: true,
        }
    }
}

impl Drop for ClaimToken {
    fn drop(&mut self) {
        if self.active {
            self.state.lock().release(self.raw, self.kind);
            self.active = false;
        }
    }
}

macro_rules! reservation_role {
    ($reservation:ident, $claim:ident) => {
        /// Role-preserving provisional namespace claim. Dropping it rolls the
        /// allocation back; committing returns only the matching claim role.
        #[derive(Debug)]
        pub struct $reservation(ReservationToken);

        impl $reservation {
            pub const fn raw(&self) -> i32 {
                self.0.raw.get()
            }

            pub fn commit(self) -> $claim {
                $claim(self.0.commit())
            }
        }

        /// Role-preserving ownership of one live namespace-number role.
        #[derive(Debug)]
        pub struct $claim(ClaimToken);

        impl $claim {
            pub const fn raw(&self) -> i32 {
                self.0.raw.get()
            }
        }
    };
}

reservation_role!(TaskReservation, TaskClaim);
reservation_role!(ThreadReservation, ThreadClaim);

macro_rules! claim_role {
    ($claim:ident) => {
        /// Role-preserving ownership of one live namespace-number role.
        #[derive(Debug)]
        pub struct $claim(ClaimToken);

        impl $claim {
            pub const fn raw(&self) -> i32 {
                self.0.raw.get()
            }

            pub(crate) fn belongs_to(&self, registry: &IdRegistry) -> bool {
                Arc::ptr_eq(&self.0.state, &registry.state)
            }
        }
    };
}

claim_role!(ProcessGroupClaim);
claim_role!(SessionClaim);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct IdRegistryCounts {
    pub reserved_numbers: usize,
    pub task_claims: usize,
    pub thread_claims: usize,
    pub process_group_claims: usize,
    pub session_claims: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum IdError {
    #[error("Linux PID namespace is exhausted")]
    Exhausted,
    #[error("Linux namespace identity {0} is outside the allocator range")]
    OutOfRange(i32),
    #[error("Linux namespace identity {0} is already reserved")]
    AlreadyReserved(i32),
    #[error("Linux namespace identity {0} has no live task or object")]
    UnknownNamespaceId(i32),
    #[error("Linux namespace identity {0} has too many live claims")]
    ClaimCountExhausted(i32),
}

/// Authoritative object index. Multi-object mutations take this lock first and
/// may then take at most one Task or subsystem leaf lock.
///
/// The lock is private: the only way to read or write the task graph is a
/// [`SettledRegistryView`], and the only way to get one is
/// [`Registry::settled`], which first publishes every thread birth the
/// [`ThreadLedger`] holds. No membership reader can therefore observe a
/// thread-group without its born-but-unpublished threads — a thread's
/// visibility never depends on which lane created it.
#[derive(Debug)]
pub struct Registry {
    state: RegistryLock,
    ledger: ThreadLedger,
}

impl Registry {
    pub(super) fn new(state: RegistryState, ledger: ThreadLedger) -> Self {
        Self {
            state: RegistryLock::new(state),
            ledger,
        }
    }

    /// Settle pending thread births, then hand out the task graph.
    pub(super) fn settled(&self) -> SettledRegistryView<'_> {
        self.ledger.settle(&self.state);
        SettledRegistryView { lock: &self.state }
    }

    /// The thread-identity ledger that owns pending births and the
    /// `RLIMIT_NPROC` credits of in-flight thread clones.
    pub(crate) const fn thread_ledger(&self) -> &ThreadLedger {
        &self.ledger
    }
}

/// The task graph after [`Registry::settled`]: every thread birth recorded
/// before the view was created is published in it.
#[derive(Clone, Copy, Debug)]
pub(super) struct SettledRegistryView<'a> {
    lock: &'a RegistryLock,
}

impl<'a> SettledRegistryView<'a> {
    pub(super) fn read(self) -> RwLockReadGuard<'a, RegistryState> {
        self.lock.read()
    }

    pub(super) fn try_read_until(
        self,
        deadline: std::time::Instant,
    ) -> Option<RwLockReadGuard<'a, RegistryState>> {
        self.lock.try_read_until(deadline)
    }

    pub(super) fn write(self) -> RwLockWriteGuard<'a, RegistryState> {
        self.lock.write()
    }

    #[cfg(test)]
    pub(super) fn try_write(self) -> Option<RwLockWriteGuard<'a, RegistryState>> {
        self.lock.try_write()
    }

    pub(super) fn write_unpublished(self) -> RwLockWriteGuard<'a, RegistryState> {
        self.lock.write_unpublished()
    }

    pub(super) fn try_write_unpublished_until(
        self,
        deadline: std::time::Instant,
    ) -> Option<RwLockWriteGuard<'a, RegistryState>> {
        self.lock.try_write_unpublished_until(deadline)
    }
}

/// The registry's reader/writer lock. Reachable only through [`Registry`]'s
/// private field: the [`ThreadLedger`] receives it by reference to publish
/// births, and every other user goes through [`SettledRegistryView`].
#[derive(Debug)]
pub(super) struct RegistryLock {
    inner: RwLock<RegistryState>,
}

impl RegistryLock {
    fn new(state: RegistryState) -> Self {
        Self {
            inner: RwLock::new(state),
        }
    }

    pub(super) fn read(&self) -> RwLockReadGuard<'_, RegistryState> {
        self.inner.read()
    }

    fn try_read_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<RwLockReadGuard<'_, RegistryState>> {
        self.inner.try_read_until(deadline)
    }

    pub(super) fn write(&self) -> RwLockWriteGuard<'_, RegistryState> {
        let mut state = self.inner.write();
        state.publish_epoch();
        state
    }

    #[cfg(test)]
    fn try_write(&self) -> Option<RwLockWriteGuard<'_, RegistryState>> {
        let mut state = self.inner.try_write()?;
        state.publish_epoch();
        Some(state)
    }

    fn write_unpublished(&self) -> RwLockWriteGuard<'_, RegistryState> {
        self.inner.write()
    }

    fn try_write_unpublished_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<RwLockWriteGuard<'_, RegistryState>> {
        self.inner.try_write_until(deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_and_thread_ids_share_one_namespace() {
        let registry = IdRegistry::with_range_for_tests(1, 2);
        let (task, task_reservation) = registry.reserve_task().expect("task reservation");
        let task_claim = task_reservation.commit();
        let (thread, thread_reservation) = registry.reserve_thread().expect("thread reservation");
        let thread_claim = thread_reservation.commit();

        assert_eq!(task.raw(), 1);
        assert_eq!(thread.raw(), 2);
        assert_eq!(registry.reserve_task().unwrap_err(), IdError::Exhausted);

        drop(task_claim);
        drop(thread_claim);
    }

    #[test]
    fn dropped_reservation_rolls_back_without_publication() {
        let registry = IdRegistry::with_range_for_tests(1, 1);
        let (_, reservation) = registry.reserve_task().expect("reservation");
        drop(reservation);

        let (task, _) = registry.reserve_task().expect("rolled-back number");
        assert_eq!(task.raw(), 1);
    }

    #[test]
    fn process_group_keeps_reaped_leader_number_reserved() {
        let registry = IdRegistry::with_range_for_tests(1, 1);
        let (leader, reservation) = registry.reserve_task().expect("leader");
        let leader_claim = reservation.commit();
        let group = ProcessGroupId::from_leader(leader);
        let group_claim = registry.claim_process_group(group).expect("group claim");

        drop(leader_claim);
        assert_eq!(registry.reserve_task().unwrap_err(), IdError::Exhausted);
        drop(group_claim);

        assert_eq!(registry.reserve_task().expect("reusable").0.raw(), 1);
    }

    #[test]
    fn session_keeps_reaped_leader_number_reserved() {
        let registry = IdRegistry::with_range_for_tests(7, 7);
        let (leader, reservation) = registry.reserve_task().expect("leader");
        let leader_claim = reservation.commit();
        let session = SessionId::from_leader(leader);
        let session_claim = registry.claim_session(session).expect("session claim");

        drop(leader_claim);
        assert!(registry.is_reserved_number(7));
        drop(session_claim);
        assert!(!registry.is_reserved_number(7));
    }

    #[test]
    fn allocator_wraps_and_skips_live_claims() {
        let registry = IdRegistry::with_range_for_tests(1, 3);
        let (_, first) = registry.reserve_task().expect("first");
        let first = first.commit();
        let (_, second) = registry.reserve_task().expect("second");
        let second = second.commit();
        let (_, third) = registry.reserve_task().expect("third");
        let third = third.commit();

        drop(second);
        let (reused, _) = registry.reserve_thread().expect("wrapped free ID");
        assert_eq!(reused.raw(), 2);

        drop(first);
        drop(third);
    }

    #[test]
    fn root_bootstrap_preserves_exact_tgid() {
        let root = TaskId::for_root_bootstrap(42).expect("root ID");
        let (registry, root_claim) = IdRegistry::with_root(root).expect("root registry");

        assert_eq!(root_claim.raw(), 42);
        assert!(registry.is_reserved_number(42));
        assert_eq!(registry.reserve_task().expect("child").0.raw(), 43);
    }
}
