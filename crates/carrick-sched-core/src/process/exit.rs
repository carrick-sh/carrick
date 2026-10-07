//! Reserved exit participants share topology custody while retaining live
//! thread membership. Consumers supply revision capacity, not revision policy.
use super::TaskKey;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct TaskRevision(u64);

impl TaskRevision {
    pub const INITIAL: Self = Self(1);
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExitTopologyChanged(pub TaskKey);

/// Updated only by an admitted membership publication under the registry guard.
#[derive(Debug)]
pub struct ExitParticipantRevision {
    task: TaskKey,
    revision: AtomicU64,
}

impl ExitParticipantRevision {
    pub fn capture(task: TaskKey, revision: TaskRevision) -> Self {
        Self {
            task,
            revision: AtomicU64::new(revision.raw()),
        }
    }
    pub fn validate(
        &self,
        task: TaskKey,
        current: TaskRevision,
    ) -> Result<(), ExitTopologyChanged> {
        if self.task != task || self.revision.load(Ordering::Relaxed) != current.raw() {
            return Err(ExitTopologyChanged(self.task));
        }
        Ok(())
    }
    pub fn prepare_membership(
        self: &Arc<Self>,
        task: TaskKey,
        current: TaskRevision,
        next: TaskRevision,
    ) -> Result<PreparedExitMembershipRevision, ExitTopologyChanged> {
        self.validate(task, current)?;
        if current.next() != Some(next) {
            return Err(ExitTopologyChanged(self.task));
        }
        Ok(PreparedExitMembershipRevision {
            participant: Arc::clone(self),
            next,
        })
    }
}

/// Affine publication admitted before irreversible thread work.
pub struct PreparedExitMembershipRevision {
    participant: Arc<ExitParticipantRevision>,
    next: TaskRevision,
}

/// One owned topology publication credit retained across live membership work.
#[derive(Debug)]
pub struct PreparedExitParticipant<Credit> {
    revision: Arc<ExitParticipantRevision>,
    publication: Credit,
}
impl<Credit> PreparedExitParticipant<Credit> {
    pub fn reserve(task: TaskKey, current: TaskRevision, publication: Credit) -> Self {
        Self {
            revision: Arc::new(ExitParticipantRevision::capture(task, current)),
            publication,
        }
    }
    pub fn revision(&self) -> Arc<ExitParticipantRevision> {
        Arc::clone(&self.revision)
    }
    /// The consumer consumes its preadmitted capacity under the registry guard.
    /// It does not choose a captured successor: publication advances the live
    /// revision after every intervening admitted membership transition.
    pub fn publish(
        mut self,
        current: TaskRevision,
        consume: impl FnOnce(&mut Credit, TaskRevision) -> TaskRevision,
    ) -> TaskRevision {
        let next = consume(&mut self.publication, current);
        self.revision.revision.store(next.raw(), Ordering::Relaxed);
        next
    }
}
impl PreparedExitMembershipRevision {
    pub fn publish(self) {
        self.participant
            .revision
            .store(self.next.raw(), Ordering::Relaxed);
    }
}

use super::registry::{ProcessRegistry, RegistryFailure};
use super::wait::WaitIdentitySource;
use super::{ChildExitSignal, TaskId, TaskLifecycle};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

/// Borrowed resource accesses to the registry's sole live payload.
pub trait ExitLive<C>: WaitIdentitySource {
    type Credit;
    type Error;
    fn exit_container(&self) -> C;
    fn exit_lifecycle(&self) -> TaskLifecycle;
    fn exit_children(&self) -> BTreeSet<TaskKey>;
    fn exit_autoreaps(&self) -> bool;
    fn exit_revision(&self) -> TaskRevision;
    fn exit_reserve_credit(&self) -> Result<Self::Credit, Self::Error>;
}
pub trait ExitZombie {
    fn exit_key(&self) -> TaskKey;
}

#[derive(Debug)]
pub enum ExitError<E> {
    Unknown(TaskId),
    Stale(TaskId),
    Busy(TaskId),
    AlreadyExiting(TaskId),
    Topology(TaskId),
    Resource(E),
}

/// Topology and capacity admission from one registry snapshot. The consumer
/// attaches its transaction reservation before releasing the registry guard.
#[derive(Debug)]
pub struct PreparedExitTopology<Credit> {
    task_revision: Arc<ExitParticipantRevision>,
    children: Vec<TaskKey>,
    reserved_ids: BTreeSet<TaskId>,
    affected_revisions: BTreeMap<TaskId, PreparedExitParticipant<Credit>>,
    adopter: Option<TaskKey>,
    autoreap_parent: Option<TaskKey>,
    prepared_adopter_children: Option<BTreeSet<TaskKey>>,
    prepared_parent_children: Option<BTreeSet<TaskKey>>,
    namespace_init: Option<TaskKey>,
}

impl<Credit> PreparedExitTopology<Credit> {
    pub fn task_revision(&self) -> Arc<ExitParticipantRevision> {
        Arc::clone(&self.task_revision)
    }
    pub fn reserved_ids(&self) -> &BTreeSet<TaskId> {
        &self.reserved_ids
    }
    pub fn participants(&self) -> &BTreeMap<TaskId, PreparedExitParticipant<Credit>> {
        &self.affected_revisions
    }
    pub fn adopter(&self) -> Option<TaskKey> {
        self.adopter
    }
    pub fn autoreap_parent(&self) -> Option<TaskKey> {
        self.autoreap_parent
    }
    pub fn namespace_init(&self) -> Option<TaskKey> {
        self.namespace_init
    }
}

impl<
    C: Copy + Ord,
    L: ExitLive<C>,
    Z: ExitZombie,
    R,
    Reservation,
    Retired,
    Group,
    Session,
    Failure: RegistryFailure,
> ProcessRegistry<C, L, Z, R, Reservation, Retired, Group, Session, Failure>
{
    pub fn prepare_exit_topology(
        &self,
        task_key: TaskKey,
        explicit_adopter: Option<TaskKey>,
    ) -> Result<PreparedExitTopology<L::Credit>, ExitError<L::Error>> {
        let available = |id| {
            if self.reservations.contains_key(&id) {
                Err(ExitError::Busy(id))
            } else {
                Ok(())
            }
        };
        available(task_key.id)?;
        let task = self
            .tasks
            .get(&task_key.id)
            .ok_or(ExitError::Unknown(task_key.id))?;
        if task.wait_identity().key != task_key {
            return Err(ExitError::Stale(task_key.id));
        }
        if task.exit_lifecycle() == TaskLifecycle::Exiting {
            return Err(ExitError::AlreadyExiting(task_key.id));
        }
        if self.zombies.contains_key(&task_key.id) {
            return Err(ExitError::Topology(task_key.id));
        }
        let identity = task.wait_identity();
        let exact_live = |key: TaskKey| {
            self.tasks.get(&key.id).filter(|record| {
                record.wait_identity().key == key && record.exit_lifecycle() == TaskLifecycle::Live
            })
        };
        let adopter = if let Some(key) = explicit_adopter {
            let record = self.tasks.get(&key.id).ok_or(ExitError::Unknown(key.id))?;
            if record.wait_identity().key != key {
                return Err(ExitError::Stale(key.id));
            }
            if record.exit_lifecycle() != TaskLifecycle::Live {
                return Err(ExitError::Unknown(key.id));
            }
            let mut ancestor = identity.parent;
            let mut authenticated = false;
            while let Some(candidate) = ancestor {
                if candidate == key {
                    authenticated = true;
                    break;
                }
                let record = self
                    .tasks
                    .get(&candidate.id)
                    .filter(|record| record.wait_identity().key == candidate)
                    .ok_or(ExitError::Topology(candidate.id))?;
                ancestor = record.wait_identity().parent;
            }
            if !authenticated {
                return Err(ExitError::Topology(key.id));
            }
            Some(key)
        } else {
            self.container_inits
                .get(&task.exit_container())
                .copied()
                .filter(|key| *key != task_key && exact_live(*key).is_some())
        };
        let namespace_init = self
            .container_inits
            .get(&task.exit_container())
            .copied()
            .filter(|key| *key == task_key || exact_live(*key).is_some());
        let mut children: Vec<_> = task.exit_children().into_iter().collect();
        children.sort_by_key(|child| child.serial);
        let adopter = adopter.filter(|_| !children.is_empty());
        let mut reserved_ids = BTreeSet::from([task_key.id]);
        let mut affected_revisions = BTreeMap::new();
        let reserve = |record: &L| {
            let identity = record.wait_identity();
            record
                .exit_reserve_credit()
                .map(|credit| {
                    PreparedExitParticipant::reserve(identity.key, record.exit_revision(), credit)
                })
                .map_err(ExitError::Resource)
        };
        for child in &children {
            available(child.id)?;
            reserved_ids.insert(child.id);
            if let Some(record) = self.tasks.get(&child.id) {
                if record.wait_identity().key != *child {
                    return Err(ExitError::Topology(child.id));
                }
                affected_revisions.insert(child.id, reserve(record)?);
            } else if self
                .zombies
                .get(&child.id)
                .is_none_or(|record| record.exit_key() != *child)
            {
                return Err(ExitError::Topology(child.id));
            }
        }
        let autoreap_parent = identity.parent.filter(|parent| {
            identity.exit_signal == ChildExitSignal::SIGCHLD
                && self.tasks.get(&parent.id).is_some_and(|record| {
                    record.wait_identity().key == *parent && record.exit_autoreaps()
                })
        });
        let prepared_adopter_children = if let Some(key) = adopter {
            available(key.id)?;
            reserved_ids.insert(key.id);
            let record = self
                .tasks
                .get(&key.id)
                .filter(|record| record.wait_identity().key == key)
                .ok_or(ExitError::Topology(key.id))?;
            affected_revisions.insert(key.id, reserve(record)?);
            let mut prepared = record.exit_children();
            if autoreap_parent == Some(key) {
                prepared.remove(&task_key);
            }
            prepared.extend(children.iter().copied());
            Some(prepared)
        } else {
            None
        };
        let prepared_parent_children =
            if let Some(key) = autoreap_parent.filter(|key| Some(*key) != adopter) {
                available(key.id)?;
                reserved_ids.insert(key.id);
                let record = self
                    .tasks
                    .get(&key.id)
                    .filter(|record| record.wait_identity().key == key)
                    .ok_or(ExitError::Topology(key.id))?;
                affected_revisions.insert(key.id, reserve(record)?);
                let mut prepared = record.exit_children();
                prepared.remove(&task_key);
                Some(prepared)
            } else {
                None
            };
        Ok(PreparedExitTopology {
            task_revision: Arc::new(ExitParticipantRevision::capture(
                task_key,
                task.exit_revision(),
            )),
            children,
            reserved_ids,
            affected_revisions,
            adopter,
            autoreap_parent,
            prepared_adopter_children,
            prepared_parent_children,
            namespace_init,
        })
    }
}

pub trait ExitLivePublication<C>: ExitLive<C> {
    fn exit_reparent(&mut self, parent: Option<TaskKey>);
    fn exit_publish_children(&mut self, children: BTreeSet<TaskKey>);
    fn exit_publish_credit(&mut self, participant: PreparedExitParticipant<Self::Credit>);
}
pub trait ExitZombiePublication: ExitZombie {
    fn exit_reparent(&mut self, parent: Option<TaskKey>);
}
impl<
    C: Copy + Ord,
    L: ExitLive<C>,
    Z: ExitZombie,
    R,
    Reservation,
    Retired,
    Group,
    Session,
    Failure: RegistryFailure,
> ProcessRegistry<C, L, Z, R, Reservation, Retired, Group, Session, Failure>
{
    pub fn validate_exit_topology(
        &self,
        task: TaskKey,
        plan: &PreparedExitTopology<L::Credit>,
    ) -> Result<(), ExitError<L::Error>> {
        let record = self
            .tasks
            .get(&task.id)
            .ok_or(ExitError::Unknown(task.id))?;
        plan.task_revision
            .validate(record.wait_identity().key, record.exit_revision())
            .map_err(|error| ExitError::Topology(error.0.id))?;
        for (id, participant) in &plan.affected_revisions {
            let record = self.tasks.get(id).ok_or(ExitError::Topology(*id))?;
            participant
                .revision()
                .validate(record.wait_identity().key, record.exit_revision())
                .map_err(|error| ExitError::Topology(error.0.id))?;
        }
        for child in &plan.children {
            let live = self
                .tasks
                .get(&child.id)
                .is_some_and(|record| record.wait_identity().key == *child);
            let dead = self
                .zombies
                .get(&child.id)
                .is_some_and(|record| record.exit_key() == *child);
            if !live && !dead {
                return Err(ExitError::Topology(child.id));
            }
        }
        Ok(())
    }
}
impl<
    C: Copy + Ord,
    L: ExitLivePublication<C>,
    Z: ExitZombiePublication,
    R,
    Reservation,
    Retired,
    Group,
    Session,
    Failure: RegistryFailure,
> ProcessRegistry<C, L, Z, R, Reservation, Retired, Group, Session, Failure>
{
    /// Infallible after validation under the same write guard, before retiring
    /// publication. Resource adapters cannot select a different parent/child.
    pub fn publish_exit_topology(&mut self, plan: &mut PreparedExitTopology<L::Credit>) {
        for child in &plan.children {
            if let Some(record) = self.tasks.get_mut(&child.id) {
                record.exit_reparent(plan.adopter);
            } else if let Some(record) = self.zombies.get_mut(&child.id) {
                record.exit_reparent(plan.adopter);
            }
        }
        if let (Some(key), Some(children)) = (plan.adopter, plan.prepared_adopter_children.take())
            && let Some(record) = self.tasks.get_mut(&key.id)
        {
            record.exit_publish_children(children);
        }
        if let (Some(key), Some(children)) =
            (plan.autoreap_parent, plan.prepared_parent_children.take())
            && let Some(record) = self.tasks.get_mut(&key.id)
        {
            record.exit_publish_children(children);
        }
        for (id, participant) in core::mem::take(&mut plan.affected_revisions) {
            if let Some(record) = self.tasks.get_mut(&id) {
                record.exit_publish_credit(participant);
            }
        }
    }
}

#[derive(Debug)]
pub struct TaskGraphReservation<Transaction> {
    transaction: Transaction,
    incarnation: Arc<TaskReservationIncarnation>,
    scope: TaskReservationScope,
}
#[derive(Debug)]
enum TaskReservationScope {
    Exclusive,
    ExitParticipant(Arc<ExitParticipantRevision>),
}
impl<Transaction: Copy> TaskGraphReservation<Transaction> {
    pub fn exclusive(transaction: Transaction) -> Self {
        Self::with_incarnation(transaction, Arc::new(TaskReservationIncarnation))
    }
    fn with_incarnation(
        transaction: Transaction,
        incarnation: Arc<TaskReservationIncarnation>,
    ) -> Self {
        Self {
            transaction,
            incarnation,
            scope: TaskReservationScope::Exclusive,
        }
    }
    pub fn transaction(&self) -> Transaction {
        self.transaction
    }
    pub fn permits_nonfinal_thread_exit(&self) -> bool {
        matches!(self.scope, TaskReservationScope::ExitParticipant(_))
    }
    /// New process topology needs an exclusive admission. A live exit
    /// participant retains its already-admitted thread membership work only.
    pub fn permits_process_birth(&self) -> bool {
        matches!(self.scope, TaskReservationScope::Exclusive)
    }
    pub fn prepare_membership_revision(
        &self,
        task: TaskKey,
        current: TaskRevision,
        next: TaskRevision,
    ) -> Result<Option<PreparedExitMembershipRevision>, ExitTopologyChanged> {
        match &self.scope {
            TaskReservationScope::Exclusive => Ok(None),
            TaskReservationScope::ExitParticipant(revision) => {
                revision.prepare_membership(task, current, next).map(Some)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskSetError {
    Busy(TaskId),
    Stale,
}
#[derive(Debug)]
pub struct ReservedTaskSet<Transaction> {
    task_ids: Vec<TaskId>,
    incarnation: Arc<TaskReservationIncarnation>,
    transaction: Transaction,
}
impl<Transaction> ReservedTaskSet<Transaction> {
    /// Coverage is meaningful only after the registry has authenticated this
    /// permit's transaction and opaque incarnation with `validate_task_set`.
    pub fn covers(&self, task: TaskId) -> bool {
        self.task_ids.contains(&task)
    }
}
impl<
    C: Copy + Ord,
    L,
    Z,
    R,
    Transaction: Copy + Eq,
    Retired,
    Group,
    Session,
    Failure: RegistryFailure,
> ProcessRegistry<C, L, Z, R, TaskGraphReservation<Transaction>, Retired, Group, Session, Failure>
{
    pub fn reserve_task_set(
        &mut self,
        mut task_ids: Vec<TaskId>,
        transaction: Transaction,
    ) -> Result<ReservedTaskSet<Transaction>, TaskSetError> {
        task_ids.sort_unstable();
        task_ids.dedup();
        for id in &task_ids {
            if self.reservations.contains_key(id) {
                return Err(TaskSetError::Busy(*id));
            }
        }
        let incarnation = Arc::new(TaskReservationIncarnation);
        for id in &task_ids {
            self.reservations.insert(
                *id,
                TaskGraphReservation::with_incarnation(transaction, Arc::clone(&incarnation)),
            );
        }
        Ok(ReservedTaskSet {
            task_ids,
            incarnation,
            transaction,
        })
    }
    pub fn validate_task_set(
        &self,
        permit: &ReservedTaskSet<Transaction>,
    ) -> Result<(), TaskSetError> {
        if permit.task_ids.iter().all(|id| {
            self.reservations.get(id).is_some_and(|row| {
                row.transaction == permit.transaction
                    && Arc::ptr_eq(&row.incarnation, &permit.incarnation)
            })
        }) {
            Ok(())
        } else {
            Err(TaskSetError::Stale)
        }
    }
    pub fn release_task_set(
        &mut self,
        permit: &ReservedTaskSet<Transaction>,
    ) -> Result<ReleasedTaskSet<Transaction>, TaskSetError> {
        self.validate_task_set(permit)?;
        for id in &permit.task_ids {
            self.reservations.remove(id);
        }
        Ok(ReleasedTaskSet {
            transaction: permit.transaction,
            incarnation: Arc::clone(&permit.incarnation),
            task_ids: permit.task_ids.clone(),
        })
    }
    /// Rollback releases only identities still owned by this transaction.
    pub fn rollback_task_set(&mut self, permit: &ReservedTaskSet<Transaction>) -> bool {
        let mut changed = false;
        for id in &permit.task_ids {
            if self.reservations.get(id).is_some_and(|row| {
                row.transaction == permit.transaction
                    && Arc::ptr_eq(&row.incarnation, &permit.incarnation)
            }) {
                self.reservations.remove(id);
                changed = true;
            }
        }
        changed
    }
}

pub trait ExitRetiring {
    fn exit_key(&self) -> TaskKey;
}
#[derive(Debug)]
pub struct ExitReceiptPublication<Retiring, Receipt> {
    pub retiring: Retiring,
    /// Keep an autoreaped resource receipt alive until the consumer releases
    /// its graph guard; its retained numeric claim is a resource, not policy.
    pub autoreaped_receipt: Option<Receipt>,
}
impl<
    C: Copy + Ord,
    L: ExitLive<C>,
    Z: ExitZombie,
    R: ExitRetiring,
    Reservation,
    Retired,
    Group,
    Session,
    Failure: RegistryFailure,
> ProcessRegistry<C, L, Z, R, Reservation, Retired, Group, Session, Failure>
{
    pub fn publish_exit_receipt(
        &mut self,
        task: TaskKey,
        plan: &PreparedExitTopology<L::Credit>,
        receipt: Z,
        group: super::ProcessGroupId,
        session: super::SessionId,
    ) -> Result<ExitReceiptPublication<R, Z>, ExitTopologyChanged> {
        if receipt.exit_key() != task
            || plan.task_revision.task != task
            || self
                .retiring_tasks
                .get(&task.id)
                .is_none_or(|record| record.exit_key() != task)
        {
            return Err(ExitTopologyChanged(task));
        }
        let retiring = self
            .retiring_tasks
            .remove(&task.id)
            .ok_or(ExitTopologyChanged(task))?;
        let autoreaped_receipt = if plan.autoreap_parent.is_some() {
            self.remove_group_member(group, session, task);
            Some(receipt)
        } else {
            self.zombies.insert(task.id, receipt);
            None
        };
        Ok(ExitReceiptPublication {
            retiring,
            autoreaped_receipt,
        })
    }
}

/// Proof that the owner released this exact reservation set. Only a successful
/// release constructs it; transport publication occurs before its consumption.
#[derive(Debug)]
pub struct ReleasedTaskSet<Transaction> {
    transaction: Transaction,
    incarnation: Arc<TaskReservationIncarnation>,
    task_ids: Vec<TaskId>,
}

pub trait ExitMember {
    fn exit_task(&self) -> TaskKey;
}
pub trait ExitEffectSource<C>: ExitLive<C> {
    type Member: ExitMember;
    type Resources;
    fn exit_members(&self) -> (Vec<Self::Member>, Self::Resources);
    fn exit_begin(&self) -> bool;
}

/// Cancellation targets are inaccessible until matching topology release.
pub struct PendingExitEffects<Member, Resources, Transaction> {
    task: TaskKey,
    transaction: Transaction,
    incarnation: Arc<TaskReservationIncarnation>,
    resources: Option<Resources>,
    members: Vec<Member>,
    parent: Option<TaskKey>,
    signal: ChildExitSignal,
}
/// Owned admission result shared by every execution-lane consumer.
pub type ExitEffectAdmission<C, L, Transaction> = Result<
    PendingExitEffects<
        <L as ExitEffectSource<C>>::Member,
        <L as ExitEffectSource<C>>::Resources,
        Transaction,
    >,
    ExitError<<L as ExitLive<C>>::Error>,
>;
pub struct ReadyExitEffects<Member> {
    members: Vec<Member>,
    parent: Option<TaskKey>,
    signal: ChildExitSignal,
}
pub struct ExitParentPermit {
    parent: Option<TaskKey>,
    signal: ChildExitSignal,
}
impl<Member, Resources, Transaction: Eq> PendingExitEffects<Member, Resources, Transaction> {
    pub fn take_resources(&mut self) -> Option<Resources> {
        self.resources.take()
    }
    pub fn after_release(
        self,
        release: ReleasedTaskSet<Transaction>,
    ) -> Result<ReadyExitEffects<Member>, ExitTopologyChanged> {
        if self.transaction != release.transaction
            || !Arc::ptr_eq(&self.incarnation, &release.incarnation)
            || !release.task_ids.contains(&self.task.id)
        {
            return Err(ExitTopologyChanged(self.task));
        }
        Ok(ReadyExitEffects {
            members: self.members,
            parent: self.parent,
            signal: self.signal,
        })
    }
}
impl<Member> ReadyExitEffects<Member> {
    /// Parent notification authority is published only after member cancellation.
    pub fn cancel_members(self, mut cancel: impl FnMut(Member)) -> ExitParentPermit {
        for member in self.members {
            cancel(member);
        }
        ExitParentPermit {
            parent: self.parent,
            signal: self.signal,
        }
    }
}
impl ExitParentPermit {
    pub fn parent(&self) -> Option<TaskKey> {
        self.parent
    }
    pub fn signal(&self) -> ChildExitSignal {
        self.signal
    }
}
impl<
    C: Copy + Ord,
    L: ExitEffectSource<C>,
    Z: ExitZombie,
    R,
    Transaction: Copy + Eq,
    Retired,
    Group,
    Session,
    Failure: RegistryFailure,
> ProcessRegistry<C, L, Z, R, TaskGraphReservation<Transaction>, Retired, Group, Session, Failure>
{
    pub fn begin_exit_effects(
        &self,
        task: TaskKey,
        plan: &PreparedExitTopology<L::Credit>,
        permit: &ReservedTaskSet<Transaction>,
    ) -> ExitEffectAdmission<C, L, Transaction> {
        if task != plan.task_revision.task {
            return Err(ExitError::Topology(task.id));
        }
        self.validate_task_set(permit)
            .map_err(|_| ExitError::Topology(task.id))?;
        if plan
            .reserved_ids
            .iter()
            .any(|id| !permit.task_ids.contains(id))
            || !matches!(self.reservations.get(&task.id).map(|row| &row.scope),
                Some(TaskReservationScope::ExitParticipant(revision))
                    if Arc::ptr_eq(revision, &plan.task_revision))
            || plan.affected_revisions.iter().any(|(id, participant)| {
                !matches!(self.reservations.get(id).map(|row| &row.scope),
                    Some(TaskReservationScope::ExitParticipant(revision))
                        if Arc::ptr_eq(revision, &participant.revision))
            })
        {
            return Err(ExitError::Topology(task.id));
        }
        self.validate_exit_topology(task, plan)?;
        let record = self
            .tasks
            .get(&task.id)
            .ok_or(ExitError::Unknown(task.id))?;
        if record.exit_lifecycle() != TaskLifecycle::Live {
            return Err(ExitError::Topology(task.id));
        }
        let identity = record.wait_identity();
        let (members, resources) = record.exit_members();
        if members.iter().any(|member| member.exit_task() != task) {
            return Err(ExitError::Topology(task.id));
        }
        if !record.exit_begin() {
            return Err(ExitError::AlreadyExiting(task.id));
        }
        Ok(PendingExitEffects {
            task,
            transaction: permit.transaction,
            incarnation: Arc::clone(&permit.incarnation),
            resources: Some(resources),
            members,
            parent: identity.parent,
            signal: identity.exit_signal,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitSignalDisposition {
    Default,
    Ignore,
    Caught,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExitSignalState {
    pub disposition: ExitSignalDisposition,
    pub blocked: bool,
}
impl ExitSignalState {
    pub fn needs_notification(self, signal: super::LinuxSignal) -> bool {
        match self.disposition {
            ExitSignalDisposition::Ignore => false,
            ExitSignalDisposition::Caught => true,
            ExitSignalDisposition::Default => {
                self.blocked
                    || !matches!(
                        carrick_signal_core::policy::Signal::from_number(signal.raw())
                            .map(carrick_signal_core::policy::default_delivery),
                        Some(carrick_signal_core::policy::Delivery::Ignore)
                    )
            }
        }
    }
}
pub trait ExitSignalSource {
    fn exit_signal_state(&self, signal: super::LinuxSignal) -> ExitSignalState;
}
pub trait ExitNotificationSource {
    type Target: ExitSignalSource;
    fn exit_notification_target(&self) -> Self::Target;
}
pub struct ExitParentTarget<Target> {
    parent: TaskKey,
    signal: ChildExitSignal,
    payload: Target,
}
pub struct ExitParentNotification<Target> {
    pub parent: TaskKey,
    pub signal: Option<super::LinuxSignal>,
    pub payload: Target,
}
impl<Target: ExitSignalSource> ExitParentTarget<Target> {
    /// Snapshot signal locks only after releasing the registry guard. The
    /// retained exact parent handle preserves the consumer's resource lifetime.
    pub fn prepare(self) -> ExitParentNotification<Target> {
        let signal = match self.signal {
            ChildExitSignal::Signal(signal)
                if self
                    .payload
                    .exit_signal_state(signal)
                    .needs_notification(signal) =>
            {
                Some(signal)
            }
            _ => None,
        };
        ExitParentNotification {
            parent: self.parent,
            signal,
            payload: self.payload,
        }
    }
}
impl<
    C: Copy + Ord,
    L: WaitIdentitySource + ExitNotificationSource,
    Z,
    R,
    Reservation,
    Retired,
    Group,
    Session,
    Failure: RegistryFailure,
> ProcessRegistry<C, L, Z, R, Reservation, Retired, Group, Session, Failure>
{
    pub fn select_exit_parent(
        &self,
        permit: &ExitParentPermit,
    ) -> Option<ExitParentTarget<L::Target>> {
        let parent = permit.parent?;
        let record = self
            .tasks
            .get(&parent.id)
            .filter(|record| record.wait_identity().key == parent)?;
        Some(ExitParentTarget {
            parent,
            signal: permit.signal,
            payload: record.exit_notification_target(),
        })
    }
}

#[derive(Debug)]
struct TaskReservationIncarnation;

impl<
    C: Copy + Ord,
    L: ExitLive<C>,
    Z,
    R,
    Transaction: Copy + Eq,
    Retired,
    Group,
    Session,
    Failure: RegistryFailure,
> ProcessRegistry<C, L, Z, R, TaskGraphReservation<Transaction>, Retired, Group, Session, Failure>
{
    pub fn bind_exit_participants(
        &mut self,
        permit: &ReservedTaskSet<Transaction>,
        plan: &PreparedExitTopology<L::Credit>,
    ) -> Result<(), TaskSetError> {
        self.validate_task_set(permit)?;
        let task = plan.task_revision.task;
        if !permit.task_ids.contains(&task.id)
            || plan
                .affected_revisions
                .keys()
                .any(|id| !permit.task_ids.contains(id))
        {
            return Err(TaskSetError::Stale);
        }
        if let Some(row) = self.reservations.get_mut(&task.id) {
            row.scope = TaskReservationScope::ExitParticipant(Arc::clone(&plan.task_revision));
        }
        for (id, participant) in &plan.affected_revisions {
            if let Some(row) = self.reservations.get_mut(id) {
                row.scope = TaskReservationScope::ExitParticipant(participant.revision());
            }
        }
        Ok(())
    }
}

impl<
    C: Copy + Ord,
    L: ExitLive<C>,
    Z,
    R,
    Transaction: Copy + Eq,
    Retired,
    Group,
    Session,
    Failure: RegistryFailure,
> ProcessRegistry<C, L, Z, R, TaskGraphReservation<Transaction>, Retired, Group, Session, Failure>
{
    pub fn reserve_exit_task_set(
        &mut self,
        plan: &PreparedExitTopology<L::Credit>,
        transaction: Transaction,
    ) -> Result<ReservedTaskSet<Transaction>, TaskSetError> {
        let permit =
            self.reserve_task_set(plan.reserved_ids.iter().copied().collect(), transaction)?;
        if let Err(error) = self.bind_exit_participants(&permit, plan) {
            self.rollback_task_set(&permit);
            return Err(error);
        }
        Ok(permit)
    }
}
