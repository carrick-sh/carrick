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
    scope: TaskReservationScope,
}
#[derive(Debug)]
enum TaskReservationScope {
    Exclusive,
    ExitParticipant(Arc<ExitParticipantRevision>),
}
impl<Transaction: Copy> TaskGraphReservation<Transaction> {
    pub fn exclusive(transaction: Transaction) -> Self {
        Self {
            transaction,
            scope: TaskReservationScope::Exclusive,
        }
    }
    pub fn transaction(&self) -> Transaction {
        self.transaction
    }
    pub fn exit_participant(
        transaction: Transaction,
        revision: Arc<ExitParticipantRevision>,
    ) -> Self {
        Self {
            transaction,
            scope: TaskReservationScope::ExitParticipant(revision),
        }
    }
    pub fn permits_nonfinal_thread_exit(&self) -> bool {
        matches!(self.scope, TaskReservationScope::ExitParticipant(_))
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
    transaction: Transaction,
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
        for id in &task_ids {
            self.reservations
                .insert(*id, TaskGraphReservation::exclusive(transaction));
        }
        Ok(ReservedTaskSet {
            task_ids,
            transaction,
        })
    }
    pub fn validate_task_set(
        &self,
        permit: &ReservedTaskSet<Transaction>,
    ) -> Result<(), TaskSetError> {
        if permit.task_ids.iter().all(|id| {
            self.reservations
                .get(id)
                .map(TaskGraphReservation::transaction)
                == Some(permit.transaction)
        }) {
            Ok(())
        } else {
            Err(TaskSetError::Stale)
        }
    }
    pub fn release_task_set(
        &mut self,
        permit: &ReservedTaskSet<Transaction>,
    ) -> Result<(), TaskSetError> {
        self.validate_task_set(permit)?;
        for id in &permit.task_ids {
            self.reservations.remove(id);
        }
        Ok(())
    }
    /// Rollback releases only identities still owned by this transaction.
    pub fn rollback_task_set(&mut self, permit: &ReservedTaskSet<Transaction>) -> bool {
        let mut changed = false;
        for id in &permit.task_ids {
            if self
                .reservations
                .get(id)
                .map(TaskGraphReservation::transaction)
                == Some(permit.transaction)
            {
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
