//! Guard-retained process publication in the sole process registry.
use super::exit::{ReservedTaskSet, TaskGraphReservation, TaskRevision};
use super::registry::{ProcessRegistry, RegistryFailure, RegistryInvariant};
use super::wait::{WaitIdentity, WaitIdentitySource};
use super::{SessionId, TaskId, TaskKey, TaskLifecycle};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BirthSnapshot {
    pub key: TaskKey,
    pub revision: TaskRevision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BirthAttachment {
    Parent,
    ExternalPeerRoot,
}

pub trait BirthLive: WaitIdentitySource {
    type Error;
    fn birth_lifecycle(&self) -> TaskLifecycle;
    fn birth_revision(&self) -> TaskRevision;
    fn birth_session(&self) -> SessionId;
    fn birth_prepare_parent_revision(&self) -> Result<TaskRevision, Self::Error>;
    fn birth_publish_child(&mut self, child: TaskKey, revision: TaskRevision);
}

#[derive(Debug, Eq, PartialEq)]
pub enum BirthError<E> {
    CallerGone,
    CallerRevision,
    ParentGone,
    ParentRevision,
    Reservation,
    Busy(TaskId),
    Collision(TaskId),
    IdentityMissing,
    ParentMismatch,
    Resource(E),
}

type BirthRegistry<C, L, Z, R, T, Retired, Group, Session, Failure> =
    ProcessRegistry<C, L, Z, R, TaskGraphReservation<T>, Retired, Group, Session, Failure>;

/// Exclusive registry custody spans validation, resource publication and the
/// infallible parent/identity/live-row publication. Dropping it publishes nothing.
#[must_use = "publish the admitted child or release registry custody without publication"]
pub struct AdmittedProcessBirth<'a, C, L, Z, R, T, Retired, Group, Session, Failure> {
    owner: &'a mut BirthRegistry<C, L, Z, R, T, Retired, Group, Session, Failure>,
    child: WaitIdentity,
    session: SessionId,
    parent: TaskKey,
    attachment: BirthAttachment,
    parent_revision: TaskRevision,
}

impl<
    C: Copy + Ord,
    L: BirthLive,
    Z,
    R,
    T: Copy + Eq,
    Retired,
    Group,
    Session,
    Failure: RegistryFailure,
> BirthRegistry<C, L, Z, R, T, Retired, Group, Session, Failure>
{
    /// Authenticate and retain the one registry write admission. Existing
    /// process-fork reservations must still belong to this exact incarnation;
    /// no thread-birth or exit-participant membership rule is changed here.
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    pub fn admit_process_birth(
        &mut self,
        caller: BirthSnapshot,
        parent: BirthSnapshot,
        child: WaitIdentity,
        session: SessionId,
        attachment: BirthAttachment,
        permit: Option<&ReservedTaskSet<T>>,
    ) -> Result<
        AdmittedProcessBirth<'_, C, L, Z, R, T, Retired, Group, Session, Failure>,
        BirthError<L::Error>,
    > {
        let caller_record = self
            .tasks
            .get(&caller.key.id)
            .ok_or(BirthError::CallerGone)?;
        if caller_record.wait_identity().key != caller.key
            || caller_record.birth_lifecycle() != TaskLifecycle::Live
        {
            return Err(BirthError::CallerGone);
        }
        if caller_record.birth_revision() != caller.revision {
            return Err(BirthError::CallerRevision);
        }
        let parent_record = self
            .tasks
            .get(&parent.key.id)
            .ok_or(BirthError::ParentGone)?;
        if parent_record.wait_identity().key != parent.key
            || parent_record.birth_lifecycle() != TaskLifecycle::Live
        {
            return Err(BirthError::ParentGone);
        }
        if parent_record.birth_revision() != parent.revision {
            return Err(BirthError::ParentRevision);
        }
        if let Some(permit) = permit {
            self.validate_task_set(permit)
                .map_err(|_| BirthError::Reservation)?;
            if !permit.covers(caller.key.id) || !permit.covers(parent.key.id) {
                return Err(BirthError::Reservation);
            }
        }
        for id in [caller.key.id, parent.key.id, child.key.id] {
            if let Some(reservation) = self.reservations.get(&id)
                && (permit.is_none_or(|permit| !permit.covers(id))
                    || !reservation.permits_process_birth())
            {
                return Err(BirthError::Busy(id));
            }
        }
        if self.tasks.contains_key(&child.key.id)
            || self.retiring_tasks.contains_key(&child.key.id)
            || self.zombies.contains_key(&child.key.id)
        {
            return Err(BirthError::Collision(child.key.id));
        }
        let expected_parent = match attachment {
            BirthAttachment::Parent => Some(parent.key),
            BirthAttachment::ExternalPeerRoot => None,
        };
        if child.parent != expected_parent {
            return Err(BirthError::ParentMismatch);
        }
        // Preserve the host's revision-capacity admission even for an external
        // peer root, whose parent revision is not subsequently published.
        let parent_revision = parent_record
            .birth_prepare_parent_revision()
            .map_err(BirthError::Resource)?;
        if !self.process_groups.contains_key(&child.group)
            || self
                .sessions
                .get(&session)
                .is_none_or(|record| !record.process_groups.contains(&child.group))
        {
            return Err(BirthError::IdentityMissing);
        }
        Ok(AdmittedProcessBirth {
            owner: self,
            child,
            session,
            parent: parent.key,
            attachment,
            parent_revision,
        })
    }
}

impl<C: Copy + Ord, L: BirthLive, Z, R, T, Retired, Group, Session, Failure: RegistryFailure>
    AdmittedProcessBirth<'_, C, L, Z, R, T, Retired, Group, Session, Failure>
{
    /// Infallible graph publication after the consumer commits its admitted
    /// resource custody. The exclusive registry borrow remains retained here.
    pub fn publish(self, child: L) {
        if child.wait_identity() != self.child || child.birth_session() != self.session {
            Failure::fail(RegistryInvariant::BirthPayloadMismatch);
        }
        if self.attachment == BirthAttachment::Parent {
            match self.owner.tasks.get_mut(&self.parent.id) {
                Some(parent) => parent.birth_publish_child(self.child.key, self.parent_revision),
                None => Failure::fail(RegistryInvariant::BirthPayloadMismatch),
            }
        }
        match self.owner.process_groups.get_mut(&self.child.group) {
            Some(group) => {
                group.members.insert(self.child.key);
            }
            None => Failure::fail(RegistryInvariant::BirthPayloadMismatch),
        }
        self.owner.tasks.insert(self.child.key.id, child);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::process::registry::{ProcessGroupRecord, SessionRecord};
    use crate::process::{
        ChildExitSignal, ProcessGroupId, ProcessRelations, SessionId, TaskSerial,
    };
    use alloc::collections::{BTreeMap, BTreeSet};
    use alloc::rc::Rc;
    use core::cell::Cell;
    use core::marker::PhantomData;

    struct Failure;
    impl RegistryFailure for Failure {
        fn fail(invariant: RegistryInvariant) -> ! {
            panic!("{invariant:?}")
        }
    }
    struct Live {
        identity: WaitIdentity,
        relations: ProcessRelations,
        revision: TaskRevision,
        lifecycle: TaskLifecycle,
        reads: Rc<Cell<usize>>,
        admissions: Rc<Cell<usize>>,
    }
    impl WaitIdentitySource for Live {
        fn wait_identity(&self) -> WaitIdentity {
            self.reads.set(self.reads.get() + 1);
            self.identity
        }
    }
    impl BirthLive for Live {
        type Error = ();
        fn birth_lifecycle(&self) -> TaskLifecycle {
            self.lifecycle
        }
        fn birth_revision(&self) -> TaskRevision {
            self.revision
        }
        fn birth_session(&self) -> SessionId {
            SessionId::from_abi_positive(1).unwrap()
        }
        fn birth_prepare_parent_revision(&self) -> Result<TaskRevision, ()> {
            self.admissions.set(self.admissions.get() + 1);
            self.revision.next().ok_or(())
        }
        fn birth_publish_child(&mut self, child: TaskKey, revision: TaskRevision) {
            self.relations.add_child(child);
            self.revision = revision;
        }
    }
    impl crate::process::exit::ExitLive<()> for Live {
        type Credit = ();
        type Error = ();
        fn exit_container(&self) {}
        fn exit_lifecycle(&self) -> TaskLifecycle {
            self.lifecycle
        }
        fn exit_children(&self) -> BTreeSet<TaskKey> {
            self.relations.children().clone()
        }
        fn exit_autoreaps(&self) -> bool {
            false
        }
        fn exit_revision(&self) -> TaskRevision {
            self.revision
        }
        fn exit_reserve_credit(&self) -> Result<(), ()> {
            Ok(())
        }
    }
    impl crate::process::exit::ExitZombie for TaskKey {
        fn exit_key(&self) -> TaskKey {
            *self
        }
    }
    type Registry = BirthRegistry<(), Live, TaskKey, TaskKey, u32, (), (), (), Failure>;
    fn key(id: i32, serial: u64) -> TaskKey {
        TaskKey {
            id: TaskId::from_abi_positive(id).unwrap(),
            serial: TaskSerial::from_raw_u64(serial).unwrap(),
        }
    }
    fn identity(task: TaskKey, parent: Option<TaskKey>) -> WaitIdentity {
        WaitIdentity {
            key: task,
            parent,
            tracer: None,
            group: ProcessGroupId::from_abi_positive(1).unwrap(),
            exit_signal: ChildExitSignal::SIGCHLD,
        }
    }
    fn live(task: TaskKey, parent: Option<TaskKey>) -> Live {
        Live {
            identity: identity(task, parent),
            relations: ProcessRelations::new(parent),
            revision: TaskRevision::INITIAL,
            lifecycle: TaskLifecycle::Live,
            reads: Rc::new(Cell::new(0)),
            admissions: Rc::new(Cell::new(0)),
        }
    }
    fn registry() -> Registry {
        let parent = key(1, 1);
        let group = ProcessGroupId::from_leader(parent.id);
        let mut owner = Registry {
            epoch: 1,
            container_inits: BTreeMap::new(),
            tasks: BTreeMap::new(),
            zombies: BTreeMap::new(),
            retiring_tasks: BTreeMap::new(),
            process_groups: BTreeMap::new(),
            process_group_by_namespace: BTreeMap::new(),
            reservations: BTreeMap::new(),
            retired_threads: (),
            sessions: BTreeMap::new(),
            session_by_namespace: BTreeMap::new(),
            failure: PhantomData,
        };
        owner.tasks.insert(parent.id, live(parent, None));
        owner.publish_process_group(
            group,
            ProcessGroupRecord {
                object: (),
                members: BTreeSet::from([parent]),
                container: (),
                namespace_id: 1,
            },
        );
        owner.publish_session(
            SessionId::from_leader(parent.id),
            SessionRecord {
                object: (),
                process_groups: BTreeSet::from([group]),
                container: (),
                namespace_id: 1,
            },
        );
        owner
    }
    fn snapshot(task: TaskKey) -> BirthSnapshot {
        BirthSnapshot {
            key: task,
            revision: TaskRevision::INITIAL,
        }
    }
    type Admission<'a> =
        AdmittedProcessBirth<'a, (), Live, TaskKey, TaskKey, u32, (), (), (), Failure>;
    fn admit<'a>(
        owner: &'a mut Registry,
        child: TaskKey,
        permit: Option<&ReservedTaskSet<u32>>,
    ) -> Result<Admission<'a>, BirthError<()>> {
        let parent = snapshot(key(1, 1));
        owner.admit_process_birth(
            parent,
            parent,
            identity(child, Some(parent.key)),
            SessionId::from_abi_positive(1).unwrap(),
            BirthAttachment::Parent,
            permit,
        )
    }
    #[test]
    fn admitted_birth_publishes_one_exact_row_parent_edge_group_and_revision() {
        let mut owner = registry();
        let parent = key(1, 1);
        let child = key(2, 2);
        {
            let _admission = admit(&mut owner, child, None).unwrap();
        }
        assert_eq!(owner.tasks.len(), 1);
        assert!(owner.tasks[&parent.id].relations.children().is_empty());
        assert_eq!(owner.tasks[&parent.id].revision.raw(), 1);
        admit(&mut owner, child, None)
            .unwrap()
            .publish(live(child, Some(parent)));
        assert_eq!(owner.tasks.len(), 2);
        assert_eq!(
            owner.tasks[&parent.id].relations.children(),
            &BTreeSet::from([child])
        );
        assert_eq!(owner.tasks[&parent.id].revision.raw(), 2);
        assert_eq!(
            owner.process_groups[&ProcessGroupId::from_leader(parent.id)].members,
            BTreeSet::from([parent, child])
        );
    }
    #[test]
    fn birth_authenticates_caller_and_selected_parent_exact_keys_and_revisions() {
        for changed in 0..4 {
            let mut owner = registry();
            let parent = key(1, 1);
            let mut caller = snapshot(parent);
            let mut selected = snapshot(parent);
            let expected = match changed {
                0 => {
                    caller.key.serial = TaskSerial::from_raw_u64(99).unwrap();
                    BirthError::CallerGone
                }
                1 => {
                    caller.revision = caller.revision.next().unwrap();
                    BirthError::CallerRevision
                }
                2 => {
                    selected.key.serial = TaskSerial::from_raw_u64(99).unwrap();
                    BirthError::ParentGone
                }
                _ => {
                    selected.revision = selected.revision.next().unwrap();
                    BirthError::ParentRevision
                }
            };
            assert_eq!(
                owner
                    .admit_process_birth(
                        caller,
                        selected,
                        identity(key(2, 2), Some(selected.key)),
                        SessionId::from_abi_positive(1).unwrap(),
                        BirthAttachment::Parent,
                        None
                    )
                    .err(),
                Some(expected)
            );
            assert_eq!(owner.tasks[&parent.id].admissions.get(), 0);
            assert_eq!(owner.tasks[&parent.id].revision.raw(), 1);
            assert!(owner.tasks[&parent.id].relations.children().is_empty());
        }
    }
    #[test]
    fn birth_reservation_requires_live_exact_incarnation_and_both_parent_ids() {
        let mut owner = registry();
        let parent = key(1, 1);
        let stale = owner.reserve_task_set(alloc::vec![parent.id], 7).unwrap();
        owner.release_task_set(&stale).unwrap();
        let current = owner.reserve_task_set(alloc::vec![parent.id], 7).unwrap();
        assert_eq!(
            admit(&mut owner, key(2, 2), Some(&stale)).err(),
            Some(BirthError::Reservation)
        );
        assert!(admit(&mut owner, key(2, 2), Some(&current)).is_ok());
        owner.release_task_set(&current).unwrap();
        let unrelated = owner
            .reserve_task_set(alloc::vec![key(500, 500).id], 7)
            .unwrap();
        assert_eq!(
            admit(&mut owner, key(2, 2), Some(&unrelated)).err(),
            Some(BirthError::Reservation)
        );
        owner.release_task_set(&unrelated).unwrap();
        assert_eq!(
            admit(&mut owner, key(2, 2), Some(&unrelated)).err(),
            Some(BirthError::Reservation)
        );
        let busy = owner.reserve_task_set(alloc::vec![parent.id], 8).unwrap();
        assert_eq!(
            admit(&mut owner, key(2, 2), None).err(),
            Some(BirthError::Busy(parent.id))
        );
        owner.release_task_set(&busy).unwrap();

        let caller = key(2, 2);
        let child = key(3, 3);
        owner.tasks.insert(caller.id, live(caller, Some(parent)));
        for reserved in [caller.id, parent.id] {
            let incomplete = owner.reserve_task_set(alloc::vec![reserved], 9).unwrap();
            assert_eq!(
                owner
                    .admit_process_birth(
                        snapshot(caller),
                        snapshot(parent),
                        identity(child, Some(parent)),
                        SessionId::from_leader(parent.id),
                        BirthAttachment::Parent,
                        Some(&incomplete),
                    )
                    .err(),
                Some(BirthError::Reservation),
            );
            owner.release_task_set(&incomplete).unwrap();
        }
        let complete = owner
            .reserve_task_set(alloc::vec![caller.id, parent.id], 9)
            .unwrap();
        let mut foreign_owner = registry();
        let foreign = foreign_owner
            .reserve_task_set(alloc::vec![caller.id, parent.id], 9)
            .unwrap();
        assert_eq!(
            owner
                .admit_process_birth(
                    snapshot(caller),
                    snapshot(parent),
                    identity(child, Some(parent)),
                    SessionId::from_leader(parent.id),
                    BirthAttachment::Parent,
                    Some(&foreign),
                )
                .err(),
            Some(BirthError::Reservation),
        );
        assert!(
            owner
                .admit_process_birth(
                    snapshot(caller),
                    snapshot(parent),
                    identity(child, Some(parent)),
                    SessionId::from_leader(parent.id),
                    BirthAttachment::Parent,
                    Some(&complete),
                )
                .is_ok()
        );
        owner.release_task_set(&complete).unwrap();
    }
    #[test]
    fn exit_participant_reservation_cannot_admit_a_new_process() {
        let mut owner = registry();
        let parent = key(1, 1);
        let plan = owner.prepare_exit_topology(parent, None).unwrap();
        let permit = owner.reserve_exit_task_set(&plan, 7).unwrap();
        assert_eq!(
            admit(&mut owner, key(2, 2), Some(&permit)).err(),
            Some(BirthError::Busy(parent.id)),
        );
        assert_eq!(owner.tasks.len(), 1);
        assert_eq!(owner.tasks[&parent.id].revision.raw(), 1);
        assert_eq!(owner.tasks[&parent.id].admissions.get(), 0);
        assert!(owner.tasks[&parent.id].relations.children().is_empty());
        owner.validate_exit_topology(parent, &plan).unwrap();
        owner.release_task_set(&permit).unwrap();
    }
    #[test]
    fn birth_collision_preserves_each_existing_population_and_parent_revision() {
        for population in 0..3 {
            let mut owner = registry();
            let existing = key(2, 99);
            match population {
                0 => {
                    owner.tasks.insert(existing.id, live(existing, None));
                }
                1 => {
                    owner.retiring_tasks.insert(existing.id, existing);
                }
                _ => {
                    owner.zombies.insert(existing.id, existing);
                }
            }
            assert_eq!(
                admit(&mut owner, key(2, 2), None).err(),
                Some(BirthError::Collision(existing.id))
            );
            assert_eq!(owner.tasks[&key(1, 1).id].revision.raw(), 1);
            assert_eq!(owner.tasks[&key(1, 1).id].admissions.get(), 0);
            match population {
                0 => assert_eq!(owner.tasks[&existing.id].identity.key, existing),
                1 => assert_eq!(owner.retiring_tasks[&existing.id], existing),
                _ => assert_eq!(owner.zombies[&existing.id], existing),
            }
        }
    }
    #[test]
    fn birth_needs_both_identity_objects_and_live_parents() {
        for missing in 0..3 {
            let mut owner = registry();
            if missing == 0 {
                owner.process_groups.clear();
            } else if missing == 1 {
                owner.sessions.clear();
            } else {
                owner
                    .sessions
                    .get_mut(&SessionId::from_abi_positive(1).unwrap())
                    .unwrap()
                    .process_groups
                    .clear();
            }
            assert_eq!(
                admit(&mut owner, key(2, 2), None).err(),
                Some(BirthError::IdentityMissing)
            );
            assert_eq!(owner.tasks[&key(1, 1).id].admissions.get(), 1);
        }
        let mut owner = registry();
        owner.tasks.get_mut(&key(1, 1).id).unwrap().lifecycle = TaskLifecycle::Exiting;
        assert_eq!(
            admit(&mut owner, key(2, 2), None).err(),
            Some(BirthError::CallerGone)
        );
    }
    #[test]
    fn external_peer_root_keeps_parent_children_and_revision_unchanged() {
        let mut owner = registry();
        let parent = key(1, 1);
        let child = key(2, 2);
        owner
            .admit_process_birth(
                snapshot(parent),
                snapshot(parent),
                identity(child, None),
                SessionId::from_abi_positive(1).unwrap(),
                BirthAttachment::ExternalPeerRoot,
                None,
            )
            .unwrap()
            .publish(live(child, None));
        assert!(owner.tasks[&parent.id].relations.children().is_empty());
        assert_eq!(owner.tasks[&parent.id].revision.raw(), 1);
        assert_eq!(owner.tasks[&parent.id].admissions.get(), 1);
        assert_eq!(owner.tasks[&child.id].identity.key, child);
    }
    #[test]
    fn admitted_birth_rejects_changed_payload_before_publishing_any_edge() {
        let mut owner = registry();
        let parent = key(1, 1);
        let child = key(2, 2);
        let admitted = admit(&mut owner, child, None).unwrap();
        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            admitted.publish(live(key(2, 99), Some(parent)));
        }));
        assert!(rejected.is_err());
        assert_eq!(owner.tasks.len(), 1);
        assert!(owner.tasks[&parent.id].relations.children().is_empty());
        assert_eq!(owner.tasks[&parent.id].revision.raw(), 1);
    }
    #[test]
    fn birth_work_does_not_visit_512_unrelated_rows() {
        let mut owner = registry();
        let mut counters = alloc::vec::Vec::new();
        for id in 1000..1512 {
            let row = live(key(id, id as u64), None);
            counters.push((row.reads.clone(), row.admissions.clone()));
            owner.tasks.insert(row.identity.key.id, row);
        }
        admit(&mut owner, key(2, 2), None)
            .unwrap()
            .publish(live(key(2, 2), Some(key(1, 1))));
        for (reads, admissions) in counters {
            assert_eq!((reads.get(), admissions.get()), (0, 0));
        }
    }
}
