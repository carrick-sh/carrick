//! The single live, retiring and zombie process population. Resource payloads
//! and fatal reporting belong to consumers; registry/index decisions do not.
use super::{ProcessGroupId, SessionId, TaskId, TaskKey};
use alloc::collections::{BTreeMap, BTreeSet};
use core::marker::PhantomData;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryInvariant {
    EpochExhausted,
    BirthPayloadMismatch,
    ProcessGroupCollision,
    ProcessGroupIndexLost,
    SessionCollision,
    SessionIndexLost,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
    struct Scope(u32);
    struct Failure;
    impl RegistryFailure for Failure {
        fn fail(invariant: RegistryInvariant) -> ! {
            panic!("{invariant:?}");
        }
    }
    type Registry = ProcessRegistry<Scope, (), (), (), (), (), (), (), Failure>;
    fn registry() -> Registry {
        Registry {
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
        }
    }

    #[test]
    fn equal_namespace_names_keep_distinct_group_and_session_custody() {
        let mut owner = registry();
        let a = ProcessGroupId::from_abi_positive(10).unwrap();
        let b = ProcessGroupId::from_abi_positive(11).unwrap();
        for (id, scope) in [(a, Scope(1)), (b, Scope(2))] {
            owner.publish_process_group(
                id,
                ProcessGroupRecord {
                    object: (),
                    members: BTreeSet::new(),
                    container: scope,
                    namespace_id: 1,
                },
            );
            owner.publish_session(
                SessionId::from_abi_positive(id.raw()).unwrap(),
                SessionRecord {
                    object: (),
                    process_groups: BTreeSet::from([id]),
                    container: scope,
                    namespace_id: 1,
                },
            );
        }
        owner.remove_process_group(a).unwrap();
        owner
            .remove_session(SessionId::from_abi_positive(a.raw()).unwrap())
            .unwrap();
        assert_eq!(
            owner.process_group_by_namespace.get(&(Scope(2), 1)),
            Some(&b)
        );
        assert_eq!(
            owner.session_by_namespace.get(&(Scope(2), 1)),
            Some(&SessionId::from_abi_positive(b.raw()).unwrap())
        );
        assert!(
            !owner
                .process_group_by_namespace
                .contains_key(&(Scope(1), 1))
        );
        assert!(!owner.session_by_namespace.contains_key(&(Scope(1), 1)));
    }

    #[test]
    fn namespace_collision_preserves_the_original_group() {
        let mut owner = registry();
        let a = ProcessGroupId::from_abi_positive(10).unwrap();
        let b = ProcessGroupId::from_abi_positive(11).unwrap();
        owner.publish_process_group(
            a,
            ProcessGroupRecord {
                object: (),
                members: BTreeSet::new(),
                container: Scope(1),
                namespace_id: 1,
            },
        );
        let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.publish_process_group(
                b,
                ProcessGroupRecord {
                    object: (),
                    members: BTreeSet::new(),
                    container: Scope(1),
                    namespace_id: 1,
                },
            );
        }));
        assert!(refused.is_err());
        assert_eq!(owner.process_groups.len(), 1);
        assert_eq!(
            owner.process_group_by_namespace.get(&(Scope(1), 1)),
            Some(&a)
        );
        assert!(!owner.process_groups.contains_key(&b));
    }
    #[test]
    fn last_member_retirement_preserves_other_namespace_and_exact_generation() {
        let mut owner = registry();
        let a = ProcessGroupId::from_abi_positive(10).unwrap();
        let b = ProcessGroupId::from_abi_positive(11).unwrap();
        let key = TaskKey {
            id: TaskId::from_abi_positive(10).unwrap(),
            serial: super::super::TaskSerial::from_raw_u64(2).unwrap(),
        };
        let stale = TaskKey {
            serial: super::super::TaskSerial::from_raw_u64(1).unwrap(),
            ..key
        };
        let other_key = TaskKey {
            id: TaskId::from_abi_positive(11).unwrap(),
            serial: super::super::TaskSerial::from_raw_u64(3).unwrap(),
        };
        for (id, scope) in [(a, Scope(1)), (b, Scope(2))] {
            owner.publish_process_group(
                id,
                ProcessGroupRecord {
                    object: (),
                    members: BTreeSet::from([if id == a { key } else { other_key }]),
                    container: scope,
                    namespace_id: 1,
                },
            );
            owner.publish_session(
                SessionId::from_abi_positive(id.raw()).unwrap(),
                SessionRecord {
                    object: (),
                    process_groups: BTreeSet::from([id]),
                    container: scope,
                    namespace_id: 1,
                },
            );
        }
        let session = SessionId::from_abi_positive(a.raw()).unwrap();
        owner.remove_group_member(a, session, stale);
        assert!(owner.process_groups.contains_key(&a));
        assert!(owner.sessions.contains_key(&session));
        owner.remove_group_member(a, session, key);
        assert!(!owner.process_groups.contains_key(&a));
        assert!(!owner.sessions.contains_key(&session));
        assert_eq!(
            owner.process_group_by_namespace.get(&(Scope(2), 1)),
            Some(&b)
        );
        assert_eq!(
            owner.session_by_namespace.get(&(Scope(2), 1)),
            Some(&SessionId::from_abi_positive(b.raw()).unwrap())
        );
        assert_eq!(
            owner.process_groups[&b].members,
            BTreeSet::from([other_key])
        );
    }
}

/// Consumer effect after the shared owner detects an impossible graph state.
pub trait RegistryFailure {
    fn fail(invariant: RegistryInvariant) -> !;
}

#[derive(Debug)]
pub struct ProcessGroupRecord<Object, Container> {
    pub object: Object,
    pub members: BTreeSet<TaskKey>,
    pub container: Container,
    pub namespace_id: u32,
}

#[derive(Debug)]
pub struct SessionRecord<Object, Container> {
    pub object: Object,
    pub process_groups: BTreeSet<ProcessGroupId>,
    pub container: Container,
    pub namespace_id: u32,
}

/// Storage shared by host and guest process owners, without a mirrored host
/// population. Live/dead payload types retain their consumer's resource claims.
#[derive(Debug)]
pub struct ProcessRegistry<C, L, Z, R, Reservation, Retired, Group, Session, Failure> {
    pub epoch: u64,
    pub container_inits: BTreeMap<C, TaskKey>,
    pub tasks: BTreeMap<TaskId, L>,
    pub zombies: BTreeMap<TaskId, Z>,
    pub retiring_tasks: BTreeMap<TaskId, R>,
    pub process_groups: BTreeMap<ProcessGroupId, ProcessGroupRecord<Group, C>>,
    pub process_group_by_namespace: BTreeMap<(C, u32), ProcessGroupId>,
    pub reservations: BTreeMap<TaskId, Reservation>,
    pub retired_threads: Retired,
    pub sessions: BTreeMap<SessionId, SessionRecord<Session, C>>,
    pub session_by_namespace: BTreeMap<(C, u32), SessionId>,
    pub failure: PhantomData<Failure>,
}

impl<C: Copy + Ord, L, Z, R, Reservation, Retired, Group, Session, Failure: RegistryFailure>
    ProcessRegistry<C, L, Z, R, Reservation, Retired, Group, Session, Failure>
{
    /// Retire a group's last exact task member and then its empty session.
    /// Namespace indexes are retired by the same owner as the records.
    pub fn remove_group_member(
        &mut self,
        group_id: ProcessGroupId,
        session_id: SessionId,
        task: TaskKey,
    ) {
        let remove_group = if let Some(group) = self.process_groups.get_mut(&group_id) {
            group.members.remove(&task);
            group.members.is_empty()
        } else {
            false
        };
        if !remove_group {
            return;
        }
        self.remove_process_group(group_id);
        let remove_session = if let Some(session) = self.sessions.get_mut(&session_id) {
            session.process_groups.remove(&group_id);
            session.process_groups.is_empty()
        } else {
            false
        };
        if remove_session {
            self.remove_session(session_id);
        }
    }

    pub fn publish_epoch(&mut self) {
        self.epoch = self
            .epoch
            .checked_add(1)
            .unwrap_or_else(|| Failure::fail(RegistryInvariant::EpochExhausted));
    }

    pub fn publish_process_group(
        &mut self,
        id: ProcessGroupId,
        record: ProcessGroupRecord<Group, C>,
    ) {
        let namespace_key = (record.container, record.namespace_id);
        if self.process_groups.contains_key(&id)
            || self.process_group_by_namespace.contains_key(&namespace_key)
        {
            Failure::fail(RegistryInvariant::ProcessGroupCollision);
        }
        self.process_group_by_namespace.insert(namespace_key, id);
        self.process_groups.insert(id, record);
    }

    pub fn remove_process_group(
        &mut self,
        id: ProcessGroupId,
    ) -> Option<ProcessGroupRecord<Group, C>> {
        let record = self.process_groups.remove(&id)?;
        if self
            .process_group_by_namespace
            .remove(&(record.container, record.namespace_id))
            != Some(id)
        {
            Failure::fail(RegistryInvariant::ProcessGroupIndexLost);
        }
        Some(record)
    }

    pub fn publish_session(&mut self, id: SessionId, record: SessionRecord<Session, C>) {
        let namespace_key = (record.container, record.namespace_id);
        if self.sessions.contains_key(&id) || self.session_by_namespace.contains_key(&namespace_key)
        {
            Failure::fail(RegistryInvariant::SessionCollision);
        }
        self.session_by_namespace.insert(namespace_key, id);
        self.sessions.insert(id, record);
    }

    pub fn remove_session(&mut self, id: SessionId) -> Option<SessionRecord<Session, C>> {
        let record = self.sessions.remove(&id)?;
        if self
            .session_by_namespace
            .remove(&(record.container, record.namespace_id))
            != Some(id)
        {
            Failure::fail(RegistryInvariant::SessionIndexLost);
        }
        Some(record)
    }
}
