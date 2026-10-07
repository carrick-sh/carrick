#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::exit::{ExitParticipantRevision, TaskRevision};
use super::{TaskId, TaskKey, TaskSerial};
use alloc::sync::Arc;

#[test]
fn topology_publication_uses_current_membership_revision_and_owned_credit() {
    use super::exit::PreparedExitParticipant;
    let current = TaskRevision::INITIAL;
    let participant = PreparedExitParticipant::reserve(key(1), current, ());
    let revision = participant.revision();
    let born = current.next().unwrap();
    revision
        .prepare_membership(key(1), current, born)
        .unwrap()
        .publish();
    let published = participant.publish(born, |_, current| current.next().unwrap());
    assert_eq!(published, born.next().unwrap());
    assert!(revision.validate(key(1), published).is_ok());
    assert!(revision.validate(key(1), born).is_err());
}

fn key(serial: u64) -> TaskKey {
    TaskKey {
        id: TaskId::from_abi_positive(2).unwrap(),
        serial: TaskSerial::from_raw_u64(serial).unwrap(),
    }
}

#[test]
fn reserved_exit_tracks_admitted_membership_without_accepting_foreign_generation() {
    let current = TaskRevision::INITIAL;
    let participant = Arc::new(ExitParticipantRevision::capture(key(1), current));
    let next = current.next().unwrap();
    let admission = participant
        .prepare_membership(key(1), current, next)
        .unwrap();
    assert!(participant.validate(key(1), next).is_err());
    admission.publish();
    assert!(participant.validate(key(1), next).is_ok());
    assert!(participant.validate(key(2), next).is_err());
    assert!(
        participant
            .prepare_membership(key(2), next, next.next().unwrap())
            .is_err()
    );
    assert!(participant.prepare_membership(key(1), next, next).is_err());
}

#[test]
fn dropping_membership_admission_preserves_reserved_exit_revision() {
    let current = TaskRevision::INITIAL;
    let participant = Arc::new(ExitParticipantRevision::capture(key(1), current));
    drop(
        participant
            .prepare_membership(key(1), current, current.next().unwrap())
            .unwrap(),
    );
    assert!(participant.validate(key(1), current).is_ok());
    assert!(
        participant
            .validate(key(1), current.next().unwrap())
            .is_err()
    );
}

#[test]
fn exit_topology_owner_refuses_recycled_adopter_before_selecting_children() {
    use super::exit::{
        ExitError, ExitLive, ExitLivePublication, ExitZombie, ExitZombiePublication,
    };
    use super::registry::{ProcessRegistry, RegistryFailure, RegistryInvariant};
    use super::wait::{WaitIdentity, WaitIdentitySource};
    use super::{ChildExitSignal, ProcessGroupId, TaskLifecycle};
    use alloc::collections::{BTreeMap, BTreeSet};
    use core::marker::PhantomData;
    struct Live {
        key: TaskKey,
        parent: Option<TaskKey>,
        children: BTreeSet<TaskKey>,
    }
    impl WaitIdentitySource for Live {
        fn wait_identity(&self) -> WaitIdentity {
            WaitIdentity {
                key: self.key,
                parent: self.parent,
                tracer: None,
                group: ProcessGroupId::from_abi_positive(1).unwrap(),
                exit_signal: ChildExitSignal::SIGCHLD,
            }
        }
    }
    impl ExitLive<u32> for Live {
        type Credit = ();
        type Error = ();
        fn exit_container(&self) -> u32 {
            1
        }
        fn exit_lifecycle(&self) -> TaskLifecycle {
            TaskLifecycle::Live
        }
        fn exit_children(&self) -> BTreeSet<TaskKey> {
            self.children.clone()
        }
        fn exit_autoreaps(&self) -> bool {
            true
        }
        fn exit_revision(&self) -> TaskRevision {
            TaskRevision::INITIAL
        }
        fn exit_reserve_credit(&self) -> Result<(), ()> {
            Ok(())
        }
    }
    impl ExitLivePublication<u32> for Live {
        fn exit_reparent(&mut self, parent: Option<TaskKey>) {
            self.parent = parent;
        }
        fn exit_publish_children(&mut self, children: BTreeSet<TaskKey>) {
            self.children = children;
        }
        fn exit_publish_credit(&mut self, participant: super::exit::PreparedExitParticipant<()>) {
            participant.publish(TaskRevision::INITIAL, |_, current| current.next().unwrap());
        }
    }
    struct Dead {
        key: TaskKey,
        parent: Option<TaskKey>,
    }
    impl ExitZombie for Dead {
        fn exit_key(&self) -> TaskKey {
            self.key
        }
    }
    impl ExitZombiePublication for Dead {
        fn exit_reparent(&mut self, parent: Option<TaskKey>) {
            self.parent = parent;
        }
    }
    struct Failure;
    impl RegistryFailure for Failure {
        fn fail(_: RegistryInvariant) -> ! {
            panic!("invariant")
        }
    }
    let parent = TaskKey {
        id: TaskId::from_abi_positive(1).unwrap(),
        ..key(1)
    };
    let task = key(2);
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Transaction(u32);
    let mut owner: ProcessRegistry<
        u32,
        Live,
        Dead,
        TaskKey,
        super::exit::TaskGraphReservation<Transaction>,
        (),
        (),
        (),
        Failure,
    > = ProcessRegistry {
        epoch: 1,
        container_inits: BTreeMap::from([(1, parent)]),
        tasks: BTreeMap::from([
            (
                parent.id,
                Live {
                    key: parent,
                    parent: None,
                    children: BTreeSet::from([task]),
                },
            ),
            (
                task.id,
                Live {
                    key: task,
                    parent: Some(parent),
                    children: BTreeSet::new(),
                },
            ),
        ]),
        zombies: BTreeMap::new(),
        retiring_tasks: BTreeMap::new(),
        reservations: BTreeMap::new(),
        retired_threads: (),
        process_groups: BTreeMap::new(),
        process_group_by_namespace: BTreeMap::new(),
        sessions: BTreeMap::new(),
        session_by_namespace: BTreeMap::new(),
        failure: PhantomData,
    };
    let reservation = owner
        .reserve_task_set(alloc::vec![parent.id, task.id, parent.id], Transaction(1))
        .unwrap();
    assert_eq!(owner.reservations.len(), 2);
    assert!(
        owner
            .reserve_task_set(alloc::vec![task.id], Transaction(2))
            .is_err()
    );
    assert_eq!(owner.reservations.len(), 2);
    owner.validate_task_set(&reservation).unwrap();
    owner.release_task_set(&reservation).unwrap();
    assert!(owner.reservations.is_empty());
    let stale = TaskKey {
        serial: TaskSerial::from_raw_u64(9).unwrap(),
        ..parent
    };
    assert!(
        matches!(owner.prepare_exit_topology(task, Some(stale)), Err(ExitError::Stale(found)) if found == parent.id)
    );
    let mut plan = owner.prepare_exit_topology(task, None).unwrap();
    assert_eq!(plan.adopter(), None);
    assert_eq!(plan.autoreap_parent(), Some(parent));
    assert_eq!(plan.reserved_ids().len(), 2);
    owner.validate_exit_topology(task, &plan).unwrap();
    owner.publish_exit_topology(&mut plan);
    assert!(owner.tasks[&parent.id].children.is_empty());
    owner.retiring_tasks.insert(task.id, task);
    let receipt = owner
        .publish_exit_receipt(
            task,
            &plan,
            Dead {
                key: task,
                parent: Some(parent),
            },
            ProcessGroupId::from_abi_positive(1).unwrap(),
            super::SessionId::from_abi_positive(1).unwrap(),
        )
        .unwrap();
    assert_eq!(receipt.retiring, task);
    assert!(receipt.autoreaped_receipt.is_some());
    assert!(owner.zombies.is_empty());
    assert!(owner.retiring_tasks.is_empty());

    let live_child = TaskKey {
        id: TaskId::from_abi_positive(3).unwrap(),
        ..key(3)
    };
    let dead_child = TaskKey {
        id: TaskId::from_abi_positive(4).unwrap(),
        ..key(4)
    };
    owner.tasks.get_mut(&task.id).unwrap().children = BTreeSet::from([live_child, dead_child]);
    owner.tasks.insert(
        live_child.id,
        Live {
            key: live_child,
            parent: Some(task),
            children: BTreeSet::new(),
        },
    );
    owner.zombies.insert(
        dead_child.id,
        Dead {
            key: dead_child,
            parent: Some(task),
        },
    );
    let mut plan = owner.prepare_exit_topology(task, Some(parent)).unwrap();
    assert_eq!(plan.adopter(), Some(parent));
    assert_eq!(plan.reserved_ids().len(), 4);
    owner.validate_exit_topology(task, &plan).unwrap();
    owner.publish_exit_topology(&mut plan);
    assert_eq!(owner.tasks[&live_child.id].parent, Some(parent));
    assert_eq!(owner.zombies[&dead_child.id].parent, Some(parent));
    assert_eq!(
        owner.tasks[&parent.id].children,
        BTreeSet::from([live_child, dead_child])
    );
    owner.tasks.get_mut(&live_child.id).unwrap().key.serial = TaskSerial::from_raw_u64(99).unwrap();
    assert!(
        matches!(owner.prepare_exit_topology(task, None), Err(ExitError::Topology(found)) if found == live_child.id)
    );
}

impl super::exit::ExitRetiring for TaskKey {
    fn exit_key(&self) -> TaskKey {
        *self
    }
}
