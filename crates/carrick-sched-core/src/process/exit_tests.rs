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
        id: TaskId::from_registry_allocation(core::num::NonZeroI32::new(2).unwrap()),
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

/// A process graph whose live and dead rows are plain keyed records, shared
/// by the exit topology tests.
mod topology {
    use super::super::exit::TaskRevision;
    use super::super::exit::{ExitLive, ExitLivePublication, ExitZombie, ExitZombiePublication};
    use super::super::registry::{ProcessRegistry, RegistryFailure, RegistryInvariant};
    use super::super::wait::{WaitIdentity, WaitIdentitySource};
    use super::super::{ChildExitSignal, ProcessGroupId, TaskLifecycle};
    use super::TaskKey;
    use alloc::collections::BTreeSet;
    pub(super) struct Live {
        pub(super) key: TaskKey,
        pub(super) parent: Option<TaskKey>,
        pub(super) children: BTreeSet<TaskKey>,
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
    impl super::super::exit::ExitEffectSource<u32> for Live {
        type Member = TaskKey;
        type Resources = ();
        fn exit_members(&self) -> (alloc::vec::Vec<TaskKey>, ()) {
            (alloc::vec![self.key], ())
        }
        fn exit_begin(&self) -> bool {
            true
        }
    }
    pub(super) struct ParentSignals;
    impl super::super::exit::ExitSignalSource for ParentSignals {
        fn exit_signal_state(
            &self,
            _: super::super::LinuxSignal,
        ) -> super::super::exit::ExitSignalState {
            super::super::exit::ExitSignalState {
                disposition: super::super::exit::ExitSignalDisposition::Default,
                default_disposition: super::super::exit::DefaultSignalDisposition::Ignore,
                blocked: false,
            }
        }
    }
    impl super::super::exit::ExitNotificationSource for Live {
        type Target = ParentSignals;
        fn exit_notification_target(&self) -> ParentSignals {
            ParentSignals
        }
    }
    impl ExitLivePublication<u32> for Live {
        fn exit_reparent(&mut self, parent: Option<TaskKey>) {
            self.parent = parent;
        }
        fn exit_publish_children(&mut self, children: BTreeSet<TaskKey>) {
            self.children = children;
        }
        fn exit_forget_child(&mut self, child: TaskKey) {
            self.children.remove(&child);
        }
        fn exit_publish_credit(
            &mut self,
            participant: super::super::exit::PreparedExitParticipant<()>,
        ) {
            participant.publish(TaskRevision::INITIAL, |_, current| current.next().unwrap());
        }
    }
    pub(super) struct Dead {
        pub(super) key: TaskKey,
        pub(super) parent: Option<TaskKey>,
        pub(super) autoreap: Option<super::super::exit::DeferredAutoreap<()>>,
    }
    impl ExitZombie for Dead {
        fn exit_parent(&self) -> Option<TaskKey> {
            self.parent
        }
        fn exit_key(&self) -> TaskKey {
            self.key
        }
        fn exit_is_autoreap(&self) -> bool {
            self.autoreap.is_some()
        }
    }
    impl ExitZombiePublication<()> for Dead {
        fn exit_reparent(&mut self, parent: Option<TaskKey>) {
            self.parent = parent;
        }
        fn exit_publish_autoreap(&mut self, accounting: super::super::exit::DeferredAutoreap<()>) {
            self.autoreap = Some(accounting);
        }
        fn exit_reparent_autoreap(&mut self, parent: super::super::exit::AutoreapParent<()>) {
            self.autoreap.as_mut().unwrap().reparent(parent);
        }
        fn exit_take_autoreap(&mut self) -> Option<super::super::exit::DeferredAutoreap<()>> {
            self.autoreap.take()
        }
    }
    pub(super) struct Failure;
    impl RegistryFailure for Failure {
        fn fail(_: RegistryInvariant) -> ! {
            panic!("invariant")
        }
    }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) struct Transaction(pub(super) u32);
    pub(super) type Owner = ProcessRegistry<
        u32,
        Live,
        Dead,
        TaskKey,
        super::super::exit::TaskGraphReservation<Transaction>,
        (),
        (),
        (),
        Failure,
    >;
    /// One container whose init is `init`, holding `tasks` and `zombies`.
    pub(super) fn owner(
        init: TaskKey,
        tasks: impl IntoIterator<Item = Live>,
        zombies: impl IntoIterator<Item = Dead>,
    ) -> Owner {
        use alloc::collections::BTreeMap;
        ProcessRegistry {
            epoch: 1,
            container_inits: BTreeMap::from([(1, init)]),
            tasks: tasks.into_iter().map(|live| (live.key.id, live)).collect(),
            zombies: zombies
                .into_iter()
                .map(|dead| (dead.key.id, dead))
                .collect(),
            retiring_tasks: BTreeMap::new(),
            reservations: BTreeMap::new(),
            retired_threads: (),
            process_groups: BTreeMap::new(),
            process_group_by_namespace: BTreeMap::new(),
            sessions: BTreeMap::new(),
            session_by_namespace: BTreeMap::new(),
            failure: core::marker::PhantomData,
        }
    }
}

/// #705: exit no longer sorts its children by serial on the EL1 stack. With
/// 96 children (every third already a zombie) whose serials run against
/// their key order, as adopted children's do, and again with serials in key
/// order, exit reserves exactly the task, every child and the adopter, and
/// publishes the same graph: each child, live or dead, reparented to the
/// namespace init, which holds its own children plus all of them.
#[test]
fn exit_reparents_many_children_identically_whatever_their_serial_order() {
    use super::exit::ExitZombie;
    use alloc::collections::{BTreeMap, BTreeSet};
    use alloc::vec::Vec;
    use topology::{Dead, Live};
    const CHILDREN: i32 = 96;
    let id = |raw: i32| TaskId::from_registry_allocation(core::num::NonZeroI32::new(raw).unwrap());
    let serial = |raw: u64| TaskSerial::from_raw_u64(raw).unwrap();
    let published = |against_key_order: bool| {
        let init = TaskKey {
            id: id(1),
            serial: serial(1),
        };
        let sibling = TaskKey {
            id: id(500),
            serial: serial(2),
        };
        let task = TaskKey {
            id: id(2),
            serial: serial(3),
        };
        let children: Vec<TaskKey> = (0..CHILDREN)
            .map(|index| TaskKey {
                id: id(10 + index),
                serial: serial(if against_key_order {
                    1000 - index as u64
                } else {
                    100 + index as u64
                }),
            })
            .collect();
        let zombie = |index: usize| index.is_multiple_of(3);
        let mut tasks = alloc::vec![
            Live {
                key: init,
                parent: None,
                children: BTreeSet::from([task, sibling]),
            },
            Live {
                key: sibling,
                parent: Some(init),
                children: BTreeSet::new(),
            },
            Live {
                key: task,
                parent: Some(init),
                children: children.iter().copied().collect(),
            },
        ];
        let mut zombies = Vec::new();
        for (index, child) in children.iter().enumerate() {
            if zombie(index) {
                zombies.push(Dead {
                    key: *child,
                    parent: Some(task),
                    autoreap: None,
                });
            } else {
                tasks.push(Live {
                    key: *child,
                    parent: Some(task),
                    children: BTreeSet::new(),
                });
            }
        }
        let mut owner = topology::owner(init, tasks, zombies);
        let mut plan = owner.prepare_exit_topology(task, None).unwrap();
        assert_eq!(plan.adopter(), Some(init));
        let mut reserved: BTreeSet<TaskId> = children.iter().map(|child| child.id).collect();
        reserved.extend([task.id, init.id]);
        assert_eq!(plan.reserved_ids(), &reserved);
        owner.validate_exit_topology(task, &plan).unwrap();
        owner.publish_exit_topology(&mut plan);
        let mut adopted = BTreeSet::from([task, sibling]);
        adopted.extend(children.iter().copied());
        assert_eq!(owner.tasks[&init.id].children, adopted);
        for (index, child) in children.iter().enumerate() {
            let parent = if zombie(index) {
                assert_eq!(owner.zombies[&child.id].exit_key(), *child);
                owner.zombies[&child.id].exit_parent()
            } else {
                owner.tasks[&child.id].parent
            };
            assert_eq!(parent, Some(init), "child {index} not reparented");
        }
        // The graph, with serials normalized away, for comparison.
        let parents: BTreeMap<TaskId, Option<TaskId>> = owner
            .tasks
            .values()
            .map(|live| (live.key.id, live.parent.map(|key| key.id)))
            .chain(
                owner
                    .zombies
                    .values()
                    .map(|dead| (dead.key.id, dead.parent.map(|key| key.id))),
            )
            .collect();
        let adopted: BTreeSet<TaskId> = adopted.iter().map(|key| key.id).collect();
        (parents, adopted, plan.reserved_ids().clone())
    };
    assert_eq!(published(true), published(false));
}

#[test]
fn exit_topology_owner_refuses_recycled_adopter_before_selecting_children() {
    use super::ProcessGroupId;
    use super::exit::{ExitError, ExitZombie};
    use super::registry::ProcessRegistry;
    use alloc::collections::{BTreeMap, BTreeSet};
    use core::marker::PhantomData;
    use topology::{Dead, Live, Owner, Transaction};
    let parent = TaskKey {
        id: TaskId::from_registry_allocation(core::num::NonZeroI32::new(1).unwrap()),
        ..key(1)
    };
    let task = key(2);
    let mut owner: Owner = ProcessRegistry {
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
    let plan = owner.prepare_exit_topology(task, None).unwrap();
    let unrelated = owner
        .reserve_task_set(alloc::vec![parent.id], Transaction(4))
        .unwrap();
    assert!(
        owner.begin_exit_effects(task, &plan, &unrelated).is_err(),
        "exit begin requires the reservation owning this plan"
    );
    let unrelated_release = owner.release_task_set(&unrelated).unwrap();
    let permit = owner.reserve_exit_task_set(&plan, Transaction(3)).unwrap();
    let effects = owner.begin_exit_effects(task, &plan, &permit).unwrap();
    assert!(effects.after_release(unrelated_release).is_err());
    let effects = owner.begin_exit_effects(task, &plan, &permit).unwrap();
    let _old_release = owner.release_task_set(&permit).unwrap();
    let rebound = owner.reserve_exit_task_set(&plan, Transaction(3)).unwrap();
    assert!(owner.validate_task_set(&permit).is_err());
    assert!(!owner.rollback_task_set(&permit));
    assert_eq!(owner.reservations.len(), plan.reserved_ids().len());
    let rebound_release = owner.release_task_set(&rebound).unwrap();
    assert!(
        effects.after_release(rebound_release).is_err(),
        "same numeric transaction is not the same reservation incarnation"
    );
    let permit = owner.reserve_exit_task_set(&plan, Transaction(5)).unwrap();
    let effects = owner.begin_exit_effects(task, &plan, &permit).unwrap();
    let release = owner.release_task_set(&permit).unwrap();
    let ready = effects.after_release(release).unwrap();
    let mut cancelled = alloc::vec::Vec::new();
    let parent_permit = ready.cancel_members(|member| cancelled.push(member));
    assert_eq!(cancelled, alloc::vec![task]);
    assert_eq!(parent_permit.parent(), Some(parent));
    let notification = owner.select_exit_parent(&parent_permit).unwrap().prepare();
    assert_eq!(notification.parent, parent);
    assert_eq!(notification.signal, None);
    assert!(
        super::exit::ExitSignalState {
            disposition: super::exit::ExitSignalDisposition::Default,
            default_disposition: super::exit::DefaultSignalDisposition::Ignore,
            blocked: true
        }
        .needs_notification()
    );
    assert!(
        !super::exit::ExitSignalState {
            disposition: super::exit::ExitSignalDisposition::Ignore,
            default_disposition: super::exit::DefaultSignalDisposition::Ignore,
            blocked: true
        }
        .needs_notification()
    );

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
    assert!(owner.tasks[&parent.id].children.contains(&task));
    owner.retiring_tasks.insert(task.id, task);
    let receipt = owner
        .publish_exit_receipt(
            task,
            &mut plan,
            Dead {
                key: task,
                parent: Some(parent),
                autoreap: None,
            },
            ProcessGroupId::from_abi_positive(1).unwrap(),
            super::SessionId::from_abi_positive(1).unwrap(),
        )
        .unwrap();
    assert_eq!(receipt, task);
    assert!(owner.zombies[&task.id].exit_is_autoreap());
    assert!(owner.tasks[&parent.id].children.contains(&task));
    assert!(owner.complete_exit_autoreap(task).unwrap().is_some());
    assert!(owner.tasks[&parent.id].children.is_empty());
    assert!(owner.zombies.is_empty());
    assert!(owner.retiring_tasks.is_empty());

    let live_child = TaskKey {
        id: TaskId::from_registry_allocation(core::num::NonZeroI32::new(3).unwrap()),
        ..key(3)
    };
    let dead_child = TaskKey {
        id: TaskId::from_registry_allocation(core::num::NonZeroI32::new(4).unwrap()),
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
            autoreap: None,
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

impl super::exit::ExitMember for TaskKey {
    fn exit_task(&self) -> TaskKey {
        *self
    }
}

#[test]
fn exit_effect_work_visits_only_own_members_at_all_scales() {
    use super::exit::*;
    use super::registry::*;
    use super::wait::{WaitIdentity, WaitIdentitySource};
    use super::{ChildExitSignal, ProcessGroupId, TaskLifecycle};
    use alloc::collections::{BTreeMap, BTreeSet};
    use alloc::vec::Vec;
    use core::cell::Cell;
    use core::marker::PhantomData;
    struct Member(TaskKey);
    impl ExitMember for Member {
        fn exit_task(&self) -> TaskKey {
            self.0
        }
    }
    struct Live {
        key: TaskKey,
        members: usize,
        reads: Cell<usize>,
        member_reads: Cell<usize>,
    }
    impl WaitIdentitySource for Live {
        fn wait_identity(&self) -> WaitIdentity {
            self.reads.set(self.reads.get() + 1);
            WaitIdentity {
                key: self.key,
                parent: None,
                tracer: None,
                group: ProcessGroupId::from_abi_positive(1).unwrap(),
                exit_signal: ChildExitSignal::None,
            }
        }
    }
    impl ExitLive<()> for Live {
        type Credit = ();
        type Error = ();
        fn exit_container(&self) {}
        fn exit_lifecycle(&self) -> TaskLifecycle {
            TaskLifecycle::Live
        }
        fn exit_children(&self) -> BTreeSet<TaskKey> {
            BTreeSet::new()
        }
        fn exit_autoreaps(&self) -> bool {
            false
        }
        fn exit_revision(&self) -> TaskRevision {
            TaskRevision::INITIAL
        }
        fn exit_reserve_credit(&self) -> Result<(), ()> {
            Ok(())
        }
    }
    impl ExitEffectSource<()> for Live {
        type Member = Member;
        type Resources = ();
        fn exit_members(&self) -> (Vec<Member>, ()) {
            self.member_reads
                .set(self.member_reads.get() + self.members);
            ((0..self.members).map(|_| Member(self.key)).collect(), ())
        }
        fn exit_begin(&self) -> bool {
            true
        }
    }
    struct Dead;
    impl ExitZombie for Dead {
        fn exit_parent(&self) -> Option<TaskKey> {
            None
        }
        fn exit_key(&self) -> TaskKey {
            panic!("no zombie")
        }
        fn exit_is_autoreap(&self) -> bool {
            false
        }
    }
    struct Failure;
    impl RegistryFailure for Failure {
        fn fail(_: RegistryInvariant) -> ! {
            panic!("invariant")
        }
    }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Transaction(u32);
    for n in [0, 1, 8, 32, 128] {
        let task = key(1);
        let mut owner: ProcessRegistry<
            (),
            Live,
            Dead,
            (),
            TaskGraphReservation<Transaction>,
            (),
            (),
            (),
            Failure,
        > = ProcessRegistry {
            epoch: 1,
            container_inits: BTreeMap::new(),
            tasks: BTreeMap::new(),
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
        owner.tasks.insert(
            task.id,
            Live {
                key: task,
                members: n,
                reads: Cell::new(0),
                member_reads: Cell::new(0),
            },
        );
        for id in 100..612 {
            let other = TaskKey {
                id: TaskId::from_registry_allocation(core::num::NonZeroI32::new(id).unwrap()),
                ..key(99)
            };
            owner.tasks.insert(
                other.id,
                Live {
                    key: other,
                    members: 1,
                    reads: Cell::new(0),
                    member_reads: Cell::new(0),
                },
            );
        }
        let plan = owner.prepare_exit_topology(task, None).unwrap();
        let permit = owner.reserve_exit_task_set(&plan, Transaction(1)).unwrap();
        assert!(
            owner.begin_exit_effects(key(2), &plan, &permit).is_err(),
            "a stale task serial must be refused even with no members"
        );
        let effects = owner.begin_exit_effects(task, &plan, &permit).unwrap();
        let release = owner.release_task_set(&permit).unwrap();
        let mut cancelled = 0;
        let parent = effects
            .after_release(release)
            .unwrap()
            .cancel_members(|member| {
                assert_eq!(member.0, task);
                cancelled += 1;
            });
        assert_eq!(parent.parent(), None);
        assert_eq!(cancelled, n);
        assert_eq!(owner.tasks[&task.id].member_reads.get(), n);
        assert!(owner.tasks[&task.id].reads.get() <= 4);
        for (id, other) in &owner.tasks {
            if *id != task.id {
                assert_eq!((other.reads.get(), other.member_reads.get()), (0, 0));
            }
        }
    }
}

#[test]
fn prepared_exit_effects_reject_stale_membership_snapshot() {
    use super::exit::*;
    use super::registry::*;
    use super::wait::{WaitIdentity, WaitIdentitySource};
    use super::{ChildExitSignal, ProcessGroupId, TaskLifecycle};
    use alloc::collections::{BTreeMap, BTreeSet};
    use alloc::vec::Vec;
    use core::cell::Cell;
    use core::marker::PhantomData;
    struct Member(TaskKey, usize);
    impl ExitMember for Member {
        fn exit_task(&self) -> TaskKey {
            self.0
        }
    }
    struct Live {
        key: TaskKey,
        members: usize,
        revision: TaskRevision,
        exiting: Cell<bool>,
        reads: Cell<usize>,
        member_reads: Cell<usize>,
    }
    impl WaitIdentitySource for Live {
        fn wait_identity(&self) -> WaitIdentity {
            self.reads.set(self.reads.get() + 1);
            WaitIdentity {
                key: self.key,
                parent: None,
                tracer: None,
                group: ProcessGroupId::from_abi_positive(1).unwrap(),
                exit_signal: ChildExitSignal::None,
            }
        }
    }
    impl ExitLive<()> for Live {
        type Credit = ();
        type Error = ();
        fn exit_container(&self) {}
        fn exit_lifecycle(&self) -> TaskLifecycle {
            if self.exiting.get() {
                TaskLifecycle::Exiting
            } else {
                TaskLifecycle::Live
            }
        }
        fn exit_children(&self) -> BTreeSet<TaskKey> {
            BTreeSet::new()
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
    impl ExitEffectSource<()> for Live {
        type Member = Member;
        type Resources = ();
        fn exit_members(&self) -> (Vec<Member>, ()) {
            self.member_reads
                .set(self.member_reads.get() + self.members);
            (
                (0..self.members)
                    .map(|index| Member(self.key, index))
                    .collect(),
                (),
            )
        }
        fn exit_begin(&self) -> bool {
            !self.exiting.replace(true)
        }
    }
    struct Dead;
    impl ExitZombie for Dead {
        fn exit_parent(&self) -> Option<TaskKey> {
            None
        }
        fn exit_key(&self) -> TaskKey {
            panic!("no zombie")
        }
        fn exit_is_autoreap(&self) -> bool {
            false
        }
    }
    struct Failure;
    impl RegistryFailure for Failure {
        fn fail(_: RegistryInvariant) -> ! {
            panic!("invariant")
        }
    }
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Transaction(u32);
    for n in [1] {
        let task = key(1);
        let mut owner: ProcessRegistry<
            (),
            Live,
            Dead,
            (),
            TaskGraphReservation<Transaction>,
            (),
            (),
            (),
            Failure,
        > = ProcessRegistry {
            epoch: 1,
            container_inits: BTreeMap::new(),
            tasks: BTreeMap::new(),
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
        owner.tasks.insert(
            task.id,
            Live {
                key: task,
                members: n,
                revision: TaskRevision::INITIAL,
                exiting: Cell::new(false),
                reads: Cell::new(0),
                member_reads: Cell::new(0),
            },
        );
        for id in 100..612 {
            let other = TaskKey {
                id: TaskId::from_registry_allocation(core::num::NonZeroI32::new(id).unwrap()),
                ..key(99)
            };
            owner.tasks.insert(
                other.id,
                Live {
                    key: other,
                    members: 1,
                    revision: TaskRevision::INITIAL,
                    exiting: Cell::new(false),
                    reads: Cell::new(0),
                    member_reads: Cell::new(0),
                },
            );
        }
        let plan = owner.prepare_exit_topology(task, None).unwrap();
        let permit = owner.reserve_exit_task_set(&plan, Transaction(1)).unwrap();
        let unactivated = owner.prepare_exit_effects(task, &plan, &permit).unwrap();
        owner.release_task_set(&permit).unwrap();
        assert!(
            owner
                .begin_prepared_exit_effects(task, &plan, &permit, unactivated)
                .is_err()
        );
        assert_eq!(owner.tasks[&task.id].exit_lifecycle(), TaskLifecycle::Live);
        let permit = owner.reserve_exit_task_set(&plan, Transaction(2)).unwrap();
        let stale = owner.prepare_exit_effects(task, &plan, &permit).unwrap();
        let current = owner.tasks[&task.id].revision;
        let next = current.next().unwrap();
        let membership = owner.reservations[&task.id]
            .prepare_membership_revision(task, current, next)
            .unwrap()
            .unwrap();
        let row = owner.tasks.get_mut(&task.id).unwrap();
        row.members += 1;
        row.revision = next;
        membership.publish();
        assert!(
            owner
                .begin_prepared_exit_effects(task, &plan, &permit, stale)
                .is_err(),
            "an admitted birth must invalidate the earlier member snapshot"
        );
        assert_eq!(owner.tasks[&task.id].exit_lifecycle(), TaskLifecycle::Live);
        let effects = owner.prepare_exit_effects(task, &plan, &permit).unwrap();
        let effects = owner
            .begin_prepared_exit_effects(task, &plan, &permit, effects)
            .unwrap();
        assert_eq!(
            owner.tasks[&task.id].exit_lifecycle(),
            TaskLifecycle::Exiting
        );
        let release = owner.release_task_set(&permit).unwrap();
        let mut cancelled = Vec::new();
        let parent = effects
            .after_release(release)
            .unwrap()
            .cancel_members(|member| {
                assert_eq!(member.0, task);
                cancelled.push(member.1);
            });
        assert_eq!(parent.parent(), None);
        assert_eq!(cancelled, [0, 1]);
        assert_eq!(owner.tasks[&task.id].member_reads.get(), 3 * n + 1);

        for (id, other) in &owner.tasks {
            if *id != task.id {
                assert_eq!((other.reads.get(), other.member_reads.get()), (0, 0));
            }
        }
    }
}
