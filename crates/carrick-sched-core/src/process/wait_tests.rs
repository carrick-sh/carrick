#![allow(clippy::unwrap_used, clippy::expect_used)]
use super::registry::*;
use super::wait::*;
use super::*;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::Cell;
use core::marker::PhantomData;
use core::time::Duration;

struct Failure;
impl RegistryFailure for Failure {
    fn fail(invariant: RegistryInvariant) -> ! {
        panic!("{invariant:?}")
    }
}
struct Live {
    identity: WaitIdentity,
    children: Vec<TaskKey>,
    tracees: Vec<TaskKey>,
    event: Cell<Option<u32>>,
    wake: u64,
    charge: TaskRusage,
    revision: u64,
    exhausted: bool,
    reads: Cell<usize>,
    identity_reads: Cell<usize>,
}
impl WaitIdentitySource for Live {
    fn wait_identity(&self) -> WaitIdentity {
        self.identity_reads.set(self.identity_reads.get() + 1);
        self.identity
    }
}
impl WaitLive for Live {
    type Event = u32;
    type Revision = u64;
    type Error = ();
    fn wait_children(&self) -> Vec<TaskKey> {
        self.children.clone()
    }
    fn wait_tracees(&self) -> Vec<TaskKey> {
        self.tracees.clone()
    }
    fn wait_wake_generation(&self) -> TaskWakeGeneration {
        TaskWakeGeneration::from_task_counter(self.wake)
    }
    fn wait_event(&self, _: WaitJobControl, consume: bool) -> Option<u32> {
        self.reads.set(self.reads.get() + 1);
        if consume {
            self.event.take()
        } else {
            self.event.get()
        }
    }
    fn prepare_reap(&self) -> Result<u64, ()> {
        if self.exhausted {
            Err(())
        } else {
            Ok(self.revision + 1)
        }
    }
    fn commit_reap(&mut self, child: TaskKey, charge: TaskRusage, revision: u64) {
        self.children.retain(|key| *key != child);
        self.charge.user_time += charge.user_time;
        self.charge.system_time += charge.system_time;
        self.revision = revision;
    }
}
impl<U> WaitZombie<u32, U> for Zombie<u32, U> {
    fn wait_zombie(&self) -> &Zombie<u32, U> {
        self
    }
}
type GenericRegistry<Z> = ProcessRegistry<u32, Live, Z, Live, (), (), (), (), Failure>;
type Registry = GenericRegistry<Zombie<u32, u32>>;
fn key(id: i32, serial: u64) -> TaskKey {
    TaskKey {
        id: TaskId::from_abi_positive(id).unwrap(),
        serial: TaskSerial::from_raw_u64(serial).unwrap(),
    }
}
fn live(key: TaskKey, parent: Option<TaskKey>) -> Live {
    Live {
        identity: WaitIdentity {
            key,
            parent,
            tracer: None,
            group: ProcessGroupId::from_abi_positive(1).unwrap(),
            exit_signal: ChildExitSignal::SIGCHLD,
        },
        children: Vec::new(),
        tracees: Vec::new(),
        event: Cell::new(None),
        wake: 17,
        charge: TaskRusage::default(),
        revision: 1,
        exhausted: false,
        reads: Cell::new(0),
        identity_reads: Cell::new(0),
    }
}
fn registry() -> Registry {
    empty_registry()
}
fn empty_registry<Z>() -> GenericRegistry<Z> {
    ProcessRegistry {
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
fn query() -> WaitQuery {
    WaitQuery {
        target: WaitTarget::Any,
        class: WaitChildClass::Sigchld,
        job_control: WaitJobControl::NONE,
    }
}
fn zombie(child: TaskKey, parent: TaskKey) -> Zombie<u32, u32> {
    zombie_with_uid(child, parent)
}
fn zombie_with_uid<U: Default>(child: TaskKey, parent: TaskKey) -> Zombie<u32, U> {
    Zombie {
        key: child,
        namespace_pid: child.id.raw() as u32,
        container: 1,
        parent: Some(parent),
        process_group: ProcessGroupId::from_abi_positive(1).unwrap(),
        session: SessionId::from_abi_positive(1).unwrap(),
        namespace_process_group: 1,
        namespace_session: 1,
        status: LinuxWaitStatus::from_wait_encoding(0),
        ruid: U::default(),
        euid: U::default(),
        rusage: TaskRusage {
            user_time: Duration::from_micros(7),
            system_time: Duration::from_micros(3),
        },
        children_rusage: TaskRusage {
            user_time: Duration::from_micros(5),
            system_time: Duration::from_micros(2),
        },
        exit_signal: ChildExitSignal::SIGCHLD,
        diagnostic_name: alloc::string::String::new(),
    }
}

#[test]
fn shared_wait_observes_then_consumes_exact_child_and_charges_once() {
    let mut owner = registry();
    let parent = key(1, 1);
    let child = key(2, 2);
    let mut p = live(parent, None);
    p.children.push(child);
    owner.tasks.insert(parent.id, p);
    owner.zombies.insert(child.id, zombie(child, parent));
    assert!(matches!(
        owner.scan_wait(parent.id, query()),
        Ok(WaitSelection::Exited(_))
    ));
    assert!(owner.zombies.contains_key(&child.id));
    assert_eq!(owner.tasks[&parent.id].charge, TaskRusage::default());
    let reaped = owner.consume_wait(parent.id, query()).unwrap();
    assert_eq!(reaped.reaped_parent, Some(parent));
    assert!(matches!(reaped.selection, WaitSelection::Exited(_)));
    assert_eq!(
        owner.tasks[&parent.id].charge.user_time,
        Duration::from_micros(12)
    );
    assert_eq!(
        owner.tasks[&parent.id].charge.system_time,
        Duration::from_micros(5)
    );
    assert_eq!(owner.tasks[&parent.id].revision, 2);
    assert!(owner.tasks[&parent.id].children.is_empty());
    assert!(matches!(
        owner.consume_wait(parent.id, query()).unwrap().selection,
        WaitSelection::NoChild
    ));
    assert_eq!(
        owner.tasks[&parent.id].charge.user_time,
        Duration::from_micros(12)
    );
}

#[test]
fn shared_wait_refuses_stale_incarnation_and_samples_live_retirement() {
    let mut owner = registry();
    let parent = key(1, 1);
    let child = key(2, 2);
    let mut p = live(parent, None);
    p.children.push(child);
    owner.tasks.insert(parent.id, p);
    owner.zombies.insert(child.id, zombie(key(2, 3), parent));
    assert!(matches!(
        owner.scan_wait(parent.id, query()),
        Ok(WaitSelection::NoChild)
    ));
    owner
        .retiring_tasks
        .insert(child.id, live(child, Some(parent)));
    match owner.scan_wait(parent.id, query()).unwrap() {
        WaitSelection::StillRunning(token) => assert_eq!(token.wake_generation().raw(), 17),
        _ => panic!("retiring exact child must retain wait population"),
    }
    owner.tasks.get_mut(&parent.id).unwrap().wake = 18;
    match owner.scan_wait(parent.id, query()).unwrap() {
        WaitSelection::StillRunning(token) => assert_eq!(token.wake_generation().raw(), 18),
        _ => panic!("wake must be sampled by the registry scan"),
    }
}

#[test]
fn shared_wait_reap_admission_failure_preserves_zombie_edges_and_cpu() {
    let mut owner = registry();
    let parent = key(1, 1);
    let child = key(2, 2);
    let mut p = live(parent, None);
    p.children.push(child);
    p.exhausted = true;
    owner.tasks.insert(parent.id, p);
    owner.zombies.insert(child.id, zombie(child, parent));
    assert!(matches!(
        owner.consume_wait(parent.id, query()),
        Err(WaitError::Revision(()))
    ));
    assert!(owner.zombies.contains_key(&child.id));
    assert_eq!(owner.tasks[&parent.id].children, [child]);
    assert_eq!(owner.tasks[&parent.id].charge, TaskRusage::default());
    owner.tasks.get_mut(&parent.id).unwrap().exhausted = false;
    owner.reservations.insert(child.id, ());
    assert!(
        matches!(owner.consume_wait(parent.id,query()),Err(WaitError::Busy(id)) if id==child.id)
    );
    assert!(owner.zombies.contains_key(&child.id));
}

#[test]
fn shared_wait_clone_partition_does_not_filter_nonchild_ptrace_stops() {
    let mut owner = registry();
    let parent = key(1, 1);
    let child = key(2, 2);
    let tracee = key(3, 3);
    let mut p = live(parent, None);
    p.children.push(child);
    p.tracees = alloc::vec![child, tracee];
    owner.tasks.insert(parent.id, p);
    let mut c = live(child, Some(parent));
    c.identity.exit_signal = ChildExitSignal::None;
    c.event.set(Some(2));
    owner.tasks.insert(child.id, c);
    let mut t = live(tracee, None);
    t.identity.tracer = Some(parent);
    t.event.set(Some(3));
    owner.tasks.insert(tracee.id, t);
    assert!(matches!(
        owner.scan_wait(parent.id, query()),
        Ok(WaitSelection::Event(3))
    ));
    assert_eq!(owner.tasks[&child.id].reads.get(), 0);
    assert_eq!(owner.tasks[&tracee.id].reads.get(), 1);
    assert!(matches!(
        owner.consume_wait(parent.id, query()).unwrap().selection,
        WaitSelection::Event(3)
    ));
    assert_eq!(owner.tasks[&tracee.id].event.get(), None);
    assert_eq!(owner.tasks[&child.id].event.get(), Some(2));
    let mut clone_query = query();
    clone_query.class = WaitChildClass::Clone;
    assert!(matches!(
        owner
            .consume_wait(parent.id, clone_query)
            .unwrap()
            .selection,
        WaitSelection::Event(2)
    ));
}

#[test]
fn shared_wait_work_visits_children_without_scanning_unrelated_processes() {
    for count in [1, 8, 32, 128] {
        let mut owner = registry();
        let parent = key(1, 1);
        let mut p = live(parent, None);
        for id in 2..count + 2 {
            let child = key(id, id as u64);
            p.children.push(child);
            owner.tasks.insert(child.id, live(child, Some(parent)));
        }
        owner.tasks.insert(parent.id, p);
        for id in 1000..1512 {
            let unrelated = key(id, id as u64);
            owner.tasks.insert(unrelated.id, live(unrelated, None));
        }
        assert!(matches!(
            owner.precheck_wait::<u32>(parent.id, query()),
            Ok(WaitReadiness::StillRunning(_))
        ));
        for (id, record) in owner.tasks.iter().rev() {
            if id.raw() >= 1000 {
                assert_eq!(record.identity_reads.get(), 0);
                assert_eq!(record.reads.get(), 0);
            } else if *id != parent.id {
                assert_eq!(
                    record.identity_reads.get(),
                    if id.raw() == 2 { 2 } else { 1 }
                );
                assert_eq!(record.reads.get(), 1);
            }
        }
        assert_eq!(owner.tasks[&parent.id].identity_reads.get(), 1);
    }
}

#[test]
fn shared_wait_two_children_rescan_and_parent_reservation_keep_events() {
    let mut owner = registry();
    let parent = key(1, 1);
    let first = key(2, 2);
    let second = key(3, 3);
    let mut p = live(parent, None);
    p.children = alloc::vec![first, second];
    owner.tasks.insert(parent.id, p);
    owner.tasks.insert(second.id, live(second, Some(parent)));
    owner.zombies.insert(first.id, zombie(first, parent));
    assert_eq!(
        owner.precheck_wait::<u32>(parent.id, query()).unwrap(),
        WaitReadiness::Ready
    );
    owner.reservations.insert(parent.id, ());
    assert!(
        matches!(owner.consume_wait(parent.id, query()), Err(WaitError::Busy(id)) if id == parent.id)
    );
    assert!(owner.zombies.contains_key(&first.id));
    owner.reservations.remove(&parent.id);
    owner.consume_wait(parent.id, query()).unwrap();
    assert_eq!(owner.tasks[&parent.id].children, [second]);
    assert!(matches!(
        owner.precheck_wait::<u32>(parent.id, query()).unwrap(),
        WaitReadiness::StillRunning(_)
    ));
    owner.tasks.remove(&second.id);
    owner.zombies.insert(second.id, zombie(second, parent));
    assert!(
        matches!(owner.consume_wait(parent.id, query()).unwrap().selection, WaitSelection::Exited(receipt) if receipt.key == second)
    );
    assert_eq!(
        owner.tasks[&parent.id].charge.user_time,
        Duration::from_micros(24)
    );
}

#[test]
fn shared_wait_consuming_precheck_does_not_require_cloning_receipts() {
    #[derive(Default)]
    struct NonCloneUid;
    let mut owner = empty_registry::<Zombie<u32, NonCloneUid>>();
    let parent = key(1, 1);
    let child = key(2, 2);
    let mut p = live(parent, None);
    p.children.push(child);
    owner.tasks.insert(parent.id, p);
    owner
        .zombies
        .insert(child.id, zombie_with_uid(child, parent));
    assert_eq!(
        owner
            .precheck_wait::<NonCloneUid>(parent.id, query())
            .unwrap(),
        WaitReadiness::Ready
    );
    assert!(owner.zombies.contains_key(&child.id));
    assert_eq!(owner.tasks[&parent.id].charge, TaskRusage::default());
}

#[test]
fn consuming_wait_retains_only_selected_owned_claim_until_result_release() {
    struct OwnedZombie {
        receipt: Zombie<u32, u32>,
        releases: alloc::rc::Rc<Cell<usize>>,
    }
    impl WaitZombie<u32, u32> for OwnedZombie {
        fn wait_zombie(&self) -> &Zombie<u32, u32> {
            &self.receipt
        }
    }
    impl Drop for OwnedZombie {
        fn drop(&mut self) {
            self.releases.set(self.releases.get() + 1);
        }
    }
    let mut owner = empty_registry::<OwnedZombie>();
    let parent = key(1, 1);
    let first = key(2, 2);
    let second = key(3, 3);
    let mut p = live(parent, None);
    p.children = alloc::vec![first, second];
    owner.tasks.insert(parent.id, p);
    let first_releases = alloc::rc::Rc::new(Cell::new(0));
    let second_releases = alloc::rc::Rc::new(Cell::new(0));
    for (child, releases) in [(first, &first_releases), (second, &second_releases)] {
        owner.zombies.insert(
            child.id,
            OwnedZombie {
                receipt: zombie(child, parent),
                releases: releases.clone(),
            },
        );
    }
    let mut first_query = query();
    first_query.target = WaitTarget::Exact(first);
    let consumed_first = owner.consume_wait(parent.id, first_query).unwrap();
    assert!(
        matches!(consumed_first.selection, WaitSelection::Exited(ref receipt) if receipt.key == first)
    );
    assert_eq!(
        first_releases.get(),
        0,
        "reap must return owned numeric custody"
    );
    assert_eq!(second_releases.get(), 0);
    assert!(!owner.zombies.contains_key(&first.id));
    assert!(owner.zombies.contains_key(&second.id));
    let consumed_second = owner.consume_wait(parent.id, query()).unwrap();
    assert!(
        matches!(consumed_second.selection, WaitSelection::Exited(ref receipt) if receipt.key == second)
    );
    assert_eq!(second_releases.get(), 0);
    assert!(matches!(
        owner.consume_wait(parent.id, query()).unwrap().selection,
        WaitSelection::NoChild
    ));
    drop(consumed_first);
    assert_eq!(first_releases.get(), 1);
    assert_eq!(second_releases.get(), 0);
    drop(consumed_second);
    assert_eq!(second_releases.get(), 1);
}
