// Native custody tests over the production shared process-owner adapter.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use carrick_guest_arch::{AddressContext, ContextGeneration, FrameGpa, MmGeneration, RootGpa};
use carrick_sched_core::ParkedContextWords;
use carrick_sched_core::process::exit::{ExitSignalDisposition, ExitSignalState};
use carrick_sched_core::process::{LinuxSignal, TaskSerial, WaitChildClass, WaitTarget};
use core::cell::{Cell, RefCell};
use core::num::NonZeroU64;
use core::time::Duration;
use std::rc::Rc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Uid(u32);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Transaction(u64);
struct Failure;
impl RegistryFailure for Failure {
    fn fail(invariant: RegistryInvariant) -> ! {
        panic!("{invariant:?}")
    }
}
impl GuestProcessFailure for Failure {
    fn fail_process(invariant: GuestProcessInvariant) -> ! {
        panic!("{invariant:?}")
    }
}
#[derive(Default)]
struct Work {
    member_visits: Cell<usize>,
    event_reads: Cell<usize>,
    resource_visits: Cell<usize>,
    signal_reads: Cell<usize>,
    revision_reads: Cell<usize>,
}
struct Claim(Rc<Cell<usize>>);
impl Drop for Claim {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}
#[derive(Clone)]
struct Signals {
    state: Rc<Cell<ExitSignalState>>,
    order: Rc<RefCell<Vec<&'static str>>>,
    work: Rc<Work>,
}
impl ExitSignalSource for Signals {
    fn exit_signal_state(&self, signal: LinuxSignal) -> ExitSignalState {
        assert_eq!(signal, LinuxSignal::SIGCHLD);
        self.work.signal_reads.set(self.work.signal_reads.get() + 1);
        self.order.borrow_mut().push("signal");
        self.state.get()
    }
}
#[derive(Clone)]
struct Member {
    task: TaskKey,
    order: Rc<RefCell<Vec<&'static str>>>,
}
impl ExitMember for Member {
    fn exit_task(&self) -> TaskKey {
        self.task
    }
}
impl Member {
    fn cancel(self) {
        self.order.borrow_mut().push("cancel");
    }
}
struct Budget {
    reserved: Cell<u64>,
}
struct Credit {
    source: Rc<Budget>,
    remaining: u64,
}
impl Drop for Credit {
    fn drop(&mut self) {
        self.source
            .reserved
            .set(self.source.reserved.get() - self.remaining);
    }
}
struct Native<C = ParkedContextWords> {
    context_type: PhantomData<C>,
    task: TaskKey,
    members: usize,
    work: Rc<Work>,
    budget: Rc<Budget>,
    signals: Signals,
    autoreap: bool,
    own_usage: TaskRusage,
    wake: u64,
}
impl<C: ProcessContext> NativeProcessCustody for Native<C> {
    type Context = C;
    type Claim = Claim;
    type Event = ();
    type Credit = Credit;
    type Error = ();
    type Transaction = Transaction;
    type Member = Member;
    type Resources = Rc<Work>;
    type SignalTarget = Signals;
    fn next_revision(&self, current: TaskRevision) -> Result<TaskRevision, ()> {
        self.work
            .revision_reads
            .set(self.work.revision_reads.get() + 1);
        current
            .raw()
            .checked_add(self.budget.reserved.get())
            .and_then(|n| n.checked_add(1))
            .ok_or(())?;
        current.next().ok_or(())
    }
    fn reserve_exit_credit(&self, current: TaskRevision) -> Result<Credit, ()> {
        self.next_revision(current)?;
        self.budget.reserved.set(self.budget.reserved.get() + 1);
        Ok(Credit {
            source: self.budget.clone(),
            remaining: 1,
        })
    }
    fn consume_exit_credit(&self, credit: &mut Credit, current: TaskRevision) -> TaskRevision {
        assert!(Rc::ptr_eq(&credit.source, &self.budget));
        assert_eq!(credit.remaining, 1);
        credit.remaining = 0;
        self.budget.reserved.set(self.budget.reserved.get() - 1);
        current.next().unwrap()
    }
    fn wait_event(&self, _: WaitJobControl, _: bool) -> Option<()> {
        self.work.event_reads.set(self.work.event_reads.get() + 1);
        None
    }
    fn wake_generation(&self) -> TaskWakeGeneration {
        TaskWakeGeneration::from_task_counter(self.wake)
    }
    fn own_members_and_resources(&self) -> (Vec<Member>, Rc<Work>) {
        self.work
            .member_visits
            .set(self.work.member_visits.get() + self.members);
        self.work
            .resource_visits
            .set(self.work.resource_visits.get() + 1);
        (
            (0..self.members)
                .map(|_| Member {
                    task: self.task,
                    order: self.signals.order.clone(),
                })
                .collect(),
            self.work.clone(),
        )
    }
    fn signal_target(&self) -> Signals {
        self.signals.clone()
    }
    fn autoreaps_children(&self) -> bool {
        self.autoreap
    }
    fn own_rusage(&self) -> TaskRusage {
        self.own_usage
    }
}
type Owner = GuestProcessOwner<(), Uid, Native, Failure>;
type Task = GuestTask<(), Uid, Native>;
type Published = GuestPublishedExit<(), Uid, Native>;
fn key(id: i32, serial: u64) -> TaskKey {
    TaskKey {
        id: TaskId::from_abi_positive(id).unwrap(),
        serial: TaskSerial::from_raw_u64(serial).unwrap(),
    }
}
fn address(task: TaskKey) -> AddressContext<RootGpa> {
    AddressContext {
        root: RootGpa::page_aligned(FrameGpa::new((task.id.raw() as u64 + 1) * 4096)).unwrap(),
        mm: MmGeneration::new(NonZeroU64::new(task.serial.raw()).unwrap()),
        generation: ContextGeneration::new(NonZeroU64::new(1).unwrap()),
    }
}
fn task(
    task: TaskKey,
    parent: Option<TaskKey>,
    releases: Rc<Cell<usize>>,
    members: usize,
    order: Rc<RefCell<Vec<&'static str>>>,
) -> Task {
    let work = Rc::new(Work::default());
    let signals = Signals {
        state: Rc::new(Cell::new(ExitSignalState {
            disposition: ExitSignalDisposition::Caught,
            blocked: false,
        })),
        order,
        work: work.clone(),
    };
    let native = Native {
        context_type: PhantomData,
        task,
        members,
        work,
        budget: Rc::new(Budget {
            reserved: Cell::new(0),
        }),
        signals,
        autoreap: false,
        own_usage: TaskRusage {
            user_time: Duration::from_micros(7),
            system_time: Duration::from_micros(3),
        },
        wake: 11,
    };
    let mut frame = [0; 20];
    frame[15] = 0x400000;
    frame[16] = 0x23;
    frame[17] = 0x202;
    frame[18] = 0x800000;
    frame[19] = 0x1b;
    let context = ParkedContextWords::from_parts(
        frame,
        address(task),
        0x9000,
        0,
        [0; carrick_sched_core::X86_XSAVE_BYTES],
    );
    GuestTask::new(
        GuestTaskMetadata {
            key: task,
            container: (),
            namespace_pid: task.id.raw() as u32,
            identity: TaskIdentity::led_by(key(1, 1).id),
            namespace_process_group: 1,
            namespace_session: 1,
            receipt_uid: |uid| Uid(uid.raw()),
            exit_signal: ChildExitSignal::SIGCHLD,
            diagnostic_name: "native".into(),
        },
        parent,
        context,
        native,
        Claim(releases),
    )
}
fn owner() -> Owner {
    let mut owner = Owner::new();
    owner
        .seed_initial(task(
            key(1, 1),
            None,
            Rc::new(Cell::new(0)),
            1,
            Rc::new(RefCell::new(Vec::new())),
        ))
        .unwrap();
    owner
}
fn birth(owner: &mut Owner, parent: TaskKey, child: TaskKey, releases: Rc<Cell<usize>>) {
    let snapshot = owner.capture_parent(parent).unwrap();
    let child_row = task(
        child,
        Some(parent),
        releases,
        1,
        Rc::new(RefCell::new(Vec::new())),
    );
    owner
        .admit_child(
            snapshot,
            snapshot,
            &child_row,
            BirthAttachment::Parent,
            None,
        )
        .unwrap()
        .publish(child_row);
}
fn exit(owner: &mut Owner, task: TaskKey, adopter: Option<TaskKey>) -> Published {
    owner
        .prepare_exit(task, adopter)
        .unwrap()
        .reserve(Transaction(task.serial.raw()))
        .unwrap()
        .begin(LinuxWaitStatus::from_wait_encoding(5 << 8))
        .unwrap()
        .publish()
        .unwrap()
}
fn query(target: WaitTarget) -> WaitQuery {
    WaitQuery {
        target,
        class: WaitChildClass::Sigchld,
        job_control: WaitJobControl::NONE,
    }
}
#[test]
fn initial_task_preserves_exact_parked_context_and_seeds_once() {
    let mut owner = owner();
    assert!(
        owner
            .task(key(1, 1))
            .unwrap()
            .context()
            .authenticates(address(key(1, 1)))
    );
    assert_eq!(owner.task(key(1, 1)).unwrap().parent(), None);
    assert!(matches!(
        owner.seed_initial(task(
            key(2, 2),
            None,
            Rc::new(Cell::new(0)),
            1,
            Rc::new(RefCell::new(Vec::new()))
        )),
        Err(GuestProcessError::InitialAlreadySeeded)
    ));
    assert_eq!(owner.registry.tasks.len(), 1);
}
#[test]
fn stale_parent_and_changed_revision_refuse_birth_without_resource_loss() {
    let mut owner = owner();
    let parent = key(1, 1);
    let captured = owner.capture_parent(parent).unwrap();
    birth(&mut owner, parent, key(2, 2), Rc::new(Cell::new(0)));
    let releases = Rc::new(Cell::new(0));
    let row = task(
        key(3, 3),
        Some(parent),
        releases.clone(),
        1,
        Rc::new(RefCell::new(Vec::new())),
    );
    assert!(matches!(
        owner.admit_child(captured, captured, &row, BirthAttachment::Parent, None),
        Err(GuestProcessError::Birth(BirthError::CallerRevision))
    ));
    let mut stale = owner.capture_parent(parent).unwrap();
    stale.key.serial = TaskSerial::from_raw_u64(99).unwrap();
    assert!(matches!(
        owner.admit_child(stale, stale, &row, BirthAttachment::Parent, None),
        Err(GuestProcessError::Birth(BirthError::CallerGone))
    ));
    assert_eq!(releases.get(), 0);
    let current = owner.capture_parent(parent).unwrap();
    owner
        .admit_child(current, current, &row, BirthAttachment::Parent, None)
        .unwrap()
        .publish(row);
    assert_eq!(
        owner.task(parent).unwrap().children(),
        &BTreeSet::from([key(2, 2), key(3, 3)])
    );
}
#[test]
fn two_children_exit_before_wait_consume_once_and_keep_claims_owned() {
    let mut owner = owner();
    let parent = key(1, 1);
    let first = key(2, 2);
    let second = key(3, 3);
    let first_releases = Rc::new(Cell::new(0));
    let second_releases = Rc::new(Cell::new(0));
    birth(&mut owner, parent, first, first_releases.clone());
    birth(&mut owner, parent, second, second_releases.clone());
    let done = exit(&mut owner, first, None);
    done.effects.cancel_members(Member::cancel);
    let done = exit(&mut owner, second, None);
    done.effects.cancel_members(Member::cancel);
    assert_eq!(first_releases.get(), 0);
    assert!(matches!(
        owner.precheck_wait(parent, query(WaitTarget::Any)).unwrap(),
        WaitReadiness::Ready
    ));
    assert!(
        matches!(owner.scan_wait(parent, query(WaitTarget::Exact(first))).unwrap(), WaitSelection::Exited(receipt) if receipt.key == first && receipt.status.raw() == 5 << 8)
    );
    assert_eq!(first_releases.get(), 0);
    let first_result = owner
        .consume_wait(parent, query(WaitTarget::Exact(first)))
        .unwrap();
    assert_eq!(
        first_result.reaped_record.as_ref().unwrap().receipt.key,
        first
    );
    assert_eq!(first_releases.get(), 0);
    assert_eq!(
        owner.task(parent).unwrap().children_rusage().user_time,
        Duration::from_micros(7)
    );
    assert!(matches!(
        owner
            .consume_wait(parent, query(WaitTarget::Exact(first)))
            .unwrap()
            .selection,
        WaitSelection::NoChild
    ));
    assert!(matches!(
        owner.precheck_wait(parent, query(WaitTarget::Any)).unwrap(),
        WaitReadiness::Ready
    ));
    let second_result = owner.consume_wait(parent, query(WaitTarget::Any)).unwrap();
    assert_eq!(
        second_result.reaped_record.as_ref().unwrap().receipt.key,
        second
    );
    assert_eq!(
        owner.task(parent).unwrap().children_rusage().user_time,
        Duration::from_micros(14)
    );
    drop(first_result);
    assert_eq!((first_releases.get(), second_releases.get()), (1, 0));
    drop(second_result);
    assert_eq!(second_releases.get(), 1);
}
#[test]
fn recycled_numeric_child_does_not_authorize_stale_caller_or_wait() {
    let mut owner = owner();
    let parent = key(1, 1);
    let old = key(2, 2);
    birth(&mut owner, parent, old, Rc::new(Cell::new(0)));
    let done = exit(&mut owner, old, None);
    done.effects.cancel_members(Member::cancel);
    drop(owner.consume_wait(parent, query(WaitTarget::Any)).unwrap());
    let current = key(2, 99);
    birth(&mut owner, parent, current, Rc::new(Cell::new(0)));
    assert!(matches!(owner.task(old), Err(GuestProcessError::Stale(found)) if found == old));
    assert!(
        matches!(owner.precheck_wait(old, query(WaitTarget::Any)), Err(GuestProcessError::Stale(found)) if found == old)
    );
    assert_eq!(owner.task(current).unwrap().key(), current);
}
#[test]
fn released_exact_members_cancel_before_parent_signal_snapshot() {
    let mut owner = owner();
    let parent = key(1, 1);
    let order = Rc::new(RefCell::new(Vec::new()));
    owner.task_mut(parent).unwrap().native_mut().signals.order = order.clone();
    let snapshot = owner.capture_parent(parent).unwrap();
    let row = task(
        key(2, 2),
        Some(parent),
        Rc::new(Cell::new(0)),
        2,
        order.clone(),
    );
    owner
        .admit_child(snapshot, snapshot, &row, BirthAttachment::Parent, None)
        .unwrap()
        .publish(row);
    let done = exit(&mut owner, key(2, 2), None);
    assert!(owner.registry.reservations.is_empty());
    assert!(order.borrow().is_empty());
    let permit = done.effects.cancel_members(Member::cancel);
    assert_eq!(&*order.borrow(), &["cancel", "cancel"]);
    let target = owner.select_exit_parent(&permit).unwrap();
    let notification = target.prepare();
    assert_eq!(notification.parent, parent);
    assert_eq!(notification.signal, Some(LinuxSignal::SIGCHLD));
    assert_eq!(&*order.borrow(), &["cancel", "cancel", "signal"]);
}
#[test]
fn exiting_parent_reparents_live_and_zombie_children_through_shared_topology() {
    let mut owner = owner();
    let root = key(1, 1);
    let parent = key(2, 2);
    let live_child = key(3, 3);
    let dead_child = key(4, 4);
    birth(&mut owner, root, parent, Rc::new(Cell::new(0)));
    birth(&mut owner, parent, live_child, Rc::new(Cell::new(0)));
    birth(&mut owner, parent, dead_child, Rc::new(Cell::new(0)));
    let done = exit(&mut owner, dead_child, None);
    done.effects.cancel_members(Member::cancel);
    let done = exit(&mut owner, parent, None);
    done.effects.cancel_members(Member::cancel);
    assert_eq!(owner.task(live_child).unwrap().parent(), Some(root));
    assert_eq!(
        owner.registry.zombies[&dead_child.id].receipt.parent,
        Some(root)
    );
    assert_eq!(
        owner.task(root).unwrap().children(),
        &BTreeSet::from([parent, live_child, dead_child])
    );
    let consumed = owner
        .consume_wait(root, query(WaitTarget::Exact(dead_child)))
        .unwrap();
    assert_eq!(consumed.reaped_record.unwrap().receipt.key, dead_child);
}
#[test]
fn shared_explicit_subreaper_adopts_orphans_and_preserves_subtree_cpu_charge() {
    let mut owner = owner();
    let root = key(1, 1);
    let subreaper = key(2, 2);
    let exiting = key(3, 3);
    let child = key(4, 4);
    birth(&mut owner, root, subreaper, Rc::new(Cell::new(0)));
    birth(&mut owner, subreaper, exiting, Rc::new(Cell::new(0)));
    birth(&mut owner, exiting, child, Rc::new(Cell::new(0)));
    let done = exit(&mut owner, child, None);
    done.effects.cancel_members(Member::cancel);
    drop(
        owner
            .consume_wait(exiting, query(WaitTarget::Exact(child)))
            .unwrap(),
    );
    let orphan = key(5, 5);
    birth(&mut owner, exiting, orphan, Rc::new(Cell::new(0)));
    let done = exit(&mut owner, exiting, Some(subreaper));
    done.effects.cancel_members(Member::cancel);
    assert_eq!(owner.task(orphan).unwrap().parent(), Some(subreaper));
    let consumed = owner
        .consume_wait(subreaper, query(WaitTarget::Exact(exiting)))
        .unwrap();
    assert!(
        matches!(consumed.selection, WaitSelection::Exited(receipt) if receipt.total_charge_to_reaper().user_time == Duration::from_micros(14))
    );
    assert_eq!(
        owner.task(subreaper).unwrap().children_rusage().user_time,
        Duration::from_micros(14)
    );
}
#[test]
fn autoreap_returns_owned_receipt_without_cpu_charge_or_wait_edge() {
    let mut owner = owner();
    let parent = key(1, 1);
    owner.task_mut(parent).unwrap().native_mut().autoreap = true;
    let releases = Rc::new(Cell::new(0));
    birth(&mut owner, parent, key(2, 2), releases.clone());
    let done = exit(&mut owner, key(2, 2), None);
    let permit = done.effects.cancel_members(Member::cancel);
    assert_eq!(permit.parent(), Some(parent));
    assert!(owner.registry.zombies.is_empty());
    assert!(owner.task(parent).unwrap().children().is_empty());
    assert_eq!(
        owner.task(parent).unwrap().children_rusage(),
        TaskRusage::default()
    );
    assert!(matches!(
        owner.precheck_wait(parent, query(WaitTarget::Any)).unwrap(),
        WaitReadiness::NoChild
    ));
    assert_eq!(releases.get(), 0);
    assert_eq!(
        done.autoreaped_receipt.as_ref().unwrap().receipt.key,
        key(2, 2)
    );
    drop(done.autoreaped_receipt);
    assert_eq!(releases.get(), 1);
}
#[test]
fn dropping_reserved_exit_rolls_back_exact_reservation_without_state_change() {
    let mut owner = owner();
    let parent = key(1, 1);
    birth(&mut owner, parent, key(2, 2), Rc::new(Cell::new(0)));
    birth(&mut owner, key(2, 2), key(3, 3), Rc::new(Cell::new(0)));
    let revision = owner.capture_parent(parent).unwrap().revision;
    {
        let _reserved = owner
            .prepare_exit(key(2, 2), None)
            .unwrap()
            .reserve(Transaction(4))
            .unwrap();
    }
    assert!(owner.registry.reservations.is_empty());
    assert_eq!(owner.capture_parent(parent).unwrap().revision, revision);
    assert_eq!(
        owner.task(key(2, 2)).unwrap().lifecycle(),
        TaskLifecycle::Live
    );
    assert_eq!(
        owner.task(parent).unwrap().native().budget.reserved.get(),
        0
    );
    assert_eq!(
        owner
            .task(key(3, 3))
            .unwrap()
            .native()
            .budget
            .reserved
            .get(),
        0
    );
}
#[test]
fn early_error_after_exit_begin_preserves_live_graph_and_reservation_custody() {
    let mut owner = owner();
    let root = key(1, 1);
    let exiting = key(2, 2);
    let live = key(3, 3);
    let dead = key(4, 4);
    let releases = Rc::new(Cell::new(0));
    birth(&mut owner, root, exiting, releases.clone());
    birth(&mut owner, exiting, live, releases.clone());
    birth(&mut owner, exiting, dead, releases.clone());
    exit(&mut owner, dead, None)
        .effects
        .cancel_members(Member::cancel);
    let snapshot: Vec<_> = [root, exiting, live]
        .into_iter()
        .map(|key| {
            let row = owner.task(key).unwrap();
            (
                key,
                row.parent(),
                row.children().clone(),
                row.revision(),
                row.identity(),
            )
        })
        .collect();
    let dead_parent = owner.registry.zombies[&dead.id].receipt.parent;
    let order = owner.task(exiting).unwrap().native().signals.order.clone();
    let aborted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(), ()> {
        let _pending = owner
            .prepare_exit(exiting, None)
            .unwrap()
            .reserve(Transaction(20))
            .unwrap()
            .begin(LinuxWaitStatus::from_wait_encoding(7 << 8))
            .unwrap();
        Err(())
    }));
    assert!(
        matches!(aborted, Ok(Err(()))),
        "unpublished exit abandonment invoked fail-stop"
    );
    assert!(owner.registry.reservations.is_empty());
    assert!(owner.registry.retiring_tasks.is_empty());
    assert_eq!(owner.registry.tasks.len(), 3);
    assert_eq!(owner.registry.zombies.len(), 1);
    assert_eq!(owner.registry.zombies[&dead.id].receipt.parent, dead_parent);
    for (key, parent, children, revision, identity) in snapshot {
        let row = owner.task(key).unwrap();
        assert_eq!(row.lifecycle(), TaskLifecycle::Live);
        assert_eq!(
            (row.parent(), row.children(), row.revision(), row.identity()),
            (parent, &children, revision, identity)
        );
        assert_eq!(row.native().budget.reserved.get(), 0);
    }
    assert_eq!(releases.get(), 0);
    assert!(order.borrow().is_empty());
    // A fresh admission proves that no stale participant or reservation gate
    // survived the abandoned one, and only publication changes the graph.
    exit(&mut owner, exiting, None)
        .effects
        .cancel_members(Member::cancel);
    assert_eq!(owner.task(live).unwrap().parent(), Some(root));
    assert_eq!(owner.registry.zombies[&dead.id].receipt.parent, Some(root));
}

#[test]
fn adapter_exit_work_visits_exactly_own_members_and_no_unrelated_native_resources() {
    for count in [0, 1, 8, 32, 128] {
        let mut owner = owner();
        let parent = key(1, 1);
        let snapshot = owner.capture_parent(parent).unwrap();
        let row = task(
            key(2, 2),
            Some(parent),
            Rc::new(Cell::new(0)),
            count,
            Rc::new(RefCell::new(Vec::new())),
        );
        let work = row.native().work.clone();
        owner
            .admit_child(snapshot, snapshot, &row, BirthAttachment::Parent, None)
            .unwrap()
            .publish(row);
        let mut unrelated = Vec::new();
        for id in 1000..1512 {
            let row = task(
                key(id, id as u64),
                None,
                Rc::new(Cell::new(0)),
                1,
                Rc::new(RefCell::new(Vec::new())),
            );
            unrelated.push(row.native().work.clone());
            // Test-only sole-registry population setup, never a second selector.
            let key = row.key();
            owner
                .registry
                .process_groups
                .get_mut(&row.identity().process_group)
                .unwrap()
                .members
                .insert(key);
            owner.registry.tasks.insert(key.id, row);
        }
        let done = exit(&mut owner, key(2, 2), None);
        let mut cancelled = 0;
        done.effects.cancel_members(|member| {
            assert_eq!(member.exit_task(), key(2, 2));
            cancelled += 1;
        });
        assert_eq!(cancelled, count);
        assert_eq!(work.member_visits.get(), count);
        assert_eq!(work.resource_visits.get(), 1);
        assert_eq!(work.signal_reads.get(), 0);
        for work in unrelated {
            assert_eq!(
                (
                    work.member_visits.get(),
                    work.resource_visits.get(),
                    work.signal_reads.get(),
                    work.revision_reads.get()
                ),
                (0, 0, 0, 0)
            );
        }
    }
}

#[test]
fn wrong_exact_member_is_refused_before_begin_and_reserved_drop_rolls_back() {
    let mut owner = owner();
    birth(&mut owner, key(1, 1), key(2, 2), Rc::new(Cell::new(0)));
    owner.task_mut(key(2, 2)).unwrap().native_mut().task = key(3, 3);
    let error = {
        let result = owner
            .prepare_exit(key(2, 2), None)
            .unwrap()
            .reserve(Transaction(9))
            .unwrap()
            .begin(LinuxWaitStatus::from_wait_encoding(0));
        match result {
            Err(error) => error,
            Ok(pending) => {
                let _ = pending.publish();
                panic!("shared begin accepted a member of another exact task");
            }
        }
    };
    assert!(
        matches!(error, GuestProcessError::Exit(ExitError::Topology(found)) if found == key(2, 2).id)
    );
    assert!(owner.registry.reservations.is_empty());
    assert_eq!(
        owner.task(key(2, 2)).unwrap().lifecycle(),
        TaskLifecycle::Live
    );
}
#[test]
fn adapter_wait_work_visits_only_own_children_with_512_unrelated_rows() {
    for count in [1, 8, 32, 128] {
        let mut owner = owner();
        let parent = key(1, 1);
        let mut own = Vec::new();
        for id in 2..count + 2 {
            birth(
                &mut owner,
                parent,
                key(id, id as u64),
                Rc::new(Cell::new(0)),
            );
            own.push(
                owner
                    .task(key(id, id as u64))
                    .unwrap()
                    .native()
                    .work
                    .clone(),
            );
        }
        let mut unrelated = Vec::new();
        for id in 1000..1512 {
            let row = task(
                key(id, id as u64),
                None,
                Rc::new(Cell::new(0)),
                1,
                Rc::new(RefCell::new(Vec::new())),
            );
            let key = row.key();
            unrelated.push(row.native().work.clone());
            owner
                .registry
                .process_groups
                .get_mut(&row.identity().process_group)
                .unwrap()
                .members
                .insert(key);
            owner.registry.tasks.insert(key.id, row);
        }
        assert!(
            matches!(owner.precheck_wait(parent, query(WaitTarget::Any)).unwrap(), WaitReadiness::StillRunning(token) if token.wake_generation().raw() == 11)
        );
        for work in own {
            assert_eq!(work.event_reads.get(), 1);
        }
        for work in unrelated {
            assert_eq!(work.event_reads.get(), 0);
        }
    }
}

#[test]
fn copied_wait_status_must_not_reap_a_newly_ready_other_child() {
    use super::super::native_process_entry::{WaitWork, scan_wait};
    let mut owner = owner();
    let parent = key(1, 1);
    let first = key(2, 2);
    let child = key(3, 3);
    birth(&mut owner, parent, first, Rc::new(Cell::new(0)));
    birth(&mut owner, parent, child, Rc::new(Cell::new(0)));
    let _ = exit(&mut owner, child, None);
    let WaitWork::Status(observed) = scan_wait(&owner, parent, query(WaitTarget::Any)).unwrap()
    else {
        panic!("zombie")
    };
    let observed_key = observed.zombie().key;
    let copied = observed.copy_with(|_| Ok::<_, ()>(())).unwrap();
    let _ = exit(&mut owner, first, None);
    let super::super::native_process_entry::CopiedWaitOutcome::Consumed(consumed) =
        copied.consume(&mut owner).unwrap()
    else {
        panic!("authorized reap")
    };
    let WaitSelection::Exited(consumed) = consumed.selection else {
        panic!("zombie")
    };
    assert_eq!(consumed.key, observed_key);
    assert!(matches!(
        owner
            .scan_wait(parent, query(WaitTarget::Exact(first)))
            .unwrap(),
        WaitSelection::Exited(_)
    ));
}

#[test]
fn competing_reap_keeps_original_any_and_group_query() {
    use super::super::native_process_entry::{CopiedWaitOutcome, WaitWork, scan_wait};
    for target in [
        WaitTarget::Any,
        WaitTarget::ProcessGroup(TaskIdentity::led_by(key(1, 1).id).process_group),
    ] {
        for replacement_ready in [false, true] {
            let mut owner = owner();
            let parent = key(1, 1);
            let selected = key(2, 2);
            let remaining = key(3, 3);
            let releases = Rc::new(Cell::new(0));
            birth(&mut owner, parent, selected, Rc::new(Cell::new(0)));
            birth(&mut owner, parent, remaining, releases.clone());
            let _ = exit(&mut owner, selected, None);
            let WaitWork::Status(observed) = scan_wait(&owner, parent, query(target)).unwrap()
            else {
                panic!("zombie")
            };
            let copied = observed
                .copy_with(|zombie| {
                    assert_eq!(zombie.key, selected);
                    Ok::<_, ()>(())
                })
                .unwrap();
            drop(
                owner
                    .consume_wait(parent, query(WaitTarget::Exact(selected)))
                    .unwrap(),
            );
            if replacement_ready {
                let _ = exit(&mut owner, remaining, None);
            }
            let CopiedWaitOutcome::Rescan(selection) = copied.consume(&mut owner).unwrap() else {
                panic!("original query must be rescanned")
            };
            if replacement_ready {
                let WaitWork::Status(replacement) = selection else {
                    panic!("fresh status copy required")
                };
                assert_eq!(replacement.zombie().key, remaining);
                assert_eq!(releases.get(), 0);
                assert!(matches!(
                    owner
                        .scan_wait(parent, query(WaitTarget::Exact(remaining)))
                        .unwrap(),
                    WaitSelection::Exited(_)
                ));
                let copied = replacement
                    .copy_with(|zombie| {
                        assert_eq!(zombie.key, remaining);
                        Ok::<_, ()>(())
                    })
                    .unwrap();
                let CopiedWaitOutcome::Consumed(consumed) = copied.consume(&mut owner).unwrap()
                else {
                    panic!("fresh authorization")
                };
                assert!(
                    matches!(consumed.selection, WaitSelection::Exited(ref zombie) if zombie.key == remaining)
                );
                drop(consumed);
                assert_eq!(releases.get(), 1);
            } else {
                assert!(matches!(
                    selection,
                    WaitWork::Other(WaitSelection::StillRunning(_))
                ));
            }
        }
    }
}

#[test]
fn failed_external_status_copy_leaves_zombie_and_claim_owned() {
    use super::super::native_process_entry::{WaitWork, scan_wait};
    let mut owner = owner();
    let parent = key(1, 1);
    let child = key(2, 2);
    let releases = Rc::new(Cell::new(0));
    birth(&mut owner, parent, child, releases.clone());
    let _ = exit(&mut owner, child, None);
    let WaitWork::Status(work) = scan_wait(&owner, parent, query(WaitTarget::Any)).unwrap() else {
        panic!("zombie")
    };
    assert!(work.copy_with(|_| Err::<(), _>(14)).is_err());
    assert_eq!(releases.get(), 0);
    assert!(matches!(
        owner
            .scan_wait(parent, query(WaitTarget::Exact(child)))
            .unwrap(),
        WaitSelection::Exited(_)
    ));
}

#[test]
fn visible_child_pid_lookup_survives_exit_and_rejects_unowned_rows() {
    let mut owner = owner();
    let parent = key(1, 1);
    let child = key(2, 2);
    let snapshot = owner.capture_parent(parent).unwrap();
    let mut row = task(
        child,
        Some(parent),
        Rc::new(Cell::new(0)),
        1,
        Rc::new(RefCell::new(Vec::new())),
    );
    row.metadata.namespace_pid = 72;
    owner
        .admit_child(snapshot, snapshot, &row, BirthAttachment::Parent, None)
        .unwrap()
        .publish(row);
    assert_eq!(owner.namespace_child_key(parent, 72).unwrap(), Some(child));
    assert_eq!(owner.namespace_child_key(parent, 2).unwrap(), None);
    assert_eq!(owner.namespace_child_key(child, 72).unwrap(), None);
    let _ = exit(&mut owner, child, None);
    assert_eq!(owner.namespace_child_key(parent, 72).unwrap(), Some(child));
    drop(
        owner
            .consume_wait(parent, query(WaitTarget::Exact(child)))
            .unwrap(),
    );
    assert_eq!(owner.namespace_child_key(parent, 72).unwrap(), None);
}

#[test]
fn entry_fork_admission_precedes_mm_commit_and_returns_reserved_publication() {
    use super::super::native_process_entry::PreparedFork;
    let mut owner = owner();
    let parent = key(1, 1);
    let child = key(2, 2);
    let releases = Rc::new(Cell::new(0));
    let row = task(
        child,
        Some(parent),
        releases.clone(),
        1,
        Rc::new(RefCell::new(Vec::new())),
    );
    let committed = Rc::new(Cell::new(0));
    let prep = match PreparedFork::prepare(
        &mut owner,
        parent,
        parent,
        row,
        committed.clone(),
        BirthAttachment::Parent,
        Transaction(83),
    ) {
        Ok(prep) => prep,
        Err(_) => panic!("prepare"),
    };
    assert!(matches!(
        owner.precheck_wait(parent, query(WaitTarget::Any)),
        Err(GuestProcessError::Wait(WaitError::Busy(_)))
    ));
    let published = match prep.publish_with(&mut owner, |mm| {
        mm.set(mm.get() + 1);
        child
    }) {
        Ok(published) => published,
        Err(_) => panic!("publish"),
    };
    assert_eq!(published.born, child);
    assert_eq!(committed.get(), 1);
    assert_eq!(releases.get(), 0);
    owner.release_birth(&published.reservation).unwrap();
    assert_eq!(owner.task(child).unwrap().parent(), Some(parent));
}

#[test]
fn entry_fork_abort_returns_mm_and_child_custody_without_publication() {
    use super::super::native_process_entry::PreparedFork;
    let mut owner = owner();
    let parent = key(1, 1);
    let child = key(2, 2);
    let row = task(
        child,
        Some(parent),
        Rc::new(Cell::new(0)),
        1,
        Rc::new(RefCell::new(Vec::new())),
    );
    let prep = match PreparedFork::prepare(
        &mut owner,
        parent,
        parent,
        row,
        97u32,
        BirthAttachment::Parent,
        Transaction(84),
    ) {
        Ok(prep) => prep,
        Err(_) => panic!("prepare"),
    };
    let (row, mm) = match prep.abort(&mut owner) {
        Ok(returned) => returned,
        Err(_) => panic!("abort"),
    };
    assert_eq!(row.key(), child);
    assert_eq!(mm, 97);
    assert!(owner.task(child).is_err());
    assert_eq!(
        owner.precheck_wait(parent, query(WaitTarget::Any)).unwrap(),
        WaitReadiness::NoChild
    );
}

#[test]
fn entry_exit_returns_resources_and_cancel_effects_before_native_service() {
    use super::super::native_process_entry::publish_exit;
    let mut owner = owner();
    let parent = key(1, 1);
    let child = key(2, 2);
    birth(&mut owner, parent, child, Rc::new(Cell::new(0)));
    let work = owner.task(child).unwrap().native().work.clone();
    let (resources, published) = publish_exit(
        &mut owner,
        child,
        None,
        Transaction(85),
        LinuxWaitStatus::from_wait_encoding(9 << 8),
    )
    .unwrap();
    assert!(Rc::ptr_eq(&resources.unwrap(), &work));
    assert_eq!(work.signal_reads.get(), 0);
    assert!(owner.task(child).is_err());
    assert!(matches!(
        owner
            .scan_wait(parent, query(WaitTarget::Exact(child)))
            .unwrap(),
        WaitSelection::Exited(_)
    ));
    drop(published);
}

impl<C: ProcessContext> super::super::native_process_custody::ProcessResources for Native<C> {
    type Context = C;
    type Claim = Claim;
    type Event = ();
    type Transaction = Transaction;
    type Member = Member;
    type Resources = Rc<Work>;
    type SignalTarget = Signals;
    fn wait_event(&self, flags: WaitJobControl, consume: bool) -> Option<()> {
        NativeProcessCustody::wait_event(self, flags, consume)
    }
    fn own_members_and_resources(&self) -> (Vec<Member>, Rc<Work>) {
        NativeProcessCustody::own_members_and_resources(self)
    }
    fn signal_target(&self) -> Signals {
        NativeProcessCustody::signal_target(self)
    }
    fn autoreaps_children(&self) -> bool {
        NativeProcessCustody::autoreaps_children(self)
    }
    fn own_rusage(&self) -> TaskRusage {
        NativeProcessCustody::own_rusage(self)
    }
}

#[test]
fn entry_adapter_uses_retained_primitive_custody_through_fork_exit_wait() {
    use super::super::native_process_custody::RetainedProcessCustody;
    use super::super::native_process_entry::{PreparedFork, WaitWork, publish_exit, scan_wait};
    fn retained(row: Task) -> GuestTask<(), Uid, RetainedProcessCustody<Native>> {
        let parent = row.parent();
        GuestTask::new(
            row.metadata,
            parent,
            row.context,
            RetainedProcessCustody::new(row.native),
            row.claim,
        )
    }
    let mut owner = GuestProcessOwner::<(), Uid, RetainedProcessCustody<Native>, Failure>::new();
    let parent = key(1, 1);
    let child = key(2, 2);
    owner
        .seed_initial(retained(task(
            parent,
            None,
            Rc::new(Cell::new(0)),
            1,
            Rc::new(RefCell::new(Vec::new())),
        )))
        .unwrap();
    let releases = Rc::new(Cell::new(0));
    let row = retained(task(
        child,
        Some(parent),
        releases.clone(),
        1,
        Rc::new(RefCell::new(Vec::new())),
    ));
    let prepared = match PreparedFork::prepare(
        &mut owner,
        parent,
        parent,
        row,
        (),
        BirthAttachment::Parent,
        Transaction(89),
    ) {
        Ok(prepared) => prepared,
        Err(_) => panic!("prepare"),
    };
    let published = match prepared.publish_with(&mut owner, |()| ()) {
        Ok(published) => published,
        Err(_) => panic!("publish"),
    };
    owner.release_birth(&published.reservation).unwrap();
    let (resources, effects) = publish_exit(
        &mut owner,
        child,
        None,
        Transaction(90),
        LinuxWaitStatus::from_wait_encoding(4 << 8),
    )
    .unwrap();
    assert!(resources.is_some());
    drop(effects);
    let WaitWork::Status(status) = scan_wait(&owner, parent, query(WaitTarget::Any)).unwrap()
    else {
        panic!("status")
    };
    let copied = status
        .copy_with(|zombie| {
            assert_eq!(zombie.key, child);
            Ok::<_, ()>(())
        })
        .unwrap();
    let super::super::native_process_entry::CopiedWaitOutcome::Consumed(consumed) =
        copied.consume(&mut owner).unwrap()
    else {
        panic!("authorized reap")
    };
    assert_eq!(releases.get(), 0);
    drop(consumed);
    assert_eq!(releases.get(), 1);
}

#[test]
fn failed_mm_commit_keeps_unpublished_child_preparation_and_exact_reservation() {
    use super::super::native_process_entry::{ForkTryError, PreparedFork};
    let mut owner = owner();
    let parent = key(1, 1);
    let child = key(2, 2);
    let releases = Rc::new(Cell::new(0));
    let row = task(
        child,
        Some(parent),
        releases.clone(),
        1,
        Rc::new(RefCell::new(Vec::new())),
    );
    let prep = match PreparedFork::prepare(
        &mut owner,
        parent,
        parent,
        row,
        97u32,
        BirthAttachment::Parent,
        Transaction(93),
    ) {
        Ok(prep) => prep,
        Err(_) => panic!("prepare"),
    };
    let ForkTryError::Commit(error, prep) = prep
        .try_publish_with(&mut owner, |mm| Err::<(), _>((14, mm)))
        .err()
        .unwrap()
    else {
        panic!("commit refusal")
    };
    assert_eq!(error, 14);
    assert_eq!(releases.get(), 0);
    assert!(owner.task(child).is_err());
    assert!(matches!(
        owner.precheck_wait(parent, query(WaitTarget::Any)),
        Err(GuestProcessError::Wait(WaitError::Busy(_)))
    ));
    let (_, mm) = match prep.abort(&mut owner) {
        Ok(returned) => returned,
        Err(_) => panic!("abort"),
    };
    assert_eq!(mm, 97);
}
#[test]
fn namespace_child_group_resolves_a_child_job_group_and_preserves_scope() {
    let mut owner = owner();
    let parent = key(1, 1);
    let selected = key(2, 2);
    let other = key(3, 3);
    birth(&mut owner, parent, selected, Rc::new(Cell::new(0)));
    birth(&mut owner, parent, other, Rc::new(Cell::new(0)));
    let group = carrick_sched_core::process::ProcessGroupId::from_leader(selected.id);
    let old_group = owner.task(selected).unwrap().identity().process_group;
    owner
        .registry
        .process_groups
        .get_mut(&old_group)
        .unwrap()
        .members
        .remove(&selected);
    let row = owner.registry.tasks.get_mut(&selected.id).unwrap();
    row.metadata.identity.process_group = group;
    row.metadata.namespace_process_group = 42;
    owner.registry.publish_process_group(
        group,
        ProcessGroupRecord {
            object: (),
            members: BTreeSet::from([selected]),
            container: (),
            namespace_id: 42,
        },
    );
    assert_eq!(
        owner.namespace_child_group(parent, 42).unwrap(),
        Some(group)
    );
    assert_eq!(owner.namespace_child_group(parent, 99).unwrap(), None);
    let _ = exit(&mut owner, other, None);
    assert!(matches!(
        owner
            .scan_wait(parent, query(WaitTarget::ProcessGroup(group)))
            .unwrap(),
        WaitSelection::StillRunning(_)
    ));
    let _ = exit(&mut owner, selected, None);
    assert_eq!(
        owner.namespace_child_group(parent, 42).unwrap(),
        Some(group)
    );
    let result = owner
        .consume_wait(parent, query(WaitTarget::ProcessGroup(group)))
        .unwrap();
    assert!(
        matches!(result.selection, WaitSelection::Exited(ref zombie) if zombie.key == selected)
    );
    drop(result);
    assert_eq!(owner.namespace_child_group(parent, 42).unwrap(), None);
    assert!(matches!(
        owner
            .scan_wait(parent, query(WaitTarget::Exact(other)))
            .unwrap(),
        WaitSelection::Exited(_)
    ));
}

#[test]
fn nonchild_wait_has_no_ptrace_relationship_and_preserves_own_children() {
    let mut owner = owner();
    let root = key(1, 1);
    let caller = key(2, 2);
    let own_child = key(3, 3);
    let peer = key(4, 4);
    let releases = Rc::new(Cell::new(0));
    birth(&mut owner, root, caller, releases.clone());
    birth(&mut owner, caller, own_child, releases.clone());
    birth(&mut owner, root, peer, releases.clone());
    assert_eq!(owner.task(caller).unwrap().wait_identity().tracer, None);
    assert!(owner.task(caller).unwrap().wait_tracees().is_empty());
    assert_eq!(owner.namespace_child_key(caller, 4).unwrap(), None);
    assert!(matches!(
        owner
            .scan_wait(caller, query(WaitTarget::Exact(peer)))
            .unwrap(),
        WaitSelection::NoChild
    ));
    assert_eq!(
        owner.namespace_child_key(caller, 3).unwrap(),
        Some(own_child)
    );
    assert!(matches!(
        owner.scan_wait(caller, query(WaitTarget::Any)).unwrap(),
        WaitSelection::StillRunning(_)
    ));
    assert_eq!(releases.get(), 0);
}

#[test]
fn owner_instantiated_with_aarch64_context_checks_fork_child_and_syscall_return() {
    let parent_addr = address(key(1, 1));
    let mut thread = carrick_sched_core::ThreadCtx::ZERO;
    thread.x[0] = 0xdead_beef;
    thread.x[1] = 0x1234;
    thread.pc = 0x400000;
    thread.sp_el0 = 0x800000;

    let arm_ctx = carrick_sched_core::Aarch64ParkedContext::from_parts(thread, parent_addr);

    // (a) ARM context authenticates against its own binding and REFUSES a binding differing in each of root, mm, and generation (three refusals)
    assert!(arm_ctx.authenticates(parent_addr));

    let diff_root = AddressContext {
        root: RootGpa::page_aligned(FrameGpa::new(0x9000)).unwrap(),
        mm: parent_addr.mm,
        generation: parent_addr.generation,
    };
    assert!(!arm_ctx.authenticates(diff_root));

    let diff_mm = AddressContext {
        root: parent_addr.root,
        mm: MmGeneration::new(NonZeroU64::new(parent_addr.mm.raw().get() + 99).unwrap()),
        generation: parent_addr.generation,
    };
    assert!(!arm_ctx.authenticates(diff_mm));

    let diff_gen = AddressContext {
        root: parent_addr.root,
        mm: parent_addr.mm,
        generation: ContextGeneration::new(
            NonZeroU64::new(parent_addr.generation.raw().get() + 99).unwrap(),
        ),
    };
    assert!(!arm_ctx.authenticates(diff_gen));

    // ASID in upper register bits authenticates against clean page-aligned GPA
    let asid_ctx = carrick_sched_core::Aarch64ParkedContext::from_register(
        thread,
        0xabcd_0000_0000_0000 | parent_addr.root.address().raw(),
        parent_addr.mm.raw().get(),
        parent_addr.generation.raw().get(),
    );
    assert!(asid_ctx.authenticates(parent_addr));
    assert!(!asid_ctx.authenticates(diff_root));

    // (b) fork_child yields x0 = 0 and the child binding, and the child refuses the parent's binding
    let child_addr = address(key(2, 1));
    let child_ctx = arm_ctx.fork_child(child_addr);
    assert_eq!(child_ctx.syscall_return(), 0);
    assert_eq!(child_ctx.native.x[0], 0);
    assert_eq!(child_ctx.native.x[1], 0x1234);
    assert_eq!(child_ctx.native.pc, 0x400000);
    assert_eq!(child_ctx.native.sp_el0, 0x800000);

    // Child authenticates against child binding
    assert!(child_ctx.authenticates(child_addr));

    // Child REFUSES parent's binding
    assert!(!child_ctx.authenticates(parent_addr));

    // Also test set_syscall_return
    let mut returned_ctx = arm_ctx;
    returned_ctx.set_syscall_return(42);
    assert_eq!(returned_ctx.syscall_return(), 42);
    assert_eq!(returned_ctx.native.x[0], 42);
    assert_eq!(returned_ctx.native.x[1], 0x1234);

    // Instantiate GuestProcessOwner with Native<Aarch64ParkedContext>
    let releases = Rc::new(Cell::new(0));
    let native = Native {
        context_type: PhantomData::<carrick_sched_core::Aarch64ParkedContext>,
        task: key(1, 1),
        members: 1,
        work: Rc::new(Work::default()),
        budget: Rc::new(Budget {
            reserved: Cell::new(0),
        }),
        signals: Signals {
            state: Rc::new(Cell::new(ExitSignalState {
                disposition: ExitSignalDisposition::Caught,
                blocked: false,
            })),
            order: Rc::new(RefCell::new(Vec::new())),
            work: Rc::new(Work::default()),
        },
        autoreap: false,
        own_usage: TaskRusage {
            user_time: Duration::from_micros(7),
            system_time: Duration::from_micros(3),
        },
        wake: 11,
    };
    let task = GuestTask::new(
        GuestTaskMetadata {
            key: key(1, 1),
            container: (),
            namespace_pid: 1,
            identity: TaskIdentity::led_by(key(1, 1).id),
            namespace_process_group: 1,
            namespace_session: 1,
            receipt_uid: |uid| Uid(uid.raw()),
            exit_signal: ChildExitSignal::SIGCHLD,
            diagnostic_name: "native_arm".into(),
        },
        None,
        returned_ctx,
        native,
        Claim(releases),
    );
    let mut owner = GuestProcessOwner::<
        (),
        Uid,
        Native<carrick_sched_core::Aarch64ParkedContext>,
        Failure,
    >::new();
    owner.seed_initial(task).unwrap();
    let row = owner.task(key(1, 1)).unwrap();
    assert_eq!(row.context().syscall_return(), 42);
    assert_eq!(row.context().native.x[0], 42);
    assert!(row.context().authenticates(parent_addr));
    assert!(!row.context().authenticates(child_addr));
}

#[test]
fn group_exists_in_session_checks_live_tasks() {
    let o = owner();
    assert!(o.group_exists_in_session(1, 1));
    assert!(!o.group_exists_in_session(1, 2));
    assert!(!o.group_exists_in_session(2, 1));
}

#[test]
fn exit_uid_receipt_reads_thread_credentials_without_a_metadata_mirror() {
    for exit_tid in [2, 50] {
        let mut owner = owner();
        let child = key(2, 2);
        birth(&mut owner, key(1, 1), child, Rc::new(Cell::new(0)));
        let row = owner.task_mut(child).unwrap();
        if exit_tid != 2 {
            row.spawn_thread(2, exit_tid).unwrap();
        }
        row.credentials_for_mut(exit_tid).unwrap().ruid =
            carrick_sched_core::process::TaskUid::new(1000);
        row.select_exit_thread(exit_tid).unwrap();
        let done = exit(&mut owner, child, None);
        done.effects.cancel_members(Member::cancel);
        assert_eq!(owner.registry.zombies[&child.id].receipt.ruid, Uid(1000));
        assert_eq!(
            owner
                .task(key(1, 1))
                .unwrap()
                .credentials_for(1)
                .unwrap()
                .ruid
                .raw(),
            0
        );
    }
}
