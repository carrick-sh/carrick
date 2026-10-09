//! Retained primitive resource custody for the shared guest process owner.
//! Graph admission and Linux lifecycle policy stay in `process_owner`.
extern crate alloc;
use super::process_owner::NativeProcessCustody;
use alloc::{sync::Arc, vec::Vec};
use carrick_sched_core::process::{
    ProcessContext, TaskRusage,
    exit::{ExitMember, ExitSignalSource, TaskRevision},
    wait::{TaskWakeGeneration, WaitJobControl},
};
use core::sync::atomic::{AtomicU64, Ordering};

/// Native handles supplied by the execution lane. These accesses do not choose
/// graph participants or implement Linux wait, exit, or signal policy.
pub trait ProcessResources {
    type Context: ProcessContext;
    type Claim;
    type Event;
    type Transaction: Copy + Eq;
    type Member: ExitMember;
    type Resources;
    type SignalTarget: ExitSignalSource;
    fn wait_event(&self, flags: WaitJobControl, consume: bool) -> Option<Self::Event>;
    fn own_members_and_resources(&self) -> (Vec<Self::Member>, Self::Resources);
    fn signal_target(&self) -> Self::SignalTarget;
    fn autoreaps_children(&self) -> bool;
    fn own_rusage(&self) -> TaskRusage;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CustodyExhausted;

/// Wake generation belongs to a task and is retained by its wait continuation.
#[derive(Clone)]
pub struct ProcessWake(Arc<AtomicU64>);
impl Default for ProcessWake {
    fn default() -> Self {
        Self::new()
    }
}
impl ProcessWake {
    pub fn new() -> Self {
        Self(Arc::new(AtomicU64::new(0)))
    }
    pub fn generation(&self) -> TaskWakeGeneration {
        TaskWakeGeneration::from_task_counter(self.0.load(Ordering::Acquire))
    }
    pub fn publish(&self) -> Result<TaskWakeGeneration, CustodyExhausted> {
        let previous = self
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .map_err(|_| CustodyExhausted)?;
        Ok(TaskWakeGeneration::from_task_counter(previous + 1))
    }
}

/// One reserved publication step, returned automatically when admission drops.
pub struct RevisionCredit {
    source: Arc<AtomicU64>,
    remaining: bool,
}
impl Drop for RevisionCredit {
    fn drop(&mut self) {
        if self.remaining {
            self.source.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Caller owns exclusive graph access when requesting or consuming revision
/// credits. The retained atomic counter keeps dropped preparations independent
/// of the lifetime of a borrow of the live row.
pub struct RetainedProcessCustody<R> {
    resources: R,
    reserved: Arc<AtomicU64>,
    wake: ProcessWake,
}
impl<R> RetainedProcessCustody<R> {
    pub fn new(resources: R) -> Self {
        Self {
            resources,
            reserved: Arc::new(AtomicU64::new(0)),
            wake: ProcessWake::new(),
        }
    }
    pub fn resources(&self) -> &R {
        &self.resources
    }
    pub fn resources_mut(&mut self) -> &mut R {
        &mut self.resources
    }
    pub fn wake(&self) -> ProcessWake {
        self.wake.clone()
    }
}
impl<R: ProcessResources> NativeProcessCustody for RetainedProcessCustody<R> {
    type Context = R::Context;
    type Claim = R::Claim;
    type Event = R::Event;
    type Credit = RevisionCredit;
    type Error = CustodyExhausted;
    type Transaction = R::Transaction;
    type Member = R::Member;
    type Resources = R::Resources;
    type SignalTarget = R::SignalTarget;
    fn next_revision(&self, current: TaskRevision) -> Result<TaskRevision, Self::Error> {
        current
            .raw()
            .checked_add(self.reserved.load(Ordering::Relaxed))
            .and_then(|v| v.checked_add(1))
            .ok_or(CustodyExhausted)?;
        current.next().ok_or(CustodyExhausted)
    }
    fn reserve_exit_credit(
        &self,
        current: TaskRevision,
    ) -> Result<RevisionCredit, CustodyExhausted> {
        self.next_revision(current)?;
        self.reserved.fetch_add(1, Ordering::Relaxed);
        Ok(RevisionCredit {
            source: self.reserved.clone(),
            remaining: true,
        })
    }
    fn consume_exit_credit(
        &self,
        credit: &mut RevisionCredit,
        current: TaskRevision,
    ) -> TaskRevision {
        if !credit.remaining || !Arc::ptr_eq(&credit.source, &self.reserved) {
            super::dispatch::invalid_completion(super::dispatch::NativeInvariant::RevisionCredit);
        }
        let next = current.next().unwrap_or_else(|| {
            super::dispatch::invalid_completion(super::dispatch::NativeInvariant::RevisionCredit)
        });
        credit.remaining = false;
        self.reserved.fetch_sub(1, Ordering::Relaxed);
        next
    }
    fn wait_event(&self, flags: WaitJobControl, consume: bool) -> Option<R::Event> {
        self.resources.wait_event(flags, consume)
    }
    fn wake_generation(&self) -> TaskWakeGeneration {
        self.wake.generation()
    }
    fn own_members_and_resources(&self) -> (Vec<R::Member>, R::Resources) {
        self.resources.own_members_and_resources()
    }
    fn signal_target(&self) -> R::SignalTarget {
        self.resources.signal_target()
    }
    fn autoreaps_children(&self) -> bool {
        self.resources.autoreaps_children()
    }
    fn own_rusage(&self) -> TaskRusage {
        self.resources.own_rusage()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn retained_wake_detects_publication_after_wait_snapshot() {
        let wake = ProcessWake::new();
        let retained = wake.clone();
        let before = retained.generation();
        let after = wake.publish().expect("generation capacity");
        assert_eq!(after.raw(), before.raw() + 1);
        assert_eq!(retained.generation(), after);
    }
    use super::super::process_owner::{GuestProcessOwner, GuestTask, GuestTaskMetadata};
    use carrick_guest_arch::{AddressContext, ContextGeneration, FrameGpa, MmGeneration, RootGpa};
    use carrick_sched_core::{
        ParkedContextWords,
        process::{
            ChildExitSignal, LinuxSignal, LinuxWaitStatus, TaskId, TaskIdentity, TaskKey,
            TaskSerial, WaitChildClass, WaitTarget,
            birth::BirthAttachment,
            exit::{ExitSignalDisposition, ExitSignalState},
            wait::{WaitQuery, WaitReadiness, WaitSelection},
        },
    };
    use core::num::NonZeroU64;
    #[derive(Clone)]
    struct Member(TaskKey);
    impl ExitMember for Member {
        fn exit_task(&self) -> TaskKey {
            self.0
        }
    }
    #[derive(Clone)]
    struct Signals;
    impl ExitSignalSource for Signals {
        fn exit_signal_state(&self, _: LinuxSignal) -> ExitSignalState {
            ExitSignalState {
                disposition: ExitSignalDisposition::Default,
                blocked: false,
            }
        }
    }
    struct Handles {
        task: TaskKey,
    }
    impl ProcessResources for Handles {
        type Context = ParkedContextWords;
        type Claim = ();
        type Event = ();
        type Transaction = u64;
        type Member = Member;
        type Resources = ();
        type SignalTarget = Signals;
        fn wait_event(&self, _: WaitJobControl, _: bool) -> Option<()> {
            None
        }
        fn own_members_and_resources(&self) -> (Vec<Member>, ()) {
            (alloc::vec![Member(self.task)], ())
        }
        fn signal_target(&self) -> Signals {
            Signals
        }
        fn autoreaps_children(&self) -> bool {
            false
        }
        fn own_rusage(&self) -> TaskRusage {
            TaskRusage::default()
        }
    }
    fn key(id: i32) -> TaskKey {
        TaskKey {
            id: TaskId::from_abi_positive(id).unwrap(),
            serial: TaskSerial::from_raw_u64(id as u64).unwrap(),
        }
    }
    type Row = GuestTask<(), (), RetainedProcessCustody<Handles>>;
    fn row(task: TaskKey, parent: Option<TaskKey>, leader: TaskKey) -> Row {
        let address = AddressContext {
            root: RootGpa::page_aligned(FrameGpa::new(task.serial.raw() * 4096)).unwrap(),
            mm: MmGeneration::new(NonZeroU64::new(task.serial.raw()).unwrap()),
            generation: ContextGeneration::new(NonZeroU64::new(1).unwrap()),
        };
        GuestTask::new(
            GuestTaskMetadata {
                key: task,
                container: (),
                namespace_pid: task.id.raw() as u32,
                identity: TaskIdentity::led_by(leader.id),
                namespace_process_group: leader.id.raw() as u32,
                namespace_session: leader.id.raw() as u32,
                receipt_uid: |_| (),
                exit_signal: ChildExitSignal::SIGCHLD,
                diagnostic_name: alloc::string::String::new(),
            },
            parent,
            ParkedContextWords::from_parts(
                [0; 20],
                address,
                0,
                0,
                [0; carrick_sched_core::X86_XSAVE_BYTES],
            ),
            RetainedProcessCustody::new(Handles { task }),
            (),
        )
    }
    #[test]
    fn two_live_children_publish_exit_and_reap_through_shared_owner() {
        let root = key(17);
        let first = key(18);
        let second = key(19);
        let mut owner = GuestProcessOwner::<(), (), RetainedProcessCustody<Handles>>::new();
        owner.seed_initial(row(root, None, root)).unwrap();
        for child in [first, second] {
            let snapshot = owner.capture_parent(root).unwrap();
            let child_row = row(child, Some(root), root);
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
        let query = WaitQuery {
            target: WaitTarget::Any,
            class: WaitChildClass::Sigchld,
            job_control: WaitJobControl::NONE,
        };
        assert!(matches!(
            owner.precheck_wait(root, query).unwrap(),
            WaitReadiness::StillRunning(_)
        ));
        let wake = owner.task(root).unwrap().native().wake();
        for (child, code) in [(second, 7), (first, 9)] {
            let published = owner
                .prepare_exit(child, None)
                .unwrap()
                .reserve(child.serial.raw())
                .unwrap()
                .begin(LinuxWaitStatus::from_wait_encoding(code << 8))
                .unwrap()
                .publish()
                .unwrap();
            let permit = published
                .effects
                .cancel_members(|member| assert_eq!(member.exit_task(), child));
            let parent = owner.select_exit_parent(&permit).unwrap().prepare();
            assert_eq!(parent.parent, root);
            wake.publish().unwrap();
            let exact = WaitQuery {
                target: WaitTarget::Exact(child),
                ..query
            };
            let consumed = owner.consume_wait(root, exact).unwrap();
            assert!(
                matches!(consumed.selection, WaitSelection::Exited(receipt) if receipt.key == child && receipt.status.raw() == code << 8)
            );
            assert!(matches!(
                owner.consume_wait(root, exact).unwrap().selection,
                WaitSelection::NoChild
            ));
        }
        assert!(matches!(
            owner.precheck_wait(root, query).unwrap(),
            WaitReadiness::NoChild
        ));
        assert_eq!(wake.generation().raw(), 2);
    }
    #[test]
    fn dropping_revision_credit_releases_capacity_without_publication() {
        let custody = RetainedProcessCustody::new(Handles { task: key(17) });
        let mut credit = custody.reserve_exit_credit(TaskRevision::INITIAL).unwrap();
        assert_eq!(custody.reserved.load(Ordering::Relaxed), 1);
        let next = custody.consume_exit_credit(&mut credit, TaskRevision::INITIAL);
        assert_eq!(next.raw(), TaskRevision::INITIAL.raw() + 1);
        assert_eq!(custody.reserved.load(Ordering::Relaxed), 0);
        drop(credit);
        let credit = custody.reserve_exit_credit(next).unwrap();
        assert_eq!(custody.reserved.load(Ordering::Relaxed), 1);
        drop(credit);
        assert_eq!(custody.reserved.load(Ordering::Relaxed), 0);
    }
    #[test]
    fn exhausted_wake_refuses_without_wrapping_or_invalidating_snapshot() {
        let wake = ProcessWake::new();
        wake.0.store(u64::MAX, Ordering::Relaxed);
        assert_eq!(wake.publish(), Err(CustodyExhausted));
        assert_eq!(wake.generation().raw(), u64::MAX);
    }
    #[test]
    fn reservation_exhaustion_preserves_existing_publication_credit() {
        let custody = RetainedProcessCustody::new(Handles { task: key(17) });
        custody
            .reserved
            .store(u64::MAX - TaskRevision::INITIAL.raw(), Ordering::Relaxed);
        assert!(custody.next_revision(TaskRevision::INITIAL).is_err());
        assert!(custody.reserve_exit_credit(TaskRevision::INITIAL).is_err());
        assert_eq!(
            custody.reserved.load(Ordering::Relaxed),
            u64::MAX - TaskRevision::INITIAL.raw()
        );
    }
}
