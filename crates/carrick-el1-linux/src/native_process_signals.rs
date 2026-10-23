//! Retained signal resources for an admitted fresh native process.
//! Signal and child-exit decisions remain in the shared Linux signal policy.
extern crate alloc;
use alloc::sync::{Arc, Weak};
use carrick_el1::lock::SpinLock;
use carrick_el1_abi::{Lifecycle, ThreadLifecyclePage};
use carrick_personality_linux::signal::{EnqueueOutcome, SignalInbox, StaleTarget};
use carrick_sched_core::process::exit::{
    DefaultSignalDisposition, ExitSignalDisposition, ExitSignalSource, ExitSignalState,
};
use carrick_sched_core::process::{LinuxSignal, TaskKey};
use carrick_signal_core::SignalSet;
use carrick_signal_core::policy::{
    Action, ActionError, ActionInheritance, ActionTable, ChildEvent, ChildInterest, Disposition,
    SigBlockMask, SighandSharing, Signal, child_decision,
};
use core::ops::Deref;
use core::sync::atomic::{AtomicU64, Ordering};

/// The retained thread control authority supplies the live typed mask.
pub trait BlockedMaskSource {
    fn blocked_mask(&self) -> SigBlockMask;
}
impl BlockedMaskSource for carrick_el1_abi::ThreadControlSlot {
    fn blocked_mask(&self) -> SigBlockMask {
        SigBlockMask::blocking_all_of(SignalSet::from_bits(self.blocked().0))
    }
}
impl<S: BlockedMaskSource + ?Sized> BlockedMaskSource for &S {
    fn blocked_mask(&self) -> SigBlockMask {
        (**self).blocked_mask()
    }
}
impl<S: BlockedMaskSource + ?Sized> BlockedMaskSource for Arc<S> {
    fn blocked_mask(&self) -> SigBlockMask {
        (**self).blocked_mask()
    }
}
use alloc::vec::Vec;
use carrick_personality_linux::signal::PendingSignals;

struct SignalResources<'a, T> {
    actions: ActionTable,
    inbox: SignalInbox<TaskKey, T>,
    thread_pending: Vec<(carrick_sched_core::RecordRef, PendingSignals<T>)>,
    forced_faults: Vec<(carrick_sched_core::RecordRef, Signal)>,
    projections: Vec<(
        carrick_sched_core::RecordRef,
        Weak<NativeSignalProjection<'a, T>>,
    )>,
}

impl<T> SignalResources<'_, T> {
    fn thread_pending_set(&self, record: carrick_sched_core::RecordRef) -> SignalSet {
        self.thread_pending
            .binary_search_by_key(&record, |(record, _)| *record)
            .map_or(SignalSet::EMPTY, |index| {
                self.thread_pending[index].1.present()
            })
    }
    fn thread_pending_mut(
        &mut self,
        record: carrick_sched_core::RecordRef,
    ) -> &mut PendingSignals<T> {
        let index = match self
            .thread_pending
            .binary_search_by_key(&record, |(record, _)| *record)
        {
            Ok(index) => index,
            Err(index) => {
                self.thread_pending
                    .insert(index, (record, PendingSignals::default()));
                index
            }
        };
        &mut self.thread_pending[index].1
    }
    fn take_thread_pending(&mut self, record: carrick_sched_core::RecordRef) -> PendingSignals<T> {
        self.thread_pending
            .binary_search_by_key(&record, |(record, _)| *record)
            .map(|index| self.thread_pending.remove(index).1)
            .unwrap_or_default()
    }
    fn restore_thread_pending(
        &mut self,
        record: carrick_sched_core::RecordRef,
        pending: PendingSignals<T>,
    ) {
        if !pending.is_empty() {
            *self.thread_pending_mut(record) = pending;
        }
    }
}

// The summary is conservative across native processes: a signal in another
// process may cause an extra slow checkpoint, but an empty/unblocked word can
// never hide work from the exact owner. Mutations serialize here; IRQ/fault
// return reads only the published atomic word.
static SUMMARY_COUNTS: SpinLock<[u64; 64]> = SpinLock::new([0; 64]);
static SUMMARY_WORD: AtomicU64 = AtomicU64::new(0);

pub(crate) fn pending_summary_word() -> u64 {
    SUMMARY_WORD.load(Ordering::Acquire)
}

fn publish_summary_delta(before: u64, after: u64) {
    if before == after {
        return;
    }
    let mut counts = SUMMARY_COUNTS.lock();
    let mut changed = before ^ after;
    while changed != 0 {
        let bit = changed & changed.wrapping_neg();
        let index = bit.trailing_zeros() as usize;
        if after & bit != 0 {
            counts[index] = counts[index].saturating_add(1);
        } else {
            counts[index] = counts[index].saturating_sub(1);
        }
        changed &= !bit;
    }
    let mut word = 0;
    for (index, count) in counts.iter().enumerate() {
        if *count != 0 {
            word |= 1u64 << index;
        }
    }
    SUMMARY_WORD.store(word, Ordering::Release);
}

#[derive(Clone, Copy)]
enum ProjectionUpdate {
    All,
    Member(carrick_sched_core::RecordRef),
    None,
}

struct SignalShared<'a, T> {
    page: &'a ThreadLifecyclePage,
    state: SpinLock<SignalResources<'a, T>>,
    summary: AtomicU64,
    process_summary: AtomicU64,
    #[cfg(test)]
    projection_visits: core::sync::atomic::AtomicUsize,
    #[cfg(test)]
    projection_stores: core::sync::atomic::AtomicUsize,
}

impl<'a, T> SignalShared<'a, T> {
    fn new(page: &'a ThreadLifecyclePage, resources: SignalResources<'a, T>) -> Self {
        let shared = Self {
            page,
            state: SpinLock::new(resources),
            summary: AtomicU64::new(0),
            process_summary: AtomicU64::new(0),
            #[cfg(test)]
            projection_visits: core::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            projection_stores: core::sync::atomic::AtomicUsize::new(0),
        };
        {
            let state = shared.state.lock();
            shared.refresh_summary(&state, ProjectionUpdate::All);
        }
        shared
    }

    fn refresh_summary(&self, resources: &SignalResources<'a, T>, update: ProjectionUpdate) {
        let process = resources.inbox.pending().present().bits();
        let mut present = process;
        for (_, pending) in &resources.thread_pending {
            present |= pending.present().bits();
        }
        for (_, signal) in &resources.forced_faults {
            present |= signal.bit();
        }
        // A process queue change affects every member. A thread queue change
        // affects only its exact record, regardless of unrelated live members.
        // The queue lock serializes this cache with every projection publication.
        let update = if self.process_summary.swap(process, Ordering::Relaxed) != process {
            ProjectionUpdate::All
        } else {
            update
        };
        match update {
            ProjectionUpdate::All => {
                for (record, projection) in &resources.projections {
                    #[cfg(test)]
                    self.projection_visits.fetch_add(1, Ordering::Relaxed);
                    self.publish_projection(resources, *record, projection, process);
                }
            }
            ProjectionUpdate::Member(record) => {
                if let Ok(index) = resources.projections.binary_search_by(|(candidate, _)| {
                    #[cfg(test)]
                    self.projection_visits.fetch_add(1, Ordering::Relaxed);
                    candidate.cmp(&record)
                }) {
                    self.publish_projection(
                        resources,
                        record,
                        &resources.projections[index].1,
                        process,
                    );
                }
            }
            ProjectionUpdate::None => {}
        }
        let before = self.summary.swap(present, Ordering::Relaxed);
        publish_summary_delta(before, present);
    }
    fn publish_projection(
        &self,
        resources: &SignalResources<'a, T>,
        record: carrick_sched_core::RecordRef,
        projection: &Weak<NativeSignalProjection<'a, T>>,
        process: u64,
    ) {
        let Some(projection) = projection.upgrade() else {
            return;
        };
        let pending = process | resources.thread_pending_set(record).bits();
        projection
            .control
            .replace_from_locked_queue(carrick_el1_abi::PendingSignals(pending));
        #[cfg(test)]
        self.projection_stores.fetch_add(1, Ordering::Relaxed);
    }
}

impl<'a, T> Deref for SignalShared<'a, T> {
    type Target = SpinLock<SignalResources<'a, T>>;
    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl<'a, T> Drop for SignalShared<'a, T> {
    fn drop(&mut self) {
        publish_summary_delta(self.summary.load(Ordering::Relaxed), 0);
    }
}
// Default stops await process-owner stop/wait-event custody. Both wait
// interruption and dequeue selection must leave them pending.
fn awaits_stop_custody(action: Action, signal: Signal) -> bool {
    action.disposition == Disposition::Default
        && carrick_signal_core::policy::default_delivery(signal)
            == carrick_signal_core::policy::Delivery::Stop
}
/// A retained member's read-only projection of its native pending queue.
/// It cannot dequeue signals. The final member snapshot releases both this
/// projection and exact-incarnation control custody before slot reuse.
pub struct NativeSignalProjection<'a, T> {
    owner: Weak<SignalShared<'a, T>>,
    control: carrick_el1_abi::NativePendingCustody<'a>,
}
impl<T> NativeSignalProjection<'_, T> {
    pub fn rehome(&self, record: carrick_sched_core::RecordRef) {
        let Some(owner) = self.owner.upgrade() else {
            return;
        };
        let mut state = owner.lock();
        let Some(index) = state
            .projections
            .iter()
            .position(|(_, projection)| projection.as_ptr() == core::ptr::from_ref(self))
        else {
            return;
        };
        if state.projections[index].0 == record {
            return;
        }
        let (previous, projection) = state.projections.remove(index);
        let index = state
            .projections
            .partition_point(|(current, _)| *current < record);
        state.projections.insert(index, (record, projection));
        let pending = state.take_thread_pending(previous);
        state.restore_thread_pending(record, pending);
        for (current, _) in &mut state.forced_faults {
            if *current == previous {
                *current = record;
            }
        }
        owner.refresh_summary(&state, ProjectionUpdate::Member(record));
    }
}
/// One actual sighand and pending owner, retained by exact task handles.
pub struct NativeProcessSignals<'a, T> {
    key: TaskKey,
    resources: Arc<SignalShared<'a, T>>,
}
impl<'a, T> Clone for NativeProcessSignals<'a, T> {
    fn clone(&self) -> Self {
        Self {
            key: self.key,
            resources: self.resources.clone(),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalActionError {
    Stale,
    Action(ActionError),
}
/// A fork snapshot cannot receive signals before its own lifecycle is admitted.
pub struct NativeForkSignals<T> {
    key: TaskKey,
    actions: ActionTable,
    inbox: SignalInbox<TaskKey, T>,
}

impl<T> NativeForkSignals<T> {
    pub fn admit(self, page: &ThreadLifecyclePage) -> NativeProcessSignals<'_, T> {
        NativeProcessSignals {
            key: self.key,
            resources: Arc::new(SignalShared::new(
                page,
                SignalResources {
                    actions: self.actions,
                    inbox: self.inbox,
                    thread_pending: Vec::new(),
                    forced_faults: Vec::new(),
                    projections: Vec::new(),
                },
            )),
        }
    }
}

impl<'a, T> NativeProcessSignals<'a, T> {
    /// Fresh native-root admission owns the initial default actions and empty
    /// pending queue. This does not claim to import another launcher's sighand.
    pub fn fresh_root(key: TaskKey, page: &'a ThreadLifecyclePage) -> Self {
        Self {
            key,
            resources: Arc::new(SignalShared::new(
                page,
                SignalResources {
                    actions: ActionTable::default(),
                    inbox: SignalInbox::new(key),
                    thread_pending: Vec::new(),
                    forced_faults: Vec::new(),
                    projections: Vec::new(),
                },
            )),
        }
    }
    pub fn project_member(
        &self,
        record: carrick_sched_core::RecordRef,
        control: carrick_el1_abi::NativePendingCustody<'a>,
    ) -> Arc<NativeSignalProjection<'a, T>> {
        let projection = Arc::new(NativeSignalProjection {
            owner: Arc::downgrade(&self.resources),
            control,
        });
        let mut resources = self.resources.lock();
        resources
            .projections
            .retain(|(_, projection)| projection.strong_count() != 0);
        let index = resources
            .projections
            .partition_point(|(current, _)| *current < record);
        resources
            .projections
            .insert(index, (record, Arc::downgrade(&projection)));
        self.resources
            .refresh_summary(&resources, ProjectionUpdate::Member(record));
        projection
    }
    /// Future rt_sigaction adapters update this authority after wire validation.
    pub fn install_action(
        &self,
        key: TaskKey,
        signal: Signal,
        action: Action,
    ) -> Result<Action, SignalActionError> {
        if key != self.key {
            return Err(SignalActionError::Stale);
        }
        let mut resources = self.resources.lock();
        let old = resources
            .actions
            .install(signal, action)
            .map_err(SignalActionError::Action)?;
        if action.disposition == Disposition::Ignore {
            let selected = SignalSet::EMPTY.with(signal);
            resources.inbox.pending_mut().discard(selected);
            let SignalResources {
                thread_pending,
                forced_faults,
                ..
            } = &mut *resources;
            for (record, pending) in thread_pending.iter_mut() {
                if !forced_faults.contains(&(*record, signal)) {
                    pending.discard(selected);
                }
            }
            thread_pending.retain(|(_, pending)| !pending.is_empty());
            self.resources
                .refresh_summary(&resources, ProjectionUpdate::All);
        }
        Ok(old)
    }
    pub fn forced_action(&self, signal: Signal, blocked: SigBlockMask) -> Action {
        let mut resources = self.resources.lock();
        let action = resources.actions.action(signal);
        if blocked.contains(signal) || action.disposition == Disposition::Ignore {
            let _ = resources.actions.install(signal, Action::default());
            Action::default()
        } else {
            resources.actions.prepare_delivery(
                signal,
                &mut carrick_signal_core::policy::MaskState::new(blocked),
            );
            action
        }
    }
    pub fn force_sigsegv(
        &self,
        tid: carrick_sched_core::RecordRef,
        blocked: SigBlockMask,
        info: Option<T>,
    ) {
        self.force_fault(tid, Signal::SEGV, blocked, info);
    }
    pub fn force_fault(
        &self,
        tid: carrick_sched_core::RecordRef,
        signal: Signal,
        blocked: SigBlockMask,
        info: Option<T>,
    ) {
        let mut resources = self.resources.lock();
        if !resources.forced_faults.contains(&(tid, signal)) {
            resources.forced_faults.push((tid, signal));
        }
        if blocked.contains(signal)
            || resources.actions.action(signal).disposition == Disposition::Ignore
        {
            let _ = resources.actions.install(signal, Action::default());
        }
        resources.thread_pending_mut(tid).enqueue(signal, info);
        self.resources
            .refresh_summary(&resources, ProjectionUpdate::Member(tid));
    }
    pub fn action(&self, signal: Signal) -> Action {
        self.resources.lock().actions.action(signal)
    }
    pub fn non_interrupting_signals(&self) -> SignalSet {
        let resources = self.resources.lock();
        let mut set = resources.actions.non_interrupting_signals();
        for (_, signal) in &resources.forced_faults {
            set = set.without(*signal);
        }
        set
    }
    pub fn enqueue(
        &self,
        key: TaskKey,
        signal: Signal,
        info: Option<T>,
    ) -> Result<EnqueueOutcome, StaleTarget> {
        if key != self.key {
            return Err(StaleTarget);
        }
        self.publish_fatal(signal);
        let mut resources = self.resources.lock();
        let outcome = resources.inbox.enqueue_for(key, signal, info);
        self.resources
            .refresh_summary(&resources, ProjectionUpdate::None);
        outcome
    }
    pub fn enqueue_thread(
        &self,
        tid: carrick_sched_core::RecordRef,
        signal: Signal,
        info: Option<T>,
    ) -> EnqueueOutcome {
        self.publish_fatal(signal);
        let mut res = self.resources.lock();
        let outcome = res.thread_pending_mut(tid).enqueue(signal, info);
        self.resources
            .refresh_summary(&res, ProjectionUpdate::Member(tid));
        outcome
    }
    fn publish_fatal(&self, signal: Signal) {
        if signal == Signal::KILL {
            self.resources
                .page
                .process_exit_custody()
                .publish_cancellation(carrick_core::terminal::ProcessCancellation::FatalSignal);
        }
    }

    pub fn pending_set(&self, tid: carrick_sched_core::RecordRef) -> SignalSet {
        let resources = self.resources.lock();
        let proc = resources.inbox.pending().present();
        let thread = resources.thread_pending_set(tid);
        proc.union(thread)
    }
    pub fn has_deliverable(
        &self,
        tid: carrick_sched_core::RecordRef,
        blocked: SigBlockMask,
    ) -> bool {
        let resources = self.resources.lock();
        let thread = resources.thread_pending_set(tid);
        let mut selected = blocked.select(resources.inbox.pending().present().union(thread));
        while let Some(number) = selected.lowest() {
            let Some(signal) = Signal::from_number(number) else {
                return false;
            };
            let action = resources.actions.action(signal);
            if carrick_signal_core::policy::action_interrupts_wait(signal, action)
                && !awaits_stop_custody(action, signal)
            {
                return true;
            }
            selected = selected.without(signal);
        }
        resources.forced_faults.iter().any(|(id, _)| *id == tid)
    }
    pub fn take_deliverable(
        &self,
        tid: carrick_sched_core::RecordRef,
        blocked: SigBlockMask,
    ) -> Option<(Signal, Option<T>, Action)> {
        loop {
            let mut resources = self.resources.lock();
            let mut thread_pending = resources.take_thread_pending(tid);
            let forced = resources
                .forced_faults
                .iter()
                .find_map(|(id, signal)| (*id == tid).then_some(*signal));
            let present = resources
                .inbox
                .pending()
                .present()
                .union(thread_pending.present());
            let mut unblocked = if present.contains(Signal::KILL) {
                SignalSet::EMPTY.with(Signal::KILL)
            } else if let Some(signal) = forced {
                SignalSet::EMPTY.with(signal)
            } else {
                blocked.select(present)
            };
            // This lane has no process stop/wait-event custody yet. Preserve
            // default stops for that owner instead of consuming a silent no-op.
            let mut inspect = unblocked;
            while let Some(number) = inspect.lowest() {
                let Some(signal) = Signal::from_number(number) else {
                    break;
                };
                if awaits_stop_custody(resources.actions.action(signal), signal) {
                    unblocked = unblocked.without(signal);
                }
                inspect = inspect.without(signal);
            }
            let delivery = carrick_personality_linux::signal::take_pending(
                &mut thread_pending,
                resources.inbox.pending_mut(),
                unblocked,
            );
            resources.restore_thread_pending(tid, thread_pending);
            self.resources
                .refresh_summary(&resources, ProjectionUpdate::Member(tid));
            let delivery = delivery?;
            let signal = delivery.entry.signal;
            if resources.forced_faults.contains(&(tid, signal)) {
                resources
                    .forced_faults
                    .retain(|pair| *pair != (tid, signal));
                self.resources
                    .refresh_summary(&resources, ProjectionUpdate::Member(tid));
            }
            let action = resources.actions.action(signal);
            if action.disposition == Disposition::Ignore
                || (action.disposition == Disposition::Default
                    && carrick_signal_core::policy::default_delivery(signal)
                        == carrick_signal_core::policy::Delivery::Ignore)
            {
                continue;
            }
            resources.actions.prepare_delivery(
                signal,
                &mut carrick_signal_core::policy::MaskState::new(blocked),
            );
            return Some((signal, delivery.entry.info, action));
        }
    }
    pub fn take_timedwait(
        &self,
        tid: carrick_sched_core::RecordRef,
        set: SignalSet,
    ) -> Option<(Signal, Option<T>)> {
        let mut resources = self.resources.lock();
        let mut thread_pending = resources.take_thread_pending(tid);
        let delivery = {
            let proc_pending = resources.inbox.pending_mut();
            carrick_personality_linux::signal::take_pending(&mut thread_pending, proc_pending, set)
        };
        resources.restore_thread_pending(tid, thread_pending);
        self.resources
            .refresh_summary(&resources, ProjectionUpdate::Member(tid));
        let delivery = delivery?;
        Some((delivery.entry.signal, delivery.entry.info))
    }
    pub fn reset_for_exec(&self) {
        let mut res = self.resources.lock();
        res.actions = res.actions.clone_for_exec();
    }
    pub fn pending_count(&self) -> usize {
        self.resources.lock().inbox.pending().len()
    }
    pub fn for_fork(&self, child: TaskKey) -> Option<NativeForkSignals<T>> {
        let source = self.resources.lock();
        let ActionInheritance::Copied(actions) =
            source.actions.for_clone(self.key, SighandSharing::Copy)
        else {
            return None;
        };
        Some(NativeForkSignals {
            key: child,
            actions,
            inbox: source.inbox.for_fork(child),
        })
    }
    pub fn autoreaps_children(&self) -> bool {
        child_decision(
            self.action(Signal::CHLD),
            ChildEvent::Exited,
            ChildInterest::default(),
        )
        .auto_reap
    }
    pub fn exit_source<M: BlockedMaskSource>(&self, mask: M) -> NativeExitSignals<'a, T, M> {
        NativeExitSignals {
            signals: self.clone(),
            mask,
        }
    }
}

/// Native signal locks are leaves: their operations never acquire the process
/// graph or scheduler buckets. Exit delivery may sample them while retaining
/// graph custody to select and notify the same live parent generation.
pub struct NativeExitSignals<'a, T, M> {
    signals: NativeProcessSignals<'a, T>,
    mask: M,
}
impl<'a, T, M: BlockedMaskSource> ExitSignalSource for NativeExitSignals<'a, T, M> {
    fn exit_signal_state(&self, signal: LinuxSignal) -> ExitSignalState {
        let Some(signal) = Signal::from_number(signal.raw()) else {
            super::dispatch::invalid_completion(super::dispatch::NativeInvariant::SignalNumber)
        };
        let action = self.signals.action(signal);
        let disposition = match action.disposition {
            Disposition::Default => ExitSignalDisposition::Default,
            Disposition::Ignore => ExitSignalDisposition::Ignore,
            Disposition::Handler(_) => ExitSignalDisposition::Caught,
        };
        let default_disposition = match carrick_signal_core::policy::default_delivery(signal) {
            carrick_signal_core::policy::Delivery::Ignore => DefaultSignalDisposition::Ignore,
            _ => DefaultSignalDisposition::Deliver,
        };
        ExitSignalState {
            disposition,
            default_disposition,
            blocked: self.mask.blocked_mask().contains(signal),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use carrick_sched_core::process::TaskSerial;
    use carrick_signal_core::policy::{Disposition, HandlerAddress};
    fn key(raw: i32, serial: u64) -> TaskKey {
        TaskKey {
            id: carrick_personality_linux::identity::task_id_from_linux_pid(raw).unwrap(),
            serial: TaskSerial::from_raw_u64(serial).unwrap(),
        }
    }
    fn fresh<'a, T>(key: TaskKey) -> NativeProcessSignals<'a, T> {
        NativeProcessSignals::fresh_root(
            key,
            alloc::boxed::Box::leak(alloc::boxed::Box::new(ThreadLifecyclePage::new())),
        )
    }

    #[test]
    fn fatal_cancellation_survives_native_dequeue_and_fork_gets_fresh_authority() {
        let page = ThreadLifecyclePage::new();
        let task = key(41, 11);
        let signals = NativeProcessSignals::<()>::fresh_root(task, &page);
        assert!(signals.enqueue(key(42, 12), Signal::KILL, None).is_err());
        assert_eq!(page.process_exit_custody().cancellation(), None);
        signals.enqueue(task, Signal::KILL, None).unwrap();
        // The recipient takes delivery; cancellation remains process-wide.
        let recipient = carrick_sched_core::RecordRef {
            id: carrick_sched_core::RecordId::from_raw(1).unwrap(),
            incarnation: 1,
        };
        assert_eq!(
            signals
                .take_deliverable(recipient, SigBlockMask::NONE)
                .unwrap()
                .0,
            Signal::KILL
        );
        assert_eq!(signals.pending_count(), 0);
        assert_eq!(
            page.process_exit_custody().cancellation(),
            Some(carrick_core::terminal::ProcessCancellation::FatalSignal)
        );
        let child_page = ThreadLifecyclePage::new();
        let _child = signals.for_fork(key(42, 12)).unwrap().admit(&child_page);
        assert_eq!(child_page.process_exit_custody().cancellation(), None);
    }

    #[test]
    fn thread_signal_projection_work_is_bounded_by_lookup_depth() {
        for population in [1usize, 8, 32, 128] {
            let controls: Vec<_> = (0..population)
                .map(|_| carrick_el1_abi::ThreadControlSlot::new())
                .collect();
            let signals = fresh::<()>(key(41, 11));
            let record = |index: usize| carrick_sched_core::RecordRef {
                id: carrick_sched_core::RecordId::from_raw((index + 1) as u32).unwrap(),
                incarnation: 1,
            };
            // Reverse registration catches an accidentally unsorted lookup table.
            let _projections: Vec<_> = (0..population)
                .rev()
                .map(|index| {
                    signals.project_member(
                        record(index),
                        carrick_el1_abi::NativePendingCustody::try_admit(Arc::new(
                            carrick_core::lifecycle::MemberControlCustody::retain(&controls[index])
                                .unwrap(),
                        ))
                        .unwrap(),
                    )
                })
                .collect();
            signals
                .resources
                .projection_visits
                .store(0, Ordering::Relaxed);
            signals
                .resources
                .projection_stores
                .store(0, Ordering::Relaxed);
            let target = population / 2;
            signals.enqueue_thread(record(target), Signal::ALRM, None);
            for (index, control) in controls.iter().enumerate() {
                assert_eq!(
                    control.pending().load().0,
                    if index == target {
                        Signal::ALRM.bit()
                    } else {
                        0
                    }
                );
            }
            assert_eq!(
                signals
                    .take_deliverable(record(target), SigBlockMask::NONE)
                    .unwrap()
                    .0,
                Signal::ALRM
            );
            assert!(
                controls
                    .iter()
                    .all(|control| control.pending().load().0 == 0)
            );
            let visits = signals.resources.projection_visits.load(Ordering::Relaxed);
            let budget = 2 * (population.ilog2() as usize + 2);
            assert!(
                visits <= budget,
                "{population} members: {visits} visits > {budget}"
            );
            assert_eq!(
                signals.resources.projection_stores.load(Ordering::Relaxed),
                2
            );
        }
    }

    #[test]
    fn process_projection_updates_cover_late_members_and_rehomes() {
        let first = carrick_el1_abi::ThreadControlSlot::new();
        let second = carrick_el1_abi::ThreadControlSlot::new();
        let task = key(41, 11);
        let signals = fresh::<()>(task);
        let record = |id| carrick_sched_core::RecordRef {
            id: carrick_sched_core::RecordId::from_raw(id).unwrap(),
            incarnation: 1,
        };
        let first_projection = signals.project_member(
            record(1),
            carrick_el1_abi::NativePendingCustody::try_admit(Arc::new(
                carrick_core::lifecycle::MemberControlCustody::retain(&first).unwrap(),
            ))
            .unwrap(),
        );
        signals.enqueue(task, Signal::KILL, None).unwrap();
        let _second_projection = signals.project_member(
            record(2),
            carrick_el1_abi::NativePendingCustody::try_admit(Arc::new(
                carrick_core::lifecycle::MemberControlCustody::retain(&second).unwrap(),
            ))
            .unwrap(),
        );
        first_projection.rehome(record(3));
        assert_eq!(first.pending().load().0, Signal::KILL.bit());
        assert_eq!(second.pending().load().0, Signal::KILL.bit());
        assert_eq!(
            signals
                .take_deliverable(record(2), SigBlockMask::NONE)
                .unwrap()
                .0,
            Signal::KILL
        );
        assert_eq!(first.pending().load().0, 0);
        assert_eq!(second.pending().load().0, 0);

        // Ordinary process and per-thread signals retain full pending words.
        signals.enqueue_thread(record(3), Signal::STOP, None);
        signals.enqueue(task, Signal::ALRM, None).unwrap();
        assert_eq!(
            first.pending().load().0,
            Signal::STOP.bit() | Signal::ALRM.bit()
        );
        assert_eq!(second.pending().load().0, Signal::ALRM.bit());
        signals
            .install_action(
                task,
                Signal::ALRM,
                Action {
                    disposition: Disposition::Ignore,
                    ..Action::default()
                },
            )
            .unwrap();
        assert_eq!(first.pending().load().0, Signal::STOP.bit());
        assert_eq!(second.pending().load().0, 0);
    }

    #[test]
    fn native_pending_projection_keeps_exact_member_and_rehomed_queue() {
        let first = carrick_el1_abi::ThreadControlSlot::new();
        let second = carrick_el1_abi::ThreadControlSlot::new();
        let signals = fresh::<()>(key(41, 11));
        let first_custody =
            Arc::new(carrick_core::lifecycle::MemberControlCustody::retain(&first).unwrap());
        let second_custody =
            Arc::new(carrick_core::lifecycle::MemberControlCustody::retain(&second).unwrap());
        let record = |id| carrick_sched_core::RecordRef {
            id: carrick_sched_core::RecordId::from_raw(id).unwrap(),
            incarnation: 1,
        };
        let first_projection = signals.project_member(
            record(1),
            carrick_el1_abi::NativePendingCustody::try_admit(first_custody).unwrap(),
        );
        let _second_projection = signals.project_member(
            record(2),
            carrick_el1_abi::NativePendingCustody::try_admit(second_custody).unwrap(),
        );
        signals.enqueue_thread(record(1), Signal::STOP, None);
        assert_eq!(first.pending().load().0, Signal::STOP.bit());
        assert_eq!(second.pending().load().0, 0);
        signals.enqueue(key(41, 11), Signal::ALRM, None).unwrap();
        assert_eq!(second.pending().load().0, Signal::ALRM.bit());
        first_projection.rehome(record(3));
        assert!(signals.pending_set(record(3)).contains(Signal::STOP));
        assert!(!signals.pending_set(record(1)).contains(Signal::STOP));
        signals.enqueue_thread(record(2), Signal::KILL, None);
        assert_eq!(first.pending().load().0 & Signal::KILL.bit(), 0);
        assert_ne!(second.pending().load().0 & Signal::KILL.bit(), 0);
        assert_eq!(
            signals
                .take_deliverable(record(2), SigBlockMask::NONE)
                .unwrap()
                .0,
            Signal::KILL
        );
        assert_eq!(second.pending().load().0 & Signal::KILL.bit(), 0);
        drop(first_projection);
        assert_eq!(first.pending().load().0, 0);
    }

    #[test]
    fn duplicate_member_projection_must_preserve_pending() {
        let control = carrick_el1_abi::ThreadControlSlot::new();
        let custody =
            Arc::new(carrick_core::lifecycle::MemberControlCustody::retain(&control).unwrap());
        let signals = fresh::<()>(key(41, 11));
        let record = carrick_sched_core::RecordRef {
            id: carrick_sched_core::RecordId::from_raw(1).unwrap(),
            incarnation: 1,
        };
        let projection = signals.project_member(
            record,
            carrick_el1_abi::NativePendingCustody::try_admit(custody.clone()).unwrap(),
        );
        signals.enqueue_thread(record, Signal::KILL, None);
        let duplicate = carrick_el1_abi::NativePendingCustody::try_admit(custody);
        assert_eq!(
            duplicate.err(),
            Some(carrick_el1_abi::NativePendingAlreadyAdmitted)
        );
        let shared = projection.clone();
        drop(shared);
        assert_eq!(control.pending().load().0, Signal::KILL.bit());
        assert!(signals.pending_set(record).contains(Signal::KILL));
        drop(projection);
        assert_eq!(control.pending().load().0, 0);
    }

    #[test]
    fn process_sigint_waits_for_unblocked_worker_and_survives_exec() {
        let task = key(41, 11);
        let signals = fresh::<u32>(task);
        let main = carrick_sched_core::RecordRef {
            id: carrick_sched_core::RecordId::from_raw(1).unwrap(),
            incarnation: 7,
        };
        let worker = carrick_sched_core::RecordRef {
            id: carrick_sched_core::RecordId::from_raw(2).unwrap(),
            incarnation: 9,
        };
        let sigint = Signal::from_number(2).unwrap();
        signals.enqueue(task, sigint, Some(77)).unwrap();
        let blocked_main = SigBlockMask::blocking_all_of(SignalSet::EMPTY.with(sigint));
        assert!(!signals.has_deliverable(main, blocked_main));
        assert!(signals.take_deliverable(main, blocked_main).is_none());
        signals.reset_for_exec();
        assert_eq!(signals.pending_count(), 1);
        assert!(signals.has_deliverable(worker, SigBlockMask::NONE));
        let selected = signals
            .take_deliverable(worker, SigBlockMask::NONE)
            .unwrap();
        assert_eq!((selected.0, selected.1), (sigint, Some(77)));
        assert_eq!(signals.pending_count(), 0);
    }
    #[test]
    fn installing_ignore_discards_process_and_thread_pending() {
        let task = key(41, 11);
        let signals = fresh::<u32>(task);
        let record = carrick_sched_core::RecordRef {
            id: carrick_sched_core::RecordId::from_raw(1).unwrap(),
            incarnation: 7,
        };
        let usr1 = Signal::from_number(10).unwrap();
        signals.enqueue(task, usr1, Some(41)).unwrap();
        signals.enqueue_thread(record, usr1, Some(42));
        signals
            .install_action(
                task,
                usr1,
                Action {
                    disposition: Disposition::Ignore,
                    ..Action::default()
                },
            )
            .unwrap();
        assert_eq!(signals.pending_set(record), SignalSet::EMPTY);
        signals.enqueue(task, usr1, Some(43)).unwrap();
        assert_eq!(
            signals.take_timedwait(record, SignalSet::EMPTY.with(usr1)),
            Some((usr1, Some(43))),
            "blocked ignored signals remain waitable"
        );
    }

    #[test]
    fn recycled_record_cannot_consume_another_thread_incarnations_signal() {
        let signals = fresh::<u32>(key(41, 11));
        let old = carrick_sched_core::RecordRef {
            id: carrick_sched_core::RecordId::from_raw(1).unwrap(),
            incarnation: 7,
        };
        let replacement = carrick_sched_core::RecordRef {
            incarnation: 8,
            ..old
        };
        let usr1 = Signal::from_number(10).unwrap();
        signals.enqueue_thread(old, usr1, Some(41));
        assert_eq!(signals.pending_set(replacement), SignalSet::EMPTY);
        assert!(
            signals
                .take_timedwait(replacement, SignalSet::EMPTY.with(usr1))
                .is_none()
        );
        assert_eq!(
            signals.take_timedwait(old, SignalSet::EMPTY.with(usr1)),
            Some((usr1, Some(41)))
        );
    }

    #[test]
    fn default_stop_remains_pending_until_the_job_control_owner_can_stop() {
        let task = key(41, 11);
        let signals = fresh::<()>(task);
        let record = carrick_sched_core::RecordRef {
            id: carrick_sched_core::RecordId::from_raw(1).unwrap(),
            incarnation: 1,
        };
        for number in [19, 20, 21, 22] {
            let stop = Signal::from_number(number).unwrap();
            signals.enqueue(task, stop, None).unwrap();
            // wait4, sigsuspend and sigtimedwait use this same interruption
            // predicate: an unowned default stop must leave each wait parked.
            assert!(!signals.has_deliverable(record, SigBlockMask::NONE));
        }
        assert!(
            signals
                .take_deliverable(record, SigBlockMask::NONE)
                .is_none()
        );
        assert!(signals.pending_set(record).contains(Signal::STOP));
        signals.enqueue(task, Signal::KILL, None).unwrap();
        assert_eq!(
            signals
                .take_deliverable(record, SigBlockMask::NONE)
                .unwrap()
                .0,
            Signal::KILL
        );
        assert!(signals.pending_set(record).contains(Signal::STOP));
    }

    #[test]
    fn reset_hand_is_committed_with_selected_action_snapshot() {
        let task = key(41, 11);
        let signals = fresh::<()>(task);
        let caught = Action {
            disposition: Disposition::Handler(HandlerAddress(0x400000)),
            flags: carrick_signal_core::policy::ActionFlags {
                reset_hand: true,
                ..Default::default()
            },
            ..Action::default()
        };
        let usr1 = Signal::from_number(10).unwrap();
        signals.install_action(task, usr1, caught).unwrap();
        signals.enqueue(task, usr1, None).unwrap();
        let (_, _, snapshot) = signals
            .take_deliverable(
                carrick_sched_core::RecordRef {
                    id: carrick_sched_core::RecordId::from_raw(1).unwrap(),
                    incarnation: 1,
                },
                SigBlockMask::NONE,
            )
            .unwrap();
        assert_eq!(snapshot, caught);
        assert_eq!(signals.action(usr1).disposition, Disposition::Default);
    }

    #[test]
    fn blocked_or_ignored_synchronous_segv_forces_default() {
        let task = key(41, 11);
        let signals = fresh::<()>(task);
        let caught = Action {
            disposition: Disposition::Handler(HandlerAddress(0x400000)),
            ..Action::default()
        };
        signals.install_action(task, Signal::SEGV, caught).unwrap();
        let blocked = SigBlockMask::blocking_all_of(SignalSet::EMPTY.with(Signal::SEGV));
        assert_eq!(
            signals.forced_action(Signal::SEGV, blocked).disposition,
            Disposition::Default
        );
        signals
            .install_action(
                task,
                Signal::SEGV,
                Action {
                    disposition: Disposition::Ignore,
                    ..Action::default()
                },
            )
            .unwrap();
        assert_eq!(
            signals
                .forced_action(Signal::SEGV, SigBlockMask::NONE)
                .disposition,
            Disposition::Default
        );
    }

    #[test]
    fn forced_bus_is_thread_exact_and_cannot_be_blocked_or_ignored() {
        let task = key(41, 11);
        let signals = fresh::<u32>(task);
        let record = carrick_sched_core::RecordRef {
            id: carrick_sched_core::RecordId::from_raw(1).unwrap(),
            incarnation: 1,
        };
        let other = carrick_sched_core::RecordRef {
            incarnation: 2,
            ..record
        };
        let blocked = SigBlockMask::blocking_all_of(SignalSet::EMPTY.with(Signal::BUS));
        signals
            .install_action(
                task,
                Signal::BUS,
                Action {
                    disposition: Disposition::Ignore,
                    ..Action::default()
                },
            )
            .unwrap();
        signals.force_fault(record, Signal::BUS, blocked, Some(42));
        assert!(signals.take_deliverable(other, blocked).is_none());
        let (signal, info, action) = signals.take_deliverable(record, blocked).unwrap();
        assert_eq!(signal, Signal::BUS);
        assert_eq!(info, Some(42));
        assert_eq!(action.disposition, Disposition::Default);
        assert!(signals.take_deliverable(record, blocked).is_none());
    }

    #[test]
    fn retained_exit_handle_reads_later_action_and_actual_control_mask() {
        let key = key(41, 11);
        let signals = fresh::<()>(key);
        let control = Arc::new(carrick_el1_abi::ThreadControlSlot::new());
        let retained = signals.exit_source(control.clone());
        signals
            .install_action(
                key,
                Signal::CHLD,
                Action {
                    disposition: Disposition::Handler(HandlerAddress(0x400000)),
                    ..Action::default()
                },
            )
            .unwrap();
        control.init_blocked(carrick_el1_abi::BlockedMask(Signal::CHLD.bit()));
        assert_eq!(
            retained.exit_signal_state(LinuxSignal::SIGCHLD),
            ExitSignalState {
                disposition: ExitSignalDisposition::Caught,
                default_disposition: DefaultSignalDisposition::Ignore,
                blocked: true
            }
        );
    }
    #[test]
    fn fork_copies_actions_without_pending_or_parent_mutation_aliases() {
        let parent_key = key(41, 11);
        let child_key = key(42, 12);
        let parent = fresh::<u32>(parent_key);
        let caught = Action {
            disposition: Disposition::Handler(HandlerAddress(0x400000)),
            ..Action::default()
        };
        parent
            .install_action(parent_key, Signal::CHLD, caught)
            .unwrap();
        parent.enqueue(parent_key, Signal::CHLD, Some(7)).unwrap();
        let child = parent
            .for_fork(child_key)
            .unwrap()
            .admit(alloc::boxed::Box::leak(alloc::boxed::Box::new(
                ThreadLifecyclePage::new(),
            )));
        assert_eq!(child.action(Signal::CHLD), caught);
        assert_eq!(child.pending_count(), 0);
        assert_eq!(parent.pending_count(), 1);
        parent
            .install_action(
                parent_key,
                Signal::CHLD,
                Action {
                    disposition: Disposition::Ignore,
                    ..Action::default()
                },
            )
            .unwrap();
        assert_eq!(child.action(Signal::CHLD), caught);
        assert!(child.enqueue(parent_key, Signal::CHLD, None).is_err());
        assert_eq!(
            child.install_action(parent_key, Signal::CHLD, Action::default()),
            Err(SignalActionError::Stale)
        );
        child.enqueue(child_key, Signal::CHLD, None).unwrap();
        assert_eq!(child.pending_count(), 1);
        assert_eq!(
            parent.pending_count(),
            0,
            "SIG_IGN discards only parent's pending queue"
        );
    }

    #[test]
    fn child_policy_reads_default_explicit_ignore_no_child_wait_and_blocked_caught() {
        let task = key(41, 11);
        let signals = fresh::<()>(task);
        let control = Arc::new(carrick_el1_abi::ThreadControlSlot::new());
        let retained = signals.exit_source(control.clone());
        assert!(!signals.autoreaps_children());
        assert!(
            !retained
                .exit_signal_state(LinuxSignal::SIGCHLD)
                .needs_notification()
        );
        control.init_blocked(carrick_el1_abi::BlockedMask(Signal::CHLD.bit()));
        assert!(
            retained
                .exit_signal_state(LinuxSignal::SIGCHLD)
                .needs_notification()
        );
        signals
            .install_action(
                task,
                Signal::CHLD,
                Action {
                    disposition: Disposition::Ignore,
                    ..Action::default()
                },
            )
            .unwrap();
        assert!(signals.autoreaps_children());
        assert!(
            !retained
                .exit_signal_state(LinuxSignal::SIGCHLD)
                .needs_notification()
        );
        let mut no_child_wait = Action::default();
        no_child_wait.flags.no_child_wait = true;
        signals
            .install_action(task, Signal::CHLD, no_child_wait)
            .unwrap();
        assert!(signals.autoreaps_children());
        control.init_blocked(carrick_el1_abi::BlockedMask(0));
        let caught = Action {
            disposition: Disposition::Handler(HandlerAddress(0x400000)),
            ..no_child_wait
        };
        signals.install_action(task, Signal::CHLD, caught).unwrap();
        assert!(signals.autoreaps_children());
        assert!(
            retained
                .exit_signal_state(LinuxSignal::SIGCHLD)
                .needs_notification()
        );
        signals
            .install_action(
                task,
                Signal::CHLD,
                Action {
                    disposition: caught.disposition,
                    ..Action::default()
                },
            )
            .unwrap();
        assert!(!signals.autoreaps_children());
        assert_eq!(
            signals.install_action(task, Signal::KILL, Action::default()),
            Err(SignalActionError::Action(ActionError::Uncatchable))
        );
    }
}
