//! Complete Linux signal delivery, queuing, disposition, masking, and authority.
//!
//! Carrick represents signal actions and masks in Linux ABI form, queuing
//! standard signals with bitset coalescing and real-time signals in strict FIFO
//! order with optional `siginfo_t` payloads. The [`SignalAuthority`] facade
//! provides atomic signal dequeue and reservation across thread- and task-level
//! pending queues.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;

use carrick_abi::{LinuxSigaction, LinuxSigaltstack, LinuxSiginfo, SigSet, WaitSigMask};
use carrick_fatal::carrick_fatal;

use crate::kernel::ids::{LinuxSignal, LinuxTid, SighandId};
use crate::kernel::operations::KernelOperationError;

use super::{JobControlStopInvalidationGeneration, ObjectRevision, TaskRef, ThreadRef};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalDisposition {
    Default,
    Ignore,
    Caught,
}

/// Complete Linux signal-action authority shared according to
/// `CLONE_SIGHAND`. An absent entry is `SIG_DFL`; stored records retain every
/// guest-visible field needed for delivery and `rt_sigaction` round trips.
#[derive(Debug)]
pub struct Sighand {
    id: SighandId,
    actions: Mutex<BTreeMap<LinuxSignal, LinuxSigaction>>,
    revision: ObjectRevision,
}

impl Sighand {
    pub fn new(id: SighandId) -> Self {
        Self {
            id,
            actions: Mutex::new(BTreeMap::new()),
            revision: ObjectRevision::new(),
        }
    }

    pub(super) fn for_fork_copy(id: SighandId, parent: &Self) -> Self {
        Self {
            id,
            actions: Mutex::new(parent.actions.lock().clone()),
            revision: ObjectRevision::new(),
        }
    }

    pub(crate) fn for_exec(id: SighandId, caller: &Self) -> Self {
        let actions = caller
            .actions
            .lock()
            .iter()
            .filter_map(|(signal, action)| {
                (action.sa_handler == crate::linux_abi::LINUX_SIG_IGN).then_some((*signal, *action))
            })
            .collect();
        Self {
            id,
            actions: Mutex::new(actions),
            revision: ObjectRevision::new(),
        }
    }

    pub const fn id(&self) -> SighandId {
        self.id
    }

    /// Install one complete Linux action. Explicit `SIG_DFL` records retain
    /// their flags, mask, and restorer for exact `rt_sigaction` round trips.
    pub fn install_action(&self, signal: LinuxSignal, action: LinuxSigaction) {
        let mut actions = self.actions.lock();
        if actions.insert(signal, action) != Some(action) {
            self.revision.publish();
        }
    }

    pub fn action(&self, signal: LinuxSignal) -> LinuxSigaction {
        self.action_entry(signal)
            .unwrap_or_else(LinuxSigaction::empty)
    }

    fn action_with_revision(&self, signal: LinuxSignal) -> (u64, LinuxSigaction) {
        let actions = self.actions.lock();
        let action = actions
            .get(&signal)
            .copied()
            .unwrap_or_else(LinuxSigaction::empty);
        (self.revision.load(), action)
    }

    pub fn action_entry(&self, signal: LinuxSignal) -> Option<LinuxSigaction> {
        self.actions.lock().get(&signal).copied()
    }

    pub fn actions(&self) -> Vec<(LinuxSignal, LinuxSigaction)> {
        self.actions
            .lock()
            .iter()
            .map(|(signal, action)| (*signal, *action))
            .collect()
    }

    pub fn replace_actions(&self, replacement: Vec<(LinuxSignal, LinuxSigaction)>) {
        let replacement = replacement.into_iter().collect::<BTreeMap<_, _>>();
        let mut actions = self.actions.lock();
        if *actions != replacement {
            *actions = replacement;
            self.revision.publish();
        }
    }

    pub fn disposition(&self, signal: LinuxSignal) -> SignalDisposition {
        match self.action(signal).sa_handler {
            crate::linux_abi::LINUX_SIG_DFL => SignalDisposition::Default,
            crate::linux_abi::LINUX_SIG_IGN => SignalDisposition::Ignore,
            _ => SignalDisposition::Caught,
        }
    }

    pub(in crate::kernel) fn snapshot_until(
        &self,
        deadline: std::time::Instant,
    ) -> Option<(u64, Vec<(LinuxSignal, LinuxSigaction)>)> {
        let actions = self.actions.try_lock_until(deadline)?;
        Some((
            self.revision.load(),
            actions
                .iter()
                .map(|(signal, action)| (*signal, *action))
                .collect(),
        ))
    }

    pub(in crate::kernel) fn revision(&self) -> u64 {
        self.revision.load()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]

pub struct PendingSignal {
    pub signal: LinuxSignal,
    pub siginfo: Option<LinuxSiginfo>,
}

/// Typed standard/real-time pending queue used by task- and thread-directed
/// owners. Standard signals coalesce to one presence bit. Real-time signals
/// retain one FIFO entry per send, including an explicit no-payload entry so a
/// later queued `siginfo` can never attach to the wrong delivery.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PendingQueue {
    present: SigSet,
    standard_siginfos: BTreeMap<LinuxSignal, LinuxSiginfo>,
    realtime: BTreeMap<LinuxSignal, VecDeque<Option<LinuxSiginfo>>>,
}

impl PendingQueue {
    pub const fn present(&self) -> SigSet {
        self.present
    }

    pub fn pending_count(&self) -> usize {
        let realtime = self.realtime.values().map(VecDeque::len).sum::<usize>();
        let realtime_signals = self.realtime.len();
        let distinct = self.present.raw().count_ones() as usize;
        distinct.saturating_sub(realtime_signals) + realtime
    }

    pub fn enqueue_standard(
        &mut self,
        signal: LinuxSignal,
        siginfo: Option<LinuxSiginfo>,
    ) -> Result<(), KernelOperationError> {
        if signal.raw() >= 32 {
            return Err(KernelOperationError::RealtimeSignalInStandardQueue(signal));
        }
        let already_pending = self.present.contains(signal.raw());
        self.present = self.present.with(signal.raw());
        if !already_pending && let Some(siginfo) = siginfo {
            // Standard signals coalesce into the first pending instance. Later
            // generations neither add nor replace siginfo until that instance
            // is dequeued.
            self.standard_siginfos.insert(signal, siginfo);
        }
        self.assert_invariants();
        Ok(())
    }

    pub fn enqueue_realtime(
        &mut self,
        signal: LinuxSignal,
        siginfo: Option<LinuxSiginfo>,
    ) -> Result<(), KernelOperationError> {
        if signal.raw() < 32 {
            return Err(KernelOperationError::StandardSignalInRealtimeQueue(signal));
        }
        self.realtime.entry(signal).or_default().push_back(siginfo);
        self.present = self.present.with(signal.raw());
        self.assert_invariants();
        Ok(())
    }

    /// Discard every pending instance whose signal is in `signals`.
    ///
    /// Linux job-control generation uses this for its task-wide cancellation
    /// rule: generating SIGCONT discards every pending stop signal, while
    /// generating a stop signal discards every pending SIGCONT.
    pub fn discard(&mut self, signals: SigSet) -> bool {
        let discarded = !self.present.intersect(signals).is_empty();
        if !discarded {
            return false;
        }
        self.present = self.present.difference(signals);
        self.standard_siginfos
            .retain(|signal, _| !signals.contains(signal.raw()));
        self.realtime
            .retain(|signal, _| !signals.contains(signal.raw()));
        self.assert_invariants();
        true
    }

    pub fn entries(&self) -> Vec<PendingSignal> {
        let mut entries = Vec::new();
        for raw in 1..=64 {
            if !self.present.contains(raw) {
                continue;
            }
            let Ok(signal) = LinuxSignal::for_signal_number(raw) else {
                carrick_fatal!(
                    "kernel::pending_signals",
                    "present bitset contains invalid signal number"
                );
            };
            if let Some(realtime) = self.realtime.get(&signal) {
                entries.extend(
                    realtime
                        .iter()
                        .copied()
                        .map(|siginfo| PendingSignal { signal, siginfo }),
                );
            } else {
                entries.push(PendingSignal {
                    signal,
                    siginfo: self.standard_siginfos.get(&signal).copied(),
                });
            }
        }
        entries
    }

    pub fn from_entries(entries: &[PendingSignal]) -> Self {
        let mut queue = Self::default();
        for entry in entries {
            if entry.signal.raw() >= 32 {
                let _ = queue.enqueue_realtime(entry.signal, entry.siginfo);
            } else {
                let _ = queue.enqueue_standard(entry.signal, entry.siginfo);
            }
        }
        queue
    }

    pub fn take_lowest_in(&mut self, wanted: SigSet) -> Option<PendingSignal> {
        let raw = self.present.intersect(wanted).lowest_signum()?;
        let signal = LinuxSignal::for_signal_number(raw).ok()?;
        let siginfo = if let Some(instances) = self.realtime.get_mut(&signal) {
            let siginfo = instances.pop_front().flatten();
            if instances.is_empty() {
                self.realtime.remove(&signal);
                self.present = self.present.without(raw);
            }
            siginfo
        } else {
            self.present = self.present.without(raw);
            self.standard_siginfos.remove(&signal)
        };
        self.assert_invariants();
        Some(PendingSignal { signal, siginfo })
    }

    fn requeue_front(&mut self, pending: PendingSignal) {
        let signal = pending.signal;
        if signal.raw() >= 32 {
            self.realtime
                .entry(signal)
                .or_default()
                .push_front(pending.siginfo);
        } else if let Some(siginfo) = pending.siginfo {
            self.standard_siginfos.insert(signal, siginfo);
        } else {
            self.standard_siginfos.remove(&signal);
        }
        self.present = self.present.with(signal.raw());
        self.assert_invariants();
    }

    fn assert_invariants(&self) {
        debug_assert!(self.realtime.iter().all(
            |(signal, instances)| !instances.is_empty() && self.present.contains(signal.raw())
        ));
        debug_assert!(
            self.standard_siginfos
                .keys()
                .all(|signal| self.present.contains(signal.raw()))
        );
    }
}

/// Task-directed pending-signal authority. The hint is an index published from
/// the queue while locked; `false` proves empty and `true` requires locked
/// revalidation.
#[derive(Debug, Default)]
pub struct TaskPendingSignals {
    queue: Mutex<PendingQueue>,
    pending_hint: AtomicU64,
    revision: ObjectRevision,
}

impl TaskPendingSignals {
    pub const fn new() -> Self {
        Self {
            queue: Mutex::new(PendingQueue {
                present: SigSet::EMPTY,
                standard_siginfos: BTreeMap::new(),
                realtime: BTreeMap::new(),
            }),
            pending_hint: AtomicU64::new(0),
            revision: ObjectRevision::new(),
        }
    }

    pub fn pending_count(&self) -> usize {
        self.queue.lock().pending_count()
    }

    pub fn revision(&self) -> u64 {
        self.revision.load()
    }

    pub fn may_be_nonempty(&self) -> bool {
        self.pending_hint.load(Ordering::Acquire) != 0
    }

    pub fn present(&self) -> SigSet {
        self.queue.lock().present()
    }

    pub fn enqueue_standard(&self, signal: LinuxSignal, siginfo: Option<LinuxSiginfo>) {
        let mut queue = self.queue.lock();
        let _ = queue.enqueue_standard(signal, siginfo);
        self.publish_queue(&queue);
    }

    pub fn enqueue_realtime(&self, signal: LinuxSignal, siginfo: Option<LinuxSiginfo>) {
        let mut queue = self.queue.lock();
        let _ = queue.enqueue_realtime(signal, siginfo);
        self.publish_queue(&queue);
    }

    pub fn take_lowest_in(&self, wanted: SigSet) -> Option<PendingSignal> {
        let mut queue = self.queue.lock();
        let pending = queue.take_lowest_in(wanted)?;
        self.publish_queue(&queue);
        Some(pending)
    }

    pub fn snapshot_entries(&self) -> Vec<PendingSignal> {
        self.queue.lock().entries()
    }

    pub fn replace_entries(&self, entries: &[PendingSignal]) {
        let replacement = PendingQueue::from_entries(entries);
        let mut queue = self.queue.lock();
        if *queue != replacement {
            *queue = replacement;
            self.publish_queue(&queue);
        }
    }

    pub(super) fn discard(&self, signals: SigSet) {
        let mut queue = self.queue.lock();
        if queue.discard(signals) {
            self.publish_queue(&queue);
        }
    }

    fn publish_queue(&self, queue: &PendingQueue) {
        self.pending_hint
            .store(queue.present().raw(), Ordering::Release);
        self.revision.publish();
        debug_assert_eq!(
            self.pending_hint.load(Ordering::Relaxed),
            queue.present().raw()
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandlerFrameState {
    pub on_altstack: bool,
    pub restore_mask: Option<SigSet>,
}

/// Complete per-thread Linux signal state. The containing Kernel `Thread`
/// serializes mutations; no field is process-global or keyed by a reusable raw
/// backend TID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThreadSignalState {
    blocked: SigSet,
    pending: PendingQueue,
    altstack: Option<LinuxSigaltstack>,
    handler_frames: Vec<HandlerFrameState>,
    armed_restore_mask: Option<SigSet>,
    routed_siginfos: BTreeMap<LinuxSignal, VecDeque<LinuxSiginfo>>,
    pending_actions: BTreeMap<LinuxSignal, VecDeque<LinuxSigaction>>,
}

impl ThreadSignalState {
    /// Summary-shaped constructor retained for existing Kernel model tests.
    /// Production signal publication uses the typed queue/altstack methods.
    pub fn new(
        blocked: SigSet,
        pending: SigSet,
        altstack_enabled: bool,
        handler_frame_depth: usize,
    ) -> Self {
        let mut pending_queue = PendingQueue::default();
        for raw in 1..=64 {
            if pending.contains(raw)
                && let Ok(signal) = LinuxSignal::for_signal_number(raw)
            {
                if raw >= 32 {
                    let _ = pending_queue.enqueue_realtime(signal, None);
                } else {
                    let _ = pending_queue.enqueue_standard(signal, None);
                }
            }
        }
        Self {
            blocked,
            pending: pending_queue,
            altstack: altstack_enabled.then(LinuxSigaltstack::empty),
            handler_frames: vec![
                HandlerFrameState {
                    on_altstack: false,
                    restore_mask: None,
                };
                handler_frame_depth
            ],
            armed_restore_mask: None,
            routed_siginfos: BTreeMap::new(),
            pending_actions: BTreeMap::new(),
        }
    }

    pub(crate) fn for_fork(caller: &Self) -> Self {
        Self {
            blocked: caller.blocked,
            pending: PendingQueue::default(),
            altstack: caller.altstack,
            handler_frames: caller.handler_frames.clone(),
            armed_restore_mask: caller.armed_restore_mask,
            routed_siginfos: BTreeMap::new(),
            pending_actions: BTreeMap::new(),
        }
    }

    pub(crate) fn for_clone_thread(caller: &Self) -> Self {
        Self {
            blocked: caller.blocked,
            pending: PendingQueue::default(),
            altstack: None,
            handler_frames: Vec::new(),
            armed_restore_mask: None,
            routed_siginfos: BTreeMap::new(),
            pending_actions: BTreeMap::new(),
        }
    }

    pub(crate) fn for_exec(caller: &Self) -> Self {
        Self {
            blocked: caller.blocked,
            pending: caller.pending.clone(),
            altstack: None,
            handler_frames: Vec::new(),
            armed_restore_mask: None,
            routed_siginfos: caller.routed_siginfos.clone(),
            pending_actions: BTreeMap::new(),
        }
    }

    pub const fn blocked(&self) -> SigSet {
        self.blocked
    }

    pub fn set_blocked(&mut self, blocked: SigSet) {
        self.blocked = blocked;
    }

    pub const fn pending(&self) -> SigSet {
        self.pending.present()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.pending_count()
    }

    pub fn snapshot_pending_entries(&self) -> Vec<PendingSignal> {
        self.pending.entries()
    }

    pub fn replace_pending_entries(&mut self, entries: &[PendingSignal]) {
        self.pending = PendingQueue::from_entries(entries);
    }

    pub fn enqueue_standard(&mut self, signal: LinuxSignal, siginfo: Option<LinuxSiginfo>) {
        let _ = self.pending.enqueue_standard(signal, siginfo);
    }

    pub fn enqueue_realtime(&mut self, signal: LinuxSignal, siginfo: Option<LinuxSiginfo>) {
        let _ = self.pending.enqueue_realtime(signal, siginfo);
    }

    pub fn take_lowest_in(&mut self, wanted: SigSet) -> Option<PendingSignal> {
        self.pending.take_lowest_in(wanted)
    }

    fn requeue_front(&mut self, pending: PendingSignal) {
        self.pending.requeue_front(pending);
    }

    pub(super) fn discard_pending(&mut self, signals: SigSet) {
        if self.pending.discard(signals) {
            self.routed_siginfos
                .retain(|signal, _| !signals.contains(signal.raw()));
            self.pending_actions
                .retain(|signal, _| !signals.contains(signal.raw()));
        }
    }

    pub const fn altstack(&self) -> Option<LinuxSigaltstack> {
        self.altstack
    }

    pub fn set_altstack(&mut self, altstack: Option<LinuxSigaltstack>) {
        self.altstack = altstack;
    }

    pub const fn altstack_enabled(&self) -> bool {
        self.altstack.is_some()
    }

    pub fn handler_frame_depth(&self) -> usize {
        self.handler_frames.len()
    }

    pub fn handler_frames(&self) -> Vec<HandlerFrameState> {
        self.handler_frames.clone()
    }

    pub fn has_altstack_handler_frame(&self) -> bool {
        self.handler_frames.iter().any(|frame| frame.on_altstack)
    }

    pub fn clear_handler_frames(&mut self) {
        self.handler_frames.clear();
    }

    pub fn push_handler_frame(&mut self, frame: HandlerFrameState) {
        self.handler_frames.push(frame);
    }

    pub fn pop_handler_frame(&mut self) -> Option<HandlerFrameState> {
        self.handler_frames.pop()
    }

    pub const fn armed_restore_mask(&self) -> Option<SigSet> {
        self.armed_restore_mask
    }

    pub fn take_armed_restore_mask(&mut self) -> Option<SigSet> {
        self.armed_restore_mask.take()
    }

    pub fn arm_restore_mask(&mut self, restore_mask: Option<SigSet>) {
        self.armed_restore_mask = restore_mask;
    }

    pub fn record_routed_siginfo(&mut self, signal: LinuxSignal, siginfo: LinuxSiginfo) {
        let entries = self.routed_siginfos.entry(signal).or_default();
        if signal.raw() < 32 {
            entries.clear();
        }
        entries.push_back(siginfo);
    }

    pub fn take_routed_siginfo(&mut self, signal: LinuxSignal) -> Option<LinuxSiginfo> {
        let entries = self.routed_siginfos.get_mut(&signal)?;
        let siginfo = entries.pop_front();
        if entries.is_empty() {
            self.routed_siginfos.remove(&signal);
        }
        siginfo
    }

    fn take_all_routed_siginfos(&mut self, signal: LinuxSignal) -> Vec<LinuxSiginfo> {
        self.routed_siginfos
            .remove(&signal)
            .map_or_else(Vec::new, |entries| entries.into_iter().collect())
    }

    pub fn record_pending_action(&mut self, signal: LinuxSignal, action: LinuxSigaction) {
        self.pending_actions
            .entry(signal)
            .or_default()
            .push_back(action);
    }

    pub fn take_pending_action(&mut self, signal: LinuxSignal) -> Option<LinuxSigaction> {
        let actions = self.pending_actions.get_mut(&signal)?;
        let action = actions.pop_front();
        if actions.is_empty() {
            self.pending_actions.remove(&signal);
        }
        action
    }

    pub fn routed_siginfos(&self) -> Vec<(LinuxSignal, LinuxSiginfo)> {
        self.routed_siginfos
            .iter()
            .flat_map(|(signal, entries)| entries.iter().map(|info| (*signal, *info)))
            .collect()
    }

    pub fn pending_actions(&self) -> Vec<(LinuxSignal, LinuxSigaction)> {
        self.pending_actions
            .iter()
            .flat_map(|(signal, entries)| entries.iter().map(|action| (*signal, *action)))
            .collect()
    }
}

impl Default for ThreadSignalState {
    fn default() -> Self {
        Self::new(SigSet::EMPTY, SigSet::EMPTY, false, 0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalPendingOwner {
    Thread,
    Task,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalDequeue {
    pub owner: SignalPendingOwner,
    pub pending: PendingSignal,
    pub(crate) job_control_generation: Option<JobControlStopInvalidationGeneration>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignalWaitReservation {
    dequeue: SignalDequeue,
    action: LinuxSigaction,
    action_generation: u64,
    effective_mask: SigSet,
    persistent_restore: SigSet,
    mask_generation: u64,
    temporary: WaitSigMask,
    origin: SignalReservationOrigin,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalReservationOrigin {
    Kernel,
    HostSlot { tid: i32 },
}

fn is_default_ignored_signal(signum: i32) -> bool {
    matches!(
        signum,
        crate::linux_abi::LINUX_SIGCHLD
            | crate::linux_abi::LINUX_SIGURG
            | crate::linux_abi::LINUX_SIGWINCH
    )
}

impl SignalWaitReservation {
    pub const fn signum(self) -> i32 {
        self.dequeue.pending.signal.raw()
    }

    pub const fn action(self) -> LinuxSigaction {
        self.action
    }

    pub const fn action_generation(self) -> u64 {
        self.action_generation
    }

    pub const fn effective_mask(self) -> SigSet {
        self.effective_mask
    }

    pub const fn persistent_restore(self) -> SigSet {
        self.persistent_restore
    }

    pub const fn mask_generation(self) -> u64 {
        self.mask_generation
    }

    pub const fn temporary(self) -> WaitSigMask {
        self.temporary
    }

    pub const fn origin(self) -> SignalReservationOrigin {
        self.origin
    }

    pub(crate) const fn dequeue(self) -> SignalDequeue {
        self.dequeue
    }
}

/// Exact signal leaf bundle captured from one [`super::core::KernelContext`].
/// The facade contains operations only; all state and revisions remain in the
/// referenced Kernel objects.
#[derive(Clone, Debug)]
pub struct SignalAuthority {
    sighand: Arc<Sighand>,
    task_pending: Arc<TaskPendingSignals>,
    task: TaskRef,
    thread: ThreadRef,
}

impl SignalAuthority {
    pub(crate) fn new(
        sighand: Arc<Sighand>,
        task_pending: Arc<TaskPendingSignals>,
        task: TaskRef,
        thread: ThreadRef,
    ) -> Self {
        Self {
            sighand,
            task_pending,
            task,
            thread,
        }
    }

    pub fn sighand_id(&self) -> SighandId {
        self.sighand.id()
    }

    pub fn action(&self, signal: LinuxSignal) -> LinuxSigaction {
        self.sighand.action(signal)
    }

    pub fn action_generation(&self) -> u64 {
        self.sighand.revision()
    }

    pub fn action_with_generation(&self, signal: LinuxSignal) -> (u64, LinuxSigaction) {
        self.sighand.action_with_revision(signal)
    }

    pub fn install_action(&self, signal: LinuxSignal, action: LinuxSigaction) {
        self.sighand.install_action(signal, action);
    }

    pub fn blocked(&self) -> SigSet {
        self.thread.signal_state.lock().blocked()
    }

    pub fn signal_state_generation(&self) -> u64 {
        self.thread.revision.load()
    }

    pub fn set_blocked(&self, blocked: SigSet) {
        let mut state = self.thread.signal_state.lock();
        state.set_blocked(blocked);
        self.thread.publish_signal_state(&state);
    }

    pub fn thread_pending(&self) -> SigSet {
        self.thread.signal_state.lock().pending()
    }

    pub fn task_pending(&self) -> SigSet {
        self.task_pending.present()
    }

    pub fn may_have_thread_pending(&self) -> bool {
        self.thread.may_have_pending_signals()
    }

    pub fn may_have_task_pending(&self) -> bool {
        self.task_pending.may_be_nonempty()
    }

    pub fn enqueue_thread_standard(&self, signal: LinuxSignal, siginfo: Option<LinuxSiginfo>) {
        let mut state = self.thread.signal_state.lock();
        state.enqueue_standard(signal, siginfo);
        self.thread.publish_signal_state(&state);
    }

    pub fn enqueue_thread_realtime(&self, signal: LinuxSignal, siginfo: Option<LinuxSiginfo>) {
        let mut state = self.thread.signal_state.lock();
        state.enqueue_realtime(signal, siginfo);
        self.thread.publish_signal_state(&state);
    }

    pub fn enqueue_task_standard(&self, signal: LinuxSignal, siginfo: Option<LinuxSiginfo>) {
        self.task_pending.enqueue_standard(signal, siginfo);
    }

    pub fn enqueue_task_realtime(&self, signal: LinuxSignal, siginfo: Option<LinuxSiginfo>) {
        self.task_pending.enqueue_realtime(signal, siginfo);
    }

    /// Choose and dequeue one candidate under the canonical thread-then-task
    /// lock order. A same-signum tie is thread-directed, preserving provenance.
    /// Job-control generation stays locked through dequeue so a later default
    /// action carries the exact stop-invalidation epoch in which it left
    /// pending state.
    pub fn take_lowest_in(&self, wanted: SigSet) -> Option<SignalDequeue> {
        let generation_guard = self.task.lock_signal_generation();
        let mut thread = self.thread.signal_state.lock();
        let mut task = self.task_pending.queue.lock();
        let thread_signal = thread.pending().intersect(wanted).lowest_signum();
        let task_signal = task.present().intersect(wanted).lowest_signum();
        let owner = match (thread_signal, task_signal) {
            (None, None) => return None,
            (Some(_), None) => SignalPendingOwner::Thread,
            (None, Some(_)) => SignalPendingOwner::Task,
            (Some(thread), Some(task)) if thread <= task => SignalPendingOwner::Thread,
            (Some(_), Some(_)) => SignalPendingOwner::Task,
        };
        let pending = match owner {
            SignalPendingOwner::Thread => {
                let mut pending = thread.take_lowest_in(wanted)?;
                if pending.siginfo.is_none() {
                    pending.siginfo = thread.take_routed_siginfo(pending.signal);
                }
                self.thread.publish_signal_state(&thread);
                pending
            }
            SignalPendingOwner::Task => {
                let pending = task.take_lowest_in(wanted)?;
                self.task_pending.publish_queue(&task);
                pending
            }
        };
        drop(thread);
        drop(task);
        let job_control_generation = self.task.job_control_generation_for_dequeue(pending.signal);
        drop(generation_guard);
        Some(SignalDequeue {
            owner,
            pending,
            job_control_generation,
        })
    }

    pub fn has_pending_in(&self, wanted: SigSet) -> bool {
        let _generation_guard = self.task.lock_signal_generation();
        let thread = self.thread.signal_state.lock();
        let task = self.task_pending.queue.lock();
        !thread
            .pending()
            .union(task.present())
            .intersect(wanted)
            .is_empty()
    }

    /// Atomically choose and reserve one signal for an interruptible wait.
    /// Pending ownership, the live effective mask, exact action and both
    /// generations are sampled under one canonical lock transaction. Ignored
    /// candidates are discarded in-place and the transaction continues to the
    /// next deliverable instance without relying on another wake edge.
    pub fn reserve_deliverable_for_wait(
        &self,
        temporary: WaitSigMask,
    ) -> Option<SignalWaitReservation> {
        self.reserve_deliverable_for_wait_inner(temporary, None)
    }

    pub fn reserve_deliverable_for_wait_with_host_slot(
        &self,
        temporary: WaitSigMask,
        tid: i32,
        signum: i32,
    ) -> Option<SignalWaitReservation> {
        self.reserve_deliverable_for_wait_inner(temporary, Some((tid, signum)))
    }

    fn reserve_deliverable_for_wait_inner(
        &self,
        temporary: WaitSigMask,
        host_slot: Option<(i32, i32)>,
    ) -> Option<SignalWaitReservation> {
        let leader_tid = LinuxTid::for_task_leader(self.task.key().id);
        let is_leader = self.thread.key().tid == leader_tid;
        let leader_blocked = if !is_leader {
            self.task
                .thread(leader_tid)
                .map(|l| l.signal_state().blocked())
        } else {
            None
        };
        let generation_guard = self.task.lock_signal_generation();
        let mut thread = self.thread.signal_state.lock();
        let mut task = self.task_pending.queue.lock();
        let actions = self.sighand.actions.lock();
        let host_inserted = host_slot.and_then(|(tid, signum)| {
            let signal = LinuxSignal::for_signal_number(signum).ok()?;
            let inserted = if signum >= 32 {
                let siginfos = thread.take_all_routed_siginfos(signal);
                if siginfos.is_empty() {
                    let _ = thread.take_pending_action(signal);
                    thread.enqueue_realtime(signal, None);
                } else {
                    for siginfo in siginfos {
                        let _ = thread.take_pending_action(signal);
                        thread.enqueue_realtime(signal, Some(siginfo));
                    }
                }
                true
            } else {
                let inserted = !thread.pending().contains(signum);
                let siginfo = thread.take_routed_siginfo(signal);
                let _ = thread.take_pending_action(signal);
                thread.enqueue_standard(signal, siginfo);
                inserted
            };
            self.thread.publish_signal_state(&thread);
            inserted.then_some((tid, signum))
        });
        let live_mask = thread.blocked();
        let armed_restore = thread.armed_restore_mask();
        let persistent_restore = armed_restore.unwrap_or(live_mask);
        let effective_mask = armed_restore.map_or_else(
            || match temporary {
                WaitSigMask::Additive(extra) => persistent_restore.union(extra),
                WaitSigMask::Replace(replacement) => replacement,
            },
            |_| live_mask,
        );
        let mask_generation = self.thread.revision.load();
        let action_generation = self.sighand.revision.load();
        let available_task = if let Some(leader_mask) = leader_blocked {
            task.present().intersect(leader_mask)
        } else {
            task.present()
        };
        loop {
            let candidates = thread
                .pending()
                .union(available_task)
                .difference(effective_mask);
            let signum = candidates.lowest_signum()?;
            let signal = LinuxSignal::for_signal_number(signum).ok()?;
            let action = actions
                .get(&signal)
                .copied()
                .unwrap_or_else(LinuxSigaction::empty);
            let ignored = action.sa_handler == crate::linux_abi::LINUX_SIG_IGN
                || action.sa_handler == crate::linux_abi::LINUX_SIG_DFL
                    && is_default_ignored_signal(signum);
            let thread_has = thread.pending().contains(signum);
            let dequeue = if thread_has {
                let mut pending = thread.take_lowest_in(SigSet::EMPTY.with(signum))?;
                if pending.siginfo.is_none() {
                    pending.siginfo = thread.take_routed_siginfo(pending.signal);
                }
                self.thread.publish_signal_state(&thread);
                SignalDequeue {
                    owner: SignalPendingOwner::Thread,
                    pending,
                    job_control_generation: self
                        .task
                        .job_control_generation_for_dequeue(pending.signal),
                }
            } else {
                let pending = task.take_lowest_in(SigSet::EMPTY.with(signum))?;
                self.task_pending.publish_queue(&task);
                SignalDequeue {
                    owner: SignalPendingOwner::Task,
                    pending,
                    job_control_generation: self
                        .task
                        .job_control_generation_for_dequeue(pending.signal),
                }
            };
            if ignored {
                continue;
            }
            drop(actions);
            drop(task);
            drop(thread);
            drop(generation_guard);
            return Some(SignalWaitReservation {
                dequeue,
                action,
                action_generation,
                effective_mask,
                persistent_restore,
                mask_generation,
                temporary,
                origin: host_inserted.map_or(SignalReservationOrigin::Kernel, |(tid, signum)| {
                    if signum == dequeue.pending.signal.raw() {
                        SignalReservationOrigin::HostSlot { tid }
                    } else {
                        SignalReservationOrigin::Kernel
                    }
                }),
            });
        }
    }

    /// Return an unconsumed exact reservation to the same pending owner. The
    /// canonical thread-then-task lock order matches dequeue, and real-time
    /// payloads return to the front so cancellation cannot reorder them.
    pub fn requeue_reserved(&self, dequeued: SignalDequeue) {
        let _generation_guard = self.task.lock_signal_generation();
        let mut thread = self.thread.signal_state.lock();
        let mut task = self.task_pending.queue.lock();
        match dequeued.owner {
            SignalPendingOwner::Thread => {
                thread.requeue_front(dequeued.pending);
                self.thread.publish_signal_state(&thread);
            }
            SignalPendingOwner::Task => {
                task.requeue_front(dequeued.pending);
                self.task_pending.publish_queue(&task);
            }
        }
    }

    pub fn altstack(&self) -> Option<LinuxSigaltstack> {
        self.thread.signal_state.lock().altstack()
    }

    pub fn set_altstack(&self, altstack: Option<LinuxSigaltstack>) {
        let mut state = self.thread.signal_state.lock();
        state.set_altstack(altstack);
        self.thread.publish_signal_state(&state);
    }

    pub fn handler_frame_depth(&self) -> usize {
        self.thread.signal_state.lock().handler_frame_depth()
    }

    pub fn push_handler_frame(&self, frame: HandlerFrameState) {
        let mut state = self.thread.signal_state.lock();
        state.push_handler_frame(frame);
        self.thread.publish_signal_state(&state);
    }

    pub fn pop_handler_frame(&self) -> Option<HandlerFrameState> {
        let mut state = self.thread.signal_state.lock();
        let frame = state.pop_handler_frame();
        if frame.is_some() {
            self.thread.publish_signal_state(&state);
        }
        frame
    }

    pub fn armed_restore_mask(&self) -> Option<SigSet> {
        self.thread.signal_state.lock().armed_restore_mask()
    }

    pub fn arm_restore_mask(&self, restore_mask: Option<SigSet>) {
        let mut state = self.thread.signal_state.lock();
        state.arm_restore_mask(restore_mask);
        self.thread.publish_signal_state(&state);
    }

    pub fn record_pending_action(&self, signal: LinuxSignal, action: LinuxSigaction) {
        let mut state = self.thread.signal_state.lock();
        state.record_pending_action(signal, action);
        self.thread.publish_signal_state(&state);
    }

    pub fn take_pending_action(&self, signal: LinuxSignal) -> Option<LinuxSigaction> {
        let mut state = self.thread.signal_state.lock();
        let action = state.take_pending_action(signal);
        if action.is_some() {
            self.thread.publish_signal_state(&state);
        }
        action
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::container::{Container, LaunchContext, RunId};
    use crate::kernel::ids::{ChildExitSignal, LinuxTid, ObjectIdRegistry, TaskId};
    use crate::kernel::objects::{
        Credentials, FileTable, FsContext, Mm, Task, TaskIdentity, TaskKey, TaskShared, ThreadKey,
        ThreadResources,
    };
    use carrick_hal::ThreadId;

    struct Fixture {
        _ids: ObjectIdRegistry,
        task: TaskRef,
        leader: ThreadRef,
    }

    impl Fixture {
        fn new() -> Self {
            let ids = ObjectIdRegistry::new();
            let task_id = TaskId::for_root_bootstrap(100).expect("task ID");
            let key = TaskKey {
                id: task_id,
                serial: ids.task_serial().expect("task serial"),
            };
            let mm = Arc::new(Mm::new_reference(ids.mm_id().expect("mm ID")));
            let sighand = Arc::new(Sighand::new(ids.sighand_id().expect("sighand ID")));
            let shared = Arc::new(TaskShared::new(mm, sighand));
            let resources = Arc::new(ThreadResources::new(
                Arc::new(FileTable::new(ids.file_table_id().expect("files ID"))),
                Arc::new(FsContext::new(ids.fs_context_id().expect("fs ID"))),
                Arc::new(Credentials::root(
                    ids.credentials_id().expect("credentials ID"),
                )),
            ));
            let container = Arc::new(Container::new(LaunchContext::unmanaged(RunId::new(
                "objects-fixture",
            ))));
            let task = Arc::new(Task::new(
                key,
                None,
                TaskIdentity::led_by(task_id),
                shared,
                resources.credentials(),
                container,
                ChildExitSignal::SIGCHLD,
            ));
            let leader = task
                .attach_thread(
                    ThreadKey {
                        tid: LinuxTid::for_task_leader(task_id),
                        serial: ids.thread_serial().expect("thread serial"),
                    },
                    ThreadId::synthetic_for_tests(100),
                    resources,
                )
                .expect("leader thread");
            Self {
                _ids: ids,
                task,
                leader,
            }
        }
    }

    fn siginfo(signal: LinuxSignal, payload: i32) -> LinuxSiginfo {
        let mut info: LinuxSiginfo = unsafe { std::mem::zeroed() };
        info.si_signo = signal.raw();
        info.si_code = crate::linux_abi::LINUX_SI_QUEUE;
        info._pad[..4].copy_from_slice(&payload.to_ne_bytes());
        info
    }

    #[test]
    fn sighand_retains_full_actions_and_exec_preserves_only_ignore() {
        let ids = ObjectIdRegistry::new();
        let source = Sighand::new(ids.sighand_id().expect("source sighand"));
        let ignored = LinuxSignal::for_signal_number(10).expect("ignored signal");
        let caught = LinuxSignal::for_signal_number(12).expect("caught signal");
        let mut ignored_action = LinuxSigaction::empty();
        ignored_action.sa_handler = crate::linux_abi::LINUX_SIG_IGN;
        ignored_action.sa_flags = 0x4000_0000;
        ignored_action.sa_mask = [0x55];
        let caught_action = LinuxSigaction {
            sa_handler: 0x1234_5000,
            sa_flags: 0x0800_0004,
            sa_restorer: 0x7777_0000,
            sa_mask: [0xaa],
        };
        source.install_action(ignored, ignored_action);
        source.install_action(caught, caught_action);

        let copied = Sighand::for_fork_copy(ids.sighand_id().expect("copy sighand"), &source);
        assert_eq!(copied.action(ignored), ignored_action);
        assert_eq!(copied.action(caught), caught_action);

        let exec = Sighand::for_exec(ids.sighand_id().expect("exec sighand"), &source);
        assert_eq!(exec.action(ignored), ignored_action);
        assert_eq!(exec.action(caught), LinuxSigaction::empty());
    }

    #[test]
    fn pending_queue_coalesces_standard_and_preserves_realtime_fifo_payloads() {
        let standard = LinuxSignal::for_signal_number(10).expect("standard signal");
        let realtime = LinuxSignal::for_signal_number(34).expect("realtime signal");
        let first_standard = siginfo(standard, 1);
        let coalesced_standard = siginfo(standard, 2);
        let first_rt = siginfo(realtime, 3);
        let second_rt = siginfo(realtime, 4);
        let mut queue = PendingQueue::default();

        queue
            .enqueue_standard(standard, Some(first_standard))
            .expect("standard signal");
        queue
            .enqueue_standard(standard, Some(coalesced_standard))
            .expect("standard signal");
        queue
            .enqueue_realtime(realtime, Some(first_rt))
            .expect("realtime signal");
        queue
            .enqueue_realtime(realtime, Some(second_rt))
            .expect("realtime signal");

        assert_eq!(queue.pending_count(), 3);
        assert_eq!(
            queue.take_lowest_in(SigSet::from_raw(u64::MAX)),
            Some(PendingSignal {
                signal: standard,
                siginfo: Some(first_standard),
            })
        );
        assert_eq!(
            queue.take_lowest_in(SigSet::from_raw(u64::MAX)),
            Some(PendingSignal {
                signal: realtime,
                siginfo: Some(first_rt),
            })
        );
        assert!(queue.present().contains(realtime.raw()));
        assert_eq!(
            queue.take_lowest_in(SigSet::from_raw(u64::MAX)),
            Some(PendingSignal {
                signal: realtime,
                siginfo: Some(second_rt),
            })
        );
        assert!(queue.present().is_empty());
    }

    #[test]
    fn task_pending_hint_never_hides_authoritative_queue_state() {
        let pending = TaskPendingSignals::new();
        let signal = LinuxSignal::for_signal_number(17).expect("signal");
        assert!(!pending.may_be_nonempty());

        pending.enqueue_standard(signal, Some(siginfo(signal, 9)));
        assert!(pending.may_be_nonempty());
        assert!(pending.present().contains(signal.raw()));

        let delivered = pending.take_lowest_in(SigSet::EMPTY.with(signal.raw()));
        assert_eq!(delivered.map(|entry| entry.signal), Some(signal));
        assert!(!pending.may_be_nonempty());
        assert!(pending.present().is_empty());
    }

    #[test]
    fn thread_signal_lifecycle_transforms_preserve_linux_owners() {
        let blocked = SigSet::EMPTY.with(10);
        let thread_pending = LinuxSignal::for_signal_number(12).expect("pending signal");
        let mut caller = ThreadSignalState::default();
        caller.set_blocked(blocked);
        caller.enqueue_standard(thread_pending, Some(siginfo(thread_pending, 7)));
        caller.set_altstack(Some(LinuxSigaltstack {
            ss_sp: 0x4000,
            ss_flags: 0,
            __pad: 0,
            ss_size: 0x2000,
        }));
        caller.push_handler_frame(HandlerFrameState {
            on_altstack: true,
            restore_mask: Some(SigSet::EMPTY.with(2)),
        });
        caller.arm_restore_mask(Some(SigSet::EMPTY.with(3)));

        let forked = ThreadSignalState::for_fork(&caller);
        assert_eq!(forked.blocked(), blocked);
        assert!(forked.pending().is_empty());
        assert!(forked.altstack_enabled());
        assert_eq!(forked.handler_frame_depth(), 1);

        let cloned = ThreadSignalState::for_clone_thread(&caller);
        assert_eq!(cloned.blocked(), blocked);
        assert!(cloned.pending().is_empty());
        assert!(!cloned.altstack_enabled());
        assert_eq!(cloned.handler_frame_depth(), 0);

        let exec = ThreadSignalState::for_exec(&caller);
        assert_eq!(exec.blocked(), blocked);
        assert!(exec.pending().contains(thread_pending.raw()));
        assert!(!exec.altstack_enabled());
        assert_eq!(exec.handler_frame_depth(), 0);
        assert_eq!(exec.armed_restore_mask(), None);
    }

    #[test]
    fn signal_authority_preserves_thread_first_same_signum_provenance() {
        let fixture = Fixture::new();
        let shared = fixture.task.shared();
        let authority = SignalAuthority::new(
            shared.sighand(),
            shared.pending_signals(),
            Arc::clone(&fixture.task),
            Arc::clone(&fixture.leader),
        );
        let signal = LinuxSignal::for_signal_number(34).expect("realtime signal");
        let thread_info = siginfo(signal, 11);
        let task_info = siginfo(signal, 22);
        authority.enqueue_task_realtime(signal, Some(task_info));
        authority.enqueue_thread_realtime(signal, Some(thread_info));

        let wanted = SigSet::EMPTY.with(signal.raw());
        assert_eq!(
            authority.take_lowest_in(wanted),
            Some(SignalDequeue {
                owner: SignalPendingOwner::Thread,
                pending: PendingSignal {
                    signal,
                    siginfo: Some(thread_info),
                },
                job_control_generation: None,
            })
        );
        assert_eq!(
            authority.take_lowest_in(wanted),
            Some(SignalDequeue {
                owner: SignalPendingOwner::Task,
                pending: PendingSignal {
                    signal,
                    siginfo: Some(task_info),
                },
                job_control_generation: None,
            })
        );
        assert!(!authority.may_have_thread_pending());
        assert!(!authority.may_have_task_pending());
    }

    #[test]

    fn pending_queue_mismatched_signal_returns_typed_error() {
        let standard = LinuxSignal::for_signal_number(10).expect("standard signal");
        let realtime = LinuxSignal::for_signal_number(34).expect("realtime signal");
        let mut queue = PendingQueue::default();

        assert!(matches!(
            queue.enqueue_standard(realtime, None),
            Err(KernelOperationError::RealtimeSignalInStandardQueue(s)) if s == realtime
        ));
        assert!(matches!(
            queue.enqueue_realtime(standard, None),
            Err(KernelOperationError::StandardSignalInRealtimeQueue(s)) if s == standard
        ));
    }
}
