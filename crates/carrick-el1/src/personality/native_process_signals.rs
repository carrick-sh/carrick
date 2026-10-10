//! Retained signal resources for an admitted fresh native process.
//! Signal and child-exit decisions remain in the shared Linux signal policy.
extern crate alloc;
use crate::lock::SpinLock;
use alloc::sync::Arc;
use carrick_personality_linux::signal::{EnqueueOutcome, SignalInbox, StaleTarget};
use carrick_sched_core::process::exit::{ExitSignalDisposition, ExitSignalSource, ExitSignalState};
use carrick_sched_core::process::{LinuxSignal, TaskKey};
use carrick_signal_core::SignalSet;
use carrick_signal_core::policy::{
    Action, ActionError, ActionInheritance, ActionTable, ChildEvent, ChildInterest, Disposition,
    SigBlockMask, SighandSharing, Signal, child_decision,
};

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

struct SignalResources<T> {
    actions: ActionTable,
    inbox: SignalInbox<TaskKey, T>,
    thread_pending: Vec<(carrick_sched_core::RecordRef, PendingSignals<T>)>,
    forced_segv: Vec<carrick_sched_core::RecordRef>,
}
/// One actual sighand and pending owner, retained by exact task handles.
pub struct NativeProcessSignals<T> {
    key: TaskKey,
    resources: Arc<SpinLock<SignalResources<T>>>,
}
impl<T> Clone for NativeProcessSignals<T> {
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
impl<T> NativeProcessSignals<T> {
    /// Fresh native-root admission owns the initial default actions and empty
    /// pending queue. This does not claim to import another launcher's sighand.
    pub fn fresh_root(key: TaskKey) -> Self {
        Self {
            key,
            resources: Arc::new(SpinLock::new(SignalResources {
                actions: ActionTable::default(),
                inbox: SignalInbox::new(key),
                thread_pending: Vec::new(),
                forced_segv: Vec::new(),
            })),
        }
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
                forced_segv,
                ..
            } = &mut *resources;
            for (record, pending) in thread_pending.iter_mut() {
                if signal != Signal::SEGV || !forced_segv.contains(record) {
                    pending.discard(selected);
                }
            }
            thread_pending.retain(|(_, pending)| !pending.is_empty());
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
        let mut resources = self.resources.lock();
        let signal = Signal::SEGV;
        if !resources.forced_segv.contains(&tid) {
            resources.forced_segv.push(tid);
        }
        if blocked.contains(signal)
            || resources.actions.action(signal).disposition == Disposition::Ignore
        {
            let _ = resources.actions.install(signal, Action::default());
        }
        if let Some((_, pending)) = resources
            .thread_pending
            .iter_mut()
            .find(|(id, _)| *id == tid)
        {
            pending.enqueue(signal, info);
        } else {
            let mut pending = PendingSignals::default();
            pending.enqueue(signal, info);
            resources.thread_pending.push((tid, pending));
        }
    }
    pub fn action(&self, signal: Signal) -> Action {
        self.resources.lock().actions.action(signal)
    }
    pub fn enqueue(
        &self,
        key: TaskKey,
        signal: Signal,
        info: Option<T>,
    ) -> Result<EnqueueOutcome, StaleTarget> {
        self.resources.lock().inbox.enqueue_for(key, signal, info)
    }
    pub fn enqueue_thread(
        &self,
        tid: carrick_sched_core::RecordRef,
        signal: Signal,
        info: Option<T>,
    ) -> EnqueueOutcome {
        let mut res = self.resources.lock();
        if let Some((_, p)) = res.thread_pending.iter_mut().find(|(t, _)| *t == tid) {
            p.enqueue(signal, info)
        } else {
            let mut p = PendingSignals::default();
            let outcome = p.enqueue(signal, info);
            res.thread_pending.push((tid, p));
            outcome
        }
    }
    pub fn pending_set(&self, tid: carrick_sched_core::RecordRef) -> SignalSet {
        let resources = self.resources.lock();
        let proc = resources.inbox.pending().present();
        let thread = resources
            .thread_pending
            .iter()
            .find(|(t, _)| *t == tid)
            .map_or(SignalSet::EMPTY, |(_, p)| p.present());
        proc.union(thread)
    }
    pub fn has_deliverable(
        &self,
        tid: carrick_sched_core::RecordRef,
        blocked: SigBlockMask,
    ) -> bool {
        let resources = self.resources.lock();
        let thread = resources
            .thread_pending
            .iter()
            .find(|(id, _)| *id == tid)
            .map_or(SignalSet::EMPTY, |(_, pending)| pending.present());
        let mut selected = blocked.select(resources.inbox.pending().present().union(thread));
        while let Some(number) = selected.lowest() {
            let Some(signal) = Signal::from_number(number) else {
                return false;
            };
            let action = resources.actions.action(signal);
            let ignored = action.disposition == Disposition::Ignore
                || (action.disposition == Disposition::Default
                    && carrick_signal_core::policy::default_delivery(signal)
                        == carrick_signal_core::policy::Delivery::Ignore);
            if !ignored {
                return true;
            }
            selected = selected.without(signal);
        }
        resources.forced_segv.contains(&tid)
    }
    pub fn take_deliverable(
        &self,
        tid: carrick_sched_core::RecordRef,
        blocked: SigBlockMask,
    ) -> Option<(Signal, Option<T>, Action)> {
        loop {
            let mut resources = self.resources.lock();
            let idx = resources.thread_pending.iter().position(|(t, _)| *t == tid);
            let mut thread_pending = idx
                .map(|i| resources.thread_pending.remove(i).1)
                .unwrap_or_default();
            let forced = resources.forced_segv.contains(&tid);
            let present = resources
                .inbox
                .pending()
                .present()
                .union(thread_pending.present());
            let mut unblocked = if present.contains(Signal::KILL) {
                SignalSet::EMPTY.with(Signal::KILL)
            } else if forced {
                SignalSet::EMPTY.with(Signal::SEGV)
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
                if resources.actions.action(signal).disposition == Disposition::Default
                    && carrick_signal_core::policy::default_delivery(signal)
                        == carrick_signal_core::policy::Delivery::Stop
                {
                    unblocked = unblocked.without(signal);
                }
                inspect = inspect.without(signal);
            }
            let delivery = carrick_personality_linux::signal::take_pending(
                &mut thread_pending,
                resources.inbox.pending_mut(),
                unblocked,
            );
            if !thread_pending.is_empty() {
                resources.thread_pending.push((tid, thread_pending));
            }
            let delivery = delivery?;
            let signal = delivery.entry.signal;
            if signal == Signal::SEGV {
                resources.forced_segv.retain(|id| *id != tid);
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
        let idx = resources.thread_pending.iter().position(|(t, _)| *t == tid);
        let mut thread_pending = idx
            .map(|i| resources.thread_pending.remove(i).1)
            .unwrap_or_default();
        let delivery = {
            let proc_pending = resources.inbox.pending_mut();
            carrick_personality_linux::signal::take_pending(&mut thread_pending, proc_pending, set)
        };
        if !thread_pending.is_empty() {
            resources.thread_pending.push((tid, thread_pending));
        }
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
    pub fn for_fork(&self, child: TaskKey) -> Option<Self> {
        let source = self.resources.lock();
        let ActionInheritance::Copied(actions) =
            source.actions.for_clone(self.key, SighandSharing::Copy)
        else {
            return None;
        };
        Some(Self {
            key: child,
            resources: Arc::new(SpinLock::new(SignalResources {
                actions,
                inbox: source.inbox.for_fork(child),
                thread_pending: Vec::new(),
                forced_segv: Vec::new(),
            })),
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
    pub fn exit_source<M: BlockedMaskSource>(&self, mask: M) -> NativeExitSignals<T, M> {
        NativeExitSignals {
            signals: self.clone(),
            mask,
        }
    }
}

/// Signal locks are sampled only when shared exit preparation requests them,
/// after the process graph guard and member cancellation have completed.
pub struct NativeExitSignals<T, M> {
    signals: NativeProcessSignals<T>,
    mask: M,
}
impl<T, M: BlockedMaskSource> ExitSignalSource for NativeExitSignals<T, M> {
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
        ExitSignalState {
            disposition,
            blocked: self.mask.blocked_mask().contains(signal),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use carrick_sched_core::process::{TaskId, TaskSerial};
    use carrick_signal_core::policy::{Disposition, HandlerAddress};
    fn key(raw: i32, serial: u64) -> TaskKey {
        TaskKey {
            id: TaskId::from_abi_positive(raw).unwrap(),
            serial: TaskSerial::from_raw_u64(serial).unwrap(),
        }
    }
    #[test]
    fn installing_ignore_discards_process_and_thread_pending() {
        let task = key(41, 11);
        let signals = NativeProcessSignals::<u32>::fresh_root(task);
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
        let signals = NativeProcessSignals::<u32>::fresh_root(key(41, 11));
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
        let signals = NativeProcessSignals::<()>::fresh_root(task);
        let record = carrick_sched_core::RecordRef {
            id: carrick_sched_core::RecordId::from_raw(1).unwrap(),
            incarnation: 1,
        };
        signals.enqueue(task, Signal::STOP, None).unwrap();
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
        let signals = NativeProcessSignals::<()>::fresh_root(task);
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
        let signals = NativeProcessSignals::<()>::fresh_root(task);
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
    fn retained_exit_handle_reads_later_action_and_actual_control_mask() {
        let key = key(41, 11);
        let signals = NativeProcessSignals::<()>::fresh_root(key);
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
                blocked: true
            }
        );
    }
    #[test]
    fn fork_copies_actions_without_pending_or_parent_mutation_aliases() {
        let parent_key = key(41, 11);
        let child_key = key(42, 12);
        let parent = NativeProcessSignals::<u32>::fresh_root(parent_key);
        let caught = Action {
            disposition: Disposition::Handler(HandlerAddress(0x400000)),
            ..Action::default()
        };
        parent
            .install_action(parent_key, Signal::CHLD, caught)
            .unwrap();
        parent.enqueue(parent_key, Signal::CHLD, Some(7)).unwrap();
        let child = parent.for_fork(child_key).unwrap();
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
        let signals = NativeProcessSignals::<()>::fresh_root(task);
        let control = Arc::new(carrick_el1_abi::ThreadControlSlot::new());
        let retained = signals.exit_source(control.clone());
        assert!(!signals.autoreaps_children());
        assert!(
            !retained
                .exit_signal_state(LinuxSignal::SIGCHLD)
                .needs_notification(LinuxSignal::SIGCHLD)
        );
        control.init_blocked(carrick_el1_abi::BlockedMask(Signal::CHLD.bit()));
        assert!(
            retained
                .exit_signal_state(LinuxSignal::SIGCHLD)
                .needs_notification(LinuxSignal::SIGCHLD)
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
                .needs_notification(LinuxSignal::SIGCHLD)
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
                .needs_notification(LinuxSignal::SIGCHLD)
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
