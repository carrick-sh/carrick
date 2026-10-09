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
    thread_pending: Vec<(u32, PendingSignals<T>)>,
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
        self.resources
            .lock()
            .actions
            .install(signal, action)
            .map_err(SignalActionError::Action)
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
    pub fn enqueue_thread(&self, tid: u32, signal: Signal, info: Option<T>) -> EnqueueOutcome {
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
    pub fn pending_set(&self, tid: u32) -> SignalSet {
        let resources = self.resources.lock();
        let proc = resources.inbox.pending().present();
        let thread = resources
            .thread_pending
            .iter()
            .find(|(t, _)| *t == tid)
            .map_or(SignalSet::EMPTY, |(_, p)| p.present());
        proc.union(thread)
    }
    pub fn take_deliverable(
        &self,
        tid: u32,
        blocked: SigBlockMask,
    ) -> Option<(Signal, Option<T>, Action)> {
        let mut resources = self.resources.lock();
        let actions = resources.actions.clone();
        let idx = resources.thread_pending.iter().position(|(t, _)| *t == tid);
        let mut thread_pending = idx
            .map(|i| resources.thread_pending.remove(i).1)
            .unwrap_or_default();
        let delivery = {
            let proc_pending = resources.inbox.pending_mut();
            let unblocked = blocked.select(proc_pending.present().union(thread_pending.present()));
            carrick_personality_linux::signal::take_pending(
                &mut thread_pending,
                proc_pending,
                unblocked,
            )
        };
        if !thread_pending.is_empty() {
            resources.thread_pending.push((tid, thread_pending));
        }
        let delivery = delivery?;
        let signal = delivery.entry.signal;
        let action = actions.action(signal);
        Some((signal, delivery.entry.info, action))
    }
    pub fn take_timedwait(&self, tid: u32, set: SignalSet) -> Option<(Signal, Option<T>)> {
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
        assert_eq!(parent.pending_count(), 1);
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
