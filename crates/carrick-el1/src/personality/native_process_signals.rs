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
    Action, ActionError, ActionInheritance, ActionTable, ChildEvent, ChildInterest, Delivery,
    Disposition, SigBlockMask, SighandSharing, Signal, child_decision, default_delivery,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeSignalError {
    Stale,
    Unsupported,
}
fn native_delivery(action: Action, signal: Signal) -> Result<Delivery, NativeSignalError> {
    let delivery = match action.disposition {
        Disposition::Ignore => Delivery::Ignore,
        Disposition::Default => default_delivery(signal),
        Disposition::Handler(_) => return Err(NativeSignalError::Unsupported),
    };
    match delivery {
        Delivery::Stop | Delivery::Handler(_) => Err(NativeSignalError::Unsupported),
        supported => Ok(supported),
    }
}

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
struct SignalResources<T> {
    actions: ActionTable,
    inbox: SignalInbox<TaskKey, T>,
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
        if action.disposition == Disposition::Ignore
            || (action.disposition == Disposition::Default
                && default_delivery(signal) == Delivery::Ignore)
        {
            resources
                .inbox
                .pending_mut()
                .discard(SignalSet::EMPTY.with(signal));
        }
        Ok(old)
    }
    /// Admission and action inspection share the same lock as ignore discard.
    /// Linux queues blocked ignored signals too; a later ignore installation
    /// discards them. The caller's retained control owns the mask.
    pub fn queue_self(
        &self,
        key: TaskKey,
        signal: Signal,
        mask: SigBlockMask,
    ) -> Result<(), NativeSignalError> {
        if key != self.key {
            return Err(NativeSignalError::Stale);
        }
        let mut resources = self.resources.lock();
        let delivery = native_delivery(resources.actions.action(signal), signal);
        if !mask.contains(signal) {
            match delivery? {
                Delivery::Ignore | Delivery::Continue => return Ok(()),
                Delivery::Terminate { .. } => {}
                _ => return Err(NativeSignalError::Unsupported),
            }
        }
        resources
            .inbox
            .enqueue_for(key, signal, None)
            .map_err(|_| NativeSignalError::Stale)?;
        Ok(())
    }
    /// Select/dequeue by the existing Linux pending policy. Unsupported native
    /// handler/job-control delivery keeps the pending entry rather than losing it.
    pub fn take_self(
        &self,
        key: TaskKey,
        mask: SigBlockMask,
    ) -> Result<Option<(Signal, Delivery)>, NativeSignalError> {
        if key != self.key {
            return Err(NativeSignalError::Stale);
        }
        let mut resources = self.resources.lock();
        let selected = mask.select(resources.inbox.pending().present());
        let Some(signal) = selected.lowest().and_then(Signal::from_number) else {
            return Ok(None);
        };
        let delivery = native_delivery(resources.actions.action(signal), signal)?;
        if delivery == Delivery::Ignore {
            // Discard every instance of an ignored RT signal in one key visit.
            resources
                .inbox
                .pending_mut()
                .discard(SignalSet::EMPTY.with(signal));
            return Ok(Some((signal, delivery)));
        }
        let entry = resources
            .inbox
            .pending_mut()
            .take_in(selected)
            .ok_or(NativeSignalError::Stale)?;
        Ok(Some((entry.signal, delivery)))
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
fn invalid_signal() -> ! {
    #[cfg(target_os = "none")]
    {
        crate::substrate::sched::hw::fatal_entry_binding()
    }
    #[cfg(not(target_os = "none"))]
    carrick_fatal::carrick_fatal!(
        "el1::native_process_signals",
        "validated Linux signal crossed invalid numbering domain"
    )
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
            invalid_signal()
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
    fn ignore_installation_discards_pending_only_for_the_exact_owner() {
        let first = key(41, 11);
        let second = key(42, 12);
        let left = NativeProcessSignals::<()>::fresh_root(first);
        let right = NativeProcessSignals::<()>::fresh_root(second);
        let signal = Signal::from_number(13).unwrap();
        left.enqueue(first, signal, None).unwrap();
        right.enqueue(second, signal, None).unwrap();
        let ignored = Action {
            disposition: Disposition::Ignore,
            ..Action::default()
        };
        assert!(left.install_action(second, signal, ignored).is_err());
        assert_eq!(left.pending_count(), 1);
        left.install_action(first, signal, ignored).unwrap();
        assert_eq!(left.pending_count(), 0);
        assert_eq!(right.pending_count(), 1);
        assert_eq!(right.action(signal), Action::default());
    }

    #[test]
    fn blocked_self_signal_selection_and_coalescing_are_owner_local() {
        for scale in [1, 8, 32] {
            let first = key(41, 11);
            let second = key(42, 12);
            let left = NativeProcessSignals::<()>::fresh_root(first);
            let right = NativeProcessSignals::<()>::fresh_root(second);
            let signal = Signal::from_number(6).unwrap();
            let blocked = SigBlockMask::blocking_all_of(SignalSet::EMPTY.with(signal));
            for _ in 0..scale {
                left.queue_self(first, signal, blocked).unwrap();
                right.queue_self(second, signal, blocked).unwrap();
            }
            assert_eq!(left.pending_count(), 1);
            assert_eq!(right.pending_count(), 1);
            assert_eq!(left.take_self(first, blocked).unwrap(), None);
            assert_eq!(
                left.take_self(second, SigBlockMask::NONE),
                Err(NativeSignalError::Stale)
            );
            assert_eq!(left.pending_count(), 1);
            assert_eq!(
                left.take_self(first, SigBlockMask::NONE).unwrap(),
                Some((signal, Delivery::Terminate { core_dump: true }))
            );
            assert_eq!(left.pending_count(), 0);
            assert_eq!(right.pending_count(), 1);
        }
    }

    #[test]
    fn blocked_ignored_signals_queue_but_reinstallation_discards_them() {
        let owner = key(41, 11);
        let signals = NativeProcessSignals::<()>::fresh_root(owner);
        for (signal, action) in [
            (
                Signal::from_number(13).unwrap(),
                Action {
                    disposition: Disposition::Ignore,
                    ..Action::default()
                },
            ),
            (Signal::CHLD, Action::default()),
        ] {
            let blocked = SigBlockMask::blocking_all_of(SignalSet::EMPTY.with(signal));
            signals.install_action(owner, signal, action).unwrap();
            signals.queue_self(owner, signal, blocked).unwrap();
            assert_eq!(signals.pending_count(), 1);
            assert_eq!(signals.take_self(owner, blocked).unwrap(), None);
            signals.install_action(owner, signal, action).unwrap();
            assert_eq!(signals.pending_count(), 0);
            signals.queue_self(owner, signal, blocked).unwrap();
            assert_eq!(
                signals.take_self(owner, SigBlockMask::NONE).unwrap(),
                Some((signal, Delivery::Ignore))
            );
            assert_eq!(signals.pending_count(), 0);
        }
    }

    #[test]
    fn unblocking_ignored_realtime_population_discards_all_instances() {
        let owner = key(41, 11);
        let signal = Signal::from_number(40).unwrap();
        for scale in [1, 8, 32] {
            let signals = NativeProcessSignals::<()>::fresh_root(owner);
            signals
                .install_action(
                    owner,
                    signal,
                    Action {
                        disposition: Disposition::Ignore,
                        ..Action::default()
                    },
                )
                .unwrap();
            let blocked = SigBlockMask::blocking_all_of(SignalSet::EMPTY.with(signal));
            for _ in 0..scale {
                signals.queue_self(owner, signal, blocked).unwrap();
            }
            assert_eq!(signals.pending_count(), scale);
            assert_eq!(
                signals.take_self(owner, SigBlockMask::NONE).unwrap(),
                Some((signal, Delivery::Ignore))
            );
            assert_eq!(signals.pending_count(), 0);
        }
    }

    #[test]
    fn unsupported_native_handler_delivery_keeps_the_pending_entry() {
        let owner = key(41, 11);
        let signals = NativeProcessSignals::<()>::fresh_root(owner);
        let signal = Signal::from_number(13).unwrap();
        signals
            .install_action(
                owner,
                signal,
                Action {
                    disposition: Disposition::Handler(HandlerAddress(0x400100)),
                    ..Action::default()
                },
            )
            .unwrap();
        assert_eq!(
            signals.queue_self(owner, signal, SigBlockMask::NONE),
            Err(NativeSignalError::Unsupported)
        );
        assert_eq!(signals.pending_count(), 0);
        let blocked = SigBlockMask::blocking_all_of(SignalSet::EMPTY.with(signal));
        signals.queue_self(owner, signal, blocked).unwrap();
        assert_eq!(
            signals.take_self(owner, SigBlockMask::NONE),
            Err(NativeSignalError::Unsupported)
        );
        assert_eq!(signals.pending_count(), 1);
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
        assert_eq!(parent.pending_count(), 0);
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
