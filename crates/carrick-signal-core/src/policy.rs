//! Pure Linux signal policy extracted from kernel/objects/signal.rs.
//!
//! Semantic authority: https://man7.org/linux/man-pages/man7/signal.7.html,
//! sigaction(2), sigprocmask(2), sigsuspend(2), wait(2), clone(2), fork(2)
//! and execve(2). Numbering is Linux asm-generic, as used by AArch64.
//! `carrick-abi` is the repository's wire-ABI source of truth; its current std
//! dependency closure cannot enter this no_std core. These minimal domain
//! equivalents store no host types or ABI structs. The adapter translates the
//! named action flags and retains unsupported wire fields itself.
//!
//! The consuming EL1 owner serializes action lookup/reset, pending dequeue and
//! mask publication in one transaction. No graph, lock or scheduler is created
//! here. Exact-generation keys are the caller's existing task/thread keys.

use alloc::collections::{BTreeMap, VecDeque};

use crate::{SignalSet, StandardSignalSlot};

/// Validated Linux kernel signal (1..=64), not libc's adjusted SIGRTMIN.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Signal(u8);

impl Signal {
    pub const KILL: Self = Self(9);
    pub const ALRM: Self = Self(14);
    pub const CHLD: Self = Self(17);
    pub const CONT: Self = Self(18);
    pub const STOP: Self = Self(19);
    pub const RTMIN: Self = Self(32);

    pub const fn from_number(number: i32) -> Option<Self> {
        if number >= 1 && number <= 64 {
            Some(Self(number as u8))
        } else {
            None
        }
    }

    pub const fn number(self) -> i32 {
        self.0 as i32
    }

    pub const fn bit(self) -> u64 {
        1u64 << (self.0 - 1)
    }

    pub const fn is_realtime(self) -> bool {
        self.0 >= Self::RTMIN.0
    }

    pub const fn uncatchable(self) -> bool {
        self.0 == Self::KILL.0 || self.0 == Self::STOP.0
    }
}

/// Typed block polarity. SIGKILL/SIGSTOP are removed at every construction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SigBlockMask(SignalSet);

impl SigBlockMask {
    pub const NONE: Self = Self(SignalSet::EMPTY);

    pub const fn blocking_all_of(signals: SignalSet) -> Self {
        Self(signals.without(Signal::KILL).without(Signal::STOP))
    }

    pub const fn signals(self) -> SignalSet {
        self.0
    }

    pub const fn contains(self, signal: Signal) -> bool {
        self.0.contains(signal)
    }

    pub const fn select(self, pending: SignalSet) -> SignalSet {
        pending.difference(self.0)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Disposition {
    #[default]
    Default,
    Ignore,
    Handler(HandlerAddress),
}

/// Guest handler address; never a host function pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandlerAddress(pub u64);

/// Guest rt_sigreturn trampoline address, never a host code pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestorerAddress(pub u64);

/// Architecture affects the return trampoline, not Linux signal numbering.
/// Frame layout and executable-address validation remain the HAL/owner's work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandlerReturnPolicy {
    Aarch64 { trampoline: RestorerAddress },
    X86_64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandlerReturnError {
    MissingRestorer,
}

/// Preflight a caught handler before committing entry. sigaction(2)'s
/// SA_RESTORER marks a libc-provided trampoline; x86_64 requires it, while
/// AArch64 has a kernel/vDSO fallback. An absent required trampoline is a
/// delivery fault for the consuming owner, not a sigaction-install errno.
pub fn handler_return(
    action: Action,
    architecture: HandlerReturnPolicy,
) -> Result<RestorerAddress, HandlerReturnError> {
    if let Some(restorer) = action.restorer {
        return Ok(restorer);
    }
    match architecture {
        HandlerReturnPolicy::Aarch64 { trampoline } => Ok(trampoline),
        HandlerReturnPolicy::X86_64 => Err(HandlerReturnError::MissingRestorer),
    }
}

/// Named policy flags, translated from SA_* by the ABI adapter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ActionFlags {
    pub reset_hand: bool,
    pub nodefer: bool,
    pub restart: bool,
    pub siginfo: bool,
    pub no_child_wait: bool,
    pub no_child_stop: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Action {
    pub disposition: Disposition,
    pub flags: ActionFlags,
    pub mask: SignalSet,
    /// Some iff SA_RESTORER is set, even if its supplied address is zero.
    pub restorer: Option<RestorerAddress>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionError {
    Uncatchable,
}

/// One sighand's actions. Missing entries are SIG_DFL. BTreeMap keys have a
/// fixed maximum population of 62; operation cost does not grow with tasks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActionTable {
    actions: BTreeMap<Signal, Action>,
}

impl ActionTable {
    pub fn action(&self, signal: Signal) -> Action {
        self.actions.get(&signal).copied().unwrap_or_default()
    }

    /// Return the old action, or reject any installation on SIGKILL/SIGSTOP.
    pub fn install(&mut self, signal: Signal, action: Action) -> Result<Action, ActionError> {
        if signal.uncatchable() {
            return Err(ActionError::Uncatchable);
        }
        Ok(self.actions.insert(signal, action).unwrap_or_default())
    }

    /// Exec makes a private table: caught handlers reset and ignored actions
    /// stay ignored. Reset default metadata as the existing kernel Sighand does.
    pub fn for_exec(&self) -> Self {
        Self {
            actions: self
                .actions
                .iter()
                .filter(|(_, action)| action.disposition == Disposition::Ignore)
                .map(|(&signal, &action)| (signal, action))
                .collect(),
        }
    }

    /// CLONE_SIGHAND selects the exact existing authority; it does not copy
    /// or reference-count a second table. The caller publishes this edge in
    /// its graph. Clone flag validity (e.g. CLONE_VM) is admission policy.
    pub fn for_clone<K>(&self, existing_key: K, sharing: SighandSharing) -> ActionInheritance<K> {
        match sharing {
            SighandSharing::Share => ActionInheritance::Shared(existing_key),
            SighandSharing::Copy => ActionInheritance::Copied(self.clone()),
        }
    }

    /// Called after a signal has been selected and removed from pending state.
    /// SA_RESETHAND resets on entry, while the returned delivery keeps the
    /// original flags for this handler and interrupted wait.
    pub fn prepare_delivery(&mut self, signal: Signal, masks: &mut MaskState) -> Delivery {
        let action = self.action(signal);
        match action.disposition {
            Disposition::Ignore => Delivery::Ignore,
            Disposition::Default => default_delivery(signal),
            Disposition::Handler(address) => {
                if action.flags.reset_hand {
                    self.actions.insert(
                        signal,
                        Action {
                            disposition: Disposition::Default,
                            ..action
                        },
                    );
                }
                let effective = masks.effective();
                let restore_mask = masks.blocked;
                let mut handler_mask = effective.signals().union(action.mask);
                if !action.flags.nodefer {
                    handler_mask = handler_mask.with(signal);
                }
                masks.temporary = None;
                masks.blocked = SigBlockMask::blocking_all_of(handler_mask);
                Delivery::Handler(HandlerDelivery {
                    address,
                    siginfo: action.flags.siginfo,
                    restart: action.flags.restart,
                    restore_mask,
                })
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SighandSharing {
    Share,
    Copy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionInheritance<K> {
    Shared(K),
    Copied(ActionTable),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandlerDelivery {
    pub address: HandlerAddress,
    pub siginfo: bool,
    pub restart: bool,
    /// Persistent pre-wait mask for temporary-mask waits, otherwise the
    /// interrupted thread mask. The owner saves this in the signal frame.
    pub restore_mask: SigBlockMask,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    Ignore,
    Continue,
    Stop,
    Terminate { core_dump: bool },
    Handler(HandlerDelivery),
}

pub const fn default_delivery(signal: Signal) -> Delivery {
    match signal.number() {
        17 | 23 | 28 => Delivery::Ignore,
        18 => Delivery::Continue,
        19..=22 => Delivery::Stop,
        3..=8 | 11 | 24 | 25 | 31 => Delivery::Terminate { core_dump: true },
        _ => Delivery::Terminate { core_dump: false },
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaskChange {
    Block(SignalSet),
    Unblock(SignalSet),
    Set(SignalSet),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaskError {
    TemporaryActive,
}

/// A thread's persistent mask and its atomic temporary-mask wait selection.
/// The owner enrolls the wait and publishes this transition atomically with
/// respect to signal generation, avoiding the unblock-then-sleep lost wake.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MaskState {
    blocked: SigBlockMask,
    temporary: Option<SigBlockMask>,
}

impl MaskState {
    pub const fn new(blocked: SigBlockMask) -> Self {
        Self {
            blocked,
            temporary: None,
        }
    }

    pub fn effective(self) -> SigBlockMask {
        self.temporary.unwrap_or(self.blocked)
    }

    pub fn select(self, pending: SignalSet) -> SignalSet {
        self.effective().select(pending)
    }

    pub fn change(&mut self, change: MaskChange) -> Result<SigBlockMask, MaskError> {
        if self.temporary.is_some() {
            return Err(MaskError::TemporaryActive);
        }
        let old = self.blocked;
        let signals = match change {
            MaskChange::Block(signals) => old.signals().union(signals),
            MaskChange::Unblock(signals) => old.signals().difference(signals),
            MaskChange::Set(signals) => signals,
        };
        self.blocked = SigBlockMask::blocking_all_of(signals);
        Ok(old)
    }

    /// ppoll/pselect/sigsuspend: replacement, never additive masking.
    pub fn begin_temporary(&mut self, mask: SigBlockMask) -> Result<(), MaskError> {
        if self.temporary.is_some() {
            return Err(MaskError::TemporaryActive);
        }
        self.temporary = Some(mask);
        Ok(())
    }

    /// Normal wait completion/cancel restores the persistent mask. Handler
    /// entry instead consumes the temporary mask and saves restoration data.
    pub fn end_temporary(&mut self) -> bool {
        self.temporary.take().is_some()
    }

    /// Called only after the consuming owner validates the guest sigreturn
    /// frame. User edits to that frame's mask are accepted by that owner.
    pub fn restore_after_handler(&mut self, mask: SigBlockMask) {
        self.blocked = mask;
        self.temporary = None;
    }

    pub fn for_fork(self) -> Self {
        Self::new(self.effective())
    }

    pub fn reset_for_exec(&mut self) {
        self.blocked = self.effective();
        self.temporary = None;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnqueueOutcome {
    Queued,
    Coalesced,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingEntry<T> {
    pub signal: Signal,
    pub info: Option<T>,
}

/// One process- or thread-owned pending set. Extracts the kernel queue's
/// first-standard/FIFO-real-time algorithm. StandardSignalSlot explicitly
/// retains the first instance; real-time instances use a FIFO VecDeque. The
/// production PendingQueue's replacement flag is not used by this policy.
/// Presence selection and count are O(1), enqueue/dequeue O(log 64), never a
/// traversal of payloads or other owners. Allocation/RLIMIT admission is the
/// consuming owner's responsibility before enqueue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingSignals<T> {
    present: SignalSet,
    standard: BTreeMap<Signal, StandardSignalSlot<Option<T>>>,
    realtime: BTreeMap<Signal, VecDeque<Option<T>>>,
    count: usize,
}

impl<T> Default for PendingSignals<T> {
    fn default() -> Self {
        Self {
            present: SignalSet::EMPTY,
            standard: BTreeMap::new(),
            realtime: BTreeMap::new(),
            count: 0,
        }
    }
}

impl<T> PendingSignals<T> {
    pub const fn present(&self) -> SignalSet {
        self.present
    }
    pub const fn len(&self) -> usize {
        self.count
    }
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn enqueue(&mut self, signal: Signal, info: Option<T>) -> EnqueueOutcome {
        if signal.is_realtime() {
            self.realtime.entry(signal).or_default().push_back(info);
        } else if !self.standard.entry(signal).or_default().publish_first(info) {
            return EnqueueOutcome::Coalesced;
        }
        self.present = self.present.with(signal);
        self.count += 1;
        EnqueueOutcome::Queued
    }

    pub fn take_in(&mut self, selected: SignalSet) -> Option<PendingEntry<T>> {
        let signal = Signal::from_number(self.present.intersect(selected).lowest()?)?;
        let info = if signal.is_realtime() {
            let queue = self.realtime.get_mut(&signal)?;
            let info = queue.pop_front()?;
            if queue.is_empty() {
                self.realtime.remove(&signal);
                self.present = self.present.without(signal);
            }
            info
        } else {
            let info = self.standard.remove(&signal)?.take()?;
            self.present = self.present.without(signal);
            info
        };
        self.count -= 1;
        Some(PendingEntry { signal, info })
    }

    /// Discard all selected instances (ignore installation/job control).
    /// Work depends on at most 64 signal keys, never queued payload population
    /// except destruction of the discarded payloads themselves.
    pub fn discard(&mut self, selected: SignalSet) {
        self.standard.retain(|signal, _| {
            if selected.contains(*signal) {
                self.count -= 1;
                false
            } else {
                true
            }
        });
        self.realtime.retain(|signal, queue| {
            if selected.contains(*signal) {
                self.count -= queue.len();
                false
            } else {
                true
            }
        });
        self.present = self.present.difference(selected);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingOwner {
    Thread,
    Process,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingDelivery<T> {
    pub owner: PendingOwner,
    pub entry: PendingEntry<T>,
}

/// Preserve the kernel's lowest-number selection and thread-first same-number
/// tie. signal(7) specifies RT number/FIFO ordering, not cross-owner ties.
pub fn take_pending<T>(
    thread: &mut PendingSignals<T>,
    process: &mut PendingSignals<T>,
    selected: SignalSet,
) -> Option<PendingDelivery<T>> {
    let thread_signal = thread.present.intersect(selected).lowest();
    let process_signal = process.present.intersect(selected).lowest();
    let owner = match (thread_signal, process_signal) {
        (None, None) => return None,
        (Some(_), None) => PendingOwner::Thread,
        (None, Some(_)) => PendingOwner::Process,
        (Some(t), Some(p)) if t <= p => PendingOwner::Thread,
        (Some(_), Some(_)) => PendingOwner::Process,
    };
    let entry = match owner {
        PendingOwner::Thread => thread.take_in(selected)?,
        PendingOwner::Process => process.take_in(selected)?,
    };
    Some(PendingDelivery { owner, entry })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaleTarget;

/// The owner key must carry its existing graph incarnation/generation. This
/// consumes an exact task key for a process queue, or exact thread key for a
/// thread queue, rather than inventing IDs or looking up a reusable raw PID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignalInbox<K, T> {
    key: K,
    pending: PendingSignals<T>,
}

impl<K: Eq, T> SignalInbox<K, T> {
    pub fn new(key: K) -> Self {
        Self {
            key,
            pending: PendingSignals::default(),
        }
    }
    pub fn pending(&self) -> &PendingSignals<T> {
        &self.pending
    }
    pub fn pending_mut(&mut self) -> &mut PendingSignals<T> {
        &mut self.pending
    }

    pub fn enqueue_for(
        &mut self,
        target: K,
        signal: Signal,
        info: Option<T>,
    ) -> Result<EnqueueOutcome, StaleTarget> {
        if target != self.key {
            return Err(StaleTarget);
        }
        Ok(self.pending.enqueue(signal, info))
    }

    pub fn for_fork(&self, child: K) -> Self {
        Self::new(child)
    }
    // Exec keeps this owner and its pending queue unchanged.
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryTarget<P, T> {
    pub process: P,
    pub thread: T,
    pub blocked: SigBlockMask,
    pub live: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetChoice<T> {
    pub target: Option<T>,
    /// Stable work unit: candidate thread rows inspected, at most N.
    pub examined: usize,
}

/// Linux permits any live unblocked thread; select the first eligible row in
/// the caller's stable order. The caller supplies this process's thread census,
/// revalidates the exact key and publishes the wake before releasing admission.
/// If all threads block it, retain the process pending signal and do not wake
/// an ineligible leader. Masks/exits require a new selection, not a cached TID.
pub fn choose_process_target<P: Eq, T>(
    process: P,
    signal: Signal,
    targets: impl IntoIterator<Item = DeliveryTarget<P, T>>,
) -> TargetChoice<T> {
    let mut examined = 0;
    for target in targets {
        examined += 1;
        if target.process == process && target.live && !target.blocked.contains(signal) {
            return TargetChoice {
                target: Some(target.thread),
                examined,
            };
        }
    }
    TargetChoice {
        target: None,
        examined,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildEvent {
    Exited,
    Stopped,
    Continued,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ChildInterest {
    pub blocked: bool,
    pub synchronous_wait: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChildDecision {
    pub auto_reap: bool,
    pub notify: bool,
}

/// SIGCHLD only. wait(2) distinguishes default-ignore from explicit SIG_IGN.
/// Linux still generates caught SIGCHLD under SA_NOCLDWAIT; SA_NOCLDSTOP
/// suppresses stop/continue notification without erasing child wait events.
/// The owner computes `blocked`/synchronous interest across eligible threads;
/// a saved temporary-mask restore value is not synchronous signal interest.
pub fn child_decision(action: Action, event: ChildEvent, interest: ChildInterest) -> ChildDecision {
    let exited = event == ChildEvent::Exited;
    let ignored = action.disposition == Disposition::Ignore;
    let caught = matches!(action.disposition, Disposition::Handler(_));
    let auto_reap = exited && (ignored || action.flags.no_child_wait);
    let notify = !ignored
        && (exited || !action.flags.no_child_stop)
        && (caught || interest.blocked || interest.synchronous_wait);
    ChildDecision { auto_reap, notify }
}
