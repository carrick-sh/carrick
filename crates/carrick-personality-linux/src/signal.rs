//! Linux pending-signal ownership, coalescing and delivery selection.
//!
//! Authority: signal(7), fork(2), execve(2). The owner serializes dequeue
//! and mask publication; signal-core supplies storage, not queue policy.

use alloc::collections::{BTreeMap, VecDeque};

use carrick_signal_core::StandardSignalSlot;
use carrick_signal_core::policy::Signal;
pub use carrick_signal_core::{SignalSet, policy};

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

pub const RT_SIGSET_SIZE: u64 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalCall {
    Kill,
    Tkill,
    Tgkill,
    RtSigsuspend,
    RtSigaction,
    RtSigpending,
    RtSigtimedwait,
    RtSigqueueinfo,
    RtSigreturn,
    RtTgsigqueueinfo,
    PidfdSendSignal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalOutcome {
    /// The same task resumes a restored context without a result word.
    Restored,
    Returned {
        result: crate::abi::entry::SyscallResult,
        work: bool,
    },
    Transferred {
        progress: carrick_core_abi::Served,
        result: crate::abi::entry::SyscallResult,
    },
}

pub fn signal_effect(outcome: &SignalOutcome) -> crate::dispatch::FamilyCompletion {
    use crate::dispatch::FamilyCompletion;
    match *outcome {
        SignalOutcome::Restored => FamilyCompletion::FrameRestored,
        SignalOutcome::Returned { result, work: true } => {
            FamilyCompletion::CompleteWithWork(result.raw())
        }
        SignalOutcome::Returned {
            result,
            work: false,
        } => FamilyCompletion::Complete(result.raw()),
        SignalOutcome::Transferred {
            progress: carrick_core_abi::Served::Returned { .. },
            result,
        } => FamilyCompletion::Switched(result.raw()),
        SignalOutcome::Transferred {
            progress: carrick_core_abi::Served::Idle,
            ..
        } => FamilyCompletion::Suspended,
    }
}

pub trait ProcessSignals {
    fn rt_sigaction(
        &mut self,
        signum: i32,
        act: Option<carrick_signal_core::policy::Action>,
    ) -> Result<carrick_signal_core::policy::Action, i32>;

    fn rt_sigpending(&self, blocked: carrick_signal_core::policy::SigBlockMask) -> u64;

    fn kill(
        &mut self,
        pid: i32,
        sig: i32,
        info: Option<crate::abi::signal::LinuxSiginfo>,
    ) -> Result<(), i32>;

    fn tkill(
        &mut self,
        tid: u32,
        sig: i32,
        info: Option<crate::abi::signal::LinuxSiginfo>,
    ) -> Result<(), i32>;

    fn tgkill(
        &mut self,
        tgid: u32,
        tid: u32,
        sig: i32,
        info: Option<crate::abi::signal::LinuxSiginfo>,
    ) -> Result<(), i32>;

    fn rt_sigtimedwait(
        &mut self,
        set: carrick_signal_core::SignalSet,
        timeout_ns: Option<u64>,
    ) -> Result<
        (
            carrick_signal_core::policy::Signal,
            Option<crate::abi::signal::LinuxSiginfo>,
        ),
        i32,
    >;

    fn rt_sigsuspend(&mut self, mask: carrick_signal_core::policy::SigBlockMask)
    -> Result<(), i32>;

    fn take_deliverable(
        &mut self,
        tid: u32,
        blocked: carrick_signal_core::policy::SigBlockMask,
    ) -> Option<(
        carrick_signal_core::policy::Signal,
        Option<crate::abi::signal::LinuxSiginfo>,
        carrick_signal_core::policy::Action,
    )> {
        let _ = (tid, blocked);
        None
    }
}

pub trait SignalNative<'a>: crate::lifecycle::UserCopy {
    fn arguments(&self) -> [u64; 6];
    fn process_signals(&mut self) -> Option<&mut dyn ProcessSignals>;
    fn current_blocked(&self) -> carrick_signal_core::policy::SigBlockMask;
    fn set_current_blocked(&mut self, mask: carrick_signal_core::policy::SigBlockMask);
    fn current_pid(&self) -> u32;
    fn current_tid(&self) -> u32;
    fn current_uid(&self) -> u32 {
        0
    }
    fn restore_signal_frame(&mut self) -> Result<u64, i32>;
}

pub fn invoke(call: SignalCall, native: &mut dyn SignalNative<'_>) -> Option<SignalOutcome> {
    use crate::abi::signal::{
        LINUX_EBADF, LINUX_EFAULT, LINUX_EINTR, LINUX_EINVAL, LINUX_SI_TKILL, LINUX_SI_USER,
        LinuxSigaction, LinuxSiginfo, RT_SIGSET_SIZE,
    };
    use zerocopy::{FromBytes, IntoBytes};
    let args = native.arguments();
    let returned = |val: i64, work: bool| {
        Some(SignalOutcome::Returned {
            result: crate::abi::entry::SyscallResult::new(val),
            work,
        })
    };
    match call {
        SignalCall::RtSigaction => {
            let [signum, act_ptr, oldact_ptr, size, _, _] = args;
            let signum = signum as i32;
            if size != RT_SIGSET_SIZE {
                return returned(LINUX_EINVAL.guest_retval(), false);
            }
            if signum <= 0 || signum > 64 || signum == 9 || signum == 19 {
                return returned(LINUX_EINVAL.guest_retval(), false);
            }
            let new_action = if act_ptr != 0 {
                let mut bytes = [0u8; core::mem::size_of::<LinuxSigaction>()];
                if !native.copy_in(&mut bytes, carrick_guest_arch::UserVa::new(act_ptr)) {
                    return returned(LINUX_EFAULT.guest_retval(), false);
                }
                let Ok(newact) = LinuxSigaction::ref_from_bytes(&bytes) else {
                    return returned(LINUX_EFAULT.guest_retval(), false);
                };
                let disposition = match newact.sa_handler {
                    0 => carrick_signal_core::policy::Disposition::Default,
                    1 => carrick_signal_core::policy::Disposition::Ignore,
                    addr => carrick_signal_core::policy::Disposition::Handler(
                        carrick_signal_core::policy::HandlerAddress(addr),
                    ),
                };
                let flags = carrick_signal_core::policy::ActionFlags {
                    reset_hand: newact.sa_flags & 0x80000000 != 0,
                    nodefer: newact.sa_flags & 0x40000000 != 0,
                    restart: newact.sa_flags & 0x10000000 != 0,
                    siginfo: newact.sa_flags & 0x00000004 != 0,
                    no_child_wait: newact.sa_flags & 0x00000002 != 0,
                    no_child_stop: newact.sa_flags & 0x00000001 != 0,
                };
                let restorer = if newact.sa_flags & 0x04000000 != 0 {
                    Some(carrick_signal_core::policy::RestorerAddress(
                        newact.sa_restorer,
                    ))
                } else {
                    None
                };
                let mask = carrick_signal_core::SignalSet::from_bits(newact.sa_mask[0])
                    .without(carrick_signal_core::policy::Signal::KILL)
                    .without(carrick_signal_core::policy::Signal::STOP);
                Some(carrick_signal_core::policy::Action {
                    disposition,
                    flags,
                    mask,
                    restorer,
                })
            } else {
                None
            };
            let old_action = if oldact_ptr != 0 {
                let signals = native.process_signals()?;
                match signals.rt_sigaction(signum, None) {
                    Ok(action) => Some(action),
                    Err(e) => return returned(e as i64, false),
                }
            } else {
                None
            };
            if let Some(action) = new_action {
                let signals = native.process_signals()?;
                if let Err(e) = signals.rt_sigaction(signum, Some(action)) {
                    return returned(e as i64, false);
                }
            }
            if let Some(current) = old_action {
                let mut oldact = LinuxSigaction::empty();
                oldact.sa_handler = match current.disposition {
                    carrick_signal_core::policy::Disposition::Default => 0,
                    carrick_signal_core::policy::Disposition::Ignore => 1,
                    carrick_signal_core::policy::Disposition::Handler(addr) => addr.0,
                };
                let mut flags = 0u64;
                if current.flags.siginfo {
                    flags |= 0x00000004; // SA_SIGINFO
                }
                if current.flags.nodefer {
                    flags |= 0x40000000; // SA_NODEFER
                }
                if current.flags.reset_hand {
                    flags |= 0x80000000; // SA_RESETHAND
                }
                if current.flags.restart {
                    flags |= 0x10000000; // SA_RESTART
                }
                if current.flags.no_child_stop {
                    flags |= 0x00000001; // SA_NOCLDSTOP
                }
                if current.flags.no_child_wait {
                    flags |= 0x00000002; // SA_NOCLDWAIT
                }
                if let Some(restorer) = current.restorer {
                    flags |= 0x04000000; // SA_RESTORER
                    oldact.sa_restorer = restorer.0;
                }
                oldact.sa_flags = flags;
                oldact.sa_mask = [current.mask.bits()];
                let bytes = IntoBytes::as_bytes(&oldact);
                if !native.copy_out(carrick_guest_arch::UserVa::new(oldact_ptr), bytes) {
                    return returned(LINUX_EFAULT.guest_retval(), false);
                }
            }
            returned(0, false)
        }
        SignalCall::RtSigpending => {
            let [set_ptr, size, _, _, _, _] = args;
            if size != RT_SIGSET_SIZE {
                return returned(LINUX_EINVAL.guest_retval(), false);
            }
            if set_ptr == 0 {
                return returned(LINUX_EFAULT.guest_retval(), false);
            }
            let blocked = native.current_blocked();
            let pending = {
                let signals = native.process_signals()?;
                signals.rt_sigpending(blocked)
            };
            if !native.copy_out(
                carrick_guest_arch::UserVa::new(set_ptr),
                &pending.to_le_bytes(),
            ) {
                return returned(LINUX_EFAULT.guest_retval(), false);
            }
            returned(0, false)
        }
        SignalCall::RtSigreturn => {
            let res = native.restore_signal_frame();
            match res {
                Ok(new_mask) => {
                    native.set_current_blocked(
                        carrick_signal_core::policy::SigBlockMask::blocking_all_of(
                            carrick_signal_core::SignalSet::from_bits(new_mask),
                        ),
                    );
                    Some(SignalOutcome::Restored)
                }
                Err(err) => returned(
                    carrick_syscall_abi::LinuxErrno::new(err).guest_retval(),
                    false,
                ),
            }
        }
        SignalCall::Kill => {
            let [pid, sig, _, _, _, _] = args;
            let pid = pid as i32;
            let sig = sig as i32;
            let sender_pid = native.current_pid() as i32;
            let sender_uid = native.current_uid();
            let info = if sig != 0 {
                Some(LinuxSiginfo::kill(
                    sig,
                    LINUX_SI_USER,
                    sender_pid,
                    sender_uid,
                ))
            } else {
                None
            };
            let signals = native.process_signals()?;
            match signals.kill(pid, sig, info) {
                Ok(()) => returned(0, false),
                Err(e) => returned(
                    carrick_syscall_abi::LinuxErrno::new(e).guest_retval(),
                    false,
                ),
            }
        }
        SignalCall::Tkill => {
            let [tid, sig, _, _, _, _] = args;
            let tid = tid as u32;
            let sig = sig as i32;
            let sender_pid = native.current_pid() as i32;
            let sender_uid = native.current_uid();
            let info = if sig != 0 {
                Some(LinuxSiginfo::kill(
                    sig,
                    LINUX_SI_TKILL,
                    sender_pid,
                    sender_uid,
                ))
            } else {
                None
            };
            let signals = native.process_signals()?;
            match signals.tkill(tid, sig, info) {
                Ok(()) => returned(0, false),
                Err(e) => returned(
                    carrick_syscall_abi::LinuxErrno::new(e).guest_retval(),
                    false,
                ),
            }
        }
        SignalCall::Tgkill => {
            let [tgid, tid, sig, _, _, _] = args;
            let tgid = tgid as u32;
            let tid = tid as u32;
            let sig = sig as i32;
            let sender_pid = native.current_pid() as i32;
            let sender_uid = native.current_uid();
            let info = if sig != 0 {
                Some(LinuxSiginfo::kill(
                    sig,
                    LINUX_SI_TKILL,
                    sender_pid,
                    sender_uid,
                ))
            } else {
                None
            };
            let signals = native.process_signals()?;
            match signals.tgkill(tgid, tid, sig, info) {
                Ok(()) => returned(0, false),
                Err(e) => returned(
                    carrick_syscall_abi::LinuxErrno::new(e).guest_retval(),
                    false,
                ),
            }
        }
        SignalCall::RtSigqueueinfo => {
            let [tgid, sig, uinfo_ptr, _, _, _] = args;
            let tgid = tgid as i32;
            let sig = sig as i32;
            if tgid <= 0 {
                return returned(LINUX_EINVAL.guest_retval(), false);
            }
            let mut bytes = [0u8; core::mem::size_of::<LinuxSiginfo>()];
            if !native.copy_in(&mut bytes, carrick_guest_arch::UserVa::new(uinfo_ptr)) {
                return returned(LINUX_EFAULT.guest_retval(), false);
            }
            let Ok(info) = LinuxSiginfo::ref_from_bytes(&bytes) else {
                return returned(LINUX_EFAULT.guest_retval(), false);
            };
            let signals = native.process_signals()?;
            match signals.kill(tgid, sig, Some(*info)) {
                Ok(()) => returned(0, false),
                Err(e) => returned(
                    carrick_syscall_abi::LinuxErrno::new(e).guest_retval(),
                    false,
                ),
            }
        }
        SignalCall::RtTgsigqueueinfo => {
            let [tgid, tid, sig, uinfo_ptr, _, _] = args;
            let tgid = tgid as u32;
            let tid = tid as u32;
            let sig = sig as i32;
            let mut bytes = [0u8; core::mem::size_of::<LinuxSiginfo>()];
            if !native.copy_in(&mut bytes, carrick_guest_arch::UserVa::new(uinfo_ptr)) {
                return returned(LINUX_EFAULT.guest_retval(), false);
            }
            let Ok(info) = LinuxSiginfo::ref_from_bytes(&bytes) else {
                return returned(LINUX_EFAULT.guest_retval(), false);
            };
            let signals = native.process_signals()?;
            match signals.tgkill(tgid, tid, sig, Some(*info)) {
                Ok(()) => returned(0, false),
                Err(e) => returned(
                    carrick_syscall_abi::LinuxErrno::new(e).guest_retval(),
                    false,
                ),
            }
        }
        SignalCall::PidfdSendSignal => {
            let [_pidfd, _sig, _uinfo, flags, _, _] = args;
            if flags != 0 {
                return returned(LINUX_EINVAL.guest_retval(), false);
            }
            returned(LINUX_EBADF.guest_retval(), false)
        }
        SignalCall::RtSigsuspend => {
            let [mask_ptr, size, _, _, _, _] = args;
            if size != RT_SIGSET_SIZE {
                return returned(LINUX_EINVAL.guest_retval(), false);
            }
            let mut bytes = [0u8; 8];
            if !native.copy_in(&mut bytes, carrick_guest_arch::UserVa::new(mask_ptr)) {
                return returned(LINUX_EFAULT.guest_retval(), false);
            }
            let mask_bits = u64::from_le_bytes(bytes);
            let mask = carrick_signal_core::policy::SigBlockMask::blocking_all_of(
                carrick_signal_core::SignalSet::from_bits(mask_bits),
            );
            let signals = native.process_signals()?;
            match signals.rt_sigsuspend(mask) {
                Ok(()) => Some(SignalOutcome::Transferred {
                    progress: carrick_core_abi::Served::Idle,
                    result: crate::abi::entry::SyscallResult::new(LINUX_EINTR.guest_retval()),
                }),
                Err(e) => returned(
                    carrick_syscall_abi::LinuxErrno::new(e).guest_retval(),
                    false,
                ),
            }
        }
        SignalCall::RtSigtimedwait => {
            let [uthese_ptr, uinfo_ptr, uts_ptr, size, _, _] = args;
            if size != RT_SIGSET_SIZE {
                return returned(LINUX_EINVAL.guest_retval(), false);
            }
            let mut bytes = [0u8; 8];
            if !native.copy_in(&mut bytes, carrick_guest_arch::UserVa::new(uthese_ptr)) {
                return returned(LINUX_EFAULT.guest_retval(), false);
            }
            let set = carrick_signal_core::SignalSet::from_bits(u64::from_le_bytes(bytes));
            let timeout_ns = if uts_ptr != 0 {
                let mut ts_bytes = [0u8; 16];
                if !native.copy_in(&mut ts_bytes, carrick_guest_arch::UserVa::new(uts_ptr)) {
                    return returned(LINUX_EFAULT.guest_retval(), false);
                }
                let mut sec_bytes = [0u8; 8];
                sec_bytes.copy_from_slice(&ts_bytes[0..8]);
                let sec = i64::from_le_bytes(sec_bytes);
                let mut nsec_bytes = [0u8; 8];
                nsec_bytes.copy_from_slice(&ts_bytes[8..16]);
                let nsec = i64::from_le_bytes(nsec_bytes);
                if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
                    return returned(LINUX_EINVAL.guest_retval(), false);
                }
                Some(
                    (sec as u64)
                        .saturating_mul(1_000_000_000)
                        .saturating_add(nsec as u64),
                )
            } else {
                None
            };
            let timedwait_res = {
                let signals = native.process_signals()?;
                signals.rt_sigtimedwait(set, timeout_ns)
            };
            match timedwait_res {
                Ok((sig, info)) => {
                    if uinfo_ptr != 0 {
                        let info = info.unwrap_or_else(|| {
                            LinuxSiginfo::kill(sig.number(), LINUX_SI_USER, 0, 0)
                        });
                        let bytes = IntoBytes::as_bytes(&info);
                        let _ = native.copy_out(carrick_guest_arch::UserVa::new(uinfo_ptr), bytes);
                    }
                    returned(sig.number() as i64, false)
                }
                Err(e) => returned(
                    carrick_syscall_abi::LinuxErrno::new(e).guest_retval(),
                    false,
                ),
            }
        }
    }
}
