//! Linux lifecycle policy over neutral pool transitions and native context hooks.
use crate::abi::entry::SyscallResult;
use crate::abi::thread::{
    AltStack, BlockedMask, BornRecord, EntryRef, EntryState, GateState, Lifecycle,
    LifecycleDecline, ThreadControlSlot, ThreadLifecyclePage, TransitionError,
};
use carrick_personality_api::{NativeRunFailureCause, NativeRunFailureReason};
use carrick_sched_core::process::{TerminationKind, TerminationStatus};
pub use carrick_syscall_abi::LinuxWaitOptions;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct LinuxWaitStatus(i32);

/// Refusal to encode a non-terminal or invalid terminal notification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalStatusError {
    InvalidSignal,
    NonTerminal,
}

impl LinuxWaitStatus {
    pub const fn from_wait_encoding(raw: i32) -> Self {
        Self(raw)
    }

    pub const fn from_termination_status(
        status: TerminationStatus,
    ) -> Result<Self, TerminalStatusError> {
        match status.kind() {
            TerminationKind::Exited => Ok(Self::exited(status.code() as u8)),
            TerminationKind::Signaled { core_dump } => {
                if status.code() == 0 || status.code() > 64 {
                    return Err(TerminalStatusError::InvalidSignal);
                }
                Ok(Self::signaled(status.code() as u8, core_dump))
            }
        }
    }

    /// Root publication accepts only exact terminal wait encodings.
    pub const fn terminal_status(self) -> Result<TerminationStatus, TerminalStatusError> {
        if self.0 & !0xff00 == 0 {
            return Ok(TerminationStatus::exited(((self.0 >> 8) & 0xff) as u32));
        }
        let signal = self.0 & 0x7f;
        if self.0 & !0xff == 0 && signal >= 1 && signal <= 64 {
            return Ok(TerminationStatus::signaled(
                signal as u32,
                self.0 & 0x80 != 0,
            ));
        }
        Err(TerminalStatusError::NonTerminal)
    }

    pub const fn to_termination_status(self) -> TerminationStatus {
        if self.is_signaled() {
            let sig = (self.0 & 0x7f) as u32;
            let core_dump = (self.0 & 0x80) != 0;
            TerminationStatus::signaled(sig, core_dump)
        } else {
            let code = ((self.0 >> 8) & 0xff) as u32;
            TerminationStatus::exited(code)
        }
    }

    pub const fn signaled(sig: u8, core_dumped: bool) -> Self {
        let core_bit = if core_dumped { 0x80 } else { 0 };
        Self((sig as i32 & 0x7f) | core_bit)
    }

    pub const fn exited(status: u8) -> Self {
        Self((status as i32) << 8)
    }

    pub const fn stopped(sig: u8) -> Self {
        Self(((sig as i32) << 8) | 0x7f)
    }

    pub const fn continued() -> Self {
        Self(0xffff)
    }

    pub const fn is_signaled(self) -> bool {
        (self.0 & 0x7f) != 0 && (self.0 & 0x7f) != 0x7f
    }

    pub const fn term_signal(self) -> Option<u8> {
        if self.is_signaled() {
            Some((self.0 & 0x7f) as u8)
        } else {
            None
        }
    }

    pub const fn raw(self) -> i32 {
        self.0
    }
}

pub fn wait_child_class(options: LinuxWaitOptions) -> carrick_sched_core::process::WaitChildClass {
    use carrick_sched_core::process::WaitChildClass;
    if options.contains(LinuxWaitOptions::WALL) {
        WaitChildClass::All
    } else if options.contains(LinuxWaitOptions::WCLONE) {
        WaitChildClass::Clone
    } else {
        WaitChildClass::Sigchld
    }
}

/// Linux `pid_t` selector carried by wait4 (including negative selectors).
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub struct ProcessWaitPid(i32);
impl ProcessWaitPid {
    pub const fn from_syscall_argument(raw: u64) -> Self {
        Self(raw as i32)
    }
    pub const fn raw(self) -> i32 {
        self.0
    }
}

/// Typed `waitid(2)` selector. Invalid raw id types remain explicit so the
/// process owner, rather than an ISA adapter or host wait API, lowers EINVAL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessWaitId {
    All,
    Pid(u32),
    ProcessGroup(u32),
    PidFd(u32),
    Invalid,
}
impl ProcessWaitId {
    pub const fn from_syscall_arguments(id_type: u64, id: u64) -> Self {
        match id_type {
            0 => Self::All,
            1 if id <= u32::MAX as u64 => Self::Pid(id as u32),
            2 if id <= u32::MAX as u64 => Self::ProcessGroup(id as u32),
            3 if id <= u32::MAX as u64 => Self::PidFd(id as u32),
            _ => Self::Invalid,
        }
    }
    pub const fn pid(pid: u32) -> Self {
        Self::Pid(pid)
    }
}
#[derive(
    ::core::clone::Clone,
    ::core::marker::Copy,
    ::core::fmt::Debug,
    ::core::cmp::Eq,
    ::core::cmp::PartialEq,
)]
pub enum LifecycleCall {
    Exit,
    SigAltStack,
    SigProcMask,
    SetRobustList,
    GetPid,
    GetTid,
    Clone,
    Fork,
    Wait4,
    WaitId,
    ExitGroup,
}

/// A primitive returns data, never an entry completion or a final frame write.
pub enum LifecycleOutcome {
    Redispatch,
    HostCustody,
    Returned {
        result: SyscallResult,
        work: bool,
    },
    Transferred {
        progress: carrick_core_abi::Served,
        result: SyscallResult,
    },
}

/// Outcome of preparing or waiting on an `rt_sigreturn` frame copy-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigreturnCopyOutcome {
    /// Contention or unbacked frame preparation parked the caller cleanly.
    Transferred {
        progress: carrick_core_abi::Served,
        result: SyscallResult,
    },
    /// Contention cleared synchronously; restart `rt_sigreturn` cleanly.
    RetrySyscall,
    /// Synchronous reply or thread exit already forced `SIGSEGV` or
    /// termination; return without restarting `rt_sigreturn` or writing errno.
    Settled,
    /// Inline frame validation or mapping lookup failed; caller must force
    /// `SIGSEGV` without returning `-EFAULT`.
    Fault,
}

pub fn lifecycle_effect(outcome: &LifecycleOutcome) -> crate::dispatch::FamilyCompletion {
    use crate::dispatch::FamilyCompletion;
    match *outcome {
        LifecycleOutcome::Redispatch => FamilyCompletion::FrameRestored,
        LifecycleOutcome::HostCustody => FamilyCompletion::HostCustody,
        LifecycleOutcome::Returned { result, work: true } => {
            FamilyCompletion::CompleteWithWork(result.raw())
        }
        LifecycleOutcome::Returned {
            result,
            work: false,
        } => FamilyCompletion::Complete(result.raw()),
        LifecycleOutcome::Transferred {
            progress: carrick_core_abi::Served::Returned { .. },
            result,
        } => FamilyCompletion::Switched(result.raw()),
        LifecycleOutcome::Transferred {
            progress: carrick_core_abi::Served::Idle,
            ..
        } => FamilyCompletion::Suspended,
    }
}

use crate::thread::{
    CHILD_TID_CLEAR, LifecycleThread, RobustListHead, RobustListLen, RobustListSlot,
    SYS_SET_ROBUST_LIST, set_robust_list, setup_open,
};
use carrick_core::Served;
use carrick_core_abi::EntryMmKey;
use carrick_core_abi::ExecutionBinding;
use carrick_guest_arch::{CounterFrequency, CounterTick, UserVa};
use carrick_sched_core::{RecordRef, ThreadIdentity};
use core::sync::atomic::Ordering;

/// A retained native slot reader returns owned scalar state, never a borrowed slot.
pub type RobustSlotReader<'r> =
    dyn FnMut(&ThreadLifecyclePage, EntryRef) -> Option<(u64, u32)> + 'r;

/// What one delegated `mmap` takes from its thread's retained sources.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct MapSourceTake {
    /// The source for exactly this call, when its key matches.
    pub matched: Option<carrick_core_abi::HostBackingIdentity>,
    /// Sources this thread holds but no call will map: the reservation
    /// owner retires them so the carrier releases them.
    pub orphans: alloc::vec::Vec<carrick_core_abi::HostBackingIdentity>,
}

/// Original preparation refusal, observed before service admission or retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputPreparationRefusal {
    Fault,
    OwnerBusy,
    OwnerDependency,
}

/// A bounded owner write either faults or retains its exact producer receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnedCopyError {
    Fault,
    Wait(carrick_core_abi::PortalOwnerWait),
    /// The execution or preparation venue cannot authorize a copy here.
    Unavailable,
}

/// Native process custody supplied by the execution lane. Registry decisions
/// remain in the shared scheduler owner; this adapter retains machine context.
/// The process owner either supplies stock or retains the whole admission.
pub enum ThreadBirthAdmission {
    Unmanaged,
    Ready,
    Owned(LifecycleOutcome),
}

pub trait CopyoutEffect: Send {
    /// Commit only after all output bytes were delivered. Drop cancels otherwise.
    fn commit(&mut self) -> Result<(), carrick_syscall_abi::LinuxErrno>;
}

/// A sample and the carrier's ring-published realtime calibration.
pub struct RealtimeCounter {
    pub tick: CounterTick,
    pub frequency: CounterFrequency,
    pub offset_ns: u64,
}

/// Outcome of enrolling a floor-declined raw `exit` on a peer's refundable
/// exit reservation release.
pub enum ExitReservationWait {
    /// Enrolled on the reservation release queue and parked; the saved `exit`
    /// syscall reruns when the reservation settles.
    Parked(LifecycleOutcome),
    /// No refundable reservation remained under the wait-bucket guard; the
    /// caller probes once without spinning.
    ProbeOnce,
}

pub trait ProcessNative<'ipc, C: carrick_core_abi::EntryContext = carrick_sched_core::ThreadCtx> {
    fn monotonic_counter(&mut self) -> Option<(CounterTick, CounterFrequency)> {
        None
    }
    /// Sample the counter and the carrier’s ring-published realtime calibration.
    fn realtime_counter(&mut self) -> Option<RealtimeCounter> {
        None
    }
    /// Read one CPU-time clock through the task owner: the caller's, or the
    /// process or thread its dynamic id names, sampled as it asks. `None`:
    /// this venue has no CPU ledger (the call stays unrouted). `Err`: Linux's
    /// errno for a target the caller cannot read (EINVAL for no such process,
    /// or a thread outside the caller's thread group).
    fn cpu_clock_nanos(
        &mut self,
        _clock: carrick_syscall_abi::LinuxCpuClock,
    ) -> Option<Result<u64, carrick_syscall_abi::LinuxErrno>> {
        None
    }
    fn process_tms(&mut self) -> Option<carrick_syscall_abi::LinuxTms> {
        None
    }
    /// Native scheduler publication belongs to the admitted process execution
    /// owner, which also delivers architecture-specific wake effects.
    fn native_futex(
        &mut self,
        _call: crate::sched::FutexCall,
        _copy: &mut dyn carrick_core::user_copy::UserCopy,
    ) -> Option<LifecycleOutcome> {
        None
    }
    /// Authenticate a shared futex word as private anonymous storage of this
    /// process's MM, the one rule both ISAs key shared-private waits by
    /// (#2124). `Ok(false)` leaves the shared operation unrouted. `Err` is
    /// the memory owner's retry or failure; it retains `retained` first, so
    /// a relative timeout keeps its first-attempt expiry.
    fn futex_shared_private(
        &mut self,
        _address: UserVa,
        _retained: Option<crate::sched::RelativeFutexWait>,
    ) -> Result<bool, LifecycleOutcome> {
        Ok(false)
    }
    fn enqueue_thread(&mut self, _record: RecordRef) -> BornEnqueue {
        BornEnqueue::Refused
    }
    /// `sched_yield` whose slot owes a runnable sibling the CPU
    /// ([`carrick_sched_core::YieldTurn::Rotate`]): the owner saves the
    /// caller's completed syscall (result 0) and requeues it at the tail,
    /// and the execution lane runs the head. `None`: the owner kept the
    /// caller, which completes the yield in place.
    fn native_yield(&mut self) -> Option<LifecycleOutcome> {
        None
    }
    fn wake_thread_join(&mut self, _mm: carrick_core_abi::EntryMmKey, _address: UserVa) -> bool {
        false
    }
    fn retire_thread_current(
        &mut self,
        _record: RecordRef,
        _retirement: carrick_core::terminal::ZoneRetirement<'_, '_>,
    ) -> bool {
        false
    }
    /// The admitted process graph owns root identity; namespace PID 1 does not.
    fn is_root_process(&self) -> bool;
    /// Whether this process's memory owner can finish an output or prepare
    /// an input on its MM. Only then is a copy the entry could not make
    /// "not yet" (the owner waits for the page, or answers EFAULT for an
    /// address that is not the guest's); otherwise the entry's own refusal
    /// is final, EFAULT.
    fn owner_reaches_memory(&mut self) -> bool {
        true
    }
    /// A native execution record owns its complete published descriptor
    /// namespace even when the carrier supplied its initial table. Borrowed
    /// host records retain their host mutation owner.
    fn owns_descriptor_namespace(&self) -> bool {
        false
    }
    /// Whether another thread may share the caller's descriptor table
    /// (`CLONE_FILES`): every ring thread of a process shares its one table,
    /// so this is "the process has another live thread". `true` when the
    /// venue can't tell, so a caller that needs a private table declines
    /// rather than mutating a table a sibling still uses.
    fn shares_descriptor_namespace(&self) -> bool {
        true
    }
    /// Resume this exact thread's retained operation before a new syscall is
    /// dispatched. Readiness alone cannot authorize a user return.
    fn resume_owned_continuation(&mut self) -> Option<LifecycleOutcome> {
        None
    }
    /// Finish deferred physical enrollment after the operation frames unwind.
    fn drain_owned_preparation(&mut self) {}
    fn take_handoff_receipt(&mut self) -> Option<carrick_core_abi::EntryHandoffReceipt<C>> {
        None
    }
    fn store_handoff_receipt(&mut self, _receipt: carrick_core_abi::EntryHandoffReceipt<C>) {}
    fn prepare_object_park(&mut self) {}
    fn take_run_failure(&mut self) -> Option<NativeRunFailureCause> {
        None
    }
    fn take_relative_futex_wait(&mut self) -> Option<crate::sched::RelativeFutexWait> {
        None
    }
    fn retain_relative_futex_wait(&mut self, _operation: crate::sched::RelativeFutexWait) {}
    /// The accepted `epoll_pwait` this thread's rerun continues, if any.
    fn take_accepted_epoll_wait(&mut self) -> Option<carrick_core_abi::wait::AcceptedWait> {
        None
    }
    /// Retain an accepted `epoll_pwait` for this thread's rerun. `false`:
    /// this venue retains no rerun answers.
    fn retain_accepted_epoll_wait(&mut self, _wait: carrick_core_abi::wait::AcceptedWait) -> bool {
        false
    }
    /// A syscall entry begins. Answers retained for the rerun of this
    /// thread's last call (the carrier's thread-stock reply, #1974) belong
    /// to exactly this entry: whatever syscall it is, no later entry sees
    /// them.
    fn scope_rerun_answers_to_entry(&mut self) {}
    /// Prepare an unavailable input and retain its exact syscall until ready.
    fn wait_guest_copy(&mut self, request: GuestCopyRequest) -> LifecycleOutcome;
    /// Observe preparation without changing continuation ownership or policy.
    fn wait_guest_copy_observed(
        &mut self,
        request: GuestCopyRequest,
        _observe: &mut dyn FnMut(InputPreparationRefusal),
    ) -> LifecycleOutcome {
        self.wait_guest_copy(request)
    }
    /// Prepare an unavailable `rt_sigreturn` frame page without translating a
    /// real fault into `-EFAULT`; faults return `SigreturnCopyOutcome::Fault`
    /// so the caller forces `SIGSEGV`.
    fn wait_sigreturn_copy_observed(
        &mut self,
        _request: GuestCopyRequest,
        _observe: &mut dyn FnMut(InputPreparationRefusal),
    ) -> SigreturnCopyOutcome {
        SigreturnCopyOutcome::Fault
    }

    /// An admitted process may retain an exact-MM write authority (including COW).
    /// None means this venue does not own user transfers.
    fn copy_out_owned(
        &mut self,
        _dst: UserVa,
        _bytes: &[u8],
    ) -> Option<Result<(), OwnedCopyError>> {
        None
    }
    fn yield_owned_operation(
        &mut self,
        operation: carrick_sched_core::object_wait::OperationToken,
    ) -> carrick_core::mm::transaction::OwnedOperationYield {
        carrick_core::mm::transaction::OwnedOperationYield::Unrouted(operation)
    }
    fn prepare_owned_copyout(
        &mut self,
        _request: carrick_core::mm::transaction::CopyoutRequest,
        operation: carrick_sched_core::object_wait::OperationToken,
    ) -> carrick_core::mm::transaction::CopyoutPreparation {
        carrick_core::mm::transaction::CopyoutPreparation::Unrouted(operation)
    }
    /// Retain constructor custody with output; drop rolls it back on cancellation.
    fn complete_constructor_output(
        &mut self,
        _address: UserVa,
        _bytes: alloc::vec::Vec<u8>,
        _effect: alloc::boxed::Box<dyn CopyoutEffect + 'ipc>,
    ) -> LifecycleOutcome {
        LifecycleOutcome::Returned {
            result: SyscallResult::new(carrick_syscall_abi::LINUX_EFAULT.guest_retval()),
            work: false,
        }
    }
    /// Retain a completed answer while its destination waits for its owner.
    fn complete_copyout(
        &mut self,
        _address: UserVa,
        _bytes: alloc::vec::Vec<u8>,
        _result: SyscallResult,
    ) -> LifecycleOutcome {
        LifecycleOutcome::Returned {
            result: SyscallResult::new(carrick_syscall_abi::LINUX_EFAULT.guest_retval()),
            work: false,
        }
    }
    /// Retain the result and disjoint value-result fields in the caller's MM.
    fn complete_copyout_spans(
        &mut self,
        _spans: alloc::vec::Vec<(UserVa, alloc::vec::Vec<u8>)>,
        _result: SyscallResult,
    ) -> LifecycleOutcome {
        LifecycleOutcome::Returned {
            result: SyscallResult::new(carrick_syscall_abi::LINUX_EFAULT.guest_retval()),
            work: false,
        }
    }
    /// Retain the completed poll result and its individual output fields.
    fn complete_poll_copyout(
        &mut self,
        _fields: alloc::vec::Vec<carrick_syscall_abi::PollReventsOutput>,
        _result: SyscallResult,
    ) -> LifecycleOutcome {
        LifecycleOutcome::Returned {
            result: SyscallResult::new(carrick_syscall_abi::LINUX_EFAULT.guest_retval()),
            work: false,
        }
    }
    /// The private file byte source the native host-file venue retained for
    /// exactly this thread's retried `mmap` with `key`, consumed once, and
    /// every source this thread was given but will not map (to retire).
    fn take_map_source(&mut self, _key: crate::native_host_file::NativeMapKey) -> MapSourceTake {
        MapSourceTake::default()
    }
    /// Probe interruption at owned-wait enrollment or resumption. After
    /// enrollment, the existing signal/queue owners cancel the exact park.
    /// Resumption reports pending delivery without claiming the OnCpu record.
    fn interrupt_pending_wait(&mut self) -> bool {
        false
    }
    /// Swap an `epoll_pwait` sigmask in for a ring-owned wait (see
    /// `UserCopy::arm_wait_sigmask`). `false`: no native signal owner.
    fn arm_wait_sigmask(&mut self, _temporary: u64) -> bool {
        false
    }
    /// Undo [`arm_wait_sigmask`](Self::arm_wait_sigmask) without a checkpoint.
    fn disarm_wait_sigmask(&mut self) {}
    fn binding(&self) -> ExecutionBinding;
    fn pid_exists(&self, _pid: u32) -> Option<bool> {
        None
    }
    fn fork(&mut self, child_tid: ProcessForkChildTid) -> LifecycleOutcome;
    fn wait4(
        &mut self,
        pid: ProcessWaitPid,
        status: UserVa,
        options: LinuxWaitOptions,
        rusage: UserVa,
    ) -> LifecycleOutcome;
    fn waitid(
        &mut self,
        _id: ProcessWaitId,
        _info: UserVa,
        _options: LinuxWaitOptions,
    ) -> LifecycleOutcome {
        LifecycleOutcome::Returned {
            result: SyscallResult::new(carrick_syscall_abi::LINUX_ENOSYS.guest_retval()),
            work: false,
        }
    }
    fn exit_group(&mut self, status: u8) -> LifecycleOutcome;
    fn as_identity_venue(&mut self) -> Option<&mut dyn crate::identity::ProcessIdentityVenue> {
        None
    }
    fn as_sysinfo_venue(&mut self) -> Option<&mut dyn crate::sysinfo::ProcessSysinfoVenue> {
        None
    }
    fn as_ipc_venue(&mut self) -> Option<&mut dyn crate::ipc::ProcessIpcVenue> {
        None
    }
    fn thread_spawned(
        &mut self,
        _caller_tid: u32,
        _child_tid: u32,
        publish: &mut dyn FnMut() -> Result<(), i64>,
    ) -> Result<(), i64> {
        publish()
    }
    /// Notify an owned exit only after a claim's rollback or Born enqueue has
    /// finished. The venue releases graph ownership before publishing a wake.
    fn prepare_thread_birth(&mut self) -> ThreadBirthAdmission {
        ThreadBirthAdmission::Unmanaged
    }
    fn bind_thread_birth(
        &mut self,
        _record: RecordRef,
        _control: &ThreadControlSlot,
    ) -> Result<(), i64> {
        Ok(())
    }
    fn lifecycle_admission_settled(&mut self) -> Result<(), i64> {
        Ok(())
    }
    /// An unmanaged clone (no venue stock) found the ring pool empty. The
    /// host ledger stocks this pool, so the empty pool is contention, not a
    /// host birth (#1974): keep the clone, release the execution lease
    /// through carrier work whose request asks the host for stock, and rerun
    /// the clone in ring. A rerun that finds the pool empty after the host
    /// stocked lost the stock to a sibling and waits again. `None` keeps
    /// today's host-issued birth for this call: the host answered that it
    /// can stock nothing (no standing depth, `RLIMIT_NPROC`, exhaustion), or
    /// there is no venue to wait in.
    fn await_unmanaged_thread_stock(&mut self) -> Option<LifecycleOutcome> {
        None
    }
    fn retire_thread_verdict(&mut self, _verdict: carrick_core::terminal::RetirementVerdict) {}
    /// Retire a thread whose raw `exit` raced its group's terminal close.
    fn retire_closing_thread_exit(&mut self) -> Option<LifecycleOutcome> {
        None
    }
    /// Enrol on an active refundable peer exit reservation's release, or
    /// report `ProbeOnce` when none remains under the wait-bucket guard.
    fn await_exit_reservation(&mut self) -> Option<ExitReservationWait> {
        None
    }
    /// Retire the process when a raw `exit` caller is the authenticated sole
    /// surviving thread and zero refundable reservations remain.
    fn retire_sole_surviving_raw_exit(&mut self, _status: u8) -> Option<LifecycleOutcome> {
        None
    }
    fn publish_exit_reservation_notification(
        &mut self,
        _notification: carrick_core::terminal::TerminalNotification,
    ) {
    }
    fn route_host_thread_exit(
        &mut self,
        _verdict: carrick_core::terminal::RetirementVerdict,
    ) -> bool {
        false
    }
    fn set_calling_tid(&mut self, _tid: u32) {}

    fn has_thread(&self, _tid: u32) -> bool {
        false
    }
    fn get_affinity(
        &self,
        _pid: u32,
    ) -> Result<carrick_core::affinity::CpuAffinity, carrick_syscall_abi::LinuxErrno> {
        Err(carrick_syscall_abi::LINUX_ESRCH)
    }
    fn set_affinity(
        &mut self,
        _pid: u32,
        _mask: carrick_core::affinity::CpuAffinity,
    ) -> Result<carrick_core::affinity::CpuAffinity, carrick_syscall_abi::LinuxErrno> {
        Err(carrick_syscall_abi::LINUX_ESRCH)
    }
    fn read_robust_list(
        &self,
        _tid: u32,
        _read_slot: &mut RobustSlotReader<'_>,
    ) -> Result<(u64, u32), i64> {
        Err(crate::identity::ESRCH)
    }
    fn signal_venue(&mut self) -> Option<&mut dyn crate::signal::ProcessSignals> {
        None
    }
}

pub use carrick_core::user_copy::{CopyOutcome, GuestCopyRequest, UserCopy};

pub struct ChildContext {
    pub result: SyscallResult,
    pub stack: UserVa,
    pub tls: Option<UserVa>,
    pub visible_tid: u32,
}

/// Credential admission and the Born record share the owner's transaction;
/// runnable publication follows after its graph guard is released.
pub struct ThreadBirth<'a, 'b> {
    pub page: &'a ThreadLifecyclePage,
    pub claim: &'b mut Option<carrick_core::lifecycle::ClaimedEntry>,
    pub born: BornRecord,
    pub record: RecordRef,
    pub caller_tid: Option<u32>,
    pub child_tid: u32,
}

impl ThreadBirth<'_, '_> {
    /// Restore the claim on refusal so the enclosing clone rollback owns it.
    pub fn record(&mut self) -> Result<(), i64> {
        let claim = self.claim.take().ok_or(crate::identity::EINVAL)?;
        match self.page.record_born(claim, self.born) {
            Ok(_) => Ok(()),
            Err(refusal) => {
                let (_, claim) = refusal.into_parts();
                *self.claim = Some(claim);
                Err(crate::identity::EINVAL)
            }
        }
    }
}

pub struct ExitRecord {
    pub reference: RecordRef,
    pub identity: ThreadIdentity,
    pub home: bool,
    pub unadopted: bool,
    pub on_cpu: bool,
    pub needs_host: bool,
    pub cancelled: bool,
    pub object_operation: bool,
}

/// Whether a committed birth was made runnable.
///
/// Born membership is already published when the record is queued, so a
/// refusal cannot be rolled back as a clone failure: the birth owner fails
/// closed. Before #1100 the outcome was `()`, and a refused record was
/// silently left on no run queue.
#[must_use = "a refused birth enqueue leaves a published thread unrunnable"]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BornEnqueue {
    Queued,
    Refused,
}

impl From<carrick_sched_core::Requeue> for BornEnqueue {
    fn from(requeue: carrick_sched_core::Requeue) -> Self {
        if requeue.is_queued() {
            Self::Queued
        } else {
            Self::Refused
        }
    }
}

/// ISA hooks acquire retained metadata and move real native context. They do
/// not route, validate clone flags, lower errno or publish entry completion.
pub trait LifecycleNative<'a>: UserCopy {
    fn monotonic_counter(&mut self) -> Option<(CounterTick, CounterFrequency)> {
        None
    }
    /// Sample the counter and the carrier’s ring-published realtime calibration.
    fn realtime_counter(&mut self) -> Option<RealtimeCounter> {
        None
    }
    /// Read one CPU-time clock through the task owner: the caller's, or the
    /// process or thread its dynamic id names, sampled as it asks. `None`:
    /// this venue has no CPU ledger (the call stays unrouted). `Err`: Linux's
    /// errno for a target the caller cannot read (EINVAL for no such process,
    /// or a thread outside the caller's thread group).
    fn cpu_clock_nanos(
        &mut self,
        _clock: carrick_syscall_abi::LinuxCpuClock,
    ) -> Option<Result<u64, carrick_syscall_abi::LinuxErrno>> {
        None
    }
    fn process_tms(&mut self) -> Option<carrick_syscall_abi::LinuxTms> {
        None
    }
    /// Resume an input before any syscall effect has been committed.
    fn wait_guest_copy(&mut self, request: GuestCopyRequest) -> LifecycleOutcome;
    /// Retain a completed setup operation's original output after `NotYet`.
    /// The shared policy already attempted the copy; do not restart it here.
    fn finish_signal_output(
        &mut self,
        address: UserVa,
        bytes: alloc::vec::Vec<u8>,
        work: bool,
    ) -> LifecycleOutcome;

    fn finish_time_output(
        &mut self,
        _records: [Option<(UserVa, alloc::vec::Vec<u8>)>; 2],
        _result: SyscallResult,
    ) -> LifecycleOutcome {
        LifecycleOutcome::Returned {
            result: SyscallResult::from_errno(carrick_syscall_abi::LINUX_EFAULT),
            work: false,
        }
    }

    /// Terminal custody loss must never become a guest errno or leave exit parked.
    /// The run failure names the caller's site (#2853).
    #[track_caller]
    fn fail_lifecycle(&mut self, reason: NativeRunFailureReason) -> !;
    fn prepare_thread_birth(&mut self) -> ThreadBirthAdmission {
        ThreadBirthAdmission::Unmanaged
    }
    fn lifecycle_admission_settled(&mut self) -> Result<(), i64> {
        Ok(())
    }
    /// See [`ProcessNative::await_unmanaged_thread_stock`].
    fn await_unmanaged_thread_stock(&mut self) -> Option<LifecycleOutcome> {
        None
    }

    fn arguments(&self) -> [u64; 6];
    fn guest_isa(&self) -> carrick_guest_arch::GuestIsa;
    fn binding(&self) -> Option<ExecutionBinding>;
    fn task_state(&self) -> Option<&'a crate::abi::entry::LinuxTaskState>;
    fn process_pid(&self) -> Option<u32> {
        None
    }
    fn visible_tid(&self) -> Option<u32> {
        None
    }
    fn register_robust_list(&self, head: u64, len: u64) -> Option<SyscallResult> {
        let thread = self.thread()?;
        set_robust_list(
            thread.page,
            RobustListSlot::new(thread.slot, None),
            RobustListHead::new(head),
            RobustListLen::new(len),
        )
        .linux_result()
        .map(SyscallResult::new)
    }
    fn thread(&self) -> Option<LifecycleThread<'a>>;
    fn born_slot(
        &self,
        page: &ThreadLifecyclePage,
        entry: EntryRef,
    ) -> Option<&'a ThreadControlSlot>;
    fn record_decline(&self, reason: LifecycleDecline);
    fn has_scheduler(&self) -> bool;
    fn user_sp(&mut self) -> Option<UserVa>;
    fn affinity(&self) -> Option<u64>;
    fn allocate_record(
        &mut self,
        identity: ThreadIdentity,
    ) -> Result<RecordRef, carrick_sched_core::Exhausted>;
    fn free_record(&mut self, record: RecordRef);
    fn retain_native_birth(&mut self, _record: RecordRef, _control: &ThreadControlSlot) -> bool {
        false
    }
    /// Undo retained service/control admission before freeing an unpublished birth.
    fn release_native_birth(&mut self, _record: RecordRef, _control: &ThreadControlSlot) -> bool {
        false
    }
    /// ISA-only context availability, checked before any output or pool claim.
    fn can_prepare_child(&self, stack: UserVa, tls: Option<UserVa>) -> bool;
    fn prepare_child(&mut self, record: RecordRef, context: ChildContext);
    /// Make a committed birth runnable. A refusal is returned, never
    /// dropped: the caller fails closed (#1100).
    fn enqueue_born(&mut self, record: RecordRef) -> BornEnqueue;
    fn exit_record(&self) -> Option<ExitRecord>;
    fn wake_child_tid(&mut self, mm: EntryMmKey, address: UserVa) -> bool;
    fn release_current(
        &mut self,
        record: RecordRef,
        retirement: carrick_core::terminal::ZoneRetirement<'_, '_>,
    ) -> bool;
    fn run_next(&mut self, timeout_result: SyscallResult) -> (Served, SyscallResult);
    fn result(&self) -> SyscallResult;
    fn set_result(&mut self, result: SyscallResult);
    /// Native custody for an admitted process fork through the guest process venue.
    fn process_fork(&mut self, _child_tid: ProcessForkChildTid) -> Option<LifecycleOutcome> {
        None
    }
    fn process_wait4(
        &mut self,
        _pid: ProcessWaitPid,
        _status: UserVa,
        _options: LinuxWaitOptions,
        _rusage: UserVa,
    ) -> Option<LifecycleOutcome> {
        None
    }
    fn process_waitid(
        &mut self,
        _id: ProcessWaitId,
        _info: UserVa,
        _options: LinuxWaitOptions,
    ) -> Option<LifecycleOutcome> {
        None
    }
    fn process_exit_group(&mut self, _status: u8) -> Option<LifecycleOutcome> {
        None
    }
    /// Retire a thread whose raw `exit` raced its group's terminal close.
    fn retire_closing_thread_exit(&mut self) -> Option<LifecycleOutcome> {
        None
    }
    /// Enrol on an active refundable peer exit reservation's release, or
    /// report `ProbeOnce` when none remains under the wait-bucket guard.
    fn await_exit_reservation(&mut self) -> Option<ExitReservationWait> {
        None
    }
    /// Retire the process when a raw `exit` caller is the authenticated sole
    /// surviving thread and zero refundable reservations remain.
    fn retire_sole_surviving_raw_exit(&mut self, _status: u8) -> Option<LifecycleOutcome> {
        None
    }
    fn exit_reservation_released(
        &mut self,
        _notification: carrick_core::terminal::TerminalNotification,
    ) {
    }
    /// Exact retained process owner for an adopted thread's terminal handoff.
    fn process_exit_binding(&self) -> Option<ExecutionBinding> {
        None
    }

    fn publish_born(&mut self, mut birth: ThreadBirth<'a, '_>) -> Result<(), i64> {
        birth.record()?;
        if self.enqueue_born(birth.record) == BornEnqueue::Refused {
            self.fail_lifecycle(NativeRunFailureReason::BornEnqueueRefused);
        }
        Ok(())
    }
    fn thread_exited(&mut self, _verdict: carrick_core::terminal::RetirementVerdict) {}
    fn route_host_thread_exit(
        &mut self,
        _verdict: carrick_core::terminal::RetirementVerdict,
    ) -> bool {
        false
    }
}
/// Linux aarch64 syscall numbers served here (`SYS_SET_ROBUST_LIST` is the
/// shared canonical number from [`crate::thread`]).
pub const SYS_EXIT: usize = 93;
pub const SYS_SIGALTSTACK: usize = 132;
pub const SYS_RT_SIGPROCMASK: usize = 135;
pub const SYS_GETTID: usize = 178;
pub const SYS_GETPID: usize = 172;
pub const SYS_CLONE: usize = 220;

// clone(2) flags.
const CLONE_VM: u64 = 0x0000_0100;
const CLONE_FS: u64 = 0x0000_0200;
const CLONE_FILES: u64 = 0x0000_0400;
const CLONE_SIGHAND: u64 = 0x0000_0800;
const CLONE_VFORK: u64 = 0x0000_4000;
/// The exact clone flags of vfork(2): `CLONE_VM|CLONE_VFORK|SIGCHLD`.
pub const VFORK_CLONE_FLAGS: u64 =
    CLONE_VM | CLONE_VFORK | carrick_signal_core::policy::Signal::CHLD.number() as u64;
const CLONE_THREAD: u64 = 0x0001_0000;
const CLONE_SYSVSEM: u64 = 0x0004_0000;
const CLONE_SETTLS: u64 = 0x0008_0000;
const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
/// Ignored by Linux (clone(2): "historical"), so serving it changes nothing;
/// musl's `pthread_create` passes it.
const CLONE_DETACHED: u64 = 0x0040_0000;
const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
/// The low byte: the child's exit signal. A thread has none.
const CSIGNAL: u64 = 0xff;

/// What the parent of a process fork does until its child leaves the
/// parent's image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessForkParent {
    /// fork(2): the parent returns the child's pid at once.
    Runs,
    /// vfork(2) (`CLONE_VM|CLONE_VFORK|SIGCHLD`): the parent returns the
    /// child's pid only after the child's exec is admitted or the child
    /// exits. A venue that cannot guarantee that release may return at once.
    SuspendedUntilExecOrExit,
}

/// Child-only effects of a process fork. The TID address and the stack belong
/// to the new MM, so callers must not copy through the parent's UserCopy
/// aperture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessForkChildTid {
    pub address: UserVa,
    pub set: bool,
    pub clear: bool,
    /// The child's user stack pointer; `None` keeps the parent's.
    pub stack: Option<UserVa>,
    pub parent: ProcessForkParent,
}

impl ProcessForkChildTid {
    pub const NONE: Self = Self {
        address: UserVa::new(0),
        set: false,
        clear: false,
        stack: None,
        parent: ProcessForkParent::Runs,
    };

    /// vfork(2) served with a copy-on-write child: Linux's `clone(2)` lets
    /// the child run on `stack` (glibc passes the caller's own sp), and the
    /// parent is suspended as [`ProcessForkParent::SuspendedUntilExecOrExit`]
    /// describes.
    pub const fn vfork(stack: UserVa) -> Self {
        Self {
            stack: if stack.raw() == 0 { None } else { Some(stack) },
            parent: ProcessForkParent::SuspendedUntilExecOrExit,
            ..Self::NONE
        }
    }

    pub const fn flags(self) -> u64 {
        (if self.set { CLONE_CHILD_SETTID } else { 0 })
            | (if self.clear { CLONE_CHILD_CLEARTID } else { 0 })
    }
}

/// Every flag a libc or Go thread creation passes.
const THREAD_CLONE_REQUIRED: u64 =
    CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;
/// The flags a libc thread creation may add.
const THREAD_CLONE_OPTIONAL: u64 =
    CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | CLONE_DETACHED;

// rt_sigprocmask(2).
const SIG_BLOCK: u64 = 0;
const SIG_UNBLOCK: u64 = 1;
const SIG_SETMASK: u64 = 2;
/// `sizeof(kernel sigset_t)` on arm64.
const RT_SIGSET_SIZE: u64 = 8;
/// SIGKILL (9) and SIGSTOP (19) as mask bits (`signum - 1`): Linux drops
/// them from every mask a thread installs.
const UNBLOCKABLE: u64 = 0x0004_0100;

// sigaltstack(2).
const SS_ONSTACK: u32 = 1;
const SS_DISABLE: u32 = 2;
/// `sizeof(stack_t)` on arm64: `ss_sp`, `ss_flags` (+4 pad), `ss_size`.
const STACK_T_SIZE: usize = 24;

/// `stack_t` as its three little-endian 64-bit words: `ss_sp`, `ss_flags`
/// in the low half of the second (the pad is zero), `ss_size`.
fn stack_t_words(bytes: &[u8; STACK_T_SIZE]) -> [u64; 3] {
    let mut words = [0u64; 3];
    for (word, chunk) in words.iter_mut().zip(bytes.chunks_exact(8)) {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(chunk);
        *word = u64::from_le_bytes(raw);
    }
    words
}

fn stack_t_bytes(words: [u64; 3]) -> [u8; STACK_T_SIZE] {
    let mut bytes = [0u8; STACK_T_SIZE];
    for (chunk, word) in bytes.chunks_exact_mut(8).zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

/// Whether `nr` is a call this module may serve.
pub const fn is_lifecycle_syscall(nr: usize) -> bool {
    matches!(
        nr,
        SYS_EXIT
            | SYS_SET_ROBUST_LIST
            | SYS_SIGALTSTACK
            | SYS_RT_SIGPROCMASK
            | SYS_GETTID
            | SYS_GETPID
            | SYS_CLONE
    )
}

/// Execute Linux policy, leaving ordinary result installation and completion
/// publication to the authenticated entry owner.
fn returned(result: SyscallResult, work: bool) -> LifecycleOutcome {
    LifecycleOutcome::Returned { result, work }
}

pub fn invoke<'a>(
    call: LifecycleCall,
    native: &mut dyn LifecycleNative<'a>,
) -> Option<LifecycleOutcome> {
    let args = native.arguments();
    if call == LifecycleCall::SetRobustList {
        return Some(returned(
            native.register_robust_list(args[0], args[1])?,
            false,
        ));
    }
    if call == LifecycleCall::GetPid {
        return Some(returned(
            SyscallResult::new(i64::from(native.process_pid()?)),
            false,
        ));
    }
    if call == LifecycleCall::GetTid
        && let Some(tid) = native.visible_tid()
    {
        return Some(returned(SyscallResult::new(i64::from(tid)), false));
    }
    // Without their flags, Linux ignores parent_tid, tls and child_tid.
    // The ISA decoder has already canonicalized x86's native ctid arg3 to
    // arg4, so both guest ISAs use this one process-fork matcher.
    if call == LifecycleCall::Clone
        && args[0] == carrick_signal_core::policy::Signal::CHLD.number() as u64
        && args[1] == 0
    {
        return native.process_fork(ProcessForkChildTid::NONE);
    }
    // Child-local TID effects preserve fork's separate MM. All other clone
    // sharing flags and exit signals stay on the existing thread/refusal path.
    if call == LifecycleCall::Clone
        && args[0] & !(CSIGNAL | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID) == 0
        && args[0] & CSIGNAL == carrick_signal_core::policy::Signal::CHLD.number() as u64
        && args[0] & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID) != 0
        && args[1] == 0
    {
        return native.process_fork(ProcessForkChildTid {
            address: UserVa::new(args[4]),
            set: args[0] & CLONE_CHILD_SETTID != 0,
            clear: args[0] & CLONE_CHILD_CLEARTID != 0,
            ..ProcessForkChildTid::NONE
        });
    }
    // vfork(2) as every libc issues it (glibc/musl `vfork`, dash, x86's
    // decoded vfork 58): exactly CLONE_VM|CLONE_VFORK|SIGCHLD. Linux ignores
    // parent_tid, tls and child_tid without their flags; arg1 is the child's
    // stack (glibc on arm64 passes its own sp, x86 vfork passes zero). The
    // process venue serves it as a copy-on-write fork whose parent stays
    // suspended until the child execs or exits; no venue keeps the fallback.
    if call == LifecycleCall::Clone && args[0] == VFORK_CLONE_FLAGS {
        return native.process_fork(ProcessForkChildTid::vfork(UserVa::new(args[1])));
    }
    match call {
        LifecycleCall::Fork => return native.process_fork(ProcessForkChildTid::NONE),
        LifecycleCall::Wait4 => {
            return native.process_wait4(
                ProcessWaitPid::from_syscall_argument(args[0]),
                UserVa::new(args[1]),
                LinuxWaitOptions::from_bits_retain(args[2]),
                UserVa::new(args[3]),
            );
        }
        LifecycleCall::WaitId => {
            return native.process_waitid(
                ProcessWaitId::from_syscall_arguments(args[0], args[1]),
                UserVa::new(args[2]),
                LinuxWaitOptions::from_bits_retain(args[3]),
            );
        }
        LifecycleCall::ExitGroup => return native.process_exit_group(args[0] as u8),
        _ => {}
    }
    // The last thread owns the process terminal transition, even for raw
    // exit(2). Its leader has no pooled lifecycle entry to retire.
    if call == LifecycleCall::Exit
        && native
            .thread()
            .is_some_and(|thread| carrick_core::terminal::raw_exit_is_process(thread.page))
        && let Some(outcome) = native.process_exit_group(args[0] as u8)
    {
        return Some(outcome);
    }
    let thread = native.thread().or_else(|| {
        if call == LifecycleCall::Exit {
            native.record_decline(LifecycleDecline::ExitVenue);
        }
        None
    })?;
    match call {
        LifecycleCall::GetTid => {
            if !thread.page.serves_threads() {
                return None;
            }
            Some(returned(
                SyscallResult::new(i64::from(thread.slot.visible_tid()?)),
                false,
            ))
        }
        LifecycleCall::SigProcMask => Some(match serve_sigprocmask(args, thread, native)? {
            Ok(work) => returned(SyscallResult::new(0), work),
            Err(error) => settle_setup_error(error, native),
        }),
        LifecycleCall::SigAltStack => {
            let sp = native.user_sp().map(UserVa::raw);
            let isa = native.guest_isa();
            Some(match serve_sigaltstack(args, thread, native, sp, isa)? {
                Ok(()) => returned(SyscallResult::new(0), false),
                Err(error) => settle_setup_error(error, native),
            })
        }
        LifecycleCall::Clone => serve_clone(args, thread, native),
        LifecycleCall::Exit => {
            if !native.has_scheduler() {
                native.record_decline(LifecycleDecline::ExitScheduler);
                return None;
            }
            // A raw exit never returns to user mode (`_exit(2)`): its
            // re-decisions run here, in ring, never by replaying the saved
            // `exit` through a user return where a signal could run a
            // handler in the middle of exit. Each further pass follows a
            // `ProbeOnce`, which saw no refundable peer reservation under the
            // wait bucket, so the next pass either reserves above the floor,
            // finds itself the last thread, finds the group closing, or parks.
            loop {
                let decline = match serve_exit(thread, native) {
                    Ok(outcome) => return Some(outcome),
                    Err(decline) => decline,
                };
                if let Some(outcome) = native.retire_closing_thread_exit() {
                    return Some(outcome);
                }
                if !matches!(decline, ServeExitDecline::Floor) {
                    break;
                }
                match native.await_exit_reservation() {
                    Some(ExitReservationWait::Parked(outcome)) => return Some(outcome),
                    Some(ExitReservationWait::ProbeOnce) => {
                        if let Some(outcome) = native.retire_closing_thread_exit() {
                            return Some(outcome);
                        }
                        if let Some(outcome) = native.retire_sole_surviving_raw_exit(args[0] as u8)
                        {
                            return Some(outcome);
                        }
                        // The same last-thread check a fresh `exit` entry
                        // makes above, without leaving the ring.
                        if carrick_core::terminal::raw_exit_is_process(thread.page)
                            && let Some(outcome) = native.process_exit_group(args[0] as u8)
                        {
                            return Some(outcome);
                        }
                    }
                    None => break,
                }
            }
            let binding = native.binding()?;
            let identity = carrick_core::terminal::ThreadTerminalIdentity::from_exit(
                binding,
                thread.slot.entry(),
                TerminationStatus::exited(args[0] as u32),
            )?;
            let verdict = carrick_core::terminal::TerminalCustody::<
                carrick_core::terminal::Thread,
                carrick_core::terminal::Live,
            >::admitted(identity)
            .begin()
            .route_to_host();
            native
                .route_host_thread_exit(verdict)
                .then_some(LifecycleOutcome::HostCustody)
        }
        _ => None,
    }
}

/// Refusal keeps input redispatch separate from an already committed answer.
#[derive(Debug)]
pub enum SignalSetupError {
    Errno(carrick_syscall_abi::LinuxErrno, bool),
    Input(GuestCopyRequest),
    Output {
        address: UserVa,
        bytes: alloc::vec::Vec<u8>,
        work: bool,
    },
}
fn settle_setup_error<'a>(
    error: SignalSetupError,
    native: &mut dyn LifecycleNative<'a>,
) -> LifecycleOutcome {
    match error {
        SignalSetupError::Errno(errno, work) => {
            returned(SyscallResult::new(errno.guest_retval()), work)
        }
        SignalSetupError::Input(request) => native.wait_guest_copy(request),
        SignalSetupError::Output {
            address,
            bytes,
            work,
        } => native.finish_signal_output(address, bytes, work),
    }
}

/// Copy a completed setup answer before allocating continuation storage.
/// The memory adapter must refuse before writing when it cannot retain its
/// own partial progress; the output hook takes over without retrying here.
pub(crate) fn copy_setup_output(
    user: &mut (impl UserCopy + ?Sized),
    address: UserVa,
    bytes: &[u8],
    work: bool,
) -> Result<(), SignalSetupError> {
    match user.copy_out(address, bytes) {
        CopyOutcome::Done => Ok(()),
        CopyOutcome::Fault => Err(SignalSetupError::Errno(
            carrick_syscall_abi::LINUX_EFAULT,
            work,
        )),
        CopyOutcome::NotYet(_) => Err(SignalSetupError::Output {
            address,
            bytes: bytes.to_vec(),
            work,
        }),
    }
}

/// `rt_sigprocmask(how, set, oldset, sigsetsize)`. `Some(work)`: served
/// (result 0); `work` when a pending signal may now be deliverable to this
/// thread, or must move to a sibling because this thread just blocked it.
pub fn serve_sigprocmask(
    args: [u64; 6],
    thread: LifecycleThread<'_>,
    user: &mut (impl UserCopy + ?Sized),
) -> Option<Result<bool, SignalSetupError>> {
    let [how, set, oldset, size] = [args[0], args[1], args[2], args[3]];
    if !setup_open(thread.page) {
        return None;
    }
    if size != RT_SIGSET_SIZE {
        return Some(Err(SignalSetupError::Errno(
            carrick_syscall_abi::LINUX_EINVAL,
            false,
        )));
    }
    // The owning thread is the only writer of its mask.
    let old = thread.slot.blocked();
    let new = if set != 0 {
        let mut bytes = [0u8; 8];
        match user.copy_in(&mut bytes, UserVa::new(set)) {
            CopyOutcome::Done => {}
            CopyOutcome::Fault => {
                return Some(Err(SignalSetupError::Errno(
                    carrick_syscall_abi::LINUX_EFAULT,
                    false,
                )));
            }
            CopyOutcome::NotYet(request) => return Some(Err(SignalSetupError::Input(request))),
        }
        let bits = u64::from_le_bytes(bytes);
        let mask = match how {
            SIG_BLOCK => old.0 | bits,
            SIG_UNBLOCK => old.0 & !bits,
            SIG_SETMASK => bits,
            _ => {
                return Some(Err(SignalSetupError::Errno(
                    carrick_syscall_abi::LINUX_EINVAL,
                    false,
                )));
            }
        };
        Some(BlockedMask(mask & !UNBLOCKABLE))
    } else {
        None
    };
    let work = if let Some(new) = new {
        let (prev, pending) = thread
            .slot
            .store_blocked_then_read_pending(new, thread.slot.pending());
        let pending = pending.0 | thread.page.pending().load().0;
        let deliverable = pending & !new.0;
        let newly_blocked = pending & new.0 & !prev.0;
        deliverable | newly_blocked != 0
    } else {
        false
    };
    if oldset != 0 {
        return Some(
            copy_setup_output(user, UserVa::new(oldset), &old.0.to_le_bytes(), work).map(|()| work),
        );
    }
    Some(Ok(work))
}

/// `sigaltstack(ss, old_ss)`. `sp` is the caller's stack pointer, when
/// known. An active alternate stack reads `ss` first (so an invalid input
/// pointer returns `EFAULT`), then rejects replacement with `EPERM`, while a
/// query may still report `SS_ONSTACK`. Valid replacement (including
/// `SS_DISABLE`) is committed before copying `old_ss` out, so an invalid
/// `old_ss` returns `EFAULT` with the replacement retained.
fn serve_sigaltstack(
    args: [u64; 6],
    thread: LifecycleThread<'_>,
    user: &mut (impl UserCopy + ?Sized),
    sp: Option<u64>,
    isa: carrick_guest_arch::GuestIsa,
) -> Option<Result<(), SignalSetupError>> {
    let [ss, old_ss] = [args[0], args[1]];
    if !setup_open(thread.page) {
        return None;
    }
    let current = thread.slot.read_altstack();
    let on_stack = if !current.is_disabled() {
        let sp = sp?;
        let top = current.sp.checked_add(current.size)?;
        sp > current.sp && sp <= top
    } else {
        false
    };
    let replacement = if ss != 0 {
        let mut bytes = [0u8; STACK_T_SIZE];
        match user.copy_in(&mut bytes, UserVa::new(ss)) {
            CopyOutcome::Done => {}
            CopyOutcome::Fault => {
                return Some(Err(SignalSetupError::Errno(
                    carrick_syscall_abi::LINUX_EFAULT,
                    false,
                )));
            }
            CopyOutcome::NotYet(request) => return Some(Err(SignalSetupError::Input(request))),
        }
        if on_stack {
            return Some(Err(SignalSetupError::Errno(
                carrick_syscall_abi::LINUX_EPERM,
                false,
            )));
        }
        let [sp, flags, size] = stack_t_words(&bytes);
        let flags = flags as u32;
        let accepted = SS_ONSTACK | SS_DISABLE | carrick_syscall_abi::LINUX_SS_AUTODISARM as u32;
        if flags & !accepted != 0 || flags & (SS_DISABLE | SS_ONSTACK) == (SS_DISABLE | SS_ONSTACK)
        {
            return Some(Err(SignalSetupError::Errno(
                carrick_syscall_abi::LINUX_EINVAL,
                false,
            )));
        }
        if flags & SS_DISABLE != 0 {
            Some(AltStack::DISABLED)
        } else {
            let stack = AltStack {
                sp,
                size,
                flags: flags & !SS_ONSTACK,
            };
            if stack.size < crate::signal::minimum_signal_stack_size(isa) {
                return Some(Err(SignalSetupError::Errno(
                    carrick_syscall_abi::LINUX_ENOMEM,
                    false,
                )));
            }
            Some(stack)
        }
    } else {
        None
    };
    if let Some(stack) = replacement {
        thread.slot.write_altstack(stack);
    }
    if old_ss != 0 {
        let (sp, flags, size) = if current.is_disabled() {
            (0, SS_DISABLE, 0)
        } else {
            (
                current.sp,
                current.flags | if on_stack { SS_ONSTACK } else { 0 },
                current.size,
            )
        };
        return Some(copy_setup_output(
            user,
            UserVa::new(old_ss),
            &stack_t_bytes([sp, u64::from(flags), size]),
            false,
        ));
    }
    Some(Ok(()))
}

/// The preimage of one clone tid output (`CloneTidOutputTransaction`): the
/// word the copyout replaces, restored if the clone backs out.
struct TidOutput {
    address: u64,
    preimage: [u8; 4],
}

impl TidOutput {
    fn capture(address: u64, user: &mut (impl UserCopy + ?Sized)) -> Option<Option<Self>> {
        if address == 0 {
            return Some(None);
        }
        let mut preimage = [0u8; 4];
        user.copy_in(&mut preimage, UserVa::new(address))
            .is_done()
            .then_some(Some(Self { address, preimage }))
    }
}

/// The parent and child tid outputs of one clone, published and rolled back
/// together, exactly as the host lane does: the parent word first, then the
/// child word; if either copyout fails, every written word gets its preimage
/// back (and the host lane then answers the forwarded clone, EFAULT included).
/// A copyout refused "not now" backs out the same way, then the clone waits
/// for the word's owner and reruns (#2359).
struct TidOutputs {
    parent: Option<TidOutput>,
    child: Option<TidOutput>,
}

impl TidOutputs {
    fn publish(&self, visible_tid: u32, user: &mut (impl UserCopy + ?Sized)) -> CopyOutcome {
        let bytes = visible_tid.to_le_bytes();
        let Some(parent) = &self.parent else {
            return self.publish_child(&bytes, user);
        };
        let written = user.copy_out(UserVa::new(parent.address), &bytes);
        if !written.is_done() {
            return written;
        }
        let child = self.publish_child(&bytes, user);
        if !child.is_done() {
            let _ = user
                .copy_out(UserVa::new(parent.address), &parent.preimage)
                .is_done();
        }
        child
    }

    fn publish_child(&self, bytes: &[u8; 4], user: &mut (impl UserCopy + ?Sized)) -> CopyOutcome {
        self.child.as_ref().map_or(CopyOutcome::Done, |child| {
            user.copy_out(UserVa::new(child.address), bytes)
        })
    }

    fn rollback(&self, user: &mut (impl UserCopy + ?Sized)) {
        for output in [&self.parent, &self.child].into_iter().flatten() {
            let _ = user
                .copy_out(UserVa::new(output.address), &output.preimage)
                .is_done();
        }
    }
}

/// `clone(flags, stack, parent_tid, tls, child_tid)` creating a thread.
/// `Some(visible tid)`: the child is born and queued.
fn serve_clone<'a>(
    args: [u64; 6],
    thread: LifecycleThread<'a>,
    native: &mut dyn LifecycleNative<'a>,
) -> Option<LifecycleOutcome> {
    if !native.has_scheduler() {
        return None;
    }
    let [flags, stack, parent_tid, tls, child_tid] = [args[0], args[1], args[2], args[3], args[4]];
    let page = thread.page;
    if !page.serves_threads()
        || flags & CSIGNAL != 0
        || flags & THREAD_CLONE_REQUIRED != THREAD_CLONE_REQUIRED
        || flags & !(THREAD_CLONE_REQUIRED | THREAD_CLONE_OPTIONAL) != 0
        || stack == 0
    {
        return None;
    }
    let placement_stack = UserVa::new(stack);
    let placement_tls = (flags & CLONE_SETTLS != 0).then_some(UserVa::new(tls));
    if !native.can_prepare_child(placement_stack, placement_tls) {
        return None;
    }
    let binding = native.binding()?;
    let caller_tid = native.visible_tid().or_else(|| thread.slot.visible_tid());
    let mm = binding.mm.raw();
    if mm == 0 {
        return None;
    }
    let flag = |bit: u64, address: u64| if flags & bit != 0 { address } else { 0 };
    let clear_child_tid = flag(CLONE_CHILD_CLEARTID, child_tid);
    let outputs = TidOutputs {
        parent: TidOutput::capture(flag(CLONE_PARENT_SETTID, parent_tid), native)?,
        child: TidOutput::capture(flag(CLONE_CHILD_SETTID, child_tid), native)?,
    };

    let state = native.task_state()?;
    let affinity = native.affinity()?;
    let managed = match native.prepare_thread_birth() {
        ThreadBirthAdmission::Unmanaged => false,
        ThreadBirthAdmission::Ready => true,
        ThreadBirthAdmission::Owned(outcome) => return Some(outcome),
    };
    let claimed = loop {
        match page.claim_any() {
            Ok(claimed) => break claimed,
            Err(TransitionError::GateClosed(_)) => {
                // A speculative claim may have been observed by an exit before
                // the gate check backed it out. That rollback also owes a wake.
                if native.lifecycle_admission_settled().is_err() {
                    native.fail_lifecycle(NativeRunFailureReason::BirthSettlement);
                }
                return Some(returned(SyscallResult::new(-11), false));
            }
            Err(error) => {
                if error == TransitionError::PoolEmpty {
                    if managed {
                        match native.prepare_thread_birth() {
                            ThreadBirthAdmission::Ready => continue,
                            ThreadBirthAdmission::Owned(outcome) => return Some(outcome),
                            ThreadBirthAdmission::Unmanaged => {
                                native.fail_lifecycle(NativeRunFailureReason::BirthSettlement);
                            }
                        }
                    }
                    // Busy, not a host birth: the host ledger stocks an
                    // unmanaged pool, and this clone reruns in ring after it.
                    // `PoolEmpty` ignores the gate; the ledger stocks only an
                    // Open one, so HostOnly and closing pages stay the host's.
                    if !managed
                        && page.gate() == GateState::Open
                        && let Some(outcome) = native.await_unmanaged_thread_stock()
                    {
                        return Some(outcome);
                    }
                    native.record_decline(LifecycleDecline::ClonePoolEmpty);
                }
                if managed {
                    native.fail_lifecycle(NativeRunFailureReason::BirthSettlement);
                }
                return None;
            }
        }
    };
    // This exact owned claim is the sole authority for Claimed -> Reserved.
    // A refused rollback is terminal; a parked exit must not be stranded, and
    // settlement must never be published as though the rollback succeeded.
    let entry = claimed.entry();
    // Bound at the clone instant (director ruling 2): the caller's mask and
    // affinity as they are now.
    let blocked = thread.slot.blocked();
    let (Some(identity), Some(child_slot)) = (page.identity(entry), native.born_slot(page, entry))
    else {
        if page.unclaim(claimed).is_err() {
            native.fail_lifecycle(NativeRunFailureReason::ClaimRollback);
        }
        if native.lifecycle_admission_settled().is_err() {
            native.fail_lifecycle(NativeRunFailureReason::BirthSettlement);
        }
        if managed {
            native.fail_lifecycle(NativeRunFailureReason::BirthSettlement);
        }
        return None;
    };
    let Ok(visible) = i32::try_from(identity.visible_tid) else {
        if page.unclaim(claimed).is_err() {
            native.fail_lifecycle(NativeRunFailureReason::ClaimRollback);
        }
        if native.lifecycle_admission_settled().is_err() {
            native.fail_lifecycle(NativeRunFailureReason::BirthSettlement);
        }
        if managed {
            native.fail_lifecycle(NativeRunFailureReason::BirthSettlement);
        }
        return None;
    };
    if !child_slot.publish_visible_tid(identity.visible_tid) {
        if page.unclaim(claimed).is_err() {
            native.fail_lifecycle(NativeRunFailureReason::ClaimRollback);
        }
        if native.lifecycle_admission_settled().is_err() {
            native.fail_lifecycle(NativeRunFailureReason::BirthSettlement);
        }
        if managed {
            native.fail_lifecycle(NativeRunFailureReason::BirthSettlement);
        }
        return None;
    }
    let Ok(record) = native.allocate_record(ThreadIdentity {
        tid: u64::from(identity.tid),
        serial: identity.thread_serial,
        mm,
        file_table: state.file_table.load(Ordering::Acquire),
        // The host binds the child's execution generation at adoption.
        generation: 0,
        affinity_source: child_slot.affinity_source(),
        affinity,
        lifecycle_page: core::ptr::from_ref(page).addr() as u64,
        control_slot: core::ptr::from_ref(child_slot).addr() as u64,
    }) else {
        // Exhausted: the identity goes back to the pool, the host clones.
        if page.unclaim(claimed).is_err() {
            native.fail_lifecycle(NativeRunFailureReason::ClaimRollback);
        }
        if native.lifecycle_admission_settled().is_err() {
            native.fail_lifecycle(NativeRunFailureReason::BirthSettlement);
        }
        return managed.then(|| returned(SyscallResult::new(-11), false));
    };
    if child_slot
        .reset_for_birth(blocked, clear_child_tid, entry)
        .is_err()
        || child_slot
            .set_affinity(carrick_core::affinity::CpuAffinity::from_words(&[affinity]))
            .is_err()
    {
        native.free_record(record);
        if page.unclaim(claimed).is_err() {
            native.fail_lifecycle(NativeRunFailureReason::ClaimRollback);
        }
        if native.lifecycle_admission_settled().is_err() {
            native.fail_lifecycle(NativeRunFailureReason::BirthSettlement);
        }
        if managed {
            native.fail_lifecycle(NativeRunFailureReason::BirthSettlement);
        }
        return None;
    }
    if managed && !native.retain_native_birth(record, child_slot) {
        native.fail_lifecycle(NativeRunFailureReason::BirthSettlement);
    }
    let published = outputs.publish(identity.visible_tid, native);
    if !published.is_done() {
        if managed && !native.release_native_birth(record, child_slot) {
            native.fail_lifecycle(NativeRunFailureReason::BirthSettlement);
        }
        native.free_record(record);
        if page.unclaim(claimed).is_err() {
            native.fail_lifecycle(NativeRunFailureReason::ClaimRollback);
        }
        if native.lifecycle_admission_settled().is_err() {
            native.fail_lifecycle(NativeRunFailureReason::BirthSettlement);
        }
        // "Not now" (#2359): the word's memory owner is busy (a sibling's
        // exit can hold the MM editor) or the page is not yet backed. The
        // clone is fully backed out, so it keeps its call: the owner makes
        // the word writable, or parks this thread on its holder's release,
        // and the clone reruns in ring. Before, the refusal returned EFAULT
        // from a clone that created no thread.
        if let CopyOutcome::NotYet(request) = published {
            match native.wait_guest_copy(request) {
                // The owner found a real fault: answer it as one.
                LifecycleOutcome::Returned { .. } => {}
                waiting => return Some(waiting),
            }
        }
        return managed.then(|| {
            returned(
                SyscallResult::from_errno(carrick_syscall_abi::LINUX_EFAULT),
                false,
            )
        });
    }

    if page.thread_born().is_none() {
        outputs.rollback(native);
        if managed && !native.release_native_birth(record, child_slot) {
            native.fail_lifecycle(NativeRunFailureReason::BirthSettlement);
        }
        native.free_record(record);
        if page.unclaim(claimed).is_err() {
            native.fail_lifecycle(NativeRunFailureReason::ClaimRollback);
        }
        if native.lifecycle_admission_settled().is_err() {
            native.fail_lifecycle(NativeRunFailureReason::BirthSettlement);
        }
        if managed {
            native.fail_lifecycle(NativeRunFailureReason::BirthSettlement);
        }
        return None;
    }

    if !managed {
        child_slot.bind_zone_record(record);
    }

    // Native context installation happens only while the new record is unpublished.
    native.prepare_child(
        record,
        ChildContext {
            result: SyscallResult::new(0),
            stack: placement_stack,
            tls: placement_tls,
            visible_tid: identity.visible_tid,
        },
    );
    let born = BornRecord {
        caller_task: binding.task.raw(),
        caller_serial: binding.thread_generation.raw(),
        clone_flags: flags,
        clear_child_tid,
        blocked,
    };
    let mut claim = Some(claimed);
    if let Err(error) = native.publish_born(ThreadBirth {
        page,
        claim: &mut claim,
        born,
        record,
        caller_tid,
        child_tid: identity.visible_tid,
    }) {
        let _ = page.try_exit();
        outputs.rollback(native);
        if managed && !native.release_native_birth(record, child_slot) {
            native.fail_lifecycle(NativeRunFailureReason::BirthSettlement);
        }
        native.free_record(record);
        if let Some(claimed) = claim
            && page.unclaim(claimed).is_err()
        {
            native.fail_lifecycle(NativeRunFailureReason::ClaimRollback);
        }
        if native.lifecycle_admission_settled().is_err() {
            native.fail_lifecycle(NativeRunFailureReason::BirthSettlement);
        }
        return Some(returned(SyscallResult::new(error), false));
    }
    if native.lifecycle_admission_settled().is_err() {
        native.fail_lifecycle(NativeRunFailureReason::BirthSettlement);
    }
    Some(returned(SyscallResult::new(visible as i64), false))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServeExitDecline {
    Floor,
    Other,
}

/// `exit(status)` of a non-leader thread that EL1 switched in, when it is
/// not the last thread: `Ok` with how the vCPU goes on, either the exit
/// itself or the owner's wait before it reruns.
fn serve_exit<'a>(
    thread: LifecycleThread<'a>,
    native: &mut dyn LifecycleNative<'a>,
) -> Result<LifecycleOutcome, ServeExitDecline> {
    let (page, slot) = (thread.page, thread.slot);
    macro_rules! decline {
        ($reason:expr) => {{
            native.record_decline($reason);
            Err(ServeExitDecline::Other)
        }};
    }
    if !page.serves_threads() {
        return decline!(LifecycleDecline::ExitDisabled);
    }
    if page.gate() != GateState::Open {
        return decline!(LifecycleDecline::ExitGate);
    }
    // The leader holds no pool entry. At the live floor, recheck terminal
    // ownership through the reservation wait path. A peer may have committed
    // its reservation since the entry check without changing the live count.
    let entry = slot.entry().ok_or_else(|| {
        native.record_decline(LifecycleDecline::ExitNoEntry);
        if carrick_core::terminal::raw_exit_at_floor(page) {
            ServeExitDecline::Floor
        } else {
            ServeExitDecline::Other
        }
    })?;
    if !matches!(
        page.state(entry.index()),
        Some((generation, EntryState::Born | EntryState::Published))
            if generation == entry.generation()
    ) {
        return decline!(LifecycleDecline::ExitEntryState);
    }
    // A registered robust list is no reason to leave the ring: no lane walks
    // it yet, and a ring-born member has no host lane to leave to (#2109).
    // A pending signal is delivered (or re-targeted) by the host.
    if page.pending().load().0 != 0 || slot.pending().load().0 != 0 {
        return decline!(LifecycleDecline::ExitPending);
    }
    let binding = native.binding().ok_or(ServeExitDecline::Other)?;
    let mm = binding.mm.raw();
    let record = native.exit_record().ok_or_else(|| {
        native.record_decline(LifecycleDecline::ExitNoCurrent);
        ServeExitDecline::Other
    })?;
    if mm == 0 {
        return decline!(LifecycleDecline::ExitNoMm);
    }
    if record.home {
        return decline!(LifecycleDecline::ExitHome);
    }
    // An adopted job's terminal completion stays with its retained runtime owner.
    if !record.unadopted && native.process_exit_binding() != Some(binding) {
        return decline!(LifecycleDecline::ExitHostAdopted);
    }
    if !record.on_cpu {
        return decline!(LifecycleDecline::ExitClaim);
    }
    if record.needs_host {
        return decline!(LifecycleDecline::ExitHostWork);
    }
    if record.cancelled {
        return decline!(LifecycleDecline::ExitCancelled);
    }
    if record.object_operation {
        return decline!(LifecycleDecline::ExitObjectOperation);
    }
    if record.identity.tid != binding.task.raw() {
        return decline!(LifecycleDecline::ExitIdentity);
    }
    let identity = carrick_core::terminal::ThreadTerminalIdentity::from_exit(
        binding,
        Some(entry),
        carrick_sched_core::process::TerminationStatus::exited(native.arguments()[0] as u32),
    )
    .ok_or(ServeExitDecline::Other)?;
    let custody = carrick_core::terminal::TerminalCustody::<
        carrick_core::terminal::Thread,
        carrick_core::terminal::Live,
    >::admitted(identity)
    .begin();
    // Core reserves the page's nonfinal membership before the native
    // handoff; a declined handoff restores that membership on drop.
    let (custody, mut membership) = custody.reserve_member(page, slot).map_err(|(_, error)| {
        native.record_decline(LifecycleDecline::ExitLast);
        match error {
            carrick_core::lifecycle::MemberMembershipError::Floor => ServeExitDecline::Floor,
            _ => ServeExitDecline::Other,
        }
    })?;
    // The member claim precedes ABI admission, so a host retirement which
    // already owns the live unit never encounters a new Exiting state.
    let mut admission = match page.begin_exit(entry) {
        Ok(admission) => admission,
        Err(_) => {
            if let Some(notification) = membership.rollback_with_wake() {
                native.exit_reservation_released(notification);
            }
            native.record_decline(LifecycleDecline::ExitAdmission);
            return Err(ServeExitDecline::Other);
        }
    };
    let clear_child_tid = slot.clear_child_tid();
    if clear_child_tid != 0 {
        let status = native.result();
        let copied = match native.copy_out(UserVa::new(clear_child_tid), &CHILD_TID_CLEAR) {
            CopyOutcome::Done => true,
            CopyOutcome::Fault => false,
            CopyOutcome::NotYet(request) => {
                // "Not now" (#2359): the word's memory owner is busy (a
                // sibling's exit holds the MM editor) or the page is not
                // yet backed. Nothing is committed, so restore the exit's
                // admission and membership and keep the call: the owner
                // makes the word writable, or parks this thread on its
                // holder's release, and the exit reruns in ring. A clone
                // thread has no host task to take the exit instead.
                native.set_result(status);
                drop(admission);
                if let Some(notification) = membership.rollback_with_wake() {
                    native.exit_reservation_released(notification);
                }
                return match native.wait_guest_copy(request) {
                    // The owner found a real fault: the host lane keeps it.
                    LifecycleOutcome::Returned { .. } => {
                        decline!(LifecycleDecline::ExitClearTidCopyout)
                    }
                    waiting => Ok(waiting),
                };
            }
        };
        let woken =
            copied && native.wake_child_tid(EntryMmKey::from_raw(mm), UserVa::new(clear_child_tid));
        if !woken {
            // The host exits the thread instead: clearing the word again
            // and waking are idempotent.
            native.set_result(status);
            drop(admission);
            if let Some(notification) = membership.rollback_with_wake() {
                native.exit_reservation_released(notification);
            }
            return decline!(if copied {
                LifecycleDecline::ExitClearTidWake
            } else {
                LifecycleDecline::ExitClearTidCopyout
            });
        }
        // Copy and wake are already complete on either release outcome.
        // Publish that progress before a requeue can expose the record. The
        // exact-address CAS preserves a newer set_tid_address if one won.
        slot.mark_child_tid_cleared_in_zone(clear_child_tid);
    }
    let Some(retirement) = custody.zone_retirement(slot, &mut membership, Some(&mut admission))
    else {
        drop(admission);
        if let Some(notification) = membership.rollback_with_wake() {
            native.exit_reservation_released(notification);
        }
        return Err(ServeExitDecline::Other);
    };
    if !native.release_current(record.reference, retirement) {
        // Requeue/refusal retains the progress already published above, so
        // the next lane cannot clear and wake the joiner a second time. A
        // refusal ahead of the scheduler's rollback still holds the reserved
        // unit: restore it here and take the waiter wake it owes, rather
        // than deferring a wake no later lane drains. After a requeue's
        // rollback this only drains the wake that rollback deferred.
        drop(admission);
        if let Some(notification) = membership.rollback_with_wake() {
            native.exit_reservation_released(notification);
        }
        return Err(ServeExitDecline::Other);
    }
    if admission.commit_with_member(slot).is_err() {
        // Unreachable (checked above; only this thread leaves Born or
        // Published that way): the host must look at this process.
        native.fail_lifecycle(NativeRunFailureReason::NativeQuarantined);
    }
    let reservation_wake = membership.publish_with_wake();
    if let Some(notification) = reservation_wake {
        native.exit_reservation_released(notification);
    }
    native.thread_exited(custody.into_verdict(page));
    let (progress, result) = if record.unadopted {
        native.run_next(SyscallResult::new(crate::sched::ETIMEDOUT_RESULT as i64))
    } else {
        // The retained runtime consumes this exact terminal handoff; another
        // guest task must not execute on the exiting job's host lease.
        (Served::Idle, SyscallResult::new(0))
    };
    Ok(LifecycleOutcome::Transferred { progress, result })
}

#[cfg(test)]
mod signal_setup_copy_contract {
    use super::*;

    struct Copy {
        writes: usize,
        fault: bool,
    }
    impl UserCopy for Copy {
        fn copy_in(&mut self, _: &mut [u8], _: UserVa) -> CopyOutcome {
            CopyOutcome::Fault
        }
        fn copy_out(&mut self, _: UserVa, _: &[u8]) -> CopyOutcome {
            self.writes += 1;
            CopyOutcome::from_completed(!self.fault)
        }
    }

    #[test]
    fn resident_setup_outputs_complete_in_shared_policy() {
        let page = ThreadLifecyclePage::new();
        let slot = ThreadControlSlot::new();
        let thread = LifecycleThread {
            page: &page,
            slot: &slot,
        };
        let mut copy = Copy {
            writes: 0,
            fault: false,
        };
        assert!(matches!(
            serve_sigprocmask([0, 0, 1, 8, 0, 0], thread, &mut copy),
            Some(Ok(false))
        ));
        assert_eq!(copy.writes, 1);
        assert!(matches!(
            serve_sigaltstack(
                [0, 1, 0, 0, 0, 0],
                thread,
                &mut copy,
                None,
                carrick_guest_arch::GuestIsa::Aarch64
            ),
            Some(Ok(()))
        ));
        assert_eq!(copy.writes, 2);
    }

    #[test]
    fn resident_setup_output_fault_is_typed_without_continuation() {
        let page = ThreadLifecyclePage::new();
        let slot = ThreadControlSlot::new();
        let thread = LifecycleThread {
            page: &page,
            slot: &slot,
        };
        let mut copy = Copy {
            writes: 0,
            fault: true,
        };
        assert!(
            matches!(serve_sigprocmask([0, 0, 1, 8, 0, 0], thread, &mut copy), Some(Err(SignalSetupError::Errno(errno, false))) if errno == carrick_syscall_abi::LINUX_EFAULT)
        );
        assert!(
            matches!(serve_sigaltstack([0, 1, 0, 0, 0, 0], thread, &mut copy, None, carrick_guest_arch::GuestIsa::Aarch64), Some(Err(SignalSetupError::Errno(errno, false))) if errno == carrick_syscall_abi::LINUX_EFAULT)
        );
        assert_eq!(copy.writes, 2);
    }
}
