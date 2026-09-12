//! Continuation readiness probes and resumption contexts.
//!
//! Owns [`ReadinessProbe`], [`SignalReadinessProbe`], [`ReservedSignal`],
//! [`ResumeContext`], [`StaleThreadCause`], and [`ContinuationWakeToken`].

use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Weak};
use std::time::Instant;

use carrick_abi::{SigBlockMask, SigSet, WaitSigMask};
use carrick_guest_mem::SharedFutexLocation;
use parking_lot::Mutex;

use super::{
    BlockedContinuation, ContinuationDetail, ContinuationEvent, ContinuationFamily, ContinuationId,
    ExecutionGeneration, FutexSource, FutexWait, MmId, OwnedFdRegistration, TaskKey, ThreadKey,
    VforkParentWait, WaitFdAuthority,
};
use crate::dispatch::{BlockingHostWrite, BlockingRecordLock, DispatchOutcome};
use crate::kernel::{Kernel, Task};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResumeContext {
    pub(in crate::vcpu_loop) thread: ThreadKey,
    pub(in crate::vcpu_loop) task: TaskKey,
    pub(in crate::vcpu_loop) execution: ExecutionGeneration,
    pub(in crate::vcpu_loop) mm: MmId,
    pub(in crate::vcpu_loop) asid_generation: u64,
}

impl ResumeContext {
    #[cfg(test)]
    pub(in crate::vcpu_loop) fn for_test(
        thread: ThreadKey,
        task: TaskKey,
        execution: ExecutionGeneration,
        mm: MmId,
        asid_generation: u64,
    ) -> Self {
        Self {
            thread,
            task,
            execution,
            mm,
            asid_generation,
        }
    }
}

/// Why a blocked continuation refused to resume on the thread that woke it.
///
/// A resume is a generation-exact hand-off: the lease that resumes must be
/// the continuation's own thread at the successor of the lease that last held
/// the continuation — `+1` when the wake landed during that lease's
/// settlement, `+2` when the wake bumped a parked thread. A lease that
/// re-parks without consuming re-stamps the authority
/// (`BlockedContinuation::carry_through_lease`), so intervening control
/// quanta or refused admissions never widen the window. Naming which check failed is what
/// lets a live refusal be attributed to a scheduling defect instead of being
/// read as an opaque `StaleThread`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaleThreadCause {
    /// `resume_continuation`: the lease is not the continuation thread, or
    /// its generation is not the continuation generation's +1/+2 successor.
    LeaseSuccession {
        lease_thread: ThreadKey,
        continuation_thread: ThreadKey,
        original_generation: u64,
        resumed_generation: u64,
    },
    /// `authorize_resume`: the resume context names a different thread,
    /// task or execution generation than the continuation authority.
    ResumeIdentity {
        resume_thread: ThreadKey,
        resume_execution: u64,
        authority_thread: ThreadKey,
        authority_execution: u64,
    },
    KernelGone,
    TaskNotLive,
    ThreadNotSchedulable,
    ContextUnavailable,
    ContextMismatch,
}

#[derive(Clone, Copy, Debug)]
enum ReservedSignalSource {
    Kernel(crate::kernel::objects::SignalDequeue),
    HostSlot {
        tid: i32,
        dequeued: crate::kernel::objects::SignalDequeue,
    },
}

struct ReservedSignalInner {
    authority: crate::kernel::objects::SignalAuthority,
    signum: i32,
    siginfo: Option<crate::linux_abi::LinuxSiginfo>,
    job_control_generation: Option<crate::kernel::objects::JobControlStopInvalidationGeneration>,
    action_generation: u64,
    mask_generation: u64,
    action: carrick_abi::LinuxSigaction,
    effective_mask: SigSet,
    persistent_restore: SigSet,
    temporary: WaitSigMask,
    source: ReservedSignalSource,
    settlement: AtomicU8,
}

impl Drop for ReservedSignalInner {
    fn drop(&mut self) {
        if self.settlement.load(Ordering::Acquire) != 0 {
            return;
        }
        match self.source {
            ReservedSignalSource::Kernel(dequeued) => {
                self.authority.requeue_reserved(dequeued);
            }
            ReservedSignalSource::HostSlot { dequeued, .. } => {
                self.authority.requeue_reserved(dequeued);
            }
        }
    }
}

#[derive(Clone)]
pub struct ReservedSignal(Arc<ReservedSignalInner>);

impl PartialEq for ReservedSignal {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for ReservedSignal {}

impl std::fmt::Debug for ReservedSignal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReservedSignal")
            .field("signum", &self.signum())
            .field("action_generation", &self.action_generation())
            .field("host_slot_tid", &self.host_slot_tid())
            .finish_non_exhaustive()
    }
}

impl ReservedSignal {
    #[cfg(test)]
    pub(crate) fn kernel(
        authority: crate::kernel::objects::SignalAuthority,
        dequeued: crate::kernel::objects::SignalDequeue,
        action_generation: u64,
        action: carrick_abi::LinuxSigaction,
        persistent_restore: SigSet,
    ) -> Self {
        let mask_generation = authority.signal_state_generation();
        let effective_mask = authority.blocked();
        Self(Arc::new(ReservedSignalInner {
            authority,
            signum: dequeued.pending.signal.raw(),
            siginfo: dequeued.pending.siginfo,
            job_control_generation: dequeued.job_control_generation,
            action_generation,
            mask_generation,
            action,
            effective_mask,
            persistent_restore,
            temporary: WaitSigMask::NONE,
            source: ReservedSignalSource::Kernel(dequeued),
            settlement: AtomicU8::new(0),
        }))
    }

    pub(in crate::vcpu_loop) fn from_kernel_reservation(
        authority: crate::kernel::objects::SignalAuthority,
        reservation: crate::kernel::objects::SignalWaitReservation,
    ) -> Self {
        let dequeue = reservation.dequeue();
        let source = match reservation.origin() {
            crate::kernel::objects::SignalReservationOrigin::Kernel => {
                ReservedSignalSource::Kernel(dequeue)
            }
            crate::kernel::objects::SignalReservationOrigin::HostSlot { tid } => {
                ReservedSignalSource::HostSlot {
                    tid,
                    dequeued: dequeue,
                }
            }
        };
        Self(Arc::new(ReservedSignalInner {
            authority,
            signum: reservation.signum(),
            siginfo: dequeue.pending.siginfo,
            job_control_generation: dequeue.job_control_generation,
            action_generation: reservation.action_generation(),
            mask_generation: reservation.mask_generation(),
            action: reservation.action(),
            effective_mask: reservation.effective_mask(),
            persistent_restore: reservation.persistent_restore(),
            temporary: reservation.temporary(),
            source,
            settlement: AtomicU8::new(0),
        }))
    }

    pub fn signum(&self) -> i32 {
        self.0.signum
    }

    pub fn action(&self) -> carrick_abi::LinuxSigaction {
        self.0.action
    }

    pub fn action_generation(&self) -> u64 {
        self.0.action_generation
    }

    pub fn mask_generation(&self) -> u64 {
        self.0.mask_generation
    }

    pub fn siginfo(&self) -> Option<crate::linux_abi::LinuxSiginfo> {
        self.0.siginfo
    }

    pub fn persistent_restore(&self) -> SigSet {
        self.0.persistent_restore
    }

    pub fn effective_mask(&self) -> SigSet {
        self.0.effective_mask
    }

    pub fn temporary_mask(&self) -> WaitSigMask {
        self.0.temporary
    }

    pub fn host_slot_tid(&self) -> Option<i32> {
        match self.0.source {
            ReservedSignalSource::HostSlot { tid, .. } => Some(tid),
            ReservedSignalSource::Kernel(_) => None,
        }
    }

    pub(crate) fn restore_persistent_after_default_action(&self) {
        self.0.authority.set_blocked(self.0.persistent_restore);
        self.0.authority.arm_restore_mask(None);
    }

    pub(crate) fn job_control_generation(
        &self,
    ) -> Option<crate::kernel::objects::JobControlStopInvalidationGeneration> {
        self.0.job_control_generation
    }

    /// Transfer the exact dequeued instance to guest delivery. Only the first
    /// caller can consume it; cancellation/drop before this point requeues it.
    pub fn consume(&self) -> bool {
        self.0
            .settlement
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContinuationWakeToken {
    pub(in crate::vcpu_loop) continuation: ContinuationId,
    pub(in crate::vcpu_loop) thread: ThreadKey,
    pub(in crate::vcpu_loop) thread_serial: u64,
    pub(in crate::vcpu_loop) execution: ExecutionGeneration,
    pub(in crate::vcpu_loop) execution_raw: u64,
    pub(in crate::vcpu_loop) mm_generation: u64,
    pub(in crate::vcpu_loop) asid_generation: u64,
    pub(in crate::vcpu_loop) resource_generation: u64,
    pub(in crate::vcpu_loop) registration_generation: u64,
}

impl ContinuationWakeToken {
    pub const fn continuation(self) -> ContinuationId {
        self.continuation
    }

    #[cfg(test)]
    pub(in crate::vcpu_loop) fn with_thread_serial_offset_for_test(mut self, offset: u64) -> Self {
        self.thread_serial += offset;
        self
    }

    #[cfg(test)]
    pub(in crate::vcpu_loop) fn with_execution_generation_offset_for_test(
        mut self,
        offset: u64,
    ) -> Self {
        self.execution_raw += offset;
        self
    }

    #[cfg(test)]
    pub(in crate::vcpu_loop) fn with_resource_generation_offset_for_test(
        mut self,
        offset: u64,
    ) -> Self {
        self.resource_generation += offset;
        self
    }

    #[cfg(test)]
    pub(in crate::vcpu_loop) fn with_mm_generation_offset_for_test(mut self, offset: u64) -> Self {
        self.mm_generation += offset;
        self
    }

    #[cfg(test)]
    pub(in crate::vcpu_loop) fn with_asid_generation_offset_for_test(
        mut self,
        offset: u64,
    ) -> Self {
        self.asid_generation += offset;
        self
    }

    #[cfg(test)]
    pub(in crate::vcpu_loop) fn with_registration_generation_offset_for_test(
        mut self,
        offset: u64,
    ) -> Self {
        self.registration_generation += offset;
        self
    }
}

#[derive(Clone, Debug)]
pub(in crate::vcpu_loop) enum ReadinessProbe {
    Futex {
        table: FutexSource,
        wait: FutexWait,
        deadline: Option<Instant>,
    },
    Fds {
        registrations: Vec<OwnedFdRegistration>,
        file_table: Arc<crate::kernel::objects::FileTable>,
        fd_authority: WaitFdAuthority,
        deadline: Option<Instant>,
    },
    SharedWord {
        location: SharedFutexLocation,
        generation: FutexWait,
        value: u32,
        deadline: Option<Instant>,
    },
    HostWrite {
        host_fd: i32,
        write: Arc<Mutex<BlockingHostWrite>>,
        completion: Arc<Mutex<Option<DispatchOutcome>>>,
    },
    RecordLock {
        lock: Arc<BlockingRecordLock>,
        completion: Arc<Mutex<Option<DispatchOutcome>>>,
    },
    TaskWake {
        task: Weak<Task>,
        observed: u64,
        deadline: Option<Instant>,
    },
    Vfork {
        wait: VforkParentWait,
    },
    Timer {
        deadline: Instant,
    },
    Passive {
        deadline: Option<Instant>,
    },
}

#[derive(Clone, Debug)]
pub(in crate::vcpu_loop) struct SignalReadinessProbe {
    pub(in crate::vcpu_loop) kernel: Weak<Kernel>,
    pub(in crate::vcpu_loop) task_ref: Weak<Task>,
    pub(in crate::vcpu_loop) observed_task_wake: u64,
    pub(in crate::vcpu_loop) observed_task_event: u64,
    pub(in crate::vcpu_loop) task: TaskKey,
    pub(in crate::vcpu_loop) thread: ThreadKey,
    pub(in crate::vcpu_loop) temporary: Option<WaitSigMask>,
    pub(in crate::vcpu_loop) family: ContinuationFamily,
    pub(in crate::vcpu_loop) wait_set: Option<SigSet>,
    pub(in crate::vcpu_loop) signal_wait_block: Option<SigBlockMask>,
}

impl SignalReadinessProbe {
    pub(in crate::vcpu_loop) fn from_continuation(continuation: &BlockedContinuation) -> Self {
        let state = continuation.state();
        let (wait_set, signal_wait_block) = match state.detail {
            ContinuationDetail::Signals {
                wait_set,
                block_mask,
            } => (Some(wait_set), Some(block_mask)),
            _ => (None, None),
        };
        // A process wait subscribes to the parent's task wake, and
        // `event_after_task_wake` turns ANY such edge into `Ready` for it. It
        // must therefore subscribe at the generation its child scan observed,
        // not at the capture's re-reading, or `subscribe_wake` enrols past the
        // exit edge that already fired. See `ChildWaitPrecheck`.
        let observed_task_wake = match state.detail {
            ContinuationDetail::Process { precheck, .. } => precheck.wake_generation(),
            _ => state.authority.task_wake_generation,
        };
        Self {
            kernel: state.authority.kernel.clone(),
            task_ref: state.authority.task_ref.clone(),
            observed_task_wake,
            observed_task_event: state.authority.task_event_generation,
            task: state.authority.task,
            thread: state.authority.thread,
            temporary: state.signal_masks.temporary(),
            family: continuation.family(),
            wait_set,
            signal_wait_block,
        }
    }

    /// Interpret an actual task-wake edge. Process waits deliberately use a
    /// generic task wake as a redispatch hint because the authoritative child
    /// or host-process state is consumed by the syscall itself. That rule must
    /// not leak into enrollment's state-only readiness sample: doing so makes
    /// every quiet wait4 continuation immediately runnable and livelocks the
    /// carrier without any producer event.
    pub(in crate::vcpu_loop) fn event_after_task_wake(&self) -> Option<ContinuationEvent> {
        if matches!(
            self.family,
            ContinuationFamily::WaitOnProcExit
                | ContinuationFamily::WaitOnProcState
                | ContinuationFamily::WaitOnHvpatchChild
        ) {
            return Some(ContinuationEvent::Ready);
        }
        self.event()
    }

    /// Sample authoritative signal state without assuming that a producer
    /// edge occurred. This is safe to call during continuation enrollment.
    pub(in crate::vcpu_loop) fn event(&self) -> Option<ContinuationEvent> {
        let kernel = self.kernel.upgrade()?;
        let context = kernel.context(self.task.id, self.thread.tid).ok()?;
        if context.task().key() != self.task || context.thread().key() != self.thread {
            return None;
        }
        let authority = context.signal_authority();
        let host_signum = crate::host_signal::take_pending_for(self.thread.tid.raw());
        if self.family == ContinuationFamily::VforkParent {
            // Linux waits for vfork completion in TASK_KILLABLE. That means
            // only SIGKILL may interrupt the wait; caught signals and other
            // default actions stay pending until the exact child exec/exit
            // gate releases the parent. Reserve SIGKILL as a typed signal
            // event so the delivery tail terminates the parent without ever
            // manufacturing a successful vfork return.
            if host_signum != 0 && host_signum != crate::linux_abi::LINUX_SIGKILL {
                crate::host_signal::publish_pending_for(self.thread.tid.raw(), host_signum);
            }
            let kill_only = WaitSigMask::Replace(
                SigSet::EMPTY
                    .complement()
                    .without(crate::linux_abi::LINUX_SIGKILL),
            );
            let reservation = if host_signum == crate::linux_abi::LINUX_SIGKILL {
                authority.reserve_deliverable_for_wait_with_host_slot(
                    kill_only,
                    self.thread.tid.raw(),
                    host_signum,
                )
            } else {
                authority.reserve_deliverable_for_wait(kill_only)
            };
            return reservation.map(|reservation| {
                ContinuationEvent::ReservedSignal(ReservedSignal::from_kernel_reservation(
                    authority,
                    reservation,
                ))
            });
        }
        if let Some(wait_set) = self.wait_set {
            if host_signum != 0 && wait_set.contains(host_signum) {
                crate::host_signal::publish_pending_for(self.thread.tid.raw(), host_signum);
                return Some(ContinuationEvent::Ready);
            }
            if authority.has_pending_in(wait_set) {
                if host_signum != 0 {
                    crate::host_signal::publish_pending_for(self.thread.tid.raw(), host_signum);
                }
                return Some(ContinuationEvent::Ready);
            }
            let blocked =
                SigSet::from_raw(self.signal_wait_block.unwrap_or(SigBlockMask::NONE).raw());
            let reservation = if host_signum == 0 {
                authority.reserve_deliverable_for_wait(WaitSigMask::Replace(blocked))
            } else {
                authority.reserve_deliverable_for_wait_with_host_slot(
                    WaitSigMask::Replace(blocked),
                    self.thread.tid.raw(),
                    host_signum,
                )
            };
            return reservation.map(|reservation| {
                ContinuationEvent::ReservedSignal(ReservedSignal::from_kernel_reservation(
                    authority,
                    reservation,
                ))
            });
        }
        let temporary = self.temporary.unwrap_or(WaitSigMask::NONE);
        let reservation = if host_signum == 0 {
            authority.reserve_deliverable_for_wait(temporary)
        } else {
            authority.reserve_deliverable_for_wait_with_host_slot(
                temporary,
                self.thread.tid.raw(),
                host_signum,
            )
        };
        reservation.map(|reservation| {
            ContinuationEvent::ReservedSignal(ReservedSignal::from_kernel_reservation(
                authority,
                reservation,
            ))
        })
    }
}

impl ReadinessProbe {
    /// Whether a cycle of the carrier reactor has to touch this registration to
    /// build its `pollfd` array. Everything else — a futex, a timer, a child
    /// wait, a vfork release — is woken by its producer or by its deadline, and
    /// re-examining it on every cycle is the O(live blocked tasks) scan
    /// [`ReactorWorkSet`] exists to remove.
    pub(in crate::vcpu_loop) const fn contributes_pollfds(&self) -> bool {
        matches!(self, Self::Fds { .. } | Self::HostWrite { .. })
    }

    pub(in crate::vcpu_loop) fn from_continuation(continuation: &BlockedContinuation) -> Self {
        let state = continuation.state();
        match &state.detail {
            ContinuationDetail::Fds {
                registrations,
                file_table,
                fd_authority,
                ..
            }
            | ContinuationDetail::Select {
                registrations,
                file_table,
                fd_authority,
                ..
            } => Self::Fds {
                registrations: registrations.clone(),
                file_table: Arc::clone(file_table),
                fd_authority: fd_authority.clone(),
                deadline: state.deadline,
            },
            ContinuationDetail::SharedFutex {
                location,
                generation,
                value,
                ..
            }
            | ContinuationDetail::SharedWord {
                location,
                generation,
                value,
                ..
            } => Self::SharedWord {
                location: *location,
                generation: generation.clone(),
                value: *value,
                deadline: state.deadline,
            },
            ContinuationDetail::HostWrite(write) => {
                let host_fd = write.lock().host_fd();
                Self::HostWrite {
                    host_fd,
                    write: Arc::clone(write),
                    completion: Arc::clone(&state.producer_completion),
                }
            }
            // Enroll against the generation the CHILD SCAN observed, never
            // the one the capture re-read: the capture happens after the
            // syscall has already decided to block, so a child that exits in
            // that window publishes its wake edge before the reading and the
            // probe then compares equal forever. See `ChildWaitPrecheck`.
            ContinuationDetail::Process { precheck, .. } => Self::TaskWake {
                task: state.authority.task_ref.clone(),
                observed: precheck.wake_generation(),
                deadline: state.deadline,
            },
            // A signal park must hear `task.wake()` — THE single door — like
            // every other park: a thread-directed post to a FORKED task's
            // sigsuspend/sigtimedwait park has no other prompt vehicle (the
            // root task's raw lane masked this; the container lane's child
            // task saw its handler run only on a late fallback sweep,
            // sigsuspendxthread `suspended_thread_woke=false`).
            ContinuationDetail::Signals { .. } => {
                let task = state.authority.task_ref.clone();
                let observed = state.authority.task_wake_generation;
                Self::TaskWake {
                    task,
                    observed,
                    deadline: state.deadline,
                }
            }
            ContinuationDetail::Vfork { wait, .. } => Self::Vfork { wait: wait.clone() },
            ContinuationDetail::Sleep => state
                .deadline
                .map_or(Self::Passive { deadline: None }, |deadline| Self::Timer {
                    deadline,
                }),
            ContinuationDetail::Futex { wait, .. } => state.private_futex.as_ref().map_or(
                Self::Passive {
                    deadline: state.deadline,
                },
                |table| Self::Futex {
                    table: table.clone(),
                    wait: wait.clone(),
                    deadline: state.deadline,
                },
            ),
            ContinuationDetail::RecordLock(lock) => Self::RecordLock {
                lock: Arc::clone(lock),
                completion: Arc::clone(&state.producer_completion),
            },
        }
    }

    pub(in crate::vcpu_loop) fn poll(&mut self) -> Option<ContinuationEvent> {
        let deadline_event = |deadline: Option<Instant>| {
            deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
                .then_some(ContinuationEvent::Timeout)
        };
        match self {
            Self::Futex {
                table,
                wait,
                deadline,
            } => {
                if let Some(event) = deadline_event(*deadline) {
                    return Some(event);
                }
                // Never dequeue here: the reactor's poll is a pure read and
                // the queue slot must stay live for `FUTEX_WAKE` to count it.
                table.0.is_woken(wait).then_some(ContinuationEvent::Ready)
            }
            Self::Fds {
                registrations,
                deadline,
                ..
            } => {
                if let Some(event) = deadline_event(*deadline) {
                    return Some(event);
                }
                if registrations.is_empty() {
                    return None;
                }
                let mut pollfds = registrations
                    .iter()
                    .map(|registration| libc::pollfd {
                        fd: registration.fd.as_raw_fd(),
                        events: registration.events,
                        revents: 0,
                    })
                    .collect::<Vec<_>>();
                let ready =
                    unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, 0) };
                (ready > 0).then_some(ContinuationEvent::Ready)
            }
            Self::SharedWord {
                location,
                generation,
                value,
                deadline,
            } => {
                if let Some(event) = deadline_event(*deadline) {
                    return Some(event);
                }
                if generation.is_woken() {
                    return Some(ContinuationEvent::Ready);
                }
                // SAFETY: the continuation pins the exact MM generation and
                // owns the wait token; cancellation precedes MM teardown.
                let current = unsafe {
                    (location.wait_addr().raw() as *const std::sync::atomic::AtomicU32)
                        .as_ref()
                        .map(|word| word.load(Ordering::Acquire))
                };
                current
                    .is_none_or(|current| current != *value)
                    .then_some(ContinuationEvent::Ready)
            }
            Self::HostWrite {
                write, completion, ..
            } => {
                let outcome = {
                    let mut write = write.lock();
                    match crate::dispatch::drive_blocking_host_write(&mut write) {
                        crate::dispatch::BlockingHostWriteStep::Done(outcome) => Some(outcome),
                        crate::dispatch::BlockingHostWriteStep::Wait => None,
                    }
                };
                if let Some(outcome) = outcome {
                    *completion.lock() = Some(outcome);
                    Some(ContinuationEvent::Ready)
                } else {
                    None
                }
            }
            Self::RecordLock { lock, completion } => {
                let outcome = match crate::dispatch::try_drive_blocking_record_lock(lock) {
                    crate::dispatch::BlockingRecordLockStep::Done(outcome) => Some(outcome),
                    crate::dispatch::BlockingRecordLockStep::Wait => None,
                };
                if let Some(outcome) = outcome {
                    *completion.lock() = Some(outcome);
                    Some(ContinuationEvent::Ready)
                } else {
                    None
                }
            }
            Self::TaskWake {
                task,
                observed,
                deadline,
            } => {
                if let Some(event) = deadline_event(*deadline) {
                    return Some(event);
                }
                let current = task
                    .upgrade()
                    .map_or(u64::MAX, |task| task.wake_generation());
                (current != *observed).then_some(ContinuationEvent::Ready)
            }
            Self::Vfork { wait } => wait
                .released_reason()
                .is_some()
                .then_some(ContinuationEvent::Ready),
            Self::Timer { deadline } => {
                (Instant::now() >= *deadline).then_some(ContinuationEvent::Timeout)
            }
            Self::Passive { deadline } => deadline_event(*deadline),
        }
    }
}
