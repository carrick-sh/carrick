//! Execution capability for the shared ring IPC transfer engine.
//!
//! Object state and descriptor ownership never depend on a saved-register
//! layout. An execution venue supplies only the live record, its scheduler
//! park/wake boundary and, for host-owned ARM tasks, the legacy handback
//! words. Call words come from the shared [`GuestDispatchFrame`]; the
//! syscall-instruction rewind for a parked call comes from its
//! [`GuestDispatchFrame::operation_resume_pc`] hook.
//!
//! Only ARM's [`Sched`] implements this today. x86 builds no capability
//! (#1756 slice 1), so its in-ring pipe transfers stay the counted refusal.

use super::{IpcServed, Sched, ThreadCpu, UserWord};
use crate::dispatch::GuestDispatchFrame;
use carrick_el1_abi::{Counters, CurrentTask, EntryContext, SlotId, TrapFrame};
use carrick_sched_core::object_wait::{
    ObjectStateSnapshot, ObjectWaitError, ObjectWaitKey, ObjectWaitSnapshot, ObjectWakeReport,
    OperationToken,
};
use carrick_sched_core::{WakeEffects, ZoneTables};

/// Exact running-record custody and its execution transport. No object lock
/// or copy permit may survive [`Self::park`] or [`Self::finish_object_wake`].
pub trait IpcExecution {
    type Context: EntryContext;
    type Frame: GuestDispatchFrame;
    fn zone(&self) -> &ZoneTables<Self::Context>;
    fn slot(&self) -> SlotId;
    fn task(&self) -> &CurrentTask;
    fn counters(&self) -> &Counters;
    /// The slot's timer counter (`CNTVCT` on ARM).
    fn now(&self) -> u64;
    fn ticks(&self, ns: u64) -> u64;
    fn take_object_operation(&self) -> Result<Option<OperationToken>, ObjectWaitError>;
    fn observe_object(&self, key: ObjectWaitKey) -> Result<ObjectWaitSnapshot, ObjectWaitError>;
    /// Notify under the caller's object lock; see [`Self::finish_object_wake`].
    fn notify_object(
        &self,
        key: ObjectWaitKey,
    ) -> Result<(ObjectWakeReport, WakeEffects), ObjectWaitError>;
    /// Deliver a notification's effects once every lock is released.
    fn finish_object_wake(&mut self, effects: WakeEffects);
    fn may_time_park(&self) -> bool;
    fn object_wait_expired(&self) -> bool;
    /// Park the running record on `key` with `operation`, resuming at the
    /// frame's syscall instruction. `interrupt` is probed once after
    /// enrollment. A refusal returns the same token to the caller.
    fn park(
        &mut self,
        frame: &mut Self::Frame,
        key: ObjectWaitKey,
        snapshot: ObjectStateSnapshot,
        operation: OperationToken,
        deadline: Option<u64>,
        interrupt: Option<&mut dyn FnMut() -> bool>,
    ) -> Result<IpcServed, (ObjectWaitError, OperationToken)>;
    /// Park on an owner-memory wait, keeping its enrollment (and the owner's
    /// notification lease) live through the park.
    fn park_owner(
        &mut self,
        frame: &mut Self::Frame,
        wait: carrick_core_abi::PortalOwnerWait,
        operation: OperationToken,
    ) -> Result<IpcServed, (ObjectWaitError, OperationToken)>;
    /// ARM's existing SA_RESTART marker for a zero-progress interrupted
    /// call: the shared signal checkpoint restores `original_argument`.
    fn mark_restart(&mut self, frame: &mut Self::Frame, original_argument: u64);
    /// Hand an owned operation to a host-owned task ([`super::IPC_HANDBACK_NR`]).
    fn hand_back(&mut self, frame: &mut Self::Frame, packed_token: u64);
}

impl<C: ThreadCpu, U: UserWord> IpcExecution for Sched<'_, C, U> {
    type Context = carrick_el1_abi::Aarch64ParkedContext;
    type Frame = TrapFrame;
    fn zone(&self) -> &ZoneTables<Self::Context> {
        self.zone
    }
    fn slot(&self) -> SlotId {
        self.slot
    }
    fn task(&self) -> &CurrentTask {
        self.task
    }
    fn counters(&self) -> &Counters {
        self.counters
    }
    fn now(&self) -> u64 {
        self.cpu.now()
    }
    fn ticks(&self, ns: u64) -> u64 {
        Sched::ticks(self, ns)
    }
    fn take_object_operation(&self) -> Result<Option<OperationToken>, ObjectWaitError> {
        Sched::take_object_operation(self)
    }
    fn observe_object(&self, key: ObjectWaitKey) -> Result<ObjectWaitSnapshot, ObjectWaitError> {
        Sched::observe_object(self, key)
    }
    fn notify_object(
        &self,
        key: ObjectWaitKey,
    ) -> Result<(ObjectWakeReport, WakeEffects), ObjectWaitError> {
        Sched::notify_object(self, key)
    }
    fn finish_object_wake(&mut self, effects: WakeEffects) {
        Sched::finish_object_wake(self, effects);
    }
    fn may_time_park(&self) -> bool {
        Sched::may_time_park(self)
    }
    fn object_wait_expired(&self) -> bool {
        Sched::object_wait_expired(self)
    }
    fn park(
        &mut self,
        frame: &mut TrapFrame,
        key: ObjectWaitKey,
        snapshot: ObjectStateSnapshot,
        operation: OperationToken,
        deadline: Option<u64>,
        interrupt: Option<&mut dyn FnMut() -> bool>,
    ) -> Result<IpcServed, (ObjectWaitError, OperationToken)> {
        let Some(resume) = frame.operation_resume_pc() else {
            return Err((ObjectWaitError::Stale, operation));
        };
        let parked = self.park_object(frame, key, snapshot, resume, operation, deadline)?;
        // Enrollment precedes the single pending-signal probe. A signal
        // before enrollment is seen here; a later one owns queue intake.
        if interrupt.is_some_and(|interrupt| interrupt()) {
            self.task.linux.mark_pending_host_work();
        }
        let served = if self.task.linux.has_pending_host_work() {
            self.leave_after_object_park(parked)
        } else {
            self.resume_after_object_park(frame, parked, 0)
        };
        Ok(match served {
            Some(super::Served::Returned { switched }) => IpcServed::Returned { switched },
            Some(super::Served::Idle) | None => IpcServed::Idle,
        })
    }
    fn park_owner(
        &mut self,
        frame: &mut TrapFrame,
        wait: carrick_core_abi::PortalOwnerWait,
        operation: OperationToken,
    ) -> Result<IpcServed, (ObjectWaitError, OperationToken)> {
        let enrollment =
            carrick_core_abi::wait::PortalWaitEnrollment::for_owner(self.zone, wait.handle(), wait)
                .unwrap_or_else(|_| {
                    crate::dispatch::invalid_completion(
                        crate::dispatch::NativeInvariant::EntryBinding,
                    )
                });
        IpcExecution::park(
            self,
            frame,
            enrollment.key(),
            enrollment.observed_snapshot(),
            operation,
            None,
            None,
        )
    }
    fn mark_restart(&mut self, frame: &mut TrapFrame, original_argument: u64) {
        frame.esr = 0xfffe;
        frame.far = original_argument;
    }
    fn hand_back(&mut self, frame: &mut TrapFrame, packed_token: u64) {
        frame.x[8] = super::IPC_HANDBACK_NR;
        frame.x[0] = packed_token;
    }
}
