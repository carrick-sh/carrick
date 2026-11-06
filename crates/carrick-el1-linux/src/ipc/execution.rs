//! Execution capability for the shared ring IPC adapter.
//!
//! Object state and descriptor ownership never depend on a saved-register
//! layout. An execution venue supplies only the live record, register access,
//! and the park/wake boundary; both admission and transfer stay in `ipc`.

use super::{IpcServed, Sched, ThreadCpu, TrapFrame, UserWord};
use carrick_el1_abi::{Counters, CurrentTask, EntryContext, SlotId};
use carrick_sched_core::object_wait::{
    ObjectStateSnapshot, ObjectWaitError, ObjectWaitKey, ObjectWaitSnapshot, ObjectWakeReport,
    OperationToken,
};
use carrick_sched_core::{WakeEffects, ZoneTables};

/// Linux call words used by IPC, independent of the ISA register layout.
/// Read inputs before publishing the result: an ISA may share its first
/// argument and return register. The legacy handback hooks belong to host-owned ARM tasks;
/// a native execution owner must never permit the adapter to hand back.
pub trait IpcFrame {
    fn argument(&self, index: usize) -> u64;
    /// Canonical Linux ordinal used for family selection.
    fn ordinal(&self) -> carrick_syscall_abi::CanonicalNr;
    /// Original ISA ordinal retained for refusal census and handback.
    fn native_number(&self) -> carrick_guest_arch::NativeOrdinal;
    fn set_result(&mut self, result: u64);
    fn mark_restart(&mut self, original_argument: u64);
    fn set_handback_number(&mut self);
}

impl IpcFrame for TrapFrame {
    fn argument(&self, index: usize) -> u64 {
        self.x[index]
    }
    fn ordinal(&self) -> carrick_syscall_abi::CanonicalNr {
        carrick_syscall_abi::CanonicalNr(self.x[8])
    }
    fn native_number(&self) -> carrick_guest_arch::NativeOrdinal {
        carrick_guest_arch::NativeOrdinal::new(self.x[8])
    }
    fn set_result(&mut self, result: u64) {
        self.x[0] = result;
    }
    fn mark_restart(&mut self, original_argument: u64) {
        self.esr = 0xfffe;
        self.far = original_argument;
    }
    fn set_handback_number(&mut self) {
        self.x[8] = super::IPC_HANDBACK_NR;
    }
}

/// Exact running-record custody and its execution transport. No object lock
/// or copy permit may survive `park` or `finish_object_wake`.
pub trait IpcExecution {
    type Context: EntryContext;
    type Frame: IpcFrame;
    fn zone(&self) -> &ZoneTables<Self::Context>;
    fn slot(&self) -> SlotId;
    fn task(&self) -> &CurrentTask;
    fn counters(&self) -> &Counters;
    fn now(&self) -> u64;
    fn ticks(&self, ns: u64) -> u64;
    fn take_object_operation(&self) -> Result<Option<OperationToken>, ObjectWaitError>;
    fn finish_object_wake(&mut self, effects: WakeEffects);
    #[allow(clippy::too_many_arguments)]
    fn park(
        &mut self,
        frame: &mut Self::Frame,
        key: ObjectWaitKey,
        snapshot: ObjectStateSnapshot,
        operation: OperationToken,
        deadline: Option<u64>,
        interrupt: Option<&mut dyn FnMut() -> bool>,
    ) -> Result<IpcServed, (ObjectWaitError, OperationToken)>;

    fn park_owner(
        &mut self,
        frame: &mut Self::Frame,
        wait: carrick_core_abi::PortalOwnerWait,
        operation: OperationToken,
    ) -> Result<IpcServed, (ObjectWaitError, OperationToken)>;

    fn observe_object(&self, key: ObjectWaitKey) -> Result<ObjectWaitSnapshot, ObjectWaitError> {
        carrick_core::wait::observe_object(self.zone(), self.slot(), key, &|owned| {
            crate::sched::object_wait::deliver_completion(self.zone(), self.slot(), owned)
        })
    }
    fn notify_object(
        &self,
        key: ObjectWaitKey,
    ) -> Result<(ObjectWakeReport, WakeEffects), ObjectWaitError> {
        carrick_core::wait::notify_object(self.zone(), self.slot(), key)
    }
    fn object_wait_expired(&self) -> bool {
        carrick_core::wait::object_wait_expired(self.zone(), self.slot())
    }
    fn may_time_park(&self) -> bool {
        carrick_core::wait::may_time_park(self.zone(), self.slot())
    }
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
        self.ticks(ns)
    }
    fn take_object_operation(&self) -> Result<Option<OperationToken>, ObjectWaitError> {
        self.take_object_operation()
    }
    fn finish_object_wake(&mut self, effects: WakeEffects) {
        self.finish_object_wake(effects);
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
        self.park(
            frame,
            enrollment.key(),
            enrollment.observed_snapshot(),
            operation,
            None,
            None,
        )
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
        let Some(resume) = carrick_core::wait::OperationResumePc::new(frame.elr.wrapping_sub(4))
        else {
            return Err((ObjectWaitError::Stale, operation));
        };
        let parked = self.park_object(frame, key, snapshot, resume, operation, deadline)?;
        // Enrollment precedes the one pending-signal probe.
        if interrupt.is_some_and(|probe| probe()) {
            self.task.linux.mark_pending_host_work();
        }
        let served = if self.task.linux.has_pending_host_work() {
            self.leave_after_object_park(parked)
        } else {
            self.resume_after_object_park(frame, parked, 0)
        };
        Ok(match served {
            Some(carrick_core::Served::Returned { switched }) => IpcServed::Returned { switched },
            Some(carrick_core::Served::Idle) | None => IpcServed::Idle,
        })
    }
}
