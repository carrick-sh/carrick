//! Scheduler custody for retained IPC, independent of the saved ISA context.

use super::frame::IpcFrame;
use crate::substrate::sched::{Sched, Served, ThreadCpu, UserWord};
use carrick_core::wait::{ObjectParked, OperationResumePc};
use carrick_el1_abi::{Counters, CurrentTask, EntryContext, SlotId};
use carrick_sched_core::object_wait::{
    ObjectStateSnapshot, ObjectWaitError, ObjectWaitKey, ObjectWaitSnapshot, ObjectWakeReport,
    OperationToken,
};
use carrick_sched_core::{WakeEffects, ZoneTables};

/// The operation owns its token across contention. Only this venue may save
/// the running context and consume its park ticket after object locks drop.
pub trait IpcScheduler<'zone> {
    type Context: EntryContext + 'static;
    type Frame: IpcFrame;
    fn zone(&self) -> &'zone ZoneTables<Self::Context>;
    fn slot(&self) -> SlotId;
    fn task(&self) -> &'zone CurrentTask;
    fn counters(&self) -> &Counters;
    fn now(&self) -> u64;
    fn ticks(&self, ns: u64) -> u64;
    fn observe_object(&self, key: ObjectWaitKey) -> Result<ObjectWaitSnapshot, ObjectWaitError>;
    fn take_object_operation(&self) -> Result<Option<OperationToken>, ObjectWaitError>;
    fn notify_object(
        &self,
        key: ObjectWaitKey,
    ) -> Result<(ObjectWakeReport, WakeEffects), ObjectWaitError>;
    fn finish_object_wake(&mut self, effects: WakeEffects);
    fn may_time_park(&self) -> bool;
    fn object_wait_expired(&self) -> bool;
    #[allow(clippy::too_many_arguments)]
    fn park_object(
        &mut self,
        frame: &Self::Frame,
        key: ObjectWaitKey,
        snapshot: ObjectStateSnapshot,
        resume: OperationResumePc,
        operation: OperationToken,
        deadline: Option<u64>,
    ) -> Result<ObjectParked<'zone, Self::Context>, (ObjectWaitError, OperationToken)>;
    fn leave_after_object_park(
        &mut self,
        parked: ObjectParked<'zone, Self::Context>,
    ) -> Option<Served>;
    fn resume_after_object_park(
        &mut self,
        frame: &mut Self::Frame,
        parked: ObjectParked<'zone, Self::Context>,
        timeout_result: u64,
    ) -> Option<Served>;
}

impl<'zone, C: ThreadCpu, U: UserWord> IpcScheduler<'zone> for Sched<'zone, C, U> {
    type Context = carrick_el1_abi::Aarch64ParkedContext;
    type Frame = carrick_el1_abi::TrapFrame;
    fn zone(&self) -> &'zone ZoneTables<Self::Context> {
        self.zone
    }
    fn slot(&self) -> SlotId {
        self.slot
    }
    fn task(&self) -> &'zone CurrentTask {
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
    fn observe_object(&self, key: ObjectWaitKey) -> Result<ObjectWaitSnapshot, ObjectWaitError> {
        self.observe_object(key)
    }
    fn take_object_operation(&self) -> Result<Option<OperationToken>, ObjectWaitError> {
        self.take_object_operation()
    }
    fn notify_object(
        &self,
        key: ObjectWaitKey,
    ) -> Result<(ObjectWakeReport, WakeEffects), ObjectWaitError> {
        self.notify_object(key)
    }
    fn finish_object_wake(&mut self, effects: WakeEffects) {
        self.finish_object_wake(effects)
    }
    fn may_time_park(&self) -> bool {
        self.may_time_park()
    }
    fn object_wait_expired(&self) -> bool {
        self.object_wait_expired()
    }
    fn park_object(
        &mut self,
        frame: &Self::Frame,
        key: ObjectWaitKey,
        snapshot: ObjectStateSnapshot,
        resume: OperationResumePc,
        operation: OperationToken,
        deadline: Option<u64>,
    ) -> Result<ObjectParked<'zone, Self::Context>, (ObjectWaitError, OperationToken)> {
        self.park_object(frame, key, snapshot, resume, operation, deadline)
    }
    fn leave_after_object_park(
        &mut self,
        parked: ObjectParked<'zone, Self::Context>,
    ) -> Option<Served> {
        self.leave_after_object_park(parked)
    }
    fn resume_after_object_park(
        &mut self,
        frame: &mut Self::Frame,
        parked: ObjectParked<'zone, Self::Context>,
        timeout_result: u64,
    ) -> Option<Served> {
        self.resume_after_object_park(frame, parked, timeout_result)
    }
}
