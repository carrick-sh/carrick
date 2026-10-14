//! OS personality trait and execution flow primitives.

pub use carrick_core::personality::UserCopy;
use carrick_el1::isa::x86::Kernel;
use carrick_el1::isa::x86::context::{
    native::{CpuBinding, NativeFrame},
    scheduler::{InterruptFrame, XsaveArea},
};
use carrick_el1_abi::{Counters, CurrentTask};
use carrick_guest_arch::UserVa;
pub use carrick_personality_api::{
    CallContext, EntryDecodeError, PersonalityAbi, TerminationStatus,
};

pub use carrick_sched_core::process::TerminationKind;

/// Request to terminate the root process with a wait status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminationRequest {
    status: TerminationStatus,
}

impl TerminationRequest {
    pub const fn new(status: TerminationStatus) -> Self {
        Self { status }
    }

    pub const fn status(self) -> TerminationStatus {
        self.status
    }
}

/// Token representing a suspended execution continuation (placeholder for
/// future typed continuation key).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OwnedContinuation {
    pub key: u64,
}

impl OwnedContinuation {
    pub const fn new(key: u64) -> Self {
        Self { key }
    }
}

/// Control flow outcome from dispatching an OS personality service.
pub enum ControlFlow<R, C = OwnedContinuation> {
    /// Return to user mode with a personality return value.
    Return(R),
    /// Suspend the current execution context and yield execution capacity.
    Suspend(C),
    /// Terminate the task with an exit status.
    Terminate(TerminationRequest),
}

/// Carrier execution context provided to the personality dispatch entry.
pub struct ExecutionContext<'a> {
    pub task: &'static CurrentTask,
    pub binding: &'a CpuBinding,
    pub counters: &'a Counters,
    pub frame: &'a mut NativeFrame,
    pub xsave: &'a mut XsaveArea,
}

/// Trait implemented by an OS personality running on the generic carrier,
/// building on `carrick_core::personality::PersonalityAbi`.
pub trait Personality: PersonalityAbi<Kernel> + 'static + Default {
    type Return;
    type Continuation;

    fn is_counted_call(&self, _call: &Self::Call) -> bool {
        true
    }
    fn call_stack(&self, call: &Self::Call) -> UserVa;
    fn dispatch(
        &mut self,
        call: Self::Call,
        cx: &mut ExecutionContext<'_>,
    ) -> ControlFlow<Self::Return, Self::Continuation>;

    fn on_irq_return(&mut self, _frame: &mut InterruptFrame, _xsave: &mut XsaveArea) {}

    fn on_user_return(&mut self, _frame: &mut NativeFrame, _xsave: &mut XsaveArea) {}

    fn has_pending_host_work(&mut self, _task: &CurrentTask) -> bool {
        false
    }

    fn handle_unrecognized_call(
        &mut self,
        frame: &mut NativeFrame,
        _task: &CurrentTask,
        _binding: &CpuBinding,
        _counters: &Counters,
    ) {
        crate::entry::doorbell(carrick_el1::isa::x86::context::native::FATAL_PORT, frame);
        crate::entry::halt();
    }

    fn handle_page_fault(_frame: &mut crate::entry::PageFaultStack, _fpstate: &XsaveArea) -> u64 {
        1
    }

    fn on_counted_completion(&mut self, _binding: &CpuBinding) {}

    fn schedule(slot: carrick_sched_core::SlotId) -> !;

    fn fixture_hold_check(
        &self,
        _table: &carrick_el1::isa::x86::context::native::ShootdownTable,
        _target_mode: u32,
    ) -> Result<(), carrick_el1::isa::ArchError> {
        Ok(())
    }

    fn on_timer(&mut self, _slot: carrick_sched_core::SlotId) {}

    fn on_boot() {}
}
