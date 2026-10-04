//! Typed task-to-CPU binding; no task graph or MM authority is allocated here.
//! M5 supplies the issued TaskIdentity and authenticated root from their owners.

use crate::TrapError;
use crate::threaded::{GuestCpuState, X86TaskCpuStateV1};
pub use carrick_guest_arch as core_arch;
use core_arch::{AddressContext, GuestIsa, RootGpa, TaskIdentity};

/// Exact issued identity and hardware context expected at a stopped boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuestArchBinding {
    task: TaskIdentity,
    context: AddressContext<RootGpa>,
}
impl GuestArchBinding {
    pub const fn x86(task: TaskIdentity, context: AddressContext<RootGpa>) -> Self {
        Self { task, context }
    }
    pub const fn task(self) -> TaskIdentity {
        self.task
    }
    pub const fn context(self) -> AddressContext<RootGpa> {
        self.context
    }
    pub const fn isa(self) -> GuestIsa {
        GuestIsa::X86_64
    }

    pub fn validate_x86(self, state: &X86TaskCpuStateV1) -> Result<(), TrapError> {
        if state.mm_generation() != self.context.mm.raw().get()
            || state.asid_generation() != self.context.generation.raw().get()
            || state.cr3() != self.context.root.address().raw()
        {
            return Err(TrapError::Hypervisor(
                "x86 CPU image does not match its issued MM/context/root binding".into(),
            ));
        }
        Ok(())
    }
    pub fn validate(self, state: &GuestCpuState) -> Result<(), TrapError> {
        match state {
            GuestCpuState::X86_64V1(state) => self.validate_x86(state),
            GuestCpuState::Aarch64V1(_) => Err(TrapError::Hypervisor(
                "x86 binding rejects an ARM CPU image".into(),
            )),
        }
    }
}
