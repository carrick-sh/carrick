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
        if state.gprs()[7] != state.rsp()
            || state.mm_generation() != self.context.mm.raw().get()
            || state.asid_generation() != self.context.generation.raw().get()
            || state.cr3() != self.context.root.address().raw()
        {
            return Err(TrapError::Hypervisor(
                "x86 CPU image does not match its issued MM/context/root binding".into(),
            ));
        }
        Ok(())
    }
    /// Admit `successor` as this binding's `execve` replacement. Exec keeps
    /// the carrier and the task and replaces the address space, so a
    /// successor naming another task, or this binding's own MM, is refused.
    /// The admitted successor validates only its own CPU image; this binding
    /// keeps refusing it.
    pub fn exec_successor(self, successor: Self) -> Result<Self, TrapError> {
        if successor.task.carrier != self.task.carrier
            || successor.task.task != self.task.task
            || successor.context.mm == self.context.mm
        {
            return Err(TrapError::Hypervisor(
                "x86 exec successor must keep its carrier and task and replace its MM".into(),
            ));
        }
        Ok(successor)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threaded::{X86_TASK_RESUME_MAGIC, X86_TASK_RESUME_PAYLOAD_LEN, X86_TASK_XSAVE_LEN};
    use core::num::NonZeroU64;
    use core_arch::{
        CarrierGeneration, ContextGeneration, ExecutionGeneration, FrameGpa, MmGeneration,
        TaskSerial,
    };

    fn binding(task: u64, execution: u64, root: u64, mm: u64, asid: u64) -> GuestArchBinding {
        let nz = |raw| NonZeroU64::new(raw).unwrap();
        GuestArchBinding::x86(
            TaskIdentity {
                carrier: CarrierGeneration::new(nz(1)),
                task: TaskSerial::new(nz(task)),
                execution: ExecutionGeneration::new(nz(execution)),
            },
            AddressContext {
                root: RootGpa::page_aligned(FrameGpa::new(root)).unwrap(),
                mm: MmGeneration::new(nz(mm)),
                generation: ContextGeneration::new(nz(asid)),
            },
        )
    }

    fn image(binding: GuestArchBinding) -> X86TaskCpuStateV1 {
        let mut resume = [0u8; X86_TASK_RESUME_PAYLOAD_LEN];
        resume[56..64].copy_from_slice(&X86_TASK_RESUME_MAGIC.to_le_bytes());
        let mut gprs = [0; 16];
        gprs[7] = 0x9000;
        X86TaskCpuStateV1::new(
            gprs,
            0x40_0000,
            0x202,
            gprs[7],
            0x8000_0031,
            binding.context().root.address().raw(),
            0x40620,
            0xd01,
            0,
            0,
            binding.context().mm.raw().get(),
            binding.context().generation.raw().get(),
            vec![0; X86_TASK_XSAVE_LEN],
            resume.to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn exec_successor_keeps_the_task_replaces_the_mm_and_refuses_the_stale_image() {
        let predecessor = binding(7, 1, 0x7000, 20, 1);
        let successor = binding(7, 1, 0x9000, 21, 2);
        let admitted = predecessor.exec_successor(successor).unwrap();
        assert_eq!(admitted, successor);
        admitted.validate_x86(&image(successor)).unwrap();
        assert!(admitted.validate_x86(&image(predecessor)).is_err());
        assert!(predecessor.validate_x86(&image(successor)).is_err());

        assert!(
            predecessor
                .exec_successor(binding(8, 1, 0x9000, 21, 2))
                .is_err(),
            "exec keeps the task"
        );
        assert!(
            predecessor
                .exec_successor(binding(7, 2, 0x9000, 20, 2))
                .is_err(),
            "exec replaces the MM"
        );
    }
}
