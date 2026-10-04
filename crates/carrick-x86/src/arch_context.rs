//! One checked saved CPU image and its exact task/root binding.
//! Snapshot conversion is shared with the existing engine; resume bytes remain
//! the validated V1 ABI, not a second syscall-continuation implementation.
use crate::X86VcpuSnapshot;
use carrick_hal::TrapError;
use carrick_hal::guest_arch_binding::{
    GuestArchBinding,
    core_arch::{ContextGeneration, MmGeneration},
};
use carrick_hal::threaded::{X86_TASK_RESUME_PAYLOAD_LEN, X86TaskCpuStateV1};

#[derive(Clone, Debug)]
pub struct X86ArchContext {
    binding: GuestArchBinding,
    state: X86TaskCpuStateV1,
}
impl X86ArchContext {
    pub fn new(binding: GuestArchBinding, state: X86TaskCpuStateV1) -> Result<Self, TrapError> {
        binding.validate_x86(&state)?;
        Ok(Self { binding, state })
    }
    pub fn capture(
        binding: GuestArchBinding,
        image: &X86VcpuSnapshot,
        resume: [u8; X86_TASK_RESUME_PAYLOAD_LEN],
    ) -> Result<Self, TrapError> {
        let context = binding.context();
        Self::new(
            binding,
            task_state_from_snapshot(image, context.mm, context.generation, resume)?,
        )
    }
    pub const fn binding(&self) -> GuestArchBinding {
        self.binding
    }
    pub const fn state(&self) -> &X86TaskCpuStateV1 {
        &self.state
    }
    pub fn hardware_image(&self) -> X86VcpuSnapshot {
        snapshot_from_task(&self.state)
    }
}

pub fn snapshot_from_task(state: &X86TaskCpuStateV1) -> X86VcpuSnapshot {
    X86VcpuSnapshot {
        gprs: *state.gprs(),
        rip: state.rip(),
        rsp: state.rsp(),
        rflags: state.rflags(),
        cr0: state.cr0(),
        cr3: state.cr3(),
        cr4: state.cr4(),
        efer: state.efer(),
        fs_base: state.fs_base(),
        gs_base: state.gs_base(),
        xsave: Some(*state.xsave()),
    }
}

/// The sole snapshot-to-V1 conversion used by carrier staging and the engine.
pub fn task_state_from_snapshot(
    snapshot: &X86VcpuSnapshot,
    mm: MmGeneration,
    context: ContextGeneration,
    resume: [u8; X86_TASK_RESUME_PAYLOAD_LEN],
) -> Result<X86TaskCpuStateV1, TrapError> {
    let xsave = snapshot.xsave.ok_or_else(|| {
        TrapError::Hypervisor("x86 snapshot did not capture complete XSAVE state".to_owned())
    })?;
    X86TaskCpuStateV1::new(
        snapshot.gprs,
        snapshot.rip,
        snapshot.rflags,
        snapshot.rsp,
        snapshot.cr0,
        snapshot.cr3,
        snapshot.cr4,
        snapshot.efer,
        snapshot.fs_base,
        snapshot.gs_base,
        mm.raw().get(),
        context.raw().get(),
        xsave.to_vec(),
        resume.to_vec(),
    )
}
