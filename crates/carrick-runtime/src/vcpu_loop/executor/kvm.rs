//! KVM task binding onto the shared executor submission authority.
use std::sync::Arc;

use carrick_hal::TrapError;
use carrick_hal::guest_arch_binding::GuestArchBinding;
use carrick_hal::threaded::GuestCpuState;
use carrick_kernel::kernel::objects::{ExecutionGeneration, MigratableTaskState, ThreadKey};
use carrick_kernel::kernel::{KernelContext, Scheduler, SubmissionAuthority};

use super::{PersistentTaskBinding, TaskBindingDirectory, TaskBindingResolver, TaskLoadIdentity};

pub(crate) struct KvmTaskBinding {
    identity: TaskLoadIdentity,
    arch: GuestArchBinding,
}

impl KvmTaskBinding {
    pub(crate) fn new(
        context: &KernelContext,
        state: &MigratableTaskState,
        arch: GuestArchBinding,
        generation: ExecutionGeneration,
    ) -> Result<Self, TrapError> {
        let identity = TaskLoadIdentity {
            abi: carrick_abi::LinuxGuestAbi::X86_64,
            version: 1,
            mm: context.shared().mm().id(),
            asid_generation: state.asid_generation,
        };
        if state.mm != identity.mm
            || state.cpu.guest_abi() != identity.abi
            || state.cpu.version() != identity.version
            || arch.task().task.raw().get() != context.task().key().serial.raw()
            || arch.task().execution.raw().get() != generation.raw()
        {
            return Err(TrapError::Hypervisor(
                "KVM task binding differs from the issued kernel root".to_owned(),
            ));
        }
        let binding = Self { identity, arch };
        binding.validate_task_state(state)?;
        Ok(binding)
    }
}

impl PersistentTaskBinding for KvmTaskBinding {
    fn load_identity(&self) -> TaskLoadIdentity {
        self.identity
    }

    fn validate_task_state(&self, state: &MigratableTaskState) -> Result<(), TrapError> {
        let GuestCpuState::X86_64V1(cpu) = &state.cpu else {
            return Err(TrapError::Hypervisor(
                "KVM binding received a non-x86 saved CPU".to_owned(),
            ));
        };
        if state.mm != self.identity.mm
            || state.asid_generation != self.identity.asid_generation
            || cpu.mm_generation() != state.mm.raw()
            || cpu.asid_generation() != state.asid_generation
        {
            return Err(TrapError::Hypervisor(
                "KVM binding rejected saved MM or generation".to_owned(),
            ));
        }
        self.arch.validate_x86(cpu)
    }
}

pub(crate) type KvmTaskBindingDirectory = TaskBindingDirectory<KvmTaskBinding>;

impl TaskBindingResolver<KvmTaskBinding> for KvmTaskBindingDirectory {
    fn install_scheduler(self: &Arc<Self>, scheduler: &Arc<Scheduler>) -> Result<(), TrapError> {
        TaskBindingDirectory::install_scheduler(self, scheduler)
    }

    fn resolve(
        &self,
        thread: ThreadKey,
        generation: ExecutionGeneration,
    ) -> Result<Arc<KvmTaskBinding>, TrapError> {
        self.resolve_active(thread, generation)
    }

    fn take_submission_authority(
        &self,
        thread: ThreadKey,
        generation: ExecutionGeneration,
    ) -> Option<SubmissionAuthority> {
        self.take_authority(thread, generation)
    }

    fn restore_submission_authority(
        &self,
        authority: SubmissionAuthority,
    ) -> Result<(), SubmissionAuthority> {
        self.restore_authority(authority)
    }

    fn retire(&self, thread: ThreadKey, generation: ExecutionGeneration) {
        TaskBindingDirectory::retire(self, thread, generation);
    }
}
