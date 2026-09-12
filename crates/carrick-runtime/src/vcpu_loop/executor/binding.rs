//! Persistent task binding and registration directory for the HVPatch executor.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::Mutex;

use carrick_abi::LinuxGuestAbi;
use carrick_fatal::carrick_fatal;

#[cfg(test)]
use crate::kernel::SchedulerError;
use crate::kernel::objects::{
    ExecutionFailure, ExecutionGeneration, ExecutorId, MigratableTaskState, ThreadExecutionLease,
    ThreadKey,
};
use crate::kernel::{MmId, Scheduler, SubmissionAuthority};
use crate::trap::TrapError;
use crate::vcpu_loop::{
    ContainerJobReservation, HvpatchLoopResult, PersistentProcessMemberPublication,
    ProcessPhysicalRetirement,
};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use crate::vcpu_loop::{HvpatchProcessFailpoint, check_hvpatch_process_failpoint};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskLoadIdentity {
    pub abi: LinuxGuestAbi,
    pub version: u16,
    pub mm: MmId,
    pub asid_generation: u64,
}

pub trait PersistentTaskBinding {
    fn load_identity(&self) -> TaskLoadIdentity;

    fn validate_task_state(&self, state: &MigratableTaskState) -> Result<(), TrapError>;

    fn after_terminal_settlement(&self) {}

    /// The scheduler settled this thread against a TERMINAL target: nothing
    /// will run it again, so its job publishes here or nowhere.
    fn after_reaped_settlement(&self) {
        self.after_terminal_settlement();
    }

    fn after_executor_failure_settlement(&self) {
        self.after_terminal_settlement();
    }

    /// Whether this binding's address space has stopped admitting loads.
    ///
    /// Asked only to classify a REJECTED load: `true` means another thread in
    /// the group is retiring the address space (an `execve` or an exit), which
    /// on Linux terminates this thread. Backends without a retiring address
    /// space answer `false` and keep the failure fatal.
    fn address_space_is_retiring(&self) -> bool {
        false
    }

    fn mark_exec_transferred(&self) -> Result<(), TrapError> {
        Err(TrapError::Hypervisor(
            "task binding has no exec-transfer terminal authority".to_owned(),
        ))
    }

    fn take_address_space_retirement(
        &self,
    ) -> Option<crate::hvpatch::PendingAddressSpaceRetirement> {
        None
    }

    fn retire_detached_address_space(
        &self,
        _root_ticket: Option<crate::hvpatch::Stage1RootRetirementTicket>,
    ) -> Result<Option<crate::hvpatch::Stage1RootRetirementReceipt>, TrapError> {
        Err(TrapError::Hypervisor(
            "task binding has no detached address-space cleanup authority".to_owned(),
        ))
    }

    fn retire_detached_shared_mm_edge(&self) -> Result<(), TrapError> {
        Err(TrapError::Hypervisor(
            "task binding has no detached shared-MM cleanup authority".to_owned(),
        ))
    }

    fn retire_detached_exec_predecessor(
        &self,
        _root_ticket: Option<crate::hvpatch::Stage1RootRetirementTicket>,
    ) -> Result<Option<crate::hvpatch::Stage1RootRetirementReceipt>, TrapError> {
        Err(TrapError::Hypervisor(
            "task binding has no detached exec predecessor authority".to_owned(),
        ))
    }
}

impl PersistentTaskBinding for crate::vcpu_loop::continuation::HvpatchTaskBinding {
    fn load_identity(&self) -> TaskLoadIdentity {
        self.identity()
    }

    fn validate_task_state(&self, state: &MigratableTaskState) -> Result<(), TrapError> {
        self.validate_state(state)
    }

    fn after_terminal_settlement(&self) {
        crate::vcpu_loop::continuation::HvpatchTaskBinding::after_terminal_settlement(self);
    }

    fn after_reaped_settlement(&self) {
        crate::vcpu_loop::continuation::HvpatchTaskBinding::after_reaped_settlement(self);
    }

    fn after_executor_failure_settlement(&self) {
        crate::vcpu_loop::continuation::HvpatchTaskBinding::after_executor_failure_settlement(self);
    }

    fn address_space_is_retiring(&self) -> bool {
        crate::vcpu_loop::continuation::HvpatchTaskBinding::address_space_is_retiring(self)
    }

    fn mark_exec_transferred(&self) -> Result<(), TrapError> {
        crate::vcpu_loop::continuation::HvpatchTaskBinding::mark_exec_transferred(self)
    }

    fn take_address_space_retirement(
        &self,
    ) -> Option<crate::hvpatch::PendingAddressSpaceRetirement> {
        crate::vcpu_loop::continuation::HvpatchTaskBinding::take_address_space_retirement(self)
    }

    fn retire_detached_address_space(
        &self,
        root_ticket: Option<crate::hvpatch::Stage1RootRetirementTicket>,
    ) -> Result<Option<crate::hvpatch::Stage1RootRetirementReceipt>, TrapError> {
        crate::vcpu_loop::continuation::HvpatchTaskBinding::retire_detached_address_space(
            self,
            root_ticket,
        )
    }

    fn retire_detached_shared_mm_edge(&self) -> Result<(), TrapError> {
        crate::vcpu_loop::continuation::HvpatchTaskBinding::retire_detached_shared_mm_edge(self)
    }

    fn retire_detached_exec_predecessor(
        &self,
        root_ticket: Option<crate::hvpatch::Stage1RootRetirementTicket>,
    ) -> Result<Option<crate::hvpatch::Stage1RootRetirementReceipt>, TrapError> {
        crate::vcpu_loop::continuation::HvpatchTaskBinding::retire_detached_exec_predecessor(
            self,
            root_ticket,
        )
    }
}

pub struct ExecutorSubmissionContext<'a> {
    pub(crate) scheduler: &'a Scheduler,
    #[cfg(test)]
    pub(crate) publish_test_descendant:
        &'a dyn Fn(Arc<crate::kernel::Thread>, ExecutionGeneration) -> Result<(), TrapError>,
    pub(crate) current: Option<&'a SubmissionAuthority>,
    // The worker lends ownership, not an alias, for exactly one resident poll.
    // This lets the HVPatch logical state machine consume and replace exec
    // authority while making it impossible to retain a borrow across a
    // Pending boundary. The worker takes the exact lease back before it saves
    // or settles the task.
    pub(crate) lease: Option<ThreadExecutionLease>,
    pub(crate) exec_replacement: Option<PendingExecReplacement>,
}

pub(crate) struct PendingExecReplacement {
    pub(crate) transition: crate::kernel::exec::CommittedExecTransition,
    pub(crate) replacement_mm: Arc<crate::hvpatch::Stage1MmLease>,
    pub(crate) retired_mm: Option<crate::hvpatch::Stage1MmRetirement>,
}

/// Borrowed worker authority passed into one engine-resident logical quantum.
/// It is deliberately non-owning: neither the job nor a continuation may
/// retain an executor kick/preemption or descendant-publication capability
/// after `run_until_boundary` returns.
pub(crate) struct HvpatchQuantumControl<'a, 'lease> {
    pub(crate) need_resched: &'a AtomicBool,
    pub(crate) submission: &'a mut ExecutorSubmissionContext<'lease>,
    pub(crate) executor_id: Option<ExecutorId>,
    pub(crate) binding: Option<&'a Arc<crate::vcpu_loop::continuation::HvpatchTaskBinding>>,
    pub(crate) cow_invalidation_observer: Option<&'a crate::hvpatch::CowInvalidationObserver>,
}

impl<'a, 'lease> HvpatchQuantumControl<'a, 'lease> {
    pub(crate) fn cow_invalidation_binding(
        &self,
    ) -> Option<(
        ExecutorId,
        &Arc<crate::vcpu_loop::continuation::HvpatchTaskBinding>,
        &crate::hvpatch::CowInvalidationObserver,
    )> {
        Some((
            self.executor_id?,
            self.binding?,
            self.cow_invalidation_observer?,
        ))
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        need_resched: &'a AtomicBool,
        submission: &'a mut ExecutorSubmissionContext<'lease>,
    ) -> Self {
        Self {
            need_resched,
            submission,
            executor_id: None,
            binding: None,
            cow_invalidation_observer: None,
        }
    }
    pub(crate) fn need_resched(&self) -> bool {
        self.need_resched.load(Ordering::Acquire)
    }

    pub(crate) fn current_submission_key(
        &self,
    ) -> Result<(ThreadKey, ExecutionGeneration), TrapError> {
        let current = self.submission.current.ok_or_else(|| {
            TrapError::Hypervisor("resident task has no worker-held authority".to_owned())
        })?;
        Ok((current.thread_key(), current.generation()))
    }

    #[cfg(test)]
    pub(crate) const fn submission(&self) -> &ExecutorSubmissionContext<'_> {
        self.submission
    }

    pub(crate) fn execution_lease_mut(&mut self) -> Result<&mut ThreadExecutionLease, TrapError> {
        self.submission.execution_lease_mut()
    }

    pub(crate) const fn execution_lease_slot_mut(&mut self) -> &mut Option<ThreadExecutionLease> {
        self.submission.execution_lease_slot_mut()
    }

    pub(crate) fn publish_exec_replacement(
        &mut self,
        replacement: PendingExecReplacement,
    ) -> Result<(), TrapError> {
        if self
            .submission
            .exec_replacement
            .replace(replacement)
            .is_some()
        {
            return Err(TrapError::Hypervisor(
                "quantum published more than one exec replacement".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn prepare_hvpatch_submission(
        &self,
        directory: &Arc<HvpatchTaskBindingDirectory>,
        shape: HvpatchSubmissionShape,
        thread: Arc<crate::kernel::Thread>,
        generation: ExecutionGeneration,
        binding: Arc<crate::vcpu_loop::continuation::HvpatchTaskBinding>,
    ) -> Result<PreparedHvpatchSubmission, TrapError> {
        self.submission
            .prepare_hvpatch_submission(directory, shape, thread, generation, binding)
    }
}

impl ExecutorSubmissionContext<'_> {
    pub(crate) fn execution_lease_mut(&mut self) -> Result<&mut ThreadExecutionLease, TrapError> {
        self.lease.as_mut().ok_or_else(|| {
            TrapError::Hypervisor("quantum has no mutable execution lease authority".to_owned())
        })
    }

    pub(crate) const fn execution_lease_slot_mut(&mut self) -> &mut Option<ThreadExecutionLease> {
        &mut self.lease
    }

    pub(crate) fn take_execution_lease(&mut self) -> Result<ThreadExecutionLease, TrapError> {
        self.lease.take().ok_or_else(|| {
            TrapError::Hypervisor("quantum returned without execution lease authority".to_owned())
        })
    }

    #[allow(dead_code)]
    pub(crate) fn prepare_hvpatch_submission(
        &self,
        directory: &Arc<HvpatchTaskBindingDirectory>,
        shape: HvpatchSubmissionShape,
        thread: Arc<crate::kernel::Thread>,
        generation: ExecutionGeneration,
        binding: Arc<crate::vcpu_loop::continuation::HvpatchTaskBinding>,
    ) -> Result<PreparedHvpatchSubmission, TrapError> {
        let current = self.current.ok_or_else(|| {
            TrapError::Hypervisor(
                "resident HVPatch task has no worker-held submission authority".to_owned(),
            )
        })?;
        directory.prepare_submission(
            self.scheduler,
            shape,
            Some(current),
            thread,
            generation,
            binding,
        )
    }

    #[cfg(test)]
    pub fn publish_test_descendant(
        &self,
        thread: Arc<crate::kernel::Thread>,
        generation: ExecutionGeneration,
    ) -> Result<(), TrapError> {
        (self.publish_test_descendant)(thread, generation)
    }
}

pub(crate) struct ExecBindingTransition {
    pub(crate) predecessor_thread: ThreadKey,
    pub(crate) predecessor_generation: ExecutionGeneration,
    pub(crate) successor_thread: ThreadKey,
    pub(crate) successor_generation: ExecutionGeneration,
    pub(crate) identity: TaskLoadIdentity,
    pub(crate) replacement_mm: Option<Arc<crate::hvpatch::Stage1MmLease>>,
    pub(crate) authority: Option<SubmissionAuthority>,
}

pub trait TaskBindingResolver<B>: Send + Sync + 'static {
    fn install_scheduler(self: &Arc<Self>, _scheduler: &Arc<Scheduler>) -> Result<(), TrapError> {
        Ok(())
    }

    fn resolve(
        &self,
        thread: ThreadKey,
        generation: ExecutionGeneration,
    ) -> Result<Arc<B>, TrapError>;

    #[allow(private_interfaces)]
    fn take_submission_authority(
        &self,
        _thread: ThreadKey,
        _generation: ExecutionGeneration,
    ) -> Option<SubmissionAuthority> {
        None
    }

    #[allow(private_interfaces)]
    fn restore_submission_authority(
        &self,
        authority: SubmissionAuthority,
    ) -> Result<(), SubmissionAuthority> {
        Err(authority)
    }

    #[cfg(test)]
    #[allow(private_interfaces)]
    fn publish_test_root(
        &self,
        _scheduler: &Scheduler,
        _thread: Arc<crate::kernel::Thread>,
        _authority: SubmissionAuthority,
    ) -> Result<(), SchedulerError> {
        Err(crate::kernel::RunQueueError::SubmissionRejected.into())
    }

    #[cfg(test)]
    #[allow(private_interfaces)]
    fn publish_test_descendant(
        &self,
        _scheduler: &Scheduler,
        _parent: &SubmissionAuthority,
        _thread: Arc<crate::kernel::Thread>,
        _generation: ExecutionGeneration,
    ) -> Result<(), TrapError> {
        Err(TrapError::Hypervisor(
            "resolver does not support test descendant publication".to_owned(),
        ))
    }

    fn retire(&self, _thread: ThreadKey, _generation: ExecutionGeneration) {}

    fn cancel_dormant(
        &self,
        _scheduler: &Scheduler,
        _reason: ExecutionFailure,
    ) -> Result<usize, TrapError> {
        Ok(0)
    }

    #[allow(private_interfaces)]
    fn replace_exec(
        &self,
        _scheduler: &Scheduler,
        _transition: ExecBindingTransition,
    ) -> Result<ExecBindingReplacement<B>, TrapError> {
        Err(TrapError::Hypervisor(
            "task binding resolver does not support exec replacement".to_owned(),
        ))
    }
}

pub(crate) struct ExecBindingReplacement<B> {
    pub(crate) binding: Arc<B>,
    pub(crate) authority: Option<SubmissionAuthority>,
}

#[derive(Default)]
pub(crate) struct HvpatchTaskBindingDirectory {
    pub(crate) bindings:
        Mutex<std::collections::BTreeMap<(ThreadKey, ExecutionGeneration), HvpatchTaskRecord>>,
    scheduler: Mutex<std::sync::Weak<Scheduler>>,
}

pub(crate) struct HvpatchTaskRecord {
    pub(crate) binding: Arc<crate::vcpu_loop::continuation::HvpatchTaskBinding>,
    pub(crate) authority: Option<SubmissionAuthority>,
    pub(crate) active: bool,
}

impl HvpatchTaskBindingDirectory {
    pub(crate) fn install_scheduler(
        self: &Arc<Self>,
        scheduler: &Arc<Scheduler>,
    ) -> Result<(), TrapError> {
        let mut installed = self.scheduler.lock();
        if installed.strong_count() != 0 {
            return Ok(());
        }
        *installed = Arc::downgrade(scheduler);
        drop(installed);
        scheduler
            .install_generation_observer(
                Arc::clone(self) as Arc<dyn crate::kernel::scheduler::SchedulerGenerationObserver>
            )
            .map_err(|error| TrapError::Hypervisor(error.to_string()))
    }

    #[cfg(test)]
    pub(crate) fn publish(
        &self,
        thread: ThreadKey,
        generation: ExecutionGeneration,
        binding: Arc<crate::vcpu_loop::continuation::HvpatchTaskBinding>,
    ) -> Result<(), TrapError> {
        if self
            .bindings
            .lock()
            .insert(
                (thread, generation),
                HvpatchTaskRecord {
                    binding,
                    authority: None,
                    active: true,
                },
            )
            .is_some()
        {
            return Err(TrapError::Hypervisor(
                "duplicate exact HVPatch task binding publication".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn retire(&self, thread: ThreadKey, generation: ExecutionGeneration) {
        self.bindings.lock().remove(&(thread, generation));
    }

    pub(crate) fn prepare_submission(
        self: &Arc<Self>,
        scheduler: &Scheduler,
        shape: HvpatchSubmissionShape,
        grant_authority: Option<&SubmissionAuthority>,
        thread: Arc<crate::kernel::Thread>,
        generation: ExecutionGeneration,
        binding: Arc<crate::vcpu_loop::continuation::HvpatchTaskBinding>,
    ) -> Result<PreparedHvpatchSubmission, TrapError> {
        let key = (thread.key(), generation);
        let mut bindings = self.bindings.lock();
        if bindings.contains_key(&key) {
            return Err(TrapError::Hypervisor(
                "duplicate exact dormant HVPatch submission".to_owned(),
            ));
        }
        let authority = match (shape, grant_authority) {
            (HvpatchSubmissionShape::Root, None) => scheduler
                .admit_process_root(key.0, key.1)
                .map_err(|error| TrapError::Hypervisor(error.to_string()))?,
            (HvpatchSubmissionShape::Descendant { grant }, Some(authority))
                if (authority.thread_key(), authority.generation()) == grant =>
            {
                authority
                    .admit_descendant(key.0, key.1)
                    .map_err(|error| TrapError::Hypervisor(error.to_string()))?
            }
            (HvpatchSubmissionShape::SameTaskSibling { grant }, Some(authority))
                if (authority.thread_key(), authority.generation()) == grant =>
            {
                authority
                    .admit_same_task_sibling(key.0, key.1)
                    .map_err(|error| TrapError::Hypervisor(error.to_string()))?
            }
            (HvpatchSubmissionShape::PeerRoot { grant }, Some(authority))
                if (authority.thread_key(), authority.generation()) == grant =>
            {
                authority
                    .admit_peer_root(key.0, key.1)
                    .map_err(|error| TrapError::Hypervisor(error.to_string()))?
            }
            _ => {
                return Err(TrapError::Hypervisor(
                    "HVPatch submission shape does not match worker-held authority".to_owned(),
                ));
            }
        };
        bindings.insert(
            key,
            HvpatchTaskRecord {
                binding,
                authority: Some(authority),
                active: false,
            },
        );
        Ok(PreparedHvpatchSubmission {
            directory: Arc::clone(self),
            key,
            armed: true,
        })
    }

    #[cfg(test)]
    pub(crate) fn install_root_authority(
        &self,
        scheduler: &Scheduler,
        thread: Arc<crate::kernel::Thread>,
        authority: SubmissionAuthority,
    ) -> Result<(), SchedulerError> {
        let key = (authority.thread_key(), authority.generation());
        let mut bindings = self.bindings.lock();
        let record = bindings
            .get_mut(&key)
            .ok_or(crate::kernel::RunQueueError::AuthorityMismatch)?;
        if record.authority.is_some() {
            return Err(crate::kernel::RunQueueError::SubmissionRejected.into());
        }
        record.authority = Some(authority);
        match record
            .authority
            .as_ref()
            .unwrap_or_else(|| std::process::abort())
            .publish(scheduler, thread)
        {
            Ok(()) => Ok(()),
            Err(error) => {
                record.authority.take();
                Err(error)
            }
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn rollover_exact(
        &self,
        thread: ThreadKey,
        predecessor: ExecutionGeneration,
        successor: ExecutionGeneration,
    ) -> Result<(), TrapError> {
        if predecessor.raw().checked_add(1) != Some(successor.raw()) {
            return Err(TrapError::Hypervisor(
                "HVPatch binding rollover rejected non-successor generation".to_owned(),
            ));
        }
        let mut bindings = self.bindings.lock();
        if bindings.contains_key(&(thread, successor)) {
            if !bindings.contains_key(&(thread, predecessor)) {
                return Ok(());
            }
            return Err(TrapError::Hypervisor(
                "HVPatch binding rollover found overlapping generations".to_owned(),
            ));
        }
        let record = bindings.get(&(thread, predecessor)).ok_or_else(|| {
            TrapError::Hypervisor("missing predecessor HVPatch binding".to_owned())
        })?;
        if record.authority.is_some() {
            return Err(TrapError::Hypervisor(
                "HVPatch binding rollover requires scheduler-owned authority transaction"
                    .to_owned(),
            ));
        }
        let record = bindings
            .remove(&(thread, predecessor))
            .unwrap_or_else(|| std::process::abort());
        bindings.insert((thread, successor), record);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
// Root is production-wired in this slice. The other shapes are intentionally
// prepared now so the subsequent fork/clone conversion cannot fall back to a
// generic descendant edge while it replaces the compatibility materializers.
#[allow(dead_code)]
pub(crate) enum HvpatchSubmissionShape {
    Root,
    Descendant {
        grant: (ThreadKey, ExecutionGeneration),
    },
    SameTaskSibling {
        grant: (ThreadKey, ExecutionGeneration),
    },
    PeerRoot {
        grant: (ThreadKey, ExecutionGeneration),
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HvpatchActivationProof {
    pub(crate) thread: ThreadKey,
    pub(crate) generation: ExecutionGeneration,
    pub(crate) identity: TaskLoadIdentity,
}

impl HvpatchActivationProof {
    pub(crate) fn validate(
        context: &crate::kernel::KernelContext,
        state: &MigratableTaskState,
        generation: ExecutionGeneration,
        identity: TaskLoadIdentity,
        start_gate: crate::kernel::objects::OpenedStartGate,
    ) -> Result<Self, TrapError> {
        if start_gate.thread() != context.thread().key()
            || start_gate.generation() != generation
            || context.thread().execution_state().generation() != Some(generation)
            || context.shared().mm().id() != state.mm
            || identity.mm != state.mm
            || identity.asid_generation != state.asid_generation
            || state.cpu.task_identity() != (state.mm.raw(), state.asid_generation)
            || state.cpu.guest_abi() != identity.abi
            || state.cpu.version() != identity.version
        {
            return Err(TrapError::Hypervisor(
                "HVPatch activation proof rejected Kernel/CPU/MM/ASID/start state".to_owned(),
            ));
        }
        Ok(Self {
            thread: context.thread().key(),
            generation,
            identity,
        })
    }
}

pub(crate) struct PreparedHvpatchSubmission {
    directory: Arc<HvpatchTaskBindingDirectory>,
    key: (ThreadKey, ExecutionGeneration),
    armed: bool,
}

impl PreparedHvpatchSubmission {
    pub(crate) fn activate(
        mut self,
        scheduler: &Scheduler,
        thread: Arc<crate::kernel::Thread>,
        proof: HvpatchActivationProof,
    ) -> Result<(), TrapError> {
        if self.key != (proof.thread, proof.generation) || thread.key() != proof.thread {
            return Err(TrapError::Hypervisor(
                "HVPatch activation proof names a different submission".to_owned(),
            ));
        }
        // Lock order: the exec retarget path nests `directory.bindings` INSIDE
        // the scheduler's generation mutex and the executor kick binding lock
        // (`retarget_running_exec` -> `rebind_exact_with` -> `replace_exec`),
        // and scheduler publication consults every kick's binding lock
        // (`enqueue_exact` -> `has_running`). Publishing while this directory
        // lock is held therefore closes an ABBA cycle against a sibling
        // exec: a load-dependent whole-carrier wedge, seen as executor-2 in
        // `replace_exec` vs executor-7 in `activate` on `os_exec.test`.
        //
        // The record is made resolvable BEFORE the row is published (an
        // executor may take the row the instant it lands and must resolve
        // the binding), the directory lock is released for the publication,
        // and a rejected publication rolls the record back to dormant so the
        // armed drop below removes it exactly as before.
        let publication = {
            let mut bindings = self.directory.bindings.lock();
            let record = bindings.get_mut(&self.key).ok_or_else(|| {
                TrapError::Hypervisor("missing dormant HVPatch submission".to_owned())
            })?;
            if record.active || record.binding.identity() != proof.identity {
                return Err(TrapError::Hypervisor(
                    "HVPatch dormant binding identity changed before activation".to_owned(),
                ));
            }
            let authority = record
                .authority
                .as_ref()
                .ok_or_else(|| TrapError::Hypervisor("dormant authority missing".to_owned()))?;
            record.active = true;
            authority.publication_handle()
        };
        match publication.publish(scheduler, thread) {
            Ok(()) => {
                self.armed = false;
                Ok(())
            }
            Err(error) => {
                let mut bindings = self.directory.bindings.lock();
                if let Some(record) = bindings.get_mut(&self.key) {
                    record.active = false;
                }
                Err(TrapError::Hypervisor(error.to_string()))
            }
        }
    }
}

impl Drop for PreparedHvpatchSubmission {
    fn drop(&mut self) {
        if self.armed {
            let mut bindings = self.directory.bindings.lock();
            if bindings.get(&self.key).is_some_and(|record| !record.active) {
                bindings.remove(&self.key);
            }
        }
    }
}

#[cfg(test)]
static VFORK_ACTIVATION_HOOK: parking_lot::Mutex<Option<Box<dyn Fn() + Send + Sync>>> =
    parking_lot::Mutex::new(None);

#[cfg(test)]
pub(crate) struct TestHookGuard;

#[cfg(test)]
impl Drop for TestHookGuard {
    fn drop(&mut self) {
        *VFORK_ACTIVATION_HOOK.lock() = None;
    }
}

pub(crate) struct PreparedVforkChildActivation {
    dormant: PreparedHvpatchSubmission,
    scheduler: Arc<Scheduler>,
    child_thread: Arc<crate::kernel::Thread>,
    proof: HvpatchActivationProof,
    member_publication: PersistentProcessMemberPublication,
    job_reservation: ContainerJobReservation,
    job_result: HvpatchLoopResult,
    job_completion: crate::vcpu_loop::continuation::LogicalJobCompletion,
    process_retirement: ProcessPhysicalRetirement,
}

impl PreparedVforkChildActivation {
    // This is the typed handoff boundary for one atomic activation. Keeping
    // the independently owned guards as arguments makes omission visible at
    // compile time; a loose builder would permit partially armed activation.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        dormant: PreparedHvpatchSubmission,
        scheduler: Arc<Scheduler>,
        child_thread: Arc<crate::kernel::Thread>,
        proof: HvpatchActivationProof,
        member_publication: PersistentProcessMemberPublication,
        job_reservation: ContainerJobReservation,
        job_result: HvpatchLoopResult,
        job_completion: crate::vcpu_loop::continuation::LogicalJobCompletion,
        process_retirement: ProcessPhysicalRetirement,
    ) -> Self {
        Self {
            dormant,
            scheduler,
            child_thread,
            proof,
            member_publication,
            job_reservation,
            job_result,
            job_completion,
            process_retirement,
        }
    }

    pub(crate) fn activate(self) -> Result<(), TrapError> {
        let Self {
            dormant,
            scheduler,
            child_thread,
            proof,
            member_publication,
            job_reservation,
            job_result,
            job_completion,
            process_retirement,
        } = self;
        let fail_unpublished_child = |error: TrapError| {
            scheduler
                .fail_runnable_exact(
                    child_thread.key(),
                    proof.generation,
                    ExecutionFailure::SnapshotRestoreFailed,
                )
                .unwrap_or_else(|cleanup_error| {
                    carrick_fatal!(
                        "kernel::scheduler_rollback",
                        "scheduler fail_runnable_exact rollback failed during vfork child activation failure cleanup: child_key={:?}, gen={:?}, error={cleanup_error}",
                        child_thread.key(),
                        proof.generation
                    );
                });
            error
        };

        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        if let Err(error) = check_hvpatch_process_failpoint(HvpatchProcessFailpoint::Activation) {
            return Err(fail_unpublished_child(TrapError::Hypervisor(
                error.to_string(),
            )));
        }

        dormant
            .activate(&scheduler, Arc::clone(&child_thread), proof)
            .map_err(fail_unpublished_child)?;

        job_reservation
            .activate_with_process_retirement(job_result, job_completion, process_retirement)
            .map_err(|error| fail_unpublished_child(TrapError::Hypervisor(error.to_string())))?;

        #[cfg(test)]
        if let Some(hook) = VFORK_ACTIVATION_HOOK.lock().as_ref() {
            hook();
        }

        member_publication.commit();
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn set_test_hook(hook: impl Fn() + Send + Sync + 'static) -> TestHookGuard {
        *VFORK_ACTIVATION_HOOK.lock() = Some(Box::new(hook));
        TestHookGuard
    }
}

impl std::fmt::Debug for PreparedVforkChildActivation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedVforkChildActivation")
            .field("child_thread", &self.child_thread.key())
            .field("proof_thread", &self.proof.thread)
            .field("proof_generation", &self.proof.generation)
            .finish()
    }
}

impl crate::kernel::scheduler::SchedulerGenerationObserver for HvpatchTaskBindingDirectory {
    fn transition(
        &self,
        thread: ThreadKey,
        predecessor: ExecutionGeneration,
        successor: ExecutionGeneration,
        kind: crate::kernel::scheduler::SchedulerGenerationTransition,
    ) -> Result<(), crate::kernel::RunQueueError> {
        let scheduler = self
            .scheduler
            .lock()
            .upgrade()
            .ok_or(crate::kernel::RunQueueError::ObserverSchedulerGone)?;
        let mut bindings = self.bindings.lock();
        let mut record = bindings
            .remove(&(thread, predecessor))
            .ok_or(crate::kernel::RunQueueError::ObserverBindingMissing)?;
        if kind == crate::kernel::scheduler::SchedulerGenerationTransition::Terminal {
            return Ok(());
        }
        if bindings.contains_key(&(thread, successor)) {
            bindings.insert((thread, predecessor), record);
            return Err(crate::kernel::RunQueueError::DuplicateObserverBinding);
        }
        if let Some(authority) = record.authority.take() {
            let transition = match kind {
                crate::kernel::scheduler::SchedulerGenerationTransition::Runnable => {
                    if authority.is_active() {
                        authority.rollover_exact(&scheduler, thread, predecessor, thread, successor)
                    } else {
                        authority.reactivate_exact(&scheduler, predecessor, successor)
                    }
                }
                crate::kernel::scheduler::SchedulerGenerationTransition::Blocked => {
                    authority.park_exact(&scheduler, predecessor, successor)
                }
                crate::kernel::scheduler::SchedulerGenerationTransition::Terminal => {
                    unreachable!()
                }
            };
            match transition {
                Ok(authority) => record.authority = Some(authority),
                Err((error, authority)) => {
                    record.authority = Some(authority);
                    bindings.insert((thread, predecessor), record);
                    return Err(error);
                }
            }
        }
        bindings.insert((thread, successor), record);
        Ok(())
    }

    fn retire_reaped(&self, thread: ThreadKey, predecessor: ExecutionGeneration) {
        // The scheduler has established that the exact thread left the kernel
        // graph, so the record this directory put back when its rollover
        // failed is unreachable: `resolve` keys on (thread, generation) and
        // nothing will ever ask for this pair again. Dropping it releases the
        // `SubmissionAuthority` it holds, which is what lets the run queue
        // drain and the container finish closing.
        HvpatchTaskBindingDirectory::retire(self, thread, predecessor);
    }
}

impl TaskBindingResolver<crate::vcpu_loop::continuation::HvpatchTaskBinding>
    for HvpatchTaskBindingDirectory
{
    fn install_scheduler(self: &Arc<Self>, scheduler: &Arc<Scheduler>) -> Result<(), TrapError> {
        HvpatchTaskBindingDirectory::install_scheduler(self, scheduler)
    }

    fn resolve(
        &self,
        thread: ThreadKey,
        generation: ExecutionGeneration,
    ) -> Result<Arc<crate::vcpu_loop::continuation::HvpatchTaskBinding>, TrapError> {
        let bindings = self.bindings.lock();
        // Two different defects wear one message otherwise, and telling them
        // apart is the whole diagnosis when an executor claims a row it
        // cannot service: a record that is PRESENT but dormant means the row
        // became claimable before its submission activated (a claimability
        // gate hole), while an ABSENT record means the row outlived the
        // binding it named -- or predated any binding at all, which is what
        // named the pre-publication window.
        match bindings.get(&(thread, generation)) {
            Some(record) if record.active => Ok(Arc::clone(&record.binding)),
            Some(_) => Err(TrapError::Hypervisor(
                "exact HVPatch task binding is still dormant".to_owned(),
            )),
            None => Err(TrapError::Hypervisor(
                "missing exact HVPatch task binding".to_owned(),
            )),
        }
    }
    fn take_submission_authority(
        &self,
        thread: ThreadKey,
        generation: ExecutionGeneration,
    ) -> Option<SubmissionAuthority> {
        let mut bindings = self.bindings.lock();
        let record = bindings.get_mut(&(thread, generation))?;
        record.active.then(|| record.authority.take()).flatten()
    }

    fn restore_submission_authority(
        &self,
        authority: SubmissionAuthority,
    ) -> Result<(), SubmissionAuthority> {
        let key = (authority.thread_key(), authority.generation());
        let mut bindings = self.bindings.lock();
        let Some(record) = bindings.get_mut(&key) else {
            return Err(authority);
        };
        if !record.active || record.authority.is_some() {
            return Err(authority);
        }
        record.authority = Some(authority);
        Ok(())
    }

    fn retire(&self, thread: ThreadKey, generation: ExecutionGeneration) {
        HvpatchTaskBindingDirectory::retire(self, thread, generation);
    }

    fn cancel_dormant(
        &self,
        scheduler: &Scheduler,
        reason: ExecutionFailure,
    ) -> Result<usize, TrapError> {
        let candidates = self
            .bindings
            .lock()
            .iter()
            .map(|(&(thread, generation), record)| {
                (thread, generation, Arc::clone(&record.binding))
            })
            .collect::<Vec<_>>();
        let mut cancelled = 0usize;
        for (thread, generation, binding) in candidates {
            if scheduler
                .fail_blocked_exact(thread, generation, reason)
                .map_err(|error| {
                    TrapError::Hypervisor(format!(
                        "cancel dormant binding {thread:?} generation {generation:?}: {error}"
                    ))
                })?
            {
                binding.after_terminal_settlement();
                let _ = binding.cancel_dormant_backend();
                cancelled = cancelled
                    .checked_add(1)
                    .ok_or_else(|| TrapError::Hypervisor("dormant cancellation overflow".into()))?;
            }
        }
        Ok(cancelled)
    }

    fn replace_exec(
        &self,
        scheduler: &Scheduler,
        transition: ExecBindingTransition,
    ) -> Result<ExecBindingReplacement<crate::vcpu_loop::continuation::HvpatchTaskBinding>, TrapError>
    {
        let ExecBindingTransition {
            predecessor_thread,
            predecessor_generation,
            successor_thread,
            successor_generation,
            identity,
            replacement_mm,
            authority,
        } = transition;
        let mut bindings = self.bindings.lock();
        if bindings.contains_key(&(successor_thread, successor_generation)) {
            return Err(TrapError::Hypervisor(
                "exec replacement binding already exists".to_owned(),
            ));
        }
        let mut record = bindings
            .remove(&(predecessor_thread, predecessor_generation))
            .ok_or_else(|| TrapError::Hypervisor("missing predecessor exec binding".to_owned()))?;
        if record.authority.is_some() {
            bindings.insert((predecessor_thread, predecessor_generation), record);
            return Err(TrapError::Hypervisor(
                "exec replacement found authority outside running quantum".to_owned(),
            ));
        }
        let replacement_result = match replacement_mm {
            Some(replacement_mm) => record
                .binding
                .replacement_with_stage1_mm(identity, replacement_mm),
            None => {
                #[cfg(test)]
                {
                    Ok(record.binding.replacement(identity))
                }
                #[cfg(not(test))]
                {
                    Err(TrapError::Hypervisor(
                        "production exec replacement omitted fresh stage-1/ASID lease".to_owned(),
                    ))
                }
            }
        };
        let replacement = match replacement_result {
            Ok(replacement) => Arc::new(replacement),
            Err(error) => {
                bindings.insert((predecessor_thread, predecessor_generation), record);
                return Err(error);
            }
        };
        let authority = match authority {
            Some(authority) => match authority.replace_exec_exact(
                scheduler,
                predecessor_thread,
                predecessor_generation,
                successor_thread,
                successor_generation,
            ) {
                Ok(authority) => Some(authority),
                Err((error, authority)) => {
                    record.authority = Some(authority);
                    bindings.insert((predecessor_thread, predecessor_generation), record);
                    return Err(TrapError::Hypervisor(error.to_string()));
                }
            },
            None => None,
        };
        bindings.insert(
            (successor_thread, successor_generation),
            HvpatchTaskRecord {
                binding: Arc::clone(&replacement),
                authority: None,
                active: true,
            },
        );
        Ok(ExecBindingReplacement {
            binding: replacement,
            authority,
        })
    }
}
