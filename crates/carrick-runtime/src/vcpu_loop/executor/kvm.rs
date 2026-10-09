//! KVM task binding onto the shared executor submission authority.
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;

use carrick_hal::TrapError;
use carrick_hal::guest_arch_binding::{GuestArchBinding, core_arch::TaskIdentity};
use carrick_hal::threaded::GuestCpuState;
use carrick_kernel::kernel::objects::{ExecutionGeneration, MigratableTaskState, ThreadKey};
use carrick_kernel::kernel::{KernelContext, KernelTaskBinding, Scheduler, SubmissionAuthority};

use super::{
    ExactHardwareKick, ExecutorCpuReceipt, ExecutorExit, ExecutorSaveError,
    ExecutorSubmissionContext, GuestIdleExit, PersistentExecutor, PersistentExecutorFactory,
    RunnableTask, SavedRunnable,
};
use super::{PersistentTaskBinding, TaskBindingDirectory, TaskBindingResolver, TaskLoadIdentity};

use carrick_hal::x8664_arch::{SyscallNorm, X8664GuestArch};
use carrick_kernel::compat::CompatReporter;
use carrick_kernel::dispatch::{DispatchOutcome, SyscallDispatcher, SyscallRequest};
use carrick_kernel::kernel::continuation::{
    BlockedContinuation, ContinuationCapture, RestartClass, fold_continuation_completion,
    resume_continuation,
};
use carrick_kernel::kernel::objects::{ExecutorId, ThreadExecutionLease};
use carrick_vmm_kvm::carrier_cpu::CarrierRunExit;
use carrick_vmm_kvm::cpl0_boot::{
    GuestExitStatus, InitialProcessExit, InitialSyscallDisposition, ProductionCpuFactory,
    ProductionCpuLease, ProductionForwardFrame,
};
use carrick_x86::arch_context::X86ArchContext;

pub(crate) struct KvmPersistentExecutorFactory {
    physical: Arc<ProductionCpuFactory>,
    dispatcher: Arc<Mutex<SyscallDispatcher>>,
    reporter: Arc<CompatReporter>,
    completed: mpsc::Sender<Result<InitialProcessExit, String>>,
    next_slot: AtomicUsize,
    exits: Arc<AtomicUsize>,
    max_exits: usize,
    stats: Arc<KvmForwardStats>,
    scheduler: Arc<Scheduler>,
    first_forward_hook: Arc<Mutex<Option<KvmFirstForwardHook>>>,
}

pub type KvmFirstForwardHook =
    Box<dyn FnOnce(&mut ProductionCpuLease) -> Result<(), TrapError> + Send>;

type KvmForwardCounts = BTreeMap<&'static str, u64>;

#[derive(Default)]
pub(crate) struct KvmForwardStats {
    host: Mutex<KvmForwardCounts>,
    refusal: Mutex<KvmForwardCounts>,
}

impl KvmForwardStats {
    fn record(&self, class: crate::prepare::InitialForwardClass) -> Result<(), TrapError> {
        let map = match class {
            crate::prepare::InitialForwardClass::Host(_) => &self.host,
            crate::prepare::InitialForwardClass::Refuse(_) => &self.refusal,
        };
        let mut map = map
            .lock()
            .map_err(|_| TrapError::Hypervisor("KVM forward counters poisoned".into()))?;
        let count = map.entry(class.family()).or_default();
        *count = count
            .checked_add(1)
            .ok_or_else(|| TrapError::Hypervisor("KVM forward counter overflow".into()))?;
        Ok(())
    }

    pub(crate) fn snapshot(&self) -> Result<(KvmForwardCounts, KvmForwardCounts), TrapError> {
        let host = self
            .host
            .lock()
            .map_err(|_| TrapError::Hypervisor("KVM forward counters poisoned".into()))?
            .clone();
        let refusal = self
            .refusal
            .lock()
            .map_err(|_| TrapError::Hypervisor("KVM forward counters poisoned".into()))?
            .clone();
        Ok((host, refusal))
    }
}

impl KvmPersistentExecutorFactory {
    pub(crate) fn new(
        physical: Arc<ProductionCpuFactory>,
        dispatcher: Arc<Mutex<SyscallDispatcher>>,
        reporter: Arc<CompatReporter>,
        completed: mpsc::Sender<Result<InitialProcessExit, String>>,
        max_exits: usize,
        stats: Arc<KvmForwardStats>,
        scheduler: Arc<Scheduler>,
    ) -> Self {
        Self {
            physical,
            dispatcher,
            reporter,
            completed,
            next_slot: AtomicUsize::new(0),
            exits: Arc::new(AtomicUsize::new(0)),
            max_exits,
            stats,
            scheduler,
            first_forward_hook: Arc::new(Mutex::new(None)),
        }
    }

    pub(crate) fn install_first_forward_hook(
        &self,
        hook: KvmFirstForwardHook,
    ) -> Result<(), TrapError> {
        let mut slot = self
            .first_forward_hook
            .lock()
            .map_err(|_| TrapError::Hypervisor("KVM fixture hook poisoned".into()))?;
        if slot.replace(hook).is_some() {
            return Err(TrapError::Hypervisor(
                "KVM fixture hook already installed".into(),
            ));
        }
        Ok(())
    }
}

impl PersistentExecutorFactory for KvmPersistentExecutorFactory {
    type Executor = KvmPersistentExecutor;

    fn create(&self, _executor: ExecutorId) -> Result<Self::Executor, TrapError> {
        let slot = self.next_slot.fetch_add(1, Ordering::AcqRel);
        Ok(KvmPersistentExecutor {
            physical: self.physical.claim(slot)?,
            dispatcher: Arc::clone(&self.dispatcher),
            reporter: Arc::clone(&self.reporter),
            completed: self.completed.clone(),
            exits: Arc::clone(&self.exits),
            max_exits: self.max_exits,
            stats: Arc::clone(&self.stats),
            scheduler: Arc::clone(&self.scheduler),
            binding: None,
            task: None,
            completion_sent: false,
            first_forward_hook: Arc::clone(&self.first_forward_hook),
        })
    }
}

pub(crate) struct KvmPersistentExecutor {
    physical: ProductionCpuLease,
    dispatcher: Arc<Mutex<SyscallDispatcher>>,
    reporter: Arc<CompatReporter>,
    completed: mpsc::Sender<Result<InitialProcessExit, String>>,
    exits: Arc<AtomicUsize>,
    max_exits: usize,
    stats: Arc<KvmForwardStats>,
    scheduler: Arc<Scheduler>,
    binding: Option<Arc<KvmTaskBinding>>,
    task: Option<TaskIdentity>,
    completion_sent: bool,
    first_forward_hook: Arc<Mutex<Option<KvmFirstForwardHook>>>,
}

struct RetainedForward {
    frame: ProductionForwardFrame,
    request: SyscallRequest,
}

enum ForwardDecision {
    Immediate(InitialSyscallDisposition),
    Blocked(SyscallRequest, Box<DispatchOutcome>),
}

impl KvmPersistentExecutor {
    fn block_forward(
        binding: &Arc<KvmTaskBinding>,
        submission: &mut ExecutorSubmissionContext<'_>,
        request: SyscallRequest,
        outcome: DispatchOutcome,
        frame: Option<ProductionForwardFrame>,
    ) -> Result<ExecutorExit, TrapError> {
        let context = binding.fresh_context()?;
        let restart =
            if carrick_kernel::kernel::continuation::is_restartable_syscall(request.number.raw()) {
                RestartClass::RestartSyscall
            } else {
                RestartClass::Never
            };
        let capture = ContinuationCapture::from_lease(
            &context,
            submission.execution_lease_mut()?,
            request,
            restart,
        )
        .map_err(|error| TrapError::Hypervisor(error.to_string()))?;
        let continuation = BlockedContinuation::from_dispatch_outcome(outcome, capture)
            .map_err(|error| TrapError::Hypervisor(error.to_string()))?;
        if let Some(frame) = frame {
            let mut retained = binding
                .retained
                .lock()
                .map_err(|_| TrapError::Hypervisor("KVM retained frame poisoned".into()))?;
            if retained.is_some() {
                return Err(TrapError::Hypervisor("KVM forward already retained".into()));
            }
            *retained = Some(RetainedForward { frame, request });
        }
        Ok(ExecutorExit::BlockedContinuation {
            continuation: Box::new(continuation),
            vfork_activation: None,
        })
    }

    fn task(&self) -> Result<TaskIdentity, TrapError> {
        self.task
            .ok_or_else(|| TrapError::Hypervisor("KVM executor has no loaded task".into()))
    }

    fn publish_exit(&mut self, result: InitialProcessExit) -> Result<(), TrapError> {
        self.completed
            .send(Ok(result))
            .map_err(|_| TrapError::Hypervisor("KVM completion receiver closed".into()))?;
        self.completion_sent = true;
        Ok(())
    }
}

impl Drop for KvmPersistentExecutor {
    fn drop(&mut self) {
        if !self.completion_sent {
            let _ = self
                .completed
                .send(Err("KVM worker stopped before terminal guest exit".into()));
        }
    }
}

impl PersistentExecutor for KvmPersistentExecutor {
    type TaskBinding = KvmTaskBinding;

    fn load(&mut self, task: &RunnableTask<'_, Self::TaskBinding>) -> Result<(), TrapError> {
        let state = task.validate_for_load()?;
        let carrick_hal::threaded::GuestCpuState::X86_64V1(cpu) = &state.cpu else {
            return Err(TrapError::Hypervisor(
                "KVM load received non-x86 CPU".into(),
            ));
        };
        let arch =
            X86ArchContext::new(task.binding().arch(), cpu.as_ref().clone()).map_err(|error| {
                TrapError::Hypervisor(format!("KVM task image binding at load: {error}"))
            })?;
        self.physical.cpu_mut().load(arch).map_err(|error| {
            TrapError::Hypervisor(format!("KVM physical CPU restore at load: {error}"))
        })?;
        self.task = Some(task.binding().arch().task());
        self.binding = Some(Arc::clone(task.binding()));
        Ok(())
    }

    fn run_until_boundary(
        &mut self,
        need_resched: &AtomicBool,
        submission: &mut ExecutorSubmissionContext<'_>,
    ) -> Result<ExecutorExit, TrapError> {
        let result = (|| {
            if need_resched.load(Ordering::Acquire) {
                return Ok(ExecutorExit::Preempted);
            }
            let task = self.task()?;
            if let Some(binding) = self.binding.as_ref().cloned()
                && submission
                    .execution_lease_mut()?
                    .blocked_continuation()
                    .is_some()
            {
                let retained = binding
                    .retained
                    .lock()
                    .map_err(|_| TrapError::Hypervisor("KVM retained frame poisoned".into()))?
                    .take()
                    .ok_or_else(|| {
                        TrapError::Hypervisor("KVM blocked task lost forward frame".into())
                    })?;
                let context = binding.fresh_context()?;
                let event = submission
                    .execution_lease_mut()?
                    .blocked_continuation()
                    .ok_or_else(|| TrapError::Hypervisor("KVM continuation vanished".into()))?
                    .ready_event()
                    .map_err(|error| TrapError::Hypervisor(format!("KVM wake event: {error:?}")))?;
                let result =
                    resume_continuation(submission.execution_lease_mut()?, event, &context)
                        .map_err(|error| TrapError::Hypervisor(format!("KVM resume: {error:?}")))?;
                let mut dispatcher = self
                    .dispatcher
                    .lock()
                    .map_err(|_| TrapError::Hypervisor("KVM dispatcher poisoned".into()))?;
                let outcome =
                    self.physical
                        .with_retained_forward(task, &retained.frame, |venue| {
                            let folded = fold_continuation_completion(
                                result.completion,
                                &dispatcher,
                                &context,
                                venue,
                            )
                            .map_err(|error| TrapError::Hypervisor(error.to_string()))?;
                            match folded {
                                Some(outcome) => Ok(outcome),
                                None => dispatcher
                                    .dispatch(&context, retained.request, venue, &self.reporter)
                                    .map_err(|error| TrapError::Hypervisor(error.to_string())),
                            }
                        })?;
                drop(dispatcher);
                match outcome {
                    DispatchOutcome::Returned { value } => {
                        self.physical
                            .complete_forward(task, retained.frame, value)?;
                        return Ok(ExecutorExit::Syscall);
                    }
                    DispatchOutcome::Errno { errno } => {
                        self.physical.complete_forward(
                            task,
                            retained.frame,
                            errno.guest_retval(),
                        )?;
                        return Ok(ExecutorExit::Syscall);
                    }
                    other => {
                        let mut slot = binding.retained.lock().map_err(|_| {
                            TrapError::Hypervisor("KVM retained frame poisoned".into())
                        })?;
                        let request = retained.request;
                        *slot = Some(retained);
                        drop(slot);
                        return Self::block_forward(&binding, submission, request, other, None);
                    }
                }
            }
            let exited = self
                .exits
                .fetch_add(1, Ordering::AcqRel)
                .checked_add(1)
                .ok_or_else(|| TrapError::Hypervisor("KVM exit count overflow".into()))?;
            if exited > self.max_exits {
                return Err(TrapError::Hypervisor(
                    "KVM guest exit budget exceeded".into(),
                ));
            }
            let stopped = self.physical.cpu_mut().run_loaded(task).map_err(|error| {
                TrapError::Hypervisor(format!("KVM stopped run boundary: {error}"))
            })?;
            match &stopped.exit {
                CarrierRunExit::PhysicalDoorbell { .. } => {
                    let status = self
                        .physical
                        .service_physical_doorbell(task, &stopped.exit)?;
                    self.scheduler.poke_executor_control();
                    if let Some(status) = status {
                        self.publish_exit(InitialProcessExit::Exited {
                            code: status.code(),
                            exits: exited,
                        })?;
                        Ok(ExecutorExit::Exited)
                    } else {
                        Ok(ExecutorExit::ResumeEl1)
                    }
                }
                CarrierRunExit::SyscallTrap => {
                    let binding = self.binding.as_ref().ok_or_else(|| {
                        TrapError::Hypervisor("KVM forward lost task binding".into())
                    })?;
                    let mut dispatcher = self
                        .dispatcher
                        .lock()
                        .map_err(|_| TrapError::Hypervisor("KVM dispatcher poisoned".into()))?;
                    let (decision, token) =
                        self.physical.capture_forward(task, |venue, frame| {
                            let bridge = frame.rax == 281
                                && carrick_el1_abi::HostPollEpollBridge::is_bridge(
                                    frame.rdi, frame.rcx,
                                );
                            let syscall = if bridge {
                                carrick_guest_mem::X8664SyscallFrame {
                                    rax: 7,
                                    rdi: frame.rsi,
                                    rsi: frame.rdx,
                                    rdx: frame.r10,
                                    r10: 0,
                                    r8: 0,
                                    r9: 0,
                                }
                            } else {
                                carrick_guest_mem::X8664SyscallFrame {
                                    rax: frame.rax,
                                    rdi: frame.rdi,
                                    rsi: frame.rsi,
                                    rdx: frame.rdx,
                                    r10: frame.r10,
                                    r8: frame.r8,
                                    r9: frame.r9,
                                }
                            };
                            let raw = match X8664GuestArch::normalize_syscall(&syscall) {
                                SyscallNorm::Plain(raw) => raw,
                                SyscallNorm::ArchPrctl { code, addr } => {
                                    let value = carrick_hal::x8664_arch::service_arch_prctl(
                                        venue, code, addr,
                                    )?;
                                    return Ok(ForwardDecision::Immediate(
                                        InitialSyscallDisposition::Return(value),
                                    ));
                                }
                            };
                            let host_poll = raw.native_number.0 == 7
                                && (bridge
                                    || crate::prepare::initial_poll_has_only_host_fds(
                                        venue, raw.args,
                                    ));
                            let class = crate::prepare::classify_initial_x86_forward(
                                raw.native_number,
                                raw.args,
                                host_poll,
                            );
                            self.stats.record(class)?;
                            match class {
                                crate::prepare::InitialForwardClass::Host(_) => {}
                                refusal @ crate::prepare::InitialForwardClass::Refuse(_) => {
                                    self.reporter.record(
                                        carrick_kernel::compat::CompatEvent::partial_syscall(
                                            raw.number.0,
                                            format!("x86_native_{}", raw.native_number.0),
                                            carrick_kernel::compat::SyscallArgs::new(raw.args),
                                            format!("cpl0_{}_owner_unbound", refusal.family()),
                                        ),
                                    );
                                    return Ok(ForwardDecision::Immediate(
                                        InitialSyscallDisposition::Refused(
                                            carrick_abi::LINUX_ENOSYS,
                                        ),
                                    ));
                                }
                            }
                            let kernel = binding.fresh_context()?;
                            let request = SyscallRequest::from_raw(raw)
                                .with_current_guest_sp(Some(frame.rsp));
                            let outcome = dispatcher
                                .dispatch(&kernel, request, venue, &self.reporter)
                                .map_err(|error| {
                                    TrapError::Hypervisor(format!("dispatch x86 syscall: {error}"))
                                })?;
                            match outcome {
                                DispatchOutcome::Returned { value } => {
                                    Ok(ForwardDecision::Immediate(
                                        InitialSyscallDisposition::Return(value),
                                    ))
                                }
                                DispatchOutcome::Errno { errno } => Ok(ForwardDecision::Immediate(
                                    InitialSyscallDisposition::Refused(errno),
                                )),
                                DispatchOutcome::Exit { code }
                                | DispatchOutcome::ThreadExit { code } => {
                                    Ok(ForwardDecision::Immediate(InitialSyscallDisposition::Exit(
                                        GuestExitStatus::from_linux_code(code),
                                    )))
                                }
                                other => Ok(ForwardDecision::Blocked(request, Box::new(other))),
                            }
                        })?;
                    {
                        let hook = self
                            .first_forward_hook
                            .lock()
                            .map_err(|_| TrapError::Hypervisor("KVM fixture hook poisoned".into()))?
                            .take();
                        if let Some(hook) = hook {
                            hook(&mut self.physical)?;
                        }
                    }
                    drop(dispatcher);
                    match decision {
                        ForwardDecision::Blocked(request, outcome) => {
                            return Self::block_forward(
                                binding,
                                submission,
                                request,
                                *outcome,
                                Some(token),
                            );
                        }
                        ForwardDecision::Immediate(InitialSyscallDisposition::Return(value)) => {
                            self.physical.complete_forward(task, token, value)?
                        }
                        ForwardDecision::Immediate(InitialSyscallDisposition::Refused(errno)) => {
                            self.physical
                                .complete_forward(task, token, errno.guest_retval())?
                        }
                        ForwardDecision::Immediate(InitialSyscallDisposition::Exit(status)) => {
                            self.publish_exit(InitialProcessExit::Exited {
                                code: status.code(),
                                exits: exited,
                            })?;
                            return Ok(ExecutorExit::Exited);
                        }
                    }
                    // A physical peer parked after HLT may have acquired an
                    // interrupt while this CPU stayed in the guest. The stopped
                    // forward is the same bounded inspection point used by the
                    // carrier's physical coordinator.
                    self.scheduler.poke_executor_control();
                    Ok(ExecutorExit::Syscall)
                }
                CarrierRunExit::Kick => Ok(ExecutorExit::Preempted),
                CarrierRunExit::FaultDoorbellWord(first) => {
                    let record = self.physical.capture_fault_record(task, *first)?;
                    self.publish_exit(InitialProcessExit::Fault {
                        record,
                        exits: exited,
                    })?;
                    Ok(ExecutorExit::Exited)
                }
                CarrierRunExit::FaultException { .. } | CarrierRunExit::Halt => {
                    Err(TrapError::Hypervisor("unexpected KVM task exit".into()))
                }
            }
        })();
        if let Err(error) = &result {
            if !self.completion_sent {
                let _ = self.completed.send(Err(error.to_string()));
                self.completion_sent = true;
            }
        }
        result
    }

    fn take_cpu_receipt(&mut self) -> ExecutorCpuReceipt {
        ExecutorCpuReceipt::default()
    }

    fn hardware_kick(&self) -> Result<ExactHardwareKick, TrapError> {
        let slot = self
            .physical
            .physical_slot()
            .ok_or_else(|| TrapError::Hypervisor("KVM executor has no physical slot".into()))?;
        ExactHardwareKick::new(
            Box::new(carrick_vmm_kvm::KvmKickHandle::for_current_thread()),
            u64::from(slot.raw()),
            super::current_owner_thread_port(),
        )
    }

    fn save(
        &mut self,
        mut lease: ThreadExecutionLease,
    ) -> Result<SavedRunnable, ExecutorSaveError> {
        let task = match self.task.take() {
            Some(task) => task,
            None => {
                return Err(ExecutorSaveError::new(
                    TrapError::Hypervisor("KVM save without task".into()),
                    lease,
                ));
            }
        };
        let saved = match self.physical.cpu_mut().save_and_detach(task) {
            Ok(saved) => saved,
            Err(error) => {
                return Err(ExecutorSaveError::new(
                    TrapError::Hypervisor(format!("KVM save and detach: {error}")),
                    lease,
                ));
            }
        };
        let (mm, asid_generation) = match lease.task_state_authority() {
            Ok(identity) => identity,
            Err(error) => {
                return Err(ExecutorSaveError::new(
                    TrapError::Hypervisor(error.to_string()),
                    lease,
                ));
            }
        };
        if let Err(error) = lease.replace_task_state(MigratableTaskState {
            cpu: GuestCpuState::X86_64V1(Arc::new(saved.state().clone())),
            mm,
            asid_generation,
        }) {
            return Err(ExecutorSaveError::new(
                TrapError::Hypervisor(error.to_string()),
                lease,
            ));
        }
        self.binding = None;
        Ok(SavedRunnable::new(lease))
    }

    fn invalidate_asid(
        &mut self,
        _generation: crate::hvpatch::AsidGeneration,
    ) -> Result<(), TrapError> {
        Ok(())
    }
    fn audit_boundary(&mut self) -> Result<(), TrapError> {
        if self
            .physical
            .physical_slot()
            .is_some_and(|slot| slot.raw() == 1)
        {
            self.physical.audit_unloaded_peer()
        } else {
            self.physical.cpu_mut().audit_idle()
        }
    }
    fn destroy(mut self) -> Result<(), TrapError> {
        self.audit_boundary()
    }

    fn wait_in_guest(&mut self) -> Result<GuestIdleExit, TrapError> {
        if self
            .physical
            .physical_slot()
            .is_none_or(|slot| slot.raw() != 1)
        {
            return Ok(GuestIdleExit::Unsupported);
        }
        match self.physical.run_idle_peer()? {
            exit @ CarrierRunExit::PhysicalDoorbell { .. } => {
                if let Some(status) = self.physical.service_idle_peer_doorbell(&exit)? {
                    let exits = self.exits.load(Ordering::Acquire);
                    self.publish_exit(InitialProcessExit::Exited {
                        code: status.code(),
                        exits,
                    })?;
                }
                Ok(GuestIdleExit::Idle)
            }
            CarrierRunExit::Halt => Ok(GuestIdleExit::Unsupported),
            CarrierRunExit::Kick => Ok(GuestIdleExit::Idle),
            other => Err(TrapError::Hypervisor(format!(
                "idle KVM peer needs a host task handback: {other:?}"
            ))),
        }
    }
}

pub(crate) struct KvmTaskBinding {
    identity: TaskLoadIdentity,
    arch: GuestArchBinding,
    thread: ThreadKey,
    kernel_binding: KernelTaskBinding,
    retained: Mutex<Option<RetainedForward>>,
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
        let binding = Self {
            identity,
            arch,
            thread: context.thread().key(),
            kernel_binding: context.task_binding(),
            retained: Mutex::new(None),
        };
        binding.validate_task_state(state)?;
        Ok(binding)
    }

    pub(crate) const fn arch(&self) -> GuestArchBinding {
        self.arch
    }

    pub(crate) fn fresh_context(&self) -> Result<KernelContext, TrapError> {
        self.kernel_binding
            .capture(self.thread.tid)
            .map_err(|error| {
                TrapError::Hypervisor(format!("KVM task binding became stale: {error}"))
            })
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
