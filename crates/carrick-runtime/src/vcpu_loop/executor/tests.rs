use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread::{self, ThreadId as HostThreadId};
use std::time::{Duration, Instant};

use carrick_abi::LinuxCloneFlags;
use carrick_hal::ThreadId;
use carrick_hal::threaded::{Aarch64SyscallContinuationV1, Aarch64TaskCpuStateV1, GuestCpuState};

use super::{
    ExecBindingTransition, ExecutorBoundaryAudit, ExecutorCpuReceipt, ExecutorExit, ExecutorPool,
    ExecutorPoolConfig, ExecutorPoolEvent, ExecutorSaveError, ExecutorSubmissionContext,
    HvpatchActivationProof, HvpatchQuantumControl, HvpatchSubmissionShape,
    HvpatchTaskBindingDirectory, PersistentExecutor, PersistentExecutorFactory,
    PersistentTaskBinding, ReceiptLog, RunnableTask, SavedRunnable, TaskBindingResolver,
    TaskLoadIdentity, WorkerBoundaryAudit, WorkerKick, executor_claim_probe_asid_generation,
    process_leader_event_identity, restore_worker_vcpu_before_binding_publication,
    retire_failed_hvpatch_clone_authority,
};
use crate::compat::SyscallArgs;
use crate::dispatch::{DispatchOutcome, SyscallDispatcher, SyscallRequest};
use crate::kernel::objects::{
    BlockedReason, ExecutionFailure, ExecutionGeneration, ExecutorId, MigratableTaskState,
    ThreadExecutionLease, ThreadExecutionState,
};
use crate::kernel::scheduler::{ExecutorBinding, ExecutorKick, ExecutorKickToken};
use crate::kernel::{
    ClonePlan, Kernel, KernelContext, RootBootstrap, Scheduler, SchedulerError,
    SubmissionAuthority, ThreadKey,
};
use crate::trap::TrapError;

#[derive(Clone)]
struct TestVcpuKick;

impl carrick_hal::VcpuKick for TestVcpuKick {
    fn kick(&self) {}
}

fn test_hardware_kick(raw_vcpu_id: u64) -> super::ExactHardwareKick {
    super::ExactHardwareKick::new(
        Box::new(TestVcpuKick),
        raw_vcpu_id.max(1),
        super::current_owner_thread_port(),
    )
    .unwrap()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
    Syscalls(usize),
    ComputeUntilKick,
    Block,
    Yield,
    Preempt,
    Exit,
    FailRun,
    PanicRun,
    LoseLease,
    Invalid,
}

#[derive(Debug)]
struct DescendantPublication {
    child_thread: Arc<crate::kernel::Thread>,
    child_generation: ExecutionGeneration,
    after_progress: usize,
    published: Option<std::sync::mpsc::Sender<()>>,
}

#[derive(Debug)]
struct FakeBinding {
    marker: u64,
    steps: parking_lot::Mutex<VecDeque<Step>>,
    load_fails: AtomicBool,
    save_fails: AtomicBool,
    audit_fails: AtomicBool,
    entered: parking_lot::Mutex<Option<Arc<Barrier>>>,
    resume: parking_lot::Mutex<Option<Arc<Barrier>>>,
    progress: AtomicUsize,
    load_identity: parking_lot::Mutex<Option<TaskLoadIdentity>>,
    required_continuation_sequence: parking_lot::Mutex<Option<u64>>,
    blocked_continuation:
        parking_lot::Mutex<Option<crate::vcpu_loop::continuation::BlockedContinuation>>,
    blocked_vfork_activation: parking_lot::Mutex<Option<super::PreparedVforkChildActivation>>,
    terminal_settlement_notification: parking_lot::Mutex<Option<std::sync::mpsc::Sender<()>>>,
    descendant: parking_lot::Mutex<Option<DescendantPublication>>,
    pending_address_space_retirement:
        parking_lot::Mutex<Option<crate::hvpatch::PendingAddressSpaceRetirement>>,
    retire_detached_address_space_gate: parking_lot::Mutex<Option<std::sync::mpsc::Sender<()>>>,
    retire_detached_address_space_resume: parking_lot::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}

impl FakeBinding {
    fn new(marker: u64, steps: impl IntoIterator<Item = Step>) -> Arc<Self> {
        Arc::new(Self {
            marker,
            steps: parking_lot::Mutex::new(steps.into_iter().collect()),
            load_fails: AtomicBool::new(false),
            save_fails: AtomicBool::new(false),
            audit_fails: AtomicBool::new(false),
            entered: parking_lot::Mutex::new(None),
            resume: parking_lot::Mutex::new(None),
            progress: AtomicUsize::new(0),
            load_identity: parking_lot::Mutex::new(None),
            required_continuation_sequence: parking_lot::Mutex::new(None),
            blocked_continuation: parking_lot::Mutex::new(None),
            blocked_vfork_activation: parking_lot::Mutex::new(None),
            terminal_settlement_notification: parking_lot::Mutex::new(None),
            descendant: parking_lot::Mutex::new(None),
            pending_address_space_retirement: parking_lot::Mutex::new(None),
            retire_detached_address_space_gate: parking_lot::Mutex::new(None),
            retire_detached_address_space_resume: parking_lot::Mutex::new(None),
        })
    }

    fn override_expected_abi(&self, abi: carrick_abi::LinuxGuestAbi) {
        self.load_identity
            .lock()
            .as_mut()
            .expect("installed load identity")
            .abi = abi;
    }

    fn override_expected_version(&self, version: u16) {
        self.load_identity
            .lock()
            .as_mut()
            .expect("installed load identity")
            .version = version;
    }

    fn override_expected_mm(&self, mm: crate::kernel::MmId) {
        self.load_identity
            .lock()
            .as_mut()
            .expect("installed load identity")
            .mm = mm;
    }

    fn override_expected_asid_generation(&self, asid_generation: u64) {
        self.load_identity
            .lock()
            .as_mut()
            .expect("installed load identity")
            .asid_generation = asid_generation;
    }

    fn require_continuation_sequence(&self, sequence: u64) {
        *self.required_continuation_sequence.lock() = Some(sequence);
    }

    fn block_with_continuation(
        &self,
        continuation: crate::vcpu_loop::continuation::BlockedContinuation,
    ) {
        *self.blocked_continuation.lock() = Some(continuation);
    }

    fn block_with_vfork_continuation(
        &self,
        continuation: crate::vcpu_loop::continuation::BlockedContinuation,
        vfork_activation: super::PreparedVforkChildActivation,
    ) {
        *self.blocked_continuation.lock() = Some(continuation);
        *self.blocked_vfork_activation.lock() = Some(vfork_activation);
    }

    fn notify_on_terminal_settlement(&self, notification: std::sync::mpsc::Sender<()>) {
        *self.terminal_settlement_notification.lock() = Some(notification);
    }
}

impl PersistentTaskBinding for FakeBinding {
    fn load_identity(&self) -> TaskLoadIdentity {
        self.load_identity
            .lock()
            .expect("fake binding installed before publication")
    }

    fn validate_task_state(&self, state: &MigratableTaskState) -> Result<(), TrapError> {
        let Some(expected) = *self.required_continuation_sequence.lock() else {
            return Ok(());
        };
        let actual = match &state.cpu {
            GuestCpuState::Aarch64V1(state) => state
                .syscall_continuation
                .map(|continuation| continuation.sequence),
            GuestCpuState::X86_64V1(_) => None,
        };
        if actual != Some(expected) || expected == 0 {
            return Err(TrapError::Hypervisor(format!(
                "fake task continuation mismatch: expected {expected}, got {actual:?}"
            )));
        }
        Ok(())
    }

    fn after_terminal_settlement(&self) {
        if let Some(notification) = self.terminal_settlement_notification.lock().take() {
            notification
                .send(())
                .expect("publish fake terminal settlement");
        }
    }

    fn take_address_space_retirement(
        &self,
    ) -> Option<crate::hvpatch::PendingAddressSpaceRetirement> {
        self.pending_address_space_retirement.lock().take()
    }

    fn retire_detached_address_space(
        &self,
        root_ticket: Option<crate::hvpatch::Stage1RootRetirementTicket>,
    ) -> Result<Option<crate::hvpatch::Stage1RootRetirementReceipt>, TrapError> {
        if let Some(gate) = self.retire_detached_address_space_gate.lock().take() {
            let _ = gate.send(());
        }
        if let Some(resume) = self.retire_detached_address_space_resume.lock().take() {
            let _ = resume.recv_timeout(std::time::Duration::from_secs(5));
        }
        Ok(root_ticket.map(|ticket| ticket.complete_for_test()))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackendEventKind {
    Create,
    Destroy,
    Load,
    Save,
    Run,
    Audit,
    Invalidate,
}

#[derive(Clone, Debug)]
struct BackendEvent {
    kind: BackendEventKind,
    executor: ExecutorId,
    host_thread: HostThreadId,
    task: Option<(ThreadKey, ExecutionGeneration)>,
}

/// One recorded `(ttbr0, ttbr1, asid, tls, sp_el1)` row observed by the
/// fake backend when a task loads onto an executor.
type InheritedStateRow = (u64, u64, u64, u64, u64);

#[derive(Clone, Default)]
struct FakeFactory {
    bindings: Arc<parking_lot::Mutex<BTreeMap<ThreadKey, Arc<FakeBinding>>>>,
    authorities:
        Arc<parking_lot::Mutex<BTreeMap<(ThreadKey, ExecutionGeneration), SubmissionAuthority>>>,
    scheduler: Arc<parking_lot::Mutex<std::sync::Weak<Scheduler>>>,
    events: Arc<parking_lot::Mutex<Vec<BackendEvent>>>,
    create_calls: Arc<AtomicUsize>,
    fail_create_call: Arc<AtomicUsize>,
    panic_initial_audit_call: Arc<AtomicUsize>,
    initial_audit_gate: Arc<parking_lot::Mutex<Option<Arc<Barrier>>>>,
    fail_invalidation_generation: Arc<AtomicU64>,
    fail_hardware_kick: Arc<AtomicBool>,
    drift_hardware_on_load: Arc<AtomicBool>,
    hardware_vcpu_offset: Arc<AtomicU64>,
    owner_dirty_mode: Arc<AtomicUsize>,
    owner_dirty_fds: Arc<parking_lot::Mutex<Vec<(i32, i32)>>>,
    destroy_mode: Arc<AtomicUsize>,
    snapshot_count: Arc<AtomicUsize>,
    concurrent_loads: Arc<parking_lot::Mutex<BTreeSet<(ThreadKey, ExecutionGeneration)>>>,
    inherited_state: Arc<parking_lot::Mutex<Vec<InheritedStateRow>>>,
    retired_bindings: Arc<parking_lot::Mutex<Vec<(ThreadKey, ExecutionGeneration)>>>,
    directory: Arc<parking_lot::Mutex<Option<Arc<HvpatchTaskBindingDirectory>>>>,
}

impl FakeFactory {
    fn install(&self, context: &KernelContext, binding: Arc<FakeBinding>) {
        let mm = context.shared().mm().id();
        *binding.load_identity.lock() = Some(TaskLoadIdentity {
            abi: carrick_abi::LinuxGuestAbi::Aarch64,
            version: 1,
            mm,
            asid_generation: mm.raw(),
        });
        self.bindings.lock().insert(context.thread().key(), binding);
    }

    fn install_directory(&self, directory: Arc<HvpatchTaskBindingDirectory>) {
        *self.directory.lock() = Some(directory);
    }

    fn record(
        &self,
        kind: BackendEventKind,
        executor: ExecutorId,
        task: Option<(ThreadKey, ExecutionGeneration)>,
    ) {
        self.events.lock().push(BackendEvent {
            kind,
            executor,
            host_thread: thread::current().id(),
            task,
        });
    }
}

impl TaskBindingResolver<FakeBinding> for FakeFactory {
    fn install_scheduler(self: &Arc<Self>, scheduler: &Arc<Scheduler>) -> Result<(), TrapError> {
        *self.scheduler.lock() = Arc::downgrade(scheduler);
        scheduler
            .install_generation_observer(
                Arc::clone(self) as Arc<dyn crate::kernel::scheduler::SchedulerGenerationObserver>
            )
            .map_err(|error| TrapError::Hypervisor(error.to_string()))
    }

    fn resolve(
        &self,
        thread: ThreadKey,
        _generation: ExecutionGeneration,
    ) -> Result<Arc<FakeBinding>, TrapError> {
        self.bindings
            .lock()
            .get(&thread)
            .cloned()
            .ok_or_else(|| TrapError::Hypervisor(format!("missing fake binding for {thread:?}")))
    }

    fn retire(&self, thread: ThreadKey, generation: ExecutionGeneration) {
        if let Some(dir) = self.directory.lock().as_ref() {
            dir.retire(thread, generation);
        }
        self.authorities.lock().remove(&(thread, generation));
        self.retired_bindings.lock().push((thread, generation));
    }

    fn cancel_dormant(
        &self,
        scheduler: &Scheduler,
        failure: ExecutionFailure,
    ) -> Result<usize, TrapError> {
        if let Some(dir) = self.directory.lock().as_ref() {
            dir.cancel_dormant(scheduler, failure)
        } else {
            Ok(0)
        }
    }

    fn take_submission_authority(
        &self,
        thread: ThreadKey,
        generation: ExecutionGeneration,
    ) -> Option<SubmissionAuthority> {
        self.authorities.lock().remove(&(thread, generation))
    }

    fn restore_submission_authority(
        &self,
        authority: SubmissionAuthority,
    ) -> Result<(), SubmissionAuthority> {
        let key = (authority.thread_key(), authority.generation());
        let mut authorities = self.authorities.lock();
        if authorities.contains_key(&key) {
            return Err(authority);
        }
        authorities.insert(key, authority);
        Ok(())
    }

    fn publish_test_root(
        &self,
        scheduler: &Scheduler,
        thread: Arc<crate::kernel::Thread>,
        authority: SubmissionAuthority,
    ) -> Result<(), SchedulerError> {
        let key = (authority.thread_key(), authority.generation());
        let mut authorities = self.authorities.lock();
        if authorities.contains_key(&key) {
            return Err(crate::kernel::RunQueueError::SubmissionRejected.into());
        }
        authority.publish(scheduler, thread)?;
        authorities.insert(key, authority);
        Ok(())
    }

    fn publish_test_descendant(
        &self,
        scheduler: &Scheduler,
        parent: &SubmissionAuthority,
        thread: Arc<crate::kernel::Thread>,
        generation: ExecutionGeneration,
    ) -> Result<(), TrapError> {
        let authority = parent
            .admit_descendant(thread.key(), generation)
            .map_err(|error| TrapError::Hypervisor(error.to_string()))?;
        self.publish_test_root(scheduler, thread, authority)
            .map_err(|error| TrapError::Hypervisor(error.to_string()))
    }
}

impl crate::kernel::scheduler::SchedulerGenerationObserver for FakeFactory {
    fn transition(
        &self,
        thread: ThreadKey,
        predecessor: ExecutionGeneration,
        successor: ExecutionGeneration,
        kind: crate::kernel::scheduler::SchedulerGenerationTransition,
    ) -> Result<(), crate::kernel::RunQueueError> {
        let Some(scheduler) = self.scheduler.lock().upgrade() else {
            return Err(crate::kernel::RunQueueError::Closed);
        };
        let mut authorities = self.authorities.lock();
        let Some(authority) = authorities.remove(&(thread, predecessor)) else {
            return Ok(());
        };
        if kind == crate::kernel::scheduler::SchedulerGenerationTransition::Terminal {
            return Ok(());
        }
        if authorities.contains_key(&(thread, successor)) {
            return Err(crate::kernel::RunQueueError::SubmissionRejected);
        }
        let authority = if kind == crate::kernel::scheduler::SchedulerGenerationTransition::Blocked
        {
            authority
                .park_exact(&scheduler, predecessor, successor)
                .map_err(|(error, _authority)| error)?
        } else if authority.is_active() {
            authority
                .rollover_exact(&scheduler, thread, predecessor, thread, successor)
                .map_err(|(error, _authority)| error)?
        } else {
            authority
                .reactivate_exact(&scheduler, predecessor, successor)
                .map_err(|(error, _authority)| error)?
        };
        authorities.insert((thread, successor), authority);
        Ok(())
    }
}

struct FakeExecutor {
    id: ExecutorId,
    factory: FakeFactory,
    owner: HostThreadId,
    create_call: usize,
    current: Option<(ThreadKey, ExecutionGeneration, Arc<FakeBinding>)>,
    owner_dirty_cleanup: Option<Box<dyn FnOnce()>>,
    credentials: u64,
    restart_state: u64,
    mailbox: u64,
    tls: u64,
    user_ns: u64,
    system_ns: u64,
}

struct BoundaryAuditProbe;

#[derive(Debug)]
struct MaliciousBinding {
    identity: TaskLoadIdentity,
    entered: Arc<Barrier>,
    resume: Arc<Barrier>,
}

impl PersistentTaskBinding for MaliciousBinding {
    fn load_identity(&self) -> TaskLoadIdentity {
        self.identity
    }

    fn validate_task_state(&self, _state: &MigratableTaskState) -> Result<(), TrapError> {
        Ok(())
    }
}

#[derive(Debug, Default)]
struct MaliciousFactory {
    bindings: parking_lot::Mutex<BTreeMap<ThreadKey, Arc<MaliciousBinding>>>,
    authorities:
        parking_lot::Mutex<BTreeMap<(ThreadKey, ExecutionGeneration), SubmissionAuthority>>,
}

impl MaliciousFactory {
    fn install(&self, context: &KernelContext, entered: Arc<Barrier>, resume: Arc<Barrier>) {
        let mm = context.shared().mm().id();
        self.bindings.lock().insert(
            context.thread().key(),
            Arc::new(MaliciousBinding {
                identity: TaskLoadIdentity {
                    abi: carrick_abi::LinuxGuestAbi::Aarch64,
                    version: 1,
                    mm,
                    asid_generation: mm.raw(),
                },
                entered,
                resume,
            }),
        );
    }
}

impl TaskBindingResolver<MaliciousBinding> for MaliciousFactory {
    fn resolve(
        &self,
        thread: ThreadKey,
        _generation: ExecutionGeneration,
    ) -> Result<Arc<MaliciousBinding>, TrapError> {
        self.bindings
            .lock()
            .get(&thread)
            .cloned()
            .ok_or_else(|| TrapError::Hypervisor("missing malicious binding".to_owned()))
    }

    fn take_submission_authority(
        &self,
        thread: ThreadKey,
        generation: ExecutionGeneration,
    ) -> Option<SubmissionAuthority> {
        self.authorities.lock().remove(&(thread, generation))
    }

    fn restore_submission_authority(
        &self,
        authority: SubmissionAuthority,
    ) -> Result<(), SubmissionAuthority> {
        let key = (authority.thread_key(), authority.generation());
        let mut authorities = self.authorities.lock();
        if authorities.contains_key(&key) {
            return Err(authority);
        }
        authorities.insert(key, authority);
        Ok(())
    }

    fn publish_test_root(
        &self,
        scheduler: &Scheduler,
        thread: Arc<crate::kernel::Thread>,
        authority: SubmissionAuthority,
    ) -> Result<(), SchedulerError> {
        let key = (authority.thread_key(), authority.generation());
        let mut authorities = self.authorities.lock();
        if authorities.contains_key(&key) {
            return Err(crate::kernel::RunQueueError::SubmissionRejected.into());
        }
        authority.publish(scheduler, thread)?;
        authorities.insert(key, authority);
        Ok(())
    }

    fn retire(&self, thread: ThreadKey, generation: ExecutionGeneration) {
        self.authorities.lock().remove(&(thread, generation));
    }
}

struct MaliciousExecutor {
    id: ExecutorId,
    current: Option<Arc<MaliciousBinding>>,
}

impl PersistentExecutorFactory for MaliciousFactory {
    type Executor = MaliciousExecutor;

    fn create(&self, executor: ExecutorId) -> Result<Self::Executor, TrapError> {
        Ok(MaliciousExecutor {
            id: executor,
            current: None,
        })
    }
}

impl PersistentExecutor for MaliciousExecutor {
    type TaskBinding = MaliciousBinding;

    fn load(&mut self, task: &RunnableTask<'_, Self::TaskBinding>) -> Result<(), TrapError> {
        task.validate_for_load()?;
        self.current = Some(Arc::clone(task.binding()));
        Ok(())
    }

    fn run_until_boundary(
        &mut self,
        _need_resched: &AtomicBool,
        _submission: &mut super::ExecutorSubmissionContext<'_>,
    ) -> Result<ExecutorExit, TrapError> {
        let binding = self.current.as_ref().expect("malicious binding loaded");
        binding.entered.wait();
        binding.resume.wait();
        Err(TrapError::Hypervisor(
            "malicious backend retains binding through failure".to_owned(),
        ))
    }

    fn take_cpu_receipt(&mut self) -> ExecutorCpuReceipt {
        ExecutorCpuReceipt::default()
    }

    fn hardware_kick(&self) -> Result<super::ExactHardwareKick, TrapError> {
        Ok(test_hardware_kick(u64::from(self.id.raw_for_probe())))
    }

    fn save(&mut self, lease: ThreadExecutionLease) -> Result<SavedRunnable, ExecutorSaveError> {
        Err(ExecutorSaveError::new(
            TrapError::Hypervisor("malicious executor cannot save".to_owned()),
            lease,
        ))
    }

    fn invalidate_asid(
        &mut self,
        _generation: crate::hvpatch::AsidGeneration,
    ) -> Result<(), TrapError> {
        Ok(())
    }

    fn audit_boundary(&mut self) -> Result<(), TrapError> {
        Ok(())
    }

    fn destroy(self) -> Result<(), TrapError> {
        drop(self.current);
        Ok(())
    }
}

impl PersistentExecutor for BoundaryAuditProbe {
    type TaskBinding = FakeBinding;

    fn load(&mut self, _task: &RunnableTask<'_, Self::TaskBinding>) -> Result<(), TrapError> {
        panic!("audit-only backend cannot load a task")
    }

    fn run_until_boundary(
        &mut self,
        _need_resched: &AtomicBool,
        _submission: &mut super::ExecutorSubmissionContext<'_>,
    ) -> Result<ExecutorExit, TrapError> {
        panic!("audit-only backend cannot run a task")
    }

    fn take_cpu_receipt(&mut self) -> ExecutorCpuReceipt {
        panic!("audit-only backend has no CPU receipt")
    }

    fn hardware_kick(&self) -> Result<super::ExactHardwareKick, TrapError> {
        panic!("audit-only backend has no hardware kick")
    }

    fn save(&mut self, _lease: ThreadExecutionLease) -> Result<SavedRunnable, ExecutorSaveError> {
        panic!("audit-only backend cannot save a task")
    }

    fn invalidate_asid(
        &mut self,
        _generation: crate::hvpatch::AsidGeneration,
    ) -> Result<(), TrapError> {
        panic!("audit-only backend cannot invalidate an ASID")
    }

    fn audit_boundary(&mut self) -> Result<(), TrapError> {
        Ok(())
    }

    fn destroy(self) -> Result<(), TrapError> {
        Ok(())
    }
}

impl PersistentExecutorFactory for FakeFactory {
    type Executor = FakeExecutor;

    fn create(&self, executor: ExecutorId) -> Result<Self::Executor, TrapError> {
        let call = self.create_calls.fetch_add(1, Ordering::SeqCst) + 1;
        self.record(BackendEventKind::Create, executor, None);
        if self.fail_create_call.load(Ordering::SeqCst) == call {
            return Err(TrapError::Hypervisor("injected create failure".to_owned()));
        }
        Ok(FakeExecutor {
            id: executor,
            factory: self.clone(),
            owner: thread::current().id(),
            create_call: call,
            current: None,
            owner_dirty_cleanup: None,
            credentials: 0,
            restart_state: 0,
            mailbox: 0,
            tls: 0,
            user_ns: 0,
            system_ns: 0,
        })
    }
}

impl PersistentExecutor for FakeExecutor {
    type TaskBinding = FakeBinding;

    fn load(&mut self, task: &RunnableTask<'_, Self::TaskBinding>) -> Result<(), TrapError> {
        assert_eq!(thread::current().id(), self.owner);
        task.validate_for_load()?;
        let key = (task.thread_key(), task.generation());
        assert_eq!(task.lease().generation(), task.generation());
        assert_eq!(task.lease().executor(), self.id);
        if !self.factory.concurrent_loads.lock().insert(key) {
            return Err(TrapError::Hypervisor("concurrent double-load".to_owned()));
        }
        let binding = Arc::clone(task.binding());
        if binding.load_fails.load(Ordering::SeqCst) {
            self.factory.concurrent_loads.lock().remove(&key);
            return Err(TrapError::Hypervisor("injected load failure".to_owned()));
        }
        self.factory.inherited_state.lock().push((
            binding.marker,
            self.credentials,
            self.restart_state,
            self.mailbox,
            self.tls,
        ));
        self.credentials = binding.marker + 1;
        self.restart_state = binding.marker + 2;
        self.mailbox = binding.marker + 3;
        self.tls = binding.marker + 4;
        self.current = Some((key.0, key.1, Arc::clone(&binding)));
        if self.factory.drift_hardware_on_load.load(Ordering::SeqCst) {
            self.factory.hardware_vcpu_offset.store(1, Ordering::SeqCst);
        }
        self.factory
            .record(BackendEventKind::Load, self.id, Some(key));
        Ok(())
    }

    fn run_until_boundary(
        &mut self,
        need_resched: &AtomicBool,
        submission: &mut super::ExecutorSubmissionContext<'_>,
    ) -> Result<ExecutorExit, TrapError> {
        assert_eq!(thread::current().id(), self.owner);
        let (thread, generation, binding) = self.current.as_ref().expect("loaded task");
        self.factory
            .record(BackendEventKind::Run, self.id, Some((*thread, *generation)));
        binding.progress.fetch_add(1, Ordering::SeqCst);
        if let Some(gate) = binding.entered.lock().take() {
            gate.wait();
        }
        if let Some(gate) = binding.resume.lock().take() {
            gate.wait();
        }
        let should_publish = binding
            .descendant
            .lock()
            .as_ref()
            .is_some_and(|publication| {
                binding.progress.load(Ordering::SeqCst) >= publication.after_progress
            });
        if should_publish {
            let publication = binding
                .descendant
                .lock()
                .take()
                .expect("ready descendant publication");
            submission
                .publish_test_descendant(
                    Arc::clone(&publication.child_thread),
                    publication.child_generation,
                )
                .expect("publish descendant during closing");
            if let Some(published) = publication.published {
                published.send(()).expect("publish descendant receipt");
            }
        }
        let step = {
            let mut steps = binding.steps.lock();
            let step = steps.pop_front().unwrap_or(Step::Exit);
            match step {
                Step::Syscalls(remaining) if remaining > 1 => {
                    steps.push_front(Step::Syscalls(remaining - 1));
                    Step::Syscalls(remaining)
                }
                other => other,
            }
        };
        self.user_ns = self.user_ns.saturating_add(7_000);
        self.system_ns = self.system_ns.saturating_add(3_000);
        match step {
            Step::Syscalls(_) => Ok(ExecutorExit::Syscall),
            Step::ComputeUntilKick => {
                let deadline = Instant::now() + Duration::from_secs(2);
                while !need_resched.load(Ordering::Acquire) && Instant::now() < deadline {
                    binding.progress.fetch_add(1, Ordering::Relaxed);
                    thread::yield_now();
                }
                if need_resched.load(Ordering::Acquire) {
                    Ok(ExecutorExit::Preempted)
                } else {
                    Err(TrapError::Hypervisor(
                        "fake compute task was never kicked".to_owned(),
                    ))
                }
            }
            Step::Block => {
                let continuation = binding.blocked_continuation.lock().take();
                let vfork_activation = binding.blocked_vfork_activation.lock().take();
                if let Some(continuation) = continuation {
                    Ok(ExecutorExit::BlockedContinuation {
                        continuation: Box::new(continuation),
                        vfork_activation,
                    })
                } else {
                    Ok(ExecutorExit::Blocked(BlockedReason::HostWait))
                }
            }
            Step::Yield => Ok(ExecutorExit::Yielded),
            Step::Preempt => Ok(ExecutorExit::Preempted),
            Step::Exit => Ok(ExecutorExit::Exited),
            Step::FailRun => Err(TrapError::Hypervisor("injected run failure".to_owned())),
            Step::PanicRun => panic!("injected executor panic"),
            Step::LoseLease => {
                let lease = submission
                    .execution_lease_slot_mut()
                    .take()
                    .expect("worker injected exact lease");
                std::mem::forget(lease);
                Ok(ExecutorExit::InvalidState)
            }
            Step::Invalid => Ok(ExecutorExit::InvalidState),
        }
    }

    fn take_cpu_receipt(&mut self) -> ExecutorCpuReceipt {
        let receipt = ExecutorCpuReceipt {
            user_ns: self.user_ns,
            system_ns: self.system_ns,
        };
        self.user_ns = 0;
        self.system_ns = 0;
        receipt
    }

    fn hardware_kick(&self) -> Result<super::ExactHardwareKick, TrapError> {
        if self.factory.fail_hardware_kick.load(Ordering::SeqCst) {
            return Err(TrapError::Hypervisor(
                "injected missing exact hardware identity".to_owned(),
            ));
        }
        Ok(test_hardware_kick(
            u64::from(self.id.raw_for_probe())
                + self.factory.hardware_vcpu_offset.load(Ordering::SeqCst),
        ))
    }

    fn save(&mut self, lease: ThreadExecutionLease) -> Result<SavedRunnable, ExecutorSaveError> {
        assert_eq!(thread::current().id(), self.owner);
        let Some((thread, generation, binding)) = self.current.take() else {
            return Err(ExecutorSaveError::new(
                TrapError::Hypervisor("save without loaded task".to_owned()),
                lease,
            ));
        };
        self.factory
            .record(BackendEventKind::Save, self.id, Some((thread, generation)));
        self.factory
            .concurrent_loads
            .lock()
            .remove(&(thread, generation));
        self.factory.snapshot_count.fetch_add(1, Ordering::SeqCst);
        if binding.save_fails.load(Ordering::SeqCst) {
            return Err(ExecutorSaveError::new(
                TrapError::Hypervisor("injected save failure".to_owned()),
                lease,
            ));
        }
        if !binding.audit_fails.load(Ordering::SeqCst) {
            self.credentials = 0;
            self.restart_state = 0;
            self.mailbox = 0;
            self.tls = 0;
        }
        match self.factory.owner_dirty_mode.load(Ordering::SeqCst) {
            1 => {
                let guard = carrick_thread::fork_quiesce::acquire_topology_lock(
                    carrick_observability::probes::HvpatchTopologyOperation::AliasMap,
                    1,
                    1,
                );
                self.owner_dirty_cleanup = Some(Box::new(move || drop(guard)));
            }
            3 => {
                let guard = SyscallDispatcher::dirty_executor_boundary_path_guard_for_test();
                self.owner_dirty_cleanup = Some(Box::new(move || drop(guard)));
            }
            4 => {
                let guard =
                    crate::dispatch::resources::dirty_executor_boundary_resources_guard_for_test();
                self.owner_dirty_cleanup = Some(Box::new(move || drop(guard)));
            }
            5 => {
                let guard = crate::fanotify::InternalOpenGuard::enter();
                self.owner_dirty_cleanup = Some(Box::new(move || drop(guard)));
            }
            6 => {
                let mut blocked = unsafe { std::mem::zeroed::<libc::sigset_t>() };
                let mut previous = unsafe { std::mem::zeroed::<libc::sigset_t>() };
                assert_eq!(unsafe { libc::sigemptyset(&mut blocked) }, 0);
                assert_eq!(unsafe { libc::sigaddset(&mut blocked, libc::SIGUSR1) }, 0);
                assert_eq!(
                    unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut previous) },
                    0
                );
                self.owner_dirty_cleanup = Some(Box::new(move || {
                    assert_eq!(
                        unsafe {
                            libc::pthread_sigmask(
                                libc::SIG_SETMASK,
                                &previous,
                                std::ptr::null_mut(),
                            )
                        },
                        0
                    );
                }));
            }
            7 => {
                let fds = SyscallDispatcher::dirty_sysv_executor_boundary_state_for_test();
                self.factory.owner_dirty_fds.lock().push(fds);
            }
            _ => {}
        }
        Ok(SavedRunnable::new(lease))
    }

    fn invalidate_asid(
        &mut self,
        generation: crate::hvpatch::AsidGeneration,
    ) -> Result<(), TrapError> {
        assert_eq!(thread::current().id(), self.owner);
        if self
            .factory
            .fail_invalidation_generation
            .load(Ordering::SeqCst)
            == generation.generation()
        {
            return Err(TrapError::Hypervisor(
                "injected ASID invalidation failure".to_owned(),
            ));
        }
        self.factory
            .record(BackendEventKind::Invalidate, self.id, None);
        Ok(())
    }

    fn audit_boundary(&mut self) -> Result<(), TrapError> {
        assert_eq!(thread::current().id(), self.owner);
        self.factory.record(BackendEventKind::Audit, self.id, None);
        if self.current.is_none()
            && self.factory.panic_initial_audit_call.load(Ordering::SeqCst) == self.create_call
        {
            if let Some(gate) = self.factory.initial_audit_gate.lock().take() {
                gate.wait();
            }
            panic!("injected initial boundary audit panic");
        }
        if self
            .current
            .as_ref()
            .is_some_and(|(_, _, binding)| binding.audit_fails.load(Ordering::SeqCst))
            || self.credentials != 0
            || self.restart_state != 0
            || self.mailbox != 0
            || self.tls != 0
        {
            return Err(TrapError::Hypervisor(
                "injected or observed dirty executor boundary".to_owned(),
            ));
        }
        Ok(())
    }

    fn destroy(mut self) -> Result<(), TrapError> {
        assert_eq!(thread::current().id(), self.owner);
        if let Some(cleanup) = self.owner_dirty_cleanup.take() {
            cleanup();
        }
        self.factory
            .record(BackendEventKind::Destroy, self.id, None);
        match self.factory.destroy_mode.load(Ordering::SeqCst) {
            1 => Err(TrapError::Hypervisor(
                "injected executor destroy failure".to_owned(),
            )),
            2 => panic!("injected executor destroy panic"),
            _ => Ok(()),
        }
    }
}

fn bootstrap(pid: i32) -> (Arc<Kernel>, KernelContext) {
    let input = RootBootstrap::for_reference_model(
        pid,
        ThreadId::synthetic_for_tests(pid),
        "executor test".to_owned(),
    )
    .expect("bootstrap input");
    Kernel::bootstrap_root(input).expect("kernel")
}

#[test]
fn executor_event_ring_excludes_nonleader_quantum_churn() {
    assert_eq!(process_leader_event_identity(5, 5), Some((5, 5)));
    assert_eq!(process_leader_event_identity(5, 6), None);
}

#[test]
fn executor_claim_probe_keeps_invalid_snapshot_claims_observable() {
    assert_eq!(executor_claim_probe_asid_generation(Some(17)), 17);
    assert_eq!(executor_claim_probe_asid_generation(None), 0);
}

#[test]
fn pre_fork_exec_hardware_and_shutdown_guards_are_fail_closed() {
    let source = include_str!("../executor.rs");
    let backend_source = include_str!("backend.rs");
    let concrete_load = backend_source
        .split("impl PersistentExecutor for HvpatchPersistentExecutor")
        .nth(1)
        .and_then(|tail| tail.split("fn run_until_boundary").next())
        .expect("concrete HVPatch task load");
    let begin_asid = concrete_load
        .find("begin_asid_load")
        .expect("strong ASID load admission");
    let overlay = concrete_load
        .find("overlay_task_state_on_live_executor")
        .expect("live executor task overlay");
    let resident = concrete_load
        .find("mark_resident")
        .expect("post-install ASID residence");
    let dirty = concrete_load
        .find("arm_hardware_dirty")
        .expect("pre-mutation ASID load arm");
    let barrier = concrete_load
        .find("complete_task_load_barrier")
        .expect("post-TTBR DSB/ISB load barrier");
    assert!(begin_asid < dirty && dirty < overlay && overlay < barrier && barrier < resident);

    let worker_loop = source
        .split("fn run_executor_loop")
        .nth(1)
        .and_then(|tail| tail.split("fn service_owner_thread_commands").next())
        .expect("persistent worker loop");
    let save = worker_loop.find("backend.save(lease)").expect("task save");
    let invalidate = worker_loop
        .find("invalidate_after_exec")
        .expect("post-save ASID invalidation");
    let release = worker_loop
        .find("retirement.complete(root_receipt)")
        .expect("post-ack ASID/root release");
    assert!(save < invalidate && invalidate < release);
    let exec_retirement = worker_loop
        .split("if let Some(mut retirement) = pending_exec_retirement.take()")
        .nth(1)
        .and_then(|tail| {
            tail.split("if let Some(mut retirement) = terminal_retirement")
                .next()
        })
        .expect("exec retirement order");
    let exec_invalidate = exec_retirement
        .find("invalidate_after_exec")
        .expect("exec exact TLBI fanout");
    let exec_cleanup = exec_retirement
        .find("retire_detached_exec_predecessor")
        .expect("detached exec predecessor cleanup");
    let exec_ticket = exec_retirement
        .find("take_root_retirement_ticket")
        .expect("exec root retirement ticket");
    let exec_release = exec_retirement
        .find("retirement.complete(root_receipt)")
        .expect("exec ASID/root release");
    assert!(
        exec_invalidate < exec_ticket && exec_ticket < exec_cleanup && exec_cleanup < exec_release
    );
    let terminal = worker_loop
        .split("if let Some(mut retirement) = terminal_retirement")
        .nth(1)
        .and_then(|tail| tail.split("if let Some(authority)").next())
        .expect("terminal retirement order");
    let terminal_invalidate = terminal
        .find("invalidate_after_exec")
        .expect("terminal exact TLBI fanout");
    let detached_cleanup = terminal
        .find("retire_detached_address_space")
        .expect("detached stage-2/inventory cleanup");
    let terminal_ticket = terminal
        .find("take_root_retirement_ticket")
        .expect("terminal root retirement ticket");
    let terminal_release = terminal
        .find("retirement.complete(root_receipt)")
        .expect("terminal ASID/root release");
    assert!(
        terminal_invalidate < terminal_ticket
            && terminal_ticket < detached_cleanup
            && detached_cleanup < terminal_release
    );
    assert!(!terminal.contains("acquire_process_retire_topology_lock_servicing"));
    let pre_load = worker_loop
        .split("if let Err(error) = backend.load(&task)")
        .next()
        .expect("worker pre-load path");
    assert!(
        !pre_load.contains("invalidate_asid"),
        "ordinary task load must never invalidate an ASID"
    );

    let concrete_retarget = backend_source
        .split(concat!("fn retarget_loaded_", "task(&mut self, binding:"))
        .nth(1)
        .and_then(|tail| tail.split("fn save(").next())
        .expect("concrete HVPatch loaded retarget");
    assert!(concrete_retarget.contains("validate_loaded_hardware_identity()?"));

    let exec_cutover = source
        .split("if let Some(replacement) = exec_replacement")
        .nth(1)
        .and_then(|tail| tail.split("} else if let Err").next())
        .expect("worker-owned exec cutover");
    let validate = exec_cutover
        .find("validate_loaded_hardware_identity()")
        .expect("live vCPU/Mach preflight");
    let publish = exec_cutover
        .find(".replace_exec(")
        .expect("combined successor publication");
    assert!(validate < publish);

    let pool_source = include_str!("pool.rs");
    let marker = pool_source
        .find(concat!("post-join exact dormant ", "cancellation failed"))
        .expect("post-join cancellation boundary");
    let cancel = pool_source[..marker]
        .rfind("cancel_dormant")
        .expect("stable exact cancellation");
    let fail_stop = pool_source[marker..]
        .find("carrick_fatal!")
        .map(|offset| marker + offset)
        .expect("cancellation failure fail-stop");
    let wait = pool_source[fail_stop..]
        .find("self.scheduler.wait_closed()")
        .map(|offset| fail_stop + offset)
        .expect("queue closure wait");
    assert!(cancel < fail_stop && fail_stop < wait);
}

#[test]
fn hvpatch_quantum_borrows_a_fresh_injected_engine_at_every_boundary() {
    #[derive(Default)]
    struct InjectedEngine {
        polls: usize,
    }

    struct SevenBoundaryJob {
        exits: VecDeque<ExecutorExit>,
        observed: Arc<parking_lot::Mutex<Vec<usize>>>,
    }

    impl crate::vcpu_loop::continuation::PersistentQuantumJob for SevenBoundaryJob {
        fn poll_quantum_with_engine(
            &mut self,
            engine: &mut dyn std::any::Any,
            control: &mut HvpatchQuantumControl<'_, '_>,
        ) -> ExecutorExit {
            let engine = engine
                .downcast_mut::<InjectedEngine>()
                .expect("exact injected engine type");
            engine.polls += 1;
            self.observed.lock().push(engine.polls);
            assert!(!control.need_resched());
            let _ = control.submission();
            self.exits.pop_front().expect("scripted boundary")
        }
    }

    let boundaries = [
        ExecutorExit::Blocked(BlockedReason::HostWait),
        ExecutorExit::Blocked(BlockedReason::ChildState),
        ExecutorExit::Yielded,
        ExecutorExit::Quiesced,
        ExecutorExit::Preempted,
        ExecutorExit::Yielded,
        ExecutorExit::Exited,
    ];
    let expected_discriminants = boundaries
        .iter()
        .map(std::mem::discriminant)
        .collect::<Vec<_>>();
    let observed = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let completion = crate::vcpu_loop::continuation::LogicalJobCompletion::pending();
    let quantum = crate::vcpu_loop::continuation::HvpatchTaskQuantum::new(
        Box::new(SevenBoundaryJob {
            exits: boundaries.into_iter().collect(),
            observed: Arc::clone(&observed),
        }),
        completion.clone(),
    );
    let (kernel, _) = bootstrap(13_991);
    let scheduler = Scheduler::new(Arc::clone(&kernel));
    let reject_descendant = |_, _| {
        Err(TrapError::Hypervisor(
            "seven-boundary test publishes no descendants".to_owned(),
        ))
    };
    let mut submission = ExecutorSubmissionContext {
        scheduler: &scheduler,
        publish_test_descendant: &reject_descendant,
        current: None,
        lease: None,
        exec_replacement: None,
    };
    let need_resched = AtomicBool::new(false);
    let mut control = HvpatchQuantumControl::for_test(&need_resched, &mut submission);

    for (index, expected) in expected_discriminants.into_iter().enumerate() {
        // This value represents the executor-owned engine after load. It is
        // dropped after every returned boundary, exactly where the real
        // backend's save path detaches its task state from the worker vCPU.
        let mut engine = InjectedEngine::default();
        let actual = quantum.poll_quantum_with_engine(&mut engine, &mut control);
        assert_eq!(std::mem::discriminant(&actual), expected);
        assert_eq!(engine.polls, 1, "boundary {index} reused a retained engine");
    }
    assert_eq!(*observed.lock(), vec![1; 7]);
    quantum.after_terminal_settlement();
    assert!(completion.is_finished());
}

fn sibling(kernel: &Arc<Kernel>, parent: &KernelContext, host_tid: i32) -> KernelContext {
    let plan = ClonePlan::from_flags(
        LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
    )
    .expect("thread clone plan");
    kernel
        .reserve_thread_clone(parent, plan, None)
        .expect("reserve sibling")
        .prepare(ThreadId::synthetic_for_tests(host_tid))
        .expect("prepare sibling")
        .commit()
        .expect("publish sibling")
        .start_thread()
        .expect("start sibling")
        .into_context()
}

fn process_child(
    kernel: &Arc<Kernel>,
    parent: &KernelContext,
    host_tid: i32,
    name: &str,
) -> KernelContext {
    kernel
        .reserve_fork(
            parent,
            ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("process fork plan"),
            name.to_owned(),
            None,
        )
        .expect("reserve process child")
        .prepare_reference(ThreadId::synthetic_for_tests(host_tid))
        .expect("prepare process child")
        .commit()
        .expect("publish process child")
        .start_child()
        .expect("start process child")
        .into_parts()
        .0
}

pub(crate) fn task_state(context: &KernelContext, marker: u64) -> MigratableTaskState {
    task_state_with_continuation(context, marker, None)
}

fn task_state_with_continuation(
    context: &KernelContext,
    marker: u64,
    syscall_continuation: Option<Aarch64SyscallContinuationV1>,
) -> MigratableTaskState {
    let mm = context.shared().mm().id();
    MigratableTaskState {
        cpu: GuestCpuState::from_aarch64_v1(Aarch64TaskCpuStateV1 {
            gprs: std::array::from_fn(|index| marker + index as u64),
            pc: marker + 0x1000,
            pstate: marker + 0x2000,
            trap_pc: marker + 0x2100,
            trap_pstate: marker + 0x2200,
            sp_el0: marker + 0x3000,
            elr_el1: marker + 0x3100,
            spsr_el1: marker + 0x3200,
            ttbr0: marker + 0x4000,
            ttbr1: marker + 0x5000,
            tcr: marker + 0x6000,
            sctlr_el1: marker + 0x6100,
            mair_el1: marker + 0x6200,
            vbar_el1: marker + 0x6300,
            cpacr_el1: marker + 0x6400,
            cntkctl_el1: marker + 0x6500,
            tpidr_el1: marker + 0x6600,
            actlr_el1: marker + 0x7000,
            tpidr_el0: marker + 0x8000,
            tpidrro_el0: marker + 0x9000,
            contextidr_el1: marker + 0xa000,
            vregs: std::array::from_fn(|index| marker as u128 + index as u128),
            fpsr: marker as u32,
            fpcr: marker as u32 + 1,
            pending_resume_pc: Some(marker + 0xb000),
            last_syscall_nr: Some(marker),
            last_syscall_orig_x0: marker + 2,
            last_fault_esr: marker + 3,
            last_exit_class: marker,
            is_forked_child: false,
            syscall_continuation,
            mm_generation: mm.raw(),
            asid_generation: mm.raw(),
        }),
        mm,
        asid_generation: mm.raw(),
    }
}

fn publish(context: &KernelContext, marker: u64) -> ExecutionGeneration {
    context
        .thread()
        .publish_initial_task_state(task_state(context, marker))
        .expect("publish task state")
}

pub(crate) fn hvpatch_test_binding(
    context: &KernelContext,
    state: &MigratableTaskState,
    marker: u64,
) -> Arc<crate::vcpu_loop::continuation::HvpatchTaskBinding> {
    hvpatch_test_binding_with_completion(
        context,
        state,
        marker,
        crate::vcpu_loop::continuation::LogicalJobCompletion::pending(),
    )
}

fn hvpatch_test_binding_with_completion(
    context: &KernelContext,
    state: &MigratableTaskState,
    marker: u64,
    completion: crate::vcpu_loop::continuation::LogicalJobCompletion,
) -> Arc<crate::vcpu_loop::continuation::HvpatchTaskBinding> {
    struct ExitJob;

    impl crate::vcpu_loop::continuation::PersistentQuantumJob for ExitJob {
        fn poll_quantum_with_engine(
            &mut self,
            _engine: &mut dyn std::any::Any,
            _control: &mut HvpatchQuantumControl<'_, '_>,
        ) -> ExecutorExit {
            ExecutorExit::Exited
        }
    }

    assert_eq!(context.shared().mm().id(), state.mm);
    Arc::new(crate::vcpu_loop::continuation::HvpatchTaskBinding::new(
        TaskLoadIdentity {
            abi: state.cpu.guest_abi(),
            version: state.cpu.version(),
            mm: state.mm,
            asid_generation: state.asid_generation,
        },
        Arc::new(crate::vcpu_loop::continuation::HvpatchTaskQuantum::new(
            Box::new(ExitJob),
            completion,
        )),
        Box::new(marker),
    ))
}

pub(crate) fn activate_hvpatch_test_submission(
    dormant: super::PreparedHvpatchSubmission,
    scheduler: &Scheduler,
    context: &KernelContext,
    state: &MigratableTaskState,
    generation: ExecutionGeneration,
    binding: &crate::vcpu_loop::continuation::HvpatchTaskBinding,
) {
    let start_gate = context
        .thread()
        .take_opened_start_gate(generation)
        .expect("exact opened start gate");
    let proof = HvpatchActivationProof::validate(
        context,
        state,
        generation,
        binding.identity(),
        start_gate,
    )
    .expect("exact activation proof");
    dormant
        .activate(scheduler, Arc::clone(context.thread()), proof)
        .expect("activate exact dormant submission");
}

#[test]
fn dormant_submission_is_invisible_until_exact_activation() {
    let (kernel, context) = bootstrap(13_993);
    let state = task_state(&context, 93);
    let generation = context
        .thread()
        .publish_initial_task_state(state.clone())
        .expect("publish root state");
    let scheduler = Arc::new(Scheduler::new(kernel));
    let directory = Arc::new(HvpatchTaskBindingDirectory::default());
    directory.install_scheduler(&scheduler).unwrap();
    let binding = hvpatch_test_binding(&context, &state, 93);
    let dormant = directory
        .prepare_submission(
            &scheduler,
            HvpatchSubmissionShape::Root,
            None,
            Arc::clone(context.thread()),
            generation,
            Arc::clone(&binding),
        )
        .expect("prepare dormant root");

    assert_eq!(scheduler.queued_len(), 0);
    assert!(
        <HvpatchTaskBindingDirectory as TaskBindingResolver<_>>::resolve(
            directory.as_ref(),
            context.thread().key(),
            generation,
        )
        .is_err()
    );
    activate_hvpatch_test_submission(
        dormant,
        &scheduler,
        &context,
        &state,
        generation,
        binding.as_ref(),
    );
    assert_eq!(scheduler.queued_len(), 1);
    let resolved = <HvpatchTaskBindingDirectory as TaskBindingResolver<_>>::resolve(
        directory.as_ref(),
        context.thread().key(),
        generation,
    )
    .expect("binding visible only after activation");
    assert!(Arc::ptr_eq(&resolved, &binding));
}

/// An executor kick that records, every time the scheduler consults its
/// binding, whether the HVPatch binding directory was free. Exec retarget
/// nests `directory.bindings` INSIDE a kick's binding lock
/// (`rebind_exact_with` -> `replace_exec`), so any publication that
/// consults kicks while holding the directory closes an ABBA cycle.
struct DirectoryLockOrderProbeKick {
    directory: Arc<HvpatchTaskBindingDirectory>,
    consulted: AtomicUsize,
    directory_free: AtomicBool,
}

impl std::fmt::Debug for DirectoryLockOrderProbeKick {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DirectoryLockOrderProbeKick")
            .field("consulted", &self.consulted.load(Ordering::Acquire))
            .field(
                "directory_free",
                &self.directory_free.load(Ordering::Acquire),
            )
            .finish()
    }
}

impl ExecutorKick for DirectoryLockOrderProbeKick {
    fn try_bind(&self, _binding: ExecutorBinding) -> bool {
        false
    }

    fn unbind(&self, _binding: ExecutorBinding) {}

    fn rebind_exact_with(
        &self,
        _predecessor: ExecutorBinding,
        _successor: ExecutorBinding,
        _publish: &mut dyn FnMut() -> bool,
    ) -> bool {
        false
    }

    fn deliver_exact(&self, _token: ExecutorKickToken) -> bool {
        false
    }

    fn current_binding(&self) -> Option<ExecutorBinding> {
        self.consulted.fetch_add(1, Ordering::AcqRel);
        if self.directory.bindings.try_lock().is_none() {
            self.directory_free.store(false, Ordering::Release);
        }
        None
    }
}

#[test]
fn exact_activation_publishes_without_holding_the_binding_directory() {
    let (kernel, context) = bootstrap(13_994);
    let state = task_state(&context, 94);
    let generation = context
        .thread()
        .publish_initial_task_state(state.clone())
        .expect("publish root state");
    let scheduler = Arc::new(Scheduler::new(kernel));
    let directory = Arc::new(HvpatchTaskBindingDirectory::default());
    directory.install_scheduler(&scheduler).unwrap();
    let probe = Arc::new(DirectoryLockOrderProbeKick {
        directory: Arc::clone(&directory),
        consulted: AtomicUsize::new(0),
        directory_free: AtomicBool::new(true),
    });
    let registration = scheduler
        .register_executor(Arc::clone(&probe) as Arc<dyn ExecutorKick>)
        .expect("register probe executor");
    let binding = hvpatch_test_binding(&context, &state, 94);
    let dormant = directory
        .prepare_submission(
            &scheduler,
            HvpatchSubmissionShape::Root,
            None,
            Arc::clone(context.thread()),
            generation,
            Arc::clone(&binding),
        )
        .expect("prepare dormant root");

    activate_hvpatch_test_submission(
        dormant,
        &scheduler,
        &context,
        &state,
        generation,
        binding.as_ref(),
    );

    assert!(
        probe.consulted.load(Ordering::Acquire) > 0,
        "publication must consult the registered executor kicks"
    );
    assert!(
        probe.directory_free.load(Ordering::Acquire),
        "activation held the binding directory while consulting executor kicks; \
         exec retarget takes those locks in the opposite order"
    );
    assert_eq!(scheduler.queued_len(), 1);
    assert!(
        <HvpatchTaskBindingDirectory as TaskBindingResolver<_>>::resolve(
            directory.as_ref(),
            context.thread().key(),
            generation,
        )
        .is_ok()
    );
    scheduler.unregister_executor(&registration).unwrap();
}

#[test]
fn opened_start_gate_is_kernel_minted_only_after_start_and_consumed_once() {
    let (kernel, root) = bootstrap(13_989);
    let published = kernel
        .reserve_fork(
            &root,
            ClonePlan::from_flags(LinuxCloneFlags::empty()).unwrap(),
            "start-gated".to_owned(),
            None,
        )
        .unwrap()
        .prepare_reference(ThreadId::synthetic_for_tests(23_989))
        .unwrap()
        .commit()
        .unwrap();
    let before_start = published.context().expect("published child context");
    let state = task_state(before_start, 89);
    let generation = before_start
        .thread()
        .publish_initial_task_state(state)
        .unwrap();
    assert!(
        before_start
            .thread()
            .take_opened_start_gate(generation)
            .is_none()
    );

    let started = published.start_child().unwrap();
    assert!(
        started
            .context()
            .thread()
            .take_opened_start_gate(generation)
            .is_some()
    );
    assert!(
        started
            .context()
            .thread()
            .take_opened_start_gate(generation)
            .is_none()
    );
}

#[test]
fn same_task_clone_binding_stays_dormant_until_kernel_gate_opens() {
    let (kernel, root) = bootstrap(13_988);
    let root_state = task_state(&root, 88);
    let root_generation = root
        .thread()
        .publish_initial_task_state(root_state.clone())
        .unwrap();
    let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
    let directory = Arc::new(HvpatchTaskBindingDirectory::default());
    directory.install_scheduler(&scheduler).unwrap();
    let root_binding = hvpatch_test_binding(&root, &root_state, 88);
    let root_submission = directory
        .prepare_submission(
            &scheduler,
            HvpatchSubmissionShape::Root,
            None,
            Arc::clone(root.thread()),
            root_generation,
            Arc::clone(&root_binding),
        )
        .unwrap();
    activate_hvpatch_test_submission(
        root_submission,
        &scheduler,
        &root,
        &root_state,
        root_generation,
        root_binding.as_ref(),
    );
    let root_authority = directory
        .take_submission_authority(root.thread().key(), root_generation)
        .unwrap();

    let published = kernel
        .reserve_thread_clone(
            &root,
            ClonePlan::from_flags(
                LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
            )
            .unwrap(),
            None,
        )
        .unwrap()
        .prepare(ThreadId::synthetic_for_tests(23_988))
        .unwrap()
        .reserve_publication_eventually()
        .unwrap()
        .commit()
        .unwrap();
    let child = published.context().unwrap().retain_exact();
    let child_state = task_state(&child, 89);
    let child_generation = child
        .thread()
        .publish_initial_task_state(child_state.clone())
        .unwrap();
    let child_binding = hvpatch_test_binding(&child, &child_state, 89);
    let dormant = directory
        .prepare_submission(
            &scheduler,
            HvpatchSubmissionShape::SameTaskSibling {
                grant: (root.thread().key(), root_generation),
            },
            Some(&root_authority),
            Arc::clone(child.thread()),
            child_generation,
            Arc::clone(&child_binding),
        )
        .unwrap();
    assert_eq!(scheduler.queued_len(), 1);
    assert!(
        directory
            .resolve(child.thread().key(), child_generation)
            .is_err()
    );
    assert!(
        child
            .thread()
            .take_opened_start_gate(child_generation)
            .is_none()
    );

    let started = published.start_thread().unwrap();
    let gate = started
        .context()
        .thread()
        .take_opened_start_gate(child_generation)
        .unwrap();
    let proof = HvpatchActivationProof::validate(
        &child,
        &child_state,
        child_generation,
        child_binding.identity(),
        gate,
    )
    .unwrap();
    dormant
        .activate(&scheduler, Arc::clone(child.thread()), proof)
        .unwrap();
    assert_eq!(scheduler.queued_len(), 2);
    assert!(
        directory
            .resolve(child.thread().key(), child_generation)
            .is_ok()
    );
    directory
        .restore_submission_authority(root_authority)
        .unwrap();
}

#[test]
fn dormant_and_active_clone_directory_retirement_is_exact() {
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Phase {
        TidCopyout,
        BackendCommit,
        TokenBind,
        RegistryHandle,
        StartProof,
        Activation,
    }
    for (case, phase) in [
        Phase::TidCopyout,
        Phase::BackendCommit,
        Phase::TokenBind,
        Phase::RegistryHandle,
        Phase::StartProof,
        Phase::Activation,
    ]
    .into_iter()
    .enumerate()
    {
        let (kernel, root) = bootstrap(13_980 + case as i32);
        let root_state = task_state(&root, 80 + case as u64);
        let root_generation = root
            .thread()
            .publish_initial_task_state(root_state.clone())
            .unwrap();
        let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
        let directory = Arc::new(HvpatchTaskBindingDirectory::default());
        directory.install_scheduler(&scheduler).unwrap();
        let root_binding = hvpatch_test_binding(&root, &root_state, 80 + case as u64);
        let root_submission = directory
            .prepare_submission(
                &scheduler,
                HvpatchSubmissionShape::Root,
                None,
                Arc::clone(root.thread()),
                root_generation,
                Arc::clone(&root_binding),
            )
            .unwrap();
        activate_hvpatch_test_submission(
            root_submission,
            &scheduler,
            &root,
            &root_state,
            root_generation,
            root_binding.as_ref(),
        );
        let root_authority = directory
            .take_submission_authority(root.thread().key(), root_generation)
            .unwrap();
        let published = kernel
            .reserve_thread_clone(
                &root,
                ClonePlan::from_flags(
                    LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
                )
                .unwrap(),
                None,
            )
            .unwrap()
            .prepare(ThreadId::synthetic_for_tests(23_980 + case as i32))
            .unwrap()
            .commit()
            .unwrap();
        let child = published.context().unwrap().retain_exact();
        let child_state = task_state(&child, 90 + case as u64);
        let child_generation = child
            .thread()
            .publish_initial_task_state(child_state.clone())
            .unwrap();
        let has_logical_handle = matches!(
            phase,
            Phase::RegistryHandle | Phase::StartProof | Phase::Activation
        );
        let completion =
            has_logical_handle.then(crate::vcpu_loop::continuation::LogicalJobCompletion::pending);
        let child_binding = hvpatch_test_binding(&child, &child_state, 90 + case as u64);
        let mut dormant = has_logical_handle.then(|| {
            directory
                .prepare_submission(
                    &scheduler,
                    HvpatchSubmissionShape::SameTaskSibling {
                        grant: (root.thread().key(), root_generation),
                    },
                    Some(&root_authority),
                    Arc::clone(child.thread()),
                    child_generation,
                    Arc::clone(&child_binding),
                )
                .unwrap()
        });
        if matches!(phase, Phase::StartProof | Phase::Activation) {
            let started = published.start_thread().unwrap();
            let gate = started
                .context()
                .thread()
                .take_opened_start_gate(child_generation)
                .unwrap();
            let proof = HvpatchActivationProof::validate(
                &child,
                &child_state,
                child_generation,
                child_binding.identity(),
                gate,
            )
            .unwrap();
            if phase == Phase::Activation {
                dormant
                    .take()
                    .unwrap()
                    .activate(&scheduler, Arc::clone(child.thread()), proof)
                    .unwrap();
                assert!(
                    directory
                        .resolve(child.thread().key(), child_generation)
                        .is_ok()
                );
            }
        }
        drop(dormant);
        retire_failed_hvpatch_clone_authority(
            &scheduler,
            &kernel,
            &child,
            child_generation,
            |thread, generation| directory.retire(thread, generation),
        )
        .unwrap();
        if let Some(completion) = &completion {
            assert!(!completion.is_finished());
            completion.publish();
        }
        assert!(completion.as_ref().is_none_or(|value| value.is_finished()));
        assert!(
            directory
                .resolve(child.thread().key(), child_generation)
                .is_err()
        );
        assert!(
            kernel
                .context(root.task().key().id, child.thread().key().tid)
                .is_err()
        );
        assert_eq!(scheduler.queued_len(), 1);
        directory
            .restore_submission_authority(root_authority)
            .unwrap();
    }
}

#[test]
fn task_only_save_restores_worker_vcpu_before_binding_publication_can_fail() {
    let mut worker_vcpu = None;
    let result = restore_worker_vcpu_before_binding_publication(
        &mut worker_vcpu,
        0xfeed_u64,
        (),
        |(), worker_vcpu| {
            assert_eq!(*worker_vcpu, Some(0xfeed));
            Err(TrapError::Hypervisor(
                "injected binding publication failure".to_owned(),
            ))
        },
    );
    assert!(result.is_err());
    assert_eq!(worker_vcpu, Some(0xfeed));
}

#[test]
fn clone_failure_retirement_is_scheduler_then_kernel_and_never_silent() {
    let (kernel, root) = bootstrap(13_979);
    let published = kernel
        .reserve_thread_clone(
            &root,
            ClonePlan::from_flags(
                LinuxCloneFlags::THREAD | LinuxCloneFlags::SIGHAND | LinuxCloneFlags::VM,
            )
            .unwrap(),
            None,
        )
        .unwrap()
        .prepare(ThreadId::synthetic_for_tests(23_979))
        .unwrap()
        .commit()
        .unwrap();
    let child = published.context().unwrap().retain_exact();
    let state = task_state(&child, 79);
    let generation = child
        .thread()
        .publish_initial_task_state(state)
        .expect("publish child runnable");
    let scheduler = Scheduler::new(Arc::clone(&kernel));

    retire_failed_hvpatch_clone_authority(&scheduler, &kernel, &child, generation, |_, _| {})
        .expect("exact child retirement");
    assert!(matches!(
        child.thread().execution_state(),
        ThreadExecutionState::Failed { .. }
    ));
    assert!(
        kernel
            .context(child.task().key().id, child.thread().key().tid)
            .is_err()
    );
    assert!(
        retire_failed_hvpatch_clone_authority(&scheduler, &kernel, &child, generation, |_, _| {},)
            .is_err(),
        "a duplicate or stale retirement must remain observable"
    );
}

#[test]
fn dormant_submission_drop_rolls_back_binding_and_queue_authority() {
    let (kernel, context) = bootstrap(13_994);
    let state = task_state(&context, 94);
    let generation = context
        .thread()
        .publish_initial_task_state(state.clone())
        .expect("publish root state");
    let scheduler = Scheduler::new(kernel);
    let directory = Arc::new(HvpatchTaskBindingDirectory::default());
    let binding = hvpatch_test_binding(&context, &state, 94);
    let dormant = directory
        .prepare_submission(
            &scheduler,
            HvpatchSubmissionShape::Root,
            None,
            Arc::clone(context.thread()),
            generation,
            Arc::clone(&binding),
        )
        .expect("prepare dormant root");
    drop(dormant);

    assert_eq!(scheduler.queued_len(), 0);
    assert!(
        <HvpatchTaskBindingDirectory as TaskBindingResolver<_>>::resolve(
            directory.as_ref(),
            context.thread().key(),
            generation,
        )
        .is_err()
    );
    let retry = directory
        .prepare_submission(
            &scheduler,
            HvpatchSubmissionShape::Root,
            None,
            Arc::clone(context.thread()),
            generation,
            binding,
        )
        .expect("rollback releases exact key and authority");
    drop(retry);
    scheduler.close();
    scheduler.wait_closed();
}

#[test]
fn dormant_submission_rejects_duplicate_exact_key() {
    let (kernel, context) = bootstrap(13_995);
    let state = task_state(&context, 95);
    let generation = context
        .thread()
        .publish_initial_task_state(state.clone())
        .expect("publish root state");
    let scheduler = Scheduler::new(kernel);
    let directory = Arc::new(HvpatchTaskBindingDirectory::default());
    let binding = hvpatch_test_binding(&context, &state, 95);
    let first = directory
        .prepare_submission(
            &scheduler,
            HvpatchSubmissionShape::Root,
            None,
            Arc::clone(context.thread()),
            generation,
            Arc::clone(&binding),
        )
        .expect("prepare first exact row");
    assert!(
        directory
            .prepare_submission(
                &scheduler,
                HvpatchSubmissionShape::Root,
                None,
                Arc::clone(context.thread()),
                generation,
                binding,
            )
            .is_err()
    );
    drop(first);
}

#[test]
fn dormant_activation_coalesces_onto_a_preexisting_exact_queue_row() {
    // The run queue holds at most one row per exact (thread, generation),
    // so a row that is already there IS the row this activation wants.
    // Activation therefore coalesces onto it and the binding resolves;
    // what protects against a second submission for the same key is
    // `prepare_submission`'s duplicate-binding check, not the queue.
    let (kernel, context) = bootstrap(13_998);
    let state = task_state(&context, 108);
    let generation = context
        .thread()
        .publish_initial_task_state(state.clone())
        .expect("publish root state");
    let scheduler = Scheduler::new(kernel);
    let directory = Arc::new(HvpatchTaskBindingDirectory::default());
    let binding = hvpatch_test_binding(&context, &state, 108);
    let dormant = directory
        .prepare_submission(
            &scheduler,
            HvpatchSubmissionShape::Root,
            None,
            Arc::clone(context.thread()),
            generation,
            Arc::clone(&binding),
        )
        .expect("prepare dormant root");
    let foreign = scheduler
        .admit_root(context.thread().key(), generation)
        .expect("inject competing exact authority");
    foreign
        .publish(&scheduler, Arc::clone(context.thread()))
        .expect("inject competing queue row");
    let start_gate = context
        .thread()
        .take_opened_start_gate(generation)
        .expect("opened root start gate");
    let proof = HvpatchActivationProof::validate(
        &context,
        &state,
        generation,
        binding.identity(),
        start_gate,
    )
    .unwrap();

    dormant
        .activate(&scheduler, Arc::clone(context.thread()), proof)
        .expect("activation coalesces onto the exact row already queued");
    assert!(
        <HvpatchTaskBindingDirectory as TaskBindingResolver<_>>::resolve(
            directory.as_ref(),
            context.thread().key(),
            generation,
        )
        .is_ok()
    );
    assert_eq!(scheduler.queued_len(), 1);
}

#[test]
fn a_legitimate_wake_before_activation_does_not_reject_the_dormant_submission() {
    // The child/successor task is published to the Kernel as runnable
    // BEFORE its dormant submission is activated, and `activate` releases
    // the binding-directory lock before publishing (4150290e1, the ABBA
    // fix). A real producer that wakes the task in that window queues the
    // exact `(thread, generation)` row first; `publish_unique` then sees
    // its own key and rejects the activation, which every production
    // caller lowers into a guest-fatal `TrapError`.
    //
    // A wake and an activation assert the SAME fact about the SAME exact
    // generation, and the run queue already coalesces by exact key
    // (`runnable_wake_is_idempotent_and_never_duplicates_the_row`), so
    // this must not be an error.
    let (kernel, context) = bootstrap(13_997);
    let state = task_state(&context, 109);
    let generation = context
        .thread()
        .publish_initial_task_state(state.clone())
        .expect("publish root state");
    let scheduler = Scheduler::new(kernel);
    let directory = Arc::new(HvpatchTaskBindingDirectory::default());
    let binding = hvpatch_test_binding(&context, &state, 109);
    let dormant = directory
        .prepare_submission(
            &scheduler,
            HvpatchSubmissionShape::Root,
            None,
            Arc::clone(context.thread()),
            generation,
            Arc::clone(&binding),
        )
        .expect("prepare dormant root");
    scheduler
        .make_runnable(context.thread().key())
        .expect("a real producer wakes the freshly published task");
    // The wake is durable but its row is held: a dormant submission owns
    // no claimable row (`a_wake_before_activation_leaves_the_dormant_row_
    // unclaimable`).
    assert_eq!(scheduler.queued_len(), 0);
    let start_gate = context
        .thread()
        .take_opened_start_gate(generation)
        .expect("opened root start gate");
    let proof = HvpatchActivationProof::validate(
        &context,
        &state,
        generation,
        binding.identity(),
        start_gate,
    )
    .unwrap();

    dormant
        .activate(&scheduler, Arc::clone(context.thread()), proof)
        .expect("a wake-queued exact row must not reject its own activation");
    assert_eq!(scheduler.queued_len(), 1);
    assert!(
        <HvpatchTaskBindingDirectory as TaskBindingResolver<_>>::resolve(
            directory.as_ref(),
            context.thread().key(),
            generation,
        )
        .is_ok()
    );
}

#[test]
fn a_clone_rollback_tolerates_a_child_that_already_settled() {
    // The second half of the threading residual. Even with the
    // claimability gate closed, `rollback_published_hvpatch_clone`
    // treated ANY refusal from `fail_runnable_exact` as a carrier fault:
    //
    //   carrick: FATAL: authoritative HVPatch clone rollback: fail exact
    //   HVPatch clone runnable: thread execution transition
    //   fail_runnable_generation is invalid from Failed { generation:
    //   ExecutionGeneration(2), reason: SnapshotRestoreFailed }
    //
    // `std::process::abort()` there kills every Linux process in the
    // carrier for a condition that is, at worst, one failed clone. The
    // generation the rollback exists to retire has ALREADY been retired
    // -- terminally, by whoever settled it -- so there is nothing left to
    // fail and nothing that justifies ending the carrier.
    let (kernel, root) = bootstrap(13_993);
    // A cloned thread, the shape the field hit: the child is published to
    // the Kernel as `Runnable { INITIAL }` before its submission
    // activates, and the rollback retires it while its task lives on.
    let context = sibling(&kernel, &root, 23_993);
    let state = task_state(&context, 108);
    let generation = context
        .thread()
        .publish_initial_task_state(state)
        .expect("publish child state");
    let scheduler = Scheduler::new(Arc::clone(&kernel));

    // Something else settled this generation terminally first.
    scheduler
        .fail_runnable_exact(
            context.thread().key(),
            generation,
            crate::kernel::objects::ExecutionFailure::SnapshotRestoreFailed,
        )
        .expect("settle the child terminally");

    let retired = std::cell::Cell::new(None);
    let outcome = retire_failed_hvpatch_clone_authority(
        &scheduler,
        &kernel,
        &context,
        generation,
        |thread, generation| retired.set(Some((thread, generation))),
    )
    .expect("an already-settled child must not be a carrier fault");
    assert!(
        matches!(
            outcome,
            super::FailedCloneRetirement::AlreadySettled(
                crate::kernel::objects::ThreadExecutionState::Failed { .. }
            )
        ),
        "the rollback must name what it found, not abort: {outcome:?}",
    );
    assert_eq!(
        retired.get(),
        Some((context.thread().key(), generation)),
        "the rollback still retires the child's binding",
    );
}

#[test]
fn a_dropped_dormant_submission_leaves_no_claimable_row_for_its_generation() {
    // The residual of the pre-activation wake window, and the one the
    // claimability gate (119f07e97, ported onto the per-CPU queues by
    // 16e262602) does not cover.
    //
    // `spawn_persistent_hvpatch_clone_thread` publishes the child to the
    // Kernel as Runnable at `ExecutionGeneration::INITIAL`, opens its
    // start gate, and only then activates the dormant submission that
    // owns it. Every error arm between those two points does
    // `drop(dormant)` and then `rollback_published_hvpatch_clone`. That
    // drop removes the binding record AND releases the submission
    // authority, and releasing an authority clears the key's ADMISSION
    // gate -- so for the whole rollback the child would be a
    // Kernel-runnable generation with no binding and no gate. A producer
    // that woke it there (a futex on the tid the clone already copied
    // out, a group signal) enqueued a CLAIMABLE row; an executor claimed
    // it, `resolve` reported "missing exact HVPatch task binding", the
    // worker settled the task `Failed { SnapshotRestoreFailed }`, and the
    // rollback's own `fail_runnable_exact` then found that Failed
    // generation and aborted the carrier:
    //
    //   carrick: FATAL: authoritative HVPatch clone rollback: fail exact
    //   HVPatch clone runnable: thread execution transition
    //   fail_runnable_generation is invalid from Failed { generation:
    //   ExecutionGeneration(2), reason: SnapshotRestoreFailed }
    //
    // (cpython-threading `test_reinit_tls_after_fork`, host load ~30;
    // crash report carrick-2026-09-08-052842.ips names exactly this frame
    // pair.)
    //
    // The reservation `publish_initial_task_state_gated` takes belongs to
    // the thread's FIRST generation rather than to any one authority, so
    // it outlives the `drop(dormant)`. A generation that never published
    // can never resolve, so no wake for it is ever claimable; publication
    // or terminal retirement is the only lift.
    let (kernel, context) = bootstrap(13_994);
    let state = task_state(&context, 109);
    let scheduler = Scheduler::new(kernel);
    // The production order: the child's claimability is reserved before it
    // is Kernel-runnable, and that reservation outlives the authority the
    // rollback drops.
    let generation = scheduler
        .publish_initial_task_state_gated(context.thread(), state.clone())
        .expect("publish child state");
    let executor = scheduler
        .register_executor(Arc::new(WorkerKick::new(Arc::new(ReceiptLog::default()))))
        .unwrap();
    let directory = Arc::new(HvpatchTaskBindingDirectory::default());
    let binding = hvpatch_test_binding(&context, &state, 109);
    let dormant = directory
        .prepare_submission(
            &scheduler,
            HvpatchSubmissionShape::Root,
            None,
            Arc::clone(context.thread()),
            generation,
            Arc::clone(&binding),
        )
        .expect("prepare dormant child submission");

    // The rollback arm: the submission dies before it ever activates,
    // while the Kernel thread stays Runnable at this generation.
    drop(dormant);
    assert!(
        <HvpatchTaskBindingDirectory as TaskBindingResolver<_>>::resolve(
            directory.as_ref(),
            context.thread().key(),
            generation,
        )
        .is_err(),
        "the dropped submission's binding is gone, as the rollback intends",
    );

    // A real producer wakes the still-Kernel-runnable generation.
    scheduler
        .make_runnable(context.thread().key())
        .expect("a producer may still wake the published thread");

    let claimable = scheduler.queued_len();
    if claimable != 0 {
        let running = scheduler.take(&executor).expect("claim the queued row");
        let resolved = <HvpatchTaskBindingDirectory as TaskBindingResolver<_>>::resolve(
            directory.as_ref(),
            running.thread_key(),
            running.generation(),
        );
        assert!(
            resolved.is_ok(),
            "an executor claimed a row whose submission never published: {:?}",
            resolved.err(),
        );
    }
    assert_eq!(
        claimable, 0,
        "a never-published generation must never hand an executor a row",
    );

    // And the rollback that follows still retires the generation and
    // drains the queue: a held row is not a stranded one.
    scheduler
        .fail_runnable_exact(
            context.thread().key(),
            generation,
            crate::kernel::objects::ExecutionFailure::SnapshotSaveFailed,
        )
        .expect("the rollback owns an unclaimed runnable generation");
    assert_eq!(scheduler.queued_len(), 0);
    scheduler.unregister_executor(&executor).unwrap();
}

#[test]
fn a_wake_before_activation_leaves_the_dormant_row_unclaimable() {
    // The other half of the pre-activation wake window. A fork child, a
    // cloned thread and an exec successor are all published to the Kernel
    // as runnable BEFORE the dormant submission that owns them is
    // activated, so a real producer can wake them in that window and
    // enqueue the exact `(thread, generation)` row. Idempotent
    // publication (50503566a) stops that row from failing its own
    // ACTIVATION -- it does not stop an EXECUTOR from claiming it first.
    //
    // A claim in that window resolves a binding record whose `active` is
    // still false, so `resolve` reports "missing exact HVPatch task
    // binding", the worker fails the task with `SnapshotRestoreFailed`,
    // and the clone rollback aborts the carrier (rc=134, run `hwfix-4`).
    //
    // The row must therefore not be CLAIMABLE until the submission that
    // owns it is published: the wake stays durable, the run queue holds
    // it, and activation releases it.
    let (kernel, context) = bootstrap(13_995);
    let state = task_state(&context, 110);
    let generation = context
        .thread()
        .publish_initial_task_state(state.clone())
        .expect("publish root state");
    let scheduler = Scheduler::new(kernel);
    let executor = scheduler
        .register_executor(Arc::new(WorkerKick::new(Arc::new(ReceiptLog::default()))))
        .unwrap();
    let directory = Arc::new(HvpatchTaskBindingDirectory::default());
    let binding = hvpatch_test_binding(&context, &state, 110);
    let dormant = directory
        .prepare_submission(
            &scheduler,
            HvpatchSubmissionShape::Root,
            None,
            Arc::clone(context.thread()),
            generation,
            Arc::clone(&binding),
        )
        .expect("prepare dormant root");
    scheduler
        .make_runnable(context.thread().key())
        .expect("a real producer wakes the freshly published task");

    // Drive the exact order the field hit: wake, then CLAIM, then
    // activate. `take` is only reached when a claimable row exists, so
    // this cannot block once the window is closed.
    let claimable = scheduler.queued_len();
    if claimable != 0 {
        let running = scheduler
            .take(&executor)
            .expect("claim the wake-queued row");
        let resolved = <HvpatchTaskBindingDirectory as TaskBindingResolver<_>>::resolve(
            directory.as_ref(),
            running.thread_key(),
            running.generation(),
        );
        assert!(
            resolved.is_ok(),
            "an executor claimed a row whose submission is still dormant: {:?}",
            resolved.err(),
        );
    }
    assert_eq!(
        claimable, 0,
        "a wake before activation must not publish a claimable row",
    );

    let start_gate = context
        .thread()
        .take_opened_start_gate(generation)
        .expect("opened root start gate");
    let proof = HvpatchActivationProof::validate(
        &context,
        &state,
        generation,
        binding.identity(),
        start_gate,
    )
    .unwrap();
    dormant
        .activate(&scheduler, Arc::clone(context.thread()), proof)
        .expect("activation publishes the wake's held row");

    // Activation is publication: the held row becomes claimable exactly
    // once, and the claim now resolves.
    assert_eq!(scheduler.queued_len(), 1);
    let running = scheduler
        .take(&executor)
        .expect("claim the row activation released");
    <HvpatchTaskBindingDirectory as TaskBindingResolver<_>>::resolve(
        directory.as_ref(),
        running.thread_key(),
        running.generation(),
    )
    .expect("an activated submission resolves for its claimant");
    scheduler.settle_runnable(running).unwrap();
    scheduler.unregister_executor(&executor).unwrap();
}

#[test]
fn dormant_submission_activates_all_four_exact_authority_shapes() {
    let (kernel, root) = bootstrap(13_996);
    let sibling = sibling(&kernel, &root, 23_996);
    let first_child = process_child(&kernel, &root, 33_996, "first-child");
    let peer_child = process_child(&kernel, &root, 43_996, "peer-child");
    let scheduler = Arc::new(Scheduler::new(kernel));
    let directory = Arc::new(HvpatchTaskBindingDirectory::default());
    directory.install_scheduler(&scheduler).unwrap();

    let root_state = task_state(&root, 96);
    let sibling_state = task_state(&sibling, 97);
    let first_child_state = task_state(&first_child, 98);
    let peer_child_state = task_state(&peer_child, 99);
    let root_generation = root
        .thread()
        .publish_initial_task_state(root_state.clone())
        .unwrap();
    let sibling_generation = sibling
        .thread()
        .publish_initial_task_state(sibling_state.clone())
        .unwrap();
    let first_child_generation = first_child
        .thread()
        .publish_initial_task_state(first_child_state.clone())
        .unwrap();
    let peer_child_generation = peer_child
        .thread()
        .publish_initial_task_state(peer_child_state.clone())
        .unwrap();
    let root_binding = hvpatch_test_binding(&root, &root_state, 96);
    let sibling_binding = hvpatch_test_binding(&sibling, &sibling_state, 97);
    let first_child_binding = hvpatch_test_binding(&first_child, &first_child_state, 98);
    let peer_child_binding = hvpatch_test_binding(&peer_child, &peer_child_state, 99);

    let root_submission = directory
        .prepare_submission(
            &scheduler,
            HvpatchSubmissionShape::Root,
            None,
            Arc::clone(root.thread()),
            root_generation,
            Arc::clone(&root_binding),
        )
        .unwrap();
    activate_hvpatch_test_submission(
        root_submission,
        &scheduler,
        &root,
        &root_state,
        root_generation,
        root_binding.as_ref(),
    );
    let root_grant = (root.thread().key(), root_generation);
    let root_authority = directory
        .take_submission_authority(root_grant.0, root_grant.1)
        .expect("worker holds exact root authority during resident quantum");
    assert!(
        directory
            .prepare_submission(
                &scheduler,
                HvpatchSubmissionShape::SameTaskSibling { grant: root_grant },
                None,
                Arc::clone(sibling.thread()),
                sibling_generation,
                Arc::clone(&sibling_binding),
            )
            .is_err()
    );
    let reject_descendant = |_, _| {
        Err(TrapError::Hypervisor(
            "worker-held grant test publishes no nested descendant".to_owned(),
        ))
    };
    let worker_submission = ExecutorSubmissionContext {
        scheduler: &scheduler,
        publish_test_descendant: &reject_descendant,
        current: Some(&root_authority),
        lease: None,
        exec_replacement: None,
    };

    let sibling_submission = worker_submission
        .prepare_hvpatch_submission(
            &directory,
            HvpatchSubmissionShape::SameTaskSibling { grant: root_grant },
            Arc::clone(sibling.thread()),
            sibling_generation,
            Arc::clone(&sibling_binding),
        )
        .unwrap();
    activate_hvpatch_test_submission(
        sibling_submission,
        &scheduler,
        &sibling,
        &sibling_state,
        sibling_generation,
        sibling_binding.as_ref(),
    );

    let child_submission = directory
        .prepare_submission(
            &scheduler,
            HvpatchSubmissionShape::Descendant { grant: root_grant },
            Some(&root_authority),
            Arc::clone(first_child.thread()),
            first_child_generation,
            Arc::clone(&first_child_binding),
        )
        .unwrap();
    activate_hvpatch_test_submission(
        child_submission,
        &scheduler,
        &first_child,
        &first_child_state,
        first_child_generation,
        first_child_binding.as_ref(),
    );
    let first_child_authority = directory
        .take_submission_authority(first_child.thread().key(), first_child_generation)
        .expect("worker holds exact child authority during resident quantum");

    let peer_submission = directory
        .prepare_submission(
            &scheduler,
            HvpatchSubmissionShape::PeerRoot {
                grant: (first_child.thread().key(), first_child_generation),
            },
            Some(&first_child_authority),
            Arc::clone(peer_child.thread()),
            peer_child_generation,
            Arc::clone(&peer_child_binding),
        )
        .unwrap();
    activate_hvpatch_test_submission(
        peer_submission,
        &scheduler,
        &peer_child,
        &peer_child_state,
        peer_child_generation,
        peer_child_binding.as_ref(),
    );

    assert_eq!(scheduler.queued_len(), 4);
    directory
        .restore_submission_authority(root_authority)
        .expect("restore root authority after resident quantum");
    directory
        .restore_submission_authority(first_child_authority)
        .expect("restore child authority after resident quantum");
}

#[test]
fn dormant_submission_rejects_each_wrong_non_root_authority_shape() {
    let (kernel, root) = bootstrap(13_997);
    let root_sibling = sibling(&kernel, &root, 23_997);
    let first_child = process_child(&kernel, &root, 33_997, "first-child");
    let peer_child = process_child(&kernel, &root, 43_997, "peer-child");
    let scheduler = Scheduler::new(Arc::clone(&kernel));
    let directory = Arc::new(HvpatchTaskBindingDirectory::default());
    let root_state = task_state(&root, 100);
    let root_generation = root
        .thread()
        .publish_initial_task_state(root_state.clone())
        .unwrap();
    let root_binding = hvpatch_test_binding(&root, &root_state, 100);
    let root_submission = directory
        .prepare_submission(
            &scheduler,
            HvpatchSubmissionShape::Root,
            None,
            Arc::clone(root.thread()),
            root_generation,
            Arc::clone(&root_binding),
        )
        .unwrap();
    activate_hvpatch_test_submission(
        root_submission,
        &scheduler,
        &root,
        &root_state,
        root_generation,
        root_binding.as_ref(),
    );
    let root_grant = (root.thread().key(), root_generation);
    let root_authority = directory
        .take_submission_authority(root_grant.0, root_grant.1)
        .expect("worker-held root grant");

    let first_child_state = task_state(&first_child, 101);
    let first_child_generation = first_child
        .thread()
        .publish_initial_task_state(first_child_state.clone())
        .unwrap();
    let sibling_state = task_state(&root_sibling, 102);
    let sibling_generation = root_sibling
        .thread()
        .publish_initial_task_state(sibling_state.clone())
        .unwrap();
    assert!(
        directory
            .prepare_submission(
                &scheduler,
                HvpatchSubmissionShape::SameTaskSibling { grant: root_grant },
                Some(&root_authority),
                Arc::clone(first_child.thread()),
                first_child_generation,
                hvpatch_test_binding(&first_child, &first_child_state, 101),
            )
            .is_err()
    );
    for shape in [
        HvpatchSubmissionShape::Descendant { grant: root_grant },
        HvpatchSubmissionShape::PeerRoot { grant: root_grant },
    ] {
        assert!(
            directory
                .prepare_submission(
                    &scheduler,
                    shape,
                    Some(&root_authority),
                    Arc::clone(root_sibling.thread()),
                    sibling_generation,
                    hvpatch_test_binding(&root_sibling, &sibling_state, 102),
                )
                .is_err()
        );
    }

    let first_child_binding = hvpatch_test_binding(&first_child, &first_child_state, 101);
    let first_child_submission = directory
        .prepare_submission(
            &scheduler,
            HvpatchSubmissionShape::Descendant { grant: root_grant },
            Some(&root_authority),
            Arc::clone(first_child.thread()),
            first_child_generation,
            Arc::clone(&first_child_binding),
        )
        .expect("correct descendant shape remains usable after rejection");
    activate_hvpatch_test_submission(
        first_child_submission,
        &scheduler,
        &first_child,
        &first_child_state,
        first_child_generation,
        first_child_binding.as_ref(),
    );
    let first_child_authority = directory
        .take_submission_authority(first_child.thread().key(), first_child_generation)
        .expect("worker-held child grant");

    let child_sibling = sibling(&kernel, &first_child, 53_997);
    let child_sibling_state = task_state(&child_sibling, 106);
    let child_sibling_generation = child_sibling
        .thread()
        .publish_initial_task_state(child_sibling_state.clone())
        .unwrap();
    assert!(
        directory
            .prepare_submission(
                &scheduler,
                HvpatchSubmissionShape::Descendant { grant: root_grant },
                Some(&root_authority),
                Arc::clone(child_sibling.thread()),
                child_sibling_generation,
                hvpatch_test_binding(&child_sibling, &child_sibling_state, 106),
            )
            .is_err()
    );

    let peer_state = task_state(&peer_child, 105);
    let peer_generation = peer_child
        .thread()
        .publish_initial_task_state(peer_state.clone())
        .unwrap();
    assert!(
        directory
            .prepare_submission(
                &scheduler,
                HvpatchSubmissionShape::Descendant {
                    grant: (first_child.thread().key(), first_child_generation),
                },
                Some(&first_child_authority),
                Arc::clone(peer_child.thread()),
                peer_generation,
                hvpatch_test_binding(&peer_child, &peer_state, 105),
            )
            .is_err()
    );
    let peer_sibling = sibling(&kernel, &peer_child, 63_997);
    let peer_sibling_state = task_state(&peer_sibling, 107);
    let peer_sibling_generation = peer_sibling
        .thread()
        .publish_initial_task_state(peer_sibling_state.clone())
        .unwrap();
    assert!(
        directory
            .prepare_submission(
                &scheduler,
                HvpatchSubmissionShape::PeerRoot {
                    grant: (first_child.thread().key(), first_child_generation),
                },
                Some(&first_child_authority),
                Arc::clone(peer_sibling.thread()),
                peer_sibling_generation,
                hvpatch_test_binding(&peer_sibling, &peer_sibling_state, 107),
            )
            .is_err()
    );
    directory
        .restore_submission_authority(root_authority)
        .expect("restore root authority");
    directory
        .restore_submission_authority(first_child_authority)
        .expect("restore child authority");
}

#[test]
fn dormant_root_submission_rejects_a_process_child_authority_shape() {
    let (kernel, root) = bootstrap(13_992);
    let child = process_child(&kernel, &root, 23_992, "not-root");
    let state = task_state(&child, 92);
    let generation = child
        .thread()
        .publish_initial_task_state(state.clone())
        .expect("publish child state");
    let scheduler = Scheduler::new(kernel);
    let directory = Arc::new(HvpatchTaskBindingDirectory::default());
    let binding = hvpatch_test_binding(&child, &state, 92);

    assert!(
        directory
            .prepare_submission(
                &scheduler,
                HvpatchSubmissionShape::Root,
                None,
                Arc::clone(child.thread()),
                generation,
                binding,
            )
            .is_err()
    );
}

fn enqueue_root(
    scheduler: &Arc<Scheduler>,
    context: &KernelContext,
    generation: ExecutionGeneration,
) -> SubmissionAuthority {
    let authority = scheduler
        .admit_root(context.thread().key(), generation)
        .expect("admit root");
    authority
        .publish(scheduler, Arc::clone(context.thread()))
        .expect("publish root");
    authority
}

fn config(workers: usize) -> ExecutorPoolConfig {
    ExecutorPoolConfig {
        bound_workers: workers,
        spare_executors: 0,
        vcpu_ceiling: workers + 1,
        reserve: 1,
    }
}

fn start_pool(
    scheduler: Arc<Scheduler>,
    factory: Arc<FakeFactory>,
    workers: usize,
) -> ExecutorPool<FakeFactory, FakeFactory> {
    ExecutorPool::start(
        config(workers),
        scheduler,
        Arc::clone(&factory),
        factory,
        ExecutorBoundaryAudit::production(),
    )
    .expect("start executor pool")
}

#[test]
fn a_second_pool_on_one_kernel_cannot_replace_the_debug_owner() {
    let (kernel, _root) = bootstrap(14_005);
    let first_scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
    let first_factory = Arc::new(FakeFactory::default());
    let first_pool = start_pool(first_scheduler, first_factory, 1);

    let second_scheduler = Arc::new(Scheduler::new(kernel));
    let second_factory = Arc::new(FakeFactory::default());
    let error = ExecutorPool::start(
        config(1),
        second_scheduler,
        Arc::clone(&second_factory),
        second_factory,
        ExecutorBoundaryAudit::production(),
    )
    .expect_err("a carrier cannot publish a second executor debug owner");
    assert!(
        error.to_string().contains("already registered"),
        "unexpected failure: {error}",
    );

    first_pool.shutdown().expect("first pool remains healthy");
}

#[test]
fn pool_size_is_bounded_and_zero_host_capacity_fails_before_creation() {
    // The per-CPU set is capped by the backend's vCPU budget.
    assert_eq!(
        ExecutorPoolConfig {
            bound_workers: 12,
            spare_executors: 0,
            vcpu_ceiling: 8,
            reserve: 2,
        }
        .bound_worker_count()
        .unwrap(),
        6
    );
    assert_eq!(
        ExecutorPoolConfig {
            bound_workers: 0,
            spare_executors: 0,
            vcpu_ceiling: 8,
            reserve: 99,
        }
        .bound_worker_count()
        .unwrap(),
        1
    );
    assert!(
        ExecutorPoolConfig {
            bound_workers: 8,
            spare_executors: 0,
            vcpu_ceiling: 0,
            reserve: 0,
        }
        .executor_count()
        .is_err()
    );
}

#[test]
fn spares_take_only_what_the_vcpu_budget_leaves_after_the_guest_cpus() {
    let config = ExecutorPoolConfig {
        bound_workers: 4,
        spare_executors: 8,
        vcpu_ceiling: 60,
        reserve: 0,
    };
    assert_eq!(config.bound_worker_count().unwrap(), 4);
    assert_eq!(config.spare_worker_count().unwrap(), 8);
    assert_eq!(config.executor_count().unwrap(), 12);

    // A tight ceiling spends it on guest CPUs first; spares get the rest.
    let tight = ExecutorPoolConfig {
        bound_workers: 4,
        spare_executors: 8,
        vcpu_ceiling: 6,
        reserve: 0,
    };
    assert_eq!(tight.bound_worker_count().unwrap(), 4);
    assert_eq!(tight.spare_worker_count().unwrap(), 2);

    // The `=0` bisection hatch really yields no spares.
    let none = ExecutorPoolConfig {
        spare_executors: 0,
        ..config
    };
    assert_eq!(none.spare_worker_count().unwrap(), 0);
    assert_eq!(none.executor_count().unwrap(), 4);
}

#[test]
fn creation_is_transactional_and_every_created_vcpu_dies_on_its_owner_worker() {
    let caller = thread::current().id();
    let (kernel, _) = bootstrap(14_001);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let factory = Arc::new(FakeFactory::default());
    factory.fail_create_call.store(3, Ordering::SeqCst);
    let error = ExecutorPool::start(
        config(4),
        scheduler,
        Arc::clone(&factory),
        Arc::clone(&factory),
        ExecutorBoundaryAudit::production(),
    )
    .expect_err("third create must abort startup");
    assert_eq!(error.configured_workers(), 4);
    let events = factory.events.lock().clone();
    let creates: Vec<_> = events
        .iter()
        .filter(|event| event.kind == BackendEventKind::Create)
        .collect();
    let destroys: Vec<_> = events
        .iter()
        .filter(|event| event.kind == BackendEventKind::Destroy)
        .collect();
    assert_eq!(creates.len(), 3);
    assert_eq!(destroys.len(), 2);
    assert!(creates.iter().all(|event| event.host_thread != caller));
    for destroy in destroys {
        let create = creates
            .iter()
            .find(|event| event.executor == destroy.executor)
            .expect("matching create");
        assert_eq!(create.host_thread, destroy.host_thread);
    }
}

#[test]
fn multi_worker_initial_audit_panic_returns_transactionally_and_destroys_every_created_backend() {
    let caller = thread::current().id();
    let (kernel, _) = bootstrap(14_005);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let factory = Arc::new(FakeFactory::default());
    factory.panic_initial_audit_call.store(2, Ordering::SeqCst);
    let gate = Arc::new(Barrier::new(2));
    *factory.initial_audit_gate.lock() = Some(Arc::clone(&gate));
    let (result_tx, result_rx) = std::sync::mpsc::channel();
    let start_factory = Arc::clone(&factory);
    let starter = thread::spawn(move || {
        let result = ExecutorPool::start(
            config(3),
            scheduler,
            Arc::clone(&start_factory),
            start_factory,
            ExecutorBoundaryAudit::production(),
        );
        result_tx
            .send(result.is_err())
            .expect("publish startup result");
    });
    gate.wait();
    assert_eq!(
        result_rx.recv_timeout(Duration::from_secs(1)),
        Ok(true),
        "initial audit panic must not strand startup behind other worker senders"
    );
    starter.join().expect("join pool starter");

    let events = factory.events.lock().clone();
    let creates: Vec<_> = events
        .iter()
        .filter(|event| event.kind == BackendEventKind::Create)
        .collect();
    let destroys: Vec<_> = events
        .iter()
        .filter(|event| event.kind == BackendEventKind::Destroy)
        .collect();
    assert_eq!(creates.len(), 2);
    assert_eq!(destroys.len(), 2);
    assert!(creates.iter().all(|event| event.host_thread != caller));
    for create in creates {
        let destroy = destroys
            .iter()
            .find(|event| event.executor == create.executor)
            .expect("created backend must be destroyed during rollback");
        assert_eq!(create.host_thread, destroy.host_thread);
    }
}

#[test]
fn sequential_generations_reuse_one_executor_and_migration_follows_save() {
    let (kernel, first) = bootstrap(14_010);
    let second = sibling(&kernel, &first, 24_010);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let factory = Arc::new(FakeFactory::default());
    let first_binding = FakeBinding::new(10, [Step::Yield, Step::Exit]);
    let second_binding = FakeBinding::new(20, [Step::Exit]);
    factory.install(&first, first_binding);
    factory.install(&second, second_binding);
    let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
    let first_authority = enqueue_root(&scheduler, &first, publish(&first, 10));
    let second_authority = enqueue_root(&scheduler, &second, publish(&second, 20));
    drop((first_authority, second_authority));
    let report = pool.shutdown().expect("clean shutdown");
    assert_eq!(report.created(), 1);
    assert_eq!(report.destroyed(), 1);
    let events = factory.events.lock();
    let loaded: Vec<_> = events
        .iter()
        .filter(|event| event.kind == BackendEventKind::Load)
        .collect();
    assert_eq!(loaded.len(), 3);
    assert_eq!(
        loaded
            .iter()
            .map(|event| event.executor)
            .collect::<BTreeSet<_>>()
            .len(),
        1
    );
    assert!(factory.concurrent_loads.lock().is_empty());
    let first_loads: Vec<_> = loaded
        .iter()
        .filter(|event| {
            event
                .task
                .is_some_and(|(key, _)| key == first.thread().key())
        })
        .collect();
    assert_eq!(first_loads.len(), 2);
    let save_position = events
        .iter()
        .position(|event| {
            event.kind == BackendEventKind::Save
                && event
                    .task
                    .is_some_and(|(key, _)| key == first.thread().key())
        })
        .unwrap();
    let reload_position = events
        .iter()
        .rposition(|event| {
            event.kind == BackendEventKind::Load
                && event
                    .task
                    .is_some_and(|(key, _)| key == first.thread().key())
        })
        .unwrap();
    assert!(save_position < reload_position);
}

#[test]
fn hvpatch_binding_rollover_publishes_exact_successor_before_retiring_predecessor() {
    struct ExitJob;
    impl crate::vcpu_loop::continuation::PersistentQuantumJob for ExitJob {
        fn poll_quantum_with_engine(
            &mut self,
            _engine: &mut dyn std::any::Any,
            _control: &mut HvpatchQuantumControl<'_, '_>,
        ) -> ExecutorExit {
            ExecutorExit::Exited
        }
    }

    let (kernel, context) = bootstrap(14_011);
    let first = publish(&context, 11);
    let scheduler = Scheduler::new(kernel);
    let executor = scheduler
        .register_executor(Arc::new(WorkerKick::new(Arc::new(ReceiptLog::default()))))
        .unwrap();
    scheduler.make_runnable(context.thread().key()).unwrap();
    let running = scheduler.take(&executor).unwrap();
    scheduler.settle_runnable(running).unwrap();
    let successor = context.thread().execution_state().generation().unwrap();
    assert_eq!(successor.raw(), first.raw() + 1);

    let completion = crate::vcpu_loop::continuation::LogicalJobCompletion::pending();
    let binding = Arc::new(crate::vcpu_loop::continuation::HvpatchTaskBinding::new(
        TaskLoadIdentity {
            abi: carrick_abi::LinuxGuestAbi::Aarch64,
            version: 1,
            mm: context.shared().mm().id(),
            asid_generation: context.shared().mm().id().raw(),
        },
        Arc::new(crate::vcpu_loop::continuation::HvpatchTaskQuantum::new(
            Box::new(ExitJob),
            completion,
        )),
        Box::new(17_u64),
    ));
    let directory = HvpatchTaskBindingDirectory::default();
    directory
        .publish(context.thread().key(), first, Arc::clone(&binding))
        .unwrap();
    directory
        .rollover_exact(context.thread().key(), first, successor)
        .unwrap();
    assert!(
        <HvpatchTaskBindingDirectory as TaskBindingResolver<_>>::resolve(
            &directory,
            context.thread().key(),
            first,
        )
        .is_err()
    );
    let resolved = <HvpatchTaskBindingDirectory as TaskBindingResolver<_>>::resolve(
        &directory,
        context.thread().key(),
        successor,
    )
    .unwrap();
    assert!(Arc::ptr_eq(&resolved, &binding));
    let successor_running = scheduler.take(&executor).unwrap();
    scheduler.settle_exited(successor_running).unwrap();
    scheduler.unregister_executor(&executor).unwrap();
    scheduler.close();
    scheduler.wait_closed();
}

#[test]
fn shutdown_cancels_dormant_exact_binding_and_completes_once() {
    struct BlockedJob;
    impl crate::vcpu_loop::continuation::PersistentQuantumJob for BlockedJob {
        fn poll_quantum_with_engine(
            &mut self,
            _engine: &mut dyn std::any::Any,
            _control: &mut HvpatchQuantumControl<'_, '_>,
        ) -> ExecutorExit {
            ExecutorExit::Blocked(BlockedReason::HostWait)
        }
    }

    let (kernel, context) = bootstrap(14_014);
    let generation = publish(&context, 14);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let directory = Arc::new(HvpatchTaskBindingDirectory::default());
    directory.install_scheduler(&scheduler).unwrap();
    let completion = crate::vcpu_loop::continuation::LogicalJobCompletion::pending();
    let binding = Arc::new(crate::vcpu_loop::continuation::HvpatchTaskBinding::new(
        TaskLoadIdentity {
            abi: carrick_abi::LinuxGuestAbi::Aarch64,
            version: 1,
            mm: context.shared().mm().id(),
            asid_generation: context.shared().mm().id().raw(),
        },
        Arc::new(crate::vcpu_loop::continuation::HvpatchTaskQuantum::new(
            Box::new(BlockedJob),
            completion.clone(),
        )),
        Box::new(14_u64),
    ));
    directory
        .publish(context.thread().key(), generation, binding)
        .unwrap();
    let authority = scheduler
        .admit_root(context.thread().key(), generation)
        .unwrap();
    directory
        .install_root_authority(&scheduler, Arc::clone(context.thread()), authority)
        .unwrap();

    let executor = scheduler
        .register_executor(Arc::new(WorkerKick::new(Arc::new(ReceiptLog::default()))))
        .unwrap();
    let running = scheduler.take(&executor).unwrap();
    scheduler.close();
    assert_eq!(
        directory
            .cancel_dormant(&scheduler, ExecutionFailure::SnapshotRestoreFailed)
            .unwrap(),
        0,
        "pre-join cancellation may observe the still-running predecessor"
    );
    scheduler
        .settle_blocked(running, BlockedReason::HostWait)
        .unwrap();
    let blocked_generation = context.thread().execution_state().generation().unwrap();
    assert!(!completion.is_finished());
    scheduler.unregister_executor(&executor).unwrap();

    assert_eq!(
        directory
            .cancel_dormant(&scheduler, ExecutionFailure::SnapshotRestoreFailed)
            .unwrap(),
        1
    );
    assert_eq!(
        directory
            .cancel_dormant(&scheduler, ExecutionFailure::SnapshotRestoreFailed)
            .unwrap(),
        0,
        "terminal completion and retirement are exact-once"
    );
    scheduler.wait_closed();
    assert!(completion.is_finished());
    assert!(matches!(
        context.thread().execution_state(),
        ThreadExecutionState::Failed { .. }
    ));
    assert!(
        <HvpatchTaskBindingDirectory as TaskBindingResolver<_>>::resolve(
            directory.as_ref(),
            context.thread().key(),
            blocked_generation,
        )
        .is_err()
    );
}

#[test]
fn exec_replacement_keeps_worker_identity_and_swaps_thread_mm_asid_binding() {
    struct ExitJob;
    impl crate::vcpu_loop::continuation::PersistentQuantumJob for ExitJob {
        fn poll_quantum_with_engine(
            &mut self,
            _engine: &mut dyn std::any::Any,
            _control: &mut HvpatchQuantumControl<'_, '_>,
        ) -> ExecutorExit {
            ExecutorExit::Exited
        }
    }

    let (kernel, context) = bootstrap(14_016);
    let old_mm = context.shared().mm().id();
    let old_generation = publish(&context, 16);
    let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
    let directory = Arc::new(HvpatchTaskBindingDirectory::default());
    directory.install_scheduler(&scheduler).unwrap();
    let completion = crate::vcpu_loop::continuation::LogicalJobCompletion::pending();
    let old_binding = Arc::new(crate::vcpu_loop::continuation::HvpatchTaskBinding::new(
        TaskLoadIdentity {
            abi: carrick_abi::LinuxGuestAbi::Aarch64,
            version: 1,
            mm: old_mm,
            asid_generation: old_mm.raw(),
        },
        Arc::new(crate::vcpu_loop::continuation::HvpatchTaskQuantum::new(
            Box::new(ExitJob),
            completion,
        )),
        Box::new(16_u64),
    ));
    directory
        .publish(
            context.thread().key(),
            old_generation,
            Arc::clone(&old_binding),
        )
        .unwrap();
    let authority = scheduler
        .admit_root(context.thread().key(), old_generation)
        .unwrap();
    directory
        .install_root_authority(&scheduler, Arc::clone(context.thread()), authority)
        .unwrap();
    let worker = Arc::new(WorkerKick::new(Arc::new(ReceiptLog::default())));
    let registration = scheduler.register_executor(worker).unwrap();
    let mut running = scheduler.take(&registration).unwrap();
    let worker_id = running.executor();
    let predecessor_authority = directory
        .take_submission_authority(context.thread().key(), old_generation)
        .expect("running generation authority");

    let prepared = kernel
        .prepare_exec_with_registry_id(&context, ThreadId::synthetic_for_tests(114_016), None)
        .unwrap();
    let old_lease = running.take_lease();
    context.thread().exit_from_executor(old_lease).unwrap();
    let committed = kernel.commit_exec_transition(prepared, None).unwrap();
    let committed_context = committed.context().retain_exact();
    let new_mm = committed_context.shared().mm().id();
    let committed = committed
        .attach_successor_asid_generation(new_mm, new_mm.raw())
        .unwrap();
    assert_ne!(new_mm, old_mm);
    let new_generation = committed_context
        .thread()
        .publish_initial_task_state(task_state(&committed_context, 17))
        .unwrap();
    let new_lease = committed_context
        .thread()
        .claim_runnable(worker_id)
        .unwrap();
    let identity = TaskLoadIdentity {
        abi: carrick_abi::LinuxGuestAbi::Aarch64,
        version: 1,
        mm: new_mm,
        asid_generation: new_mm.raw(),
    };
    let replacement_record = scheduler
        .retarget_running_exec(&mut running, committed, new_lease, |transition| {
            directory.replace_exec(
                &scheduler,
                ExecBindingTransition {
                    predecessor_thread: context.thread().key(),
                    predecessor_generation: old_generation,
                    successor_thread: transition.successor_thread,
                    successor_generation: new_generation,
                    identity,
                    replacement_mm: None,
                    authority: Some(predecessor_authority),
                },
            )
        })
        .unwrap();
    let super::ExecBindingReplacement {
        binding: replacement_binding,
        authority: replacement_authority,
    } = replacement_record;
    directory
        .restore_submission_authority(
            replacement_authority.expect("exec retains exact successor authority"),
        )
        .unwrap();

    assert_eq!(running.executor(), worker_id);
    assert_eq!(running.thread_key(), committed_context.thread().key());
    assert_eq!(running.generation(), new_generation);
    assert_eq!(replacement_binding.identity(), identity);
    assert!(!Arc::ptr_eq(&replacement_binding, &old_binding));
    assert!(
        directory
            .resolve(context.thread().key(), old_generation)
            .is_err()
    );
    assert!(Arc::ptr_eq(
        &directory
            .resolve(committed_context.thread().key(), new_generation)
            .unwrap(),
        &replacement_binding
    ));
    scheduler.settle_exited(running).unwrap();
    scheduler.unregister_executor(&registration).unwrap();
    scheduler.close();
    scheduler.wait_closed();
}

#[test]
fn compute_bound_preemption_reaches_the_exact_live_hardware_kick() {
    #[derive(Clone)]
    struct CountingKick(Arc<AtomicUsize>);
    impl carrick_hal::VcpuKick for CountingKick {
        fn kick(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let (kernel, first) = bootstrap(14_012);
    let second = sibling(&kernel, &first, 24_012);
    publish(&first, 12);
    publish(&second, 13);
    let scheduler = Scheduler::new(kernel);
    let worker = Arc::new(WorkerKick::new(Arc::new(ReceiptLog::default())));
    let executor = scheduler.register_executor(worker.clone()).unwrap();
    scheduler.make_runnable(first.thread().key()).unwrap();
    let running = scheduler.take(&executor).unwrap();
    let kicks = Arc::new(AtomicUsize::new(0));
    let owner = super::current_owner_thread_port();
    let wrong_owner = owner.wrapping_add(1).max(1);
    assert!(
        !worker.publish_hardware(
            super::ExactHardwareKick::new(
                Box::new(CountingKick(Arc::clone(&kicks))),
                12,
                wrong_owner,
            )
            .unwrap()
        )
    );
    assert!(
        worker.publish_hardware(
            super::ExactHardwareKick::new(Box::new(CountingKick(Arc::clone(&kicks))), 12, owner,)
                .unwrap()
        )
    );
    assert!(
        !worker.publish_hardware(
            super::ExactHardwareKick::new(Box::new(CountingKick(Arc::clone(&kicks))), 12, owner,)
                .unwrap()
        ),
        "exact hardware identity is publish-once for one loaded binding"
    );
    scheduler.make_runnable(second.thread().key()).unwrap();
    assert_eq!(scheduler.request_preemption(), 1);
    assert_eq!(kicks.load(Ordering::SeqCst), 1);
    scheduler.settle_exited(running).unwrap();
    scheduler.unregister_executor(&executor).unwrap();
}

#[test]
fn worker_hardware_identity_is_create_owned_across_idle_load_save_and_shutdown() {
    #[derive(Clone)]
    struct CountingKick(Arc<AtomicUsize>);
    impl carrick_hal::VcpuKick for CountingKick {
        fn kick(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let (kernel, context) = bootstrap(14_249);
    publish(&context, 97);
    let scheduler = Scheduler::new(kernel);
    let worker = Arc::new(WorkerKick::new(Arc::new(ReceiptLog::default())));
    let owner = super::current_owner_thread_port();
    let kicks = Arc::new(AtomicUsize::new(0));

    // HVF's first valid hv_vcpu_t is zero. Absence is represented by the
    // Option/result capability, never by rejecting that numeric identity.
    let hardware =
        super::ExactHardwareKick::new(Box::new(CountingKick(Arc::clone(&kicks))), 0, owner)
            .expect("raw HVF vCPU zero is an exact live identity");
    assert!(
        worker.publish_hardware(hardware),
        "factory publishes hardware while the worker is still idle"
    );

    let registration = scheduler.register_executor(worker.clone()).unwrap();
    scheduler.make_runnable(context.thread().key()).unwrap();
    let first = scheduler.take(&registration).unwrap();
    assert_eq!(worker.hardware.lock().as_ref().unwrap().raw_vcpu_id, 0);
    scheduler.settle_runnable(first).unwrap();
    assert_eq!(
        worker.hardware.lock().as_ref().unwrap().raw_vcpu_id,
        0,
        "save/unbind must retain worker-owned hardware"
    );

    let second = scheduler.take(&registration).unwrap();
    assert_eq!(worker.hardware.lock().as_ref().unwrap().raw_vcpu_id, 0);
    scheduler.settle_exited(second).unwrap();
    assert_eq!(
        worker.hardware.lock().as_ref().unwrap().raw_vcpu_id,
        0,
        "idle worker retains the same kick until shutdown"
    );
    assert!(
        super::ExactHardwareKick::new(Box::new(CountingKick(kicks)), 0, 0).is_err(),
        "a missing Mach owner identity still fails closed"
    );

    let source = include_str!("../executor.rs");
    let worker_main = source
        .split("fn executor_worker")
        .nth(1)
        .and_then(|tail| tail.split("fn terminal_drain").next())
        .expect("worker lifecycle");
    assert!(
        worker_main.find("backend.hardware_kick()").unwrap()
            < worker_main.find("boundary.audit_clean").unwrap(),
        "hardware must publish once at create before the idle audit"
    );
    let run_loop = source
        .split("fn run_executor_loop")
        .nth(1)
        .and_then(|tail| tail.split("fn service_owner_thread_commands").next())
        .expect("worker run loop");
    assert_eq!(
        run_loop.matches("publish_hardware").count(),
        0,
        "task load must not republish worker-owned hardware"
    );
    let pool_source = include_str!("pool.rs");
    let unbind = pool_source
        .split("fn unbind(&self, binding: ExecutorBinding)")
        .nth(1)
        .and_then(|tail| tail.split("fn rebind_exact_with").next())
        .expect("kick unbind");
    assert!(
        !unbind.contains("hardware.lock().take()"),
        "task save/unbind must not clear worker hardware"
    );

    worker.hardware.lock().take().expect("shutdown owns kick");
    scheduler.unregister_executor(&registration).unwrap();
    scheduler.close();
    scheduler.wait_closed();
}

/// RED-FIRST RECEIPT for the reaped-settlement publication.
///
/// A yield whose target is reaped in flight settles cleanly — round 3 and
/// round 4 fixed that — but the job the thread owns is left with NO
/// publisher: no successor is queued, no executor runs that generation
/// again, and no exit or exec path names it. Its `HvpatchLoopResult` is
/// never filled and `wait_process_jobs` waits for the life of the process.
/// That is the `go_types` wedge: the guest printed PASS, eighteen
/// executors parked in `take_row`, and main sat in
/// `HvpatchLoopResult::wait`.
///
/// The reap is driven from the test thread while the worker is held inside
/// its first quantum, so the settlement that follows is deterministic
/// rather than load-dependent.
#[test]
fn a_reaped_yield_publishes_the_process_job_it_would_have_stranded() {
    let (kernel, context) = bootstrap(14_610);
    let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
    let factory = Arc::new(FakeFactory::default());
    let binding = FakeBinding::new(170, [Step::Yield, Step::Exit]);
    let entered = Arc::new(Barrier::new(2));
    let resume = Arc::new(Barrier::new(2));
    *binding.entered.lock() = Some(Arc::clone(&entered));
    *binding.resume.lock() = Some(Arc::clone(&resume));
    let (terminal_tx, terminal_rx) = std::sync::mpsc::channel();
    binding.notify_on_terminal_settlement(terminal_tx);
    factory.install(&context, Arc::clone(&binding));
    let generation = publish(&context, 170);
    let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
    // Publish THROUGH the factory so it holds the authority: the reaped
    // rejection this test needs comes from the factory's own rollover, and
    // an authority it never saw would make the transition a silent `Ok`.
    let authority = scheduler
        .admit_root(context.thread().key(), generation)
        .expect("admit root");
    TaskBindingResolver::<FakeBinding>::publish_test_root(
        &*factory,
        &scheduler,
        Arc::clone(context.thread()),
        authority,
    )
    .expect("publish the root through the factory");

    // The worker is inside its first quantum with the row claimed. Reap
    // the task here: the yield settlement that follows names a target the
    // kernel graph holds only as a retirement.
    entered.wait();
    assert!(kernel.reap_task_record_for_test(context.thread().task_key().id));
    resume.wait();

    let published = terminal_rx.recv_timeout(std::time::Duration::from_secs(60));
    let _ = pool.shutdown();
    published.expect(
        "a settlement whose target was reaped must publish the process job it owns; \
         nothing else can",
    );
}

#[test]
fn terminal_settlement_retires_the_exact_binding_before_worker_destroy() {
    let (kernel, context) = bootstrap(14_013);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let factory = Arc::new(FakeFactory::default());
    factory.install(&context, FakeBinding::new(13, [Step::Exit]));
    let generation = publish(&context, 13);
    let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
    let authority = enqueue_root(&scheduler, &context, generation);
    drop(authority);
    let report = pool.shutdown().expect("terminal settlement");
    assert_eq!(
        factory.retired_bindings.lock().as_slice(),
        &[(context.thread().key(), generation)]
    );
    let events = factory.events.lock();
    let destroy = events
        .iter()
        .position(|event| event.kind == BackendEventKind::Destroy)
        .expect("worker destroy");
    assert!(
        events[..destroy]
            .iter()
            .any(|event| event.kind == BackendEventKind::Save),
        "terminal binding retirement follows detach/save and precedes worker destroy"
    );
    assert_eq!(report.created(), report.destroyed());
}

#[test]
fn persistent_save_restores_worker_controls_after_task_snapshot_before_detach() {
    let source = include_str!("backend.rs");
    let save = source
        .split("fn save(\n        &mut self")
        .nth(1)
        .and_then(|tail| tail.split("fn take_pending_retirement").next())
        .expect("persistent executor save body");
    let snapshot = save
        .find("snapshot_task_state_from_live_executor")
        .expect("task snapshot and continuation export");
    let publication = save
        .find("lease.replace_task_state")
        .expect("saved task state publication");
    let neutralize = save
        .find("engine.restore_persistent_executor_invariants")
        .expect("worker control restore");
    let detach = save.find("self.current.take()").expect("engine detach");
    assert!(snapshot < publication);
    assert!(publication < neutralize);
    assert!(neutralize < detach);
}

#[test]
fn task_migrates_between_workers_only_after_complete_save_and_unbind() {
    let (kernel, context) = bootstrap(14_015);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let factory = Arc::new(FakeFactory::default());
    let mut steps = vec![Step::Yield; 20];
    steps.push(Step::Exit);
    factory.install(&context, FakeBinding::new(15, steps));
    let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 2);
    let authority = enqueue_root(&scheduler, &context, publish(&context, 15));
    drop(authority);
    pool.shutdown().expect("clean migration shutdown");
    let events = factory.events.lock();
    let task_events: Vec<_> = events
        .iter()
        .filter(|event| {
            event
                .task
                .is_some_and(|(key, _)| key == context.thread().key())
        })
        .collect();
    let loads: Vec<_> = task_events
        .iter()
        .enumerate()
        .filter(|(_, event)| event.kind == BackendEventKind::Load)
        .collect();
    assert!(
        loads
            .iter()
            .map(|(_, event)| event.executor)
            .collect::<BTreeSet<_>>()
            .len()
            > 1,
        "the real two-worker run must exercise migration"
    );
    for window in loads.windows(2) {
        if window[0].1.executor == window[1].1.executor {
            continue;
        }
        assert!(
            task_events[window[0].0 + 1..window[1].0]
                .iter()
                .any(|event| event.kind == BackendEventKind::Save)
        );
    }
    assert!(factory.concurrent_loads.lock().is_empty());
}

#[test]
fn resident_task_crosses_ten_thousand_syscalls_without_snapshot_or_tick() {
    let (kernel, context) = bootstrap(14_020);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let factory = Arc::new(FakeFactory::default());
    let binding = FakeBinding::new(30, [Step::Syscalls(10_000), Step::Exit]);
    factory.install(&context, Arc::clone(&binding));
    let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
    let authority = enqueue_root(&scheduler, &context, publish(&context, 30));
    drop(authority);
    pool.shutdown().expect("clean shutdown");
    assert_eq!(binding.progress.load(Ordering::SeqCst), 10_001);
    assert_eq!(
        factory.snapshot_count.load(Ordering::SeqCst),
        1,
        "only terminal save"
    );
    assert!(!scheduler.need_resched());
    assert_eq!(
        scheduler.snapshot_count(),
        0,
        "ordinary syscalls never settle"
    );
}

#[test]
fn queued_task_preempts_resident_syscall_loop_at_boundary() {
    let (kernel, first) = bootstrap(14_025);
    let second = sibling(&kernel, &first, 24_025);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let factory = Arc::new(FakeFactory::default());

    let first_entered = Arc::new(Barrier::new(2));
    let first_resume = Arc::new(Barrier::new(2));
    let first_binding = FakeBinding::new(31, [Step::Syscalls(10_000), Step::Exit]);
    *first_binding.entered.lock() = Some(Arc::clone(&first_entered));
    *first_binding.resume.lock() = Some(Arc::clone(&first_resume));

    let second_entered = Arc::new(Barrier::new(2));
    let second_binding = FakeBinding::new(32, [Step::Exit]);
    *second_binding.entered.lock() = Some(Arc::clone(&second_entered));

    factory.install(&first, Arc::clone(&first_binding));
    factory.install(&second, Arc::clone(&second_binding));

    let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
    let first_authority = enqueue_root(&scheduler, &first, publish(&first, 31));

    first_entered.wait();
    let second_authority = enqueue_root(&scheduler, &second, publish(&second, 32));
    first_resume.wait();

    second_entered.wait();
    let progress_when_b_entered = first_binding.progress.load(Ordering::SeqCst);
    assert!(
        progress_when_b_entered < 10_000,
        "task B must enter before task A exhausts its syscalls (progress: {progress_when_b_entered})"
    );

    drop((first_authority, second_authority));
    let report = pool.shutdown().expect("clean shutdown");
    assert_eq!(first_binding.progress.load(Ordering::SeqCst), 10_001);
    assert_eq!(second_binding.progress.load(Ordering::SeqCst), 1);
    assert_eq!(report.created(), 1);
    assert_eq!(report.destroyed(), 1);
}

#[test]
fn demand_preemption_and_exact_signal_kick_advance_two_compute_tasks_without_stale_leak() {
    let (kernel, first) = bootstrap(14_030);
    let second = sibling(&kernel, &first, 24_030);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let factory = Arc::new(FakeFactory::default());
    let first_gate = Arc::new(Barrier::new(2));
    let second_gate = Arc::new(Barrier::new(2));
    let first_binding = FakeBinding::new(40, [Step::ComputeUntilKick, Step::Exit]);
    *first_binding.entered.lock() = Some(Arc::clone(&first_gate));
    let second_binding = FakeBinding::new(50, [Step::ComputeUntilKick, Step::Exit]);
    *second_binding.entered.lock() = Some(Arc::clone(&second_gate));
    factory.install(&first, Arc::clone(&first_binding));
    factory.install(&second, Arc::clone(&second_binding));
    let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
    let first_authority = enqueue_root(&scheduler, &first, publish(&first, 40));
    first_gate.wait();
    let second_authority = enqueue_root(&scheduler, &second, publish(&second, 50));
    assert!(scheduler.need_resched());
    assert_eq!(scheduler.request_preemption(), 1);
    second_gate.wait();
    assert!(matches!(
        scheduler.wake(second.thread().key()),
        Ok(crate::kernel::WakeDisposition::Kicked)
    ));
    drop((first_authority, second_authority));
    let report = pool.shutdown().expect("clean shutdown");
    assert!(first_binding.progress.load(Ordering::SeqCst) > 0);
    assert!(second_binding.progress.load(Ordering::SeqCst) > 0);
    for context in [&first, &second] {
        let saves = factory
            .events
            .lock()
            .iter()
            .filter(|event| {
                event.kind == BackendEventKind::Save
                    && event
                        .task
                        .is_some_and(|(key, _)| key == context.thread().key())
            })
            .count();
        assert_eq!(saves, 2, "one preemption plus terminal save");
    }
    let kick_threads: BTreeSet<_> = report
        .events()
        .iter()
        .filter_map(|event| match event.event {
            ExecutorPoolEvent::KickDelivered { thread, .. } => Some(thread),
            _ => None,
        })
        .collect();
    assert_eq!(
        kick_threads,
        BTreeSet::from([first.thread().key(), second.thread().key()])
    );
}

#[test]
fn rebind_in_delivery_validation_to_mutation_window_cannot_flag_or_receipt_successor() {
    let (kernel, context) = bootstrap(14_035);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let receipts = Arc::new(ReceiptLog::default());
    let kick = Arc::new(WorkerKick::new(Arc::clone(&receipts)));
    let registration = scheduler
        .register_executor(Arc::clone(&kick) as Arc<dyn crate::kernel::ExecutorKick>)
        .expect("register exact worker kick");
    let authority = enqueue_root(&scheduler, &context, publish(&context, 55));
    drop(authority);
    let running = scheduler
        .take(&registration)
        .expect("claim first generation");
    let stale_generation = running.generation();
    let gate = Arc::new(Barrier::new(2));
    kick.install_delivery_validation_gate(Arc::clone(&gate));
    let receipt_gate = Arc::new(Barrier::new(2));
    kick.install_delivery_receipt_gate(Arc::clone(&receipt_gate));

    let wake_scheduler = Arc::clone(&scheduler);
    let thread_key = context.thread().key();
    let delivery = thread::spawn(move || wake_scheduler.wake(thread_key));
    gate.wait();

    let (successor_tx, successor_rx) = std::sync::mpsc::channel();
    let (settlement_probe_tx, settlement_probe_rx) = std::sync::mpsc::channel();
    let successor_attempt = Arc::new(Barrier::new(2));
    let successor_attempt_thread = Arc::clone(&successor_attempt);
    let settle_scheduler = Arc::clone(&scheduler);
    let settle_registration = registration.clone();
    let settle_receipts = Arc::clone(&receipts);
    let settle_kick = Arc::clone(&kick);
    let settlement = thread::spawn(move || {
        settlement_probe_tx
            .send(settle_kick.binding.try_lock().is_none())
            .expect("publish settlement-thread lock probe");
        successor_attempt_thread.wait();
        settle_scheduler
            .settle_runnable(running)
            .expect("unbind and publish successor");
        let successor = settle_scheduler
            .take(&settle_registration)
            .expect("bind exact successor generation");
        settle_receipts.record(
            successor.executor(),
            ExecutorPoolEvent::Loaded {
                thread: successor.thread_key(),
                generation: successor.generation(),
            },
        );
        let successor_generation = successor.generation();
        let successor_executor = successor.executor();
        let successor_thread = successor.thread_key();
        settle_scheduler
            .settle_exited(successor)
            .expect("settle exact successor generation");
        settle_receipts.record(
            successor_executor,
            ExecutorPoolEvent::SettledExited {
                thread: successor_thread,
                generation: successor_generation,
            },
        );
        successor_tx
            .send(successor_generation)
            .expect("publish exact successor generation");
    });
    assert!(
        settlement_probe_rx
            .recv()
            .expect("receive settlement-thread lock probe"),
        "the actual settlement thread must observe WouldBlock on the held validation lock"
    );
    gate.wait();
    receipt_gate.wait();
    let receipt_lock_held = kick.binding.try_lock().is_none();
    successor_attempt.wait();
    let early_successor = if receipt_lock_held {
        receipt_gate.wait();
        None
    } else {
        let successor = successor_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("old implementation permits successor before stale kick receipt");
        receipt_gate.wait();
        Some(successor)
    };
    let disposition = delivery.join().expect("join delayed delivery").unwrap();
    let successor_generation = early_successor.unwrap_or_else(|| {
        successor_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("successor claim after exact delivery mutation")
    });
    settlement.join().expect("join successor settlement");

    assert!(
        receipt_lock_held,
        "causal kick receipt must publish while the exact binding lock is retained"
    );
    assert_eq!(disposition, crate::kernel::WakeDisposition::Kicked);
    assert_ne!(successor_generation, stale_generation);
    assert!(!kick.need_resched.load(Ordering::Acquire));
    let events = receipts.snapshot();
    let old_kick = events
        .iter()
        .position(|receipt| {
            matches!(
                receipt.event,
                ExecutorPoolEvent::KickDelivered { generation, .. }
                    if generation == stale_generation
            )
        })
        .expect("old exact kick receipt");
    let successor_loaded = events
        .iter()
        .position(|receipt| {
            matches!(
                receipt.event,
                ExecutorPoolEvent::Loaded { generation, .. }
                    if generation == successor_generation
            )
        })
        .expect("successor load receipt");
    let successor_settled = events
        .iter()
        .position(|receipt| {
            matches!(
                receipt.event,
                ExecutorPoolEvent::SettledExited { generation, .. }
                    if generation == successor_generation
            )
        })
        .expect("successor settlement receipt");
    assert!(old_kick < successor_loaded);
    assert!(old_kick < successor_settled);
}

#[test]
fn blocked_task_releases_the_only_worker_immediately() {
    let (kernel, blocked) = bootstrap(14_040);
    let runnable = sibling(&kernel, &blocked, 24_040);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let factory = Arc::new(FakeFactory::default());
    factory.install(&blocked, FakeBinding::new(60, [Step::Block]));
    factory.install(&runnable, FakeBinding::new(70, [Step::Exit]));
    let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
    let blocked_authority = enqueue_root(&scheduler, &blocked, publish(&blocked, 60));
    let runnable_authority = enqueue_root(&scheduler, &runnable, publish(&runnable, 70));
    drop((blocked_authority, runnable_authority));
    pool.shutdown().expect("clean shutdown");
    assert!(matches!(
        blocked.thread().execution_state(),
        ThreadExecutionState::Blocked { .. }
    ));
    assert!(matches!(
        runnable.thread().execution_state(),
        ThreadExecutionState::Exited { .. }
    ));
}

#[test]
fn pool_drives_owned_blocked_continuation_into_kernel_state() {
    use crate::vcpu_loop::continuation::{
        BlockedContinuation, ContinuationBackend, ContinuationCapture, RestartClass,
    };

    let (kernel, blocked) = bootstrap(14_045);
    let runnable = sibling(&kernel, &blocked, 24_045);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let factory = Arc::new(FakeFactory::default());
    let blocked_generation = publish(&blocked, 61);
    let continuation = BlockedContinuation::from_dispatch_outcome(
        DispatchOutcome::WaitOnSleep {
            duration: Duration::from_secs(30),
            remaining: None,
        },
        ContinuationCapture::new(
            &blocked,
            blocked_generation,
            SyscallRequest::new(101, SyscallArgs([0; 6])),
            RestartClass::Never,
            ContinuationBackend::Hvpatch,
        )
        .expect("capture continuation"),
    )
    .expect("owned continuation");
    let continuation_id = continuation.id();
    let blocked_binding = FakeBinding::new(61, [Step::Block]);
    blocked_binding.block_with_continuation(continuation);
    factory.install(&blocked, blocked_binding);
    factory.install(&runnable, FakeBinding::new(71, [Step::Exit]));
    let runnable_generation = publish(&runnable, 71);
    let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
    let blocked_authority = enqueue_root(&scheduler, &blocked, blocked_generation);
    let runnable_authority = enqueue_root(&scheduler, &runnable, runnable_generation);
    drop((blocked_authority, runnable_authority));
    pool.shutdown().expect("clean shutdown");

    assert!(matches!(
        blocked.thread().execution_state(),
        ThreadExecutionState::Blocked {
            continuation: Some(actual),
            ..
        } if actual == continuation_id
    ));
    assert!(
        scheduler
            .binding_for_thread(blocked.thread().key())
            .is_none()
    );
    assert!(matches!(
        runnable.thread().execution_state(),
        ThreadExecutionState::Exited { .. }
    ));
}

#[test]
fn load_save_run_panic_audit_and_invalid_state_fail_exact_task_and_retire_worker() {
    for (case, step) in [
        ("run", Step::FailRun),
        ("panic", Step::PanicRun),
        ("invalid", Step::Invalid),
    ] {
        let (kernel, context) = bootstrap(14_100 + i32::try_from(case.len()).unwrap());
        let scheduler = Arc::new(Scheduler::new(kernel));
        let factory = Arc::new(FakeFactory::default());
        let binding = FakeBinding::new(80, [step]);
        factory.install(&context, binding);
        let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
        let authority = enqueue_root(&scheduler, &context, publish(&context, 80));
        drop(authority);
        let report = pool.shutdown().expect_err("worker failure must surface");
        assert_eq!(report.retired_workers(), 1, "{case}");
        assert_eq!(report.report().created(), 1, "{case}");
        assert_eq!(report.report().destroyed(), 1, "{case}");
        let events = factory.events.lock();
        let create = events
            .iter()
            .find(|event| event.kind == BackendEventKind::Create)
            .expect("failed phase still creates one owner backend");
        let destroy = events
            .iter()
            .find(|event| event.kind == BackendEventKind::Destroy)
            .expect("failed phase destroys the owner backend");
        assert_eq!(create.host_thread, destroy.host_thread, "{case}");
        assert!(matches!(
            context.thread().execution_state(),
            ThreadExecutionState::Failed { .. }
        ));
    }

    for (case, inject) in [("load", 0_u8), ("save", 1_u8), ("audit", 2_u8)] {
        let (kernel, context) = bootstrap(14_200 + i32::from(inject));
        let scheduler = Arc::new(Scheduler::new(kernel));
        let factory = Arc::new(FakeFactory::default());
        let binding = FakeBinding::new(90, [Step::Yield]);
        binding.load_fails.store(inject == 0, Ordering::SeqCst);
        binding.save_fails.store(inject == 1, Ordering::SeqCst);
        binding.audit_fails.store(inject == 2, Ordering::SeqCst);
        factory.install(&context, binding);
        let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
        let authority = enqueue_root(&scheduler, &context, publish(&context, 90));
        drop(authority);
        let report = pool.shutdown().expect_err("worker failure must surface");
        assert_eq!(report.retired_workers(), 1, "{case}");
        assert_eq!(report.report().created(), 1, "{case}");
        assert_eq!(report.report().destroyed(), 1, "{case}");
        let events = factory.events.lock();
        let create = events
            .iter()
            .find(|event| event.kind == BackendEventKind::Create)
            .expect("failed phase still creates one owner backend");
        let destroy = events
            .iter()
            .find(|event| event.kind == BackendEventKind::Destroy)
            .expect("failed phase destroys the owner backend");
        assert_eq!(create.host_thread, destroy.host_thread, "{case}");
        assert!(matches!(
            context.thread().execution_state(),
            ThreadExecutionState::Failed { .. }
        ));
    }
}

#[test]
fn controller_close_failing_audit_worker_retires_across_census_race() {
    let (kernel, context) = bootstrap(14_290);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let factory = Arc::new(FakeFactory::default());
    let binding = FakeBinding::new(90, [Step::Yield]);
    binding.audit_fails.store(true, Ordering::SeqCst);
    factory.install(&context, binding);

    let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);

    // Wait until the worker has parked:
    let deadline = Instant::now() + Duration::from_secs(5);
    while scheduler.waiter_count() != 1 {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for executor to park"
        );
        thread::yield_now();
    }

    let (census_arrived_tx, census_arrived_rx) = std::sync::mpsc::channel();
    let (census_resume_tx, census_resume_rx) = std::sync::mpsc::channel();
    let (unpark_tx, unpark_rx) = std::sync::mpsc::channel();
    scheduler.install_close_census_gate(census_arrived_tx, census_resume_rx);
    scheduler.install_post_unpark_epoch_gate(unpark_tx);

    let authority = scheduler
        .admit_root(context.thread().key(), publish(&context, 90))
        .unwrap();

    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
    let shutdown_thread = thread::spawn(move || {
        shutdown_tx
            .send(pool.shutdown())
            .expect("send shutdown result");
    });

    census_arrived_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("close reached census");

    // Wake the parked executor during census pause:
    authority
        .publish(&scheduler, Arc::clone(context.thread()))
        .unwrap();

    // Wait for the worker to unpark and read the epoch:
    unpark_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("worker unparked and read epoch");

    // Release close census:
    census_resume_tx.send(()).unwrap();

    // Release authority so active_authorities reaches 0 and queue can drain:
    drop(authority);

    let report = shutdown_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("shutdown must return without deadlock")
        .expect_err("worker audit failure must surface");

    shutdown_thread.join().expect("shutdown thread join");

    assert_eq!(report.retired_workers(), 1);
    assert_eq!(report.report().created(), 1);
    assert_eq!(report.report().destroyed(), 1);
    assert!(matches!(
        context.thread().execution_state(),
        ThreadExecutionState::Failed { .. }
    ));

    let summary = scheduler.scheduler_summary();
    assert_eq!(summary.lifecycle, "closed");
    assert_eq!(scheduler.closed_waiter_observations(), 1);
}

#[test]
fn last_worker_failure_fails_queued_exact_generation_and_shutdown_returns() {
    let (kernel, first) = bootstrap(14_240);
    let second = sibling(&kernel, &first, 24_240);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let factory = Arc::new(FakeFactory::default());
    let run_gate = Arc::new(Barrier::new(2));
    let first_binding = FakeBinding::new(91, [Step::FailRun]);
    *first_binding.entered.lock() = Some(Arc::clone(&run_gate));
    factory.install(&first, first_binding);
    factory.install(&second, FakeBinding::new(92, [Step::Exit]));
    let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
    let first_generation = publish(&first, 91);
    let second_generation = publish(&second, 92);
    let first_authority = enqueue_root(&scheduler, &first, first_generation);
    let second_authority = enqueue_root(&scheduler, &second, second_generation);
    run_gate.wait();
    drop((first_authority, second_authority));

    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
    let shutdown = thread::spawn(move || {
        shutdown_tx
            .send(pool.shutdown())
            .expect("publish shutdown result");
    });
    let result = shutdown_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("last-worker failure must not strand queued generations");
    let error = result.expect_err("backend failure remains reported");
    shutdown.join().expect("join shutdown observer");

    assert!(matches!(
        first.thread().execution_state(),
        ThreadExecutionState::Failed { .. }
    ));
    assert!(matches!(
        second.thread().execution_state(),
        ThreadExecutionState::Failed { .. }
    ));
    assert_eq!(error.report().created(), 1);
    assert_eq!(error.report().destroyed(), 1);
    assert_eq!(error.report().joined(), 1);
    let mut retired = factory.retired_bindings.lock().clone();
    retired.sort();
    let mut expected = vec![
        (first.thread().key(), first_generation),
        (second.thread().key(), second_generation),
    ];
    expected.sort();
    assert_eq!(
        retired, expected,
        "queued terminal drain retires both exact rows"
    );
}

#[test]
fn malicious_backend_retained_binding_cannot_receive_authority_or_hold_terminal_drain_open() {
    let (kernel, first) = bootstrap(14_242);
    let second = sibling(&kernel, &first, 24_242);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let factory = Arc::new(MaliciousFactory::default());
    let entered = Arc::new(Barrier::new(2));
    let resume = Arc::new(Barrier::new(2));
    factory.install(&first, Arc::clone(&entered), Arc::clone(&resume));
    factory.install(
        &second,
        Arc::new(Barrier::new(1)),
        Arc::new(Barrier::new(1)),
    );
    let first_generation = publish(&first, 92);
    let second_generation = publish(&second, 93);
    let pool = ExecutorPool::start(
        config(1),
        Arc::clone(&scheduler),
        Arc::clone(&factory),
        factory,
        ExecutorBoundaryAudit::production(),
    )
    .expect("start malicious-binding pool");
    pool.submit_root(Arc::clone(first.thread()), first_generation)
        .expect("pool owns first root authority");
    entered.wait();
    pool.submit_root(Arc::clone(second.thread()), second_generation)
        .expect("pool owns queued second-root authority before failure");
    resume.wait();

    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
    let shutdown = thread::spawn(move || {
        shutdown_tx
            .send(pool.shutdown())
            .expect("publish retained-authority shutdown result");
    });
    let result = shutdown_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("failure cleanup must revoke its exact authority before terminal drain");
    let error = result.expect_err("backend failure remains reported");
    shutdown.join().expect("join retained-authority shutdown");

    assert!(matches!(
        first.thread().execution_state(),
        ThreadExecutionState::Failed { .. }
    ));
    assert!(matches!(
        second.thread().execution_state(),
        ThreadExecutionState::Failed { .. }
    ));
    assert_eq!(error.report().created(), 1);
    assert_eq!(error.report().destroyed(), 1);
    assert_eq!(error.report().joined(), 1);
}

#[test]
fn run_error_and_panic_charge_exact_cpu_receipt_once_before_failure() {
    for (offset, step) in [Step::FailRun, Step::PanicRun].into_iter().enumerate() {
        let (kernel, context) = bootstrap(14_245 + i32::try_from(offset).unwrap());
        let scheduler = Arc::new(Scheduler::new(kernel));
        let factory = Arc::new(FakeFactory::default());
        factory.install(&context, FakeBinding::new(93, [step]));
        let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
        let authority = enqueue_root(&scheduler, &context, publish(&context, 93));
        drop(authority);
        pool.shutdown()
            .expect_err("failed run must retire and report worker");

        assert_eq!(context.thread().cpu_us(), 7);
        assert_eq!(context.thread().system_cpu_us(), 3);
        assert!(matches!(
            context.thread().execution_state(),
            ThreadExecutionState::Failed { .. }
        ));
    }
}

#[test]
fn missing_scoped_lease_return_fails_and_retires_exact_claim() {
    let (kernel, context) = bootstrap(14_247);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let factory = Arc::new(FakeFactory::default());
    factory.install(&context, FakeBinding::new(95, [Step::LoseLease]));
    let generation = publish(&context, 95);
    let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
    let authority = enqueue_root(&scheduler, &context, generation);
    drop(authority);

    pool.shutdown()
        .expect_err("missing scoped lease return must retire worker");
    assert!(matches!(
        context.thread().execution_state(),
        ThreadExecutionState::Failed { .. }
    ));
    assert_eq!(
        factory.retired_bindings.lock().as_slice(),
        &[(context.thread().key(), generation)]
    );
}

#[test]
fn missing_exact_hardware_identity_fails_pool_start_before_any_task_claim() {
    let (kernel, context) = bootstrap(14_248);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let factory = Arc::new(FakeFactory::default());
    factory.fail_hardware_kick.store(true, Ordering::SeqCst);
    factory.install(&context, FakeBinding::new(96, [Step::Exit]));
    publish(&context, 96);
    let error = ExecutorPool::start(
        config(1),
        scheduler,
        Arc::clone(&factory),
        Arc::clone(&factory),
        ExecutorBoundaryAudit::production(),
    );
    assert!(
        error.is_err(),
        "missing hardware must fail before pool publication"
    );
    let events = factory.events.lock();
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind == BackendEventKind::Create)
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind == BackendEventKind::Destroy)
            .count(),
        1
    );
    assert!(
        events.iter().all(|event| event.task.is_none()),
        "startup failure must never claim or load a task"
    );
}

#[test]
fn mismatched_hardware_identity_fails_exact_loaded_claim() {
    let (kernel, context) = bootstrap(14_250);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let factory = Arc::new(FakeFactory::default());
    factory.drift_hardware_on_load.store(true, Ordering::SeqCst);
    factory.install(&context, FakeBinding::new(98, [Step::Exit]));
    let generation = publish(&context, 98);
    let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
    let authority = enqueue_root(&scheduler, &context, generation);
    drop(authority);

    pool.shutdown()
        .expect_err("changed vCPU identity must retire the loaded worker");
    assert!(matches!(
        context.thread().execution_state(),
        ThreadExecutionState::Failed { .. }
    ));
    assert_eq!(
        factory.retired_bindings.lock().as_slice(),
        &[(context.thread().key(), generation)]
    );
}

#[test]
fn invalid_migration_authority_and_invalidation_failure_never_load_or_run_backend() {
    fn reject_case(
        pid: i32,
        continuation: Option<Aarch64SyscallContinuationV1>,
        configure: impl FnOnce(&Arc<Kernel>, &KernelContext, &Arc<FakeBinding>, &Arc<FakeFactory>),
    ) {
        let (kernel, context) = bootstrap(pid);
        let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
        let factory = Arc::new(FakeFactory::default());
        let binding = FakeBinding::new(94, [Step::Exit]);
        factory.install(&context, Arc::clone(&binding));
        configure(&kernel, &context, &binding, &factory);
        let generation = context
            .thread()
            .publish_initial_task_state(task_state_with_continuation(&context, 94, continuation))
            .expect("publish migration test state");
        let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
        let authority = enqueue_root(&scheduler, &context, generation);
        drop(authority);
        let error = pool
            .shutdown()
            .expect_err("invalid migration authority must retire worker");

        assert_eq!(error.retired_workers(), 1);
        assert!(matches!(
            context.thread().execution_state(),
            ThreadExecutionState::Failed { .. }
        ));
        assert!(!factory.events.lock().iter().any(|event| {
            matches!(
                event.kind,
                BackendEventKind::Invalidate | BackendEventKind::Load | BackendEventKind::Run
            )
        }));
        assert!(factory.inherited_state.lock().is_empty());
        assert!(factory.concurrent_loads.lock().is_empty());
    }

    reject_case(14_247, None, |_kernel, _context, binding, _factory| {
        binding.override_expected_abi(carrick_abi::LinuxGuestAbi::X86_64);
    });
    reject_case(14_248, None, |_kernel, _context, binding, _factory| {
        binding.override_expected_version(2);
    });
    reject_case(14_249, None, |kernel, context, binding, _factory| {
        let other = process_child(kernel, context, 24_249, "stale-mm");
        binding.override_expected_mm(other.shared().mm().id());
    });
    reject_case(14_250, None, |_kernel, _context, binding, _factory| {
        binding.override_expected_asid_generation(u64::MAX - 1);
    });
    reject_case(14_251, None, |_kernel, _context, binding, _factory| {
        binding.require_continuation_sequence(7);
    });
    reject_case(
        14_252,
        Some(Aarch64SyscallContinuationV1 {
            sequence: 0,
            state: 0,
            trap_kind: 0,
            response_action: 0,
            flags: 0,
            native_nr: 0,
            args: [0; 6],
            x8: 0,
            resume_pc: 0,
            spsr: 0,
            fp: 0,
            lr: 0,
            sp: 0,
            esr: 0,
            return_value: 0,
            resume_x16: 0,
            resume_x17: 0,
        }),
        |_kernel, _context, binding, _factory| {
            binding.require_continuation_sequence(7);
        },
    );
}

#[test]
fn retirement_command_invalidates_on_exact_resident_owner_worker_only() {
    let (process, context) = crate::hvpatch::process_context_for_tests(14_254);
    let scheduler = Arc::new(Scheduler::new(Arc::clone(context.kernel())));
    let factory = Arc::new(FakeFactory::default());
    let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
    let executor = pool.executor_ids()[0];
    let lease = process.stage1_mm_lease().expect("exact MM lease");
    lease
        .begin_asid_load(executor)
        .expect("load admission")
        .mark_resident()
        .expect("resident executor");
    let retired = process
        .mm_resources()
        .retire(process.task_key())
        .expect("retire process MM");
    let retirement = retired
        .retirement()
        .expect("last MM owner retirement authority");

    pool.invalidate_asid_retirement_timeout(retirement, Duration::from_secs(5))
        .expect("owner-thread invalidation and exact ack");

    assert!(retirement.pending().is_empty());
    let invalidations = factory
        .events
        .lock()
        .iter()
        .filter(|event| event.kind == BackendEventKind::Invalidate)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(invalidations.len(), 1);
    assert_eq!(invalidations[0].executor, executor);
    assert_ne!(invalidations[0].host_thread, thread::current().id());
    retired
        .complete_for_test()
        .expect("release exact ASID/root only after all acks");
    pool.shutdown().expect("pool shutdown");
}

#[test]
fn failed_owner_thread_invalidation_retires_worker_and_quarantines_generation() {
    let (process, context) = crate::hvpatch::process_context_for_tests(14_256);
    let scheduler = Arc::new(Scheduler::new(Arc::clone(context.kernel())));
    let factory = Arc::new(FakeFactory::default());
    let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
    let executor = pool.executor_ids()[0];
    let lease = process.stage1_mm_lease().expect("exact MM lease");
    lease
        .begin_asid_load(executor)
        .expect("load admission")
        .mark_resident()
        .expect("resident executor");
    factory
        .fail_invalidation_generation
        .store(lease.asid_generation().generation(), Ordering::SeqCst);
    let retired = process
        .mm_resources()
        .retire(process.task_key())
        .expect("retire process MM");
    let retirement = retired
        .retirement()
        .expect("last MM owner retirement authority");

    assert!(pool.invalidate_asid_retirement(retirement).is_err());
    assert_eq!(retirement.pending(), vec![executor]);
    assert!(
        retired
            .complete_for_test()
            .unwrap_err()
            .to_string()
            .contains("awaits executor invalidation")
    );
    assert!(pool.shutdown().is_err());
}

#[test]
fn ordinary_task_load_never_performs_an_asid_invalidation() {
    let (kernel, context) = bootstrap(14_255);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let factory = Arc::new(FakeFactory::default());
    factory.install(&context, FakeBinding::new(97, [Step::Exit]));
    let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
    let authority = enqueue_root(&scheduler, &context, publish(&context, 97));
    drop(authority);

    pool.shutdown().expect("pool shutdown");

    assert!(
        !factory
            .events
            .lock()
            .iter()
            .any(|event| event.kind == BackendEventKind::Invalidate)
    );
}

#[test]
fn destroy_error_and_panic_are_terminal_and_reported_after_join() {
    for destroy_mode in [1, 2] {
        let (kernel, context) = bootstrap(14_250 + destroy_mode as i32);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let factory = Arc::new(FakeFactory::default());
        factory.destroy_mode.store(destroy_mode, Ordering::SeqCst);
        factory.install(&context, FakeBinding::new(95, [Step::Exit]));
        let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
        let authority = enqueue_root(&scheduler, &context, publish(&context, 95));
        drop(authority);
        let error = pool
            .shutdown()
            .expect_err("destroy failure must be reported");
        assert_eq!(error.retired_workers(), 1);
        assert_eq!(error.report().created(), 1);
        assert_eq!(error.report().destroyed(), 0);
        assert_eq!(error.report().joined(), 1);
    }
}

#[test]
fn authority_rolls_across_yield_and_preempt_before_normal_descendant_publication() {
    let (kernel, root) = bootstrap(14_290);
    let child = process_child(&kernel, &root, 24_290, "child");
    let scheduler = Arc::new(Scheduler::new(kernel));
    let factory = Arc::new(FakeFactory::default());
    let root_binding = FakeBinding::new(98, [Step::Yield, Step::Preempt, Step::Yield, Step::Exit]);
    let child_binding = FakeBinding::new(99, [Step::Exit]);
    factory.install(&root, Arc::clone(&root_binding));
    factory.install(&child, child_binding);
    let root_generation = publish(&root, 98);
    let child_generation = publish(&child, 99);
    let (published_tx, published_rx) = std::sync::mpsc::channel();
    *root_binding.descendant.lock() = Some(DescendantPublication {
        child_thread: Arc::clone(child.thread()),
        child_generation,
        after_progress: 4,
        published: Some(published_tx),
    });
    let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
    pool.submit_root(Arc::clone(root.thread()), root_generation)
        .expect("pool-owned root publication");
    published_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("descendant publication after three authority rollovers");
    let report = pool.shutdown().expect("normal descendant drain");

    assert!(matches!(
        root.thread().execution_state(),
        ThreadExecutionState::Exited { .. }
    ));
    assert!(matches!(
        child.thread().execution_state(),
        ThreadExecutionState::Exited { .. }
    ));
    assert_eq!(report.created(), 1);
    assert_eq!(report.destroyed(), 1);
    assert_eq!(report.joined(), 1);
}

#[test]
fn shutdown_drains_recursive_child_and_grandchild_before_destroy_and_join() {
    let (kernel, root) = bootstrap(14_300);
    let child = process_child(&kernel, &root, 24_300, "child");
    let grandchild = process_child(&kernel, &child, 34_300, "grandchild");
    let scheduler = Arc::new(Scheduler::new(kernel));
    let factory = Arc::new(FakeFactory::default());
    let root_binding = FakeBinding::new(100, [Step::Yield, Step::Preempt, Step::Yield, Step::Exit]);
    let root_entered = Arc::new(Barrier::new(2));
    let root_resume = Arc::new(Barrier::new(2));
    *root_binding.entered.lock() = Some(Arc::clone(&root_entered));
    *root_binding.resume.lock() = Some(Arc::clone(&root_resume));
    let child_binding = FakeBinding::new(110, [Step::Yield, Step::Preempt, Step::Exit]);
    let grandchild_binding = FakeBinding::new(120, [Step::Exit]);
    factory.install(&root, Arc::clone(&root_binding));
    factory.install(&child, Arc::clone(&child_binding));
    factory.install(&grandchild, Arc::clone(&grandchild_binding));
    let root_generation = publish(&root, 100);
    let child_generation = publish(&child, 110);
    let grandchild_generation = publish(&grandchild, 120);
    *root_binding.descendant.lock() = Some(DescendantPublication {
        child_thread: Arc::clone(child.thread()),
        child_generation,
        after_progress: 4,
        published: None,
    });
    *child_binding.descendant.lock() = Some(DescendantPublication {
        child_thread: Arc::clone(grandchild.thread()),
        child_generation: grandchild_generation,
        after_progress: 3,
        published: None,
    });
    let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
    pool.submit_root(Arc::clone(root.thread()), root_generation)
        .expect("pool retains root authority before publication");
    root_entered.wait();
    let close_started = Arc::new(Barrier::new(2));
    scheduler.install_close_started_gate(Arc::clone(&close_started));
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
    let shutdown = thread::spawn(move || {
        shutdown_tx
            .send(pool.shutdown())
            .expect("publish recursive shutdown result");
    });
    close_started.wait();
    root_resume.wait();
    let report = shutdown_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("recursive Closing drain result")
        .expect("recursive drain");
    shutdown.join().expect("join recursive shutdown");
    assert!(matches!(
        root.thread().execution_state(),
        ThreadExecutionState::Exited { .. }
    ));
    assert!(matches!(
        child.thread().execution_state(),
        ThreadExecutionState::Exited { .. }
    ));
    assert!(matches!(
        grandchild.thread().execution_state(),
        ThreadExecutionState::Exited { .. }
    ));
    assert_eq!(report.created(), report.destroyed());
    assert_eq!(report.destroyed(), report.joined());
    let events = report.events();
    let last_exit = events
        .iter()
        .rposition(|event| matches!(event.event, ExecutorPoolEvent::SettledExited { .. }))
        .unwrap();
    let destroy = events
        .iter()
        .position(|event| matches!(event.event, ExecutorPoolEvent::Destroyed))
        .unwrap();
    assert!(last_exit < destroy);
}

#[test]
fn alternating_tasks_never_inherit_cpu_mailbox_restart_or_tls_state() {
    let (kernel, first) = bootstrap(14_400);
    let second = sibling(&kernel, &first, 24_400);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let factory = Arc::new(FakeFactory::default());
    factory.install(&first, FakeBinding::new(130, [Step::Yield, Step::Exit]));
    factory.install(&second, FakeBinding::new(140, [Step::Yield, Step::Exit]));
    let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
    let first_authority = enqueue_root(&scheduler, &first, publish(&first, 130));
    let second_authority = enqueue_root(&scheduler, &second, publish(&second, 140));
    drop((first_authority, second_authority));
    pool.shutdown().expect("clean alternating shutdown");
    assert!(factory.inherited_state.lock().iter().all(
        |(_, credentials, restart, mailbox, tls)| {
            (*credentials, *restart, *mailbox, *tls) == (0, 0, 0, 0)
        }
    ));
    assert_eq!(first.thread().cpu_us(), 14);
    assert_eq!(first.thread().system_cpu_us(), 6);
    assert_eq!(second.thread().cpu_us(), 14);
    assert_eq!(second.thread().system_cpu_us(), 6);
}

#[test]
fn boundary_inventory_is_typed_exhaustive_and_receipts_are_totally_ordered() {
    let inventory = ExecutorBoundaryAudit::production().inventory();
    for required in [
        "vcpu-owner",
        "topology-depth",
        "hvf-fork-snapshot",
        "signal-progress",
        "active-kernel-context",
        "sysv-mq-fd-cache",
        "logical-mq-wait-state",
        "fanotify-internal-open-depth",
        "path-resolution-depth",
        "host-signal-mask",
        "exact-kick-binding",
        "task-cpu-accounting",
        "task-mailbox-continuation",
    ] {
        assert!(
            inventory.iter().any(|entry| entry.name == required),
            "{required}"
        );
    }
    assert!(
        inventory
            .iter()
            .all(|entry| entry.name != "sysv-mq-wait-cache" && entry.name != "sysv-mq-blocked-ids"),
        "SysV wait-word and blocked-id state belongs to the continuation, not executor TLS"
    );

    let (kernel, context) = bootstrap(14_500);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let factory = Arc::new(FakeFactory::default());
    factory.install(&context, FakeBinding::new(150, [Step::Exit]));
    let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
    let generation = publish(&context, 150);
    let authority = enqueue_root(&scheduler, &context, generation);
    drop(authority);
    let report = pool.shutdown().expect("clean receipt shutdown");
    let sequences: Vec<_> = report.events().iter().map(|event| event.sequence).collect();
    assert!(sequences.windows(2).all(|window| window[0] < window[1]));
    for expected in [
        ExecutorPoolEvent::Created,
        ExecutorPoolEvent::AuditPassed,
        ExecutorPoolEvent::Claimed {
            thread: context.thread().key(),
            generation,
        },
        ExecutorPoolEvent::Loaded {
            thread: context.thread().key(),
            generation,
        },
        ExecutorPoolEvent::Saved {
            thread: context.thread().key(),
            generation,
        },
        ExecutorPoolEvent::Destroyed,
        ExecutorPoolEvent::Joined,
    ] {
        assert!(report.events().iter().any(|event| event.event == expected));
    }
}

#[test]
fn host_signal_mask_boundary_error_names_the_changed_signal() {
    struct RestoreSignalMask(libc::sigset_t);
    impl Drop for RestoreSignalMask {
        fn drop(&mut self) {
            let result =
                unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.0, std::ptr::null_mut()) };
            assert_eq!(result, 0);
        }
    }

    let boundary = WorkerBoundaryAudit::capture().expect("capture host signal mask baseline");
    let mut blocked = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    let mut previous = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    assert_eq!(unsafe { libc::sigemptyset(&mut blocked) }, 0);
    assert_eq!(unsafe { libc::sigaddset(&mut blocked, libc::SIGUSR1) }, 0);
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut previous) },
        0
    );
    let restore = RestoreSignalMask(previous);

    let error = boundary
        .audit_runtime_owned()
        .expect_err("changed host signal mask must fail closed")
        .to_string();
    assert_eq!(
        error,
        format!(
            "hypervisor operation failed: persistent executor boundary audit failed: host-signal-mask: added=[{}], removed=[]",
            libc::SIGUSR1
        )
    );
    drop(restore);
}

#[test]
fn real_owner_boundary_state_fails_or_resets_and_successor_observes_clean_state() {
    let (kernel, context) = bootstrap(14_550);
    let scheduler = Arc::new(Scheduler::new(Arc::clone(&kernel)));
    let receipts = Arc::new(ReceiptLog::default());
    let kick = Arc::new(WorkerKick::new(Arc::clone(&receipts)));
    let registration = scheduler
        .register_executor(Arc::clone(&kick) as Arc<dyn crate::kernel::ExecutorKick>)
        .expect("register audit executor");
    let mut backend = BoundaryAuditProbe;
    let boundary = WorkerBoundaryAudit::capture().expect("capture host signal mask baseline");

    let topology = carrick_thread::fork_quiesce::acquire_topology_lock(
        carrick_observability::probes::HvpatchTopologyOperation::AliasMap,
        1,
        1,
    );
    assert!(boundary.audit_runtime(&mut backend).is_err());
    drop(topology);
    boundary
        .audit_runtime(&mut backend)
        .expect("topology unwound");

    SyscallDispatcher::with_dirty_executor_boundary_path_resolution_for_test(|| {
        assert!(boundary.audit_runtime(&mut backend).is_err());
    });
    boundary
        .audit_runtime(&mut backend)
        .expect("path depth unwound");

    crate::dispatch::resources::with_dirty_captured_resources_for_executor_test(&context, || {
        assert!(boundary.audit_runtime(&mut backend).is_err())
    });
    boundary
        .audit_runtime(&mut backend)
        .expect("active/captured resources unwound");
    crate::dispatch::resources::with_dirty_retiring_resources_for_executor_test(
        context.resources().files(),
        || assert!(boundary.audit_runtime(&mut backend).is_err()),
    );
    boundary
        .audit_runtime(&mut backend)
        .expect("retiring resources unwound");

    let fanotify = crate::fanotify::InternalOpenGuard::enter();
    assert!(boundary.audit_runtime(&mut backend).is_err());
    drop(fanotify);
    boundary
        .audit_runtime(&mut backend)
        .expect("fanotify unwound");

    crate::vcpu_loop::signal::note_signal_progress();
    assert_ne!(crate::vcpu_loop::signal::signal_progress_count(), 0);
    boundary
        .audit_runtime(&mut backend)
        .expect("signal progress is resettable executor state");
    assert_eq!(crate::vcpu_loop::signal::signal_progress_count(), 0);

    struct RestoreSignalMask(libc::sigset_t);
    impl Drop for RestoreSignalMask {
        fn drop(&mut self) {
            let result =
                unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.0, std::ptr::null_mut()) };
            assert_eq!(result, 0);
        }
    }
    let mut blocked = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    let mut previous = unsafe { std::mem::zeroed::<libc::sigset_t>() };
    assert_eq!(unsafe { libc::sigemptyset(&mut blocked) }, 0);
    assert_eq!(unsafe { libc::sigaddset(&mut blocked, libc::SIGUSR1) }, 0);
    assert_eq!(
        unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut previous) },
        0
    );
    let restore = RestoreSignalMask(previous);
    assert!(boundary.audit_runtime(&mut backend).is_err());
    drop(restore);
    boundary
        .audit_runtime(&mut backend)
        .expect("host signal mask restored");

    let (cached_fd, wait_word_fd) =
        SyscallDispatcher::dirty_sysv_executor_boundary_state_for_test();
    boundary
        .audit_runtime(&mut backend)
        .expect("SysV host-fd cache is resettable executor state");
    assert_eq!(unsafe { libc::fcntl(cached_fd, libc::F_GETFD) }, -1);
    assert_eq!(unsafe { libc::fcntl(wait_word_fd, libc::F_GETFD) }, -1);
    assert!(SyscallDispatcher::sysv_executor_boundary_state_is_clear_for_test());
    boundary
        .audit_runtime(&mut backend)
        .expect("SysV reset leaves successor clean");

    let generation = publish(&context, 155);
    let authority = enqueue_root(&scheduler, &context, generation);
    drop(authority);
    let running = scheduler
        .take(&registration)
        .expect("bind exact kick state");
    assert!(boundary.audit_clean(&mut backend, &kick).is_err());
    scheduler
        .settle_exited(running)
        .expect("clear exact kick binding");
    boundary
        .audit_clean(&mut backend, &kick)
        .expect("successor observes no kick identity");

    scheduler
        .unregister_executor(&registration)
        .expect("unregister audit executor");
}

#[test]
fn prohibited_real_owner_state_retires_worker_and_cleanup_leaves_no_inherited_state() {
    for mode in [1, 3, 4, 5, 6] {
        let (kernel, context) = bootstrap(14_560 + mode as i32);
        let scheduler = Arc::new(Scheduler::new(kernel));
        let factory = Arc::new(FakeFactory::default());
        factory.owner_dirty_mode.store(mode, Ordering::SeqCst);
        factory.install(&context, FakeBinding::new(156, [Step::Yield]));
        let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
        let authority = enqueue_root(&scheduler, &context, publish(&context, 156));
        drop(authority);
        let error = pool
            .shutdown()
            .expect_err("dirty real owner state must retire worker");

        assert_eq!(error.retired_workers(), 1, "dirty owner mode {mode}");
        assert!(matches!(
            context.thread().execution_state(),
            ThreadExecutionState::Failed { .. }
        ));
        assert_eq!(error.report().created(), 1);
        assert_eq!(error.report().destroyed(), 1);
        assert_eq!(error.report().joined(), 1);
        for (cached_fd, wait_word_fd) in factory.owner_dirty_fds.lock().iter().copied() {
            assert_eq!(unsafe { libc::fcntl(cached_fd, libc::F_GETFD) }, -1);
            assert_eq!(unsafe { libc::fcntl(wait_word_fd, libc::F_GETFD) }, -1);
        }
    }
}

#[test]
fn save_error_retains_exact_lease_authority_until_failure_settlement() {
    let (kernel, context) = bootstrap(14_600);
    let scheduler = Arc::new(Scheduler::new(kernel));
    let factory = Arc::new(FakeFactory::default());
    let binding = FakeBinding::new(160, [Step::Yield]);
    binding.save_fails.store(true, Ordering::SeqCst);
    factory.install(&context, binding);
    let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
    let authority = enqueue_root(&scheduler, &context, publish(&context, 160));
    drop(authority);
    pool.shutdown().expect_err("save failure retires worker");
    assert!(matches!(
        context.thread().execution_state(),
        ThreadExecutionState::Failed {
            reason: ExecutionFailure::SnapshotSaveFailed,
            ..
        }
    ));
}

#[test]
fn pre_exit_executor_failure_publishes_an_error_instead_of_thread_done() {
    struct MissingTerminalResult {
        settlement: super::super::HvpatchExternalTerminalSettlement,
    }

    impl crate::vcpu_loop::continuation::PersistentQuantumJob for MissingTerminalResult {
        fn poll_quantum_with_engine(
            &mut self,
            _engine: &mut dyn std::any::Any,
            _control: &mut HvpatchQuantumControl<'_, '_>,
        ) -> ExecutorExit {
            unreachable!("executor failure settles this job without another poll")
        }

        fn after_terminal_settlement(&mut self) {
            self.settlement.publish_terminal(None);
        }
    }

    let (kernel, context) = bootstrap(14_601);
    let generation = publish(&context, 161);
    let scheduler = Scheduler::new(kernel);
    let executor = scheduler
        .register_executor(Arc::new(WorkerKick::new(Arc::new(ReceiptLog::default()))))
        .expect("register failure-settlement executor");
    scheduler
        .make_runnable(context.thread().key())
        .expect("queue failure-settlement job");
    let running = scheduler.take(&executor).expect("claim failing job");

    let result = super::super::HvpatchLoopResult::pending();
    let completion = crate::vcpu_loop::continuation::LogicalJobCompletion::pending();
    let settlement =
        super::super::HvpatchExternalTerminalSettlement::new(result.clone(), completion.clone());
    let binding = Arc::new(crate::vcpu_loop::continuation::HvpatchTaskBinding::new(
        TaskLoadIdentity {
            abi: carrick_abi::LinuxGuestAbi::Aarch64,
            version: 1,
            mm: context.shared().mm().id(),
            asid_generation: context.shared().mm().id().raw(),
        },
        Arc::new(crate::vcpu_loop::continuation::HvpatchTaskQuantum::new(
            Box::new(MissingTerminalResult {
                settlement: settlement.clone(),
            }),
            completion.clone(),
        )),
        Box::new(161_u64),
    ));
    let directory = HvpatchTaskBindingDirectory::default();
    directory
        .publish(context.thread().key(), generation, binding)
        .expect("publish exact failure-settlement binding");

    assert!(
        super::fail_running_and_retire::<crate::vcpu_loop::continuation::HvpatchTaskBinding, _>(
            &directory,
            &scheduler,
            running,
            ExecutionFailure::SnapshotRestoreFailed,
            &ReceiptLog::default(),
        )
        .is_none(),
        "exact failure settlement itself must succeed",
    );
    assert!(completion.is_finished());
    assert!(matches!(
        result.wait(),
        Err(crate::runtime::RuntimeError::CarrierFailed(_))
    ));

    scheduler
        .unregister_executor(&executor)
        .expect("unregister failure-settlement executor");
    scheduler.close();
    scheduler.wait_closed();
}

struct VforkTestFixture {
    kernel: Arc<Kernel>,
    parent: KernelContext,
    child: KernelContext,
    parent_generation: ExecutionGeneration,
    child_generation: ExecutionGeneration,
    wait: crate::kernel::VforkParentWait,
    scheduler: Arc<Scheduler>,
    factory: Arc<FakeFactory>,
    parent_binding: Arc<FakeBinding>,
    parent_authority: Option<SubmissionAuthority>,
    directory: Arc<HvpatchTaskBindingDirectory>,
    dormant: Option<super::PreparedHvpatchSubmission>,
    child_proof: HvpatchActivationProof,
    child_threads: crate::vcpu_loop::VcpuThreadRegistry,
    terminal_settlement: super::super::HvpatchExternalTerminalSettlement,
    runtime_directory: Arc<super::super::HvpatchRuntimeDirectory>,
    job_result: super::super::HvpatchLoopResult,
    job_completion: crate::vcpu_loop::continuation::LogicalJobCompletion,
}

impl VforkTestFixture {
    fn new(parent_tid: i32, child_tid: i32) -> Self {
        let (kernel, parent) = bootstrap(parent_tid);
        let plan = ClonePlan::from_flags(LinuxCloneFlags::VFORK | LinuxCloneFlags::VM).unwrap();
        let published = kernel
            .reserve_fork(&parent, plan, "vfork-fixture".to_owned(), None)
            .unwrap()
            .prepare_reference(ThreadId::synthetic_for_tests(child_tid))
            .unwrap()
            .commit()
            .unwrap();
        let child_ref = published.context().unwrap().retain_exact();
        let child_state = task_state(&child_ref, 20);
        let child_generation = child_ref
            .thread()
            .publish_initial_task_state(child_state.clone())
            .unwrap();
        let job_result = crate::vcpu_loop::HvpatchLoopResult::pending();
        let job_completion = crate::vcpu_loop::continuation::LogicalJobCompletion::pending();
        let hvpatch_child_binding = hvpatch_test_binding_with_completion(
            &child_ref,
            &child_state,
            20,
            job_completion.clone(),
        );

        let scheduler = Arc::new(Scheduler::new(kernel.clone()));
        let factory = Arc::new(FakeFactory::default());
        let parent_binding = FakeBinding::new(10, [Step::Block, Step::Exit]);
        let fake_child_binding = FakeBinding::new(20, [Step::Exit]);
        factory.install(&parent, Arc::clone(&parent_binding));
        factory.install(&child_ref, Arc::clone(&fake_child_binding));
        let parent_generation = publish(&parent, 10);
        let parent_authority = scheduler
            .admit_root(parent.thread().key(), parent_generation)
            .expect("admit root");

        let directory = Arc::new(HvpatchTaskBindingDirectory::default());
        factory.install_directory(Arc::clone(&directory));
        let dormant = directory
            .prepare_submission(
                &scheduler,
                HvpatchSubmissionShape::Descendant {
                    grant: (parent.thread().key(), parent_generation),
                },
                Some(&parent_authority),
                Arc::clone(child_ref.thread()),
                child_generation,
                Arc::clone(&hvpatch_child_binding),
            )
            .unwrap();

        let (child_context, wait) = published.into_parts().unwrap();
        let wait = wait.unwrap();
        let child = child_context;
        let start_gate = child
            .thread()
            .take_opened_start_gate(child_generation)
            .unwrap();
        let child_proof = HvpatchActivationProof::validate(
            &child,
            &child_state,
            child_generation,
            hvpatch_child_binding.identity(),
            start_gate,
        )
        .unwrap();

        let child_threads = crate::vcpu_loop::VcpuThreadRegistry::new();
        let terminal_settlement = super::super::HvpatchExternalTerminalSettlement::new(
            job_result.clone(),
            job_completion.clone(),
        );
        let runtime_directory = Arc::new(super::super::HvpatchRuntimeDirectory::default());

        Self {
            kernel,
            parent,
            child,
            parent_generation,
            child_generation,
            wait,
            scheduler,
            factory,
            parent_binding,
            parent_authority: Some(parent_authority),
            directory,
            dormant: Some(dormant),
            child_proof,
            child_threads,
            terminal_settlement,
            runtime_directory,
            job_result,
            job_completion,
        }
    }

    fn make_activation(
        &mut self,
        proof: Option<HvpatchActivationProof>,
    ) -> super::PreparedVforkChildActivation {
        let member_pub = super::super::PersistentProcessMemberPublication::new(
            self.child_threads.clone(),
            &self.terminal_settlement,
        );
        let dormant = self.dormant.take().expect("dormant submission");
        let job_reservation = self
            .runtime_directory
            .container_job_group(self.child.container().id())
            .reserve()
            .expect("reserve vfork child job");
        super::PreparedVforkChildActivation::new(
            dormant,
            Arc::clone(&self.scheduler),
            Arc::clone(self.child.thread()),
            proof.unwrap_or(self.child_proof),
            member_pub,
            job_reservation,
            self.job_result.clone(),
            self.job_completion.clone(),
            {
                let retirement = super::super::ProcessPhysicalRetirement::default();
                retirement
                    .publish(vec![self.job_completion.clone()])
                    .expect("publish fixture process retirement");
                retirement
            },
        )
    }

    fn make_continuation(&self) -> crate::vcpu_loop::continuation::BlockedContinuation {
        let parent_capture = crate::vcpu_loop::continuation::ContinuationCapture::new(
            &self.parent,
            self.parent_generation,
            SyscallRequest::new(220, SyscallArgs([0; 6])),
            crate::vcpu_loop::continuation::RestartClass::Never,
            crate::vcpu_loop::continuation::ContinuationBackend::Hvpatch,
        )
        .unwrap();
        crate::vcpu_loop::continuation::BlockedContinuation::from_vfork_parent(
            parent_capture,
            self.child.task().key(),
            self.wait.clone(),
        )
        .unwrap()
    }
}

#[test]
fn dropped_vfork_activation_releases_unpublished_job_reservation() {
    let mut fixture = VforkTestFixture::new(14_500, 24_500);
    let activation = fixture.make_activation(None);
    assert_eq!(fixture.runtime_directory.live_job_group_count(), 1);
    assert_eq!(fixture.runtime_directory.live_process_job_count(), 0);

    drop(activation);

    assert_eq!(fixture.runtime_directory.live_job_group_count(), 0);
    assert_eq!(fixture.runtime_directory.live_process_job_count(), 0);
    assert!(fixture.child_threads.is_empty());
}

#[test]
fn vfork_deferred_child_activation_runs_after_parent_backend_saved() {
    let mut fixture = VforkTestFixture::new(14_501, 24_501);
    let continuation = fixture.make_continuation();
    let activation = fixture.make_activation(None);

    let parent_key = fixture.parent.thread().key();
    let factory_events = Arc::clone(&fixture.factory.events);
    let save_observed_at_activation = Arc::new(AtomicBool::new(false));
    let observed_flag = Arc::clone(&save_observed_at_activation);
    let kernel = Arc::clone(&fixture.kernel);
    let child = fixture.child.retain_exact();
    let (terminal_tx, terminal_rx) = std::sync::mpsc::channel();
    fixture
        .parent_binding
        .notify_on_terminal_settlement(terminal_tx);

    let _guard = super::PreparedVforkChildActivation::set_test_hook(move || {
        let events = factory_events.lock().clone();
        let parent_saved = events.iter().any(|e| {
            e.kind == BackendEventKind::Save && e.task.is_some_and(|(k, _)| k == parent_key)
        });
        observed_flag.store(parent_saved, Ordering::SeqCst);
        kernel
            .exit_task(
                child.task().key().id,
                crate::kernel::LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .unwrap();
    });

    fixture
        .parent_binding
        .block_with_vfork_continuation(continuation, activation);

    let pool = start_pool(
        Arc::clone(&fixture.scheduler),
        Arc::clone(&fixture.factory),
        1,
    );
    let parent_auth = fixture.parent_authority.take().unwrap();
    parent_auth
        .publish(&fixture.scheduler, Arc::clone(fixture.parent.thread()))
        .unwrap();
    drop(parent_auth);

    terminal_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("parent terminal settlement after vfork release");

    pool.shutdown().expect("clean pool shutdown");

    assert_eq!(fixture.runtime_directory.live_job_group_count(), 1);
    assert_eq!(fixture.runtime_directory.live_process_job_count(), 1);
    if !fixture.job_result.is_ready() {
        fixture
            .job_result
            .publish(Ok(super::super::VcpuLoopOutcome::ThreadDone));
        fixture.job_completion.publish();
    }
    assert_eq!(
        fixture
            .runtime_directory
            .container_job_group(fixture.child.container().id())
            .join()
            .expect("join activated vfork child"),
        1
    );
    assert_eq!(fixture.runtime_directory.live_job_group_count(), 0);

    assert!(
        save_observed_at_activation.load(Ordering::SeqCst),
        "Parent backend must be saved before child activation runs"
    );
}

#[test]
fn vfork_continuation_enrollment_failure_releases_job_reservation() {
    let mut fixture = VforkTestFixture::new(14_505, 24_505);
    let continuation = fixture.make_continuation();
    let activation = fixture.make_activation(None);
    fixture
        .parent_binding
        .block_with_vfork_continuation(continuation, activation);

    let pool = start_pool(
        Arc::clone(&fixture.scheduler),
        Arc::clone(&fixture.factory),
        1,
    );
    pool.control.wait_service.fail_next_enroll_for_test();
    let parent_auth = fixture.parent_authority.take().unwrap();
    parent_auth
        .publish(&fixture.scheduler, Arc::clone(fixture.parent.thread()))
        .unwrap();
    drop(parent_auth);

    let _ = pool.shutdown();

    assert_eq!(fixture.runtime_directory.live_job_group_count(), 0);
    assert_eq!(fixture.runtime_directory.live_process_job_count(), 0);
    assert!(fixture.child_threads.is_empty());
}

#[test]
fn vfork_release_during_child_activation_preserves_wake_edge_through_parent_settlement() {
    let mut fixture = VforkTestFixture::new(14_502, 24_502);
    let continuation = fixture.make_continuation();
    let activation = fixture.make_activation(None);

    let kernel = Arc::clone(&fixture.kernel);
    let child = fixture.child.retain_exact();
    let (terminal_tx, terminal_rx) = std::sync::mpsc::channel();
    fixture
        .parent_binding
        .notify_on_terminal_settlement(terminal_tx);

    // Release vfork during activation (after dormant.activate succeeds, before parent blocked settlement)
    let _guard = super::PreparedVforkChildActivation::set_test_hook(move || {
        kernel
            .exit_task(
                child.task().key().id,
                crate::kernel::LinuxWaitStatus::from_wait_encoding(0),
                None,
            )
            .unwrap();
    });

    fixture
        .parent_binding
        .block_with_vfork_continuation(continuation, activation);

    let pool = start_pool(
        Arc::clone(&fixture.scheduler),
        Arc::clone(&fixture.factory),
        1,
    );
    let parent_auth = fixture.parent_authority.take().unwrap();
    parent_auth
        .publish(&fixture.scheduler, Arc::clone(fixture.parent.thread()))
        .unwrap();
    drop(parent_auth);

    terminal_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("released vfork parent terminal settlement");

    let report = pool
        .shutdown()
        .expect("clean pool shutdown when release edge preserved");
    let _ = report;

    assert!(matches!(
        fixture.parent.thread().execution_state(),
        ThreadExecutionState::Exited { .. }
    ));
}

#[test]
fn vfork_child_activation_failure_rolls_back_and_fails_parent_claim() {
    let mut fixture = VforkTestFixture::new(14_503, 24_503);
    let continuation = fixture.make_continuation();

    // Invalid proof with mismatched thread
    let invalid_proof = HvpatchActivationProof {
        thread: fixture.parent.thread().key(),
        generation: fixture.child_generation,
        identity: TaskLoadIdentity {
            abi: carrick_abi::LinuxGuestAbi::Aarch64,
            version: 1,
            mm: fixture.child.shared().mm().id(),
            asid_generation: fixture.child.shared().mm().id().raw(),
        },
    };
    let activation = fixture.make_activation(Some(invalid_proof));

    fixture
        .parent_binding
        .block_with_vfork_continuation(continuation, activation);

    let pool = start_pool(
        Arc::clone(&fixture.scheduler),
        Arc::clone(&fixture.factory),
        1,
    );
    let parent_auth = fixture.parent_authority.take().unwrap();
    parent_auth
        .publish(&fixture.scheduler, Arc::clone(fixture.parent.thread()))
        .unwrap();
    drop(parent_auth);

    let _ = pool.shutdown();

    // Child dormant submission rolled back (not present in directory)
    assert!(
        <HvpatchTaskBindingDirectory as TaskBindingResolver<_>>::resolve(
            fixture.directory.as_ref(),
            fixture.child.thread().key(),
            fixture.child_generation,
        )
        .is_err()
    );
    // Child member publication rolled back
    assert!(fixture.child_threads.is_empty());
    assert!(matches!(
        fixture.child.thread().execution_state(),
        ThreadExecutionState::Failed { .. }
    ));
    // Parent is in exact Failed state, not stranded in Blocked
    assert!(matches!(
        fixture.parent.thread().execution_state(),
        ThreadExecutionState::Failed {
            reason: ExecutionFailure::SnapshotRestoreFailed,
            ..
        }
    ));
}

#[test]
fn vfork_child_activation_failpoint_rolls_back_and_fails_parent_claim() {
    let mut fixture = VforkTestFixture::new(14_504, 24_504);
    let continuation = fixture.make_continuation();
    let activation = fixture.make_activation(None);

    super::super::install_hvpatch_process_failpoint(
        super::super::HvpatchProcessFailpoint::Activation,
    );

    fixture
        .parent_binding
        .block_with_vfork_continuation(continuation, activation);

    let pool = start_pool(
        Arc::clone(&fixture.scheduler),
        Arc::clone(&fixture.factory),
        1,
    );
    let parent_auth = fixture.parent_authority.take().unwrap();
    parent_auth
        .publish(&fixture.scheduler, Arc::clone(fixture.parent.thread()))
        .unwrap();
    drop(parent_auth);

    let _ = pool.shutdown();

    assert!(
        <HvpatchTaskBindingDirectory as TaskBindingResolver<_>>::resolve(
            fixture.directory.as_ref(),
            fixture.child.thread().key(),
            fixture.child_generation,
        )
        .is_err()
    );
    assert!(fixture.child_threads.is_empty());
    assert!(matches!(
        fixture.child.thread().execution_state(),
        ThreadExecutionState::Failed { .. }
    ));
    assert!(matches!(
        fixture.parent.thread().execution_state(),
        ThreadExecutionState::Failed {
            reason: ExecutionFailure::SnapshotRestoreFailed,
            ..
        }
    ));
}

struct TerminalRetirementTestCleanup {
    resume_tx: Option<std::sync::mpsc::Sender<()>>,
    pool: Option<ExecutorPool<FakeFactory, FakeFactory>>,
}

impl Drop for TerminalRetirementTestCleanup {
    fn drop(&mut self) {
        if let Some(resume) = self.resume_tx.take() {
            let _ = resume.send(());
        }
        if let Some(pool) = self.pool.take() {
            let _ = pool.shutdown();
        }
    }
}

#[test]
fn terminal_retirement_does_not_hold_topology_lock_across_detached_cleanup() {
    let (process, context) = crate::hvpatch::process_context_for_tests(14_990);
    let scheduler = Arc::new(Scheduler::new(Arc::clone(context.kernel())));
    let factory = Arc::new(FakeFactory::default());
    let binding = FakeBinding::new(99, [Step::Exit]);
    let (gate_tx, gate_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    *binding.retire_detached_address_space_gate.lock() = Some(gate_tx);
    *binding.retire_detached_address_space_resume.lock() = Some(resume_rx);
    let tid = ThreadId::from_guest_supplied_tid(context.thread().key().tid.raw());
    let pending = process
        .begin_address_space_retirement(0, tid, None)
        .expect("pending retirement");
    *binding.pending_address_space_retirement.lock() = Some(pending);
    factory.install(&context, Arc::clone(&binding));

    let pool = start_pool(Arc::clone(&scheduler), Arc::clone(&factory), 1);
    let mut cleanup = TerminalRetirementTestCleanup {
        resume_tx: Some(resume_tx),
        pool: Some(pool),
    };
    let generation = publish(&context, 99);
    let authority = enqueue_root(&scheduler, &context, generation);
    drop(authority);

    gate_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("worker must reach detached cleanup gate");

    // While detached terminal cleanup is running, the executor does NOT hold
    // the carrier topology lock. Concurrent attempts to acquire topology
    // locks for fork or COW must succeed.
    let try_fork = carrick_thread::fork_quiesce::try_acquire_topology_lock(
        carrick_observability::probes::HvpatchTopologyOperation::InProcessFork,
        process.pid(),
        context.thread().key().tid.raw(),
    );
    assert!(
        try_fork.is_some(),
        "while detached terminal cleanup is running, InProcessFork must succeed because carrier topology lock is not held"
    );
    drop(try_fork);

    let try_cow = carrick_thread::fork_quiesce::try_acquire_topology_lock(
        carrick_observability::probes::HvpatchTopologyOperation::FrameCow,
        process.pid(),
        context.thread().key().tid.raw(),
    );
    assert!(
        try_cow.is_some(),
        "while detached terminal cleanup is running, FrameCow must succeed because carrier topology lock is not held"
    );
    drop(try_cow);

    // Release the worker and shut down the pool before asserting
    if let Some(resume) = cleanup.resume_tx.take() {
        let _ = resume.send(());
    }
    let pool = cleanup.pool.take().expect("pool");
    pool.wait_for_event(
        |event| matches!(event, ExecutorPoolEvent::SettledExited { .. }),
        Duration::from_secs(5),
    )
    .expect("worker settlement event observed");
    pool.shutdown().expect("pool shutdown");

    assert!(matches!(
        context.thread().execution_state(),
        ThreadExecutionState::Exited { .. }
    ));
}
