//! Process-owned runtime state reserved before either lane publishes a thread.

use carrick_hal::threaded::GuestCpuState;
use std::fmt;
use std::sync::{Arc, Weak};

use carrick_kernel::kernel::thread_adoption::{
    ThreadBirthAdoptionFactory, ThreadBirthAdoptionReservation,
};
use carrick_kernel::kernel::{KernelContext, TaskKey, ThreadKey};

use super::binding::InjectedExecutionLeaseSlot;
use super::*;

/// Resolves Send service tokens only under their exact process/MM authority.
struct OwnedProcessBirthTemplate<T> {
    owner: TaskKey,
    mm: carrick_kernel::kernel::MmId,
    graph: Weak<carrick_kernel::kernel::Kernel>,
    resource: parking_lot::Mutex<T>,
}
impl<T> OwnedProcessBirthTemplate<T> {
    fn new(context: &KernelContext, resource: T) -> Self {
        Self {
            owner: context.task().key(),
            mm: context.shared().mm().id(),
            graph: Arc::downgrade(context.kernel()),
            resource: parking_lot::Mutex::new(resource),
        }
    }
    fn with_authority<R>(
        &self,
        owner: TaskKey,
        mm: carrick_kernel::kernel::MmId,
        graph: &Arc<carrick_kernel::kernel::Kernel>,
        resolve: impl FnOnce(&mut T) -> R,
    ) -> Option<R> {
        if owner != self.owner
            || mm != self.mm
            || !Weak::ptr_eq(&self.graph, &Arc::downgrade(graph))
        {
            return None;
        }
        Some(resolve(&mut self.resource.lock()))
    }

    #[cfg(test)]
    fn with_owner<R>(
        &self,
        context: &KernelContext,
        resolve: impl FnOnce(&mut T) -> R,
    ) -> Option<R> {
        self.with_authority(
            context.task().key(),
            context.shared().mm().id(),
            context.kernel(),
            resolve,
        )
    }
}

/// EL0 state comes from the born record; MM/system state belongs to its process.
#[derive(Clone)]
struct ProcessThreadCpuTemplate {
    owner: TaskKey,
    graph: Weak<carrick_kernel::kernel::Kernel>,
    cpu: carrick_kernel::kernel::objects::MigratableTaskState,
}

impl ProcessThreadCpuTemplate {
    fn capture(
        context: &KernelContext,
        cpu: carrick_kernel::kernel::objects::MigratableTaskState,
    ) -> Result<Self, TrapError> {
        if cpu.mm != context.shared().mm().id() {
            return Err(TrapError::Hypervisor(
                "birth CPU template has a foreign MM".into(),
            ));
        }
        Ok(Self {
            owner: context.task().key(),
            graph: Arc::downgrade(context.kernel()),
            cpu,
        })
    }

    fn reserve(&self) -> ProcessThreadCpuReservation {
        let mut cpu = self.cpu.clone();
        if let GuestCpuState::Aarch64V1(registers) = &mut cpu.cpu {
            *registers = Arc::new((**registers).clone());
        }
        ProcessThreadCpuReservation {
            owner: self.owner,
            graph: self.graph.clone(),
            cpu,
        }
    }
}

struct ProcessThreadCpuReservation {
    owner: TaskKey,
    graph: Weak<carrick_kernel::kernel::Kernel>,
    cpu: carrick_kernel::kernel::objects::MigratableTaskState,
}

impl ProcessThreadCpuReservation {
    fn for_born(
        mut self,
        context: &KernelContext,
        frame: &carrick_el1_abi::ThreadCtx,
    ) -> Result<carrick_kernel::kernel::objects::MigratableTaskState, TrapError> {
        if context.task().key() != self.owner
            || !Weak::ptr_eq(&self.graph, &Arc::downgrade(context.kernel()))
            || context.shared().mm().id() != self.cpu.mm
        {
            return Err(TrapError::Hypervisor(
                "birth CPU template rejected a foreign process".into(),
            ));
        }
        let GuestCpuState::Aarch64V1(registers) = &mut self.cpu.cpu else {
            return Err(TrapError::Hypervisor(
                "birth CPU template has another architecture".into(),
            ));
        };
        let registers = Arc::get_mut(registers).ok_or_else(|| {
            TrapError::Hypervisor("birth CPU reservation lost exclusive custody".into())
        })?;
        registers.gprs = frame.x;
        registers.pc = frame.pc;
        registers.pstate = frame.pstate;
        registers.trap_pc = frame.pc;
        registers.trap_pstate = frame.pstate;
        registers.elr_el1 = frame.pc;
        registers.spsr_el1 = frame.pstate;
        registers.sp_el0 = frame.sp_el0;
        registers.tpidr_el0 = frame.tpidr_el0;
        registers.tpidrro_el0 = frame.tpidrro_el0;
        registers.contextidr_el1 = frame.contextidr_el1;
        registers.vregs = frame.v;
        registers.fpsr = frame.fpsr as u32;
        registers.fpcr = frame.fpcr as u32;
        registers.last_fault_esr = 0;
        registers.last_exit_class = 0;
        registers.last_syscall_orig_x0 = 0;
        registers.is_forked_child = false;
        registers.last_syscall_nr = None;
        registers.syscall_continuation = None;
        registers.pending_resume_pc = None;
        Ok(self.cpu)
    }
}

pub(super) enum ThreadAdoptionOrigin {
    HostClone(PreparedSyscall),
    AbiBorn,
}

/// Shared process resources, not a running job, backend or executor lease.
pub(super) struct ProcessThreadAdoptionFactory<E: ThreadedEngine> {
    owner: TaskKey,
    cpu_template: Option<ProcessThreadCpuTemplate>,
    backend_template: Option<
        Arc<
            OwnedProcessBirthTemplate<
                carrick_vmm_hvf::hvf_aarch64_engine::HvpatchThreadBirthTemplate,
            >,
        >,
    >,
    kernel: Weak<KernelState>,
    task: Weak<carrick_kernel::kernel::objects::Task>,
    registry: Arc<ThreadRegistry>,
    futex: Arc<FutexTable>,
    platform_futex: Arc<dyn PlatformFutex>,
    platform_futex_factory: PlatformFutexFactory,
    threads: VcpuThreadRegistry,
    kicker: Arc<dyn VcpuRegistry>,
    max_traps: usize,
    engine: std::marker::PhantomData<fn() -> E>,
}

impl<E: ThreadedEngine> fmt::Debug for ProcessThreadAdoptionFactory<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessThreadAdoptionFactory")
            .field("owner", &self.owner)
            .finish_non_exhaustive()
    }
}

struct ReservedThreadRuntime<E: ThreadedEngine> {
    kernel: Kernel,
    state: Vec<ThreadRuntimeState<E>>,
    injected_lease: Arc<InjectedExecutionLeaseSlot>,
    origin: ThreadAdoptionOrigin,
    cpu: Option<ProcessThreadCpuReservation>,
    backend: Option<carrick_vmm_hvf::hvf_aarch64_engine::HvpatchTaskOnlyEngineState>,
    cow: Option<(Arc<memory::KernelFrameCowAuthority>, std::num::NonZeroU64)>,
    submission: carrick_kernel::kernel::scheduler::ProcessBirthSubmission,
}

pub(super) struct AdoptedThreadRuntime<E: ThreadedEngine> {
    pub(super) kernel: Kernel,
    pub(super) cpu: Option<carrick_kernel::kernel::objects::MigratableTaskState>,
    pub(super) backend: Option<carrick_vmm_hvf::hvf_aarch64_engine::HvpatchTaskOnlyEngineState>,
    pub(super) cow: Option<(Arc<memory::KernelFrameCowAuthority>, std::num::NonZeroU64)>,
    pub(super) state: ThreadRuntimeState<E>,
    pub(super) injected_lease: Arc<InjectedExecutionLeaseSlot>,
    pub(super) submission: carrick_kernel::kernel::scheduler::ProcessBirthSubmission,
}

impl<E: ThreadedEngine + 'static> ProcessThreadAdoptionFactory<E>
where
    E::SiblingSpec: 'static,
{
    pub(super) fn with_cpu_template(
        mut self,
        context: &KernelContext,
        cpu: carrick_kernel::kernel::objects::MigratableTaskState,
    ) -> Result<Self, TrapError> {
        let kernel = self
            .kernel
            .upgrade()
            .ok_or_else(|| TrapError::Hypervisor("birth CPU factory lost its owner".into()))?;
        if context.task().key() != self.owner
            || !Arc::ptr_eq(
                context.kernel(),
                kernel
                    .hvpatch_process
                    .as_ref()
                    .ok_or_else(|| {
                        TrapError::Hypervisor("birth CPU factory lost its process".into())
                    })?
                    .kernel_graph(),
            )
        {
            return Err(TrapError::Hypervisor(
                "birth factory rejected a foreign CPU owner".into(),
            ));
        }
        self.cpu_template = Some(ProcessThreadCpuTemplate::capture(context, cpu)?);
        Ok(self)
    }

    pub(super) fn with_backend_template(
        mut self,
        context: &KernelContext,
        template: Option<carrick_vmm_hvf::hvf_aarch64_engine::HvpatchThreadBirthTemplate>,
    ) -> Self {
        self.backend_template =
            template.map(|template| Arc::new(OwnedProcessBirthTemplate::new(context, template)));
        self
    }

    pub(super) fn capture(kernel: &Kernel, state: &ThreadRuntimeState<E>) -> Option<Self> {
        Some(Self {
            owner: kernel.hvpatch_process.as_ref()?.task_key(),
            cpu_template: None,
            backend_template: None,
            kernel: Arc::downgrade(kernel),
            task: Arc::downgrade(&state.kernel_thread.as_ref()?.task()?),
            registry: state.registry.clone(),
            futex: state.futex.clone(),
            platform_futex: state.platform_futex.clone(),
            platform_futex_factory: state.platform_futex_factory.clone(),
            threads: state.threads.clone(),
            kicker: state.kicker.clone(),
            max_traps: state.max_traps,
            engine: std::marker::PhantomData,
        })
    }
}

impl<E: ThreadedEngine + 'static> ThreadBirthAdoptionFactory for ProcessThreadAdoptionFactory<E>
where
    E::SiblingSpec: 'static,
{
    fn executable_births(&self) -> bool {
        self.backend_template.is_some() && self.cpu_template.is_some()
    }
    fn adopt_first_host_entry(
        &self,
        context: &KernelContext,
        reservation: ThreadBirthAdoptionReservation,
        frame: &carrick_el1_abi::ThreadCtx,
    ) -> Result<(), String> {
        activate_born_thread::<E>(context, reservation, frame).map_err(|error| error.to_string())
    }

    fn owner(&self) -> TaskKey {
        self.owner
    }

    fn reserve(&self, thread: ThreadKey) -> Option<ThreadBirthAdoptionReservation> {
        self.reserve_with_origin(thread, ThreadAdoptionOrigin::AbiBorn)
    }
}

impl<E: ThreadedEngine + 'static> ProcessThreadAdoptionFactory<E>
where
    E::SiblingSpec: 'static,
{
    fn reserve_with_origin(
        &self,
        thread: ThreadKey,
        origin: ThreadAdoptionOrigin,
    ) -> Option<ThreadBirthAdoptionReservation> {
        let kernel = self.kernel.upgrade()?;
        let process = kernel.hvpatch_process.as_ref()?;
        if process.task_key() != self.owner || kernel.process_exiting() {
            return None;
        }
        let task = self.task.upgrade()?;
        if task.key() != self.owner {
            return None;
        }
        if self.cpu_template.as_ref().is_some_and(|template| {
            template.cpu.mm != task.shared().mm().id()
                || template.cpu.asid_generation != process.asid_generation()
        }) {
            return None;
        }
        let scheduler = kernel
            .hvpatch_runtime
            .as_ref()?
            .continuation_services(process.kernel_graph())
            .0;
        let submission = scheduler.reserve_process_birth(&task, thread).ok()?;
        let backend = match &self.backend_template {
            Some(template) => Some(template.with_authority(
                task.key(),
                task.shared().mm().id(),
                process.kernel_graph(),
                |template| {
                    let GuestCpuState::Aarch64V1(cpu) = &self.cpu_template.as_ref()?.cpu.cpu else {
                        return None;
                    };
                    let identity =
                        carrick_vmm_hvf::hvf_aarch64_engine::HvpatchCarrierTaskIdentity {
                            task_serial: self.owner.serial.raw(),
                            thread_serial: thread.serial.raw(),
                            execution_generation:
                                carrick_kernel::kernel::objects::ExecutionGeneration::INITIAL.raw(),
                            linux_pid: process.pid(),
                            linux_tid: thread.tid.raw(),
                            asid: (cpu.ttbr0 >> 48) as u16,
                        };
                    template
                        .reserve(
                            identity,
                            kernel
                                .hvpatch_runtime
                                .as_ref()?
                                .carrier_tasks(process.kernel_graph()),
                        )
                        .ok()
                },
            )??),
            None => None,
        };
        let cow = match &backend {
            Some(backend) => {
                let GuestCpuState::Aarch64V1(cpu) = &self.cpu_template.as_ref()?.cpu.cpu else {
                    return None;
                };
                let mm = task.shared().mm().id();
                Some((
                    Arc::new(memory::KernelFrameCowAuthority {
                        runtime: Arc::downgrade(&kernel),
                        deferred_anonymous: kernel.dispatcher.deferred_anonymous_state(mm),
                        kernel: process.kernel_graph().clone(),
                        mm,
                        owner_inventory: backend.frame_cow_owner_inventory(),
                        tid: ThreadId::from_kernel_thread_identity(thread.tid.raw()),
                        identity: carrick_hal::FrameCowIdentity {
                            linux_pid: process.pid(),
                            linux_tid: thread.tid.raw(),
                            mm: mm.raw(),
                            asid: (cpu.ttbr0 >> 48) as u16,
                        },
                        pt_quiesce: kernel.dispatcher.pt_quiesce(),
                    }),
                    memory::reserve_child_cow_authority_identity().ok()?,
                ))
            }
            None => None,
        };
        let mut state = Vec::new();
        state.try_reserve_exact(1).ok()?;
        let (execution_lease, injected_lease) = ExecutionLeaseCell::injected();
        let mut reserved = ThreadRuntimeState::<E>::new(
            self.registry.clone(),
            self.futex.clone(),
            self.platform_futex.clone(),
            self.platform_futex_factory.clone(),
            kernel.process_fork_barrier.clone(),
            kernel.crash_capture.clone(),
            None,
            Some(process.pid()),
            thread.tid,
            kernel.fatal_signal.current_generation(),
            ThreadId::from_kernel_thread_identity(thread.tid.raw()),
            self.threads.clone(),
            self.kicker.clone(),
            carrick_hal::InGuestFlag::for_guest_thread(),
            self.max_traps,
        );
        reserved.execution_lease = execution_lease;
        state.push(reserved);
        Some(ThreadBirthAdoptionReservation::new(
            self.owner,
            thread,
            ReservedThreadRuntime {
                kernel,
                state,
                injected_lease,
                origin,
                backend,
                cow,
                cpu: self
                    .cpu_template
                    .as_ref()
                    .map(ProcessThreadCpuTemplate::reserve),
                submission,
            },
        ))
    }
}

pub(super) fn reserve_thread_runtime<E: ThreadedEngine + 'static>(
    kernel: &Kernel,
    state: &ThreadRuntimeState<E>,
    thread: ThreadKey,
    syscall: PreparedSyscall,
) -> Option<ThreadBirthAdoptionReservation>
where
    E::SiblingSpec: 'static,
{
    ProcessThreadAdoptionFactory::capture(kernel, state)?
        .reserve_with_origin(thread, ThreadAdoptionOrigin::HostClone(syscall))
}

/// Both origins consume the same process-owned runtime cell. ABI replay has
/// no parent's clone completion token: its first syscall captures its own.
pub(super) fn adopt_thread_runtime<E: ThreadedEngine + 'static>(
    reservation: ThreadBirthAdoptionReservation,
    context: &KernelContext,
    frame: Option<&carrick_el1_abi::ThreadCtx>,
) -> Result<AdoptedThreadRuntime<E>, TrapError>
where
    E::SiblingSpec: 'static,
{
    if reservation.owner() != context.task().key() || reservation.thread() != context.thread().key()
    {
        return Err(TrapError::Hypervisor(
            "thread adoption capacity belongs to another exact task/thread".into(),
        ));
    }
    let mut reserved = reservation
        .consume::<ReservedThreadRuntime<E>>()
        .map_err(|_| {
            TrapError::Hypervisor("thread adoption capacity has another execution lane".into())
        })?;
    let process =
        reserved.kernel.hvpatch_process.as_ref().ok_or_else(|| {
            TrapError::Hypervisor("thread adoption lost its owner process".into())
        })?;
    if process.task_key() != context.task().key()
        || !Arc::ptr_eq(process.kernel_graph(), context.kernel())
    {
        return Err(TrapError::Hypervisor(
            "thread adoption rejected foreign kernel authority".into(),
        ));
    }
    let mut state = reserved.state.pop().ok_or_else(|| {
        TrapError::Hypervisor("thread adoption runtime cell was already consumed".into())
    })?;
    state.kernel_thread = Some(context.thread().clone());
    state.service_kernel_context = Some(context.retain_exact());
    let cpu = match (reserved.cpu.take(), frame) {
        (Some(cpu), Some(frame)) => Some(cpu.for_born(context, frame)?),
        (None, None) => None,
        _ => {
            return Err(TrapError::Hypervisor(
                "birth adoption requires its reserved CPU and first-entry frame".into(),
            ));
        }
    };
    state.syscall_completion = match reserved.origin {
        ThreadAdoptionOrigin::HostClone(syscall) => {
            SyscallCompletionOwnership::Guest(SyscallCompletionToken::new(
                syscall,
                context.retain_exact(),
                reserved.kernel.dispatcher.observers().cloned(),
            ))
        }
        ThreadAdoptionOrigin::AbiBorn => SyscallCompletionOwnership::Idle,
    };
    Ok(AdoptedThreadRuntime {
        kernel: reserved.kernel,
        backend: reserved.backend,
        cow: reserved.cow,
        cpu,
        state,
        injected_lease: reserved.injected_lease,
        submission: reserved.submission,
    })
}

fn activate_born_thread<E: ThreadedEngine + 'static>(
    context: &KernelContext,
    reservation: ThreadBirthAdoptionReservation,
    frame: &carrick_el1_abi::ThreadCtx,
) -> Result<(), TrapError>
where
    E::SiblingSpec: 'static,
{
    let mut adopted = adopt_thread_runtime::<E>(reservation, context, Some(frame))?;
    let cpu = adopted
        .cpu
        .take()
        .ok_or_else(|| TrapError::Hypervisor("born adoption lost CPU custody".into()))?;
    let mut backend = adopted
        .backend
        .take()
        .ok_or_else(|| TrapError::Hypervisor("born adoption lost backend custody".into()))?;
    let (cow, authority_id) = adopted
        .cow
        .take()
        .ok_or_else(|| TrapError::Hypervisor("born adoption lost COW custody".into()))?;
    let runtime = adopted
        .kernel
        .hvpatch_runtime
        .as_ref()
        .ok_or_else(|| TrapError::Hypervisor("born adoption lost directory".into()))?
        .clone();
    let scheduler = runtime.continuation_services(context.kernel()).0;
    let generation = scheduler
        .publish_initial_task_state_gated(context.thread(), cpu.clone())
        .map_err(|error| TrapError::Hypervisor(error.to_string()))?;
    let token = cow
        .issue_reserved_hvpatch_child_token(context, authority_id)
        .map_err(TrapError::Hypervisor)?;
    lifecycle::bind_activate_child::<carrick_vmm_hvf::hvf_aarch64_engine::HvfAarch64Engine, _>(
        &mut lifecycle::ProductionHvpatchCloneBackendOps,
        &mut backend,
        token,
        || Ok(()),
    )
    .map_err(|error| TrapError::Hypervisor(error.to_string()))?;
    let tid = ThreadId::from_kernel_thread_identity(context.thread().key().tid.raw());
    adopted
        .state
        .registry
        .register_child_with_tid(tid, context.thread().control_slot().clear_child_tid());
    let threads = adopted.state.threads.clone();
    let mut logical = binding::prepare_hvpatch_logical_job(binding::HvpatchLogicalJobInput {
        kernel: adopted.kernel,
        state: adopted.state,
        task_backend: executor::HvpatchTaskEngineBindingState::task_only(backend),
        context: context.retain_exact(),
        cpu,
        generation,
        injected_lease: adopted.injected_lease,
        bootstrap_process_child: None,
        bootstrap_thread_child: false,
    })?;
    let dormant = runtime.persistent_bindings().prepare_submission(
        &scheduler,
        executor::HvpatchSubmissionShape::ProcessBirth(adopted.submission),
        None,
        context.thread().clone(),
        generation,
        logical.binding.clone(),
    )?;
    threads::enroll_persistent_process_member(&threads, &logical.terminal_settlement);
    let gate = context
        .thread()
        .take_opened_start_gate(generation)
        .ok_or_else(|| TrapError::Hypervisor("born adoption lost start proof".into()))?;
    logical.install_start_gate(gate)?;
    dormant.activate(
        &scheduler,
        context.thread().clone(),
        logical.activation_proof()?,
    )
}

#[cfg(test)]
mod tests {
    use super::super::tests::*;
    use super::*;
    use parking_lot::Mutex;

    fn state(
        kernel: &Kernel,
        context: &KernelContext,
        max_traps: usize,
    ) -> ThreadRuntimeState<CrashCaptureTestEngine> {
        ThreadRuntimeState::new(
            Arc::new(ThreadRegistry::new(context.thread().registry_id())),
            Arc::new(FutexTable::new()),
            Arc::new(NoopPlatformFutex),
            Arc::new(|_| Arc::new(NoopPlatformFutex)),
            kernel.process_fork_barrier.clone(),
            kernel.crash_capture.clone(),
            Some(context.thread().clone()),
            Some(kernel.hvpatch_process.as_ref().unwrap().pid()),
            context.thread().key().tid,
            kernel.fatal_signal.current_generation(),
            context.thread().registry_id(),
            Arc::new(Mutex::new(Vec::new())),
            Arc::new(carrick_hal::GenericVcpuRegistry::new()),
            carrick_hal::InGuestFlag::for_guest_thread(),
            max_traps,
        )
    }

    #[test]
    fn born_cpu_template_keeps_own_mm_and_complete_el0_frame_with_two_live_processes() {
        let (_, owner_scheduler, _, owner, _, _) =
            test_carrier_graph_with_dispatcher!(72_493, SyscallDispatcher::new());
        let peer =
            owner
                .kernel()
                .reserve_fork(
                    &owner,
                    carrick_kernel::kernel::ClonePlan::from_flags(
                        carrick_abi::LinuxCloneFlags::empty(),
                    )
                    .unwrap(),
                    "cpu-template-peer".into(),
                    None,
                )
                .unwrap()
                .prepare_reference(ThreadId::synthetic_for_tests(72_494))
                .unwrap()
                .commit()
                .unwrap()
                .start_child()
                .unwrap()
                .into_parts()
                .0;
        let owner_cpu = executor::tests::task_state(&owner, 1_001);
        let peer_cpu = executor::tests::task_state(&peer, 2_002);
        let template = ProcessThreadCpuTemplate::capture(&owner, owner_cpu.clone()).unwrap();
        let backend = OwnedProcessBirthTemplate::new(&owner, 17_u64);
        assert_eq!(backend.with_owner(&owner, |value| *value), Some(17));
        assert!(
            backend.with_owner(&peer, |value| *value).is_none(),
            "a live peer must not resolve another process's backend token"
        );
        assert_eq!(backend.with_owner(&owner, |value| *value), Some(17));
        let mut frame = carrick_el1_abi::ThreadCtx::ZERO;
        frame.x = std::array::from_fn(|i| 9_000 + i as u64);
        frame.pc = 0x1010;
        frame.pstate = 0x2000;
        frame.sp_el0 = 0x3030;
        frame.tpidr_el0 = 0x4040;
        frame.tpidrro_el0 = 0x5050;
        frame.contextidr_el1 = 0x6060;
        frame.v = std::array::from_fn(|i| 7_000 + i as u128);
        frame.fpsr = 0x80;
        frame.fpcr = 0x90;
        let reserved_cpu = template.reserve();
        let GuestCpuState::Aarch64V1(reserved_registers) = &reserved_cpu.cpu.cpu else {
            panic!("architecture");
        };
        let reserved_address = Arc::as_ptr(reserved_registers);
        assert_eq!(Arc::strong_count(reserved_registers), 1);
        let born = reserved_cpu.for_born(&owner, &frame).unwrap();
        let GuestCpuState::Aarch64V1(cpu) = &born.cpu else {
            panic!("architecture");
        };
        assert_eq!(
            Arc::as_ptr(cpu),
            reserved_address,
            "post-birth frame merge must consume the pre-owned CPU allocation"
        );
        let GuestCpuState::Aarch64V1(own) = &owner_cpu.cpu else {
            panic!("architecture");
        };
        let GuestCpuState::Aarch64V1(driver) = &peer_cpu.cpu else {
            panic!("architecture");
        };
        assert_eq!(
            cpu.gprs, frame.x,
            "first entry must use the born frame, not the template thread's registers"
        );
        assert_eq!(
            (cpu.pc, cpu.pstate, cpu.sp_el0),
            (frame.pc, frame.pstate, frame.sp_el0)
        );
        assert_eq!(
            (cpu.tpidr_el0, cpu.tpidrro_el0, cpu.contextidr_el1),
            (frame.tpidr_el0, frame.tpidrro_el0, frame.contextidr_el1)
        );
        assert_eq!(cpu.vregs, frame.v);
        assert_eq!((cpu.fpsr, cpu.fpcr), (frame.fpsr as u32, frame.fpcr as u32));
        assert_eq!(
            (cpu.ttbr0, cpu.ttbr1, cpu.tcr),
            (own.ttbr0, own.ttbr1, own.tcr)
        );
        assert_ne!(cpu.ttbr0, driver.ttbr0);
        assert!(template.reserve().for_born(&peer, &frame).is_err());
        assert!(ProcessThreadCpuTemplate::capture(&owner, peer_cpu).is_err());
        assert!(owner.exact_thread_is_live() && peer.exact_thread_is_live());
        owner_scheduler.close();
    }

    #[test]
    fn shared_adoption_consumes_born_cpu_capacity_for_the_exact_new_thread() {
        let (_, scheduler, kernel, owner, process, _) =
            test_carrier_graph_with_dispatcher!(72_495, SyscallDispatcher::new());
        let owner_state = state(&kernel, &owner, 1_005);
        let mut source = executor::tests::task_state(&owner, 1_005);
        source.asid_generation = process.asid_generation();
        let GuestCpuState::Aarch64V1(registers) = &mut source.cpu else {
            panic!("architecture");
        };
        Arc::make_mut(registers).asid_generation = process.asid_generation();
        let factory = ProcessThreadAdoptionFactory::capture(&kernel, &owner_state)
            .unwrap()
            .with_cpu_template(&owner, source.clone())
            .unwrap();
        let prepared = owner
            .kernel()
            .reserve_thread_clone(
                &owner,
                carrick_kernel::kernel::ClonePlan::from_flags(
                    carrick_abi::LinuxCloneFlags::THREAD
                        | carrick_abi::LinuxCloneFlags::SIGHAND
                        | carrick_abi::LinuxCloneFlags::VM,
                )
                .unwrap(),
                None,
            )
            .unwrap();
        let mut stale = source.clone();
        stale.asid_generation = process.asid_generation().checked_add(1).unwrap();
        let stale_factory = ProcessThreadAdoptionFactory::capture(&kernel, &owner_state)
            .unwrap()
            .with_cpu_template(&owner, stale)
            .unwrap();
        assert!(
            stale_factory.reserve(prepared.key()).is_none(),
            "stale image capacity must decline before Born"
        );
        let ticket = factory.reserve(prepared.key()).unwrap();
        let born = prepared
            .prepare(ThreadId::synthetic_for_tests(72_496))
            .unwrap()
            .commit()
            .unwrap()
            .start_thread()
            .unwrap()
            .into_context();
        let mut frame = carrick_el1_abi::ThreadCtx::ZERO;
        frame.pc = 0x4040;
        frame.sp_el0 = 0x8080;
        frame.x[8] = 172;
        frame.contextidr_el1 = born.thread().key().tid.raw() as u64;
        let adopted =
            adopt_thread_runtime::<CrashCaptureTestEngine>(ticket, &born, Some(&frame)).unwrap();
        assert_eq!(
            adopted.state.kernel_thread.as_ref().unwrap().key(),
            born.thread().key()
        );
        assert!(matches!(
            adopted.state.syscall_completion,
            SyscallCompletionOwnership::Idle
        ));
        let cpu = adopted.cpu.as_ref().unwrap();
        let GuestCpuState::Aarch64V1(registers) = &cpu.cpu else {
            panic!("architecture");
        };
        assert_eq!(registers.pc, frame.pc);
        assert_eq!(registers.gprs[8], 172);
        assert_eq!(
            registers.contextidr_el1,
            born.thread().key().tid.raw() as u64
        );
        assert_eq!(cpu.mm, source.mm);
        assert!(
            adopted
                .submission
                .activate(&scheduler, born.thread())
                .is_err(),
            "binding generation has not been published yet"
        );
        scheduler.close();
    }

    #[test]
    fn abi_runtime_adoption_uses_its_process_capacity_with_two_live_processes() {
        let (_, owner_scheduler, owner_kernel, owner, _, _) =
            test_carrier_graph_with_dispatcher!(72_491, SyscallDispatcher::new());
        let (_, peer_scheduler, peer_kernel, peer, _, _) =
            test_carrier_graph_with_dispatcher!(72_492, SyscallDispatcher::new());
        let owner_state = state(&owner_kernel, &owner, 1_001);
        let peer_state = state(&peer_kernel, &peer, 2_002);
        let factory = ProcessThreadAdoptionFactory::capture(&owner_kernel, &owner_state).unwrap();
        let reservation = factory.reserve(owner.thread().key()).unwrap();
        let adopted =
            adopt_thread_runtime::<CrashCaptureTestEngine>(reservation, &owner, None).unwrap();
        assert!(Arc::ptr_eq(&adopted.kernel, &owner_kernel));
        assert!(Arc::ptr_eq(&adopted.state.registry, &owner_state.registry));
        assert!(Arc::ptr_eq(&adopted.state.futex, &owner_state.futex));
        assert!(!Arc::ptr_eq(&adopted.state.registry, &peer_state.registry));
        assert!(!Arc::ptr_eq(&adopted.state.futex, &peer_state.futex));
        assert_eq!(adopted.state.max_traps, 1_001);
        assert_eq!(
            adopted.state.kernel_thread.as_ref().unwrap().key(),
            owner.thread().key()
        );
        assert!(matches!(
            adopted.state.syscall_completion,
            SyscallCompletionOwnership::Idle
        ));
        let reservation = factory.reserve(owner.thread().key()).unwrap();
        assert!(adopt_thread_runtime::<CrashCaptureTestEngine>(reservation, &peer, None).is_err());
        assert!(owner.exact_thread_is_live());
        assert!(peer.exact_thread_is_live());
        owner_scheduler.close();
        peer_scheduler.close();
    }
}
