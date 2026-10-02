//! Process-owned runtime state reserved before either lane publishes a thread.

use std::fmt;
use std::sync::{Arc, Weak};

use carrick_kernel::kernel::thread_adoption::{
    ThreadBirthAdoptionFactory, ThreadBirthAdoptionReservation,
};
use carrick_kernel::kernel::{KernelContext, TaskKey, ThreadKey};

use super::binding::InjectedExecutionLeaseSlot;
use super::*;

pub(super) enum ThreadAdoptionOrigin {
    HostClone(PreparedSyscall),
    AbiBorn,
}

/// Shared process resources, not a running job, backend or executor lease.
pub(super) struct ProcessThreadAdoptionFactory<E: ThreadedEngine> {
    owner: TaskKey,
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
    submission: carrick_kernel::kernel::scheduler::ProcessBirthSubmission,
}

pub(super) struct AdoptedThreadRuntime<E: ThreadedEngine> {
    pub(super) kernel: Kernel,
    pub(super) state: ThreadRuntimeState<E>,
    pub(super) injected_lease: Arc<InjectedExecutionLeaseSlot>,
    pub(super) submission: carrick_kernel::kernel::scheduler::ProcessBirthSubmission,
}

impl<E: ThreadedEngine + 'static> ProcessThreadAdoptionFactory<E>
where
    E::SiblingSpec: 'static,
{
    pub(super) fn capture(kernel: &Kernel, state: &ThreadRuntimeState<E>) -> Option<Self> {
        Some(Self {
            owner: kernel.hvpatch_process.as_ref()?.task_key(),
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
        let scheduler = kernel
            .hvpatch_runtime
            .as_ref()?
            .continuation_services(process.kernel_graph())
            .0;
        let submission = scheduler.reserve_process_birth(&task, thread).ok()?;
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
        state,
        injected_lease: reserved.injected_lease,
        submission: reserved.submission,
    })
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
    fn abi_runtime_adoption_uses_its_process_capacity_with_two_live_processes() {
        let (_, owner_scheduler, owner_kernel, owner, _, _) =
            test_carrier_graph_with_dispatcher!(72_491, SyscallDispatcher::new());
        let (_, peer_scheduler, peer_kernel, peer, _, _) =
            test_carrier_graph_with_dispatcher!(72_492, SyscallDispatcher::new());
        let owner_state = state(&owner_kernel, &owner, 1_001);
        let peer_state = state(&peer_kernel, &peer, 2_002);
        let factory = ProcessThreadAdoptionFactory::capture(&owner_kernel, &owner_state).unwrap();
        let reservation = factory.reserve(owner.thread().key()).unwrap();
        let adopted = adopt_thread_runtime::<CrashCaptureTestEngine>(reservation, &owner).unwrap();
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
        assert!(adopt_thread_runtime::<CrashCaptureTestEngine>(reservation, &peer).is_err());
        assert!(owner.exact_thread_is_live());
        assert!(peer.exact_thread_is_live());
        owner_scheduler.close();
        peer_scheduler.close();
    }
}
