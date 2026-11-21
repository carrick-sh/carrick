//! The x86 CPL0 venue of the shared root exec transaction (#2142).
//!
//! The run root's `execve` is the native exec service's on x86, as a fork
//! child's is: the carrier loads and stages the successor, the ring adopts
//! it, commits its own exec effects and switches its slot, then settles on
//! the loaded lane. That settlement ([`RootExecSettled`]) is where the Kernel's
//! half runs: [`drive_root_exec`] from `begin` to `settle`, in one call,
//! before this CPU enters the guest again. The ring is past its no-return
//! point by then, so every recoverable errno (ENOENT, ENOEXEC, E2BIG, the
//! stock's ENOMEM) was already returned before the seal, and any failure
//! here kills the process with the exec's past-no-return verdict.
//!
//! The successor's image, page tables, signal dispositions, ring descriptor
//! table and CR3 are the ring's; this venue installs none of them. It
//! commits the Kernel task graph to the ring-issued MM the exec owner
//! authenticated, closes the root's host descriptors marked close-on-exec,
//! publishes the successor's executable identity, and hands the worker an
//! exec replacement that retargets the root's loaded custody.

use std::future::Future;
use std::sync::Arc;
use std::time::Instant;

use carrick_hal::TrapError;
use carrick_hal::guest_arch_binding::{
    GuestArchBinding,
    core_arch::{AddressContext, ExecutionGeneration as ArchExecutionGeneration, RootGpa},
};
use carrick_hal::threaded::{GuestCpuState, X86TaskCpuStateV1};
use carrick_kernel::dispatch::{PreparedDispatchMmExec, SyscallDispatcher};
use carrick_kernel::kernel::exec::CommittedExecTransition;
use carrick_kernel::kernel::exec_transaction::{
    Drained, ExecPastNoReturn, ExecStep, ExecTerminal, ImageReplacement, RootExecVenue,
    SignalReset, drive_root_exec,
};
use carrick_kernel::kernel::objects::{ExecutorId, MigratableTaskState};
use carrick_kernel::kernel::{KernelContext, PreparedExec};
use carrick_mem::memory::AddressSpace;
use carrick_x86_cpl0_host::cpl0_boot::exec_service::RootExecSettled;

use super::super::ExecutorSubmissionContext;
use super::super::binding::PendingExecReplacement;
use super::Cpl0TaskBinding;
use crate::runtime::exec::X86RootExecLoad;

/// Why the Kernel's half of a settled root exec killed the process.
pub(super) struct RootExecKilled {
    pub(super) cause: String,
}

/// Run the Kernel's half of the run root's settled exec on its loaded lane.
/// `Ok(None)`: the successor is committed and `submission` carries its exec
/// replacement, which the worker applies before this CPU's next guest
/// entry. `Ok(Some(_))`: the process dies past the point of no return.
pub(super) fn serve_root_exec(
    dispatcher: &SyscallDispatcher,
    predecessor: &Arc<Cpl0TaskBinding>,
    mut settled: RootExecSettled,
    submission: &mut ExecutorSubmissionContext<'_>,
) -> Result<Option<RootExecKilled>, TrapError> {
    let identity = settled
        .take_load()
        .downcast::<X86RootExecLoad>()
        .map_err(|_| TrapError::Hypervisor("root exec settled another loader's load".into()))?
        .identity;
    let state = settled
        .state()
        .cloned()
        .ok_or_else(|| TrapError::Hypervisor("root exec settled without its CPU state".into()))?;
    let successor = settled.successor();
    let execution = settled.execution();
    let context = predecessor.fresh_context()?;
    let worker_executor = submission.execution_lease_mut()?.executor();
    let mut venue = Cpl0RootExecVenue {
        dispatcher,
        context,
        predecessor,
        settled: Some(settled),
        successor,
        execution,
        state: Some(state),
        image: AddressSpace::from_regions(0, Vec::new())
            .map_err(|error| TrapError::Hypervisor(format!("empty exec image: {error}")))?,
        worker_executor,
        submission,
    };
    // The driver awaits nothing: it completes on its first poll.
    let polled = {
        let mut drive = std::pin::pin!(drive_root_exec(
            &mut venue,
            Drained::new(Instant::now()),
            identity,
        ));
        drive
            .as_mut()
            .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    };
    match polled {
        std::task::Poll::Ready(result) => {
            result.map_err(|error| TrapError::Hypervisor(format!("CPL0 root exec: {error}")))
        }
        std::task::Poll::Pending => Err(TrapError::Hypervisor(
            "CPL0 root exec transaction suspended".into(),
        )),
    }
}

struct Cpl0RootExecVenue<'a, 's> {
    dispatcher: &'a SyscallDispatcher,
    /// The caller's exact context, then the committed successor's.
    context: KernelContext,
    predecessor: &'a Arc<Cpl0TaskBinding>,
    /// Consumed when the Kernel preparation takes its authenticated MM.
    settled: Option<RootExecSettled>,
    successor: AddressContext<RootGpa>,
    /// The ring's execution generation of the successor's thread.
    execution: ArchExecutionGeneration,
    state: Option<X86TaskCpuStateV1>,
    /// The successor's maps and auxv are the ring's: the host's `/proc`
    /// projection of the image is empty, as it is for the booted root.
    image: AddressSpace,
    worker_executor: ExecutorId,
    submission: &'a mut ExecutorSubmissionContext<'s>,
}

impl Cpl0RootExecVenue<'_, '_> {
    fn killed(cause: impl Into<String>) -> ExecTerminal<RootExecKilled> {
        ExecTerminal::new(Ok(RootExecKilled {
            cause: cause.into(),
        }))
    }
}

/// The ring installed the successor before it settled: past the predecessor
/// lease's retirement, the image steps have nothing left to do on the host.
struct Cpl0ImageReplacement<'a, 's> {
    predecessor: &'a Arc<carrick_kernel::kernel::Thread>,
    submission: &'a mut ExecutorSubmissionContext<'s>,
}

impl<'a, 's> ImageReplacement<Cpl0RootExecVenue<'a, 's>> for Cpl0ImageReplacement<'_, 's> {
    fn arm_no_return(
        &mut self,
        mut prepared: PreparedExec,
        _dispatch_mm: Option<&PreparedDispatchMmExec>,
    ) -> ExecStep<PreparedExec, RootExecKilled> {
        prepared.enter_no_return();
        // The predecessor's execution lease ends here; the successor's is
        // claimed once its task state is published.
        let slot = self.submission.authority_slot_mut();
        let lease = slot.take_lease().ok_or_else(|| {
            Cpl0RootExecVenue::killed("root exec lost its predecessor execution lease")
        })?;
        let consumed =
            self.predecessor
                .exit_predecessor_for_exec(lease)
                .map_err(|(error, _)| {
                    Cpl0RootExecVenue::killed(format!("retire the root exec predecessor: {error}"))
                })?;
        slot.consume_predecessor_for_exec(consumed);
        Ok(prepared)
    }

    fn install_image(&mut self, armed: PreparedExec) -> ExecStep<PreparedExec, RootExecKilled> {
        Ok(armed)
    }

    /// The ring allocates the root's descriptors in the namespace the
    /// carrier published for its boot table, and closed their close-on-exec
    /// ones in place at its commit. The successor's staged table takes that
    /// namespace over before the commit retires the predecessor's.
    fn publish_mm(&mut self, installed: PreparedExec) -> ExecStep<PreparedExec, RootExecKilled> {
        installed
            .old_file_table()
            .hand_ipc_to_exec_successor(&installed.replacement_file_table())
            .map_err(|error| {
                Cpl0RootExecVenue::killed(format!(
                    "hand the root's descriptor namespace to its successor: {error:?}"
                ))
            })?;
        Ok(installed)
    }
}

impl<'a, 's> RootExecVenue for Cpl0RootExecVenue<'a, 's> {
    type Outcome = RootExecKilled;
    type Prepared = PreparedExec;
    type Envelope = ();
    type Armed = PreparedExec;
    type Installed = PreparedExec;
    type Replaced = PreparedExec;
    type Committed = CommittedExecTransition;
    type Resident = ();
    type Entry = MigratableTaskState;

    fn dispatcher(&self) -> &SyscallDispatcher {
        self.dispatcher
    }

    fn image(&self) -> &AddressSpace {
        &self.image
    }

    fn exec_context(&self) -> &KernelContext {
        &self.context
    }

    /// The carrier process hosts the whole guest.
    fn renames_host_process(&self) -> bool {
        false
    }

    fn record_stage(
        &self,
        _phase: carrick_observability::probes::HvpatchExecRuntimeStagePhase,
        _started: Instant,
    ) {
    }

    fn fail_past_no_return(
        &mut self,
        _verdict: ExecPastNoReturn,
        cause: &str,
    ) -> ExecTerminal<RootExecKilled> {
        Self::killed(cause)
    }

    /// The ring reset the caller's signal state in its own exec commit: the
    /// exec owner yields a root settlement only for a commit-effects word
    /// with every obligation done, which discharged that reset.
    fn reset_exec_signals(&mut self) -> SignalReset {
        SignalReset::Done
    }

    fn prepare_mm(&mut self) -> ExecStep<(PreparedExec, ()), RootExecKilled> {
        let settled = self
            .settled
            .take()
            .ok_or_else(|| Self::killed("root exec settlement consumed twice"))?;
        let (_, authenticated) = settled.consume();
        let kernel = Arc::clone(self.context.kernel());
        let issued = kernel
            .adopt_authenticated_exec_mm(authenticated)
            .map_err(|error| Self::killed(format!("root exec issued MM: {error}")))?;
        let prepared = kernel
            .prepare_exec_with_registry_id(
                &self.context,
                self.context.thread().registry_id(),
                issued,
                None,
            )
            .map_err(|error| Self::killed(format!("prepare the root's Kernel exec: {error}")))?;
        if prepared.replacement_mm_id().raw() != self.successor.mm.raw().get() {
            return Err(Self::killed(
                "root exec prepared another MM than the ring's",
            ));
        }
        Ok((prepared, ()))
    }

    fn replace_image<R>(
        &mut self,
        prepared: PreparedExec,
        _topology_lock_started: Instant,
        replace: impl FnOnce(
            &mut dyn ImageReplacement<Self>,
            PreparedExec,
        ) -> ExecStep<R, RootExecKilled>,
    ) -> ExecStep<R, RootExecKilled> {
        let mut transaction = Cpl0ImageReplacement {
            predecessor: self.context.thread(),
            submission: &mut *self.submission,
        };
        replace(&mut transaction, prepared)
    }

    fn commit(
        &mut self,
        replaced: PreparedExec,
        dispatch_mm: &mut Option<PreparedDispatchMmExec>,
    ) -> ExecStep<(KernelContext, CommittedExecTransition), RootExecKilled> {
        let kernel = Arc::clone(self.context.kernel());
        let committed = kernel
            .commit_exec_transition(replaced, None)
            .map_err(|error| Self::killed(format!("commit the root's Kernel exec: {error}")))?;
        if let Some(dispatch_mm) = dispatch_mm.take() {
            dispatch_mm.commit();
        }
        let successor_mm = committed.context().shared().mm().id();
        let committed = committed
            .attach_successor_asid_generation(successor_mm, self.successor.generation.raw().get())
            .map_err(|error| Self::killed(format!("root exec root generation: {error}")))?;
        Ok((committed.context().retain_exact(), committed))
    }

    fn adopt_successor_context(
        &mut self,
        committed_context: &KernelContext,
    ) -> ExecStep<(), RootExecKilled> {
        self.context = committed_context.retain_exact();
        Ok(())
    }

    /// The ring installed the successor's space before it settled.
    fn load_successor_mm(
        &mut self,
        _committed_context: &KernelContext,
        _committed: &mut CommittedExecTransition,
    ) -> ExecStep<(), RootExecKilled> {
        Ok(())
    }

    fn entry_state(
        &mut self,
        committed_context: &KernelContext,
        _resident: (),
    ) -> ExecStep<MigratableTaskState, RootExecKilled> {
        let state = self
            .state
            .take()
            .ok_or_else(|| Self::killed("root exec entry state taken twice"))?;
        Ok(MigratableTaskState {
            cpu: GuestCpuState::X86_64V1(Arc::new(state)),
            mm: committed_context.shared().mm().id(),
            asid_generation: self.successor.generation.raw().get(),
        })
    }

    /// Fault-time memory authority is the ring's.
    fn bind_successor_memory(
        &mut self,
        _committed_context: &KernelContext,
    ) -> ExecStep<(), RootExecKilled> {
        Ok(())
    }

    /// The executor's binding follows the successor at the retarget.
    fn rebind_identity(&mut self, _committed_context: &KernelContext) {}

    fn verify_image(&mut self) -> ExecStep<(), RootExecKilled> {
        Ok(())
    }

    /// The identity, vvar and thread words are the ring's own.
    fn stamp_port(&mut self, _committed_context: &KernelContext) -> ExecStep<(), RootExecKilled> {
        Ok(())
    }

    fn publish_replacement(
        &mut self,
        committed_context: &KernelContext,
        committed: CommittedExecTransition,
        entry: MigratableTaskState,
    ) -> ExecStep<(), RootExecKilled> {
        let thread = committed_context.thread();
        thread
            .publish_initial_task_state(entry)
            .map_err(|error| Self::killed(format!("publish the root successor: {error}")))?;
        let lease = thread
            .claim_runnable(self.worker_executor)
            .map_err(|error| Self::killed(format!("claim the root successor: {error}")))?;
        self.submission.authority_slot_mut().set_lease(lease);
        // The carrier authenticates the successor's forwards against the
        // ring thread's execution generation, not the Kernel thread's.
        let arch = GuestArchBinding::x86(
            carrick_hal::guest_arch_binding::core_arch::TaskIdentity {
                execution: self.execution,
                ..self.predecessor.arch().task()
            },
            self.successor,
        );
        let replacement = PendingExecReplacement::cpl0(committed, arch)
            .map_err(|error| Self::killed(format!("root exec replacement: {error}")))?;
        if self
            .submission
            .exec_replacement
            .replace(replacement)
            .is_some()
        {
            return Err(Self::killed(
                "quantum published more than one exec replacement",
            ));
        }
        Ok(())
    }
}
