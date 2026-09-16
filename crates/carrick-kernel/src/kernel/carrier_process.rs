//! The kernel-level view of one Linux process's carrier handle.
//!
//! Dispatch reaches "the process this dispatcher is bound to" through this
//! trait instead of the HVPatch carrier's `ProcessContext`. Everything a
//! syscall handler asks of a process — its identity, its kernel graph, child
//! waits, pidfd exit watches, ptrace stops, interval-timer delivery and the
//! two mm-authority bindings made at dispatcher bind time — is answered from
//! the kernel graph keyed by the process's exact `TaskKey`. The carrier keeps
//! what only it owns (stage-1 mm, exec MM reservations, address-space
//! retirement) on its concrete type and forwards the primitives below.
//!
//! The derived operations are provided methods, so every implementor — the
//! HVPatch `ProcessContext` and the in-crate `TestCarrierProcess` — lowers a
//! wait outcome, a thread exit or a ptrace stop through the same code; a test
//! double cannot drift from the carrier.

use std::sync::Arc;

use carrick_fatal::carrick_fatal;

use crate::kernel::{
    ChildExit, ProcessThreadExit, RetiredThreadResources, WaitResult, identity_operation_errno,
};

/// The handle through which dispatch reaches the process a carrier runs.
///
/// The required methods are the carrier's own facts: the exact task binding
/// and everything the carrier attaches to the process's mm at dispatcher
/// bind time. The stage-1 address space is reached only as a
/// [`carrick_hal::stage1_mm::Stage1MmProjection`]; the carrier's lease type
/// never crosses into the kernel.
pub trait CarrierProcess: Send + Sync {
    fn kernel_graph(&self) -> &Arc<crate::kernel::Kernel>;

    fn task_key(&self) -> crate::kernel::TaskKey;

    fn task_binding(&self) -> crate::kernel::KernelTaskBinding;

    fn context_for_linux_tid(
        &self,
        tid: crate::kernel::LinuxTid,
    ) -> Result<crate::kernel::KernelContext, crate::kernel::KernelError>;

    fn mm_access_authority(&self) -> Option<&crate::kernel::MmAccessAuthority>;

    fn stage1_mm_projection(
        &self,
    ) -> Result<Arc<dyn carrick_hal::stage1_mm::Stage1MmProjection>, crate::run_result::RuntimeError>;

    fn bind_vma_source(&self, source: crate::kernel::SharedVmaSnapshotSource);

    fn bind_mm_mutation_authority(
        &self,
        authority: crate::dispatch::mm_mutation::ForeignMmMutationAuthority,
    );

    fn task_id(&self) -> crate::kernel::TaskId {
        self.task_key().id
    }

    fn pid(&self) -> i32 {
        self.task_id().raw()
    }

    fn process_timer_delivery(&self) -> std::sync::Arc<dyn carrick_hal::TimerDelivery> {
        std::sync::Arc::new(ProcessTimerDelivery::new(
            self.kernel_graph(),
            self.task_key(),
        ))
    }

    fn stop_for_ptrace_signal(&self, signum: i32) -> bool {
        let Ok(signal) = crate::kernel::LinuxSignal::for_signal_number(signum) else {
            return false;
        };
        self.kernel_graph()
            .stop_task_for_ptrace(self.task_id(), signal)
    }

    fn stop_for_ptrace_fault(&self, fault: crate::kernel::objects::PtraceSynchronousFault) -> bool {
        self.kernel_graph()
            .stop_task_for_ptrace_fault(self.task_id(), fault)
    }

    fn consume_ptrace_resume_signal(&self, signum: i32) -> bool {
        let Ok(signal) = crate::kernel::LinuxSignal::for_signal_number(signum) else {
            return false;
        };
        self.kernel_graph()
            .consume_ptrace_resume_signal(self.task_id(), signal)
    }

    fn register_pidfd_watch(
        &self,
        target: i32,
        watch: &std::sync::Arc<crate::dispatch::fd_table::PidfdWatch>,
    ) -> Option<crate::kernel::TaskKey> {
        let target = crate::kernel::TaskId::from_abi_positive(target).ok()?;
        self.kernel_graph()
            .register_task_exit_subscriber(target, watch)
    }

    fn process_is_live(&self, target: crate::kernel::TaskKey) -> bool {
        self.kernel_graph().task_key_is_live(target)
    }

    fn live_process_key(&self, target: i32) -> Option<crate::kernel::TaskKey> {
        let target = crate::kernel::TaskId::from_abi_positive(target).ok()?;
        self.kernel_graph().live_task_key(target)
    }

    fn exit_thread(
        &self,
        tid: crate::kernel::LinuxTid,
    ) -> Result<ProcessThreadExit, crate::kernel::KernelOperationError> {
        let context = match self.context_for_linux_tid(tid) {
            Ok(context) => context,
            Err(crate::kernel::KernelError::UnknownThread(_)) => {
                // Exec replacement may already have retired this exact old
                // thread while its host loop is unwinding.
                return Ok(ProcessThreadExit::AlreadyRetired);
            }
            Err(_) if !self.kernel_graph().task_is_live(self.task_id()) => {
                return Ok(ProcessThreadExit::AlreadyRetired);
            }
            Err(_) => {
                return Err(crate::kernel::KernelOperationError::UnknownTask(
                    self.task_id(),
                ));
            }
        };
        // Capture the retiring thread's exact owner/table generation before
        // Kernel publication removes the thread from the authoritative graph.
        // Callers use this receipt to consume only that generation's close
        // events; recapturing afterward could select a surviving peer table.
        let retired =
            RetiredThreadResources::new(context.task().key(), context.resources().files());
        let observed = self.kernel_graph().reservation_epoch();
        match self.kernel_graph().exit_thread(&context, None) {
            Ok(_) => Ok(ProcessThreadExit::Retired(retired)),
            Err(crate::kernel::KernelOperationError::TaskBusy(_)) => {
                // NEVER park the executor host thread on the reservation
                // condvar here: the holder can be an exec survivor's
                // terminal path waiting for THIS executor's ASID ack — a
                // cycle observed live (executor-2 in this condvar,
                // executor-4 in `invalidate_after_exec`'s recv, nine of
                // ten acks). The caller parks as a retryable job instead.
                Ok(ProcessThreadExit::Busy {
                    observed_epoch: observed,
                })
            }
            Err(crate::kernel::KernelOperationError::LastThreadRequiresTaskExit(_)) => {
                Ok(ProcessThreadExit::LastThread)
            }
            Err(crate::kernel::KernelOperationError::UnknownThread(_))
                if !context.exact_thread_is_live() =>
            {
                Ok(ProcessThreadExit::AlreadyRetired)
            }
            Err(crate::kernel::KernelOperationError::ParentExited)
            | Err(crate::kernel::KernelOperationError::UnknownTask(_))
                if !self.kernel_graph().task_is_live(self.task_id()) =>
            {
                Ok(ProcessThreadExit::AlreadyRetired)
            }
            Err(error) => Err(error),
        }
    }

    /// Ask the kernel graph for a reapable child. NEVER blocks: every caller
    /// runs inside dispatch, implements a blocking wait by re-dispatching on
    /// [`WaitResult::StillRunning`] (the vcpu loop's bounded child-wait park),
    /// and hands `WNOHANG` straight back to the guest.
    fn wait_child_with_job_control(
        &self,
        target: Option<i32>,
        class: crate::kernel::WaitChildClass,
        nowait: bool,
        include_stopped: bool,
        include_continued: bool,
    ) -> WaitResult {
        let target = target.and_then(|raw| crate::kernel::TaskId::from_abi_positive(raw).ok());
        let outcome = self.kernel_graph().wait_child_with_job_control(
            self.task_id(),
            target,
            class,
            include_stopped,
            include_continued,
            wait_mode(nowait),
        );
        wait_result(self, "authoritative child wait failed", outcome)
    }

    fn wait_child_key(
        &self,
        target: crate::kernel::TaskKey,
        class: crate::kernel::WaitChildClass,
        nowait: bool,
    ) -> WaitResult {
        let outcome =
            self.kernel_graph()
                .wait_child_key(self.task_id(), target, class, wait_mode(nowait));
        wait_result(self, "authoritative pidfd child wait failed", outcome)
    }

    fn wait_child_in_process_group_with_job_control(
        &self,
        group: i32,
        class: crate::kernel::WaitChildClass,
        nowait: bool,
        include_stopped: bool,
        include_continued: bool,
    ) -> WaitResult {
        let Ok(group) = crate::kernel::ProcessGroupId::from_abi_positive(group) else {
            return WaitResult::NoChild;
        };
        let outcome = self
            .kernel_graph()
            .wait_child_in_process_group_with_job_control(
                self.task_id(),
                group,
                class,
                include_stopped,
                include_continued,
                wait_mode(nowait),
            );
        wait_result(
            self,
            "authoritative process-group child wait failed",
            outcome,
        )
    }

    /// This process's OWN process group. A peer's group is a different
    /// question with a different answer — `Kernel::process_identity` includes
    /// the zombie table, because Linux keeps an unreaped process addressable —
    /// so it deliberately has no `target` parameter to be reached through.
    fn process_group(&self) -> Result<i32, crate::linux_abi::LinuxErrno> {
        self.kernel_graph()
            .task_identity(self.task_id())
            .map(|identity| identity.process_group.raw())
            .map_err(identity_operation_errno)
    }
}

/// `WNOWAIT` peeks; every other wait reaps.
fn wait_mode(nowait: bool) -> crate::kernel::WaitMode {
    if nowait {
        crate::kernel::WaitMode::Observe
    } else {
        crate::kernel::WaitMode::Consume
    }
}

/// Lower a kernel-graph wait outcome to the dispatch-side result the
/// three wait entry points share.
fn wait_result<P: CarrierProcess + ?Sized>(
    process: &P,
    failure: &'static str,
    outcome: Result<crate::kernel::WaitOutcome, crate::kernel::KernelOperationError>,
) -> WaitResult {
    // Sampled before this outcome is interpreted, so the `TaskBusy` arm
    // below — which reports "nothing reapable yet" WITHOUT having scanned
    // the child set — still hands the continuation a generation that
    // precedes any edge a concurrent exit can publish. An earlier reading
    // is always safe (at worst one spurious redispatch); a later one loses
    // the edge. See `ChildWaitPrecheck`.
    let busy_precheck = crate::kernel::ChildWaitPrecheck::unsampled();
    match outcome {
        Ok(crate::kernel::WaitOutcome::Exited(zombie)) => {
            let Ok(visible_pid) = i32::try_from(zombie.namespace_pid) else {
                carrick_fatal!(
                    "hvpatch::wait_identity",
                    "zombie namespace_pid exceeds i32 in wait_result"
                );
            };
            WaitResult::Exited(ChildExit::new(
                zombie.key.id,
                visible_pid,
                zombie.ruid,
                zombie.status.raw(),
            ))
        }
        // A P_PIDFD wait runs in Consume mode too, so reporting a
        // job-control event as "still running" DISCARDS it. Render the
        // wait-status encoding and let the caller decide whether it asked
        // for it.
        Ok(crate::kernel::WaitOutcome::Stopped { task, signal, ruid }) => {
            let Some(visible_pid) = visible_task_id(process, task) else {
                return WaitResult::NoChild;
            };
            WaitResult::StateChanged(ChildExit::new(
                task,
                visible_pid,
                ruid,
                (signal.raw() << 8) | 0x7f,
            ))
        }
        Ok(crate::kernel::WaitOutcome::Continued { task, ruid }) => {
            let Some(visible_pid) = visible_task_id(process, task) else {
                return WaitResult::NoChild;
            };
            WaitResult::StateChanged(ChildExit::new(task, visible_pid, ruid, 0xffff))
        }
        Ok(crate::kernel::WaitOutcome::StillRunning(precheck)) => {
            WaitResult::StillRunning(precheck)
        }
        Ok(crate::kernel::WaitOutcome::NoChild) => WaitResult::NoChild,
        Err(crate::kernel::KernelOperationError::TaskBusy(_)) => {
            // A reservation is mid-flight — typically THIS process's
            // own fork holding its task reserved from admission
            // through child materialization. Report "nothing reapable
            // yet" instead of parking on the reservation condvar: a
            // guest `WNOHANG` must return 0 immediately (CPython's
            // `Pool._join_exited_workers` polls `waitpid(WNOHANG)`
            // from one thread while another forks the replacement
            // worker, and blocking here stalled the poll for the
            // whole fork), and a BLOCKING wait re-dispatches through
            // the vcpu loop's bounded park, which re-runs this query.
            // The condvar park was also invisible to fork-quiesce
            // kicks — an unbounded parking_lot wait inside dispatch.
            WaitResult::StillRunning(busy_precheck)
        }
        Err(error) => {
            tracing::error!(pid = process.pid(), %error, "{failure}");
            WaitResult::NoChild
        }
    }
}

fn visible_task_id<P: CarrierProcess + ?Sized>(
    process: &P,
    task: crate::kernel::TaskId,
) -> Option<i32> {
    let observer = process.task_binding().capture_signal_snapshot().ok()?;
    let internal = u32::try_from(task.raw()).ok()?;
    crate::namespace::pid::kernel_to_ns_for(observer.context(), internal)
        .and_then(|visible| i32::try_from(visible).ok())
}

#[derive(Clone)]
struct ProcessTimerTarget {
    kernel: std::sync::Weak<crate::kernel::Kernel>,
    task: crate::kernel::TaskKey,
}

impl ProcessTimerTarget {
    fn task(&self) -> Option<std::sync::Arc<crate::kernel::Task>> {
        let kernel = self.kernel.upgrade()?;
        if !kernel.task_key_is_live(self.task) {
            return None;
        }
        kernel
            .registry()
            .task(self.task.id)
            .filter(|task| task.key() == self.task)
    }

    fn deliver(&self, signum: i32, siginfo: Option<crate::linux_abi::LinuxSiginfo>) -> bool {
        if signum == 0 {
            return self.task().is_some();
        }
        let Ok(signal) = crate::kernel::LinuxSignal::for_signal_number(signum) else {
            return false;
        };
        let Some(kernel) = self.kernel.upgrade() else {
            return false;
        };
        kernel.post_signal_to_task_key(self.task, signal, siginfo)
    }

    fn deliver_to_thread(
        &self,
        tid: i32,
        signum: i32,
        siginfo: Option<crate::linux_abi::LinuxSiginfo>,
    ) -> bool {
        if signum == 0 {
            return self.task().is_some();
        }
        let Ok(signal) = crate::kernel::LinuxSignal::for_signal_number(signum) else {
            return false;
        };
        let Some(kernel) = self.kernel.upgrade() else {
            return false;
        };
        let Some(task) = self.task() else {
            return false;
        };
        let Ok(linux_tid) = crate::kernel::LinuxTid::from_abi_positive(tid) else {
            return false;
        };
        if let Some(thread) = task.thread(linux_tid) {
            kernel.post_signal_to_thread_key(task.key(), thread.key(), signal, siginfo)
        } else {
            kernel.post_signal_to_task_key(self.task, signal, siginfo)
        }
    }
}

struct ProcessItimerSlot {
    generation: std::sync::atomic::AtomicU64,
    spec: parking_lot::Mutex<Option<carrick_hal::TimerSpecNs>>,
}

impl ProcessItimerSlot {
    fn new() -> Self {
        Self {
            generation: std::sync::atomic::AtomicU64::new(0),
            spec: parking_lot::Mutex::new(None),
        }
    }

    fn replace(&self, spec: Option<carrick_hal::TimerSpecNs>) -> u64 {
        use std::sync::atomic::Ordering;
        let mut current = self.spec.lock();
        let generation = self
            .generation
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);
        *current = spec;
        generation
    }

    fn generation_matches(&self, generation: u64) -> bool {
        self.generation.load(std::sync::atomic::Ordering::Acquire) == generation
    }

    fn retire_one_shot(&self, generation: u64) {
        let mut current = self.spec.lock();
        if self.generation_matches(generation) {
            *current = None;
        }
    }
}

pub struct ProcessTimerDelivery {
    target: ProcessTimerTarget,
    slots: [std::sync::Arc<ProcessItimerSlot>; carrick_timer_core::itimer::ITIMER_COUNT],
}

impl ProcessTimerDelivery {
    pub(crate) fn new(
        kernel: &std::sync::Arc<crate::kernel::Kernel>,
        task: crate::kernel::TaskKey,
    ) -> Self {
        Self {
            target: ProcessTimerTarget {
                kernel: std::sync::Arc::downgrade(kernel),
                task,
            },
            slots: std::array::from_fn(|_| std::sync::Arc::new(ProcessItimerSlot::new())),
        }
    }

    fn drive_itimer(
        target: ProcessTimerTarget,
        slot: std::sync::Arc<ProcessItimerSlot>,
        which: usize,
        generation: u64,
        spec: carrick_hal::TimerSpecNs,
        signum: i32,
    ) {
        if carrick_timer_core::itimer::is_cpu_timer(which) {
            // ITIMER_VIRTUAL/PROF measure THIS process's CPU. Under HVPatch
            // every guest process shares the carrier, so the carrier-wide
            // counters would charge siblings' CPU to this timer; read the
            // task's own threads instead. A vanished task ends the timer.
            let cpu_now = || {
                target
                    .task()
                    .map(|task| task.self_cpu_ns_including_active())
            };
            let Some(start_ns) = cpu_now() else {
                return;
            };
            let mut cpu_due_ns = start_ns.saturating_add(spec.value);
            loop {
                if !slot.generation_matches(generation) {
                    return;
                }
                let Some(now_ns) = cpu_now() else {
                    return;
                };
                if now_ns >= cpu_due_ns {
                    let siginfo = crate::linux_abi::LinuxSiginfo::kernel(signum);
                    if !target.deliver(signum, Some(siginfo)) {
                        return;
                    }
                    if spec.interval == 0 {
                        slot.retire_one_shot(generation);
                        return;
                    }
                    cpu_due_ns = now_ns.saturating_add(spec.interval);
                } else {
                    let diff = cpu_due_ns - now_ns;
                    let delay_ns = carrick_timer_core::itimer::cpu_timer_recheck_delay_ns(
                        carrick_timer_core::CpuNs(diff),
                    );
                    std::thread::sleep(std::time::Duration::from_nanos(delay_ns.raw()));
                }
            }
        }

        std::thread::sleep(std::time::Duration::from_nanos(spec.value));

        loop {
            if !slot.generation_matches(generation) {
                return;
            }
            let siginfo = crate::linux_abi::LinuxSiginfo::kernel(signum);
            if !target.deliver(signum, Some(siginfo)) {
                return;
            }
            if spec.interval == 0 {
                slot.retire_one_shot(generation);
                return;
            }
            std::thread::sleep(std::time::Duration::from_nanos(spec.interval));
        }
    }
}

impl Drop for ProcessTimerDelivery {
    fn drop(&mut self) {
        for slot in &self.slots {
            slot.replace(None);
        }
    }
}

impl carrick_hal::TimerDelivery for ProcessTimerDelivery {
    fn owns_itimer_state(&self) -> bool {
        true
    }

    fn arm_itimer(
        &self,
        which: usize,
        spec: carrick_hal::TimerSpecNs,
        _needs_periodic: bool,
        signum: i32,
    ) -> bool {
        let Some(slot) = self.slots.get(which).cloned() else {
            return false;
        };
        let generation = slot.replace(Some(spec));
        let target = self.target.clone();
        let pid = self.target.task.id.raw();
        let _ = std::thread::Builder::new()
            .name(format!("carrick-hvpatch-itimer-{pid}-{which}"))
            .spawn(move || {
                Self::drive_itimer(target, slot, which, generation, spec, signum);
            });
        true
    }

    fn disarm_itimer(&self, which: usize) {
        if let Some(slot) = self.slots.get(which) {
            slot.replace(None);
        }
    }

    fn arm_posix(
        &self,
        id: i32,
        spec: carrick_hal::TimerSpecNs,
    ) -> Option<carrick_hal::PosixTimerSpec> {
        let armed = carrick_timer_core::posix::arm(id, spec)?;
        if spec.value > 0 {
            let target = self.target.clone();
            let signum = armed.signum;
            let generation = armed.generation;
            let slot = armed.slot.clone();
            let target_tid = armed.target_tid;
            let target_cpu = target.clone();
            let si_value = armed.si_value;
            let cpu_now: Option<std::sync::Arc<dyn Fn() -> Option<u64> + Send + Sync>> =
                if carrick_timer_core::posix::is_process_cpu_clock(slot.clock_id) {
                    // CLOCK_PROCESS_CPUTIME_ID or dynamic per-process clock
                    Some(std::sync::Arc::new(move || {
                        let task = target_cpu.task()?;
                        Some(
                            task.self_cpu_ns_including_active()
                                .saturating_add(task.self_system_cpu_us().saturating_mul(1000)),
                        )
                    }))
                } else if carrick_timer_core::posix::is_thread_cpu_clock(slot.clock_id) {
                    // CLOCK_THREAD_CPUTIME_ID or dynamic per-thread clock
                    Some(std::sync::Arc::new(move || {
                        let task = target_cpu.task()?;
                        if let Some(tid) = target_tid {
                            let linux_tid = crate::kernel::LinuxTid::from_abi_positive(tid).ok()?;
                            let thread = task.thread(linux_tid)?;
                            Some(thread.total_cpu_ns_including_active())
                        } else {
                            Some(
                                task.self_cpu_ns_including_active()
                                    .saturating_add(task.self_system_cpu_us().saturating_mul(1000)),
                            )
                        }
                    }))
                } else {
                    None
                };
            let on_fire = move || {
                let siginfo = crate::linux_abi::LinuxSiginfo::timer(signum, id, 0, si_value);
                if let Some(tid) = target_tid {
                    target.deliver_to_thread(tid, signum, Some(siginfo));
                } else {
                    target.deliver(signum, Some(siginfo));
                }
            };
            let _ = std::thread::Builder::new()
                .name(format!("carrick-hvpatch-ptimer-{id}"))
                .spawn(move || {
                    carrick_timer_core::posix::run_fallback_with_cpu(
                        slot, generation, spec, cpu_now, on_fire,
                    );
                });
        }
        Some(armed.old)
    }

    fn disarm_posix(&self, id: i32) {
        let _ = carrick_timer_core::posix::arm(id, carrick_hal::TimerSpecNs::DISARM);
    }

    fn current_arm(&self, _which: usize) -> Option<carrick_hal::TimerArm> {
        // HVPatch interval timers are not inherited across fork. Exec retains
        // this delivery object with its dispatcher, so no replay seam is needed.
        None
    }
}

/// Test doubles for the carrier handle. An inline module rather than loose
/// `cfg`-gated items so every tool that classifies source by test scope (the
/// K1 callsite census among them) sees them as the test code they are.
///
/// Reachable through the `test-support` feature as well as `cfg(test)`,
/// because the consumers are a SIBLING crate's tests: carrick-runtime's own
/// suites and `carrick-kernel-example`'s backend both build a kernel-side
/// process without a VM from these.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    // Test-only code that a sibling crate compiles through `test-support`,
    // so `cfg(test)` is not set for it and clippy's
    // `allow-{unwrap,expect,panic}-in-tests` does not apply. The doubles are
    // still test code: an invariant they cannot satisfy is a broken fixture,
    // not a runtime condition. The one place a caller can meaningfully
    // recover -- booting the kernel graph -- returns `Result` instead
    // (`TestCarrierProcess::new`).
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

    use std::num::{NonZeroU16, NonZeroU64};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use carrick_guest_mem::Gpa;
    use carrick_hal::stage1_mm::Stage1MmProjection;

    use super::CarrierProcess;

    /// A fixed `(ASID, stage-1 root)` binding for kernel-side tests that need
    /// an mm backend or a stage-1 projection without a carrier.
    pub fn test_mm_binding(asid: u16, stage1_root: u64) -> crate::kernel::MmBinding {
        let asid = crate::kernel::Asid::from_registry_allocation(
            NonZeroU16::new(asid).expect("nonzero test ASID"),
        );
        let root = crate::kernel::Stage1Root::for_aarch64_4k(Gpa(stage1_root))
            .expect("aligned stage-1 root");
        crate::kernel::MmBinding::for_aarch64(asid, root)
    }

    /// Kernel-side stand-in for the carrier's stage-1 lease: a fixed binding
    /// at ASID generation 1 and a COW invalidation counter, which is all the
    /// projection seam asks of an mm. It is minted by no carrier and holds no
    /// page tables, so a dispatcher or kernel fixture bound over it never
    /// touches the carrier's ASID pool.
    #[derive(Debug)]
    pub struct TestStage1MmProjection {
        binding: crate::kernel::MmBinding,
        cow_invalidation_generation: AtomicU64,
    }

    impl TestStage1MmProjection {
        /// A projection over one fixed `(ASID, stage-1 root)` binding.
        pub fn new(binding: crate::kernel::MmBinding) -> Self {
            Self {
                binding,
                cow_invalidation_generation: AtomicU64::new(0),
            }
        }

        /// The binding this projection publishes, so a fixture can bind an
        /// `MmBackend` over the same one.
        pub fn binding(&self) -> crate::kernel::MmBinding {
            self.binding
        }
    }

    impl Stage1MmProjection for TestStage1MmProjection {
        fn foreign_mm_binding(&self) -> carrick_hal::ForeignMmBinding {
            let asid = carrick_hal::ForeignAsid::from_kernel_allocation(
                NonZeroU16::new(self.binding.asid.raw()).expect("nonzero test ASID"),
            );
            carrick_hal::ForeignMmBinding::for_aarch64(asid, self.binding.stage1_root.gpa())
        }

        fn foreign_stage1_identity(
            &self,
            mm: carrick_hal::ForeignMmId,
        ) -> carrick_hal::ForeignStage1Identity {
            let binding = self.foreign_mm_binding();
            let asid_generation = carrick_hal::ForeignAsidGeneration::from_runtime_binding(
                binding.asid(),
                NonZeroU64::new(1).expect("nonzero test ASID generation"),
            );
            carrick_hal::ForeignStage1Identity::new(mm, binding, asid_generation)
                .expect("test stage-1 identity")
        }

        fn publish_foreign_cow_invalidation(
            &self,
        ) -> carrick_hal::ForeignCowInvalidationGeneration {
            let generation = self
                .cow_invalidation_generation
                .fetch_add(1, Ordering::AcqRel)
                + 1;
            carrick_hal::ForeignCowInvalidationGeneration::from_runtime_publication(
                NonZeroU64::new(generation).expect("nonzero test COW invalidation generation"),
            )
        }
    }

    /// In-crate `MmBackend` double: the fixed binding a test hands it, plus the
    /// VMA source and frame-inventory binding a carrier attaches at dispatcher
    /// bind time, so a bound test process snapshots the way a stage-1 backend
    /// does (same three tables, same changed-during-observation check). Unbound
    /// it reports an empty address space at revision 1, which is what
    /// `kernel/exec.rs`'s tests relied on before it was promoted here.
    pub struct TestMmBackend {
        binding: crate::kernel::MmBinding,
        vma_source: parking_lot::RwLock<Option<crate::kernel::SharedVmaSnapshotSource>>,
        inventory: parking_lot::RwLock<
            Option<(std::sync::Weak<crate::kernel::Kernel>, crate::kernel::MmId)>,
        >,
        revision: std::sync::atomic::AtomicU64,
    }

    impl TestMmBackend {
        /// An unbound backend over `binding`: empty address space, revision 1.
        pub fn new(binding: crate::kernel::MmBinding) -> Self {
            Self {
                binding,
                vma_source: parking_lot::RwLock::new(None),
                inventory: parking_lot::RwLock::new(None),
                revision: std::sync::atomic::AtomicU64::new(1),
            }
        }

        /// Attach the frame inventory of `mm` on `kernel`, the way a carrier
        /// bind does, so a snapshot reports this mm's mappings.
        pub fn bind_inventory(&self, kernel: &Arc<crate::kernel::Kernel>, mm: crate::kernel::MmId) {
            *self.inventory.write() = Some((Arc::downgrade(kernel), mm));
            self.revision
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }

        /// Attach the VMA snapshot source a carrier bind publishes.
        pub fn bind_vma_source(&self, source: crate::kernel::SharedVmaSnapshotSource) {
            *self.vma_source.write() = Some(source);
            self.revision
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }

        /// Whether a carrier bind attached a VMA source, for tests of the bind
        /// path itself.
        pub fn vma_source_bound(&self) -> bool {
            self.vma_source.read().is_some()
        }
    }

    impl std::fmt::Debug for TestMmBackend {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("TestMmBackend")
                .field("binding", &self.binding)
                .field("vma_source_bound", &self.vma_source_bound())
                .field("inventory_bound", &self.inventory.read().is_some())
                .finish()
        }
    }

    impl crate::kernel::MmBackend for TestMmBackend {
        fn snapshot(
            &self,
            deadline: std::time::Instant,
        ) -> Result<crate::kernel::MmBackendSnapshot, crate::kernel::SnapshotError> {
            use std::sync::atomic::Ordering;

            let before = self.revision.load(Ordering::Acquire);
            let vma_source = self.vma_source.read().clone();
            let inventory = self.inventory.read().clone();
            let (vmas, vma_revision) = match &vma_source {
                Some(source) => {
                    let snapshot = source.snapshot(deadline)?;
                    (snapshot.vmas, Some(snapshot.revision))
                }
                None => (Vec::new(), None),
            };
            let (mapping_ids, frame_inventory_revision) = match inventory
                .and_then(|(kernel, mm)| kernel.upgrade().map(|kernel| (kernel, mm)))
            {
                Some((kernel, mm)) => {
                    let frames = kernel
                        .frame_inventory()
                        .snapshot_for_mm_until(mm, deadline)
                        .ok_or_else(|| {
                            if std::time::Instant::now() >= deadline {
                                crate::kernel::SnapshotError::TimedOut
                            } else {
                                crate::kernel::SnapshotError::Busy
                            }
                        })?;
                    (
                        frames
                            .mappings
                            .into_iter()
                            .map(|mapping| mapping.mapping)
                            .collect(),
                        Some(frames.revision),
                    )
                }
                None => (Vec::new(), None),
            };
            let after = self.revision.load(Ordering::Acquire);
            let vma_source_moved = match (&vma_source, vma_revision) {
                (Some(source), Some(revision)) => source.revision() != revision,
                _ => false,
            };
            if before != after || vma_source_moved {
                return Err(crate::kernel::SnapshotError::ChangedDuringObservation);
            }
            Ok(crate::kernel::MmBackendSnapshot {
                revision: after,
                binding: self.binding,
                vmas,
                vma_revision,
                mapping_ids,
                frame_inventory_revision,
            })
        }

        fn revision(&self) -> u64 {
            self.revision.load(std::sync::atomic::Ordering::Acquire)
        }

        fn vma_revision(
            &self,
            _deadline: std::time::Instant,
        ) -> Result<Option<crate::kernel::VmaRevision>, crate::kernel::SnapshotError> {
            Ok(self
                .vma_source
                .read()
                .as_ref()
                .map(|source| source.revision()))
        }
    }

    /// Kernel-only stand-in for the HVPatch carrier's process handle, for
    /// dispatch tests that bind a dispatcher to a real kernel graph without a VM.
    ///
    /// It publishes a root task exactly the way the carrier's own test fixture
    /// does (`RootBootstrap::with_mm_backend` + `Kernel::bootstrap_root`, the
    /// backend's inventory bound to the root mm), backed by a [`TestMmBackend`]
    /// instead of a stage-1 backend and with no `MmResources`. The one carrier
    /// fact the dispatcher bind path cannot do without is a stage-1
    /// projection: `bind_hvpatch_process_exact` builds the foreign-mm mutation
    /// authority from it and fail-stops otherwise, so the double answers with
    /// a [`TestStage1MmProjection`] over the same binding its backend publishes.
    pub struct TestCarrierProcess {
        binding: crate::kernel::KernelTaskBinding,
        backend: Arc<TestMmBackend>,
        stage1: Arc<TestStage1MmProjection>,
        mm_access: Option<crate::kernel::MmAccessAuthority>,
    }

    impl TestCarrierProcess {
        /// Boot a root task `pid` on its own kernel graph and return the handle
        /// together with the root's exact context.
        ///
        /// Fallible rather than panicking: booting a kernel graph is the one
        /// step here a caller can meaningfully report on (a duplicate root pid
        /// or an exhausted id registry), and an out-of-crate caller compiling
        /// this through `test-support` is not under `cfg(test)`.
        pub fn new(
            pid: i32,
        ) -> Result<(Self, crate::kernel::KernelContext), crate::kernel::KernelError> {
            let stage1 = Arc::new(TestStage1MmProjection::new(test_mm_binding(1, 0x4000)));
            let backend = Arc::new(TestMmBackend::new(stage1.binding()));
            let bootstrap = crate::kernel::RootBootstrap::with_mm_backend(
                pid,
                carrick_hal::ThreadId::synthetic_for_tests(pid),
                Arc::clone(&backend) as Arc<dyn crate::kernel::MmBackend>,
                "hvpatch-test-root".to_owned(),
                Arc::new(carrick_hal::NullHostSignalBridge::default()),
            )?;
            let (kernel, root) = crate::kernel::Kernel::bootstrap_root(bootstrap)?;
            backend.bind_inventory(&kernel, root.shared().mm().id());
            Ok((
                Self {
                    binding: root.task_binding(),
                    backend,
                    stage1,
                    mm_access: None,
                },
                root,
            ))
        }

        /// Enable the foreign-MM access facade the carrier installs when its
        /// engine exposes a foreign-MM endpoint, without a production authority
        /// constructor on the dispatcher.
        pub fn enable_mm_access_for_tests(&mut self) {
            self.mm_access = Some(crate::kernel::MmAccessAuthority::new());
        }

        /// The `MmBackend` double this process publishes, for a fixture that
        /// needs to bind a VMA source or read the snapshot revision.
        pub fn backend(&self) -> &Arc<TestMmBackend> {
            &self.backend
        }

        /// The binding the double's projection and backend both publish.
        pub fn stage1_binding(&self) -> crate::kernel::MmBinding {
            self.stage1.binding()
        }
    }

    impl CarrierProcess for TestCarrierProcess {
        fn kernel_graph(&self) -> &Arc<crate::kernel::Kernel> {
            self.binding.kernel()
        }

        fn task_key(&self) -> crate::kernel::TaskKey {
            self.binding.task_key()
        }

        fn task_binding(&self) -> crate::kernel::KernelTaskBinding {
            self.binding.clone()
        }

        fn context_for_linux_tid(
            &self,
            tid: crate::kernel::LinuxTid,
        ) -> Result<crate::kernel::KernelContext, crate::kernel::KernelError> {
            self.binding.capture(tid)
        }

        fn mm_access_authority(&self) -> Option<&crate::kernel::MmAccessAuthority> {
            self.mm_access.as_ref()
        }

        fn stage1_mm_projection(
            &self,
        ) -> Result<Arc<dyn Stage1MmProjection>, crate::run_result::RuntimeError> {
            Ok(Arc::clone(&self.stage1) as Arc<dyn Stage1MmProjection>)
        }

        fn bind_vma_source(&self, source: crate::kernel::SharedVmaSnapshotSource) {
            self.backend.bind_vma_source(source);
        }

        fn bind_mm_mutation_authority(
            &self,
            authority: crate::dispatch::mm_mutation::ForeignMmMutationAuthority,
        ) {
            let context = self
                .context_for_linux_tid(crate::kernel::LinuxTid::for_task_leader(self.task_id()))
                .expect("test carrier process leader context");
            context
                .shared()
                .mm()
                .install_foreign_mm_mutation_authority_for_test(authority);
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
pub use test_support::{
    TestCarrierProcess, TestMmBackend, TestStage1MmProjection, test_mm_binding,
};

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::dispatch::SyscallDispatcher;
    use crate::kernel::MmBackend as _;

    /// The dispatcher bind path attaches its VMA source and the frame
    /// inventory to the process's mm backend; on the double both tables must
    /// land, or a test process would snapshot differently from a carrier one.
    #[test]
    fn dispatcher_bind_attaches_both_snapshot_tables_to_the_test_backend() {
        let (process, root) = TestCarrierProcess::new(83_900).expect("test carrier process");
        assert!(!process.backend().vma_source_bound());
        let process = Arc::new(process);
        let dispatcher = SyscallDispatcher::new();
        dispatcher.bind_hvpatch_process(process.clone());

        let bound = dispatcher.hvpatch_process().expect("bound carrier process");
        assert_eq!(bound.task_key(), root.task().key());
        assert_eq!(bound.pid(), 83_900);
        let projection = bound
            .stage1_mm_projection()
            .expect("bound carrier process projection");
        assert!(process.backend().vma_source_bound());
        let snapshot = process
            .backend()
            .snapshot(Instant::now() + Duration::from_secs(1))
            .expect("bound test backend snapshot");
        assert_eq!(snapshot.binding, process.stage1_binding());
        assert_eq!(
            projection.foreign_mm_binding(),
            carrick_hal::ForeignMmBinding::for_aarch64(
                carrick_hal::ForeignAsid::from_kernel_allocation(
                    std::num::NonZeroU16::new(snapshot.binding.asid.raw()).expect("test ASID"),
                ),
                snapshot.binding.stage1_root.gpa(),
            )
        );
        assert!(snapshot.vma_revision.is_some());
        assert!(snapshot.frame_inventory_revision.is_some());
    }
}
