//! The trap source and the run loop: scripted Linux tasks on host threads.
//!
//! A real backend observes a guest's syscall entry and turns it into a
//! `SyscallRequest`; this one reads the next [`Step`] of a script instead.
//! Each Linux task is one host thread owning its own `SyscallDispatcher`
//! (forked from its parent's, exactly as the carrier forks one per Linux
//! process), its own `TaskMemory` and its own [`ExampleProcess`] handle.
//! What the loop then does with every `DispatchOutcome` it meets is the
//! backend contract, and each arm below names the carrier arm it mirrors.
//!
//! Waits never park the thread inside the kernel: a `WaitOnHvpatchChild` or
//! `WaitOnFds` outcome is re-dispatched after a `yield_now`, bounded by
//! [`WAIT_BOUND`] so a lost wake is a failed run, not a hang.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use carrick_abi::{LINUX_BOOTSTRAP_PID, LinuxCloneFlags, LinuxErrno};
use carrick_guest_mem::MemoryError;
use carrick_hal::{NullGuestTimerBridge, NullHostSignalBridge};
use carrick_kernel::compat::CompatReporter;
use carrick_kernel::dispatch::mm_authority::PrepareDispatchMmForkError;
use carrick_kernel::dispatch::{CarrierBridges, DispatchError, SyscallDispatcher};
use carrick_kernel::kernel::continuation::CarrierWaitService;
use carrick_kernel::kernel::objects::ExecutionGeneration;
use carrick_kernel::kernel::{
    CarrierProcess, ChildExitSignal, CloneObjectMode, ClonePlan, ClonePlanError, KernelError,
    KernelOperationError, KernelTaskBinding, LinuxWaitStatus, Scheduler, SnapshotError, TaskKey,
};
use carrick_kernel::thread::ThreadId;
use parking_lot::{Condvar, Mutex};

use crate::memory::TaskMemory;
use crate::operand::{Expect, Operand, Save, Step, Syscall};
use crate::process::{AddressSpace, AddressSpaceError, AsidAllocator, ExampleProcess};
use crate::report::{Completion, Output, RunReport};

/// The bound on every wait in this backend: a child that has not exited, a
/// pipe that has not been written, a task thread that has not finished. A
/// wake that never comes fails the run with [`ExampleError::WaitTimedOut`].
pub const WAIT_BOUND: Duration = Duration::from_secs(5);

/// The pid of the root Linux task: `init` of its pid namespace, exactly as
/// the carrier numbers its root.
const ROOT_PID: i32 = LINUX_BOOTSTRAP_PID as i32;

/// Specification of an output buffer: (argument index, guest address, length).
type OutBufferSpec = (usize, u64, usize);

/// Resolved syscall arguments and output buffer specifications.
type ResolvedArgs = ([u64; 6], Vec<OutBufferSpec>);

/// Why a run failed.
#[derive(Debug, thiserror::Error)]
pub enum ExampleError {
    #[error("{syscall} failed with errno {}", .errno.get())]
    Errno {
        syscall: &'static str,
        errno: LinuxErrno,
    },
    #[error("task {pid} expected {expected} on {label}, got {actual}")]
    Expectation {
        pid: i32,
        label: &'static str,
        expected: String,
        actual: String,
    },
    #[error("a VM-less backend cannot interpret this outcome: {0}")]
    Unsupported(String),
    #[error("script: {0}")]
    Script(String),
    #[error("{0} did not complete within {bound} s", bound = WAIT_BOUND.as_secs())]
    WaitTimedOut(&'static str),
    #[error("dispatch: {0}")]
    Dispatch(#[from] DispatchError),
    #[error("kernel: {0}")]
    Kernel(#[from] KernelError),
    #[error("kernel operation: {0}")]
    KernelOperation(#[from] KernelOperationError),
    #[error("clone plan: {0}")]
    ClonePlan(#[from] ClonePlanError),
    #[error("address space: {0}")]
    AddressSpace(#[from] AddressSpaceError),
    #[error("dispatcher fork preparation: {0}")]
    DispatcherFork(#[from] PrepareDispatchMmForkError),
    #[error("dispatcher fork install: {0}")]
    DispatcherForkInstall(#[from] SnapshotError),
    #[error("guest memory: {0}")]
    Memory(#[from] MemoryError),
    #[error("spawn a task thread: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("task {pid} failed: {error}")]
    Task { pid: i32, error: Box<ExampleError> },
}

/// The backend: one kernel per run, one host thread per Linux task.
pub struct ScriptedBackend {
    bridges: CarrierBridges,
}

impl Default for ScriptedBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptedBackend {
    /// A backend on `carrick-hal`'s Null bridges: no host signal source and
    /// no timer wheel, which is all a scripted task needs.
    pub fn new() -> Self {
        Self {
            bridges: CarrierBridges {
                host_signal: Arc::new(NullHostSignalBridge::default()),
                timers: Arc::new(NullGuestTimerBridge::default()),
            },
        }
    }

    /// Boot the root task and run `script` on the calling thread; every
    /// child it forks runs on its own thread and is joined (bounded) before
    /// the report is returned.
    ///
    /// The bootstrap is the carrier's: a dispatcher on the backend's bridges,
    /// a root task over the backend's own `MmBackend`, and the dispatcher
    /// bound to the root's [`ExampleProcess`] so child waits resolve in the
    /// kernel graph.
    pub fn run_root(self, script: Vec<Step>) -> Result<RunReport, ExampleError> {
        let asids = AsidAllocator::new();
        let space = AddressSpace::allocate(&asids)?;
        let (process, root_context) = ExampleProcess::boot_root(
            ROOT_PID,
            "example-root",
            Arc::clone(&self.bridges.host_signal),
            space,
        )?;
        let scheduler = Arc::new(Scheduler::new(Arc::clone(root_context.kernel())));
        let wait_service = CarrierWaitService::try_new(scheduler).map_err(|e| {
            ExampleError::Unsupported(format!("carrier wait service init failed: {e}"))
        })?;

        let shared = Arc::new(Shared {
            asids,
            ledger: Mutex::new(Ledger::default()),
            children: Mutex::new(Vec::new()),
            dispatches: AtomicUsize::new(0),
            parked_notifications: Mutex::new(HashSet::new()),
            parked_condvar: Condvar::new(),
            wait_service,
            process_bindings: Mutex::new(HashMap::new()),
        });
        shared
            .process_bindings
            .lock()
            .insert(process.task_key(), process.task_binding());
        let process = Arc::new(process);
        let dispatcher = SyscallDispatcher::with_bridges(self.bridges);
        dispatcher.bind_hvpatch_process(Arc::clone(&process) as Arc<dyn CarrierProcess>);
        if let Some(failure) = process.take_bind_failure() {
            return Err(failure.into());
        }
        let root_generation = crate::driver::seed_initial_task_state(&root_context)?;
        let mut root = Task {
            dispatcher,
            process,
            memory: TaskMemory::new(),
            slots: Vec::new(),
            last_child: None,
            reporter: CompatReporter::default(),
            execution_generation: root_generation,
        };
        shared.ledger.lock().tasks_started = 1;
        let root_exit = root.run(&script, &shared);
        // Every child thread is joined before the verdict, whatever the root
        // did: a task that outlives its parent's script is a backend defect.
        let joined = Self::join_children(&shared);
        let exit_code = root_exit?;
        joined?;
        let ledger = std::mem::take(&mut *shared.ledger.lock());
        if let Some((pid, error)) = ledger.task_failures.into_iter().next() {
            return Err(ExampleError::Task {
                pid,
                error: Box::new(error),
            });
        }
        Ok(RunReport {
            exit_code,
            completions: ledger.completions,
            outputs: ledger.outputs,
            deaths: ledger.deaths,
            tasks_started: ledger.tasks_started,
            dispatches: shared.dispatches.load(Ordering::SeqCst),
            dispatch_events: ledger.dispatch_events,
        })
    }

    /// Join every task thread, each bounded by [`WAIT_BOUND`]. A thread that
    /// is still running past the bound is left detached and reported.
    fn join_children(shared: &Shared) -> Result<(), ExampleError> {
        let deadline = Instant::now() + WAIT_BOUND;
        loop {
            let Some(handle) = shared.children.lock().pop() else {
                return Ok(());
            };
            while !handle.is_finished() {
                if Instant::now() >= deadline {
                    return Err(ExampleError::WaitTimedOut("a child task thread"));
                }
                thread::yield_now();
            }
            handle
                .join()
                .map_err(|_| ExampleError::Script("a child task thread panicked".to_owned()))?;
        }
    }
}

/// State every task of a run shares.
pub(crate) struct Shared {
    pub(crate) asids: AsidAllocator,
    pub(crate) ledger: Mutex<Ledger>,
    pub(crate) children: Mutex<Vec<JoinHandle<()>>>,
    pub(crate) dispatches: AtomicUsize,
    pub(crate) parked_notifications: Mutex<HashSet<(i32, &'static str)>>,
    pub(crate) parked_condvar: Condvar,
    pub(crate) wait_service: CarrierWaitService,
    pub(crate) process_bindings: Mutex<HashMap<TaskKey, KernelTaskBinding>>,
}

impl Shared {
    pub(crate) fn notify_parked(&self, pid: i32, label: &'static str) {
        self.parked_notifications.lock().insert((pid, label));
        self.parked_condvar.notify_all();
    }

    pub(crate) fn await_parked(
        &self,
        pid: i32,
        label: &'static str,
        timeout: Duration,
    ) -> Result<(), ExampleError> {
        let deadline = Instant::now() + timeout;
        let mut parked = self.parked_notifications.lock();
        while !parked.contains(&(pid, label)) {
            let now = Instant::now();
            if now >= deadline {
                return Err(ExampleError::WaitTimedOut(label));
            }
            let remaining = deadline.saturating_duration_since(now);
            let timed_out = self
                .parked_condvar
                .wait_for(&mut parked, remaining)
                .timed_out();
            if timed_out && !parked.contains(&(pid, label)) {
                return Err(ExampleError::WaitTimedOut(label));
            }
        }
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct Ledger {
    pub(crate) completions: Vec<Completion>,
    pub(crate) outputs: Vec<Output>,
    pub(crate) deaths: Vec<(i32, i32)>,
    pub(crate) dispatch_events: Vec<(i32, &'static str)>,
    pub(crate) tasks_started: usize,
    pub(crate) task_failures: Vec<(i32, ExampleError)>,
}

/// How one issued syscall ended internally.
#[derive(Debug)]
pub(crate) enum InternalCompletion {
    Returned(i64),
    Errno(LinuxErrno),
    Exit(i32),
    Death(i32),
    Fork { flags: u64, exit_signal: u32 },
}

/// One Linux task: a host thread's worth of backend state.
pub(crate) struct Task {
    pub(crate) dispatcher: SyscallDispatcher,
    pub(crate) process: Arc<ExampleProcess>,
    pub(crate) memory: TaskMemory,
    pub(crate) slots: Vec<i64>,
    pub(crate) last_child: Option<i32>,
    pub(crate) reporter: CompatReporter,
    pub(crate) execution_generation: ExecutionGeneration,
}

impl Task {
    /// Run `script` to its `exit_group`, returning the exit code.
    fn run(&mut self, script: &[Step], shared: &Arc<Shared>) -> Result<i32, ExampleError> {
        let mut steps = script.iter();
        while let Some(step) = steps.next() {
            match step {
                Step::ChildMarker(_) => {
                    return Err(ExampleError::Script(
                        "child_marker without a preceding fork".to_owned(),
                    ));
                }
                Step::HostSleepMs(ms) => {
                    thread::sleep(Duration::from_millis(*ms));
                }
                Step::AwaitParked { pid, label } => {
                    shared.await_parked(*pid, label, WAIT_BOUND)?;
                }
                Step::Sys(syscall) => {
                    let (args, outs) = self.resolve(syscall)?;
                    let completion = crate::driver::drive(self, syscall, args, shared)?;
                    match completion {
                        InternalCompletion::Fork { flags, exit_signal } => {
                            let Some(Step::ChildMarker(child_script)) = steps.next() else {
                                return Err(ExampleError::Script(
                                    "fork must be followed by child_marker".to_owned(),
                                ));
                            };
                            let child_pid =
                                self.on_fork(flags, exit_signal, child_script, shared)?;
                            self.last_child = Some(child_pid);
                            self.finish_syscall(syscall, Ok(child_pid as i64), outs, shared)?;
                        }
                        InternalCompletion::Exit(code) => {
                            let pid = self.process.pid();
                            shared.ledger.lock().completions.push(Completion {
                                pid,
                                label: syscall.label,
                                result: Ok(code as i64),
                            });
                            let expectation_check = match &syscall.expect {
                                Expect::Any => Ok(()),
                                Expect::Ret(expected) => Err(ExampleError::Expectation {
                                    pid,
                                    label: syscall.label,
                                    expected: format!("return value {expected}"),
                                    actual: format!("exit code {code}"),
                                }),
                                Expect::Errno(expected) => Err(ExampleError::Expectation {
                                    pid,
                                    label: syscall.label,
                                    expected: format!("errno {}", expected.get()),
                                    actual: format!("exit code {code}"),
                                }),
                                Expect::Death(sig) => Err(ExampleError::Expectation {
                                    pid,
                                    label: syscall.label,
                                    expected: format!("death by signal {sig}"),
                                    actual: format!("exit code {code}"),
                                }),
                            };
                            self.on_exit(code, shared)?;
                            expectation_check?;
                            return Ok(code);
                        }
                        InternalCompletion::Death(sig) => {
                            let pid = self.process.pid();
                            shared.ledger.lock().deaths.push((pid, sig));
                            let expectation_check = match &syscall.expect {
                                Expect::Any => Ok(()),
                                Expect::Death(expected) if *expected == sig => Ok(()),
                                Expect::Death(expected) => Err(ExampleError::Expectation {
                                    pid,
                                    label: syscall.label,
                                    expected: format!("death by signal {expected}"),
                                    actual: format!("death by signal {sig}"),
                                }),
                                Expect::Ret(expected) => Err(ExampleError::Expectation {
                                    pid,
                                    label: syscall.label,
                                    expected: format!("return value {expected}"),
                                    actual: format!("death by signal {sig}"),
                                }),
                                Expect::Errno(expected) => Err(ExampleError::Expectation {
                                    pid,
                                    label: syscall.label,
                                    expected: format!("errno {}", expected.get()),
                                    actual: format!("death by signal {sig}"),
                                }),
                            };
                            self.on_exit(sig, shared)?;
                            expectation_check?;
                            return Ok(sig);
                        }
                        InternalCompletion::Returned(value) => {
                            self.finish_syscall(syscall, Ok(value), outs, shared)?;
                        }
                        InternalCompletion::Errno(errno) => {
                            self.finish_syscall(syscall, Err(errno), outs, shared)?;
                        }
                    }
                }
            }
        }
        Err(ExampleError::Script(
            "script ended without exit_group".to_owned(),
        ))
    }

    /// The child thread's body: run, and record a failure for the root to
    /// report.
    fn run_child(mut self, script: &[Step], shared: &Arc<Shared>) {
        let pid = self.process.pid();
        if let Err(error) = self.run(script, shared) {
            shared.ledger.lock().task_failures.push((pid, error));
        }
    }

    fn resolve(&mut self, syscall: &Syscall) -> Result<ResolvedArgs, ExampleError> {
        let mut args = [0u64; 6];
        let mut outs = Vec::new();
        for (i, op) in syscall.args.iter().enumerate() {
            args[i] = match op {
                Operand::Lit(v) => *v as u64,
                Operand::Slot(s) => self
                    .slots
                    .get(*s)
                    .copied()
                    .map(|v| v as u64)
                    .ok_or_else(|| ExampleError::Script(format!("slot {s} is unset")))?,
                Operand::LastChild => self
                    .last_child
                    .map(|pid| pid as u64)
                    .ok_or_else(|| ExampleError::Script("no child has been forked".to_owned()))?,
                Operand::Bytes(b) => self.memory.put(b)?,
                Operand::CStr(s) => {
                    let mut b = s.as_bytes().to_vec();
                    b.push(0);
                    self.memory.put(&b)?
                }
                Operand::Out(n) => {
                    let a = self.memory.alloc_zeroed(*n)?;
                    outs.push((i, a, *n));
                    a
                }
            };
        }
        Ok((args, outs))
    }

    fn save_slot(&mut self, slot: usize, value: i64) {
        if self.slots.len() <= slot {
            self.slots.resize(slot + 1, 0);
        }
        self.slots[slot] = value;
    }

    fn finish_syscall(
        &mut self,
        syscall: &Syscall,
        result: Result<i64, LinuxErrno>,
        outs: Vec<OutBufferSpec>,
        shared: &Arc<Shared>,
    ) -> Result<(), ExampleError> {
        let pid = self.process.pid();
        let mut captured_outputs = Vec::new();
        for (arg_idx, addr, len) in &outs {
            let bytes = self.memory.read(*addr, *len)?;
            captured_outputs.push(Output {
                pid,
                label: syscall.label,
                arg: *arg_idx,
                bytes,
            });
        }

        {
            let mut ledger = shared.ledger.lock();
            ledger.completions.push(Completion {
                pid,
                label: syscall.label,
                result,
            });
            ledger.outputs.extend(captured_outputs);
        }

        // Validate expectations before applying any saves so a failed syscall cannot contaminate state.
        match &syscall.expect {
            Expect::Any => {
                if let Err(errno) = result {
                    return Err(ExampleError::Errno {
                        syscall: syscall.label,
                        errno,
                    });
                }
            }
            Expect::Ret(expected) => match result {
                Ok(val) if val == *expected => {}
                Ok(val) => {
                    return Err(ExampleError::Expectation {
                        pid,
                        label: syscall.label,
                        expected: format!("return value {expected}"),
                        actual: format!("return value {val}"),
                    });
                }
                Err(errno) => {
                    return Err(ExampleError::Expectation {
                        pid,
                        label: syscall.label,
                        expected: format!("return value {expected}"),
                        actual: format!("errno {}", errno.get()),
                    });
                }
            },
            Expect::Errno(expected) => match result {
                Err(errno) if errno == *expected => {}
                Err(errno) => {
                    return Err(ExampleError::Expectation {
                        pid,
                        label: syscall.label,
                        expected: format!("errno {}", expected.get()),
                        actual: format!("errno {}", errno.get()),
                    });
                }
                Ok(val) => {
                    return Err(ExampleError::Expectation {
                        pid,
                        label: syscall.label,
                        expected: format!("errno {}", expected.get()),
                        actual: format!("return value {val}"),
                    });
                }
            },
            Expect::Death(sig) => {
                return Err(ExampleError::Expectation {
                    pid,
                    label: syscall.label,
                    expected: format!("death by signal {sig}"),
                    actual: format!("{result:?}"),
                });
            }
        }

        for save in &syscall.saves {
            match save {
                Save::Ret(slot) => match result {
                    Ok(val) => self.save_slot(*slot, val),
                    Err(errno) => {
                        return Err(ExampleError::Script(format!(
                            "cannot save return value on failed syscall {} ({errno:?})",
                            syscall.label
                        )));
                    }
                },
                Save::OutI32 { arg, index, slot } => {
                    let out = outs.iter().find(|(a, _, _)| a == arg).ok_or_else(|| {
                        ExampleError::Script(format!("no out buffer for arg {arg}"))
                    })?;
                    let byte_offset = index
                        .checked_mul(4)
                        .ok_or_else(|| ExampleError::Script("out_i32 index overflow".to_owned()))?;
                    let end_offset = byte_offset
                        .checked_add(4)
                        .ok_or_else(|| ExampleError::Script("out_i32 index overflow".to_owned()))?;
                    if end_offset > out.2 {
                        return Err(ExampleError::Script(format!(
                            "out_i32 index {index} (byte range {byte_offset}..{end_offset}) exceeds out buffer len {}",
                            out.2
                        )));
                    }
                    let offset = out.1 + byte_offset as u64;
                    let bytes = self.memory.read(offset, 4)?;
                    let word = <[u8; 4]>::try_from(bytes.as_slice())
                        .map_err(|_| ExampleError::Script("invalid i32 slice".to_owned()))?;
                    let val = i32::from_le_bytes(word);
                    self.save_slot(*slot, val as i64);
                }
            }
        }

        Ok(())
    }

    /// The `Fork` arm, mirroring the carrier's in-process fork through the
    /// public kernel operations only:
    ///
    /// 1. `Kernel::reserve_fork` on the clone plan the dispatcher lowered the
    ///    flags to, then `prepare_with_mm_backend` over a fresh
    ///    [`AddressSpace`] -- the child's mm is this backend's, not a VM's.
    /// 2. The child's dispatcher: `prepare_fork_mm` snapshots the parent's
    ///    dispatch-side mm metadata, and `fork_clone_with_prepared_mm_authorized`
    ///    installs it under the host-alias permit of a sole-executor mutation
    ///    guard (`with_mm_executor_mutation`), as the carrier does under its
    ///    page-table authority.
    /// 3. `PreparedFork::commit` publishes the child; `into_parts` opens its
    ///    start gate and yields the child's `KernelContext`.
    /// 4. The child's dispatcher is bound to the child's [`ExampleProcess`],
    ///    and the child runs its script on a new host thread over a copy of
    ///    the parent's memory and slots. The parent's `clone` completes with
    ///    the child's visible pid.
    ///
    /// The observers chain, the lifecycle probes and the `pidfd`/tid-store
    /// side effects of the carrier's arm have no counterpart here: the first
    /// two are instrumentation, the last were refused before this point.
    fn on_fork(
        &mut self,
        flags: u64,
        exit_signal: u32,
        child_script: &[Step],
        shared: &Arc<Shared>,
    ) -> Result<i32, ExampleError> {
        let parent = self.dispatcher.capture_one_task_context()?;
        let plan = ClonePlan::from_flags(LinuxCloneFlags::from_bits_retain(flags))?
            .with_exit_signal(ChildExitSignal::for_clone_request(exit_signal));
        let parent_pid = self.process.pid();
        let reservation = parent.kernel().reserve_fork(
            &parent,
            plan,
            format!("example-child-of-{parent_pid}"),
            None,
        )?;
        let child_pid = reservation.visible_child_id();
        let child_tid = ThreadId::from_guest_supplied_tid(child_pid);
        let space = AddressSpace::allocate(&shared.asids)?;
        let prepared = reservation.prepare_with_mm_backend(space.mm_backend(), child_tid)?;

        let parent_mm_id = parent.shared().mm().id();
        let child_mm_id = prepared.child_mm_id();
        let prepared_mm =
            self.dispatcher
                .prepare_fork_mm(parent_mm_id, child_mm_id, CloneObjectMode::Copy)?;
        let (parent_guest_pid, child_guest_pid) = (guest_pid(parent_pid)?, guest_pid(child_pid)?);
        let child_dispatcher =
            self.dispatcher
                .with_mm_executor_mutation(|dispatcher, guard| {
                    let permit = guard.host_alias_permit();
                    dispatcher.fork_clone_with_prepared_mm_authorized(
                        parent_mm_id,
                        child_mm_id,
                        parent_guest_pid,
                        child_guest_pid,
                        prepared_mm,
                        &permit,
                    )
                })??;

        let published = prepared.commit()?;
        let (child_context, _vfork_parent_wait) = published.into_parts()?;
        let child_process = Arc::new(ExampleProcess::new(&child_context, space));
        child_dispatcher
            .bind_hvpatch_process(Arc::clone(&child_process) as Arc<dyn CarrierProcess>);
        if let Some(failure) = child_process.take_bind_failure() {
            return Err(failure.into());
        }

        let child_generation = crate::driver::seed_initial_task_state(&child_context)?;
        shared
            .process_bindings
            .lock()
            .insert(child_process.task_key(), child_process.task_binding());
        let child = Task {
            dispatcher: child_dispatcher,
            process: child_process,
            memory: self.memory.clone(),
            slots: self.slots.clone(),
            last_child: None,
            reporter: CompatReporter::default(),
            execution_generation: child_generation,
        };
        let script = child_script.to_vec();
        let shared_for_child = Arc::clone(shared);
        shared.ledger.lock().tasks_started += 1;
        let handle = thread::Builder::new()
            .name(format!("linux-task-{child_pid}"))
            .spawn(move || child.run_child(&script, &shared_for_child))?;
        shared.children.lock().push(handle);
        Ok(child_pid)
    }

    /// The `Exit` arm: take this Linux process through its terminal, as the
    /// carrier's terminal path does.
    ///
    /// Linux closes every fd before the parent can observe the exit, so the
    /// file table is retired first (`retire_hvpatch_process_fds`, while the
    /// task is still registered), then the zombie is published with the
    /// `wait(2)` encoding of a normal exit, `(code & 0xff) << 8` -- the same
    /// form `RunResult::wait_status_encoding` produces for the carrier.
    /// `SIGCHLD` is not posted to the parent: a scripted task has no signal
    /// delivery, and the parent's `wait4` observes the zombie directly.
    fn on_exit(&mut self, code: i32, shared: &Arc<Shared>) -> Result<(), ExampleError> {
        let context = self.dispatcher.capture_one_task_context()?;
        self.dispatcher.retire_hvpatch_process_fds(&context);
        let status = LinuxWaitStatus::from_wait_encoding((code & 0xff) << 8);
        context.kernel().exit_task_key_eventually_notifying(
            context.task().key(),
            status,
            None,
            |parent| {
                if let Some(parent_key) = parent
                    && let Some(binding) = shared.process_bindings.lock().get(&parent_key)
                    && let Ok(snapshot) = binding.capture_signal_snapshot()
                {
                    let _ = snapshot.context().task().publish_wake_subscriptions();
                }
            },
        )?;
        Ok(())
    }
}

/// A Linux pid as the dispatcher's fork clone names it.
fn guest_pid(pid: i32) -> Result<u32, ExampleError> {
    u32::try_from(pid).map_err(|_| ExampleError::Script(format!("pid {pid} is not positive")))
}
