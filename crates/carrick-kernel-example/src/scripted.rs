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
//! Waits are parked as kernel continuations on the shared wait service, bounded
//! by [`WAIT_BOUND`] so a lost wake is a failed run, not a hang.

use std::collections::HashSet;
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
use carrick_kernel::kernel::continuation::{CarrierWaitService, ContinuationWakeToken};
use carrick_kernel::kernel::objects::ExecutionGeneration;
use carrick_kernel::kernel::{
    CarrierProcess, ChildExitSignal, CloneObjectMode, ClonePlan, ClonePlanError, KernelContext,
    KernelError, KernelOperationError, LinuxWaitStatus, Scheduler, SnapshotError, TaskKey,
};
use carrick_kernel::thread::{FutexTable, ThreadId, ThreadRegistry};
use parking_lot::{Condvar, Mutex};

use crate::memory::TaskMemory;
use crate::operand::{Expect, Layout, Operand, Save, Step, Syscall};
use crate::process::{AddressSpace, AddressSpaceError, AsidAllocator, ExampleProcess};
use crate::report::{Completion, Output, RunReport};

/// The bound on every wait in this backend: a child that has not exited, a
/// pipe that has not been written, a task thread that has not finished. A
/// wake that never comes fails the run with [`ExampleError::WaitTimedOut`].
pub const WAIT_BOUND: Duration = Duration::from_secs(5);

/// The pid of the root Linux task: `init` of its pid namespace, exactly as
/// the carrier numbers its root.
const ROOT_PID: i32 = LINUX_BOOTSTRAP_PID as i32;

/// Specification of an output buffer: (argument index, optional tag, guest address, length).
#[derive(Clone, Copy, Debug)]
pub(crate) struct OutBufferSpec {
    pub(crate) arg: usize,
    pub(crate) tag: Option<&'static str>,
    pub(crate) addr: u64,
    pub(crate) len: usize,
}

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
    #[error("task {pid} (tid {tid}) failed: {error}")]
    Task {
        pid: i32,
        tid: i32,
        error: Box<ExampleError>,
    },
}

/// The backend: one kernel per run, one host thread per Linux task.
pub struct ScriptedBackend {
    bridges: CarrierBridges,
    fs_backend: Option<Box<dyn carrick_vfs::fs_backend::FsBackend>>,
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
            fs_backend: None,
        }
    }

    /// Configure a custom filesystem backend (e.g. [`carrick_vfs::fs_backend::HostFsBackend`]).
    pub fn with_fs_backend(mut self, fs: Box<dyn carrick_vfs::fs_backend::FsBackend>) -> Self {
        self.fs_backend = Some(fs);
        self
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
            active_wait_tokens: Mutex::new(Vec::new()),
            wait_service,
            process_exit_codes: Mutex::new(std::collections::HashMap::new()),
        });
        let process = Arc::new(process);
        let mut dispatcher = SyscallDispatcher::with_bridges(self.bridges);
        if let Some(fs) = self.fs_backend {
            dispatcher.set_fs_backend(fs);
        }
        dispatcher.bind_hvpatch_process(Arc::clone(&process) as Arc<dyn CarrierProcess>);
        if let Some(failure) = process.take_bind_failure() {
            return Err(failure.into());
        }
        // Match carrier bootstrap: canonical file operations use the run's authority.
        dispatcher
            .activate_file_authority(root_context.resources().files())
            .map_err(DispatchError::FileAuthorityFatal)?;
        let root_generation =
            crate::driver::seed_initial_task_state(&root_context, process.asid_generation())?;
        let thread_registry = Arc::new(ThreadRegistry::new(ThreadId::from_guest_supplied_tid(
            ROOT_PID,
        )));
        let futex_table = Arc::new(FutexTable::new());
        let root_context_for_task = root_context.retain_exact();
        let mut root = Task {
            dispatcher: Arc::new(Mutex::new(dispatcher)),
            process,
            context: root_context_for_task,
            memory: Arc::new(Mutex::new(TaskMemory::new())),
            thread_registry,
            futex_table,
            tid: ROOT_PID,
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
        let script_exit_code = root_exit?;
        joined?;
        let ledger = std::mem::take(&mut *shared.ledger.lock());
        if let Some((pid, tid, error)) = ledger.task_failures.into_iter().next() {
            return Err(ExampleError::Task {
                pid,
                tid,
                error: Box::new(error),
            });
        }
        let exit_code = shared
            .process_exit_codes
            .lock()
            .get(&ROOT_PID)
            .copied()
            .unwrap_or(script_exit_code);
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
    pub(crate) active_wait_tokens: Mutex<Vec<(TaskKey, ContinuationWakeToken)>>,
    pub(crate) wait_service: CarrierWaitService,
    pub(crate) process_exit_codes: Mutex<std::collections::HashMap<i32, i32>>,
}

impl Shared {
    pub(crate) fn register_active_token(&self, task_key: TaskKey, token: ContinuationWakeToken) {
        self.active_wait_tokens.lock().push((task_key, token));
    }

    pub(crate) fn unregister_active_token(&self, token: ContinuationWakeToken) {
        self.active_wait_tokens.lock().retain(|(_, t)| *t != token);
    }

    pub(crate) fn wake_active_tokens_for_task(&self, task_key: TaskKey) {
        let tokens: Vec<ContinuationWakeToken> = {
            let mut guard = self.active_wait_tokens.lock();
            let mut matched = Vec::new();
            guard.retain(|(k, token)| {
                if *k == task_key {
                    matched.push(*token);
                    false
                } else {
                    true
                }
            });
            matched
        };
        for token in tokens {
            self.wait_service.publish_ready(token);
        }
    }

    pub(crate) fn notify_parked(&self, id: i32, label: &'static str) {
        self.parked_notifications.lock().insert((id, label));
        self.parked_condvar.notify_all();
    }

    pub(crate) fn await_parked(
        &self,
        id: i32,
        label: &'static str,
        timeout: Duration,
    ) -> Result<(), ExampleError> {
        let deadline = Instant::now() + timeout;
        let mut parked = self.parked_notifications.lock();
        while !parked.contains(&(id, label)) {
            let now = Instant::now();
            if now >= deadline {
                return Err(ExampleError::WaitTimedOut(label));
            }
            let remaining = deadline.saturating_duration_since(now);
            let timed_out = self
                .parked_condvar
                .wait_for(&mut parked, remaining)
                .timed_out();
            if timed_out && !parked.contains(&(id, label)) {
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
    pub(crate) dispatch_events: Vec<(i32, i32, &'static str)>,
    pub(crate) tasks_started: usize,
    pub(crate) task_failures: Vec<(i32, i32, ExampleError)>,
}

/// How one issued syscall ended internally.
#[derive(Debug)]
pub(crate) enum InternalCompletion {
    Returned(i64),
    Errno(LinuxErrno),
    Exit(i32),
    ThreadExit(i32),
    Death(i32),
    Fork {
        flags: u64,
        exit_signal: u32,
    },
    CloneThread {
        flags: u64,
        clear_child_tid_addr: u64,
    },
    Cancelled(carrick_kernel::kernel::continuation::CancellationCause),
}

/// One Linux task: a host thread's worth of backend state.
pub(crate) struct Task {
    pub(crate) dispatcher: Arc<Mutex<SyscallDispatcher>>,
    pub(crate) process: Arc<ExampleProcess>,
    pub(crate) context: KernelContext,
    pub(crate) memory: Arc<Mutex<TaskMemory>>,
    pub(crate) thread_registry: Arc<ThreadRegistry>,
    pub(crate) futex_table: Arc<FutexTable>,
    pub(crate) tid: i32,
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
            if !self.context.exact_thread_is_live()
                || !self
                    .process
                    .kernel_graph()
                    .task_is_live(self.process.task_id())
            {
                return Ok(0);
            }
            match step {
                Step::ChildMarker(_) => {
                    return Err(ExampleError::Script(
                        "child_marker without a preceding fork or clone".to_owned(),
                    ));
                }
                Step::AllocBuffer { slot, bytes } => {
                    let addr = self.memory.lock().put(bytes)?;
                    self.save_slot(*slot, addr as i64);
                }
                Step::WriteBuffer { slot, bytes } => {
                    let addr = self
                        .slots
                        .get(*slot)
                        .copied()
                        .ok_or_else(|| ExampleError::Script(format!("slot {slot} is unset")))?
                        as u64;
                    self.memory.lock().write(addr, bytes)?;
                }
                Step::AwaitParked { pid, label } => {
                    let resolved_id = match pid {
                        Operand::Lit(v) => *v as i32,
                        Operand::Slot(s) => self
                            .slots
                            .get(*s)
                            .copied()
                            .map(|v| v as i32)
                            .ok_or_else(|| ExampleError::Script(format!("slot {s} is unset")))?,
                        Operand::Negated(s) => self
                            .slots
                            .get(*s)
                            .copied()
                            .and_then(|v| v.checked_neg())
                            .map(|v| v as i32)
                            .ok_or_else(|| {
                                ExampleError::Script(format!("slot {s} is unset or overflow"))
                            })?,
                        Operand::LastChild => self.last_child.ok_or_else(|| {
                            ExampleError::Script("no child has been forked".to_owned())
                        })?,
                        other => {
                            return Err(ExampleError::Script(format!(
                                "await_parked does not support operand {other:?}"
                            )));
                        }
                    };
                    shared.await_parked(resolved_id, label, WAIT_BOUND)?;
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
                        InternalCompletion::CloneThread {
                            flags,
                            clear_child_tid_addr,
                        } => {
                            let Some(Step::ChildMarker(child_script)) = steps.next() else {
                                return Err(ExampleError::Script(
                                    "clone must be followed by child_marker".to_owned(),
                                ));
                            };
                            let child_tid = self.on_clone_thread(
                                flags,
                                clear_child_tid_addr,
                                child_script,
                                shared,
                            )?;
                            self.finish_syscall(syscall, Ok(child_tid as i64), outs, shared)?;
                        }
                        InternalCompletion::Exit(code) => {
                            let pid = self.process.pid();
                            let tid = self.tid;
                            shared.ledger.lock().completions.push(Completion {
                                pid,
                                tid,
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
                        InternalCompletion::ThreadExit(code) => {
                            let pid = self.process.pid();
                            let tid = self.tid;
                            shared.ledger.lock().completions.push(Completion {
                                pid,
                                tid,
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
                            self.on_exit_thread(code, shared)?;
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
                            self.on_death(sig, shared)?;
                            expectation_check?;
                            return Ok(sig);
                        }
                        InternalCompletion::Cancelled(cause) => {
                            if cause
                                == carrick_kernel::kernel::continuation::CancellationCause::ProcessExit
                                || !self.context.exact_thread_is_live()
                                || !self
                                    .process
                                    .kernel_graph()
                                    .task_is_live(self.process.task_id())
                            {
                                return Ok(0);
                            }
                            return Err(ExampleError::Unsupported(format!(
                                "continuation cancelled with cause {cause:?}"
                            )));
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
        if !self.context.exact_thread_is_live()
            || !self
                .process
                .kernel_graph()
                .task_is_live(self.process.task_id())
        {
            return Ok(0);
        }
        Err(ExampleError::Script(
            "script ended without exit_group".to_owned(),
        ))
    }

    /// The child thread's body: run, and record a failure for the root to
    /// report.
    fn run_child(mut self, script: &[Step], shared: &Arc<Shared>) {
        let pid = self.process.pid();
        let tid = self.tid;
        if let Err(error) = self.run(script, shared) {
            shared.ledger.lock().task_failures.push((pid, tid, error));
        }
    }

    fn resolve(&mut self, syscall: &Syscall) -> Result<ResolvedArgs, ExampleError> {
        let mut args = [0u64; 6];
        let mut outs = Vec::new();
        for (i, op) in syscall.args.iter().enumerate() {
            args[i] = self.resolve_operand(i, op, &mut outs)?;
        }
        // Validate that capture tags within one syscall are unique.
        let mut seen_tags = HashSet::new();
        for out in &outs {
            if let Some(tag) = out.tag
                && !seen_tags.insert(tag)
            {
                return Err(ExampleError::Script(format!(
                    "duplicate capture tag '{tag}' in syscall {}",
                    syscall.label
                )));
            }
        }
        Ok((args, outs))
    }

    fn resolve_operand(
        &mut self,
        arg_idx: usize,
        op: &Operand,
        outs: &mut Vec<OutBufferSpec>,
    ) -> Result<u64, ExampleError> {
        match op {
            Operand::Lit(v) => Ok(*v as u64),
            Operand::Slot(s) => self
                .slots
                .get(*s)
                .copied()
                .map(|v| v as u64)
                .ok_or_else(|| ExampleError::Script(format!("slot {s} is unset"))),
            Operand::Negated(s) => {
                let val = self
                    .slots
                    .get(*s)
                    .copied()
                    .ok_or_else(|| ExampleError::Script(format!("slot {s} is unset")))?;
                let neg = val.checked_neg().ok_or_else(|| {
                    ExampleError::Script(format!("negation overflow on slot {s} ({val})"))
                })?;
                Ok(neg as u64)
            }
            Operand::LastChild => self
                .last_child
                .map(|pid| pid as u64)
                .ok_or_else(|| ExampleError::Script("no child has been forked".to_owned())),
            Operand::Bytes(b) => self.memory.lock().put(b).map_err(ExampleError::from),
            Operand::CStr(s) => {
                let mut b = s.as_bytes().to_vec();
                b.push(0);
                self.memory.lock().put(&b).map_err(ExampleError::from)
            }
            Operand::Out(n) => {
                let a = self.memory.lock().alloc_zeroed(*n)?;
                outs.push(OutBufferSpec {
                    arg: arg_idx,
                    tag: None,
                    addr: a,
                    len: *n,
                });
                Ok(a)
            }
            Operand::TaggedOut(tag, n) => {
                let a = self.memory.lock().alloc_zeroed(*n)?;
                outs.push(OutBufferSpec {
                    arg: arg_idx,
                    tag: Some(*tag),
                    addr: a,
                    len: *n,
                });
                Ok(a)
            }
            Operand::InOut(b) => {
                let a = self.memory.lock().put(b)?;
                outs.push(OutBufferSpec {
                    arg: arg_idx,
                    tag: None,
                    addr: a,
                    len: b.len(),
                });
                Ok(a)
            }
            Operand::TaggedInOut(tag, b) => {
                let a = self.memory.lock().put(b)?;
                outs.push(OutBufferSpec {
                    arg: arg_idx,
                    tag: Some(*tag),
                    addr: a,
                    len: b.len(),
                });
                Ok(a)
            }
            Operand::Layout(layout) => self.resolve_layout(arg_idx, layout, outs),
        }
    }

    fn resolve_layout(
        &mut self,
        arg_idx: usize,
        layout: &Layout,
        outs: &mut Vec<OutBufferSpec>,
    ) -> Result<u64, ExampleError> {
        use crate::operand::RelocWidth;
        let mut buffer = layout.bytes.clone();
        for reloc in &layout.relocations {
            let val = self.resolve_operand(arg_idx, &reloc.operand, outs)?;
            let width_bytes = reloc.width.bytes();
            let end = reloc
                .offset
                .checked_add(width_bytes)
                .ok_or_else(|| ExampleError::Script("relocation offset overflow".to_owned()))?;
            if end > buffer.len() {
                return Err(ExampleError::Script(format!(
                    "relocation at offset {} (width {}) exceeds layout size {}",
                    reloc.offset,
                    width_bytes,
                    buffer.len()
                )));
            }
            let range_error = |_| {
                ExampleError::Script(format!(
                    "relocation value {val} does not fit in width {:?}",
                    reloc.width
                ))
            };
            match reloc.width {
                RelocWidth::U8 => buffer[reloc.offset] = u8::try_from(val).map_err(range_error)?,
                RelocWidth::U16 => buffer[reloc.offset..end]
                    .copy_from_slice(&u16::try_from(val).map_err(range_error)?.to_le_bytes()),
                RelocWidth::I16 => buffer[reloc.offset..end].copy_from_slice(
                    &i16::try_from(val as i64)
                        .map_err(range_error)?
                        .to_le_bytes(),
                ),
                RelocWidth::U32 => buffer[reloc.offset..end]
                    .copy_from_slice(&u32::try_from(val).map_err(range_error)?.to_le_bytes()),
                RelocWidth::I32 => buffer[reloc.offset..end].copy_from_slice(
                    &i32::try_from(val as i64)
                        .map_err(range_error)?
                        .to_le_bytes(),
                ),
                RelocWidth::U64 | RelocWidth::I64 => {
                    buffer[reloc.offset..end].copy_from_slice(&val.to_le_bytes());
                }
            }
        }
        let addr = self.memory.lock().put(&buffer)?;
        if layout.capture {
            outs.push(OutBufferSpec {
                arg: arg_idx,
                tag: layout.tag,
                addr,
                len: buffer.len(),
            });
        }
        Ok(addr)
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
        let tid = self.tid;
        let mut captured_outputs = Vec::new();
        for out in &outs {
            let bytes = self.memory.lock().read(out.addr, out.len)?;
            captured_outputs.push(Output {
                pid,
                tid,
                label: syscall.label,
                arg: out.arg,
                tag: out.tag,
                bytes,
            });
        }

        {
            let mut ledger = shared.ledger.lock();
            ledger.completions.push(Completion {
                pid,
                tid,
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
                    let out = outs
                        .iter()
                        .find(|o| o.arg == *arg && o.tag.is_none())
                        .or_else(|| outs.iter().find(|o| o.arg == *arg))
                        .ok_or_else(|| {
                            ExampleError::Script(format!("no out buffer for arg {arg}"))
                        })?;
                    let byte_offset = index
                        .checked_mul(4)
                        .ok_or_else(|| ExampleError::Script("out_i32 index overflow".to_owned()))?;
                    let end_offset = byte_offset
                        .checked_add(4)
                        .ok_or_else(|| ExampleError::Script("out_i32 index overflow".to_owned()))?;
                    if end_offset > out.len {
                        return Err(ExampleError::Script(format!(
                            "out_i32 index {index} (byte range {byte_offset}..{end_offset}) exceeds out buffer len {}",
                            out.len
                        )));
                    }
                    let offset = out.addr + byte_offset as u64;
                    let bytes = self.memory.lock().read(offset, 4)?;
                    let word = <[u8; 4]>::try_from(bytes.as_slice())
                        .map_err(|_| ExampleError::Script("invalid i32 slice".to_owned()))?;
                    let val = i32::from_le_bytes(word);
                    self.save_slot(*slot, val as i64);
                }
                Save::OutI32At { arg, offset, slot } => {
                    let out = outs
                        .iter()
                        .find(|o| o.arg == *arg && o.tag.is_none())
                        .or_else(|| outs.iter().find(|o| o.arg == *arg))
                        .ok_or_else(|| {
                            ExampleError::Script(format!("no out buffer for arg {arg}"))
                        })?;
                    let end_offset = offset.checked_add(4).ok_or_else(|| {
                        ExampleError::Script("out_i32_at offset overflow".to_owned())
                    })?;
                    if end_offset > out.len {
                        return Err(ExampleError::Script(format!(
                            "out_i32_at offset {offset} (byte range {offset}..{end_offset}) exceeds out buffer len {}",
                            out.len
                        )));
                    }
                    let addr = out.addr + *offset as u64;
                    let bytes = self.memory.lock().read(addr, 4)?;
                    let word = <[u8; 4]>::try_from(bytes.as_slice())
                        .map_err(|_| ExampleError::Script("invalid i32 slice".to_owned()))?;
                    let val = i32::from_le_bytes(word);
                    self.save_slot(*slot, val as i64);
                }
                Save::TaggedOutI32 { tag, offset, slot } => {
                    let out = outs.iter().find(|o| o.tag == Some(*tag)).ok_or_else(|| {
                        ExampleError::Script(format!("no out buffer with tag {tag}"))
                    })?;
                    let end_offset = offset.checked_add(4).ok_or_else(|| {
                        ExampleError::Script("tagged_out_i32 offset overflow".to_owned())
                    })?;
                    if end_offset > out.len {
                        return Err(ExampleError::Script(format!(
                            "tagged_out_i32 offset {offset} (byte range {offset}..{end_offset}) exceeds out buffer len {}",
                            out.len
                        )));
                    }
                    let addr = out.addr + *offset as u64;
                    let bytes = self.memory.lock().read(addr, 4)?;
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
        let mut dispatcher = self.dispatcher.lock();
        let parent = &self.context;
        let plan = ClonePlan::from_flags(LinuxCloneFlags::from_bits_retain(flags))?
            .with_exit_signal(ChildExitSignal::for_clone_request(exit_signal));
        let parent_pid = self.process.pid();
        let reservation = parent.kernel().reserve_fork(
            parent,
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
            dispatcher.prepare_fork_mm(parent_mm_id, child_mm_id, CloneObjectMode::Copy)?;
        let (parent_guest_pid, child_guest_pid) = (guest_pid(parent_pid)?, guest_pid(child_pid)?);
        let child_dispatcher = dispatcher.with_mm_executor_mutation(|dispatcher, guard| {
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

        let child_generation = crate::driver::seed_initial_task_state(
            &child_context,
            child_process.asid_generation(),
        )?;
        let child_thread_registry = Arc::new(ThreadRegistry::new(child_tid));
        let child_futex_table = Arc::new(FutexTable::new());
        let child_context_for_task = child_context.retain_exact();
        let child = Task {
            dispatcher: Arc::new(Mutex::new(child_dispatcher)),
            process: child_process,
            context: child_context_for_task,
            memory: Arc::new(Mutex::new(self.memory.lock().clone())),
            thread_registry: child_thread_registry,
            futex_table: child_futex_table,
            tid: child_pid,
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

    /// The `CloneThread` arm: spawn a sibling thread sharing this process's
    /// address space, dispatcher, and futex table.
    fn on_clone_thread(
        &mut self,
        flags: u64,
        clear_child_tid_addr: u64,
        child_script: &[Step],
        shared: &Arc<Shared>,
    ) -> Result<i32, ExampleError> {
        let _dispatcher = self.dispatcher.lock();
        let parent = &self.context;
        let plan = ClonePlan::from_flags(LinuxCloneFlags::from_bits_retain(flags))?;
        let reservation = parent.kernel().reserve_thread_clone(parent, plan, None)?;
        let child_tid = reservation.visible_tid();
        let thread_id = ThreadId::from_guest_supplied_tid(child_tid);

        let prepared = reservation.prepare(thread_id)?;
        let published = prepared.commit()?;
        let child_context = published.into_context()?;

        // Register in ThreadRegistry only AFTER prepare/commit succeeds
        // so no leaked registry entry remains on failed publication.
        self.thread_registry
            .register_child_with_tid(thread_id, clear_child_tid_addr);

        let child_generation =
            crate::driver::seed_initial_task_state(&child_context, self.process.asid_generation())?;
        let child_context_for_task = child_context.retain_exact();
        let child = Task {
            dispatcher: Arc::clone(&self.dispatcher),
            process: Arc::clone(&self.process),
            context: child_context_for_task,
            memory: Arc::clone(&self.memory),
            thread_registry: Arc::clone(&self.thread_registry),
            futex_table: Arc::clone(&self.futex_table),
            tid: child_tid,
            slots: self.slots.clone(),
            last_child: None,
            reporter: CompatReporter::default(),
            execution_generation: child_generation,
        };
        let script = child_script.to_vec();
        let shared_for_child = Arc::clone(shared);
        shared.ledger.lock().tasks_started += 1;
        let handle = thread::Builder::new()
            .name(format!("linux-thread-{child_tid}"))
            .spawn(move || child.run_child(&script, &shared_for_child))?;
        shared.children.lock().push(handle);
        Ok(child_tid)
    }

    /// Serialize process terminal publication through the per-process dispatcher mutex
    /// across liveness check, fd retirement, kernel exit publication, and recording
    /// the winning exit code.
    fn on_process_terminal(
        &mut self,
        status: LinuxWaitStatus,
        shared: &Arc<Shared>,
    ) -> Result<(), ExampleError> {
        let task_key = self.context.task().key();
        let pid = self.process.pid();
        let disp = self.dispatcher.lock();
        if !self.context.exact_thread_is_live()
            || !self
                .process
                .kernel_graph()
                .task_is_live(self.process.task_id())
        {
            return Ok(());
        }
        disp.retire_hvpatch_process_fds(&self.context);
        let adopter = disp.hvpatch_orphan_adopter();
        let zombie = self.context.kernel().exit_task_key_eventually_notifying(
            task_key,
            status,
            adopter,
            |_| {},
        )?;
        let raw = zombie.status.raw();
        let winning_code = if (raw & 0x7f) != 0 {
            raw & 0x7f
        } else {
            (raw >> 8) & 0xff
        };
        shared
            .process_exit_codes
            .lock()
            .entry(pid)
            .or_insert(winning_code);
        drop(disp);
        shared.wake_active_tokens_for_task(task_key);
        Ok(())
    }

    fn on_exit(&mut self, code: i32, shared: &Arc<Shared>) -> Result<(), ExampleError> {
        let status = LinuxWaitStatus::from_wait_encoding((code & 0xff) << 8);
        self.on_process_terminal(status, shared)
    }

    fn on_death(&mut self, sig: i32, shared: &Arc<Shared>) -> Result<(), ExampleError> {
        // man 2 wait4: WTERMSIG is encoded as (sig & 0x7f).
        let status = LinuxWaitStatus::from_wait_encoding(sig & 0x7f);
        self.on_process_terminal(status, shared)
    }

    /// Single thread exit via `exit(2)` (not `exit_group`).
    fn on_exit_thread(&mut self, code: i32, shared: &Arc<Shared>) -> Result<(), ExampleError> {
        let thread_id = ThreadId::from_guest_supplied_tid(self.tid);
        let linux_tid = self.context.thread().key().tid;
        let deadline = Instant::now() + WAIT_BOUND;
        loop {
            let dispatcher = self.dispatcher.lock();
            let res = self.process.exit_thread(linux_tid)?;
            match res {
                carrick_kernel::kernel::ProcessThreadExit::Retired(retired) => {
                    dispatcher.close_draining_file_table(
                        self.context.kernel(),
                        &retired.files(),
                        Some(retired.owner()),
                        None,
                    );
                    break;
                }
                carrick_kernel::kernel::ProcessThreadExit::AlreadyRetired => {
                    break;
                }
                carrick_kernel::kernel::ProcessThreadExit::LastThread => {
                    drop(dispatcher);
                    self.on_exit(code, shared)?;
                    break;
                }
                carrick_kernel::kernel::ProcessThreadExit::Busy { observed_epoch } => {
                    drop(dispatcher);
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(ExampleError::WaitTimedOut("reservation busy epoch change"));
                    }
                    let remaining = deadline.saturating_duration_since(now);
                    let current_thread = std::thread::current();
                    let callback = Arc::new(move || {
                        current_thread.unpark();
                    });
                    if let Some(_sub) = self
                        .context
                        .kernel()
                        .subscribe_reservation_change(observed_epoch, callback)
                    {
                        std::thread::park_timeout(remaining);
                    }
                }
            }
        }
        if let Some(clear_addr) = self.thread_registry.clear_child_tid(thread_id)
            && clear_addr != 0
        {
            let _ = self.memory.lock().write(clear_addr, &[0u8; 4]);
            self.futex_table.wake(clear_addr, 1);
        }
        self.thread_registry.exit(thread_id);
        Ok(())
    }
}

/// A Linux pid as the dispatcher's fork clone names it.
fn guest_pid(pid: i32) -> Result<u32, ExampleError> {
    u32::try_from(pid).map_err(|_| ExampleError::Script(format!("pid {pid} is not positive")))
}
