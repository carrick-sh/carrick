//! The trap source and the run loop: scripted Linux tasks on host threads.
//!
//! A real backend observes a guest's syscall entry and turns it into a
//! `SyscallRequest`; this one reads the next [`Step`] of a script instead.
//! Each Linux task is one host thread owning its own `SyscallDispatcher`
//! (forked from its parent's, exactly as the carrier forks one per Linux
//! process), its own `LinearMemory` and its own [`ExampleProcess`] handle.
//! What the loop then does with every `DispatchOutcome` it meets is the
//! backend contract, and each arm below names the carrier arm it mirrors.
//!
//! Waits never park the thread inside the kernel: a `WaitOnHvpatchChild` or
//! `WaitOnFds` outcome is re-dispatched after a `yield_now`, bounded by
//! [`WAIT_BOUND`] so a lost wake is a failed run, not a hang.

use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use carrick_abi::syscall::nr;
use carrick_abi::{LINUX_BOOTSTRAP_PID, LINUX_SIGCHLD, LinuxCloneFlags, LinuxErrno};
use carrick_guest_mem::{GuestMemory, MemoryError};
use carrick_hal::{NullGuestTimerBridge, NullHostSignalBridge};
use carrick_kernel::compat::{CompatReporter, SyscallArgs};
use carrick_kernel::dispatch::mm_authority::PrepareDispatchMmForkError;
use carrick_kernel::dispatch::{
    CarrierBridges, DispatchError, DispatchOutcome, LinearMemory, SyscallDispatcher, SyscallRequest,
};
use carrick_kernel::kernel::{
    CarrierProcess, ChildExitSignal, CloneObjectMode, ClonePlan, ClonePlanError, KernelError,
    KernelOperationError, LinuxWaitStatus, SnapshotError,
};
use carrick_kernel::thread::ThreadId;
use parking_lot::Mutex;

use crate::process::{AddressSpace, AddressSpaceError, AsidAllocator, ExampleProcess};

/// The bound on every wait in this backend: a child that has not exited, a
/// pipe that has not been written, a task thread that has not finished. A
/// wake that never comes fails the run with [`ExampleError::WaitTimedOut`].
pub const WAIT_BOUND: Duration = Duration::from_secs(5);

/// The pid of the root Linux task: `init` of its pid namespace, exactly as
/// the carrier numbers its root.
const ROOT_PID: i32 = LINUX_BOOTSTRAP_PID as i32;

/// Where each task's `LinearMemory` sits in its guest address space, and the
/// scratch layout the steps use inside it.
const GUEST_BASE: u64 = 0x1000_0000;
const GUEST_LEN: usize = 0x1000;
/// `pipe2`'s `int pipefd[2]`.
const FD_PAIR: u64 = GUEST_BASE;
/// `wait4`'s `int *wstatus`.
const WSTATUS: u64 = GUEST_BASE + 0x10;
/// The `read`/`write` payload.
const BUFFER: u64 = GUEST_BASE + 0x100;
const BUFFER_LEN: usize = GUEST_LEN - 0x100;

/// Where a step takes an fd or a pid from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operand {
    /// A literal value.
    Literal(i64),
    /// Slot `n` of the task's slot table (`pipe2` fills slots 0 and 1).
    Slot(usize),
    /// The pid the task's most recent fork returned.
    LastChild,
}

/// One syscall of a script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sys {
    /// `pipe2(2)`: the two fds land in slots 0 and 1.
    Pipe2 { flags: u64 },
    /// `clone(2)` as `fork`: `clone(SIGCHLD, 0, 0, 0, 0)`. The next step must
    /// be [`Step::child_marker`], which the child runs and the parent skips.
    Fork,
    /// `write(2)` of `data` to `fd`.
    Write { fd: Operand, data: Vec<u8> },
    /// `read(2)` of up to `len` bytes from `fd`; what came back is recorded
    /// in [`RunReport::read_results`].
    Read { fd: Operand, len: usize },
    /// `wait4(2)` on `pid`; the status is recorded in
    /// [`RunReport::wait_statuses`].
    Wait4 { pid: Operand, options: u64 },
    /// `exit_group(2)`: the task's last step.
    ExitGroup { code: i32 },
}

/// One step of a script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Issue a syscall.
    Sys(Sys),
    /// The script the child of the preceding [`Sys::Fork`] runs.
    ChildMarker(Vec<Step>),
}

impl Step {
    /// Issue `sys`.
    pub fn sys(sys: Sys) -> Self {
        Self::Sys(sys)
    }

    /// The child's script; must directly follow a [`Sys::Fork`].
    pub fn child_marker(script: Vec<Step>) -> Self {
        Self::ChildMarker(script)
    }

    /// Slot `index` of the task's slot table.
    pub const fn slot(index: usize) -> Operand {
        Operand::Slot(index)
    }

    /// The pid of the task's most recent fork.
    pub const fn last_child() -> Operand {
        Operand::LastChild
    }
}

/// What a run produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunReport {
    exit_code: i32,
    read_results: Vec<Vec<u8>>,
    wait_statuses: Vec<i32>,
    tasks_started: usize,
}

impl RunReport {
    /// The root task's `exit_group` code.
    pub const fn exit_code(&self) -> i32 {
        self.exit_code
    }

    /// The bytes every [`Sys::Read`] returned, in completion order.
    pub fn read_results(&self) -> &[Vec<u8>] {
        &self.read_results
    }

    /// The `wstatus` every [`Sys::Wait4`] reported, in completion order.
    pub fn wait_statuses(&self) -> &[i32] {
        &self.wait_statuses
    }

    /// How many Linux tasks ran: the root plus every published child.
    pub const fn tasks_started(&self) -> usize {
        self.tasks_started
    }
}

/// Why a run failed.
#[derive(Debug, thiserror::Error)]
pub enum ExampleError {
    #[error("{syscall} failed with errno {}", .errno.get())]
    Errno {
        syscall: &'static str,
        errno: LinuxErrno,
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
        let shared = Arc::new(Shared {
            asids: AsidAllocator::new(),
            ledger: Mutex::new(Ledger::default()),
            children: Mutex::new(Vec::new()),
        });
        let space = AddressSpace::allocate(&shared.asids)?;
        let (process, _root) = ExampleProcess::boot_root(
            ROOT_PID,
            "example-root",
            Arc::clone(&self.bridges.host_signal),
            space,
        )?;
        let process = Arc::new(process);
        let dispatcher = SyscallDispatcher::with_bridges(self.bridges);
        dispatcher.bind_hvpatch_process(Arc::clone(&process) as Arc<dyn CarrierProcess>);
        if let Some(failure) = process.take_bind_failure() {
            return Err(failure.into());
        }
        let mut root = Task {
            dispatcher,
            process,
            memory: LinearMemory::new(GUEST_BASE, vec![0; GUEST_LEN]),
            slots: Vec::new(),
            last_child: None,
            reporter: CompatReporter::default(),
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
            read_results: ledger.read_results,
            wait_statuses: ledger.wait_statuses,
            tasks_started: ledger.tasks_started,
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
struct Shared {
    asids: AsidAllocator,
    ledger: Mutex<Ledger>,
    children: Mutex<Vec<JoinHandle<()>>>,
}

#[derive(Default)]
struct Ledger {
    read_results: Vec<Vec<u8>>,
    wait_statuses: Vec<i32>,
    tasks_started: usize,
    task_failures: Vec<(i32, ExampleError)>,
}

/// How one issued syscall ended, once every wait it met has been serviced.
#[derive(Debug)]
enum Completion {
    Returned(i64),
    Exit(i32),
    Fork { flags: u64, exit_signal: u32 },
}

/// One Linux task: a host thread's worth of backend state.
struct Task {
    dispatcher: SyscallDispatcher,
    process: Arc<ExampleProcess>,
    memory: LinearMemory,
    slots: Vec<i64>,
    last_child: Option<i32>,
    reporter: CompatReporter,
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
                Step::Sys(Sys::Fork) => {
                    let Some(Step::ChildMarker(child_script)) = steps.next() else {
                        return Err(ExampleError::Script(
                            "fork must be followed by child_marker".to_owned(),
                        ));
                    };
                    self.fork(child_script, shared)?;
                }
                Step::Sys(Sys::ExitGroup { code }) => return self.exit_group(*code),
                Step::Sys(sys) => self.step(sys, shared)?,
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

    fn operand(&self, operand: Operand) -> Result<i64, ExampleError> {
        match operand {
            Operand::Literal(value) => Ok(value),
            Operand::Slot(index) => self
                .slots
                .get(index)
                .copied()
                .ok_or_else(|| ExampleError::Script(format!("slot {index} is unset"))),
            Operand::LastChild => self
                .last_child
                .map(i64::from)
                .ok_or_else(|| ExampleError::Script("no child has been forked".to_owned())),
        }
    }

    fn step(&mut self, sys: &Sys, shared: &Arc<Shared>) -> Result<(), ExampleError> {
        match sys {
            Sys::Pipe2 { flags } => {
                self.returned("pipe2", nr::PIPE2.raw(), [FD_PAIR, *flags, 0, 0, 0, 0])?;
                let pair = self.memory.read_bytes(FD_PAIR, 8)?;
                let (read_end, write_end) = (i32_at(&pair, 0)?, i32_at(&pair, 4)?);
                self.slots = vec![i64::from(read_end), i64::from(write_end)];
            }
            Sys::Write { fd, data } => {
                if data.len() > BUFFER_LEN {
                    return Err(ExampleError::Script(format!(
                        "write of {} bytes exceeds the {BUFFER_LEN}-byte buffer",
                        data.len()
                    )));
                }
                self.memory.write_bytes(BUFFER, data)?;
                let fd = self.operand(*fd)?;
                self.returned(
                    "write",
                    nr::WRITE.raw(),
                    [fd as u64, BUFFER, data.len() as u64, 0, 0, 0],
                )?;
            }
            Sys::Read { fd, len } => {
                if *len > BUFFER_LEN {
                    return Err(ExampleError::Script(format!(
                        "read of {len} bytes exceeds the {BUFFER_LEN}-byte buffer"
                    )));
                }
                let fd = self.operand(*fd)?;
                let count = self.returned(
                    "read",
                    nr::READ.raw(),
                    [fd as u64, BUFFER, *len as u64, 0, 0, 0],
                )?;
                let count = usize::try_from(count).map_err(|_| {
                    ExampleError::Script(format!("read returned a negative length {count}"))
                })?;
                let bytes = self.memory.read_bytes(BUFFER, count)?;
                shared.ledger.lock().read_results.push(bytes);
            }
            Sys::Wait4 { pid, options } => {
                let pid = self.operand(*pid)?;
                self.returned(
                    "wait4",
                    nr::WAIT4.raw(),
                    [pid as u64, WSTATUS, *options, 0, 0, 0],
                )?;
                let status = i32_at(&self.memory.read_bytes(WSTATUS, 4)?, 0)?;
                shared.ledger.lock().wait_statuses.push(status);
            }
            Sys::Fork | Sys::ExitGroup { .. } => {
                return Err(ExampleError::Script(
                    "fork and exit_group are interpreted by the run loop".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Issue a syscall that must complete with a return value.
    fn returned(
        &mut self,
        syscall: &'static str,
        number: u64,
        args: [u64; 6],
    ) -> Result<i64, ExampleError> {
        match self.issue(syscall, number, args)? {
            Completion::Returned(value) => Ok(value),
            other => Err(ExampleError::Script(format!(
                "{syscall} completed as {other:?} instead of returning"
            ))),
        }
    }

    /// Issue one syscall and interpret its outcome until it completes.
    ///
    /// The arms are the backend contract stated on each `DispatchOutcome`
    /// variant. `Returned`/`Errno` complete the call; `Exit` and `Fork` hand
    /// the work only the execution lane can do back to the run loop
    /// (`on_exit`, `on_fork`); `SchedulerYield` completes with 0 and yields
    /// the host thread (the only lease a VM-less backend holds); the two wait
    /// outcomes a scripted task can meet are re-dispatched after a yield,
    /// bounded by [`WAIT_BOUND`], because this backend has no continuation
    /// reactor to park them on. Every other outcome is refused by name.
    fn issue(
        &mut self,
        syscall: &'static str,
        number: u64,
        args: [u64; 6],
    ) -> Result<Completion, ExampleError> {
        let deadline = Instant::now() + WAIT_BOUND;
        loop {
            // The context is captured per dispatch through the process
            // binding, as the carrier does at every syscall boundary: a fork
            // or an exit moves the task's revision, and a stale context is
            // refused by the kernel operations that check it.
            let context = self.dispatcher.capture_one_task_context()?;
            let outcome = self.dispatcher.dispatch(
                &context,
                SyscallRequest::new(number, SyscallArgs::from(args)),
                &mut self.memory,
                &self.reporter,
            )?;
            match outcome {
                DispatchOutcome::Returned { value } => return Ok(Completion::Returned(value)),
                DispatchOutcome::Errno { errno } => {
                    return Err(ExampleError::Errno { syscall, errno });
                }
                DispatchOutcome::Exit { code } => return Ok(Completion::Exit(code)),
                DispatchOutcome::Fork {
                    flags,
                    pidfd_out,
                    clone_parent,
                    parent_tid_addr,
                    child_tid_addr,
                    exit_signal,
                    child_stack,
                    vfork,
                } => {
                    let plain = pidfd_out.is_none()
                        && !clone_parent
                        && parent_tid_addr.is_none()
                        && child_tid_addr.is_none()
                        && child_stack == 0
                        && vfork.is_none();
                    if !plain {
                        return Err(ExampleError::Unsupported(format!(
                            "clone flags {flags:#x}: only a plain fork (no CLONE_PIDFD, \
                             CLONE_PARENT, tid stores, child stack or vfork) runs here"
                        )));
                    }
                    return Ok(Completion::Fork { flags, exit_signal });
                }
                DispatchOutcome::SchedulerYield => {
                    thread::yield_now();
                    return Ok(Completion::Returned(0));
                }
                DispatchOutcome::WaitOnHvpatchChild { .. } | DispatchOutcome::WaitOnFds { .. } => {
                    if Instant::now() >= deadline {
                        return Err(ExampleError::WaitTimedOut(syscall));
                    }
                    thread::yield_now();
                }
                other => return Err(ExampleError::Unsupported(format!("{other:?}"))),
            }
        }
    }

    fn fork(&mut self, child_script: &[Step], shared: &Arc<Shared>) -> Result<(), ExampleError> {
        let Completion::Fork { flags, exit_signal } = self.issue(
            "clone",
            nr::CLONE.raw(),
            [LINUX_SIGCHLD as u64, 0, 0, 0, 0, 0],
        )?
        else {
            return Err(ExampleError::Script(
                "clone completed without a fork outcome".to_owned(),
            ));
        };
        let child_pid = self.on_fork(flags, exit_signal, child_script, shared)?;
        self.last_child = Some(child_pid);
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

        let child = Task {
            dispatcher: child_dispatcher,
            process: child_process,
            memory: self.memory.clone(),
            slots: self.slots.clone(),
            last_child: None,
            reporter: CompatReporter::default(),
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

    fn exit_group(&mut self, code: i32) -> Result<i32, ExampleError> {
        match self.issue(
            "exit_group",
            nr::EXIT_GROUP.raw(),
            [code as u64, 0, 0, 0, 0, 0],
        )? {
            Completion::Exit(code) => {
                self.on_exit(code)?;
                Ok(code)
            }
            other => Err(ExampleError::Script(format!(
                "exit_group completed as {other:?} instead of exiting"
            ))),
        }
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
    fn on_exit(&mut self, code: i32) -> Result<(), ExampleError> {
        let context = self.dispatcher.capture_one_task_context()?;
        self.dispatcher.retire_hvpatch_process_fds(&context);
        let status = LinuxWaitStatus::from_wait_encoding((code & 0xff) << 8);
        context
            .kernel()
            .exit_task_key_eventually(context.task().key(), status)?;
        Ok(())
    }
}

/// A Linux pid as the dispatcher's fork clone names it.
fn guest_pid(pid: i32) -> Result<u32, ExampleError> {
    u32::try_from(pid).map_err(|_| ExampleError::Script(format!("pid {pid} is not positive")))
}

/// The native-endian `i32` at `offset` of a guest read.
fn i32_at(bytes: &[u8], offset: usize) -> Result<i32, ExampleError> {
    bytes
        .get(offset..offset + 4)
        .and_then(|word| <[u8; 4]>::try_from(word).ok())
        .map(i32::from_ne_bytes)
        .ok_or_else(|| ExampleError::Script(format!("no i32 at offset {offset} of a guest read")))
}
