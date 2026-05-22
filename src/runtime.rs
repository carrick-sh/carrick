use std::path::{Path, PathBuf};

use crate::compat::{CompatReport, CompatReporter};
use crate::dispatch::{
    Aarch64SyscallFrame, DispatchError, DispatchOutcome, GuestMemory, ProcMapsEntry,
    SyscallDispatcher, SyscallRequest,
};
use crate::memory::{AddressSpace, AddressSpaceError};
use crate::rootfs::RootFs;
use crate::trap::{HvfTrapEngine, TrapError};
use serde::Serialize;
use thiserror::Error;

/// JSON-serialisable snapshot of the guest layout the trap engine is about
/// to run. Written by `run-elf --debug-state-path` / `run --debug-state-path`
/// before vCPU launch so the lldb plugin can resolve guest addresses back
/// to image / segment context.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct DebugStateSnapshot {
    pub entry: u64,
    pub initial_stack_pointer: Option<u64>,
    pub el0_trampoline_entry: Option<u64>,
    pub el1_vectors_base: Option<u64>,
    pub stage1_page_tables_base: Option<u64>,
    pub regions: Vec<DebugRegionSnapshot>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct DebugRegionSnapshot {
    pub start: u64,
    pub end: u64,
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl DebugStateSnapshot {
    pub fn from_address_space(image: &AddressSpace) -> Self {
        Self {
            entry: image.entry(),
            initial_stack_pointer: image.initial_stack_pointer(),
            el0_trampoline_entry: image.el0_trampoline_entry(),
            el1_vectors_base: image.el1_vectors_base(),
            stage1_page_tables_base: image.stage1_page_tables_base(),
            regions: image
                .regions()
                .iter()
                .map(|region| DebugRegionSnapshot {
                    start: region.start,
                    end: region.end,
                    read: region.perms.read,
                    write: region.perms.write,
                    execute: region.perms.execute,
                })
                .collect(),
        }
    }

    pub fn write_to(&self, path: &Path) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| {
            std::io::Error::other(format!("serialize: {e}"))
        })?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, bytes)
    }
}

/// Write a debug-state snapshot iff a path was provided. Returns the path
/// back so the CLI can mention it.
pub fn maybe_dump_debug_state(
    image: &AddressSpace,
    path: Option<&PathBuf>,
) -> Option<PathBuf> {
    let path = path?;
    let snapshot = DebugStateSnapshot::from_address_space(image);
    if let Err(err) = snapshot.write_to(path) {
        eprintln!("warning: failed to write debug state to {path:?}: {err}");
        return None;
    }
    Some(path.clone())
}

pub const DEFAULT_MAX_TRAPS: usize = 1_000_000;

pub trait SyscallTrap {
    fn next_syscall(&mut self) -> Result<Aarch64SyscallFrame, TrapError>;
    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError>;
    /// Real macOS fork. Returns the child pid in the parent, 0 in the
    /// child. After this returns, the trap engine in the child holds a
    /// freshly rebuilt HVF context pointing at the same COW'd guest
    /// memory; the runtime then writes the appropriate retval into the
    /// guest's x0 via `complete_syscall`.
    fn fork(&mut self) -> Result<crate::trap::ForkOutcome, TrapError>;
    /// `execve(2)` — tear down the current guest address space and
    /// re-initialise this engine with `new_image`. Does NOT advance
    /// past a syscall (execve has no successful return); the next
    /// `next_syscall` resumes at the new image's entry point.
    fn execve_into(&mut self, new_image: &AddressSpace) -> Result<(), TrapError>;
    fn is_forked_child(&self) -> bool {
        false
    }
    /// Inject a guest signal frame for `signum`. Writes a
    /// `CarrickSigframe` to SP_EL0, points the guest's x30 at
    /// `sa_restorer`, sets x0 to `signum`, and redirects the vCPU's
    /// next resumed PC (`ELR_EL1`) to the user handler. The pre-signal
    /// register state is preserved in the frame and recovered by
    /// `restore_from_sigframe` on `rt_sigreturn`.
    ///
    /// `pending_syscall_retval` is the retval the dispatcher computed
    /// for the syscall that was just trapped, since signals are
    /// delivered between `complete_syscall` and the next vCPU run we
    /// already wrote it into x0; the frame snapshots the post-retval
    /// state so the handler-return path picks up where the caller left
    /// off. Pass `None` when injecting outside a syscall completion
    /// (e.g. when raising at the top of the trap loop before the first
    /// syscall has run).
    fn inject_signal(
        &mut self,
        signum: i32,
        handler: u64,
        sa_restorer: u64,
        pending_syscall_retval: Option<i64>,
    ) -> Result<(), TrapError>;
    /// Restore vCPU state from the `CarrickSigframe` at SP_EL0. Called
    /// when the guest invokes `rt_sigreturn(2)`. Does NOT advance PC
    /// past the syscall the way `complete_syscall` does — the restored
    /// PC IS the next PC.
    fn restore_from_sigframe(&mut self) -> Result<(), TrapError>;
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("failed to load ELF image: {0}")]
    AddressSpace(#[from] AddressSpaceError),
    #[error("trap engine failed: {0}")]
    Trap(#[from] TrapError),
    #[error("syscall dispatch failed: {0}")]
    Dispatch(#[from] DispatchError),
    #[error("guest did not exit after {max_traps} traps")]
    TrapLimitExceeded { max_traps: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub traps: usize,
    pub report: CompatReport,
    #[serde(default)]
    pub trap_limit_hit: bool,
}

pub fn run_static_elf_with_hvf(
    path: impl AsRef<Path>,
    max_traps: usize,
) -> Result<RunResult, RuntimeError> {
    run_static_elf_with_hvf_and_dispatcher(path, SyscallDispatcher::new(), max_traps)
}

pub fn run_static_elf_with_hvf_and_dispatcher(
    path: impl AsRef<Path>,
    dispatcher: SyscallDispatcher,
    max_traps: usize,
) -> Result<RunResult, RuntimeError> {
    let path = path.as_ref();
    run_static_elf_with_hvf_args_and_dispatcher(
        path,
        dispatcher,
        [path.to_string_lossy().into_owned()],
        std::iter::empty(),
        max_traps,
    )
}

pub fn run_static_elf_with_hvf_args_and_dispatcher<A, E>(
    path: impl AsRef<Path>,
    dispatcher: SyscallDispatcher,
    argv: A,
    env: E,
    max_traps: usize,
) -> Result<RunResult, RuntimeError>
where
    A: IntoIterator<Item = String>,
    E: IntoIterator<Item = String>,
{
    run_static_elf_with_hvf_args_and_dispatcher_debug(
        path, dispatcher, argv, env, max_traps, None,
    )
}

pub fn run_static_elf_with_hvf_args_and_dispatcher_debug<A, E>(
    path: impl AsRef<Path>,
    dispatcher: SyscallDispatcher,
    argv: A,
    env: E,
    max_traps: usize,
    debug_state_path: Option<&PathBuf>,
) -> Result<RunResult, RuntimeError>
where
    A: IntoIterator<Item = String>,
    E: IntoIterator<Item = String>,
{
    let image = AddressSpace::load_elf(path)?
        .with_linux_initial_stack(argv, env)?
        .with_el0_trampoline()?
        .with_el1_vectors()?
        .with_stage1_page_tables()?;
    if let Some(p) = maybe_dump_debug_state(&image, debug_state_path) {
        eprintln!("debug state written: {}", p.display());
    }
    run_address_space_with_hvf_and_dispatcher(image, dispatcher, max_traps)
}

pub fn run_static_elf_bytes_with_hvf_and_dispatcher(
    bytes: &[u8],
    dispatcher: SyscallDispatcher,
    max_traps: usize,
) -> Result<RunResult, RuntimeError> {
    let image = AddressSpace::load_elf_bytes(bytes)?.with_el0_trampoline()?
        .with_el1_vectors()?
        .with_stage1_page_tables()?;
    run_address_space_with_hvf_and_dispatcher(image, dispatcher, max_traps)
}

pub fn run_static_elf_bytes_with_hvf_args_and_dispatcher<A, E>(
    bytes: &[u8],
    dispatcher: SyscallDispatcher,
    argv: A,
    env: E,
    max_traps: usize,
) -> Result<RunResult, RuntimeError>
where
    A: IntoIterator<Item = String>,
    E: IntoIterator<Item = String>,
{
    let image = AddressSpace::load_elf_bytes(bytes)?
        .with_linux_initial_stack(argv, env)?
        .with_el0_trampoline()?
        .with_el1_vectors()?
        .with_stage1_page_tables()?;
    run_address_space_with_hvf_and_dispatcher(image, dispatcher, max_traps)
}

pub fn run_rootfs_elf_with_hvf_args_and_dispatcher<A, E>(
    path: impl AsRef<Path>,
    rootfs: &RootFs,
    dispatcher: SyscallDispatcher,
    argv: A,
    env: E,
    max_traps: usize,
) -> Result<RunResult, RuntimeError>
where
    A: IntoIterator<Item = String>,
    E: IntoIterator<Item = String>,
{
    run_rootfs_elf_with_hvf_args_and_dispatcher_debug(
        path, rootfs, dispatcher, argv, env, max_traps, None,
    )
}

pub fn run_rootfs_elf_with_hvf_args_and_dispatcher_debug<A, E>(
    path: impl AsRef<Path>,
    rootfs: &RootFs,
    dispatcher: SyscallDispatcher,
    argv: A,
    env: E,
    max_traps: usize,
    debug_state_path: Option<&PathBuf>,
) -> Result<RunResult, RuntimeError>
where
    A: IntoIterator<Item = String>,
    E: IntoIterator<Item = String>,
{
    let image = AddressSpace::load_elf_from_rootfs(path, rootfs)?
        .with_linux_initial_stack(argv, env)?
        .with_el0_trampoline()?
        .with_el1_vectors()?
        .with_stage1_page_tables()?;
    if let Some(p) = maybe_dump_debug_state(&image, debug_state_path) {
        eprintln!("debug state written: {}", p.display());
    }
    run_address_space_with_hvf_and_dispatcher(image, dispatcher, max_traps)
}

/// Run an ELF whose filesystem is entirely in the dispatcher's overlay
/// (i.e. `--fs host` after `extract_layers`). The initial binary AND its
/// PT_INTERP are loaded via `dispatcher.read_exec_file` — the same
/// overlay-first reader used by the guest-runtime execve path — so no
/// in-memory `RootFs` is required.
pub fn run_elf_from_dispatcher_debug<A, E>(
    path: &str,
    dispatcher: SyscallDispatcher,
    argv: A,
    env: E,
    max_traps: usize,
    debug_state_path: Option<&PathBuf>,
) -> Result<RunResult, RuntimeError>
where
    A: IntoIterator<Item = String>,
    E: IntoIterator<Item = String>,
{
    let bytes = dispatcher
        .read_exec_file(path)
        .ok_or_else(|| RuntimeError::AddressSpace(AddressSpaceError::Io(
            std::io::Error::new(std::io::ErrorKind::NotFound, path.to_owned()),
        )))?;
    let image = AddressSpace::load_elf_bytes_with_reader(
        &bytes,
        &|p| dispatcher.read_exec_file(p),
    )?
    .with_linux_initial_stack(argv, env)?
    .with_el0_trampoline()?
    .with_el1_vectors()?
    .with_stage1_page_tables()?;
    if let Some(p) = maybe_dump_debug_state(&image, debug_state_path) {
        eprintln!("debug state written: {}", p.display());
    }
    run_address_space_with_hvf_and_dispatcher(image, dispatcher, max_traps)
}

pub fn run_rootfs_elf_with_hvf_args<A, E>(
    path: impl AsRef<Path>,
    rootfs: &RootFs,
    argv: A,
    env: E,
    max_traps: usize,
) -> Result<RunResult, RuntimeError>
where
    A: IntoIterator<Item = String>,
    E: IntoIterator<Item = String>,
{
    run_rootfs_elf_with_hvf_args_debug(path, rootfs, argv, env, max_traps, None)
}

pub fn run_rootfs_elf_with_hvf_args_debug<A, E>(
    path: impl AsRef<Path>,
    rootfs: &RootFs,
    argv: A,
    env: E,
    max_traps: usize,
    debug_state_path: Option<&PathBuf>,
) -> Result<RunResult, RuntimeError>
where
    A: IntoIterator<Item = String>,
    E: IntoIterator<Item = String>,
{
    let path = path.as_ref();
    run_rootfs_elf_with_hvf_args_and_dispatcher_debug(
        path,
        rootfs,
        SyscallDispatcher::with_rootfs_and_executable(
            rootfs.clone(),
            path.to_string_lossy().into_owned(),
        ),
        argv,
        env,
        max_traps,
        debug_state_path,
    )
}

fn run_address_space_with_hvf_and_dispatcher(
    image: AddressSpace,
    mut dispatcher: SyscallDispatcher,
    max_traps: usize,
) -> Result<RunResult, RuntimeError> {
    let mut trap = HvfTrapEngine::new()?;
    trap.map_address_space(&image)?;
    // Hand the dispatcher the real region list so `/proc/self/maps`
    // reflects the loaded ELF, runtime regions, bootstrap pages, and
    // stack instead of the legacy hard-coded summary. Go's runtime
    // and glibc's malloc introspection both parse this file.
    dispatcher.set_address_space_regions(proc_maps_from_address_space(&image));
    run_threaded_hvf_loop(trap, dispatcher, max_traps)
}

/// Convert the engine's `AddressSpace` regions into the dispatcher's
/// `ProcMapsEntry` view. Region paths are left empty here — the
/// `/proc/self/maps` renderer applies labels based on each region's
/// start address (matching the well-known runtime bases in
/// `crate::memory`).
fn proc_maps_from_address_space(image: &AddressSpace) -> Vec<ProcMapsEntry> {
    image
        .regions()
        .iter()
        .map(|region| ProcMapsEntry {
            start: region.start,
            end: region.end,
            read: region.perms.read,
            write: region.perms.write,
            execute: region.perms.execute,
            path: String::new(),
        })
        .collect()
}

pub fn run_syscall_loop<M, T>(
    memory: &mut M,
    trap: &mut T,
    max_traps: usize,
) -> Result<RunResult, RuntimeError>
where
    M: GuestMemory,
    T: SyscallTrap,
{
    run_syscall_loop_with_dispatcher(memory, trap, SyscallDispatcher::new(), max_traps)
}

pub fn run_syscall_loop_with_dispatcher<M, T>(
    memory: &mut M,
    trap: &mut T,
    dispatcher: SyscallDispatcher,
    max_traps: usize,
) -> Result<RunResult, RuntimeError>
where
    M: GuestMemory,
    T: SyscallTrap,
{
    run_split_loop(memory, trap, dispatcher, max_traps)
}

pub fn run_combined_syscall_loop<R>(
    runtime: &mut R,
    max_traps: usize,
) -> Result<RunResult, RuntimeError>
where
    R: GuestMemory + SyscallTrap,
{
    run_combined_syscall_loop_with_dispatcher(runtime, SyscallDispatcher::new(), max_traps)
}

pub fn run_combined_syscall_loop_with_dispatcher<R>(
    runtime: &mut R,
    mut dispatcher: SyscallDispatcher,
    max_traps: usize,
) -> Result<RunResult, RuntimeError>
where
    R: GuestMemory + SyscallTrap,
{
    let mut reporter = CompatReporter::default();
    crate::host_signal::install_default_handlers();
    // Snapshot the host stdin termios so a guest crash mid-`stty raw`
    // doesn't leave the user's terminal wedged. The guard drops at the
    // end of this function and restores the saved state if we touched
    // it.
    let _termios_guard = crate::host_tty::TermiosRestoreGuard::new();

    // Per-thread blocking-I/O waiter (owns this thread's kqueue). Recreated in
    // a forked child below (kqueue is not inherited across fork).
    let mut waiter = crate::io_wait::ThreadWaiter::new();
    for traps in 1..=max_traps {
        let frame = runtime.next_syscall()?;
        if std::env::var_os("CARRICK_TRACE_TRAPS").is_some() {
            let name = crate::syscall::lookup_aarch64(frame.x8)
                .map(|s| s.name)
                .unwrap_or("<unknown>");
            eprintln!(
                "trap#{traps}: x8={} ({name}) x0={:#x} x1={:#x} x2={:#x} x3={:#x} x4={:#x} x5={:#x}",
                frame.x8, frame.x0, frame.x1, frame.x2, frame.x3, frame.x4, frame.x5
            );
        }
        // Service blocking I/O (WaitOnFds) by waiting WITHOUT re-entering the
        // dispatcher's blocking path: poll the host fds, then re-dispatch on
        // readiness (single-threaded, so no lock contention, but the same code
        // path keeps semantics identical across runtimes).
        let outcome = loop {
            let oc = dispatcher.dispatch(
                SyscallRequest::from_aarch64_frame(frame),
                runtime,
                &mut reporter,
            )?;
            match oc {
                DispatchOutcome::WaitOnFds { fds, timeout, on_timeout } => {
                    match waiter.wait(&fds, timeout) {
                        crate::io_wait::WaitResult::Ready => continue,
                        crate::io_wait::WaitResult::TimedOut => {
                            break DispatchOutcome::Returned { value: on_timeout }
                        }
                        crate::io_wait::WaitResult::Interrupted => {
                            break DispatchOutcome::Errno { errno: crate::linux_abi::LINUX_EINTR }
                        }
                    }
                }
                other => break other,
            }
        };

        let mut last_syscall_retval: Option<i64> = None;

        match outcome {
            DispatchOutcome::WaitOnFds { .. } => unreachable!("serviced by the wait loop above"),
            DispatchOutcome::Exit { code } => {
                crate::probes::guest_exit(code);
                if runtime.is_forked_child() {
                    forked_child_exit(code, dispatcher.stdout(), dispatcher.stderr());
                }
                return Ok(RunResult {
                    exit_code: code,
                    stdout: dispatcher.stdout().to_vec(),
                    stderr: dispatcher.stderr().to_vec(),
                    traps,
                    report: reporter.finish(),
                    trap_limit_hit: false,
                });
            }
            DispatchOutcome::Returned { value } => {
                runtime.complete_syscall(value)?;
                last_syscall_retval = Some(value);
            }
            DispatchOutcome::Errno { errno } => {
                let value = -(errno as i64);
                runtime.complete_syscall(value)?;
                last_syscall_retval = Some(value);
            }
            DispatchOutcome::Fork => {
                let outcome = runtime.fork()?;
                let retval: i64 = match outcome {
                    crate::trap::ForkOutcome::Parent { child_pid } => i64::from(child_pid),
                    crate::trap::ForkOutcome::Child => {
                        dispatcher.clear_output_buffers();
                        // kqueue is NOT inherited across fork, and the inherited
                        // self-pipe is shared with the parent — give the child
                        // fresh ones so its parked-thread wakes are its own.
                        crate::host_signal::reinit_after_fork();
                        waiter = crate::io_wait::ThreadWaiter::new();
                        0
                    }
                };
                runtime.complete_syscall(retval)?;
                last_syscall_retval = Some(retval);
            }
            DispatchOutcome::Execve { path, argv, env } => {
                crate::probes::execve_argv(&path, &argv);
                // Reflect the new program into the host process name
                // (`carrick: <basename>`), so a hung forked-exec'd
                // child is identifiable in `ps -M` / Activity Monitor.
                let base = path.rsplit('/').next().unwrap_or(&path);
                crate::dispatch::set_host_process_name(base.as_bytes());
                match load_execve_image(&dispatcher, &path, argv, env) {
                    Ok(new_image) => {
                        crate::probes::execve_loaded(
                            &path,
                            new_image.entry(),
                            new_image.initial_stack_pointer().unwrap_or(0),
                            new_image.regions().len() as u64,
                        );
                        dispatcher.close_cloexec_fds();
                        runtime.execve_into(&new_image)?;
                    }
                    Err(errno) => {
                        let value = -(errno as i64);
                        runtime.complete_syscall(value)?;
                        last_syscall_retval = Some(value);
                    }
                }
            }
            DispatchOutcome::SigReturn => {
                // Pop the Carrick sigframe at SP_EL0 and restore the
                // pre-signal register state. No `complete_syscall` —
                // the restored x0 IS the syscall return value the
                // pre-empted caller observes.
                runtime.restore_from_sigframe()?;
                // Deliver the NEXT pending signal (if any) before resuming the
                // restored context — the kernel delivers all deliverable pending
                // signals back-to-back before returning to userspace. The just-
                // handled signal was already cleared from the pending set when
                // delivered, so this can't re-deliver it. `last_syscall_retval`
                // is None on this path, so the next inject preserves the
                // restored x0.
            }
            DispatchOutcome::CloneThread { .. }
            | DispatchOutcome::ThreadExit { .. }
            | DispatchOutcome::FutexWait { .. } => {
                // These are emitted only on the multi-threaded
                // `dispatch_threaded` path (run_vcpu_until_exit). The
                // single-threaded loops here always pass `thread: None`, so
                // the dispatcher never produces them.
                unreachable!("thread-clone outcomes only arise on the threaded runtime path")
            }
        }

        if let Some(action) =
                deliver_pending_signal(runtime, &mut dispatcher, last_syscall_retval)?
                && let Some(signum) = action.term_signal {
                    if runtime.is_forked_child() {
                        forked_child_die_by_signal(
                            signum,
                            dispatcher.stdout(),
                            dispatcher.stderr(),
                        );
                    }
                    return Ok(RunResult {
                        exit_code: 128 + signum,
                        stdout: dispatcher.stdout().to_vec(),
                        stderr: dispatcher.stderr().to_vec(),
                        traps,
                        report: reporter.finish(),
                        trap_limit_hit: false,
                    });
                }
    }

    Ok(RunResult {
        exit_code: -1,
        stdout: dispatcher.stdout().to_vec(),
        stderr: dispatcher.stderr().to_vec(),
        traps: max_traps,
        report: reporter.finish(),
        trap_limit_hit: true,
    })
}

// ===================================================================
// Multi-threaded HVF runtime: one host thread + one HVF vCPU per guest
// thread, sharing ONE process VM (stage-2 mappings are visible to every
// vCPU). All syscall servicing serialises through ONE big kernel lock
// (`Arc<Mutex<KernelState>>`); guest user-mode runs truly concurrently,
// handlers run one at a time. See [[plan-syscall-macro-split]] /
// thread-creating-clone plan Task 5+6.
// ===================================================================

use crate::thread::{FutexTable, ThreadId, ThreadRegistry};
use std::sync::{Arc, Mutex};

/// All shared kernel state behind the big lock: the syscall dispatcher
/// (open-fd table, fs/mem/proc/etc.) and the compat reporter. Wrapped so a
/// single mutex serialises every handler across all guest-thread vCPUs.
struct KernelState {
    dispatcher: SyscallDispatcher,
    reporter: CompatReporter,
}

/// `SyscallDispatcher` holds `Rc<RefCell<OpenDescription>>` (non-atomic
/// refcounts), so it is `!Send` by default. The big `Mutex<KernelState>`
/// guarantees only ONE host thread ever touches the dispatcher at a time —
/// the `Rc` refcounts are therefore never updated concurrently — so moving
/// the `Arc<Mutex<KernelState>>` across threads and locking it per syscall
/// is sound. We assert that with this wrapper.
// SAFETY invariant documented on SendKernel: the Mutex serialises all access to the !Send dispatcher.
#[allow(clippy::arc_with_non_send_sync)]
struct SendKernel(Arc<Mutex<KernelState>>);
// SAFETY: see the type doc — the Mutex serialises all access to the
// non-atomic-refcounted Rc state, so concurrent refcount mutation (the only
// reason SyscallDispatcher is !Send) cannot occur.
unsafe impl Send for SendKernel {}

impl SendKernel {
    fn clone_handle(&self) -> SendKernel {
        SendKernel(Arc::clone(&self.0))
    }
}

/// What a single vCPU loop did when it stopped.
enum VcpuLoopOutcome {
    /// Whole-process exit (last thread, exit_group, or fatal signal). Carries
    /// the assembled RunResult so the main thread can return it.
    ProcessExit(Box<RunResult>),
    /// Just this thread finished (`exit(2)` with siblings still alive). The
    /// host thread returns; its vCPU is left to the kernel at process exit.
    ThreadDone,
    /// Trap limit hit without exit (used for the main thread's RunResult).
    TrapLimit(Box<RunResult>),
}

/// Top-level multi-threaded HVF entry. Builds the shared kernel lock + the
/// thread registry + futex table, then runs the MAIN guest thread's vCPU
/// through `run_vcpu_until_exit`. Thread-creating clones spawn sibling host
/// threads that run the same function on their own vCPU.
fn run_threaded_hvf_loop(
    trap: HvfTrapEngine,
    dispatcher: SyscallDispatcher,
    max_traps: usize,
) -> Result<RunResult, RuntimeError> {
    crate::host_signal::install_default_handlers();
    let _termios_guard = crate::host_tty::TermiosRestoreGuard::new();

    let main_tid: ThreadId = std::process::id() as ThreadId;
    let registry = Arc::new(ThreadRegistry::new(main_tid));
    let futex = Arc::new(FutexTable::new());
    // SAFETY invariant documented on SendKernel: the Mutex serialises all access to the !Send dispatcher.
    #[allow(clippy::arc_with_non_send_sync)]
    let kernel = SendKernel(Arc::new(Mutex::new(KernelState {
        dispatcher,
        reporter: CompatReporter::default(),
    })));
    // Track spawned sibling threads so the process doesn't tear down while a
    // worker is mid-flight. We join them after the main thread finishes.
    let threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>> =
        Arc::new(Mutex::new(Vec::new()));

    let outcome = run_vcpu_until_exit(
        kernel.clone_handle(),
        trap,
        Arc::clone(&registry),
        Arc::clone(&futex),
        main_tid,
        Arc::clone(&threads),
        max_traps,
    )?;

    let result = match outcome {
        VcpuLoopOutcome::ProcessExit(r) | VcpuLoopOutcome::TrapLimit(r) => *r,
        VcpuLoopOutcome::ThreadDone => {
            // The main thread ran exit(2) while siblings were alive. Assemble
            // a result from the shared kernel buffers; siblings keep running
            // until the process exits, but for the run-to-completion CLI we
            // collect output now.
            #[allow(clippy::expect_used)]
            let mut k = kernel.0.lock().expect("kernel lock poisoned");
            let report = std::mem::take(&mut k.reporter).finish();
            RunResult {
                exit_code: 0,
                stdout: k.dispatcher.stdout().to_vec(),
                stderr: k.dispatcher.stderr().to_vec(),
                traps: 0,
                report,
                trap_limit_hit: false,
            }
        }
    };

    Ok(result)
}

/// Run one vCPU (one guest thread) until it exits the process, finishes its
/// own thread, or hits the trap limit. Holds NO lock during the vCPU run;
/// takes the big kernel lock only to dispatch + complete each syscall.
#[allow(clippy::too_many_arguments)]
fn run_vcpu_until_exit(
    kernel: SendKernel,
    mut engine: HvfTrapEngine,
    mut registry: Arc<ThreadRegistry>,
    futex: Arc<FutexTable>,
    mut this_tid: ThreadId,
    threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    max_traps: usize,
) -> Result<VcpuLoopOutcome, RuntimeError> {
    let trace = std::env::var_os("CARRICK_TRACE_TRAPS").is_some();
    // Per-thread blocking-I/O waiter (owns this thread's kqueue). Recreated in
    // a forked child below (kqueue is not inherited across fork).
    let mut waiter = crate::io_wait::ThreadWaiter::new();
    for traps in 1..=max_traps {
        // ---- vCPU run: NO kernel lock held ----
        let frame = engine.next_syscall()?;
        if trace {
            let name = crate::syscall::lookup_aarch64(frame.x8)
                .map(|s| s.name)
                .unwrap_or("<unknown>");
            eprintln!(
                "tid#{this_tid} trap#{traps}: x8={} ({name}) x0={:#x} x1={:#x} x2={:#x} x3={:#x} x4={:#x}",
                frame.x8, frame.x0, frame.x1, frame.x2, frame.x3, frame.x4
            );
        }

        // ---- syscall service: kernel lock held ONLY during dispatch ----
        // A blocking-mode I/O syscall returns WaitOnFds; we then wait on the
        // host fds with the lock RELEASED (the block above dropped it) so
        // sibling threads run — the whole point of fixing the big kernel lock.
        // On readiness we re-dispatch (re-take the lock briefly); on timeout /
        // signal we synthesize the terminal outcome.
        let outcome = loop {
            let oc = {
                #[allow(clippy::expect_used)]
                let mut k = kernel.0.lock().expect("kernel lock poisoned");
                let KernelState { dispatcher, reporter } = &mut *k;
                dispatcher.dispatch_threaded(
                    SyscallRequest::from_aarch64_frame(frame),
                    &mut engine,
                    reporter,
                    this_tid,
                    &registry,
                    &futex,
                )?
            };
            match oc {
                DispatchOutcome::WaitOnFds { fds, timeout, on_timeout } => {
                    match waiter.wait(&fds, timeout) {
                        crate::io_wait::WaitResult::Ready => continue,
                        crate::io_wait::WaitResult::TimedOut => {
                            break DispatchOutcome::Returned { value: on_timeout }
                        }
                        crate::io_wait::WaitResult::Interrupted => {
                            break DispatchOutcome::Errno { errno: crate::linux_abi::LINUX_EINTR }
                        }
                    }
                }
                other => break other,
            }
        };

        let mut last_syscall_retval: Option<i64> = None;

        match outcome {
            DispatchOutcome::WaitOnFds { .. } => unreachable!("serviced by the wait loop above"),
            DispatchOutcome::Exit { code } => {
                // A forked child process (real macOS fork) exits via _exit so
                // the rebuilt HVF context doesn't run the panicky Drops, and
                // its buffered stdio is flushed to the inherited host fds.
                if engine.is_forked_child() {
                    crate::probes::guest_exit(code);
                    #[allow(clippy::expect_used)]
                    let k = kernel.0.lock().expect("kernel lock poisoned");
                    forked_child_exit(code, k.dispatcher.stdout(), k.dispatcher.stderr());
                }
                // exit_group, or exit(2) as the last live thread. Tear the
                // whole process down. For the main thread we return a
                // RunResult; siblings just terminate the process.
                let last = registry.exit(this_tid);
                if !last && this_tid != (std::process::id() as ThreadId) {
                    // A sibling ran exit_group(94): flush shared buffers and
                    // terminate the entire process (other threads share it).
                    #[allow(clippy::expect_used)]
                    let k = kernel.0.lock().expect("kernel lock poisoned");
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                    let _ = std::io::Write::flush(&mut std::io::stderr());
                    let out = k.dispatcher.stdout().to_vec();
                    let err = k.dispatcher.stderr().to_vec();
                    drop(k);
                    let _ = unsafe { libc::write(1, out.as_ptr() as *const _, out.len()) };
                    let _ = unsafe { libc::write(2, err.as_ptr() as *const _, err.len()) };
                    unsafe { libc::_exit(code) };
                }
                let result = assemble_run_result(&kernel, code, traps, false);
                return Ok(VcpuLoopOutcome::ProcessExit(Box::new(result)));
            }
            DispatchOutcome::Returned { value } => {
                engine.complete_syscall(value)?;
                last_syscall_retval = Some(value);
            }
            DispatchOutcome::Errno { errno } => {
                let v = -(errno as i64);
                engine.complete_syscall(v)?;
                last_syscall_retval = Some(v);
            }
            DispatchOutcome::FutexWait { addr, timeout } => {
                // Block with the kernel lock RELEASED so a sibling FUTEX_WAKE
                // can run. The wait is interrupted if a signal becomes pending
                // so even an all-threads-parked process delivers it; the
                // ungated signal check below then runs. Re-lock only to
                // complete the syscall.
                use crate::thread::FutexWaitOutcome;
                let retval: i64 = match futex.wait(addr, timeout, &crate::host_signal::has_pending)
                {
                    FutexWaitOutcome::Woken => 0,
                    FutexWaitOutcome::TimedOut => -(crate::linux_abi::LINUX_ETIMEDOUT as i64),
                    FutexWaitOutcome::Interrupted => -(crate::linux_abi::LINUX_EINTR as i64),
                };
                engine.complete_syscall(retval)?;
                last_syscall_retval = Some(retval);
            }
            DispatchOutcome::CloneThread {
                stack,
                tls,
                flags: _,
                parent_tid_addr,
                child_tid_addr,
            } => {
                const CLONE_CHILD_CLEARTID: u64 = 0x00200000;
                const CLONE_CHILD_SETTID: u64 = 0x01000000;
                // The flags were already validated by the dispatcher; recover
                // the clear/settid intents from the addrs it passed (it only
                // sets child_tid_addr when one of those flags is present).
                let clear_addr = if child_tid_addr != 0 { child_tid_addr } else { 0 };

                // Allocate the child tid + register it (under the kernel lock
                // for ordering with live_count/exit, though the registry has
                // its own lock).
                let tid = registry.register_child(clear_addr);

                // Write parent_tid / child_tid (i32 LE) into guest memory as
                // requested by CLONE_PARENT_SETTID / CLONE_CHILD_SETTID. The
                // dispatcher passes the addrs only when the flag is set.
                let tid_bytes = tid.to_le_bytes();
                if parent_tid_addr != 0 {
                    let _ = engine.write_bytes(parent_tid_addr, &tid_bytes);
                }
                let _ = CLONE_CHILD_SETTID;
                let _ = CLONE_CHILD_CLEARTID;
                if child_tid_addr != 0 {
                    // CLONE_CHILD_SETTID writes the tid; CLONE_CHILD_CLEARTID
                    // wants it cleared on exit (recorded above). Writing the
                    // tid here is correct for SETTID and harmless for a pure
                    // CLEARTID word the child will overwrite. glibc passes the
                    // same address for both.
                    let _ = engine.write_bytes(child_tid_addr, &tid_bytes);
                }

                // Build the child spec (snapshot parent regs + share VM +
                // mapping descriptors) BEFORE the parent resumes.
                let spec = engine.build_thread_spec(stack, tls)?;

                // Spawn the sibling host thread.
                let child_kernel = kernel.clone_handle();
                let child_registry = Arc::clone(&registry);
                let child_futex = Arc::clone(&futex);
                let child_threads = Arc::clone(&threads);
                let handle = std::thread::Builder::new()
                    .name(format!("guest-tid-{tid}"))
                    .spawn(move || {
                        if std::env::var_os("CARRICK_TRACE_TRAPS").is_some() {
                            eprintln!("[sibling tid#{tid}] thread started, building vCPU");
                        }
                        match HvfTrapEngine::from_thread_spec(spec) {
                            Ok(child_engine) => {
                                if std::env::var_os("CARRICK_TRACE_TRAPS").is_some() {
                                    let pc = child_engine.program_counter().unwrap_or(0);
                                    eprintln!("[sibling tid#{tid}] vCPU built, pc={pc:#x}, entering loop");
                                }
                                let r = run_vcpu_until_exit(
                                    child_kernel,
                                    child_engine,
                                    child_registry,
                                    child_futex,
                                    tid,
                                    child_threads,
                                    max_traps,
                                );
                                if let Err(e) = r {
                                    tracing::error!(tid, error = %e, "thread sibling vCPU loop failed");
                                }
                            }
                            Err(e) => {
                                tracing::error!(tid, error = %e, "thread sibling vCPU failed to start");
                                // Remove the failed thread so live_count stays
                                // accurate (parent already saw tid via clone).
                                child_registry.exit(tid);
                            }
                        }
                    })
                    .map_err(|e| RuntimeError::Trap(TrapError::Hypervisor(format!(
                        "spawn guest thread failed: {e}"
                    ))))?;
                #[allow(clippy::expect_used)]
                threads.lock().expect("threads lock poisoned").push(handle);

                // Parent's clone(2) returns the child tid.
                engine.complete_syscall(tid as i64)?;
            }
            DispatchOutcome::ThreadExit { code } => {
                // CLONE_CHILD_CLEARTID: zero the word + wake one waiter.
                if let Some(addr) = registry.clear_child_tid(this_tid)
                    && addr != 0 {
                        let _ = engine.write_bytes(addr, &0i32.to_le_bytes());
                        futex.wake(addr, 1);
                    }
                let last = registry.exit(this_tid);
                if last {
                    let result = assemble_run_result(&kernel, code, traps, false);
                    return Ok(VcpuLoopOutcome::ProcessExit(Box::new(result)));
                }
                // Not last: this host thread is done. Its vCPU + VM-clone Arc
                // leak to process exit (the forked-child Drop discipline).
                return Ok(VcpuLoopOutcome::ThreadDone);
            }
            DispatchOutcome::Execve { path, argv, env } => {
                crate::probes::execve_argv(&path, &argv);
                let base = path.rsplit('/').next().unwrap_or(&path).to_owned();
                crate::dispatch::set_host_process_name(base.as_bytes());
                #[allow(clippy::expect_used)]
                let image = {
                    let mut k = kernel.0.lock().expect("kernel lock poisoned");
                    let res = load_execve_image(&k.dispatcher, &path, argv, env);
                    match res {
                        Ok(img) => {
                            crate::probes::execve_loaded(
                                &path,
                                img.entry(),
                                img.initial_stack_pointer().unwrap_or(0),
                                img.regions().len() as u64,
                            );
                            k.dispatcher.close_cloexec_fds();
                            Some(img)
                        }
                        Err(errno) => {
                            drop(k);
                            engine.complete_syscall(-(errno as i64))?;
                            None
                        }
                    }
                };
                if let Some(img) = image {
                    engine.execve_into(&img)?;
                }
            }
            DispatchOutcome::SigReturn => {
                engine.restore_from_sigframe()?;
                // Deliver the next pending signal (if any) before resuming —
                // the kernel delivers all deliverable pending signals before
                // returning to userspace. The just-handled signal was cleared
                // when delivered, so this can't re-deliver it.
            }
            DispatchOutcome::Fork => {
                // Process-creating fork. Real macOS fork of a MULTI-vCPU HVF
                // process is unsafe (other vCPUs/threads would be left in an
                // inconsistent HVF state), so only allow it when this is the
                // sole live guest thread — which is the overwhelmingly common
                // case (apt's http method, dpkg's tar subprocess, etc. fork
                // before any pthread_create). With siblings alive, surface
                // ENOSYS so glibc falls back rather than wedging the VM.
                if registry.live_count() > 1 {
                    engine.complete_syscall(-(crate::linux_abi::LINUX_ENOSYS as i64))?;
                } else {
                    let fork_outcome = engine.fork()?;
                    let retval: i64 = match fork_outcome {
                        crate::trap::ForkOutcome::Parent { child_pid } => i64::from(child_pid),
                        crate::trap::ForkOutcome::Child => {
                            #[allow(clippy::expect_used)]
                            let mut k = kernel.0.lock().expect("kernel lock poisoned");
                            k.dispatcher.clear_output_buffers();
                            // A forked process is single-threaded by definition
                            // (fork copies only the calling thread). Reset to a
                            // fresh registry keyed by the child's host pid so
                            // gettid/getpid/kill-self all agree (the inherited
                            // registry could carry stale sibling tids from the
                            // parent, breaking self-signal targeting). live_count
                            // becomes 1, restoring single-threaded signal
                            // delivery + real fork in the child.
                            this_tid = std::process::id() as ThreadId;
                            registry = Arc::new(ThreadRegistry::new(this_tid));
                            // kqueue isn't inherited across fork; the self-pipe
                            // is shared with the parent. Fresh ones for the child.
                            crate::host_signal::reinit_after_fork();
                            waiter = crate::io_wait::ThreadWaiter::new();
                            0
                        }
                    };
                    engine.complete_syscall(retval)?;
                    last_syscall_retval = Some(retval);
                }
            }
        }

        // Signal delivery. host_signal is process-global with an atomic
        // pending slot, so `take_pending` (inside deliver_pending_signal,
        // under the kernel lock) drains it exactly once: whichever thread
        // grabs it delivers the process-directed signal to ITS vCPU, which is
        // valid Linux semantics (an arbitrary unblocking thread handles it).
        // Threads parked in FUTEX_WAIT interrupt on a pending signal (see the
        // FutexWait arm) and reach here too. No live_count gate — multi-
        // threaded guests deliver while running. Per-thread signal masks /
        // tgkill targeting remain a follow-up.
        {
            #[allow(clippy::expect_used)]
            let mut k = kernel.0.lock().expect("kernel lock poisoned");
            if let Some(action) =
                deliver_pending_signal(&mut engine, &mut k.dispatcher, last_syscall_retval)?
                && let Some(signum) = action.term_signal {
                    if engine.is_forked_child() {
                        let out = k.dispatcher.stdout().to_vec();
                        let err = k.dispatcher.stderr().to_vec();
                        drop(k);
                        forked_child_die_by_signal(signum, &out, &err);
                    }
                    drop(k);
                    let result = assemble_run_result(&kernel, 128 + signum, traps, false);
                    return Ok(VcpuLoopOutcome::ProcessExit(Box::new(result)));
                }
        }
    }

    let result = assemble_run_result(&kernel, -1, max_traps, true);
    Ok(VcpuLoopOutcome::TrapLimit(Box::new(result)))
}

/// Snapshot the shared kernel buffers + reporter into a RunResult. Called on
/// whole-process exit / trap limit.
fn assemble_run_result(
    kernel: &SendKernel,
    exit_code: i32,
    traps: usize,
    trap_limit_hit: bool,
) -> RunResult {
    crate::probes::guest_exit(exit_code);
    #[allow(clippy::expect_used)]
    let mut k = kernel.0.lock().expect("kernel lock poisoned");
    let report = std::mem::take(&mut k.reporter).finish();
    RunResult {
        exit_code,
        stdout: k.dispatcher.stdout().to_vec(),
        stderr: k.dispatcher.stderr().to_vec(),
        traps,
        report,
        trap_limit_hit,
    }
}

/// Outcome of `deliver_pending_signal`. `term_signal` is `Some(signum)` when
/// the pending signal had no installed handler and the default action
/// (terminate) applies. The conventional process exit code is `128 + signum`,
/// but a forked child instead dies BY this signal (see
/// `forked_child_die_by_signal`) so the parent's `wait4` reports WIFSIGNALED.
struct PendingSignalAction {
    term_signal: Option<i32>,
}

/// Drain whatever signal is sitting in the host pending slot and
/// dispatch it to the guest. Returns `Ok(None)` when nothing was
/// pending. Returns `Ok(Some(...))` with `exit_code: Some(code)` when
/// a default-action signal fires (the runtime should treat this like
/// an `exit_group(code)`). Returns `Ok(Some(...))` with
/// `exit_code: None` when the handler was injected (or the signal was
/// SIG_IGN'd) and the vCPU should resume.
fn deliver_pending_signal<T>(
    trap: &mut T,
    dispatcher: &mut SyscallDispatcher,
    last_syscall_retval: Option<i64>,
) -> Result<Option<PendingSignalAction>, RuntimeError>
where
    T: SyscallTrap,
{
    let pending = crate::host_signal::take_pending();
    let pending = if pending == 0 {
        // Nothing newly arrived in the host slot. Deliver the next signal that
        // was raised while blocked and has since been unblocked (held in the
        // dispatcher's pending set) — one per cycle, so each handler runs and
        // returns via rt_sigreturn before the next is injected (matching the
        // kernel delivering all pending signals before returning to userspace).
        match dispatcher.take_deliverable_pending() {
            Some(s) => s,
            None => return Ok(None),
        }
    } else {
        pending
    };
    // A blocked signal must not be delivered — hold it pending until the
    // guest unblocks it (rt_sigprocmask) or waits for it (rt_sigtimedwait).
    if dispatcher.signal_blocked(pending) {
        dispatcher.mark_signal_pending(pending);
        return Ok(Some(PendingSignalAction { term_signal: None }));
    }
    if dispatcher.signal_is_ignored(pending) {
        return Ok(Some(PendingSignalAction { term_signal: None }));
    }
    match dispatcher.registered_signal_handler(pending) {
        Some(action) => {
            // Block the signal (+ its sa_mask) for the duration of the handler,
            // as the kernel does — restored by rt_sigreturn. Prevents the same
            // signal re-entering its own handler and a nested injected sigframe
            // clobbering the live handler's stack frame (saved LR -> wild `ret`).
            // sa_restorer is only valid when SA_RESTORER is set in sa_flags;
            // otherwise the kernel ignores the field (it may hold uninitialised
            // garbage) and returns via the VDSO trampoline. glibc on aarch64
            // never sets SA_RESTORER, so pass 0 and let inject_signal synthesise
            // a trampoline. (Using the garbage restorer made the handler `ret`
            // to a wild PC — the "PROT_REA" crash.)
            let restorer = if action.sa_flags & crate::linux_abi::LINUX_SA_RESTORER != 0 {
                action.sa_restorer
            } else {
                0
            };
            trap.inject_signal(pending, action.sa_handler, restorer, last_syscall_retval)?;
            Ok(Some(PendingSignalAction { term_signal: None }))
        }
        None => Ok(Some(PendingSignalAction {
            term_signal: Some(pending),
        })),
    }
}

/// Build a new AddressSpace for an execve target. Resolves the path
/// through the dispatcher's rootfs when present; falls back to the
/// host filesystem otherwise (useful for tests where no rootfs is
/// configured).
fn load_execve_image(
    dispatcher: &SyscallDispatcher,
    path: &str,
    argv: Vec<String>,
    env: Vec<String>,
) -> Result<AddressSpace, i32> {
    use crate::linux_abi::LINUX_ENOENT;
    let mut argv = if argv.is_empty() {
        vec![path.to_string()]
    } else {
        argv
    };

    // Resolve `#!` shebang scripts the way the Linux kernel does: read
    // the file, and if it begins with `#!`, re-target exec at the
    // interpreter with the script path spliced into argv. Bounded to 4
    // levels (Linux's BINPRM_MAX_RECURSION) to stop interpreter loops.
    let mut path = path.to_string();
    for _ in 0..4 {
        let Some(head) = dispatcher.read_exec_file(&path) else {
            break;
        };
        if !head.starts_with(b"#!") {
            break;
        }
        let Some((interp, optarg)) = parse_shebang(&head) else {
            return Err(LINUX_ENOENT);
        };
        // Linux: execve("/script", ["script", a, b]) on `#!/i x` ->
        // execve("/i", ["/i", "x", "/script", a, b]). The script path
        // takes argv[1] (or [2] with an interpreter arg); the original
        // argv[1..] follow.
        let mut new_argv = Vec::with_capacity(argv.len() + 3);
        new_argv.push(interp.clone());
        if let Some(arg) = optarg {
            new_argv.push(arg);
        }
        new_argv.push(path.clone());
        new_argv.extend(argv.into_iter().skip(1));
        argv = new_argv;
        path = interp;
    }

    // Read the main binary AND resolve its interpreter OVERLAY-FIRST via
    // `read_exec_file`, so execve works for guest-created/overlay binaries
    // (downloaded/extracted ELF, /tmp/p, dpkg-unpacked binary) and needs no
    // in-memory rootfs layer (which `--fs host` drops after seeding). When
    // there's no overlay/rootfs at all (e.g. a bare RunElf test), fall back
    // to reading the main binary straight off the host filesystem.
    let raw = match dispatcher.read_exec_file(&path) {
        Some(bytes) => {
            AddressSpace::load_elf_bytes_with_reader(&bytes, &|p| dispatcher.read_exec_file(p))
                .map_err(|_| LINUX_ENOENT)?
        }
        None => AddressSpace::load_elf(&path).map_err(|_| LINUX_ENOENT)?,
    };
    raw.with_el0_trampoline()
        .and_then(|a| a.with_el1_vectors())
        .and_then(|a| a.with_stage1_page_tables())
        .and_then(|a| a.with_linux_initial_stack(argv, env))
        .map_err(|_| LINUX_ENOENT)
}

/// Parse a `#!` shebang line into (interpreter, optional single arg),
/// matching Linux semantics: skip blanks after `#!`, take the
/// interpreter up to the next whitespace, then the remainder of the
/// line (trimmed) as ONE argument. Only the first line is consulted.
fn parse_shebang(head: &[u8]) -> Option<(String, Option<String>)> {
    let line_end = head.iter().position(|&b| b == b'\n').unwrap_or(head.len());
    // Linux caps the shebang line at BINPRM_BUF_SIZE (256); honour it.
    let line = &head[2..line_end.min(256)];
    let line = std::str::from_utf8(line).ok()?;
    let line = line.trim_start_matches([' ', '\t']);
    let mut parts = line.splitn(2, [' ', '\t']);
    let interp = parts.next()?.to_string();
    if interp.is_empty() {
        return None;
    }
    let optarg = parts
        .next()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    Some((interp, optarg))
}

/// Called from a forked child when the guest hits `exit_group`. Flushes
/// any buffered guest stdout/stderr to the host's fd 1 / fd 2 (which
/// the child inherited from the parent process) and then calls
/// `_exit(2)` to bypass Rust's normal Drop chain. Without this, the
/// rebuilt HVF context in the child would trigger an `applevisor::Vcpu`
/// Drop panic ("no VM or vCPU available") during shutdown.
fn forked_child_exit(code: i32, stdout_buf: &[u8], stderr_buf: &[u8]) -> ! {
    let _ = unsafe {
        libc::write(1, stdout_buf.as_ptr() as *const _, stdout_buf.len())
    };
    let _ = unsafe {
        libc::write(2, stderr_buf.as_ptr() as *const _, stderr_buf.len())
    };
    unsafe { libc::_exit(code) };
}

/// Called from a forked child when a default-action signal (no installed
/// handler) must terminate it. Flushes buffered stdio to the inherited host
/// fds, then makes THIS host process die *by* `signum` — resetting the
/// disposition to default and unblocking it first — so the parent's `wait4`
/// (a passthrough of host `waitpid`) reports WIFSIGNALED(signum) instead of a
/// normal exit with code `128 + signum`. The raw signal number round-trips:
/// the host status's low 7 bits carry whatever number we die by, and the
/// guest reads them back as a Linux signal number. Falls back to `_exit` if
/// the signal somehow doesn't terminate the host process (a few Linux signal
/// numbers map to default-ignore dispositions on macOS).
fn forked_child_die_by_signal(signum: i32, stdout_buf: &[u8], stderr_buf: &[u8]) -> ! {
    let _ = unsafe { libc::write(1, stdout_buf.as_ptr() as *const _, stdout_buf.len()) };
    let _ = unsafe { libc::write(2, stderr_buf.as_ptr() as *const _, stderr_buf.len()) };
    // `signum` is a Linux number; die by the corresponding HOST signal so the
    // host wait status carries the right value. `wait4` translates it back to
    // Linux for the parent guest, so the round-trip preserves WTERMSIG.
    let host_signum = crate::host_signal::linux_to_host_signum(signum);
    unsafe {
        libc::signal(host_signum, libc::SIG_DFL);
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, host_signum);
        libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        libc::raise(host_signum);
        // Only reached if the signal didn't terminate us (e.g. a Linux signal
        // number that is default-ignore on macOS). Preserve the conventional
        // shell exit code so behaviour degrades gracefully.
        libc::_exit(128 + signum)
    }
}

fn run_split_loop<M, T>(
    memory: &mut M,
    trap: &mut T,
    mut dispatcher: SyscallDispatcher,
    max_traps: usize,
) -> Result<RunResult, RuntimeError>
where
    M: GuestMemory,
    T: SyscallTrap,
{
    let mut reporter = CompatReporter::default();
    crate::host_signal::install_default_handlers();
    // Snapshot the host stdin termios so a guest crash mid-`stty raw`
    // doesn't leave the user's terminal wedged. The guard drops at the
    // end of this function and restores the saved state if we touched
    // it.
    let _termios_guard = crate::host_tty::TermiosRestoreGuard::new();

    // Per-thread blocking-I/O waiter (owns this thread's kqueue). Recreated in
    // a forked child below (kqueue is not inherited across fork).
    let mut waiter = crate::io_wait::ThreadWaiter::new();
    for traps in 1..=max_traps {
        let frame = trap.next_syscall()?;
        let outcome = loop {
            let oc = dispatcher.dispatch(
                SyscallRequest::from_aarch64_frame(frame),
                memory,
                &mut reporter,
            )?;
            match oc {
                DispatchOutcome::WaitOnFds { fds, timeout, on_timeout } => {
                    match waiter.wait(&fds, timeout) {
                        crate::io_wait::WaitResult::Ready => continue,
                        crate::io_wait::WaitResult::TimedOut => {
                            break DispatchOutcome::Returned { value: on_timeout }
                        }
                        crate::io_wait::WaitResult::Interrupted => {
                            break DispatchOutcome::Errno { errno: crate::linux_abi::LINUX_EINTR }
                        }
                    }
                }
                other => break other,
            }
        };

        let mut last_syscall_retval: Option<i64> = None;

        match outcome {
            DispatchOutcome::WaitOnFds { .. } => unreachable!("serviced by the wait loop above"),
            DispatchOutcome::Exit { code } => {
                if trap.is_forked_child() {
                    forked_child_exit(code, dispatcher.stdout(), dispatcher.stderr());
                }
                return Ok(RunResult {
                    exit_code: code,
                    stdout: dispatcher.stdout().to_vec(),
                    stderr: dispatcher.stderr().to_vec(),
                    traps,
                    report: reporter.finish(),
                    trap_limit_hit: false,
                });
            }
            DispatchOutcome::Returned { value } => {
                trap.complete_syscall(value)?;
                last_syscall_retval = Some(value);
            }
            DispatchOutcome::Errno { errno } => {
                let value = -(errno as i64);
                trap.complete_syscall(value)?;
                last_syscall_retval = Some(value);
            }
            DispatchOutcome::Fork => {
                let outcome = trap.fork()?;
                let retval: i64 = match outcome {
                    crate::trap::ForkOutcome::Parent { child_pid } => i64::from(child_pid),
                    crate::trap::ForkOutcome::Child => {
                        dispatcher.clear_output_buffers();
                        // kqueue is NOT inherited across fork, and the inherited
                        // self-pipe is shared with the parent — give the child
                        // fresh ones so its parked-thread wakes are its own.
                        crate::host_signal::reinit_after_fork();
                        waiter = crate::io_wait::ThreadWaiter::new();
                        0
                    }
                };
                trap.complete_syscall(retval)?;
                last_syscall_retval = Some(retval);
            }
            DispatchOutcome::Execve { path, argv, env } => {
                crate::probes::execve_argv(&path, &argv);
                // Reflect the new program into the host process name
                // (`carrick: <basename>`), so a hung forked-exec'd
                // child is identifiable in `ps -M` / Activity Monitor.
                let base = path.rsplit('/').next().unwrap_or(&path);
                crate::dispatch::set_host_process_name(base.as_bytes());
                match load_execve_image(&dispatcher, &path, argv, env) {
                    Ok(new_image) => {
                        crate::probes::execve_loaded(
                            &path,
                            new_image.entry(),
                            new_image.initial_stack_pointer().unwrap_or(0),
                            new_image.regions().len() as u64,
                        );
                        // Linux semantics: drop every fd marked FD_CLOEXEC.
                        // Without this, a forked-then-exec'd child keeps
                        // its parent's pipe ends open, which leaves the
                        // host kernel pipe in a state where the parent's
                        // POLLIN can't fire — the cause of the apt update
                        // deadlock between apt-main and its http method.
                        dispatcher.close_cloexec_fds();
                        trap.execve_into(&new_image)?;
                    }
                    Err(errno) => {
                        let value = -(errno as i64);
                        trap.complete_syscall(value)?;
                        last_syscall_retval = Some(value);
                    }
                }
            }
            DispatchOutcome::SigReturn => {
                trap.restore_from_sigframe()?;
                // Deliver the next pending signal (if any) before resuming —
                // the kernel delivers all deliverable pending signals before
                // returning to userspace. The just-handled signal was cleared
                // when delivered, so this can't re-deliver it.
            }
            DispatchOutcome::CloneThread { .. }
            | DispatchOutcome::ThreadExit { .. }
            | DispatchOutcome::FutexWait { .. } => {
                // These are emitted only on the multi-threaded
                // `dispatch_threaded` path (run_vcpu_until_exit). The
                // single-threaded loops here always pass `thread: None`, so
                // the dispatcher never produces them.
                unreachable!("thread-clone outcomes only arise on the threaded runtime path")
            }
        }

        if let Some(action) =
                deliver_pending_signal(trap, &mut dispatcher, last_syscall_retval)?
                && let Some(signum) = action.term_signal {
                    if trap.is_forked_child() {
                        forked_child_die_by_signal(
                            signum,
                            dispatcher.stdout(),
                            dispatcher.stderr(),
                        );
                    }
                    return Ok(RunResult {
                        exit_code: 128 + signum,
                        stdout: dispatcher.stdout().to_vec(),
                        stderr: dispatcher.stderr().to_vec(),
                        traps,
                        report: reporter.finish(),
                        trap_limit_hit: false,
                    });
                }
    }

    Ok(RunResult {
        exit_code: -1,
        stdout: dispatcher.stdout().to_vec(),
        stderr: dispatcher.stderr().to_vec(),
        traps: max_traps,
        report: reporter.finish(),
        trap_limit_hit: true,
    })
}

impl SyscallTrap for HvfTrapEngine {
    fn fork(&mut self) -> Result<crate::trap::ForkOutcome, TrapError> {
        self.fork()
    }

    fn execve_into(&mut self, new_image: &AddressSpace) -> Result<(), TrapError> {
        self.execve_into(new_image)
    }

    fn is_forked_child(&self) -> bool {
        HvfTrapEngine::is_forked_child(self)
    }

    fn next_syscall(&mut self) -> Result<Aarch64SyscallFrame, TrapError> {
        self.run_until_syscall()
    }

    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError> {
        self.complete_syscall(return_value)
    }

    fn inject_signal(
        &mut self,
        signum: i32,
        handler: u64,
        sa_restorer: u64,
        pending_syscall_retval: Option<i64>,
    ) -> Result<(), TrapError> {
        HvfTrapEngine::inject_signal(self, signum, handler, sa_restorer, pending_syscall_retval)
    }

    fn restore_from_sigframe(&mut self) -> Result<(), TrapError> {
        HvfTrapEngine::restore_from_sigframe(self)
    }
}
