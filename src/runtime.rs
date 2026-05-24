use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::compat::{CompatReport, CompatReporter};
use crate::dispatch::{
    Aarch64SyscallFrame, DispatchError, DispatchOutcome, GuestMemory, ProcMapsEntry,
    SyscallDispatcher, SyscallRequest,
};
use crate::memory::{AddressSpace, AddressSpaceError};
use crate::rootfs::RootFs;

/// Process-wide fork quiesce barrier (defined in `fork_quiesce` so the blocking
/// wait predicates can reach the same instance).
fn fork_barrier() -> &'static crate::fork_quiesce::QuiesceBarrier {
    crate::fork_quiesce::barrier()
}
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
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::other(format!("serialize: {e}")))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, bytes)
    }
}

/// Write a debug-state snapshot iff a path was provided. Returns the path
/// back so the CLI can mention it.
pub fn maybe_dump_debug_state(image: &AddressSpace, path: Option<&PathBuf>) -> Option<PathBuf> {
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
    /// Run the vCPU until it traps. `Ok(Some(frame))` is a guest syscall;
    /// `Ok(None)` means the vCPU was forced out of the guest by a cross-thread
    /// kick (`hv_vcpus_exit`, [`crate::vcpu_kick`]) with no syscall pending —
    /// the loop should run signal delivery and resume. `Err` is a real fault.
    fn next_syscall(&mut self) -> Result<Option<Aarch64SyscallFrame>, TrapError>;
    /// The guest PC the vCPU is currently parked at. Used as the resume address
    /// when injecting a signal on a non-syscall (kick) exit, where `ELR_EL1`
    /// does not hold a meaningful return address.
    fn current_pc(&self) -> Result<u64, TrapError>;
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
    /// `interrupted_pc` is `Some(pc)` when injecting on a non-syscall kick exit
    /// (the vCPU was mid-userspace; `pc` is where it should resume after the
    /// handler returns and is redirected via `Reg::PC` rather than `ELR_EL1`).
    /// `None` is the syscall-boundary case (resume via the post-svc `ELR_EL1`).
    /// `altstack` is `Some((ss_sp, ss_size))` when the handler was registered
    /// `SA_ONSTACK` and an alternate signal stack is installed — the frame is
    /// pushed onto that stack instead of the interrupted SP_EL0. `None` keeps
    /// the frame on the current stack.
    fn inject_signal(
        &mut self,
        signum: i32,
        handler: u64,
        sa_restorer: u64,
        pending_syscall_retval: Option<i64>,
        interrupted_pc: Option<u64>,
        altstack: Option<(u64, u64)>,
        saved_sigmask: u64,
        // Some((si_code, si_addr)) for a synchronous fault (SIGSEGV/SIGBUS),
        // None for a SI_USER-shaped delivery.
        fault_siginfo: Option<(i32, u64)>,
    ) -> Result<(), TrapError>;
    /// Restore vCPU state from the `CarrickSigframe` at SP_EL0. Called
    /// when the guest invokes `rt_sigreturn(2)`. Does NOT advance PC
    /// past the syscall the way `complete_syscall` does — the restored
    /// PC IS the next PC.
    fn restore_from_sigframe(&mut self) -> Result<u64, TrapError>;
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
    run_static_elf_with_hvf_args_and_dispatcher_debug(path, dispatcher, argv, env, max_traps, None)
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
    let path = path.as_ref();
    let argv: Vec<String> = argv.into_iter().collect();
    let env: Vec<String> = env.into_iter().collect();
    dispatcher.set_executable_identity(path.to_string_lossy().into_owned(), argv.clone());
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
    let image = AddressSpace::load_elf_bytes(bytes)?
        .with_el0_trampoline()?
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
    let argv: Vec<String> = argv.into_iter().collect();
    let env: Vec<String> = env.into_iter().collect();
    if let Some(first) = argv.first() {
        dispatcher.set_executable_identity(first.clone(), argv.clone());
    }
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
    let path = path.as_ref();
    let argv: Vec<String> = argv.into_iter().collect();
    let env: Vec<String> = env.into_iter().collect();
    dispatcher.set_executable_identity(path.to_string_lossy().into_owned(), argv.clone());
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
    let argv: Vec<String> = argv.into_iter().collect();
    let env: Vec<String> = env.into_iter().collect();
    dispatcher.set_executable_identity(path.to_owned(), argv.clone());
    let bytes = dispatcher.read_exec_file(path).ok_or_else(|| {
        RuntimeError::AddressSpace(AddressSpaceError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            path.to_owned(),
        )))
    })?;
    let image =
        AddressSpace::load_elf_bytes_with_reader(&bytes, &|p| dispatcher.read_exec_file(p))?
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
    // stack instead of the legacy hard-coded summary. Language runtimes,
    // malloc implementations, and debuggers all parse this file.
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
    let reporter = CompatReporter::default();
    crate::host_signal::install_default_handlers();
    // Snapshot the host stdin termios so a guest crash mid-`stty raw`
    // doesn't leave the user's terminal wedged. The guard drops at the
    // end of this function and restores the saved state if we touched
    // it.
    let _termios_guard = crate::host_tty::TermiosRestoreGuard::new();

    let this_tid = std::process::id() as ThreadId;
    // Per-thread blocking-I/O waiter (owns this thread's kqueue). Recreated in
    // a forked child below (kqueue is not inherited across fork).
    let mut waiter = crate::io_wait::ThreadWaiter::new(this_tid);
    let trace_traps = std::env::var_os("CARRICK_TRACE_TRAPS").is_some();
    for traps in 1..=max_traps {
        let frame = match runtime.next_syscall()? {
            Some(f) => f,
            None => {
                // Forced out of the guest by a kick (process-directed signal
                // pump). Deliver at the interrupted PC, then resume.
                let pc = runtime.current_pc()?;
                if let Some(action) =
                    deliver_pending_signal(runtime, &dispatcher, None, this_tid, Some(pc))?
                    && let Some(signum) = action.term_signal
                {
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
                continue;
            }
        };
        if trace_traps {
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
                &reporter,
            )?;
            match oc {
                DispatchOutcome::WaitOnFds {
                    fds,
                    timeout,
                    on_timeout,
                    block_signals,
                } => match waiter.wait(&fds, timeout, block_signals) {
                    crate::io_wait::WaitResult::Ready => continue,
                    crate::io_wait::WaitResult::TimedOut => {
                        break DispatchOutcome::Returned { value: on_timeout };
                    }
                    crate::io_wait::WaitResult::Interrupted => {
                        break DispatchOutcome::Errno {
                            errno: crate::linux_abi::LINUX_EINTR,
                        };
                    }
                },
                DispatchOutcome::WaitOnPollFds {
                    fds,
                    timeout,
                    on_timeout,
                    block_signals,
                } => match waiter.wait_poll(&fds, timeout, block_signals) {
                    crate::io_wait::WaitResult::Ready => continue,
                    crate::io_wait::WaitResult::TimedOut => {
                        break DispatchOutcome::Returned { value: on_timeout };
                    }
                    crate::io_wait::WaitResult::Interrupted => {
                        break DispatchOutcome::Errno {
                            errno: crate::linux_abi::LINUX_EINTR,
                        };
                    }
                },
                DispatchOutcome::WaitOnProcExit { pid, block_signals } => {
                    match waiter.wait_proc_exit(pid, block_signals) {
                        // Ready (child exited) → re-dispatch the waitid to reap.
                        crate::io_wait::WaitResult::Ready => continue,
                        // Interrupted (signal/quiesce) → EINTR; the guest re-issues.
                        crate::io_wait::WaitResult::Interrupted
                        | crate::io_wait::WaitResult::TimedOut => {
                            break DispatchOutcome::Errno {
                                errno: crate::linux_abi::LINUX_EINTR,
                            };
                        }
                    }
                }
                other => break other,
            }
        };

        let mut last_syscall_retval: Option<i64> = None;

        match outcome {
            DispatchOutcome::WaitOnFds { .. }
            | DispatchOutcome::WaitOnPollFds { .. }
            | DispatchOutcome::WaitOnProcExit { .. } => {
                unreachable!("serviced by the wait loop above")
            }
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
            DispatchOutcome::Fork { pidfd_out } => {
                let outcome = runtime.fork()?;
                let retval: i64 = match outcome {
                    crate::trap::ForkOutcome::Parent { child_pid } => {
                        waiter = crate::io_wait::ThreadWaiter::new(this_tid);
                        // CLONE_PIDFD: hand the parent a pidfd for the new child.
                        if let Some(addr) = pidfd_out {
                            let fd = dispatcher.install_child_pidfd(child_pid).unwrap_or(-1);
                            let _ = runtime.write_bytes(addr, &fd.to_le_bytes());
                        }
                        i64::from(child_pid)
                    }
                    crate::trap::ForkOutcome::Child => {
                        dispatcher.clear_output_buffers();
                        // kqueue is NOT inherited across fork, and the inherited
                        // self-pipe is shared with the parent — give the child
                        // fresh ones so its parked-thread wakes are its own.
                        crate::host_signal::reinit_after_fork();
                        // The child's pid changed; its waiter watches for
                        // signals targeted at the new tid (or process-directed).
                        waiter = crate::io_wait::ThreadWaiter::new(std::process::id() as ThreadId);
                        0
                    }
                };
                runtime.complete_syscall(retval)?;
                last_syscall_retval = Some(retval);
            }
            DispatchOutcome::Execve { path, argv, env } => {
                crate::probes::execve_argv(&path, &argv);
                let proc_argv = argv.clone();
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
                        dispatcher.set_executable_identity(path.clone(), proc_argv);
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
                let restored_sigmask = runtime.restore_from_sigframe()?;
                dispatcher.restore_signal_mask(this_tid, restored_sigmask);
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
            | DispatchOutcome::SignalThread { .. }
            | DispatchOutcome::FutexWait { .. }
            | DispatchOutcome::SharedFutexWait { .. } => {
                // These are emitted only on the multi-threaded
                // `dispatch_threaded` path (run_vcpu_until_exit). The
                // single-threaded loops here always pass `thread: None`, so
                // the dispatcher never produces them.
                unreachable!("thread-clone outcomes only arise on the threaded runtime path")
            }
        }

        if let Some(action) =
            deliver_pending_signal(runtime, &dispatcher, last_syscall_retval, this_tid, None)?
            && let Some(signum) = action.term_signal
        {
            if runtime.is_forked_child() {
                forked_child_die_by_signal(signum, dispatcher.stdout(), dispatcher.stderr());
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
// vCPU). Shared runtime state is explicit: dispatcher subsystems protect
// their own mutable state, descriptor aliases are thread-safe, and
// compatibility reporting is internally synchronized.
// ===================================================================

use crate::thread::{FutexTable, ThreadId, ThreadRegistry};
use parking_lot::Mutex;
use std::sync::Arc;

struct KernelState {
    dispatcher: SyscallDispatcher,
    reporter: CompatReporter,
    fork: crate::fork_coord::ForkCoordinator,
}

impl KernelState {
    fn new(dispatcher: SyscallDispatcher) -> Self {
        Self {
            dispatcher,
            reporter: CompatReporter::default(),
            fork: crate::fork_coord::ForkCoordinator::new(),
        }
    }
}

type Kernel = Arc<KernelState>;

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

struct ThreadRuntimeState {
    registry: Arc<ThreadRegistry>,
    futex: Arc<FutexTable>,
    this_tid: ThreadId,
    threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    kicker: Arc<crate::vcpu_kick::VcpuKicker>,
    waiter: crate::io_wait::ThreadWaiter,
    max_traps: usize,
    trace: bool,
}

impl ThreadRuntimeState {
    fn new(
        registry: Arc<ThreadRegistry>,
        futex: Arc<FutexTable>,
        this_tid: ThreadId,
        threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
        kicker: Arc<crate::vcpu_kick::VcpuKicker>,
        max_traps: usize,
    ) -> Self {
        Self {
            registry,
            futex,
            this_tid,
            threads,
            kicker,
            waiter: crate::io_wait::ThreadWaiter::new(this_tid),
            max_traps,
            trace: std::env::var_os("CARRICK_TRACE_TRAPS").is_some(),
        }
    }

    fn register_vcpu(&self, engine: &HvfTrapEngine) {
        self.kicker
            .register(self.this_tid, engine.vcpu_kick_handle());
        self.registry
            .record_thread_port(self.this_tid, crate::host_proc::current_thread_port());
    }

    fn trace_syscall(&self, traps: usize, frame: Aarch64SyscallFrame) {
        if !self.trace {
            return;
        }
        let name = crate::syscall::lookup_aarch64(frame.x8)
            .map(|s| s.name)
            .unwrap_or("<unknown>");
        eprintln!(
            "tid#{} trap#{}: x8={} ({name}) x0={:#x} x1={:#x} x2={:#x} x3={:#x} x4={:#x}",
            self.this_tid, traps, frame.x8, frame.x0, frame.x1, frame.x2, frame.x3, frame.x4
        );
    }

    fn service_threaded_syscall(
        &mut self,
        kernel: &Kernel,
        engine: &mut HvfTrapEngine,
        frame: Aarch64SyscallFrame,
    ) -> Result<DispatchOutcome, RuntimeError> {
        loop {
            let request = SyscallRequest::from_aarch64_frame(frame);
            let outcome = kernel.dispatcher.dispatch_threaded(
                request,
                engine,
                &kernel.reporter,
                self.this_tid,
                &self.registry,
                &self.futex,
            )?;
            match outcome {
                DispatchOutcome::WaitOnFds {
                    fds,
                    timeout,
                    on_timeout,
                    block_signals,
                } => match self.waiter.wait(&fds, timeout, block_signals) {
                    crate::io_wait::WaitResult::Ready => continue,
                    crate::io_wait::WaitResult::TimedOut => {
                        break Ok(DispatchOutcome::Returned { value: on_timeout });
                    }
                    crate::io_wait::WaitResult::Interrupted => {
                        break Ok(DispatchOutcome::Errno {
                            errno: crate::linux_abi::LINUX_EINTR,
                        });
                    }
                },
                DispatchOutcome::WaitOnPollFds {
                    fds,
                    timeout,
                    on_timeout,
                    block_signals,
                } => match self.waiter.wait_poll(&fds, timeout, block_signals) {
                    crate::io_wait::WaitResult::Ready => continue,
                    crate::io_wait::WaitResult::TimedOut => {
                        break Ok(DispatchOutcome::Returned { value: on_timeout });
                    }
                    crate::io_wait::WaitResult::Interrupted => {
                        break Ok(DispatchOutcome::Errno {
                            errno: crate::linux_abi::LINUX_EINTR,
                        });
                    }
                },
                DispatchOutcome::WaitOnProcExit { pid, block_signals } => {
                    match self.waiter.wait_proc_exit(pid, block_signals) {
                        // Ready (child exited) → re-dispatch the waitid to reap.
                        crate::io_wait::WaitResult::Ready => continue,
                        // Interrupted (signal/quiesce) → EINTR; the guest re-issues.
                        crate::io_wait::WaitResult::Interrupted
                        | crate::io_wait::WaitResult::TimedOut => {
                            break Ok(DispatchOutcome::Errno {
                                errno: crate::linux_abi::LINUX_EINTR,
                            });
                        }
                    }
                }
                other => break Ok(other),
            }
        }
    }

    fn complete_returned(
        &self,
        engine: &mut HvfTrapEngine,
        value: i64,
    ) -> Result<i64, RuntimeError> {
        engine.complete_syscall(value)?;
        Ok(value)
    }

    fn complete_errno(&self, engine: &mut HvfTrapEngine, errno: i32) -> Result<i64, RuntimeError> {
        self.complete_returned(engine, -(errno as i64))
    }

    fn complete_futex_wait(
        &self,
        engine: &mut HvfTrapEngine,
        wait: crate::thread::FutexWait,
        timeout: Option<Duration>,
    ) -> Result<i64, RuntimeError> {
        use crate::thread::FutexWaitOutcome;

        let retval: i64 =
            match self
                .futex
                .wait_prepared_for_thread(wait, timeout, self.this_tid, &|| {
                    // Return (spurious EINTR) on a pending signal OR a fork
                    // quiesce, so the thread reaches its run-loop-top barrier.
                    crate::host_signal::has_pending_for(self.this_tid)
                        || crate::fork_quiesce::is_quiescing()
                }) {
                FutexWaitOutcome::Woken => 0,
                FutexWaitOutcome::TimedOut => -(crate::linux_abi::LINUX_ETIMEDOUT as i64),
                FutexWaitOutcome::Interrupted => -(crate::linux_abi::LINUX_EINTR as i64),
            };
        self.complete_returned(engine, retval)
    }

    fn complete_shared_futex_wait(
        &self,
        engine: &mut HvfTrapEngine,
        host_addr: usize,
        value: u32,
        timeout: Option<Duration>,
    ) -> Result<i64, RuntimeError> {
        let retval = shared_futex_wait(host_addr, value, timeout, self.this_tid);
        self.complete_returned(engine, retval)
    }

    fn spawn_clone_thread(
        &self,
        kernel: &Kernel,
        engine: &mut HvfTrapEngine,
        stack: u64,
        tls: u64,
        parent_tid_addr: u64,
        child_tid_addr: u64,
    ) -> Result<ThreadId, RuntimeError> {
        let clear_addr = if child_tid_addr != 0 {
            child_tid_addr
        } else {
            0
        };
        let tid = self.registry.register_child(clear_addr);
        let tid_bytes = tid.to_le_bytes();
        if parent_tid_addr != 0 {
            let _ = engine.write_bytes(parent_tid_addr, &tid_bytes);
        }
        if child_tid_addr != 0 {
            let _ = engine.write_bytes(child_tid_addr, &tid_bytes);
        }

        let spec = engine.build_thread_spec(stack, tls)?;
        let child_kernel = Arc::clone(kernel);
        let child_registry = Arc::clone(&self.registry);
        let child_futex = Arc::clone(&self.futex);
        let child_threads = Arc::clone(&self.threads);
        let child_kicker = Arc::clone(&self.kicker);
        // Cleanup handles kept past the move into run_vcpu_until_exit: if the
        // sibling loop returns Err, its normal thread-exit cleanup never ran, so
        // we MUST still drop it from the registry + kicker here. Otherwise it
        // lingers as a phantom live thread — inflating the fork quiesce's
        // `others` count (every fork then times out → EAGAIN) and leaving a
        // stale vCPU id in the kicker.
        let cleanup_registry = Arc::clone(&self.registry);
        let cleanup_kicker = Arc::clone(&self.kicker);
        let cleanup_kernel = Arc::clone(kernel);
        let max_traps = self.max_traps;
        let trace = self.trace;
        let handle = std::thread::Builder::new()
            .name(format!("guest-tid-{tid}"))
            .spawn(move || {
                if trace {
                    eprintln!("[sibling tid#{tid}] thread started, building vCPU");
                }
                match HvfTrapEngine::from_thread_spec(spec) {
                    Ok(child_engine) => {
                        if trace {
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
                            child_kicker,
                            max_traps,
                        );
                        if let Err(e) = r {
                            tracing::error!(tid, error = %e, "thread sibling vCPU loop failed");
                            // The errored loop skipped its own thread-exit
                            // cleanup; deregister it here so it doesn't haunt
                            // the registry/kicker as a phantom thread.
                            cleanup_registry.exit(tid);
                            cleanup_kicker.unregister(tid);
                            crate::host_signal::forget_thread(tid);
                            cleanup_kernel.dispatcher.forget_thread_signal_state(tid);
                        }
                    }
                    Err(e) => {
                        tracing::error!(tid, error = %e, "thread sibling vCPU failed to start");
                        child_registry.exit(tid);
                    }
                }
            })
            .map_err(|e| {
                RuntimeError::Trap(TrapError::Hypervisor(format!(
                    "spawn guest thread failed: {e}"
                )))
            })?;
        self.threads.lock().push(handle);
        Ok(tid)
    }

    fn complete_signal_thread(
        &self,
        engine: &mut HvfTrapEngine,
        target: ThreadId,
        signum: i32,
    ) -> Result<i64, RuntimeError> {
        let retval: i64 = if self.registry.is_live(target) {
            crate::host_signal::publish_pending_for(target, signum);
            self.kicker.kick(target);
            0
        } else {
            -(crate::linux_abi::LINUX_ESRCH as i64)
        };
        self.complete_returned(engine, retval)
    }

    fn handle_thread_exit(
        &self,
        kernel: &Kernel,
        engine: &mut HvfTrapEngine,
        code: i32,
        traps: usize,
    ) -> VcpuLoopOutcome {
        if let Some(addr) = self.registry.clear_child_tid(self.this_tid)
            && addr != 0
        {
            let _ = engine.write_bytes(addr, &0i32.to_le_bytes());
            self.futex.wake(addr, 1);
        }
        let last = self.registry.exit(self.this_tid);
        self.kicker.unregister(self.this_tid);
        crate::host_signal::forget_thread(self.this_tid);
        kernel.dispatcher.forget_thread_signal_state(self.this_tid);
        if last {
            let result = assemble_run_result(kernel, code, traps, false);
            VcpuLoopOutcome::ProcessExit(Box::new(result))
        } else {
            VcpuLoopOutcome::ThreadDone
        }
    }

    fn handle_execve(
        &self,
        kernel: &Kernel,
        engine: &mut HvfTrapEngine,
        path: String,
        argv: Vec<String>,
        env: Vec<String>,
    ) -> Result<(), RuntimeError> {
        crate::probes::execve_argv(&path, &argv);
        let proc_argv = argv.clone();
        let base = path.rsplit('/').next().unwrap_or(&path).to_owned();
        crate::dispatch::set_host_process_name(base.as_bytes());
        match load_execve_image(&kernel.dispatcher, &path, argv, env) {
            Ok(img) => {
                crate::probes::execve_loaded(
                    &path,
                    img.entry(),
                    img.initial_stack_pointer().unwrap_or(0),
                    img.regions().len() as u64,
                );
                kernel
                    .dispatcher
                    .set_executable_identity(path.clone(), proc_argv);
                kernel.dispatcher.close_cloexec_fds();
                engine.execve_into(&img)?;
                Ok(())
            }
            Err(errno) => {
                let retval = -(errno as i64);
                engine.complete_syscall(retval)?;
                Ok(())
            }
        }
    }

    fn handle_fork(
        &mut self,
        kernel: &Kernel,
        engine: &mut HvfTrapEngine,
        pidfd_out: Option<u64>,
    ) -> Result<Option<i64>, RuntimeError> {
        // Serialize forks: at most one quiesce/fork in flight. When another
        // fork already holds the token, BLOCK rather than surfacing EAGAIN —
        // a multithreaded guest (Go's os/exec spawning concurrently) does not
        // retry a failed clone. Park at the in-flight fork's barrier so it can
        // count this thread as quiesced and complete, then retry the token.
        // This makes concurrent forks serialize transparently. The in-flight
        // forker is waiting on exactly this thread (live_count includes it), so
        // parking here can't deadlock it; once it ends the quiesce we wake and
        // win (or lose to a third forker and park again).
        while !fork_barrier().try_begin_fork() {
            fork_barrier().park_if_quiescing();
            std::thread::yield_now();
        }
        // Clear any VM published by a previous fork so siblings that release
        // their vCPUs this round see only THIS fork's republished VM (or, on a
        // quiesce abort, fall back to the still-live existing VM).
        crate::trap::clear_rebuilt_vm_for_fork();
        // Stop-the-world: a multithreaded guest can fork only if every OTHER
        // guest vCPU thread is first paused at its lock-safe run-loop top, so
        // the child (which has only THIS thread after libc::fork) doesn't
        // inherit a carrick lock held by a thread that won't exist in it.
        let others = self.registry.live_count().saturating_sub(1);
        let mut quiesced = false;
        if others > 0 {
            let barrier = fork_barrier();
            barrier.set_quiescing();
            // Wake every other thread so it reaches the barrier: kick in-guest
            // vCPUs, and nudge blocked futex / io_wait waiters (same wakes as a
            // process-directed signal). The flag is set FIRST so a woken thread
            // observes `is_quiescing()` at the run-loop top and parks.
            self.kicker.kick_all_except(self.this_tid);
            self.futex.notify_signal_pending();
            crate::host_signal::wake_all_waiters();
            if !barrier.wait_quiesced(others, std::time::Duration::from_secs(5)) {
                if std::env::var_os("CARRICK_FORK_DEBUG").is_some() {
                    eprintln!(
                        "[fork] quiesce TIMEOUT: others={others} paused={} live_count={} tid={}",
                        barrier.paused_count(),
                        self.registry.live_count(),
                        self.this_tid,
                    );
                }
                barrier.end_quiesce();
                barrier.end_fork();
                engine.complete_syscall(-(crate::linux_abi::LINUX_EAGAIN as i64))?;
                return Ok(None);
            }
            quiesced = true;
        }

        let prepared_fork = kernel.fork.prepare_host_fork();
        let fork_outcome = match engine.fork() {
            Ok(outcome) => outcome,
            Err(error) => {
                if quiesced {
                    fork_barrier().end_quiesce();
                }
                fork_barrier().end_fork();
                kernel
                    .fork
                    .restart_after_fork_error(prepared_fork, &self.kicker, &self.futex);
                return Err(RuntimeError::Trap(error));
            }
        };

        let retval = match fork_outcome {
            crate::trap::ForkOutcome::Parent { child_pid } => {
                // Publish the rebuilt VM so quiesced siblings recreate their
                // vCPUs in it, THEN resume them.
                if quiesced {
                    engine.publish_vm_for_siblings();
                    fork_barrier().end_quiesce();
                }
                fork_barrier().end_fork();
                kernel
                    .fork
                    .restart_after_parent_fork(prepared_fork, &self.kicker, &self.futex);
                self.waiter = crate::io_wait::ThreadWaiter::new(self.this_tid);
                // CLONE_PIDFD: allocate a pidfd for the new child and write its
                // fd to the guest pidfd-out pointer. The child's pid mirrors a
                // real host pid, so the pidfd watches it via EVFILT_PROC.
                if let Some(addr) = pidfd_out {
                    let fd = kernel
                        .dispatcher
                        .install_child_pidfd(child_pid)
                        .unwrap_or(-1);
                    let _ = engine.write_bytes(addr, &fd.to_le_bytes());
                }
                i64::from(child_pid)
            }
            crate::trap::ForkOutcome::Child => {
                kernel.dispatcher.clear_output_buffers();
                // Don't inherit the parent's accumulated guest CPU time: the
                // child's new vCPU starts the hypervisor exec clock at zero.
                crate::guest_cpu::reset();
                self.this_tid = std::process::id() as ThreadId;
                self.registry = Arc::new(ThreadRegistry::new(self.this_tid));
                crate::thread::set_current_registry(Arc::clone(&self.registry));
                // The other guest threads do not exist in the child (libc::fork
                // replicates only the calling thread). Drop their stale
                // bookkeeping: a fresh futex table (no phantom waiters), a fresh
                // kicker (only this vCPU is registered below), and an empty
                // thread-handle vec. The (copied) quiesce flag is cleared so the
                // child's run loop doesn't park.
                self.futex = Arc::new(crate::thread::FutexTable::new());
                self.kicker = Arc::new(crate::vcpu_kick::VcpuKicker::new());
                self.threads = Arc::new(parking_lot::Mutex::new(Vec::new()));
                // Clear the quiesce + fork flags the child inherited (copied)
                // from the parent so the child's single-threaded run loop runs.
                fork_barrier().end_quiesce();
                fork_barrier().end_fork();
                crate::host_signal::reinit_after_fork();
                self.waiter = crate::io_wait::ThreadWaiter::new(self.this_tid);
                self.kicker
                    .register(self.this_tid, engine.vcpu_kick_handle());
                self.registry
                    .record_thread_port(self.this_tid, crate::host_proc::current_thread_port());
                kernel
                    .fork
                    .restart_after_child_fork(prepared_fork, &self.kicker, &self.futex);
                0
            }
        };
        Ok(Some(retval))
    }
}

/// Top-level multi-threaded HVF entry. Builds the shared dispatcher lock + the
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
    // Publish for the /proc/<tid>/stat + /proc/<pid>/task/ synthesis.
    crate::thread::set_current_registry(Arc::clone(&registry));
    // Record the root guest pid (before any fork) so /proc/<pid>/ can tell a
    // guest process (any descendant of the root) from a host process.
    crate::host_proc::set_root_guest_pid(std::process::id());
    // Create the shared reaped-child CPU table before any fork so every guest
    // descendant inherits the same MAP_SHARED region (child CPU → parent
    // cutime/cstime + RUSAGE_CHILDREN).
    crate::guest_cpu::init_child_table();
    let futex = Arc::new(FutexTable::new());
    let kernel = Arc::new(KernelState::new(dispatcher));
    // Track spawned sibling threads so the process doesn't tear down while a
    // worker is mid-flight. We join them after the main thread finishes.
    let threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
    // Registry of live vCPUs so a signalling thread (tgkill) or the
    // process-directed signal pump can force a target out of `hv_vcpu_run`.
    let kicker = Arc::new(crate::vcpu_kick::VcpuKicker::new());
    // Daemon that kicks in-guest vCPUs when a process-directed signal arrives
    // (host SIGINT etc.), so a thread spinning in guest userspace delivers it
    // promptly rather than only at its next syscall — and wakes futex-parked
    // threads so they too deliver promptly (no 50ms poll latency).
    kernel.fork.start_signal_pump(&kicker, &futex);

    let outcome = run_vcpu_until_exit(
        Arc::clone(&kernel),
        trap,
        Arc::clone(&registry),
        Arc::clone(&futex),
        main_tid,
        Arc::clone(&threads),
        Arc::clone(&kicker),
        max_traps,
    )?;

    let result = match outcome {
        VcpuLoopOutcome::ProcessExit(r) | VcpuLoopOutcome::TrapLimit(r) => *r,
        VcpuLoopOutcome::ThreadDone => {
            // The main thread ran exit(2) while siblings were alive. Assemble
            // a result from the shared kernel buffers; siblings keep running
            // until the process exits, but for the run-to-completion CLI we
            // collect output now.
            let report = kernel.reporter.snapshot();
            RunResult {
                exit_code: 0,
                stdout: kernel.dispatcher.stdout(),
                stderr: kernel.dispatcher.stderr(),
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
/// takes the dispatcher lock only to dispatch + complete each syscall.
#[allow(clippy::too_many_arguments)]
fn run_vcpu_until_exit(
    kernel: Kernel,
    mut engine: HvfTrapEngine,
    registry: Arc<ThreadRegistry>,
    futex: Arc<FutexTable>,
    this_tid: ThreadId,
    threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
    kicker: Arc<crate::vcpu_kick::VcpuKicker>,
    max_traps: usize,
) -> Result<VcpuLoopOutcome, RuntimeError> {
    let mut state = ThreadRuntimeState::new(registry, futex, this_tid, threads, kicker, max_traps);
    state.register_vcpu(&engine);
    for traps in 1..=state.max_traps {
        // Lock-safe point: no carrick lock is held here (each iteration acquires
        // and releases its syscall's locks within the iteration). If another
        // thread is forking a multithreaded guest, release this vCPU (so the
        // forker can hv_vm_destroy), park until the fork completes, then
        // recreate the vCPU in the parent's rebuilt VM and resume.
        if fork_barrier().is_quiescing() {
            engine.release_vcpu_for_fork()?;
            fork_barrier().park_if_quiescing();
            engine.rebuild_vcpu_after_fork()?;
            state.register_vcpu(&engine);
        }
        // ---- vCPU run: NO dispatcher lock held ----
        let frame = match engine.next_syscall() {
            Ok(Some(f)) => f,
            Ok(None) => {
                // The vCPU was forced out of the guest by a cross-thread kick
                // (hv_vcpus_exit) with no syscall pending — deliver a signal at
                // the interrupted PC, then resume. A spurious kick with nothing
                // deliverable just costs this one extra iteration.
                let pc = engine.current_pc()?;
                if let Some(outcome) = service_signals_threaded(
                    &kernel,
                    &mut engine,
                    state.this_tid,
                    None,
                    Some(pc),
                    traps,
                )? {
                    return Ok(outcome);
                }
                continue;
            }
            Err(TrapError::EL0Fault {
                syndrome, elr, far, ..
            }) => {
                // A synchronous guest EL0 fault (nil deref, bad access). Deliver
                // it to the guest as SIGSEGV/SIGBUS (Linux semantics) so its
                // handler / Go's sigpanic runs, instead of killing the guest.
                if let Some(outcome) = deliver_fault_signal(
                    &kernel,
                    &mut engine,
                    state.this_tid,
                    syndrome,
                    elr,
                    far,
                    traps,
                )? {
                    return Ok(outcome);
                }
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        state.trace_syscall(traps, frame);

        // ---- syscall service: no dispatcher-wide lock held ----
        // A blocking-mode I/O syscall returns WaitOnFds; we then wait on the
        // host fds without holding subsystem locks so sibling threads run.
        // On readiness we re-dispatch; on timeout / signal we synthesize the
        // terminal outcome.
        let outcome = state.service_threaded_syscall(&kernel, &mut engine, frame)?;

        let mut last_syscall_retval: Option<i64> = None;

        match outcome {
            DispatchOutcome::WaitOnFds { .. }
            | DispatchOutcome::WaitOnPollFds { .. }
            | DispatchOutcome::WaitOnProcExit { .. } => {
                unreachable!("serviced by the wait loop above")
            }
            DispatchOutcome::Exit { code } => {
                crate::trap::dump_kick_stats();
                // A forked child process (real macOS fork) exits via _exit so
                // the rebuilt HVF context doesn't run the panicky Drops, and
                // its buffered stdio is flushed to the inherited host fds.
                if engine.is_forked_child() {
                    crate::probes::guest_exit(code);
                    forked_child_exit(code, kernel.dispatcher.stdout(), kernel.dispatcher.stderr());
                }
                // exit_group, or exit(2) as the last live thread. Tear the
                // whole process down. For the main thread we return a
                // RunResult; siblings just terminate the process.
                let last = state.registry.exit(state.this_tid);
                if !last && state.this_tid != (std::process::id() as ThreadId) {
                    // A sibling ran exit_group(94): flush shared buffers and
                    // terminate the entire process (other threads share it).
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                    let _ = std::io::Write::flush(&mut std::io::stderr());
                    let out = kernel.dispatcher.stdout();
                    let err = kernel.dispatcher.stderr();
                    let _ = unsafe { libc::write(1, out.as_ptr() as *const _, out.len()) };
                    let _ = unsafe { libc::write(2, err.as_ptr() as *const _, err.len()) };
                    unsafe { libc::_exit(code) };
                }
                let result = assemble_run_result(&kernel, code, traps, false);
                return Ok(VcpuLoopOutcome::ProcessExit(Box::new(result)));
            }
            DispatchOutcome::Returned { value } => {
                last_syscall_retval = Some(state.complete_returned(&mut engine, value)?);
            }
            DispatchOutcome::Errno { errno } => {
                last_syscall_retval = Some(state.complete_errno(&mut engine, errno)?);
            }
            DispatchOutcome::FutexWait { wait, timeout } => {
                // Block with the dispatcher lock RELEASED so a sibling FUTEX_WAKE
                // can run. The wait is interrupted if a signal becomes pending
                // so even an all-threads-parked process delivers it; the
                // ungated signal check below then runs. Re-lock only to
                // complete the syscall.
                last_syscall_retval =
                    Some(state.complete_futex_wait(&mut engine, wait, timeout)?);
            }
            DispatchOutcome::SharedFutexWait {
                host_addr,
                value,
                timeout,
            } => {
                // Cross-process futex (MAP_SHARED): block on the host __ulock
                // keyed by the shared physical page, with the dispatcher lock
                // released. Interruptible by a signal deliverable to this thread.
                last_syscall_retval = Some(state.complete_shared_futex_wait(
                    &mut engine,
                    host_addr,
                    value,
                    timeout,
                )?);
            }
            DispatchOutcome::CloneThread {
                stack,
                tls,
                flags: _,
                parent_tid_addr,
                child_tid_addr,
            } => {
                let tid = state.spawn_clone_thread(
                    &kernel,
                    &mut engine,
                    stack,
                    tls,
                    parent_tid_addr,
                    child_tid_addr,
                )?;
                state.complete_returned(&mut engine, tid as i64)?;
            }
            DispatchOutcome::ThreadExit { code } => {
                return Ok(state.handle_thread_exit(&kernel, &mut engine, code, traps));
            }
            DispatchOutcome::SignalThread {
                tid: target,
                signum,
            } => {
                last_syscall_retval =
                    Some(state.complete_signal_thread(&mut engine, target, signum)?);
            }
            DispatchOutcome::Execve { path, argv, env } => {
                state.handle_execve(&kernel, &mut engine, path, argv, env)?;
            }
            DispatchOutcome::SigReturn => {
                let restored_sigmask = engine.restore_from_sigframe()?;
                kernel
                    .dispatcher
                    .restore_signal_mask(state.this_tid, restored_sigmask);
                // Deliver the next pending signal (if any) before resuming —
                // the kernel delivers all deliverable pending signals before
                // returning to userspace. The just-handled signal was cleared
                // when delivered, so this can't re-deliver it.
            }
            DispatchOutcome::Fork { pidfd_out } => {
                if let Some(retval) = state.handle_fork(&kernel, &mut engine, pidfd_out)? {
                    last_syscall_retval = Some(state.complete_returned(&mut engine, retval)?);
                }
            }
        }

        // Signal delivery. A signal targeted at THIS tid (guest tgkill/tkill)
        // takes priority; otherwise a process-directed signal in the global
        // slot is deliverable by any thread (valid Linux semantics — an
        // arbitrary unblocking thread handles it). Threads parked in FUTEX_WAIT
        // / blocking I/O interrupt on a pending-for-them signal and reach here
        // too; a thread forced out of the guest by a kick (frame == None) lands
        // here with `interrupted_pc` so the handler resumes at the right PC.
        if let Some(outcome) = service_signals_threaded(
            &kernel,
            &mut engine,
            state.this_tid,
            last_syscall_retval,
            None,
            traps,
        )? {
            return Ok(outcome);
        }
    }

    let result = assemble_run_result(&kernel, -1, state.max_traps, true);
    Ok(VcpuLoopOutcome::TrapLimit(Box::new(result)))
}

/// Snapshot the shared kernel buffers + reporter into a RunResult. Called on
/// whole-process exit / trap limit.
fn assemble_run_result(
    kernel: &Kernel,
    exit_code: i32,
    traps: usize,
    trap_limit_hit: bool,
) -> RunResult {
    crate::probes::guest_exit(exit_code);
    let report = kernel.reporter.snapshot();
    RunResult {
        exit_code,
        stdout: kernel.dispatcher.stdout(),
        stderr: kernel.dispatcher.stderr(),
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
/// Block on a cross-process (`MAP_SHARED`) futex via the host `__ulock`,
/// interruptibly. Mirrors the parking-lot `FutexWait` contract: returns 0 when
/// woken (or the futex word already changed — the guest re-checks), `-EINTR`
/// when a signal deliverable to THIS thread is pending, `-ETIMEDOUT` at the
/// guest's deadline. `__ulock_wait` is woken by another process's
/// `__ulock_wake` on the same physical page; we cap each wait slice so a
/// pending guest signal (whose cross-thread kick can't interrupt `__ulock`)
/// is still observed promptly. errnos are translated host→Linux.
fn shared_futex_wait(
    host_addr: usize,
    value: u32,
    timeout: Option<std::time::Duration>,
    this_tid: ThreadId,
) -> i64 {
    let deadline = timeout.map(|d| std::time::Instant::now() + d);
    loop {
        if crate::host_signal::has_pending_for(this_tid as i32)
            || crate::fork_quiesce::is_quiescing()
        {
            return -(crate::linux_abi::LINUX_EINTR as i64);
        }
        let slice_us: u32 = match deadline {
            Some(dl) => {
                let now = std::time::Instant::now();
                if now >= dl {
                    return -(crate::linux_abi::LINUX_ETIMEDOUT as i64);
                }
                u32::try_from((dl - now).as_micros().min(20_000)).unwrap_or(20_000)
            }
            // No guest timeout: 20ms slices so a pending signal is seen promptly.
            None => 20_000,
        };
        let r = crate::ulock::wait(host_addr, value, slice_us);
        if r >= 0 {
            // Woken by a wake, or the value already differed — either way the
            // guest re-evaluates its own condition. Linux FUTEX_WAIT returns 0.
            return 0;
        }
        // `-errno` is a HOST errno; translate the ones we act on to Linux.
        let host_errno = (-r) as i32;
        if host_errno == libc::ETIMEDOUT || host_errno == libc::EINTR {
            // Slice expired or a signal nudged us — re-check deadline + pending
            // at the top of the loop rather than surfacing a spurious return.
            continue;
        }
        // EFAULT (bad futex address) shares its value on macOS and Linux (14).
        return -i64::from(host_errno);
    }
}

fn deliver_pending_signal<T>(
    trap: &mut T,
    dispatcher: &SyscallDispatcher,
    last_syscall_retval: Option<i64>,
    tid: ThreadId,
    interrupted_pc: Option<u64>,
) -> Result<Option<PendingSignalAction>, RuntimeError>
where
    T: SyscallTrap,
{
    let pending = crate::host_signal::take_pending_for(tid);
    let pending = if pending == 0 {
        // Nothing newly arrived in the host slot. Deliver the next signal that
        // was raised while blocked and has since been unblocked (held in the
        // dispatcher's pending set) — one per cycle, so each handler runs and
        // returns via rt_sigreturn before the next is injected (matching the
        // kernel delivering all pending signals before returning to userspace).
        match dispatcher.take_deliverable_pending(tid) {
            Some(s) => s,
            None => return Ok(None),
        }
    } else {
        pending
    };
    // Fires only when this thread actually drained a signal — so a
    // `signal-publish` for tid X with no matching `signal-deliver` from X means
    // X never drained it (routing/tid-mismatch or blocked-thread non-delivery).
    crate::probes::signal_deliver(tid, pending);
    // A blocked signal must not be delivered — hold it pending until the
    // guest unblocks it (rt_sigprocmask) or waits for it (rt_sigtimedwait).
    if dispatcher.signal_blocked(tid, pending) {
        dispatcher.mark_signal_pending(tid, pending);
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
            // SA_ONSTACK: run the handler on the alternate signal stack if one
            // is installed. The kernel pushes the sigframe at the top of the
            // alt stack instead of the interrupted SP. Go installs its handlers
            // this way, and LTP sigaltstack01 deliberately makes the main stack
            // unusable so the handler MUST land on the alt stack.
            let altstack = if action.sa_flags & crate::linux_abi::LINUX_SA_ONSTACK != 0 {
                dispatcher.signal_altstack(tid)
            } else {
                None
            };
            let saved_sigmask = dispatcher.enter_signal_handler(tid, pending, action);
            trap.inject_signal(
                pending,
                action.sa_handler,
                restorer,
                last_syscall_retval,
                interrupted_pc,
                altstack,
                saved_sigmask,
                None, // SI_USER-shaped (tkill/sysmon); faults use deliver_fault_signal
            )?;
            Ok(Some(PendingSignalAction { term_signal: None }))
        }
        None => Ok(Some(PendingSignalAction {
            term_signal: Some(pending),
        })),
    }
}

/// Run signal delivery for one iteration of the multi-threaded vCPU loop under
/// the dispatcher lock. Returns `Some(outcome)` when a default-action (terminate)
/// signal fires and the process should end; `None` to keep running. Shared by
/// the post-syscall path (`interrupted_pc = None`) and the kick path
/// (`interrupted_pc = Some(pc)`, no syscall ran).
fn service_signals_threaded(
    kernel: &Kernel,
    engine: &mut HvfTrapEngine,
    this_tid: ThreadId,
    last_syscall_retval: Option<i64>,
    interrupted_pc: Option<u64>,
    traps: usize,
) -> Result<Option<VcpuLoopOutcome>, RuntimeError> {
    if let Some(action) = deliver_pending_signal(
        engine,
        &kernel.dispatcher,
        last_syscall_retval,
        this_tid,
        interrupted_pc,
    )? && let Some(signum) = action.term_signal
    {
        if engine.is_forked_child() {
            let out = kernel.dispatcher.stdout();
            let err = kernel.dispatcher.stderr();
            forked_child_die_by_signal(signum, &out, &err);
        }
        let result = assemble_run_result(kernel, 128 + signum, traps, false);
        return Ok(Some(VcpuLoopOutcome::ProcessExit(Box::new(result))));
    }
    Ok(None)
}

/// Map an EL0 synchronous-fault `ESR_EL1` to the Linux `(signum, si_code)` the
/// kernel would deliver, or `None` for a class we don't translate (kept fatal).
/// ESR EC: 0x20/0x21 = instruction abort, 0x24/0x25 = data abort. DFSC (low 6
/// bits): 0b0001LL translation fault → SEGV_MAPERR; 0b0011LL permission fault →
/// SEGV_ACCERR; 0b100001 alignment → SIGBUS/BUS_ADRALN.
fn el0_fault_signal(esr: u64) -> Option<(i32, i32)> {
    const SIGSEGV: i32 = 11;
    const SIGBUS: i32 = 7;
    const SEGV_MAPERR: i32 = 1;
    const SEGV_ACCERR: i32 = 2;
    const BUS_ADRALN: i32 = 1;
    let ec = (esr >> 26) & 0x3f;
    let dfsc = esr & 0x3f;
    let segv_code = if (0x0c..=0x0f).contains(&dfsc) {
        SEGV_ACCERR
    } else {
        SEGV_MAPERR
    };
    match ec {
        0x20 | 0x21 => Some((SIGSEGV, segv_code)), // instruction abort
        0x24 | 0x25 => {
            if dfsc == 0x21 {
                Some((SIGBUS, BUS_ADRALN)) // alignment fault
            } else {
                Some((SIGSEGV, segv_code))
            }
        }
        _ => None,
    }
}

/// Deliver a synchronous guest EL0 fault as a Linux signal (SIGSEGV/SIGBUS with
/// `si_addr` = faulting address), exactly as the kernel does — so Go's
/// nil-deref→sigpanic→recover idiom (and any guest SIGSEGV handler) works
/// instead of carrick killing the guest. Returns `Some(outcome)` to terminate
/// (no handler, signal blocked, or untranslatable fault — Linux forces the
/// default action), `None` to resume into the injected handler. `elr` is the
/// faulting instruction's PC (resumed unless the handler advances it).
fn deliver_fault_signal(
    kernel: &Kernel,
    engine: &mut HvfTrapEngine,
    this_tid: ThreadId,
    esr: u64,
    elr: u64,
    far: u64,
    traps: usize,
) -> Result<Option<VcpuLoopOutcome>, RuntimeError> {
    let dispatcher = &kernel.dispatcher;
    let terminate = |signum: i32| -> Result<Option<VcpuLoopOutcome>, RuntimeError> {
        if engine.is_forked_child() {
            let out = dispatcher.stdout();
            let err = dispatcher.stderr();
            forked_child_die_by_signal(signum, &out, &err);
        }
        let result = assemble_run_result(kernel, 128 + signum, traps, false);
        Ok(Some(VcpuLoopOutcome::ProcessExit(Box::new(result))))
    };

    // Untranslatable fault (EC=0 unknown, FP trap, …): default to SIGSEGV
    // termination so it's still fatal+visible, but with proper exit semantics.
    let Some((signum, si_code)) = el0_fault_signal(esr) else {
        return terminate(11);
    };
    crate::probes::signal_deliver(this_tid, signum);

    // A synchronous fault with the signal blocked, or no handler installed,
    // forces the default action (terminate) on Linux.
    let action = dispatcher.registered_signal_handler(signum);
    if dispatcher.signal_blocked(this_tid, signum) || action.is_none() {
        return terminate(signum);
    }
    let action = action.unwrap();
    let restorer = if action.sa_flags & crate::linux_abi::LINUX_SA_RESTORER != 0 {
        action.sa_restorer
    } else {
        0
    };
    let altstack = if action.sa_flags & crate::linux_abi::LINUX_SA_ONSTACK != 0 {
        dispatcher.signal_altstack(this_tid)
    } else {
        None
    };
    let saved_sigmask = dispatcher.enter_signal_handler(this_tid, signum, action);
    // The fault trapped via the EL1 HVC trampoline (like a syscall): ELR_EL1
    // already holds the faulting EL0 instruction (aborts don't advance it), and
    // there's a pending eret to EL0. So use the syscall-boundary form
    // (`interrupted_pc=None`): inject sets the handler via ELR_EL1 and snapshots
    // saved_pc=ELR_EL1=the faulting instruction (re-run on return unless the
    // handler advances it, e.g. Go's sigpanic). `elr` is kept for the probe.
    let _ = elr;
    engine.inject_signal(
        signum,
        action.sa_handler,
        restorer,
        None,
        None,
        altstack,
        saved_sigmask,
        Some((si_code, far)),
    )?;
    Ok(None)
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
fn forked_child_exit(code: i32, stdout_buf: impl AsRef<[u8]>, stderr_buf: impl AsRef<[u8]>) -> ! {
    // Publish our total guest CPU so our parent's wait4 can roll it into its
    // child-time totals (cutime/cstime, RUSAGE_CHILDREN) — Linux does this for
    // reaped children, and the child's guest CPU isn't visible in the host
    // rusage the parent's wait4 collects.
    crate::guest_cpu::record_child_exit(std::process::id(), crate::guest_cpu::total_ns());
    let stdout_buf = stdout_buf.as_ref();
    let stderr_buf = stderr_buf.as_ref();
    let _ = unsafe { libc::write(1, stdout_buf.as_ptr() as *const _, stdout_buf.len()) };
    let _ = unsafe { libc::write(2, stderr_buf.as_ptr() as *const _, stderr_buf.len()) };
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
fn forked_child_die_by_signal(
    signum: i32,
    stdout_buf: impl AsRef<[u8]>,
    stderr_buf: impl AsRef<[u8]>,
) -> ! {
    // Publish guest CPU for the parent's wait4 child-time accounting (as in
    // forked_child_exit) before dying by the signal.
    crate::guest_cpu::record_child_exit(std::process::id(), crate::guest_cpu::total_ns());
    let stdout_buf = stdout_buf.as_ref();
    let stderr_buf = stderr_buf.as_ref();
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
    let reporter = CompatReporter::default();
    crate::host_signal::install_default_handlers();
    // Snapshot the host stdin termios so a guest crash mid-`stty raw`
    // doesn't leave the user's terminal wedged. The guard drops at the
    // end of this function and restores the saved state if we touched
    // it.
    let _termios_guard = crate::host_tty::TermiosRestoreGuard::new();

    let this_tid = std::process::id() as ThreadId;
    // Per-thread blocking-I/O waiter (owns this thread's kqueue). Recreated in
    // a forked child below (kqueue is not inherited across fork).
    let mut waiter = crate::io_wait::ThreadWaiter::new(this_tid);
    for traps in 1..=max_traps {
        let frame = match trap.next_syscall()? {
            Some(f) => f,
            None => {
                // Kicked out of the guest for signal delivery (process-directed
                // pump). Deliver at the interrupted PC, then resume.
                let pc = trap.current_pc()?;
                if let Some(action) =
                    deliver_pending_signal(trap, &dispatcher, None, this_tid, Some(pc))?
                    && let Some(signum) = action.term_signal
                {
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
                continue;
            }
        };
        let outcome = loop {
            let oc = dispatcher.dispatch(
                SyscallRequest::from_aarch64_frame(frame),
                memory,
                &reporter,
            )?;
            match oc {
                DispatchOutcome::WaitOnFds {
                    fds,
                    timeout,
                    on_timeout,
                    block_signals,
                } => match waiter.wait(&fds, timeout, block_signals) {
                    crate::io_wait::WaitResult::Ready => continue,
                    crate::io_wait::WaitResult::TimedOut => {
                        break DispatchOutcome::Returned { value: on_timeout };
                    }
                    crate::io_wait::WaitResult::Interrupted => {
                        break DispatchOutcome::Errno {
                            errno: crate::linux_abi::LINUX_EINTR,
                        };
                    }
                },
                DispatchOutcome::WaitOnPollFds {
                    fds,
                    timeout,
                    on_timeout,
                    block_signals,
                } => match waiter.wait_poll(&fds, timeout, block_signals) {
                    crate::io_wait::WaitResult::Ready => continue,
                    crate::io_wait::WaitResult::TimedOut => {
                        break DispatchOutcome::Returned { value: on_timeout };
                    }
                    crate::io_wait::WaitResult::Interrupted => {
                        break DispatchOutcome::Errno {
                            errno: crate::linux_abi::LINUX_EINTR,
                        };
                    }
                },
                DispatchOutcome::WaitOnProcExit { pid, block_signals } => {
                    match waiter.wait_proc_exit(pid, block_signals) {
                        // Ready (child exited) → re-dispatch the waitid to reap.
                        crate::io_wait::WaitResult::Ready => continue,
                        // Interrupted (signal/quiesce) → EINTR; the guest re-issues.
                        crate::io_wait::WaitResult::Interrupted
                        | crate::io_wait::WaitResult::TimedOut => {
                            break DispatchOutcome::Errno {
                                errno: crate::linux_abi::LINUX_EINTR,
                            };
                        }
                    }
                }
                other => break other,
            }
        };

        let mut last_syscall_retval: Option<i64> = None;

        match outcome {
            DispatchOutcome::WaitOnFds { .. }
            | DispatchOutcome::WaitOnPollFds { .. }
            | DispatchOutcome::WaitOnProcExit { .. } => {
                unreachable!("serviced by the wait loop above")
            }
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
            DispatchOutcome::Fork { pidfd_out } => {
                let outcome = trap.fork()?;
                let retval: i64 = match outcome {
                    crate::trap::ForkOutcome::Parent { child_pid } => {
                        waiter = crate::io_wait::ThreadWaiter::new(this_tid);
                        // CLONE_PIDFD: hand the parent a pidfd for the new child.
                        if let Some(addr) = pidfd_out {
                            let fd = dispatcher.install_child_pidfd(child_pid).unwrap_or(-1);
                            let _ = memory.write_bytes(addr, &fd.to_le_bytes());
                        }
                        i64::from(child_pid)
                    }
                    crate::trap::ForkOutcome::Child => {
                        dispatcher.clear_output_buffers();
                        // kqueue is NOT inherited across fork, and the inherited
                        // self-pipe is shared with the parent — give the child
                        // fresh ones so its parked-thread wakes are its own.
                        crate::host_signal::reinit_after_fork();
                        // The child's pid changed; its waiter watches for
                        // signals targeted at the new tid (or process-directed).
                        waiter = crate::io_wait::ThreadWaiter::new(std::process::id() as ThreadId);
                        0
                    }
                };
                trap.complete_syscall(retval)?;
                last_syscall_retval = Some(retval);
            }
            DispatchOutcome::Execve { path, argv, env } => {
                crate::probes::execve_argv(&path, &argv);
                let proc_argv = argv.clone();
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
                        dispatcher.set_executable_identity(path.clone(), proc_argv);
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
                let restored_sigmask = trap.restore_from_sigframe()?;
                dispatcher.restore_signal_mask(this_tid, restored_sigmask);
                // Deliver the next pending signal (if any) before resuming —
                // the kernel delivers all deliverable pending signals before
                // returning to userspace. The just-handled signal was cleared
                // when delivered, so this can't re-deliver it.
            }
            DispatchOutcome::CloneThread { .. }
            | DispatchOutcome::ThreadExit { .. }
            | DispatchOutcome::SignalThread { .. }
            | DispatchOutcome::FutexWait { .. }
            | DispatchOutcome::SharedFutexWait { .. } => {
                // These are emitted only on the multi-threaded
                // `dispatch_threaded` path (run_vcpu_until_exit). The
                // single-threaded loops here always pass `thread: None`, so
                // the dispatcher never produces them.
                unreachable!("thread-clone outcomes only arise on the threaded runtime path")
            }
        }

        if let Some(action) =
            deliver_pending_signal(trap, &dispatcher, last_syscall_retval, this_tid, None)?
            && let Some(signum) = action.term_signal
        {
            if trap.is_forked_child() {
                forked_child_die_by_signal(signum, dispatcher.stdout(), dispatcher.stderr());
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

    fn next_syscall(&mut self) -> Result<Option<Aarch64SyscallFrame>, TrapError> {
        self.run_until_syscall()
    }

    fn current_pc(&self) -> Result<u64, TrapError> {
        self.program_counter()
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
        interrupted_pc: Option<u64>,
        altstack: Option<(u64, u64)>,
        saved_sigmask: u64,
        fault_siginfo: Option<(i32, u64)>,
    ) -> Result<(), TrapError> {
        HvfTrapEngine::inject_signal(
            self,
            signum,
            handler,
            sa_restorer,
            pending_syscall_retval,
            interrupted_pc,
            altstack,
            saved_sigmask,
            fault_siginfo,
        )
    }

    fn restore_from_sigframe(&mut self) -> Result<u64, TrapError> {
        HvfTrapEngine::restore_from_sigframe(self)
    }
}
