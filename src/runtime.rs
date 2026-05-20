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
            std::io::Error::new(std::io::ErrorKind::Other, format!("serialize: {e}"))
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
    run_combined_syscall_loop_with_dispatcher(&mut trap, dispatcher, max_traps)
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
        let outcome = dispatcher.dispatch(
            SyscallRequest::from_aarch64_frame(frame),
            runtime,
            &mut reporter,
        )?;

        let mut last_syscall_retval: Option<i64> = None;
        let mut suppress_signal_check = false;

        match outcome {
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
                // Don't immediately re-deliver another pending signal
                // until the handler-return path has completed unwinding.
                suppress_signal_check = true;
            }
        }

        if !suppress_signal_check {
            if let Some(action) =
                deliver_pending_signal(runtime, &dispatcher, last_syscall_retval)?
            {
                if let Some(exit) = action.exit_code {
                    return Ok(RunResult {
                        exit_code: exit,
                        stdout: dispatcher.stdout().to_vec(),
                        stderr: dispatcher.stderr().to_vec(),
                        traps,
                        report: reporter.finish(),
                        trap_limit_hit: false,
                    });
                }
            }
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

/// Outcome of `deliver_pending_signal`. The `exit_code` field is
/// `Some` when the pending signal had no installed handler and the
/// default action (terminate) applies.
struct PendingSignalAction {
    exit_code: Option<i32>,
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
    dispatcher: &SyscallDispatcher,
    last_syscall_retval: Option<i64>,
) -> Result<Option<PendingSignalAction>, RuntimeError>
where
    T: SyscallTrap,
{
    let pending = crate::host_signal::take_pending();
    if pending == 0 {
        return Ok(None);
    }
    if dispatcher.signal_is_ignored(pending) {
        return Ok(Some(PendingSignalAction { exit_code: None }));
    }
    match dispatcher.registered_signal_handler(pending) {
        Some(action) => {
            let handler = action.sa_handler;
            let restorer = action.sa_restorer;
            if restorer == 0 {
                tracing::warn!(
                    signum = pending,
                    "guest handler for signal has no sa_restorer; falling back to default terminate"
                );
                return Ok(Some(PendingSignalAction {
                    exit_code: Some(128 + pending),
                }));
            }
            trap.inject_signal(pending, handler, restorer, last_syscall_retval)?;
            Ok(Some(PendingSignalAction { exit_code: None }))
        }
        None => Ok(Some(PendingSignalAction {
            exit_code: Some(128 + pending),
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
    use crate::dispatch::LINUX_ENOENT;
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

    let raw = if let Some(rootfs) = dispatcher.rootfs() {
        AddressSpace::load_elf_from_rootfs(&path, rootfs).map_err(|_| LINUX_ENOENT)?
    } else {
        AddressSpace::load_elf(&path).map_err(|_| LINUX_ENOENT)?
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
    let mut parts = line.splitn(2, |c| c == ' ' || c == '\t');
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

    for traps in 1..=max_traps {
        let frame = trap.next_syscall()?;
        let outcome = dispatcher.dispatch(
            SyscallRequest::from_aarch64_frame(frame),
            memory,
            &mut reporter,
        )?;

        let mut last_syscall_retval: Option<i64> = None;
        let mut suppress_signal_check = false;

        match outcome {
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
                suppress_signal_check = true;
            }
        }

        if !suppress_signal_check {
            if let Some(action) =
                deliver_pending_signal(trap, &dispatcher, last_syscall_retval)?
            {
                if let Some(exit) = action.exit_code {
                    return Ok(RunResult {
                        exit_code: exit,
                        stdout: dispatcher.stdout().to_vec(),
                        stderr: dispatcher.stderr().to_vec(),
                        traps,
                        report: reporter.finish(),
                        trap_limit_hit: false,
                    });
                }
            }
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
