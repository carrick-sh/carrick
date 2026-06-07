//! The run lifecycle: load an image, drive the trap→dispatch→complete loop, and
//! own the fork/clone, signal-delivery, and fault-handling models.
//!
//! # The loop
//!
//! Every `run_*` entry point converges on [`finish_and_run_image`], which
//! finalises a loaded [`AddressSpace`] (EL0 trampoline → EL1 vectors → stage-1
//! page tables → vDSO) and enters the trap engine. The core of the runtime is a
//! tight loop:
//!
//! 1. `next_syscall` runs the vCPU (`hv_vcpu_run`) until the guest executes
//!    `svc #0`, faults synchronously at EL0, or is forced out by a cross-thread
//!    kick.
//! 2. The trapped frame (`x8` = syscall number, `x0..x5` = args) is handed to
//!    the [`SyscallDispatcher`], which emulates it against Darwin host
//!    primitives and returns a [`DispatchOutcome`].
//! 3. The loop acts on the outcome — write the return value into `x0` and resume
//!    (`Returned`/`Errno`), block on host fds and re-dispatch on readiness
//!    (`WaitOn*`), spawn/teardown a process or thread (`Fork`/`CloneThread`/
//!    `Execve`/`Exit`), or pop a signal frame (`SigReturn`).
//! 4. Between syscalls it delivers any pending signal ([`deliver_pending_signal`]).
//!
//! There are **two** loop implementations, chosen by the guest's threading:
//!
//! - **Single-threaded** ([`run_combined_syscall_loop_with_dispatcher`], and its
//!   split-view sibling [`run_split_loop`]): one vCPU, no locks, no thread
//!   registry. Used by `run-elf` of a static binary, the in-process test
//!   harnesses, and LTP fixtures. A guest `fork(2)` here is a plain `libc::fork`;
//!   the child keeps running the same loop.
//! - **Multi-threaded** ([`run_threaded_hvf_loop`] → [`run_vcpu_until_exit`]):
//!   **one host thread plus one HVF vCPU per guest thread**, all sharing one
//!   process VM (stage-2 mappings are visible to every vCPU). Shared kernel
//!   state lives behind [`KernelState`] (an `Arc`, each subsystem internally
//!   synchronised — there is no longer a single big lock). This is the path real
//!   workloads (Go, CPython, Node, apt/dpkg) take.
//!
//! Both loops produce a [`RunResult`] (exit code + captured stdio + the
//! [`CompatReport`]).
//!
//! # The fork/clone model (the hard part)
//!
//! macOS HVF is **not fork-safe**: a live VM in the parent at `libc::fork(2)`
//! makes the child's `hv_vm_create` return `HV_BUSY`. carrick has three distinct
//! fork shapes, and each works around this differently:
//!
//! - **`clone(2)` that creates a thread** (`CLONE_VM`): no `libc::fork` at all.
//!   [`ThreadRuntimeState::spawn_clone_thread`] spawns a host thread that builds
//!   its own vCPU in the *same* VM and runs [`run_vcpu_until_exit`]. HVF caps
//!   concurrent vCPUs (64 on this host); a guest with more live threads than the
//!   cap blocks in `wait_for_vcpu_slot` until one frees, since `clone(2)` already
//!   reported success and the guest may `join` the thread.
//! - **`fork(2)` from a single-threaded guest**: a plain `libc::fork`. The
//!   engine snapshots and rebuilds the address space; the child resets its
//!   per-process state (event ring, self-pipe, kqueue — none survive fork) and
//!   continues.
//! - **`fork(2)` from a multithreaded guest** ([`ThreadRuntimeState::handle_fork`]):
//!   a *stop-the-world*. `libc::fork` replicates only the calling thread, so the
//!   child would otherwise inherit carrick locks held by threads that no longer
//!   exist. The forker therefore quiesces every **other** live vCPU at its
//!   lock-safe run-loop top (via the kicker + the [`fork_quiesce`] barrier),
//!   tears the VM down, forks, and republishes a rebuilt VM the parked siblings
//!   recreate their vCPUs in. Concurrent forks serialise transparently (a loser
//!   parks at the in-flight fork's barrier). The quiesce loop re-reads the live
//!   sibling count every iteration — a sibling that exits mid-quiesce must drop
//!   out, or the wait would spin forever waiting for a parker that no longer
//!   exists (this was the multithreaded-fork wedge).
//!
//! [`fork_quiesce`]: crate::fork_quiesce
//!
//! Orthogonal to fork, a stage-1 **page-table edit** (mmap/mprotect/munmap that
//! changes the guest's shared descriptors) is its own, lighter stop-the-world:
//! [`ThreadRuntimeState::pt_pause`] kicks in-guest siblings out so none walks a
//! half-edited table, but — unlike fork — it *keeps* every vCPU alive. The
//! handshake between an editing coordinator and a vCPU about to enter the guest
//! is a Dekker pattern on `quiescing` ↔ `in_guest` (SeqCst), so neither side
//! misses the other.
//!
//! # PID-namespace placement and the supervisor
//!
//! A container `carrick run` that requests PID-ns placement forks the
//! [`namespace::supervisor`](crate::namespace::supervisor) **before any VM
//! exists** ([`maybe_fork_ns_supervisor`]):
//! the parent becomes the userspace stand-in for the Linux kernel (orphan
//! reparenting, exit-status harvest, teardown) and never creates a VM; the child
//! continues into HVF as the guest-init (ns-pid 1). The three outcomes are
//! [`SupervisorRole`]. `run-elf` never requests placement, so this is a no-op
//! there.
//!
//! # Faults are signals
//!
//! A synchronous guest EL0 fault (nil deref, bad access, `BRK`, single-step) is
//! not fatal to carrick: [`fault`]'s `deliver_fault_signal` maps the `ESR_EL1`
//! to the Linux `(signum, si_code)` the kernel would deliver (SIGSEGV/SIGBUS/
//! SIGTRAP) and injects it into the guest, so Go's `sigpanic`/`recover`, glibc
//! backtraces, and any installed handler run exactly as on Linux.
//!
//! # The forked-child `_exit` rule (do not break this)
//!
//! A `libc::fork`ed child shares the parent's fd table. Unwinding through an
//! fd-owning `Drop` (the dispatcher's buffers, an `applevisor::Vcpu`) in the
//! child double-closes an inherited fd — tripping std's IO-safety abort — or
//! runs the no-VM `Vcpu` Drop and panics. So on **every** exit path the loops
//! check `is_forked_child()` / `is_forked_guest_process()` and route through the
//! `_exit`-based [`exec`] helpers (`forked_child_exit` flushes buffered stdio to
//! the inherited host fds then `_exit`s; `forked_child_die_by_signal` re-raises
//! the signal so the parent's `wait4` reports `WIFSIGNALED`).
//!
//! [`AddressSpace`]: crate::memory::AddressSpace

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::compat::{CompatReport, CompatReporter};
use crate::dispatch::{
    Aarch64SyscallFrame, DispatchError, DispatchOutcome, GuestMemory, MemoryError, ProcMapsEntry,
    SyscallDispatcher, SyscallRequest,
};
use crate::memory::{AddressSpace, AddressSpaceError};
use crate::rootfs::RootFs;

mod fault;
use fault::deliver_fault_signal;
#[cfg(test)]
use fault::el0_debug_signal;
mod exec;
use exec::{
    forked_child_die_by_signal, forked_child_exit, load_execve_image, stop_after_traced_exec,
    stop_by_signal,
};

/// Process-wide fork quiesce barrier (defined in `fork_quiesce` so the blocking
/// wait predicates can reach the same instance).
fn fork_barrier() -> &'static crate::fork_quiesce::QuiesceBarrier {
    crate::fork_quiesce::barrier()
}

/// Process-wide page-table-edit Pause-Modify-Resume barrier (defined in
/// `fork_quiesce` alongside the fork barrier).
fn pt_barrier() -> &'static crate::fork_quiesce::PtQuiesce {
    crate::fork_quiesce::pt_barrier()
}
use crate::trap::{HvfTrapEngine, TrapError};
// `SyscallTrap` moved to carrick-hvf (`crate::trap`); re-export it from this
// module so the original `carrick_runtime::runtime::SyscallTrap` path (used by
// the runtime_loop tests and the engine crate) is unchanged.
pub use crate::trap::SyscallTrap;
use serde::Serialize;
use thiserror::Error;

const SIGNAL_WAIT_SLICE: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VdsoDebugMode {
    Full,
    Disabled,
    NoGetrandom,
    NoFastpaths,
    ClockSyscalls,
}

fn vdso_enabled_for_debug() -> bool {
    vdso_debug_mode() != VdsoDebugMode::Disabled
}

fn vdso_debug_mode() -> VdsoDebugMode {
    vdso_debug_mode_from_env(
        std::env::var("CARRICK_DISABLE_VDSO").ok().as_deref(),
        std::env::var("CARRICK_VDSO_MODE").ok().as_deref(),
    )
}

fn vdso_debug_mode_from_env(disable: Option<&str>, mode: Option<&str>) -> VdsoDebugMode {
    if debug_env_flag_enabled(disable) {
        return VdsoDebugMode::Disabled;
    }
    match mode {
        Some("no-getrandom" | "nogetrandom" | "without-getrandom") => VdsoDebugMode::NoGetrandom,
        Some("no-fastpaths" | "nofastpaths" | "minimal") => VdsoDebugMode::NoFastpaths,
        Some("clock-syscalls" | "clocksyscalls" | "clock-syscall") => VdsoDebugMode::ClockSyscalls,
        _ => VdsoDebugMode::Full,
    }
}

fn debug_env_flag_enabled(value: Option<&str>) -> bool {
    matches!(
        value,
        Some("1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON")
    )
}

fn hardware_tso_for_debug(requested: bool) -> bool {
    requested && !debug_env_flag_enabled(std::env::var("CARRICK_DISABLE_TSO").ok().as_deref())
}

#[cfg(test)]
fn hardware_tso_for_debug_from_env(requested: bool, disable: Option<&str>) -> bool {
    requested && !debug_env_flag_enabled(disable)
}

fn with_optional_vdso(image: AddressSpace) -> Result<AddressSpace, AddressSpaceError> {
    match vdso_debug_mode() {
        VdsoDebugMode::Full => image.with_vdso(),
        VdsoDebugMode::Disabled => Ok(image),
        VdsoDebugMode::NoGetrandom => image.with_vdso_without_getrandom(),
        VdsoDebugMode::NoFastpaths => image.with_vdso_without_fastpaths(),
        VdsoDebugMode::ClockSyscalls => image.with_vdso_clock_syscalls(),
    }
}

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

// `SyscallTrap` (the trap-engine contract the loops drive) moved into
// carrick-hvf alongside `TrapError`/`ForkOutcome`/`HvfTrapEngine`. Re-exported
// from `crate::trap`; imported here via the `use crate::trap::{…}` below so
// `SplitView`/`HvfTrapEngine` impls and the loop bounds are unchanged.

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("failed to load ELF image: {0}")]
    AddressSpace(#[from] AddressSpaceError),
    // Reading a rootfs-backed ELF (main binary / PT_INTERP) lives at the runtime
    // layer now that AddressSpace loading is rootfs-agnostic (closure reader) —
    // this is what decoupled `memory` from `rootfs` (build-graph A2.5).
    #[error("failed to read rootfs-backed ELF: {0}")]
    RootFs(#[from] crate::rootfs::RootFsError),
    #[error("trap engine failed: {0}")]
    Trap(#[from] TrapError),
    #[error("syscall dispatch failed: {0}")]
    Dispatch(#[from] DispatchError),
    #[error("filesystem backend error: {0}")]
    FsBackend(anyhow::Error),
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
    let argv0 = canonical_host_executable_path(path);
    run_static_elf_with_hvf_args_and_dispatcher(
        path,
        dispatcher,
        [argv0],
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
    let identity = argv
        .first()
        .cloned()
        .unwrap_or_else(|| canonical_host_executable_path(path));
    dispatcher.set_executable_identity(
        identity,
        argv.clone(),
        env.iter().map(|s| s.as_bytes().to_vec()).collect(),
    );
    let file = std::fs::read(path).map_err(AddressSpaceError::Io)?;
    let image = AddressSpace::load_elf_bytes_with_reader(&file, &|p| {
        dispatcher
            .read_exec_file(p)
            .or_else(|| std::fs::read(p).ok())
    })?
    .with_vdso_auxv(vdso_enabled_for_debug())
    .with_linux_initial_stack(argv, env)?;
    finish_and_run_image(image, dispatcher, max_traps, debug_state_path)
}

fn canonical_host_executable_path(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

pub fn run_static_elf_bytes_with_hvf_and_dispatcher(
    bytes: &[u8],
    dispatcher: SyscallDispatcher,
    max_traps: usize,
) -> Result<RunResult, RuntimeError> {
    let image = AddressSpace::load_elf_bytes(bytes)?;
    finish_and_run_image(image, dispatcher, max_traps, None)
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
        dispatcher.set_executable_identity(
            first.clone(),
            argv.clone(),
            env.iter().map(|s| s.as_bytes().to_vec()).collect(),
        );
    }
    let image = AddressSpace::load_elf_bytes(bytes)?
        .with_vdso_auxv(vdso_enabled_for_debug())
        .with_linux_initial_stack(argv, env)?;
    finish_and_run_image(image, dispatcher, max_traps, None)
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
    dispatcher.set_executable_identity(
        path.to_string_lossy().into_owned(),
        argv.clone(),
        env.iter().map(|s| s.as_bytes().to_vec()).collect(),
    );
    // Read the main binary from the rootfs here (runtime layer); AddressSpace
    // resolves any PT_INTERP through the rootfs read-closure, staying
    // rootfs-agnostic so `memory` doesn't depend on `rootfs`.
    let file = rootfs.read(path)?;
    // Redirect x86_64 binaries through Rosetta 2 (binfmt_misc-style). Rosetta
    // is read from the host (not the rootfs); it is statically linked, so the
    // rootfs reader below is never asked for a Rosetta PT_INTERP.
    let path_str = path.to_string_lossy();
    // argv normalises to opaque bytes (Linux ABI) past this point so the rosetta
    // and non-rosetta arms share a type; with_linux_initial_stack accepts bytes.
    let (file, argv): (Vec<u8>, Vec<Vec<u8>>) =
        match maybe_redirect_to_rosetta(&path_str, &file, &argv) {
            None => (file, argv.into_iter().map(String::into_bytes).collect()),
            Some(Ok((rosetta_bytes, new_argv))) => {
                dispatcher.set_executable_path(ROSETTA_INTERPRETER);
                (rosetta_bytes, new_argv)
            }
            Some(Err(errno)) => return Err(rosetta_unavailable(errno, &path_str)),
        };
    let image = AddressSpace::load_elf_bytes_with_reader(&file, &|p| {
        rootfs.read(p).ok().or_else(|| std::fs::read(p).ok())
    })?
    .with_vdso_auxv(vdso_enabled_for_debug())
    .with_linux_initial_stack(argv, env)?;
    finish_and_run_image(image, dispatcher, max_traps, debug_state_path)
}

/// Docker/runc entrypoint semantics: when the program name contains no `/`,
/// resolve it against `$PATH` (like `execvp`) using the guest rootfs, returning
/// the first directory whose `dir/name` is a readable executable. A name that
/// already contains `/` (absolute or relative) is returned unchanged — matching
/// Linux `execve(2)`, which does NOT search `$PATH`. This applies ONLY to the
/// initial entrypoint; the guest's own `execve(2)` syscall keeps full-path
/// semantics via `resolve_exec_path`. Without this, `carrick run alpine ls`
/// (a bare command, as Docker accepts) failed with "failed to read ELF bytes: ls".
fn resolve_entrypoint_path(path: &str, env: &[String], dispatcher: &SyscallDispatcher) -> String {
    if path.contains('/') {
        return path.to_owned();
    }
    const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    let search = env
        .iter()
        .find_map(|e| e.strip_prefix("PATH="))
        .filter(|p| !p.is_empty())
        .unwrap_or(DEFAULT_PATH);
    for dir in search.split(':') {
        if dir.is_empty() {
            continue;
        }
        let candidate = format!("{}/{}", dir.trim_end_matches('/'), path);
        if dispatcher.read_exec_file(&candidate).is_some() {
            return candidate;
        }
    }
    // No match: keep the bare name so the existing NotFound error names it.
    path.to_owned()
}

/// Resolve the initial entrypoint program for `carrick run`: PATH-resolve a bare
/// command (`resolve_entrypoint_path`, Docker `execvp` semantics) and then
/// resolve any `#!` shebang script to its interpreter, so a script entrypoint
/// runs like Docker / `execve(2)` instead of failing "not an ELF binary".
/// Returns the final (program path, argv as opaque Linux-ABI bytes).
fn resolve_entrypoint_program(
    path: &str,
    env: &[String],
    argv: Vec<Vec<u8>>,
    dispatcher: &SyscallDispatcher,
) -> Result<(String, Vec<Vec<u8>>), i32> {
    let resolved = resolve_entrypoint_path(path, env, dispatcher);
    exec::resolve_shebang(dispatcher, resolved, argv)
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
    // Docker accepts a bare entrypoint command (`carrick run alpine ls`); resolve
    // it against $PATH like runc/execvp before loading. A name with '/' is left
    // as-is. Guest execve(2) is unaffected (it keeps full-path semantics).
    // Identity for /proc/self/{exe,cmdline} reflects the entrypoint the user
    // asked for (before shebang/Rosetta rewriting).
    dispatcher.set_executable_identity(
        path.to_owned(),
        argv.clone(),
        env.iter().map(|s| s.as_bytes().to_vec()).collect(),
    );
    // PATH-resolve a bare command AND resolve `#!` shebang scripts to their
    // interpreter (Docker / execve(2) semantics) before loading, so a script
    // entrypoint runs instead of failing "not an ELF binary".
    let argv_bytes: Vec<Vec<u8>> = argv.into_iter().map(String::into_bytes).collect();
    let (resolved, argv) = resolve_entrypoint_program(path, &env, argv_bytes, &dispatcher)
        .map_err(|_| {
            RuntimeError::AddressSpace(AddressSpaceError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                path.to_owned(),
            )))
        })?;
    let path: &str = &resolved;
    let bytes = dispatcher.read_exec_file(path).ok_or_else(|| {
        RuntimeError::AddressSpace(AddressSpaceError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            path.to_owned(),
        )))
    })?;
    // Redirect x86_64 binaries through Rosetta 2 (binfmt_misc-style). argv is
    // already opaque bytes (Linux ABI).
    let (bytes, argv): (Vec<u8>, Vec<Vec<u8>>) =
        match maybe_redirect_to_rosetta(path, &bytes, &argv) {
            None => (bytes, argv),
            Some(Ok((rosetta_bytes, new_argv))) => {
                // /proc/self/exe should resolve to the interpreter that's actually
                // loaded (Rosetta opens it during its startup handshake).
                dispatcher.set_executable_path(ROSETTA_INTERPRETER);
                (rosetta_bytes, new_argv)
            }
            Some(Err(errno)) => return Err(rosetta_unavailable(errno, path)),
        };
    let image =
        AddressSpace::load_elf_bytes_with_reader(&bytes, &|p| dispatcher.read_exec_file(p))?
            .with_vdso_auxv(vdso_enabled_for_debug())
            .with_linux_initial_stack(argv, env)?;
    finish_and_run_image(image, dispatcher, max_traps, debug_state_path)
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

/// The caller's role after [`maybe_fork_ns_supervisor`].
#[allow(clippy::large_enum_variant)]
enum SupervisorRole {
    /// PARENT (NsSupervisor): it ran the kqueue loop until the guest-init exited;
    /// the result carries the init's exit code to propagate up.
    Parent(RunResult),
    /// CHILD (guest-init, ns-pid 1): continue into HVF and run the guest. A
    /// post-fork error here must `_exit`, NOT unwind — unwinding through
    /// fd-bearing `Drop`s in the forked child double-closes an inherited fd and
    /// trips std's IO-safety abort (SIGABRT).
    ForkedInit,
    /// No fork happened — placement was not requested, or region/pipe/fork setup
    /// failed (degraded to running the guest in-process). Errors propagate normally.
    InProcess,
}

/// Fork the per-container NsSupervisor before any HVF VM exists, if PID-ns
/// placement was requested. See [`SupervisorRole`] for the three outcomes.
fn maybe_fork_ns_supervisor() -> Result<SupervisorRole, RuntimeError> {
    if !crate::namespace::pid::supervisor_requested() {
        return Ok(SupervisorRole::InProcess);
    }
    // Allocate the shared member table + the registration pipe BEFORE the fork
    // so both processes inherit them. On any setup failure, degrade to running
    // the guest in-process without a supervisor (identity-ish placement still
    // works for the common single-process case via the region if it allocated).
    if !crate::namespace::pid::alloc_region() {
        return Ok(SupervisorRole::InProcess);
    }
    let mut pipe_fds = [0i32; 2];
    // SAFETY: standard pipe(2) into a 2-element array.
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        return Ok(SupervisorRole::InProcess);
    }
    let (pipe_read, pipe_write) = (pipe_fds[0], pipe_fds[1]);
    // Make BOTH ends non-blocking: the write end so a guest's registration
    // notify never blocks on a full pipe; the READ end so the supervisor's
    // drain loop terminates on EAGAIN instead of blocking forever once the
    // pending bytes are consumed (the supervisor rescans on a timeout anyway).
    // SAFETY: fcntl on our own pipe fds.
    unsafe {
        let fl_w = libc::fcntl(pipe_write, libc::F_GETFL);
        libc::fcntl(pipe_write, libc::F_SETFL, fl_w | libc::O_NONBLOCK);
        let fl_r = libc::fcntl(pipe_read, libc::F_GETFL);
        libc::fcntl(pipe_read, libc::F_SETFL, fl_r | libc::O_NONBLOCK);
    }
    crate::namespace::pid::set_reg_pipe_write(pipe_write);

    // SAFETY: fork(2). We are single-threaded at this point in the run path
    // (the HVF VM + sibling vCPU threads do not exist yet — that is the whole
    // reason the supervisor fork happens HERE), so fork is safe.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        // Fork failed: close the pipe and run without a supervisor.
        unsafe {
            libc::close(pipe_read);
            libc::close(pipe_write);
        }
        crate::namespace::pid::set_reg_pipe_write(-1);
        return Ok(SupervisorRole::InProcess);
    }
    if pid == 0 {
        // CHILD: the guest-init (ns-pid 1). Close the supervisor's read end,
        // fill the region's init slot with our pid, and continue into HVF.
        unsafe {
            libc::close(pipe_read);
        }
        crate::namespace::pid::set_init(std::process::id());
        return Ok(SupervisorRole::ForkedInit);
    }
    // PARENT: the NsSupervisor. Close the write end (only members write), run
    // the kqueue loop until the init exits, then propagate its status.
    unsafe {
        libc::close(pipe_write);
    }
    crate::namespace::pid::set_reg_pipe_write(-1);
    // Detached runs (`carrick run -d`) set CARRICK_CONTAINER_ID before launch.
    // The supervisor owns the container's lifetime, so it records the live
    // init/supervisor pids (status → Running) here and marks the registry entry
    // Exited (or removes it, for --rm) when the init exits. A foreground run has
    // no id set, so this is a no-op (the CLI handles foreground status itself).
    let container_id = std::env::var("CARRICK_CONTAINER_ID").ok();
    if let Some(id) = container_id.as_deref()
        && let Ok(mut state) = crate::container::ContainerState::load(id)
    {
        state.status = crate::container::ContainerStatus::Running;
        state.supervisor_pid = std::process::id() as i32;
        state.init_pid = pid;
        let _ = state.persist();
    }
    let exit = crate::namespace::supervisor::run(pid, pipe_read);
    let code = crate::namespace::supervisor::status_to_exit_code(exit.init_status);
    if let Some(id) = container_id.as_deref() {
        crate::container::mark_exited(id, code);
    }
    Ok(SupervisorRole::Parent(RunResult {
        exit_code: code,
        stdout: Vec::new(),
        stderr: Vec::new(),
        traps: 0,
        report: Default::default(),
        trap_limit_hit: false,
    }))
}

fn run_address_space_with_hvf_and_dispatcher(
    image: AddressSpace,
    dispatcher: SyscallDispatcher,
    max_traps: usize,
) -> Result<RunResult, RuntimeError> {
    // PID-namespace placement (container runs only): fork the NsSupervisor
    // BEFORE creating the HVF VM. macOS HVF state is not fork-safe — a VM live
    // in the parent at fork(2) makes the child's hv_vm_create return HV_BUSY
    // (see HvfTrapEngine::fork). So the supervisor (the parent) must never
    // create a VM: it forks here, the CHILD goes on to HvfTrapEngine::new() and
    // runs the guest as ns-pid 1, and the PARENT runs the kqueue supervisor
    // loop and exits with the init's status (docs/namespaces-design.md §3.2).
    // `run-elf` never requests placement, so this is a no-op there.
    let role = maybe_fork_ns_supervisor()?;
    if let SupervisorRole::Parent(result) = role {
        return Ok(result);
    }
    let forked_init = matches!(role, SupervisorRole::ForkedInit);
    // Run the guest. In the forked guest-init, errors must NOT unwind (see below),
    // so capture the fallible tail in a closure and branch on the role.
    let run = (move || -> Result<RunResult, RuntimeError> {
        let mut trap = HvfTrapEngine::new()?;
        trap.map_address_space(&image)?;
        // Hand the dispatcher the real region list + auxv so /proc/self/maps
        // (regions, bootstrap pages, stack) and /proc/self/auxv reflect the loaded
        // ELF instead of the legacy summary. Language runtimes, malloc
        // implementations, and debuggers parse these; refreshed again on each execve.
        apply_image_proc_state(&dispatcher, &image);
        // Boot-stamp the identity page before the guest runs a single syscall,
        // so the very first fast-path getpid/get*id reads the right value.
        stamp_identity_page(&mut trap, &dispatcher);
        run_threaded_hvf_loop(trap, dispatcher, max_traps)
    })();
    match run {
        Ok(r) => Ok(r),
        Err(e) if forked_init => {
            // Forked guest-init: a post-fork failure (HVF VM creation / mapping)
            // must terminate WITHOUT unwinding. The forked child shares the
            // parent's fd table; dropping fd-owning state on the way out
            // double-closes an inherited fd and aborts via std's IO-safety check
            // (SIGABRT). Print the error (stderr is inherited + unbuffered) and
            // `_exit` with docker's "couldn't start the container" code (125) —
            // the NsSupervisor parent harvests this and propagates it.
            eprintln!("carrick: {e}");
            // SAFETY: `_exit` is async-signal-safe and skips atexit/Drop cleanup,
            // which is exactly what a forked child must do. Nothing is buffered
            // (stderr written above; the guest never started).
            unsafe { libc::_exit(125) };
        }
        Err(e) => Err(e),
    }
}

/// Finish a freshly-loaded image (its initial stack already set, if any) and
/// run it: install the EL0 trampoline, EL1 vectors, stage-1 page tables and
/// vDSO, optionally dump debug state, then enter the HVF run loop. This
/// trampoline→vectors→page-tables→vdso→dump→run tail was duplicated verbatim
/// across every `run_*` entry point; the entry points now differ only in how
/// they obtain the image bytes (host file / raw bytes / rootfs / overlay) and
/// set up identity + Rosetta redirection.
fn finish_and_run_image(
    image: AddressSpace,
    dispatcher: SyscallDispatcher,
    max_traps: usize,
    debug_state_path: Option<&PathBuf>,
) -> Result<RunResult, RuntimeError> {
    // Arm this (initial) process's deadlock watchdog; forked children re-arm in
    // the ForkOutcome::Child path. No-op unless CARRICK_DEADLOCK_WATCHDOG_MS set.
    crate::deadlock_watchdog::arm();
    let image = image.with_el0_trampoline()?;
    // The syscall shim swaps the legacy EL1 vectors for the identity-fast-path
    // dispatcher and adds the kernel-hole identity page it reads. Opt-in; the
    // legacy path is byte-identical when off. See docs/syscall-shim-design.md.
    let image = if crate::syscall_shim_enabled() {
        image.with_el1_vectors_shim()?.with_identity_page()?
    } else {
        image.with_el1_vectors()?
    };
    let image = image.with_stage1_page_tables()?;
    let image = with_optional_vdso(image)?;
    if let Some(p) = maybe_dump_debug_state(&image, debug_state_path) {
        eprintln!("debug state written: {}", p.display());
    }
    run_address_space_with_hvf_and_dispatcher(image, dispatcher, max_traps)
}

/// Convert the engine's `AddressSpace` regions into the dispatcher's
/// `ProcMapsEntry` view. Region paths are left empty here — the
/// `/proc/self/maps` renderer applies labels based on each region's
/// start address (matching the well-known runtime bases in
/// `crate::memory`).
/// Refresh the dispatcher's per-image `/proc` state — `/proc/self/maps` regions
/// and the `/proc/self/auxv` image — from a freshly loaded `AddressSpace`.
/// Called at boot and on each `execve` so both files track the CURRENT image
/// (previously only the boot image was reflected, leaving maps/auxv stale after
/// a guest `execve`d a new binary). Kept as one call so the two can't drift.
fn apply_image_proc_state(dispatcher: &SyscallDispatcher, image: &AddressSpace) {
    dispatcher.set_address_space_regions(proc_maps_from_address_space(image));
    dispatcher.set_auxv_image(image.linux_auxv_image().to_vec());
}

/// Stamp the per-process identity page the EL1 syscall shim reads (no-op unless
/// the shim is enabled). Must run before the guest issues any intercepted
/// syscall: at boot, and again in a forked child / after execve, since the
/// child's pid and the new image's identity differ. Credential changes
/// (`set*uid`/`set*gid`) re-stamp from the dispatcher itself. See
/// `docs/syscall-shim-design.md`.
fn stamp_identity_page<M: GuestMemory>(memory: &mut M, dispatcher: &SyscallDispatcher) {
    if !crate::syscall_shim_enabled() {
        return;
    }
    let id = dispatcher.identity_snapshot();
    let base = crate::memory::LINUX_IDENTITY_PAGE_BASE;
    for (off, val) in [
        (crate::memory::IDENTITY_OFF_PID, id.pid),
        (crate::memory::IDENTITY_OFF_UID, id.uid),
        (crate::memory::IDENTITY_OFF_EUID, id.euid),
        (crate::memory::IDENTITY_OFF_GID, id.gid),
        (crate::memory::IDENTITY_OFF_EGID, id.egid),
    ] {
        // Best-effort: the page is only absent when the shim is off (handled
        // above) or on a non-HVF stub; a stamp failure can't corrupt the guest.
        let _ = memory.write_bytes(base + off, &val.to_le_bytes());
    }
}

/// Stamp the running guest thread's guest-visible tid into the vCPU's TPIDR_EL1,
/// which the EL1 shim returns for `gettid` without a VM exit (no-op unless the
/// shim is enabled). Must run whenever the vCPU is (re)created — boot, clone,
/// fork, exec — since TPIDR_EL1 resets. The EL1 gettid handler traps normally if
/// this is left 0, so a missed stamp is a slow-but-correct fallback, never a
/// wrong tid. See `docs/syscall-shim-design.md`.
fn stamp_guest_tid(
    engine: &crate::trap::HvfTrapEngine,
    this_tid: ThreadId,
    registry: &crate::thread::ThreadRegistry,
) {
    if !crate::syscall_shim_enabled() {
        return;
    }
    if let Some(tid) = crate::dispatch::guest_visible_tid(this_tid, registry) {
        let _ = engine.set_guest_thread_id(u64::from(tid));
    }
}

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
                {
                    if let Some(signum) = action.stop_signal {
                        stop_by_signal(signum);
                        continue;
                    }
                    if let Some(signum) = action.term_signal {
                        if runtime.is_forked_child() || dispatcher.is_forked_guest_process() {
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
        let outcome = dispatch_single_threaded_syscall(
            &mut dispatcher,
            SyscallRequest::from_aarch64_frame(frame),
            runtime,
            &reporter,
            &mut waiter,
        )?;

        let mut last_syscall_retval: Option<i64> = None;

        match outcome {
            DispatchOutcome::WaitOnFds { .. }
            | DispatchOutcome::BlockingHostWrite(_)
            | DispatchOutcome::WaitOnFdsSelect { .. }
            | DispatchOutcome::WaitOnPollFds { .. }
            | DispatchOutcome::WaitOnProcExit { .. }
            | DispatchOutcome::WaitOnSignals { .. }
            | DispatchOutcome::WaitOnSleep { .. } => {
                let value = -(crate::linux_abi::LINUX_EINTR as i64);
                runtime.complete_syscall(value)?;
                last_syscall_retval = Some(value);
            }
            DispatchOutcome::Exit { code } => {
                crate::probes::guest_exit(code);
                if runtime.is_forked_child() || dispatcher.is_forked_guest_process() {
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
            DispatchOutcome::SignalDeath { signum } => {
                if runtime.is_forked_child() || dispatcher.is_forked_guest_process() {
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
            DispatchOutcome::Returned { value } => {
                runtime.complete_syscall(value)?;
                last_syscall_retval = Some(value);
            }
            DispatchOutcome::Errno { errno } => {
                let value = -(errno as i64);
                runtime.complete_syscall(value)?;
                last_syscall_retval = Some(value);
            }
            DispatchOutcome::Fork {
                pidfd_out,
                exit_signal,
                vfork,
            } => {
                // The single-threaded loop (run-elf) keeps the ordinary CoW fork
                // even for a vfork clone: it has no sibling threads, and Go / the
                // conformance gate exercise the THREADED loop
                // (run_vcpu_until_exit / handle_fork) where the faithful vfork
                // share-RAM + parent-suspend lives. A run-elf vfork therefore
                // behaves as a plain fork — safe (same as before), just not the
                // faithful CLONE_VM|CLONE_VFORK.
                let _ = vfork;
                let outcome = runtime.fork()?;
                let retval: i64 = match outcome {
                    crate::trap::ForkOutcome::Parent { child_pid } => {
                        crate::event_ring::rec(crate::event_ring::FORK, child_pid, 0, 0);
                        crate::guest_cpu::register_child(child_pid as u32);
                        // Watch the child's exit (EVFILT_PROC/NOTE_EXIT) so the
                        // signal pump delivers the requested exit signal to this
                        // (parent) tid when it exits — without a host SIGCHLD
                        // handler, which would break wait4's host-waitpid reap.
                        crate::host_signal::register_child_exit_watch(
                            child_pid,
                            this_tid as i32,
                            i32::try_from(exit_signal).unwrap_or(crate::linux_abi::LINUX_SIGCHLD),
                        );
                        // CLONE_PIDFD: hand the parent a pidfd for the new child.
                        if let Some(addr) = pidfd_out {
                            let fd = dispatcher.install_child_pidfd(child_pid).unwrap_or(-1);
                            let _ = runtime.write_bytes(addr, &fd.to_le_bytes());
                        }
                        // PID namespace: allocate the child's ns-pid and record
                        // the mapping (we are its ns-parent), then return the
                        // ns-pid — not the host pid — as the fork retval (§5.3).
                        // Identity when namespaces are off.
                        i64::from(crate::namespace::pid::register_child(
                            child_pid as u32,
                            std::process::id(),
                        ))
                    }
                    crate::trap::ForkOutcome::Child => {
                        dispatcher.clear_output_buffers();
                        // The forked child only keeps the forking thread, so its
                        // inherited event-ring watchdog is dead — reset the ring +
                        // re-arm it for the child (before any child rec()).
                        crate::event_ring::reinit_after_fork();
                        // kqueue is NOT inherited across fork, and the inherited
                        // self-pipe is shared with the parent — give the child
                        // fresh ones so its parked-thread wakes are its own.
                        crate::host_signal::reinit_after_fork();
                        // Threads don't survive fork: re-arm the child's deadlock
                        // watchdog (shares the tree-global progress counter).
                        crate::deadlock_watchdog::arm();
                        // PID namespace: block until the parent has registered
                        // our ns-pid, so our first getpid()/getppid() see the
                        // mapping (§5.3). No-op when namespaces are off.
                        crate::namespace::pid::await_self_registration();
                        // Re-stamp the identity page: the child's pid changed
                        // (ns-pid now registered), so a fast-path getpid is right.
                        stamp_identity_page(runtime, &dispatcher);
                        // The child's pid changed; its waiter watches for
                        // process-directed signals immediately, then upgrades
                        // to a per-thread kqueue only if it parks.
                        waiter = crate::io_wait::ThreadWaiter::process_only(
                            std::process::id() as ThreadId
                        );
                        0
                    }
                };
                runtime.complete_syscall(retval)?;
                last_syscall_retval = Some(retval);
            }
            DispatchOutcome::Execve { path, argv, env } => {
                crate::probes::execve_argv(&path, &argv);
                crate::event_ring::rec(crate::event_ring::EXEC, 1, 0, 0);
                // proctitle / cmdline identity is display text (lossy decode).
                let proc_argv: Vec<String> = argv
                    .iter()
                    .map(|a| String::from_utf8_lossy(a).into_owned())
                    .collect();
                // Reflect the new program into the host process name
                // (`carrick: <basename>`), so a hung forked-exec'd
                // child is identifiable in `ps -M` / Activity Monitor.
                let base = path.rsplit('/').next().unwrap_or(&path);
                crate::dispatch::set_host_process_name(base.as_bytes());
                let proc_env = env.clone();
                match load_execve_image(&dispatcher, &path, argv, env) {
                    Ok(new_image) => {
                        crate::probes::execve_loaded(
                            &path,
                            new_image.entry(),
                            new_image.initial_stack_pointer().unwrap_or(0),
                            new_image.regions().len() as u64,
                        );
                        dispatcher.set_executable_identity(path.clone(), proc_argv, proc_env);
                        // Refresh /proc/self/maps + /proc/self/auxv for the new image.
                        apply_image_proc_state(&dispatcher, &new_image);
                        dispatcher.close_cloexec_fds();
                        runtime.execve_into(&new_image)?;
                        // execve_into rebuilt a fresh (zeroed) identity page.
                        stamp_identity_page(runtime, &dispatcher);
                        stop_after_traced_exec(&dispatcher);
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
            DispatchOutcome::SetMemoryModel { tso } => {
                // Rosetta requested hardware x86_64 TSO on this vCPU. Toggle
                // ACTLR_EL1.EnTSO, then complete prctl with 0.
                runtime.set_memory_model(hardware_tso_for_debug(tso))?;
                runtime.complete_syscall(0)?;
                last_syscall_retval = Some(0);
            }
            DispatchOutcome::MapHostAlias {
                va,
                ipa,
                len,
                payload,
                file,
            } => {
                // Back a dynamic high-VA mmap; complete with the VA.
                runtime.map_host_alias(va, ipa, len, &payload, file)?;
                runtime.complete_syscall(va as i64)?;
                last_syscall_retval = Some(va as i64);
            }
            DispatchOutcome::SharedFutexWait {
                host_addr,
                value,
                timeout,
            } => {
                // A cross-process MAP_SHARED futex (e.g. /dev/shm-backed
                // LTP tst_checkpoint) goes through __ulock so a waker in
                // another carrick process is reached. Single-threaded
                // guests (like LTP test binaries) hit this path too; the
                // legacy `dispatch_threaded`-only short-circuit was the
                // root cause of LTP pause01 TBROKing on
                // `tst_checkpoint_wake ETIMEDOUT`.
                let retval = shared_futex_wait(host_addr, value, timeout, this_tid);
                runtime.complete_syscall(retval)?;
                last_syscall_retval = Some(retval);
            }
            DispatchOutcome::CloneThread { .. }
            | DispatchOutcome::ThreadExit { .. }
            | DispatchOutcome::SignalThread { .. }
            | DispatchOutcome::FutexWait { .. } => {
                // These are emitted only on the multi-threaded
                // `dispatch_threaded` path (run_vcpu_until_exit). The
                // single-threaded loops here always pass `thread: None`, so
                // the dispatcher never produces them.
                let value = -(crate::linux_abi::LINUX_ENOSYS as i64);
                runtime.complete_syscall(value)?;
                last_syscall_retval = Some(value);
            }
        }

        if trace_traps && let Some(ret) = last_syscall_retval {
            // Return-side companion to the entry line above: shows what carrick
            // returned to the guest. A negative value in [-4095, -1] is -errno
            // (decode it), otherwise it's a plain return. This makes the trap
            // stream a request+result log — the reducer aligns it against the
            // Docker oracle to localise a divergence (wrong errno) or the last
            // syscall before a hang (no return line printed).
            if (-4095..0).contains(&ret) {
                let e = (-ret) as u32;
                let ename = crate::linux_abi::errno_name(e).unwrap_or("?");
                eprintln!("trap#{traps}:   -> errno={e} ({ename})");
            } else {
                eprintln!("trap#{traps}:   -> ret={ret:#x} ({ret})");
            }
        }

        if let Some(action) =
            deliver_pending_signal(runtime, &dispatcher, last_syscall_retval, this_tid, None)?
        {
            if let Some(signum) = action.stop_signal {
                stop_by_signal(signum);
                continue;
            }
            if let Some(signum) = action.term_signal {
                if runtime.is_forked_child() || dispatcher.is_forked_guest_process() {
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

/// Defense-in-depth backstop around a syscall dispatch. A panic inside a
/// handler would otherwise unwind a vCPU thread: on a SIBLING vCPU it silently
/// kills only that thread (the guest then hangs waiting on it), and on any
/// thread it tears through frames holding now-released-but-possibly-half-edited
/// subsystem locks (`parking_lot` releases on unwind but the protected state
/// may be torn), so NO guest thread can safely resume. We cannot recover, so
/// log the offending syscall and abort deterministically — a clean SIGABRT
/// (with a core for diagnosing the carrick bug) beats a hung or corrupted
/// guest. The CLI panic hook has already printed the panic + backtrace.
fn dispatch_with_panic_backstop(
    syscall_nr: u64,
    tid: ThreadId,
    run: impl FnOnce() -> Result<DispatchOutcome, DispatchError>,
) -> Result<DispatchOutcome, DispatchError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)) {
        Ok(result) => result,
        Err(_) => {
            eprintln!(
                "carrick: FATAL — panic in syscall {syscall_nr} handler on vCPU tid {tid}; \
                 aborting guest (subsystem state may be torn, cannot safely resume)"
            );
            std::process::abort();
        }
    }
}

fn raise_sigpipe_for_blocking_write(
    dispatcher: &SyscallDispatcher,
    write: &crate::dispatch::BlockingHostWrite,
    outcome: DispatchOutcome,
) -> DispatchOutcome {
    if write.sigpipe_on_epipe()
        && matches!(
            &outcome,
            DispatchOutcome::Errno {
                errno: crate::linux_abi::LINUX_EPIPE
            }
        )
        && !dispatcher.signal_is_ignored(crate::linux_abi::LINUX_SIGPIPE)
    {
        dispatcher.mark_signal_pending(write.tid(), crate::linux_abi::LINUX_SIGPIPE);
    }
    outcome
}

fn partial_write_interrupt_outcome(write: &crate::dispatch::BlockingHostWrite) -> DispatchOutcome {
    if write.offset() > 0 {
        DispatchOutcome::Returned {
            value: write.offset() as i64,
        }
    } else {
        DispatchOutcome::Errno {
            errno: crate::linux_abi::LINUX_EINTR,
        }
    }
}

fn dispatch_single_threaded_syscall<M: GuestMemory>(
    dispatcher: &mut SyscallDispatcher,
    request: SyscallRequest,
    memory: &mut M,
    reporter: &CompatReporter,
    waiter: &mut crate::io_wait::ThreadWaiter,
) -> Result<DispatchOutcome, RuntimeError> {
    use crate::io_wait::WaitResult;

    // Service blocking I/O by waiting without re-entering the dispatcher's
    // blocking path: poll the host fds, then re-dispatch the same syscall on
    // readiness. This is the common single-threaded path for the combined and
    // split runtimes; the threaded runtime keeps its own fork-quiesce handling.
    let mut signal_wait_deadline = None;
    let mut sleep_deadline: Option<Instant> = None;
    loop {
        let outcome =
            dispatch_with_panic_backstop(request.number, std::process::id() as ThreadId, || {
                dispatcher.dispatch(request, memory, reporter)
            })?;
        match outcome {
            DispatchOutcome::BlockingHostWrite(mut write) => {
                waiter.ensure_full();
                loop {
                    match crate::dispatch::drive_blocking_host_write(&mut write) {
                        crate::dispatch::BlockingHostWriteStep::Done(outcome) => {
                            return Ok(raise_sigpipe_for_blocking_write(
                                dispatcher, &write, outcome,
                            ));
                        }
                        crate::dispatch::BlockingHostWriteStep::Wait => {
                            match waiter.wait(
                                &[crate::io_wait::WaitFd::raw(write.host_fd(), libc::POLLOUT)],
                                None,
                                0,
                            ) {
                                WaitResult::Ready => continue,
                                WaitResult::Interrupted => {
                                    return Ok(partial_write_interrupt_outcome(&write));
                                }
                                WaitResult::TimedOut => {
                                    return Ok(DispatchOutcome::Returned {
                                        value: write.offset() as i64,
                                    });
                                }
                                WaitResult::Errno(errno) => {
                                    if write.offset() > 0 {
                                        return Ok(DispatchOutcome::Returned {
                                            value: write.offset() as i64,
                                        });
                                    }
                                    return Ok(DispatchOutcome::Errno { errno });
                                }
                            }
                        }
                    }
                }
            }
            DispatchOutcome::WaitOnFds {
                fds,
                timeout,
                on_timeout,
                block_signals,
            } => {
                waiter.ensure_full();
                match waiter.wait(&fds, timeout, block_signals) {
                    WaitResult::Ready => continue,
                    WaitResult::TimedOut => {
                        return Ok(DispatchOutcome::Returned { value: on_timeout });
                    }
                    WaitResult::Interrupted => {
                        return Ok(DispatchOutcome::Errno {
                            errno: crate::linux_abi::LINUX_EINTR,
                        });
                    }
                    // Could not pin a watched fd (host fd table exhausted). The
                    // errno is already Linux; surface it verbatim.
                    WaitResult::Errno(errno) => return Ok(DispatchOutcome::Errno { errno }),
                }
            }
            DispatchOutcome::WaitOnFdsSelect {
                fds,
                timeout,
                block_signals,
                clear_on_timeout,
            } => {
                waiter.ensure_full();
                match waiter.wait(&fds, timeout, block_signals) {
                    // A fd became ready -> re-dispatch; the handler re-reads the
                    // (untouched) input sets and reports the now-ready fds.
                    WaitResult::Ready => continue,
                    // Timeout -> select returns 0 with the fd-sets zeroed. The
                    // handler left them intact (so Ready/EINTR are correct), so
                    // zero them here before completing.
                    WaitResult::TimedOut => {
                        for (addr, len) in &clear_on_timeout {
                            let zeros = vec![0u8; *len];
                            let _ = memory.write_bytes(*addr, &zeros);
                        }
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    // Signal interrupt -> EINTR; Linux leaves the fd-sets
                    // unmodified on EINTR, and the handler already did.
                    WaitResult::Interrupted => {
                        return Ok(DispatchOutcome::Errno {
                            errno: crate::linux_abi::LINUX_EINTR,
                        });
                    }
                    WaitResult::Errno(errno) => return Ok(DispatchOutcome::Errno { errno }),
                }
            }
            DispatchOutcome::WaitOnPollFds {
                fds,
                timeout,
                on_timeout,
                block_signals,
            } => {
                waiter.ensure_full();
                match waiter.wait_poll(&fds, timeout, block_signals) {
                    WaitResult::Ready => continue,
                    WaitResult::TimedOut => {
                        return Ok(DispatchOutcome::Returned { value: on_timeout });
                    }
                    WaitResult::Interrupted => {
                        return Ok(DispatchOutcome::Errno {
                            errno: crate::linux_abi::LINUX_EINTR,
                        });
                    }
                    // Could not pin a watched fd (host fd table exhausted). The
                    // errno is already Linux; surface it verbatim.
                    WaitResult::Errno(errno) => return Ok(DispatchOutcome::Errno { errno }),
                }
            }
            DispatchOutcome::WaitOnProcExit { pid, block_signals } => {
                waiter.ensure_full();
                match waiter.wait_proc_exit(pid, block_signals) {
                    // Ready (child exited) -> re-dispatch the waitid to reap.
                    WaitResult::Ready => continue,
                    // Interrupted (signal/quiesce) -> EINTR; the guest re-issues.
                    WaitResult::Interrupted | WaitResult::TimedOut => {
                        return Ok(DispatchOutcome::Errno {
                            errno: crate::linux_abi::LINUX_EINTR,
                        });
                    }
                    // wait_proc_exit never builds PinnedWaitFds, so this is
                    // unreachable in practice; present for exhaustiveness.
                    WaitResult::Errno(errno) => {
                        return Ok(DispatchOutcome::Errno { errno });
                    }
                }
            }
            DispatchOutcome::WaitOnSignals { wait_set, timeout } => {
                let slice = match signal_wait_slice(&mut signal_wait_deadline, timeout) {
                    Some(slice) => slice,
                    None => {
                        return Ok(DispatchOutcome::Errno {
                            errno: crate::linux_abi::LINUX_EAGAIN,
                        });
                    }
                };
                waiter.ensure_full();
                match waiter.wait(&[], Some(slice), !wait_set) {
                    WaitResult::Ready | WaitResult::Interrupted => continue,
                    WaitResult::TimedOut => {
                        if signal_wait_expired(signal_wait_deadline) {
                            return Ok(DispatchOutcome::Errno {
                                errno: crate::linux_abi::LINUX_EAGAIN,
                            });
                        }
                        continue;
                    }
                    // WaitOnSignals waits over an EMPTY fd slice, so new() never
                    // dups and this is unreachable; present for exhaustiveness.
                    WaitResult::Errno(errno) => {
                        return Ok(DispatchOutcome::Errno { errno });
                    }
                }
            }
            DispatchOutcome::WaitOnSleep { duration } => {
                // Single-vCPU path: no fork-quiesce, but still wait via the
                // waiter so a guest signal interrupts the sleep (EINTR). The
                // deadline is preserved across re-dispatch (signal re-wait).
                let deadline = *sleep_deadline.get_or_insert_with(|| Instant::now() + duration);
                let now = Instant::now();
                if now >= deadline {
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                waiter.ensure_full();
                match waiter.wait(&[], Some(deadline - now), 0) {
                    WaitResult::Ready => continue,
                    WaitResult::TimedOut => {
                        if Instant::now() >= deadline {
                            return Ok(DispatchOutcome::Returned { value: 0 });
                        }
                        continue;
                    }
                    WaitResult::Interrupted => {
                        return Ok(DispatchOutcome::Errno {
                            errno: crate::linux_abi::LINUX_EINTR,
                        });
                    }
                    WaitResult::Errno(errno) => return Ok(DispatchOutcome::Errno { errno }),
                }
            }
            other => return Ok(other),
        }
    }
}

fn signal_wait_slice(
    deadline: &mut Option<Instant>,
    timeout: Option<Duration>,
) -> Option<Duration> {
    if let Some(timeout) = timeout {
        let target = deadline.get_or_insert_with(|| Instant::now() + timeout);
        let now = Instant::now();
        if now >= *target {
            return None;
        }
        Some((*target - now).min(SIGNAL_WAIT_SLICE))
    } else {
        *deadline = None;
        Some(SIGNAL_WAIT_SLICE)
    }
}

fn signal_wait_expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|target| Instant::now() >= target)
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

    fn begin_exec_replacement(&self, owner: ThreadId) {
        crate::fork_quiesce::begin_exec_replacement(owner);
    }

    fn end_exec_replacement(&self) {
        crate::fork_quiesce::end_exec_replacement();
    }

    fn exec_replacing_other_thread(&self, tid: ThreadId) -> bool {
        crate::fork_quiesce::exec_replacing_other_thread(tid)
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
    /// This vCPU's "currently in `hv_vcpu_run`" flag, shared with the kicker so
    /// a page-table-edit coordinator can tell whether this thread is walking
    /// guest memory. Set true around `next_syscall`, false otherwise.
    in_guest: Arc<std::sync::atomic::AtomicBool>,
    waiter: crate::io_wait::ThreadWaiter,
    max_traps: usize,
    trace: bool,
    /// Set on a vfork (`CLONE_VM|CLONE_VFORK`) CHILD: the write end of the pipe
    /// whose read end the suspended PARENT blocks on. The child writes one byte
    /// (then closes it) at its first `execve` to release the parent; any other
    /// child exit closes this fd implicitly, giving the parent's `read()` EOF.
    /// `None` on the parent and on ordinary (non-vfork) children.
    vfork_release_fd: Option<i32>,
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
        let in_guest = kicker.register_in_guest(this_tid);
        Self {
            registry,
            futex,
            this_tid,
            threads,
            kicker,
            in_guest,
            waiter: crate::io_wait::ThreadWaiter::new(this_tid),
            max_traps,
            trace: std::env::var_os("CARRICK_TRACE_TRAPS").is_some(),
            vfork_release_fd: None,
        }
    }

    fn register_vcpu(&self, engine: &HvfTrapEngine) {
        self.kicker
            .register(self.this_tid, engine.vcpu_kick_handle());
        self.registry
            .record_thread_port(self.this_tid, crate::host_proc::current_thread_port());
    }

    /// Pause sibling vCPUs for a stage-1 page-table edit (mmap/mprotect/munmap),
    /// returning an RAII guard that resumes them on drop. carrick (the VMM)
    /// edits the guest's shared stage-1 descriptors from the host; a sibling
    /// walking a block mid-edit would fault. We become the sole edit
    /// coordinator, raise the quiesce flag, kick in-guest siblings out of
    /// `hv_vcpu_run`, and wait until none is walking the tables. The Dekker
    /// handshake at the run-loop top guarantees a sibling either observes the
    /// quiesce (and parks) or has its `in_guest` flag observed here — never
    /// both miss. Siblings blocked in host syscalls have `in_guest == false`
    /// and need no wake (this is what the reverted attempt-1 got wrong: it
    /// waited on a paused-count and fired spurious signals, deadlocking).
    fn pt_pause(&self) -> crate::fork_quiesce::PtPauseGuard {
        let b = pt_barrier();
        // Serialize editors: at most one stop-the-world at a time. A loser parks
        // (if the winner has raised quiescing) or yields (tiny pre-flag window),
        // then retries.
        loop {
            if b.try_become_coordinator() {
                break;
            }
            if b.is_quiescing() {
                b.park();
            } else {
                std::thread::yield_now();
            }
        }
        b.set_quiescing();
        let tid = self.this_tid;
        crate::probes::pt_pause_begin(
            tid,
            i32::from(self.kicker.any_other_in_guest(self.this_tid)),
            self.kicker.count() as i32,
        );
        // Force in-guest siblings out so they reach the run-loop-top park, then
        // wait until none is walking the tables. Re-kick each spin in case a
        // vCPU was between runs when the first kick landed. The deadline is a
        // backstop against a logic bug — it must converge quickly in practice;
        // a `pt-pause-timeout` fire means a sibling stayed in guest.
        let start = std::time::Instant::now();
        let deadline = start + std::time::Duration::from_millis(500);
        let mut spins: i32 = 0;
        while self.kicker.any_other_in_guest(self.this_tid) {
            self.kicker.kick_all_except(self.this_tid);
            if std::time::Instant::now() >= deadline {
                crate::probes::pt_pause_timeout(tid, start.elapsed().as_micros() as i64);
                break;
            }
            spins = spins.saturating_add(1);
            std::thread::yield_now();
        }
        crate::probes::pt_pause_ready(tid, spins, start.elapsed().as_micros() as i64);
        b.pause_guard(tid)
    }

    fn release_and_park_vcpu_for_fork(
        &self,
        engine: &mut HvfTrapEngine,
    ) -> Result<(), RuntimeError> {
        engine.release_vcpu_for_fork()?;
        // Drop out of the kicker the instant the vCPU is gone: while parked we
        // have no live vCPU, so another fork must not count us in `others` nor
        // try to kick a destroyed vCPU.
        self.kicker.unregister(self.this_tid);
        fork_barrier().park_if_quiescing();
        // Recreate the vCPU under the topology lock so vcpu_create cannot race
        // another fork's hv_vm_destroy/create. Register only after it exists.
        {
            let _topo = crate::fork_quiesce::topology_lock()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            engine.rebuild_vcpu_after_fork()?;
            self.register_vcpu(engine);
        }
        Ok(())
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

    /// Return-side companion to [`Self::trace_syscall`]: logs what carrick handed
    /// back to the guest. A value in `[-4095, -1]` is -errno (decoded); otherwise
    /// a plain return. Pairs with the entry line so the trap stream is a full
    /// request+result log — the reducer aligns it against the Docker oracle to
    /// localise a wrong-errno divergence or the last syscall before a hang.
    fn trace_syscall_return(&self, traps: usize, ret: Option<i64>) {
        if !self.trace {
            return;
        }
        let Some(ret) = ret else { return };
        if (-4095..0).contains(&ret) {
            let e = (-ret) as u32;
            let ename = crate::linux_abi::errno_name(e).unwrap_or("?");
            eprintln!(
                "tid#{} trap#{traps}:   -> errno={e} ({ename})",
                self.this_tid
            );
        } else {
            eprintln!(
                "tid#{} trap#{traps}:   -> ret={ret:#x} ({ret})",
                self.this_tid
            );
        }
    }

    fn service_threaded_syscall(
        &mut self,
        kernel: &Kernel,
        engine: &mut HvfTrapEngine,
        frame: Aarch64SyscallFrame,
    ) -> Result<DispatchOutcome, RuntimeError> {
        // Stage-1 page-table editors — munmap(215), mremap(216), mmap(222),
        // mprotect(226) — mutate the shared guest descriptors from the host.
        // With sibling vCPUs live, Pause-Modify-Resume them so none walks a
        // half-edited descriptor tree; the guard's drop resumes them on every
        // exit path of this syscall. Single-vCPU (no siblings): skip entirely
        // — the common case stays a plain dispatch with zero added cost.
        let _pt_pause = match frame.x8 {
            215 | 216 | 222 | 226 if self.kicker.count() > 1 => Some(self.pt_pause()),
            _ => None,
        };
        let mut signal_wait_deadline = None;
        // Monotonic deadline for a WaitOnSleep, established on first dispatch and
        // preserved across quiesce-park re-dispatch so the sleep isn't restarted.
        let mut sleep_deadline: Option<Instant> = None;
        loop {
            let request = SyscallRequest::from_aarch64_frame(frame);
            let outcome = dispatch_with_panic_backstop(request.number, self.this_tid, || {
                kernel.dispatcher.dispatch_threaded(
                    request,
                    engine,
                    &kernel.reporter,
                    self.this_tid,
                    &self.registry,
                    &self.futex,
                )
            })?;
            match outcome {
                DispatchOutcome::BlockingHostWrite(mut write) => {
                    self.waiter.ensure_full();
                    loop {
                        if crate::fork_quiesce::is_quiescing() {
                            self.release_and_park_vcpu_for_fork(engine)?;
                            continue;
                        }
                        match crate::dispatch::drive_blocking_host_write(&mut write) {
                            crate::dispatch::BlockingHostWriteStep::Done(outcome) => {
                                return Ok(raise_sigpipe_for_blocking_write(
                                    &kernel.dispatcher,
                                    &write,
                                    outcome,
                                ));
                            }
                            crate::dispatch::BlockingHostWriteStep::Wait => {
                                match self.waiter.wait(
                                    &[crate::io_wait::WaitFd::raw(write.host_fd(), libc::POLLOUT)],
                                    None,
                                    0,
                                ) {
                                    crate::io_wait::WaitResult::Ready => continue,
                                    crate::io_wait::WaitResult::Interrupted => {
                                        if crate::fork_quiesce::is_quiescing() {
                                            self.release_and_park_vcpu_for_fork(engine)?;
                                            continue;
                                        }
                                        return Ok(partial_write_interrupt_outcome(&write));
                                    }
                                    crate::io_wait::WaitResult::TimedOut => {
                                        return Ok(DispatchOutcome::Returned {
                                            value: write.offset() as i64,
                                        });
                                    }
                                    crate::io_wait::WaitResult::Errno(errno) => {
                                        if write.offset() > 0 {
                                            return Ok(DispatchOutcome::Returned {
                                                value: write.offset() as i64,
                                            });
                                        }
                                        return Ok(DispatchOutcome::Errno { errno });
                                    }
                                }
                            }
                        }
                    }
                }
                DispatchOutcome::WaitOnFds {
                    fds,
                    timeout,
                    on_timeout,
                    block_signals,
                } => {
                    self.waiter.ensure_full();
                    match self.waiter.wait(&fds, timeout, block_signals) {
                        crate::io_wait::WaitResult::Ready => continue,
                        crate::io_wait::WaitResult::TimedOut => {
                            break Ok(DispatchOutcome::Returned { value: on_timeout });
                        }
                        crate::io_wait::WaitResult::Interrupted => {
                            if crate::fork_quiesce::is_quiescing() {
                                self.release_and_park_vcpu_for_fork(engine)?;
                                continue;
                            }
                            break Ok(DispatchOutcome::Errno {
                                errno: crate::linux_abi::LINUX_EINTR,
                            });
                        }
                        // Could not pin a watched fd (host fd table exhausted).
                        // The errno is already Linux; surface it verbatim.
                        crate::io_wait::WaitResult::Errno(errno) => {
                            break Ok(DispatchOutcome::Errno { errno });
                        }
                    }
                }
                DispatchOutcome::WaitOnFdsSelect {
                    fds,
                    timeout,
                    block_signals,
                    clear_on_timeout,
                } => {
                    self.waiter.ensure_full();
                    match self.waiter.wait(&fds, timeout, block_signals) {
                        // See the non-threaded loop above for the select fd-set
                        // input==output rationale: leave the sets intact across
                        // the wait; zero them only on timeout.
                        crate::io_wait::WaitResult::Ready => continue,
                        crate::io_wait::WaitResult::TimedOut => {
                            for (addr, len) in &clear_on_timeout {
                                let zeros = vec![0u8; *len];
                                let _ = engine.write_bytes(*addr, &zeros);
                            }
                            break Ok(DispatchOutcome::Returned { value: 0 });
                        }
                        crate::io_wait::WaitResult::Interrupted => {
                            if crate::fork_quiesce::is_quiescing() {
                                self.release_and_park_vcpu_for_fork(engine)?;
                                continue;
                            }
                            break Ok(DispatchOutcome::Errno {
                                errno: crate::linux_abi::LINUX_EINTR,
                            });
                        }
                        crate::io_wait::WaitResult::Errno(errno) => {
                            break Ok(DispatchOutcome::Errno { errno });
                        }
                    }
                }
                DispatchOutcome::WaitOnPollFds {
                    fds,
                    timeout,
                    on_timeout,
                    block_signals,
                } => {
                    self.waiter.ensure_full();
                    match self.waiter.wait_poll(&fds, timeout, block_signals) {
                        crate::io_wait::WaitResult::Ready => continue,
                        crate::io_wait::WaitResult::TimedOut => {
                            break Ok(DispatchOutcome::Returned { value: on_timeout });
                        }
                        crate::io_wait::WaitResult::Interrupted => {
                            if crate::fork_quiesce::is_quiescing() {
                                self.release_and_park_vcpu_for_fork(engine)?;
                                continue;
                            }
                            break Ok(DispatchOutcome::Errno {
                                errno: crate::linux_abi::LINUX_EINTR,
                            });
                        }
                        // Could not pin a watched fd (host fd table exhausted).
                        // The errno is already Linux; surface it verbatim.
                        crate::io_wait::WaitResult::Errno(errno) => {
                            break Ok(DispatchOutcome::Errno { errno });
                        }
                    }
                }
                DispatchOutcome::WaitOnProcExit { pid, block_signals } => {
                    self.waiter.ensure_full();
                    match self.waiter.wait_proc_exit(pid, block_signals) {
                        // Ready (child exited) → re-dispatch the waitid to reap.
                        crate::io_wait::WaitResult::Ready => continue,
                        // Interrupted (signal/quiesce) → EINTR; the guest re-issues.
                        crate::io_wait::WaitResult::Interrupted
                        | crate::io_wait::WaitResult::TimedOut => {
                            if crate::fork_quiesce::is_quiescing() {
                                self.release_and_park_vcpu_for_fork(engine)?;
                                continue;
                            }
                            break Ok(DispatchOutcome::Errno {
                                errno: crate::linux_abi::LINUX_EINTR,
                            });
                        }
                        // wait_proc_exit never builds PinnedWaitFds, so this is
                        // unreachable in practice; present for exhaustiveness.
                        crate::io_wait::WaitResult::Errno(errno) => {
                            break Ok(DispatchOutcome::Errno { errno });
                        }
                    }
                }
                DispatchOutcome::WaitOnSignals { wait_set, timeout } => {
                    let slice = match signal_wait_slice(&mut signal_wait_deadline, timeout) {
                        Some(slice) => slice,
                        None => {
                            break Ok(DispatchOutcome::Errno {
                                errno: crate::linux_abi::LINUX_EAGAIN,
                            });
                        }
                    };
                    self.waiter.ensure_full();
                    match self.waiter.wait(&[], Some(slice), !wait_set) {
                        crate::io_wait::WaitResult::Ready => continue,
                        crate::io_wait::WaitResult::TimedOut => {
                            if signal_wait_expired(signal_wait_deadline) {
                                break Ok(DispatchOutcome::Errno {
                                    errno: crate::linux_abi::LINUX_EAGAIN,
                                });
                            }
                            continue;
                        }
                        crate::io_wait::WaitResult::Interrupted => {
                            if crate::fork_quiesce::is_quiescing() {
                                self.release_and_park_vcpu_for_fork(engine)?;
                            }
                            if crate::fork_quiesce::exec_replacing_other_thread(self.this_tid) {
                                break Ok(DispatchOutcome::Errno {
                                    errno: crate::linux_abi::LINUX_EINTR,
                                });
                            }
                            continue;
                        }
                        // WaitOnSignals waits over an EMPTY fd slice, so new()
                        // never dups and this is unreachable; present for
                        // exhaustiveness.
                        crate::io_wait::WaitResult::Errno(errno) => {
                            break Ok(DispatchOutcome::Errno { errno });
                        }
                    }
                }
                DispatchOutcome::WaitOnSleep { duration } => {
                    // The fix for the multithreaded-fork deadlock: sleep via the
                    // waiter (NOT a blocking host nanosleep in the dispatcher) so
                    // a sleeping sibling reaches here, observes the fork-quiesce,
                    // and PARKS — letting a sibling's fork complete. The deadline
                    // is preserved across the park so the sleep is not restarted.
                    let deadline = *sleep_deadline.get_or_insert_with(|| Instant::now() + duration);
                    let now = Instant::now();
                    if now >= deadline {
                        break Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    self.waiter.ensure_full();
                    match self.waiter.wait(&[], Some(deadline - now), 0) {
                        crate::io_wait::WaitResult::Ready => continue,
                        crate::io_wait::WaitResult::TimedOut => {
                            if Instant::now() >= deadline {
                                break Ok(DispatchOutcome::Returned { value: 0 });
                            }
                            continue;
                        }
                        crate::io_wait::WaitResult::Interrupted => {
                            if crate::fork_quiesce::is_quiescing() {
                                self.release_and_park_vcpu_for_fork(engine)?;
                                continue;
                            }
                            break Ok(DispatchOutcome::Errno {
                                errno: crate::linux_abi::LINUX_EINTR,
                            });
                        }
                        crate::io_wait::WaitResult::Errno(errno) => {
                            break Ok(DispatchOutcome::Errno { errno });
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

        let retval: i64 = loop {
            let outcome =
                match self
                    .futex
                    .wait_prepared_for_thread(wait, timeout, self.this_tid, &|| {
                        crate::host_signal::has_pending_for(self.this_tid)
                            || crate::fork_quiesce::is_quiescing()
                            || crate::fork_quiesce::exec_replacing_other_thread(self.this_tid)
                    }) {
                    FutexWaitOutcome::Woken => 0,
                    FutexWaitOutcome::TimedOut => -(crate::linux_abi::LINUX_ETIMEDOUT as i64),
                    FutexWaitOutcome::Interrupted if crate::fork_quiesce::is_quiescing() => {
                        self.release_and_park_vcpu_for_fork(engine)?;
                        continue;
                    }
                    FutexWaitOutcome::Interrupted => -(crate::linux_abi::LINUX_EINTR as i64),
                };
            break outcome;
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
        let retval = loop {
            let retval = shared_futex_wait(host_addr, value, timeout, self.this_tid);
            if retval == -(crate::linux_abi::LINUX_EINTR as i64)
                && crate::fork_quiesce::is_quiescing()
            {
                self.release_and_park_vcpu_for_fork(engine)?;
                continue;
            }
            break retval;
        };
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
                // Wait (if necessary) for room under the HVF concurrent-vCPU cap
                // BEFORE taking the topology lock. carrick binds one vCPU per
                // guest thread for its whole lifetime; HVF caps concurrent vCPUs
                // (64 on this host), so a guest with more live threads than the
                // cap (CPython test_queue.test_many_threads spawns 100) would
                // otherwise hit HV_NO_RESOURCES here — and since clone() already
                // reported this tid as a success to the guest, the thread that
                // failed to get a vCPU silently never ran, deadlocking any join
                // on it. Blocking here (clone still succeeds, matching Linux,
                // which has no such cap) lets the thread start as soon as another
                // guest thread exits and frees a slot. Done OUTSIDE the topology
                // lock so a fork in flight isn't stalled behind a full gate.
                HvfTrapEngine::wait_for_vcpu_slot();
                // Build the vCPU + register it in the kicker UNDER the topology
                // lock, so this is atomic w.r.t. a fork's VM teardown: a fork
                // either sees this vCPU in the kicker (and waits for it to park)
                // or hasn't released the lock yet (so we build in the REBUILT VM
                // afterwards). Never create a vCPU in a VM a fork is destroying.
                let topo = crate::fork_quiesce::topology_lock()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if !child_registry.is_live(tid) {
                    drop(topo);
                    child_kicker.unregister(tid);
                    crate::host_signal::forget_thread(tid);
                    child_kernel.dispatcher.forget_thread_signal_state(tid);
                    return;
                }
                match HvfTrapEngine::from_thread_spec(spec) {
                    Ok(child_engine) => {
                        child_kicker.register(tid, child_engine.vcpu_kick_handle());
                        drop(topo);
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
                        match r {
                            Ok(VcpuLoopOutcome::ProcessExit(result)) => {
                                let _ = std::io::Write::flush(&mut std::io::stdout());
                                let _ = std::io::Write::flush(&mut std::io::stderr());
                                let _ = unsafe {
                                    libc::write(
                                        1,
                                        result.stdout.as_ptr() as *const _,
                                        result.stdout.len(),
                                    )
                                };
                                let _ = unsafe {
                                    libc::write(
                                        2,
                                        result.stderr.as_ptr() as *const _,
                                        result.stderr.len(),
                                    )
                                };
                                unsafe { libc::_exit(result.exit_code) };
                            }
                            Ok(VcpuLoopOutcome::TrapLimit(_)) | Ok(VcpuLoopOutcome::ThreadDone) => {
                            }
                            Err(e) => {
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
                    }
                    Err(e) => {
                        drop(topo);
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
            // A sibling thread is going away but the process lives on: destroy
            // its vCPU now (the no-op Drop won't), else it leaks live and a
            // later fork's hv_vm_destroy hits HV_BUSY on the dead thread's vCPU.
            engine.destroy_vcpu_on_thread_exit();
            VcpuLoopOutcome::ThreadDone
        }
    }

    fn terminate_siblings_for_exec(
        &self,
        kernel: &Kernel,
        _engine: &mut HvfTrapEngine,
    ) -> Result<(), RuntimeError> {
        // Linux execve replaces the whole thread group. Carrick's execve path
        // destroys and recreates the process-wide HVF VM, so every sibling vCPU
        // must be gone before `execve_into` runs. Hold the topology lock for the
        // whole drain so a newly-created guest thread cannot build a vCPU from a
        // stale pre-exec ThreadSpec while the VM is being replaced.
        let _topology = crate::fork_quiesce::topology_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        kernel.begin_exec_replacement(self.this_tid);
        self.kicker.kick_all_except(self.this_tid);
        self.futex.notify_signal_pending();
        crate::host_signal::wake_all_waiters();

        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            use std::sync::atomic::Ordering::SeqCst;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while crate::trap::VCPU_LIVE.load(SeqCst) > 1 {
                if std::time::Instant::now() >= deadline {
                    kernel.end_exec_replacement();
                    return Err(RuntimeError::Trap(TrapError::Hypervisor(format!(
                        "execve thread-group teardown timed out: vcpu_live={} kicker={}",
                        crate::trap::VCPU_LIVE.load(SeqCst),
                        self.kicker.count()
                    ))));
                }
                self.kicker.kick_all_except(self.this_tid);
                self.futex.notify_signal_pending();
                crate::host_signal::wake_all_waiters();
                std::thread::sleep(std::time::Duration::from_micros(200));
            }
        }

        let removed = self.registry.remove_all_except(self.this_tid);
        for tid in removed {
            self.kicker.unregister(tid);
            crate::host_signal::forget_thread(tid);
            kernel.dispatcher.forget_thread_signal_state(tid);
        }
        kernel.end_exec_replacement();
        Ok(())
    }

    fn handle_execve(
        &mut self,
        kernel: &Kernel,
        engine: &mut HvfTrapEngine,
        path: String,
        argv: Vec<Vec<u8>>,
        env: Vec<Vec<u8>>,
    ) -> Result<(), RuntimeError> {
        crate::probes::execve_argv(&path, &argv);
        // The proctitle / /proc/self/cmdline identity is display text; lossily
        // decode the byte argv (a genuinely non-UTF-8 argv is rare).
        let proc_argv: Vec<String> = argv
            .iter()
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        let base = path.rsplit('/').next().unwrap_or(&path).to_owned();
        crate::dispatch::set_host_process_name(base.as_bytes());
        let proc_env = env.clone();
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
                    .set_executable_identity(path.clone(), proc_argv, proc_env);
                // Refresh /proc/self/maps + /proc/self/auxv for the new image.
                apply_image_proc_state(&kernel.dispatcher, &img);
                kernel.dispatcher.close_cloexec_fds();
                if self.registry.live_count() > 1 {
                    self.terminate_siblings_for_exec(kernel, engine)?;
                }
                engine.execve_into(&img)?;
                // execve_into rebuilt a fresh vCPU: re-stamp the identity page
                // (zeroed) and TPIDR_EL1 (reset) for the same thread/tid.
                stamp_identity_page(engine, &kernel.dispatcher);
                stamp_guest_tid(engine, self.this_tid, &self.registry);
                // vfork: the execve SUCCEEDED and we now have our own private VM
                // (execve_into rebuilt fresh, un-shared buffers). Release the
                // suspended parent by writing one byte to the inherited pipe, then
                // close it so the new program doesn't inherit the host fd. A FAILED
                // execve returns above via `?` WITHOUT releasing — the child then
                // `_exit`s and the parent's `read()` gets EOF instead (faithful
                // vfork: parent resumes on successful execve OR child exit).
                if let Some(fd) = self.vfork_release_fd.take() {
                    let _ = unsafe { libc::write(fd, [0u8; 1].as_ptr().cast(), 1) };
                    unsafe { libc::close(fd) };
                }
                stop_after_traced_exec(&kernel.dispatcher);
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
        exit_signal: u32,
        vfork: Option<u64>,
    ) -> Result<Option<i64>, RuntimeError> {
        // vfork (CLONE_VM|CLONE_VFORK): the child SHARES the parent's guest RAM
        // (engine.fork_vfork() below) and the parent vCPU is SUSPENDED here until
        // the child execve's or exits (Parent arm below). The two are
        // co-dependent — shared RAM with a concurrently-running parent would race
        // on the same physical pages — so they are wired together. An ordinary
        // fork (`vfork == false`) keeps the CoW snapshot and does not suspend.
        // Serialize forks: at most one quiesce/fork in flight. When another
        // fork already holds the token, BLOCK rather than surfacing EAGAIN —
        // a multithreaded guest (Go's os/exec spawning concurrently) does not
        // retry a failed clone. Park at the in-flight fork's barrier so it can
        // count this thread as quiesced and complete, then retry the token. If
        // this thread is already inside handle_fork, it will not reach the
        // normal run-loop-top release path, so it must release its vCPU here
        // before parking; otherwise the barrier counts it but hv_vm_destroy
        // still sees its vCPU live.
        // This makes concurrent forks serialize transparently. The in-flight
        // forker is waiting on exactly this thread (live_count includes it), so
        // parking here can't deadlock it; once it ends the quiesce we wake and
        // win (or lose to a third forker and park again).
        while !fork_barrier().try_begin_fork() {
            if fork_barrier().is_quiescing() {
                self.release_and_park_vcpu_for_fork(engine)?;
            }
            std::thread::yield_now();
        }
        // Serialize VM topology against sibling vCPU creation for the whole
        // fork: while held, no thread can build a vCPU (they block in
        // spawn_clone_thread's critical section), so `hv_vm_destroy` below can't
        // race a being-born vCPU into HV_BUSY. Held until this function returns.
        let _topology = crate::fork_quiesce::topology_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Clear any VM published by a previous fork so siblings that release
        // their vCPUs this round see only THIS fork's republished VM (or, on a
        // quiesce abort, fall back to the still-live existing VM).
        crate::trap::clear_rebuilt_vm_for_fork();
        // Stop-the-world: a multithreaded guest can fork only if every OTHER
        // guest vCPU thread is first paused at its lock-safe run-loop top, so
        // the child (which has only THIS thread after libc::fork) doesn't
        // inherit a carrick lock held by a thread that won't exist in it.
        // Count the OTHER threads with a LIVE vCPU (kicker-registered) — not the
        // registry's live_count, which includes a sibling that has a tid but
        // hasn't built its vCPU yet (it holds the topology lock we now own, so
        // it's blocked before vcpu_create and has nothing to quiesce). Counting
        // it would make wait_quiesced wait for a thread that can't park.
        let mut others = self.kicker.count().saturating_sub(1);
        crate::probes::fork_quiesce(0, others as i64, self.kicker.count() as i64, self.this_tid);
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
            loop {
                // Re-read the LIVE sibling count each iteration. A vCPU that EXITS
                // mid-quiesce (the importer thread finishing, a joined ForkWait
                // worker) drops out of the kicker, so an `others` captured ONCE
                // goes stale-HIGH and wait_quiesced waits for a parker that no
                // longer exists → spins forever. THIS is the multithreaded-fork
                // wedge: observed `others=4` while the kicker had already fallen
                // to 3 (only 2 siblings could ever park). Tracking the live count
                // lets the wait complete as siblings leave; it reaches 0 (→
                // wait_quiesced returns true immediately) if they all exit.
                others = self.kicker.count().saturating_sub(1);
                if barrier.wait_quiesced(others, Duration::from_millis(50)) {
                    break;
                }
                crate::probes::fork_quiesce(
                    1,
                    others as i64,
                    barrier.paused_count() as i64,
                    self.this_tid,
                );
                // Do not surface EAGAIN to the guest here. Go's os/exec does
                // not retry a failed clone, and the in-flight fork is an
                // internal Carrick serialization point rather than guest
                // resource exhaustion. Keep nudging every wait class until all
                // live vCPUs reach the barrier.
                self.kicker.kick_all_except(self.this_tid);
                self.futex.notify_signal_pending();
                crate::host_signal::wake_all_waiters();
            }
            quiesced = true;
        }

        // INVARIANT before tearing down the VM: no OTHER guest vCPU is live
        // besides this forker's (VCPU_LIVE == 1). The quiesce above is supposed
        // to guarantee it, but `wait_quiesced`'s `paused` counter is a racy
        // proxy — across back-to-back forks a slow-waking parker from the
        // PREVIOUS fork can satisfy `paused >= others` while a sibling has not
        // actually released its vCPU (proven via the on-HV_BUSY dump: VCPU_LIVE=1,
        // kicker=6 after a "successful" quiesce). Hold the invariant true: give
        // the kicked siblings a BOUNDED window (sleeping, NOT spinning) to finish
        // releasing, re-nudging; if it still doesn't hold, ABORT LOUDLY rather
        // than proceed into a corrupting hv_vm_destroy (HV_BUSY) or spin forever.
        // A clean abort lets the kernel reclaim the HVF VM — no wedged spinning
        // guest. Asserting the invariant (and dying loudly if violated) is the
        // contract; enforcing it by an unbounded spin is not.
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            use std::sync::atomic::Ordering::SeqCst;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while crate::trap::VCPU_LIVE.load(SeqCst) > 1 {
                if std::time::Instant::now() >= deadline {
                    tracing::error!(
                        vcpu_live = crate::trap::VCPU_LIVE.load(SeqCst),
                        kicker = self.kicker.count(),
                        others,
                        pid = std::process::id(),
                        "fork quiesce failed to release sibling vCPUs in 5s; aborting \
                         to avoid HV_BUSY VM corruption"
                    );
                    std::process::abort();
                }
                self.kicker.kick_all_except(self.this_tid);
                self.futex.notify_signal_pending();
                crate::host_signal::wake_all_waiters();
                std::thread::sleep(std::time::Duration::from_micros(200));
            }
        }

        // Publish the arena high-water so the child snapshot's mincore scan is
        // bounded to the guest's used prefix, not all 32 GiB (see
        // clone_region_for_child / GUEST_ARENA_HIGH_WATER).
        crate::trap::set_guest_arena_high_water(kernel.dispatcher.mmap_arena_high_water());
        // vfork: an inherited pipe to SUSPEND the parent until the child
        // execve/_exit. Created BEFORE the fork so BOTH processes inherit BOTH
        // ends; these are host fds (NOT in the guest fd table). On a pipe()
        // failure, degrade to a non-suspending shared fork (vfork_pipe = None) —
        // the RAM share is still correct, only the suspend is skipped — rather
        // than fail the guest's clone.
        let vfork_pipe: Option<(i32, i32)> = if vfork.is_some() {
            let mut fds = [0i32; 2];
            if unsafe { libc::pipe(fds.as_mut_ptr()) } == 0 {
                // CLOEXEC hygiene: carrick's guest execve is an in-process VM
                // rebuild (not a host exec), so handle_execve still closes the
                // write end explicitly — but mark both ends CLOEXEC so a real host
                // exec (orchestrator helpers) can never inherit them. (macOS has
                // no pipe2, so set FD_CLOEXEC after pipe.)
                unsafe {
                    libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC);
                    libc::fcntl(fds[1], libc::F_SETFD, libc::FD_CLOEXEC);
                }
                Some((fds[0], fds[1]))
            } else {
                None
            }
        } else {
            None
        };
        let prepared_fork = kernel.fork.prepare_host_fork();
        // vfork shares the parent's guest RAM (CLONE_VM); an ordinary fork takes a
        // private CoW snapshot of each region. CRITICAL: gate the SHARE on the
        // suspend pipe existing, NOT on vfork.is_some() — if pipe() failed
        // (vfork_pipe == None) the parent CANNOT be suspended, and sharing RAM
        // with a running parent silently corrupts guest memory. So a pipe()
        // failure degrades to a plain CoW fork (share + suspend stay strictly
        // coupled: either both or neither). The child-stack SP set below stays
        // keyed on `vfork` because a CoW child of a clone()-with-stack still needs
        // its SP.
        let fork_result = if vfork_pipe.is_some() {
            engine.fork_vfork()
        } else {
            engine.fork()
        };
        let fork_outcome = match fork_result {
            Ok(outcome) => outcome,
            Err(error) => {
                if let Some((r, w)) = vfork_pipe {
                    unsafe {
                        libc::close(r);
                        libc::close(w);
                    }
                }
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
                let child_exit_needs_signal_pump = kernel
                    .dispatcher
                    .child_exit_signal_needs_pump(self.this_tid, exit_signal);
                kernel.fork.restart_after_parent_fork(
                    prepared_fork,
                    &self.kicker,
                    &self.futex,
                    child_exit_needs_signal_pump,
                );
                // engine.fork() rebuilt this thread's own vCPU, so its old
                // kicker handle is stale. Re-register the new one (under the
                // topology lock we still hold) — otherwise a later fork can't
                // kick this thread out of the guest and it never quiesces.
                self.register_vcpu(engine);
                if child_exit_needs_signal_pump {
                    // Watch the child's exit (EVFILT_PROC/NOTE_EXIT) so the
                    // signal pump delivers the requested signal to this
                    // (parent) tid when it exits — without a host SIGCHLD
                    // handler, which would break wait4's host-waitpid reap.
                    // Default unblocked SIGCHLD skips this path; wait4/waitid
                    // own the reap and no guest-visible notification is lost.
                    crate::host_signal::register_child_exit_watch(
                        child_pid,
                        self.this_tid,
                        i32::try_from(exit_signal).unwrap_or(crate::linux_abi::LINUX_SIGCHLD),
                    );
                }
                crate::event_ring::rec(crate::event_ring::FORK, child_pid, 0, 0);
                crate::guest_cpu::register_child(child_pid as u32);
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
                // PID namespace: allocate the child's ns-pid + record the
                // mapping (we are its ns-parent), and return the ns-pid as the
                // fork retval (§5.3). Identity when namespaces are off.
                let retval = i64::from(crate::namespace::pid::register_child(
                    child_pid as u32,
                    std::process::id(),
                ));
                // vfork: SUSPEND this (parent) vCPU thread until the child
                // execve's (it writes one byte) or exits (the OS closes the
                // child's write end → our read() returns EOF). We still hold
                // `_topology` for the whole function, so no concurrent fork can
                // quiesce us (a sibling forker blocks on the topology lock until
                // we resume) — a plain blocking read is therefore safe and cannot
                // deadlock the quiesce. Retry on EINTR so a delivered signal does
                // not cut the vfork window short. The child's own syscalls keep
                // the deadlock-watchdog tree-global progress counter advancing, so
                // a legitimately suspended parent is not mistaken for a stall.
                if let Some((vf_read, _vf_write)) = vfork_pipe {
                    unsafe { libc::close(_vf_write) }; // parent only reads
                    // Bounded suspend: the child should execve/_exit within ms, but
                    // a pathological guest (a child that blocks before execve, or a
                    // contrived process-shared-futex rendezvous with a frozen
                    // sibling) must NOT wedge the parent forever — we still hold
                    // topology_lock here, so an indefinite block would stall every
                    // sibling fork/thread-spawn in the process. Poll with a deadline
                    // (EINTR re-polls on the remaining budget); on expiry resume the
                    // parent DEGRADED with a loud diagnostic rather than hanging.
                    const VFORK_SUSPEND_TIMEOUT: Duration = Duration::from_secs(60);
                    let deadline = std::time::Instant::now() + VFORK_SUSPEND_TIMEOUT;
                    let mut byte = [0u8; 1];
                    loop {
                        let now = std::time::Instant::now();
                        if now >= deadline {
                            tracing::error!(
                                child_pid,
                                "vfork parent-suspend timed out (60s) waiting for child \
                                 execve/_exit; resuming parent degraded"
                            );
                            break;
                        }
                        let remaining_ms =
                            (deadline - now).as_millis().min(i32::MAX as u128) as i32;
                        let mut pfd = libc::pollfd {
                            fd: vf_read,
                            events: libc::POLLIN,
                            revents: 0,
                        };
                        let r = unsafe { libc::poll(&mut pfd, 1, remaining_ms) };
                        if r > 0 {
                            // Readable: a byte (child execve'd) or EOF (child exited).
                            let _ = unsafe { libc::read(vf_read, byte.as_mut_ptr().cast(), 1) };
                            break;
                        }
                        if r == 0 {
                            continue; // deadline re-checked at loop top
                        }
                        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                            break; // unexpected poll error — stop waiting
                        }
                        // EINTR → re-poll on the remaining budget.
                    }
                    unsafe { libc::close(vf_read) };
                    // The vfork child shared the parent's guest RAM until it
                    // execve'd or exited. Its child-side identity stamp therefore
                    // overwrote the shared EL1 shim identity page; restore the
                    // parent's getpid/get*id fast-path values before resuming it.
                    stamp_identity_page(engine, &kernel.dispatcher);
                }
                retval
            }
            crate::trap::ForkOutcome::Child => {
                kernel.dispatcher.clear_output_buffers();
                // A forked child must NOT inherit its PARENT's vfork suspend-pipe
                // write end (copied across libc::fork). Holding it open would keep
                // the grandparent's pipe alive — defeating the EOF release if this
                // child's parent _exits without execve — and re-firing it at our
                // OWN execve would release the grandparent spuriously. Drop the
                // inherited copy so only the genuine vfork child holds the writer.
                if let Some(stale) = self.vfork_release_fd.take() {
                    unsafe { libc::close(stale) };
                }
                // vfork: keep the WRITE end of OUR suspend pipe (close the read
                // end the parent owns). `handle_execve` writes one byte to it at
                // our first successful execve to release the parent; any other
                // exit closes it implicitly → the parent's read() gets EOF.
                if let Some((vf_read, vf_write)) = vfork_pipe {
                    unsafe { libc::close(vf_read) };
                    self.vfork_release_fd = Some(vf_write);
                }
                // vfork with an explicit child_stack (clone's stack arg != 0): run
                // the child on it. fork(2) keeps the parent's SP, which is correct
                // for child_stack==NULL (Go os/exec) but wrong for a clone() that
                // supplies a stack + child function (glibc/musl's clone() wrapper):
                // such a child expects SP == child_stack so it can pop fn/arg the
                // parent pushed there (visible via shared RAM). Set it before resume.
                if let Some(child_stack) = vfork
                    && child_stack != 0
                    && let Err(e) = engine.set_guest_sp_el0(child_stack)
                {
                    tracing::warn!(?e, "vfork: failed to set child SP_EL0");
                }
                // Don't inherit the parent's accumulated guest CPU time: the
                // child's new vCPU starts the hypervisor exec clock at zero.
                crate::guest_cpu::reset();
                let parent_tid = self.this_tid;
                self.this_tid = std::process::id() as ThreadId;
                // The child inherits the parent's blocked mask + alternate
                // signal stack (POSIX) but has a NEW tid; re-key the dispatcher's
                // per-tid signal state so an inherited SA_ONSTACK alt stack isn't
                // silently lost (the mask survives via the host fallback; the
                // altstack has none). (audit M2; probe forkaltstack)
                kernel
                    .dispatcher
                    .migrate_thread_signal_state(parent_tid, self.this_tid);
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
                crate::event_ring::reinit_after_fork();
                crate::host_signal::reinit_after_fork();
                // PID namespace: block until the parent registered our ns-pid
                // before any guest code runs (§5.3). No-op when ns off.
                crate::namespace::pid::await_self_registration();
                // Re-stamp identity + tid: the child's pid changed and the vCPU
                // was rebuilt (fresh registry holds only this thread).
                stamp_identity_page(engine, &kernel.dispatcher);
                stamp_guest_tid(engine, self.this_tid, &self.registry);
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
    // PID-namespace launch placement (container runs only — `run-elf` never
    // requests it). The MAP_SHARED ns table is allocated and the init slot
    // filled in `maybe_fork_ns_supervisor` (the guest-init child branch), which
    // runs BEFORE this on the container path. As a fallback for any path that
    // reaches here with placement requested but no region yet (e.g. the
    // supervisor fork was skipped on setup failure), initialize identity-style
    // here so getpid()==1 still holds (docs/namespaces-design.md §5.2).
    if crate::namespace::pid::requested() && !crate::namespace::pid::enabled() {
        let _ = crate::namespace::pid::init(std::process::id());
    }
    let futex = Arc::new(FutexTable::new());
    let kernel = Arc::new(KernelState::new(dispatcher));
    // Track spawned sibling threads so the process doesn't tear down while a
    // worker is mid-flight. We join them after the main thread finishes.
    let threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
    // Registry of live vCPUs so a signalling thread (tgkill) or the
    // process-directed signal pump can force a target out of `hv_vcpu_run`.
    let kicker = Arc::new(crate::vcpu_kick::VcpuKicker::new());
    // Daemon that kicks in-guest vCPUs when process-directed async signals are
    // observable. Non-interactive command runners start pump-free and request it
    // lazily when a guest installs a real signal handler or forks a child whose
    // exit signal is caught/blocked; interactive terminals keep prompt Ctrl-C
    // delivery for busy guests that have not made another syscall.
    if crate::host_tty::host_isatty(0) || crate::host_tty::host_isatty(1) {
        kernel.fork.start_signal_pump(&kicker, &futex);
    }

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
    // Stamp this thread's tid into TPIDR_EL1 for the EL1 gettid fast path (main
    // thread at boot; each worker at spawn). Re-stamped after fork/exec below.
    stamp_guest_tid(&engine, state.this_tid, &state.registry);
    // Run the vCPU loop in a closure so we can run vCPU cleanup on EVERY exit
    // path — `?` errors, early returns, and the trap-limit fall-through alike.
    let result: Result<VcpuLoopOutcome, RuntimeError> = (|| {
        for traps in 1..=state.max_traps {
            if kernel.exec_replacing_other_thread(state.this_tid) {
                return Ok(state.handle_thread_exit(&kernel, &mut engine, 0, traps));
            }
            // Lock-safe point: no carrick lock is held here (each iteration acquires
            // and releases its syscall's locks within the iteration). If another
            // thread is forking a multithreaded guest, release this vCPU (so the
            // forker can hv_vm_destroy), park until the fork completes, then
            // recreate the vCPU in the parent's rebuilt VM and resume.
            if fork_barrier().is_quiescing() {
                state.release_and_park_vcpu_for_fork(&mut engine)?;
            }
            // Page-table-edit Pause-Modify-Resume: if a sibling vCPU is editing
            // the shared stage-1 tables from the host, park here (KEEPING this
            // vCPU — unlike fork) until it finishes, so this vCPU never walks a
            // half-edited descriptor tree.
            if pt_barrier().is_quiescing() {
                pt_barrier().park();
            }
            // Publish that we are about to enter the guest (and may walk page
            // tables). The store here and the re-check below form a Dekker
            // handshake with the edit coordinator, which sets `quiescing` then
            // reads `in_guest`: SeqCst guarantees at least one side observes the
            // other, so this vCPU never enters guest concurrently with an edit.
            state
                .in_guest
                .store(true, std::sync::atomic::Ordering::SeqCst);
            if pt_barrier().is_quiescing() {
                state
                    .in_guest
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                pt_barrier().park();
                continue;
            }
            // ---- vCPU run: NO dispatcher lock held ----
            let next = engine.next_syscall();
            // Out of guest now (in host): a coordinator may proceed past us.
            state
                .in_guest
                .store(false, std::sync::atomic::Ordering::SeqCst);
            let frame = match next {
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
                    syndrome,
                    elr,
                    far,
                    from_el0_direct,
                    ..
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
                        from_el0_direct,
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
                | DispatchOutcome::BlockingHostWrite(_)
                | DispatchOutcome::WaitOnFdsSelect { .. }
                | DispatchOutcome::WaitOnPollFds { .. }
                | DispatchOutcome::WaitOnProcExit { .. }
                | DispatchOutcome::WaitOnSignals { .. }
                | DispatchOutcome::WaitOnSleep { .. } => {
                    last_syscall_retval =
                        Some(state.complete_errno(&mut engine, crate::linux_abi::LINUX_EINTR)?);
                }
                DispatchOutcome::Exit { code } => {
                    crate::trap::dump_kick_stats();
                    // A forked child process (real macOS fork) exits via _exit so
                    // the rebuilt HVF context doesn't run the panicky Drops, and
                    // its buffered stdio is flushed to the inherited host fds.
                    if engine.is_forked_child() || kernel.dispatcher.is_forked_guest_process() {
                        crate::probes::guest_exit(code);
                        forked_child_exit(
                            code,
                            kernel.dispatcher.stdout(),
                            kernel.dispatcher.stderr(),
                        );
                    }
                    // exit_group, or exit(2) as the last live thread. Tear the
                    // whole process down. A plain exit(2) with live siblings is
                    // routed as ThreadExit before this branch, so Exit + !last
                    // means process-wide termination even when the caller is
                    // the main guest thread.
                    let last = state.registry.exit(state.this_tid);
                    if !last {
                        // exit_group(94) or fatal process termination: flush
                        // shared buffers and terminate the entire host process
                        // because other guest threads share the address space.
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
                DispatchOutcome::SignalDeath { signum } => {
                    crate::trap::dump_kick_stats();
                    if engine.is_forked_child() || kernel.dispatcher.is_forked_guest_process() {
                        forked_child_die_by_signal(
                            signum,
                            kernel.dispatcher.stdout(),
                            kernel.dispatcher.stderr(),
                        );
                    }
                    let code = 128 + signum;
                    let last = state.registry.exit(state.this_tid);
                    if !last {
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
                    crate::event_ring::rec(crate::event_ring::EXEC, 1, 0, 0);
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
                DispatchOutcome::Fork {
                    pidfd_out,
                    exit_signal,
                    vfork,
                } => {
                    if let Some(retval) =
                        state.handle_fork(&kernel, &mut engine, pidfd_out, exit_signal, vfork)?
                    {
                        last_syscall_retval = Some(state.complete_returned(&mut engine, retval)?);
                    }
                }
                DispatchOutcome::SetMemoryModel { tso } => {
                    // Rosetta requested hardware x86_64 TSO on this vCPU.
                    engine.set_memory_model(hardware_tso_for_debug(tso))?;
                    last_syscall_retval = Some(state.complete_returned(&mut engine, 0)?);
                }
                DispatchOutcome::MapHostAlias {
                    va,
                    ipa,
                    len,
                    payload,
                    file,
                } => {
                    engine.map_host_alias(va, ipa, len, &payload, file)?;
                    last_syscall_retval = Some(state.complete_returned(&mut engine, va as i64)?);
                }
            }

            if kernel.dispatcher.take_signal_pump_request() {
                kernel.fork.start_signal_pump(&state.kicker, &state.futex);
            }

            state.trace_syscall_return(traps, last_syscall_retval);

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
    })();
    // This thread is leaving its vCPU loop. `HvfTrapEngine::drop` is a no-op, so
    // destroy the vCPU here on every path EXCEPT ProcessExit (the whole process
    // is exiting — the kernel reclaims it) and ThreadDone (handle_thread_exit
    // already destroyed it). This plugs the leak where an errored/trap-limited
    // sibling left a live vCPU behind, tripping a later fork's hv_vm_destroy
    // into HV_BUSY.
    if !matches!(
        &result,
        Ok(VcpuLoopOutcome::ProcessExit(_)) | Ok(VcpuLoopOutcome::ThreadDone)
    ) {
        engine.destroy_vcpu_on_thread_exit();
    }
    result
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
/// `stop_signal` is the sibling default action: stop the host process by the
/// translated signal, then continue the guest loop after SIGCONT/ptrace resume.
struct PendingSignalAction {
    term_signal: Option<i32>,
    stop_signal: Option<i32>,
}

impl PendingSignalAction {
    fn ignored() -> Self {
        Self {
            term_signal: None,
            stop_signal: None,
        }
    }

    fn terminate(signum: i32) -> Self {
        Self {
            term_signal: Some(signum),
            stop_signal: None,
        }
    }

    fn stop(signum: i32) -> Self {
        Self {
            term_signal: None,
            stop_signal: Some(signum),
        }
    }
}

/// Drain whatever signal is sitting in the host pending slot and
/// dispatch it to the guest. Returns `Ok(None)` when nothing was
/// pending. Returns `Ok(Some(...))` when a default-action signal fires,
/// a handler was injected, or the signal was consumed without resuming
/// immediately.
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
    // Drain the cross-process explicit-signal ring into pending state, so the
    // normal delivery below runs each with the sender's identity. Runs in
    // dispatch context, where the dispatcher locks are safe.
    dispatcher.drain_xsignals_for_tid(tid);

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
        return Ok(Some(PendingSignalAction::ignored()));
    }
    if dispatcher.signal_is_ignored(pending) {
        return Ok(Some(PendingSignalAction::ignored()));
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
            // SA_RESTART: if this handler interrupted a blocking, restartable
            // syscall that returned EINTR, restart it instead of surfacing the
            // EINTR. Only on the syscall-boundary path (interrupted_pc is None);
            // a kick/preempt resumes mid-instruction, not at a syscall, and the
            // restartable set excludes the timeout-bearing waits (poll/select/
            // epoll/nanosleep) that EINTR even under SA_RESTART on Linux.
            let restart_syscall = interrupted_pc.is_none()
                && last_syscall_retval == Some(-(crate::linux_abi::LINUX_EINTR as i64))
                && action.sa_flags & crate::linux_abi::LINUX_SA_RESTART != 0
                && trap.last_syscall_nr().is_some_and(is_restartable_syscall);
            let saved_sigmask = dispatcher.enter_signal_handler(tid, pending, action);
            // If rt_sigqueueinfo queued a caller-supplied siginfo for this
            // (tid, signum), pop it now and hand it to inject_signal so the
            // SA_SIGINFO handler sees the original si_value payload. Failing
            // that, a plain cross-process kill leaves no queued siginfo — but the
            // host handler captured the sender's host pid, so synthesise an
            // SI_USER siginfo with the sender's ns-pid (identity when pid-ns is
            // off) instead of the all-zero si_pid that made LTP kill10 loop on
            // "received signal from 0".
            let queued_siginfo = dispatcher.take_pending_siginfo(tid, pending).or_else(|| {
                let sender_host = crate::host_signal::last_sender_for(pending);
                (sender_host > 0).then(|| {
                    let ns_pid =
                        crate::namespace::pid::host_to_ns_or_self(sender_host as u32) as i32;
                    let uid = crate::cred_ipc::read_target(sender_host).unwrap_or(0);
                    crate::linux_abi::LinuxSiginfo::kill(
                        pending,
                        crate::linux_abi::LINUX_SI_USER,
                        ns_pid,
                        uid,
                    )
                })
            });
            match trap.inject_signal(
                pending,
                action.sa_handler,
                restorer,
                last_syscall_retval,
                interrupted_pc,
                altstack,
                saved_sigmask,
                None, // SI_USER-shaped (tkill/sysmon); faults use deliver_fault_signal
                queued_siginfo,
                restart_syscall,
            ) {
                Ok(()) => Ok(Some(PendingSignalAction::ignored())),
                // Linux force_sigsegv: the signal frame couldn't be written to
                // the user stack (guest mprotect'd its own stack PROT_NONE, bad
                // SP, ...). Terminate the whole thread-group by SIGSEGV (exit
                // 139) instead of a fatal carrick error — and a sibling thread
                // takes the group down cleanly rather than silently vanishing
                // and deadlocking its peers.
                Err(TrapError::SignalDeliveryFault) => {
                    Ok(Some(PendingSignalAction::terminate(11))) // SIGSEGV
                }
                Err(e) => Err(e.into()),
            }
        }
        // No registered handler → the kernel takes the signal's DEFAULT action.
        // For SIGCHLD/SIGURG/SIGWINCH that action is IGNORE, not terminate, so the
        // signal is silently dropped. Without this, a no-handler SIGURG (Go's
        // async-preempt / GC stack-scan signal, which flies around constantly and
        // which a freshly fork+exec'd guest may receive before its runtime
        // installs the handler) was treated as a terminating default action:
        // `forked_child_die_by_signal(23)` then `raise(SIGURG)` (host default =
        // ignore, a no-op) fell through to `_exit(128+23)=151` — the ~30% flaky
        // `go build` failure (multithreaded `go` fork+exec'ing `go tool compile`).
        // Linux ignores it; so must we.
        None if is_default_ignore_signal(pending) => Ok(Some(PendingSignalAction::ignored())),
        None if is_default_stop_signal(pending) => Ok(Some(PendingSignalAction::stop(pending))),
        None => Ok(Some(PendingSignalAction::terminate(pending))),
    }
}

/// Linux aarch64 syscall numbers that auto-restart when interrupted by an
/// SA_RESTART handler (the kernel's `ERESTARTSYS` set). DELIBERATELY EXCLUDES
/// the timeout-bearing waits — poll/ppoll/select/pselect6/epoll_wait/
/// epoll_pwait/nanosleep/clock_nanosleep/futex/rt_sigtimedwait — which return
/// EINTR even under SA_RESTART on Linux (`ERESTART_RESTARTBLOCK`/no-restart), so
/// restarting them would diverge from the oracle. The blocking, restartable
/// file/socket/process-wait calls are what LTP's `tst_test` reap needs.
fn is_restartable_syscall(nr: u64) -> bool {
    // Scoped to the process-wait pair (wait4 + waitid) — exactly what LTP's
    // `tst_test` parent reap needs, and verified to match Linux via the
    // `waitrestart` probe + getpid01 (0/100 -> 100/100). The broader classic
    // restart set (read/write/accept/connect/recv/send/ioctl/fcntl/flock/
    // openat) is INTENTIONALLY excluded for now: enabling it segfaulted
    // signal-heavy children (e.g. sigaltstack02), so restarting those paths has
    // a separate bug (likely a stale ELR_EL1 on a non-wait blocking path) that
    // must be root-caused before they can be safely restarted. Timeout-bearing
    // waits (poll/select/epoll/nanosleep/futex/rt_sigtimedwait) are excluded by
    // design — Linux returns EINTR for them even under SA_RESTART.
    matches!(
        nr,
        95  // waitid
        | 260 // wait4
    )
}

/// Signals whose DEFAULT disposition is "ignore" (Linux `Ign`): a no-handler
/// instance is dropped, not a terminating default action. SIGCONT (resume) and
/// the stop signals are handled separately; everything else defaults to
/// terminate/core.
fn is_default_ignore_signal(signum: i32) -> bool {
    matches!(
        signum,
        crate::linux_abi::LINUX_SIGCHLD
            | crate::linux_abi::LINUX_SIGURG
            | crate::linux_abi::LINUX_SIGWINCH
    )
}

fn is_default_stop_signal(signum: i32) -> bool {
    matches!(
        signum,
        crate::linux_abi::LINUX_SIGSTOP
            | crate::linux_abi::LINUX_SIGTSTP
            | crate::linux_abi::LINUX_SIGTTIN
            | crate::linux_abi::LINUX_SIGTTOU
    )
}

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
    // Diagnostic: surface *host_addr right before entering __ulock so a probe
    // can see whether the kernel's compare-and-wait will succeed or short-
    // circuit. Reuses the futex-route probe encoding: op=99 marks a
    // pre-ulock-wait peek; arg2=value-passed, arg3=value-at-host-addr-NOW.
    let host_value = unsafe { (host_addr as *const u32).read() };
    crate::probes::futex_route(host_addr as u64, 99, value as i32, host_value as u64);
    loop {
        if crate::host_signal::has_pending_for(this_tid)
            || crate::fork_quiesce::is_quiescing()
            || crate::fork_quiesce::exec_replacing_other_thread(this_tid)
        {
            return -(crate::linux_abi::LINUX_EINTR as i64);
        }
        // Slice the kernel wait so a pending guest signal (whose cross-thread
        // kick can't interrupt __ulock) is still observed within ~20 ms. The
        // earlier "phantom waiter" inflation we suspected here was actually
        // macOS's `__ulock_wake` returning spurious successes (see the wake
        // path); slicing here is signal-delivery latency only, not the cause.
        let slice_us: u32 = match deadline {
            Some(dl) => {
                let now = std::time::Instant::now();
                if now >= dl {
                    return -(crate::linux_abi::LINUX_ETIMEDOUT as i64);
                }
                u32::try_from((dl - now).as_micros().min(20_000)).unwrap_or(20_000)
            }
            None => 20_000,
        };
        crate::probes::ulock_wait(host_addr as u64, value, slice_us, 0, 0);
        let r = crate::ulock::wait(host_addr, value, slice_us);
        crate::probes::ulock_wait(host_addr as u64, value, slice_us, 1, r);
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
    {
        if let Some(action) = deliver_pending_signal(
            engine,
            &kernel.dispatcher,
            last_syscall_retval,
            this_tid,
            interrupted_pc,
        )? {
            if let Some(signum) = action.stop_signal {
                stop_by_signal(signum);
                return Ok(None);
            }
            if let Some(signum) = action.term_signal {
                if engine.is_forked_child() || kernel.dispatcher.is_forked_guest_process() {
                    let out = kernel.dispatcher.stdout();
                    let err = kernel.dispatcher.stderr();
                    forked_child_die_by_signal(signum, &out, &err);
                }
                let result = assemble_run_result(kernel, 128 + signum, traps, false);
                return Ok(Some(VcpuLoopOutcome::ProcessExit(Box::new(result))));
            }
        }
    }
    Ok(None)
}

/// Build a new AddressSpace for an execve target. Resolves the path
/// through the dispatcher's rootfs when present; falls back to the
/// host filesystem otherwise (useful for tests where no rootfs is
/// configured).
/// Absolute host path to Apple's Rosetta 2 Linux ELF interpreter. This is an
/// AArch64 binary that JIT-translates an x86_64 Linux guest in user space.
pub(crate) const ROSETTA_INTERPRETER: &str = "/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta";

/// The installed Rosetta interpreter's bytes, read once and cached. `None` when
/// Rosetta isn't installed for Linux. Both the ELF-load redirect and the ioctl
/// handshake source data from this single read.
pub(crate) fn rosetta_binary_bytes() -> Option<&'static [u8]> {
    static CACHE: std::sync::OnceLock<Option<Vec<u8>>> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| std::fs::read(ROSETTA_INTERPRETER).ok())
        .as_deref()
}

/// The verification blob Apple's Rosetta `memcmp`s the licensing-ioctl result
/// against. Rosetta keeps its own copy embedded at a fixed offset and compares
/// the kernel's answer against it, so we echo back *exactly that* — sourced
/// live from the installed binary rather than embedded in carrick's source.
/// This keeps Apple's string out of our tree and stays correct if Apple
/// revises it. Returns the bytes through (and including) the NUL terminator.
pub(crate) fn rosetta_license_blob() -> Option<&'static [u8]> {
    static CACHE: std::sync::OnceLock<Option<Vec<u8>>> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| {
            let bytes = rosetta_binary_bytes()?;
            // Anchor on a short distinctive prefix; the full response is taken
            // from the binary, not encoded here.
            const ANCHOR: &[u8] = b"Our hard work";
            let start = bytes.windows(ANCHOR.len()).position(|w| w == ANCHOR)?;
            let nul = bytes[start..].iter().position(|&b| b == 0)?;
            Some(bytes[start..=start + nul].to_vec())
        })
        .as_deref()
}

/// Inspect raw ELF bytes about to be loaded into the guest. If they describe an
/// x86_64 binary, rewrite the load to run Apple's Rosetta 2 interpreter instead
/// — exactly as Linux `binfmt_misc` redirects a foreign-arch binary to its
/// registered interpreter:
///
///   argv = [`<rosetta>`, `<target>`, `<original argv[1..]>`]
///
/// Returns:
///
/// - `None`         — the binary is AArch64 (or not an ELF we recognise); the
///   caller proceeds with the original bytes/argv.
/// - `Some(Ok(..))` — the binary is x86_64; `(rosetta_bytes, new_argv)`.
/// - `Some(Err(e))` — the binary is x86_64 but Rosetta isn't readable on this
///   host (`-errno` for the caller to surface).
///
/// Rosetta itself is statically linked, so the AddressSpace loader never needs
/// to resolve a PT_INTERP for it from the guest VFS.
#[allow(clippy::type_complexity)]
pub(crate) fn maybe_redirect_to_rosetta<A: AsRef<[u8]>>(
    target_path: &str,
    target_bytes: &[u8],
    // argv items are opaque bytes (Linux ABI); accept String (initial entry)
    // or Vec<u8> (execve) and always return the byte form.
    argv: &[A],
) -> Option<Result<(Vec<u8>, Vec<Vec<u8>>), i32>> {
    use crate::elf::{Machine, inspect_elf_bytes};
    use crate::linux_abi::LINUX_ENOENT;

    let meta = inspect_elf_bytes(target_bytes).ok()?;
    if meta.machine != Machine::X86_64 {
        return None;
    }

    crate::probes::execve_argv("rosetta-redirect", &[target_path.as_bytes().to_vec()]);

    let rosetta_bytes = match rosetta_binary_bytes() {
        Some(b) => b.to_vec(),
        None => return Some(Err(LINUX_ENOENT)),
    };

    let orig_argv: Vec<Vec<u8>> = argv.iter().map(|a| a.as_ref().to_vec()).collect();
    Some(Ok((rosetta_bytes, rosetta_argv(target_path, &orig_argv))))
}

/// Build the argv carrick hands the loaded Apple Rosetta interpreter for an
/// x86_64 target. Apple's `rosetta` consumes `argv[1]` as the binary to
/// translate and presents the program with `argv = [argv[0], argv[2..]]` — i.e.
/// it passes OUR `argv[0]` straight through as the *program's* `argv[0]`. So
/// `argv[0]` MUST be the program's original `argv[0]`, not the interpreter path:
/// a multi-call binary (coreutils/busybox, which dispatch on `argv[0]`) otherwise
/// sees "rosetta" and fails ("coreutils: unknown program 'rosetta'"). Standalone
/// binaries ignore `argv[0]`, which is why glibc programs worked regardless.
///
/// Layout: `[<orig argv[0]>, <target>, <orig argv[1..]>]`. With no original argv
/// (should not happen for an execve), fall back to the target path as `argv[0]`.
fn rosetta_argv(target_path: &str, orig_argv: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut new_argv: Vec<Vec<u8>> = Vec::with_capacity(orig_argv.len() + 1);
    new_argv.push(
        orig_argv
            .first()
            .cloned()
            .unwrap_or_else(|| target_path.as_bytes().to_vec()),
    );
    new_argv.push(target_path.as_bytes().to_vec());
    new_argv.extend(orig_argv.iter().skip(1).cloned());
    new_argv
}

/// Build the `RuntimeError` for "this is an x86_64 binary but Rosetta 2 is not
/// available on the host" — surfaced from the initial-load call sites (the
/// execve path returns the bare `-errno` instead).
fn rosetta_unavailable(errno: i32, path: &str) -> RuntimeError {
    RuntimeError::FsBackend(anyhow::anyhow!(
        "{path}: x86_64 binary requires Apple Rosetta 2 at {ROSETTA_INTERPRETER} \
         (errno {errno}); is Rosetta installed for Linux? \
         `softwareupdate --install-rosetta`"
    ))
}

/// Adapter presenting a separate (`memory`, `trap`) pair as one
/// `GuestMemory + SyscallTrap` object, so `run_split_loop` reuses the combined
/// run loop instead of duplicating its ~200-line body. `GuestMemory` delegates
/// to `mem`, `SyscallTrap` to `trap`.
struct SplitView<'a, M: GuestMemory, T: SyscallTrap> {
    mem: &'a mut M,
    trap: &'a mut T,
}

impl<M: GuestMemory, T: SyscallTrap> GuestMemory for SplitView<'_, M, T> {
    fn read_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        self.mem.read_bytes(address, length)
    }
    fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.mem.write_bytes(address, bytes)
    }
    fn zero_backing(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.mem.zero_backing(address, len)
    }
    fn set_no_access(&mut self, address: u64, len: usize, no_access: bool) {
        self.mem.set_no_access(address, len, no_access);
    }
    fn protect_range(&mut self, address: u64, len: usize, prot: u64) -> Result<(), MemoryError> {
        self.mem.protect_range(address, len, prot)
    }
    fn unmap_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.mem.unmap_range(address, len)
    }
    fn unmap_alias_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.mem.unmap_alias_range(address, len)
    }
    fn shared_futex_host_addr(&self, guest_addr: u64) -> Option<usize> {
        self.mem.shared_futex_host_addr(guest_addr)
    }
}

impl<M: GuestMemory, T: SyscallTrap> SyscallTrap for SplitView<'_, M, T> {
    fn next_syscall(&mut self) -> Result<Option<Aarch64SyscallFrame>, TrapError> {
        self.trap.next_syscall()
    }
    fn current_pc(&self) -> Result<u64, TrapError> {
        self.trap.current_pc()
    }
    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError> {
        self.trap.complete_syscall(return_value)
    }
    fn fork(&mut self) -> Result<crate::trap::ForkOutcome, TrapError> {
        self.trap.fork()
    }
    fn execve_into(&mut self, new_image: &AddressSpace) -> Result<(), TrapError> {
        self.trap.execve_into(new_image)
    }
    fn is_forked_child(&self) -> bool {
        self.trap.is_forked_child()
    }
    #[allow(clippy::too_many_arguments)]
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
        queued_siginfo: Option<crate::linux_abi::LinuxSiginfo>,
        restart_syscall: bool,
    ) -> Result<(), TrapError> {
        self.trap.inject_signal(
            signum,
            handler,
            sa_restorer,
            pending_syscall_retval,
            interrupted_pc,
            altstack,
            saved_sigmask,
            fault_siginfo,
            queued_siginfo,
            restart_syscall,
        )
    }
    fn last_syscall_nr(&self) -> Option<u64> {
        self.trap.last_syscall_nr()
    }
    fn restore_from_sigframe(&mut self) -> Result<u64, TrapError> {
        self.trap.restore_from_sigframe()
    }
    fn set_memory_model(&mut self, tso: bool) -> Result<(), TrapError> {
        self.trap.set_memory_model(tso)
    }
    fn map_host_alias(
        &mut self,
        va: u64,
        ipa: u64,
        len: u64,
        payload: &[u8],
        file: Option<(libc::c_int, libc::off_t, libc::c_int)>,
    ) -> Result<(), TrapError> {
        self.trap.map_host_alias(va, ipa, len, payload, file)
    }
}

/// Single-threaded run loop over a separate (`memory`, `trap`) pair. Wraps them
/// in a [`SplitView`] and delegates to `run_combined_syscall_loop_with_dispatcher`
/// — one loop body, two entry shapes (this was ~200 duplicated lines).
fn run_split_loop<M, T>(
    memory: &mut M,
    trap: &mut T,
    dispatcher: SyscallDispatcher,
    max_traps: usize,
) -> Result<RunResult, RuntimeError>
where
    M: GuestMemory,
    T: SyscallTrap,
{
    let mut view = SplitView { mem: memory, trap };
    run_combined_syscall_loop_with_dispatcher(&mut view, dispatcher, max_traps)
}

// `impl SyscallTrap for HvfTrapEngine` moved into carrick-hvf (trap.rs):
// both the trait and the type now live there, so the impl must too (orphan
// rule). The blanket loop bounds (`T: SyscallTrap`) and `SplitView` impl below
// use the re-exported trait and are unchanged.

#[cfg(test)]
mod tests {
    use super::*;

    fn rootfs_with(files: &[(&str, &[u8])]) -> crate::rootfs::RootFs {
        let mut b = tar::Builder::new(Vec::new());
        for (path, data) in files {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Regular);
            h.set_mode(0o755);
            h.set_size(data.len() as u64);
            b.append_data(&mut h, path, *data).unwrap();
        }
        let bytes = b.into_inner().unwrap();
        crate::rootfs::RootFs::from_layers(std::iter::once(crate::rootfs::LayerSource::Tar(bytes)))
            .unwrap()
    }

    #[test]
    fn entrypoint_path_search_resolves_bare_command_like_execvp() {
        // Docker accepts a bare entrypoint command and PATH-resolves it; `env`
        // lives ONLY in /usr/bin, so finding it proves a real $PATH walk.
        let rootfs = rootfs_with(&[("bin/ls", b"\x7fELFx"), ("usr/bin/env", b"\x7fELFx")]);
        let dispatcher = SyscallDispatcher::with_rootfs(rootfs);
        let env = vec!["PATH=/usr/local/bin:/usr/bin:/bin".to_string()];

        // Bare names resolve to the first PATH dir that has them.
        assert_eq!(resolve_entrypoint_path("ls", &env, &dispatcher), "/bin/ls");
        assert_eq!(
            resolve_entrypoint_path("env", &env, &dispatcher),
            "/usr/bin/env"
        );
        // A path containing '/' is returned unchanged (execve, not execvp).
        assert_eq!(
            resolve_entrypoint_path("/sbin/foo", &env, &dispatcher),
            "/sbin/foo"
        );
        assert_eq!(resolve_entrypoint_path("./x", &env, &dispatcher), "./x");
        // Not found anywhere on PATH → keep the bare name (so the load error names it).
        assert_eq!(resolve_entrypoint_path("nope", &env, &dispatcher), "nope");
        // No PATH in env → fall back to the standard default set (covers /usr/bin).
        assert_eq!(
            resolve_entrypoint_path("env", &[], &dispatcher),
            "/usr/bin/env"
        );
    }

    #[test]
    fn entrypoint_program_resolves_shebang_to_interpreter() {
        // A script entrypoint (`#!/bin/sh`) must load its INTERPRETER with the
        // script spliced into argv — Docker / execve(2) semantics — instead of
        // being handed to the ELF loader as "not an ELF binary".
        // (`carrick run --entrypoint <script>`.)
        let rootfs = rootfs_with(&[
            ("entry.sh", b"#!/bin/sh\necho hi\n"),
            ("bin/sh", b"\x7fELFx"),
        ]);
        let dispatcher = SyscallDispatcher::with_rootfs(rootfs);

        let (path, argv) = resolve_entrypoint_program(
            "/entry.sh",
            &[],
            vec![b"/entry.sh".to_vec(), b"arg1".to_vec()],
            &dispatcher,
        )
        .expect("entrypoint program resolves");

        assert_eq!(path, "/bin/sh");
        assert_eq!(
            argv,
            vec![b"/bin/sh".to_vec(), b"/entry.sh".to_vec(), b"arg1".to_vec(),]
        );
    }

    #[test]
    fn entrypoint_program_passes_through_plain_elf() {
        // A normal ELF entrypoint is unchanged (no shebang, no argv splice).
        let rootfs = rootfs_with(&[("bin/true", b"\x7fELFx")]);
        let dispatcher = SyscallDispatcher::with_rootfs(rootfs);
        let (path, argv) =
            resolve_entrypoint_program("/bin/true", &[], vec![b"/bin/true".to_vec()], &dispatcher)
                .expect("resolve");
        assert_eq!(path, "/bin/true");
        assert_eq!(argv, vec![b"/bin/true".to_vec()]);
    }

    #[test]
    fn vdso_debug_control_is_opt_out() {
        assert_eq!(vdso_debug_mode_from_env(None, None), VdsoDebugMode::Full);
        assert_eq!(
            vdso_debug_mode_from_env(Some("0"), None),
            VdsoDebugMode::Full
        );
        assert_eq!(
            vdso_debug_mode_from_env(Some("false"), None),
            VdsoDebugMode::Full
        );
        assert_eq!(
            vdso_debug_mode_from_env(None, Some("no-getrandom")),
            VdsoDebugMode::NoGetrandom
        );
        assert_eq!(
            vdso_debug_mode_from_env(None, Some("no-fastpaths")),
            VdsoDebugMode::NoFastpaths
        );
        assert_eq!(
            vdso_debug_mode_from_env(None, Some("clock-syscalls")),
            VdsoDebugMode::ClockSyscalls
        );
        assert_eq!(
            vdso_debug_mode_from_env(Some("1"), Some("no-getrandom")),
            VdsoDebugMode::Disabled
        );
        assert_eq!(
            vdso_debug_mode_from_env(Some("true"), None),
            VdsoDebugMode::Disabled
        );
        assert_eq!(
            vdso_debug_mode_from_env(Some("yes"), None),
            VdsoDebugMode::Disabled
        );
        assert_eq!(
            vdso_debug_mode_from_env(Some("on"), None),
            VdsoDebugMode::Disabled
        );
    }

    #[test]
    fn hardware_tso_debug_control_only_suppresses_requested_tso() {
        assert!(hardware_tso_for_debug_from_env(true, None));
        assert!(hardware_tso_for_debug_from_env(true, Some("0")));
        assert!(hardware_tso_for_debug_from_env(true, Some("false")));
        assert!(!hardware_tso_for_debug_from_env(true, Some("1")));
        assert!(!hardware_tso_for_debug_from_env(true, Some("true")));
        assert!(!hardware_tso_for_debug_from_env(true, Some("yes")));
        assert!(!hardware_tso_for_debug_from_env(true, Some("on")));
        assert!(!hardware_tso_for_debug_from_env(false, None));
        assert!(!hardware_tso_for_debug_from_env(false, Some("1")));
    }

    #[test]
    fn default_ignore_signals_are_not_terminating() {
        // SIGCHLD/SIGURG/SIGWINCH default to Ign — a no-handler instance is
        // dropped, not terminated. SIGURG=23 is the one that made `go build`
        // flaky (raise(SIGURG) is a host no-op → _exit(128+23)=151).
        assert!(is_default_ignore_signal(crate::linux_abi::LINUX_SIGURG));
        assert!(is_default_ignore_signal(crate::linux_abi::LINUX_SIGCHLD));
        assert!(is_default_ignore_signal(crate::linux_abi::LINUX_SIGWINCH));
        // Genuinely-terminating defaults must NOT be treated as ignore.
        assert!(!is_default_ignore_signal(crate::linux_abi::LINUX_SIGINT)); // 2
        assert!(!is_default_ignore_signal(crate::linux_abi::LINUX_SIGTERM)); // 15
        assert!(!is_default_ignore_signal(13)); // SIGPIPE: default IS terminate
        assert!(!is_default_ignore_signal(11)); // SIGSEGV
    }

    // Linux asm-generic/siginfo.h SIGTRAP si_codes.
    const SIGTRAP: i32 = 5;
    const TRAP_BRKPT: i32 = 1;
    const TRAP_TRACE: i32 = 2;
    const TRAP_HWBKPT: i32 = 4;

    fn esr(ec: u64) -> u64 {
        ec << 26
    }

    #[test]
    fn brk_aarch64_maps_to_sigtrap_brkpt() {
        // EC=0x3c is `BRK #imm` from AArch64 — the in-guest software breakpoint
        // Go's debug-call protocol hits. Linux delivers SIGTRAP/TRAP_BRKPT.
        assert_eq!(el0_debug_signal(esr(0x3c)), Some((SIGTRAP, TRAP_BRKPT)));
    }

    #[test]
    fn software_step_maps_to_sigtrap_trace() {
        // EC=0x32/0x33 software-step exception → SIGTRAP/TRAP_TRACE (PTRACE_SINGLESTEP).
        assert_eq!(el0_debug_signal(esr(0x32)), Some((SIGTRAP, TRAP_TRACE)));
        assert_eq!(el0_debug_signal(esr(0x33)), Some((SIGTRAP, TRAP_TRACE)));
    }

    #[test]
    fn hw_breakpoint_and_watchpoint_map_to_sigtrap_hwbkpt() {
        // EC=0x30/0x31 HW breakpoint, 0x34/0x35 watchpoint → SIGTRAP/TRAP_HWBKPT.
        assert_eq!(el0_debug_signal(esr(0x30)), Some((SIGTRAP, TRAP_HWBKPT)));
        assert_eq!(el0_debug_signal(esr(0x31)), Some((SIGTRAP, TRAP_HWBKPT)));
        assert_eq!(el0_debug_signal(esr(0x34)), Some((SIGTRAP, TRAP_HWBKPT)));
        assert_eq!(el0_debug_signal(esr(0x35)), Some((SIGTRAP, TRAP_HWBKPT)));
    }

    #[test]
    fn non_debug_faults_are_not_debug_signals() {
        // Aborts and unknown classes are NOT debug exceptions — they stay on the
        // SIGSEGV/SIGBUS path (`el0_fault_signal`), so the classifier returns None.
        assert_eq!(el0_debug_signal(esr(0x20)), None); // instruction abort
        assert_eq!(el0_debug_signal(esr(0x24)), None); // data abort
        assert_eq!(el0_debug_signal(esr(0x00)), None); // unknown
    }
}

#[cfg(test)]
mod rosetta_tests {
    use super::*;

    /// Minimal goblin-parseable ELF64 header with the given `e_machine`. No
    /// program headers needed — `inspect_elf_bytes` only reads the header.
    fn synthetic_elf(e_machine: u16) -> Vec<u8> {
        let mut elf = vec![0u8; 64];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // ELFCLASS64
        elf[5] = 1; // ELFDATA2LSB
        elf[6] = 1; // EV_CURRENT
        elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        elf[18..20].copy_from_slice(&e_machine.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes()); // version
        elf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        elf
    }

    const EM_AARCH64: u16 = 183;
    const EM_X86_64: u16 = 62;

    #[test]
    fn aarch64_binary_is_not_redirected() {
        let elf = synthetic_elf(EM_AARCH64);
        let argv = vec!["/bin/sh".to_string(), "-c".to_string()];
        assert!(maybe_redirect_to_rosetta("/bin/sh", &elf, &argv).is_none());
    }

    #[test]
    fn non_elf_is_not_redirected() {
        let not_elf = b"#!/bin/sh\necho hi\n";
        let argv = vec!["/script".to_string()];
        assert!(maybe_redirect_to_rosetta("/script", not_elf, &argv).is_none());
    }

    #[test]
    fn rosetta_argv_passes_program_argv0_through_not_the_interpreter() {
        // Pure argv construction — no Rosetta install needed, so the assertion
        // always runs. bash exec'ing a coreutils multi-call symlink resolves the
        // target to the real binary (/usr/bin/coreutils) but passes argv[0]="ls".
        // Apple's `rosetta` consumes argv[1] as the binary and presents the
        // program with argv = [argv[0], argv[2..]], so argv[0] MUST be "ls" — not
        // the interpreter — or the multi-call binary dispatches on "rosetta" and
        // errors ("coreutils: unknown program 'rosetta'"). Regression for that.
        let got = rosetta_argv("/usr/bin/coreutils", &[b"ls".to_vec(), b"-l".to_vec()]);
        assert_eq!(
            got,
            vec![
                b"ls".to_vec(),                 // program argv[0], passed through
                b"/usr/bin/coreutils".to_vec(), // the x86 binary for Rosetta (argv[1])
                b"-l".to_vec(),                 // program argv[1..]
            ]
        );
        assert_ne!(
            got[0],
            ROSETTA_INTERPRETER.as_bytes(),
            "argv[0] must be the program's argv0, never the interpreter path"
        );
    }

    #[test]
    fn x86_64_binary_redirects_to_rosetta_preserving_program_argv0() {
        let elf = synthetic_elf(EM_X86_64);
        let argv = vec!["uname".to_string(), "-m".to_string()];
        match maybe_redirect_to_rosetta("/usr/bin/uname", &elf, &argv) {
            // Rosetta installed: load is rewritten to Rosetta; argv[0] preserved.
            Some(Ok((rosetta_bytes, new_argv))) => {
                assert!(rosetta_bytes.starts_with(b"\x7fELF"));
                assert_eq!(
                    new_argv,
                    vec![
                        b"uname".to_vec(),          // program argv[0] (NOT the interpreter)
                        b"/usr/bin/uname".to_vec(), // x86 binary for Rosetta
                        b"-m".to_vec(),
                    ]
                );
            }
            // No Rosetta on this host: detected as x86_64 but unavailable.
            Some(Err(errno)) => assert_eq!(errno, crate::linux_abi::LINUX_ENOENT),
            None => panic!("x86_64 ELF must be detected for redirect"),
        }
    }

    #[test]
    fn rosetta_license_blob_is_sourced_from_binary_if_present() {
        // When Rosetta is installed, the licence blob is the NUL-terminated
        // verification string read live from its binary (never embedded here).
        if let Some(blob) = rosetta_license_blob() {
            assert!(blob.starts_with(b"Our hard work"));
            assert_eq!(blob.last(), Some(&0u8), "blob must end at the NUL");
        }
    }
}
