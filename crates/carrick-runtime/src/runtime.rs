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
//! [`CompatReport`](crate::compat::CompatReport)).
//!
//! # The fork/clone model (the hard part)
//!
//! macOS HVF is **not fork-safe**: a live VM in the parent at `libc::fork(2)`
//! makes the child's `hv_vm_create` return `HV_BUSY`. carrick has three distinct
//! fork shapes, and each works around this differently:
//!
//! - **`clone(2)` that creates a thread** (`CLONE_VM`): no `libc::fork` at all.
//!   [`ThreadRuntimeState::spawn_clone_thread`](crate::vcpu_loop::ThreadRuntimeState)
//!   spawns a host thread that builds
//!   its own vCPU in the *same* VM and runs [`run_vcpu_until_exit`]. HVF caps
//!   concurrent vCPUs (64 on this host); a guest with more live threads than the
//!   cap blocks in `wait_for_vcpu_slot` until one frees, since `clone(2)` already
//!   reported success and the guest may `join` the thread.
//! - **`fork(2)` from a single-threaded guest**: a plain `libc::fork`. The
//!   engine snapshots and rebuilds the address space; the child resets its
//!   per-process state (event ring, self-pipe, kqueue — none survive fork) and
//!   continues.
//! - **`fork(2)` from a multithreaded guest**
//!   ([`ThreadRuntimeState::handle_fork`](crate::vcpu_loop::ThreadRuntimeState)):
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
//! [`ThreadRuntimeState::pt_pause`](crate::vcpu_loop::ThreadRuntimeState) kicks
//! in-guest siblings out so none walks a
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
//! not fatal to carrick: [`crate::vcpu_loop`]'s `deliver_fault_signal` maps the
//! `ESR_EL1`
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
use std::time::Instant;

use crate::compat::CompatReporter;
use crate::dispatch::{
    DispatchOutcome, GuestMemory, MemoryError, SyscallDispatcher, SyscallRequest,
};
use crate::memory::{AddressSpace, AddressSpaceError};
use crate::rootfs::RootFs;

// The EL0 synchronous-fault translation + the threaded vCPU loop were hoisted
// into the unconditional `crate::vcpu_loop` module (generic over
// `carrick_hal::ThreadedEngine`). The single-threaded loop below still uses the
// forked-child / execve helpers in `exec`, so that submodule stays here; it is
// `pub(crate)` so `vcpu_loop` can reach the same helpers.
pub(crate) mod exec;
use crate::vcpu_loop::{
    apply_image_proc_state, deliver_pending_signal, dispatch_with_panic_backstop,
    partial_write_interrupt_outcome, raise_sigpipe_for_blocking_write, signal_wait_expired,
    signal_wait_slice, stamp_identity_page,
};
use exec::{
    forked_child_die_by_signal, forked_child_exit, load_execve_image, stop_after_traced_exec,
    stop_by_signal,
};

use crate::trap::{HvfTrapEngine, TrapError};
// `SyscallTrap`/`TrapError`/`ForkOutcome` live in the carrick-hal leaf crate
// and are re-exported through `carrick_hvf::trap` (re-exported here as
// `crate::trap`). Re-export `SyscallTrap` from this module too so the original
// `carrick_runtime::runtime::SyscallTrap` path (used by the runtime_loop tests
// and the engine crate) is unchanged.
pub use crate::trap::SyscallTrap;
use serde::Serialize;

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

pub(crate) fn hardware_tso_for_debug(requested: bool) -> bool {
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

// `RunResult` / `RuntimeError` are now defined cross-platform in
// `crate::run_result` (unified with the Linux KVM loop). Re-export them under
// the original `carrick_runtime::runtime::{RunResult, RuntimeError}` paths so
// every call site (carrick-engine, carrick-cli, the runtime tests) is unchanged.
pub use crate::run_result::{RunResult, RuntimeError};

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
    let mut needs_at_base = false;
    let (file, argv): (Vec<u8>, Vec<Vec<u8>>) =
        match maybe_redirect_to_rosetta(&path_str, &file, &argv) {
            None => (file, argv.into_iter().map(String::into_bytes).collect()),
            Some(Ok(redirect)) => {
                // Faithful binfmt: keep the target's identity (/proc/self/exe
                // stays the program); flag binfmt-interpreted (uname → x86_64) and
                // record the stack argv so /proc/self/cmdline survives Rosetta's
                // argv-skip. (redirect.argv is consumed for the stack below.)
                needs_at_base = redirect.target_is_dynamic;
                dispatcher.enter_binfmt(&redirect.argv);
                (redirect.interpreter_bytes, redirect.argv)
            }
            Some(Err(errno)) => return Err(rosetta_unavailable(errno, &path_str)),
        };
    let mut image = AddressSpace::load_elf_bytes_with_reader(&file, &|p| {
        rootfs.read(p).ok().or_else(|| std::fs::read(p).ok())
    })?
    .with_vdso_auxv(vdso_enabled_for_debug());
    if needs_at_base {
        image = image.with_auxv_base(ROSETTA_AT_BASE_PLACEHOLDER);
    }
    let image = image.with_linux_initial_stack(argv, env)?;
    finish_and_run_image(image, dispatcher, max_traps, debug_state_path)
}

// `resolve_entrypoint_path` / `resolve_entrypoint_program` (Docker `execvp` PATH
// search + `#!` shebang resolution) were hoisted into the cross-platform
// `crate::exec_helpers`, shared by the macOS HVF and Linux KVM `carrick run`
// paths — only the run-loop entry that consumes the assembled image differs.

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
    // PATH-resolve a bare command AND resolve `#!` shebang scripts to their
    // interpreter (Docker / execve(2) semantics) before loading, so a script
    // entrypoint runs instead of failing "not an ELF binary".
    let argv_for_cmdline = argv.clone();
    let argv_bytes: Vec<Vec<u8>> = argv.into_iter().map(String::into_bytes).collect();
    let (resolved, argv) =
        crate::exec_helpers::resolve_entrypoint_program(path, &env, argv_bytes, &dispatcher)
            .map_err(|_| {
                RuntimeError::AddressSpace(AddressSpaceError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    path.to_owned(),
                )))
            })?;
    // /proc/self/cmdline reflects the user's argv, but /proc/self/exe MUST be the
    // RESOLVED absolute binary path — real Linux always stores the resolved path.
    // A bare `uname` would otherwise absolutize to `/uname` (cwd-relative) and
    // break anything that opens /proc/self/exe: Apple Rosetta opens it to find its
    // x86 target ("rosetta error: Unable to open /proc/self/exe"), and uutils-
    // coreutils (Ubuntu 26.04) derives its locale dir from it. Identity is set
    // AFTER resolution so the recorded exe is the real binary, not the bare name.
    dispatcher.set_executable_identity(
        resolved.clone(),
        argv_for_cmdline,
        env.iter().map(|s| s.as_bytes().to_vec()).collect(),
    );
    let path: &str = &resolved;
    let bytes = dispatcher.read_exec_file(path).ok_or_else(|| {
        RuntimeError::AddressSpace(AddressSpaceError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            path.to_owned(),
        )))
    })?;
    // Redirect x86_64 binaries through Rosetta 2 (binfmt_misc-style). argv is
    // already opaque bytes (Linux ABI).
    let mut needs_at_base = false;
    let (bytes, argv): (Vec<u8>, Vec<Vec<u8>>) =
        match maybe_redirect_to_rosetta(path, &bytes, &argv) {
            None => (bytes, argv),
            Some(Ok(redirect)) => {
                // Faithful binfmt: /proc/self/exe stays the target (the redirect
                // is transparent on real Linux; Rosetta finds itself without it).
                // Flag the guest (uname → x86_64) and record the stack argv so
                // /proc/self/cmdline survives Rosetta's argv-skip.
                needs_at_base = redirect.target_is_dynamic;
                dispatcher.enter_binfmt(&redirect.argv);
                (redirect.interpreter_bytes, redirect.argv)
            }
            Some(Err(errno)) => return Err(rosetta_unavailable(errno, path)),
        };
    // The platform-neutral image assembly (load + auxv + initial stack) is shared
    // with the KVM run path via `exec_helpers::build_run_image`; only the run-loop
    // entry below (HVF `finish_and_run_image`) is macOS-specific.
    let image = crate::exec_helpers::build_run_image(
        &bytes,
        argv,
        &env,
        &dispatcher,
        vdso_enabled_for_debug(),
        needs_at_base.then_some(ROSETTA_AT_BASE_PLACEHOLDER),
    )?;
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

// `apply_image_proc_state`, `stamp_identity_page`, and
// `proc_maps_from_address_space` were hoisted into `crate::vcpu_loop` (shared
// with the threaded loop); imported above and called unchanged here.

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
        #[cfg(feature = "trace-traps")]
        {
            let name = crate::syscall::lookup_aarch64(frame.number)
                .map(|s| s.name)
                .unwrap_or("<unknown>");
            let a = frame.args;
            eprintln!(
                "trap#{traps}: nr={} ({name}) a0={:#x} a1={:#x} a2={:#x} a3={:#x} a4={:#x} a5={:#x}",
                frame.number, a[0], a[1], a[2], a[3], a[4], a[5]
            );
        }
        let outcome = dispatch_single_threaded_syscall(
            &mut dispatcher,
            SyscallRequest::from_raw(frame),
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
            DispatchOutcome::SharedFutexWake { host_addr, count } => {
                // Cross-process MAP_SHARED futex wake from a single-threaded
                // guest (LTP tst_checkpoint_wake). Same __ulock one-at-a-time +
                // sched_yield as the threaded loop's PlatformFutex::shared_wake.
                let retval = shared_futex_wake(host_addr, count);
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

        #[cfg(feature = "trace-traps")]
        if let Some(ret) = last_syscall_retval {
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

// `dispatch_with_panic_backstop`, `raise_sigpipe_for_blocking_write`, and
// `partial_write_interrupt_outcome` were hoisted into `crate::vcpu_loop` (shared
// with the threaded loop); imported above and called unchanged here.

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

// ===================================================================
// Multi-threaded HVF runtime: one host thread + one HVF vCPU per guest
// thread, sharing ONE process VM. The loop ITSELF was hoisted into the
// unconditional `crate::vcpu_loop` (generic over `carrick_hal::ThreadedEngine`);
// `KernelState`/`Kernel`/`VcpuLoopOutcome`/`ThreadRuntimeState`/
// `run_vcpu_until_exit`/`service_signals_threaded`/`deliver_pending_signal`/
// `shared_futex_wait` (now `PlatformFutex::shared_wait`) all live there. Only the
// HVF SETUP WRAPPER (`run_threaded_hvf_loop`) stays here, building the concrete
// HVF kicker / futex table / `ForkCoordinator` and threading them in.
// ===================================================================

use crate::thread::{FutexTable, ThreadId, ThreadRegistry};
use crate::vcpu_loop::{KernelState, PlatformFutexFactory, VcpuLoopOutcome, run_vcpu_until_exit};
use parking_lot::Mutex;
use std::sync::Arc;

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
    // The CONCRETE process-private futex table threaded UNCHANGED into the
    // dispatch + complete_futex_wait path (the generation-snapshot lost-wake
    // protocol stays byte-identical). The object-safe `PlatformFutex` wraps the
    // SAME table for the SHARED-futex / notify-signal-pending ops, so the two
    // stay consistent. The factory rebuilds that pairing over a fresh table on
    // the CHILD side of a guest fork (`vcpu_loop::handle_fork`), without the
    // generic loop ever naming `HvfFutex`.
    let futex = Arc::new(FutexTable::new());
    let platform_futex: Arc<dyn carrick_hal::PlatformFutex> =
        Arc::new(crate::threaded_impl::HvfFutex(Arc::clone(&futex)));
    let platform_futex_factory: PlatformFutexFactory = Arc::new(
        |table: Arc<FutexTable>| -> Arc<dyn carrick_hal::PlatformFutex> {
            Arc::new(crate::threaded_impl::HvfFutex(table))
        },
    );
    // The HVF host-fork coordinator, boxed object-safe so the cross-platform
    // `KernelState` never names the concrete `ForkCoordinator`.
    let fork_coordinator: Box<dyn carrick_hal::HostForkCoordinator> =
        Box::new(crate::fork_coord::ForkCoordinator::new());
    // Registry of live vCPUs so a signalling thread (tgkill) or the
    // process-directed signal pump can force a target out of `hv_vcpu_run`.
    // Held object-safe as the `VcpuRegistry` the generic loop drives. Built
    // before the kernel so `HvfSignalArrival` can wake a target vCPU via it.
    let kicker: Arc<dyn carrick_hal::VcpuRegistry> = Arc::new(crate::vcpu_kick::VcpuKicker::new());
    // The HVF signal ARRIVAL/wake mechanism (kqueue pump self-pipe, per-thread
    // waiter wakes, xsig MAP_SHARED ring, child-exit watches). Delegates to the
    // existing `crate::host_signal` glue; held object-safe in `KernelState`.
    let signal_arrival: Arc<dyn carrick_hal::SignalArrival> =
        Arc::new(crate::signal_arrival::HvfSignalArrival);
    // Install the backend `TimerDelivery` the dispatch arm reaches through the
    // process-global (`dispatch/time.rs` has no KernelState ref). HVF arms an
    // EVFILT_TIMER on the pump kqueue and returns true (it owns delivery); only
    // a pump-less fork child falls back to the shared wall-clock thread.
    crate::timer_delivery::register_delivery(Arc::new(
        crate::timer_delivery_impl::HvfTimerDelivery,
    ));
    let kernel = Arc::new(KernelState::new(
        dispatcher,
        fork_coordinator,
        signal_arrival,
    ));
    // Track spawned sibling threads so the process doesn't tear down while a
    // worker is mid-flight. We join them after the main thread finishes.
    let threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
    // Daemon that kicks in-guest vCPUs when process-directed async signals are
    // observable. Non-interactive command runners start pump-free and request it
    // lazily when a guest installs a real signal handler or forks a child whose
    // exit signal is caught/blocked; interactive terminals keep prompt Ctrl-C
    // delivery for busy guests that have not made another syscall.
    if crate::host_tty::host_isatty(0) || crate::host_tty::host_isatty(1) {
        kernel.fork.start_signal_pump(&kicker, &platform_futex);
    }

    let outcome = run_vcpu_until_exit(
        Arc::clone(&kernel),
        trap,
        Arc::clone(&registry),
        Arc::clone(&futex),
        Arc::clone(&platform_futex),
        Arc::clone(&platform_futex_factory),
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

// `run_vcpu_until_exit`, `assemble_run_result`, `PendingSignalAction`,
// `deliver_pending_signal`, `is_restartable_syscall`, the default-signal
// classifiers, and `service_signals_threaded` were hoisted into
// `crate::vcpu_loop` (generic over the engine). The THREADED loop's shared-futex
// wait now goes through `PlatformFutex::shared_wait`; the macOS-only
// SINGLE-threaded loop below keeps its own free-fn `shared_futex_wait` (it has no
// `PlatformFutex` handle and is HVF-local).

/// Block on a cross-process (`MAP_SHARED`) futex via the host `__ulock`,
/// interruptibly. Returns 0 when woken (or the futex word already changed),
/// `-EINTR` when a signal deliverable to THIS thread is pending, `-ETIMEDOUT` at
/// the guest's deadline. errnos are translated host→Linux. Used by the
/// single-threaded macOS run loop; the threaded loop uses
/// `PlatformFutex::shared_wait` (which shares this logic in `HvfFutex`).
fn shared_futex_wait(
    host_addr: usize,
    value: u32,
    timeout: Option<std::time::Duration>,
    this_tid: ThreadId,
) -> i64 {
    let deadline = timeout.map(|d| std::time::Instant::now() + d);
    let host_value = unsafe { (host_addr as *const u32).read() };
    crate::probes::futex_route(host_addr as u64, 99, value as i32, host_value as u64);
    loop {
        if crate::host_signal::has_pending_for(this_tid)
            || crate::fork_quiesce::is_quiescing()
            || crate::fork_quiesce::exec_replacing_other_thread(this_tid)
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
            None => 20_000,
        };
        crate::probes::ulock_wait(host_addr as u64, value, slice_us, 0, 0);
        let r = crate::ulock::wait(host_addr, value, slice_us);
        crate::probes::ulock_wait(host_addr as u64, value, slice_us, 1, r);
        if r >= 0 {
            return 0;
        }
        let host_errno = (-r) as i32;
        if host_errno == libc::ETIMEDOUT || host_errno == libc::EINTR {
            continue;
        }
        return -i64::from(host_errno);
    }
}

/// Wake up to `count` waiters on a cross-process (`MAP_SHARED`) futex from a
/// SINGLE-THREADED guest (an LTP test binary that forks + `tst_checkpoint_wake`s
/// a child). The macOS `__ulock` analog of the threaded loop's
/// `PlatformFutex::shared_wake`: wake ONE waiter per `__ulock_wake` call with a
/// `sched_yield` between iterations (the cure for macOS `wake_by_address_any`
/// reporting spurious back-to-back successes on a SHARED address). Returns the
/// count actually woken. Byte-identical to the dispatcher's prior inline loop and
/// to `HvfFutex::shared_wake`, so the `SharedFutexWake` outcome change preserves
/// the single-threaded HVF behavior exactly.
fn shared_futex_wake(host_addr: usize, count: u32) -> i64 {
    let mut woke = 0i64;
    for i in 0..count {
        let rc = crate::ulock::wake(host_addr, false);
        crate::probes::ulock_wake(host_addr as u64, i as i32, rc);
        if rc < 0 {
            break;
        }
        woke += 1;
        unsafe { libc::sched_yield() };
    }
    woke
}

/// Absolute host path to Apple's Rosetta 2 Linux ELF interpreter. This is an
/// AArch64 binary that JIT-translates an x86_64 Linux guest in user space.
pub(crate) const ROSETTA_INTERPRETER: &str = "/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta";

/// Placeholder `AT_BASE` value for a Rosetta-redirected *dynamic* x86_64 target.
/// carrick loads the static `rosetta` interpreter as the image, so the auxv it
/// builds has no AT_BASE. A *dynamic* x86 target needs one present so Apple's
/// Rosetta emits AT_BASE in the inner x86 auxv — filled with the real
/// ld-musl/ld-linux base Rosetta maps (carrick can't know that address; Rosetta
/// chooses it and overwrites this value). It only needs to be a present,
/// non-zero, page-aligned slot. Without it, musl's dynamic linker null-derefs at
/// startup (glibc's self-locates, so glibc-dynamic tolerated the gap).
pub(crate) const ROSETTA_AT_BASE_PLACEHOLDER: u64 = 0x10_0000_0000;

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
/// Outcome of redirecting an x86_64 target through Apple's Rosetta interpreter.
pub(crate) struct RosettaRedirect {
    /// Bytes of the `rosetta` interpreter to load as the guest image.
    pub interpreter_bytes: Vec<u8>,
    /// argv to hand the interpreter: `[program argv0, target, args…]`.
    pub argv: Vec<Vec<u8>>,
    /// Whether the x86_64 target is dynamically linked (has a `PT_INTERP`). A
    /// dynamic target needs an `AT_BASE` auxv entry in the auxv carrick hands
    /// Rosetta, so Rosetta emits AT_BASE — filled with the real ld-musl/ld-linux
    /// base it maps — in the inner x86 auxv. Without it musl's dynamic linker
    /// null-derefs (glibc's self-locates, so it tolerated the gap). A static
    /// target must NOT get AT_BASE, matching Linux. See `with_auxv_base`.
    pub target_is_dynamic: bool,
}

pub(crate) fn maybe_redirect_to_rosetta<A: AsRef<[u8]>>(
    target_path: &str,
    target_bytes: &[u8],
    // argv items are opaque bytes (Linux ABI); accept String (initial entry)
    // or Vec<u8> (execve) and always return the byte form.
    argv: &[A],
) -> Option<Result<RosettaRedirect, i32>> {
    use crate::linux_abi::LINUX_ENOENT;

    // Consult the binfmt_misc registry (magic/mask). A native (aarch64) or
    // non-ELF binary matches nothing and runs directly.
    let _registration = crate::binfmt::match_registration(target_bytes)?;

    crate::probes::execve_argv("rosetta-redirect", &[target_path.as_bytes().to_vec()]);

    let rosetta_bytes = match rosetta_binary_bytes() {
        Some(b) => b.to_vec(),
        None => return Some(Err(LINUX_ENOENT)),
    };

    // A PT_INTERP means the x86 target is dynamically linked and needs an AT_BASE
    // slot in the auxv carrick hands Rosetta (see ROSETTA_AT_BASE_PLACEHOLDER).
    let target_is_dynamic = crate::elf::inspect_elf_bytes(target_bytes)
        .ok()
        .is_some_and(|m| m.interpreter.is_some());

    let orig_argv: Vec<Vec<u8>> = argv.iter().map(|a| a.as_ref().to_vec()).collect();
    Some(Ok(RosettaRedirect {
        interpreter_bytes: rosetta_bytes,
        // The registration is `P` (preserve argv[0]); `rosetta_argv` builds the
        // form Apple's rosetta requires (argv[0] passed through, target at argv[1]).
        argv: rosetta_argv(target_path, &orig_argv),
        target_is_dynamic,
    }))
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
    fn next_syscall(&mut self) -> Result<Option<carrick_hal::RawSyscall>, TrapError> {
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
        assert_eq!(
            crate::exec_helpers::resolve_entrypoint_path("ls", &env, &dispatcher),
            "/bin/ls"
        );
        assert_eq!(
            crate::exec_helpers::resolve_entrypoint_path("env", &env, &dispatcher),
            "/usr/bin/env"
        );
        // A path containing '/' is returned unchanged (execve, not execvp).
        assert_eq!(
            crate::exec_helpers::resolve_entrypoint_path("/sbin/foo", &env, &dispatcher),
            "/sbin/foo"
        );
        assert_eq!(
            crate::exec_helpers::resolve_entrypoint_path("./x", &env, &dispatcher),
            "./x"
        );
        // Not found anywhere on PATH → keep the bare name (so the load error names it).
        assert_eq!(
            crate::exec_helpers::resolve_entrypoint_path("nope", &env, &dispatcher),
            "nope"
        );
        // No PATH in env → fall back to the standard default set (covers /usr/bin).
        assert_eq!(
            crate::exec_helpers::resolve_entrypoint_path("env", &[], &dispatcher),
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

        let (path, argv) = crate::exec_helpers::resolve_entrypoint_program(
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
        let (path, argv) = crate::exec_helpers::resolve_entrypoint_program(
            "/bin/true",
            &[],
            vec![b"/bin/true".to_vec()],
            &dispatcher,
        )
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

    /// Synthetic *dynamic* x86_64 ELF: a 64-byte header plus one `PT_INTERP`
    /// program header pointing at an interpreter string, so `inspect_elf_bytes`
    /// reports `interpreter.is_some()` (the signal a target needs `AT_BASE`).
    fn synthetic_dynamic_x86_elf() -> Vec<u8> {
        const PT_INTERP: u32 = 3;
        let interp = b"/lib/ld-musl-x86_64.so.1\0";
        let ph_off = 64u64; // program headers immediately follow the ELF header
        let interp_off = 64 + 56; // one 56-byte phdr, then the interp string
        let mut elf = vec![0u8; interp_off + interp.len()];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // ELFCLASS64
        elf[5] = 1; // ELFDATA2LSB
        elf[6] = 1; // EV_CURRENT
        elf[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN (PIE)
        elf[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        elf[20..24].copy_from_slice(&1u32.to_le_bytes()); // version
        elf[32..40].copy_from_slice(&ph_off.to_le_bytes()); // e_phoff
        elf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        elf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        elf[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        let ph = ph_off as usize;
        elf[ph..ph + 4].copy_from_slice(&PT_INTERP.to_le_bytes()); // p_type
        elf[ph + 8..ph + 16].copy_from_slice(&(interp_off as u64).to_le_bytes()); // p_offset
        elf[ph + 32..ph + 40].copy_from_slice(&(interp.len() as u64).to_le_bytes()); // p_filesz
        elf[interp_off..].copy_from_slice(interp);
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
            Some(Ok(redirect)) => {
                assert!(redirect.interpreter_bytes.starts_with(b"\x7fELF"));
                assert_eq!(
                    redirect.argv,
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
    fn dynamic_x86_64_target_is_flagged_so_rosetta_gets_at_base() {
        // A dynamic x86_64 target (has PT_INTERP) must be reported as dynamic so
        // the loader adds AT_BASE to the auxv it hands Rosetta. Without AT_BASE,
        // Rosetta omits it from the inner x86 auxv and musl's dynamic linker
        // null-derefs at startup (alpine `/bin/uname` exited 139 / SIGSEGV).
        // glibc's ld self-locates, which is why glibc-dynamic targets worked.
        let dynamic = synthetic_dynamic_x86_elf();
        let argv = vec!["uname".to_string()];
        match maybe_redirect_to_rosetta("/bin/uname", &dynamic, &argv) {
            Some(Ok(redirect)) => assert!(
                redirect.target_is_dynamic,
                "a PT_INTERP x86_64 target must be flagged dynamic so AT_BASE is added"
            ),
            // No Rosetta installed: detection still ran (it precedes the rosetta
            // read), but the redirect short-circuits to ENOENT before the flag.
            Some(Err(errno)) => assert_eq!(errno, crate::linux_abi::LINUX_ENOENT),
            None => panic!("x86_64 ELF must be detected for redirect"),
        }
    }

    #[test]
    fn static_x86_64_target_is_not_flagged_dynamic() {
        // A static x86_64 target (no PT_INTERP) must NOT be flagged: Linux omits
        // AT_BASE for static binaries, and a bogus AT_BASE with no interpreter to
        // overwrite it would mislead the translated program.
        let static_elf = synthetic_elf(EM_X86_64);
        let argv = vec!["prog".to_string()];
        match maybe_redirect_to_rosetta("/bin/prog", &static_elf, &argv) {
            Some(Ok(redirect)) => assert!(
                !redirect.target_is_dynamic,
                "a static x86_64 target must NOT be flagged dynamic"
            ),
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
