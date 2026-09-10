//! Carrick command-line interface — the `carrick` binary.
//!
//! # Theory of operation
//!
//! This crate is the *front-end*: a thin, presentation-only shell over the
//! four substantive crates. It owns no emulation logic and no kernel ABI. Its
//! whole job is to (1) parse a docker-shaped command line, (2) marshal it into
//! the request types the lower crates already understand, and (3) translate the
//! result back into the output a docker user expects (streamed stdio + the
//! container's exit code, or a JSON envelope on demand). Everything below the
//! request boundary — image pull, rootfs composition, ELF load, the HVF trap
//! loop, syscall translation — lives in `carrick-engine` / `carrick-image` /
//! `carrick-runtime`, and this crate deliberately does not reimplement any of
//! it.
//!
//! The crate dependency graph encodes that division of labour:
//!
//! ```text
//!   carrick-cli  ──▶  carrick-engine  ──▶  carrick-image   (pull / store / OCI)
//!        │                  │         ──▶  carrick-runtime (Runtime::execute → HVF)
//!        │                  └──────────────────────────────  resolve_run_spec
//!        ├──▶  carrick-runtime  (container registry, dtrace consumer, apfs, vfs…)
//!        └──▶  carrick-spec     (FsBackendKind, PidMode, Mount — shared request types)
//! ```
//!
//! For a docker `run`, the CLI builds a [`carrick_engine::RunRequest`] (inside
//! its own `lifecycle::LaunchRequest`, which adds the lifecycle-only flags) and
//! hands it to `Engine::resolve`, which resolves+pulls the image and merges
//! entrypoint+cmd+env into a `RunSpec`. The CLI *then* — after the async image
//! pull has been torn down, so no tokio runtime is live across the fork — calls
//! `Runtime::execute`, the entry to the actual HVF guest. The CLI never touches
//! the manifest, the rootfs tar, or the vCPU; it only chooses the output shape
//! and the process exit code. The
//! one place the CLI *does* reach below the engine is `run-elf` (and its
//! `dispatch-syscall` sibling), which loads a host ELF directly through
//! `carrick-runtime` for unit-test / conformance fixtures with no OCI image at
//! all (see [`commands`]).
//!
//! ## Surface map
//!
//! - **Container surface** (docker-compatible): `run`, `create`, `start`,
//!   `restart`, `stop`, `kill`, `rm`, `ps`, `inspect`, `logs`, `wait`, `exec`,
//!   `shell`. Plus the image/registry verbs `pull`, `images`, `rmi`, `prune`,
//!   `tag`, `login`, `logout`, `system`. These aim for byte-shaped parity with
//!   the docker CLI (column layouts, `--format` Go-templates, exit codes 125/
//!   126/127, `STOPSIGNAL` semantics) so existing tooling and the bollard-driven
//!   conformance harness drive carrick unchanged. The lifecycle commands are
//!   *daemonless*: see [`lifecycle`].
//! - **Diagnostic surface** (carrick-specific, no docker analogue): `trace`
//!   (in-process DTrace, auto-sudo — see [`trace_cli`] and [`commands`]),
//!   `debug` (ESR decode, lldb-plugin path, debug-state inspect — see
//!   the `debug` module), `syscalls` / `trap-capabilities`
//!   (introspection of the emulation tables), `inspect-elf` / `plan-elf-load` /
//!   `load-elf` / `run-elf` / `dispatch-syscall` (ELF + syscall fixtures), and
//!   `volume` (the APFS scratch subvolume — see [`args`]).
//!
//! ## The no-`#[tokio::main]` invariant
//!
//! `main` remains synchronous so lifecycle and signed-HVF setup do not inherit
//! an ambient application runtime. OCI work uses a short-lived current-thread
//! runtime inside [`runtime_util::block_on_oci`]; the optional Docker API server
//! deliberately owns its separate Tokio runtime. Guest `fork`/`clone` are
//! logical Carrick-kernel operations inside the existing carrier and never
//! inherit or recreate a host async runtime.
//!
//! ## Process model: one carrier hosts many containers
//!
//! HVPatch keeps every logical Linux process, thread, wait edge and signal in
//! the Carrick kernel graph inside one carrier, which owns ONE HVF VM and ONE
//! kernel arena for its whole life (`carrick_runtime::carrier`). Containers are
//! namespace trees on that graph: the CLI boots one per `carrick run`, and
//! `carrick debug container-gate` (Gate B) boots two — in sequence or at once
//! — in the same carrier, the shape the Phase C embed library generalises.
//! Guest `fork`/`clone` and Docker exec do not create host subprocesses.
//! Detached launch has one typed `posix_spawn` carrier-birth boundary; the
//! Docker API server remains an operator process and launches one carrier per
//! running container. Every exit goes through `carrier::exit_carrier`, which
//! retires the VM and publishes the lifecycle ledger.
//! The loud [`install_guest_abort_banner`] panic hook attributes failures in
//! that carrier without inventing a host-process identity for logical tasks.
//!
//! Module-level theory statements: [`commands`] (dispatch + the run pipeline +
//! the trace auto-sudo re-exec), [`lifecycle`] (daemonless container
//! management), [`fs_setup`] (`--fs host|memory` backend selection + guest
//! baseline seeding), [`trace_cli`] (privilege handoff for DTrace),
//! [`runtime_util`] (the fork-safe async bridge + docker-format helpers), and
//! the `debug` module (ESR / lldb tooling).

// ── Exactly-one-platform invariant (enforced, not assumed) ──────────────────
// `carrick-cli` links exactly one VMM + host backend via a single `platform-*`
// feature (see Cargo.toml). Selecting none — or more than one — otherwise fails
// late with opaque duplicate-symbol / missing-dependency errors; these guards
// turn that into a clear diagnostic at the front door. The matching
// `platform-* ⇔ target_os` invariant is asserted in `build.rs`.
#[cfg(not(any(
    feature = "platform-macos",
    feature = "platform-linux",
    feature = "platform-freebsd",
    feature = "platform-netbsd",
)))]
compile_error!(
    "no platform selected: enable exactly one of \
     platform-macos / platform-linux / platform-freebsd / platform-netbsd"
);
#[cfg(any(
    all(feature = "platform-macos", feature = "platform-linux"),
    all(feature = "platform-macos", feature = "platform-freebsd"),
    all(feature = "platform-macos", feature = "platform-netbsd"),
    all(feature = "platform-linux", feature = "platform-freebsd"),
    all(feature = "platform-linux", feature = "platform-netbsd"),
    all(feature = "platform-freebsd", feature = "platform-netbsd"),
))]
compile_error!(
    "multiple platforms selected: enable exactly one platform-* feature \
     (each pulls a mutually-exclusive host VMM backend)"
);
// The AMP1 reader only parses a text stream and hashes the bundled D program,
// so — like the census modules below — it is declared on every platform even
// though only a libdtrace host can produce the stream.
mod amplification_profile;
#[cfg(target_os = "macos")]
mod apfs_operator;
mod args;
mod commands;
// `debug` (guest address-space snapshot for the lldb plugin) reads the macOS-only
// `runtime::DebugStateSnapshot`; HVF-only.
#[cfg(feature = "platform-macos")]
mod debug;
mod debug_amplification;
mod debug_core;
mod debug_exec_stamps;
mod fs_setup;
mod hvpatch_core_profile;
// Strict text reader for the bundled one-VM HVPatch K1 lifecycle profile.
mod hvpatch_exec_runtime_profile;
mod hvpatch_identity_host_safety_profile;
mod hvpatch_k1_profile;
mod lifecycle;
// `perf_stats` + the bulk of `trace_profile` back the BSD libdtrace-based
// `carrick trace --profile` pipeline. Other hosts retain only the shared
// `TraceProfileKind` argument vocabulary.
#[cfg_attr(not(any(target_os = "macos", target_os = "freebsd")), allow(dead_code))]
mod perf_stats;
// The quiet-host preflight's RECEIPT is read back by the amplification reader
// on every platform; only the sampling half is Darwin-capture-only.
mod quiet_host;
mod runtime_util;
mod serve;
mod supervisor_perf;
mod trace_cli;
#[cfg_attr(not(any(target_os = "macos", target_os = "freebsd")), allow(dead_code))]
mod trace_profile;

use clap::Parser;

use crate::args::Cli;
use crate::commands::run_cli;
use crate::runtime_util::register_dtrace_probes;

/// We deliberately do NOT use `#[tokio::main]`: a multi-thread tokio
/// runtime initialised before the trap loop poisons every child of a
/// `fork(2)` we perform inside a syscall handler. The worker threads
/// don't exist in the child, the I/O driver's kqueue fd state is
/// out-of-sync, and panic-on-stdio-flush is the polite failure mode.
///
/// Async work (image pulls, summary reads) runs inside a short-lived
/// current-thread runtime that drops before the trap loop even begins,
/// so by the time fork can fire there is no tokio state to break.
/// Heap-allocation census (`--features alloc-census`). `dhat` attributes every
/// allocation to a call stack, which is the only way to answer "what allocates
/// the ~20.5 GB of large-zone heap per `go build`" on this lane: all three
/// EXTERNAL routes are measured dead (`ustack()` misresolves across ~70
/// self-re-exec'd processes with independent ASLR slides and emits
/// plausible-but-false symbols; `fbt::mach_vm_allocate` never fires;
/// `syscall::mmap` sees only MAP_NORESERVE reservations because libmalloc
/// sub-allocates a few large regions).
#[cfg(feature = "alloc-census")]
#[global_allocator]
static ALLOC_CENSUS: dhat::Alloc = dhat::Alloc;

/// One output file per carrier process. The profiler must outlive all guest
/// work, so `main` holds it to the end; the only host re-exec left is
/// `carrick trace`'s sudo re-exec (`trace_cli`), whose pre-exec image never
/// drops it and writes nothing, which is expected -- the POST-exec image does
/// the work and reports.
#[cfg(feature = "alloc-census")]
static ALLOC_CENSUS_PROFILER: std::sync::Mutex<Option<dhat::Profiler>> =
    std::sync::Mutex::new(None);

/// `dhat` writes its JSON from `Profiler`'s `Drop`, and carrick's run paths end
/// in `std::process::exit` (commands.rs:478/635/1035) to propagate the guest's
/// status. `process::exit` runs libc `atexit` handlers but NOT `Drop` for
/// `main`'s locals, so holding the profiler in a local writes NOTHING -- which
/// is exactly what the first attempt did. Park it in a static and drop it from
/// an `atexit` hook instead.
#[cfg(feature = "alloc-census")]
extern "C" fn write_alloc_census() {
    if let Ok(mut slot) = ALLOC_CENSUS_PROFILER.lock() {
        drop(slot.take());
    }
}

#[cfg(feature = "alloc-census")]
fn start_alloc_census() {
    let dir = std::env::var("CARRICK_ALLOC_CENSUS_DIR").unwrap_or_else(|_| "/tmp".to_owned());
    let pid = unsafe { libc::getpid() };
    let profiler = dhat::Profiler::builder()
        .file_name(std::path::PathBuf::from(dir).join(format!("dhat-{pid}.json")))
        .build();
    if let Ok(mut slot) = ALLOC_CENSUS_PROFILER.lock() {
        *slot = Some(profiler);
    }
    // Per-pid file names, so the ~70 processes of one build cannot clobber each
    // other and a forked child inheriting this handler is harmless.
    unsafe {
        libc::atexit(write_alloc_census);
    }
}

fn seed_vm_lifecycle_command_identity()
-> Result<(), carrick_runtime::vm_lifecycle::VmLifecycleArtifactError> {
    use std::os::unix::ffi::OsStrExt as _;

    let mut command = Vec::new();
    for argument in std::env::args_os() {
        command.extend_from_slice(argument.as_os_str().as_bytes());
        command.push(0);
    }
    carrick_runtime::vm_lifecycle::install_process_command_sha256(
        carrick_runtime::vm_lifecycle::sha256_bytes(&command),
    )
}

fn main() -> anyhow::Result<()> {
    // FIRST statement: the exec-stamp gauge measures kernel exec + dyld +
    // static initializers as `pre-exec -> main-entry`, so nothing may run
    // before it (env-gated; one getenv when off).
    carrick_runtime::exec_stamps::stamp(carrick_runtime::exec_stamps::ExecStampPhase::MainEntry);
    seed_vm_lifecycle_command_identity()?;
    #[cfg(feature = "alloc-census")]
    start_alloc_census();
    // FIRST, before any dispatch: record this process as the one true
    // top-level `carrick` invocation. The NATIVEPERF supervisor record
    // (supervisor_perf) is gated on this pid so an image that reaches
    // `Commands::Run`'s tail without passing through `main` fails quiet.
    supervisor_perf::record_top_level_pid();
    configure_process_environment();
    register_dtrace_probes();
    #[cfg(feature = "platform-macos")]
    carrick_runtime::probes::dsr_cache_lifecycle(
        unsafe { libc::getpid() },
        carrick_runtime::probes::DsrCacheLifecyclePhase::HostSelfReexecProbesReady,
        0,
        0,
        0,
    );
    carrick_runtime::exec_stamps::stamp(carrick_runtime::exec_stamps::ExecStampPhase::ProbesReady);

    run_cli(Cli::parse())
}

fn configure_process_environment() {
    // Ignore SIGPIPE in the host so a guest writing to a closed
    // pipe end (eg `ls | head` after head exits) gets EPIPE from
    // libc::write instead of having the host carrick process killed
    // by SIGPIPE. The dispatcher then translates EPIPE into the
    // guest's errno; the guest sees Linux's standard EPIPE behavior.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    // Relocate `environ` onto the heap so the contiguous argv/env stack
    // bytes become a wider writable buffer for `set_host_process_name`.
    // MUST run BEFORE any setenv: the first setenv on the pristine env
    // appends a heap-allocated entry to the environ array, which breaks
    // our contiguity walk (the new heap string doesn't abut the stack
    // run) and forces the legacy argv[0]-only fallback. libuv/Postgres
    // also relocate before any env mutation. Subsequent setenv may
    // realloc our heap environ — fine: the title buffer is the stack
    // range, not the env array, so it's unaffected.
    carrick_runtime::dispatch::proctitle_init();

    // Disable Apple's os_log activity tracing for this process tree.
    // Hypervisor.framework's `hv_vcpu_create` initializes an os_log
    // handle internally, and that handle is NOT fork-safe - a forked
    // child calling `hv_vcpu_create` crashes inside `_os_log_find`
    // with EXC_BAD_ACCESS ~14% of the time (verified via macOS
    // DiagnosticReports). Setting OS_ACTIVITY_MODE=disable before any
    // HVF call drops os_log out of the path entirely and makes
    // repeated fork() + hv_vcpu_create cycles deterministic.
    // INVARIANT: both are static string literals with no interior NUL byte, so
    // CString::new cannot fail.
    #[allow(clippy::unwrap_used)]
    unsafe {
        let key = std::ffi::CString::new("OS_ACTIVITY_MODE").unwrap();
        let val = std::ffi::CString::new("disable").unwrap();
        libc::setenv(key.as_ptr(), val.as_ptr(), 1);
    }

    install_guest_abort_banner();

    tracing_subscriber::fmt()
        // CLI diagnostics must never share stdout with guest output.  The
        // performance/conformance runners hash stdout byte-for-byte, and the
        // trace auto-sudo warning is Carrick metadata rather than guest data.
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();
}

fn install_guest_abort_banner() {
    // A guest process is one carrick (host) process; an unimplemented
    // syscall or invariant violation panics it. When that process is a
    // forked child (apt's http method, dpkg, gpgv...), the panic text
    // otherwise scrolls past buried in the guest program's own output and
    // the user only sees a downstream "dpkg returned 100". Print a loud,
    // attributed, greppable banner so the ROOT cause is unmissable.
    std::panic::set_hook(Box::new(|info| {
        let pid = unsafe { libc::getpid() };
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
            .unwrap_or("<non-string panic payload>");
        let loc = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "<unknown>".to_owned());
        eprintln!(
            "\n\x1b[1;31m======== CARRICK GUEST ABORT [pid {pid}] ========\x1b[0m\n\
             {msg}\n  at {loc}\n\
             \x1b[1;31m=================================================\x1b[0m\n"
        );
        // Honor RUST_BACKTRACE like the default hook would: a one-line banner
        // with no trace has cost real investigations a full reproduce-under-
        // debugger cycle (the bridge-probe shutdown join panic among them).
        if std::env::var_os("RUST_BACKTRACE").is_some_and(|v| v != "0") {
            eprintln!("{}", std::backtrace::Backtrace::force_capture());
        }
    }));
}
