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
//! For a docker `run`, the CLI builds a [`carrick_engine::CliRunRequest`] and
//! hands it to `Engine::run`, which resolves+pulls the image, merges
//! entrypoint+cmd+env into a `RunSpec`, and calls `Runtime::execute` — the entry
//! to the actual HVF guest. The CLI never touches the manifest, the rootfs tar,
//! or the vCPU; it only chooses the output shape and the process exit code. The
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
//!   [`debug`]), `syscalls` / `trap-capabilities` / `compat-report`
//!   (introspection of the emulation tables), `inspect-elf` / `plan-elf-load` /
//!   `load-elf` / `run-elf` / `dispatch-syscall` (ELF + syscall fixtures), and
//!   `volume` (the APFS scratch subvolume — see [`args`]).
//!
//! ## The no-`#[tokio::main]` invariant
//!
//! The single most load-bearing decision in this crate is that `main` is a
//! plain synchronous function. A guest `clone(2)`/`fork(2)` is serviced by a
//! host `fork(2)` *inside a syscall handler*, deep under the trap loop. A
//! multi-thread tokio runtime initialised before that point would poison every
//! forked child: the worker threads don't exist post-fork, the I/O driver's
//! kqueue fd state is stale, and the child panics on the first stdio flush. So
//! all async work (image pulls, registry auth, summary reads) is confined to a
//! short-lived *current-thread* runtime built and dropped per call inside
//! [`runtime_util::block_on_oci`], guaranteeing no async machinery is alive in
//! the parent by the time a guest fork can fire. `configure_process_environment`
//! enforces the rest of the fork-safety contract (SIGPIPE→ignore so a guest
//! `ls | head` gets EPIPE instead of killing carrick; `OS_ACTIVITY_MODE=disable`
//! because HVF's internal os_log handle is not fork-safe; proctitle relocation
//! before any `setenv`).
//!
//! ## Process model: one guest == one host process
//!
//! Carrick has no in-process VM-per-guest. A guest *process* is a host carrick
//! process, and a guest `fork` is a real host `fork`. That is why this binary
//! installs a loud [`install_guest_abort_banner`] panic hook: an unimplemented
//! syscall in a forked grandchild (apt's http method, dpkg, gpgv) would
//! otherwise scroll past buried in the guest's own output, leaving the user
//! with only a downstream "dpkg returned 100". The banner makes the *root*
//! panic attributed and greppable.
//!
//! Module-level theory statements: [`commands`] (dispatch + the run pipeline +
//! the trace auto-sudo re-exec), [`lifecycle`] (daemonless container
//! management), [`fs_setup`] (`--fs host|memory` backend selection + guest
//! baseline seeding), [`trace_cli`] (privilege handoff for DTrace),
//! [`runtime_util`] (the fork-safe async bridge + docker-format helpers), and
//! [`debug`] (ESR / lldb tooling).

mod args;
mod commands;
mod debug;
mod fs_setup;
mod lifecycle;
mod runtime_util;
mod trace_cli;

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
fn main() -> anyhow::Result<()> {
    configure_process_environment();
    register_dtrace_probes();

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

    // Raise our own RLIMIT_NOFILE soft limit so we can back a guest that opens
    // many fds (e.g. libuv's watcher_cross_stop opens ~2500 UDP sockets, each a
    // host fd). macOS's default soft limit (often 256) would EMFILE the host
    // long before the guest's emulated limit. macOS rejects RLIM_INFINITY and
    // values above kern.maxfilesperproc (~122k), so aim for a generous fixed
    // ceiling well under that. Best-effort: leave the limit alone on failure.
    unsafe {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        const WANT: u64 = 65536;
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) == 0 && rl.rlim_cur < WANT {
            rl.rlim_cur = if rl.rlim_max != libc::RLIM_INFINITY && rl.rlim_max < WANT {
                rl.rlim_max
            } else {
                WANT
            };
            let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &rl);
        }
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
    }));
}
