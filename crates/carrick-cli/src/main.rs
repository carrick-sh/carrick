//! Carrick command-line interface.
//!
//! This binary wires image pulling, rootfs setup, ELF execution, tracing,
//! compatibility reports, and APFS volume management onto the runtime crates.

mod args;
mod commands;
mod debug;
mod fs_setup;
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
