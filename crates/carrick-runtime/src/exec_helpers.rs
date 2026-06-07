//! Cross-platform forked-child exit helpers and shebang resolution.
//!
//! Six helpers that were previously duplicated byte-for-byte between
//! `runtime/exec.rs` (macOS, `pub(crate)`) and `vcpu_loop`'s
//! `macos_helper_stubs` (Linux, `pub(super)`) now live here once.
//!
//! Every dependency is reached through `crate::...` paths that resolve
//! per-platform:
//!
//! - `crate::host_signal::linux_to_host_signum` — the Darwin signal-number
//!   mapping on macOS (via `carrick_hvf`), the identity function on Linux (the
//!   stub in `lib.rs`).
//! - `crate::guest_cpu::{record_child_exit, total_ns}` — always from
//!   `carrick_host` (an unconditional dependency on both platforms).
//! - `crate::linux_abi::LINUX_{ENOENT,SIGTRAP}` — always from `carrick_abi`.
//!
//! `load_execve_image` is intentionally NOT here: its body differs per
//! platform (Rosetta/EL-bring-up on macOS vs the KVM image builder on Linux).

use crate::dispatch::SyscallDispatcher;

/// Resolve `#!` shebang scripts the way the Linux kernel does: if `path` names
/// a file starting with `#!`, re-target at the interpreter with the script path
/// spliced into argv, repeating up to BINPRM_MAX_RECURSION (4) levels. A
/// non-script passes through unchanged. Shared by the guest `execve(2)` path
/// and the initial `carrick run` entrypoint load.
///
/// `argv` items are opaque bytes (Linux ABI); the interpreter / optional arg /
/// script path are UTF-8 (from the shebang line and the resolved path) and are
/// pushed as bytes. `#!/i x` on argv `[script, a, b]` becomes path `/i`, argv
/// `[/i, x, /script, a, b]`.
pub(crate) fn resolve_shebang(
    dispatcher: &SyscallDispatcher,
    mut path: String,
    mut argv: Vec<Vec<u8>>,
) -> Result<(String, Vec<Vec<u8>>), i32> {
    for _ in 0..4 {
        let Some(head) = dispatcher.read_exec_file(&path) else {
            break;
        };
        if !head.starts_with(b"#!") {
            break;
        }
        let Some((interp, optarg)) = parse_shebang(&head) else {
            return Err(crate::linux_abi::LINUX_ENOENT);
        };
        let mut new_argv: Vec<Vec<u8>> = Vec::with_capacity(argv.len() + 3);
        new_argv.push(interp.clone().into_bytes());
        if let Some(arg) = optarg {
            new_argv.push(arg.into_bytes());
        }
        new_argv.push(path.clone().into_bytes());
        new_argv.extend(argv.into_iter().skip(1));
        argv = new_argv;
        path = interp;
    }
    Ok((path, argv))
}

/// Parse a `#!` shebang line into (interpreter, optional single arg),
/// matching Linux semantics: skip blanks after `#!`, take the interpreter up
/// to the next whitespace, then the remainder of the line (trimmed) as ONE
/// argument. Only the first line is consulted. Linux caps the shebang line at
/// BINPRM_BUF_SIZE (256).
pub(crate) fn parse_shebang(head: &[u8]) -> Option<(String, Option<String>)> {
    let line_end = head.iter().position(|&b| b == b'\n').unwrap_or(head.len());
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

/// Called from a forked child when the guest hits `exit_group`. Flushes any
/// buffered guest stdout/stderr to the host's fd 1/fd 2 (inherited from the
/// parent process) and then calls `_exit(2)` to bypass Rust's normal Drop
/// chain. Without this, the rebuilt HVF/KVM context in the child would trigger
/// Drop panics during shutdown.
///
/// Also publishes guest CPU time so the parent's `wait4` can roll it into its
/// child-time totals (RUSAGE_CHILDREN).
pub(crate) fn forked_child_exit(
    code: i32,
    stdout_buf: impl AsRef<[u8]>,
    stderr_buf: impl AsRef<[u8]>,
) -> ! {
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
/// reports `WIFSIGNALED(signum)` instead of a normal exit. Falls back to
/// `_exit(128+signum)` if the signal doesn't terminate us.
///
/// `signum` is a Linux signal number; `linux_to_host_signum` maps it to the
/// host number (identity on Linux, Darwin mapping on macOS) so the host wait
/// status carries the right value.
pub(crate) fn forked_child_die_by_signal(
    signum: i32,
    stdout_buf: impl AsRef<[u8]>,
    stderr_buf: impl AsRef<[u8]>,
) -> ! {
    crate::guest_cpu::record_child_exit(std::process::id(), crate::guest_cpu::total_ns());
    let stdout_buf = stdout_buf.as_ref();
    let stderr_buf = stderr_buf.as_ref();
    let _ = unsafe { libc::write(1, stdout_buf.as_ptr() as *const _, stdout_buf.len()) };
    let _ = unsafe { libc::write(2, stderr_buf.as_ptr() as *const _, stderr_buf.len()) };
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

/// Stop THIS process by `signum` (job control / ptrace stop): reset the
/// disposition to default, unblock the signal, and `raise` it.
///
/// `signum` is a Linux signal number; translated to the host signal via
/// `linux_to_host_signum` (identity on Linux, Darwin mapping on macOS).
pub(crate) fn stop_by_signal(signum: i32) {
    let host_signum = crate::host_signal::linux_to_host_signum(signum);
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(host_signum, &action, std::ptr::null_mut());

        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, host_signum);
        libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        libc::raise(host_signum);
    }
}

/// After a `PTRACE_TRACEME`d exec, stop with SIGTRAP so a tracer sees the
/// exec stop.
pub(crate) fn stop_after_traced_exec(dispatcher: &SyscallDispatcher) {
    if dispatcher.is_ptrace_traceme() {
        stop_by_signal(crate::linux_abi::LINUX_SIGTRAP);
    }
}
