//! execve image loading + forked-child exit paths, split out of runtime.rs
//! (WS-F3): load_execve_image (rootfs/overlay ELF + shebang + Rosetta
//! redirect), parse_shebang, and the no-unwind forked_child_exit /
//! forked_child_die_by_signal helpers. Free functions reached via `use super::*`.
use super::*;

pub(super) fn load_execve_image(
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

    // Absolutize a RELATIVE execve target against the guest cwd before any
    // layer lookup (Linux resolves `execve("b/foo")` against the caller's cwd;
    // carrick's layers key on absolute guest paths). See `resolve_exec_path`.
    // Resolve `#!` shebang scripts the way the Linux kernel does: read
    // the file, and if it begins with `#!`, re-target exec at the
    // interpreter with the script path spliced into argv. Bounded to 4
    // levels (Linux's BINPRM_MAX_RECURSION) to stop interpreter loops.
    let mut path = dispatcher.resolve_exec_path(path);
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
    let raw_bytes = dispatcher
        .read_exec_file(&path)
        .or_else(|| std::fs::read(&path).ok())
        .ok_or(LINUX_ENOENT)?;
    // Redirect x86_64 binaries through Rosetta 2 (binfmt_misc-style), so a guest
    // `execve` of a further x86_64 image (a child process, a shell spawning a
    // tool) is translated too — not just the initial container entrypoint.
    let (raw_bytes, argv) = match maybe_redirect_to_rosetta(&path, &raw_bytes, &argv) {
        None => (raw_bytes, argv),
        Some(Ok((rosetta_bytes, new_argv))) => (rosetta_bytes, new_argv),
        Some(Err(errno)) => return Err(errno),
    };
    let raw = AddressSpace::load_elf_bytes_with_reader(&raw_bytes, &|p| {
        dispatcher.read_exec_file(p).or_else(|| std::fs::read(p).ok())
    })
    .map_err(|_| LINUX_ENOENT)?;
    let image = raw
        .with_el0_trampoline()
        .and_then(|a| a.with_el1_vectors())
        .and_then(|a| a.with_stage1_page_tables())
        .and_then(|a| a.with_vdso())
        .and_then(|a| a.with_linux_initial_stack(argv, env))
        .map_err(|_| LINUX_ENOENT)?;
    // execve point of no return (image fully built): reset CAUGHT signal
    // handlers to SIG_DFL as the kernel does, so the new image never inherits
    // the old image's handler addresses (SIG_IGN/mask/pending are preserved).
    dispatcher.reset_signal_handlers_on_execve();
    Ok(image)
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
pub(super) fn forked_child_exit(code: i32, stdout_buf: impl AsRef<[u8]>, stderr_buf: impl AsRef<[u8]>) -> ! {
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
pub(super) fn forked_child_die_by_signal(
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
