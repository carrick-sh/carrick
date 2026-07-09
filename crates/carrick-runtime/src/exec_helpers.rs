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
//!   mapping on macOS (via `carrick_vmm_hvf`), the identity function on Linux (the
//!   stub in `lib.rs`).
//! - `crate::guest_cpu::{record_child_exit, total_ns}` — always from
//!   `carrick_host` (an unconditional dependency on both platforms).
//! - `crate::linux_abi::LINUX_{ENOENT,SIGTRAP}` — always from `carrick_abi`.
//!
//! `load_execve_image` is intentionally NOT here: its body differs per
//! platform (Rosetta/EL-bring-up on macOS vs the KVM image builder on Linux).

use crate::dispatch::SyscallDispatcher;
use crate::linux_abi::LinuxErrno;

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
) -> Result<(String, Vec<Vec<u8>>), LinuxErrno> {
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

/// PATH-resolve a BARE initial-entrypoint command (`carrick run alpine ls`) the
/// way Docker/`execvp` does — searching `$PATH` (or a sane default) for the first
/// readable match in the dispatcher's rootfs. A name with `/` is left as-is. This
/// applies ONLY to the initial entrypoint; the guest's own `execve(2)` keeps
/// full-path semantics. Shared by the macOS (HVF) and KVM run paths.
//
// The OCI/entrypoint run path is live on macOS (HVF) and aarch64-KVM (`run_oci`)
// but not yet wired on x86_64-KVM, where `run_oci` is a stub until OCI-x86 lands
// — so this is legitimately unused ONLY on the x86_64 platform-linux build.
#[cfg_attr(
    all(feature = "platform-linux", target_arch = "x86_64"),
    allow(dead_code)
)]
pub(crate) fn resolve_entrypoint_path(
    path: &str,
    env: &[String],
    dispatcher: &SyscallDispatcher,
) -> String {
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
/// command, then resolve any `#!` shebang to its interpreter, so a script
/// entrypoint runs like Docker/`execve(2)`. Returns the final (program path,
/// argv as opaque Linux-ABI bytes). Shared by both backends.
#[cfg_attr(
    all(feature = "platform-linux", target_arch = "x86_64"),
    allow(dead_code)
)]
pub(crate) fn resolve_entrypoint_program(
    path: &str,
    env: &[String],
    argv: Vec<Vec<u8>>,
    dispatcher: &SyscallDispatcher,
) -> Result<(String, Vec<Vec<u8>>), LinuxErrno> {
    let resolved = resolve_entrypoint_path(path, env, dispatcher);
    resolve_shebang(dispatcher, resolved, argv)
}

/// Build the initial guest `AddressSpace` from already-read entrypoint `bytes`:
/// load the ELF (PT_INTERP / dynamic loader read through the dispatcher's rootfs
/// reader), attach the vDSO auxv, optionally force `AT_BASE` (the Rosetta
/// dynamic-target case — `None` on the native path), and serialise the initial
/// Linux stack. The platform-NEUTRAL heart of `carrick run`: the ONLY divergence
/// is the run-loop entry that consumes the returned image (HVF `finish_and_run_
/// image` vs KVM `KvmTrapEngine::new` + `run_threaded_kvm_loop`).
#[cfg_attr(
    any(
        feature = "platform-linux",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ),
    allow(dead_code)
)]
pub(crate) fn build_run_image(
    bytes: &[u8],
    argv: Vec<Vec<u8>>,
    env: &[String],
    dispatcher: &SyscallDispatcher,
    vdso_enabled: bool,
    at_base: Option<u64>,
) -> Result<crate::memory::AddressSpace, crate::memory::AddressSpaceError> {
    use goblin::elf::header::EM_AARCH64;
    build_run_image_for(
        bytes,
        argv,
        env,
        dispatcher,
        RunImageBuildOptions {
            vdso_enabled,
            at_base,
            linux_page_size: crate::page_profile::DEFAULT_LINUX_PAGE_SIZE,
            machine: EM_AARCH64,
        },
    )
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RunImageBuildOptions {
    pub(crate) vdso_enabled: bool,
    pub(crate) at_base: Option<u64>,
    pub(crate) linux_page_size: u64,
    pub(crate) machine: u16,
}

#[cfg_attr(
    any(feature = "platform-freebsd", feature = "platform-netbsd"),
    allow(dead_code)
)]
pub(crate) fn build_run_image_for(
    bytes: &[u8],
    argv: Vec<Vec<u8>>,
    env: &[String],
    dispatcher: &SyscallDispatcher,
    options: RunImageBuildOptions,
) -> Result<crate::memory::AddressSpace, crate::memory::AddressSpaceError> {
    let mut image = crate::memory::AddressSpace::load_elf_bytes_with_reader_for(
        bytes,
        &|p| dispatcher.read_exec_file(p),
        options.machine,
    )?
    .with_vdso_auxv(options.vdso_enabled);
    if let Some(base) = options.at_base {
        image = image.with_auxv_base(base);
    }
    image.with_linux_initial_stack_page_size(
        argv,
        env.iter().map(|s| s.as_bytes()),
        options.linux_page_size,
    )
}

#[cfg(any(
    feature = "platform-linux",
    feature = "platform-freebsd",
    feature = "platform-netbsd"
))]
pub(crate) fn build_run_image_for_execfn(
    bytes: &[u8],
    argv: Vec<Vec<u8>>,
    env: &[String],
    execfn: &[u8],
    dispatcher: &SyscallDispatcher,
    options: RunImageBuildOptions,
) -> Result<crate::memory::AddressSpace, crate::memory::AddressSpaceError> {
    let mut image = crate::memory::AddressSpace::load_elf_bytes_with_reader_for(
        bytes,
        &|p| dispatcher.read_exec_file(p),
        options.machine,
    )?
    .with_vdso_auxv(options.vdso_enabled);
    if let Some(base) = options.at_base {
        image = image.with_auxv_base(base);
    }
    image.with_linux_initial_stack_execfn_page_size(
        argv,
        env.iter().map(|s| s.as_bytes()),
        execfn,
        options.linux_page_size,
    )
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
    let pid = std::process::id();
    crate::guest_cpu::adopt_children_of(pid);
    let adopted_parent = crate::guest_cpu::adopted_parent_for(pid);
    crate::guest_cpu::record_child_exit_status(
        pid,
        crate::guest_cpu::total_ns(),
        (code & 0xff) << 8,
        adopted_parent.is_some(),
    );
    if let Some(parent) = adopted_parent {
        let _ = crate::host_signal::xsig_enqueue(
            parent as i32,
            crate::linux_abi::LINUX_SIGCHLD,
            0,
            pid as i32,
            0,
            0,
            0,
        );
        crate::host_signal::xsig_nudge(parent as i32);
    }
    let stdout_buf = stdout_buf.as_ref();
    let stderr_buf = stderr_buf.as_ref();
    let _ = unsafe { libc::write(1, stdout_buf.as_ptr() as *const _, stdout_buf.len()) };
    let _ = unsafe { libc::write(2, stderr_buf.as_ptr() as *const _, stderr_buf.len()) };
    unsafe { libc::_exit(code) };
}

/// Host-fs marker path for a forked-child signal death the BSD host kernel could
/// not represent as WIFSIGNALED. Keyed by the globally-unique host pid (so it
/// never collides across concurrent guests or carrick instances).
#[cfg(not(target_os = "linux"))]
fn sigdeath_marker_path(host_pid: u32) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(".carrick-sigdeath-{host_pid}"))
}

/// Parent side: consume the signal-death marker a just-reaped forked child left,
/// returning the Linux signal it died by. `Some` only for a BSD-host child whose
/// default-TERMINATE Linux signal could not be represented faithfully as a host
/// signalled death, so it `_exit(128+N)`ed and left a marker. Always `None` on a
/// Linux host (host signal numbers and dispositions match Linux, so the marker is
/// never written).
#[cfg(not(target_os = "linux"))]
pub(crate) fn consume_sigdeath_marker(host_pid: u32) -> Option<i32> {
    let path = sigdeath_marker_path(host_pid);
    let sig = *std::fs::read(&path).ok()?.first()? as i32;
    let _ = std::fs::remove_file(&path);
    Some(sig)
}

#[cfg(target_os = "linux")]
pub(crate) fn consume_sigdeath_marker(_host_pid: u32) -> Option<i32> {
    None
}

/// Test-only: plant a signal-death marker exactly as `forked_child_die_by_signal`
/// would (`[signum as u8]` at the host-pid-keyed path), so `consume_sigdeath_marker`
/// / `translate_child_wait_status` can be unit-tested without forking a real child.
#[cfg(all(test, not(target_os = "linux")))]
pub(crate) fn plant_sigdeath_marker_for_test(host_pid: u32, signum: i32) {
    let _ = std::fs::write(sigdeath_marker_path(host_pid), [signum as u8]);
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
    let pid = std::process::id();
    crate::guest_cpu::adopt_children_of(pid);
    let adopted_parent = crate::guest_cpu::adopted_parent_for(pid);
    crate::guest_cpu::record_child_exit_status(
        pid,
        crate::guest_cpu::total_ns(),
        signum & 0x7f,
        adopted_parent.is_some(),
    );
    if let Some(parent) = adopted_parent {
        let _ = crate::host_signal::xsig_enqueue(
            parent as i32,
            crate::linux_abi::LINUX_SIGCHLD,
            0,
            pid as i32,
            0,
            0,
            0,
        );
        crate::host_signal::xsig_nudge(parent as i32);
    }
    let stdout_buf = stdout_buf.as_ref();
    let stderr_buf = stderr_buf.as_ref();
    let _ = unsafe { libc::write(1, stdout_buf.as_ptr() as *const _, stdout_buf.len()) };
    let _ = unsafe { libc::write(2, stderr_buf.as_ptr() as *const _, stderr_buf.len()) };
    stop_for_debug_signal(signum);
    let host_signum = crate::host_signal::linux_to_host_signum(signum);
    #[cfg(not(target_os = "linux"))]
    if host_signum == 0 {
        let _ = std::fs::write(sigdeath_marker_path(std::process::id()), [signum as u8]);
        unsafe { libc::_exit(128 + signum) };
    }
    unsafe {
        libc::signal(host_signum, libc::SIG_DFL);
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, host_signum);
        libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        libc::raise(host_signum);
        // Only reached if the host signal did NOT terminate us. On the BSDs the
        // host signal mapped from some default-TERMINATE Linux signals is itself
        // default-IGNORE or otherwise not Linux-faithful, so `raise` may be a
        // silent no-op or report the wrong host signal. The child cannot make its
        // OWN host wait status WIFSIGNALED, so leave a marker keyed by host pid:
        // the parent's wait4 reap reconstructs WIFSIGNALED(signum) from it instead
        // of reporting `exited 128+signum`.
        #[cfg(not(target_os = "linux"))]
        let _ = std::fs::write(sigdeath_marker_path(std::process::id()), [signum as u8]);
        libc::_exit(128 + signum)
    }
}

pub(crate) fn stop_for_debug_signal(signum: i32) {
    let Ok(raw) = std::env::var("CARRICK_DEBUG_STOP_ON_SIGNAL") else {
        return;
    };
    if !debug_stop_matches_signal(&raw, signum) {
        return;
    }
    unsafe {
        libc::raise(libc::SIGSTOP);
    }
}

fn debug_stop_matches_signal(raw: &str, signum: i32) -> bool {
    raw.split(',')
        .filter_map(|value| value.trim().parse::<i32>().ok())
        .any(|wanted| wanted == signum)
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

#[cfg(test)]
mod tests {
    use super::*;

    const EM_X86_64: u16 = 62;

    #[test]
    fn debug_stop_signal_selector_accepts_comma_list() {
        assert!(debug_stop_matches_signal("5", 5));
        assert!(debug_stop_matches_signal(" 4, 5, 11 ", 5));
        assert!(!debug_stop_matches_signal("4,11", 5));
        assert!(!debug_stop_matches_signal("not-a-signal", 5));
    }

    fn synthetic_elf(machine: u16) -> Vec<u8> {
        const ET_EXEC: u16 = 2;
        const PT_LOAD: u32 = 1;
        let mut elf = vec![0u8; 0x1000];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        elf[18..20].copy_from_slice(&machine.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[24..32].copy_from_slice(&0x400000u64.to_le_bytes());
        elf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1u16.to_le_bytes());
        let ph = 64;
        elf[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        elf[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
        elf[ph + 8..ph + 16].copy_from_slice(&0u64.to_le_bytes());
        elf[ph + 16..ph + 24].copy_from_slice(&0x400000u64.to_le_bytes());
        elf[ph + 24..ph + 32].copy_from_slice(&0x400000u64.to_le_bytes());
        let len = elf.len() as u64;
        elf[ph + 32..ph + 40].copy_from_slice(&len.to_le_bytes());
        elf[ph + 40..ph + 48].copy_from_slice(&len.to_le_bytes());
        elf[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        elf
    }

    #[test]
    fn build_run_image_for_accepts_x86_64_machine() {
        let dispatcher = SyscallDispatcher::new();
        let image = build_run_image_for(
            &synthetic_elf(EM_X86_64),
            vec![b"/bin/true".to_vec()],
            &[],
            &dispatcher,
            RunImageBuildOptions {
                vdso_enabled: false,
                at_base: None,
                linux_page_size: crate::page_profile::DEFAULT_LINUX_PAGE_SIZE,
                machine: EM_X86_64,
            },
        )
        .expect("x86_64 ELF accepted when requested");

        assert_eq!(image.entry(), 0x400000);
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod sigdeath_marker_tests {
    use super::*;

    #[test]
    fn marker_round_trips_then_clears() {
        // A synthetic, host-pid-keyed marker path that no live process owns.
        let host_pid = 0x7FFD_1234u32;
        // Make the slot pristine in case a prior aborted run left a marker.
        let _ = std::fs::remove_file(sigdeath_marker_path(host_pid));

        // No marker yet → None.
        assert_eq!(consume_sigdeath_marker(host_pid), None);

        // Plant SIGPOLL (29) and consume it once.
        plant_sigdeath_marker_for_test(host_pid, 29);
        assert_eq!(consume_sigdeath_marker(host_pid), Some(29));

        // Consuming is one-shot: the marker file is removed on read.
        assert_eq!(consume_sigdeath_marker(host_pid), None);
    }
}
