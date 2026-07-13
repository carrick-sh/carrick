//! execve image loading + forked-child exit paths, split out of runtime.rs
//! (WS-F3): load_execve_image (rootfs/overlay ELF + shebang + Rosetta
//! redirect) and the no-unwind forked_child_exit / forked_child_die_by_signal
//! helpers. The shebang helpers (resolve_shebang, parse_shebang) and
//! forked-child exit functions now live in `crate::exec_helpers` (cross-
//! platform); they are re-exported here for existing call sites.
//! Free functions reached via `use super::*`.
use super::*;
use crate::linux_abi::LinuxErrno;

pub(crate) fn load_execve_image(
    dispatcher: &SyscallDispatcher,
    path: &str,
    // argv/env are opaque BYTE strings (Linux ABI), not UTF-8. `path` is a
    // String (resolved against the String/Path fs layer); argv[0] / shebang
    // interpreters are pushed as their UTF-8 bytes.
    argv: Vec<Vec<u8>>,
    env: Vec<Vec<u8>>,
) -> Result<AddressSpace, LinuxErrno> {
    use crate::linux_abi::{LINUX_ENOENT, LINUX_ENOEXEC};
    let argv = if argv.is_empty() {
        vec![path.as_bytes().to_vec()]
    } else {
        argv
    };

    // Absolutize a RELATIVE execve target against the guest cwd before any
    // layer lookup (Linux resolves `execve("b/foo")` against the caller's cwd;
    // carrick's layers key on absolute guest paths). See `resolve_exec_path`.
    // Validate the target the way the kernel does BEFORE reading the image:
    // resolution errnos (ENOENT/ENOTDIR/ELOOP/ENAMETOOLONG/EACCES) plus execute
    // permission on the final file. Done on the ABSOLUTIZED path before shebang
    // resolution so a non-executable `#!` script is EACCES, not a followed
    // interpreter (execve03/execve02). Then resolve any `#!` shebang script to
    // its interpreter (shared with the initial entrypoint load via
    // `resolve_shebang`).
    let abs_path = dispatcher.resolve_exec_path(path);
    dispatcher.check_exec_target(&abs_path)?;
    let (path, argv) = resolve_shebang(dispatcher, abs_path, argv)?;

    // Read the main binary AND resolve its interpreter OVERLAY-FIRST via
    // `read_exec_file`, so execve works for guest-created/overlay binaries
    // (downloaded/extracted ELF, /tmp/p, dpkg-unpacked binary) and needs no
    // in-memory rootfs layer (which `--fs host` drops after seeding). The
    // host-fs fallback (reading the literal absolute path straight off the
    // host) is ON only for a bare RunElf boot; a container run keeps it OFF so
    // an execve target absent from the container fs ENOENTs instead of escaping
    // to the matching HOST binary. See `SyscallDispatcher::exec_host_fs_fallback`.
    let host_fallback = dispatcher.exec_host_fs_fallback();
    let host_read = |p: &str| -> Option<Vec<u8>> {
        if host_fallback {
            std::fs::read(p).ok()
        } else {
            None
        }
    };
    let raw_bytes = dispatcher
        .read_exec_file(&path)
        .or_else(|| host_read(&path))
        .ok_or(LINUX_ENOENT)?;
    // Redirect x86_64 binaries through Rosetta 2 (binfmt_misc-style), so a guest
    // `execve` of a further x86_64 image (a child process, a shell spawning a
    // tool) is translated too — not just the initial container entrypoint.
    let mut needs_at_base = false;
    let (raw_bytes, argv) = match maybe_redirect_to_rosetta(&path, &raw_bytes, &argv) {
        None => (raw_bytes, argv),
        Some(Ok(redirect)) => {
            // Faithful binfmt: the execve target keeps its own identity; flag the
            // guest (uname → x86_64) and record the stack argv so
            // /proc/self/cmdline survives Rosetta's argv-skip.
            needs_at_base = redirect.target_is_dynamic;
            dispatcher.enter_binfmt(&redirect.argv);
            (redirect.interpreter_bytes, redirect.argv)
        }
        Some(Err(errno)) => return Err(errno),
    };
    // A file that resolved and is executable but isn't a valid ELF (and isn't a
    // `#!` script / Rosetta x86 target handled above) is ENOEXEC — "Exec format
    // error" — not ENOENT (execve03).
    let raw = AddressSpace::load_elf_bytes_with_reader(&raw_bytes, &|p| {
        dispatcher.read_exec_file(p).or_else(|| host_read(p))
    })
    .map_err(|_| LINUX_ENOEXEC)?;
    // Mirror the boot builder exactly: execve retains the macOS/HVF mailbox
    // transport and the feature-gated identity fast path selected for the
    // container. Native DSR and non-macOS VMMs use different lifecycle modules.
    let mut staged = raw.with_vdso_auxv(vdso_enabled_for_debug());
    if needs_at_base {
        staged = staged.with_auxv_base(ROSETTA_AT_BASE_PLACEHOLDER);
    }
    // Per-ISA trampoline/vDSO bytes come from the engine's GuestArch (the
    // x86_64 seam); this is the macOS/HVF execve staging path.
    use carrick_hal::GuestArch as _;
    type HvfArch = <crate::trap::HvfTrapEngine as carrick_hal::ThreadedEngine>::Arch;
    let linux_page_size = dispatcher.linux_page_size();
    let image = staged
        .with_el0_trampoline_bytes(HvfArch::entry_trampoline_bytes())
        .and_then(with_hvf_syscall_mailbox)
        .and_then(|a| a.with_stage1_page_tables())
        .and_then(with_optional_vdso::<HvfArch>)
        .and_then(|a| {
            a.with_linux_initial_stack_execfn_page_size(argv, env, path.as_bytes(), linux_page_size)
        })
        .map_err(|_| LINUX_ENOENT)?;
    // execve point of no return (image fully built): reset CAUGHT signal
    // handlers to SIG_DFL as the kernel does, so the new image never inherits
    // the old image's handler addresses (SIG_IGN/mask/pending are preserved).
    dispatcher.reset_memory_state_on_execve();
    dispatcher.reset_signal_handlers_on_execve();
    Ok(image)
}

// Shebang resolution and forked-child exit helpers are now in the
// cross-platform `exec_helpers` module. Re-export them here so the existing
// call sites in `runtime.rs` (`use exec::{…}`) and the vcpu_loop macOS import
// (`use crate::runtime::exec::{…}`) continue to resolve without change.
pub(super) use crate::exec_helpers::resolve_shebang;
pub(crate) use crate::exec_helpers::{
    forked_child_die_by_signal, forked_child_exit, stop_after_traced_exec, stop_by_signal,
};
