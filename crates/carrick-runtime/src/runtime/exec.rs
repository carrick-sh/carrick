//! execve image loading + forked-child exit paths, split out of runtime.rs
//! (WS-F3): load_execve_image (rootfs/overlay ELF + shebang + Rosetta
//! redirect) and the no-unwind forked_child_exit / forked_child_die_by_signal
//! helpers. The shebang helpers (resolve_shebang, parse_shebang) and
//! forked-child exit functions now live in `crate::exec_helpers` (cross-
//! platform); they are re-exported here for existing call sites.
//! Free functions reached via `use super::*`.
use super::*;
use crate::linux_abi::LinuxErrno;

fn is_aarch64_elf_head(bytes: &[u8]) -> bool {
    const EI_DATA: usize = 5;
    const E_MACHINE: usize = 18;
    bytes.get(..4) == Some(b"\x7fELF")
        && bytes.get(EI_DATA) == Some(&1) // ELFDATA2LSB
        && bytes
            .get(E_MACHINE..E_MACHINE + 2)
            .is_some_and(|machine| u16::from_le_bytes([machine[0], machine[1]]) == 183)
}

fn finalize_hvf_exec_base(
    dispatcher: &SyscallDispatcher,
    raw: AddressSpace,
    needs_at_base: bool,
    vdso_enabled: bool,
) -> Result<AddressSpace, LinuxErrno> {
    use crate::linux_abi::{LINUX_ENOENT, LINUX_ENOEXEC};

    let mut staged = raw.with_vdso_auxv(vdso_enabled);
    if needs_at_base {
        staged = staged.with_auxv_base(ROSETTA_AT_BASE_PLACEHOLDER);
    }
    let staged = crate::hvpatch::prepare_exec_image_for_dispatcher(staged, dispatcher)
        .map_err(|_| LINUX_ENOEXEC)?;
    use carrick_hal::GuestArch as _;
    type HvfArch = <crate::trap::HvfTrapEngine as carrick_hal::ThreadedEngine>::Arch;
    staged
        .with_el0_trampoline_bytes(HvfArch::entry_trampoline_bytes())
        .and_then(with_hvf_syscall_mailbox)
        .and_then(|address_space| address_space.with_stage1_page_tables())
        .and_then(with_optional_vdso::<HvfArch>)
        .map_err(|_| LINUX_ENOENT)
}

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
    let vdso_enabled = vdso_enabled_for_debug();
    // The cache is deliberately limited to direct little-endian AArch64 ELFs.
    // Rosetta redirects rewrite argv and carry target-specific AT_BASE state;
    // mutable/foreign images stay on the uncached path below.
    let cache_key = dispatcher
        .read_exec_file_head(&path, 20)
        .filter(|head| is_aarch64_elf_head(head))
        .and_then(|_| dispatcher.hvpatch_exec_cache_key(&path, vdso_enabled, false));
    let (base, argv) = if cache_key.is_some() {
        let base = dispatcher.with_hvpatch_exec_cache(cache_key, || {
            let raw_bytes = dispatcher
                .read_exec_file(&path)
                .or_else(|| host_read(&path))
                .ok_or(LINUX_ENOENT)?;
            let raw = AddressSpace::load_elf_bytes_with_reader(&raw_bytes, &|interpreter| {
                dispatcher
                    .read_exec_file(interpreter)
                    .or_else(|| host_read(interpreter))
            })
            .map_err(|_| LINUX_ENOEXEC)?;
            finalize_hvf_exec_base(dispatcher, raw, false, vdso_enabled)
        })?;
        (base, argv)
    } else {
        let raw_bytes = dispatcher
            .read_exec_file(&path)
            .or_else(|| host_read(&path))
            .ok_or(LINUX_ENOENT)?;
        // Redirect x86_64 binaries through Rosetta 2 (binfmt_misc-style), so a
        // later guest exec remains translated rather than being parsed as arm64.
        let mut needs_at_base = false;
        let (raw_bytes, argv) = match maybe_redirect_to_rosetta(&path, &raw_bytes, &argv) {
            None => (raw_bytes, argv),
            Some(Ok(redirect)) => {
                needs_at_base = redirect.target_is_dynamic;
                dispatcher.enter_binfmt(&redirect.argv);
                (redirect.interpreter_bytes, redirect.argv)
            }
            Some(Err(errno)) => return Err(errno),
        };
        let raw = AddressSpace::load_elf_bytes_with_reader(&raw_bytes, &|interpreter| {
            dispatcher
                .read_exec_file(interpreter)
                .or_else(|| host_read(interpreter))
        })
        .map_err(|_| LINUX_ENOEXEC)?;
        (
            finalize_hvf_exec_base(dispatcher, raw, needs_at_base, vdso_enabled)?,
            argv,
        )
    };
    let linux_page_size = dispatcher.linux_page_size();
    let image = base
        .with_linux_initial_stack_execfn_page_size(argv, env, path.as_bytes(), linux_page_size)
        .map_err(|_| LINUX_ENOENT)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_classifier_accepts_only_little_endian_aarch64_elf() {
        let mut head = [0_u8; 20];
        head[..4].copy_from_slice(b"\x7fELF");
        head[5] = 1;
        head[18..20].copy_from_slice(&183_u16.to_le_bytes());
        assert!(is_aarch64_elf_head(&head));

        head[18..20].copy_from_slice(&62_u16.to_le_bytes());
        assert!(!is_aarch64_elf_head(&head));
        head[18..20].copy_from_slice(&183_u16.to_le_bytes());
        head[5] = 2;
        assert!(!is_aarch64_elf_head(&head));
        assert!(!is_aarch64_elf_head(&head[..10]));
    }

    #[test]
    fn prepared_exec_cache_is_shared_by_in_process_fork() {
        let parent = SyscallDispatcher::new();
        let expected = AddressSpace::from_regions(0x4000, Vec::new()).expect("image");
        let first = parent
            .with_hvpatch_exec_cache(Some("tool".to_owned()), || Ok::<_, ()>(expected.clone()))
            .expect("cache insert");
        let child = parent.fork_clone_in_process(
            crate::thread::ThreadId::synthetic_for_tests(7000),
            crate::thread::ThreadId::synthetic_for_tests(7001),
            7000,
            7001,
        );
        let reused = child
            .with_hvpatch_exec_cache(Some("tool".to_owned()), || -> Result<AddressSpace, ()> {
                panic!("fork child rebuilt a shared prepared exec image")
            })
            .expect("cache hit");

        assert_eq!(first, expected);
        assert_eq!(reused, expected);
    }
}
