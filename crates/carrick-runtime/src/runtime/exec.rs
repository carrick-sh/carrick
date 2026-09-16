//! execve image loading, split out of runtime.rs (WS-F3): load_execve_image
//! (rootfs/overlay ELF + shebang + Rosetta redirect). The shebang helpers
//! (resolve_shebang, parse_shebang) and the signal-death / stop helpers live
//! in `crate::exec_helpers` (cross-platform); they are re-exported here for
//! existing call sites.
//! Free functions reached via `use super::*`.
use super::*;
use crate::exec_helpers::parse_shebang;
use crate::linux_abi::LinuxErrno;

pub(crate) struct LoadedExecImage {
    pub(crate) image: AddressSpace,
    pub(crate) source: crate::dispatch::executable_authority::ExecSource,
}

fn host_io_errno(error: std::io::Error) -> LinuxErrno {
    error
        .raw_os_error()
        .map(crate::host_to_linux_errno)
        .unwrap_or(crate::linux_abi::LINUX_EIO)
}

fn exec_source_errno(error: crate::dispatch::executable_authority::ExecSourceError) -> LinuxErrno {
    match error {
        crate::dispatch::executable_authority::ExecSourceError::Linux(errno) => errno,
        crate::dispatch::executable_authority::ExecSourceError::Host(error) => host_io_errno(error),
    }
}

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
    requires_syscall_traps: bool,
) -> Result<AddressSpace, LinuxErrno> {
    use crate::linux_abi::{LINUX_ENOENT, LINUX_ENOEXEC};

    let requires_syscall_traps = requires_syscall_traps || dispatcher.requires_syscall_traps();
    let mut staged = raw.with_vdso_auxv(vdso_enabled);
    if needs_at_base {
        staged = staged.with_auxv_base(ROSETTA_AT_BASE_PLACEHOLDER);
    }
    let staged = crate::hvpatch::prepare_exec_image_for_dispatcher(staged, dispatcher)
        .map_err(|_| LINUX_ENOEXEC)?;
    use carrick_hal::GuestArch as _;
    type HvfArch = <crate::trap::HvfTrapEngine as carrick_hal::ThreadedEngine>::Arch;
    let container = dispatcher.container();
    staged
        .with_el0_trampoline_bytes(HvfArch::entry_trampoline_bytes())
        .and_then(|image| with_hvf_syscall_mailbox(image, requires_syscall_traps))
        .and_then(|address_space| address_space.with_hvpatch_stage1_page_tables())
        .and_then(|image| {
            with_optional_vdso_for_clock_with_visibility::<HvfArch>(
                image,
                container.clock(),
                requires_syscall_traps,
            )
        })
        .map_err(|_| LINUX_ENOENT)
}

pub(crate) fn load_execve_image(
    dispatcher: &SyscallDispatcher,
    context: &crate::kernel::KernelContext,
    path: &str,
    // argv/env are opaque BYTE strings (Linux ABI), not UTF-8. `path` is a
    // String (resolved against the String/Path fs layer); argv[0] / shebang
    // interpreters are pushed as their UTF-8 bytes.
    argv: Vec<Vec<u8>>,
    env: Vec<Vec<u8>>,
    requires_syscall_traps: bool,
) -> Result<LoadedExecImage, LinuxErrno> {
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
    let host_fallback = dispatcher.exec_host_fs_fallback();
    let acquire_source = |path: &str| {
        dispatcher
            .acquire_exec_source(context, path)
            .or_else(|error| {
                if !host_fallback {
                    return Err(error);
                }
                let file = std::fs::File::open(path)
                    .map_err(crate::dispatch::executable_authority::ExecSourceError::Host)?;
                crate::dispatch::executable_authority::ExecSource::host(file, path.to_owned())
                    .map_err(crate::dispatch::executable_authority::ExecSourceError::Host)
            })
    };
    let named_source = acquire_source(&abs_path).map_err(exec_source_errno)?;
    dispatcher.check_exec_source(&abs_path, &named_source)?;
    // fanotify FAN_OPEN_EXEC, emitted after validation so a failed execve
    // generates nothing — the event means "this image is being executed", and
    // an ENOENT/EACCES target never is. Placed before shebang resolution so
    // `abs_path` is still the file the guest actually named.
    dispatcher.fanotify_notify_exec(&abs_path);
    let named_target = abs_path.clone();
    let mut path = abs_path;
    let mut argv = argv;
    let mut source = named_source;
    for _ in 0..4 {
        let head = source.read_head(256).map_err(host_io_errno)?;
        if !head.starts_with(b"#!") {
            break;
        }
        let Some((interpreter, optional_argument)) = parse_shebang(&head) else {
            return Err(crate::linux_abi::LINUX_ENOENT);
        };
        let mut next_argv = Vec::with_capacity(argv.len() + 3);
        next_argv.push(interpreter.clone().into_bytes());
        if let Some(argument) = optional_argument {
            next_argv.push(argument.into_bytes());
        }
        next_argv.push(path.into_bytes());
        next_argv.extend(argv.into_iter().skip(1));
        path = interpreter;
        argv = next_argv;
        source = acquire_source(&path).map_err(exec_source_errno)?;
        dispatcher.check_exec_source(&path, &source)?;
    }
    // Executing a `#!` script also opens its INTERPRETER for execution, and
    // Linux reports that as a second FAN_OPEN_EXEC. Skip it for a plain binary,
    // where `resolve_shebang` hands back the same path it was given.
    if path != named_target {
        dispatcher.fanotify_notify_exec(&path);
    }

    // Read the main binary AND resolve its interpreter OVERLAY-FIRST via
    // `read_exec_file`, so execve works for guest-created/overlay binaries
    // (downloaded/extracted ELF, /tmp/p, dpkg-unpacked binary) and needs no
    // in-memory rootfs layer (which `--fs host` drops after seeding). The
    // host-fs fallback (reading the literal absolute path straight off the
    // host) is ON only for a bare RunElf boot; a container run keeps it OFF so
    // an execve target absent from the container fs ENOENTs instead of escaping
    // to the matching HOST binary. See `SyscallDispatcher::exec_host_fs_fallback`.
    let host_read = |p: &str| -> Option<Vec<u8>> {
        if host_fallback {
            std::fs::read(p).ok()
        } else {
            None
        }
    };
    let vdso_enabled = vdso_enabled_for_debug();
    let requires_syscall_traps = requires_syscall_traps || dispatcher.requires_syscall_traps();
    // The cache is deliberately limited to direct little-endian AArch64 ELFs.
    // Rosetta redirects rewrite argv and carry target-specific AT_BASE state;
    // mutable/foreign images stay on the uncached path below.
    let cache_key = source
        .read_head(20)
        .ok()
        .filter(|head| is_aarch64_elf_head(head))
        .and_then(|_| {
            source.hvpatch_cache_key(
                dispatcher.linux_page_size(),
                vdso_enabled,
                requires_syscall_traps,
                false,
            )
        });
    let (base, argv) = if cache_key.is_some() {
        let base = dispatcher.with_hvpatch_exec_cache(cache_key, || {
            let raw_bytes = source.read_all().map_err(host_io_errno)?;
            let raw = AddressSpace::load_elf_bytes_with_reader(&raw_bytes, &|interpreter| {
                dispatcher
                    .read_exec_file(interpreter)
                    .or_else(|| host_read(interpreter))
            })
            .map_err(|_| LINUX_ENOEXEC)?
            .with_main_file_path(path.clone());
            finalize_hvf_exec_base(dispatcher, raw, false, vdso_enabled, requires_syscall_traps)
        })?;
        (base, argv)
    } else {
        let raw_bytes = source.read_all().map_err(host_io_errno)?;
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
        .map_err(|_| LINUX_ENOEXEC)?
        .with_main_file_path(path.clone());
        (
            finalize_hvf_exec_base(
                dispatcher,
                raw,
                needs_at_base,
                vdso_enabled,
                requires_syscall_traps,
            )?,
            argv,
        )
    };
    let linux_page_size = dispatcher.linux_page_size();
    let image = base
        .with_linux_initial_stack_execfn_page_size(argv, env, path.as_bytes(), linux_page_size)
        .map_err(|_| LINUX_ENOENT)?;
    Ok(LoadedExecImage { image, source })
}

// Shebang resolution and the signal-death / stop helpers live in the
// cross-platform `exec_helpers` module. Re-export them here so the call sites
// in `runtime.rs` (`use exec::{…}`) and the vcpu_loop macOS import
// (`use crate::runtime::exec::{…}`) resolve without change.
pub(crate) use crate::exec_helpers::{
    forked_child_die_by_signal, stop_after_traced_exec, stop_by_signal,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "syscall-shim")]
    struct ContinueInterceptor;

    #[cfg(feature = "syscall-shim")]
    impl crate::observe::SyscallInterceptor for ContinueInterceptor {
        fn intercept(
            &self,
            _process: &crate::observe::ProcessInfo<'_>,
            _call: &crate::observe::InterceptedSyscall<'_>,
        ) -> crate::observe::InterceptAction {
            crate::observe::InterceptAction::Continue
        }
    }

    #[cfg(feature = "syscall-shim")]
    fn synthetic_exec_image() -> AddressSpace {
        let permissions = carrick_mem::elf::SegmentPerms {
            read: true,
            write: false,
            execute: true,
        };
        AddressSpace::from_segments(
            0x0040_0000,
            [(
                0x0040_0000,
                permissions,
                0xd503_201f_u32.to_le_bytes().to_vec(),
                0x4000,
            )],
        )
        .expect("synthetic exec image")
    }

    #[cfg(feature = "syscall-shim")]
    fn image_region(image: &AddressSpace, start: u64) -> &[u8] {
        image
            .regions()
            .iter()
            .find(|region| region.start == start)
            .expect("required exec image region")
            .bytes()
    }

    #[cfg(feature = "syscall-shim")]
    #[test]
    fn interceptor_exec_image_preserves_closed_identity_page() {
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.install_interceptor(std::sync::Arc::new(ContinueInterceptor));

        let mut image =
            finalize_hvf_exec_base(&dispatcher, synthetic_exec_image(), false, true, false)
                .expect("interceptor-bearing exec image");
        let context = dispatcher
            .capture_one_task_context()
            .expect("exec task context");
        crate::kernel::identity_page::stamp_identity_page(&mut image, &dispatcher, &context)
            .expect("closed exec identity page remains stampable");

        let identity = image_region(&image, carrick_mem::memory::LINUX_IDENTITY_PAGE_BASE);
        let gate = usize::try_from(carrick_mem::memory::IDENTITY_OFF_SHIM_ENABLED)
            .expect("identity gate offset");
        assert_eq!(&identity[gate..gate + 4], &0_u32.to_le_bytes());
        let vdso = image_region(&image, carrick_mem::vdso::LINUX_VDSO_BASE);
        let no_fastpaths = carrick_mem::vdso::vdso_image_bytes_without_fastpaths();
        assert_eq!(&vdso[..no_fastpaths.len()], no_fastpaths.as_slice());
    }

    #[cfg(feature = "syscall-shim")]
    #[test]
    fn unrestricted_exec_image_preserves_fastpaths() {
        use carrick_hal::GuestArch as _;

        type HvfArch = <crate::trap::HvfTrapEngine as carrick_hal::ThreadedEngine>::Arch;
        let image = finalize_hvf_exec_base(
            &SyscallDispatcher::new(),
            synthetic_exec_image(),
            false,
            true,
            false,
        )
        .expect("unrestricted exec image");

        image_region(&image, carrick_mem::memory::LINUX_IDENTITY_PAGE_BASE);
        let vdso = image_region(&image, carrick_mem::vdso::LINUX_VDSO_BASE);
        assert_eq!(&vdso[..HvfArch::vdso_bytes().len()], HvfArch::vdso_bytes());
    }

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

    #[test]
    fn production_hvpatch_exec_builder_emits_only_asid_scoped_leaves() {
        const NON_GLOBAL: u64 = 1 << 11;
        let permissions = carrick_mem::elf::SegmentPerms {
            read: true,
            write: false,
            execute: true,
        };
        let raw = AddressSpace::from_segments(
            0x0040_0000,
            [(
                0x0040_0000,
                permissions,
                0xd503_201f_u32.to_le_bytes().to_vec(),
                0x4000,
            )],
        )
        .expect("synthetic exec image");
        let image = finalize_hvf_exec_base(&SyscallDispatcher::new(), raw, false, false, false)
            .expect("production HVPatch exec builder");
        let tables = image
            .regions()
            .iter()
            .find(|region| region.start == carrick_mem::memory::LINUX_PAGE_TABLES_BASE)
            .expect("exec stage-1 table region");
        for va in [
            0x0040_0000,
            carrick_mem::memory::LINUX_MMAP_BASE,
            carrick_mem::memory::LINUX_SHARED_FILE_BASE,
            carrick_mem::memory::LINUX_STACK_TOP - 0x4000,
            carrick_mem::memory::LINUX_EL1_MAINT_BASE,
            carrick_mem::memory::LINUX_IDENTITY_PAGE_BASE,
            carrick_mem::memory::LINUX_SYSCALL_MAILBOX_BASE,
            carrick_mem::memory::LINUX_ROSETTA_VA_BASE,
        ] {
            let leaf = carrick_mem::page_table::terminal_descriptor(
                carrick_mem::page_table::walk_descriptors(
                    tables.bytes(),
                    carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
                    va,
                ),
            );
            assert_ne!(
                leaf & NON_GLOBAL,
                0,
                "production exec leaf at {va:#x} escaped its ASID"
            );
        }
    }
}
