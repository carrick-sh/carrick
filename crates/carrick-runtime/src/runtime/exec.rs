//! execve image loading, split out of runtime.rs (WS-F3): load_execve_image
//! (rootfs/overlay ELF + shebang + Rosetta redirect). The shebang helpers
//! (resolve_shebang, parse_shebang) and the signal-death / stop helpers live
//! in `carrick_kernel::exec_helpers` (cross-platform); they are re-exported here for
//! existing call sites.
//! Free functions reached via `use super::*`.
use super::*;
use crate::linux_abi::LinuxErrno;
use carrick_kernel::exec_helpers::parse_shebang;

pub(crate) struct LoadedExecImage {
    pub(crate) image: AddressSpace,
    pub(crate) source: carrick_kernel::dispatch::executable_authority::ExecSource,
    pub(crate) binfmt_argv: Option<Vec<Vec<u8>>>,
}

/// Loader configuration retains physical services, never a task or dispatcher.
pub(crate) struct ExecLoaderCapabilities {
    clock: Arc<carrick_kernel::kernel::container::ClockDomain>,
    linux_page_size: u64,
    requires_syscall_traps: bool,
}

impl Clone for ExecLoaderCapabilities {
    fn clone(&self) -> Self {
        Self {
            clock: Arc::clone(&self.clock),
            linux_page_size: self.linux_page_size,
            requires_syscall_traps: self.requires_syscall_traps,
        }
    }
}

impl ExecLoaderCapabilities {
    pub(crate) fn capture(dispatcher: &SyscallDispatcher) -> Self {
        Self {
            clock: Arc::clone(dispatcher.container().clock()),
            linux_page_size: dispatcher.linux_page_size(),
            requires_syscall_traps: dispatcher.requires_syscall_traps(),
        }
    }
}

/// Carrier-retained physical capabilities for a ring-owned exec. The opaque id
/// is inherited by native fork; resolving it never consults a host task table.
pub(crate) struct NativeExecCapability {
    _id: carrick_core_abi::service::ExecCapabilityId,
    _files: carrick_kernel::dispatch::exec_files::ExecFiles,
    _loader: ExecLoaderCapabilities,
}

pub(crate) fn capture_native_exec_capability(
    dispatcher: &SyscallDispatcher,
) -> Result<NativeExecCapability, LinuxErrno> {
    let context = dispatcher
        .capture_one_task_context()
        .map_err(|_| crate::linux_abi::LINUX_ESRCH)?;
    let raw = context.resources().files().id().raw();
    let id = carrick_core_abi::service::ExecCapabilityId::new(
        core::num::NonZeroU64::new(raw).ok_or(crate::linux_abi::LINUX_ESRCH)?,
    );
    Ok(NativeExecCapability {
        _id: id,
        _files: dispatcher.capture_exec_files(&context)?,
        _loader: ExecLoaderCapabilities::capture(dispatcher),
    })
}

fn host_io_errno(error: std::io::Error) -> LinuxErrno {
    error
        .raw_os_error()
        .map(carrick_kernel::host_to_linux_errno)
        .unwrap_or(crate::linux_abi::LINUX_EIO)
}

fn exec_source_errno(
    error: carrick_kernel::dispatch::executable_authority::ExecSourceError,
) -> LinuxErrno {
    match error {
        carrick_kernel::dispatch::executable_authority::ExecSourceError::Linux(errno) => errno,
        carrick_kernel::dispatch::executable_authority::ExecSourceError::Host(error) => {
            host_io_errno(error)
        }
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

/// Inspect the exact source selected for this exec. The shebang decision and
/// direct-ELF cache classification must use the same bounded file snapshot.
fn inspect_exec_head(
    read_head: impl FnOnce(usize) -> std::io::Result<Vec<u8>>,
) -> std::io::Result<(Vec<u8>, bool)> {
    let head = read_head(256)?;
    let direct_aarch64 = is_aarch64_elf_head(&head);
    Ok((head, direct_aarch64))
}

fn finalize_hvf_exec_base(
    loader: &ExecLoaderCapabilities,
    raw: AddressSpace,
    needs_at_base: bool,
    vdso_enabled: bool,
    requires_syscall_traps: bool,
) -> Result<AddressSpace, LinuxErrno> {
    use crate::linux_abi::{LINUX_ENOENT, LINUX_ENOEXEC};

    let requires_syscall_traps = requires_syscall_traps || loader.requires_syscall_traps;
    let mut staged = raw.with_vdso_auxv(vdso_enabled);
    if needs_at_base {
        staged = staged.with_auxv_base(ROSETTA_AT_BASE_PLACEHOLDER);
    }
    let staged = crate::hvpatch::prepare_exec_image(staged).map_err(|_| LINUX_ENOEXEC)?;
    use carrick_hal::GuestArch as _;
    type HvfArch = <crate::trap::HvfTrapEngine as carrick_hal::ThreadedEngine>::Arch;
    staged
        .with_el0_trampoline_bytes(HvfArch::entry_trampoline_bytes())
        .and_then(|image| with_hvf_syscall_mailbox(image, requires_syscall_traps))
        .and_then(|address_space| address_space.with_hvpatch_stage1_page_tables())
        .and_then(|image| {
            with_optional_vdso_for_clock_with_visibility::<HvfArch>(
                image,
                &loader.clock,
                requires_syscall_traps,
            )
        })
        .map_err(|_| LINUX_ENOENT)
}

pub(crate) fn load_execve_image(
    loader: &ExecLoaderCapabilities,
    files: &carrick_kernel::dispatch::exec_files::ExecFiles,
    path: &str,
    // argv/env are opaque BYTE strings (Linux ABI), not UTF-8. `path` is a
    // String (resolved against the String/Path fs layer); argv[0] / shebang
    // interpreters are pushed as their UTF-8 bytes.
    argv: Vec<Vec<u8>>,
    env: Vec<Vec<u8>>,
    requires_syscall_traps: bool,
) -> Result<LoadedExecImage, LinuxErrno> {
    use crate::linux_abi::LINUX_ENOENT;
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
    let abs_path = files.resolve_path(path);
    let argv = if argv.is_empty() {
        vec![abs_path.as_bytes().to_vec()]
    } else {
        argv
    };
    let host_open = |path: &str| std::fs::File::open(path);
    let acquire_source = |path: &str| files.acquire_with_host_file_service(path, &host_open);
    let named_source = acquire_source(path).map_err(exec_source_errno)?;
    files.check_source(&named_source)?;
    // fanotify FAN_OPEN_EXEC, emitted after validation so a failed execve
    // generates nothing — the event means "this image is being executed", and
    // an ENOENT/EACCES target never is. Placed before shebang resolution so
    // `abs_path` is still the file the guest actually named.
    files.notify_exec(&abs_path);
    let named_target = abs_path.clone();
    let mut path = abs_path;
    let mut argv = argv;
    let mut source = named_source;
    let mut direct_aarch64 = false;
    let mut final_source_inspected = false;
    for _ in 0..4 {
        let (head, eligible) =
            inspect_exec_head(|max| source.read_head(max)).map_err(host_io_errno)?;
        direct_aarch64 = eligible;
        final_source_inspected = true;
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
        files.check_source(&source)?;
        final_source_inspected = false;
    }
    // A fourth shebang replacement exhausts the loop after acquiring its
    // interpreter. It has no preceding head snapshot to reuse.
    if !final_source_inspected {
        direct_aarch64 = source
            .read_head(20)
            .ok()
            .is_some_and(|head| is_aarch64_elf_head(&head));
    }
    // Executing a `#!` script also opens its INTERPRETER for execution, and
    // Linux reports that as a second FAN_OPEN_EXEC. Skip it for a plain binary,
    // where `resolve_shebang` hands back the same path it was given.
    if path != named_target {
        files.notify_exec(&path);
    }

    // Read the main binary AND resolve its interpreter OVERLAY-FIRST via
    // the retained file capabilities, so execve works for guest-created/overlay binaries
    // (downloaded/extracted ELF, /tmp/p, dpkg-unpacked binary) and needs no
    // in-memory rootfs layer (which `--fs host` drops after seeding). The
    // host-fs fallback (reading the literal absolute path straight off the
    // host) is ON only for a bare RunElf boot; a container run keeps it OFF so
    // an execve target absent from the container fs ENOENTs instead of escaping
    // to the matching HOST binary. The filesystem capability retains that fallback policy.
    let vdso_enabled = vdso_enabled_for_debug();
    let requires_syscall_traps = requires_syscall_traps || loader.requires_syscall_traps;
    // The cache is deliberately limited to direct little-endian AArch64 ELFs.
    // Rosetta redirects rewrite argv and carry target-specific AT_BASE state;
    // mutable/foreign images stay on the uncached path below.
    let cache_key = direct_aarch64
        .then(|| {
            source.hvpatch_cache_key(
                loader.linux_page_size,
                vdso_enabled,
                requires_syscall_traps,
                false,
            )
        })
        .flatten();
    let mut binfmt_argv = None;
    let (base, argv) = if cache_key.is_some() {
        let base = files.with_cache(cache_key, || {
            let raw_bytes = source.read_all().map_err(host_io_errno)?;
            let raw = AddressSpace::load_elf_bytes_with_reader(&raw_bytes, &|interpreter| {
                acquire_source(interpreter).ok()?.read_all().ok()
            })
            .map_err(carrick_kernel::exec_helpers::exec_image_errno)?
            .with_main_file_path(path.clone());
            finalize_hvf_exec_base(loader, raw, false, vdso_enabled, requires_syscall_traps)
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
                binfmt_argv = Some(redirect.argv.clone());
                (redirect.interpreter_bytes, redirect.argv)
            }
            Some(Err(errno)) => return Err(errno),
        };
        let raw = AddressSpace::load_elf_bytes_with_reader(&raw_bytes, &|interpreter| {
            acquire_source(interpreter).ok()?.read_all().ok()
        })
        .map_err(carrick_kernel::exec_helpers::exec_image_errno)?
        .with_main_file_path(path.clone());
        (
            finalize_hvf_exec_base(
                loader,
                raw,
                needs_at_base,
                vdso_enabled,
                requires_syscall_traps,
            )?,
            argv,
        )
    };
    let linux_page_size = loader.linux_page_size;
    let image = base
        .with_linux_initial_stack_execfn_page_size(argv, env, path.as_bytes(), linux_page_size)
        .map_err(|_| LINUX_ENOENT)?;
    Ok(LoadedExecImage {
        image,
        source,
        binfmt_argv,
    })
}

// Shebang resolution and the signal-death / stop helpers live in the
// cross-platform `exec_helpers` module. Re-export them here so the call sites
// in `runtime.rs` (`use exec::{…}`) and the vcpu_loop macOS import
// (`use crate::runtime::exec::{…}`) resolve without change.
pub(crate) use carrick_kernel::exec_helpers::{
    forked_child_die_by_signal, stop_after_traced_exec, stop_by_signal,
};

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_aarch64_exec() -> Vec<u8> {
        const ET_EXEC: u16 = 2;
        const EM_AARCH64: u16 = 183;
        const PT_LOAD: u32 = 1;
        let mut elf = vec![0_u8; 0x1004];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        elf[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
        elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
        elf[24..32].copy_from_slice(&0x400000_u64.to_le_bytes());
        elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1_u16.to_le_bytes());
        let ph = 64;
        elf[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        elf[ph + 4..ph + 8].copy_from_slice(&5_u32.to_le_bytes());
        elf[ph + 8..ph + 16].copy_from_slice(&0x1000_u64.to_le_bytes());
        elf[ph + 16..ph + 24].copy_from_slice(&0x400000_u64.to_le_bytes());
        elf[ph + 32..ph + 40].copy_from_slice(&4_u64.to_le_bytes());
        elf[ph + 40..ph + 48].copy_from_slice(&0x1000_u64.to_le_bytes());
        elf[ph + 48..ph + 56].copy_from_slice(&0x1000_u64.to_le_bytes());
        elf[0x1000..0x1004].copy_from_slice(&0xd503_201f_u32.to_le_bytes());
        elf
    }

    fn read_image_u64(image: &AddressSpace, address: u64) -> u64 {
        u64::from_le_bytes(
            image
                .read_bytes(address, 8)
                .expect("stack word")
                .try_into()
                .expect("u64 stack word"),
        )
    }

    fn read_image_c_string(image: &AddressSpace, address: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut cursor = address;
        loop {
            let byte = image.read_bytes(cursor, 1).expect("stack string byte")[0];
            if byte == 0 {
                return bytes;
            }
            bytes.push(byte);
            cursor += 1;
        }
    }

    fn execfn(image: &AddressSpace) -> Vec<u8> {
        const AT_EXECFN: u64 = 31;
        let mut cursor = image.initial_stack_pointer().expect("initial stack") + 32;
        loop {
            let tag = read_image_u64(image, cursor);
            let value = read_image_u64(image, cursor + 8);
            if tag == AT_EXECFN {
                return read_image_c_string(image, value);
            }
            assert_ne!(tag, 0, "AT_EXECFN missing from initial stack");
            cursor += 16;
        }
    }

    #[test]
    fn exec_normalizes_dot_slashes_and_dotdot_in_guest_visible_names() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("image");
        std::fs::write(&executable, synthetic_aarch64_exec()).unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir(directory.path().join("sub")).unwrap();
        let expected = executable.to_string_lossy().into_owned();
        let spellings = [
            directory
                .path()
                .join("./image")
                .to_string_lossy()
                .into_owned(),
            format!("{}//image", directory.path().display()),
            directory
                .path()
                .join("sub/../image")
                .to_string_lossy()
                .into_owned(),
        ];
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().unwrap();
        let files = dispatcher.capture_exec_files(&context).unwrap();
        let loader = ExecLoaderCapabilities::capture(&dispatcher);

        for spelling in spellings {
            let loaded = load_execve_image(&loader, &files, &spelling, vec![], vec![], false)
                .expect("load spelled executable");
            let sp = loaded.image.initial_stack_pointer().expect("initial stack");
            let argv0 = read_image_u64(&loaded.image, sp + 8);
            assert_eq!(
                read_image_c_string(&loaded.image, argv0),
                expected.as_bytes()
            );
            assert_eq!(execfn(&loaded.image), expected.as_bytes());
            let mappings: Vec<_> = loaded
                .image
                .file_mappings()
                .iter()
                .filter(|mapping| mapping.start == 0x400000)
                .collect();
            assert!(
                !mappings.is_empty() && mappings.iter().all(|mapping| mapping.path == expected),
                "main mappings did not use normalized name for {spelling}"
            );
        }
    }

    #[cfg(feature = "syscall-shim")]
    struct ContinueInterceptor;

    #[cfg(feature = "syscall-shim")]
    impl carrick_kernel::observe::SyscallInterceptor for ContinueInterceptor {
        fn intercept(
            &self,
            _process: &carrick_kernel::observe::ProcessInfo<'_>,
            _call: &carrick_kernel::observe::InterceptedSyscall<'_>,
        ) -> carrick_kernel::observe::InterceptAction {
            carrick_kernel::observe::InterceptAction::Continue
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

        let mut image = finalize_hvf_exec_base(
            &ExecLoaderCapabilities::capture(&dispatcher),
            synthetic_exec_image(),
            false,
            true,
            false,
        )
        .expect("interceptor-bearing exec image");
        let context = dispatcher
            .capture_one_task_context()
            .expect("exec task context");
        carrick_kernel::kernel::identity_page::stamp_identity_page(
            &mut image,
            &dispatcher,
            &context,
        )
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
            &ExecLoaderCapabilities::capture(&SyscallDispatcher::new()),
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
    fn exec_head_budget_reads_one_prefix_per_direct_elf() {
        // Contract runtime.exec.direct-elf-head: classification must reuse
        // the shebang prefix, so N direct execs issue exactly N head reads.
        let mut elf = vec![0_u8; 256];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[5] = 1;
        elf[18..20].copy_from_slice(&183_u16.to_le_bytes());
        for count in [1, 8, 32] {
            let mut reads = 0;
            for _ in 0..count {
                let (head, direct_aarch64) = inspect_exec_head(|max| {
                    reads += 1;
                    Ok(elf[..max].to_vec())
                })
                .expect("inspect direct ELF head");
                assert_eq!(head, elf);
                assert!(direct_aarch64);
            }
            assert_eq!(reads, count, "direct exec repeated the source head read");
        }
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
        let image = finalize_hvf_exec_base(
            &ExecLoaderCapabilities::capture(&SyscallDispatcher::new()),
            raw,
            false,
            false,
            false,
        )
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
            let leaf = carrick_mmu_core::aarch64::terminal_descriptor(
                carrick_mmu_core::aarch64::walk_descriptors(
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
    #[test]
    fn retained_exec_files_preserve_numeric_preparation_errnos() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("image");
        std::fs::write(&path, b"not an executable image").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().unwrap();
        let files = dispatcher.capture_exec_files(&context).unwrap();
        let loader = ExecLoaderCapabilities::capture(&dispatcher);
        drop(context);
        drop(dispatcher);
        let load_errno = || match load_execve_image(
            &loader,
            &files,
            path.to_str().unwrap(),
            vec![],
            vec![],
            false,
        ) {
            Ok(_) => panic!("invalid image was accepted"),
            Err(errno) => errno.get(),
        };
        assert_eq!(load_errno(), 13, "EACCES before image parsing");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(load_errno(), 8, "ENOEXEC for executable non-ELF");
        std::fs::remove_file(&path).unwrap();
        assert_eq!(load_errno(), 2, "ENOENT after unlink");
    }

    #[test]
    fn native_exec_capability_outlives_context_without_host_task_lookup() {
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().unwrap();
        let id = carrick_core_abi::service::ExecCapabilityId::new(
            core::num::NonZeroU64::new(context.resources().files().id().raw()).unwrap(),
        );
        let capability = capture_native_exec_capability(&dispatcher).unwrap();
        drop(context);

        assert_eq!(capability._id, id);
        assert!(matches!(
            capability._files.caller(),
            carrick_kernel::dispatch::exec_files::ExecCaller::Host { .. }
        ));
    }
}
