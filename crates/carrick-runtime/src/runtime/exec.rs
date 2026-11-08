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
    id: carrick_core_abi::service::ExecCapabilityId,
    files: carrick_kernel::dispatch::exec_files::ExecFiles,
    loader: ExecLoaderCapabilities,
    /// The run whose dispatcher serves this tree's host-file crossings
    /// (#894). Bound once at service installation; weak, because the run
    /// owns this capability.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    run: std::sync::OnceLock<std::sync::Weak<crate::vcpu_loop::KernelState>>,
}

impl core::fmt::Debug for NativeExecCapability {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NativeExecCapability")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl NativeExecCapability {
    pub(crate) fn id(&self) -> carrick_core_abi::service::ExecCapabilityId {
        self.id
    }

    /// Bind the run that serves this tree's host-file crossings. The first
    /// binding wins; the run is exact for the capability's whole life.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn bind_run(&self, run: std::sync::Weak<crate::vcpu_loop::KernelState>) {
        let _ = self.run.set(run);
    }
}

/// Native exec serves ring-owned fork children. Their cwd, umask and
/// credentials live in their ring task row, and the ring owner seals them
/// into the payload as the caller's access context, so the service resolves
/// and checks access with exactly the caller's authority (#1392). The
/// capability holds no per-child executable or descriptor table, so a path
/// into the caller-relative `/proc` and `/dev/fd` views (also when reached
/// through a symlink) is refused, and so is `execveat` of a real directory
/// descriptor.
fn native_child_exec_path_is_served(resolved: &str) -> bool {
    ![
        "/proc",
        "/dev/fd",
        "/dev/stdin",
        "/dev/stdout",
        "/dev/stderr",
    ]
    .iter()
    .any(|prefix| {
        resolved
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    })
}

/// `descriptor_source` selects the object behind a descriptor in the
/// caller's ring table (the table its ring owner sealed into the request):
/// `SyscallDispatcher::native_descriptor_exec_source` (#1530).
fn prepare_native_exec_image(
    capability: &NativeExecCapability,
    payload: &[u8],
    descriptor_source: impl FnOnce(
        [u64; 3],
        i32,
    ) -> Result<
        carrick_kernel::dispatch::executable_authority::ExecSource,
        LinuxErrno,
    >,
) -> Result<LoadedExecImage, LinuxErrno> {
    let view = carrick_core_abi::service::ExecPayloadView::parse(payload)
        .map_err(|_| crate::linux_abi::LINUX_EINVAL)?;
    // Served exactly or left unrouted: counted ENOSYS, never a guess.
    let access = view.access().ok_or(crate::linux_abi::LINUX_ENOSYS)?;
    // `ExecFiles` resolves from the global root; a chrooted caller's exec
    // is left unrouted until it resolves under the caller's root.
    if access.root.is_some_and(|root| root != b"/") {
        return Err(crate::linux_abi::LINUX_ENOSYS);
    }
    let cwd = core::str::from_utf8(access.cwd).map_err(|_| crate::linux_abi::LINUX_ENOSYS)?;
    let files = capability.files.for_native_access(
        cwd.to_owned(),
        carrick_abi::NsUid::new(access.ids.fsuid),
        carrick_abi::NsGid::new(access.ids.fsgid),
    );
    let path = core::str::from_utf8(view.path()).map_err(|_| crate::linux_abi::LINUX_EINVAL)?;
    let path = match view.call() {
        carrick_core_abi::service::ExecCall::Execve => path.to_owned(),
        carrick_core_abi::service::ExecCall::Execveat { dirfd, flags } => {
            const VALID: u32 = carrick_abi::LINUX_AT_EMPTY_PATH as u32
                | carrick_abi::LINUX_AT_SYMLINK_NOFOLLOW as u32;
            if flags & !VALID != 0 {
                return Err(crate::linux_abi::LINUX_EINVAL);
            }
            // The capability's lookup always follows a final symlink; a
            // no-follow exec (ELOOP on a final symlink) is left unrouted
            // until the lookup can refuse one, never served as a follow.
            if flags & carrick_abi::LINUX_AT_SYMLINK_NOFOLLOW as u32 != 0 {
                return Err(crate::linux_abi::LINUX_ENOSYS);
            }
            if path.is_empty() && flags & carrick_abi::LINUX_AT_EMPTY_PATH as u32 != 0 {
                // fexecve: `dirfd` is the executable's own descriptor, in the
                // caller's ring table, and Linux runs the open file, never
                // its name. Without a sealed table it is unrouted.
                let table = view.table().ok_or(crate::linux_abi::LINUX_ENOSYS)?;
                let source = descriptor_source(table, dirfd)?;
                let argv = view.argv().map(<[u8]>::to_vec).collect();
                let env = view.envp().map(<[u8]>::to_vec).collect();
                return load_execve_image(
                    &capability.loader,
                    &files,
                    ExecTarget::Descriptor {
                        spelling: format!("/dev/fd/{dirfd}"),
                        source,
                    },
                    argv,
                    env,
                    false,
                );
            } else if path.starts_with('/') || dirfd == -100 {
                path.to_owned()
            } else {
                // Linux resolves a relative path from `dirfd`, a descriptor
                // this capability does not hold: unrouted, never EBADF.
                return Err(crate::linux_abi::LINUX_ENOSYS);
            }
        }
    };
    if !native_child_exec_path_is_served(&files.resolve_path(&path)) {
        return Err(crate::linux_abi::LINUX_ENOSYS);
    }
    let argv = view.argv().map(<[u8]>::to_vec).collect();
    let env = view.envp().map(<[u8]>::to_vec).collect();
    load_execve_image(&capability.loader, &files, &path, argv, env, false)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct NativePreparedExecImage {
    _request: carrick_core_abi::service::ServiceIdentity,
    plan: carrick_vmm_hvf::trap::GuestMappingPlan,
    successor: carrick_kernel::dispatch::NativeSuccessorImage,
    executable: std::sync::Arc<dyn carrick_hal::fork_stock::ExecutableIdentity>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl core::fmt::Debug for NativePreparedExecImage {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("NativePreparedExecImage")
            .field("request", &self._request)
            .field("entry", &self.plan.entry)
            .finish_non_exhaustive()
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl carrick_vmm_hvf::metadata_grant::NativeExecPreparation for NativePreparedExecImage {
    fn into_parts(self: Box<Self>) -> carrick_vmm_hvf::metadata_grant::NativeExecParts {
        carrick_vmm_hvf::metadata_grant::NativeExecParts {
            plan: self.plan,
            lazy_regions: self.successor.lazy_regions,
            sources: self.successor.sources,
            executable: self.executable,
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl carrick_vmm_hvf::metadata_grant::NativeExecHostService for NativeExecCapability {
    fn prepare(
        &self,
        request: carrick_core_abi::service::ServiceRequest,
        payload: &[u8],
        successor: carrick_el1_abi::ReservationMm,
    ) -> Result<
        Box<dyn carrick_vmm_hvf::metadata_grant::NativeExecPreparation>,
        carrick_core_abi::service::ServiceFailureCode,
    > {
        let fail = |errno: LinuxErrno| {
            carrick_core_abi::service::ServiceFailureCode::new(errno.get() as u32)
                .unwrap_or(carrick_core_abi::service::ServiceFailureCode::MINIMUM)
        };
        let run = self
            .run
            .get()
            .and_then(std::sync::Weak::upgrade)
            .ok_or_else(|| fail(crate::linux_abi::LINUX_ENOSYS))?;
        let loaded = prepare_native_exec_image(self, payload, |table, fd| {
            run.dispatcher.native_descriptor_exec_source(table, fd)
        })
        .map_err(fail)?;
        let plan = carrick_vmm_hvf::trap::GuestMappingPlan::from_address_space(&loaded.image)
            .map_err(|_| fail(crate::linux_abi::LINUX_ENOMEM))?;
        // The successor's ELF images become its own root's lazy nodes; the
        // carrier maps only what the root records as opaque.
        let successor = run
            .dispatcher
            .prepare_native_successor(&loaded.image, successor)
            .map_err(fail)?;
        Ok(Box::new(NativePreparedExecImage {
            executable: run.dispatcher.retain_native_executable(loaded.source),
            _request: request.identity,
            plan,
            successor,
        }))
    }

    fn serve_host_file(
        &self,
        _request: carrick_core_abi::service::ServiceRequest,
        record: &mut [u8],
        executable: Option<std::sync::Arc<dyn carrick_hal::fork_stock::ExecutableIdentity>>,
    ) -> Result<
        Option<std::sync::Arc<dyn carrick_hal::fork_stock::HostBackingRetention>>,
        carrick_vmm_hvf::metadata_grant::NativeHostFileRefused,
    > {
        // The request identity was authenticated by the service cell; the
        // record names the caller's own ring table, pinned at service time.
        let run = self
            .run
            .get()
            .and_then(std::sync::Weak::upgrade)
            .ok_or(carrick_vmm_hvf::metadata_grant::NativeHostFileRefused)?;
        run.dispatcher
            .serve_native_host_file(record, executable)
            .map(|served| served.retained_source)
            .map_err(|_| carrick_vmm_hvf::metadata_grant::NativeHostFileRefused)
    }

    /// Retain the root's current object for its new child's MM custody.
    fn root_executable_seed(
        &self,
    ) -> Option<std::sync::Arc<dyn carrick_hal::fork_stock::ExecutableIdentity>> {
        self.run
            .get()
            .and_then(std::sync::Weak::upgrade)?
            .dispatcher
            .root_executable_seed()
    }

    /// The host-served root's live cwd and root, read once for a child the
    /// stopped root is forking (#1392). The child's ring row owns the copy.
    fn root_fork_seed(&self, record: &mut carrick_core_abi::service::RootForkSeed) -> bool {
        let Some(run) = self.run.get().and_then(std::sync::Weak::upgrade) else {
            return false;
        };
        let Ok(root) = run.dispatcher.capture_one_task_context() else {
            return false;
        };
        root.resources()
            .fs_context()
            .with_cwd_and_root(|cwd, root| record.serve(cwd.as_bytes(), root.map(str::as_bytes)))
    }
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
        id,
        files: dispatcher.capture_exec_files(&context)?,
        loader: ExecLoaderCapabilities::capture(dispatcher),
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        run: std::sync::OnceLock::new(),
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

/// What an exec runs.
pub(crate) enum ExecTarget<'a> {
    /// A path the caller named, resolved under its access.
    Path(&'a str),
    /// An open descriptor's own object (`execveat(fd, "", AT_EMPTY_PATH)`,
    /// #1530). Linux runs the open file, never its name: nothing may
    /// re-resolve it by path. `spelling` is the guest-visible program name,
    /// `/dev/fd/N` (Linux's `bprm->filename`).
    Descriptor {
        spelling: String,
        source: carrick_kernel::dispatch::executable_authority::ExecSource,
    },
}

impl<'a> From<&'a str> for ExecTarget<'a> {
    fn from(path: &'a str) -> Self {
        Self::Path(path)
    }
}

impl<'a> From<&'a String> for ExecTarget<'a> {
    fn from(path: &'a String) -> Self {
        Self::Path(path)
    }
}

pub(crate) fn load_execve_image<'a>(
    loader: &ExecLoaderCapabilities,
    files: &carrick_kernel::dispatch::exec_files::ExecFiles,
    // A path to resolve, or an open descriptor's own object (`fexecve`).
    target: impl Into<ExecTarget<'a>>,
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
    let host_open = |path: &str| std::fs::File::open(path);
    let acquire_source = |path: &str| files.acquire_with_host_file_service(path, &host_open);
    let (abs_path, named_source, descriptor) = match target.into() {
        ExecTarget::Path(path) => (
            files.resolve_path(path),
            acquire_source(path).map_err(exec_source_errno)?,
            false,
        ),
        ExecTarget::Descriptor { spelling, source } => (spelling, source, true),
    };
    let argv = if argv.is_empty() {
        vec![abs_path.as_bytes().to_vec()]
    } else {
        argv
    };
    files.check_source(&named_source)?;
    // fanotify FAN_OPEN_EXEC, emitted after validation so a failed execve
    // generates nothing — the event means "this image is being executed", and
    // an ENOENT/EACCES target never is. Placed before shebang resolution so
    // `abs_path` is still the file the guest actually named.
    files.notify_exec(&abs_path);
    // The executed file's own path names the image (`/proc/self/exe`); for a
    // descriptor that is the object's path, never a lookup of the spelling.
    let execfn = abs_path.clone();
    let named_target = if descriptor {
        named_source.resolved_path().to_owned()
    } else {
        abs_path
    };
    let mut path = named_target.clone();
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
        // An fexecve'd script's interpreter would reopen the script by name
        // (Linux passes `/dev/fd/N`, which a native exec cannot serve):
        // unrouted, never a re-resolution of the path (#1530).
        if descriptor {
            return Err(crate::linux_abi::LINUX_ENOSYS);
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
        .with_linux_initial_stack_execfn_page_size(
            argv,
            env,
            if descriptor {
                execfn.as_bytes()
            } else {
                path.as_bytes()
            },
            linux_page_size,
        )
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
        let capability = capture_native_exec_capability(&dispatcher).unwrap();
        // A released origin cannot prove a native child's authority.
        let _origin = dispatcher;
        let load_errno = || {
            let spelling = path.to_str().unwrap();
            let mut payload = vec![0; carrick_core_abi::service::EXEC_PAYLOAD_HEADER_BYTES];
            payload.extend_from_slice(spelling.as_bytes());
            payload.push(0);
            carrick_core_abi::service::encode_exec_payload_header(
                &mut payload,
                carrick_core_abi::service::ExecCall::Execve,
                spelling.len() + 1,
                0,
                0,
            )
            .unwrap();
            let payload = sealed(payload, 0, "/");
            match prepare_native_exec_image(&capability, &payload, no_descriptors) {
                Ok(_) => panic!("invalid image was accepted"),
                Err(errno) => errno.get(),
            }
        };
        assert_eq!(load_errno(), 13, "EACCES before image parsing");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(load_errno(), 8, "ENOEXEC for executable non-ELF");
        std::fs::remove_file(&path).unwrap();
        assert_eq!(load_errno(), 2, "ENOENT after unlink");
    }

    /// Seal a staged payload with a caller's access context, as the ring
    /// owner does from the caller's task row.
    fn sealed(payload: Vec<u8>, fsuid: u32, cwd: &str) -> Vec<u8> {
        sealed_in(payload, fsuid, cwd, None)
    }

    /// Seal a staged payload as the ring owner does, through the production
    /// encoder, from a task row with `fsuid` everywhere, the capabilities
    /// Linux leaves that uid, `cwd` and `root`.
    fn sealed_in(payload: Vec<u8>, fsuid: u32, cwd: &str, root: Option<&str>) -> Vec<u8> {
        seal_task_row(payload, fsuid, cwd, root, None)
    }

    /// Seal as the ring owner does for a root caller with a ring table.
    fn sealed_with_table(payload: Vec<u8>, cwd: &str, table: Option<[u64; 3]>) -> Vec<u8> {
        seal_task_row(payload, 0, cwd, None, table)
    }

    fn seal_task_row(
        mut payload: Vec<u8>,
        fsuid: u32,
        cwd: &str,
        root: Option<&str>,
        table: Option<[u64; 3]>,
    ) -> Vec<u8> {
        use carrick_personality_linux::identity::{TaskCredentials, TaskGid, TaskUid};
        use carrick_personality_linux::task_fs::{TaskFs, TaskPath};
        let mut credentials = TaskCredentials::ROOT;
        let (uid, gid) = (TaskUid::new(fsuid), TaskGid::new(fsuid));
        (
            credentials.ruid,
            credentials.euid,
            credentials.suid,
            credentials.fsuid,
        ) = (uid, uid, uid, uid);
        (
            credentials.rgid,
            credentials.egid,
            credentials.sgid,
            credentials.fsgid,
        ) = (gid, gid, gid, gid);
        if fsuid != 0 {
            credentials.cap_effective =
                carrick_personality_linux::identity::LinuxCapabilitySet::empty();
            credentials.cap_permitted =
                carrick_personality_linux::identity::LinuxCapabilitySet::empty();
        }
        let fs = TaskFs {
            cwd: TaskPath::new(cwd.as_bytes()).unwrap(),
            root: root.map(|root| TaskPath::new(root.as_bytes()).unwrap()),
        };
        let mut access = Vec::new();
        fs.encode_access(&credentials, 0o022, &mut access).unwrap();
        carrick_core_abi::service::seal_exec_payload_access(&mut payload, &access, table).unwrap();
        payload
    }

    /// A caller whose ring table resolves no descriptor.
    fn no_descriptors(
        _: [u64; 3],
        _: i32,
    ) -> Result<carrick_kernel::dispatch::executable_authority::ExecSource, LinuxErrno> {
        Err(crate::linux_abi::LINUX_ENOSYS)
    }

    fn native_exec_payload(call: carrick_core_abi::service::ExecCall, path: &str) -> Vec<u8> {
        let argv = b"successor\0";
        let mut payload = vec![0; carrick_core_abi::service::EXEC_PAYLOAD_HEADER_BYTES];
        payload.extend_from_slice(path.as_bytes());
        payload.push(0);
        payload.extend_from_slice(&(argv.len() as u32).to_le_bytes());
        payload.extend_from_slice(argv);
        carrick_core_abi::service::encode_exec_payload_header(
            &mut payload,
            call,
            path.len() + 1,
            1,
            0,
        )
        .unwrap();
        payload
    }

    /// #1392: a native child's exec resolves under the cwd and checks
    /// access with the ids its own task row carries in the payload, never
    /// the origin task's live (or captured) cwd and credentials. What the
    /// capability cannot hold (the caller's own `/proc/self` and `/dev/fd`
    /// views, an unsealed payload) stays a counted ENOSYS.
    #[test]
    fn native_child_exec_resolves_with_the_callers_own_access() {
        use carrick_core_abi::service::ExecCall;
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("static-successor");
        std::fs::write(&path, synthetic_aarch64_exec()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let absolute = path.to_str().unwrap().to_owned();
        let cwd = directory.path().to_str().unwrap().to_owned();
        let dispatcher = SyscallDispatcher::new();
        let capability = capture_native_exec_capability(&dispatcher).unwrap();
        let enosys = Err(crate::linux_abi::LINUX_ENOSYS);
        let exec = |call, spelling: &str, fsuid, cwd: &str| {
            prepare_native_exec_image(
                &capability,
                &sealed(native_exec_payload(call, spelling), fsuid, cwd),
                no_descriptors,
            )
            .map(|_| ())
        };
        // The origin task moving (red on main: every child exec ENOSYS)
        // changes nothing for a child that carries its own cwd.
        dispatcher.set_cwd("/");
        assert!(exec(ExecCall::Execve, &absolute, 0, "/").is_ok());
        assert!(exec(ExecCall::Execve, "./static-successor", 0, &cwd).is_ok());
        assert!(exec(ExecCall::Execve, "static-successor", 0, &cwd).is_ok());
        assert_eq!(
            exec(ExecCall::Execve, "./static-successor", 0, "/"),
            Err(crate::linux_abi::LINUX_ENOENT),
            "the base is the caller's cwd, not the image's directory"
        );
        // The caller's own ids decide access: 0700 root-owned is EACCES to
        // uid 1000 (the temp file's real owner maps to root in the VFS).
        assert_eq!(
            exec(ExecCall::Execve, &absolute, 1000, "/"),
            Err(crate::linux_abi::LINUX_EACCES)
        );
        // /proc/self and /dev/fd name the caller, not the boot task.
        assert_eq!(exec(ExecCall::Execve, "/proc/self/exe", 0, "/"), enosys);
        assert_eq!(exec(ExecCall::Execve, "self/exe", 0, "/proc"), enosys);
        assert_eq!(exec(ExecCall::Execve, "/dev/fd/3", 0, "/"), enosys);
        // An AT_EMPTY_PATH or dirfd exec needs the caller's descriptor table.
        assert_eq!(
            exec(
                ExecCall::Execveat {
                    dirfd: 3,
                    flags: carrick_abi::LINUX_AT_EMPTY_PATH as u32
                },
                "",
                0,
                "/"
            ),
            enosys
        );
        // A relative execveat resolves from a descriptor the capability
        // does not hold: unrouted, never EBADF (review #1409, 3).
        assert_eq!(
            exec(
                ExecCall::Execveat { dirfd: 3, flags: 0 },
                "static-successor",
                0,
                &cwd
            ),
            enosys
        );
        // A chrooted caller's exec is unrouted until it resolves under its
        // root; a root of `/` is the global root (review #1409, 2).
        let chrooted = |root| {
            prepare_native_exec_image(
                &capability,
                &sealed_in(
                    native_exec_payload(ExecCall::Execve, &absolute),
                    0,
                    "/",
                    Some(root),
                ),
                no_descriptors,
            )
            .map(|_| ())
        };
        assert_eq!(chrooted("/jail"), enosys);
        assert!(chrooted("/").is_ok());
        // A no-follow execveat is never served as a following lookup.
        assert_eq!(
            exec(
                ExecCall::Execveat {
                    dirfd: -100,
                    flags: carrick_abi::LINUX_AT_SYMLINK_NOFOLLOW as u32
                },
                &absolute,
                0,
                "/"
            ),
            enosys
        );
        // A payload its ring owner never sealed carries no authority at all.
        assert_eq!(
            prepare_native_exec_image(
                &capability,
                &native_exec_payload(ExecCall::Execve, &absolute),
                no_descriptors,
            )
            .map(|_| ()),
            enosys
        );
        drop(dispatcher);
    }

    /// `fexecve` from a native fork child (#1530): `execveat(fd, "",
    /// AT_EMPTY_PATH)` names the caller's own descriptor. The ring seals its
    /// descriptor table into the request; the service takes the object
    /// behind `fd` in that table and executes it. Linux runs the open file,
    /// never its name: replacing the path after the open must not change
    /// what runs. Red on the path-recovery version: it re-resolved the
    /// recorded path and loaded the replacement (ENOEXEC here).
    #[test]
    fn native_child_fexecve_executes_the_open_file_not_its_path() {
        use carrick_core_abi::service::ExecCall;
        use carrick_kernel::dispatch::executable_authority::ExecSource;
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("static-successor");
        std::fs::write(&path, synthetic_aarch64_exec()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let absolute = path.to_str().unwrap().to_owned();
        let dispatcher = SyscallDispatcher::new();
        let capability = capture_native_exec_capability(&dispatcher).unwrap();
        let fexecve = ExecCall::Execveat {
            dirfd: 3,
            flags: carrick_abi::LINUX_AT_EMPTY_PATH as u32,
        };
        let table = [7, 8, 9];
        let payload = |table| sealed_with_table(native_exec_payload(fexecve, ""), "/tmp", table);
        // The caller opened the image; then another task replaced the file at
        // that path with a non-image.
        let opened =
            ExecSource::host(std::fs::File::open(&path).unwrap(), absolute.clone()).unwrap();
        let replacement = directory.path().join("replacement");
        std::fs::write(&replacement, b"not an executable image").unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::rename(&replacement, &path).unwrap();

        let mut asked = None;
        let served = prepare_native_exec_image(&capability, &payload(Some(table)), |t, fd| {
            asked = Some((t, fd));
            Ok(opened.clone())
        })
        .map(|loaded| loaded.source.resolved_path().to_owned());
        assert_eq!(
            served,
            Ok(absolute.clone()),
            "fexecve runs the opened image, never the replacement at its path"
        );
        assert_eq!(
            asked,
            Some((table, 3)),
            "selected in the caller's own table"
        );
        // A closed descriptor is EBADF, as Linux reports it.
        assert_eq!(
            prepare_native_exec_image(&capability, &payload(Some(table)), |_, _| {
                Err(crate::linux_abi::LINUX_EBADF)
            })
            .map(|_| ()),
            Err(crate::linux_abi::LINUX_EBADF)
        );
        // Without a sealed table the descriptor is unrouted, never guessed.
        assert_eq!(
            prepare_native_exec_image(&capability, &payload(None), |_, _| {
                panic!("no table: nothing to select")
            })
            .map(|_| ()),
            Err(crate::linux_abi::LINUX_ENOSYS)
        );
        // An fexecve'd script is unrouted: its interpreter would reopen it by
        // name.
        let script = directory.path().join("script");
        std::fs::write(&script, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let script_source = ExecSource::host(
            std::fs::File::open(&script).unwrap(),
            script.to_str().unwrap().to_owned(),
        )
        .unwrap();
        assert_eq!(
            prepare_native_exec_image(&capability, &payload(Some(table)), |_, _| {
                Ok(script_source)
            })
            .map(|_| ()),
            Err(crate::linux_abi::LINUX_ENOSYS)
        );
        drop(dispatcher);
    }

    #[test]
    fn retained_exec_capability_prepares_a_static_binary_successor() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("static-successor");
        std::fs::write(&path, synthetic_aarch64_exec()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let dispatcher = SyscallDispatcher::new();
        let capability = capture_native_exec_capability(&dispatcher).unwrap();
        // A released origin cannot prove a native child's authority.
        let _origin = dispatcher;

        let spelling = path.to_str().unwrap();
        let argv = b"static-successor\0";
        let env = b"WITNESS=exec\0";
        let mut payload = vec![0; carrick_core_abi::service::EXEC_PAYLOAD_HEADER_BYTES];
        payload.extend_from_slice(spelling.as_bytes());
        payload.push(0);
        // Each argv/envp string is a u32 length prefix plus its NUL-terminated bytes.
        for string in [argv.as_slice(), env.as_slice()] {
            payload.extend_from_slice(&(string.len() as u32).to_le_bytes());
            payload.extend_from_slice(string);
        }
        carrick_core_abi::service::encode_exec_payload_header(
            &mut payload,
            carrick_core_abi::service::ExecCall::Execve,
            spelling.len() + 1,
            1,
            1,
        )
        .unwrap();

        let payload = sealed(payload, 0, "/");
        let loaded = prepare_native_exec_image(&capability, &payload, no_descriptors).unwrap();
        assert_eq!(loaded.image.entry(), 0x400000);
        assert_eq!(
            loaded.image.read_bytes(0x400000, 4).unwrap(),
            0xd503_201f_u32.to_le_bytes()
        );
        let stack = loaded.image.initial_stack_pointer().unwrap();
        assert_eq!(read_image_u64(&loaded.image, stack), 1);
        let argv0 = read_image_u64(&loaded.image, stack + 8);
        assert_eq!(
            read_image_c_string(&loaded.image, argv0),
            b"static-successor"
        );
    }

    /// A minimal ET_DYN AArch64 image, as the dynamic loader is.
    fn synthetic_aarch64_interpreter() -> Vec<u8> {
        let mut elf = synthetic_aarch64_exec();
        const ET_DYN: u16 = 3;
        elf[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        elf[24..32].copy_from_slice(&0x1000_u64.to_le_bytes());
        let ph = 64;
        elf[ph + 16..ph + 24].copy_from_slice(&0x1000_u64.to_le_bytes());
        elf[ph + 24..ph + 32].copy_from_slice(&0x1000_u64.to_le_bytes());
        elf
    }

    /// A minimal ET_EXEC AArch64 image whose PT_INTERP names `interpreter`.
    fn synthetic_dynamic_aarch64_exec(interpreter: &str) -> Vec<u8> {
        const PT_INTERP: u32 = 3;
        let mut elf = synthetic_aarch64_exec();
        // Two program headers: PT_LOAD (already at 64) and PT_INTERP at 120.
        elf[56..58].copy_from_slice(&2_u16.to_le_bytes());
        let interp_offset = 0x200_u64;
        let mut name = interpreter.as_bytes().to_vec();
        name.push(0);
        elf[interp_offset as usize..interp_offset as usize + name.len()].copy_from_slice(&name);
        let ph = 64 + 56;
        elf[ph..ph + 4].copy_from_slice(&PT_INTERP.to_le_bytes());
        elf[ph + 4..ph + 8].copy_from_slice(&4_u32.to_le_bytes());
        elf[ph + 8..ph + 16].copy_from_slice(&interp_offset.to_le_bytes());
        elf[ph + 16..ph + 24].copy_from_slice(&(0x400000 + interp_offset).to_le_bytes());
        elf[ph + 24..ph + 32].copy_from_slice(&(0x400000 + interp_offset).to_le_bytes());
        elf[ph + 32..ph + 40].copy_from_slice(&(name.len() as u64).to_le_bytes());
        elf[ph + 40..ph + 48].copy_from_slice(&(name.len() as u64).to_le_bytes());
        elf[ph + 48..ph + 56].copy_from_slice(&1_u64.to_le_bytes());
        elf
    }

    /// #937: a native fork child's exec of a dynamically linked binary in a
    /// usrmerge rootfs (`/lib -> usr/lib`) must resolve its PT_INTERP through
    /// the layered rootfs, exactly as the host-owned exec does.
    #[test]
    fn native_child_exec_prepares_a_dynamic_binary_through_a_usrmerge_rootfs() {
        use std::os::unix::fs::PermissionsExt as _;

        let lower = tempfile::tempdir().unwrap();
        let root = lower.path();
        std::fs::create_dir_all(root.join("usr/lib")).unwrap();
        std::fs::create_dir_all(root.join("usr/bin")).unwrap();
        std::os::unix::fs::symlink("usr/lib", root.join("lib")).unwrap();
        std::os::unix::fs::symlink("usr/bin", root.join("bin")).unwrap();
        let interpreter = root.join("usr/lib/ld-linux-aarch64.so.1");
        std::fs::write(&interpreter, synthetic_aarch64_interpreter()).unwrap();
        std::fs::set_permissions(&interpreter, std::fs::Permissions::from_mode(0o755)).unwrap();
        let binary = root.join("usr/bin/true");
        std::fs::write(
            &binary,
            synthetic_dynamic_aarch64_exec("/lib/ld-linux-aarch64.so.1"),
        )
        .unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink("usr/bin/true", root.join("launch")).unwrap();
        let rootfs = carrick_vfs::rootfs::RootFs::from_immutable_host_dir(root).unwrap();
        let dispatcher = SyscallDispatcher::with_rootfs(rootfs);

        // The host-owned exec resolves the interpreter (control).
        let context = dispatcher.capture_one_task_context().unwrap();
        let files = dispatcher.capture_exec_files(&context).unwrap();
        let loader = ExecLoaderCapabilities::capture(&dispatcher);
        drop(context);
        for spelling in ["/usr/bin/true", "/bin/true", "usr/bin/true", "/launch"] {
            load_execve_image(&loader, &files, spelling, vec![], vec![], false)
                .unwrap_or_else(|errno| panic!("host-owned exec of {spelling}: errno {errno:?}"));
        }

        let capability = capture_native_exec_capability(&dispatcher).unwrap();
        for spelling in ["/usr/bin/true", "/bin/true", "usr/bin/true", "/launch"] {
            let payload = sealed(
                native_exec_payload(carrick_core_abi::service::ExecCall::Execve, spelling),
                0,
                "/",
            );
            let loaded = prepare_native_exec_image(&capability, &payload, no_descriptors)
                .unwrap_or_else(|errno| panic!("native exec of {spelling}: errno {errno:?}"));
            assert_ne!(loaded.image.entry(), 0x400000, "entered the interpreter");
            let mut custody = carrick_hal::fork_stock::ForkHostBackingCustody::default();
            custody.bind_executable(dispatcher.retain_native_executable(loaded.source));
            assert_eq!(
                custody.executable().unwrap().display_path(),
                "/usr/bin/true"
            );
            let failed = sealed(
                native_exec_payload(carrick_core_abi::service::ExecCall::Execve, "/missing"),
                0,
                "/",
            );
            assert!(
                matches!(prepare_native_exec_image(&capability, &failed, no_descriptors), Err(errno) if errno.get() == 2)
            );
            assert_eq!(
                custody.executable().unwrap().display_path(),
                "/usr/bin/true"
            );
        }
        drop(dispatcher);
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

        assert_eq!(capability.id, id);
        assert!(matches!(
            capability.files.caller(),
            carrick_kernel::dispatch::exec_files::ExecCaller::Host { .. }
        ));
    }

    #[test]
    fn native_exec_capability_is_the_exact_extra_mount_owner() {
        let dispatcher = SyscallDispatcher::new();
        let container = dispatcher.container().id();
        let mut retirement = dispatcher.prepare_mount_retirement();
        let capability = capture_native_exec_capability(&dispatcher).unwrap();
        drop(dispatcher);

        assert_eq!(
            retirement.prepare(),
            Err(
                carrick_kernel::dispatch::fs::state::MountRetirementError::LiveOwners {
                    container,
                    owners: 2,
                },
            )
        );
        drop(capability);
        retirement.prepare().unwrap();
    }
}
