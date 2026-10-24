//! Retained executable-file services. No operation captures a host task or
//! consults the executor's current resource scope.
use std::sync::Arc;

use carrick_abi::{LinuxErrno, NsGid, NsUid};

use super::SyscallDispatcher;
use super::executable_authority::{ExecSource, ExecSourceError};

/// Physical host-file access supplied by the embedding loader.
pub type ExecHostFileService<'a> = dyn Fn(&str) -> std::io::Result<std::fs::File> + 'a;

/// Identity attached by the owner at admission. The host adapter disappears
/// with host exec ownership; it uses the same file capability implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecCaller {
    Host {
        task: crate::kernel::TaskKey,
        thread: crate::kernel::ThreadKey,
        mm: crate::kernel::MmId,
        execution: Option<crate::kernel::objects::ExecutionGeneration>,
    },
}

/// Read-only lookup into the FD authority. Exec does not interpret descriptor
/// flags, copy tables, or perform close-on-exec here.
pub trait ExecFdSources: Send + Sync {
    fn source(&self, fd: crate::kernel::FileSlotNumber) -> Result<ExecSource, ExecSourceError>;
}

struct HostExecFdSources(Arc<crate::kernel::FileTable>);
impl ExecFdSources for HostExecFdSources {
    fn source(&self, fd: crate::kernel::FileSlotNumber) -> Result<ExecSource, ExecSourceError> {
        let absent = || ExecSourceError::Linux(carrick_abi::LINUX_ENOENT);
        let _lease = self.0.acquire_functional_lease().ok_or_else(absent)?;
        let file = self.0.slot(fd).ok_or_else(absent)?;
        if let Some(source) = file.description.retained_exec_source() {
            return Ok(source);
        }
        ExecSource::from_open_description(file.description).map_err(ExecSourceError::Host)
    }
}

/// Physical filesystem capabilities may outlive their originating dispatcher.
#[derive(Clone)]
pub struct ExecFilesystem {
    rootfs: Arc<carrick_vfs::RootFsVfs>,
    mounts: Arc<carrick_vfs::VfsMounts>,
    cache: super::fs::state::PreparedExecImageCache,
    fanotify: crate::fanotify::FanotifyRegistry,
    host_fallback: bool,
}

/// Caller-selected resources, retained independently of any host TaskRef.
struct ExecFileContext {
    pub caller: ExecCaller,
    pub proc_caller: Option<super::fs::pathres::RetainedProcCaller>,
    pub cwd: String,
    pub fsuid: NsUid,
    pub fsgid: NsGid,
    pub executable: Option<ExecSource>,
    pub descriptors: Arc<dyn ExecFdSources>,
}

pub struct ExecFiles {
    filesystem: ExecFilesystem,
    context: ExecFileContext,
}

impl ExecFiles {
    fn new(filesystem: ExecFilesystem, context: ExecFileContext) -> Self {
        Self {
            filesystem,
            context,
        }
    }

    /// Source acquisition outside the loader never opts into bare-run host fallback.
    pub(super) fn without_host_fallback(mut self) -> Self {
        self.filesystem.host_fallback = false;
        self
    }

    pub fn caller(&self) -> ExecCaller {
        self.context.caller
    }

    pub fn resolve_path(&self, path: &str) -> String {
        // This spelling is also passed as the script argument to a shebang
        // interpreter. Keep `..` until filesystem traversal follows symlinks.
        if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("{}/{}", self.context.cwd.trim_end_matches('/'), path)
        }
    }

    pub fn acquire(&self, path: &str) -> Result<ExecSource, ExecSourceError> {
        self.acquire_from(path, None)
    }

    /// The embedding loader supplies physical host-file access for bare-run
    /// images. The retained filesystem decides whether fallback is permitted;
    /// magic-link refusals never reach this service.
    pub fn acquire_with_host_file_service(
        &self,
        path: &str,
        open: &ExecHostFileService<'_>,
    ) -> Result<ExecSource, ExecSourceError> {
        self.acquire_from(path, Some(open))
    }

    fn acquire_from(
        &self,
        path: &str,
        host_open: Option<&ExecHostFileService<'_>>,
    ) -> Result<ExecSource, ExecSourceError> {
        use super::fs::proc_synthetic::{proc_self_fd_number, proc_self_magic_link};
        super::fs::check_path_length(path).map_err(ExecSourceError::Linux)?;
        let path = self.resolve_path(path);
        super::fs::check_path_length(&path).map_err(ExecSourceError::Linux)?;
        let visible = self
            .context
            .proc_caller
            .and_then(|caller| u32::try_from(caller.pid.raw()).ok());
        // Proc aliases must use the captured caller, including while walking
        // an interior `..`; the context-free ProcVfs cannot select this caller.
        let mut normalized = format!(
            "/{}",
            path.split('/')
                .filter(|part| !part.is_empty() && *part != ".")
                .collect::<Vec<_>>()
                .join("/")
        );
        normalized =
            super::fs::proc_synthetic::rewrite_dev_fd_alias(&normalized).unwrap_or(normalized);
        if let Some(visible) = visible {
            for alias in ["self", "curproc", "this"] {
                let prefix = format!("/proc/{alias}/");
                if let Some(tail) = normalized.strip_prefix(&prefix) {
                    normalized = format!("/proc/{visible}/{tail}");
                    break;
                }
            }
        }
        if let Some(caller) = self.context.proc_caller
            && let Some(tail) = normalized.strip_prefix("/proc/thread-self/")
        {
            normalized = format!(
                "/proc/{}/task/{}/{tail}",
                caller.pid.raw(),
                caller.tid.raw()
            );
        }
        let directory_required = path.ends_with('/') || path.ends_with("/.");
        self.filesystem.acquire(
            &normalized,
            directory_required,
            self.context.proc_caller,
            host_open,
            |candidate| {
                // Only the captured thread's directory may select its retained
                // executable or descriptors; another thread is not this caller.
                let thread_path = self.context.proc_caller.and_then(|caller| {
                    let prefix = format!("/proc/{}/task/{}/", caller.pid.raw(), caller.tid.raw());
                    candidate
                        .strip_prefix(&prefix)
                        .map(|tail| format!("/proc/{}/{tail}", caller.pid.raw()))
                });
                let candidate = thread_path.as_deref().unwrap_or(candidate);
                let source = if proc_self_magic_link(candidate, visible) == Some("exe") {
                    Some(
                        self.context
                            .executable
                            .clone()
                            .ok_or(ExecSourceError::Linux(carrick_abi::LINUX_ENOENT)),
                    )
                } else {
                    proc_self_fd_number(candidate, visible).map(|fd| {
                        let fd = crate::kernel::FileSlotNumber::for_open_fd(fd)
                            .map_err(|_| ExecSourceError::Linux(carrick_abi::LINUX_ENOENT))?;
                        self.context.descriptors.source(fd)
                    })
                };
                source.map(|source| {
                    source.and_then(|source| {
                        if directory_required {
                            Err(ExecSourceError::Linux(carrick_abi::LINUX_ENOTDIR))
                        } else {
                            Ok(source)
                        }
                    })
                })
            },
        )
    }

    pub fn check_source(&self, source: &ExecSource) -> Result<(), LinuxErrno> {
        source.exec_access_errno(self.context.fsuid, self.context.fsgid)
    }

    pub fn notify_exec(&self, path: &str) {
        let Some(caller) = self.context.proc_caller else {
            return;
        };
        self.filesystem.fanotify.notify(
            path,
            carrick_abi::LinuxFanotifyEvents::OPEN | carrick_abi::LinuxFanotifyEvents::OPEN_EXEC,
            false,
            caller.pid.raw() as i32,
            caller.pid.raw() as i32,
        );
    }

    pub fn with_cache<E>(
        &self,
        key: Option<String>,
        build: impl FnOnce() -> Result<crate::memory::AddressSpace, E>,
    ) -> Result<crate::memory::AddressSpace, E> {
        self.filesystem.with_cache(key, build)
    }
}

impl ExecFilesystem {
    fn acquire(
        &self,
        path: &str,
        directory_required: bool,
        proc_caller: Option<super::fs::pathres::RetainedProcCaller>,
        host_open: Option<&ExecHostFileService<'_>>,
        special: impl Fn(&str) -> Option<Result<ExecSource, ExecSourceError>>,
    ) -> Result<ExecSource, ExecSourceError> {
        // A retained magic source is authoritative even in bare-run mode.
        if let Some(source) = special(path) {
            return source;
        }
        let acquire = || {
            super::fs::check_path_length(path).map_err(ExecSourceError::Linux)?;
            let observations = std::cell::RefCell::default();
            let paths = super::fs::pathres::LayeredPathView {
                rootfs: &self.rootfs,
                mounts: &self.mounts,
                proc_caller,
                resolve_observations: &observations,
            };
            if paths.symlink_follow_budget_exceeded(path) {
                return Err(ExecSourceError::Linux(carrick_abi::LINUX_ELOOP));
            }
            let walked = paths
                .resolve_dotdot_symlink_aware("/", path)
                .map_err(ExecSourceError::Linux)?;
            let (resolved, retained) = paths
                .canonicalize_with_source(&walked, &special)
                .map_err(ExecSourceError::Linux)?;
            if let Some(source) = retained {
                // A magic source was selected. Its refusal is authoritative,
                // even if the original spelling was a non-proc symlink.
                return Ok(source);
            }
            if paths
                .layered_lstat(&resolved)
                .is_ok_and(|md| md.kind == carrick_vfs::rootfs::RootFsEntryKind::Directory)
            {
                return Err(ExecSourceError::Linux(carrick_abi::LINUX_EACCES));
            }
            if directory_required {
                return Err(ExecSourceError::Linux(carrick_abi::LINUX_ENOTDIR));
            }
            self.acquire_at(&resolved)
                .map(Ok)
                .map_err(ExecSourceError::Host)
        };
        match acquire() {
            Ok(source) => source,
            Err(error) => {
                if !self.host_fallback || path.starts_with("/proc/") {
                    return Err(error);
                }
                let Some(open) = host_open else {
                    return Err(error);
                };
                let file = open(path).map_err(ExecSourceError::Host)?;
                if directory_required && !file.metadata().map_err(ExecSourceError::Host)?.is_dir() {
                    return Err(ExecSourceError::Linux(carrick_abi::LINUX_ENOTDIR));
                }
                ExecSource::host(file, path.to_owned()).map_err(ExecSourceError::Host)
            }
        }
    }
}

impl SyscallDispatcher {
    pub fn exec_filesystem(&self) -> ExecFilesystem {
        ExecFilesystem {
            rootfs: Arc::clone(&self.fs.rootfs_vfs),
            mounts: Arc::clone(&self.fs.vfs_mounts),
            cache: Arc::clone(&self.fs.hvpatch_exec_cache),
            fanotify: self.fs.fanotify_registry.clone(),
            host_fallback: self.exec_host_fs_fallback(),
        }
    }

    pub fn capture_exec_files(
        &self,
        context: &crate::kernel::KernelContext,
    ) -> Result<ExecFiles, LinuxErrno> {
        let binding = self.kernel_binding.read();
        if binding.task_key() != context.task().key()
            || !Arc::ptr_eq(binding.kernel(), context.kernel())
        {
            return Err(carrick_abi::LINUX_ESRCH);
        }
        let live = binding
            .capture(context.thread().key().tid)
            .map_err(|_| carrick_abi::LINUX_ESRCH)?;
        if !Arc::ptr_eq(live.task(), context.task())
            || !Arc::ptr_eq(live.thread(), context.thread())
            || !Arc::ptr_eq(live.shared(), context.shared())
            || !Arc::ptr_eq(live.resources(), context.resources())
        {
            return Err(carrick_abi::LINUX_ESRCH);
        }
        let credentials = context.resources().credentials();
        Ok(ExecFiles::new(
            self.exec_filesystem(),
            ExecFileContext {
                caller: ExecCaller::Host {
                    task: context.task().key(),
                    thread: context.thread().key(),
                    mm: context.shared().mm().id(),
                    execution: context.thread().execution_state().generation(),
                },
                proc_caller: super::fs::proc_synthetic::proc_visible_self(context)
                    .zip(crate::namespace::pid::ns_visible_guest_tid(context))
                    .map(|(pid, tid)| super::fs::pathres::RetainedProcCaller {
                        pid: super::NsPid(pid as i32),
                        tid: super::NsPid(tid as i32),
                    }),
                cwd: context.resources().fs_context().cwd(),
                fsuid: credentials.fsuid,
                fsgid: credentials.fsgid,
                executable: self
                    .current_executable()
                    .map(|current| current.source().clone()),
                descriptors: Arc::new(HostExecFdSources(context.resources().files())),
            },
        ))
    }
}

impl ExecFilesystem {
    fn acquire_at(&self, path: &str) -> std::io::Result<ExecSource> {
        use carrick_vfs::fs_backend::OverlayEntryKind;

        match self.rootfs.overlay.lookup_kind(path) {
            Some(OverlayEntryKind::File) => {
                if let Some(file) = self.rootfs.overlay.open_file_readonly(path) {
                    return ExecSource::host(file, path.to_owned());
                }
                let entry = self
                    .rootfs
                    .overlay
                    .shared_file_entry(path, false)
                    .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))?;
                if let Some(object) = entry.object {
                    return Ok(ExecSource::shared_object(object, path.to_owned()));
                }
                return Ok(ExecSource::shared(
                    super::executable_authority::materialize_shared(entry.contents.clone()),
                    entry.contents.object_id,
                    path.to_owned(),
                    entry.metadata.mode,
                    carrick_abi::NsUid::ROOT,
                    carrick_abi::NsGid::ROOT,
                ));
            }
            Some(OverlayEntryKind::Dir) => {
                return Err(std::io::Error::from_raw_os_error(libc::EACCES));
            }
            Some(OverlayEntryKind::Deleted) => {
                return Err(std::io::Error::from_raw_os_error(libc::ENOENT));
            }
            None => {}
        }

        if let Some(rootfs) = self.rootfs.rootfs.as_ref() {
            if let Some(file) = rootfs.open_file_readonly(path) {
                return ExecSource::host(file, path.to_owned());
            }
            if let Ok(bytes) = rootfs.read_shared(path) {
                let metadata = rootfs
                    .metadata(path)
                    .map_err(|_| std::io::Error::from_raw_os_error(libc::ENOENT))?;
                return Ok(ExecSource::shared(
                    bytes,
                    carrick_vfs::fs_backend::fresh_file_object_id(),
                    path.to_owned(),
                    metadata.mode,
                    carrick_abi::NsUid::ROOT,
                    carrick_abi::NsGid::ROOT,
                ));
            }
        }

        if let Some((bytes, metadata)) = self.mounts.resolve(path).and_then(|mount| {
            let metadata = mount.vfs.lookup(path).ok()?;
            let bytes = mount.vfs.read_file(path).ok()?;
            Some((bytes, metadata))
        }) {
            return Ok(ExecSource::shared(
                bytes.into(),
                carrick_vfs::fs_backend::fresh_file_object_id(),
                path.to_owned(),
                metadata.mode,
                carrick_abi::NsUid::new(metadata.uid),
                carrick_abi::NsGid::new(metadata.gid),
            ));
        }

        Err(std::io::Error::from_raw_os_error(libc::ENOENT))
    }
}

impl ExecFilesystem {
    pub fn with_cache<E>(
        &self,
        key: Option<String>,
        build: impl FnOnce() -> Result<crate::memory::AddressSpace, E>,
    ) -> Result<crate::memory::AddressSpace, E> {
        let Some(key) = key else {
            return build();
        };
        let slot = {
            let mut cache = self.cache.lock();
            std::sync::Arc::clone(
                cache
                    .entry(key.clone())
                    .or_insert_with(|| std::sync::Arc::new(parking_lot::Mutex::new(None))),
            )
        };
        let mut prepared = slot.lock();
        if let Some(image) = prepared.as_ref() {
            return Ok(image.clone());
        }
        let image = match build() {
            Ok(image) => image,
            Err(error) => {
                // A failed load is not cacheable. Remove its pending slot while
                // it is still locked so a later lookup creates a fresh build.
                let mut cache = self.cache.lock();
                if cache
                    .get(&key)
                    .is_some_and(|current| std::sync::Arc::ptr_eq(current, &slot))
                {
                    cache.remove(&key);
                }
                return Err(error);
            }
        };
        *prepared = Some(image.clone());
        drop(prepared);

        const MAX_PREPARED_EXEC_IMAGES: usize = 16;
        let mut cache = self.cache.lock();
        while cache.len() > MAX_PREPARED_EXEC_IMAGES {
            // Do not evict an in-flight builder: its key must remain available
            // to concurrent callers. The transient excess is at most the
            // number of simultaneous distinct builds and drains as they end.
            let evicted = cache.iter().find_map(|(candidate, slot)| {
                (candidate != &key && slot.try_lock().is_some_and(|ready| ready.is_some()))
                    .then(|| candidate.clone())
            });
            let Some(evicted) = evicted else { break };
            cache.remove(&evicted);
        }
        Ok(image)
    }
}

pub(super) fn resolve_exec_path(path: &str, cwd: &str) -> String {
    if path.starts_with('/') {
        super::normalize_abs_path(path)
    } else {
        super::normalize_abs_path(&format!("{}/{}", cwd.trim_end_matches('/'), path))
    }
}
