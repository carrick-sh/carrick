//! Retained executable-file services. No operation captures a host task or
//! consults the executor's current resource scope.
use std::sync::Arc;

use carrick_abi::{LinuxErrno, NsGid, NsUid};

use super::SyscallDispatcher;
use super::executable_authority::{ExecSource, ExecSourceError};

/// Identity attached by the owner at admission. The host adapter disappears
/// with host exec ownership; it uses the same file capability implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecCaller {
    Service(carrick_core_abi::service::ServiceIdentity),
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
    fn source(&self, fd: crate::kernel::FileSlotNumber) -> Option<ExecFdSource>;
}

pub enum ExecFdSource {
    Retained(ExecSource),
    Path(String),
}

struct HostExecFdSources(Arc<crate::kernel::FileTable>);
impl ExecFdSources for HostExecFdSources {
    fn source(&self, fd: crate::kernel::FileSlotNumber) -> Option<ExecFdSource> {
        let _lease = self.0.acquire_functional_lease()?;
        let file = self.0.read_open_files().get(&fd.raw()).cloned()?;
        if let Some(source) = file.description.retained_exec_source() {
            return Some(ExecFdSource::Retained(source));
        }
        file.description.inspect_kind(|open| {
            open.open_path()
                .map(|path| ExecFdSource::Path(path.to_owned()))
        })?
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
pub struct ExecFileContext {
    pub caller: ExecCaller,
    pub visible_pid: Option<super::NsPid>,
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
    pub fn new(filesystem: ExecFilesystem, context: ExecFileContext) -> Self {
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
        resolve_exec_path(path, &self.context.cwd)
    }

    pub fn acquire(&self, path: &str) -> Result<ExecSource, ExecSourceError> {
        use super::fs::proc_synthetic::{proc_self_fd_number, proc_self_magic_link};
        let path = self.resolve_path(path);
        let visible = self
            .context
            .visible_pid
            .and_then(|pid| u32::try_from(pid.raw()).ok());
        if proc_self_magic_link(&path, visible) == Some("exe") {
            return self
                .context
                .executable
                .clone()
                .ok_or(ExecSourceError::Linux(carrick_abi::LINUX_ENOENT));
        }
        let path = if let Some(fd) = proc_self_fd_number(&path, visible) {
            let fd = crate::kernel::FileSlotNumber::for_open_fd(fd)
                .map_err(|_| ExecSourceError::Linux(carrick_abi::LINUX_ENOENT))?;
            match self.context.descriptors.source(fd) {
                Some(ExecFdSource::Retained(source)) => return Ok(source),
                Some(ExecFdSource::Path(path)) => path,
                None => return Err(ExecSourceError::Linux(carrick_abi::LINUX_ENOENT)),
            }
        } else {
            path
        };
        self.filesystem.acquire(&path)
    }

    pub fn check_source(&self, source: &ExecSource) -> Result<(), LinuxErrno> {
        source.exec_access_errno(self.context.fsuid, self.context.fsgid)
    }

    pub fn read_interpreter(&self, path: &str) -> Option<Vec<u8>> {
        self.acquire(path).ok()?.read_all().ok()
    }

    pub fn notify_exec(&self, path: &str) {
        let Some(pid) = self.context.visible_pid else {
            return;
        };
        self.filesystem.fanotify.notify(
            path,
            carrick_abi::LinuxFanotifyEvents::OPEN | carrick_abi::LinuxFanotifyEvents::OPEN_EXEC,
            false,
            pid.raw() as i32,
            pid.raw() as i32,
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
    fn acquire(&self, path: &str) -> Result<ExecSource, ExecSourceError> {
        let acquire = || {
            super::fs::check_path_length(path).map_err(ExecSourceError::Linux)?;
            let observations = std::cell::RefCell::default();
            let paths = super::fs::pathres::LayeredPathView {
                rootfs: &self.rootfs,
                mounts: &self.mounts,
                resolve_observations: &observations,
            };
            let resolved = paths
                .canonicalize_following(path)
                .map_err(ExecSourceError::Linux)?;
            if paths
                .layered_lstat(&resolved)
                .is_ok_and(|md| md.kind == carrick_vfs::rootfs::RootFsEntryKind::Directory)
            {
                return Err(ExecSourceError::Linux(carrick_abi::LINUX_EACCES));
            }
            self.acquire_at(&resolved).map_err(ExecSourceError::Host)
        };
        acquire().or_else(|error| {
            if !self.host_fallback {
                return Err(error);
            }
            let file = std::fs::File::open(path).map_err(ExecSourceError::Host)?;
            ExecSource::host(file, path.to_owned()).map_err(ExecSourceError::Host)
        })
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

    pub fn capture_exec_files(&self, context: &crate::kernel::KernelContext) -> ExecFiles {
        let credentials = context.resources().credentials();
        ExecFiles::new(
            self.exec_filesystem(),
            ExecFileContext {
                caller: ExecCaller::Host {
                    task: context.task().key(),
                    thread: context.thread().key(),
                    mm: context.shared().mm().id(),
                    execution: context.thread().execution_state().generation(),
                },
                visible_pid: super::fs::proc_synthetic::proc_visible_self(context)
                    .map(|pid| super::NsPid(pid as i32)),
                cwd: context.resources().fs_context().cwd(),
                fsuid: credentials.fsuid,
                fsgid: credentials.fsgid,
                executable: self
                    .current_executable()
                    .map(|current| current.source().clone()),
                descriptors: Arc::new(HostExecFdSources(context.resources().files())),
            },
        )
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
