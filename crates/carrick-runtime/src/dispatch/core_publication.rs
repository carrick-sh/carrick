//! Core dump publication in the guest filesystem namespace.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::vfs::ProcMapsEntry;

use super::{SyscallDispatcher, linux_task_name_to_string, mem};

#[derive(Clone, Debug)]
pub(crate) struct CoreProcessSnapshot {
    pub identity: crate::core_dump::ProcessIdentity,
    pub auxv: Vec<(u64, u64)>,
    pub maps: Vec<ProcMapsEntry>,
    pub file_mappings: Vec<crate::core_dump::FileMapping>,
    /// `MADV_DONTDUMP` ranges: still listed as PT_LOAD, contents elided.
    pub dump_omitted: Vec<(u64, u64)>,
    pub cwd: String,
    pub rlimit_core: u64,
    pub dumpable: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct CorePublication {
    pub path: String,
    pub bytes: usize,
    pub generation: u64,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CorePublicationError {
    #[error("core snapshot lacks authoritative Kernel identity: {0}")]
    KernelIdentity(String),
    #[error("core snapshot auxv is not a sequence of 16-byte entries")]
    MalformedAuxv,
    #[error("core publication failpoint {0}")]
    Failpoint(&'static str),
    #[error("core backend {operation} failed for {path}: {error:?}")]
    Backend {
        operation: &'static str,
        path: String,
        error: crate::fs_backend::BackendError,
    },
    #[error("core backend did not rename {from} to {to}")]
    RenameMissing { from: String, to: String },
    #[error("core fsync failed for {path}: {errno}")]
    Fsync { path: String, errno: i32 },
    #[error(
        "core cleanup failed for {path}: remove error {remove_error:?}; artifact_invalidated={artifact_invalidated}"
    )]
    Cleanup {
        path: String,
        remove_error: crate::fs_backend::BackendError,
        artifact_invalidated: bool,
    },
}

fn pwrite_all_host_fd(
    fd: i32,
    mut bytes: &[u8],
    mut offset: u64,
) -> Result<(), crate::linux_abi::LinuxErrno> {
    while !bytes.is_empty() {
        let off = libc::off_t::try_from(offset).map_err(|_| crate::linux_abi::LINUX_EFBIG)?;
        // BLOCKING-IO-OK: core dump publication writes to an unshared temporary host file
        let rc =
            unsafe { libc::pwrite(fd, bytes.as_ptr().cast::<libc::c_void>(), bytes.len(), off) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            let raw_errno = err.raw_os_error().unwrap_or(libc::EIO);
            return Err(crate::host_to_linux_errno(raw_errno));
        }
        if rc == 0 {
            return Err(crate::linux_abi::LINUX_EIO);
        }
        let written = rc as usize;
        bytes = &bytes[written..];
        offset = offset.saturating_add(written as u64);
    }
    Ok(())
}

impl SyscallDispatcher {
    pub(crate) fn core_process_snapshot(
        &self,
        context: &crate::kernel::KernelContext,
    ) -> Result<CoreProcessSnapshot, CorePublicationError> {
        let identity = context
            .kernel()
            .task_identity(context.task().key().id)
            .map_err(|error| CorePublicationError::KernelIdentity(error.to_string()))?;
        let pid = u32::try_from(identity.task.id.raw())
            .ok()
            .and_then(|id| crate::namespace::pid::kernel_to_ns_for(context, id))
            .and_then(|id| i32::try_from(id).ok())
            .ok_or_else(|| {
                CorePublicationError::KernelIdentity(
                    "process is outside the caller's container namespace".to_owned(),
                )
            })?;
        let ppid = identity.parent.map_or(0, |parent| {
            u32::try_from(parent.id.raw())
                .ok()
                .and_then(|id| crate::namespace::pid::kernel_to_ns_for(context, id))
                .and_then(|id| i32::try_from(id).ok())
                .unwrap_or(0)
        });
        let pgrp = crate::namespace::pid::process_group_to_ns_for(context, identity.process_group)
            .and_then(|id| i32::try_from(id).ok())
            .ok_or_else(|| {
                CorePublicationError::KernelIdentity(
                    "process group is outside the caller's container namespace".to_owned(),
                )
            })?;
        let session = crate::namespace::pid::session_to_ns_for(context, identity.session)
            .and_then(|id| i32::try_from(id).ok())
            .ok_or_else(|| {
                CorePublicationError::KernelIdentity(
                    "session is outside the caller's container namespace".to_owned(),
                )
            })?;
        let proc = self.proc.lock();
        let mem_authority_41 = self.mem();
        let mem = mem_authority_41.lock();
        if !mem.linux_auxv_image.len().is_multiple_of(16) {
            return Err(CorePublicationError::MalformedAuxv);
        }
        let mut auxv = Vec::with_capacity(mem.linux_auxv_image.len() / 16);
        for entry in mem.linux_auxv_image.chunks_exact(16) {
            let key = u64::from_le_bytes(entry[..8].try_into().unwrap_or([0; 8]));
            let value = u64::from_le_bytes(entry[8..].try_into().unwrap_or([0; 8]));
            if key == 0 {
                break;
            }
            auxv.push((key, value));
        }
        let comm = linux_task_name_to_string(&proc.task_name);
        let psargs = proc.argv.join(" ");
        let dumpable = context.task().dumpable() == crate::kernel::DumpableMode::User;
        let maps = mem::project_core_maps(&mem);
        let file_mappings = mem.core_file_mappings.clone();
        let dump_omitted = mem
            .semantic_vmas
            .iter()
            .filter(|vma| vma.dump_policy == carrick_abi::VmaDumpPolicy::Omit)
            .map(|vma| (vma.start, vma.end))
            .collect::<Vec<_>>();
        let cwd = context.resources().fs_context().cwd();
        drop(mem);
        drop(proc);
        let rlimit_core = self
            .effective_resource_limit(crate::linux_abi::LINUX_RLIMIT_CORE)
            .rlim_cur;
        Ok(CoreProcessSnapshot {
            identity: crate::core_dump::ProcessIdentity {
                pid,
                ppid,
                pgrp,
                session,
                comm: comm.clone(),
                psargs,
            },
            auxv,
            maps,
            file_mappings,
            dump_omitted,
            cwd,
            rlimit_core,
            dumpable,
        })
    }

    /// Publish an already-bounded core in the guest filesystem namespace.
    /// The same-directory temporary is never a valid final artifact: every
    /// error removes it, and the only success edge is one atomic rename.
    pub(crate) fn publish_core_atomic(
        &self,
        snapshot: &CoreProcessSnapshot,
        generation: u64,
        payload: impl Into<crate::core_dump::CorePayload>,
    ) -> Result<CorePublication, CorePublicationError> {
        let failpoint = std::env::var("CARRICK_CORE_FAILPOINT").ok();
        self.publish_core_atomic_with_failpoint(snapshot, generation, payload, failpoint.as_deref())
    }

    fn publish_core_atomic_with_failpoint(
        &self,
        snapshot: &CoreProcessSnapshot,
        generation: u64,
        payload: impl Into<crate::core_dump::CorePayload>,
        failpoint: Option<&str>,
    ) -> Result<CorePublication, CorePublicationError> {
        let payload = payload.into();
        let resolved_cwd = self
            .canonicalize_following(&snapshot.cwd)
            .unwrap_or_else(|_| snapshot.cwd.clone());
        let final_path = if resolved_cwd == "/" {
            "/core".to_owned()
        } else {
            format!("{}/core", resolved_cwd.trim_end_matches('/'))
        };
        let temp_path = format!(
            "{}.carrick-tmp-{}-{generation}",
            final_path, snapshot.identity.pid
        );

        let m_temp = self.fs.vfs_mounts.resolve(&temp_path);
        let m_final = self.fs.vfs_mounts.resolve(&final_path);

        match (m_temp, m_final) {
            (Some(m_temp), Some(m_final)) => {
                if m_temp.point != m_final.point {
                    return Err(CorePublicationError::Backend {
                        operation: "rename",
                        path: final_path,
                        error: crate::fs_backend::BackendError::Host(crate::linux_abi::LINUX_EXDEV),
                    });
                }
                let vfs = m_temp.vfs;
                let temp_vfs_path = m_temp.full_path.clone();
                let final_vfs_path = m_final.full_path.clone();

                self.cleanup_core_artifact(&temp_path)?;
                if failpoint == Some("before-create") {
                    return Err(CorePublicationError::Failpoint("before-create"));
                }
                if failpoint == Some("unwritable-path") {
                    return Err(CorePublicationError::Failpoint("unwritable-path"));
                }

                let open_flags = crate::vfs::OpenFlags {
                    write: true,
                    create: true,
                    excl: true,
                    nofollow: true,
                    cloexec: true,
                    mode: 0o600,
                    ..Default::default()
                };
                let ctx = crate::vfs::OpenContext::default();
                let handle = vfs
                    .open(&temp_vfs_path, open_flags, &ctx)
                    .map_err(|errno| CorePublicationError::Backend {
                        operation: "create",
                        path: temp_path.clone(),
                        error: crate::fs_backend::BackendError::Host(errno),
                    })?;

                let bytes_len = usize::try_from(payload.emitted_bytes()).unwrap_or(usize::MAX);
                let publication = (|| {
                    match handle {
                        crate::vfs::VfsHandle::HostFd { host_fd, .. } => {
                            // SAFETY: transfers ownership of host_fd to scoped_fd so it is closed on scope exit.
                            let scoped_fd = unsafe { OwnedFd::from_raw_fd(host_fd) };
                            if failpoint == Some("short-write") {
                                return Err(CorePublicationError::Failpoint("short-write"));
                            }
                            pwrite_all_host_fd(scoped_fd.as_raw_fd(), &payload.header, 0).map_err(
                                |errno| CorePublicationError::Backend {
                                    operation: "write",
                                    path: temp_path.clone(),
                                    error: crate::fs_backend::BackendError::Host(errno),
                                },
                            )?;
                            for ext in &payload.extents {
                                pwrite_all_host_fd(scoped_fd.as_raw_fd(), &ext.bytes, ext.offset)
                                    .map_err(|errno| CorePublicationError::Backend {
                                    operation: "write",
                                    path: temp_path.clone(),
                                    error: crate::fs_backend::BackendError::Host(errno),
                                })?;
                            }
                            if payload.logical_size > 0 {
                                let off =
                                    libc::off_t::try_from(payload.logical_size).map_err(|_| {
                                        CorePublicationError::Backend {
                                            operation: "ftruncate",
                                            path: temp_path.clone(),
                                            error: crate::fs_backend::BackendError::Host(
                                                crate::linux_abi::LINUX_EFBIG,
                                            ),
                                        }
                                    })?;
                                let rc = unsafe { libc::ftruncate(scoped_fd.as_raw_fd(), off) };
                                if rc < 0 {
                                    let raw_errno = std::io::Error::last_os_error()
                                        .raw_os_error()
                                        .unwrap_or(libc::EIO);
                                    return Err(CorePublicationError::Backend {
                                        operation: "ftruncate",
                                        path: temp_path.clone(),
                                        error: crate::fs_backend::BackendError::Host(
                                            crate::host_to_linux_errno(raw_errno),
                                        ),
                                    });
                                }
                            }
                            if failpoint == Some("fsync") {
                                return Err(CorePublicationError::Failpoint("fsync"));
                            }
                            let fsync_res = unsafe { libc::fsync(scoped_fd.as_raw_fd()) };
                            if fsync_res < 0 {
                                let errno =
                                    std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                                return Err(CorePublicationError::Fsync {
                                    path: temp_path.clone(),
                                    errno,
                                });
                            }
                            drop(scoped_fd);
                        }
                        crate::vfs::VfsHandle::InMemoryFile {
                            contents,
                            writable: true,
                            ..
                        } => {
                            if failpoint == Some("short-write") {
                                return Err(CorePublicationError::Failpoint("short-write"));
                            }
                            let logical_size =
                                usize::try_from(payload.logical_size).map_err(|_| {
                                    CorePublicationError::Backend {
                                        operation: "write",
                                        path: temp_path.clone(),
                                        error: crate::fs_backend::BackendError::Invalid,
                                    }
                                })?;
                            let mut lock = contents.write();
                            lock.set_len(logical_size);
                            lock.write_range(0, &payload.header).map_err(|_| {
                                CorePublicationError::Backend {
                                    operation: "write",
                                    path: temp_path.clone(),
                                    error: crate::fs_backend::BackendError::Invalid,
                                }
                            })?;
                            for ext in &payload.extents {
                                let offset = usize::try_from(ext.offset).map_err(|_| {
                                    CorePublicationError::Backend {
                                        operation: "write",
                                        path: temp_path.clone(),
                                        error: crate::fs_backend::BackendError::Invalid,
                                    }
                                })?;
                                lock.write_range(offset, &ext.bytes).map_err(|_| {
                                    CorePublicationError::Backend {
                                        operation: "write",
                                        path: temp_path.clone(),
                                        error: crate::fs_backend::BackendError::Invalid,
                                    }
                                })?;
                            }
                            if failpoint == Some("fsync") {
                                return Err(CorePublicationError::Failpoint("fsync"));
                            }
                        }
                        _ => {
                            return Err(CorePublicationError::Backend {
                                operation: "create",
                                path: temp_path.clone(),
                                error: crate::fs_backend::BackendError::Host(
                                    crate::linux_abi::LINUX_EROFS,
                                ),
                            });
                        }
                    }

                    if failpoint == Some("rename") {
                        return Err(CorePublicationError::Failpoint("rename"));
                    }
                    vfs.rename(&temp_vfs_path, &final_vfs_path)
                        .map_err(|errno| CorePublicationError::Backend {
                            operation: "rename",
                            path: final_path.clone(),
                            error: crate::fs_backend::BackendError::Host(errno),
                        })?;
                    if failpoint == Some("post-publication") {
                        self.cleanup_core_artifact(&final_path)?;
                        return Err(CorePublicationError::Failpoint("post-publication"));
                    }
                    Ok(CorePublication {
                        path: final_path.clone(),
                        bytes: bytes_len,
                        generation,
                    })
                })();
                if publication.is_err() {
                    self.cleanup_core_artifact(&temp_path)?;
                }
                publication
            }
            (None, None) => {
                let backend = &self.fs.rootfs_vfs.overlay;
                self.cleanup_core_artifact(&temp_path)?;
                if failpoint == Some("before-create") {
                    return Err(CorePublicationError::Failpoint("before-create"));
                }
                if failpoint == Some("unwritable-path") {
                    return Err(CorePublicationError::Failpoint("unwritable-path"));
                }
                backend
                    .create_file(&temp_path)
                    .map_err(|error| CorePublicationError::Backend {
                        operation: "create",
                        path: temp_path.clone(),
                        error,
                    })?;
                let bytes_len = usize::try_from(payload.emitted_bytes()).unwrap_or(usize::MAX);
                let publication = (|| {
                    if failpoint == Some("short-write") {
                        return Err(CorePublicationError::Failpoint("short-write"));
                    }
                    let logical_size = usize::try_from(payload.logical_size).map_err(|_| {
                        CorePublicationError::Backend {
                            operation: "write",
                            path: temp_path.clone(),
                            error: crate::fs_backend::BackendError::Invalid,
                        }
                    })?;
                    let initial_size = logical_size.max(payload.header.len());
                    backend
                        .write_file_range(&temp_path, 0, &payload.header, initial_size)
                        .map_err(|error| CorePublicationError::Backend {
                            operation: "write",
                            path: temp_path.clone(),
                            error,
                        })?;
                    for ext in &payload.extents {
                        let offset = usize::try_from(ext.offset).map_err(|_| {
                            CorePublicationError::Backend {
                                operation: "write",
                                path: temp_path.clone(),
                                error: crate::fs_backend::BackendError::Invalid,
                            }
                        })?;
                        backend
                            .write_file_range(&temp_path, offset, &ext.bytes, logical_size)
                            .map_err(|error| CorePublicationError::Backend {
                                operation: "write",
                                path: temp_path.clone(),
                                error,
                            })?;
                    }
                    if failpoint == Some("fsync") {
                        return Err(CorePublicationError::Failpoint("fsync"));
                    }
                    if let Some(fd) =
                        backend.reopen_for_durability(&temp_path).map_err(|error| {
                            CorePublicationError::Backend {
                                operation: "reopen-for-fsync",
                                path: temp_path.clone(),
                                error,
                            }
                        })?
                    {
                        // SAFETY: transfers ownership of fd to scoped_fd so it is closed on scope exit.
                        let scoped_fd = unsafe { OwnedFd::from_raw_fd(fd) };
                        let result = unsafe { libc::fsync(scoped_fd.as_raw_fd()) };
                        if result < 0 {
                            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                            return Err(CorePublicationError::Fsync {
                                path: temp_path.clone(),
                                errno,
                            });
                        }
                        drop(scoped_fd);
                    }
                    if failpoint == Some("rename") {
                        return Err(CorePublicationError::Failpoint("rename"));
                    }
                    let renamed = backend
                        .rename_overlay_entry(&temp_path, &final_path)
                        .map_err(|error| CorePublicationError::Backend {
                            operation: "rename",
                            path: final_path.clone(),
                            error,
                        })?;
                    if !renamed {
                        return Err(CorePublicationError::RenameMissing {
                            from: temp_path.clone(),
                            to: final_path.clone(),
                        });
                    }
                    if failpoint == Some("post-publication") {
                        self.cleanup_core_artifact(&final_path)?;
                        return Err(CorePublicationError::Failpoint("post-publication"));
                    }
                    Ok(CorePublication {
                        path: final_path.clone(),
                        bytes: bytes_len,
                        generation,
                    })
                })();
                if publication.is_err() {
                    self.cleanup_core_artifact(&temp_path)?;
                }
                publication
            }
            _ => Err(CorePublicationError::Backend {
                operation: "rename",
                path: final_path,
                error: crate::fs_backend::BackendError::Host(crate::linux_abi::LINUX_EXDEV),
            }),
        }
    }

    /// Remove a core publication artifact transactionally. If a durable
    /// backend cannot unlink it, first destroy the serialized ELF identity and
    /// retry. A persistent failure remains explicit, while a path that survives
    /// cleanup cannot masquerade as a valid published core.
    fn cleanup_core_artifact(&self, path: &str) -> Result<(), CorePublicationError> {
        if let Some(m) = self.fs.vfs_mounts.resolve(path) {
            let is_regular_file = match m.vfs.lookup_nofollow(&m.full_path) {
                Ok(meta) => meta.kind == crate::vfs::EntryKind::File,
                Err(e) if e == crate::linux_abi::LINUX_ENOENT => return Ok(()),
                Err(_) => false,
            };
            match m.vfs.unlink(&m.full_path) {
                Ok(()) => Ok(()),
                Err(errno) if errno == crate::linux_abi::LINUX_ENOENT => Ok(()),
                Err(remove_errno) => {
                    let artifact_invalidated = if is_regular_file {
                        let open_flags = crate::vfs::OpenFlags {
                            write: true,
                            trunc: true,
                            nofollow: true,
                            cloexec: true,
                            ..Default::default()
                        };
                        let ctx = crate::vfs::OpenContext::default();
                        match m.vfs.open(&m.full_path, open_flags, &ctx) {
                            Ok(crate::vfs::VfsHandle::HostFd { host_fd, .. }) => {
                                // SAFETY: transfers ownership of host_fd to _scoped so it is closed on scope exit.
                                let _scoped = unsafe { OwnedFd::from_raw_fd(host_fd) };
                                true
                            }
                            Ok(crate::vfs::VfsHandle::InMemoryFile {
                                contents,
                                writable: true,
                                ..
                            }) => {
                                contents.write().clear();
                                true
                            }
                            _ => false,
                        }
                    } else {
                        false
                    };
                    if artifact_invalidated && m.vfs.unlink(&m.full_path).is_ok() {
                        return Ok(());
                    }
                    Err(CorePublicationError::Cleanup {
                        path: path.to_owned(),
                        remove_error: crate::fs_backend::BackendError::Host(remove_errno),
                        artifact_invalidated,
                    })
                }
            }
        } else {
            let backend = &self.fs.rootfs_vfs.overlay;
            let is_regular_file = backend
                .metadata(path)
                .map(|m| m.kind == crate::rootfs::RootFsEntryKind::File)
                .unwrap_or(false);
            match backend.remove_entry_checked(path) {
                Ok(_) => Ok(()),
                Err(remove_error) => {
                    let artifact_invalidated = if is_regular_file {
                        backend.set_file_contents(path, Vec::new()).is_ok()
                    } else {
                        false
                    };
                    if artifact_invalidated && backend.remove_entry_checked(path).is_ok() {
                        return Ok(());
                    }
                    Err(CorePublicationError::Cleanup {
                        path: path.to_owned(),
                        remove_error,
                        artifact_invalidated,
                    })
                }
            }
        }
    }

    /// Remove a renamed core whose matching authoritative wait status did not
    /// commit. Publication ownership is not released by rename alone.
    pub(crate) fn rollback_core_publication(
        &self,
        publication: &CorePublication,
    ) -> Result<(), CorePublicationError> {
        self.cleanup_core_artifact(&publication.path)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::dispatch::blocks_512;

    use super::*;

    #[test]
    fn hvpatch_root_binding_rekeys_prepared_dispatch_mm_to_committed_kernel_mm() {
        let dispatcher = SyscallDispatcher::new();
        let prepared = dispatcher.mm_binding.current.load_full();
        let prepared_mem = Arc::clone(&prepared.mem);
        let (process, context) = crate::hvpatch::process_context_for_tests(41_201);
        let committed_mm = context.shared().mm().id();
        let wrong_raw = committed_mm.raw().checked_add(1).expect("test MM id");
        let wrong_mm = crate::kernel::MmId::from_registry_allocation(
            std::num::NonZeroU64::new(wrong_raw).expect("nonzero test MM id"),
        );
        dispatcher
            .mm_binding
            .current
            .store(Arc::new(prepared.rebind_prepared_root(wrong_mm)));

        dispatcher.bind_hvpatch_process_exact(process, &context, None);

        let rebound = dispatcher.mm_binding.current.load_full();
        assert_eq!(rebound.mm_id, committed_mm);
        assert!(Arc::ptr_eq(&rebound.mem, &prepared_mem));
        assert_eq!(rebound.mutation_coordinator.mm(), committed_mm);
        let executor = dispatcher
            .enter_mm_executor()
            .expect("root executor admission");
        assert_eq!(executor.mm_id(), committed_mm);
    }

    struct FinalCleanupErrorBackend {
        inner: crate::fs_backend::MemoryBackend,
    }

    impl FinalCleanupErrorBackend {
        fn new() -> Self {
            Self {
                inner: crate::fs_backend::MemoryBackend::new(),
            }
        }
    }

    impl crate::fs_backend::FsBackend for FinalCleanupErrorBackend {
        fn lookup(&self, path: &str) -> Option<crate::fs_backend::OverlayEntry> {
            self.inner.lookup(path)
        }

        fn metadata(&self, path: &str) -> Option<crate::rootfs::RootFsMetadata> {
            self.inner.metadata(path)
        }

        fn file_contents(&self, path: &str) -> Option<Vec<u8>> {
            self.inner.file_contents(path)
        }

        fn make_dir(&self, path: &str) -> Result<(), crate::fs_backend::BackendError> {
            self.inner.make_dir(path)
        }

        fn create_file(&self, path: &str) -> Result<(), crate::fs_backend::BackendError> {
            self.inner.create_file(path)
        }

        fn set_file_contents(
            &self,
            path: &str,
            contents: Vec<u8>,
        ) -> Result<(), crate::fs_backend::BackendError> {
            self.inner.set_file_contents(path, contents)
        }

        fn remove_entry(&self, path: &str) -> bool {
            path != "/tmp/coretest/core" && self.inner.remove_entry(path)
        }

        fn remove_entry_checked(
            &self,
            path: &str,
        ) -> Result<bool, crate::fs_backend::BackendError> {
            if path == "/tmp/coretest/core" {
                Err(crate::fs_backend::BackendError::Io)
            } else {
                Ok(self.inner.remove_entry(path))
            }
        }

        fn mark_deleted(&self, path: &str) -> Result<(), crate::fs_backend::BackendError> {
            self.inner.mark_deleted(path)
        }

        fn child_names(
            &self,
            dir: &str,
        ) -> Vec<(String, crate::rootfs::RootFsEntryKind, Option<u64>)> {
            self.inner.child_names(dir)
        }

        fn deleted_child_names(&self, dir: &str) -> Vec<String> {
            self.inner.deleted_child_names(dir)
        }

        fn rename_overlay_entry(
            &self,
            from: &str,
            to: &str,
        ) -> Result<bool, crate::fs_backend::BackendError> {
            self.inner.rename_overlay_entry(from, to)
        }

        fn open_raw_fd(
            &self,
            path: &str,
            write: bool,
            create: bool,
            trunc: bool,
        ) -> crate::fs_backend::HostFdOpen<i32> {
            self.inner.open_raw_fd(path, write, create, trunc)
        }
    }

    fn snapshot() -> CoreProcessSnapshot {
        CoreProcessSnapshot {
            identity: crate::core_dump::ProcessIdentity {
                pid: 91,
                ppid: 1,
                pgrp: 91,
                session: 91,
                comm: "coretest".to_owned(),
                psargs: "coretest".to_owned(),
            },
            auxv: vec![(6, 4096)],
            maps: Vec::new(),
            file_mappings: Vec::new(),
            dump_omitted: Vec::new(),
            cwd: "/tmp/coretest".to_owned(),
            rlimit_core: 4096,
            dumpable: true,
        }
    }

    #[test]
    fn core_publication_routes_to_bind_mount_on_host() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let host_path = temp_dir.path().to_path_buf();
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.fs.vfs_mounts_mut().mount(
            "/evidence",
            Box::new(crate::vfs::BindVfs::new("/evidence", &host_path, false)),
        );
        let mut snapshot = snapshot();
        snapshot.cwd = "/evidence".to_owned();

        let publication = dispatcher
            .publish_core_atomic_with_failpoint(&snapshot, 15, b"bind-mount-core".to_vec(), None)
            .expect("publish to bind mount");

        assert_eq!(publication.path, "/evidence/core");
        assert_eq!(publication.bytes, 15);

        let host_core_file = host_path.join("core");
        assert!(host_core_file.exists(), "host core file must exist");
        let contents = std::fs::read(&host_core_file).expect("read host core");
        assert_eq!(contents, b"bind-mount-core");

        assert!(
            dispatcher
                .fs
                .rootfs_vfs
                .overlay
                .file_contents("/evidence/core")
                .is_none(),
            "rootfs overlay must not contain the core"
        );
    }

    #[test]
    fn core_publication_rejects_read_only_bind_mount() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let host_path = temp_dir.path().to_path_buf();
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.fs.vfs_mounts_mut().mount(
            "/evidence_ro",
            Box::new(crate::vfs::BindVfs::new("/evidence_ro", &host_path, true)),
        );
        let mut snapshot = snapshot();
        snapshot.cwd = "/evidence_ro".to_owned();

        let err = dispatcher
            .publish_core_atomic_with_failpoint(&snapshot, 16, b"must-not-write".to_vec(), None)
            .expect_err("read-only bind mount must refuse publication");

        assert!(
            matches!(
                &err,
                CorePublicationError::Backend {
                    operation: "create",
                    error: crate::fs_backend::BackendError::Host(errno),
                    ..
                } if *errno == crate::linux_abi::LINUX_EROFS
            ),
            "unexpected error: {err:?}"
        );

        assert!(
            !host_path.join("core").exists(),
            "host core file must not exist"
        );
        assert!(
            dispatcher
                .fs
                .rootfs_vfs
                .overlay
                .file_contents("/evidence_ro/core")
                .is_none(),
            "rootfs overlay must not contain the core"
        );
    }

    #[test]
    fn core_publication_on_bind_mount_failpoints_leave_no_artifacts() {
        for failpoint in [
            "before-create",
            "unwritable-path",
            "short-write",
            "fsync",
            "rename",
            "post-publication",
        ] {
            let temp_dir = tempfile::tempdir().expect("tempdir");
            let host_path = temp_dir.path().to_path_buf();
            let mut dispatcher = SyscallDispatcher::new();
            dispatcher.fs.vfs_mounts_mut().mount(
                "/evidence",
                Box::new(crate::vfs::BindVfs::new("/evidence", &host_path, false)),
            );
            let mut snapshot = snapshot();
            snapshot.cwd = "/evidence".to_owned();

            dispatcher
                .publish_core_atomic_with_failpoint(
                    &snapshot,
                    17,
                    b"failpoint-data".to_vec(),
                    Some(failpoint),
                )
                .expect_err(failpoint);

            assert!(
                !host_path.join("core").exists(),
                "final host core after {failpoint}"
            );
            assert!(
                !host_path.join("core.carrick-tmp-91-17").exists(),
                "temporary host file after {failpoint}"
            );
            assert!(
                dispatcher
                    .fs
                    .rootfs_vfs
                    .overlay
                    .file_contents("/evidence/core")
                    .is_none(),
                "final overlay core after {failpoint}"
            );
            assert!(
                dispatcher
                    .fs
                    .rootfs_vfs
                    .overlay
                    .file_contents("/evidence/core.carrick-tmp-91-17")
                    .is_none(),
                "temporary overlay core after {failpoint}"
            );
        }
    }

    #[test]
    fn core_publication_on_bind_mount_rollback_removes_host_artifact() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let host_path = temp_dir.path().to_path_buf();
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.fs.vfs_mounts_mut().mount(
            "/evidence",
            Box::new(crate::vfs::BindVfs::new("/evidence", &host_path, false)),
        );
        let mut snapshot = snapshot();
        snapshot.cwd = "/evidence".to_owned();

        let publication = dispatcher
            .publish_core_atomic_with_failpoint(&snapshot, 18, b"rollback-bind-core".to_vec(), None)
            .expect("publish before rollback");

        assert!(
            host_path.join("core").exists(),
            "host core exists after publish"
        );
        dispatcher
            .rollback_core_publication(&publication)
            .expect("rollback");

        assert!(
            !host_path.join("core").exists(),
            "host core must be removed after rollback"
        );
        assert!(
            !host_path.join("core.carrick-tmp-91-18").exists(),
            "temporary host file must not exist"
        );
        assert!(
            dispatcher
                .fs
                .rootfs_vfs
                .overlay
                .file_contents(&publication.path)
                .is_none(),
            "overlay must remain clean"
        );
    }

    #[test]
    fn core_publication_follows_symlink_cwd_to_bind_mount() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let host_path = temp_dir.path().to_path_buf();
        let real_dir = host_path.join("real_dir");
        std::fs::create_dir(&real_dir).expect("create real_dir");
        std::os::unix::fs::symlink("real_dir", host_path.join("link_dir")).expect("create symlink");

        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.fs.vfs_mounts_mut().mount(
            "/evidence",
            Box::new(crate::vfs::BindVfs::new("/evidence", &host_path, false)),
        );

        let mut snapshot = snapshot();
        snapshot.cwd = "/evidence/link_dir".to_owned();

        let publication = dispatcher
            .publish_core_atomic_with_failpoint(&snapshot, 19, b"symlink-core".to_vec(), None)
            .expect("publish via symlink cwd");

        assert_eq!(publication.path, "/evidence/real_dir/core");
        let host_core = real_dir.join("core");
        assert!(
            host_core.exists(),
            "host core file must exist at resolved target"
        );
        let contents = std::fs::read(host_core).expect("read core");
        assert_eq!(contents, b"symlink-core");
    }

    #[test]
    fn core_publication_rejects_symlink_at_temp_path_without_truncating_target() {
        use std::path::PathBuf;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        struct SymlinkInjectingVfs {
            inner: crate::vfs::BindVfs,
            host_mount_dir: PathBuf,
            inject_temp_name: String,
            victim_file: PathBuf,
            injected: Arc<AtomicBool>,
        }

        impl crate::vfs::Vfs for SymlinkInjectingVfs {
            fn lookup(&self, path: &str) -> Result<crate::vfs::Metadata, crate::vfs::VfsError> {
                self.inner.lookup(path)
            }

            fn lookup_nofollow(
                &self,
                path: &str,
            ) -> Result<crate::vfs::Metadata, crate::vfs::VfsError> {
                self.inner.lookup_nofollow(path)
            }

            fn open(
                &self,
                path: &str,
                flags: crate::vfs::OpenFlags,
                ctx: &crate::vfs::OpenContext<'_>,
            ) -> Result<crate::vfs::VfsHandle, crate::vfs::VfsError> {
                if path.ends_with(&self.inject_temp_name) {
                    let host_link = self.host_mount_dir.join(&self.inject_temp_name);
                    let _ = std::os::unix::fs::symlink(&self.victim_file, &host_link);
                    self.injected.store(true, Ordering::SeqCst);
                }
                self.inner.open(path, flags, ctx)
            }

            fn unlink(&self, path: &str) -> Result<(), crate::vfs::VfsError> {
                self.inner.unlink(path)
            }

            fn rename(&self, from: &str, to: &str) -> Result<(), crate::vfs::VfsError> {
                self.inner.rename(from, to)
            }
        }

        let temp_dir = tempfile::tempdir().expect("tempdir");
        let host_mount = temp_dir.path().join("mount");
        std::fs::create_dir(&host_mount).expect("create mount dir");
        let victim_file = temp_dir.path().join("sensitive_target.txt");
        let victim_bytes = b"CRITICAL_HOST_TARGET_DO_NOT_TRUNCATE";
        std::fs::write(&victim_file, victim_bytes).expect("write victim");

        let injected_flag = Arc::new(AtomicBool::new(false));
        let temp_name = "core.carrick-tmp-91-20".to_string();

        let injecting_vfs = SymlinkInjectingVfs {
            inner: crate::vfs::BindVfs::new("/evidence", &host_mount, false),
            host_mount_dir: host_mount.clone(),
            inject_temp_name: temp_name.clone(),
            victim_file: victim_file.clone(),
            injected: Arc::clone(&injected_flag),
        };

        let mut dispatcher = SyscallDispatcher::new();
        dispatcher
            .fs
            .vfs_mounts_mut()
            .mount("/evidence", Box::new(injecting_vfs));

        let mut snapshot = snapshot();
        snapshot.cwd = "/evidence".to_owned();

        let err = dispatcher
            .publish_core_atomic_with_failpoint(&snapshot, 20, b"malicious-payload".to_vec(), None)
            .expect_err("exclusive create must fail when symlink is injected at temp path");

        assert!(
            injected_flag.load(Ordering::SeqCst),
            "symlink must have been injected during open"
        );
        assert!(
            matches!(
                &err,
                CorePublicationError::Backend {
                    operation: "create",
                    error: crate::fs_backend::BackendError::Host(errno),
                    ..
                } if *errno == crate::linux_abi::LINUX_EEXIST
            ),
            "unexpected error: {err:?}"
        );

        let surviving_bytes = std::fs::read(&victim_file).expect("read victim file");
        assert_eq!(
            surviving_bytes, victim_bytes,
            "victim file must not be truncated or overwritten"
        );
    }

    #[test]
    fn core_publication_cleanup_does_not_truncate_symlink_target_on_unlink_failure() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let host_mount = temp_dir.path().join("mount_ro");
        std::fs::create_dir(&host_mount).expect("create mount dir");
        let victim_file = temp_dir.path().join("sensitive_ro_target.txt");
        let victim_bytes = b"CRITICAL_HOST_TARGET_DO_NOT_TRUNCATE_RO";
        std::fs::write(&victim_file, victim_bytes).expect("write victim");

        let symlink_path = host_mount.join("stale_symlink");
        std::os::unix::fs::symlink(&victim_file, &symlink_path).expect("create symlink");

        let mut dispatcher = SyscallDispatcher::new();
        dispatcher.fs.vfs_mounts_mut().mount(
            "/evidence_ro",
            Box::new(crate::vfs::BindVfs::new("/evidence_ro", &host_mount, true)),
        );

        let err = dispatcher
            .cleanup_core_artifact("/evidence_ro/stale_symlink")
            .expect_err("cleanup on read-only mount must fail without invalidating symlink target");

        assert!(
            matches!(
                &err,
                CorePublicationError::Cleanup {
                    artifact_invalidated: false,
                    ..
                }
            ),
            "cleanup must fail closed with artifact_invalidated=false: {err:?}"
        );

        let surviving_bytes = std::fs::read(&victim_file).expect("read victim file");
        assert_eq!(
            surviving_bytes, victim_bytes,
            "victim file must survive intact without truncation"
        );
    }

    #[test]
    fn atomic_core_publication_has_one_success_edge() {
        let dispatcher = SyscallDispatcher::new();
        let snapshot = snapshot();
        let publication = dispatcher
            .publish_core_atomic_with_failpoint(&snapshot, 7, b"complete".to_vec(), None)
            .expect("publish");
        assert_eq!(publication.path, "/tmp/coretest/core");
        assert_eq!(publication.bytes, 8);
        assert_eq!(
            dispatcher
                .fs
                .rootfs_vfs
                .overlay
                .file_contents(&publication.path),
            Some(b"complete".to_vec())
        );
        assert!(
            dispatcher
                .fs
                .rootfs_vfs
                .overlay
                .file_contents("/tmp/coretest/core.carrick-tmp-91-7")
                .is_none()
        );
    }

    #[test]
    fn every_publication_failpoint_leaves_no_final_or_temporary_file() {
        for failpoint in [
            "before-create",
            "unwritable-path",
            "short-write",
            "fsync",
            "rename",
            "post-publication",
        ] {
            let dispatcher = SyscallDispatcher::new();
            let snapshot = snapshot();
            dispatcher
                .publish_core_atomic_with_failpoint(
                    &snapshot,
                    9,
                    b"must-not-publish".to_vec(),
                    Some(failpoint),
                )
                .expect_err(failpoint);
            assert!(
                dispatcher
                    .fs
                    .rootfs_vfs
                    .overlay
                    .file_contents("/tmp/coretest/core")
                    .is_none(),
                "final file after {failpoint}"
            );
            assert!(
                dispatcher
                    .fs
                    .rootfs_vfs
                    .overlay
                    .file_contents("/tmp/coretest/core.carrick-tmp-91-9")
                    .is_none(),
                "temporary file after {failpoint}"
            );
        }
    }

    #[test]
    fn published_core_remains_rollback_owned_until_wait_commit() {
        let dispatcher = SyscallDispatcher::new();
        let snapshot = snapshot();
        let publication = dispatcher
            .publish_core_atomic_with_failpoint(&snapshot, 11, b"rollback".to_vec(), None)
            .expect("publish before wait commit");
        dispatcher
            .rollback_core_publication(&publication)
            .expect("rollback");
        assert!(
            dispatcher
                .fs
                .rootfs_vfs
                .overlay
                .file_contents(&publication.path)
                .is_none()
        );
        assert!(
            dispatcher
                .fs
                .rootfs_vfs
                .overlay
                .file_contents("/tmp/coretest/core.carrick-tmp-91-11")
                .is_none()
        );
    }

    #[test]
    fn post_publication_cleanup_failure_is_explicit_and_invalidates_artifact() {
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher
            .fs
            .rootfs_vfs_mut()
            .set_overlay(Box::new(FinalCleanupErrorBackend::new()));
        let error = dispatcher
            .publish_core_atomic_with_failpoint(
                &snapshot(),
                12,
                b"must-not-look-complete".to_vec(),
                Some("post-publication"),
            )
            .expect_err("failed rollback must fail closed");

        assert!(error.to_string().contains("cleanup"), "{error}");
        assert_eq!(
            dispatcher
                .fs
                .rootfs_vfs
                .overlay
                .file_contents("/tmp/coretest/core"),
            Some(Vec::new()),
            "an unlink-resistant final artifact must be structurally invalidated"
        );
    }

    #[test]
    fn wait_owned_rollback_failure_is_explicit_and_invalidates_artifact() {
        let mut dispatcher = SyscallDispatcher::new();
        dispatcher
            .fs
            .rootfs_vfs_mut()
            .set_overlay(Box::new(FinalCleanupErrorBackend::new()));
        let publication = dispatcher
            .publish_core_atomic_with_failpoint(
                &snapshot(),
                13,
                b"published-before-wait".to_vec(),
                None,
            )
            .expect("rename before authoritative wait commit");
        let error = dispatcher
            .rollback_core_publication(&publication)
            .expect_err("unlink-resistant rollback must be explicit");

        assert!(error.to_string().contains("cleanup"), "{error}");
        assert_eq!(
            dispatcher
                .fs
                .rootfs_vfs
                .overlay
                .file_contents(&publication.path),
            Some(Vec::new())
        );
    }

    struct MockInMemoryMountVfs {
        files: Arc<
            parking_lot::RwLock<
                std::collections::BTreeMap<
                    String,
                    Arc<parking_lot::RwLock<crate::vfs::SparseBuffer>>,
                >,
            >,
        >,
    }

    impl MockInMemoryMountVfs {
        fn new() -> Self {
            Self {
                files: Arc::new(parking_lot::RwLock::new(std::collections::BTreeMap::new())),
            }
        }
    }

    impl crate::vfs::Vfs for MockInMemoryMountVfs {
        fn open(
            &self,
            path: &str,
            flags: crate::vfs::OpenFlags,
            _ctx: &crate::vfs::OpenContext<'_>,
        ) -> Result<crate::vfs::VfsHandle, crate::vfs::VfsError> {
            let mut files = self.files.write();
            let buf = files
                .entry(path.to_string())
                .or_insert_with(|| {
                    Arc::new(parking_lot::RwLock::new(crate::vfs::SparseBuffer::new()))
                })
                .clone();
            Ok(crate::vfs::VfsHandle::InMemoryFile {
                path: path.to_string(),
                contents: buf,
                status_flags: 0,
                writable: flags.write,
                max_size: usize::MAX,
            })
        }

        fn lookup(&self, path: &str) -> Result<crate::vfs::Metadata, crate::vfs::VfsError> {
            let files = self.files.read();
            if let Some(buf) = files.get(path) {
                Ok(crate::vfs::Metadata {
                    kind: crate::vfs::EntryKind::File,
                    mode: 0o600,
                    size: buf.read().len() as u64,
                    mtime_secs: 0,
                    mtime_nanos: 0,
                    uid: 0,
                    gid: 0,
                })
            } else {
                Err(crate::linux_abi::LINUX_ENOENT)
            }
        }

        fn rename(&self, old_path: &str, new_path: &str) -> Result<(), crate::vfs::VfsError> {
            let mut files = self.files.write();
            if let Some(buf) = files.remove(old_path) {
                files.insert(new_path.to_string(), buf);
                Ok(())
            } else {
                Err(crate::linux_abi::LINUX_ENOENT)
            }
        }

        fn unlink(&self, path: &str) -> Result<(), crate::vfs::VfsError> {
            let mut files = self.files.write();
            if files.remove(path).is_some() {
                Ok(())
            } else {
                Err(crate::linux_abi::LINUX_ENOENT)
            }
        }
    }

    #[test]
    fn sparse_core_publication_on_in_memory_vfs_preserves_holes_and_bounds_allocation() {
        let sparse_64gib = 64 * 1024 * 1024 * 1024_u64;
        let mut dispatcher = SyscallDispatcher::new();
        let inmem_vfs = MockInMemoryMountVfs::new();
        let files_map = Arc::clone(&inmem_vfs.files);
        dispatcher
            .fs
            .vfs_mounts_mut()
            .mount("/inmem", Box::new(inmem_vfs));

        let mut snapshot = snapshot();
        snapshot.cwd = "/inmem".to_owned();

        let header = vec![0x7f, b'E', b'L', b'F'];
        let p1 = vec![0x11_u8; 4096];
        let p2 = vec![0x22_u8; 4096];
        let p3 = vec![0x33_u8; 4096];
        let extents = vec![
            crate::core_dump::CoreExtent {
                offset: 4096,
                bytes: p1.clone(),
            },
            crate::core_dump::CoreExtent {
                offset: 32 * 1024 * 1024 * 1024,
                bytes: p2.clone(),
            },
            crate::core_dump::CoreExtent {
                offset: sparse_64gib - 4096,
                bytes: p3.clone(),
            },
        ];
        let payload = crate::core_dump::CorePayload {
            header: header.clone(),
            extents,
            logical_size: sparse_64gib,
        };

        let pub_res = dispatcher
            .publish_core_atomic(&snapshot, 42, payload)
            .expect("sparse core publication on in-memory mount");

        assert_eq!(pub_res.path, "/inmem/core");
        assert_eq!(pub_res.bytes, 4 + 3 * 4096);

        // Verify that the stored file in VFS is a SparseBuffer with 64 GiB length and bounded memory
        let files = files_map.read();
        let buf = Arc::clone(files.get("/inmem/core").expect("published core file"));
        let lock = buf.read();
        assert_eq!(lock.len(), sparse_64gib as usize);
        assert_eq!(lock.allocated_bytes(), 4 + 3 * 4096);
        assert_eq!(lock.read_range(0, 4), header);
        assert_eq!(lock.read_range(4096, 4096), p1);
        assert_eq!(lock.read_range(8192, 4096), vec![0_u8; 4096]);
        assert_eq!(lock.read_range(32 * 1024 * 1024 * 1024, 4096), p2);
        assert_eq!(lock.read_range((sparse_64gib - 4096) as usize, 4096), p3);
        drop(lock);
        drop(files);

        // Open the in-memory core file and verify fstat reports allocated blocks (< 1 MiB)
        // rather than 64 GiB / 512 blocks
        let open_desc = crate::dispatch::fd_table::OpenDescription::InMemoryFile {
            path: "/inmem/core".to_string(),
            contents: buf,
            offset: 0,
            writable: false,
            max_size: usize::MAX,
            base: crate::dispatch::fd_table::OpenDescriptionBase::new(0),
        };
        let stat_source = open_desc.stat_source();
        if let crate::dispatch::fd_table::OpenStatSource::Record(rec) = stat_source {
            assert_eq!(rec.size, sparse_64gib);
            let allocated = 4 + 3 * 4096;
            let expected_blocks = blocks_512(allocated) as u64;
            assert_eq!(rec.blocks, Some(expected_blocks));
            assert!(expected_blocks * 512 <= 1024 * 1024);
        } else {
            panic!("expected OpenStatSource::Record");
        }
    }

    #[test]
    fn sparse_core_publication_failure_cleanup_on_in_memory_vfs() {
        let mut dispatcher = SyscallDispatcher::new();
        let inmem_vfs = MockInMemoryMountVfs::new();
        let files_map = Arc::clone(&inmem_vfs.files);
        dispatcher
            .fs
            .vfs_mounts_mut()
            .mount("/inmem_fail", Box::new(inmem_vfs));

        let mut snapshot = snapshot();
        snapshot.cwd = "/inmem_fail".to_owned();

        let payload = crate::core_dump::CorePayload {
            header: vec![1, 2, 3, 4],
            extents: vec![crate::core_dump::CoreExtent {
                offset: 1024 * 1024,
                bytes: vec![5, 6, 7, 8],
            }],
            logical_size: 2 * 1024 * 1024,
        };

        let err = dispatcher
            .publish_core_atomic_with_failpoint(&snapshot, 43, payload, Some("rename"))
            .expect_err("failpoint must fail");
        assert!(matches!(err, CorePublicationError::Failpoint("rename")));

        // Verify that temporary files were cleaned up
        let files = files_map.read();
        assert!(files.is_empty() || files.values().all(|b| b.read().is_empty()));
    }

    #[test]
    fn crash_register_authority_is_generation_exact() {
        let authority = crate::kernel::CrashCaptureAuthority::default();
        let first = authority.issue().expect("first generation");
        let second = authority.issue().expect("second generation");
        let third = authority.issue().expect("third generation");
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().expect("context");
        let mut registers = carrick_hal::Aarch64CoreRegisters::default();
        registers.gprs[19] = 0x1919;
        context.thread().publish_crash_registers(second, registers);
        assert_eq!(
            context.thread().crash_vote(second),
            Some(crate::kernel::CrashRegisterVote::Published(Box::new(
                registers
            ))),
            "matching generation"
        );
        assert_eq!(context.thread().crash_vote(first), None, "stale generation");
        assert_eq!(
            context.thread().crash_vote(third),
            None,
            "future generation"
        );
    }

    #[test]
    fn crash_withdrawal_never_retracts_a_published_register_file() {
        let authority = crate::kernel::CrashCaptureAuthority::default();
        let generation = authority.issue().expect("generation");
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().expect("context");
        let mut registers = carrick_hal::Aarch64CoreRegisters::default();
        registers.gprs[3] = 0x3333;
        context
            .thread()
            .publish_crash_registers(generation, registers);
        // A thread that publishes and then parks somewhere unpublishable keeps
        // its note: withdrawal answers "I never can", not "forget what I said".
        context.thread().withdraw_from_crash_capture(generation);
        assert_eq!(
            context.thread().crash_vote(generation),
            Some(crate::kernel::CrashRegisterVote::Published(Box::new(
                registers
            )))
        );
    }

    #[test]
    fn crash_quorum_completes_without_a_thread_that_left_its_vcpu_loop() {
        let authority = crate::kernel::CrashCaptureAuthority::default();
        let generation = authority.issue().expect("generation");
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().expect("context");
        let quorum =
            crate::kernel::CrashQuorum::open(std::sync::Arc::clone(context.task()), generation);

        // A live participant that has not answered is genuinely owed.
        let participation = context
            .thread()
            .enter_crash_safe_point_participation()
            .expect("crash safe-point participation");
        assert!(matches!(
            quorum.poll(),
            crate::kernel::CrashQuorumPoll::Waiting(_)
        ));

        // The same thread once its host loop has gone: the task still lists it,
        // but nothing may keep waiting for a note it can never write. This is
        // the `exit_group` terminal-claim loser that burned the full 10 s
        // collection deadline and then published no core at all.
        drop(participation);
        let crate::kernel::CrashQuorumPoll::Complete(files) = quorum.poll() else {
            panic!("a departed thread must not be expected")
        };
        assert!(files.is_empty());
    }

    #[test]
    fn crash_quorum_completes_when_a_live_participant_withdraws() {
        let authority = crate::kernel::CrashCaptureAuthority::default();
        let generation = authority.issue().expect("generation");
        let dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().expect("context");
        let quorum =
            crate::kernel::CrashQuorum::open(std::sync::Arc::clone(context.task()), generation);
        let _participation = context
            .thread()
            .enter_crash_safe_point_participation()
            .expect("crash safe-point participation");
        assert!(matches!(
            quorum.poll(),
            crate::kernel::CrashQuorumPoll::Waiting(_)
        ));
        // Parked where its register file is unreadable: still live, still a
        // participant, but permanently unable to publish for this generation.
        context.thread().withdraw_from_crash_capture(generation);
        let crate::kernel::CrashQuorumPoll::Complete(files) = quorum.poll() else {
            panic!("a withdrawn participant must not be expected")
        };
        assert!(files.is_empty());
    }
}
