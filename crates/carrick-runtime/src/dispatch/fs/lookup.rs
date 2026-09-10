//! Unified path resolver for carrick filesystem dispatch.
//!
//! Unifies path resolution across `openat`, `stat`, `statx`, and the x86 stat variants,
//! ensuring consistent fast-path ordering, single dentry-cache lookups, stat-cache lookups,
//! synthetic /proc handling, rootfs containment, and trailing-slash directory forcing.

use parking_lot::RwLock;
use std::sync::Arc;

use super::*;
use crate::rootfs::RootFsEntryKind;

/// Identifies which fast path (if any) fully resolved and answered the lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::dispatch) enum FastPathKind {
    None,
    TrustedDirfd,
    DentryCache,
    StatCache,
    ImmutableLower,
}

/// The intent of the path lookup, distinguishing between open, stat, statx, etc.
pub(in crate::dispatch) enum LookupIntent<'a> {
    Stat {
        context: &'a crate::kernel::KernelContext,
    },
    Statx {
        context: &'a crate::kernel::KernelContext,
    },
    Open {
        context: &'a crate::kernel::KernelContext,
        registry: Option<&'a crate::thread::ThreadRegistry>,
        open_flags: LinuxOpenFlags,
        access: u64,
        writable_request: bool,
        flags: u64,
        reporter: &'a CompatReporter,
    },
}

/// The target or outcome produced by the path lookup.
pub(in crate::dispatch) enum LookupTarget {
    Resolved(String),
    Stat(StatRecord),
    OpenOutcome(DispatchOutcome),
}

/// Result of a unified path resolution.
pub(in crate::dispatch) struct PathLookup {
    pub resolved_path: String,
    pub fast_path: FastPathKind,
    pub target: LookupTarget,
}

impl PathLookup {
    /// Extracts the resolved [`StatRecord`], or returns `Err(ENOENT)` if the lookup
    /// was not for a stat intent or did not yield a stat record.
    pub(in crate::dispatch) fn into_stat(self) -> Result<StatRecord, LinuxErrno> {
        match self.target {
            LookupTarget::Stat(record) => Ok(record),
            _ => Err(LINUX_ENOENT),
        }
    }

    /// The resolved path string.
    pub(in crate::dispatch) fn resolved_path(&self) -> &str {
        &self.resolved_path
    }

    /// The fast path that answered this lookup (if any).
    pub(in crate::dispatch) fn fast_path(&self) -> FastPathKind {
        self.fast_path
    }

    /// Whether any fast path answered this lookup.
    pub(in crate::dispatch) fn fast_path_answered(&self) -> bool {
        self.fast_path != FastPathKind::None
    }
}

impl SyscallDispatcher {
    /// The single, unified path resolution entry point for filesystem operations.
    ///
    /// Handles:
    /// - Linux path length limit validation (`check_path_length`)
    /// - Empty path checks (e.g. `AT_EMPTY_PATH` for stat, `ENOENT` for open)
    /// - Pre-resolution fast paths (trusted dirfd, dentry cache, stat cache, immutable lower)
    /// - Rootfs containment and ancestor resolution (`resolve_at_path`)
    /// - Trailing slash and `.` / `..` directory forcing semantics
    /// - Post-resolution fast paths (ensuring dentry cache is consulted at most once)
    /// - Synthetic `/proc` and `/sys` virtual hierarchy lookups
    /// - Magic symlink resolution (`/proc/self/{exe,cwd,root}`)
    /// - Symlink following and loop / dangling link detection
    pub(in crate::dispatch) fn lookup_path(
        &self,
        dirfd: u64,
        path: &str,
        at_flags: carrick_abi::LinuxAtFlags,
        intent: LookupIntent<'_>,
    ) -> Result<PathLookup, LinuxErrno> {
        // 1. Empty pathname checks
        if path.is_empty() {
            match intent {
                LookupIntent::Stat { .. } | LookupIntent::Statx { .. } => {
                    // AT_EMPTY_PATH stats the dirfd/fd itself; without it an empty
                    // pathname is ENOENT — NOT a stat of the cwd (lstat02/stat02 case 2).
                    if at_flags.contains(carrick_abi::LinuxAtFlags::EMPTY_PATH) {
                        let record = self.fd_stat_record(dirfd as i32)?;
                        return Ok(PathLookup {
                            resolved_path: String::new(),
                            fast_path: FastPathKind::None,
                            target: LookupTarget::Stat(record),
                        });
                    }
                    return Err(LINUX_ENOENT);
                }
                LookupIntent::Open { .. } => {
                    // An empty pathname is never valid for open()/openat(): the kernel's
                    // path walk requires at least one component and returns ENOENT for ""
                    // (openat has no AT_EMPTY_PATH).
                    return Ok(PathLookup {
                        resolved_path: String::new(),
                        fast_path: FastPathKind::None,
                        target: LookupTarget::OpenOutcome(DispatchOutcome::errno(LINUX_ENOENT)),
                    });
                }
            }
        }

        // 2. Pre-resolution fast paths
        let mut dentry_attempted = false;
        let mut dentry_fast_open_attempted = false;

        match &intent {
            LookupIntent::Stat { .. } | LookupIntent::Statx { .. } => {
                // `--fs host` trusted-dirfd fast lane: `newfstatat(dirfd, name)` on
                // getdents output served straight off the trusted host dirfd.
                if let Some(result) = self.try_trusted_dirfd_stat(dirfd, path) {
                    let record = result?;
                    return Ok(PathLookup {
                        resolved_path: path.to_string(),
                        fast_path: FastPathKind::TrustedDirfd,
                        target: LookupTarget::Stat(record),
                    });
                }
            }
            LookupIntent::Open {
                open_flags,
                access,
                writable_request,
                flags,
                ..
            } => {
                let want_create = open_flags.contains(LinuxOpenFlags::CREAT);
                let want_trunc = open_flags.contains(LinuxOpenFlags::TRUNC);

                if !want_create
                    && !want_trunc
                    && (dirfd == LINUX_AT_FDCWD || (dirfd as i32) == -100 || path.starts_with('/'))
                    && path.starts_with('/')
                {
                    dentry_fast_open_attempted = true;
                    if let Some(outcome) =
                        self.try_dentry_fast_open(path, *flags, *access, *writable_request)
                    {
                        return Ok(PathLookup {
                            resolved_path: path.to_string(),
                            fast_path: FastPathKind::DentryCache,
                            target: LookupTarget::OpenOutcome(outcome),
                        });
                    }
                }

                if let Some(outcome) = self.try_immutable_lower_absolute_open(dirfd, path, *flags) {
                    return Ok(PathLookup {
                        resolved_path: path.to_string(),
                        fast_path: FastPathKind::ImmutableLower,
                        target: LookupTarget::OpenOutcome(outcome),
                    });
                }

                if let Some(outcome) = self.try_trusted_dirfd_openat(dirfd, path, *flags) {
                    return Ok(PathLookup {
                        resolved_path: path.to_string(),
                        fast_path: FastPathKind::TrustedDirfd,
                        target: LookupTarget::OpenOutcome(outcome),
                    });
                }
            }
        }

        // 3. Trailing slash and path length limits
        check_path_length(path)?;

        let requires_dir = path.ends_with('/') || path.ends_with("/.");

        let ends_with_dot = path == "."
            || path.ends_with("/.")
            || path.trim_end_matches('/').ends_with("/.")
            || path.trim_end_matches('/') == "."
            || path == ".."
            || path.ends_with("/..")
            || path.trim_end_matches('/').ends_with("/..")
            || path.trim_end_matches('/') == "..";
        let had_trailing_slash = path.len() > 1 && path.ends_with('/');

        let in_chroot = self
            .captured_fs_context()
            .chroot_root()
            .as_deref()
            .is_some_and(|r| r != "/");

        // 4. Pre-resolution dentry cache and stat cache (for stat / statx)
        if matches!(
            intent,
            LookupIntent::Stat { .. } | LookupIntent::Statx { .. }
        ) {
            if !in_chroot
                && (dirfd == LINUX_AT_FDCWD || (dirfd as i32) == -100 || path.starts_with('/'))
                && path.starts_with('/')
                && !path.starts_with("/proc")
                && !path.starts_with("/sys")
                && !path.starts_with("/dev")
                && !path.split('/').any(|c| c == "..")
                && self.dac_overrides_permissions()
                && !self.fs.vfs_mounts.has_mount(path)
            {
                dentry_attempted = true;
                let follow =
                    !at_flags.contains(carrick_abi::LinuxAtFlags::SYMLINK_NOFOLLOW) || requires_dir;
                match self.fs.rootfs_vfs.dentry_stat(path, follow) {
                    Ok(real) => {
                        if requires_dir && real.kind != RootFsEntryKind::Directory {
                            return Err(LINUX_ENOTDIR);
                        }
                        return Ok(PathLookup {
                            resolved_path: path.to_string(),
                            fast_path: FastPathKind::DentryCache,
                            target: LookupTarget::Stat(self.stat_record_with_device(path, &real)),
                        });
                    }
                    Err(LINUX_ENOENT) => return Err(LINUX_ENOENT),
                    Err(LINUX_ENOTDIR) => return Err(LINUX_ENOTDIR),
                    Err(LINUX_ELOOP) => return Err(LINUX_ELOOP),
                    Err(_) => {}
                }
            }

            if !in_chroot
                && !requires_dir
                && dirfd == LINUX_AT_FDCWD
                && path.starts_with('/')
                && !path.starts_with("/proc")
                && !path.starts_with("/sys")
                && !path.split('/').any(|c| c == "..")
                && self.dac_overrides_permissions()
                && let Some(real) = self.fs.rootfs_vfs.overlay.stat_cache_lookup(path)
            {
                return Ok(PathLookup {
                    resolved_path: path.to_string(),
                    fast_path: FastPathKind::StatCache,
                    target: LookupTarget::Stat(self.stat_record_with_device(path, &real)),
                });
            }
        }

        // 5. Rootfs boundary check and ancestor canonicalization
        let mut resolved = self.resolve_at_path(dirfd, path)?;

        // 6. Post-resolve directory validation for Open
        if let LookupIntent::Open { open_flags, .. } = &intent {
            let want_create = open_flags.contains(LinuxOpenFlags::CREAT);
            if ends_with_dot || had_trailing_slash {
                let followed = self
                    .canonicalize_following(&resolved)
                    .unwrap_or_else(|_| resolved.clone());
                match self.layered_metadata(&followed) {
                    Ok(md) => {
                        if md.kind == RootFsEntryKind::Directory {
                            if want_create {
                                return Ok(PathLookup {
                                    resolved_path: followed,
                                    fast_path: FastPathKind::None,
                                    target: LookupTarget::OpenOutcome(DispatchOutcome::errno(
                                        LINUX_EISDIR,
                                    )),
                                });
                            }
                            resolved = followed;
                        } else {
                            return Ok(PathLookup {
                                resolved_path: followed,
                                fast_path: FastPathKind::None,
                                target: LookupTarget::OpenOutcome(DispatchOutcome::errno(
                                    LINUX_ENOTDIR,
                                )),
                            });
                        }
                    }
                    Err(_) => {
                        if want_create && had_trailing_slash {
                            return Ok(PathLookup {
                                resolved_path: followed,
                                fast_path: FastPathKind::None,
                                target: LookupTarget::OpenOutcome(DispatchOutcome::errno(
                                    LINUX_EISDIR,
                                )),
                            });
                        }
                        return Ok(PathLookup {
                            resolved_path: followed,
                            fast_path: FastPathKind::None,
                            target: LookupTarget::OpenOutcome(DispatchOutcome::errno(LINUX_ENOENT)),
                        });
                    }
                }
            }
        }

        // 7. Post-resolve Dentry Cache (ONLY ONCE) and Stat Cache
        if matches!(
            intent,
            LookupIntent::Stat { .. } | LookupIntent::Statx { .. }
        ) {
            let follow =
                !at_flags.contains(carrick_abi::LinuxAtFlags::SYMLINK_NOFOLLOW) || requires_dir;
            if !dentry_attempted
                && !resolved.starts_with("/proc")
                && !resolved.starts_with("/sys")
                && !resolved.starts_with("/dev")
                && !resolved.split('/').any(|c| c == "..")
                && self.dac_overrides_permissions()
                && self.fs.vfs_mounts.resolve(&resolved).is_none()
            {
                match self.fs.rootfs_vfs.dentry_stat(&resolved, follow) {
                    Ok(real) => {
                        if requires_dir && real.kind != RootFsEntryKind::Directory {
                            return Err(LINUX_ENOTDIR);
                        }
                        return Ok(PathLookup {
                            resolved_path: resolved.clone(),
                            fast_path: FastPathKind::DentryCache,
                            target: LookupTarget::Stat(
                                self.stat_record_with_device(&resolved, &real),
                            ),
                        });
                    }
                    Err(LINUX_ENOENT) => return Err(LINUX_ENOENT),
                    Err(LINUX_ENOTDIR) => return Err(LINUX_ENOTDIR),
                    Err(LINUX_ELOOP) => return Err(LINUX_ELOOP),
                    Err(_) => {}
                }
            }

            if !requires_dir
                && !resolved.starts_with("/proc")
                && !resolved.starts_with("/sys")
                && !resolved.split('/').any(|c| c == "..")
                && self.dac_overrides_permissions()
                && let Some(real) = self.fs.rootfs_vfs.overlay.stat_cache_lookup(&resolved)
            {
                return Ok(PathLookup {
                    resolved_path: resolved.clone(),
                    fast_path: FastPathKind::StatCache,
                    target: LookupTarget::Stat(self.stat_record_with_device(&resolved, &real)),
                });
            }
        } else if let LookupIntent::Open {
            open_flags,
            access,
            writable_request,
            flags,
            ..
        } = &intent
        {
            let want_create = open_flags.contains(LinuxOpenFlags::CREAT);
            let want_trunc = open_flags.contains(LinuxOpenFlags::TRUNC);
            if !dentry_fast_open_attempted
                && !want_create
                && !want_trunc
                && !ends_with_dot
                && !had_trailing_slash
            {
                if let Some(outcome) =
                    self.try_dentry_fast_open(&resolved, *flags, *access, *writable_request)
                {
                    return Ok(PathLookup {
                        resolved_path: resolved,
                        fast_path: FastPathKind::DentryCache,
                        target: LookupTarget::OpenOutcome(outcome),
                    });
                }
            }
        }

        // 8. Synthetic /proc, /sys and leaf handling
        match intent {
            LookupIntent::Open {
                context,
                registry,
                open_flags,
                flags,
                reporter,
                ..
            } => {
                // Trace every open attempt
                crate::probes::path_open(&resolved, 0, 0);

                let visible_self = proc_visible_self(context);
                if let Some(n) = proc_self_fd_number(&resolved, visible_self) {
                    let outcome =
                        self.reopen_proc_self_fd(context, registry, n, flags, &resolved, reporter)?;
                    return Ok(PathLookup {
                        resolved_path: resolved,
                        fast_path: FastPathKind::None,
                        target: LookupTarget::OpenOutcome(outcome),
                    });
                }

                if let Some(n) = proc_self_fdinfo_number(&resolved, visible_self) {
                    let outcome = match self.fdinfo_bytes(n) {
                        Some(bytes) => self.install_proc_synthetic_bytes(&resolved, bytes, flags),
                        None => DispatchOutcome::errno(LINUX_ENOENT),
                    };
                    return Ok(PathLookup {
                        resolved_path: resolved,
                        fast_path: FastPathKind::None,
                        target: LookupTarget::OpenOutcome(outcome),
                    });
                }

                if proc_ns_link(&resolved).is_some()
                    || (resolved.starts_with("/proc/")
                        && resolved.contains("/ns/")
                        && crate::vfs::proc::proc_ns_link_type_with_context(
                            &resolved,
                            &self.synthetic_proc_context(context),
                        )
                        .is_some())
                {
                    return Ok(PathLookup {
                        resolved_path: resolved.clone(),
                        fast_path: FastPathKind::None,
                        target: LookupTarget::OpenOutcome(self.install_proc_synthetic_bytes(
                            &resolved,
                            Vec::new(),
                            flags,
                        )),
                    });
                }

                let mut path = match proc_self_magic_link(&resolved, visible_self) {
                    Some("exe") => {
                        let proc_ctx = self.synthetic_proc_context(context);
                        let exe = proc_ctx.executable_path;
                        if exe.starts_with("/proc/") {
                            resolved
                        } else {
                            exe
                        }
                    }
                    Some("cwd") => self.cwd(),
                    Some("root") => "/".to_string(),
                    _ => resolved,
                };

                let want_create = open_flags.contains(LinuxOpenFlags::CREAT);
                let want_excl = open_flags.contains(LinuxOpenFlags::EXCL);

                if !(open_flags.contains(LinuxOpenFlags::NOFOLLOW) || (want_create && want_excl)) {
                    let resolved_target = if want_create {
                        self.canonicalize_following_allow_missing(&path)
                    } else {
                        self.canonicalize_following(&path)
                    };
                    match resolved_target {
                        Ok(target) => path = target,
                        Err(e) if e == crate::linux_abi::LINUX_ELOOP => {
                            return Ok(PathLookup {
                                resolved_path: path,
                                fast_path: FastPathKind::None,
                                target: LookupTarget::OpenOutcome(DispatchOutcome::errno(e)),
                            });
                        }
                        Err(_) => {}
                    }
                } else if !(want_create && want_excl) {
                    if let Ok(md) = self.layered_lstat(&path)
                        && md.kind == RootFsEntryKind::Symlink
                    {
                        if open_flags.contains(LinuxOpenFlags::DIRECTORY) {
                            return Ok(PathLookup {
                                resolved_path: path,
                                fast_path: FastPathKind::None,
                                target: LookupTarget::OpenOutcome(DispatchOutcome::errno(
                                    LINUX_ENOTDIR,
                                )),
                            });
                        }
                        if open_flags.contains(LinuxOpenFlags::PATH) {
                            let status = flags & !LINUX_O_CLOEXEC;
                            let open_file = OpenFile::from_open_description_with_status_flags(
                                Arc::new(RwLock::new(OpenDescription::File {
                                    base: OpenDescriptionBase::new(status),
                                    path: path.clone(),
                                    metadata: md,
                                    contents: FileContents::dense(Vec::new()),
                                    offset: 0,
                                    writable: false,
                                })),
                                status,
                                linux_fd_flags_from_open_flags(flags),
                            );
                            let Ok(fd) = self.install_fd_at_or_above(0, open_file) else {
                                return Ok(PathLookup {
                                    resolved_path: path,
                                    fast_path: FastPathKind::None,
                                    target: LookupTarget::OpenOutcome(DispatchOutcome::errno(
                                        linux_errno::EMFILE,
                                    )),
                                });
                            };
                            self.record_fd_open_path(fd, path.clone());
                            return Ok(PathLookup {
                                resolved_path: path,
                                fast_path: FastPathKind::None,
                                target: LookupTarget::OpenOutcome(DispatchOutcome::returned_i32(
                                    fd,
                                )),
                            });
                        }
                        return Ok(PathLookup {
                            resolved_path: path,
                            fast_path: FastPathKind::None,
                            target: LookupTarget::OpenOutcome(DispatchOutcome::errno(
                                crate::linux_abi::LINUX_ELOOP,
                            )),
                        });
                    }
                }

                Ok(PathLookup {
                    resolved_path: path.clone(),
                    fast_path: FastPathKind::None,
                    target: LookupTarget::Resolved(path),
                })
            }
            LookupIntent::Stat { context } | LookupIntent::Statx { context } => {
                if crate::vfs::may_be_synthetic_virtual_path(&resolved) {
                    let proc_ctx = self.synthetic_proc_context(context);
                    if let Some(contents) = crate::vfs::proc::synthetic_file(&resolved, &proc_ctx) {
                        return Ok(PathLookup {
                            resolved_path: resolved.clone(),
                            fast_path: FastPathKind::None,
                            target: LookupTarget::Stat(StatRecord::synthetic(
                                &resolved,
                                contents.len(),
                                LINUX_S_IFREG | 0o444,
                            )),
                        });
                    }
                    if crate::vfs::proc::synthetic_dir_entries(&resolved, &proc_ctx).is_some() {
                        return Ok(PathLookup {
                            resolved_path: resolved.clone(),
                            fast_path: FastPathKind::None,
                            target: LookupTarget::Stat(StatRecord::synthetic(
                                &resolved,
                                0,
                                LINUX_S_IFDIR | 0o555,
                            )),
                        });
                    }
                    if let Some(size) =
                        crate::vfs::proc::proc_ns_link_size_with_context(&resolved, &proc_ctx)
                    {
                        return Ok(PathLookup {
                            resolved_path: resolved.clone(),
                            fast_path: FastPathKind::None,
                            target: LookupTarget::Stat(StatRecord::synthetic(
                                &resolved,
                                size as usize,
                                LINUX_S_IFLNK | 0o777,
                            )),
                        });
                    }
                }
                if let Some(contents) = crate::vfs::sys::synthetic_file(&resolved) {
                    return Ok(PathLookup {
                        resolved_path: resolved.clone(),
                        fast_path: FastPathKind::None,
                        target: LookupTarget::Stat(StatRecord::synthetic(
                            &resolved,
                            contents.len(),
                            LINUX_S_IFREG | 0o444,
                        )),
                    });
                }

                let follow =
                    !at_flags.contains(carrick_abi::LinuxAtFlags::SYMLINK_NOFOLLOW) || requires_dir;
                if let Some(real) = self.fs.rootfs_vfs.overlay.real_stat(&resolved, follow) {
                    if requires_dir && real.kind != RootFsEntryKind::Directory {
                        return Err(LINUX_ENOTDIR);
                    }
                    return Ok(PathLookup {
                        resolved_path: resolved.clone(),
                        fast_path: FastPathKind::None,
                        target: LookupTarget::Stat(self.stat_record_with_device(&resolved, &real)),
                    });
                }

                let path_is_symlink = follow
                    && self
                        .fs
                        .rootfs_vfs
                        .overlay
                        .real_stat(&resolved, false)
                        .is_some_and(|link| link.kind == RootFsEntryKind::Symlink);

                let path = if follow {
                    match self.canonicalize_following(&resolved) {
                        Ok(resolved_path) => resolved_path,
                        Err(errno) if errno == crate::linux_abi::LINUX_ELOOP => return Err(errno),
                        Err(_) => resolved,
                    }
                } else {
                    resolved
                };

                if let Some(real) = self.fs.rootfs_vfs.overlay.real_stat(&path, follow) {
                    if requires_dir && real.kind != RootFsEntryKind::Directory {
                        return Err(LINUX_ENOTDIR);
                    }
                    return Ok(PathLookup {
                        resolved_path: path.clone(),
                        fast_path: FastPathKind::None,
                        target: LookupTarget::Stat(self.stat_record_with_device(&path, &real)),
                    });
                }

                if path_is_symlink
                    && self
                        .layered_lstat(&path)
                        .is_ok_and(|md| md.kind == RootFsEntryKind::Symlink)
                {
                    return Err(LINUX_ENOENT);
                }

                use crate::vfs::Vfs as _;
                if let Some(m) = self.fs.vfs_mounts.resolve(&path) {
                    if let Some(real) = m.vfs.real_stat(&m.full_path, follow) {
                        if requires_dir && real.kind != RootFsEntryKind::Directory {
                            return Err(LINUX_ENOTDIR);
                        }
                        return Ok(PathLookup {
                            resolved_path: path.clone(),
                            fast_path: FastPathKind::None,
                            target: LookupTarget::Stat(StatRecord::from_real(&path, &real)),
                        });
                    }
                    if let Ok(md) = if follow {
                        m.vfs.lookup(&m.full_path)
                    } else {
                        m.vfs.lookup_nofollow(&m.full_path)
                    } {
                        if requires_dir && md.kind != crate::vfs::EntryKind::Directory {
                            return Err(LINUX_ENOTDIR);
                        }
                        return Ok(PathLookup {
                            resolved_path: path.clone(),
                            fast_path: FastPathKind::None,
                            target: LookupTarget::Stat(StatRecord::from_metadata(
                                &vfs_md_to_rootfs_md_helper(&path, &md),
                            )),
                        });
                    }
                }

                let lookup = if follow {
                    self.fs.rootfs_vfs.lookup(&path)
                } else {
                    self.fs.rootfs_vfs.lookup_nofollow(&path)
                };
                lookup.and_then(|md| {
                    if requires_dir && md.kind != crate::vfs::EntryKind::Directory {
                        return Err(LINUX_ENOTDIR);
                    }
                    Ok(PathLookup {
                        resolved_path: path.clone(),
                        fast_path: FastPathKind::None,
                        target: LookupTarget::Stat(self.layered_identity_record(
                            &path,
                            follow,
                            &vfs_md_to_rootfs_md_helper(&path, &md),
                        )),
                    })
                })
            }
        }
    }
}
