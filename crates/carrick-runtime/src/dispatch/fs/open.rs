//! Path-opening and memfd syscall handlers and helpers:
//! `openat`, `openat2`, `memfd_create`, `memfd_secret`, `open_at_path`,
//! `open_at_path_string`, `try_vfs_open`, `try_open_trusted_dir`,
//! `try_dentry_fast_open`, `try_trusted_dirfd_openat`,
//! `try_immutable_lower_absolute_open`, and `openat2_*` validation checks.
//! Split out of `dispatch/fs.rs` (WS-F3) as `impl SyscallDispatcher` methods.

use super::*;
use crate::compat::CompatReporter;
use crate::dispatch::fd_table::{FileContents, HostFdRef, HostWriteKind, TrustedHostDir};
use parking_lot::RwLock;
use std::path::Path;
use std::sync::Arc;

/// Whether the `--fs host` trusted-dirfd fast lane is armed. Default ON;
/// `CARRICK_FS_TRUSTED_LANE=0` is the exact escape hatch (AGENTS.md: new work
/// ships on, with one switch that restores the historical path for
/// bisection). Read once per process.
fn trusted_fs_lane_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var_os("CARRICK_FS_TRUSTED_LANE").as_deref() != Some(std::ffi::OsStr::new("0"))
    })
}

/// Consolidated path, dirfd, flags, and mode arguments for `openat(2)` / `openat2(2)`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OpenAtArgs<'a> {
    pub dirfd: u64,
    pub path: &'a str,
    pub flags: u64,
    pub mode: u64,
}

impl<'a> FsView<'a> {
    fn open_at_path<M: CurrentMmMemory>(
        &self,
        cx: &mut SyscallCtx<'_, M>,
        dirfd: u64,
        pathname: u64,
        flags: u64,
        mode: u64,
    ) -> Result<DispatchOutcome, DispatchError> {
        let path = read_guest_c_string(&*cx.memory, pathname)?;
        self.open_at_path_string(
            cx.kernel,
            cx.thread.as_ref().map(|thread| thread.registry),
            OpenAtArgs {
                dirfd,
                path: &path,
                flags,
                mode,
            },
            cx.reporter,
        )
    }

    pub(in crate::dispatch) fn open_at_path_string(
        &self,
        context: &crate::kernel::KernelContext,
        registry: Option<&crate::thread::ThreadRegistry>,
        args: OpenAtArgs<'_>,
        reporter: &CompatReporter,
    ) -> Result<DispatchOutcome, DispatchError> {
        let OpenAtArgs {
            dirfd,
            path,
            flags,
            mode,
        } = args;
        let access = flags & LINUX_O_ACCMODE;
        if access != LINUX_O_RDONLY && access != LINUX_O_WRONLY && access != LINUX_O_RDWR {
            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
        }
        let writable_request = access == LINUX_O_WRONLY || access == LINUX_O_RDWR;
        // Parse the open flags once; `flags` (raw u64) is still used below where
        // the access-mode bits or a raw mask (e.g. `flags & !O_CLOEXEC`) is needed.
        let open_flags = LinuxOpenFlags::from_bits_retain(flags);
        let want_create = open_flags.contains(LinuxOpenFlags::CREAT);
        let want_excl = open_flags.contains(LinuxOpenFlags::EXCL);
        let want_trunc = open_flags.contains(LinuxOpenFlags::TRUNC);

        // O_TMPFILE: `pathname` names a directory; the result is an unnamed,
        // writable regular file. It's never linked anywhere — exactly the
        // "unlinked temp file" semantics tmpfile(3)/build tools rely on.
        // Requires write access (the kernel rejects O_RDONLY|O_TMPFILE with
        // EINVAL). (linkat(AT_EMPTY_PATH) to later materialize it is a separate
        // follow-up.)
        //
        // Back it with a REAL anonymous host fd when the backend can give us one
        // (--fs host: mkstemp + immediate unlink). A real kernel fd is shared by
        // fork(2) AND inherited across exec(2), so a forked+exec'd child's write
        // reaches the PARENT's read — which is what test_faulthandler's
        // tempfile.TemporaryFile()-to-a-subprocess pattern needs. An in-memory
        // File is PER-PROCESS (copied, not shared, across fork) so the child's
        // write never reached the parent → FAIL. MemoryBackend has no kernel fd
        // (open_anon_fd → None) and keeps the in-memory File fallback.
        if open_flags.contains(LinuxOpenFlags::TMPFILE) {
            if !writable_request {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let creds = self.cred_snapshot();
            let create_mode = (mode as u32 & 0o7777) & !(creds.umask & 0o777);
            if let Some(host_fd) = self.fs.rootfs_vfs.overlay.open_anon_fd(create_mode) {
                crate::dispatch::net::set_host_nonblocking(host_fd);
                let description = OpenDescription::HostFile {
                    host_fd: HostFdRef::new(host_fd),
                    metadata: RootFsMetadata {
                        path: Path::new("/__carrick_o_tmpfile").to_path_buf(),
                        kind: RootFsEntryKind::File,
                        mode: create_mode,
                        size: 0,
                    },
                    base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                    writable: true,
                };
                let status = flags & !LINUX_O_CLOEXEC;
                let open_file = OpenFile::from_open_description_with_status_flags(
                    Arc::new(RwLock::new(description)),
                    status,
                    linux_fd_flags_from_open_flags(flags),
                );
                return match self.install_fd_at_or_above(0, open_file) {
                    Ok(fd) => Ok(DispatchOutcome::returned_i32(fd)),
                    Err(_) => Ok(DispatchOutcome::errno(linux_errno::EMFILE)),
                };
            }
            let description = OpenDescription::File {
                path: "/__carrick_o_tmpfile".to_string(),
                metadata: RootFsMetadata {
                    path: Path::new("/__carrick_o_tmpfile").to_path_buf(),
                    kind: RootFsEntryKind::File,
                    mode: create_mode,
                    size: 0,
                },
                contents: FileContents::dense(Vec::new()),
                offset: 0,
                base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                writable: true,
            };
            return Ok(self.install_fd(description, linux_fd_flags_from_open_flags(flags)));
        }

        if false {
            drop(self.proc.lock());
        }

        let lookup = self.lookup_path(
            dirfd,
            path,
            carrick_abi::LinuxAtFlags::empty(),
            LookupIntent::Open {
                context,
                registry,
                open_flags,
                access,
                writable_request,
                flags,
                reporter,
            },
        )?;
        let _ = lookup.fast_path();
        let path = match lookup.target {
            LookupTarget::OpenOutcome(outcome) => return Ok(outcome),
            LookupTarget::Resolved(path) => path,
            LookupTarget::Stat(_) => lookup.resolved_path,
        };

        // VFS-mount routing. DevVfs serves /dev/*, ProcVfs serves
        // /proc/*, SysVfs serves /sys/*. The dispatcher converts each
        // VfsHandle variant into the matching OpenDescription, then
        // falls back to the legacy synthetic-then-overlay-then-rootfs
        // chain for any path no mount claims (or that the mount
        // returns ENOSYS for).
        // O_CREAT mode for a mount-served file: the requested bits masked by the
        // guest umask (the kernel applies `mode & ~umask`). Threaded into the
        // mount's open so e.g. glibc sem_open's `open(/dev/shm/sem.X, O_CREAT,
        // 0600)` materialises a 0600 node — without it the bind mount created
        // the file with mode 0, and a later O_RDWR reopen (multiprocessing
        // SemLock._rebuild in a forkserver child) hit EACCES.
        let vfs_create_mode = if want_create {
            (mode as u32 & 0o7777) & !(self.cred_snapshot().umask & 0o777)
        } else {
            0
        };
        // A write-intent open (O_CREAT or write access) of an OVERRIDABLE
        // single-file injection (/etc/services, /etc/resolv.conf) DETACHES the
        // injection: the read-only synthetic mount would otherwise EACCES on the
        // write. Record the override, then let the open fall through to the
        // writable overlay (after override_path, `resolve` returns None so
        // `try_vfs_open` no longer claims the path).
        if (writable_request || want_create)
            && let Some(m) = self.fs.vfs_mounts.resolve(&path)
            && m.vfs.overridable()
        {
            self.fs.vfs_mounts.override_path(&path);
        }
        // For inotify, note whether a VFS-mounted (bind/dev/proc) path already
        // existed before the open, so a created child emits IN_CREATE (not just
        // IN_OPEN). Only when something is watched, to avoid a wasted lookup.
        let vfs_preexisted = if want_create && !self.fs.inotify_registry.is_empty() {
            self.path_exists(&path)
        } else {
            true
        };
        // `--fs host` trusted-dirfd lane SEED: an O_DIRECTORY read-only open
        // outside every mount gets ONE contained openat + containment proof —
        // no eager per-child materialization, no double kind probe below —
        // and carries the trusted host dirfd the walk's dirfd-relative
        // recursion rides on. Gated on O_DIRECTORY so a regular-file open
        // never pays a wasted directory probe (fts/opendir walks always pass
        // it); gated on root because the DAC/O_NOATIME checks further down
        // are no-ops only for euid 0.
        if !want_create
            && !want_trunc
            && !writable_request
            && open_flags.contains(LinuxOpenFlags::DIRECTORY)
            && self.cred_snapshot().euid.is_root()
            && let Some(outcome) = self.try_open_trusted_dir(&path, flags)
        {
            return Ok(outcome);
        }
        // Validate O_DIRECTORY before a mount can apply O_TRUNC/O_CREAT. Linux
        // rejects a non-directory without mutating it; checking only after
        // `try_vfs_open` had already truncated or created bind-mounted files.
        if open_flags.contains(LinuxOpenFlags::DIRECTORY) {
            match self.inotify_path_kind(&path) {
                Some(false) => return Ok(DispatchOutcome::errno(LINUX_ENOTDIR)),
                None if want_create => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                _ => {}
            }
        }
        let vfs_outcome =
            self.try_vfs_open(context, registry, &path, access, flags, vfs_create_mode);
        match vfs_outcome {
            VfsOpenAttempt::Installed(fd) => {
                // VFS mounts return before the overlay/rootfs O_DIRECTORY gate
                // below. Enforce it here too: GNU mv opens its destination with
                // O_PATH|O_DIRECTORY to decide whether to append the source
                // basename. Accepting a regular bind-mounted file made mv try
                // `dest/source` and left configure's conftest files stale.
                let directory_errno = if open_flags.contains(LinuxOpenFlags::DIRECTORY) {
                    match self.fd_stat_record(fd) {
                        Ok(record) if record.mode & LINUX_S_IFMT == LINUX_S_IFDIR => None,
                        Ok(_) => Some(LINUX_ENOTDIR),
                        Err(errno) => Some(errno),
                    }
                } else {
                    None
                };
                if let Some(errno) = directory_errno {
                    let removed = self.captured_file_table().write_open_files().remove(&fd);
                    self.captured_file_table().write_fd_open_paths().remove(&fd);
                    if let Some(open_file) = removed {
                        self.release_hvpatch_classic_record_locks(context.task().key(), &open_file);
                        self.close_open_file_and_free_pty(&open_file);
                    }
                    self.note_fd_closed(fd);
                    if (0..3).contains(&fd) {
                        // Installation reused a deliberately closed stdio slot
                        // and cleared its marker. The rejected open must leave
                        // that slot closed, just as if no open had occurred.
                        self.captured_file_table().lock_closed_stdio()[fd as usize] = true;
                    }
                    return Ok(DispatchOutcome::errno(errno));
                }
                // inotify: a VFS-mount open bypasses the rootfs tail below, so
                // synthesize its events here. A freshly-created child is
                // IN_CREATE on the parent dir; every successful open is IN_OPEN
                // on the object. The fd's path is recorded by try_vfs_open's
                // install path already (host-backed) or below for read hooks.
                if !self.fs.inotify_registry.is_empty()
                    && !crate::fanotify::internal_open_in_progress()
                {
                    let is_dir = self.inotify_path_kind(&path).unwrap_or(false);
                    if want_create && !vfs_preexisted {
                        self.inotify_child(&path, carrick_abi::LINUX_IN_CREATE, is_dir);
                    }
                    self.fs
                        .inotify_registry
                        .notify_self(&path, carrick_abi::LINUX_IN_OPEN, is_dir);
                    // Ensure read/write/close hooks can recover this fd's path.
                    if self.lookup_recorded_fd_open_path(fd).is_none() {
                        self.record_fd_open_path(fd, path.clone());
                    }
                }
                // Same for fanotify. Kept as its own block (rather than folded
                // into the inotify one) because it must fire when a fanotify
                // mark exists and NO inotify watch does — the two registries
                // are independent, and sharing the `is_empty` guard would make
                // fanotify silently depend on an unrelated inotify watch.
                if !self.fs.fanotify_registry.is_empty()
                    && !crate::fanotify::internal_open_in_progress()
                {
                    self.fanotify_notify(context, &path, carrick_abi::LinuxFanotifyEvents::OPEN);
                    if self.lookup_recorded_fd_open_path(fd).is_none() {
                        self.record_fd_open_path(fd, path.clone());
                    }
                }
                return Ok(DispatchOutcome::returned_i32(fd));
            }
            VfsOpenAttempt::Errno(errno) => {
                return Ok(DispatchOutcome::errno(errno));
            }
            VfsOpenAttempt::FallThrough => {}
        }

        // DAC on open (--fs host, non-root): an existing file needs the
        // requested access (read unless O_WRONLY, write for O_WRONLY/O_RDWR)
        // plus search on every ancestor; creating a new file needs write+search
        // on the parent dir. Root bypasses (handled in dac_check).
        if let Some(errno) = self.dac_open_check(&path, access, want_create) {
            return Ok(DispatchOutcome::errno(errno));
        }

        // O_NOATIME may only be requested by the file's owner (or a holder of
        // CAP_FOWNER, modeled here as euid==0). Linux's do_dentry_open rejects a
        // non-owner with EPERM (fs/open.c -> inode_owner_or_capable). Only
        // enforce when the backing file exists and reports a real owner; a
        // not-yet-existent O_CREAT target has no owner to compare against.
        if open_flags.contains(LinuxOpenFlags::NOATIME) {
            let creds = self.cred_snapshot();
            if !creds.euid.is_root()
                && let Some(real) = self.fs.rootfs_vfs.overlay.real_stat(&path, true)
                && real.uid != creds.euid
            {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
        }

        // FIFO (named pipe): Linux named FIFO open handshake.
        // A blocking open waits for peer presence (O_RDONLY waits for a writer,
        // O_WRONLY waits for a reader; O_RDWR never blocks).
        // Blocking is handled by parking on the level-triggered presence pipes in
        // fifo_beacon via WaitOnFds with the dispatcher lock released, and
        // re-dispatching openat on readiness. Signal interruption yields EINTR
        // or restarts under SA_RESTART.
        if self.fs.rootfs_vfs.overlay.may_have_fifo_nodes()
            && let Ok(md) = self.layered_metadata(&path)
            && md.kind == RootFsEntryKind::Fifo
        {
            // An existing FIFO + O_CREAT|O_EXCL must fail like the kernel.
            if want_create && want_excl {
                return Ok(DispatchOutcome::errno(LINUX_EEXIST));
            }
            // Linux O_ACCMODE is 0=RDONLY, 1=WRONLY, 2=RDWR.
            let access_idx = (access & LINUX_O_ACCMODE) as u32;
            let is_nonblock = open_flags.contains(LinuxOpenFlags::NONBLOCK);

            let id = self.fs.rootfs_vfs.overlay.fifo_identity(&path);
            let Some(id) = id else {
                return Ok(DispatchOutcome::errno(linux_errno::ENXIO));
            };

            let host_fd_opt = self
                .fs
                .rootfs_vfs
                .overlay
                .open_fifo_nonblock(&path, access_idx);

            // Determine if this open must block waiting for a peer:
            // - O_RDWR (access_idx == 2) never blocks.
            // - O_NONBLOCK never blocks (O_RDONLY succeeds, O_WRONLY without reader -> ENXIO).
            // - O_RDONLY (access_idx == 0) blocks if no writer is currently present.
            // - O_WRONLY (access_idx == 1) blocks if host open failed (no reader on host).
            if !is_nonblock && access_idx == 0 {
                // Blocking reader: host nonblocking open succeeded (host_fd_opt is Some),
                // but Linux requires waiting until at least one writer is present.
                let Some(host_fd) = host_fd_opt else {
                    return Ok(DispatchOutcome::errno(linux_errno::ENXIO));
                };
                if !crate::dispatch::fifo_beacon::is_writer_present(id) {
                    // Register the opened host read fd as a parked reader:
                    // 1. Keeps the host read fd open across the park so macOS counts it
                    //    and any concurrent O_WRONLY open succeeds on host.
                    // 2. Asserts readers_present in fifo_beacon so writers wake.
                    crate::dispatch::net::set_host_nonblocking(host_fd);
                    let writers_present_read_fd =
                        crate::dispatch::fifo_beacon::writers_present_read_fd(id)
                            .ok_or(linux_errno::EIO)?;
                    let token =
                        crate::dispatch::fifo_beacon::ParkedOpenerToken::new_reader(host_fd, id);
                    // When the wait finishes or is interrupted, the WaitFdGuard drops the token,
                    // unregistering the parked reader from fifo_beacon and closing host_fd.
                    // On readiness, the runtime re-dispatches openat from scratch and re-opens
                    // the host FIFO.
                    return Ok(DispatchOutcome::WaitOnFds {
                        fds: WaitFds::anchored_parked_opener(
                            writers_present_read_fd,
                            libc::POLLIN,
                            token,
                        ),
                        timeout: None,
                        sig_mask: carrick_abi::WaitSigMask::Additive(carrick_abi::SigSet::EMPTY),
                        completion: FdWaitCompletion::Fd { on_timeout: 0 },
                    });
                }
            } else if !is_nonblock && access_idx == 1 && host_fd_opt.is_none() {
                // Blocking writer without reader on host: park until a reader arrives.
                let (readers_present_read_fd, token) =
                    crate::dispatch::fifo_beacon::ParkedOpenerToken::new_writer(id)
                        .ok_or(linux_errno::EIO)?;
                return Ok(DispatchOutcome::WaitOnFds {
                    fds: WaitFds::anchored_parked_opener(
                        readers_present_read_fd,
                        libc::POLLIN,
                        token,
                    ),
                    timeout: None,
                    sig_mask: carrick_abi::WaitSigMask::Additive(carrick_abi::SigSet::EMPTY),
                    completion: FdWaitCompletion::Fd { on_timeout: 0 },
                });
            }

            match host_fd_opt {
                Some(host_fd) => {
                    // Track this FIFO end for kernel-backed writer-close EOF
                    // readiness (macOS won't report it — see dispatch::fifo_beacon)
                    // and peer presence.
                    crate::dispatch::fifo_beacon::register_open(host_fd, access_idx);
                    crate::dispatch::net::set_host_nonblocking(host_fd);
                    let description = OpenDescription::HostPipe {
                        // A named FIFO's two ends are opened separately but share
                        // ONE on-disk inode, so the host inode is a join key both
                        // ends agree on (the FASYNC arm/trigger across ends works
                        // for FIFOs as it does for anonymous pipes).
                        pipe_id: host_inode_pipe_id(host_fd),
                        host_fd: HostFdRef::new(host_fd),
                        is_read_end: access != LINUX_O_WRONLY,
                        base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC)
                            .with_fs_identity(crate::vfs::FsIdentity::Overlay),
                        pty: None,
                        bidirectional: access == LINUX_O_RDWR,
                        write_kind: HostWriteKind::PipeLike,
                        stdio_stream: None,
                    };
                    let status = flags & !LINUX_O_CLOEXEC;
                    let open_file = OpenFile::from_open_description_with_status_flags(
                        Arc::new(RwLock::new(description)),
                        status,
                        linux_fd_flags_from_open_flags(flags),
                    );
                    let Ok(fd) = self.install_fd_at_or_above(0, open_file) else {
                        return Ok(DispatchOutcome::errno(linux_errno::EMFILE));
                    };
                    self.record_fd_open_path(fd, path.clone());
                    return Ok(DispatchOutcome::returned_i32(fd));
                }
                // The non-blocking open failed — most commonly O_WRONLY with no
                // reader (ENXIO, the correct O_NONBLOCK errno).
                None => return Ok(DispatchOutcome::errno(linux_errno::ENXIO)),
            }
        }

        // /proc/* and /sys/* synthetic file opens now flow through
        // ProcVfs / SysVfs (mounted in `SyscallDispatcher::new`). Any
        // unknown /proc or /sys path returns ENOSYS from the mount
        // and falls through to the overlay+rootfs lookup below, which
        // handles directory entries like /proc itself.

        if let Some(outcome) = Self::record_unimplemented_virtual_file(reporter, &path) {
            return Ok(outcome);
        }
        // Layered overlay+rootfs lookup with full openat semantics
        // (O_CREAT/O_EXCL/O_TRUNC, write-promotion of rootfs-only
        // files) lives in RootFsVfs::open_for_dispatch.
        let dispatch_result = self.fs.rootfs_vfs.open_for_dispatch(
            &path,
            want_create,
            want_excl,
            want_trunc,
            writable_request,
        );
        // USDT probe: every guest path-level open, with the resolved
        // path string and resulting size/errno. Lets dtrace operators
        // see exactly what bytes each forked carrick process is
        // serving for paths like /etc/hosts during the apt-resolver
        // run.
        match &dispatch_result {
            Ok(crate::vfs::rootfs::OpenDispatchResult::File { contents, .. }) => {
                crate::probes::path_open(&path, contents.len() as u64, 0);
            }
            Ok(crate::vfs::rootfs::OpenDispatchResult::RootFsBackedFile { metadata, .. }) => {
                crate::probes::path_open(&path, metadata.size as u64, 0);
            }
            Ok(crate::vfs::rootfs::OpenDispatchResult::HostFile { metadata, .. }) => {
                crate::probes::path_open(&path, metadata.size as u64, 0);
            }
            Ok(crate::vfs::rootfs::OpenDispatchResult::Directory { .. }) => {
                crate::probes::path_open(&path, 0, 0);
            }
            Ok(crate::vfs::rootfs::OpenDispatchResult::NotFoundCreate) => {
                crate::probes::path_open(&path, 0, 0);
            }
            Err(errno) => {
                crate::probes::path_open(&path, 0, errno.get());
            }
        }
        // O_DIRECTORY: opening anything that isn't a directory fails ENOTDIR
        // (LTP open08). Close a host fd the dispatch already opened so it
        // doesn't leak.
        if open_flags.contains(LinuxOpenFlags::DIRECTORY) {
            match &dispatch_result {
                Ok(crate::vfs::rootfs::OpenDispatchResult::HostFile { host_fd, .. }) => {
                    unsafe {
                        libc::close(*host_fd);
                    }
                    return Ok(DispatchOutcome::errno(LINUX_ENOTDIR));
                }
                Ok(crate::vfs::rootfs::OpenDispatchResult::File { .. }) => {
                    return Ok(DispatchOutcome::errno(LINUX_ENOTDIR));
                }
                Ok(crate::vfs::rootfs::OpenDispatchResult::RootFsBackedFile { .. }) => {
                    return Ok(DispatchOutcome::errno(LINUX_ENOTDIR));
                }
                _ => {}
            }
        }
        // Remember the guest path so readlink(/proc/self/fd/N) can recover it
        // (host-fd-backed descriptions store no path of their own).
        let record_path = path.clone();
        // Whether this open materialized a new file (O_CREAT on a missing path):
        // the inotify hook below emits IN_CREATE for it vs IN_OPEN for an
        // existing-file open. Captured before the match consumes `dispatch_result`.
        let inotify_created = matches!(
            &dispatch_result,
            Ok(crate::vfs::rootfs::OpenDispatchResult::NotFoundCreate)
        );
        let description = match dispatch_result {
            Ok(crate::vfs::rootfs::OpenDispatchResult::File {
                metadata,
                contents,
                writable,
            }) => OpenDescription::File {
                path,
                metadata,
                contents: FileContents::dense(contents),
                offset: 0,
                base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                writable,
            },
            Ok(crate::vfs::rootfs::OpenDispatchResult::RootFsBackedFile {
                metadata,
                contents,
                writable,
            }) => OpenDescription::File {
                path,
                metadata,
                contents: FileContents::shared_backed(contents.base, contents.dirty, contents.len),
                offset: 0,
                base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                writable,
            },
            Ok(crate::vfs::rootfs::OpenDispatchResult::HostFile {
                host_fd,
                metadata,
                writable,
            }) => {
                debug_assert!(crate::dispatch::net::host_fd_is_nonblocking(host_fd));
                if want_trunc {
                    self.invalidate_dentry_host_fd(host_fd);
                }
                OpenDescription::HostFile {
                    host_fd: HostFdRef::new(host_fd),
                    metadata,
                    base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                    writable,
                }
            }
            Ok(crate::vfs::rootfs::OpenDispatchResult::Directory { metadata }) => {
                // A directory can never be the target of a write-intent open
                // (O_WRONLY/O_RDWR) nor of an O_CREAT open — Linux returns
                // EISDIR in both cases (a directory is never "created" by
                // open(), and its dentry rejects write access). O_RDONLY
                // without O_CREAT still yields a readable directory fd.
                if writable_request || want_create {
                    return Ok(DispatchOutcome::errno(LINUX_EISDIR));
                }
                OpenDescription::Directory {
                    path,
                    metadata,
                    listing: DirListing::Pending,
                    offset: 0,
                    base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                    // The trusted lane (`try_open_trusted_dir`) already
                    // declined this open (mount/inotify/backend), so the
                    // description keeps the historical untrusted model.
                    trusted_host_dir: None,
                }
            }
            Ok(crate::vfs::rootfs::OpenDispatchResult::NotFoundCreate) => {
                // O_CREAT path: validate the parent directory exists,
                // create the empty overlay entry, return a writable
                // File description.
                // O_CREAT mode: the requested mode masked by the guest umask,
                // exactly like the kernel (`mode & ~umask`). Only applies to a
                // freshly-created file (this branch only runs when no file
                // existed). Previously hardcoded to 0o644, so creat(f, 0777)
                // always yielded 644 and umask had no effect.
                let creds = self.cred_snapshot();
                let create_mode = (mode as u32 & 0o7777) & !(creds.umask & 0o777);
                let metadata = RootFsMetadata {
                    path: Path::new(&path).to_path_buf(),
                    kind: RootFsEntryKind::File,
                    mode: create_mode,
                    size: 0,
                };
                // Disk-backed overlay (--fs host): create + open a real
                // host fd so the new file is fork-shareable. Falls back
                // to the in-memory File for MemoryBackend.
                // A new file is owned by the creating process's effective
                // uid/gid (Linux semantics). carrick stamps it so a guest that
                // setuid()'d to e.g. "nobody" before creating sees the right
                // owner. Root (0,0) is the default, so only stamp non-root.
                let create_uid = creds.fsuid;
                let mut create_gid = creds.fsgid;
                // ONE layered lookup of the parent answers both questions:
                // it must be a directory (ENOENT otherwise), and a SETGID
                // directory hands the new file ITS group, not the creator's
                // fsgid (creat08/open10/mknod05). The file's own setgid bit
                // is carried by `mode`; here we only fix the owning group.
                if let Some(parent) = Path::new(&path).parent() {
                    let parent_str = display_rootfs_path(parent);
                    let parent_md = match self.layered_metadata(&parent_str) {
                        Ok(md) if md.kind == RootFsEntryKind::Directory => md,
                        _ => return Ok(DispatchOutcome::errno(LINUX_ENOENT)),
                    };
                    if parent_md.mode & 0o2000 != 0
                        && let Some((_, pgid)) = self.fs.rootfs_vfs.overlay.get_owner(&parent_str)
                    {
                        create_gid = pgid;
                    }
                }
                let stamp_owner = !create_uid.is_root() || !create_gid.is_root();
                // A host refusal (`ENFILE`: the host would not give carrick
                // the descriptor the guest is entitled to) is the guest's
                // errno — never lowered to the in-memory create below, whose
                // own failure is the backend's `EINVAL`.
                let created = match self
                    .fs
                    .rootfs_vfs
                    .create_raw_fd(&path, create_mode, want_trunc)
                {
                    crate::fs_backend::HostFdOpen::Served(created) => Some(created),
                    crate::fs_backend::HostFdOpen::Refused(refused) => {
                        return Ok(DispatchOutcome::errno(refused));
                    }
                    crate::fs_backend::HostFdOpen::Unavailable => None,
                };
                if let Some((host_fd, mode_applied)) = created {
                    if want_trunc {
                        self.invalidate_dentry_host_fd(host_fd);
                    }
                    debug_assert!(crate::dispatch::net::host_fd_is_nonblocking(host_fd));
                    // A backend that created with the host umask (or could not
                    // represent the mode natively) still needs the guest mode
                    // forced onto the new file.
                    if !mode_applied {
                        let _ = self.fs.rootfs_vfs.set_mode(&path, create_mode);
                    }
                    if stamp_owner {
                        let _ =
                            self.fs
                                .rootfs_vfs
                                .set_owner(&path, Some(create_uid), Some(create_gid));
                    }
                    OpenDescription::HostFile {
                        host_fd: HostFdRef::new(host_fd),
                        metadata,
                        base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                        // A newly-created file's GUEST writability is its
                        // access mode, NOT the O_CREAT flag: O_RDONLY|O_CREAT
                        // creates the file but a later write/ftruncate on the
                        // fd is EINVAL (ftruncate03 read_fd). The host fd is
                        // still opened RW above so creation/overlay works.
                        writable: writable_request,
                    }
                } else {
                    match self.fs.rootfs_vfs.create_file(&path) {
                        Ok(()) => {}
                        Err(crate::fs_backend::BackendError::Host(refused)) => {
                            return Ok(DispatchOutcome::errno(refused));
                        }
                        Err(_) => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                    }
                    let _ = self.fs.rootfs_vfs.set_mode(&path, create_mode);
                    if stamp_owner {
                        let _ =
                            self.fs
                                .rootfs_vfs
                                .set_owner(&path, Some(create_uid), Some(create_gid));
                    }
                    OpenDescription::File {
                        path,
                        metadata,
                        contents: FileContents::dense(Vec::new()),
                        offset: 0,
                        base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                        // Guest writability follows the access mode, not
                        // O_CREAT (O_RDONLY|O_CREAT → read-only fd).
                        writable: writable_request,
                    }
                }
            }
            Err(errno) => return Ok(DispatchOutcome::errno(errno)),
        };

        let needs_recorded_path = !matches!(
            &description,
            OpenDescription::File { .. } | OpenDescription::Directory { .. }
        );
        let opened_is_dir = matches!(&description, OpenDescription::Directory { .. });
        let status = flags & !LINUX_O_CLOEXEC;
        let open_file = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(description)),
            status,
            linux_fd_flags_from_open_flags(flags),
        );
        let Ok(fd) = self.install_fd_at_or_above(0, open_file) else {
            return Ok(DispatchOutcome::errno(linux_errno::EMFILE));
        };
        // Always record the path for the inotify AND fanotify read/write/close
        // hooks, even for in-memory File/Directory descriptions (they otherwise
        // skip recording); the recorded entry is dropped when the fd closes.
        // This is the only path by which a later read(2)/write(2)/close(2)
        // recovers the watched guest path.
        //
        // The fanotify half is load-bearing for a DIRECTORY: under `--fs host`
        // a regular file gets a `HostFile` description (which records anyway)
        // but a directory gets `Directory`, which does not. Omitting fanotify
        // here silently dropped `FAN_CLOSE_NOWRITE` for `close(2)` on a marked
        // directory — fanotify02's eighth and final event — while every event
        // on a file still worked, which is exactly the kind of gap that reads
        // as "delivery works" until one case disagrees.
        if needs_recorded_path
            || !self.fs.inotify_registry.is_empty()
            || !self.fs.fanotify_registry.is_empty()
        {
            self.record_fd_open_path(fd, record_path.clone());
        }
        // inotify: O_CREAT that created the file is IN_CREATE on the parent dir;
        // any other successful open is IN_OPEN on the object itself (and, for a
        // directory open, IN_OPEN|IN_ISDIR). The registry fast-exits when nothing
        // is watched, so this is ~free in the common case.
        if !self.fs.inotify_registry.is_empty() && !crate::fanotify::internal_open_in_progress() {
            if inotify_created {
                self.inotify_child(&record_path, carrick_abi::LINUX_IN_CREATE, opened_is_dir);
            }
            // Any successful open is IN_OPEN, delivered BOTH to a watch on the
            // object itself (self) AND to a watch on its parent directory (child,
            // name = basename) — the kernel reports a child's open to the dir
            // watch with the child's name (inotify02 watches the dir and asserts
            // IN_OPEN with name=test_file1). A create also "opens" the new file.
            // Parent (child) event precedes the self event, matching Linux
            // fsnotify ordering (inotify10).
            self.inotify_child(&record_path, carrick_abi::LINUX_IN_OPEN, opened_is_dir);
            self.inotify_self(&record_path, carrick_abi::LINUX_IN_OPEN);
        }
        // fanotify FAN_OPEN. One event per open regardless of how many marks
        // match; `opened_is_dir` is passed through because it is already known
        // here and gates FAN_ONDIR.
        self.fanotify_notify_kind(
            context,
            &record_path,
            carrick_abi::LinuxFanotifyEvents::OPEN,
            opened_is_dir,
        );
        if inotify_created {
            self.dnotify_child(context, &record_path, LinuxDnotifyMask::CREATE);
        }
        Ok(DispatchOutcome::returned_i32(fd))
    }

    // === Trusted-dirfd fast lane (`--fs host`) ===
    //
    // A directory opened through the host backend's contained fast path
    // carries a TRUSTED host dirfd (see [`TrustedHostDir`]): its real host
    // path byte-equals sandbox_root + guest path, so a SINGLE-component child
    // name resolved against it with `O_NOFOLLOW` cannot escape (no "..", no
    // symlink following) — structural containment, NO per-op `F_GETPATH`.
    // That serves the fs-walk hot loop (openat / newfstatat / faccessat on
    // getdents output, and getdents itself) at host-syscall parity instead of
    // paying the per-op dispatch resolution stack (anchor re-verify,
    // validate_parents_fast, canonicalize probe, layered stat). Trust only
    // ever flows from the contained fast path; the VFS synthetic mounts and
    // the memory backend keep today's paths.

    /// The single path component `path` names, when the trusted-dirfd lane
    /// may serve it: non-empty, no '/', not "."/"..", within NAME_MAX, and
    /// ASCII — a non-ASCII leaf could be a Unicode alias of a
    /// differently-normalized on-disk name, which only the slow path's
    /// byte-exact readdir guard can reject.
    pub(super) fn trusted_lane_component(path: &str) -> Option<&str> {
        if path.is_empty()
            || path.len() > 255
            || !path.is_ascii()
            || path == "."
            || path == ".."
            || path.contains('/')
        {
            return None;
        }
        Some(path)
    }

    /// The guest directory path + trusted host dirfd behind guest fd `dirfd`,
    /// when its open description is a trusted Directory. `None` for AT_FDCWD,
    /// negative fds, and every untrusted description.
    pub(super) fn trusted_dir_of(&self, dirfd: u64) -> Option<(String, TrustedHostDir)> {
        let fd = dirfd as i32;
        if fd < 0 {
            return None; // AT_FDCWD and friends
        }
        let open_file = self.open_file(fd)?;
        let open = open_file.description.read()?;
        match &*open {
            OpenDescription::Directory {
                path,
                trusted_host_dir: Some(trusted),
                ..
            } => Some((path.clone(), trusted.clone())),
            _ => None,
        }
    }

    /// Compose `dir/name` and gate it for the trusted lane: the child must be
    /// outside every synthetic tree and VFS mount (a bind mount or /proc /sys
    /// /dev target under the trusted dir is claimed by its mount, never by
    /// the scratch). `None` ⇒ the caller takes the full path.
    pub(super) fn trusted_child_path(&self, dir: &str, name: &str) -> Option<String> {
        let full = if dir == "/" {
            format!("/{name}")
        } else {
            format!("{dir}/{name}")
        };
        if full.starts_with("/proc") || full.starts_with("/sys") || full.starts_with("/dev") {
            return None;
        }
        if self.fs.vfs_mounts.resolve(&full).is_some() {
            return None;
        }
        Some(full)
    }

    /// Direct absolute read from an upper-absent immutable cached lower.
    /// Every shape whose Linux semantics need the full resolver (relative
    /// dirfds, final-component nofollow, creates/writes, directories, mounts,
    /// chroot, DAC/inotify) fails closed to the historical path.
    pub(super) fn try_immutable_lower_absolute_open(
        &self,
        dirfd: u64,
        path: &str,
        flags: u64,
    ) -> Option<DispatchOutcome> {
        use std::os::fd::IntoRawFd as _;

        if !trusted_fs_lane_enabled()
            || dirfd != LINUX_AT_FDCWD
            || !path.starts_with('/')
            || !self.cred_snapshot().euid.is_root()
            || !self.fs.inotify_registry.is_empty()
            || !self.fs.fanotify_registry.is_empty()
        {
            return None;
        }
        let open_flags = LinuxOpenFlags::from_bits_retain(flags);
        if flags & LINUX_O_ACCMODE != LINUX_O_RDONLY
            || open_flags.intersects(
                LinuxOpenFlags::CREAT
                    | LinuxOpenFlags::TRUNC
                    | LinuxOpenFlags::EXCL
                    | LinuxOpenFlags::TMPFILE
                    | LinuxOpenFlags::PATH
                    | LinuxOpenFlags::DIRECTORY
                    | LinuxOpenFlags::NOFOLLOW,
            )
        {
            return None;
        }
        if self
            .captured_fs_context()
            .chroot_root()
            .as_deref()
            .is_some_and(|root| root != "/")
            || path.starts_with("/proc")
            || path.starts_with("/sys")
            || path.starts_with("/dev")
            || self.fs.vfs_mounts.resolve(path).is_some()
        {
            return None;
        }
        let (file, metadata) = match self.fs.rootfs_vfs.open_immutable_lower_readonly(path) {
            crate::fs_backend::ImmutableHostFileOpen::Served { file, metadata } => (file, metadata),
            crate::fs_backend::ImmutableHostFileOpen::Missing => {
                return Some(DispatchOutcome::errno(LINUX_ENOENT));
            }
            crate::fs_backend::ImmutableHostFileOpen::Fallback => return None,
        };
        let raw = file.into_raw_fd();
        debug_assert!(crate::dispatch::net::host_fd_is_nonblocking(raw));
        crate::probes::path_open(path, metadata.size as u64, 0);
        let description = OpenDescription::HostFile {
            host_fd: HostFdRef::with_private_file_source(
                raw,
                carrick_guest_mem::PrivateFileSource::ImmutableLower,
            ),
            metadata,
            base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
            writable: false,
        };
        let status = flags & !LINUX_O_CLOEXEC;
        let open_file = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(description)),
            status,
            linux_fd_flags_from_open_flags(flags),
        );
        let Ok(fd) = self.install_fd_at_or_above(0, open_file) else {
            return Some(DispatchOutcome::errno(linux_errno::EMFILE));
        };
        self.record_fd_open_path(fd, path.to_owned());
        Some(DispatchOutcome::returned_i32(fd))
    }

    /// `--fs host` trusted directory open — the lane SEED. A plain read-only
    /// directory open outside every mount is served by ONE contained
    /// `openat(O_DIRECTORY)` with a byte-exact containment proof
    /// ([`FsBackend::open_trusted_dir_fd`]), skipping `open_for_dispatch`'s
    /// eager per-child directory materialization entirely (entries stream on
    /// the first getdents64). `find`-style walks open the walk root once by
    /// absolute path, then recurse `openat(dirfd, name)` through
    /// [`Self::try_trusted_dirfd_openat`], which keeps every served child
    /// directory on the lane. Every dispatch-level gate (DAC, O_NOATIME, the
    /// FIFO interception) has already run when this is consulted.
    fn try_open_trusted_dir(&self, path: &str, flags: u64) -> Option<DispatchOutcome> {
        use std::os::fd::IntoRawFd;
        // Default ON with an exact `=0` escape hatch (AGENTS.md): this is the
        // SEED of the whole trusted-dirfd lane — with no directory ever
        // trusted, every dependent fast path (`try_trusted_dirfd_openat`,
        // `try_trusted_dirfd_stat`, the F_OK lane, streamed getdents) falls
        // back to the resolving path on its own, so one switch bisects the
        // entire lane against the historical behaviour.
        if !trusted_fs_lane_enabled() {
            return None;
        }
        // Notification hooks must keep today's path: the fast lane installs
        // the directory description without reaching the FAN_OPEN / IN_OPEN
        // emission at the end of the resolving open, so a fanotify mark on a
        // directory with FAN_ONDIR (LTP fanotify04, probe `fanotifyondir`)
        // saw no event while any inotify watch already steered around the
        // lane. chroot rebases absolute resolution, so keep the lane out of
        // it too.
        if !self.fs.inotify_registry.is_empty() || !self.fs.fanotify_registry.is_empty() {
            return None;
        }
        if self
            .captured_fs_context()
            .chroot_root()
            .as_deref()
            .is_some_and(|root| root != "/")
        {
            return None;
        }
        if path.starts_with("/proc") || path.starts_with("/sys") || path.starts_with("/dev") {
            return None;
        }
        if self.fs.vfs_mounts.resolve(path).is_some() {
            return None;
        }
        let trusted = if let Some(rootfs) = self.fs.rootfs_vfs.rootfs.as_ref() {
            // A lower anchor is exact only while the sparse upper contributes
            // nothing at this directory. Sample the fork-shared structural
            // generation around both proofs so a concurrent mutation makes
            // the anchor stale before it can serve a child.
            let generation = self.fs.rootfs_vfs.overlay.structural_generation();
            if self.fs.rootfs_vfs.overlay.fast_nofollow_absent(path) {
                let host_fd = rootfs.open_trusted_dir_fd(path)?;
                if self.fs.rootfs_vfs.overlay.structural_generation() != generation {
                    return None;
                }
                TrustedHostDir::immutable_lower(HostFdRef::new(host_fd.into_raw_fd()), generation)
            } else {
                // The upper holds something here. If the IMMUTABLE lower has
                // no entry at this path — `NotFound` is the only authoritative
                // answer; an I/O or shape error keeps the exact path — its
                // absence is permanent for every descendant, so the upper
                // directory is the whole merged namespace of that subtree
                // (LTP `creat05`'s guest-made scratch dir). A whiteouted or
                // merged directory still takes the layered path.
                if !matches!(
                    rootfs.symlink_metadata(path),
                    Err(crate::rootfs::RootFsError::NotFound(_))
                ) {
                    return None;
                }
                let host_fd = self.fs.rootfs_vfs.overlay.open_trusted_dir_fd(path)?;
                TrustedHostDir::merged_upper(HostFdRef::new(host_fd.into_raw_fd()))
            }
        } else {
            let host_fd = self.fs.rootfs_vfs.overlay.open_trusted_dir_fd(path)?;
            TrustedHostDir::merged_upper(HostFdRef::new(host_fd.into_raw_fd()))
        };
        crate::probes::path_open(path, 0, 0);
        let metadata = RootFsMetadata {
            path: Path::new(path).to_path_buf(),
            kind: RootFsEntryKind::Directory,
            // Parity with open_for_dispatch's Directory arm, which reports a
            // fixed 0o755 on directory open descriptions.
            mode: 0o755,
            size: 0,
        };
        let description = OpenDescription::Directory {
            path: path.to_owned(),
            metadata,
            listing: DirListing::Pending,
            offset: 0,
            base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
            trusted_host_dir: Some(trusted),
        };
        let status = flags & !LINUX_O_CLOEXEC;
        let open_file = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(description)),
            status,
            linux_fd_flags_from_open_flags(flags),
        );
        let Ok(fd) = self.install_fd_at_or_above(0, open_file) else {
            return Some(DispatchOutcome::errno(linux_errno::EMFILE));
        };
        Some(DispatchOutcome::returned_i32(fd))
    }

    pub(super) fn try_dentry_fast_open(
        &self,
        path: &str,
        flags: u64,
        access: u64,
        writable_request: bool,
    ) -> Option<DispatchOutcome> {
        let open_flags = LinuxOpenFlags::from_bits_retain(flags);
        if open_flags.intersects(
            LinuxOpenFlags::NOFOLLOW
                | LinuxOpenFlags::DIRECTORY
                | LinuxOpenFlags::TMPFILE
                | LinuxOpenFlags::PATH,
        ) || (access != LINUX_O_RDONLY && access != LINUX_O_RDWR && access != LINUX_O_WRONLY)
            || !path.starts_with('/')
            || path.ends_with('/')
            || path.ends_with("/.")
            || path.split('/').any(|c| c == "..")
            || path.starts_with("/proc")
            || path.starts_with("/sys")
            || path.starts_with("/dev")
            || !self.dac_overrides_permissions()
            || !self.fs.inotify_registry.is_empty()
            || !self.fs.fanotify_registry.is_empty()
            || self.fs.vfs_mounts.has_mount(path)
        {
            return None;
        }

        match self.fs.rootfs_vfs.dentry_fast_open(path, writable_request) {
            Ok((host_fd, real, canonical_path, source)) => {
                use std::os::fd::IntoRawFd;
                let raw = host_fd.into_raw_fd();
                debug_assert!(crate::dispatch::net::host_fd_is_nonblocking(raw));
                crate::probes::path_open(path, real.size, 0);
                let metadata = RootFsMetadata {
                    path: std::path::Path::new(path).to_path_buf(),
                    kind: RootFsEntryKind::File,
                    mode: real.mode,
                    size: usize::try_from(real.size).unwrap_or(usize::MAX),
                };
                let description = OpenDescription::HostFile {
                    host_fd: HostFdRef::with_private_file_source(raw, source),
                    metadata,
                    base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                    writable: writable_request,
                };
                let status = flags & !LINUX_O_CLOEXEC;
                let open_file = OpenFile::from_open_description_with_status_flags(
                    Arc::new(RwLock::new(description)),
                    status,
                    linux_fd_flags_from_open_flags(flags),
                );
                if let Ok(fd) = self.install_fd_at_or_above(0, open_file) {
                    self.record_fd_open_path(fd, canonical_path);
                    Some(DispatchOutcome::returned_i32(fd))
                } else {
                    Some(DispatchOutcome::errno(linux_errno::EMFILE))
                }
            }
            Err(LINUX_ENOENT) => Some(DispatchOutcome::errno(LINUX_ENOENT)),
            Err(LINUX_EISDIR) if writable_request => Some(DispatchOutcome::errno(LINUX_EISDIR)),
            Err(_) => None,
        }
    }

    /// Single-component `openat` through a TRUSTED host dirfd: service the
    /// open DIRECTLY against the host dirfd (one openat + fstat + one
    /// flistxattr-gated xattr peek), skipping `resolve_at_path` and the
    /// layered open stack. `None` ⇒ take the full path. A served directory is
    /// itself trusted (the walk's recursion stays on the lane); symlink
    /// children (`ELOOP`), FIFOs, marker nodes, and every surprise fall back
    /// to the exact slow path.
    pub(super) fn try_trusted_dirfd_openat(
        &self,
        dirfd: u64,
        path: &str,
        flags: u64,
    ) -> Option<DispatchOutcome> {
        use std::os::fd::{FromRawFd, IntoRawFd, OwnedFd};
        let open_flags = LinuxOpenFlags::from_bits_retain(flags);
        // Creating/truncating opens and the special modes keep the full path
        // (sandboxed parent creation, exact O_TRUNC, O_TMPFILE/O_PATH
        // modeling).
        if open_flags.intersects(
            LinuxOpenFlags::CREAT
                | LinuxOpenFlags::TRUNC
                | LinuxOpenFlags::EXCL
                | LinuxOpenFlags::TMPFILE
                | LinuxOpenFlags::PATH,
        ) {
            return None;
        }
        let name = Self::trusted_lane_component(path)?;
        let (dir_path, trusted_dir) = self.trusted_dir_of(dirfd)?;
        if !trusted_dir
            .namespace_is_current_against(self.fs.rootfs_vfs.overlay.structural_generation())
        {
            return None;
        }
        let host_dir = &trusted_dir.fd;
        let full = self.trusted_child_path(&dir_path, name)?;
        // inotify watches and fanotify marks need the slow path's IN_OPEN /
        // FAN_OPEN bookkeeping; a non-root euid needs its DAC checks (root —
        // the overwhelming default — bypasses both DAC and search permission).
        if !self.fs.inotify_registry.is_empty()
            || !self.fs.fanotify_registry.is_empty()
            || !self.cred_snapshot().euid.is_root()
        {
            return None;
        }
        let access = flags & LINUX_O_ACCMODE;
        let write = access == LINUX_O_WRONLY || access == LINUX_O_RDWR;
        let name_c = std::ffi::CString::new(name).ok()?;
        // Mirrors `fast_open_for_guest`: O_NONBLOCK so a racing FIFO can
        // never block the dispatcher; O_NOFOLLOW so a symlink child is ELOOP
        // (the slow path re-roots its target under the GUEST root); O_NOCTTY
        // defensively; and the guest's OWN access mode (a live MAP_SHARED
        // alias of a read-only description upgrades the host fd in place at
        // map time — `FsBackend::upgrade_host_fd_for_shared_map`).
        let base = libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NOCTTY;
        let last_errno = || std::io::Error::last_os_error().raw_os_error();
        // A read-only O_DIRECTORY request (every walker's dir open) opens the
        // directory directly; the kernel's O_DIRECTORY gives authoritative
        // ENOTDIR.
        let raw = if open_flags.contains(LinuxOpenFlags::DIRECTORY) && !write {
            let raw = unsafe {
                libc::openat(
                    host_dir.raw(),
                    name_c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | base,
                )
            };
            if raw < 0 {
                // A missing name is authoritative. ENOTDIR is authoritative
                // ONLY when the guest itself asked O_NOFOLLOW: this probe
                // carries O_NOFOLLOW, and macOS reports ENOTDIR (not ELOOP)
                // for a SYMLINK-to-directory child under
                // O_DIRECTORY|O_NOFOLLOW — which a guest that asked for
                // neither O_NOFOLLOW nor a refusal must see FOLLOWED to the
                // target directory (serving ENOTDIR there broke test_glob's
                // symlink cases). A guest that DID ask O_NOFOLLOW gets
                // ENOTDIR from Linux for every non-directory leaf — regular,
                // FIFO, and symlink whether to a file or a directory (Docker
                // oracle, 2026-09-02) — so the host answer is exact and the
                // ~10-host-call resolving fallback LTP creat05 paid per
                // cleanup probe is unnecessary. Everything else falls back.
                return match last_errno() {
                    Some(libc::ENOENT) => Some(DispatchOutcome::errno(LINUX_ENOENT)),
                    Some(libc::ENOTDIR) if open_flags.contains(LinuxOpenFlags::NOFOLLOW) => {
                        Some(DispatchOutcome::errno(LINUX_ENOTDIR))
                    }
                    _ => None,
                };
            }
            raw
        } else {
            let accmode = if write { libc::O_RDWR } else { libc::O_RDONLY };
            let raw = unsafe { libc::openat(host_dir.raw(), name_c.as_ptr(), accmode | base, 0) };
            if raw < 0 {
                // A missing name is AUTHORITATIVE under a trusted dir: the
                // scratch is the merged truth, no mount claims the path, and
                // O_CREAT was excluded above. A symlink child goes to the full
                // path (guest O_NOFOLLOW → ELOOP there), as does every other
                // error (a write-intent open of a directory lands on the slow
                // path's exact EISDIR).
                return if last_errno() == Some(libc::ENOENT) {
                    Some(DispatchOutcome::errno(LINUX_ENOENT))
                } else {
                    None
                };
            }
            raw
        };
        // SAFETY: freshly-opened owned fd; drop closes it on every fallback.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(raw, &mut st) } != 0 {
            return None;
        }
        let typ = st.st_mode as u32 & libc::S_IFMT as u32;
        if typ == libc::S_IFDIR as u32 {
            // Write-intent dir opens never reach here (the O_RDWR attempt
            // fails EISDIR → fallback → the slow path's exact EISDIR).
            crate::probes::path_open(&full, 0, 0);
            let metadata = RootFsMetadata {
                path: Path::new(&full).to_path_buf(),
                kind: RootFsEntryKind::Directory,
                mode: 0o755,
                size: 0,
            };
            let description = OpenDescription::Directory {
                path: full,
                metadata,
                listing: DirListing::Pending,
                offset: 0,
                base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
                // Single-component + O_NOFOLLOW under a trusted dir preserves
                // the byte-exact anchor: the served dir is itself trusted on
                // the same layer.
                trusted_host_dir: Some(trusted_dir.child(HostFdRef::new(fd.into_raw_fd()))),
            };
            let status = flags & !LINUX_O_CLOEXEC;
            let open_file = OpenFile::from_open_description_with_status_flags(
                Arc::new(RwLock::new(description)),
                status,
                linux_fd_flags_from_open_flags(flags),
            );
            let Ok(new_fd) = self.install_fd_at_or_above(0, open_file) else {
                return Some(DispatchOutcome::errno(linux_errno::EMFILE));
            };
            return Some(DispatchOutcome::returned_i32(new_fd));
        }
        if typ != libc::S_IFREG as u32 {
            // FIFO (must route through the non-blocking FIFO machinery),
            // real device/socket nodes: exact slow path. The O_NONBLOCK
            // probe fd closes here without ever blocking.
            return None;
        }
        if open_flags.contains(LinuxOpenFlags::DIRECTORY) {
            // O_DIRECTORY of a regular child: authoritative ENOTDIR.
            return Some(DispatchOutcome::errno(LINUX_ENOTDIR));
        }
        // Marker nodes (bound AF_UNIX sockets, mknod devices) carry their
        // guest TYPE in xattrs; the slow path owns their open semantics.
        // With the root markers proving no metadata xattrs or marker nodes
        // exist anywhere, the pass is skipped outright.
        let (override_mode, _uid, _gid, is_socket) =
            if self.fs.rootfs_vfs.overlay.serves_plain_metadata() {
                (None, None, None, false)
            } else {
                crate::fs_backend::fd_carrick_meta(raw)
            };
        if is_socket || override_mode.is_some_and(|m| m & LINUX_S_IFMT != 0) {
            return None;
        }
        let on_disk_mode = st.st_mode as u32 & 0o7777;
        let mode = override_mode
            .map(|m| m & 0o7777)
            .unwrap_or(if on_disk_mode == 0 {
                0o644
            } else {
                on_disk_mode
            });
        // Opened O_NONBLOCK above, which is exactly the host-fd invariant
        // every other install site enforces; the guest's OWN flags live in
        // the description, not the host fd.
        debug_assert!(crate::dispatch::net::host_fd_is_nonblocking(raw));
        crate::probes::path_open(&full, st.st_size as u64, 0);
        let metadata = RootFsMetadata {
            path: Path::new(&full).to_path_buf(),
            kind: RootFsEntryKind::File,
            mode,
            size: st.st_size as usize,
        };
        let description = OpenDescription::HostFile {
            host_fd: HostFdRef::new(fd.into_raw_fd()),
            metadata,
            base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
            writable: write,
        };
        let status = flags & !LINUX_O_CLOEXEC;
        let open_file = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(description)),
            status,
            linux_fd_flags_from_open_flags(flags),
        );
        let Ok(new_fd) = self.install_fd_at_or_above(0, open_file) else {
            return Some(DispatchOutcome::errno(linux_errno::EMFILE));
        };
        // readlink(/proc/self/fd/N) recovers the guest path from
        // fd_open_paths for host-fd-backed descriptions (slow-arm parity).
        self.record_fd_open_path(new_fd, full);
        Some(DispatchOutcome::returned_i32(new_fd))
    }

    /// Try to satisfy an open via the VFS mount table. Returns
    /// `Installed(fd)` when a mount handled it, `Errno(e)` when a
    /// mount explicitly failed, and `FallThrough` when no mount
    /// claimed the path (or the claiming mount returned ENOSYS). The
    /// caller wraps the legacy lookup chain inside `FallThrough`.
    pub(super) fn try_vfs_open(
        &self,
        context: &crate::kernel::KernelContext,
        registry: Option<&crate::thread::ThreadRegistry>,
        path: &str,
        access: u64,
        flags: u64,
        create_mode: u32,
    ) -> VfsOpenAttempt {
        let Some(m) = self.fs.vfs_mounts.resolve(path) else {
            return VfsOpenAttempt::FallThrough;
        };
        // Build the OpenContext only after a mount claims the path. Rootfs and
        // overlay fallthrough opens are the hot path and do not need proc, fd,
        // signal, or memory snapshots for VFS mounts.
        let (timerslack_ns, guest_arch, exec_path, argv, task_comm, env) = {
            let proc = self.proc.lock();
            (
                proc.timerslack,
                proc.reported_arch(),
                proc.executable_path.clone(),
                proc.argv.clone(),
                linux_task_name_to_string(&proc.task_name),
                proc.env.clone(),
            )
        };
        let creds = self.cred_snapshot();
        let native_guest_va = self.page_geometry().native_geometry().is_some();
        let runtime_endpoint_container = Some(context.container().id());
        let identity = self.synthetic_proc_identity(context);

        let exec_path_provider = || Some(std::borrow::Cow::Borrowed(exec_path.as_str()));
        let argv_provider = || Some(std::borrow::Cow::Borrowed(argv.as_slice()));
        let task_comm_provider = || Some(std::borrow::Cow::Borrowed(task_comm.as_str()));
        let environ_provider = || Some(std::borrow::Cow::Borrowed(env.as_slice()));
        let guest_hostname_provider =
            || Some(std::borrow::Cow::Owned(context.task().uts_ns().nodename()));
        let open_fds_provider = || Some(std::borrow::Cow::Owned(self.open_fd_numbers()));
        let network_provider = || Some(std::borrow::Cow::Borrowed(&self.network.spec));
        let network_model_provider = || Some(context.task().net_ns().view().as_ref().clone());
        let groups_provider = || Some(std::borrow::Cow::Owned(self.current_groups()));
        let signals_provider = || {
            let (sig_ignored, sig_caught, sig_shdpnd) = self.proc_status_signal_masks(context);
            (sig_ignored.raw(), sig_caught.raw(), sig_shdpnd.raw())
        };
        let oom_score_adj_provider = || {
            self.hvpatch_process().map(|process| {
                std::borrow::Cow::Owned(
                    process
                        .kernel_graph()
                        .registry()
                        .oom_score_adj_by_pid_for_container(context.container().id())
                        .into_iter()
                        .filter_map(|(pid, value)| {
                            crate::namespace::pid::kernel_to_ns_for(context, pid)
                                .map(|pid| (pid, value))
                        })
                        .collect(),
                )
            })
        };
        let creds_ns_provider = || Some(context.task().creds_ns());
        let processes_provider = || {
            Self::synthetic_proc_processes(context, self.hvpatch_process().as_ref())
                .map(std::borrow::Cow::Owned)
        };
        let threads_provider = || {
            self.synthetic_proc_threads(context, registry)
                .map(std::borrow::Cow::Owned)
        };
        let zombies_provider = || {
            self.hvpatch_process().map(|process| {
                std::borrow::Cow::Owned(
                    process
                        .kernel_graph()
                        .registry()
                        .zombies_for_container(context.container().id())
                        .into_iter()
                        .filter_map(|zombie| {
                            let to_ns = |raw: i32| {
                                u32::try_from(raw).ok().and_then(|raw| {
                                    crate::namespace::pid::kernel_to_ns_for(context, raw)
                                })
                            };
                            Some(crate::vfs::SyntheticProcZombie {
                                pid: to_ns(zombie.key.id.raw())?,
                                ppid: zombie
                                    .parent
                                    .and_then(|parent| to_ns(parent.id.raw()))
                                    .unwrap_or(1),
                                pgrp: zombie.namespace_process_group,
                                session: zombie.namespace_session,
                                comm: zombie.diagnostic_name,
                                user_cpu_us: u64::try_from(zombie.rusage.user_time.as_micros())
                                    .unwrap_or(u64::MAX),
                                system_cpu_us: u64::try_from(zombie.rusage.system_time.as_micros())
                                    .unwrap_or(u64::MAX),
                            })
                        })
                        .collect::<Vec<_>>(),
                )
            })
        };
        let sysvipc_shm_provider = || Some(std::borrow::Cow::Owned(self.sysvipc_shm_table()));
        let sysvipc_sem_provider = || Some(std::borrow::Cow::Owned(self.sysvipc_sem_table()));
        let sysvipc_msg_provider = || Some(std::borrow::Cow::Owned(self.sysvipc_msg_table()));
        // /proc and other synthetic mounts render address-space state. Hold
        // alias exclusion across the complete snapshot so it cannot describe
        // stale VMA metadata while a host replacement is installing.
        let mem_provider = || {
            let mem = self.mem_snapshot();
            let mut address_space_regions = mem.address_space_regions.clone();
            if !mem.dynamic_maps.is_empty() {
                match &mut address_space_regions {
                    Some(regions) => regions.extend(mem.dynamic_maps.clone()),
                    None => address_space_regions = Some(mem.dynamic_maps.clone()),
                }
            }
            crate::vfs::OpenContextMemorySnapshot {
                auxv: std::borrow::Cow::Owned(mem.linux_auxv_image.clone()),
                address_space_regions: address_space_regions.map(std::borrow::Cow::Owned),
                locked_memory: std::borrow::Cow::Owned(mem.locked_ranges.clone()),
                brk_current: mem.brk_current,
                mmap_next: mem.mmap_next,
                heap_base: mem.layout.heap_base,
            }
        };
        let ctx = crate::vfs::OpenContext {
            timerslack_ns,
            guest_arch,
            native_guest_va,
            ruid: creds.ruid,
            euid: creds.euid,
            suid: creds.suid,
            rgid: creds.rgid,
            egid: creds.egid,
            sgid: creds.sgid,
            runtime_endpoint_container,
            identity,
            executable_path: crate::vfs::LazyField::new(&exec_path_provider),
            argv: crate::vfs::LazyField::new(&argv_provider),
            task_comm: crate::vfs::LazyField::new(&task_comm_provider),
            guest_hostname: crate::vfs::LazyField::new(&guest_hostname_provider),
            environ: crate::vfs::LazyField::new(&environ_provider),
            open_fds: crate::vfs::LazyField::new(&open_fds_provider),
            network: crate::vfs::LazyField::new(&network_provider),
            network_model: crate::vfs::LazyField::new(&network_model_provider),
            groups: crate::vfs::LazyField::new(&groups_provider),
            signals: crate::vfs::LazyField::new(&signals_provider),
            oom_score_adj: crate::vfs::LazyField::new(&oom_score_adj_provider),
            creds_ns: crate::vfs::LazyField::new(&creds_ns_provider),
            processes: crate::vfs::LazyField::new(&processes_provider),
            threads: crate::vfs::LazyField::new(&threads_provider),
            zombies: crate::vfs::LazyField::new(&zombies_provider),
            sysvipc_shm: crate::vfs::LazyField::new(&sysvipc_shm_provider),
            sysvipc_sem: crate::vfs::LazyField::new(&sysvipc_sem_provider),
            sysvipc_msg: crate::vfs::LazyField::new(&sysvipc_msg_provider),
            mem: crate::vfs::LazyField::new(&mem_provider),
        };
        let open_flags = LinuxOpenFlags::from_bits_retain(flags);
        let vfs_flags = crate::vfs::OpenFlags {
            read: matches!(access, LINUX_O_RDONLY | LINUX_O_RDWR),
            write: matches!(access, LINUX_O_WRONLY | LINUX_O_RDWR),
            nonblock: open_flags.contains(LinuxOpenFlags::NONBLOCK),
            cloexec: open_flags.contains(LinuxOpenFlags::CLOEXEC),
            append: open_flags.contains(LinuxOpenFlags::APPEND),
            trunc: open_flags.contains(LinuxOpenFlags::TRUNC),
            create: open_flags.contains(LinuxOpenFlags::CREAT),
            excl: open_flags.contains(LinuxOpenFlags::EXCL),
            directory: open_flags.contains(LinuxOpenFlags::DIRECTORY),
            nofollow: open_flags.contains(LinuxOpenFlags::NOFOLLOW),
            mode: create_mode,
        };
        let handle = match m.vfs.open(&m.full_path, vfs_flags, &ctx) {
            Ok(h) => h,
            Err(errno) if errno == LINUX_ENOSYS => {
                return VfsOpenAttempt::FallThrough;
            }
            Err(errno) => {
                return VfsOpenAttempt::Errno(errno);
            }
        };
        let mount_fs_id = m.vfs.fs_identity();
        match handle {
            crate::vfs::VfsHandle::HostFd {
                host_fd,
                is_read_end,
                status_flags,
            } => {
                crate::dispatch::net::set_host_nonblocking(host_fd);
                // A VFS-served (e.g. bind-mounted) REGULAR file must become a
                // seekable HostFile, not a HostPipe — otherwise lseek/pread-at-
                // offset and sendfile/splice reject it (EINVAL), since a pipe
                // isn't seekable. Only genuine streams (devices, fifos) stay
                // HostPipe. fstat the real fd to decide.
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                let write_kind = if unsafe { libc::fstat(host_fd, &mut st) } == 0 {
                    HostWriteKind::from_host_mode(st.st_mode)
                } else {
                    HostWriteKind::Other
                };
                let is_regular = write_kind == HostWriteKind::RegularFile;
                let description = if is_regular {
                    OpenDescription::HostFile {
                        host_fd: HostFdRef::new(host_fd),
                        metadata: crate::rootfs::RootFsMetadata {
                            path: std::path::PathBuf::from(path),
                            kind: RootFsEntryKind::File,
                            mode: (st.st_mode & 0o7777) as u32,
                            size: st.st_size.max(0) as usize,
                        },
                        base: OpenDescriptionBase::new(status_flags as u64)
                            .with_fs_identity(mount_fs_id),
                        writable: !is_read_end,
                    }
                } else {
                    OpenDescription::HostPipe {
                        // A VFS host stream (e.g. /dev/null, a chardev) has no
                        // separate pipe peer; the host inode is a unique id.
                        pipe_id: host_inode_pipe_id(host_fd),
                        host_fd: HostFdRef::new(host_fd),
                        is_read_end,
                        base: OpenDescriptionBase::new(status_flags as u64)
                            .with_fs_identity(mount_fs_id),
                        pty: None,
                        // A VFS stream opened O_RDWR must serve BOTH directions
                        // (mirrors the O_RDWR FIFO open above). DevVfs encodes
                        // only `is_read_end = !write`, so an O_RDWR /dev/null —
                        // exactly what CPython's subprocess DEVNULL opens —
                        // came back write-only and the spawned child's
                        // `sys.stdin.read()` EBADFed (test_subprocess
                        // test_stdin_devnull's child traceback; Docker reads
                        // EOF). Shared with HVF: same latent gap there.
                        bidirectional: access == LINUX_O_RDWR,
                        write_kind,
                        stdio_stream: None,
                    }
                };
                let description_status_flags = access | (flags & !LINUX_O_CLOEXEC);
                let open_file = OpenFile::from_open_description_with_status_flags(
                    Arc::new(RwLock::new(description)),
                    description_status_flags,
                    linux_fd_flags_from_open_flags(flags),
                );
                let new_fd = match self.install_fd_at_or_above(0, open_file) {
                    Ok(fd) => fd,
                    Err(_) => return VfsOpenAttempt::Errno(linux_errno::EMFILE),
                };
                VfsOpenAttempt::Installed(new_fd)
            }
            crate::vfs::VfsHandle::SyntheticDevice { kind, status_flags } => {
                let status = ((status_flags as u64) | flags) & !LINUX_O_CLOEXEC;
                let open_file = OpenFile::from_open_description_with_status_flags(
                    Arc::new(RwLock::new(OpenDescription::SyntheticDevice {
                        kind,
                        base: OpenDescriptionBase::new(status).with_fs_identity(mount_fs_id),
                    })),
                    status,
                    linux_fd_flags_from_open_flags(flags),
                );
                let new_fd = match self.install_fd_at_or_above(0, open_file) {
                    Ok(fd) => fd,
                    Err(_) => return VfsOpenAttempt::Errno(linux_errno::EMFILE),
                };
                self.record_fd_open_path(new_fd, kind.as_str().to_string());
                VfsOpenAttempt::Installed(new_fd)
            }
            crate::vfs::VfsHandle::Bytes {
                path,
                contents,
                status_flags,
            } => {
                let status = ((status_flags as u64) | flags) & !LINUX_O_CLOEXEC;
                let open_file = OpenFile::from_open_description_with_status_flags(
                    Arc::new(RwLock::new(OpenDescription::SyntheticFile {
                        path,
                        contents,
                        offset: 0,
                        base: OpenDescriptionBase::new(status).with_fs_identity(mount_fs_id),
                    })),
                    status,
                    linux_fd_flags_from_open_flags(flags),
                );
                let new_fd = match self.install_fd_at_or_above(0, open_file) {
                    Ok(fd) => fd,
                    Err(_) => return VfsOpenAttempt::Errno(linux_errno::EMFILE),
                };
                VfsOpenAttempt::Installed(new_fd)
            }
            crate::vfs::VfsHandle::Pty {
                host_fd,
                pts_index,
                is_master,
                status_flags,
            } => {
                crate::dispatch::net::set_host_nonblocking(host_fd);
                let status = status_flags as u64;
                let open_file = OpenFile::from_open_description_with_status_flags(
                    Arc::new(RwLock::new(OpenDescription::HostPipe {
                        // A pty end's host inode is a unique id (FASYNC is not
                        // exercised on ptys).
                        pipe_id: host_inode_pipe_id(host_fd),
                        host_fd: HostFdRef::new(host_fd),
                        // A pty end is bidirectional; route reads and
                        // writes through the host fd like /dev/null.
                        is_read_end: true,
                        base: OpenDescriptionBase::new(status).with_fs_identity(mount_fs_id),
                        pty: Some(crate::vfs::PtyRole {
                            index: pts_index,
                            is_master,
                        }),
                        // pty bidirectionality is already expressed by `pty`.
                        bidirectional: false,
                        write_kind: HostWriteKind::Other,
                        stdio_stream: None,
                    })),
                    status,
                    linux_fd_flags_from_open_flags(flags),
                );
                // Remember where this pty's MASTER lives. The slave's close
                // path has to rescue the master's queued bytes before Darwin
                // destroys them, and it cannot look the master up through the
                // file table from inside the close (see
                // `dispatch::pty_registry`).
                if is_master {
                    crate::dispatch::pty_registry::register_master(
                        pts_index,
                        host_fd,
                        &open_file.description,
                    );
                }
                let new_fd = match self.install_fd_at_or_above(0, open_file) {
                    Ok(fd) => fd,
                    Err(_) => return VfsOpenAttempt::Errno(linux_errno::EMFILE),
                };
                // Record the open path (/dev/ptmx or /dev/pts/N) so
                // readlink(/proc/self/fd/<fd>) resolves it — glibc's ttyname_r
                // needs this to reopen a pty slave.
                self.record_fd_open_path(new_fd, path.to_string());
                VfsOpenAttempt::Installed(new_fd)
            }
            crate::vfs::VfsHandle::Directory {
                path,
                entries,
                status_flags,
            } => {
                // Convert synthetic VFS DirEnt entries into the RootFsDirEntry
                // shape that OpenDescription::Directory + getdents64 expects.
                let rootfs_entries: Vec<RootFsDirEntry> = entries
                    .into_iter()
                    .map(|e| {
                        let kind = match e.kind {
                            crate::vfs::EntryKind::Directory => RootFsEntryKind::Directory,
                            crate::vfs::EntryKind::Symlink => RootFsEntryKind::Symlink,
                            crate::vfs::EntryKind::CharDevice => RootFsEntryKind::CharDevice,
                            crate::vfs::EntryKind::Fifo => RootFsEntryKind::Fifo,
                            crate::vfs::EntryKind::Socket => RootFsEntryKind::Socket,
                            crate::vfs::EntryKind::File => RootFsEntryKind::File,
                        };
                        RootFsDirEntry {
                            name: e.name.clone(),
                            metadata: RootFsMetadata {
                                path: std::path::Path::new(&path).join(&e.name).to_path_buf(),
                                kind,
                                mode: 0o666,
                                size: 0,
                            },
                            ino: 0,
                        }
                    })
                    .collect();
                // A VFS mount answers `readdir` from its OWN view, which cannot
                // know about mounts layered inside it: `DevVfs` owns `/dev` and
                // has no idea `/dev/shm` is a separate bind mount, so `shm`
                // resolved and opened but never appeared in `readdir("/dev")`
                // (`vfs_mount_rw` `parent_readdir_has_mount`). The rootfs
                // listing path already injects mount children; do the same for
                // synthetic mounts so a mount point is listed by whichever
                // filesystem owns its parent.
                let mut rootfs_entries = rootfs_entries;
                self.inject_mount_dir_entries(&path, &mut rootfs_entries);
                let metadata = RootFsMetadata {
                    path: std::path::Path::new(&path).to_path_buf(),
                    kind: RootFsEntryKind::Directory,
                    mode: 0o755,
                    size: 0,
                };
                let status = status_flags as u64;
                let open_file = OpenFile::from_open_description_with_status_flags(
                    Arc::new(RwLock::new(OpenDescription::Directory {
                        path,
                        metadata,
                        listing: DirListing::Fixed(rootfs_entries),
                        offset: 0,
                        base: OpenDescriptionBase::new(status).with_fs_identity(mount_fs_id),
                        // VFS-mount (synthetic) directories never take the
                        // trusted host-dirfd lane.
                        trusted_host_dir: None,
                    })),
                    status,
                    linux_fd_flags_from_open_flags(flags),
                );
                let new_fd = match self.install_fd_at_or_above(0, open_file) {
                    Ok(fd) => fd,
                    Err(_) => return VfsOpenAttempt::Errno(linux_errno::EMFILE),
                };
                VfsOpenAttempt::Installed(new_fd)
            }
            crate::vfs::VfsHandle::InMemoryFile {
                path,
                contents,
                status_flags,
                writable,
                max_size,
            } => {
                let status = ((status_flags as u64) | flags) & !LINUX_O_CLOEXEC;
                let open_file = OpenFile::from_open_description_with_status_flags(
                    Arc::new(RwLock::new(OpenDescription::InMemoryFile {
                        path: path.clone(),
                        contents,
                        offset: 0,
                        writable,
                        max_size,
                        base: OpenDescriptionBase::new(status).with_fs_identity(mount_fs_id),
                    })),
                    status,
                    linux_fd_flags_from_open_flags(flags),
                );
                let new_fd = match self.install_fd_at_or_above(0, open_file) {
                    Ok(fd) => fd,
                    Err(_) => return VfsOpenAttempt::Errno(linux_errno::EMFILE),
                };
                self.record_fd_open_path(new_fd, path);
                VfsOpenAttempt::Installed(new_fd)
            }
        }
    }

    fn openat2_checked_path<'p>(
        &self,
        context: &crate::kernel::KernelContext,
        dirfd: u64,
        path: &'p str,
        resolve: u64,
    ) -> Result<std::borrow::Cow<'p, str>, LinuxErrno> {
        const RESOLVE_NO_XDEV: u64 = 0x01;
        const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
        const RESOLVE_NO_SYMLINKS: u64 = 0x04;
        const RESOLVE_BENEATH: u64 = 0x08;
        const RESOLVE_IN_ROOT: u64 = 0x10;

        if resolve == 0 {
            return Ok(std::borrow::Cow::Borrowed(path));
        }

        let anchor = self.openat2_anchor_for_dirfd(dirfd)?;
        let effective_path = if resolve & RESOLVE_IN_ROOT != 0 {
            std::borrow::Cow::Owned(Self::openat2_in_root_path(&anchor, path))
        } else {
            std::borrow::Cow::Borrowed(path)
        };

        if resolve & RESOLVE_BENEATH != 0 {
            if Path::new(path).is_absolute() {
                return Err(crate::linux_abi::LINUX_EXDEV);
            }
            let resolved = self.resolve_at_path(dirfd, path)?;
            if !path_is_under_or_equal(&resolved, &anchor) {
                return Err(crate::linux_abi::LINUX_EXDEV);
            }
        }

        if resolve & RESOLVE_NO_XDEV != 0
            && self.openat2_crosses_vfs_mount(&anchor, effective_path.as_ref())
        {
            return Err(crate::linux_abi::LINUX_EXDEV);
        }

        if resolve & (RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS) != 0
            && self.openat2_touches_magic_link(context, &anchor, effective_path.as_ref())
        {
            return Err(crate::linux_abi::LINUX_ELOOP);
        }

        if resolve & RESOLVE_NO_SYMLINKS != 0
            && self.openat2_touches_symlink(&anchor, effective_path.as_ref())?
        {
            return Err(crate::linux_abi::LINUX_ELOOP);
        }

        Ok(effective_path)
    }

    fn openat2_in_root_path(anchor: &str, path: &str) -> String {
        let mut components: Vec<String> = anchor
            .split('/')
            .filter(|component| !component.is_empty() && *component != ".")
            .map(str::to_owned)
            .collect();
        let root_depth = components.len();
        for component in path.split('/') {
            match component {
                "" | "." => {}
                ".." if components.len() > root_depth => {
                    components.pop();
                }
                ".." => {}
                component => components.push(component.to_owned()),
            }
        }
        if components.is_empty() {
            "/".to_owned()
        } else {
            format!("/{}", components.join("/"))
        }
    }

    pub(in crate::dispatch) fn openat2_anchor_for_dirfd(
        &self,
        dirfd: u64,
    ) -> Result<String, LinuxErrno> {
        let dirfd = (dirfd as i32) as i64 as u64;
        if dirfd == LINUX_AT_FDCWD {
            return Ok(self.cwd());
        }
        match self.open_file(dirfd as i32).as_ref() {
            Some(open_file) => match open_file.description.read().as_deref() {
                Some(OpenDescription::Directory { path, .. }) => {
                    if self.layered_metadata(path).is_err() {
                        Err(LINUX_ENOENT)
                    } else {
                        Ok(path.clone())
                    }
                }
                _ => Err(LINUX_ENOTDIR),
            },
            None if self.fd_is_valid(dirfd as i32) => Err(LINUX_ENOTDIR),
            None => Err(LINUX_EBADF),
        }
    }

    fn openat2_absolute_walk_path(&self, anchor: &str, path: &str) -> String {
        if Path::new(path).is_absolute() {
            join_rootfs_path("/", path)
        } else {
            join_rootfs_path(anchor, path)
        }
    }

    fn openat2_crosses_vfs_mount(&self, anchor: &str, path: &str) -> bool {
        let abs = self.openat2_absolute_walk_path(anchor, path);
        let mut prefix = String::new();
        for comp in abs.split('/').filter(|c| !c.is_empty() && *c != ".") {
            if comp == ".." {
                if let Some(pos) = prefix.rfind('/') {
                    prefix.truncate(pos);
                } else {
                    prefix.clear();
                }
                continue;
            }
            prefix.push('/');
            prefix.push_str(comp);
            if self.fs.vfs_mounts.resolve(&prefix).is_some() {
                return true;
            }
        }
        false
    }

    fn openat2_touches_magic_link(
        &self,
        context: &crate::kernel::KernelContext,
        anchor: &str,
        path: &str,
    ) -> bool {
        let abs = self.openat2_absolute_walk_path(anchor, path);
        let visible_self = proc_visible_self(context);
        let mut prefix = String::new();
        for comp in abs.split('/').filter(|c| !c.is_empty() && *c != ".") {
            if comp == ".." {
                if let Some(pos) = prefix.rfind('/') {
                    prefix.truncate(pos);
                } else {
                    prefix.clear();
                }
                continue;
            }
            prefix.push('/');
            prefix.push_str(comp);
            if proc_self_fd_number(&prefix, visible_self).is_some()
                || proc_self_magic_link(&prefix, visible_self).is_some()
                || proc_ns_link(&prefix).is_some()
            {
                return true;
            }
        }
        false
    }

    fn openat2_touches_symlink(&self, anchor: &str, path: &str) -> Result<bool, LinuxErrno> {
        let abs = self.openat2_absolute_walk_path(anchor, path);
        let mut prefix = String::new();
        for comp in abs.split('/').filter(|c| !c.is_empty() && *c != ".") {
            if comp == ".." {
                if let Some(pos) = prefix.rfind('/') {
                    prefix.truncate(pos);
                } else {
                    prefix.clear();
                }
                continue;
            }
            prefix.push('/');
            prefix.push_str(comp);
            match self.layered_lstat(&prefix) {
                Ok(md) if md.kind == RootFsEntryKind::Symlink => return Ok(true),
                Ok(_) => {}
                Err(errno) if errno == LINUX_ENOENT => {}
                Err(errno) => return Err(errno),
            }
        }
        Ok(false)
    }

    define_syscall! {
        fn openat(this, cx, dirfd: u64, pathname: GuestPtr, flags: u64, mode: u64) {

            let pathname = pathname.0;
            this.open_at_path(cx, dirfd, pathname, flags, mode)

        }

        fn openat2(this, cx, dirfd: u64, pathname: GuestPtr, how: GuestPtr, size: u64) {

            let how_address = how.0;
            let arg0 = dirfd;
            let arg1 = pathname.0;
            // copy_struct_from_user semantics for `open_how`:
            //  - size < sizeof(open_how) (incl. 0) → EINVAL (openat203 invalid-size-zero);
            //  - size > sizeof: the trailing bytes are forward-compat padding —
            //    they must be readable (else EFAULT, openat203 invalid-size-big)
            //    and all zero (else E2BIG, invalid-size-big-with-pad); zero pad
            //    is accepted (openat201 case 15 uses sizeof+8 with zero pad).
            if size < LINUX_OPEN_HOW_SIZE {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if size > LINUX_OPEN_HOW_SIZE {
                let pad_len = (size - LINUX_OPEN_HOW_SIZE) as usize;
                match (*cx.memory).read_bytes(how_address + LINUX_OPEN_HOW_SIZE, pad_len) {
                    Ok(pad) => {
                        if pad.iter().any(|&b| b != 0) {
                            return Ok(DispatchOutcome::errno(LINUX_E2BIG));
                        }
                    }
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                }
            }
            let how = read_open_how(&*cx.memory, how_address)?;
            // open_how validation, matching the kernel's build_open_how():
            //  - mode must be within 0o7777 (openat203 invalid-mode: mode=-1);
            //  - mode may be nonzero only when creating (openat203 invalid-flags:
            //    mode set without O_CREAT/O_TMPFILE → EINVAL);
            //  - resolve may carry only known RESOLVE_* bits (openat203
            //    invalid-resolve: resolve=-1 → EINVAL).
            let mode = how.mode;
            let flags = how.flags;
            let resolve = how.resolve;
            if flags & !LinuxOpenFlags::SUPPORTED_MASK != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if flags & crate::linux_abi::LINUX_O_PATH != 0 {
                let path_allowed = crate::linux_abi::LINUX_O_PATH
                    | LINUX_O_DIRECTORY
                    | crate::linux_abi::LINUX_O_NOFOLLOW
                    | LINUX_O_CLOEXEC;
                if flags & !path_allowed != 0 {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
            }
            if mode & !0o7777 != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if mode != 0 && flags & (LINUX_O_CREAT | crate::linux_abi::LINUX_O_TMPFILE) == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // RESOLVE_{NO_XDEV,NO_MAGICLINKS,NO_SYMLINKS,BENEATH,IN_ROOT,CACHED}.
            const VALID_RESOLVE: u64 = 0x3f;
            if resolve & !VALID_RESOLVE != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let path = read_guest_c_string(&*cx.memory, arg1)?;
            let path = match this.openat2_checked_path(cx.kernel, arg0, &path, resolve) {
                Ok(path) => path,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            this.open_at_path_string(
                cx.kernel,
                cx.thread.as_ref().map(|thread| thread.registry),
                OpenAtArgs {
                    dirfd: arg0,
                    path: path.as_ref(),
                    flags,
                    mode,
                },
                cx.reporter,
            )

        }

        fn memfd_create(this, cx, name: GuestPtr, flags: u64) {
            // memfd_create(name, flags): an anonymous in-memory file. macOS has
            // no memfd, so model it as an unlinked, writable in-memory File
            // (same shape as O_TMPFILE). MFD_CLOEXEC → FD_CLOEXEC;
            // MFD_ALLOW_SEALING is accepted (fcntl F_ADD_SEALS sealing itself is
            // a separate follow-up — that's what gates memfd_create01).
            let allowed = if flags & LINUX_MFD_HUGETLB != 0 {
                LinuxMemfdFlags::KNOWN_MASK | LinuxMemfdFlags::HUGE_BITS
            } else {
                LinuxMemfdFlags::KNOWN_MASK
            };
            // Linux validates the flags BEFORE the name (LTP memfd_create02
            // passes a valid name with bad flags and still expects EINVAL).
            if flags & !allowed != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // The name is bounded by MFD_NAME_MAX_LEN (256 − len("memfd:") − 1 =
            // 249): a NULL/unmapped pointer → EFAULT; no NUL within 250 bytes →
            // EINVAL (name too long). read_guest_c_string can't be reused — it
            // caps at PATH_MAX and returns ENAMETOOLONG, not the memfd EINVAL.
            const MFD_NAME_MAX_LEN: usize = 249;
            let memory = &*cx.memory;
            let mut name_bytes = Vec::new();
            let mut terminated = false;
            for off in 0..=MFD_NAME_MAX_LEN {
                let Some(addr) = name.0.checked_add(off as u64) else {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                };
                let byte = match memory.read_bytes(addr, 1) {
                    Ok(b) => b[0],
                    Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                };
                if byte == 0 {
                    terminated = true;
                    break;
                }
                name_bytes.push(byte);
            }
            if !terminated {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let name = String::from_utf8_lossy(&name_bytes).into_owned();
            let path = format!("/memfd:{name}");
            // Every memfd supports the sealing API. With MFD_ALLOW_SEALING the
            // initial seal set is empty; without it F_SEAL_SEAL is preset so no
            // seals can ever be added (F_ADD_SEALS → EPERM) while F_GET_SEALS
            // still succeeds. (memfd_create01)
            let Some(memfd_flags) =
                LinuxMemfdFlags::from_bits(flags & LinuxMemfdFlags::KNOWN_MASK)
            else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let initial_seals = if memfd_flags.contains(LinuxMemfdFlags::ALLOW_SEALING) {
                carrick_abi::LinuxMemfdSeals::empty().bits()
            } else {
                carrick_abi::LinuxMemfdSeals::SEAL.bits()
            };
            // A memfd is opened O_RDWR (memfd_create(2)); F_ADD_SEALS requires
            // the description carry write access (FMODE_WRITE).
            let common = Arc::new(crate::kernel::DescriptionCommon::new(LINUX_O_RDWR));
            common.set_seals(Some(initial_seals));
            // The bytes live in an unlinked host regular file rather than a
            // carrick-private buffer: a memfd's defining use is `MAP_SHARED`
            // (shared memory across fork, ring buffers, dmabuf-style
            // exchange), where every mapping and every fd read/write must see
            // one set of pages. Only a host inode gives a guest mapping a live
            // view; an in-memory buffer can only be snapshotted into a mapping.
            let Some(host_file) = super::fd_table::create_unlinked_host_file("memfd") else {
                return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
            };
            let description = OpenDescription::File {
                metadata: RootFsMetadata {
                    path: Path::new(&path).to_path_buf(),
                    kind: RootFsEntryKind::File,
                    mode: 0o777,
                    size: 0,
                },
                path,
                contents: FileContents::host_backed(host_file),
                offset: 0,
                base: OpenDescriptionBase::new(0)
                    .with_fs_identity(crate::vfs::FsIdentity::Tmpfs),
                writable: true,
            };
            let fd_flags = if memfd_flags.contains(LinuxMemfdFlags::CLOEXEC) {
                LINUX_FD_CLOEXEC
            } else {
                0
            };
            Ok(this.install_fd_with_common(description, common, fd_flags))
        }

        fn memfd_secret(this, cx, flags: u64) {
            // memfd_secret(2): an anonymous RAM-backed file whose pages the
            // kernel itself cannot address (removed from the direct map), so
            // the contents are reachable ONLY through the caller's own
            // MAP_SHARED mapping. Carrick models the guest-visible ABI: an
            // O_RDWR anonymous File description marked `secretmem`, which
            //   - rejects read(2)/write(2)-family I/O and splice with EINVAL
            //     (secretmem has no file read/write methods),
            //   - rejects MAP_PRIVATE mmap with EINVAL (mem.rs),
            //   - hides its mapped pages from `/proc/<pid>/mem` (EIO), and
            //   - supports ftruncate/fstat sizing like a memfd.
            // What carrick does NOT model: the host-kernel direct-map removal
            // itself (the pages live in ordinary guest RAM) and the implicit
            // mlock/RLIMIT_MEMLOCK accounting.
            //
            // The only accepted flag is close-on-exec, and the ABI takes the
            // O_CLOEXEC bit — NOT the FD_CLOEXEC value the man page's flag
            // name suggests. Probed differentially (`memfdsecret` probe):
            // memfd_secret(FD_CLOEXEC=1) → EINVAL; memfd_secret(O_CLOEXEC) →
            // fd with FD_CLOEXEC set.
            let _ = &cx;
            if flags & !LINUX_O_CLOEXEC != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let path = "/secretmem".to_string();
            // No sealing support: seals stay None (F_GET_SEALS/F_ADD_SEALS →
            // EINVAL), unlike memfd_create.
            let common = Arc::new(crate::kernel::DescriptionCommon::new(LINUX_O_RDWR));
            common.set_secretmem(true);
            let description = OpenDescription::File {
                metadata: RootFsMetadata {
                    path: Path::new(&path).to_path_buf(),
                    kind: RootFsEntryKind::File,
                    mode: 0o777,
                    size: 0,
                },
                path,
                contents: FileContents::dense(Vec::new()),
                offset: 0,
                base: OpenDescriptionBase::new(0)
                    .with_fs_identity(crate::vfs::FsIdentity::SecretMem),
                writable: true,
            };
            let fd_flags = if flags & LINUX_O_CLOEXEC != 0 {
                LINUX_FD_CLOEXEC
            } else {
                0
            };
            Ok(this.install_fd_with_common(description, common, fd_flags))
        }
    }
}
