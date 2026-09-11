//! Filesystem notification syscall handlers and helpers: inotify, fanotify,
//! and dnotify. Split out of `dispatch/fs.rs` as `impl SyscallDispatcher`
//! methods.

use super::state::DnotifyRegistration;
use super::*;
use crate::linux_abi::{
    LINUX_AT_FDCWD, LINUX_EBADF, LINUX_EFAULT, LINUX_EINVAL, LINUX_ENOENT, LINUX_ENOSYS,
    LINUX_ENOTDIR, LINUX_EPERM, LINUX_F_OWNER_PID, LINUX_O_ACCMODE, LINUX_O_NONBLOCK,
    LINUX_O_RDONLY, LINUX_O_RDWR, LINUX_O_WRONLY, LinuxErrno,
};
use std::path::Path;
use std::sync::Arc;

pub(crate) struct ReadFanotifyRequest<'a, M> {
    pub(crate) context: &'a crate::kernel::KernelContext,
    pub(crate) registry: Option<&'a crate::thread::ThreadRegistry>,
    pub(crate) reporter: &'a CompatReporter,
    pub(crate) memory: &'a mut M,
    pub(crate) address: u64,
    pub(crate) length: usize,
    pub(crate) group: &'a Arc<crate::fanotify::FanotifyGroup>,
    pub(crate) nonblocking: bool,
    pub(crate) guest_fd: i32,
}

impl<'a> FsView<'a> {
    pub(in crate::dispatch) fn dnotify_register(
        &self,
        context: &crate::kernel::KernelContext,
        fd: i32,
        mask: LinuxDnotifyMask,
        tid: crate::thread::ThreadId,
    ) -> Result<(), LinuxErrno> {
        let Some(open_file) = self.open_file(fd) else {
            return Err(LINUX_EBADF);
        };
        let path = match open_file.description.read().as_deref() {
            Some(OpenDescription::Directory { path, .. }) => path.clone(),
            _ => match self.lookup_recorded_fd_open_path(fd) {
                Some(path) => path,
                None => return Err(LINUX_EINVAL),
            },
        };
        let path = self.normalize_dnotify_path(&path);
        let mut registry = self.fs.dnotify_registry.lock();
        if mask.is_empty() {
            registry.retain(|entry| entry.fd != fd);
            return Ok(());
        }
        if open_file.description.common().owner().owner_pid == 0 {
            let internal = u32::try_from(context.task().key().id.raw())
                .map_err(|_| crate::linux_abi::LINUX_EOVERFLOW)?;
            let visible = crate::namespace::pid::ns_self_pid_for(context, internal);
            open_file.description.common().set_captured_owner(
                crate::kernel::objects::CapturedAsyncIoOwner::capture(
                    context,
                    LINUX_F_OWNER_PID,
                    i32::try_from(visible).map_err(|_| crate::linux_abi::LINUX_EOVERFLOW)?,
                ),
            );
        }
        let effective_mask = mask - LinuxDnotifyMask::MULTISHOT;
        if let Some(entry) = registry.iter_mut().find(|entry| entry.fd == fd) {
            entry.path = path;
            entry.mask = effective_mask;
            entry.tid = tid;
        } else {
            registry.push(DnotifyRegistration {
                fd,
                tid,
                path,
                mask: effective_mask,
            });
        }
        Ok(())
    }

    pub(in crate::dispatch) fn dnotify_close_fd(&self, fd: i32) {
        self.fs
            .dnotify_registry
            .lock()
            .retain(|entry| entry.fd != fd);
    }

    pub(in crate::dispatch) fn normalize_dnotify_path(&self, path: &str) -> String {
        let normalized = if Path::new(path).is_absolute() {
            normalize_abs_path(path)
        } else {
            normalize_abs_path(&format!("{}/{}", self.cwd().trim_end_matches('/'), path))
        };
        if normalized == "/private/tmp" {
            "/tmp".to_owned()
        } else if let Some(rest) = normalized.strip_prefix("/private/tmp/") {
            format!("/tmp/{rest}")
        } else {
            normalized
        }
    }

    pub(in crate::dispatch) fn dnotify_path_matches(&self, watched: &str, event: &str) -> bool {
        if watched == event {
            return true;
        }
        let watched_canon = self
            .canonicalize_following(watched)
            .map(|path| self.normalize_dnotify_path(&path))
            .unwrap_or_else(|_| watched.to_owned());
        let event_canon = self
            .canonicalize_following(event)
            .map(|path| self.normalize_dnotify_path(&path))
            .unwrap_or_else(|_| event.to_owned());
        watched_canon == event || watched == event_canon || watched_canon == event_canon
    }

    pub(in crate::dispatch) fn dnotify_child(
        &self,
        context: &crate::kernel::KernelContext,
        path: &str,
        mask: LinuxDnotifyMask,
    ) {
        self.dnotify_child_for_tid(context, path, mask, None);
    }

    pub(in crate::dispatch) fn dnotify_child_for_tid(
        &self,
        context: &crate::kernel::KernelContext,
        path: &str,
        mask: LinuxDnotifyMask,
        target_tid: Option<crate::thread::ThreadId>,
    ) {
        if !self.dnotify_event_supported(mask) {
            return;
        }
        let path = self.normalize_dnotify_path(path);
        let Some(parent) = Path::new(&path).parent() else {
            return;
        };
        let parent = display_rootfs_path(parent);
        self.dnotify_directory_for_tid(context, &parent, mask, target_tid);
    }

    pub(in crate::dispatch) fn dnotify_attrib(
        &self,
        context: &crate::kernel::KernelContext,
        path: &str,
    ) {
        self.dnotify_attrib_for_tid(context, path, None);
    }

    pub(in crate::dispatch) fn dnotify_attrib_for_tid(
        &self,
        context: &crate::kernel::KernelContext,
        path: &str,
        target_tid: Option<crate::thread::ThreadId>,
    ) {
        let path = self.normalize_dnotify_path(path);
        let mut candidates = vec![path.clone()];
        if let Some(parent) = Path::new(&path).parent() {
            let parent = normalize_abs_path(&display_rootfs_path(parent));
            if !candidates.contains(&parent) {
                candidates.push(parent);
            }
        }
        self.dnotify_directories_for_tid(
            context,
            &candidates,
            LinuxDnotifyMask::ATTRIB,
            target_tid,
        );
    }

    pub(in crate::dispatch) fn dnotify_directory_for_tid(
        &self,
        context: &crate::kernel::KernelContext,
        path: &str,
        mask: LinuxDnotifyMask,
        target_tid: Option<crate::thread::ThreadId>,
    ) {
        if !self.dnotify_event_supported(mask) {
            return;
        }
        let path = self.normalize_dnotify_path(path);
        self.dnotify_directories_for_tid(context, &[path], mask, target_tid);
    }

    pub(in crate::dispatch) fn dnotify_directories_for_tid(
        &self,
        context: &crate::kernel::KernelContext,
        paths: &[String],
        mask: LinuxDnotifyMask,
        _target_tid: Option<crate::thread::ThreadId>,
    ) {
        let registrations: Vec<_> = self
            .fs
            .dnotify_registry
            .lock()
            .iter()
            .filter(|entry| {
                entry.mask.intersects(mask)
                    && paths
                        .iter()
                        .any(|path| self.dnotify_path_matches(&entry.path, path))
            })
            .cloned()
            .collect();
        let mut notified = std::collections::HashSet::new();
        for entry in registrations {
            if !notified.insert(entry.fd) {
                continue;
            }
            if let Some(open_file) = self.open_file(entry.fd) {
                let common = open_file.description.common();
                let owner = common.captured_owner();
                let sig = common.async_sig();
                self.send_async_owner_signal(context, owner, sig, entry.fd);
            }
        }
    }

    pub(in crate::dispatch) fn dnotify_event_supported(&self, mask: LinuxDnotifyMask) -> bool {
        matches!(
            mask,
            LinuxDnotifyMask::CREATE
                | LinuxDnotifyMask::DELETE
                | LinuxDnotifyMask::RENAME
                | LinuxDnotifyMask::ATTRIB
        )
    }

    define_syscall! {
        fn inotify_init1(this, cx, flags: u64) {
            let known = crate::inotify::IN_NONBLOCK as u64 | crate::inotify::IN_CLOEXEC as u64;
            if flags & !known != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let Some(state) = crate::inotify::InotifyState::new() else {
                return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_EMFILE));
            };
            let description = OpenDescription::Inotify {
                base: OpenDescriptionBase::new(flags & LINUX_O_NONBLOCK),
                state: Arc::new(state),
            };
            Ok(this.install_fd_with_status_flags(
                description,
                flags & LINUX_O_NONBLOCK,
                linux_fd_flags_from_open_flags(flags),
            ))
        }

        fn inotify_add_watch(this, cx, fd: Fd, pathname: GuestPtr, mask: u64) {
            if !this.fd_is_valid(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            let Some(state) = this.inotify_state(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let path = read_guest_c_string(&*cx.memory, pathname.0)?;
            if path.is_empty() {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            let path = this.resolve_at_path(LINUX_AT_FDCWD, &path)?;
            let mask = mask as u32;
            if let Some(wd) = this.fs.inotify_registry.watch_descriptor(&path, &state) {
                let effective = state.update_watch(wd, mask)?;
                this.fs
                    .inotify_registry
                    .register(&path, &state, wd, effective);
                return Ok(DispatchOutcome::returned_i32(wd));
            }
            // Try the per-instance backend first (kqueue host-vnode watch on
            // macOS/BSD, native inotify on Linux) so cross-process directory
            // changes — a forked guest child mutating a watched dir — still
            // wake the parent. Whatever wd results (a real backend watch, or a
            // virtual dispatch-only one when the backend declines) is recorded
            // in the dispatch registry so the fs handlers can synthesize the
            // precise same-process events the coarse kqueue NOTE_* set misses.
            let wd = if let Some(m) = this.fs.vfs_mounts.resolve(&path) {
                match m.vfs.watch_fds(&m.full_path) {
                    Ok(watch_fds) => match state.add_watch_fds(watch_fds, mask) {
                        Ok(wd) => wd,
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    },
                    // Backend can't hand back a host vnode: fall back to a
                    // dispatch-only watch iff the path exists.
                    Err(errno) if errno == LINUX_ENOSYS => {
                        if !this.path_exists(&path) {
                            return Ok(DispatchOutcome::errno(crate::linux_abi::LINUX_ENOENT));
                        }
                        state.add_virtual_watch(mask)
                    }
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            } else {
                match this.fs.rootfs_vfs.watch_fds(&path) {
                    Ok(watch_fds) => match state.add_watch_fds(watch_fds, mask) {
                        Ok(wd) => wd,
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    },
                    Err(errno) if errno == LINUX_ENOSYS => {
                        // The legacy host-file open path can still yield a real
                        // host vnode (writable backend with no snapshot path).
                        match this
                            .fs
                            .rootfs_vfs
                            .open_for_dispatch(&path, false, false, false, false)
                        {
                            Ok(crate::vfs::rootfs::OpenDispatchResult::HostFile { host_fd, .. }) => {
                                match state.add_watch(host_fd, mask) {
                                    Ok(wd) => wd,
                                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                                }
                            }
                            // No host vnode (in-memory overlay): dispatch-only.
                            Ok(_) => state.add_virtual_watch(mask),
                            Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                        }
                    }
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            };
            this.fs.inotify_registry.register(&path, &state, wd, mask);
            // The dispatch registry now owns same-process event generation for
            // this instance; suppress the kqueue backend's duplicate synthesis
            // (it stays a poll_fd readiness source only).
            state.mark_dispatch_authoritative();
            Ok(DispatchOutcome::returned_i32(wd))
        }

        fn inotify_rm_watch(this, cx, fd: Fd, wd: u64) {
            if !this.fd_is_valid(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            let Some(state) = this.inotify_state(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let wd = wd as i32;
            // rm_watch removes the per-instance watch (virtual watches live in
            // the same `watches` table with no host fds, so it finds them too).
            // Drop the dispatch-registry entry to match.
            let result = state.rm_watch(wd);
            if result.is_ok() {
                state.enqueue(wd, carrick_abi::LINUX_IN_IGNORED, 0, None);
            }
            this.fs.inotify_registry.unregister(&state, wd);
            Ok(match result {
                Ok(()) => DispatchOutcome::Returned { value: 0 },
                Err(errno) => DispatchOutcome::errno(errno),
            })
        }

        fn fanotify_init(this, cx, flags: u64, event_f_flags: u64) {
            // fanotify_init(2) requires CAP_SYS_ADMIN — the CAPABILITY, not
            // euid 0. This used to gate on effective root with a comment
            // saying carrick had no finer model; it does now
            // (`has_effective_capability`), and the distinction is
            // guest-visible: Docker's default set drops CAP_SYS_ADMIN, so the
            // oracle answers EPERM for container root BOTH confined and
            // unconfined (i.e. it is a kernel check, not the seccomp profile),
            // while carrick handed root a working group fd. That extra fd type
            // is one of the pairings `splice07`/`ioctl_ficlone04` run and the
            // oracle skips.
            if !crate::dispatch::creds::has_effective_capability(
                cx.kernel,
                crate::namespace::process::CAP_SYS_ADMIN,
            ) {
                return Ok(DispatchOutcome::errno(LINUX_EPERM));
            }
            if flags & !LinuxFanotifyInitFlags::KNOWN_MASK != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let init_flags = LinuxFanotifyInitFlags::from_bits_retain(flags);
            // The class is a 2-bit FIELD, not a bit — `flags & FAN_CLASS_NOTIF`
            // is always false because FAN_CLASS_NOTIF is 0. Only the reserved
            // fourth encoding (both class bits set) is invalid.
            //
            // All THREE classes are accepted, including the permission classes
            // carrick cannot serve verdicts for. That is not a fudge — it is
            // what a kernel built without CONFIG_FANOTIFY_ACCESS_PERMISSIONS
            // does: `fanotify_init(FAN_CLASS_CONTENT, ...)` SUCCEEDS there, and
            // it is the later `fanotify_mark` carrying FAN_ACCESS_PERM /
            // FAN_OPEN_PERM that returns EINVAL. `fanotify_mark` below enforces
            // exactly that, so a permission-class group can still receive the
            // ordinary notification events it asks for and can never block
            // waiting for a verdict nothing will deliver.
            //
            // Failing the init instead is what LTP's
            // `require_fanotify_access_permissions_supported_on_fs` cannot
            // survive: it wraps the init in SAFE_FANOTIFY_INIT, so an EINVAL
            // there is a hard TBROK, where the real kernel's success followed
            // by a mark EINVAL is the intended TCONF (fanotify07).
            if init_flags.class().is_none() {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // The FID/PIDFD reporting families need file handles
            // (`name_to_handle_at`) and pidfd info records, neither of which
            // carrick has. Refusing them here is what makes the corresponding
            // event bits refusable at `fanotify_mark` below.
            const UNSUPPORTED_INIT: LinuxFanotifyInitFlags = LinuxFanotifyInitFlags::from_bits_retain(
                carrick_abi::LINUX_FAN_REPORT_FID
                    | carrick_abi::LINUX_FAN_REPORT_DIR_FID
                    | carrick_abi::LINUX_FAN_REPORT_NAME
                    | carrick_abi::LINUX_FAN_REPORT_TARGET_FID
                    | carrick_abi::LINUX_FAN_REPORT_FD_ERROR
                    | carrick_abi::LINUX_FAN_REPORT_PIDFD
                    | carrick_abi::LINUX_FAN_ENABLE_AUDIT,
            );
            if init_flags.intersects(UNSUPPORTED_INIT) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // `event_f_flags` are the open flags for the descriptors delivered
            // with each event; only the access mode is constrained.
            let access = event_f_flags & LINUX_O_ACCMODE;
            if access != LINUX_O_RDONLY && access != LINUX_O_WRONLY && access != LINUX_O_RDWR {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let group = Arc::new(crate::fanotify::FanotifyGroup::new(init_flags, event_f_flags));
            // Linux mirrors FAN_NONBLOCK into the description's O_NONBLOCK, so
            // fcntl(F_GETFL) reports it and a later F_SETFL can clear it.
            let status_flags = if init_flags.contains(LinuxFanotifyInitFlags::NONBLOCK) {
                LINUX_O_NONBLOCK
            } else {
                0
            };
            let description = OpenDescription::Fanotify {
                base: OpenDescriptionBase::new(status_flags),
                group,
            };
            // FAN_CLOEXEC is bit 0, NOT O_CLOEXEC — the generic
            // `linux_fd_flags_from_open_flags` would silently map the wrong bit
            // and fanotify08 asserts exactly this FD_CLOEXEC round-trip.
            let fd_flags = if init_flags.contains(LinuxFanotifyInitFlags::CLOEXEC) {
                carrick_abi::LinuxFdFlags::CLOEXEC.bits()
            } else {
                0
            };
            // `install_fd` builds the description common state with empty
            // status flags; the FAN_NONBLOCK mirror must reach
            // `common().status_flags()`, which is what `read` consults.
            Ok(this.install_fd_with_status_flags(description, status_flags, fd_flags))
        }

        fn fanotify_mark(this, cx, fanotify_fd: Fd, flags: u64, mask: u64, dirfd: Fd, pathname: GuestPtr) {
            // Flag validation precedes the fd lookup: the oracle answers
            // EINVAL for `fanotify_mark(-1, 0, 0, -1, NULL)` — a bad fd AND
            // a flagless command — both confined and unconfined, while
            // carrick answered EBADF by looking the fd up first.
            if flags & !LinuxFanotifyMarkFlags::KNOWN_MASK != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let mark_flags = LinuxFanotifyMarkFlags::from_bits_retain(flags);
            // Exactly one of ADD / REMOVE / FLUSH, and at most one object type.
            let (Some(command), Some(mark_type)) = (mark_flags.command(), mark_flags.mark_type())
            else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let Some(group) = this.fanotify_group(fanotify_fd.0) else {
                // A live fd that is not a fanotify group is EINVAL, not EBADF
                // (fanotify_mark(2): "fanotify_fd was not an fanotify file
                // descriptor"); only an absent fd is EBADF.
                return Ok(DispatchOutcome::errno(if this.fd_is_valid(fanotify_fd.0) {
                    LINUX_EINVAL
                } else {
                    LINUX_EBADF
                }));
            };
            // FAN_MARK_FLUSH ignores `mask` AND `pathname` entirely — it drops
            // every mark of one class from this group. Resolving the path here
            // would wrongly ENOENT a flush aimed at an already-deleted dir.
            if command == LinuxFanotifyMarkFlags::FLUSH {
                this.fs.fanotify_registry.flush(&group, mark_type);
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // ADD and REMOVE both require a non-empty mask.
            if mask == 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let events = LinuxFanotifyEvents::from_bits_retain(mask);
            // Everything outside NOTIF_MARKABLE needs a class or a reporting
            // mode carrick refused at `fanotify_init`: permission events need
            // FAN_CLASS_CONTENT; the dirent / inode-identity events
            // (FAN_CREATE, FAN_ATTRIB, FAN_MOVE, FAN_DELETE_SELF, ...) need
            // FAN_REPORT_FID. `fanotify_mark(2)` specifies EINVAL for both.
            if !LinuxFanotifyEvents::NOTIF_MARKABLE.contains(events) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let path = read_guest_c_string(&*cx.memory, pathname.0)?;
            if path.is_empty() {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            // Resolve intermediates but not the final component; that IS the
            // FAN_MARK_DONT_FOLLOW behaviour. Without the flag the final
            // symlink is followed too, so a mark placed through a symlink lands
            // on the target — fanotify04 marks the same symlink both ways and
            // asserts opening the TARGET fires only in the following case.
            let resolved = this.resolve_at_path(dirfd.0 as u64, &path)?;
            let resolved = if mark_flags.contains(LinuxFanotifyMarkFlags::DONT_FOLLOW) {
                resolved
            } else {
                match this.canonicalize_following(&resolved) {
                    Ok(target) => target,
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                }
            };
            let Some(is_dir) = this.inotify_path_kind(&resolved) else {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            };
            if mark_flags.contains(LinuxFanotifyMarkFlags::ONLYDIR) && !is_dir {
                return Ok(DispatchOutcome::errno(LINUX_ENOTDIR));
            }
            // FAN_MARK_IGNORED_MASK / FAN_MARK_IGNORE update the mark's IGNORE
            // mask instead of its event mask; both live on one mark, so an
            // ignore mark added after a normal mark filters it.
            let ignored = mark_flags
                .intersects(LinuxFanotifyMarkFlags::IGNORED_MASK | LinuxFanotifyMarkFlags::IGNORE);
            if command == LinuxFanotifyMarkFlags::ADD {
                this.fs
                    .fanotify_registry
                    .add_mark(&resolved, mark_type, &group, events, ignored);
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // REMOVE from an object this group never marked is ENOENT.
            if this
                .fs
                .fanotify_registry
                .remove_mark(&resolved, mark_type, &group, events, ignored)
            {
                Ok(DispatchOutcome::Returned { value: 0 })
            } else {
                Ok(DispatchOutcome::errno(LINUX_ENOENT))
            }
        }
    }
}

/// Partial-record protection: only whole 24-byte records are ever written, and
/// a copyout fault un-does the whole call — the descriptors just opened are
/// closed and the events are pushed back on the front of the queue, so the
/// guest's `EFAULT` leaves nothing consumed and no fd leaked.
pub(in crate::dispatch) fn read_fanotify<M: CurrentMmMemory>(
    this: &FsView<'_>,
    req: ReadFanotifyRequest<'_, M>,
) -> Result<DispatchOutcome, DispatchError> {
    // A buffer too small for even one record can never make progress.
    if req.length < carrick_abi::LINUX_FANOTIFY_EVENT_METADATA_LEN {
        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
    }
    let capacity = req.length / carrick_abi::LINUX_FANOTIFY_EVENT_METADATA_LEN;
    let events = req.group.take(capacity);
    if events.is_empty() {
        // Park on the group's readiness pipe rather than returning EAGAIN to a
        // blocking fd: `fanotify11` starts a worker thread and reads
        // immediately, so the queue is legitimately empty at read time and the
        // read must sleep until the worker's open lands.
        return Ok(crate::dispatch::would_block_outcome(
            req.group.poll_fd(),
            libc::POLLIN,
            req.nonblocking,
            None,
            WaitFdAuthority::logical(
                this.captured_slot_authority(req.guest_fd)
                    .ok_or(LINUX_EBADF)?,
            ),
        ));
    }
    let mut bytes =
        Vec::with_capacity(events.len() * carrick_abi::LINUX_FANOTIFY_EVENT_METADATA_LEN);
    let mut opened: Vec<i32> = Vec::with_capacity(events.len());
    // Every open below is carrick's own; without this the FAN_OPEN it would
    // emit lands right back on the queue this read is draining.
    let _internal = crate::fanotify::InternalOpenGuard::enter();
    for event in &events {
        // An object that has since been unlinked (or that this process cannot
        // open) still yields a record — with FAN_NOFD, exactly as Linux does
        // when it cannot open the object for the reader.
        let fd = match this.open_at_path_string(
            req.context,
            req.registry,
            OpenAtArgs {
                dirfd: LINUX_AT_FDCWD,
                path: &event.path,
                flags: req.group.event_f_flags(),
                mode: 0,
            },
            req.reporter,
        ) {
            Ok(DispatchOutcome::Returned { value }) if value >= 0 => {
                let fd = value as i32;
                opened.push(fd);
                fd
            }
            _ => crate::fanotify::NOFD,
        };
        bytes.extend_from_slice(&crate::fanotify::encode_event(event.mask, fd, event.pid));
    }
    if req.memory.write_bytes(req.address, &bytes).is_err() {
        // Roll the whole call back: close the descriptors we just handed out
        // and restore the events, so a faulting read consumes nothing.
        for fd in opened {
            this.close_fd_for_internal_rollback(fd);
        }
        req.group.requeue_front(events);
        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
    }
    Ok(DispatchOutcome::returned_len_or_errno(bytes.len()))
}
