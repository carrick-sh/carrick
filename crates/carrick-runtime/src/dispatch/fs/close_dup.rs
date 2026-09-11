//! Descriptor duplication and teardown syscall handlers and helpers:
//! `dup`, `dup2`, `dup3`, `close`, `close_range`.
//! Split out of `dispatch/fs.rs` (WS-F3) as `impl SyscallDispatcher` methods.

use super::*;
use crate::dispatch::fd_table::{HostFdRef, HostWriteKind, kernel_file_description};
use crate::linux_abi::{
    LINUX_EAGAIN, LINUX_EBADF, LINUX_EINTR, LINUX_EINVAL, LINUX_ENOMEM, LINUX_FD_CLOEXEC,
    LINUX_O_CLOEXEC, LINUX_O_RDONLY, LINUX_O_WRONLY, LinuxErrno,
};
use parking_lot::RwLock;
use std::sync::Arc;

impl SyscallDispatcher {
    fn dup_stdio_pty_role(&self, old_fd: i32) -> Option<crate::vfs::PtyRole> {
        if crate::host_tty::host_isatty(old_fd) {
            let index = self.pty_table().lock().controlling().unwrap_or(0);
            Some(crate::vfs::PtyRole {
                index,
                is_master: false,
            })
        } else {
            None
        }
    }

    /// Materialize one of the process's bare stdio fds (0/1/2, which have no
    /// fd-table entry) as a description of its own: `dup`/`fcntl(F_DUPFD)`
    /// mirror what dup3 does and grab the host fd into a `HostPipe` so future
    /// reads/writes still hit the right host endpoint (this is what dpkg-query
    /// needs at startup to redirect its diagnostic fd, and what most glibc
    /// fork+exec helpers expect to succeed), and `SCM_RIGHTS` parks the same
    /// description so a passed stdout arrives as a guest description.
    pub(in crate::dispatch) fn bare_stdio_description(
        &self,
        old_fd: i32,
    ) -> Result<Arc<crate::kernel::FileDescription>, LinuxErrno> {
        let duped = (unsafe { libc::dup(old_fd) }).host_syscall_errno()?;
        crate::dispatch::net::set_host_nonblocking(duped);
        let write_kind = HostWriteKind::for_host_fd(duped);
        let pty = self.dup_stdio_pty_role(old_fd);
        let status_flags = if old_fd == 0 {
            LINUX_O_RDONLY
        } else {
            LINUX_O_WRONLY
        };
        Ok(kernel_file_description(
            Arc::new(RwLock::new(OpenDescription::HostPipe {
                // A duped stdio fd has no separate pipe peer to coordinate
                // a FASYNC arm/trigger with; the host inode is still a
                // unique id (FASYNC is not exercised on bare stdio).
                pipe_id: host_inode_pipe_id(duped),
                // `duped` is a genuinely NEW host fd, so this fresh owned
                // handle is its one owner.
                host_fd: HostFdRef::new(duped),
                is_read_end: old_fd == 0,
                base: OpenDescriptionBase::new(0),
                pty,
                bidirectional: false,
                write_kind,
                stdio_stream: Some(old_fd),
            })),
            status_flags,
        ))
    }

    pub(super) fn duplicate_fd(&self, old_fd: i32, min_fd: i32, fd_flags: u64) -> DispatchOutcome {
        // The description Arc alone carries the backing host fd's liveness:
        // the OWNED HostFdRef lives inside the description, so `Arc::clone`
        // here is the whole dup — one refcount, no separate owner to keep in
        // lockstep.
        let description = match self.open_file(old_fd).as_ref() {
            Some(open_file) => Arc::clone(&open_file.description),
            // A closed-and-not-reopened stdio fd is genuinely closed: dup is
            // EBADF, not a host-fd grab. (The closed check must precede the
            // is_stdio_fd grab below.)
            None if is_stdio_fd(old_fd) && self.stdio_is_closed(old_fd) => {
                return DispatchOutcome::errno(LINUX_EBADF);
            }
            None if is_stdio_fd(old_fd) => match self.bare_stdio_description(old_fd) {
                Ok(description) => description,
                Err(errno) => return DispatchOutcome::errno(errno),
            },
            None => return DispatchOutcome::errno(LINUX_EBADF),
        };
        let open_file = OpenFile::new(description, fd_flags);
        let new_fd = match self.install_fd_at_or_above(min_fd, open_file) {
            Ok(fd) => fd,
            Err(_) => {
                return DispatchOutcome::errno(linux_errno::EMFILE);
            }
        };
        DispatchOutcome::returned_i32(new_fd)
    }

    fn duplicate_fd_to(
        &self,
        owner: crate::kernel::TaskKey,
        old_fd: i32,
        new_fd: i32,
        fd_flags: u64,
        same_fd_is_noop: bool,
    ) -> DispatchOutcome {
        let nofile_cur = self.nofile_limit();
        if !(0..nofile_cur).contains(&new_fd) {
            return DispatchOutcome::errno(LINUX_EBADF);
        }
        if old_fd == new_fd {
            if !same_fd_is_noop {
                return DispatchOutcome::errno(LINUX_EINVAL);
            }
            return if self.fd_is_valid(old_fd) {
                DispatchOutcome::returned_i32(new_fd)
            } else {
                DispatchOutcome::errno(LINUX_EBADF)
            };
        }

        // As in `duplicate_fd`: the description Arc alone carries the host
        // fd's liveness (the owned HostFdRef lives inside the description).
        let description = match self.open_file(old_fd).as_ref() {
            Some(open_file) => Arc::clone(&open_file.description),
            None if is_stdio_fd(old_fd) && self.stdio_is_closed(old_fd) => {
                return DispatchOutcome::errno(LINUX_EBADF);
            }
            None if is_stdio_fd(old_fd) => {
                let duped = match (unsafe { libc::dup(old_fd) }).host_syscall_errno() {
                    Ok(duped) => duped,
                    Err(errno) => return DispatchOutcome::errno(errno),
                };
                crate::dispatch::net::set_host_nonblocking(duped);
                let write_kind = HostWriteKind::for_host_fd(duped);
                let pty = self.dup_stdio_pty_role(old_fd);
                let status_flags = if old_fd == 0 {
                    LINUX_O_RDONLY
                } else {
                    LINUX_O_WRONLY
                };
                kernel_file_description(
                    Arc::new(RwLock::new(OpenDescription::HostPipe {
                        // A duped stdio fd has no separate pipe peer to coordinate
                        // a FASYNC arm/trigger with; the host inode is still a
                        // unique id (FASYNC is not exercised on bare stdio).
                        pipe_id: host_inode_pipe_id(duped),
                        // `duped` is a genuinely NEW host fd, so this fresh owned
                        // handle is its one owner.
                        host_fd: HostFdRef::new(duped),
                        is_read_end: old_fd == 0,
                        base: OpenDescriptionBase::new(0),
                        pty,
                        bidirectional: false,
                        write_kind,
                        stdio_stream: Some(old_fd),
                    })),
                    status_flags,
                )
            }
            None => return DispatchOutcome::errno(LINUX_EBADF),
        };

        // dup2/dup3 closes `new_fd` before installing the duplicate.  Carrick's
        // epoll emulation keys its interest map by guest-fd number, so the
        // detach must happen while that slot still names the DISPLACED open-file
        // description.  Detaching after insertion resolves `new_fd` through the
        // replacement and can tear down the parent's inherited registration
        // for the old description (the HvPatch Go os/exec two-pipe hang).
        //
        // Linux attaches epoll interest to the open-file description.  A forked
        // parent's reference therefore keeps the registration alive when the
        // child replaces its numeric slot; only the final logical fd reference
        // is allowed to trigger automatic close-detach.
        self.detach_fd_from_epolls(new_fd);
        self.discard_splice_pushback_if_final(new_fd);

        let replaced = {
            let files = self.captured_file_table();
            let mut table = files.write_open_files();
            let replaced = table.remove(&new_fd).map(|replaced| {
                // Only an mqueue description needs the alias walk (see
                // `mqueue_owner_alias_closed`); for everything else the
                // observation is unused and the walk is O(table) per dup2.
                let alias_remains = Self::close_needs_mqueue_alias_scan(&replaced)
                    && table
                        .values()
                        .any(|slot| Arc::ptr_eq(&slot.description, &replaced.description));
                (Arc::clone(&files), replaced, alias_remains)
            });
            retain_open_file(&description);
            table.insert(new_fd, OpenFile::new(description, fd_flags));
            replaced
        };
        if let Some((files, replaced, alias_remains)) = replaced {
            self.mqueue_owner_alias_closed_known(files.id(), &replaced, alias_remains);
            let pid = self.event_ring_guest_pid();
            self.record_fd_close_owner(new_fd, pid, &replaced);
            self.release_hvpatch_classic_record_locks(owner, &replaced);
            self.close_open_file_and_free_pty(&replaced);
        }
        self.clear_closed_stdio(new_fd);
        DispatchOutcome::returned_i32(new_fd)
    }

    define_syscall! {

        fn dup(this, cx, fd: Fd) {

            let old_fd: Fd = fd;
            // dup(2) returns the LOWEST-numbered unused descriptor, with no
            // floor — including 0/1/2 when the caller has closed them. min_fd=0
            // (not 3) lets first_free_fd hand back a CLOSED stdio number while
            // still skipping an OPEN one. Flooring at 3 made `close(0); dup(fd)`
            // return a freed fd >= 3 instead of 0, so libuv's
            // uv_pipe_open(loop, 0) wrapped a dead fd 0 and uv_run crashed
            // (test pipe_close_stdout_read_stdin). dup3/F_DUPFD already use 0.
            Ok(this.duplicate_fd(old_fd.0, 0, 0))

        }

        fn dup3(this, cx, oldfd: Fd, newfd: Fd, flags: u64) {

            let old_fd: Fd = oldfd;
            let new_fd: Fd = newfd;
            // Linux dup3 only honours O_CLOEXEC in `flags` (else EINVAL), and
            // new_fd must be a valid descriptor number: out of range (negative or
            // >= RLIMIT_NOFILE soft limit) is EBADF, NOT EINVAL. old_fd == new_fd
            // is EINVAL (dup2 handles that case in glibc without reaching here).
            // new_fd 0/1/2 is allowed — that's how shells redirect std streams.
            let nofile_cur = this.nofile_limit();
            if flags & !LINUX_O_CLOEXEC != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if !(0..nofile_cur).contains(&new_fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            if old_fd.0 == new_fd.0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            Ok(this.duplicate_fd_to(
                cx.kernel.task().key(),
                old_fd.0,
                new_fd.0,
                linux_fd_flags_from_open_flags(flags),
                false,
            ))

        }

        fn dup2(this, cx, oldfd: Fd, newfd: Fd) {

            let old_fd: Fd = oldfd;
            let new_fd: Fd = newfd;
            Ok(this.duplicate_fd_to(
                cx.kernel.task().key(),
                old_fd.0,
                new_fd.0,
                0,
                true,
            ))

        }

        fn close(this, cx, fd: Fd) {

            let fd: Fd = fd;
            // Closing a stdio number (0/1/2) frees it for reuse by the
            // lowest-free-descriptor allocator (a later open()/dup can land there).
            if fd.0 >= 0 && fd.0 < 3 {
                this.captured_file_table().lock_closed_stdio()[fd.0 as usize] = true;
            }
            this.discard_splice_pushback_if_final(fd.0);
            this.dnotify_close_fd(fd.0);
            // inotify IN_CLOSE_WRITE/IN_CLOSE_NOWRITE for a watched regular file
            // or directory — emitted while the fd is still in the table so its
            // description (writability) and recorded path are still readable.
            this.inotify_close_for_fd(fd.0);
            // fanotify FAN_CLOSE_WRITE/FAN_CLOSE_NOWRITE, emitted here for the
            // same reason: the description's writability and recorded path are
            // only readable while the fd is still in the table.
            this.fanotify_close_for_fd(cx.kernel, fd.0);
            // Auto-remove this fd from every epoll interest set BEFORE freeing
            // the fd number from open_files. ORDER IS LOAD-BEARING: the instant
            // the fd leaves open_files another thread's open/pipe/dup can recycle
            // that number and `epoll_ctl(ADD)` it; if the detach ran AFTER the
            // free it would rip out the NEW owner's freshly-added interest, whose
            // EPOLLET edge then never re-fires (the Go-netpoller hang reproduced
            // by epoll_et_pipe_eof_not_lost — a worker's close raced a sibling's
            // reuse+ADD of the same fd number). While the fd is still in the table
            // the allocator cannot hand it out, so detaching first scopes the
            // removal to THIS registration. detach takes only a read lock, so it
            // does not deadlock with the separate write below.
            this.detach_fd_from_epolls(fd.0);
            let files = this.captured_file_table();
            let removed = files.write_open_files().remove(&fd.0);
            Ok(
                if let Some(open_file) = removed {
                    this.mqueue_owner_alias_closed(&files, &open_file);
                    this.record_fd_close_owner(fd.0, cx.tid().raw(), &open_file);
                    this.release_hvpatch_classic_record_locks(
                        cx.kernel.task().key(),
                        &open_file,
                    );
                    crate::event_ring::rec(
                        crate::event_ring::FDCLOSE,
                        fd.0,
                        fd_helpers::event_ring_host_fd(&open_file),
                        0,
                    );
                    // Centralised close: frees the host fd and, for pty masters,
                    // removes the /dev/pts/N entry from the PtyTable so it becomes
                    // ENOENT — mirroring Linux devpts semantics. The same helper is
                    // used by close_range and close_cloexec_fds so every close path
                    // stays in sync.
                    this.close_open_file_and_free_pty(&open_file);
                    this.note_fd_closed(fd.0);
                    DispatchOutcome::Returned { value: 0 }
                } else if is_stdio_fd(fd.0) {
                    // Guest closing its own stdio at exit: there's nothing for
                    // us to do (host fd stays open under StdioSink::Inherit so
                    // sibling processes keep working), but reporting EBADF
                    // here makes glibc print "write error: Bad file descriptor"
                    // after the program's real output. Return success.
                    this.note_fd_closed(fd.0);
                    DispatchOutcome::Returned { value: 0 }
                } else {
                    DispatchOutcome::errno(LINUX_EBADF)
                },
            )

        }

        fn close_range(this, cx, first: u64, last: u64, flags: u64) {
            let Some(flags) = carrick_abi::LinuxCloseRangeFlags::from_bits(flags as u32) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            if first > last {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let close_selected = || {
                let cloexec_only = flags.contains(carrick_abi::LinuxCloseRangeFlags::CLOEXEC);
                // Drain matching fds out of the table so we don't iterate a
                // gigantic [first, last] (callers commonly pass last=u32::MAX).
                let fds: Vec<i32> = this
                    .captured_file_table()
                    .read_open_files()
                    .keys()
                    .copied()
                    .filter(|fd| (*fd as u64) >= first && (*fd as u64) <= last)
                    .collect();
                if cloexec_only {
                    let files = this.captured_file_table();
                    let mut table = files.write_open_files();
                    for fd in fds {
                        if let Some(open_file) = table.get_mut(&fd) {
                            open_file.fd_flags |= LINUX_FD_CLOEXEC;
                        }
                    }
                } else {
                    // Detach BEFORE freeing each fd number — same ordering rule as
                    // `close` (a freed number is instantly reusable, and a
                    // detach-after-free would rip out a sibling's reused-fd interest;
                    // see `close`). Detach (read lock) and remove (write lock) are
                    // separate per fd, so the fd is still in the table — hence not
                    // reallocatable — across its own detach.
                    for fd in fds {
                        this.discard_splice_pushback_if_final(fd);
                        this.detach_fd_from_epolls(fd);
                        let files = this.captured_file_table();
                        let removed = files.write_open_files().remove(&fd);
                        if let Some(open_file) = removed {
                            this.mqueue_owner_alias_closed(&files, &open_file);
                            this.record_fd_close_owner(fd, cx.tid().raw(), &open_file);
                            this.release_hvpatch_classic_record_locks(
                                cx.kernel.task().key(),
                                &open_file,
                            );
                            crate::event_ring::rec(
                                crate::event_ring::FDCLOSE,
                                fd,
                                fd_helpers::event_ring_host_fd(&open_file),
                                0,
                            );
                            // Centralised close so pty masters freed via close_range
                            // also drop their /dev/pts/N entry. open_files and pty_table
                            // are independent locks (no nesting), so deadlock-free.
                            this.close_open_file_and_free_pty(&open_file);
                            this.note_fd_closed(fd);
                        }
                    }
                }
                Ok(DispatchOutcome::Returned { value: 0 })
            };

            if !flags.contains(carrick_abi::LinuxCloseRangeFlags::UNSHARE) {
                return close_selected();
            }
            let unshared: crate::kernel::CloseRangeUnshare = match cx
                .kernel
                .kernel()
                .unshare_file_table_for_close_range(cx.kernel)
            {
                Ok(unshared) => unshared,
                Err(
                    crate::kernel::KernelOperationError::StaleContext
                    | crate::kernel::KernelOperationError::ParentExited
                    | crate::kernel::KernelOperationError::UnknownThread(_),
                ) => return Ok(DispatchOutcome::errno(LINUX_EINTR)),
                Err(crate::kernel::KernelOperationError::TaskBusy(_)) => {
                    return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                }
                Err(error) => {
                    tracing::error!(%error, "close_range unshare publication failed");
                    return Ok(DispatchOutcome::errno(LINUX_ENOMEM));
                }
            };
            let successor = unshared.context().resources().files();
            this.close_draining_file_table(
                cx.kernel.kernel(),
                unshared.old_file_table(),
                Some(cx.kernel.task().key()),
                Some(&successor),
            );
            this.with_kernel_resources(unshared.context(), close_selected)

        }

    }
}
