//! `/proc` synthetic path resolution, magic symlinks, and fdinfo generation.

use super::*;

/// `/dev/fd` and `/dev/std{in,out,err}` are symlinks into `/proc/self/fd` on
/// Linux — bash process substitution (`cat <(...)`) passes `/dev/fd/N` to the
/// spawned command, which `open()`s it to dup the pipe. Rewrite an ABSOLUTE
/// such path to its `/proc/self/fd` equivalent so the existing magic-fd
/// machinery serves it (open → dup N; lstat/readlink as a per-fd symlink).
/// Returns `None` for anything else. Only EXACT matches map: `/dev/fd0` (a
/// floppy) must not become `/proc/self/fd0`.
pub(crate) fn rewrite_dev_fd_alias(path: &str) -> Option<String> {
    match path {
        "/dev/fd" => Some("/proc/self/fd".to_string()),
        "/dev/stdin" => Some("/proc/self/fd/0".to_string()),
        "/dev/stdout" => Some("/proc/self/fd/1".to_string()),
        "/dev/stderr" => Some("/proc/self/fd/2".to_string()),
        _ => path
            .strip_prefix("/dev/fd/")
            .map(|rest| format!("/proc/self/fd/{rest}")),
    }
}

pub(crate) fn proc_component_is_self(pid: &str, visible_self: Option<u32>) -> bool {
    matches!(pid, "self" | "thread-self" | "curproc" | "this")
        || pid
            .parse::<u32>()
            .ok()
            .zip(visible_self)
            .is_some_and(|(pid, visible_self)| pid == visible_self)
}

pub(crate) fn is_proc_self_fd_dir(path: &str, visible_self: Option<u32>) -> bool {
    let p = path.strip_suffix('/').unwrap_or(path);
    if p == "/dev/fd" {
        return true;
    }
    let Some(rest) = p.strip_prefix("/proc/") else {
        return false;
    };
    let Some((pid, sub)) = rest.split_once('/') else {
        return false;
    };
    sub == "fd" && proc_component_is_self(pid, visible_self)
}

pub(crate) fn is_proc_self_fdinfo_dir(path: &str, visible_self: Option<u32>) -> bool {
    let p = path.strip_suffix('/').unwrap_or(path);
    let Some(rest) = p.strip_prefix("/proc/") else {
        return false;
    };
    let Some((pid, sub)) = rest.split_once('/') else {
        return false;
    };
    sub == "fdinfo" && proc_component_is_self(pid, visible_self)
}

/// If `path` is a `/proc/{self,thread-self,curproc,this}/fd/N` magic symlink,
/// return the descriptor number N. Used to serve `open()` of these (Linux
/// re-opens the file behind fd N); Apple Rosetta opens its main-binary fd this
/// way.
pub(crate) fn proc_self_fd_number(path: &str, visible_self: Option<u32>) -> Option<i32> {
    let rest = path
        .strip_prefix("/proc/self/fd/")
        .or_else(|| path.strip_prefix("/proc/thread-self/fd/"))
        .or_else(|| path.strip_prefix("/proc/curproc/fd/"))
        .or_else(|| path.strip_prefix("/proc/this/fd/"))
        .or_else(|| {
            let after = path.strip_prefix("/proc/")?;
            let (pid, tail) = after.split_once('/')?;
            if proc_component_is_self(pid, visible_self) {
                tail.strip_prefix("fd/")
            } else {
                None
            }
        })?;
    rest.parse::<i32>().ok()
}

/// If `path` is a `/proc/{self,thread-self,curproc,this,<pid>}/{exe,cwd,root}`
/// magic symlink, which one it is. These readlink to live dispatcher state
/// (the executable path, the cwd, the root), so they are resolved here rather
/// than in the pure `ProcVfs`. carrick is one guest process, so any numeric pid
/// component refers to "self".
pub(crate) fn proc_self_magic_link(path: &str, visible_self: Option<u32>) -> Option<&'static str> {
    let rest = path.strip_prefix("/proc/")?;
    let (pid, leaf) = rest.split_once('/')?;
    // ONLY this process resolves exe/cwd/root from the live dispatcher state.
    // A foreign guest pid must NOT masquerade as self (that would readlink
    // /proc/<other>/exe to OUR executable_path); for those, fall through so the
    // path resolves to ENOENT rather than leaking the inspector's identity.
    if !proc_component_is_self(pid, visible_self) {
        return None;
    }
    match leaf {
        "exe" => Some("exe"),
        "cwd" => Some("cwd"),
        "root" => Some("root"),
        _ => None,
    }
}

/// If `path` is a `/proc/{self,thread-self,curproc,this,<pid>}/ns/<type>` magic
/// symlink of a LIVE process, the namespace `<type>` (e.g. `"uts"`). These are
/// `nsfs` magic links: open(2) resolves them to an opaque namespace OBJECT, NOT
/// by following the `<type>:[<inode>]` readlink target as a path. The liveness
/// gate (`proc_live_pid`) makes a dead or foreign pid return `None` → ENOENT,
/// mirroring `proc_self_magic_link`. carrick models exactly one initial ns per
/// type, so every live pid's link names the same object.
pub(crate) fn proc_ns_link(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/proc/")?;
    let (pid, leaf) = rest.split_once('/')?;
    crate::vfs::proc::proc_live_pid(pid)?;
    let ns_type = leaf.strip_prefix("ns/")?;
    crate::vfs::proc::ns_type_inode(ns_type).map(|_| ns_type)
}

/// The `CLONE_NEW*` flag identifying namespace `<type>` — the value `NS_GET_NSTYPE`
/// returns (ioctl_ns(2)). `*_for_children` map to their base type's flag. `None`
/// for an unrecognised type.
pub(crate) fn ns_type_clone_flag(ns_type: &str) -> Option<u64> {
    Some(match ns_type {
        "mnt" => LINUX_CLONE_NEWNS,
        "uts" => LINUX_CLONE_NEWUTS,
        "ipc" => LINUX_CLONE_NEWIPC,
        "net" => LINUX_CLONE_NEWNET,
        "pid" | "pid_for_children" => LINUX_CLONE_NEWPID,
        "user" => LINUX_CLONE_NEWUSER,
        "cgroup" => LINUX_CLONE_NEWCGROUP,
        "time" | "time_for_children" => LINUX_CLONE_NEWTIME,
        _ => return None,
    })
}

/// The fd number `N` of a `/proc/<self>/fdinfo/N` path, if it is one. Self only
/// (the contents are this process's live fd state); a foreign pid falls through.
pub(crate) fn proc_self_fdinfo_number(path: &str, visible_self: Option<u32>) -> Option<i32> {
    let rest = path.strip_prefix("/proc/")?;
    let (pid, tail) = rest.split_once('/')?;
    if !proc_component_is_self(pid, visible_self) {
        return None;
    }
    tail.strip_prefix("fdinfo/")?.parse::<i32>().ok()
}

pub(crate) fn proc_visible_self(context: &crate::kernel::KernelContext) -> Option<u32> {
    u32::try_from(context.task().key().id.raw())
        .ok()
        .and_then(|pid| crate::namespace::pid::try_ns_self_pid_for(context, pid))
}

/// The file STATUS flags reportable via `fcntl(F_GETFL)` and `/proc/<pid>/fdinfo`.
/// Linux consumes creation-only flags at `open()` and clears them from
/// `f_flags`, so they must not be reported back; only the access mode and the
/// file status flags (O_APPEND/O_NONBLOCK/O_DIRECT/O_SYNC/…) remain. (audit M8)
pub(crate) fn reportable_status_flags(raw: u64) -> u64 {
    const CREATION_ONLY: u64 = LINUX_O_CREAT
        | LINUX_O_EXCL
        | LINUX_O_TRUNC
        | LINUX_O_DIRECTORY
        | LINUX_O_CLOEXEC
        | 0o400 // O_NOCTTY
        | 0o100000 // O_NOFOLLOW
        | 0o20000000; // O_TMPFILE
    raw & !CREATION_ONLY
}

impl<'a> FsView<'a> {
    pub(super) fn reopen_proc_self_fd(
        &self,
        context: &crate::kernel::KernelContext,
        registry: Option<&crate::thread::ThreadRegistry>,
        n: i32,
        flags: u64,
        _resolved: &str,
        reporter: &CompatReporter,
    ) -> Result<DispatchOutcome, LinuxErrno> {
        let Some(open_file) = self.open_file(n) else {
            return Ok(self.duplicate_fd(
                n,
                0,
                if flags & LINUX_O_CLOEXEC != 0 {
                    LINUX_FD_CLOEXEC
                } else {
                    0
                },
            ));
        };

        enum ReopenAction {
            ByPath(String),
            CopyDescription(
                Box<OpenDescription>,
                Arc<crate::kernel::DescriptionCommon>,
                u64,
            ),
            Errno(LinuxErrno),
            Duplicate,
        }

        let action = {
            let Some(mut open) = open_file.description.write() else {
                return Ok(self.duplicate_fd(
                    n,
                    0,
                    if flags & LINUX_O_CLOEXEC != 0 {
                        LINUX_FD_CLOEXEC
                    } else {
                        0
                    },
                ));
            };

            let accmode = flags & LINUX_O_ACCMODE;
            let is_writable = accmode == LINUX_O_WRONLY || accmode == LINUX_O_RDWR;
            let shared_seals = open_file.description.common().shared_seals();
            let is_secretmem = open_file.description.common().secretmem();
            let fd_flags = if flags & LINUX_O_CLOEXEC != 0 {
                LINUX_FD_CLOEXEC
            } else {
                0
            };

            match &mut *open {
                OpenDescription::File {
                    path,
                    metadata,
                    contents,
                    writable,
                    ..
                } => {
                    if !fd_table::is_anon_overlay_path(path) {
                        ReopenAction::ByPath(path.clone())
                    } else {
                        let is_memfd = shared_seals.lock().is_some();
                        // `F_SEAL_WRITE` does not refuse the open: Linux
                        // hands back a writable description whose write(2)
                        // and shared writable mmap then fail. Only the
                        // resize seals decide an `O_TRUNC` (LTP
                        // `memfd_create01` `test_seal_write` shrinks a
                        // write-sealed memfd through exactly this open).
                        let err = if is_writable {
                            if !is_memfd && !*writable {
                                Some(LINUX_EACCES)
                            } else if flags & LINUX_O_TRUNC != 0 {
                                match contents.len() {
                                    Err(errno) => Some(errno),
                                    Ok(0) => None,
                                    Ok(cur_len) => {
                                        if let Err(errno) = memfd_seal_resize_check(
                                            open_file.description.common().seals(),
                                            0,
                                            usize::try_from(cur_len).unwrap_or(usize::MAX),
                                        ) {
                                            Some(errno)
                                        } else if let Err(errno) = contents.resize(0) {
                                            Some(errno)
                                        } else {
                                            metadata.size = 0;
                                            None
                                        }
                                    }
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        };

                        if let Some(errno) = err {
                            ReopenAction::Errno(errno)
                        } else {
                            let new_desc = OpenDescription::File {
                                base: OpenDescriptionBase::new(0),
                                path: path.clone(),
                                metadata: metadata.clone(),
                                contents: contents.clone(),
                                offset: 0,
                                writable: if is_memfd {
                                    is_writable
                                } else {
                                    *writable && is_writable
                                },
                            };
                            let new_common =
                                Arc::new(crate::kernel::DescriptionCommon::new_with_seals(
                                    flags & !LINUX_O_CLOEXEC,
                                    shared_seals,
                                ));
                            if is_secretmem {
                                new_common.set_secretmem(true);
                            }
                            ReopenAction::CopyDescription(Box::new(new_desc), new_common, fd_flags)
                        }
                    }
                }
                OpenDescription::HostFile {
                    host_fd,
                    metadata,
                    writable,
                    ..
                } => {
                    let path_str = metadata.path.to_string_lossy();
                    if !fd_table::is_anon_overlay_path(&path_str) {
                        ReopenAction::ByPath(path_str.into_owned())
                    } else if is_writable && !*writable {
                        ReopenAction::Errno(LINUX_EACCES)
                    } else {
                        let dup_fd = unsafe { libc::dup(host_fd.raw()) };
                        if dup_fd < 0 {
                            ReopenAction::Errno(linux_errno::EMFILE)
                        } else {
                            unsafe { libc::fcntl(dup_fd, libc::F_SETFD, libc::FD_CLOEXEC) };
                            crate::dispatch::net::set_host_nonblocking(dup_fd);
                            // SAFETY: `dup_fd` is freshly duplicated and valid.
                            let owned = unsafe {
                                use std::os::fd::FromRawFd;
                                std::os::fd::OwnedFd::from_raw_fd(dup_fd)
                            };
                            let mut new_metadata = metadata.clone();
                            if flags & LINUX_O_TRUNC != 0 && is_writable {
                                use std::os::fd::AsRawFd;
                                unsafe { libc::ftruncate(owned.as_raw_fd(), 0) };
                                new_metadata.size = 0;
                                self.invalidate_dentry_host_fd(owned.as_raw_fd());
                            }
                            let new_desc = OpenDescription::File {
                                base: OpenDescriptionBase::new(0),
                                path: path_str.into_owned(),
                                metadata: new_metadata,
                                contents: FileContents::host_backed(owned),
                                offset: 0,
                                writable: *writable && is_writable,
                            };
                            let new_common =
                                Arc::new(crate::kernel::DescriptionCommon::new_with_seals(
                                    flags & !LINUX_O_CLOEXEC,
                                    shared_seals,
                                ));
                            if is_secretmem {
                                new_common.set_secretmem(true);
                            }
                            ReopenAction::CopyDescription(Box::new(new_desc), new_common, fd_flags)
                        }
                    }
                }
                OpenDescription::InMemoryFile {
                    path,
                    contents,
                    max_size,
                    writable,
                    ..
                } => {
                    if is_writable && !*writable {
                        ReopenAction::Errno(LINUX_EACCES)
                    } else {
                        if flags & LINUX_O_TRUNC != 0 && is_writable {
                            contents.write().clear();
                        }
                        let new_desc = OpenDescription::InMemoryFile {
                            base: OpenDescriptionBase::new(0),
                            path: path.clone(),
                            contents: Arc::clone(contents),
                            offset: 0,
                            writable: *writable && is_writable,
                            max_size: *max_size,
                        };
                        let new_common =
                            Arc::new(crate::kernel::DescriptionCommon::new_with_seals(
                                flags & !LINUX_O_CLOEXEC,
                                shared_seals,
                            ));
                        if is_secretmem {
                            new_common.set_secretmem(true);
                        }
                        ReopenAction::CopyDescription(Box::new(new_desc), new_common, fd_flags)
                    }
                }
                OpenDescription::Directory { path, .. } => ReopenAction::ByPath(path.clone()),
                OpenDescription::SyntheticFile { path, .. } => ReopenAction::ByPath(path.clone()),
                _ => ReopenAction::Duplicate,
            }
        };

        match action {
            ReopenAction::ByPath(target_path) => self
                .open_at_path_string(
                    context,
                    registry,
                    OpenAtArgs {
                        dirfd: LINUX_AT_FDCWD,
                        path: &target_path,
                        flags,
                        mode: 0,
                    },
                    reporter,
                )
                .map_err(|e| match e {
                    DispatchError::Errno(errno) => errno,
                    _ => LINUX_EFAULT,
                }),
            ReopenAction::CopyDescription(new_desc, new_common, fd_flags) => {
                Ok(self.install_fd_with_common(*new_desc, new_common, fd_flags))
            }
            ReopenAction::Errno(errno) => Ok(DispatchOutcome::errno(errno)),
            ReopenAction::Duplicate => Ok(self.duplicate_fd(
                n,
                0,
                if flags & LINUX_O_CLOEXEC != 0 {
                    LINUX_FD_CLOEXEC
                } else {
                    0
                },
            )),
        }
    }

    pub(super) fn proc_self_fd_entries(&self, path: &str, is_fdinfo: bool) -> Vec<RootFsDirEntry> {
        let fds = self.open_fd_numbers();
        let dir_path = std::path::Path::new(path);
        let (kind, mode) = if is_fdinfo {
            (RootFsEntryKind::File, 0o400)
        } else {
            (RootFsEntryKind::Symlink, 0o777)
        };
        fds.into_iter()
            .map(|fd| {
                let name = fd.to_string();
                RootFsDirEntry {
                    metadata: RootFsMetadata {
                        path: dir_path.join(&name),
                        kind,
                        mode,
                        size: 0,
                    },
                    name,
                    ino: 0,
                }
            })
            .collect()
    }

    /// Render `/proc/self/fdinfo/N` (proc_pid_fdinfo(5)): pos, the open flags
    /// (octal), a synthetic mnt_id, and the fd's inode. Pulls the live position
    /// (the in-memory cursor, or a host `lseek` for an overlay-backed file) and
    /// the status flags from the live fd table. `None` if fd N is not open.
    pub(super) fn fdinfo_bytes(&self, n: i32) -> Option<Vec<u8>> {
        let of = self.open_file(n)?;
        let desc = of.description.read();
        let cloexec = of.fd_flags & LINUX_FD_CLOEXEC != 0;
        let flags = reportable_status_flags(of.description.common().status_flags())
            | if cloexec { LINUX_O_CLOEXEC } else { 0 };
        let pos = match desc.as_deref() {
            Some(
                OpenDescription::File { offset, .. }
                | OpenDescription::SyntheticFile { offset, .. }
                | OpenDescription::Directory { offset, .. },
            ) => *offset as u64,
            Some(OpenDescription::HostFile { host_fd, .. }) => {
                host_fd_offset(host_fd.view()).unwrap_or(0)
            }
            _ => 0,
        };
        drop(desc);
        let ino = self.fd_stat_record(n).map(|r| r.ino).unwrap_or(0);
        let mut out = format!("pos:\t{pos}\nflags:\t0{flags:o}\nmnt_id:\t24\nino:\t{ino}\n");
        // An inotify fd's fdinfo also carries one `inotify wd:...mask:...` line
        // per live watch (proc_pid_fdinfo(5)); inotify12 parses the mask from it.
        if let Some(state) = self.inotify_state(n) {
            out.push_str(&state.fdinfo_lines());
        }
        Some(out.into_bytes())
    }

    /// Install a read-only synthetic-bytes fd (e.g. a rendered fdinfo file).
    /// The namespace type (`"uts"`, `"user"`, …) for an fd opened on a
    /// `/proc/<pid>/ns/<type>` nsfs magic link, or `None` if the fd is not such
    /// a link. The fd is a 0-byte `SyntheticFile` whose recorded `path` is the
    /// magic-link path; `proc_ns_link` recognises it. Keys the `NS_GET_*` ioctls.
    pub(super) fn fd_ns_link_type(&self, fd: i32) -> Option<String> {
        let files = self.captured_file_table();
        let table = files.read_open_files();
        let open_file = table.get(&fd)?;
        let description = open_file.description.read()?;
        let path = description.open_path()?;
        proc_ns_link(path).map(|t| t.to_owned())
    }

    pub(super) fn install_proc_synthetic_bytes(
        &self,
        path: &str,
        contents: Vec<u8>,
        flags: u64,
    ) -> DispatchOutcome {
        let status = flags & !LINUX_O_CLOEXEC;
        let open_file = OpenFile::from_open_description_with_status_flags(
            Arc::new(RwLock::new(OpenDescription::SyntheticFile {
                path: path.to_string(),
                contents,
                offset: 0,
                base: OpenDescriptionBase::new(status),
            })),
            status,
            linux_fd_flags_from_open_flags(flags),
        );
        match self.install_fd_at_or_above(0, open_file) {
            Ok(fd) => DispatchOutcome::returned_i32(fd),
            Err(_) => DispatchOutcome::errno(linux_errno::EMFILE),
        }
    }

    /// If `path` is `/proc/self/fd/{0,1,2}` (or `/proc/<pid>/fd/...`) and the
    /// guest's stdio is the `carrick run -t` controlling pty, return its
    /// `/dev/pts/N` path. This is the symlink glibc `ttyname(3)` reads to name
    /// the terminal. Only the three stdio fds are mapped (they're the pty
    /// slave under `-t`).
    pub(super) fn proc_self_fd_tty_link(&self, path: &str) -> Option<String> {
        let fd_part = path
            .strip_prefix("/proc/self/fd/")
            .or_else(|| path.strip_prefix("/proc/thread-self/fd/"))?;
        if !matches!(fd_part, "0" | "1" | "2") {
            return None;
        }
        let n = self.pty_table().lock().controlling()?;
        Some(format!("/dev/pts/{n}"))
    }
}
