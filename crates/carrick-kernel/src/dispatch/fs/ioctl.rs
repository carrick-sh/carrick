//! Ioctl dispatch and tty/pty/ficlone ioctl emulation.
//!
//! Handles character devices, ttys, ptys, network interface queries (`SIOCGIF*`),
//! pipe queue queries (`FIONREAD`), and file-cloning operations (`FICLONE`).

use super::*;
use crate::linux_abi::LINUX_TIOCSIG;

/// `SIOCOUTQ` (`TIOCOUTQ`): unsent bytes queued on a stream socket. `SIOCINQ`
/// is the same number as `FIONREAD` and shares that arm.
pub const LINUX_SIOCOUTQ: u64 = 0x5411;

pub(crate) fn resolve_tiocspgrp(
    context: &crate::kernel::KernelContext,
    namespace_id: i32,
) -> Result<crate::kernel::ProcessGroupId, LinuxErrno> {
    let namespace_id = u32::try_from(namespace_id)
        .ok()
        .filter(|id| *id != 0)
        .ok_or(LINUX_EINVAL)?;
    let group_id =
        crate::namespace::pid::ns_to_process_group_for(context, namespace_id).ok_or(LINUX_EPERM)?;
    let group = context
        .kernel()
        .registry()
        .process_group(group_id)
        .ok_or(LINUX_EPERM)?;
    if group.session() != context.task().session() {
        return Err(LINUX_EPERM);
    }
    Ok(group_id)
}

fn linux_termio_bytes(termios: &LinuxTermios) -> [u8; LINUX_TERMIO_SIZE] {
    let mut cc = [0u8; 8];
    cc.copy_from_slice(&termios.c_cc[..8]);
    let termio = carrick_abi::LinuxTermio {
        c_iflag: termios.c_iflag as u16,
        c_oflag: termios.c_oflag as u16,
        c_cflag: termios.c_cflag as u16,
        c_lflag: termios.c_lflag as u16,
        c_line: termios.c_line,
        c_cc: cc,
    };
    let mut out = [0u8; LINUX_TERMIO_SIZE];
    // `struct termio` is 17 bytes of fields PADDED to sizeof 18 (its u16
    // members give it alignment 2). The packed Rust mirror serializes the 17
    // real bytes; the trailing pad stays zero. Copying into the full array
    // panicked the runtime on length mismatch — a guest-reachable abort via
    // any TCGETA (probe `ioctlcluster`).
    let bytes = termio.as_bytes();
    out[..bytes.len()].copy_from_slice(bytes);
    out
}

fn write_linux_termio(
    memory: &mut impl CurrentMmMemory,
    address: u64,
    termios: &LinuxTermios,
) -> DispatchOutcome {
    write_packed(memory, address, &linux_termio_bytes(termios))
}

fn merge_linux_termio(current: &LinuxTermios, bytes: &[u8]) -> Result<LinuxTermios, LinuxErrno> {
    let legacy = carrick_abi::LinuxTermio::read_from_bytes(
        bytes
            .get(..core::mem::size_of::<carrick_abi::LinuxTermio>())
            .ok_or(LINUX_EINVAL)?,
    )
    .map_err(|_| LINUX_EINVAL)?;
    let mut next = *current;
    next.c_iflag = (next.c_iflag & 0xffff_0000) | u32::from(legacy.c_iflag);
    next.c_oflag = (next.c_oflag & 0xffff_0000) | u32::from(legacy.c_oflag);
    next.c_cflag = (next.c_cflag & 0xffff_0000) | u32::from(legacy.c_cflag);
    next.c_lflag = (next.c_lflag & 0xffff_0000) | u32::from(legacy.c_lflag);
    next.c_line = legacy.c_line;
    next.c_cc[..legacy.c_cc.len()].copy_from_slice(&legacy.c_cc);
    Ok(next)
}

fn host_fd_matches_device(host_fd: i32, path: &str) -> bool {
    let mut fd_stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(host_fd, &mut fd_stat) } != 0 {
        return false;
    }
    let Ok(c_path) = std::ffi::CString::new(path) else {
        return false;
    };
    let mut path_stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(c_path.as_ptr(), &mut path_stat) } != 0 {
        return false;
    }
    (fd_stat.st_mode & libc::S_IFMT) == libc::S_IFCHR
        && (path_stat.st_mode & libc::S_IFMT) == libc::S_IFCHR
        && fd_stat.st_rdev == path_stat.st_rdev
}

fn fd_is_random_device(this: &FsView<'_>, fd: i32) -> bool {
    this.open_file(fd)
        .is_some_and(|open_file| match open_file.description.read().as_deref() {
            Some(OpenDescription::HostPipe { host_fd, .. }) => {
                host_fd_matches_device(host_fd.raw(), "/dev/random")
                    || host_fd_matches_device(host_fd.raw(), "/dev/urandom")
            }
            Some(OpenDescription::SyntheticDevice { kind, .. }) => matches!(
                kind,
                carrick_vfs::SyntheticDeviceKind::Random
                    | carrick_vfs::SyntheticDeviceKind::Urandom
            ),
            _ => false,
        })
}

fn fd_is_proc_maps(this: &FsView<'_>, fd: i32) -> bool {
    this.open_file(fd)
        .and_then(|open_file| open_file.description().open_path_snapshot())
        .is_some_and(|path| {
            path == "/proc/self/maps"
                || path == "/proc/thread-self/maps"
                || path
                    .strip_prefix("/proc/")
                    .and_then(|tail| tail.strip_suffix("/maps"))
                    .is_some_and(|pid| {
                        !pid.is_empty() && pid.bytes().all(|byte| byte.is_ascii_digit())
                    })
        })
}

fn pidfd_get_info(
    this: &FsView<'_>,
    memory: &mut impl CurrentMmMemory,
    fd: i32,
    request: u64,
    arg: u64,
) -> DispatchOutcome {
    let Some(open_file) = this.open_file(fd) else {
        return DispatchOutcome::errno(LINUX_EBADF);
    };
    let watch = {
        let Some(description) = open_file.description.read() else {
            return DispatchOutcome::errno(LINUX_EBADF);
        };
        match &*description {
            OpenDescription::Pidfd { kqueue, .. } => Arc::clone(kqueue),
            _ => return DispatchOutcome::errno(LINUX_ENOTTY),
        }
    };
    if arg == 0 {
        return DispatchOutcome::errno(LINUX_EINVAL);
    }
    let size = usize::try_from((request >> 16) & 0x3fff).unwrap_or(0);
    if !(64..=core::mem::size_of::<carrick_abi::LinuxPidfdInfo>()).contains(&size) {
        return DispatchOutcome::errno(LINUX_EINVAL);
    }
    let mut info: carrick_abi::LinuxPidfdInfo = match read_kernel_prefix(memory, arg, size) {
        Ok(info) => info,
        Err(errno) => return DispatchOutcome::errno(errno),
    };
    let requested = info.mask;
    info = carrick_abi::LinuxPidfdInfo::default();
    if requested & carrick_abi::LINUX_PIDFD_INFO_EXIT != 0 {
        if let Some(status) = watch.exit_status() {
            info.mask |= carrick_abi::LINUX_PIDFD_INFO_EXIT;
            info.exit_code = status.raw();
        }
    }
    write_packed(memory, arg, &info.as_bytes()[..size])
}

fn is_pidfd_get_info(request: u64) -> bool {
    request & 0xc000_ffff == 0xc000_ff0b
}

fn procmap_query(
    this: &FsView<'_>,
    context: &crate::kernel::KernelContext,
    memory: &mut impl CurrentMmMemory,
    arg: u64,
) -> DispatchOutcome {
    let mut query: carrick_abi::LinuxProcmapQuery = match read_kernel_struct(memory, arg) {
        Ok(query) => query,
        Err(errno) => return DispatchOutcome::errno(errno),
    };
    let size = query.size;
    if size < <carrick_abi::LinuxProcmapQuery as KernelAbi>::ABI_SIZE as u64 {
        return DispatchOutcome::errno(LINUX_EINVAL);
    }

    const FILTER_FLAGS: u64 = carrick_abi::LINUX_PROCMAP_QUERY_VMA_READABLE
        | carrick_abi::LINUX_PROCMAP_QUERY_VMA_WRITABLE
        | carrick_abi::LINUX_PROCMAP_QUERY_VMA_EXECUTABLE
        | carrick_abi::LINUX_PROCMAP_QUERY_VMA_SHARED
        | carrick_abi::LINUX_PROCMAP_QUERY_FILE_BACKED_VMA;
    const ALL_FLAGS: u64 = FILTER_FLAGS | carrick_abi::LINUX_PROCMAP_QUERY_COVERING_OR_NEXT_VMA;
    let flags = query.query_flags;
    if flags & !ALL_FLAGS != 0 {
        return DispatchOutcome::errno(LINUX_EINVAL);
    }

    let proc_context = this.synthetic_proc_context(context);
    let executable_path = proc_context.executable_path;
    let mut maps = proc_context.address_space_regions.unwrap_or_default();
    let brk_current = proc_context.brk_current;
    let mmap_next = proc_context.mmap_next;
    maps.sort_by_key(|map| map.start);
    let query_addr = query.query_addr;
    let covering_or_next = flags & carrick_abi::LINUX_PROCMAP_QUERY_COVERING_OR_NEXT_VMA != 0;
    let page = carrick_abi::LINUX_PAGE_SIZE;
    let matches_filter = |map: &carrick_vfs::ProcMapsEntry| {
        let mut map_flags = 0;
        if map.read {
            map_flags |= carrick_abi::LINUX_PROCMAP_QUERY_VMA_READABLE;
        }
        if map.write {
            map_flags |= carrick_abi::LINUX_PROCMAP_QUERY_VMA_WRITABLE;
        }
        if map.execute {
            map_flags |= carrick_abi::LINUX_PROCMAP_QUERY_VMA_EXECUTABLE;
        }
        if map.sharing == carrick_vfs::ProcMapSharing::Shared {
            map_flags |= carrick_abi::LINUX_PROCMAP_QUERY_VMA_SHARED;
        }
        let name = if map.path.is_empty() && map.execute {
            executable_path.as_str()
        } else {
            map.path.as_str()
        };
        if !name.is_empty() && !name.starts_with('[') {
            map_flags |= carrick_abi::LINUX_PROCMAP_QUERY_FILE_BACKED_VMA;
        }
        map_flags & (flags & FILTER_FLAGS) == flags & FILTER_FLAGS
    };
    let selected = maps.into_iter().find(|map| {
        let start = map.start & !(page - 1);
        let mut semantic_end = map.end;
        if map.start == crate::memory::LINUX_HEAP_BASE
            && brk_current > map.start
            && brk_current <= map.end
        {
            semantic_end = brk_current;
        } else if map.start == crate::memory::LINUX_MMAP_BASE
            && mmap_next > map.start
            && mmap_next <= map.end
        {
            semantic_end = mmap_next;
        }
        let end = semantic_end.div_ceil(page) * page;
        let address_matches = if covering_or_next {
            end > query_addr
        } else {
            start <= query_addr && query_addr < end
        };
        address_matches && matches_filter(map)
    });
    let Some(map) = selected else {
        return DispatchOutcome::errno(LINUX_ENOENT);
    };

    let start = map.start & !(page - 1);
    let mut semantic_end = map.end;
    if map.start == crate::memory::LINUX_HEAP_BASE
        && brk_current > map.start
        && brk_current <= map.end
    {
        semantic_end = brk_current;
    } else if map.start == crate::memory::LINUX_MMAP_BASE
        && mmap_next > map.start
        && mmap_next <= map.end
    {
        semantic_end = mmap_next;
    }
    let end = semantic_end.div_ceil(page) * page;
    let mut map_flags = 0;
    if map.read {
        map_flags |= carrick_abi::LINUX_PROCMAP_QUERY_VMA_READABLE;
    }
    if map.write {
        map_flags |= carrick_abi::LINUX_PROCMAP_QUERY_VMA_WRITABLE;
    }
    if map.execute {
        map_flags |= carrick_abi::LINUX_PROCMAP_QUERY_VMA_EXECUTABLE;
    }
    if map.sharing == carrick_vfs::ProcMapSharing::Shared {
        map_flags |= carrick_abi::LINUX_PROCMAP_QUERY_VMA_SHARED;
    }
    let name = if map.path.is_empty() && map.execute {
        executable_path
    } else {
        map.path
    };
    let name_capacity = query.vma_name_size as usize;
    let name_address = query.vma_name_addr;
    let name_bytes = (!name.is_empty()).then(|| {
        let mut bytes = name.into_bytes();
        bytes.push(0);
        bytes
    });
    if let Some(name_bytes) = &name_bytes {
        if name_bytes.len() > name_capacity {
            return DispatchOutcome::errno(LINUX_E2BIG);
        }
        if name_address == 0 || memory.write_bytes(name_address, name_bytes).is_err() {
            return DispatchOutcome::errno(LINUX_EFAULT);
        }
    }

    query.vma_start = start;
    query.vma_end = end;
    query.vma_flags = map_flags;
    query.vma_page_size = page;
    query.vma_offset = 0;
    query.inode = 0;
    query.dev_major = 0;
    query.dev_minor = 0;
    query.vma_name_size = name_bytes.as_ref().map_or(0, |bytes| bytes.len() as u32);
    query.build_id_size = 0;
    match write_kernel_struct_raw(memory, arg, &query) {
        Ok(()) => DispatchOutcome::Returned { value: 0 },
        Err(_) => DispatchOutcome::errno(LINUX_EFAULT),
    }
}

/// One Linux-visible interface with an IPv4 address. Flags and MTU stay in
/// their Linux model domain; translating them through host constants would
/// discard namespace state and can contradict rtnetlink and sysfs.
pub struct HostInet4Iface {
    pub(crate) name: String,
    pub(crate) flags_linux: u16,
    pub(crate) mtu: i32,
    pub(crate) addr_be: [u8; 4],
}

pub(crate) fn inet4_interfaces_from_model(
    model: &crate::network::model::LinuxNetworkModel,
) -> Vec<HostInet4Iface> {
    let mut out = Vec::new();
    for link in &model.links {
        let addr_be = model
            .addresses
            .iter()
            .find_map(|a| {
                if a.link_name == link.name
                    && let std::net::IpAddr::V4(v4) = a.addr
                {
                    Some(v4.octets())
                } else {
                    None
                }
            })
            .unwrap_or(if link.loopback {
                [127, 0, 0, 1]
            } else {
                [0, 0, 0, 0]
            });
        out.push(HostInet4Iface {
            name: link.name.clone(),
            flags_linux: (link.flags & u32::from(u16::MAX)) as u16,
            mtu: i32::try_from(link.mtu).unwrap_or(i32::MAX),
            addr_be,
        });
    }
    out
}

/// Build one Linux `struct ifreq` (40 bytes) carrying `name` and an
/// `AF_INET` `ifr_addr` for `addr_be`. The trailing union bytes are zero.
fn linux_ifreq_inet4(name: &str, addr_be: [u8; 4]) -> LinuxIfreq {
    let mut ifr_name = [0u8; LINUX_IFNAMSIZ];
    let nb = name.as_bytes();
    let n = nb.len().min(LINUX_IFNAMSIZ - 1);
    ifr_name[..n].copy_from_slice(&nb[..n]);
    let mut ifr_ifru = [0u8; 24];
    // ifr_addr starts at offset 0 of union: sockaddr_in { family(2) port(2) addr(4) }.
    ifr_ifru[0..2].copy_from_slice(&(LINUX_AF_INET as u16).to_ne_bytes());
    ifr_ifru[4..8].copy_from_slice(&addr_be);
    LinuxIfreq { ifr_name, ifr_ifru }
}

/// The filesystem an fd's inode lives on, as far as `FICLONE`'s error
/// precedence can tell them apart. Derived from the oracle's
/// `ioctl_ficlone04` matrix (every pairing of 17 fd types), not from headers.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FicloneFs {
    /// The container rootfs: regular files and directories.
    Root {
        is_dir: bool,
    },
    /// devtmpfs (`/dev/zero` and friends).
    Dev,
    /// procfs.
    Proc,
    /// pipefs (both ends).
    Pipe,
    /// sockfs (unix and inet).
    Sock,
    /// anon_inodefs: epoll, eventfd, signalfd, timerfd, inotify.
    AnonInode,
    /// Filesystems whose files ARE regular but whose driver has no clone
    /// operation, so a same-fs pairing is EOPNOTSUPP rather than EINVAL:
    /// tmpfs-backed `memfd`, `secretmem`, and pidfs.
    Unclonable(u8),
    Other,
}

impl<'a> FsView<'a> {
    fn tty_ioctl_fd_kind(&self, fd: i32) -> Result<TtyFdKind, LinuxErrno> {
        if is_stdio_fd(fd) && !self.stdio_is_closed(fd) && !self.fd_table_contains(fd) {
            Ok(TtyFdKind::Stdio)
        } else if self.fd_is_valid(fd) {
            Ok(TtyFdKind::Other)
        } else {
            Err(LINUX_EBADF)
        }
    }

    /// If `fd` is a pty master/slave end, return its role and the backing
    /// host fd in one fd-table lookup.
    pub(super) fn pty_info(&self, fd: i32) -> Option<(crate::vfs::PtyRole, i32)> {
        self.open_file(fd)
            .and_then(|of| match of.description.read().as_deref() {
                Some(OpenDescription::HostPipe {
                    host_fd,
                    pty: Some(role),
                    ..
                }) => Some((*role, host_fd.raw())),
                _ => None,
            })
    }

    pub(super) fn tty0_console(
        &self,
        fd: i32,
    ) -> Option<Arc<dyn carrick_vfs::VirtualConsoleDevice>> {
        let of = self.open_file(fd)?;
        let desc = &of.description;
        match desc.read().as_deref() {
            Some(crate::dispatch::fd_table::OpenDescription::VirtualConsole {
                console, ..
            }) => Some(Arc::clone(console)),
            _ => None,
        }
    }

    pub(super) fn fd_is_controlling_tty(
        &self,
        cx_kernel: &crate::kernel::KernelContext,
        fd: i32,
    ) -> bool {
        let session = cx_kernel.task().session();
        let controlling_index = self.pty_table().lock().controlling();
        if let Some((role, _)) = self.pty_info(fd) {
            if role.is_master {
                return false;
            }
            if crate::kernel::tty::session(crate::kernel::tty::TtyKey::Pty(role.index))
                == Some(session)
            {
                return true;
            }
            if controlling_index == Some(role.index)
                && (crate::kernel::tty::session(crate::kernel::tty::TtyKey::Launch)
                    == Some(session)
                    || cx_kernel.kernel().tty_session(cx_kernel) == Ok(session))
            {
                return true;
            }
            false
        } else if is_stdio_fd(fd)
            && !self.stdio_is_closed(fd)
            && !self.fd_table_contains(fd)
            && controlling_index.is_some()
        {
            crate::kernel::tty::session(crate::kernel::tty::TtyKey::Launch) == Some(session)
                || cx_kernel.kernel().tty_session(cx_kernel) == Ok(session)
        } else {
            false
        }
    }

    fn pty_winsize_target(&self, role: crate::vfs::PtyRole, host_fd: i32) -> Option<i32> {
        if !role.is_master {
            return Some(host_fd);
        }
        let files = self.captured_file_table();
        let table = files.read_open_files();
        for of in table.values() {
            if let Some(OpenDescription::HostPipe {
                host_fd: slave_host_fd,
                pty: Some(slave_role),
                ..
            }) = of.description.read().as_deref()
                && !slave_role.is_master
                && slave_role.index == role.index
            {
                return Some(slave_host_fd.raw());
            }
        }
        None
    }

    /// True when the FICLONE destination cannot be written (a read-only
    /// description such as a procfs file), which Linux reports as EBADF.
    fn ficlone_dest_unwritable(&self, fd: i32) -> bool {
        self.open_file(fd).is_some_and(|of| {
            of.description.common().status_flags() & LINUX_O_ACCMODE == LINUX_O_RDONLY
        })
    }

    /// The filesystem class `FICLONE` error precedence keys on — see
    /// [`FicloneFs`].
    fn ficlone_fs(&self, fd: i32) -> FicloneFs {
        let Some(open_file) = self.open_file(fd) else {
            return FicloneFs::Other;
        };
        let Some(open) = open_file.description.read() else {
            return FicloneFs::Other;
        };
        match &*open {
            OpenDescription::Directory { .. } => FicloneFs::Root { is_dir: true },
            OpenDescription::Epoll { .. }
            | OpenDescription::EventFd { .. }
            | OpenDescription::TimerFd { .. }
            | OpenDescription::SignalFd { .. }
            | OpenDescription::Inotify { .. }
            | OpenDescription::Fanotify { .. } => FicloneFs::AnonInode,
            OpenDescription::Pidfd { .. } => FicloneFs::Unclonable(0),
            OpenDescription::PipeReader { .. } | OpenDescription::PipeWriter { .. } => {
                FicloneFs::Pipe
            }
            OpenDescription::VirtualConsole { .. } => FicloneFs::Dev,
            OpenDescription::HostPipe { pty: None, .. } => FicloneFs::Pipe,
            OpenDescription::HostSocket { .. } | OpenDescription::InMemorySocket { .. } => {
                FicloneFs::Sock
            }
            // Path-keyed classes cover File, SyntheticFile AND HostFile: the
            // guest's /dev/zero is a HostFile, so keying off the variant alone
            // put a character device on the rootfs and turned a devfs->pipefs
            // pairing into a same-fs one.
            OpenDescription::File { .. } | OpenDescription::SyntheticFile { .. } => {
                let path = open.open_path().unwrap_or_default();
                if open_file.description.common().secretmem() {
                    FicloneFs::Unclonable(1)
                } else if path.starts_with("/dev/") {
                    FicloneFs::Dev
                } else if path.starts_with("/proc/") {
                    FicloneFs::Proc
                } else if path.starts_with("/memfd:") || path.starts_with("memfd:") {
                    FicloneFs::Unclonable(2)
                } else {
                    FicloneFs::Root { is_dir: false }
                }
            }
            // A host-backed fd may carry no recorded path (the guest's
            // /dev/zero is one), so classify by the host inode's TYPE: a
            // character device lives on devtmpfs, a fifo on pipefs, a socket
            // on sockfs. Keying on the path alone put /dev/zero on the rootfs
            // and turned devfs<->pipefs pairings into same-fs ones.
            OpenDescription::HostFile { host_fd, .. } => {
                let path = open.open_path().unwrap_or_default();
                if path.starts_with("/dev/") {
                    FicloneFs::Dev
                } else if path.starts_with("/proc/") {
                    FicloneFs::Proc
                } else {
                    let mut st: libc::stat = unsafe { core::mem::zeroed() };
                    // SAFETY: host_fd is a live descriptor owned by this
                    // description; fstat only writes the stat buffer.
                    if unsafe { libc::fstat(host_fd.raw(), &mut st) } == 0 {
                        match st.st_mode & libc::S_IFMT {
                            libc::S_IFCHR => FicloneFs::Dev,
                            libc::S_IFIFO => FicloneFs::Pipe,
                            libc::S_IFSOCK => FicloneFs::Sock,
                            libc::S_IFDIR => FicloneFs::Root { is_dir: true },
                            _ => FicloneFs::Root { is_dir: false },
                        }
                    } else {
                        FicloneFs::Root { is_dir: false }
                    }
                }
            }
            _ => FicloneFs::Other,
        }
    }

    /// `FICLONE`'s errno for a (source, destination) pair, in the precedence
    /// the oracle's matrix exhibits: cross-filesystem EXDEV first (a directory
    /// cloned to `/dev/zero` is EXDEV, not EISDIR), then EISDIR for a same-fs
    /// pairing involving a directory, then EBADF for a same-fs destination
    /// that cannot be written (`/proc/self/maps` onto itself), then
    /// EOPNOTSUPP for a filesystem whose driver simply lacks the operation
    /// (memfd, secretmem, pidfs), else EINVAL. carrick answered EOPNOTSUPP for
    /// every pairing.
    ///
    /// Two regular rootfs files land on EXDEV because the oracle reports EXDEV
    /// for its own `file -> file` case: LTP builds its two instances on
    /// different mounts, and carrick's rootfs cannot distinguish them either.
    fn ficlone_errno(&self, src_fd: i32, dst_fd: i32) -> LinuxErrno {
        let src = self.ficlone_fs(src_fd);
        let dst = self.ficlone_fs(dst_fd);
        if std::env::var_os("CARRICK_FICLONE_DEBUG").is_some() {
            let name = |fd: i32| {
                self.open_file(fd)
                    .and_then(|of| {
                        let g = of.description.read()?;
                        Some(format!(
                            "{}:{}",
                            g.reexec_kind_name(),
                            g.open_path().unwrap_or("-")
                        ))
                    })
                    .unwrap_or_else(|| "<none>".into())
            };
            eprintln!(
                "FICLONEDBG src={:?}({}) dst={:?}({})",
                src,
                name(src_fd),
                dst,
                name(dst_fd)
            );
        }
        let same_fs = match (src, dst) {
            (FicloneFs::Root { .. }, FicloneFs::Root { .. }) => true,
            _ => src == dst,
        };
        if !same_fs {
            return carrick_abi::LINUX_EXDEV;
        }
        if let (FicloneFs::Root { is_dir: a }, FicloneFs::Root { is_dir: b }) = (src, dst) {
            if a || b {
                return LINUX_EISDIR;
            }
            // Distinct mounts — see the note above.
            return carrick_abi::LINUX_EXDEV;
        }
        if self.ficlone_dest_unwritable(dst_fd) {
            return LINUX_EBADF;
        }
        match src {
            FicloneFs::Unclonable(_) => LINUX_EOPNOTSUPP,
            _ => LINUX_EINVAL,
        }
    }

    /// Whether `index` is the guest's controlling pty. One lock site for the
    /// six ioctl arms that asked the table directly (the dispatch-lock
    /// burndown caps `pty_table` sites; the ISIG landing had added five).
    fn pty_is_controlling(&self, index: u32) -> bool {
        self.pty_table().lock().controlling() == Some(index)
    }

    define_syscall! {
        fn ioctl(this, cx, fd: Fd, request: u64, arg: u64) {

            let fd: Fd = fd;
            let ioctl_request = request & u32::MAX as u64;
            // A tty *control* ioctl (tcsetpgrp/tcsetattr/winsize) issued on the
            // host pty from a background process group raises SIGTTOU regardless
            // of TOSTOP and would STOP the real carrick process. Linux suppresses
            // that when the calling guest has SIGTTOU ignored or blocked (a
            // job-control shell always does, e.g. busybox ash's forkchild does
            // setpgid()+tcsetpgrp() while still background). Mirror it: block host
            // SIGTTOU around those passthroughs in exactly that case, so the host
            // op completes instead of stopping. A genuinely-default background
            // caller is NOT gated and still stops, matching Linux.
            let block_ttou = {
                let tid = Self::ctx_tid(cx);
                this.signal_is_ignored(cx.kernel, LINUX_SIGTTOU)
                    || this.signal_blocked(cx.kernel, tid, LINUX_SIGTTOU)
            };
            if !this.fd_is_valid(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // An O_PATH descriptor is not open for I/O — ioctl on it is EBADF
            // (open13 issues FIGETBSZ on an O_PATH fd).
            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            if ioctl_request == carrick_abi::LINUX_PROCMAP_QUERY && fd_is_proc_maps(this, fd.0) {
                return Ok(procmap_query(this, cx.kernel, &mut *cx.memory, arg));
            }
            if is_pidfd_get_info(ioctl_request) {
                return Ok(pidfd_get_info(this, &mut *cx.memory, fd.0, ioctl_request, arg));
            }
            let changes_tty_state = matches!(
                ioctl_request,
                LINUX_TCSETS
                    | LINUX_TCSETSW
                    | LINUX_TCSETSF
                    | LINUX_TCSETS2
                    | LINUX_TCSETSW2
                    | LINUX_TCSETSF2
                    | LINUX_TIOCSPGRP
                    | LINUX_TIOCSWINSZ
            );
            if changes_tty_state
                && this.fd_is_controlling_tty(cx.kernel, fd.0)
                && cx.kernel.kernel().tty_caller_is_background(cx.kernel)
                && !block_ttou
            {
                let orphaned = cx.kernel.kernel().caller_process_group_is_orphaned(cx.kernel);
                if orphaned {
                    return Ok(DispatchOutcome::errno(carrick_abi::LINUX_EIO));
                }
                if let Ok(signal) = crate::kernel::LinuxSignal::for_signal_number(LINUX_SIGTTOU) {
                    cx.kernel.kernel().post_signal_to_process_group(
                        cx.kernel.container().id(),
                        cx.kernel.task().process_group(),
                        signal,
                    );
                }
                return Ok(DispatchOutcome::errno(LINUX_EINTR));
            }

            // ── Rosetta 2 virtualization handshake ──────────────────────────────────
            // At startup Apple's Rosetta issues a small set of ioctls on its
            // /proc/.../exe fd to confirm it is running inside an Apple
            // virtualization environment. The size field (bits [29:16]) of the
            // request encodes the expected response length. The licensing ioctl
            // (...6125) is `memcmp`'d against a verification string Rosetta keeps
            // embedded in its own binary — so we echo back exactly that blob,
            // read live from the installed Rosetta binary (never embedded in
            // carrick). The info ioctl (...6123) is not compared; Rosetta only
            // requires a non-negative return, so a zeroed buffer suffices.
            if let Some(outcome) =
                rosetta_handshake_ioctl(&mut *cx.memory, ioctl_request, arg)
            {
                return Ok(outcome);
            }

            // ── /dev/tty0 virtual console ioctls ──────────────────────────────────
            if let Some(console) = this.tty0_console(fd.0) {
                return Ok(match ioctl_request {
                    LINUX_TCGETA | LINUX_TCGETS | LINUX_TCGETS2 => {
                        let termios = console.get_termios();
                        if ioctl_request == LINUX_TCGETS2 {
                            write_termios2(&mut *cx.memory, arg, &termios)
                        } else if ioctl_request == LINUX_TCGETA {
                            write_linux_termio(&mut *cx.memory, arg, &termios)
                        } else {
                            write_kernel_struct(&mut *cx.memory, arg, &termios)
                        }
                    }
                    LINUX_TCSETS
                    | LINUX_TCSETSW
                    | LINUX_TCSETSF
                    | LINUX_TCSETS2
                    | LINUX_TCSETSW2
                    | LINUX_TCSETSF2 => {
                        let want = if matches!(
                            ioctl_request,
                            LINUX_TCSETS2 | LINUX_TCSETSW2 | LINUX_TCSETSF2
                        ) {
                            LINUX_TERMIOS2_SIZE
                        } else {
                            LINUX_TERMIOS_KERNEL_SIZE
                        };
                        match cx.memory.read_bytes(arg, want) {
                            Ok(bytes) => {
                                let mut padded = [0u8; core::mem::size_of::<LinuxTermios>()];
                                padded[..want].copy_from_slice(&bytes);
                                match LinuxTermios::read_from_bytes(&padded) {
                                    Ok(t) => {
                                        console.set_termios(t);
                                        DispatchOutcome::Returned { value: 0 }
                                    }
                                    Err(_) => DispatchOutcome::errno(LINUX_EINVAL),
                                }
                            }
                            Err(_) => DispatchOutcome::errno(LINUX_EFAULT),
                        }
                    }
                    LINUX_TCSETA | LINUX_TCSETAW | LINUX_TCSETAF => {
                        match cx.memory.read_bytes(arg, LINUX_TERMIO_SIZE) {
                            Ok(bytes) => match merge_linux_termio(&console.get_termios(), &bytes) {
                                Ok(termios) => {
                                    console.set_termios(termios);
                                    DispatchOutcome::Returned { value: 0 }
                                }
                                Err(errno) => DispatchOutcome::errno(errno),
                            },
                            Err(_) => DispatchOutcome::errno(LINUX_EFAULT),
                        }
                    }
                    LINUX_TIOCGWINSZ => {
                        let winsize = console.get_winsize();
                        write_kernel_struct(&mut *cx.memory, arg, &winsize)
                    }
                    LINUX_TIOCSWINSZ => match cx.memory.read_bytes(arg, 8) {
                        Ok(b) => match LinuxWinsize::read_from_bytes(&b) {
                            Ok(ws) => {
                                console.set_winsize(ws);
                                DispatchOutcome::Returned { value: 0 }
                            }
                            Err(_) => DispatchOutcome::errno(LINUX_EINVAL),
                        },
                        Err(_) => DispatchOutcome::errno(LINUX_EFAULT),
                    },
                    LINUX_TCFLSH => match arg {
                        crate::linux_abi::LINUX_TCIFLUSH
                        | crate::linux_abi::LINUX_TCOFLUSH
                        | crate::linux_abi::LINUX_TCIOFLUSH => {
                            DispatchOutcome::Returned { value: 0 }
                        }
                        _ => DispatchOutcome::errno(LINUX_EINVAL),
                    },
                    _ => {
                        cx.reporter
                            .record(CompatEvent::unhandled_ioctl(fd.0, ioctl_request, arg));
                        DispatchOutcome::errno(LINUX_ENOTTY)
                    }
                });
            }

            // ── PTY ioctls ────────────────────────────────────────────────────────
            // If this fd is a pty master or slave, handle all tty ioctls here by
            // passing through to the host fd (real macOS pty). Return early so the
            // stdio-gated arms below never run for pty fds.
            if let Some((role, host_fd)) = this.pty_info(fd.0) {
                return Ok(match ioctl_request {
                    // TIOCGPTN is a MASTER-only ioctl: it returns the pts index
                    // of the master's slave. On a slave it is ENOTTY — which is
                    // exactly how libuv's uv__tty_is_slave detects a slave fd
                    // (and then reopens it non-blocking). Answering it for the
                    // slave too made libuv treat the slave as a master and leave
                    // UV_HANDLE_BLOCKING_WRITES set (tty_pty / tty_pty_partial).
                    LINUX_TIOCGPTN if role.is_master => {
                        write_packed(&mut *cx.memory, arg, &role.index.to_le_bytes())
                    }
                    LINUX_TIOCGPTN => DispatchOutcome::errno(LINUX_ENOTTY),
                    LINUX_TIOCSPTLCK => {
                        let mut buf = [0u8; 4];
                        match cx.memory.read_bytes(arg, 4) {
                            Ok(b) => buf.copy_from_slice(&b),
                            Err(_) => {
                                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                            }
                        }
                        let lock = i32::from_le_bytes(buf) != 0;
                        this.pty_table().lock().set_locked(role.index, lock);
                        DispatchOutcome::Returned { value: 0 }
                    }
                    LINUX_TCGETA | LINUX_TCGETS | LINUX_TCGETS2 => {
                        let termios = crate::host_tty::get_host_termios(host_fd)
                            .unwrap_or_else(LinuxTermios::default_cooked);
                        // glibc-aarch64 tcgetattr on a pty slave uses TCGETS2
                        // (the full 44-byte termios2); musl uses 36-byte TCGETS.
                        if ioctl_request == LINUX_TCGETS2 {
                            write_termios2(&mut *cx.memory, arg, &termios)
                        } else if ioctl_request == LINUX_TCGETA {
                            write_linux_termio(&mut *cx.memory, arg, &termios)
                        } else {
                            write_kernel_struct(&mut *cx.memory, arg, &termios)
                        }
                    }
                    LINUX_TCSETS
                    | LINUX_TCSETSW
                    | LINUX_TCSETSF
                    | LINUX_TCSETS2
                    | LINUX_TCSETSW2
                    | LINUX_TCSETSF2 => {
                        let want = if matches!(
                            ioctl_request,
                            LINUX_TCSETS2 | LINUX_TCSETSW2 | LINUX_TCSETSF2
                        ) {
                            LINUX_TERMIOS2_SIZE
                        } else {
                            LINUX_TERMIOS_KERNEL_SIZE
                        };
                        match cx.memory.read_bytes(arg, want) {
                            Ok(bytes) => {
                                let mut padded = [0u8; core::mem::size_of::<LinuxTermios>()];
                                padded[..want].copy_from_slice(&bytes);
                                match LinuxTermios::read_from_bytes(&padded) {
                                    Ok(mut t) => {
                                        // Linux's pty driver never stores CS5-CS7.
                                        crate::host_tty::coerce_pty_termios(&mut t);
                                        let _ = crate::host_tty::with_sigttou_blocked(
                                            block_ttou,
                                            || crate::host_tty::set_host_termios(host_fd, &t),
                                        );
                                        DispatchOutcome::Returned { value: 0 }
                                    }
                                    Err(_) => DispatchOutcome::errno(LINUX_EINVAL),
                                }
                            }
                            Err(_) => DispatchOutcome::errno(LINUX_EFAULT),
                        }
                    }
                    LINUX_TIOCGWINSZ => {
                        // macOS rejects winsize ioctls on a master; read from the
                        // guest's open slave fd for a master role (see
                        // pty_winsize_target). No slave open yet → 80x24 stub.
                        let ws = match this.pty_winsize_target(role, host_fd) {
                            Some(ws_fd) => crate::host_tty::get_host_winsize(ws_fd)
                                .unwrap_or_else(LinuxWinsize::terminal_80x24),
                            None => LinuxWinsize::terminal_80x24(),
                        };
                        write_kernel_struct(&mut *cx.memory, arg, &ws)
                    }
                    LINUX_TIOCSWINSZ => {
                        match cx.memory.read_bytes(arg, 8) {
                            Ok(b) => {
                                let mut ws: libc::winsize = unsafe { core::mem::zeroed() };
                                ws.ws_row = u16::from_le_bytes([b[0], b[1]]);
                                ws.ws_col = u16::from_le_bytes([b[2], b[3]]);
                                ws.ws_xpixel = u16::from_le_bytes([b[4], b[5]]);
                                ws.ws_ypixel = u16::from_le_bytes([b[6], b[7]]);
                                // macOS rejects TIOCSWINSZ on a master (ENOTTY);
                                // apply it to the guest's open slave fd for a
                                // master role. If no slave is open yet, succeed as
                                // a no-op rather than hand the guest a spurious
                                // ENOTTY (Linux always accepts it on the master).
                                match this.pty_winsize_target(role, host_fd) {
                                    Some(ws_fd) => {
                                        // SAFETY: ws_fd is a live pty fd; &ws is valid.
                                        let r = crate::host_tty::with_sigttou_blocked(
                                            block_ttou,
                                            || unsafe {
                                                libc::ioctl(
                                                    ws_fd,
                                                    libc::TIOCSWINSZ as libc::c_ulong,
                                                    &ws,
                                                )
                                            },
                                        );
                                        if r < 0 {
                                            DispatchOutcome::errno(
                                                crate::host_to_linux_errno(get_last_error()),
                                            )
                                        } else {
                                            DispatchOutcome::Returned { value: 0 }
                                        }
                                    }
                                    None => DispatchOutcome::Returned { value: 0 },
                                }
                            }
                            Err(_) => DispatchOutcome::errno(LINUX_EFAULT),
                        }
                    }
                    LINUX_TIOCGPGRP => {
                        if role.is_master {
                            return Ok(DispatchOutcome::errno(LINUX_ENOTTY));
                        }
                        let session = cx.kernel.task().session();
                        let group_res = crate::kernel::tty::foreground_process_group(
                            crate::kernel::tty::TtyKey::Pty(role.index),
                            session,
                        )
                        .or_else(|_| {
                            if this.pty_is_controlling(role.index) {
                                cx.kernel.kernel().tty_foreground_process_group(cx.kernel).map_err(|_| LINUX_ENOTTY)
                            } else {
                                Err(LINUX_ENOTTY)
                            }
                        });
                        match group_res {
                            Ok(group) => match crate::namespace::pid::process_group_to_ns_for(
                                cx.kernel,
                                group,
                            )
                            .and_then(|group| i32::try_from(group).ok())
                            {
                                Some(group) => write_packed(&mut *cx.memory, arg, &group.to_le_bytes()),
                                None => DispatchOutcome::errno(LINUX_ESRCH),
                            },
                            Err(errno) => DispatchOutcome::errno(errno),
                        }
                    }
                    LINUX_TIOCSPGRP => {
                        if role.is_master {
                            return Ok(DispatchOutcome::errno(LINUX_ENOTTY));
                        }
                        let mut buf = [0u8; 4];
                        match cx.memory.read_bytes(arg, 4) {
                            Ok(b) => buf.copy_from_slice(&b),
                            Err(_) => {
                                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                            }
                        }
                        let group = match resolve_tiocspgrp(cx.kernel, i32::from_le_bytes(buf)) {
                            Ok(group) => group,
                            Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                        };
                        let session = cx.kernel.task().session();
                        let res = crate::kernel::tty::set_foreground_process_group(
                            crate::kernel::tty::TtyKey::Pty(role.index),
                            session,
                            group,
                        );
                        if this.pty_is_controlling(role.index) {
                            let _ = cx.kernel.kernel().tty_set_foreground_process_group(cx.kernel, group);
                        }
                        match res {
                            Ok(()) => DispatchOutcome::Returned { value: 0 },
                            Err(errno) => {
                                if this.pty_is_controlling(role.index) {
                                    match cx.kernel.kernel().tty_set_foreground_process_group(cx.kernel, group) {
                                        Ok(()) => DispatchOutcome::Returned { value: 0 },
                                        Err(crate::kernel::TtyControlError::NotControlling) => DispatchOutcome::errno(LINUX_ENOTTY),
                                        Err(crate::kernel::TtyControlError::Permission) => DispatchOutcome::errno(LINUX_EPERM),
                                    }
                                } else {
                                    DispatchOutcome::errno(errno)
                                }
                            }
                        }
                    }
                    LINUX_TIOCSCTTY => {
                        if role.is_master {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                        let session = cx.kernel.task().session();
                        if session.raw() != cx.kernel.task().key().id.raw() {
                            return Ok(DispatchOutcome::errno(LINUX_EPERM));
                        }
                        // A session leader that already has a controlling
                        // terminal cannot take a second one (Linux: EPERM).
                        if crate::kernel::tty::session(crate::kernel::tty::TtyKey::Pty(role.index))
                            != Some(session)
                            && crate::kernel::tty::session_owns_tty(session)
                        {
                            return Ok(DispatchOutcome::errno(LINUX_EPERM));
                        }
                        let force = arg != 0;
                        let group = cx.kernel.task().process_group();
                        match crate::kernel::tty::attach_pty(
                            role.index,
                            cx.kernel.kernel(),
                            cx.kernel.container().id(),
                            session,
                            group,
                            force,
                        ) {
                            Ok(()) => {
                                crate::vfs::devpts::set_controlling_index(
                                    this.pty_table(),
                                    Some(role.index),
                                );
                                let _ = cx.kernel.kernel().tty_acquire(cx.kernel, force);
                                DispatchOutcome::Returned { value: 0 }
                            }
                            Err(errno) => DispatchOutcome::errno(errno),
                        }
                    }
                    LINUX_TIOCGSID => {
                        let session_res = crate::kernel::tty::session(crate::kernel::tty::TtyKey::Pty(role.index))
                            .ok_or(LINUX_ENOTTY)
                            .or_else(|_| {
                                if this.pty_is_controlling(role.index) {
                                    cx.kernel.kernel().tty_session(cx.kernel).map_err(|_| LINUX_ENOTTY)
                                } else {
                                    Err(LINUX_ENOTTY)
                                }
                            });
                        match session_res {
                            Ok(session) => match crate::namespace::pid::session_to_ns_for(
                                cx.kernel,
                                session,
                            )
                            .and_then(|session| i32::try_from(session).ok())
                            {
                                Some(session) => write_packed(&mut *cx.memory, arg, &session.to_le_bytes()),
                                None => DispatchOutcome::errno(LINUX_ESRCH),
                            },
                            Err(errno) => DispatchOutcome::errno(errno),
                        }
                    }
                    LINUX_TIOCNOTTY => {
                        // Only the session that owns this pty as its controlling
                        // terminal may give it up; anyone else gets ENOTTY
                        // (oracle `ptyflagmatrix`: `ctty_tiocnotty_errno=25`).
                        let session = cx.kernel.task().session();
                        let key = crate::kernel::tty::TtyKey::Pty(role.index);
                        if crate::kernel::tty::session(key) != Some(session) {
                            return Ok(DispatchOutcome::errno(LINUX_ENOTTY));
                        }
                        // A session LEADER giving up its terminal hangs up the
                        // foreground process group (SIGHUP, then SIGCONT) before
                        // the terminal is detached; a non-leader only drops its
                        // own reference, which this per-session model has no
                        // separate state for.
                        if session.raw() == cx.kernel.task().key().id.raw() {
                            crate::kernel::tty::route_foreground_signal_to_tty(
                                key,
                                crate::linux_abi::LINUX_SIGHUP,
                            );
                            crate::kernel::tty::route_foreground_signal_to_tty(
                                key,
                                crate::linux_abi::LINUX_SIGCONT,
                            );
                            if this.pty_is_controlling(role.index) {
                                crate::vfs::devpts::set_controlling_index(this.pty_table(), None);
                                let _ = cx.kernel.kernel().tty_detach(cx.kernel);
                            }
                            crate::kernel::tty::detach_if_session(key, session);
                        }
                        DispatchOutcome::Returned { value: 0 }
                    }
                    LINUX_TIOCSIG => {
                        // TIOCSIG is a pty MASTER ioctl; on the slave Linux answers
                        // ENOTTY and delivers nothing (oracle `ptyisig` line
                        // `tiocsig_delivered_sigint` from the slave is false).
                        if !role.is_master {
                            return Ok(DispatchOutcome::errno(LINUX_ENOTTY));
                        }
                        let mut buf = [0u8; 4];
                        match cx.memory.read_bytes(arg, 4) {
                            Ok(b) => buf.copy_from_slice(&b),
                            Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                        }
                        let signum = i32::from_le_bytes(buf);
                        if signum <= 0 || signum > 64 {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                        let session = cx.kernel.task().session();
                        match crate::kernel::tty::session(crate::kernel::tty::TtyKey::Pty(role.index)) {
                            Some(s) if s == session => {
                                crate::kernel::tty::route_foreground_signal_to_tty(
                                    crate::kernel::tty::TtyKey::Pty(role.index),
                                    signum,
                                );
                                DispatchOutcome::Returned { value: 0 }
                            }
                            _ => {
                                if this.pty_is_controlling(role.index)
                                    && cx.kernel.kernel().tty_session(cx.kernel).is_ok_and(|s| s == session)
                                {
                                    crate::kernel::tty::route_foreground_signal_to_tty(
                                        crate::kernel::tty::TtyKey::Launch,
                                        signum,
                                    );
                                    DispatchOutcome::Returned { value: 0 }
                                } else {
                                    DispatchOutcome::errno(LINUX_ENOTTY)
                                }
                            }
                        }
                    }
                    LINUX_FIONREAD => {
                        // A BSD pts supports FIONREAD/TIOCINQ on its input queue;
                        // forward to the live macOS pty fd. Without this arm a pty
                        // fd hits the catch-all below and returns ENOTTY, diverging
                        // from Linux (which reports the pending byte count).
                        let mut n: libc::c_int = 0;
                        // SAFETY: host_fd is our live pty fd; &mut n is valid stack storage.
                        let rc = unsafe { libc::ioctl(host_fd, libc::FIONREAD, &mut n) };
                        if rc < 0 {
                            DispatchOutcome::errno(crate::host_to_linux_errno(get_last_error()))
                        } else {
                            write_packed(&mut *cx.memory, arg, &(n as i32).to_le_bytes())
                        }
                    }
                    LINUX_FIONBIO => {
                        // os.set_blocking(master, False) issues FIONBIO on a pty
                        // master. Linux returns 0 and toggles O_NONBLOCK on the open
                        // description; without this arm the pty fd hit the catch-all
                        // below and returned ENOTTY. Mirror the generic FIONBIO
                        // handler: toggle Linux-visible O_NONBLOCK on the open
                        // description while keeping the host fd non-blocking so
                        // a later blocking-mode read still parks via WaitOnFds.
                        let Ok(bytes) = cx.memory.read_bytes(arg, 4) else {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        };
                        let enable =
                            i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) != 0;
                        if let Some(open_file) = this.open_file(fd.0) {
                            let common = open_file.description.common();
                            let mut status_flags = common.status_flags();
                            if enable {
                                status_flags |= LINUX_O_NONBLOCK;
                            } else {
                                status_flags &= !LINUX_O_NONBLOCK;
                            }
                            common.set_status_flags(status_flags);
                        }
                        crate::dispatch::net::set_host_nonblocking(host_fd);
                        DispatchOutcome::Returned { value: 0 }
                    }
                    // ── Line-discipline control (tcdrain/tcflush/tcflow/tcsendbreak) ──
                    // glibc maps the POSIX tc* helpers onto these ioctls. `arg` here
                    // is a small integer selector (NOT a guest pointer), so it is
                    // consumed directly. Darwin has native tcdrain/tcflush/tcflow/
                    // tcsendbreak; we translate the Linux queue/action selectors to
                    // the Darwin ones (they differ numerically) inside host_tty.
                    LINUX_TCSBRK => {
                        // tcdrain → TCSBRK(arg!=0); tcsendbreak(dur==0) → TCSBRK(0).
                        // arg==0 sends a break; arg!=0 drains the output queue.
                        let res = if arg == 0 {
                            crate::host_tty::with_sigttou_blocked(block_ttou, || {
                                crate::host_tty::host_tty_tcsendbreak(host_fd, 0)
                            })
                        } else {
                            crate::host_tty::with_sigttou_blocked(block_ttou, || {
                                crate::host_tty::host_tty_tcdrain(host_fd)
                            })
                        };
                        match res {
                            Ok(()) => DispatchOutcome::Returned { value: 0 },
                            Err(e) => DispatchOutcome::errno(
                                crate::host_to_linux_errno(e),
                            ),
                        }
                    }
                    LINUX_TCSBRKP => {
                        // tcsendbreak(duration!=0) → TCSBRKP(duration). arg is the
                        // duration in deciseconds (Linux semantics); pass through.
                        match crate::host_tty::with_sigttou_blocked(block_ttou, || {
                            crate::host_tty::host_tty_tcsendbreak(host_fd, arg as i32)
                        }) {
                            Ok(()) => DispatchOutcome::Returned { value: 0 },
                            Err(e) => DispatchOutcome::errno(
                                crate::host_to_linux_errno(e),
                            ),
                        }
                    }
                    LINUX_TCFLSH => {
                        // tcflush → TCFLSH(queue). host_tty_tcflush validates the
                        // Linux selector and returns EINVAL for out-of-range values
                        // (mirroring Linux's TCFLSH validation).
                        match crate::host_tty::host_tty_tcflush(host_fd, arg as i64) {
                            Ok(()) => DispatchOutcome::Returned { value: 0 },
                            Err(e) => DispatchOutcome::errno(
                                crate::host_to_linux_errno(e),
                            ),
                        }
                    }
                    LINUX_TCXONC => {
                        // tcflow → TCXONC(action). host_tty_tcflow validates the
                        // Linux action selector and returns EINVAL for out-of-range
                        // values (mirroring Linux's TCXONC validation).
                        match crate::host_tty::with_sigttou_blocked(block_ttou, || {
                            crate::host_tty::host_tty_tcflow(host_fd, arg as i64)
                        }) {
                            Ok(()) => DispatchOutcome::Returned { value: 0 },
                            Err(e) => DispatchOutcome::errno(
                                crate::host_to_linux_errno(e),
                            ),
                        }
                    }
                    _ => {
                        cx.reporter
                            .record(CompatEvent::unhandled_ioctl(fd.0, ioctl_request, arg));
                        DispatchOutcome::errno(LINUX_ENOTTY)
                    }
                });
            }

            // ── nsfs NS_GET_* ioctls (ioctl_ns(2)) ──────────────────────────────────
            // When `fd` is an nsfs fd (opened from /proc/<pid>/ns/<type>), the
            // NS_GET_* ioctls introspect the namespace. carrick models exactly
            // ONE initial namespace per type, so the answers are synthetic but
            // stable. Gated on the fd being an ns-link SyntheticFile so a plain
            // file/tty fd still falls through to the tty/default arms below.
            if let Some(ns_type) = this.fd_ns_link_type(fd.0) {
                return Ok(match ioctl_request {
                    // The CLONE_NEW* flag for this link's type, as the RETURN
                    // value (not written to *arg).
                    LINUX_NS_GET_NSTYPE => match ns_type_clone_flag(&ns_type) {
                        Some(flag) => DispatchOutcome::returned_u64_or_errno(flag),
                        None => DispatchOutcome::errno(LINUX_EINVAL),
                    },
                    // The owning user namespace's uid. The initial user ns is
                    // owned by root → 0. EINVAL on a non-user-ns fd (the kernel
                    // only answers this for a user namespace).
                    LINUX_NS_GET_OWNER_UID => {
                        if ns_type == "user" {
                            write_packed(&mut *cx.memory, arg, &0u32.to_le_bytes())
                        } else {
                            DispatchOutcome::errno(LINUX_EINVAL)
                        }
                    }
                    // Only hierarchical namespaces answer NS_GET_PARENT. The
                    // initial user/pid namespaces have no accessible parent
                    // here (EPERM); non-hierarchical namespaces reject the
                    // request with EINVAL.
                    LINUX_NS_GET_PARENT if ns_type == "user" || ns_type == "pid" => {
                        DispatchOutcome::errno(LINUX_EPERM)
                    }
                    LINUX_NS_GET_PARENT => DispatchOutcome::errno(LINUX_EINVAL),
                    // A namespace's owning user namespace is exposed for
                    // non-user namespaces. A user namespace fd itself has no
                    // "owning user ns" to return in this model; Docker's oracle
                    // reports EPERM for that shape (ioctl_ns04).
                    LINUX_NS_GET_USERNS if ns_type == "user" => {
                        DispatchOutcome::errno(LINUX_EPERM)
                    }
                    LINUX_NS_GET_USERNS => this.install_proc_synthetic_bytes(
                        "/proc/self/ns/user",
                        Vec::new(),
                        LINUX_O_RDONLY | LINUX_O_CLOEXEC,
                        &mut None,
                    ),
                    _ => {
                        cx.reporter
                            .record(CompatEvent::unhandled_ioctl(fd.0, ioctl_request, arg));
                        DispatchOutcome::errno(LINUX_ENOTTY)
                    }
                });
            }

            // ── perf_event ioctls ───────────────────────────────────────────────────
            // PERF_EVENT_IOC_* drive the counter behind a perf event fd (see
            // `dispatch::perf`); unknown requests on a perf fd report unhandled
            // and answer ENOTTY like every other fd kind.
            if let Some(state) = this.perf_event_state(fd.0) {
                return Ok(this.perf_event_ioctl(cx, fd.0, &state, ioctl_request, arg));
            }

            Ok(match ioctl_request {
                LINUX_TIOCGWINSZ if fd_is_tty(&this.captured_file_table().read_open_files(), fd.0) => {
                    // Prefer the live host window size when stdin/stdout/stderr
                    // is a real macOS terminal; fall back to the 80x24 stub so
                    // headless invocations (CI, redirected pipes that we still
                    // synthesize a TTY for in tests) keep prior behaviour.
                    let winsize = if crate::host_tty::host_isatty(fd.0) {
                        crate::host_tty::get_host_winsize(fd.0)
                            .unwrap_or_else(LinuxWinsize::terminal_80x24)
                    } else {
                        LinuxWinsize::terminal_80x24()
                    };
                    write_kernel_struct(&mut *cx.memory, arg, &winsize)
                }
                LINUX_TIOCGWINSZ => DispatchOutcome::errno(LINUX_ENOTTY),
                LINUX_TCGETA => {
                    if !cx.memory.guest_range_is_writable(arg, LINUX_TERMIO_SIZE) {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                    if !fd_is_tty(&this.captured_file_table().read_open_files(), fd.0) {
                        DispatchOutcome::errno(LINUX_ENOTTY)
                    } else {
                        let termios = if crate::host_tty::host_isatty(fd.0) {
                            crate::host_tty::get_host_termios(fd.0)
                                .unwrap_or_else(LinuxTermios::default_cooked)
                        } else {
                            LinuxTermios::default_cooked()
                        };
                        write_linux_termio(&mut *cx.memory, arg, &termios)
                    }
                }
                LINUX_TCGETS | LINUX_TCGETS2 if fd_is_tty(&this.captured_file_table().read_open_files(), fd.0) => {
                    // Mirror the live host terminal modes when available so
                    // `less`, `vi`, and an interactive shell see the actual
                    // ICANON/ECHO state the user has configured.
                    let termios = if crate::host_tty::host_isatty(fd.0) {
                        crate::host_tty::get_host_termios(fd.0)
                            .unwrap_or_else(LinuxTermios::default_cooked)
                    } else {
                        LinuxTermios::default_cooked()
                    };
                    // TCGETS writes the 36-byte legacy `struct termios`
                    // (KernelAbi::ABI_SIZE). Writing the 44-byte termios2 there
                    // overran glibc's tcgetattr canary and crashed ls/dpkg.
                    // TCGETS2 — what glibc-aarch64 actually uses for tcgetattr/
                    // isatty — expects the full 44-byte `struct termios2`
                    // (the c_ispeed/c_ospeed tail). musl uses TCGETS, so a
                    // musl-only probe suite never exercised this path.
                    if ioctl_request == LINUX_TCGETS2 {
                        write_termios2(&mut *cx.memory, arg, &termios)
                    } else {
                        write_kernel_struct(&mut *cx.memory, arg, &termios)
                    }
                }
                LINUX_TCGETS | LINUX_TCGETS2 => DispatchOutcome::errno(LINUX_ENOTTY),
                LINUX_RNDGETENTCNT => {
                    if !fd_is_random_device(this, fd.0) {
                        DispatchOutcome::errno(LINUX_ENOTTY)
                    } else {
                        write_packed(&mut *cx.memory, arg, &256i32.to_le_bytes())
                    }
                }
                LINUX_FICLONE => {
                    let src_fd = match i32::try_from(arg) {
                        Ok(src_fd) => src_fd,
                        Err(_) => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                    };
                    if std::env::var_os("CARRICK_FICLONE_DEBUG").is_some() {
                        eprintln!(
                            "FICLONEDBG enter dst_fd={} src_fd={} dst_valid={} src_valid={} src_opath={} dst_opath={}",
                            fd.0,
                            src_fd,
                            this.fd_is_valid(fd.0),
                            this.fd_is_valid(src_fd),
                            this.fd_is_o_path(src_fd),
                            this.fd_is_o_path(fd.0)
                        );
                    }
                    // Both descriptors must carry a usable mode: an O_PATH fd
                    // on EITHER side, or a destination not open for writing
                    // (procfs files are read-only), is EBADF ahead of every
                    // type/filesystem rule — the oracle's matrix answers EBADF
                    // for all 34 such pairings.
                    if !this.fd_is_valid(src_fd) || this.fd_is_o_path(src_fd) {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    if this.fd_is_o_path(fd.0) {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    DispatchOutcome::errno(this.ficlone_errno(src_fd, fd.0))
                }
                LINUX_TCSETS
                | LINUX_TCSETSW
                | LINUX_TCSETSF
                | LINUX_TCSETS2
                | LINUX_TCSETSW2
                | LINUX_TCSETSF2
                    if fd_is_tty(&this.captured_file_table().read_open_files(), fd.0) =>
                {
                    // Read exactly what the guest provided: 36 bytes for the
                    // legacy TCSETS*, 44 for the termios2 variants. Reading more
                    // than the guest's buffer would EFAULT at a stack-page
                    // boundary. Then pad to the 44-byte zerocopy struct to parse.
                    let want = if matches!(
                        ioctl_request,
                        LINUX_TCSETS2 | LINUX_TCSETSW2 | LINUX_TCSETSF2
                    ) {
                        LINUX_TERMIOS2_SIZE
                    } else {
                        LINUX_TERMIOS_KERNEL_SIZE
                    };
                    match cx.memory.read_bytes(arg, want) {
                        Ok(bytes) => {
                            if crate::host_tty::host_isatty(fd.0) {
                                let mut padded = [0u8; core::mem::size_of::<LinuxTermios>()];
                                padded[..want].copy_from_slice(&bytes);
                                if let Ok(t) = LinuxTermios::read_from_bytes(&padded) {
                                    let _ = crate::host_tty::with_sigttou_blocked(block_ttou, || {
                                        crate::host_tty::set_host_termios_tracking(fd.0, &t)
                                    });
                                }
                            }
                            DispatchOutcome::Returned { value: 0 }
                        }
                        Err(_) => DispatchOutcome::errno(LINUX_EFAULT),
                    }
                }
                LINUX_TCSETS
                | LINUX_TCSETSW
                | LINUX_TCSETSF
                | LINUX_TCSETS2
                | LINUX_TCSETSW2
                | LINUX_TCSETSF2 => DispatchOutcome::errno(LINUX_ENOTTY),
                LINUX_TIOCSCTTY => match this.tty_ioctl_fd_kind(fd.0) {
                    Ok(TtyFdKind::Stdio)
                        if this.pty_table().lock().controlling().is_some() =>
                    {
                        match cx.kernel.kernel().tty_acquire(cx.kernel, arg != 0) {
                            Ok(()) => DispatchOutcome::Returned { value: 0 },
                            Err(_) => DispatchOutcome::errno(LINUX_EPERM),
                        }
                    }
                    Ok(TtyFdKind::Stdio) => DispatchOutcome::errno(LINUX_ENOTTY),
                    Ok(TtyFdKind::Other) => DispatchOutcome::errno(LINUX_ENOTTY),
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                LINUX_TIOCGPGRP => match this.tty_ioctl_fd_kind(fd.0) {
                    Ok(TtyFdKind::Stdio) => {
                        match cx.kernel.kernel().tty_foreground_process_group(cx.kernel) {
                            Ok(group) => match crate::namespace::pid::process_group_to_ns_for(
                                cx.kernel,
                                group,
                            )
                                .and_then(|group| i32::try_from(group).ok())
                            {
                                Some(group) => write_packed(&mut *cx.memory, arg, &group.to_le_bytes()),
                                None => DispatchOutcome::errno(LINUX_ESRCH),
                            },
                            Err(_) => DispatchOutcome::errno(LINUX_ENOTTY),
                        }
                    }
                    Ok(TtyFdKind::Other) => DispatchOutcome::errno(LINUX_ENOTTY),
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                LINUX_TIOCSPGRP => match this.tty_ioctl_fd_kind(fd.0) {
                    Ok(TtyFdKind::Stdio) => {
                        let mut buf = [0u8; 4];
                        match cx.memory.read_bytes(arg, 4) {
                            Ok(bytes) => buf.copy_from_slice(&bytes),
                            Err(_) => {
                                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                            }
                        }
                        let group = match resolve_tiocspgrp(cx.kernel, i32::from_le_bytes(buf)) {
                            Ok(group) => group,
                            Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                        };
                        match cx.kernel.kernel().tty_set_foreground_process_group(cx.kernel, group) {
                            Ok(()) => DispatchOutcome::Returned { value: 0 },
                            Err(crate::kernel::TtyControlError::NotControlling) => DispatchOutcome::errno(LINUX_ENOTTY),
                            Err(crate::kernel::TtyControlError::Permission) => DispatchOutcome::errno(LINUX_EPERM),
                        }
                    }
                    Ok(TtyFdKind::Other) => DispatchOutcome::errno(LINUX_ENOTTY),
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                LINUX_TIOCSIG => match this.tty_ioctl_fd_kind(fd.0) {
                    Ok(TtyFdKind::Stdio) => {
                        let mut buf = [0u8; 4];
                        match cx.memory.read_bytes(arg, 4) {
                            Ok(b) => buf.copy_from_slice(&b),
                            Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                        }
                        let signum = i32::from_le_bytes(buf);
                        if signum <= 0 || signum > 64 {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                        if cx.kernel.kernel().tty_session(cx.kernel).is_err() {
                            return Ok(DispatchOutcome::errno(LINUX_ENOTTY));
                        }
                        crate::kernel::tty::route_foreground_signal_to_tty(
                            crate::kernel::tty::TtyKey::Launch,
                            signum,
                        );
                        DispatchOutcome::Returned { value: 0 }
                    }
                    Ok(TtyFdKind::Other) => DispatchOutcome::errno(LINUX_ENOTTY),
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                LINUX_FIONREAD | LINUX_SIOCOUTQ => {
                    // Stdio, eventfd, timerfd, epoll, pipe writer, directory, regular file,
                    // synthetic file: writing 0 ("nothing pending") is benign. In-memory pipe
                    // reader gets the buffered byte count from the carrick pipe buffer; a host
                    // pipe (`pipe2(2)` backing) forwards the ioctl to the real host fd so the
                    // guest sees the kernel's actual queued-byte count.
                    let available: i32 = match this.open_file(fd.0).as_ref() {
                        Some(open_file) => match open_file.description.read().as_deref() {
                            Some(OpenDescription::InMemorySocket { socket, .. }) => {
                                if ioctl_request == LINUX_SIOCOUTQ {
                                    i32::try_from(socket.outq_bytes()).unwrap_or(i32::MAX)
                                } else {
                                    i32::try_from(socket.buffered_bytes()).unwrap_or(i32::MAX)
                                }
                            }
                            _ if ioctl_request == LINUX_SIOCOUTQ => {
                                return Ok(DispatchOutcome::errno(LINUX_ENOTTY));
                            }
                            // Linux answers FIONREAD on EITHER end of a pipe
                            // with the queued byte count (LTP `pipe12` asks the
                            // write end after filling the pipe).
                            Some(
                                OpenDescription::PipeReader { pipe, .. }
                                | OpenDescription::PipeWriter { pipe, .. },
                            ) => {
                                let len = pipe.buffered_bytes();
                                i32::try_from(len).unwrap_or(i32::MAX)
                            }
                            // FIONREAD on a pipe WRITE end reports the bytes
                            // currently buffered in the pipe (Linux). macOS
                            // FIONREAD on a write fd returns 0, so consult the
                            // paired read end's queued byte count instead — pipe12
                            // reads FIONREAD on fds[1] after filling the pipe.
                            Some(OpenDescription::HostPipe {
                                is_read_end: false,
                                pipe_id,
                                pty: None,
                                bidirectional: false,
                                ..
                            }) if *pipe_id != 0 => {
                                i32::try_from(this.host_pipe_read_end_buffered_bytes(*pipe_id))
                                    .unwrap_or(i32::MAX)
                            }
                            Some(
                                OpenDescription::HostPipe { host_fd, .. }
                                | OpenDescription::HostSocket { host_fd, .. },
                            ) => {
                                let mut n: libc::c_int = 0;
                                let rc =
                                    unsafe { libc::ioctl(host_fd.raw(), libc::FIONREAD, &mut n) };
                                if rc == 0 { n as i32 } else { 0 }
                            }
                            Some(OpenDescription::Inotify { state, .. }) => {
                                i32::try_from(state.queued_bytes()).unwrap_or(i32::MAX)
                            }
                            _ => 0,
                        },
                        // stdio fd (already validated above) or any other valid fd: 0.
                        None => {
                            if ioctl_request == LINUX_SIOCOUTQ {
                                return Ok(DispatchOutcome::errno(LINUX_ENOTTY));
                            }
                            0
                        }
                    };
                    write_packed(&mut *cx.memory, arg, &available.to_le_bytes())
                }
                LINUX_FIONBIO => {
                    let Ok(bytes) = cx.memory.read_bytes(arg, 4) else {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    };
                    let enable = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) != 0;
                    if let Some(open_file) = this.open_file(fd.0) {
                        let common = open_file.description.common();
                        let mut status_flags = common.status_flags();
                        if enable {
                            status_flags |= LINUX_O_NONBLOCK;
                        } else {
                            status_flags &= !LINUX_O_NONBLOCK;
                        }
                        common.set_status_flags(status_flags);
                        let host_fd = match open_file.description.read().as_deref() {
                            Some(
                                OpenDescription::HostPipe { host_fd, .. }
                                | OpenDescription::HostSocket { host_fd, .. }
                                | OpenDescription::HostFile { host_fd, .. },
                            ) => Some(host_fd.raw()),
                            _ => None,
                        };
                        if let Some(host_fd) = host_fd {
                            crate::dispatch::net::set_host_nonblocking(host_fd);
                        }
                    }
                    DispatchOutcome::Returned { value: 0 }
                }
                LINUX_TIOCNOTTY => match this.tty_ioctl_fd_kind(fd.0) {
                    Ok(TtyFdKind::Stdio) => match cx.kernel.kernel().tty_detach(cx.kernel) {
                        Ok(()) => DispatchOutcome::Returned { value: 0 },
                        Err(_) => DispatchOutcome::errno(LINUX_ENOTTY),
                    },
                    Ok(TtyFdKind::Other) => DispatchOutcome::errno(LINUX_ENOTTY),
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                LINUX_SIOCGIFNAME => match this.open_file(fd.0).as_ref() {
                    Some(open_file) => match open_file.description.read().as_deref() {
                        Some(OpenDescription::HostSocket { .. }) => {
                            let Ok(bytes) = cx.memory.read_bytes(arg + 16, 4) else {
                                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                            };
                            let ifindex =
                                i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                            if ifindex <= 0 {
                                DispatchOutcome::errno(LINUX_ENODEV)
                            } else if let Some(name) = cx
                                .kernel
                                .task()
                                .net_ns()
                                .view()
                                .links
                                .iter()
                                .find(|link| link.index == ifindex as u32)
                                .map(|link| link.name.clone())
                            {
                                let mut ifreq_name = [0u8; LINUX_IFNAMSIZ];
                                let len = name.len().min(ifreq_name.len().saturating_sub(1));
                                ifreq_name[..len].copy_from_slice(&name.as_bytes()[..len]);
                                write_packed(&mut *cx.memory, arg, &ifreq_name)
                            } else {
                                DispatchOutcome::errno(LINUX_ENODEV)
                            }
                        }
                        _ => DispatchOutcome::errno(LINUX_ENOTTY),
                    },
                    None => DispatchOutcome::errno(LINUX_ENOTTY),
                },
                LINUX_SIOCGIFINDEX => match this.open_file(fd.0).as_ref() {
                    Some(open_file) => match open_file.description.read().as_deref() {
                        Some(OpenDescription::HostSocket { .. }) => {
                            let Ok(bytes) = cx.memory.read_bytes(arg, 16) else {
                                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                            };
                            let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
                            if end == 0 {
                                DispatchOutcome::errno(LINUX_ENODEV)
                            } else {
                                let name = String::from_utf8_lossy(&bytes[..end]);
                                if let Some(ifindex) = cx
                                    .kernel
                                    .task()
                                    .net_ns()
                                    .view()
                                    .links
                                    .iter()
                                    .find(|link| link.name == name)
                                    .and_then(|link| i32::try_from(link.index).ok())
                                {
                                    write_packed(
                                        &mut *cx.memory,
                                        arg + LINUX_IFNAMSIZ as u64,
                                        &ifindex.to_le_bytes(),
                                    )
                                } else {
                                    DispatchOutcome::errno(LINUX_ENODEV)
                                }
                            }
                        }
                        _ => DispatchOutcome::errno(LINUX_ENOTTY),
                    },
                    None => DispatchOutcome::errno(LINUX_ENOTTY),
                },
                LINUX_SIOCATMARK => {
                    // In-zone TCP has an urgent cursor of its own; consulting
                    // host_socket_lookup would misclassify it as ENOTTY.
                    let at_mark = this.open_file(fd.0).map(|open_file| {
                        open_file.description().in_memory_tcp_at_mark()
                    });
                    match at_mark {
                        Some(crate::dispatch::fd_table::InMemoryTcpAtMark::WrongSocket) => {
                            DispatchOutcome::errno(LINUX_ENOTTY)
                        }
                        Some(crate::dispatch::fd_table::InMemoryTcpAtMark::AtMark(at_mark)) => {
                            if arg == 0 {
                                DispatchOutcome::errno(LINUX_EFAULT)
                            } else {
                                write_packed(
                                    &mut *cx.memory,
                                    arg,
                                    &(at_mark as i32).to_le_bytes(),
                                )
                            }
                        }
                        Some(crate::dispatch::fd_table::InMemoryTcpAtMark::NotInMemory) | None => {
                            match this.host_socket_lookup(fd.0) {
                                Ok(_) => {
                                    // SIOCATMARK reports whether the next read sits at the
                                    // out-of-band mark. It is a STREAM-only op: Linux returns
                                    // ENOTTY on a datagram socket (sockioctl01 "ATMARK on UDP"
                                    // resets the expected errno to ENOTTY). A NULL arg faults
                                    // (sockioctl01 "invalid option buffer"). carrick keeps no
                                    // OOB queue, so a valid stream socket reports atmark = 0
                                    // (man sockatmark: 0 ⇒ not at the mark), which is the true
                                    // state for any socket with no urgent data pending.
                                    if this.socket_guest_type(fd.0) != Some(LINUX_SOCK_STREAM) {
                                        DispatchOutcome::errno(LINUX_ENOTTY)
                                    } else if arg == 0 {
                                        DispatchOutcome::errno(LINUX_EFAULT)
                                    } else {
                                        write_packed(&mut *cx.memory, arg, &0i32.to_le_bytes())
                                    }
                                }
                                // A non-socket fd (e.g. a FIFO): Linux's vfs_ioctl returns
                                // ENOTTY for SIOCATMARK, not ENOTSOCK (sockioctl01 "not a
                                // socket" resets the expected errno to ENOTTY).
                                Err(_) => DispatchOutcome::errno(LINUX_ENOTTY),
                            }
                        }
                    }
                },
                LINUX_SIOCGIFCONF => match this.host_socket_lookup(fd.0) {
                    Ok(_) => {
                        // struct ifconf: ifc_len (off 0, i32), ifc_buf (off 8, ptr).
                        if arg == 0 {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                        let conf: LinuxIfconf = match cx.memory.read_struct(arg) {
                            Ok(c) => c,
                            Err(_) => return Ok(DispatchOutcome::errno(LINUX_EFAULT)),
                        };
                        let ifc_len = conf.ifc_len.max(0) as usize;
                        let ifc_buf = conf.ifc_buf;
                        let net_ns = cx.kernel.task().net_ns();
                        let network = net_ns.view();
                        let ifaces = inet4_interfaces_from_model(&network);
                        // Linux convention: a NULL ifc_buf is a size query that
                        // reports the bytes required without writing entries.
                        let cap = if ifc_buf == 0 {
                            usize::MAX
                        } else {
                            ifc_len / std::mem::size_of::<LinuxIfreq>()
                        };
                        let mut written = 0usize;
                        let mut blob: Vec<u8> = Vec::new();
                        for iface in ifaces.iter() {
                            if written >= cap {
                                break;
                            }
                            let req = linux_ifreq_inet4(&iface.name, iface.addr_be);
                            blob.extend_from_slice(req.as_bytes());
                            written += 1;
                        }
                        if ifc_buf != 0
                            && !blob.is_empty()
                            && cx.memory.write_bytes(ifc_buf, &blob).is_err()
                        {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                        let new_len = (written * std::mem::size_of::<LinuxIfreq>()) as i32;
                        write_packed(&mut *cx.memory, arg, &new_len.to_le_bytes())
                    }
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                LINUX_SIOCGIFFLAGS
                | LINUX_SIOCGIFADDR
                | LINUX_SIOCGIFBRDADDR
                | LINUX_SIOCGIFNETMASK
                | LINUX_SIOCGIFMTU => match this.host_socket_lookup(fd.0) {
                    Ok(_) => {
                        // ifr_name occupies the first IFNAMSIZ bytes; a NULL arg
                        // faults (sockioctl01 "SIOCGIFFLAGS with invalid ifr").
                        if arg == 0 {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                        let Ok(name_bytes) = cx.memory.read_bytes(arg, LINUX_IFNAMSIZ) else {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        };
                        let end = name_bytes
                            .iter()
                            .position(|b| *b == 0)
                            .unwrap_or(name_bytes.len());
                        let name = String::from_utf8_lossy(&name_bytes[..end]).into_owned();
                        let net_ns = cx.kernel.task().net_ns();
                        let network = net_ns.view();
                        let ifaces = inet4_interfaces_from_model(&network);
                        let Some(iface) = ifaces.iter().find(|i| i.name == name) else {
                            return Ok(DispatchOutcome::errno(LINUX_ENODEV));
                        };
                        match ioctl_request {
                            LINUX_SIOCGIFFLAGS => {
                                // ifr_flags is a `short` at offset IFNAMSIZ.
                                write_packed(
                                    &mut *cx.memory,
                                    arg + LINUX_IFNAMSIZ as u64,
                                    &iface.flags_linux.to_le_bytes(),
                                )
                            }
                            LINUX_SIOCGIFADDR | LINUX_SIOCGIFNETMASK | LINUX_SIOCGIFBRDADDR => {
                                // ifr_addr (sockaddr_in) at offset IFNAMSIZ.
                                let mut sa = [0u8; 16];
                                sa[0..2].copy_from_slice(&(LINUX_AF_INET as u16).to_ne_bytes());
                                // Address: the interface IPv4 for SIOCGIFADDR; a
                                // /32 mask / broadcast best-effort for the others.
                                if ioctl_request == LINUX_SIOCGIFNETMASK {
                                    sa[4..8].copy_from_slice(&[255, 255, 255, 255]);
                                } else {
                                    sa[4..8].copy_from_slice(&iface.addr_be);
                                }
                                write_packed(&mut *cx.memory, arg + LINUX_IFNAMSIZ as u64, &sa)
                            }
                            // SIOCGIFMTU: ifr_mtu (i32) at offset IFNAMSIZ.
                            _ => write_packed(
                                &mut *cx.memory,
                                arg + LINUX_IFNAMSIZ as u64,
                                &iface.mtu.to_le_bytes(),
                            ),
                        }
                    }
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                LINUX_SIOCSIFFLAGS => match this.host_socket_lookup(fd.0) {
                    Ok(_) => {
                        // Setting interface flags needs CAP_NET_ADMIN; a NULL arg
                        // faults first (sockioctl01 "SIOCSIFFLAGS with invalid
                        // ifr"). carrick never mutates host interface state.
                        if arg == 0 {
                            DispatchOutcome::errno(LINUX_EFAULT)
                        } else {
                            DispatchOutcome::errno(LINUX_EPERM)
                        }
                    }
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                LINUX_TIOCGSID => match this.tty_ioctl_fd_kind(fd.0) {
                    Ok(TtyFdKind::Stdio) => {
                        match cx.kernel.kernel().tty_session(cx.kernel) {
                            Ok(session) => match crate::namespace::pid::session_to_ns_for(
                                cx.kernel,
                                session,
                            )
                                .and_then(|session| i32::try_from(session).ok())
                            {
                                Some(session) => write_packed(&mut *cx.memory, arg, &session.to_le_bytes()),
                                None => DispatchOutcome::errno(LINUX_ESRCH),
                            },
                            Err(_) => DispatchOutcome::errno(LINUX_ENOTTY),
                        }
                    }
                    Ok(TtyFdKind::Other) => DispatchOutcome::errno(LINUX_ENOTTY),
                    Err(errno) => DispatchOutcome::errno(errno),
                },
                _ => {
                    cx.reporter
                        .record(CompatEvent::unhandled_ioctl(fd.0, ioctl_request, arg));
                    DispatchOutcome::errno(LINUX_ENOTTY)
                }
            })

        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::net::unix_pure::{LinuxUcred, PureSocketInner};
    use crate::dispatch::{
        CompatReporter, LinearMemory, OpenDescription, OpenDescriptionBase, OpenFile, SyscallArgs,
        SyscallDispatcher, SyscallRequest,
    };
    use crate::linux_abi::{LINUX_AF_INET, LINUX_IPPROTO_TCP, LINUX_O_RDWR, LINUX_SOCK_STREAM};
    use parking_lot::RwLock;
    use std::sync::Arc;

    #[test]
    fn pidfd_get_info_reports_exit_after_pidfd_receipt_survives() {
        let mut dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().unwrap();
        let reporter = CompatReporter::default();
        let mut mux = crate::event_mux::make_event_multiplexer().expect("pidfd multiplexer");
        mux.register_user(0).expect("register pidfd user wake");
        let watch = Arc::new(PidfdWatch::new(mux));
        let status = crate::kernel::LinuxWaitStatus::from_wait_encoding(100 << 8);
        watch.publish_exit(status);

        let fd = dispatcher
            .install_fd_at_or_above(
                3,
                OpenFile::from_open_description_with_status_flags(
                    Arc::new(RwLock::new(OpenDescription::Pidfd {
                        base: OpenDescriptionBase::new(0),
                        target: PidfdTarget::Hvpatch(context.task().key()),
                        kqueue: Arc::clone(&watch),
                    })),
                    LINUX_O_RDWR,
                    0,
                ),
            )
            .unwrap();

        let base = 0x3000u64;
        let mut info = carrick_abi::LinuxPidfdInfo::default();
        info.mask = carrick_abi::LINUX_PIDFD_INFO_EXIT;
        let mut memory = LinearMemory::new(base, vec![0u8; 0x1000]);
        memory.write_bytes(base, info.as_bytes()).unwrap();

        // The current LTP fallback header encodes its 72-byte pidfd_info,
        // while newer headers encode 88. The kernel accepts compatible sizes.
        let request = 0xc048_ff0b;
        let out = dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(29, SyscallArgs::from([fd as u64, request, base, 0, 0, 0])),
                &mut memory,
                &reporter,
            )
            .unwrap();
        assert_eq!(out, DispatchOutcome::Returned { value: 0 });
        let result: carrick_abi::LinuxPidfdInfo = read_kernel_struct(&memory, base).unwrap();
        let result_mask = result.mask;
        let result_exit_code = result.exit_code;
        assert_eq!(result_mask, carrick_abi::LINUX_PIDFD_INFO_EXIT);
        assert_eq!(result_exit_code, 100 << 8);
    }

    #[test]
    fn pidfd_get_info_recognizes_compatible_struct_sizes() {
        assert!(is_pidfd_get_info(0xc040_ff0b));
        assert!(is_pidfd_get_info(0xc048_ff0b));
        assert!(is_pidfd_get_info(carrick_abi::LINUX_PIDFD_GET_INFO));
        assert!(!is_pidfd_get_info(0xc058_ff0a));
    }

    #[test]
    fn inet_in_memory_socket_fionread_and_siocoutq() {
        let mut dispatcher = SyscallDispatcher::new();
        let context = dispatcher.capture_one_task_context().unwrap();
        let reporter = CompatReporter::default();

        let (s1, s2) = PureSocketInner::pair_with_family(
            LINUX_AF_INET,
            LINUX_SOCK_STREAM,
            LINUX_IPPROTO_TCP,
            LinuxUcred::default(),
            LinuxUcred::default(),
        );

        let fd1 = dispatcher
            .install_fd_at_or_above(
                3,
                OpenFile::from_open_description_with_status_flags(
                    Arc::new(RwLock::new(OpenDescription::InMemorySocket {
                        base: OpenDescriptionBase::new(0),
                        socket: Arc::clone(&s1),
                    })),
                    LINUX_O_RDWR,
                    0,
                ),
            )
            .unwrap();

        let fd2 = dispatcher
            .install_fd_at_or_above(
                4,
                OpenFile::from_open_description_with_status_flags(
                    Arc::new(RwLock::new(OpenDescription::InMemorySocket {
                        base: OpenDescriptionBase::new(0),
                        socket: Arc::clone(&s2),
                    })),
                    LINUX_O_RDWR,
                    0,
                ),
            )
            .unwrap();

        let base = 0x3000u64;
        let mut memory = LinearMemory::new(base, vec![0u8; 0x1000]);

        // FIONREAD on fd2 initially returns 0
        let out = dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(
                    29, // ioctl
                    SyscallArgs::from([fd2 as u64, LINUX_FIONREAD, base, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap();
        assert_eq!(out, DispatchOutcome::Returned { value: 0 });
        let bytes = memory.read_bytes(base, 4).unwrap();
        assert_eq!(i32::from_le_bytes(bytes.try_into().unwrap()), 0);

        // s1 sends 15 bytes to s2
        s1.send_stream(b"hello in-memory", Vec::new()).unwrap();

        // FIONREAD on fd2 (receiver) should report 15 bytes
        let out = dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([fd2 as u64, LINUX_FIONREAD, base, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap();
        assert_eq!(out, DispatchOutcome::Returned { value: 0 });
        let bytes = memory.read_bytes(base, 4).unwrap();
        assert_eq!(
            i32::from_le_bytes(bytes.try_into().unwrap()),
            15,
            "FIONREAD on receiver must report queued bytes"
        );

        // SIOCOUTQ on fd1 (sender) should report 15 unsent/unacknowledged bytes
        let out = dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([fd1 as u64, LINUX_SIOCOUTQ, base, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap();
        assert_eq!(out, DispatchOutcome::Returned { value: 0 });
        let bytes = memory.read_bytes(base, 4).unwrap();
        assert_eq!(
            i32::from_le_bytes(bytes.try_into().unwrap()),
            15,
            "SIOCOUTQ on sender must report bytes waiting in peer buffer"
        );

        // SIOCOUTQ on fd2 (receiver) should report 0 bytes
        let out = dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([fd2 as u64, LINUX_SIOCOUTQ, base, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap();
        assert_eq!(out, DispatchOutcome::Returned { value: 0 });
        let bytes = memory.read_bytes(base, 4).unwrap();
        assert_eq!(
            i32::from_le_bytes(bytes.try_into().unwrap()),
            0,
            "SIOCOUTQ on receiver must be 0"
        );

        // Receiver reads 5 bytes
        let mut recv_buf = [0u8; 5];
        let (n, _rights) = s2.recv_stream(&mut recv_buf, 0).unwrap();
        assert_eq!(n, 5);

        // FIONREAD on fd2 should now report 10 bytes
        let out = dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([fd2 as u64, LINUX_FIONREAD, base, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap();
        assert_eq!(out, DispatchOutcome::Returned { value: 0 });
        let bytes = memory.read_bytes(base, 4).unwrap();
        assert_eq!(
            i32::from_le_bytes(bytes.try_into().unwrap()),
            10,
            "FIONREAD after partial read must report remaining bytes"
        );

        // SIOCOUTQ on fd1 should now report 10 bytes
        let out = dispatcher
            .dispatch(
                &context,
                SyscallRequest::new(
                    29,
                    SyscallArgs::from([fd1 as u64, LINUX_SIOCOUTQ, base, 0, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap();
        assert_eq!(out, DispatchOutcome::Returned { value: 0 });
        let bytes = memory.read_bytes(base, 4).unwrap();
        assert_eq!(
            i32::from_le_bytes(bytes.try_into().unwrap()),
            10,
            "SIOCOUTQ after partial read must report remaining bytes"
        );
    }
}
