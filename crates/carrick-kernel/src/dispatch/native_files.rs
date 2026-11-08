//! Carrier half of the native host-file venue (#894).
//!
//! A ring-owned (native) process has no host task and no host fd table. Its
//! descriptors live in its ring namespace; a host-backed descriptor there is
//! an `IpcBacking::Host` token naming one host resource. When the ring stages
//! a [`carrick_core_abi::host_file`] record, the carrier pins the exact
//! description the caller's table names, serves the operation on its host
//! resource through the same code the dispatcher uses for that resource, and
//! writes the reply in place. Nothing here owns a descriptor number.
//!
//! Writes also serve inherited host-file descriptions through their pinned
//! physical backing, including a parent's redirected stdout after host close.
//! Resources outside the venue's operation set remain counted ENOSYS.
use std::sync::Arc;

use carrick_abi::{LINUX_AT_FDCWD, LinuxOpenFlags};
use carrick_core_abi::host_file::{AccessContext, HostFileHeader, HostFileOp, HostFileRequestView};
use carrick_el1_abi::ipc::fd;
use zerocopy::IntoBytes;

use super::resources::NativeFsAuthority;
use super::{DispatchOutcome, SyscallDispatcher};
use crate::el1_ipc::{HostIpc, HostResource, InstallHostDescriptionError, PinnedHostResourceError};
use crate::kernel::objects::ImplicitHostStdio;

const _: () = assert!(
    core::mem::size_of::<carrick_abi::LinuxStat>()
        == carrick_personality_linux::native_host_file::LINUX_STAT_BYTES
);
const _: () = assert!(
    core::mem::size_of::<carrick_abi::LinuxStatx>()
        == carrick_personality_linux::native_host_file::LINUX_STATX_BYTES
);

/// The carrier refused a staged record; the ring answers counted ENOSYS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHostFileRefusal;

/// A served record. A private-mapping record also hands the carrier the
/// retained byte source, which it must register for the caller's MM before
/// acknowledging (the reply names it).
#[derive(Default)]
pub struct NativeHostFileServed {
    pub retained_source: Option<Arc<dyn carrick_hal::fork_stock::HostBackingRetention>>,
}

fn native_descriptor_exec_source_in(
    owner: &Arc<HostIpc>,
    table: [u64; 3],
    fd: i32,
) -> Result<super::executable_authority::ExecSource, carrick_abi::LinuxErrno> {
    if fd < 0 {
        return Err(carrick_abi::LINUX_EBADF);
    }
    let table = fd::TableId::from_raw(fd::RawTableId {
        authority: table[0],
        index: table[1],
        generation: table[2],
    });
    let source = owner.with_pinned_host_resource(table, fd::Fd(fd), |resource| {
        let file = resource.downcast_ref::<NativeOpenFile>()?;
        Some(match file.description.retained_exec_source() {
            Some(source) => Ok(source),
            None => super::executable_authority::ExecSource::from_open_description(Arc::clone(
                &file.description,
            ))
            .map_err(|error| match error.raw_os_error() {
                Some(libc::EBADF) => carrick_abi::LINUX_EBADF,
                Some(libc::EACCES) => carrick_abi::LINUX_EACCES,
                _ => carrick_abi::LINUX_EIO,
            }),
        })
    });
    match source {
        Ok(Some(source)) => source,
        Ok(None) => Err(carrick_abi::LINUX_ENOSYS),
        Err(PinnedHostResourceError::BadFd) => Err(carrick_abi::LINUX_EBADF),
        Err(PinnedHostResourceError::InZone | PinnedHostResourceError::Unavailable) => {
            Err(carrick_abi::LINUX_ENOSYS)
        }
    }
}

/// A host description the venue opened for a native process: the host
/// resource behind its `IpcBacking::Host` token, dropped when the ring
/// releases the last descriptor naming it.
pub struct NativeOpenFile {
    description: Arc<crate::kernel::FileDescription>,
}

impl NativeOpenFile {
    /// The native descriptor is a functional reference to the description,
    /// exactly as a host fd slot is: close effects and mapping rules follow.
    fn new(description: Arc<crate::kernel::FileDescription>) -> Self {
        description.retain_fd_ref();
        Self { description }
    }
}

impl Drop for NativeOpenFile {
    fn drop(&mut self) {
        // The ring released the last descriptor naming this description.
        self.description.release_fd_ref();
    }
}

/// Where one venue `openat` installs its descriptor: the lowest free number
/// of the caller's own ring table, and nowhere else. The open itself is the
/// dispatcher's one implementation ([`super::fs::OpenSink::Native`]).
pub(in crate::dispatch) struct NativeOpenSink {
    owner: Arc<HostIpc>,
    table: fd::TableId,
    flags: u64,
    refused: bool,
}

impl NativeOpenSink {
    /// The open needs a host task this caller does not have: the ring
    /// answers a counted ENOSYS, never a guessed errno.
    pub(in crate::dispatch) fn refuse(&mut self) -> DispatchOutcome {
        self.refused = true;
        DispatchOutcome::errno(carrick_abi::LINUX_ENOSYS)
    }

    pub(in crate::dispatch) fn install(
        &mut self,
        fs: &super::FsView<'_>,
        file: crate::dispatch::fd_table::OpenFile,
    ) -> Result<fd::Fd, carrick_abi::LinuxErrno> {
        let open_flags = LinuxOpenFlags::from_bits_retain(self.flags);
        // A mount-served open meets O_DIRECTORY only after the host task's
        // install, which then withdraws its fd. A ring descriptor, visible to
        // the caller's other threads at once, is checked before it exists.
        if open_flags.contains(LinuxOpenFlags::DIRECTORY) {
            let record = fs.description_stat_record(&file.description, None)?;
            if record.mode & carrick_abi::LINUX_S_IFMT != carrick_abi::LINUX_S_IFDIR {
                return Err(carrick_abi::LINUX_ENOTDIR);
            }
        }
        let access = if open_flags.contains(LinuxOpenFlags::PATH) {
            fd::AccessMode::Path
        } else {
            match self.flags & carrick_abi::LINUX_O_ACCMODE {
                carrick_abi::LINUX_O_RDONLY => fd::AccessMode::ReadOnly,
                carrick_abi::LINUX_O_WRONLY => fd::AccessMode::WriteOnly,
                // The open validated the access mode first (EINVAL).
                _ => fd::AccessMode::ReadWrite,
            }
        };
        let status = super::fs::reportable_status_flags(file.description.common().status_flags());
        let status = fd::StatusFlags {
            append: open_flags.contains(LinuxOpenFlags::APPEND),
            nonblock: open_flags.contains(LinuxOpenFlags::NONBLOCK),
            asynchronous: false,
            direct: false,
            noatime: false,
            dsync: false,
            sync: false,
            immutable: status
                & !(carrick_abi::LINUX_O_ACCMODE
                    | carrick_abi::LINUX_O_NONBLOCK
                    | carrick_abi::LINUX_O_APPEND
                    | LinuxOpenFlags::ASYNC.bits()),
        };
        match self.owner.install_host_description(
            self.table,
            Box::new(NativeOpenFile::new(Arc::clone(&file.description))),
            access,
            status,
            open_flags.contains(LinuxOpenFlags::CLOEXEC),
        ) {
            Ok(number) => Ok(number),
            Err(InstallHostDescriptionError::TooManyFiles) => Err(carrick_abi::LINUX_EMFILE),
            Err(InstallHostDescriptionError::FileTableFull) => Err(carrick_abi::LINUX_ENFILE),
            Err(InstallHostDescriptionError::NoMemory) => Err(carrick_abi::LINUX_ENOMEM),
            Err(InstallHostDescriptionError::Unavailable) => {
                self.refused = true;
                Err(carrick_abi::LINUX_ENOSYS)
            }
        }
    }
}

enum Served {
    Reply(i64, Vec<u8>),
    Source(
        Arc<dyn carrick_hal::fork_stock::HostBackingRetention>,
        carrick_core_abi::host_file::MapSourceReply,
    ),
    Refused,
}

impl Served {
    fn errno(errno: carrick_abi::LinuxErrno) -> Self {
        Self::Reply(errno.guest_retval(), Vec::new())
    }
    fn value(value: i64) -> Self {
        Self::Reply(value, Vec::new())
    }
}

fn outcome_result(outcome: DispatchOutcome) -> i64 {
    match outcome {
        DispatchOutcome::Returned { value } => value,
        DispatchOutcome::Errno { errno } => errno.guest_retval(),
        _ => carrick_abi::LINUX_EIO.guest_retval(),
    }
}

/// A ring task's chdir lookup: a `Newfstatat` whose reply area has room
/// past `struct stat` for a name ([`HostFileOp::Newfstatat`]). It runs the
/// host task's own chdir lookup ([`super::FsView::chdir_target`]: a
/// directory, searchable by the caller) under the caller's access context
/// and replies with the directory's `struct stat` followed by the cwd
/// spelling the ring then stores in the caller's row.
fn native_chdir_lookup(fs: &super::FsView<'_>, path: &str) -> Served {
    let target = match fs.chdir_target(path) {
        Ok(target) => target,
        Err(errno) => return Served::errno(errno),
    };
    let record = match fs.path_stat_record_for(None, LINUX_AT_FDCWD, &target, 0) {
        Ok(record) => record,
        Err(errno) => return Served::errno(errno),
    };
    let mut reply = native_stat_bytes(HostFileOp::Newfstatat, &record);
    reply.extend_from_slice(target.as_bytes());
    Served::Reply(0, reply)
}

impl SyscallDispatcher {
    /// The executable object behind a native process's descriptor `fd`, for
    /// `execveat(fd, "", AT_EMPTY_PATH)` (`fexecve`, #1530). The descriptor
    /// lives in the caller's ring table (`table`, the raw table id words its
    /// ring owner sealed into the exec request) and is pinned there now, as
    /// Linux resolves it for the in-progress call.
    ///
    /// Linux executes the open file, never its name, so this retains the
    /// description's own object exactly as the host lane's `/proc/self/fd/N`
    /// exec does (`HostExecFdSources`): its retained exec source, or the
    /// opened file itself (a duplicated host descriptor, or a memory file's
    /// shared bytes). A rename or replacement of the path after the open
    /// cannot change what runs.
    ///
    /// Served exactly or left unrouted: a closed descriptor is EBADF; an
    /// opened object that is not a regular file is EACCES, as Linux; an
    /// in-zone object or implicit stdio is ENOSYS.
    pub fn native_descriptor_exec_source(
        &self,
        table: [u64; 3],
        fd: i32,
    ) -> Result<super::executable_authority::ExecSource, carrick_abi::LinuxErrno> {
        let owner = self
            .kernel_binding
            .read()
            .kernel()
            .existing_ipc()
            .ok_or(carrick_abi::LINUX_ENOSYS)?;
        native_descriptor_exec_source_in(&owner, table, fd)
    }

    /// Serve one ring-staged host-file record in place for a native process
    /// of this run. A descriptor is resolved and pinned in the caller's own
    /// ring table now, as Linux resolves it for an in-progress call. A path
    /// resolves under the caller's own access context, which the ring task
    /// row owns and the record carries by value (credentials, umask, cwd and
    /// root); no host task, fd table, credential or cwd of this dispatcher's
    /// task is consulted, and nothing outlives the call.
    pub fn serve_native_host_file(
        &self,
        record: &mut [u8],
    ) -> Result<NativeHostFileServed, NativeHostFileRefusal> {
        let Some(owner) = self.kernel_binding.read().kernel().existing_ipc() else {
            return Err(NativeHostFileRefusal);
        };
        self.serve_native_host_file_in(&owner, record)
    }

    /// Serve a request whose authenticated member retains host-root resources.
    /// Descriptor allocation still belongs exclusively to the ring namespace.
    pub fn serve_host_root_file(
        &self,
        resources: &super::resources::HostRootResources,
        record: &mut [u8],
    ) -> Result<NativeHostFileServed, NativeHostFileRefusal> {
        let owner = self
            .kernel_binding
            .read()
            .kernel()
            .existing_ipc()
            .ok_or(NativeHostFileRefusal)?;
        let resources = resources.snapshot().map_err(|_| NativeHostFileRefusal)?;
        self.serve_native_host_file_with_authority(&owner, record, Some(resources.filesystem()))
    }

    /// The transient filesystem authority of one path crossing, built from
    /// the caller's access context. Fresh credential and fs-context objects:
    /// they share nothing with any host task and drop with the call.
    fn native_access_authority(&self, context: &AccessContext<'_>) -> Option<NativeFsAuthority> {
        let cwd = std::str::from_utf8(context.cwd).ok()?.to_owned();
        let root = match context.root {
            Some(root) => Some(std::str::from_utf8(root).ok()?.to_owned()),
            None => None,
        };
        let binding = self.kernel_binding.read();
        let ids = binding.kernel().object_ids();
        let id = context.ids;
        let mut credentials =
            crate::kernel::Credentials::from_values(crate::kernel::CredentialsValues {
                id: ids.credentials_id().ok()?,
                ruid: carrick_abi::NsUid::new(id.ruid),
                euid: carrick_abi::NsUid::new(id.euid),
                suid: carrick_abi::NsUid::new(id.suid),
                rgid: carrick_abi::NsGid::new(id.rgid),
                egid: carrick_abi::NsGid::new(id.egid),
                sgid: carrick_abi::NsGid::new(id.sgid),
                fsuid: carrick_abi::NsUid::new(id.fsuid),
                fsgid: carrick_abi::NsGid::new(id.fsgid),
                umask: context.umask & 0o777,
            });
        // Without `setgroups` the caller has the launch identity's groups,
        // which the host derives from `/etc/group` exactly as for the root
        // task. An installed list, even an empty one, is the complete set.
        if let Some(groups) = context.groups() {
            credentials.set_supplementary_groups(groups.map(carrick_abi::NsGid::new).collect());
        }
        let fs_context = crate::kernel::FsContext::new(ids.fs_context_id().ok()?);
        fs_context.set_cwd(cwd);
        fs_context.set_chroot_root(root);
        Some(NativeFsAuthority::new(
            Arc::new(credentials),
            Arc::new(fs_context),
        ))
    }

    fn serve_native_host_file_in(
        &self,
        owner: &Arc<HostIpc>,
        record: &mut [u8],
    ) -> Result<NativeHostFileServed, NativeHostFileRefusal> {
        self.serve_native_host_file_with_authority(owner, record, None)
    }

    fn serve_native_host_file_with_authority(
        &self,
        owner: &Arc<HostIpc>,
        record: &mut [u8],
        host_root: Option<&NativeFsAuthority>,
    ) -> Result<NativeHostFileServed, NativeHostFileRefusal> {
        let view = HostFileRequestView::parse(record).map_err(|_| NativeHostFileRefusal)?;
        let header = view.header();
        let table = fd::TableId::from_raw(fd::RawTableId {
            authority: header.table[0],
            index: header.table[1],
            generation: header.table[2],
        });
        let served = if header.op.resolves_path() {
            // Every path record leads with its caller's access context.
            let (authority, path) = if let Some(authority) = host_root {
                (authority.clone(), view.input())
            } else {
                let (context, path) =
                    AccessContext::decode(view.input()).ok_or(NativeHostFileRefusal)?;
                (
                    self.native_access_authority(&context)
                        .ok_or(NativeHostFileRefusal)?,
                    path,
                )
            };
            // Carrick's VFS names paths as UTF-8; any other byte string is
            // not served rather than altered.
            let path = std::str::from_utf8(path).map_err(|_| NativeHostFileRefusal)?;
            let capacity = view.output_capacity();
            if path.is_empty() {
                // The descriptor form of a path call (`statx(fd, "",
                // AT_EMPTY_PATH)`): it names the caller's descriptor, which
                // lives in its ring table, never a host fd table (#1503).
                self.serve_native_empty_path(owner, table, header, capacity)
            } else {
                super::resources::with_native_fs_scope(&authority, || {
                    self.serve_native_path(owner, table, header, path, capacity)
                })
                .ok_or(NativeHostFileRefusal)?
            }
        } else if header.op == HostFileOp::Poll {
            self.serve_native_poll(owner, table, header, view.input(), view.output_capacity())
        } else {
            match owner.with_pinned_host_resource(table, fd::Fd(header.fd), |resource| {
                self.serve_native_resource(header, resource, view.input(), view.output_capacity())
            }) {
                Ok(served) => served,
                // Closed after the ring staged the call: the descriptor is gone.
                Err(PinnedHostResourceError::BadFd) => Served::errno(carrick_abi::LINUX_EBADF),
                // Replaced by an in-zone object, or contended: never guess.
                Err(PinnedHostResourceError::InZone | PinnedHostResourceError::Unavailable) => {
                    Served::Refused
                }
            }
        };
        let (result, output, retained_source) = match served {
            Served::Reply(result, output) => (result, output, None),
            Served::Source(source, reply) => (0, reply.encode().to_vec(), Some(source)),
            Served::Refused => return Err(NativeHostFileRefusal),
        };
        view.reply(result, &output)
            .map_err(|_| NativeHostFileRefusal)?;
        Ok(NativeHostFileServed { retained_source })
    }

    /// A path call with an empty path. Only `statx(fd, "", AT_EMPTY_PATH)`
    /// is staged this way (the ring stages `newfstatat`'s descriptor form as
    /// [`HostFileOp::Fstat`], and an `AT_FDCWD` base as `"."`): it is the
    /// pinned descriptor's own stat, exactly as `fstat`. Any other empty
    /// path is refused (counted ENOSYS) rather than resolved: the dispatcher's
    /// empty-path lookup reads a host fd table a native process does not have.
    fn serve_native_empty_path(
        &self,
        owner: &Arc<HostIpc>,
        table: fd::TableId,
        header: HostFileHeader,
        capacity: usize,
    ) -> Served {
        let flags = u64::from(header.flags);
        if header.op != HostFileOp::Statx
            || flags & carrick_abi::LINUX_AT_EMPTY_PATH == 0
            || header.fd < 0
        {
            return Served::Refused;
        }
        if !super::format_stat::linux_statx_flags_are_supported(flags)
            || header.args[0] & carrick_abi::LINUX_STATX_RESERVED != 0
        {
            return Served::errno(carrick_abi::LINUX_EINVAL);
        }
        match owner.with_pinned_host_resource(table, fd::Fd(header.fd), |resource| {
            self.serve_native_resource(header, resource, &[], capacity)
        }) {
            Ok(served) => served,
            Err(PinnedHostResourceError::BadFd) => Served::errno(carrick_abi::LINUX_EBADF),
            Err(PinnedHostResourceError::InZone | PinnedHostResourceError::Unavailable) => {
                Served::Refused
            }
        }
    }

    /// A non-blocking readiness snapshot of a native `ppoll` set
    /// ([`HostFileOp::Poll`]). Each live entry is pinned in the caller's
    /// table now, as Linux resolves each descriptor during the scan, and
    /// observed through the same readiness the dispatcher reports for that
    /// resource to a host-served task (implicit stdio streams and venue-opened
    /// descriptions). An absent descriptor is `POLLNVAL`. An in-zone member,
    /// a contended table or a resource this venue does not observe refuses
    /// the whole set: a partial answer would misreport its ready count. The
    /// carrier never waits: an empty snapshot for a caller that would wait
    /// is refused, so the ring never reports a fake timeout (#1051 owns the
    /// blocking wait).
    ///
    /// Divergence from Linux: a zero-timeout scan that finds nothing ready
    /// while an unblocked signal is pending returns 0 here, where Linux
    /// returns EINTR. The carrier cannot see the caller's pending signals;
    /// the ring delivers the signal on return. #1051 owns poll's signal and
    /// EINTR semantics.
    fn serve_native_poll(
        &self,
        owner: &Arc<HostIpc>,
        table: fd::TableId,
        header: HostFileHeader,
        input: &[u8],
        capacity: usize,
    ) -> Served {
        use carrick_core_abi::host_file::{POLLFD_BYTES, PollWait};
        let may_wait = match PollWait::from_raw(header.args[0]) {
            Some(PollWait::Snapshot) => false,
            Some(PollWait::MayWait) => true,
            None => return Served::Refused,
        };
        if input.is_empty() || !input.len().is_multiple_of(POLLFD_BYTES) || capacity != input.len()
        {
            return Served::Refused;
        }
        let mut output = input.to_vec();
        let mut ready = 0i64;
        for entry in output.chunks_exact_mut(POLLFD_BYTES) {
            let fd = i32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
            let events = i16::from_le_bytes([entry[4], entry[5]]);
            let revents = if fd < 0 {
                0
            } else {
                match owner.with_pinned_host_resource(table, fd::Fd(fd), |resource| {
                    self.native_resource_poll_events(resource, events)
                }) {
                    Ok(Some(revents)) => {
                        revents
                            & (events
                                | carrick_abi::LINUX_POLLERR
                                | carrick_abi::LINUX_POLLHUP
                                | carrick_abi::LINUX_POLLNVAL)
                    }
                    Err(PinnedHostResourceError::BadFd) => carrick_abi::LINUX_POLLNVAL,
                    Ok(None)
                    | Err(PinnedHostResourceError::InZone | PinnedHostResourceError::Unavailable) =>
                    {
                        return Served::Refused;
                    }
                }
            };
            entry[6..8].copy_from_slice(&revents.to_le_bytes());
            ready += i64::from(revents != 0);
        }
        if ready == 0 && may_wait {
            return Served::Refused;
        }
        Served::Reply(ready, output)
    }

    /// Linux poll readiness of one pinned host resource, or `None` for a
    /// resource this venue does not observe.
    fn native_resource_poll_events(&self, resource: &HostResource, events: i16) -> Option<i16> {
        if let Some(stdio) = resource.downcast_ref::<ImplicitHostStdio>() {
            return Some(self.bare_stdio_poll_ready_events(stdio.fd.0, events));
        }
        if let Some(file) = resource.downcast_ref::<NativeOpenFile>() {
            return Some(self.description_poll_ready_events(&file.description, events));
        }
        None
    }

    fn serve_native_resource(
        &self,
        header: HostFileHeader,
        resource: &HostResource,
        input: &[u8],
        capacity: usize,
    ) -> Served {
        if let Some(stdio) = resource.downcast_ref::<ImplicitHostStdio>() {
            return self.serve_native_stdio(header, stdio.fd.0, input);
        }
        if let Some(file) = resource.downcast_ref::<NativeOpenFile>() {
            return self.serve_native_open_file(header, &file.description, input, capacity);
        }
        if let Some(file) = resource.downcast_ref::<crate::kernel::objects::IpcPhysicalHold>() {
            return match header.op {
                HostFileOp::MapPrivate => match file.retain_mapping() {
                    Some(reference) => self.native_map_reference(reference),
                    None => Served::Refused,
                },
                HostFileOp::Write => match file.retain_io() {
                    Some(lease) => {
                        self.serve_native_open_file(header, lease.description(), input, capacity)
                    }
                    None => Served::Refused,
                },
                _ => Served::Refused,
            };
        }
        Served::Refused
    }

    /// The run's own implicit stdio streams: the code the root's implicit
    /// stdio descriptors run.
    fn serve_native_stdio(&self, header: HostFileHeader, fd: i32, input: &[u8]) -> Served {
        match header.op {
            HostFileOp::Write => match fd {
                1 | 2 => Served::value(outcome_result(self.fs_view().write_stdio_sink(fd, input))),
                // Writing the run's stdin stream is not served yet.
                _ => Served::Refused,
            },
            HostFileOp::Fstat | HostFileOp::Statx => {
                let record = super::fs::implicit_stdio_stat_record(&self.fs.pty_table, fd);
                Served::Reply(0, native_stat_bytes(header.op, &record))
            }
            // lseek on an implicit stdio stream is a pipe/tty seek.
            HostFileOp::Lseek => Served::errno(carrick_abi::LINUX_ESPIPE),
            // Blocking host reads move to the owned carrier waiter (slice 3).
            _ => Served::Refused,
        }
    }

    fn serve_native_open_file(
        &self,
        header: HostFileHeader,
        description: &Arc<crate::kernel::FileDescription>,
        input: &[u8],
        capacity: usize,
    ) -> Served {
        match header.op {
            HostFileOp::Fstat | HostFileOp::Statx => {
                match self.fs_view().description_stat_record(description, None) {
                    Ok(record) => Served::Reply(0, native_stat_bytes(header.op, &record)),
                    Err(errno) => Served::errno(errno),
                }
            }
            HostFileOp::Read | HostFileOp::Pread | HostFileOp::Getdents64 => {
                self.native_read_into_record(header, description, capacity)
            }
            HostFileOp::Lseek => match self.fs_view().lseek_description(
                description,
                header.args[0] as i64,
                header.args[1],
                None,
            ) {
                Ok(Some(outcome)) => served_outcome(outcome, Vec::new()),
                Ok(None) => Served::errno(carrick_abi::LINUX_EBADF),
                Err(_) => Served::Refused,
            },
            // `args[0]`: the writer's own RLIMIT_FSIZE soft limit, as its
            // ring stamped it (unstamped, it reads as a finite 0).
            HostFileOp::Write => match self.fs_view().write_description_from_carrier(
                header.args[0],
                description,
                input,
            ) {
                Ok(super::fs::CarrierWritten::Done(outcome)) => served_outcome(outcome, Vec::new()),
                Ok(super::fs::CarrierWritten::NeedsTask) | Err(_) => Served::Refused,
            },
            HostFileOp::MapPrivate => self.native_map_source(description),
            HostFileOp::Openat
            | HostFileOp::Faccessat
            | HostFileOp::Newfstatat
            | HostFileOp::Poll => Served::Refused,
        }
    }

    fn serve_native_path(
        &self,
        owner: &Arc<HostIpc>,
        table: fd::TableId,
        header: HostFileHeader,
        path: &str,
        capacity: usize,
    ) -> Served {
        let fs = self.fs_view();
        match header.op {
            HostFileOp::Faccessat => {
                let (mode, flags) = (header.args[0], u64::from(header.flags));
                if carrick_abi::LinuxAccessMode::from_bits(mode).is_none()
                    || !super::format_stat::linux_access_flags_are_supported(flags)
                {
                    return Served::errno(carrick_abi::LINUX_EINVAL);
                }
                let resolved = match fs.resolve_at_path(LINUX_AT_FDCWD, path) {
                    Ok(resolved) => resolved,
                    Err(errno) => return Served::errno(errno),
                };
                let target = if flags & carrick_abi::LINUX_AT_SYMLINK_NOFOLLOW == 0 {
                    match fs.canonicalize_following(&resolved) {
                        Ok(target) => target,
                        Err(errno) => return Served::errno(errno),
                    }
                } else {
                    resolved
                };
                match fs.access_resolved_path(None, &target, mode, flags) {
                    DispatchOutcome::Errno { errno } if errno == carrick_abi::LINUX_ENOSYS => {
                        Served::Refused
                    }
                    outcome => Served::value(outcome_result(outcome)),
                }
            }
            HostFileOp::Newfstatat | HostFileOp::Statx => {
                let flags = u64::from(header.flags);
                let valid = if header.op == HostFileOp::Statx {
                    super::format_stat::linux_statx_flags_are_supported(flags)
                        && header.args[0] & carrick_abi::LINUX_STATX_RESERVED == 0
                } else {
                    flags
                        & !(carrick_abi::LINUX_AT_SYMLINK_NOFOLLOW
                            | carrick_abi::LINUX_AT_EMPTY_PATH
                            | carrick_abi::LINUX_AT_NO_AUTOMOUNT)
                        == 0
                };
                if !valid {
                    return Served::errno(carrick_abi::LINUX_EINVAL);
                }
                if header.op == HostFileOp::Newfstatat
                    && capacity > carrick_personality_linux::native_host_file::LINUX_STAT_BYTES
                {
                    return native_chdir_lookup(&fs, path);
                }
                match fs.path_stat_record_for(None, LINUX_AT_FDCWD, path, flags) {
                    Ok(record) => Served::Reply(0, native_stat_bytes(header.op, &record)),
                    // A caller-relative synthetic answer: unrouted.
                    Err(errno) if errno == carrick_abi::LINUX_ENOSYS => Served::Refused,
                    Err(errno) => Served::errno(errno),
                }
            }
            HostFileOp::Openat => {
                let flags = header.args[0];
                let mut native = NativeOpenSink {
                    owner: Arc::clone(owner),
                    table,
                    flags,
                    refused: false,
                };
                let reporter = crate::compat::CompatReporter::default();
                // The ring stages a cwd-relative or absolute path with
                // AT_FDCWD; the caller's cwd is the scope's.
                let opened = fs.open_with_sink(
                    &mut super::fs::OpenSink::Native(&mut native),
                    super::fs::OpenAtArgs {
                        dirfd: LINUX_AT_FDCWD,
                        path,
                        flags,
                        mode: header.args[1],
                    },
                    &reporter,
                );
                match opened {
                    _ if native.refused => Served::Refused,
                    Ok(outcome) => served_outcome(outcome, Vec::new()),
                    Err(super::DispatchError::Errno(errno)) => Served::errno(errno),
                    Err(_) => Served::Refused,
                }
            }
            _ => Served::Refused,
        }
    }

    /// Retain a carrier-opened regular file as a private-mapping byte source.
    /// A directory has no mmap operation (ENODEV, as Linux).
    fn native_map_source(&self, description: &Arc<crate::kernel::FileDescription>) -> Served {
        let Some(reference) =
            description.retain_mapping(crate::kernel::objects::MappingAdmission::Descriptor)
        else {
            return Served::errno(carrick_abi::LINUX_EBADF);
        };
        self.native_map_reference(reference)
    }

    fn native_map_reference(
        &self,
        reference: Arc<crate::kernel::objects::MappedFileReference>,
    ) -> Served {
        let description = reference.description();
        if description.common().status_flags() & carrick_abi::LINUX_O_PATH != 0 {
            return Served::errno(carrick_abi::LINUX_EBADF);
        }
        if description.common().status_flags() & carrick_abi::LINUX_O_ACCMODE
            == carrick_abi::LINUX_O_WRONLY
        {
            return Served::errno(carrick_abi::LINUX_EACCES);
        }
        let label = match description.inspect_kind(|open| match open {
            crate::dispatch::OpenDescription::File { path, .. } => Some(Some(path.clone())),
            crate::dispatch::OpenDescription::HostFile { metadata, .. } => {
                Some(Some(metadata.path.to_string_lossy().into_owned()))
            }
            crate::dispatch::OpenDescription::Directory { .. } => Some(None),
            _ => None,
        }) {
            Some(Some(Some(label))) => label,
            Some(Some(None)) => return Served::errno(carrick_abi::LINUX_ENODEV),
            _ => return Served::Refused,
        };
        match self.mem().retain_native_private_source(reference, label) {
            Some((source, identity)) => Served::Source(
                source,
                carrick_core_abi::host_file::MapSourceReply {
                    handle: identity.handle(),
                    generation: identity.generation(),
                },
            ),
            None => Served::errno(carrick_abi::LINUX_ENOMEM),
        }
    }

    /// `read`, `pread64` or `getdents64` on a venue-opened description: the
    /// dispatcher's own description cores, writing into the record's output
    /// area through a carrier buffer.
    fn native_read_into_record(
        &self,
        header: HostFileHeader,
        description: &Arc<crate::kernel::FileDescription>,
        capacity: usize,
    ) -> Served {
        let mut buffer = super::outcome::LinearMemory::new(CARRIER_BUFFER_BASE, vec![0; capacity]);
        let fs = self.fs_view();
        let outcome = match header.op {
            HostFileOp::Read => {
                let nonblocking =
                    LinuxOpenFlags::from_bits_truncate(description.common().status_flags())
                        .contains(LinuxOpenFlags::NONBLOCK);
                fs.read_description(
                    &mut buffer,
                    description,
                    CARRIER_BUFFER_BASE,
                    capacity,
                    nonblocking,
                    None,
                )
            }
            HostFileOp::Pread => fs.pread_description(
                super::fs::IoCaller::CarrierBuffer,
                &mut buffer,
                description,
                CARRIER_BUFFER_BASE,
                capacity,
                header.args[0] as usize,
                &|| {
                    Some(super::WaitFdAuthority::internal(
                        super::InternalWaitKind::HostReadiness,
                    ))
                },
                None,
            ),
            HostFileOp::Getdents64 => {
                let Some(lease) = description.retain_fd_lease() else {
                    return Served::errno(carrick_abi::LINUX_EBADF);
                };
                fs.read_directory(
                    super::fs::directory::DirectoryReadCaller::CarrierBuffer,
                    &mut buffer,
                    crate::kernel::FileSlot::new(Arc::clone(description), 0),
                    lease,
                    carrick_guest_mem::GuestVa::new(CARRIER_BUFFER_BASE),
                    capacity,
                )
            }
            _ => return Served::Refused,
        };
        match outcome {
            Ok(outcome) => served_outcome(outcome, buffer.bytes),
            Err(_) => Served::Refused,
        }
    }
}

/// Where a carrier buffer sits in the description cores' notional address
/// space: page aligned, so their page-granular batching starts on a page.
const CARRIER_BUFFER_BASE: u64 = 0x1_0000;

/// A description core's outcome as a reply: a byte count returns that prefix
/// of `bytes` as output; an errno or offset returns no output; anything else
/// (a wait) cannot arise for a venue-opened file and is refused exactly.
fn served_outcome(outcome: DispatchOutcome, mut bytes: Vec<u8>) -> Served {
    match outcome {
        DispatchOutcome::Returned { value } => {
            match usize::try_from(value) {
                Ok(len) if len <= bytes.len() => bytes.truncate(len),
                _ => bytes.clear(),
            }
            Served::Reply(value, bytes)
        }
        DispatchOutcome::Errno { errno } => Served::errno(errno),
        _ => Served::Refused,
    }
}

fn native_stat_bytes(op: HostFileOp, record: &super::StatRecord) -> Vec<u8> {
    if op == HostFileOp::Statx {
        super::format_stat::linux_statx(record).as_bytes().to_vec()
    } else {
        super::format_stat::linux_stat(record).as_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::ids::ObjectIdRegistry;
    use crate::kernel::{FileDescription, FileSlotNumber};
    use carrick_core_abi::host_file::{self, HostFileHeader};
    use carrick_el1_abi::ipc_tables::IpcTableMap;

    const FDCWD: i32 = LINUX_AT_FDCWD as i32;

    fn map() -> &'static IpcTableMap {
        // SAFETY: zero-initialized atomics, alive for the test process, used
        // only through their synchronized API.
        unsafe {
            &*std::alloc::alloc_zeroed(std::alloc::Layout::new::<IpcTableMap>())
                .cast::<IpcTableMap>()
        }
    }

    struct Fixture {
        dispatcher: SyscallDispatcher,
        owner: Arc<HostIpc>,
        table: [u64; 3],
        _rootfs: Option<tempfile::TempDir>,
        _upper: Option<tempfile::TempDir>,
    }

    /// An ubuntu-shaped rootfs: `/lib -> usr/lib`, `usr/lib/libc.so.6`,
    /// `etc/ld.so.cache`, and an empty `/tmp`.
    fn rootfs() -> tempfile::TempDir {
        let lower = tempfile::tempdir().unwrap();
        let root = lower.path();
        std::fs::create_dir_all(root.join("usr/lib")).unwrap();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::create_dir_all(root.join("tmp")).unwrap();
        std::os::unix::fs::symlink("usr/lib", root.join("lib")).unwrap();
        std::fs::write(root.join("usr/lib/libc.so.6"), b"\x7fELF-libc-bytes").unwrap();
        std::fs::write(root.join("etc/ld.so.cache"), b"cache").unwrap();
        lower
    }

    /// The root's published namespace (implicit stdio plus a regular host
    /// file at fd 3), as a native fork child inherits it.
    fn fixture_with(dispatcher: SyscallDispatcher, rootfs: Option<tempfile::TempDir>) -> Fixture {
        fixture_with_owner(dispatcher, rootfs, |_| {
            Arc::new(HostIpc::new(1 << 20).unwrap())
        })
    }

    fn fixture_with_owner(
        dispatcher: SyscallDispatcher,
        rootfs: Option<tempfile::TempDir>,
        owner: impl FnOnce(&crate::kernel::KernelContext) -> Arc<HostIpc>,
    ) -> Fixture {
        let context = dispatcher.capture_one_task_context().unwrap();
        let owner = owner(&context);
        let files = context.resources().files();
        let ids = ObjectIdRegistry::new();
        let regular = Arc::new(FileDescription::regular(ids.file_description_id().unwrap()));
        regular.retain_fd_ref();
        files.install(FileSlotNumber::for_open_fd(3).unwrap(), regular, false);
        let map = map();
        files.publish_ipc(Arc::clone(&owner), map).unwrap();
        let raw = map.lookup(files.id().raw()).unwrap();
        Fixture {
            dispatcher,
            owner,
            table: [raw.authority, raw.index, raw.generation],
            _rootfs: rootfs,
            _upper: None,
        }
    }

    fn fixture() -> Fixture {
        fixture_with(SyscallDispatcher::new(), None)
    }

    fn rootfs_fixture() -> Fixture {
        let lower = rootfs();
        let rootfs = carrick_vfs::rootfs::RootFs::from_immutable_host_dir(lower.path()).unwrap();
        fixture_with(SyscallDispatcher::with_rootfs(rootfs), Some(lower))
    }

    /// The writable upper a run uses: in memory, or a host directory
    /// (`--fs host`, whose files are host-fd descriptions).
    #[derive(Clone, Copy, Debug)]
    enum Upper {
        Memory,
        Host,
    }

    fn writable_fixture(upper: Upper) -> Fixture {
        let lower = rootfs();
        let rootfs = carrick_vfs::rootfs::RootFs::from_immutable_host_dir(lower.path()).unwrap();
        let mut dispatcher = SyscallDispatcher::with_rootfs(rootfs);
        let scratch = match upper {
            Upper::Memory => None,
            Upper::Host => {
                let scratch = tempfile::tempdir().unwrap();
                dispatcher.set_fs_backend(Box::new(
                    carrick_vfs::fs_backend::HostFsBackend::from_path(scratch.path()).unwrap(),
                ));
                Some(scratch)
            }
        };
        let mut fixture = fixture_with(dispatcher, Some(lower));
        fixture._upper = scratch;
        fixture
    }

    /// A caller's access context as its ring task row holds it: values,
    /// read once from a task's credentials and filesystem context.
    #[derive(Clone)]
    struct CallerAccess {
        credentials: Arc<crate::kernel::Credentials>,
        cwd: String,
        root: Option<String>,
    }

    fn authority_of(dispatcher: &SyscallDispatcher) -> CallerAccess {
        let context = dispatcher.capture_one_task_context().unwrap();
        let fs = context.resources().fs_context();
        CallerAccess {
            credentials: context.resources().credentials(),
            cwd: fs.cwd(),
            root: fs.chroot_root(),
        }
    }

    impl CallerAccess {
        fn in_cwd(&self, cwd: &str) -> Self {
            Self {
                cwd: cwd.to_owned(),
                ..self.clone()
            }
        }

        /// The record as the ring stages it: a path record leads its input
        /// with the caller's encoded access context.
        fn stamp(&self, bytes: &mut Vec<u8>) {
            use carrick_personality_linux::identity::{
                LinuxCapabilitySet, TaskCredentials, TaskGid, TaskUid,
            };
            use carrick_personality_linux::task_fs::{TaskFs, TaskPath};
            // The ring row these host credentials describe, encoded and
            // stamped by the production ring helpers.
            let c = &self.credentials;
            let mut row = TaskCredentials::ROOT;
            row.ruid = TaskUid::new(c.ruid.0);
            row.euid = TaskUid::new(c.euid.0);
            row.suid = TaskUid::new(c.suid.0);
            row.fsuid = TaskUid::new(c.fsuid.0);
            row.rgid = TaskGid::new(c.rgid.0);
            row.egid = TaskGid::new(c.egid.0);
            row.sgid = TaskGid::new(c.sgid.0);
            row.fsgid = TaskGid::new(c.fsgid.0);
            if let Some(groups) = c.supplementary_groups_override() {
                row.groups = groups.iter().map(|group| TaskGid::new(group.0)).collect();
                row.groups_installed = true;
            }
            if !row.fsuid.is_root() {
                row.cap_effective = LinuxCapabilitySet::empty();
            }
            let fs = TaskFs {
                cwd: TaskPath::new(self.cwd.as_bytes()).unwrap(),
                root: self
                    .root
                    .as_deref()
                    .map(|root| TaskPath::new(root.as_bytes()).unwrap()),
            };
            let mut access = Vec::new();
            fs.encode_access(&row, c.umask, &mut access).unwrap();
            *bytes =
                carrick_personality_linux::native_host_file::stamp_access_context(bytes, &access)
                    .unwrap()
                    .into_vec();
        }
    }

    fn record(
        table: [u64; 3],
        op: HostFileOp,
        fd: i32,
        args: [u64; 4],
        input: &[u8],
        output: usize,
    ) -> Vec<u8> {
        let mut bytes = vec![0u8; host_file::record_len(input.len(), output).unwrap()];
        host_file::encode(
            &mut bytes,
            HostFileHeader {
                op,
                table,
                fd,
                flags: 0,
                args,
            },
            input,
            output,
        )
        .unwrap();
        bytes
    }

    impl Fixture {
        fn serve(
            &self,
            authority: Option<&CallerAccess>,
            bytes: &mut Vec<u8>,
        ) -> Result<(), NativeHostFileRefusal> {
            if let Some(authority) = authority {
                authority.stamp(bytes);
            }
            self.dispatcher
                .serve_native_host_file_in(&self.owner, bytes)
                .map(|_| ())
        }
        fn result(&self, authority: Option<&CallerAccess>, mut bytes: Vec<u8>) -> (i64, Vec<u8>) {
            self.serve(authority, &mut bytes).unwrap();
            let reply = host_file::reply(&bytes).unwrap();
            (reply.result, reply.output.to_vec())
        }
    }

    #[test]
    fn native_stdout_write_reaches_the_runs_stdio_route() {
        let fixture = fixture();
        let bytes = record(
            fixture.table,
            HostFileOp::Write,
            1,
            [0; 4],
            b"bin\nboot\n",
            0,
        );
        assert_eq!(fixture.result(None, bytes).0, 9);
        assert_eq!(fixture.dispatcher.stdout(), b"bin\nboot\n");
    }

    #[repr(align(4096))]
    struct MutationMemory([u8; 16384]);

    impl carrick_el1_linux::file::MemoryValidator for MutationMemory {
        fn readable_bytes(&self, address: u64, len: usize) -> usize {
            let base = self.0.as_ptr().addr() as u64;
            if address < base {
                return 0;
            }
            (base + self.0.len() as u64)
                .saturating_sub(address)
                .min(len as u64) as usize
        }
        fn writable_bytes(&self, address: u64, len: usize) -> usize {
            self.readable_bytes(address, len)
        }
    }

    fn mutation_child(upper: Upper) -> Fixture {
        let mut fixture = writable_fixture(upper);
        fixture
            .dispatcher
            .kernel_binding
            .read()
            .kernel()
            .install_ipc_for_test(Arc::clone(&fixture.owner));
        let region = fixture.owner.region();
        let mut storage = region
            .provision_descriptors(256, &crate::el1_zone::HostLockWait)
            .unwrap();
        let child = region
            .fd(crate::el1_zone::HostLockWait)
            .fork(fixture.ring_fd(), &mut storage)
            .unwrap()
            .to_raw();
        fixture.table = [child.authority, child.index, child.generation];
        fixture
    }

    impl Fixture {
        fn child_call(
            &self,
            authority: &CallerAccess,
            ordinal: u64,
            mut args: [u64; 6],
            inputs: &[(usize, &[u8])],
        ) -> i64 {
            use carrick_personality_linux::native_host_file::{
                HostFileCall, HostFileStage, NativeNamespace,
            };
            let mut memory = Box::new(MutationMemory([0; 16384]));
            for (page, (argument, bytes)) in inputs.iter().enumerate() {
                let start = page * 4096;
                assert!(bytes.len() < 4096);
                memory.0[start..start + bytes.len()].copy_from_slice(bytes);
                args[*argument] = memory.0[start..].as_ptr().addr() as u64;
            }
            let Some(call) = HostFileCall::decode(carrick_abi::CanonicalNr::new(ordinal), &args)
            else {
                return -38;
            };
            let tables = carrick_el1_linux::ipc::MapTables(map());
            let venue = carrick_el1_linux::ipc::IpcVenue {
                region: self.owner.region(),
                tables: &tables,
            };
            let mut resolve =
                |number| carrick_el1_linux::ipc::native_descriptor(&venue, self.table, number);
            let mut releases = |_: &mut [host_file::MapSourceReply]| 0;
            let staged = carrick_el1_linux::dispatch::stage_native_host_file(
                call,
                &carrick_el1_abi::CurrentTask::new(),
                &*memory,
                &mut NativeNamespace {
                    table: self.table,
                    resolve: &mut resolve,
                    releases: &mut releases,
                },
            );
            match staged {
                Some(HostFileStage::Request {
                    record,
                    resolves_path,
                    output,
                    ..
                }) => {
                    let mut record = record.into_vec();
                    if resolves_path {
                        authority.stamp(&mut record);
                    }
                    carrick_personality_linux::native_host_file::stamp_write_file_size_limit::<()>(
                        &mut record,
                        || Ok(UNLIMITED),
                    )
                    .unwrap();
                    match self.dispatcher.serve_native_host_file(&mut record) {
                        Ok(_) => carrick_personality_linux::native_host_file::complete(
                            &record,
                            output,
                            &mut |_, _| panic!("a mutation has no user output"),
                        )
                        .raw(),
                        Err(NativeHostFileRefusal) => -38,
                    }
                }
                Some(HostFileStage::Returned(result)) => result.raw(),
                Some(HostFileStage::Fault { .. }) => -14,
                Some(HostFileStage::InRing) | None => -38,
                other => panic!("unexpected mutation staging: {other:?}"),
            }
        }
    }

    #[test]
    fn native_child_mkdir_dispatches_with_its_cwd_umask_and_errno_matrix() {
        for upper in [Upper::Memory, Upper::Host] {
            let fixture = mutation_child(upper);
            let authority = authority_of(&fixture.dispatcher).in_cwd("/tmp");
            let mkdir = |path: &[u8], dirfd| {
                fixture.child_call(&authority, 34, [dirfd, 0, 0o777, 0, 0, 0], &[(1, path)])
            };
            assert_eq!(mkdir(b"child-dir", FDCWD as u64), 0, "{upper:?}");
            let stat = fixture.result(
                Some(&authority),
                record(
                    fixture.table,
                    HostFileOp::Newfstatat,
                    FDCWD,
                    [0; 4],
                    b"child-dir",
                    carrick_personality_linux::native_host_file::LINUX_STAT_BYTES,
                ),
            );
            assert_eq!(stat.0, 0);
            let stat =
                <carrick_abi::LinuxStat as zerocopy::FromBytes>::read_from_bytes(&stat.1).unwrap();
            assert_eq!(stat.st_mode & 0o777, 0o777 & !authority.credentials.umask);
            for (path, dirfd, expected) in [
                (&b"child-dir"[..], FDCWD as u64, -17),
                (&b"missing/dir"[..], FDCWD as u64, -2),
                (&b"/etc/ld.so.cache/dir"[..], FDCWD as u64, -20),
                (&b""[..], FDCWD as u64, -2),
                (&b"."[..], FDCWD as u64, -17),
                (&b"bad-fd"[..], 999, -9),
                (&b"not-dir"[..], 1, -38),
            ] {
                assert_eq!(mkdir(path, dirfd), expected, "{upper:?}: {path:?}");
            }
            assert_eq!(mkdir(&[b'x'; 256], FDCWD as u64), -36);
            assert_eq!(mkdir(b"/tmp/absolute", 999), 0, "absolute ignores dirfd");
            assert!(
                fixture
                    .dispatcher
                    .fs_view()
                    .layered_metadata("/tmp/child-dir")
                    .is_ok(),
                "the parent sees the child's namespace mutation"
            );
        }
    }

    #[test]
    fn native_child_write_serves_parent_redirected_stdout_after_host_close() {
        for upper in [Upper::Memory, Upper::Host] {
            let mut fixture = writable_fixture(upper);
            let opened = root_openat(&mut fixture.dispatcher, b"/tmp/redirected\0", CREATE);
            assert!(opened >= 0, "{upper:?}: host open returned {opened}");
            let context = fixture.dispatcher.capture_one_task_context().unwrap();
            let original = Arc::downgrade(
                &context
                    .resources()
                    .files()
                    .slot(FileSlotNumber::for_open_fd(opened as i32).unwrap())
                    .unwrap()
                    .description(),
            );
            let region = fixture.owner.region();
            let ring = region.fd(crate::el1_zone::HostLockWait);
            ring.dup2(fixture.ring_fd(), fd::Fd(opened as i32), fd::Fd(1))
                .unwrap();
            let mut storage = region
                .provision_descriptors(64, &crate::el1_zone::HostLockWait)
                .unwrap();
            let child = ring.fork(fixture.ring_fd(), &mut storage).unwrap();
            let raw = child.to_raw();
            let child_table = [raw.authority, raw.index, raw.generation];
            let mut memory = super::super::outcome::LinearMemory::new(0x4000, vec![0; 4096]);
            let closed = fixture
                .dispatcher
                .dispatch(
                    &context,
                    super::super::SyscallRequest::new(
                        57,
                        crate::compat::SyscallArgs::from([opened as u64, 0, 0, 0, 0, 0]),
                    ),
                    &mut memory,
                    &crate::compat::CompatReporter::default(),
                )
                .unwrap();
            assert!(matches!(closed, DispatchOutcome::Returned { value: 0 }));
            assert!(original.upgrade().is_none(), "no publication-owner cycle");
            let mut bytes = record(
                child_table,
                HostFileOp::Write,
                1,
                [UNLIMITED, 0, 0, 0],
                b"child\n",
                0,
            );
            let result = match fixture
                .dispatcher
                .serve_native_host_file_in(&fixture.owner, &mut bytes)
            {
                Ok(_) => host_file::reply(&bytes).unwrap().result,
                Err(NativeHostFileRefusal) => -38,
            };
            assert_eq!(
                result, 6,
                "{upper:?}: native redirected write returned {result}"
            );
            assert_eq!(
                fixture.venue_contents(&authority_of(&fixture.dispatcher), b"/tmp/redirected"),
                b"child\n",
            );
            assert!(fixture.dispatcher.stdout().is_empty());
            let next = record(
                child_table,
                HostFileOp::Write,
                1,
                [UNLIMITED, 0, 0, 0],
                b"next\n",
                0,
            );
            assert_eq!(fixture.result(None, next).0, 5);
            assert_eq!(
                fixture.venue_contents(&authority_of(&fixture.dispatcher), b"/tmp/redirected"),
                b"child\nnext\n",
                "the inherited description retains its cursor",
            );
            if let Some(released) = ring.close(child, fd::Fd(1)).unwrap() {
                fixture.owner.release(released.backing).unwrap();
            }
            let closed = record(
                child_table,
                HostFileOp::Write,
                1,
                [UNLIMITED, 0, 0, 0],
                b"must not land",
                0,
            );
            assert_eq!(fixture.result(None, closed).0, -9);
            ring.retire_table(child, |_| false, |_| unreachable!())
                .unwrap();
            fixture.owner.drain_retired_tables().unwrap();
        }
    }

    #[test]
    fn native_stdio_fstat_is_the_dispatchers_implicit_stdio_record() {
        let fixture = fixture();
        let bytes = record(
            fixture.table,
            HostFileOp::Fstat,
            2,
            [0; 4],
            &[],
            carrick_personality_linux::native_host_file::LINUX_STAT_BYTES,
        );
        let (result, output) = fixture.result(None, bytes);
        assert_eq!(result, 0);
        let expected = super::super::format_stat::linux_stat(
            &super::super::fs::implicit_stdio_stat_record(&fixture.dispatcher.fs.pty_table, 2),
        );
        assert_eq!(output, expected.as_bytes());
    }

    #[test]
    fn closed_descriptor_replies_ebadf_and_unserved_resources_refuse() {
        let fixture = fixture();
        let closed = record(fixture.table, HostFileOp::Write, 9, [0; 4], b"x", 0);
        assert_eq!(
            fixture.result(None, closed).0,
            carrick_abi::LINUX_EBADF.guest_retval()
        );
        // An inherited explicit host description is a later slice.
        let mut regular = record(fixture.table, HostFileOp::Write, 3, [0; 4], b"x", 0);
        assert_eq!(
            fixture.serve(None, &mut regular),
            Err(NativeHostFileRefusal)
        );
        assert_eq!(host_file::reply(&regular), None);
        // The run's stdin stream is not written through this venue yet.
        let mut stdin = record(fixture.table, HostFileOp::Write, 0, [0; 4], b"x", 0);
        assert_eq!(fixture.serve(None, &mut stdin), Err(NativeHostFileRefusal));
        assert!(fixture.dispatcher.stdout().is_empty());
    }

    fn pollfds(entries: &[(i32, i16, i16)]) -> Vec<u8> {
        entries
            .iter()
            .flat_map(|&(fd, events, revents)| {
                let mut entry = [0u8; host_file::POLLFD_BYTES];
                entry[..4].copy_from_slice(&fd.to_le_bytes());
                entry[4..6].copy_from_slice(&events.to_le_bytes());
                entry[6..].copy_from_slice(&revents.to_le_bytes());
                entry
            })
            .collect()
    }

    fn poll_record(table: [u64; 3], wait: u64, entries: &[(i32, i16, i16)]) -> Vec<u8> {
        let input = pollfds(entries);
        record(
            table,
            HostFileOp::Poll,
            -1,
            [wait, 0, 0, 0],
            &input,
            input.len(),
        )
    }

    #[test]
    fn native_stdio_poll_snapshot_reports_the_dispatchers_stdio_readiness() {
        use carrick_abi::{LINUX_POLLIN, LINUX_POLLNVAL, LINUX_POLLOUT};
        let fixture = fixture();
        // Rust std's startup check (no events, zero timeout) over stdout and
        // stderr: nothing is ready and nothing is invalid. The stale revents
        // the guest left are overwritten.
        let (result, output) = fixture.result(
            None,
            poll_record(
                fixture.table,
                host_file::PollWait::Snapshot.raw(),
                &[(1, 0, 0x7fff), (-1, LINUX_POLLIN, 0x7fff), (2, 0, 0x7fff)],
            ),
        );
        assert_eq!(result, 0);
        assert_eq!(
            output,
            pollfds(&[(1, 0, 0), (-1, LINUX_POLLIN, 0), (2, 0, 0)])
        );
        // The captured stdout route is always writable, never readable; an
        // absent descriptor is POLLNVAL and counts as ready.
        let (result, output) = fixture.result(
            None,
            poll_record(
                fixture.table,
                host_file::PollWait::Snapshot.raw(),
                &[(1, LINUX_POLLIN | LINUX_POLLOUT, 0), (9, LINUX_POLLIN, 0)],
            ),
        );
        assert_eq!(result, 2);
        assert_eq!(
            output,
            pollfds(&[
                (1, LINUX_POLLIN | LINUX_POLLOUT, LINUX_POLLOUT),
                (9, LINUX_POLLIN, LINUX_POLLNVAL),
            ])
        );
        // A caller that would wait gets its ready snapshot.
        let (result, _) = fixture.result(
            None,
            poll_record(
                fixture.table,
                host_file::PollWait::MayWait.raw(),
                &[(2, LINUX_POLLOUT, 0)],
            ),
        );
        assert_eq!(result, 1);
    }

    #[test]
    fn native_poll_never_waits_or_answers_part_of_a_set() {
        use carrick_abi::{LINUX_POLLIN, LINUX_POLLOUT};
        let fixture = fixture();
        // An empty snapshot for a caller that would wait is refused, not a
        // fake timeout: no reply is written.
        let mut empty = poll_record(
            fixture.table,
            host_file::PollWait::MayWait.raw(),
            &[(1, LINUX_POLLIN, 0)],
        );
        assert_eq!(fixture.serve(None, &mut empty), Err(NativeHostFileRefusal));
        assert_eq!(host_file::reply(&empty), None);
        // A resource this venue does not observe refuses the whole set.
        let mut unobserved = poll_record(
            fixture.table,
            host_file::PollWait::Snapshot.raw(),
            &[(1, LINUX_POLLOUT, 0), (3, LINUX_POLLIN, 0)],
        );
        assert_eq!(
            fixture.serve(None, &mut unobserved),
            Err(NativeHostFileRefusal)
        );
        assert_eq!(host_file::reply(&unobserved), None);
        // Unknown wait words and torn arrays are not guessed at.
        let mut unknown = poll_record(fixture.table, 7, &[(1, LINUX_POLLOUT, 0)]);
        assert_eq!(
            fixture.serve(None, &mut unknown),
            Err(NativeHostFileRefusal)
        );
        let mut torn = record(
            fixture.table,
            HostFileOp::Poll,
            -1,
            [host_file::PollWait::Snapshot.raw(), 0, 0, 0],
            &[1, 0, 0],
            3,
        );
        assert_eq!(fixture.serve(None, &mut torn), Err(NativeHostFileRefusal));
    }

    /// A description the venue opened is polled through its own
    /// description readiness: the same answer the dispatcher gives a host
    /// task's descriptor for that description.
    #[test]
    fn native_poll_reports_a_venue_opened_descriptions_readiness() {
        use carrick_abi::{LINUX_POLLIN, LINUX_POLLOUT};
        let fixture = rootfs_fixture();
        let authority = authority_of(&fixture.dispatcher);
        let (fd, _) = fixture.result(
            Some(&authority),
            record(
                fixture.table,
                HostFileOp::Openat,
                FDCWD,
                [carrick_abi::LINUX_O_RDONLY, 0, 0, 0],
                b"/lib/libc.so.6",
                0,
            ),
        );
        assert_eq!(fd, 4, "lowest free descriptor after stdio and fd 3");
        let (result, output) = fixture.result(
            None,
            poll_record(
                fixture.table,
                host_file::PollWait::MayWait.raw(),
                &[(fd as i32, LINUX_POLLIN | LINUX_POLLOUT, 0)],
            ),
        );
        // A regular file is always readable and writable for poll.
        assert_eq!(result, 1);
        assert_eq!(
            output,
            pollfds(&[(
                fd as i32,
                LINUX_POLLIN | LINUX_POLLOUT,
                LINUX_POLLIN | LINUX_POLLOUT
            )])
        );
    }

    /// The ring staged the set while every member was host-backed, but a
    /// member was replaced by an in-zone object before the carrier served
    /// it (another thread's dup2). The carrier cannot observe that object,
    /// and calling it absent (POLLNVAL) would be wrong: the whole set is
    /// refused and no reply is written.
    #[test]
    fn native_poll_refuses_a_member_replaced_by_an_in_zone_object() {
        use carrick_abi::{LINUX_POLLIN, LINUX_POLLOUT};
        use carrick_el1_abi::ipc::pipe::End;
        let fixture = fixture();
        let table = fd::TableId::from_raw(fd::RawTableId {
            authority: fixture.table[0],
            index: fixture.table[1],
            generation: fixture.table[2],
        });
        let pipe = super::super::fs::pipe::PipeInner::create(
            Arc::clone(&fixture.owner),
            1,
            super::super::fs::pipe::PIPE_BUF,
        )
        .unwrap();
        // Replace fd 3 (a host description) with the pipe's read end, as a
        // dup2 from another thread would after the ring staged the set.
        let region = fixture.owner.region();
        if let Some(closed) = region
            .fd(crate::el1_zone::HostLockWait)
            .close(table, fd::Fd(3))
            .unwrap()
        {
            fixture.owner.release(closed.backing).unwrap();
        }
        pipe.retain_endpoint(End::Reader);
        pipe.install_endpoint_for_test(End::Reader, table, fd::Fd(3))
            .unwrap();
        let mut replaced = poll_record(
            fixture.table,
            host_file::PollWait::Snapshot.raw(),
            &[(1, LINUX_POLLOUT, 0), (3, LINUX_POLLIN, 0)],
        );
        assert_eq!(
            fixture.serve(None, &mut replaced),
            Err(NativeHostFileRefusal)
        );
        assert_eq!(host_file::reply(&replaced), None);
    }

    #[test]
    fn path_calls_without_the_callers_authority_are_refused() {
        let fixture = rootfs_fixture();
        let mut open = record(
            fixture.table,
            HostFileOp::Openat,
            FDCWD,
            [0; 4],
            b"/etc/ld.so.cache",
            0,
        );
        assert_eq!(fixture.serve(None, &mut open), Err(NativeHostFileRefusal));
        assert_eq!(host_file::reply(&open), None);
    }

    /// The carrier's descriptor-ceiling word, as the EL1 vector reads it.
    #[derive(Debug, Default)]
    struct CeilingWord(std::sync::atomic::AtomicU32);
    impl carrick_hal::FdCeilingPublisher for CeilingWord {
        fn raise(&self, maximum: u32) {
            self.0
                .fetch_max(maximum, std::sync::atomic::Ordering::AcqRel);
        }
        fn disable(&self) {}
    }

    /// #1398 review. A native child's venue `openat` installs its new
    /// descriptor from the carrier (`NativeOpenSink` ->
    /// `HostIpc::install_host_description`), never through a host FileTable.
    /// With the kernel's own IPC authority, as production builds it, every
    /// such number must be at or below the carrier word the EL1 vector's
    /// close/fstat fast return compares against before it is visible.
    #[test]
    fn native_openat_raises_the_kernel_descriptor_ceiling_before_install() {
        let lower = rootfs();
        let rootfs = carrick_vfs::rootfs::RootFs::from_immutable_host_dir(lower.path()).unwrap();
        let word = Arc::new(CeilingWord::default());
        let published = Arc::clone(&word);
        let fixture = fixture_with_owner(
            SyscallDispatcher::with_rootfs(rootfs),
            Some(lower),
            move |context| {
                let kernel = context.kernel();
                kernel.fd_ceiling().register(published);
                kernel.ipc().unwrap()
            },
        );
        let ceiling = || word.0.load(std::sync::atomic::Ordering::Acquire);
        assert_eq!(ceiling(), 3, "the root's FileTable published fd 3");
        let authority = authority_of(&fixture.dispatcher);
        for expected in 4..9 {
            let open = record(
                fixture.table,
                HostFileOp::Openat,
                FDCWD,
                [0; 4],
                b"/lib/libc.so.6",
                0,
            );
            let (fd, _) = fixture.result(Some(&authority), open);
            assert_eq!(fd, expected);
            assert!(
                i64::from(ceiling()) >= fd,
                "native openat fd {fd} is live above the vector's ceiling {}",
                ceiling()
            );
        }
    }

    #[test]
    fn host_root_resources_open_and_reopen_only_in_the_ring_namespace() {
        let lower = rootfs();
        let rootfs = carrick_vfs::rootfs::RootFs::from_immutable_host_dir(lower.path()).unwrap();
        let fixture = fixture_with_owner(
            SyscallDispatcher::with_rootfs(rootfs),
            Some(lower),
            |context| context.kernel().ipc().unwrap(),
        );
        let context = fixture.dispatcher.capture_one_task_context().unwrap();
        let resources = super::super::resources::HostRootResources::capture(&context);
        context.resources().fs_context().set_cwd("/usr/lib".into());
        let [authority, index, generation] = fixture.table;
        let table = fd::TableId::from_raw(fd::RawTableId {
            authority,
            index,
            generation,
        });
        for _ in 0..3 {
            let mut open = record(
                fixture.table,
                HostFileOp::Openat,
                FDCWD,
                [0; 4],
                b"libc.so.6",
                0,
            );
            fixture
                .dispatcher
                .serve_host_root_file(&resources, &mut open)
                .unwrap();
            let opened = host_file::reply(&open).unwrap().result;
            assert_eq!(opened, 4);
            assert!(
                context
                    .resources()
                    .files()
                    .slot(FileSlotNumber::for_open_fd(4).unwrap())
                    .is_none()
            );
            let region = fixture.owner.region();
            let ring = region.fd(crate::el1_zone::HostLockWait);
            let released = ring.close(table, fd::Fd(4)).unwrap().unwrap();
            fixture.owner.release(released.backing).unwrap();
        }
    }

    /// The loader's sequence: access, open through the usrmerge symlink,
    /// read, fstat, close-by-release. The new fd is the caller's lowest free
    /// descriptor in its own table.
    #[test]
    fn native_open_read_and_fstat_serve_the_loader_through_one_vfs() {
        let fixture = rootfs_fixture();
        let authority = authority_of(&fixture.dispatcher);
        let access = |path: &[u8]| {
            fixture
                .result(
                    Some(&authority),
                    record(
                        fixture.table,
                        HostFileOp::Faccessat,
                        FDCWD,
                        [4, 0, 0, 0],
                        path,
                        0,
                    ),
                )
                .0
        };
        assert_eq!(
            access(b"/etc/ld.so.preload"),
            carrick_abi::LINUX_ENOENT.guest_retval()
        );
        assert_eq!(access(b"/lib/libc.so.6"), 0);

        let open = record(
            fixture.table,
            HostFileOp::Openat,
            FDCWD,
            [carrick_abi::LINUX_O_CLOEXEC, 0, 0, 0],
            b"/lib/libc.so.6",
            0,
        );
        let (fd, _) = fixture.result(Some(&authority), open);
        assert_eq!(fd, 4, "lowest free descriptor after stdio and fd 3");
        let fd = fd as i32;
        let raw = fd::RawTableId {
            authority: fixture.table[0],
            index: fixture.table[1],
            generation: fixture.table[2],
        };
        let authority_fd = fixture.owner.region();
        let authority_fd = authority_fd.fd(crate::el1_zone::HostLockWait);
        assert_eq!(
            authority_fd.getfd(fd::TableId::from_raw(raw), fd::Fd(fd)),
            Ok(true),
            "O_CLOEXEC lands in the caller's own table"
        );

        let (read, bytes) = fixture.result(
            None,
            record(fixture.table, HostFileOp::Read, fd, [0; 4], &[], 4),
        );
        assert_eq!((read, bytes.as_slice()), (4, &b"\x7fELF"[..]));
        let (read, bytes) = fixture.result(
            None,
            record(fixture.table, HostFileOp::Pread, fd, [1, 0, 0, 0], &[], 3),
        );
        assert_eq!((read, bytes.as_slice()), (3, &b"ELF"[..]));
        let (offset, _) = fixture.result(
            None,
            record(fixture.table, HostFileOp::Lseek, fd, [0, 1, 0, 0], &[], 0),
        );
        assert_eq!(offset, 4, "pread does not move the description offset");
        let (result, stat) = fixture.result(
            None,
            record(
                fixture.table,
                HostFileOp::Fstat,
                fd,
                [0; 4],
                &[],
                carrick_personality_linux::native_host_file::LINUX_STAT_BYTES,
            ),
        );
        assert_eq!(result, 0);
        let size = i64::from_le_bytes(stat[48..56].try_into().unwrap());
        assert_eq!(size, b"\x7fELF-libc-bytes".len() as i64, "st_size");

        // The ring's close releases the last reference: the host resource
        // goes with it.
        let before = fixture.owner.retained_host_resources();
        let released = authority_fd
            .close(fd::TableId::from_raw(raw), fd::Fd(fd))
            .unwrap()
            .unwrap();
        fixture.owner.release(released.backing).unwrap();
        assert_eq!(fixture.owner.retained_host_resources(), before - 1);
    }

    /// #1503: `statx(fd, "", AT_EMPTY_PATH)` of a venue-opened file. The ring
    /// stages it as a `Statx` record naming the descriptor with an empty
    /// path (a path op, so the record carries the caller's access context).
    /// The carrier must stat the pinned descriptor, exactly as `fstat`; it
    /// used to resolve the empty path against `AT_FDCWD`, which reached for a
    /// host file table the native scope does not have and killed the carrier
    /// ("file-table access escaped its captured KernelContext scope").
    #[test]
    fn native_statx_of_a_descriptor_is_its_fstat() {
        let fixture = rootfs_fixture();
        let authority = authority_of(&fixture.dispatcher);
        let open = record(
            fixture.table,
            HostFileOp::Openat,
            FDCWD,
            [carrick_abi::LINUX_O_CLOEXEC, 0, 0, 0],
            b"/lib/libc.so.6",
            0,
        );
        let (fd, _) = fixture.result(Some(&authority), open);
        assert!(fd >= 0, "open: {fd}");
        let fd = fd as i32;
        let statx_bytes = carrick_personality_linux::native_host_file::LINUX_STATX_BYTES;
        let statx = |flags: u32, fd: i32| {
            let mut bytes = vec![0u8; host_file::record_len(0, statx_bytes).unwrap()];
            host_file::encode(
                &mut bytes,
                HostFileHeader {
                    op: HostFileOp::Statx,
                    table: fixture.table,
                    fd,
                    flags,
                    args: [0x0fff, 0, 0, 0],
                },
                &[],
                statx_bytes,
            )
            .unwrap();
            fixture.result(Some(&authority), bytes)
        };
        let (result, bytes) = statx(carrick_abi::LINUX_AT_EMPTY_PATH as u32, fd);
        assert_eq!(result, 0, "statx(fd, \"\", AT_EMPTY_PATH)");
        let size = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
        assert_eq!(size, b"\x7fELF-libc-bytes".len() as u64, "stx_size");
        let ino = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        let (result, stat) = fixture.result(
            None,
            record(
                fixture.table,
                HostFileOp::Fstat,
                fd,
                [0; 4],
                &[],
                carrick_personality_linux::native_host_file::LINUX_STAT_BYTES,
            ),
        );
        assert_eq!(result, 0);
        assert_eq!(
            ino,
            u64::from_le_bytes(stat[8..16].try_into().unwrap()),
            "statx and fstat name one inode"
        );
        // A closed descriptor is EBADF, as Linux, never a path lookup.
        let (result, _) = statx(carrick_abi::LINUX_AT_EMPTY_PATH as u32, 9);
        assert_eq!(result, carrick_abi::LINUX_EBADF.guest_retval());
    }

    /// `fexecve` from a native process (#1530) executes the open file, never
    /// its name: the exec source is the pinned description's own object. A
    /// replacement of the path after the open must not change what runs (a
    /// re-resolution would load the replacement's bytes).
    #[test]
    fn native_fexecve_source_is_the_open_file_not_its_path() {
        let fixture = rootfs_fixture();
        let authority = authority_of(&fixture.dispatcher);
        let open = record(
            fixture.table,
            HostFileOp::Openat,
            FDCWD,
            [carrick_abi::LINUX_O_CLOEXEC, 0, 0, 0],
            b"/lib/libc.so.6",
            0,
        );
        let (fd, _) = fixture.result(Some(&authority), open);
        assert!(fd >= 0, "open: {fd}");
        // Replace the file at that path after the open: a new inode with
        // different bytes takes the name.
        let lower = fixture._rootfs.as_ref().unwrap().path();
        let target = lower.join("usr/lib/libc.so.6");
        let replacement = lower.join("usr/lib/libc.so.6.new");
        std::fs::write(&replacement, b"\x7fELF-REPLACED").unwrap();
        std::fs::rename(&replacement, &target).unwrap();

        let source =
            |fd| super::native_descriptor_exec_source_in(&fixture.owner, fixture.table, fd);
        let bytes = source(fd as i32)
            .expect("the open file's exec source")
            .read_all()
            .unwrap();
        assert_eq!(
            bytes, b"\x7fELF-libc-bytes",
            "fexecve must run the opened file, never the replacement at its path"
        );
        assert_eq!(source(9).map(|_| ()), Err(carrick_abi::LINUX_EBADF));
        assert_eq!(source(-1).map(|_| ()), Err(carrick_abi::LINUX_EBADF));
    }

    /// The ring answers `fstat`/`statx` of its in-zone pipes itself; those
    /// bytes are exactly what the dispatcher reports for its own pipe ends,
    /// because both encode one shared `LinuxStatFields`. The shared inode is
    /// the one the dispatcher has always derived from the pipe's label.
    #[test]
    fn in_zone_pipe_stat_matches_the_dispatchers_pipe_record() {
        let dispatcher = SyscallDispatcher::new();
        let pipe = super::super::fd_table::InMemoryPipeTestFixture::new(1, 4096);
        let fields = carrick_abi::LinuxStatFields::CARRICK_PIPE;
        assert_eq!(
            fields.ino,
            super::super::inode_for_path(std::path::Path::new("pipe:[carrick]")),
        );
        for end in [&pipe.read, &pipe.write] {
            let record = dispatcher
                .fs_view()
                .description_stat_record(end, None)
                .unwrap();
            assert_eq!(
                super::super::format_stat::linux_stat(&record).as_bytes(),
                carrick_abi::LinuxStat::from_fields(&fields).as_bytes(),
            );
            assert_eq!(
                super::super::format_stat::linux_statx(&record).as_bytes(),
                carrick_abi::LinuxStatx::from_fields(&fields).as_bytes(),
            );
        }
    }

    /// One path: the venue's read, pread, lseek and getdents run the
    /// dispatcher's own description cores, so a native process sees exactly
    /// what the dispatcher's own syscalls return for the same file.
    #[test]
    fn native_reads_equal_the_dispatchers_own_syscalls() {
        let mut fixture = rootfs_fixture();
        let authority = authority_of(&fixture.dispatcher);
        let venue_open = |fixture: &Fixture, path: &[u8], flags: u64| {
            fixture
                .result(
                    Some(&authority),
                    record(
                        fixture.table,
                        HostFileOp::Openat,
                        FDCWD,
                        [flags, 0, 0, 0],
                        path,
                        0,
                    ),
                )
                .0 as i32
        };
        let venue = |fixture: &Fixture, op: HostFileOp, fd: i32, args: [u64; 4], cap: usize| {
            fixture.result(None, record(fixture.table, op, fd, args, &[], cap))
        };
        // The dispatcher's own syscalls on its own task, same rootfs.
        const BASE: u64 = 0x4_0000;
        let reporter = crate::compat::CompatReporter::default();
        let own = |fixture: &mut Fixture, nr: u64, args: [u64; 6], path: &[u8]| {
            let mut memory = super::super::outcome::LinearMemory::new(BASE, vec![0u8; 0x2000]);
            memory.bytes[..path.len()].copy_from_slice(path);
            let context = fixture.dispatcher.capture_one_task_context().unwrap();
            let outcome = fixture
                .dispatcher
                .dispatch(
                    &context,
                    crate::dispatch::SyscallRequest::new(nr, crate::compat::SyscallArgs(args)),
                    &mut memory,
                    &reporter,
                )
                .unwrap();
            let value = match outcome {
                DispatchOutcome::Returned { value } => value,
                DispatchOutcome::Errno { errno } => errno.guest_retval(),
                other => panic!("unexpected outcome {other:?}"),
            };
            // Byte results land at BASE + 0x1000 (the `buf` below).
            let len = usize::try_from(value).unwrap_or(0).min(0x1000);
            (value, memory.bytes[0x1000..0x1000 + len].to_vec())
        };
        let (own_fd, _) = own(
            &mut fixture,
            56,
            [FDCWD as u64, BASE, 0, 0, 0, 0],
            b"/lib/libc.so.6\0",
        );
        assert!(own_fd >= 0, "dispatcher openat: {own_fd}");
        let fd = venue_open(&fixture, b"/lib/libc.so.6", 0);
        assert!(fd >= 0, "venue openat: {fd}");
        let buf = BASE + 0x1000;
        let steps: [(HostFileOp, u64, [u64; 4], [u64; 6]); 5] = [
            (
                HostFileOp::Read,
                63,
                [0; 4],
                [own_fd as u64, buf, 4, 0, 0, 0],
            ),
            (
                HostFileOp::Pread,
                67,
                [1, 0, 0, 0],
                [own_fd as u64, buf, 3, 1, 0, 0],
            ),
            (
                HostFileOp::Lseek,
                62,
                [2, 0, 0, 0],
                [own_fd as u64, 2, 0, 0, 0, 0],
            ),
            (
                HostFileOp::Read,
                63,
                [0; 4],
                [own_fd as u64, buf, 64, 0, 0, 0],
            ),
            (
                HostFileOp::Read,
                63,
                [0; 4],
                [own_fd as u64, buf, 64, 0, 0, 0],
            ),
        ];
        for (op, nr, venue_args, own_args) in steps {
            let cap = match op {
                HostFileOp::Lseek => 0,
                _ => own_args[2] as usize,
            };
            let native = venue(&fixture, op, fd, venue_args, cap);
            let mut dispatcher = own(&mut fixture, nr, own_args, b"");
            if op == HostFileOp::Lseek {
                dispatcher.1.clear();
            }
            assert_eq!(native, dispatcher, "{op:?}");
        }

        // getdents64 on a directory: identical record bytes.
        let dir = venue_open(&fixture, b"/usr/lib", carrick_abi::LINUX_O_DIRECTORY);
        let (own_dir, _) = own(
            &mut fixture,
            56,
            [FDCWD as u64, BASE, carrick_abi::LINUX_O_DIRECTORY, 0, 0, 0],
            b"/usr/lib\0",
        );
        let native = venue(&fixture, HostFileOp::Getdents64, dir, [0; 4], 512);
        let dispatcher = own(&mut fixture, 61, [own_dir as u64, buf, 512, 0, 0, 0], b"");
        assert!(native.0 > 0, "a listing: {native:?}");
        assert_eq!(native, dispatcher, "getdents64");
    }

    /// Witness for the authority binding: a relative path resolves against
    /// the CALLER's filesystem context carried in its authority, never the
    /// serving dispatcher's own task.
    #[test]
    fn native_relative_open_resolves_with_the_callers_cwd() {
        let fixture = rootfs_fixture();
        let lower = rootfs();
        let caller = SyscallDispatcher::with_rootfs(
            carrick_vfs::rootfs::RootFs::from_immutable_host_dir(lower.path()).unwrap(),
        );
        caller.set_cwd("/usr/lib");
        let caller_authority = authority_of(&caller);
        let own_authority = authority_of(&fixture.dispatcher);
        let open = || {
            record(
                fixture.table,
                HostFileOp::Openat,
                FDCWD,
                [0; 4],
                b"libc.so.6",
                0,
            )
        };
        assert!(fixture.result(Some(&caller_authority), open()).0 >= 0);
        assert_eq!(
            fixture.result(Some(&own_authority), open()).0,
            carrick_abi::LINUX_ENOENT.guest_retval(),
            "the serving task's cwd (/) is not the caller's"
        );
    }

    #[test]
    fn native_directory_listing_and_unserved_opens() {
        let fixture = rootfs_fixture();
        let authority = authority_of(&fixture.dispatcher);
        let open = |path: &[u8], flags: u64| {
            fixture
                .result(
                    Some(&authority),
                    record(
                        fixture.table,
                        HostFileOp::Openat,
                        FDCWD,
                        [flags, 0, 0, 0],
                        path,
                        0,
                    ),
                )
                .0
        };
        let dir = open(b"/usr", carrick_abi::LINUX_O_DIRECTORY) as i32;
        assert!(dir >= 0);
        let (len, records) = fixture.result(
            None,
            record(
                fixture.table,
                HostFileOp::Getdents64,
                dir,
                [0; 4],
                &[],
                4096,
            ),
        );
        assert!(len > 0);
        let names: Vec<String> = dirent_names(&records);
        assert_eq!(names, [".", "..", "lib"]);
        let (len, _) = fixture.result(
            None,
            record(
                fixture.table,
                HostFileOp::Getdents64,
                dir,
                [0; 4],
                &[],
                4096,
            ),
        );
        assert_eq!(len, 0, "end of directory");
        assert_eq!(
            open(b"/etc/ld.so.cache", carrick_abi::LINUX_O_DIRECTORY),
            carrick_abi::LINUX_ENOTDIR.guest_retval()
        );
        // Write access is served (the open path is the dispatcher's own);
        // a caller-relative synthetic tree is still refused exactly.
        assert!(open(b"/etc/ld.so.cache", carrick_abi::LINUX_O_WRONLY) >= 0);
        let mut proc = record(
            fixture.table,
            HostFileOp::Openat,
            FDCWD,
            [0; 4],
            b"/proc/filesystems",
            0,
        );
        assert_eq!(
            fixture.serve(Some(&authority), &mut proc),
            Err(NativeHostFileRefusal)
        );
    }

    impl Fixture {
        fn venue_open(&self, authority: &CallerAccess, path: &[u8], flags: u64, mode: u64) -> i64 {
            self.result(
                Some(authority),
                record(
                    self.table,
                    HostFileOp::Openat,
                    FDCWD,
                    [flags, mode, 0, 0],
                    path,
                    0,
                ),
            )
            .0
        }
        /// A write from a native caller whose ring stamped an unlimited
        /// `RLIMIT_FSIZE`.
        fn venue_write(&self, fd: i64, bytes: &[u8]) -> i64 {
            self.result(None, self.stamped_write(fd, UNLIMITED, bytes))
                .0
        }
        fn stamped_write(&self, fd: i64, file_size_limit: u64, bytes: &[u8]) -> Vec<u8> {
            record(
                self.table,
                HostFileOp::Write,
                fd as i32,
                [file_size_limit, 0, 0, 0],
                bytes,
                0,
            )
        }
        /// The whole file, read back through a fresh read-only venue open.
        fn venue_contents(&self, authority: &CallerAccess, path: &[u8]) -> Vec<u8> {
            let fd = self.venue_open(authority, path, carrick_abi::LINUX_O_RDONLY, 0);
            assert!(fd >= 0, "reopen {:?}: {fd}", String::from_utf8_lossy(path));
            let (read, bytes) = self.result(
                None,
                record(self.table, HostFileOp::Read, fd as i32, [0; 4], &[], 4096),
            );
            assert!(read >= 0, "read back: {read}");
            bytes
        }
        fn ring_fd(&self) -> fd::TableId {
            fd::TableId::from_raw(fd::RawTableId {
                authority: self.table[0],
                index: self.table[1],
                generation: self.table[2],
            })
        }
    }

    /// The root's own `openat(2)` through its host task.
    fn root_openat(dispatcher: &mut SyscallDispatcher, path: &[u8], flags: u64) -> i64 {
        const BASE: u64 = 0x4_0000;
        let mut memory = super::super::outcome::LinearMemory::new(BASE, vec![0u8; 0x1000]);
        memory.bytes[..path.len()].copy_from_slice(path);
        let context = dispatcher.capture_one_task_context().unwrap();
        let reporter = crate::compat::CompatReporter::default();
        match dispatcher
            .dispatch(
                &context,
                crate::dispatch::SyscallRequest::new(
                    56,
                    crate::compat::SyscallArgs([FDCWD as u64, BASE, flags, 0o644, 0, 0]),
                ),
                &mut memory,
                &reporter,
            )
            .unwrap()
        {
            DispatchOutcome::Returned { value } => value,
            DispatchOutcome::Errno { errno } => errno.guest_retval(),
            other => panic!("unexpected outcome {other:?}"),
        }
    }

    const UNLIMITED: u64 = carrick_abi::LINUX_RLIM_INFINITY;

    const CREATE: u64 =
        carrick_abi::LINUX_O_WRONLY | carrick_abi::LINUX_O_CREAT | carrick_abi::LINUX_O_TRUNC;

    /// `echo x > /tmp/f` in a forked child: create, write, and the bytes
    /// are the file's, through either writable upper.
    #[test]
    fn native_create_write_lands_the_bytes() {
        for upper in [Upper::Memory, Upper::Host] {
            let fixture = writable_fixture(upper);
            let authority = authority_of(&fixture.dispatcher);
            let fd = fixture.venue_open(&authority, b"/tmp/f", CREATE, 0o644);
            assert!(fd >= 0, "{upper:?}: create: {fd}");
            let ring = fixture.owner.region();
            let ring = ring.fd(crate::el1_zone::HostLockWait);
            let (access, _) = ring.getfl(fixture.ring_fd(), fd::Fd(fd as i32)).unwrap();
            assert_eq!(access, fd::AccessMode::WriteOnly, "{upper:?}");
            assert_eq!(fixture.venue_write(fd, b"hello "), 6, "{upper:?}");
            // The description offset advances: the second write follows.
            assert_eq!(fixture.venue_write(fd, b"world\n"), 6, "{upper:?}");
            assert_eq!(
                fixture.venue_contents(&authority, b"/tmp/f"),
                b"hello world\n",
                "{upper:?}"
            );
        }
    }

    /// `: > /dev/null` and `cmd >/dev/null` in a forked child.
    #[test]
    fn native_dev_null_opens_write_only_and_swallows_writes() {
        let fixture = writable_fixture(Upper::Memory);
        let authority = authority_of(&fixture.dispatcher);
        let fd = fixture.venue_open(&authority, b"/dev/null", CREATE, 0o666);
        assert!(fd >= 0, "open /dev/null: {fd}");
        let ring = fixture.owner.region();
        let ring = ring.fd(crate::el1_zone::HostLockWait);
        let (access, _) = ring.getfl(fixture.ring_fd(), fd::Fd(fd as i32)).unwrap();
        assert_eq!(access, fd::AccessMode::WriteOnly);
        assert_eq!(fixture.venue_write(fd, b"discarded"), 9);
    }

    /// `>>`: `O_APPEND` writes land at the end, whatever the offset.
    #[test]
    fn native_append_appends() {
        for upper in [Upper::Memory, Upper::Host] {
            let fixture = writable_fixture(upper);
            let authority = authority_of(&fixture.dispatcher);
            let fd = fixture.venue_open(&authority, b"/tmp/log", CREATE, 0o644);
            assert_eq!(fixture.venue_write(fd, b"abc"), 3, "{upper:?}");
            let append = carrick_abi::LINUX_O_WRONLY | carrick_abi::LINUX_O_APPEND;
            let fd = fixture.venue_open(&authority, b"/tmp/log", append, 0);
            assert!(fd >= 0, "{upper:?}: append open: {fd}");
            let ring = fixture.owner.region();
            let ring = ring.fd(crate::el1_zone::HostLockWait);
            let (_, status) = ring.getfl(fixture.ring_fd(), fd::Fd(fd as i32)).unwrap();
            assert!(status.append, "{upper:?}: F_GETFL reports O_APPEND");
            assert_eq!(fixture.venue_write(fd, b"de"), 2, "{upper:?}");
            assert_eq!(
                fixture.venue_contents(&authority, b"/tmp/log"),
                b"abcde",
                "{upper:?}"
            );
        }
    }

    /// The root's own `write(2)` through an `O_APPEND` descriptor of an
    /// in-memory upper file lands at the end, as Linux's does: the write
    /// core the venue shares with the root.
    #[test]
    fn root_append_write_lands_at_the_end_of_an_in_memory_file() {
        let mut fixture = writable_fixture(Upper::Memory);
        let write = |dispatcher: &mut SyscallDispatcher, fd: i64, bytes: &[u8]| {
            const BASE: u64 = 0x4_0000;
            let mut memory = super::super::outcome::LinearMemory::new(BASE, bytes.to_vec());
            let context = dispatcher.capture_one_task_context().unwrap();
            let reporter = crate::compat::CompatReporter::default();
            let args = [fd as u64, BASE, bytes.len() as u64, 0, 0, 0];
            dispatcher
                .dispatch(
                    &context,
                    crate::dispatch::SyscallRequest::new(64, crate::compat::SyscallArgs(args)),
                    &mut memory,
                    &reporter,
                )
                .unwrap()
        };
        let fd = root_openat(&mut fixture.dispatcher, b"/tmp/log\0", CREATE);
        assert_eq!(
            write(&mut fixture.dispatcher, fd, b"abc"),
            DispatchOutcome::Returned { value: 3 }
        );
        let append = carrick_abi::LINUX_O_WRONLY | carrick_abi::LINUX_O_APPEND;
        let fd = root_openat(&mut fixture.dispatcher, b"/tmp/log\0", append);
        assert_eq!(
            write(&mut fixture.dispatcher, fd, b"de"),
            DispatchOutcome::Returned { value: 2 }
        );
        let authority = authority_of(&fixture.dispatcher);
        assert_eq!(fixture.venue_contents(&authority, b"/tmp/log"), b"abcde");
    }

    /// `O_TRUNC` of an existing lower file truncates it; `O_CREAT|O_EXCL`
    /// of an existing file is EEXIST (17).
    #[test]
    fn native_truncate_existing_and_exclusive_create() {
        for upper in [Upper::Memory, Upper::Host] {
            let fixture = writable_fixture(upper);
            let authority = authority_of(&fixture.dispatcher);
            assert_eq!(
                fixture.venue_contents(&authority, b"/etc/ld.so.cache"),
                b"cache"
            );
            let trunc = carrick_abi::LINUX_O_WRONLY | carrick_abi::LINUX_O_TRUNC;
            let fd = fixture.venue_open(&authority, b"/etc/ld.so.cache", trunc, 0);
            assert!(fd >= 0, "{upper:?}: truncate: {fd}");
            assert!(
                fixture
                    .venue_contents(&authority, b"/etc/ld.so.cache")
                    .is_empty(),
                "{upper:?}: truncated"
            );
            let excl = CREATE | carrick_abi::LINUX_O_EXCL;
            let exists = fixture.venue_open(&authority, b"/etc/ld.so.cache", excl, 0o644);
            assert_eq!(exists, -17, "{upper:?}: EEXIST");
            assert_eq!(exists, carrick_abi::LINUX_EEXIST.guest_retval());
        }
    }

    /// The root's own syscall `nr` through its host task, with `path` (if
    /// any) staged at the first argument the caller points at `BASE`.
    fn root_syscall(
        dispatcher: &mut SyscallDispatcher,
        nr: u64,
        args: [u64; 6],
        path: &[u8],
    ) -> i64 {
        const BASE: u64 = 0x4_0000;
        let mut memory = super::super::outcome::LinearMemory::new(BASE, vec![0u8; 0x1000]);
        memory.bytes[..path.len()].copy_from_slice(path);
        let context = dispatcher.capture_one_task_context().unwrap();
        let reporter = crate::compat::CompatReporter::default();
        match dispatcher
            .dispatch(
                &context,
                crate::dispatch::SyscallRequest::new(nr, crate::compat::SyscallArgs(args)),
                &mut memory,
                &reporter,
            )
            .unwrap()
        {
            DispatchOutcome::Returned { value } => value,
            DispatchOutcome::Errno { errno } => errno.guest_retval(),
            other => panic!("unexpected outcome {other:?}"),
        }
    }

    /// A watch anywhere in the run (here the root's inotify watch on
    /// `/etc`) leaves a native child's read-only opens served, as before
    /// write opens were: the open and its reads work, without the events a
    /// host task's open would raise. A write or create open, which no
    /// earlier venue served, stays refused while a watch exists.
    #[test]
    fn native_read_only_open_is_served_while_a_watch_exists() {
        let mut fixture = writable_fixture(Upper::Memory);
        let authority = authority_of(&fixture.dispatcher);
        let inotify = root_syscall(&mut fixture.dispatcher, 26, [0; 6], &[]);
        assert!(inotify >= 0, "inotify_init1: {inotify}");
        const BASE: u64 = 0x4_0000;
        let watch = root_syscall(
            &mut fixture.dispatcher,
            27,
            [inotify as u64, BASE, 0xfff, 0, 0, 0],
            b"/etc\0",
        );
        assert!(watch >= 0, "inotify_add_watch: {watch}");
        assert!(!fixture.dispatcher.fs.inotify_registry.is_empty());

        assert_eq!(
            fixture.venue_contents(&authority, b"/etc/ld.so.cache"),
            b"cache"
        );
        let mut create = record(
            fixture.table,
            HostFileOp::Openat,
            FDCWD,
            [CREATE, 0o644, 0, 0],
            b"/etc/new",
            0,
        );
        assert_eq!(
            fixture.serve(Some(&authority), &mut create),
            Err(NativeHostFileRefusal),
            "a create in the watched directory would owe IN_CREATE"
        );
        let mut truncate = record(
            fixture.table,
            HostFileOp::Openat,
            FDCWD,
            [
                carrick_abi::LINUX_O_WRONLY | carrick_abi::LINUX_O_TRUNC,
                0,
                0,
                0,
            ],
            b"/etc/ld.so.cache",
            0,
        );
        assert_eq!(
            fixture.serve(Some(&authority), &mut truncate),
            Err(NativeHostFileRefusal),
            "a truncate of a watched file would owe IN_MODIFY"
        );
        // A path no watch covers is created and written as without one.
        let fd = fixture.venue_open(&authority, b"/tmp/unwatched", CREATE, 0o644);
        assert!(fd >= 0, "uncovered create: {fd}");
        assert_eq!(fixture.venue_write(fd, b"ok"), 2);
        assert_eq!(fixture.venue_contents(&authority, b"/tmp/unwatched"), b"ok");
    }

    /// The writer's own `RLIMIT_FSIZE` comes from its ring's stamp, never
    /// the serving dispatcher's (unlimited here): a finite or unstamped
    /// limit refuses a regular-file write before any byte lands; an
    /// unlimited one is served. Limits never apply to stdio or a device.
    #[test]
    fn native_regular_file_writes_need_the_writers_unlimited_file_size() {
        for upper in [Upper::Memory, Upper::Host] {
            let fixture = writable_fixture(upper);
            let authority = authority_of(&fixture.dispatcher);
            let fd = fixture.venue_open(&authority, b"/tmp/limited", CREATE, 0o644);
            for limit in [4096, 0] {
                let mut write = fixture.stamped_write(fd, limit, b"bytes");
                assert_eq!(
                    fixture.serve(None, &mut write),
                    Err(NativeHostFileRefusal),
                    "{upper:?}: limit {limit}"
                );
            }
            assert!(
                fixture
                    .venue_contents(&authority, b"/tmp/limited")
                    .is_empty(),
                "{upper:?}: no byte landed"
            );
            assert_eq!(fixture.venue_write(fd, b"bytes"), 5, "{upper:?}");
            assert_eq!(
                fixture.venue_contents(&authority, b"/tmp/limited"),
                b"bytes"
            );

            let null = fixture.venue_open(&authority, b"/dev/null", CREATE, 0);
            let (written, _) = fixture.result(None, fixture.stamped_write(null, 0, b"x"));
            assert_eq!(written, 1, "{upper:?}: a device has no file-size limit");
            let (written, _) = fixture.result(None, fixture.stamped_write(1, 0, b"out"));
            assert_eq!(written, 3, "{upper:?}: nor has stdout");
        }
    }

    /// `writev(2)` through an `O_APPEND` descriptor of an in-memory upper
    /// file (musl stdio's `>>`) lands at the end, through the same write
    /// core as `write(2)`.
    #[test]
    fn root_append_writev_lands_at_the_end_of_an_in_memory_file() {
        let mut fixture = writable_fixture(Upper::Memory);
        const BASE: u64 = 0x4_0000;
        let writev = |dispatcher: &mut SyscallDispatcher, fd: i64, bytes: &[u8]| {
            let mut memory = vec![0u8; 0x1000];
            memory[..8].copy_from_slice(&(BASE + 0x100).to_le_bytes());
            memory[8..16].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
            memory[0x100..0x100 + bytes.len()].copy_from_slice(bytes);
            let mut memory = super::super::outcome::LinearMemory::new(BASE, memory);
            let context = dispatcher.capture_one_task_context().unwrap();
            let reporter = crate::compat::CompatReporter::default();
            dispatcher
                .dispatch(
                    &context,
                    crate::dispatch::SyscallRequest::new(
                        66,
                        crate::compat::SyscallArgs([fd as u64, BASE, 1, 0, 0, 0]),
                    ),
                    &mut memory,
                    &reporter,
                )
                .unwrap()
        };
        let fd = root_openat(&mut fixture.dispatcher, b"/tmp/log\0", CREATE);
        assert_eq!(
            writev(&mut fixture.dispatcher, fd, b"abc"),
            DispatchOutcome::Returned { value: 3 }
        );
        let append = carrick_abi::LINUX_O_WRONLY | carrick_abi::LINUX_O_APPEND;
        let fd = root_openat(&mut fixture.dispatcher, b"/tmp/log\0", append);
        assert_eq!(
            writev(&mut fixture.dispatcher, fd, b"de"),
            DispatchOutcome::Returned { value: 2 }
        );
        let authority = authority_of(&fixture.dispatcher);
        assert_eq!(fixture.venue_contents(&authority, b"/tmp/log"), b"abcde");
    }

    /// `cmd < /dev/null`: a venue-opened synthetic device reads through the
    /// root's read core: `/dev/null` is at end of file, `/dev/zero` fills.
    #[test]
    fn native_synthetic_device_reads() {
        let fixture = writable_fixture(Upper::Memory);
        let authority = authority_of(&fixture.dispatcher);
        let rdonly = carrick_abi::LINUX_O_RDONLY;
        let null = fixture.venue_open(&authority, b"/dev/null", rdonly, 0) as i32;
        assert!(null >= 0, "open /dev/null: {null}");
        let read = |fd: i32, op: HostFileOp, args: [u64; 4]| {
            fixture.result(None, record(fixture.table, op, fd, args, &[], 8))
        };
        assert_eq!(read(null, HostFileOp::Read, [0; 4]), (0, Vec::new()));
        assert_eq!(read(null, HostFileOp::Pread, [0; 4]), (0, Vec::new()));
        let zero = fixture.venue_open(&authority, b"/dev/zero", rdonly, 0) as i32;
        assert!(zero >= 0, "open /dev/zero: {zero}");
        assert_eq!(read(zero, HostFileOp::Read, [0; 4]), (8, vec![0; 8]));
        assert_eq!(read(zero, HostFileOp::Pread, [4, 0, 0, 0]), (8, vec![0; 8]));
    }

    /// What only a host task's open may hold stays refused for a native
    /// caller, before the mount acts: a terminal end (no pty is allocated)
    /// and the opener's own `/proc` view. Mount-served opens a native caller
    /// may hold still meet `O_DIRECTORY` before a descriptor exists.
    #[test]
    fn native_opens_that_need_a_host_task_stay_refused() {
        let fixture = writable_fixture(Upper::Memory);
        let authority = authority_of(&fixture.dispatcher);
        let refused = |path: &[u8], flags: u64| {
            let mut open = record(
                fixture.table,
                HostFileOp::Openat,
                FDCWD,
                [flags, 0, 0, 0],
                path,
                0,
            );
            assert_eq!(
                fixture.serve(Some(&authority), &mut open),
                Err(NativeHostFileRefusal),
                "{}",
                String::from_utf8_lossy(path)
            );
        };
        let rdwr = carrick_abi::LINUX_O_RDWR;
        refused(b"/dev/ptmx", rdwr);
        refused(b"/dev/pts/ptmx", rdwr);
        refused(b"/dev/tty", rdwr);
        refused(b"/proc/self/status", carrick_abi::LINUX_O_RDONLY);
        refused(b"/sys/kernel/mm", carrick_abi::LINUX_O_RDONLY);
        assert_eq!(
            fixture.dispatcher.fs.pty_table.lock().slave_name(0),
            None,
            "no pty was allocated for a refused open"
        );
        let directory = carrick_abi::LINUX_O_RDONLY | carrick_abi::LINUX_O_DIRECTORY;
        assert!(fixture.venue_open(&authority, b"/dev", directory, 0) >= 0);
        assert_eq!(
            fixture.venue_open(&authority, b"/dev/null", directory, 0),
            carrick_abi::LINUX_ENOTDIR.guest_retval()
        );
    }

    /// Two live processes: the root, opening through its host task and host
    /// fd table, and a native fork child whose descriptors live in its own
    /// ring table. Each opens through its own path. The child's descriptor
    /// lands only in its ring table: nothing is reserved or installed in
    /// the root's host table, whose numbering stays the root's alone, and
    /// closing the child's descriptor releases its description without
    /// touching the root's.
    #[test]
    fn native_open_lands_only_in_the_callers_ring_table() {
        let lower = rootfs();
        let mut root = SyscallDispatcher::with_rootfs(
            carrick_vfs::rootfs::RootFs::from_immutable_host_dir(lower.path()).unwrap(),
        );
        // The child's own ring table (a fork child's table is its own copy).
        let child = SyscallDispatcher::new();
        let owner = Arc::new(HostIpc::new(1 << 20).unwrap());
        let child_files = child
            .capture_one_task_context()
            .unwrap()
            .resources()
            .files();
        let map = map();
        child_files.publish_ipc(Arc::clone(&owner), map).unwrap();
        let raw = map.lookup(child_files.id().raw()).unwrap();
        let table = fd::TableId::from_raw(fd::RawTableId {
            authority: raw.authority,
            index: raw.index,
            generation: raw.generation,
        });
        let authority = authority_of(&root);
        let root_files = root.capture_one_task_context().unwrap().resources().files();
        let root_slots = |files: &Arc<crate::kernel::FileTable>| {
            (0..8)
                .map(|fd| {
                    files
                        .slot(FileSlotNumber::for_open_fd(fd).unwrap())
                        .is_some()
                })
                .collect::<Vec<_>>()
        };
        let before = root_slots(&root_files);

        let mut open = record(
            [raw.authority, raw.index, raw.generation],
            HostFileOp::Openat,
            FDCWD,
            [CREATE, 0o644, 0, 0],
            b"/tmp/child",
            0,
        );
        authority.stamp(&mut open);
        root.serve_native_host_file_in(&owner, &mut open).unwrap();
        let native = host_file::reply(&open).unwrap().result as i32;
        assert_eq!(native, 3, "the child's lowest free ring descriptor");
        let region = owner.region();
        let ring = region.fd(crate::el1_zone::HostLockWait);
        assert_eq!(ring.getfd(table, fd::Fd(native)), Ok(false));
        assert_eq!(
            root_slots(&root_files),
            before,
            "nothing installed in the root's host table"
        );

        // The root's next open still gets its own lowest free descriptor:
        // nothing was reserved there either.
        assert_eq!(root_openat(&mut root, b"/tmp/root\0", CREATE), 3);
        let description = owner
            .with_pinned_host_resource(table, fd::Fd(native), |resource| {
                resource
                    .downcast_ref::<NativeOpenFile>()
                    .map(|file| Arc::clone(&file.description))
            })
            .unwrap()
            .expect("a venue-opened description");
        assert_eq!(
            description.fd_ref_count(),
            1,
            "the ring descriptor's reference"
        );
        let root_description = root_files
            .slot(FileSlotNumber::for_open_fd(3).unwrap())
            .unwrap();
        assert!(
            !Arc::ptr_eq(&root_description.description(), &description),
            "two descriptions, one per process"
        );

        // Closing the child's descriptor releases its description only.
        let retained = owner.retained_host_resources();
        let released = ring.close(table, fd::Fd(native)).unwrap().unwrap();
        owner.release(released.backing).unwrap();
        assert_eq!(owner.retained_host_resources(), retained - 1);
        assert_eq!(description.fd_ref_count(), 0, "release_fd_ref ran");
        assert_eq!(root_description.description().fd_ref_count(), 1);
        assert_eq!(
            root_openat(&mut root, b"/tmp/root2\0", CREATE),
            4,
            "the child's close freed nothing in the root's table"
        );
    }

    /// #1392: a native caller's path resolves under its own cwd, carried
    /// by value, whatever the host task's live cwd or credentials are now.
    /// Two callers of one tree with separate cwds create files side by side,
    /// and the host task's later chdir changes neither.
    #[test]
    fn native_paths_resolve_under_each_callers_own_cwd() {
        let fixture = rootfs_fixture();
        let created = |authority: &CallerAccess, path: &[u8]| {
            fixture.venue_open(authority, path, CREATE, 0o644)
        };
        let base = authority_of(&fixture.dispatcher);
        let tmp = base.in_cwd("/tmp");
        let etc = base.in_cwd("/usr");
        // The host task moves after the children were "forked".
        fixture.dispatcher.set_cwd("/etc");
        assert!(created(&tmp, b"made-in-tmp") >= 0);
        assert!(created(&etc, b"made-in-usr") >= 0);
        let root = authority_of(&fixture.dispatcher).in_cwd("/");
        assert!(
            fixture.venue_open(&root, b"/tmp/made-in-tmp", carrick_abi::LINUX_O_RDONLY, 0) >= 0
        );
        assert!(
            fixture.venue_open(&root, b"/usr/made-in-usr", carrick_abi::LINUX_O_RDONLY, 0) >= 0
        );
        assert_eq!(
            fixture.venue_open(&root, b"/etc/made-in-tmp", carrick_abi::LINUX_O_RDONLY, 0),
            carrick_abi::LINUX_ENOENT.guest_retval(),
            "the host task's cwd was never the base"
        );

        // A path record without its caller's access context is refused.
        let mut bare = record(fixture.table, HostFileOp::Openat, FDCWD, [0; 4], b"/tmp", 0);
        assert_eq!(fixture.serve(None, &mut bare), Err(NativeHostFileRefusal));
    }

    /// #1392: a caller's installed group list, even an empty one
    /// (`setgroups(0, NULL)`), is its complete set; only a caller that never
    /// ran `setgroups` gets the launch identity's `/etc/group` groups.
    #[test]
    fn native_access_keeps_an_installed_empty_group_list() {
        let fixture = rootfs_fixture();
        let authority = |groups: Option<&[u32]>| {
            let mut bytes = Vec::new();
            AccessContext::encode_into(
                &mut bytes,
                carrick_core_abi::host_file::AccessIds {
                    ruid: 1000,
                    euid: 1000,
                    suid: 1000,
                    fsuid: 1000,
                    rgid: 1000,
                    egid: 1000,
                    sgid: 1000,
                    fsgid: 1000,
                },
                0o022,
                groups,
                b"/",
                None,
            )
            .unwrap();
            let (context, _) = AccessContext::decode(&bytes).unwrap();
            fixture
                .dispatcher
                .native_access_authority(&context)
                .unwrap()
                .credentials
        };
        assert_eq!(
            authority(Some(&[])).supplementary_groups_override(),
            Some(&[][..])
        );
        assert_eq!(
            authority(Some(&[7])).supplementary_groups_override(),
            Some(&[carrick_abi::NsGid::new(7)][..])
        );
        assert_eq!(authority(None).supplementary_groups_override(), None);
        assert_eq!(authority(None).fsuid, carrick_abi::NsUid::new(1000));
    }

    /// Review #1409 (3): `O_NOATIME` is the owner's or `CAP_FOWNER`'s, which
    /// the carrier models from the fsuid (`dac_identity`), never the euid.
    /// A split identity tells them apart.
    #[test]
    fn native_noatime_open_is_keyed_on_the_fsuid() {
        // A host upper reports the file's real owner (the test's host uid).
        let fixture = writable_fixture(Upper::Host);
        let root = authority_of(&fixture.dispatcher).in_cwd("/");
        assert!(fixture.venue_open(&root, b"/tmp/noatime", CREATE, 0o644) >= 0);
        let split = |euid: u32, fsuid: u32| {
            let mut access = root.clone();
            access.credentials = Arc::new(crate::kernel::Credentials::from_values(
                crate::kernel::CredentialsValues {
                    id: fixture
                        .dispatcher
                        .kernel_binding
                        .read()
                        .kernel()
                        .object_ids()
                        .credentials_id()
                        .unwrap(),
                    ruid: carrick_abi::NsUid::new(euid),
                    euid: carrick_abi::NsUid::new(euid),
                    suid: carrick_abi::NsUid::new(euid),
                    rgid: carrick_abi::NsGid::ROOT,
                    egid: carrick_abi::NsGid::ROOT,
                    sgid: carrick_abi::NsGid::ROOT,
                    fsuid: carrick_abi::NsUid::new(fsuid),
                    fsgid: carrick_abi::NsGid::ROOT,
                    umask: 0o022,
                },
            ));
            fixture.venue_open(
                &access,
                b"/tmp/noatime",
                carrick_abi::LINUX_O_RDONLY | LinuxOpenFlags::NOATIME.bits(),
                0,
            )
        };
        assert_eq!(
            split(0, 4321),
            carrick_abi::LINUX_EPERM.guest_retval(),
            "a non-owner fsuid has no CAP_FOWNER, whatever the euid"
        );
        assert!(split(4321, 0) >= 0, "fsuid 0 holds CAP_FOWNER");
    }

    /// #1392: the chdir lookup (a `Newfstatat` with a name area) answers the
    /// directory's canonical spelling, ENOTDIR for a file and ENOENT for a
    /// missing name.
    #[test]
    fn native_chdir_lookup_names_the_canonical_directory() {
        let fixture = rootfs_fixture();
        let base = authority_of(&fixture.dispatcher).in_cwd("/usr");
        let lookup = |authority: &CallerAccess, path: &[u8]| {
            fixture.result(
                Some(authority),
                record(
                    fixture.table,
                    HostFileOp::Newfstatat,
                    FDCWD,
                    [0; 4],
                    path,
                    carrick_personality_linux::native_host_file::LINUX_STAT_BYTES + 4096,
                ),
            )
        };
        let (result, output) = lookup(&base, b"../tmp/./");
        assert_eq!(result, 0);
        let name = &output[carrick_personality_linux::native_host_file::LINUX_STAT_BYTES..];
        assert_eq!(name, b"/tmp");
        assert!(fixture.venue_open(&base, b"/tmp/plain", CREATE, 0o644) >= 0);
        assert_eq!(
            lookup(&base, b"/tmp/plain").0,
            carrick_abi::LINUX_ENOTDIR.guest_retval()
        );
        assert_eq!(
            lookup(&base, b"/nonexistent").0,
            carrick_abi::LINUX_ENOENT.guest_retval()
        );
    }

    fn published_private_source(
        fixture: &mut Fixture,
        path: &str,
    ) -> Arc<dyn carrick_hal::fork_stock::HostBackingRetention> {
        let context = fixture.dispatcher.capture_one_task_context().unwrap();
        let mut memory =
            super::super::outcome::LinearMemory::new(0x4000, [path.as_bytes(), &[0]].concat());
        let opened = fixture
            .dispatcher
            .dispatch(
                &context,
                super::super::SyscallRequest::new(
                    56,
                    crate::compat::SyscallArgs::from([(-100_i64) as u64, 0x4000, 0, 0, 0, 0]),
                ),
                &mut memory,
                &crate::compat::CompatReporter::default(),
            )
            .unwrap();
        let DispatchOutcome::Returned { value: number } = opened else {
            panic!("host open: {opened:?}");
        };
        let slot = context
            .resources()
            .files()
            .slot(FileSlotNumber::for_open_fd(number as i32).unwrap())
            .unwrap();
        let original = Arc::downgrade(&slot.description());
        drop(slot);
        let mut map = record(
            fixture.table,
            HostFileOp::MapPrivate,
            number as i32,
            [0; 4],
            &[],
            carrick_core_abi::host_file::MapSourceReply::BYTES,
        );
        let source = fixture
            .dispatcher
            .serve_native_host_file_in(&fixture.owner, &mut map)
            .unwrap()
            .retained_source
            .expect("published physical source");
        let closed = fixture
            .dispatcher
            .dispatch(
                &context,
                super::super::SyscallRequest::new(
                    57,
                    crate::compat::SyscallArgs::from([number as u64, 0, 0, 0, 0, 0]),
                ),
                &mut memory,
                &crate::compat::CompatReporter::default(),
            )
            .unwrap();
        assert!(matches!(closed, DispatchOutcome::Returned { value: 0 }));
        assert!(
            original.upgrade().is_none(),
            "mapping does not own the publication description"
        );
        source
    }

    #[test]
    fn published_private_map_source_survives_host_close_without_a_publication_cycle() {
        use carrick_hal::fork_stock::HostBackingRead;
        let source = published_private_source(&mut rootfs_fixture(), "/lib/libc.so.6");
        let bytes = source
            .read(HostBackingRead::new(source.identity(), 4096).unwrap())
            .unwrap();
        assert_eq!(&bytes[..15], b"\x7fELF-libc-bytes");
        assert!(bytes[15..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn published_private_source_rechecks_eof_after_truncation() {
        use carrick_hal::fork_stock::HostBackingRead;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source");
        std::fs::write(&path, vec![0x41; 4097]).unwrap();
        let mut dispatcher = SyscallDispatcher::default();
        dispatcher.set_fs_backend(Box::new(
            carrick_vfs::fs_backend::HostFsBackend::from_path(std::path::Path::new("/")).unwrap(),
        ));
        let mut fixture = fixture_with(dispatcher, None);
        let source = published_private_source(&mut fixture, path.to_str().unwrap());
        let second_page =
            HostBackingRead::new(source.identity().advance(4096).unwrap(), 4096).unwrap();
        let bytes = source.read(second_page).unwrap();
        assert_eq!(bytes[0], 0x41);
        assert!(bytes[1..].iter().all(|byte| *byte == 0));
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(4096)
            .unwrap();
        assert_eq!(
            source.read(second_page),
            Err(carrick_hal::fork_stock::HostBackingReadError::Inaccessible),
            "no supply past the new EOF"
        );
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(0)
            .unwrap();
        assert_eq!(
            source.read(HostBackingRead::new(source.identity(), 4096).unwrap()),
            Err(carrick_hal::fork_stock::HostBackingReadError::Inaccessible),
        );
    }

    #[test]
    fn native_private_map_source_reads_the_opened_file() {
        use carrick_hal::fork_stock::HostBackingRead;
        let fixture = rootfs_fixture();
        let authority = authority_of(&fixture.dispatcher);
        let mut open = record(
            fixture.table,
            HostFileOp::Openat,
            FDCWD,
            [0; 4],
            b"/lib/libc.so.6",
            0,
        );
        fixture.serve(Some(&authority), &mut open).unwrap();
        let fd = host_file::reply(&open).unwrap().result as i32;
        let mut map = record(
            fixture.table,
            HostFileOp::MapPrivate,
            fd,
            [0; 4],
            &[],
            carrick_core_abi::host_file::MapSourceReply::BYTES,
        );
        let served = fixture
            .dispatcher
            .serve_native_host_file_in(&fixture.owner, &mut map)
            .unwrap();
        let source = served
            .retained_source
            .expect("a mapping retains its source");
        let reply = host_file::reply(&map).unwrap();
        assert_eq!(reply.result, 0);
        let named = carrick_core_abi::host_file::MapSourceReply::decode(reply.output).unwrap();
        let identity = source.identity();
        assert_eq!(
            (named.handle, named.generation),
            (identity.handle(), identity.generation())
        );
        let bytes = source
            .read(HostBackingRead::new(identity.advance(4).unwrap(), 4096).unwrap())
            .unwrap();
        // The file's bytes at offset 4, then the zero tail of the last page
        // within EOF's page (Linux zero-fills a partial final page).
        assert_eq!(&bytes[..11], b"-libc-bytes", "file bytes at offset 4");
        assert!(bytes[11..].iter().all(|byte| *byte == 0), "zero page tail");

        // A second mapping of the same description gets its own source, so
        // retiring one mapping's source never drops the other's.
        let mut again = record(
            fixture.table,
            HostFileOp::MapPrivate,
            fd,
            [0; 4],
            &[],
            carrick_core_abi::host_file::MapSourceReply::BYTES,
        );
        let second = fixture
            .dispatcher
            .serve_native_host_file_in(&fixture.owner, &mut again)
            .unwrap()
            .retained_source
            .expect("a second mapping retains a source");
        assert_ne!(
            second.identity().handle(),
            identity.handle(),
            "each private mapping owns an exclusive source"
        );

        // A directory has no mmap operation; stdio is not a mapping source.
        let mut dir = record(
            fixture.table,
            HostFileOp::Openat,
            FDCWD,
            [carrick_abi::LINUX_O_DIRECTORY, 0, 0, 0],
            b"/usr",
            0,
        );
        fixture.serve(Some(&authority), &mut dir).unwrap();
        let dir = host_file::reply(&dir).unwrap().result as i32;
        let map_dir = record(
            fixture.table,
            HostFileOp::MapPrivate,
            dir,
            [0; 4],
            &[],
            carrick_core_abi::host_file::MapSourceReply::BYTES,
        );
        assert_eq!(
            fixture.result(None, map_dir).0,
            carrick_abi::LINUX_ENODEV.guest_retval()
        );
        let mut map_stdio = record(
            fixture.table,
            HostFileOp::MapPrivate,
            1,
            [0; 4],
            &[],
            carrick_core_abi::host_file::MapSourceReply::BYTES,
        );
        assert_eq!(
            fixture.serve(None, &mut map_stdio),
            Err(NativeHostFileRefusal)
        );
    }

    fn dirent_names(records: &[u8]) -> Vec<String> {
        let mut names = Vec::new();
        let mut at = 0;
        while at + 19 <= records.len() {
            let reclen = u16::from_le_bytes([records[at + 16], records[at + 17]]) as usize;
            let name = &records[at + 19..at + reclen];
            let end = name.iter().position(|b| *b == 0).unwrap_or(name.len());
            names.push(String::from_utf8_lossy(&name[..end]).into_owned());
            at += reclen;
        }
        names
    }
}
