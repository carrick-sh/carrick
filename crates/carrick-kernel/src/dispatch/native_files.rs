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
//! Slice 1 serves the run's implicit stdio streams (write and fstat); other
//! host resources are refused exactly (counted ENOSYS in the ring).
use std::sync::Arc;

use carrick_abi::{LINUX_AT_FDCWD, LinuxOpenFlags};
use carrick_core_abi::host_file::{HostFileHeader, HostFileOp, HostFileRequestView};
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
    PipePair([fd::Fd; 2], [fd::BackingToken; 2]),
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

impl SyscallDispatcher {
    /// Serve one ring-staged host-file record in place for a native process
    /// of this run. A descriptor is resolved and pinned in the caller's own
    /// ring table now, as Linux resolves it for an in-progress call. A path
    /// resolves under `authority` (the caller's credentials and filesystem
    /// context); no host task, fd table or credential of this dispatcher's
    /// task is consulted.
    pub fn serve_native_host_file(
        &self,
        authority: Option<&NativeFsAuthority>,
        record: &mut [u8],
    ) -> Result<NativeHostFileServed, NativeHostFileRefusal> {
        let Some(owner) = self.kernel_binding.read().kernel().existing_ipc() else {
            return Err(NativeHostFileRefusal);
        };
        self.serve_native_host_file_in(&owner, authority, record)
    }

    fn serve_native_host_file_in(
        &self,
        owner: &Arc<HostIpc>,
        authority: Option<&NativeFsAuthority>,
        record: &mut [u8],
    ) -> Result<NativeHostFileServed, NativeHostFileRefusal> {
        let mut view = HostFileRequestView::parse(record).map_err(|_| NativeHostFileRefusal)?;
        let header = view.header();
        let table = fd::TableId::from_raw(fd::RawTableId {
            authority: header.table[0],
            index: header.table[1],
            generation: header.table[2],
        });
        let served = if header.op == HostFileOp::Pipe2 {
            if !view.input().is_empty() || view.output_capacity() != 8 {
                return Err(NativeHostFileRefusal);
            }
            self.serve_native_pipe(owner, table, header.args[0])
        } else if header.op.resolves_path() {
            let authority = authority.ok_or(NativeHostFileRefusal)?;
            // Carrick's VFS names paths as UTF-8; any other byte string is
            // not served rather than altered.
            let path = std::str::from_utf8(view.input()).map_err(|_| NativeHostFileRefusal)?;
            super::resources::with_native_fs_scope(authority, || {
                self.serve_native_path(owner, table, header, path)
            })
            .ok_or(NativeHostFileRefusal)?
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
            Served::PipePair(pair, backings) => {
                let mut args = header.args;
                args[1] = backings[0].0;
                args[2] = backings[1].0;
                view.set_args(args);
                let mut output = Vec::with_capacity(8);
                for number in pair {
                    output.extend_from_slice(&number.0.to_le_bytes());
                }
                (0, output, None)
            }
            Served::Reply(result, output) => (result, output, None),
            Served::Source(source, reply) => (0, reply.encode().to_vec(), Some(source)),
            Served::Refused => return Err(NativeHostFileRefusal),
        };
        view.reply(result, &output)
            .map_err(|_| NativeHostFileRefusal)?;
        Ok(NativeHostFileServed { retained_source })
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
            | HostFileOp::Pipe2 => Served::Refused,
        }
    }

    fn serve_native_pipe(&self, owner: &Arc<HostIpc>, table: fd::TableId, flags: u64) -> Served {
        let (pipe, _pair) = match self.fs_view().create_pipe_pair(Arc::clone(owner), flags) {
            Ok(pair) => pair,
            Err(errno) => return Served::errno(errno),
        };
        match pipe.install_native_pair(table, flags & carrick_abi::LINUX_O_CLOEXEC != 0) {
            Ok(pair) => Served::PipePair(pair, pipe.native_pair_backings()),
            Err(InstallHostDescriptionError::TooManyFiles) => {
                Served::errno(carrick_abi::LINUX_EMFILE)
            }
            Err(InstallHostDescriptionError::FileTableFull) => {
                Served::errno(carrick_abi::LINUX_ENFILE)
            }
            Err(InstallHostDescriptionError::NoMemory) => Served::errno(carrick_abi::LINUX_ENOMEM),
            Err(InstallHostDescriptionError::Unavailable) => Served::Refused,
        }
    }

    fn serve_native_path(
        &self,
        owner: &Arc<HostIpc>,
        table: fd::TableId,
        header: HostFileHeader,
        path: &str,
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
        let Some(reference) = description.retain_mapping() else {
            return Served::errno(carrick_abi::LINUX_EBADF);
        };
        match self
            .mem()
            .lock()
            .retain_native_private_source(reference, label)
        {
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
        let context = dispatcher.capture_one_task_context().unwrap();
        let owner = Arc::new(HostIpc::new(1 << 20).unwrap());
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

    /// A process's filesystem authority as the capability captures it.
    fn authority_of(dispatcher: &SyscallDispatcher) -> NativeFsAuthority {
        let context = dispatcher.capture_one_task_context().unwrap();
        NativeFsAuthority::new(
            context.resources().credentials(),
            context.resources().fs_context(),
        )
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
            authority: Option<&NativeFsAuthority>,
            bytes: &mut [u8],
        ) -> Result<(), NativeHostFileRefusal> {
            self.dispatcher
                .serve_native_host_file_in(&self.owner, authority, bytes)
                .map(|_| ())
        }
        fn result(
            &self,
            authority: Option<&NativeFsAuthority>,
            mut bytes: Vec<u8>,
        ) -> (i64, Vec<u8>) {
            self.serve(authority, &mut bytes).unwrap();
            let reply = host_file::reply(&bytes).unwrap();
            (reply.result, reply.output.to_vec())
        }
    }

    #[test]
    fn native_child_pipe_pair_owns_only_its_table_and_round_trips_in_zone() {
        use crate::el1_zone::HostLockWait;
        use carrick_el1_abi::ipc::{IpcBacking, pipe::End};
        for flags in [
            0,
            carrick_abi::LINUX_O_NONBLOCK,
            carrick_abi::LINUX_O_CLOEXEC,
            carrick_abi::LINUX_O_NONBLOCK | carrick_abi::LINUX_O_CLOEXEC,
        ] {
            let fixture = fixture();
            let parent =
                crate::el1_ipc::HostTable::create(Arc::clone(&fixture.owner), 64, 1).unwrap();
            let child = parent.fork().unwrap();
            let raw = child.id().to_raw();
            let table = [raw.authority, raw.index, raw.generation];
            let before = fixture.owner.retained_host_resources();
            use carrick_personality_linux::native_host_file::{
                HostFileCall, HostFileStage, HostFileUser, NativeNamespace, complete, stage,
            };
            struct Output;
            impl HostFileUser for Output {
                fn copy_in(&mut self, _: &mut [u8], _: u64) -> bool {
                    false
                }
                fn writable(&mut self, address: u64, len: usize) -> usize {
                    if address == 0x10000 && len == 8 {
                        len
                    } else {
                        0
                    }
                }
            }
            let call = HostFileCall::decode(
                carrick_personality_linux::crossing::nr::PIPE2,
                &[0x10000, flags, 0, 0, 0, 0],
            )
            .unwrap();
            let mut namespace = NativeNamespace {
                table,
                resolve: &mut |_| panic!("pipe creation resolves no input descriptor"),
                releases: &mut |_| 0,
            };
            let Some(HostFileStage::Request {
                mut record, output, ..
            }) = stage(call, &mut namespace, &mut Output)
            else {
                panic!("native pipe2 must stage creation");
            };
            fixture.serve(None, &mut record).unwrap();
            let mut bytes = Vec::new();
            let result = complete(&record, output, &mut |address, output| {
                assert_eq!(address, 0x10000);
                bytes.extend_from_slice(output);
                true
            });
            assert_eq!(result.raw(), 0);
            assert_eq!(bytes, [0i32.to_le_bytes(), 1i32.to_le_bytes()].concat());
            assert_eq!(
                fixture.owner.retained_host_resources(),
                before,
                "no host resource token for an in-zone pipe"
            );
            let region = fixture.owner.region();
            let fds = region.fd(HostLockWait);
            assert_eq!(fds.getfd(parent.id(), fd::Fd(0)), Err(fd::Error::BadFd));
            assert!(
                fixture.dispatcher.open_file(4).is_none(),
                "root host table is untouched"
            );
            let mut object = None;
            for (number, access, end) in [
                (0, fd::AccessMode::ReadOnly, End::Reader),
                (1, fd::AccessMode::WriteOnly, End::Writer),
            ] {
                assert_eq!(
                    fds.getfd(child.id(), fd::Fd(number)),
                    Ok(flags & carrick_abi::LINUX_O_CLOEXEC != 0)
                );
                let (seen_access, status) = fds.getfl(child.id(), fd::Fd(number)).unwrap();
                assert_eq!(seen_access, access);
                assert_eq!(status.nonblock, flags & carrick_abi::LINUX_O_NONBLOCK != 0);
                let (pin, description) = fds.pin(child.id(), fd::Fd(number)).unwrap();
                let Some(IpcBacking::Pipe {
                    object: seen,
                    end: seen_end,
                }) = IpcBacking::decode(description.backing)
                else {
                    panic!("pipe must stay in zone");
                };
                assert_eq!(seen_end, end);
                if let Some(object) = object {
                    assert_eq!(seen, object);
                } else {
                    object = Some(seen);
                }
                assert!(fds.unpin(pin).unwrap().is_none());
            }
            let object = object.unwrap();
            fixture.owner.ensure_pipe_storage(object).unwrap();
            {
                let mut guard = region.lock(object, &HostLockWait).unwrap();
                let mut pipe = guard.pipe().unwrap();
                assert_eq!(pipe.try_write(b"a").result, Ok(1));
                let mut bytes = [0; 1];
                assert_eq!(pipe.try_read(&mut bytes).result, Ok(1));
                assert_eq!(&bytes, b"a");
            }
            let writer = fds.close(child.id(), fd::Fd(1)).unwrap().unwrap();
            fixture.owner.release(writer.backing).unwrap();
            {
                let mut guard = region.lock(object, &HostLockWait).unwrap();
                assert_eq!(
                    guard.pipe().unwrap().try_read(&mut [0; 1]).result,
                    Ok(0),
                    "no carrier pin keeps the writer alive"
                );
            }
            let reader = fds.close(child.id(), fd::Fd(0)).unwrap().unwrap();
            fixture.owner.release(reader.backing).unwrap();
            assert!(
                region.lock(object, &HostLockWait).is_err(),
                "final close retires the object"
            );
        }
    }

    #[test]
    fn native_pipe_failed_completion_withdraws_only_the_created_pair() {
        use crate::el1_zone::HostLockWait;
        use carrick_personality_linux::native_host_file::HostFileOutput;
        for reuse in [false, true] {
            let fixture = fixture();
            let child =
                crate::el1_ipc::HostTable::create(Arc::clone(&fixture.owner), 64, 64).unwrap();
            let raw = child.id().to_raw();
            let table = [raw.authority, raw.index, raw.generation];
            let mut record = record(table, HostFileOp::Pipe2, 0, [0; 4], &[], 8);
            fixture.serve(None, &mut record).unwrap();
            let peer = child.fork().unwrap();
            let region = fixture.owner.region();
            let fds = region.fd(HostLockWait);
            let current = carrick_el1_abi::CurrentTask::new();
            let result = carrick_el1_linux::ipc::complete_host_file::<
                carrick_sched_core::ParkedContextWords,
            >(
                || Some(fixture.owner.region()),
                &record,
                Some(HostFileOutput {
                    address: 0x10000,
                    len: 8,
                }),
                &mut |_, _| {
                    if reuse {
                        // A live sibling replaced the returned reader number
                        // before the failing copy completes. It now names a writer.
                        assert!(
                            fds.dup2(child.id(), fd::Fd(1), fd::Fd(0))
                                .unwrap()
                                .is_none()
                        );
                    }
                    false
                },
                None,
                &current,
            )
            .unwrap();
            assert_eq!(result.raw(), carrick_abi::LINUX_EFAULT.guest_retval());
            assert_eq!(fds.getfd(child.id(), fd::Fd(1)), Err(fd::Error::BadFd));
            if reuse {
                assert_eq!(
                    fds.getfl(child.id(), fd::Fd(0)).unwrap().0,
                    fd::AccessMode::WriteOnly
                );
                assert!(fds.close(child.id(), fd::Fd(0)).unwrap().is_none());
            } else {
                assert_eq!(
                    fds.getfd(child.id(), fd::Fd(0)),
                    Err(fd::Error::BadFd),
                    "failed copyout must not leak the pair"
                );
            }
            for fd in [fd::Fd(0), fd::Fd(1)] {
                assert_eq!(
                    fds.getfd(peer.id(), fd),
                    Ok(false),
                    "rollback belongs only to the creator's table"
                );
            }
        }
    }

    #[test]
    fn native_pipe_pair_limit_and_invalid_flags_publish_nothing() {
        use crate::el1_zone::HostLockWait;
        let fixture = fixture();
        let table = crate::el1_ipc::HostTable::create(Arc::clone(&fixture.owner), 1, 1).unwrap();
        let raw = table.id().to_raw();
        let words = [raw.authority, raw.index, raw.generation];
        for (flags, errno) in [
            (0, carrick_abi::LINUX_EMFILE),
            (1, carrick_abi::LINUX_EINVAL),
        ] {
            let (result, bytes) = fixture.result(
                None,
                record(words, HostFileOp::Pipe2, 0, [flags, 0, 0, 0], &[], 8),
            );
            assert_eq!(result, errno.guest_retval());
            assert!(bytes.is_empty());
            assert_eq!(
                fixture
                    .owner
                    .region()
                    .fd(HostLockWait)
                    .getfd(table.id(), fd::Fd(0)),
                Err(fd::Error::BadFd)
            );
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
        fn venue_open(
            &self,
            authority: &NativeFsAuthority,
            path: &[u8],
            flags: u64,
            mode: u64,
        ) -> i64 {
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
        fn venue_contents(&self, authority: &NativeFsAuthority, path: &[u8]) -> Vec<u8> {
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
        root.serve_native_host_file_in(&owner, Some(&authority), &mut open)
            .unwrap();
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

    /// The retained capability offers path authority only while the origin
    /// still holds exactly the admitted superuser identity and the same
    /// filesystem context; a set*id or chdir after capture withdraws it.
    #[test]
    fn native_path_authority_requires_the_unchanged_superuser_origin() {
        let fixture = rootfs_fixture();
        let context = fixture.dispatcher.capture_one_task_context().unwrap();
        let files = fixture.dispatcher.capture_exec_files(&context).unwrap();
        drop(context);
        assert!(files.native_fs_authority().is_some());
        fixture.dispatcher.set_cwd("/usr");
        assert!(
            files.native_fs_authority().is_none(),
            "a changed cwd is not the snapshot's authority"
        );

        let unprivileged = rootfs_fixture();
        unprivileged
            .dispatcher
            .set_credentials(carrick_abi::NsUid(1000), carrick_abi::NsGid(1000));
        let context = unprivileged.dispatcher.capture_one_task_context().unwrap();
        let files = unprivileged
            .dispatcher
            .capture_exec_files(&context)
            .unwrap();
        assert!(
            files.native_fs_authority().is_none(),
            "only the admitted superuser identity resolves for native callers"
        );
    }

    /// A private file mapping's byte source: the reply names the identity
    /// the ring maps with, and the retained source reads the file's bytes
    /// at the mapping's offset as its pages fault in.
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
            .serve_native_host_file_in(&fixture.owner, None, &mut map)
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
            .serve_native_host_file_in(&fixture.owner, None, &mut again)
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
