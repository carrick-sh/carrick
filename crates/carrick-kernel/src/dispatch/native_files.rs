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

/// Open flags the slice serves: a read-only open of an existing object.
/// Anything else (write access, creation, `O_PATH`, `O_TMPFILE`, ...) is
/// refused exactly until a later slice serves it.
fn native_open_flags_served(flags: u64) -> bool {
    let served = LinuxOpenFlags::CLOEXEC
        | LinuxOpenFlags::DIRECTORY
        | LinuxOpenFlags::NOFOLLOW
        | LinuxOpenFlags::NONBLOCK
        | LinuxOpenFlags::LARGEFILE
        | LinuxOpenFlags::NOCTTY;
    flags & carrick_abi::LINUX_O_ACCMODE == carrick_abi::LINUX_O_RDONLY
        && LinuxOpenFlags::from_bits_retain(flags & !carrick_abi::LINUX_O_ACCMODE)
            .difference(served)
            .is_empty()
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
        let view = HostFileRequestView::parse(record).map_err(|_| NativeHostFileRefusal)?;
        let header = view.header();
        let table = fd::TableId::from_raw(fd::RawTableId {
            authority: header.table[0],
            index: header.table[1],
            generation: header.table[2],
        });
        let served = if header.op.resolves_path() {
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
            return self.serve_native_open_file(header, &file.description, capacity);
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
            // Opened read-only by this slice.
            HostFileOp::Write => Served::errno(carrick_abi::LINUX_EBADF),
            HostFileOp::MapPrivate => self.native_map_source(description),
            HostFileOp::Openat | HostFileOp::Faccessat | HostFileOp::Newfstatat => Served::Refused,
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
            HostFileOp::Openat => self.native_open(owner, table, path, header.args[0]),
            _ => Served::Refused,
        }
    }

    /// Open an existing rootfs object read-only for a native process and
    /// install it as the lowest free descriptor of the caller's table.
    fn native_open(
        &self,
        owner: &Arc<HostIpc>,
        table: fd::TableId,
        path: &str,
        flags: u64,
    ) -> Served {
        if !native_open_flags_served(flags) {
            return Served::Refused;
        }
        let fs = self.fs_view();
        if let Err(errno) = super::fs::check_path_length(path) {
            return Served::errno(errno);
        }
        let resolved = match fs.resolve_at_path(LINUX_AT_FDCWD, path) {
            Ok(resolved) => resolved,
            Err(errno) => return Served::errno(errno),
        };
        let open_flags = LinuxOpenFlags::from_bits_retain(flags);
        let target = if open_flags.contains(LinuxOpenFlags::NOFOLLOW) {
            match fs.layered_lstat(&resolved) {
                Ok(md) if md.kind == carrick_vfs::rootfs::RootFsEntryKind::Symlink => {
                    return Served::errno(crate::linux_abi::LINUX_ELOOP);
                }
                _ => resolved,
            }
        } else {
            match fs.canonicalize_following(&resolved) {
                Ok(target) => target,
                Err(errno) => return Served::errno(errno),
            }
        };
        // Mount-served, synthetic and device opens need a caller task view
        // (proc, dev and bind mounts): unrouted until a later slice.
        if crate::vfs::may_be_synthetic_virtual_path(&target)
            || target == "/dev"
            || target.starts_with("/dev/")
            || self.fs.vfs_mounts.resolve(&target).is_some()
        {
            return Served::Refused;
        }
        // A FIFO open blocks for its peer: the owned carrier waiter's slice.
        if fs
            .layered_metadata(&target)
            .is_ok_and(|md| md.kind == carrick_vfs::rootfs::RootFsEntryKind::Fifo)
        {
            return Served::Refused;
        }
        if let Some(errno) = fs.dac_open_check(&target, carrick_abi::LINUX_O_RDONLY, false) {
            return Served::errno(errno);
        }
        let existing = match self
            .fs
            .rootfs_vfs
            .open_for_dispatch(&target, false, false, false, false)
        {
            Ok(existing) => existing,
            Err(errno) => return Served::errno(errno),
        };
        let directory = matches!(
            existing,
            carrick_vfs::vfs::rootfs::OpenDispatchResult::Directory { .. }
        );
        if open_flags.contains(LinuxOpenFlags::DIRECTORY) && !directory {
            if let carrick_vfs::vfs::rootfs::OpenDispatchResult::HostFile { host_fd, .. } = existing
            {
                // SAFETY: the dispatch opened this host fd for us; nothing
                // else has adopted it.
                unsafe { libc::close(host_fd) };
            }
            return Served::errno(carrick_abi::LINUX_ENOTDIR);
        }
        let description = match fs.description_for_existing(existing, target, flags, false, false) {
            Ok(description) => description,
            Err(errno) => return Served::errno(errno),
        };
        let file = crate::dispatch::fd_table::OpenFile::from_open_description_with_status_flags(
            std::sync::Arc::new(parking_lot::RwLock::new(description)),
            flags & !carrick_abi::LINUX_O_CLOEXEC,
            super::linux_fd_flags_from_open_flags(flags),
        );
        let status = super::fs::reportable_status_flags(file.description.common().status_flags());
        let status = fd::StatusFlags {
            append: false,
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
        match owner.install_host_description(
            table,
            Box::new(NativeOpenFile::new(Arc::clone(&file.description))),
            fd::AccessMode::ReadOnly,
            status,
            open_flags.contains(LinuxOpenFlags::CLOEXEC),
        ) {
            Ok(number) => Served::value(i64::from(number.0)),
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
                    super::fs::IoCaller::CarrierBuffer,
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
    }

    /// An ubuntu-shaped rootfs: `/lib -> usr/lib`, `usr/lib/libc.so.6`,
    /// `etc/ld.so.cache`.
    fn rootfs() -> tempfile::TempDir {
        let lower = tempfile::tempdir().unwrap();
        let root = lower.path();
        std::fs::create_dir_all(root.join("usr/lib")).unwrap();
        std::fs::create_dir_all(root.join("etc")).unwrap();
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
        // Write access and synthetic paths are later slices: refused exactly.
        let mut write = record(
            fixture.table,
            HostFileOp::Openat,
            FDCWD,
            [carrick_abi::LINUX_O_WRONLY, 0, 0, 0],
            b"/etc/ld.so.cache",
            0,
        );
        assert_eq!(
            fixture.serve(Some(&authority), &mut write),
            Err(NativeHostFileRefusal)
        );
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
