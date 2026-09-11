//! Filesystem syscall handlers — VFS-routed file I/O.
//!
//! These are methods on [`SyscallDispatcher`] (see `super` for the dispatcher
//! struct, the normalized dispatch table, and the [`DispatchOutcome`] protocol).
//! This module and its `fs/` submodules implement every path- and fd-bearing
//! syscall: `openat`/`read`/`write`/`close`, the `*stat*` family, directory
//! ops, `rename`/`link`/`unlink`, `fcntl` (incl. POSIX record locks),
//! `sendfile`/`copy_file_range`, xattrs, and the access checks.
//!
//! # Routing: VFS mount table first, rootfs+overlay fallthrough
//!
//! A path-bearing syscall is resolved against [`fs::FsState`] in two layers.
//! First the unified VFS mount table ([`fs::FsState::vfs_mounts`]) — `DevVfs` at
//! `/dev`, `ProcVfs` at `/proc`, `SysVfs` at `/sys`. If a mount claims the path
//! and handles the operation, its answer wins. Otherwise the call *falls
//! through* (`VfsOpenAttempt::FallThrough`) to the `/` mount
//! ([`fs::FsState::rootfs_vfs`]): an immutable OCI rootfs layered under a
//! writable overlay. Reads see the overlay shadowing the rootfs; writes,
//! creates, and metadata changes land in the overlay (the base image is never
//! mutated). The rootfs/overlay is held as a typed field rather than a regular
//! mount because ~50 legacy call sites still reach into it directly.
//!
//! With `--fs host`, regular-file opens are backed by a real macOS fd
//! (`OpenDescription::HostFile`) so the guest sees the host's APFS, mediated by
//! cap-std; in the default in-memory mode an `openat` of a rootfs/overlay file
//! materializes its bytes into an `OpenDescription::File`/`Directory`. Either
//! way the descriptor lands in the fd table (see [`fd_table`]).
//!
//! # Linux↔Darwin translation lives here
//!
//! macOS does the heavy lifting (real `libc` calls under the hood for host
//! backends), but the *shapes* differ and every divergence is reconciled in
//! this module: the `struct flock` field order and `l_type` constants
//! (`forward_record_lock`), the `struct stat`/`statx` wire layout
//! (`fs/stat.rs`), `AT_*`/`O_*` flag bits, `S_IF*` type bits, the `dirent64`
//! record format, and the magic `/proc/self/fd/N` re-open symlinks. The guiding
//! rule is "be Linux, on Darwin": where a constant or layout collides, the Linux
//! value is what the guest must observe.
//!
//! # Submodules (`fs/`)
//!
//! Pure `impl SyscallDispatcher` splits (WS-F3), type-transparent to callers:
//! `state` (the [`fs::FsState`]/[`fs::RuntimeIo`] owned state), `fd_helpers`
//! (the lowest-free-fd allocator + `install_fd*` + typed fd-kind accessors),
//! `pathres` (layered path/symlink resolution across the rootfs layers),
//! `stat` (fd stat/statx record assembly), `sendfile` (data-movement +
//! the Darwin `copyfile`/`fclonefileat` fast path), `access` (DAC checks),
//! and `xattr`.
pub(in crate::dispatch::fs) use super::*;
use crate::linux_abi::{
    LINUX_ELOOP, LINUX_ENOSPC, LINUX_ENXIO, LINUX_EOVERFLOW, LINUX_SEEK_DATA, LINUX_SEEK_HOLE,
};
use crate::vfs::PtyRole;

syscall_table! {
    /// Per-module syscall routing for the `fs` subsystem (Task A1).
    ///
    /// Owns the `number → handler` arms for every syscall this module
    /// implements. `resolve_handler` in `dispatch/mod.rs` chains this with
    /// the other modules' tables. Add a `fs` syscall by adding an arm
    /// HERE — no shared routing table to edit.
    pub(crate) fn dispatch_fs;
    0 => io_setup,
    1 => io_destroy,
    2 => io_submit,
    3 => io_cancel,
    4 => io_getevents,
    17 => getcwd,
    23 => dup,
    24 => dup3,
    carrick_abi::CARRICK_PRIVATE_X86_DUP2 => dup2,
    carrick_abi::CARRICK_PRIVATE_X86_STAT => x86_stat,
    carrick_abi::CARRICK_PRIVATE_X86_FSTAT => x86_fstat,
    carrick_abi::CARRICK_PRIVATE_X86_LSTAT => x86_lstat,
    carrick_abi::CARRICK_PRIVATE_X86_NEWFSTATAT => x86_newfstatat,
    26 => inotify_init1,
    27 => inotify_add_watch,
    28 => inotify_rm_watch,
    29 => ioctl,
    32 => flock,
    33 => mknodat,
    46 => ftruncate,
    47 => fallocate,
    48 => faccessat,
    34 => mkdirat,
    35 => unlinkat,
    36 => symlinkat,
    37 => linkat,
    38 => renameat,
    49 => chdir,
    50 => fchdir,
    51 => chroot,
    52 => fchmod,
    53 => fchmodat,
    452 => fchmodat2, // validates the flags arg (nr 53 ignores it)
    54 => fchownat,
    55 => fchown,
    56 => openat,
    57 => close,
    59 => pipe2,
    61 => getdents64,
    62 => lseek,
    63 => read,
    64 => write,
    65 => readv,
    66 => writev,
    67 => pread64,
    68 => pwrite64,
    69 => preadv,
    70 => pwritev,
    71 => sendfile,
    75 => vmsplice,
    76 => splice,
    78 => readlinkat,
    79 => newfstatat,
    80 => fstat,
    81 => sync,
    82 => fsync,
    83 => fdatasync,
    88 => utimensat,
    262 => fanotify_init,
    263 => fanotify_mark,
    267 => syncfs,
    84 => sync_file_range,
    451 => cachestat,
    276 => renameat2,
    279 => memfd_create,
    447 => memfd_secret,
    285 => copy_file_range,
    // preadv2/pwritev2: positional vectored I/O plus a RWF_* flags arg. The
    // flags are advisory for our backing — RWF_HIPRI (high-priority hint),
    // RWF_{D,}SYNC (durability; we don't buffer), RWF_NOWAIT (a regular file
    // never blocks) — so we route to preadv/pwritev, whose 5-arg handlers
    // ignore the trailing flags. (A future RWF_APPEND need would want its own
    // pwritev2 handler that writes at EOF.)
    286 => preadv,
    287 => pwritev,
    291 => statx,
    436 => close_range,
    437 => openat2,
    439 => faccessat2,
    5 => sys_setxattr_path,
    6 => sys_lsetxattr_path,
    7 => sys_setxattr_fd,
    8 => sys_getxattr_path,
    9 => sys_lgetxattr_path,
    10 => sys_getxattr_fd,
    11 => sys_listxattr_path,
    12 => sys_llistxattr_path,
    13 => sys_listxattr_fd,
    14 => sys_removexattr_path,
    15 => sys_lremovexattr_path,
    16 => sys_removexattr_fd,
    43 => sys_statfs,
    44 => sys_fstatfs,
    45 => sys_truncate,
    77 => tee,
}

mutation_syscall_table! {
    pub(crate) fn dispatch_fs_mutation;
    25 => fcntl,
}

/// Canonical (AArch64) numbers of the syscalls that STRUCTURALLY mutate the path
/// namespace — create/remove/rename a directory, symlink, or special node.
/// These are the only fs syscalls that can change how an UNRELATED path
/// resolves, so a successful one must invalidate the fork-coherent resolve
/// cache ([`crate::fs_resolve_cache`]). The numbers mirror the `=> handler` arms
/// in the `syscall_table!` above; content-only writes (write/pwrite/ftruncate)
/// are deliberately EXCLUDED so a syscall-bound write loop keeps its cached
/// resolves. Bumping is unconditional (even on a failed mutation) — a spurious
/// invalidation only costs a re-resolve, whereas missing one would serve a
/// stale path, and these syscalls are never in a hot loop.
pub(crate) fn is_structural_namespace_mutation(canonical_nr: u64) -> bool {
    matches!(
        canonical_nr,
        33      // mknodat
            | 34  // mkdirat
            | 35  // unlinkat  (unlink + rmdir via AT_REMOVEDIR)
            | 36  // symlinkat
            | 37  // linkat
            | 38  // renameat
            | 276 // renameat2
    )
}

mod access;
mod directory;
pub(in crate::dispatch) mod fd_helpers;
pub(crate) mod ioctl;
#[cfg(test)]
pub(crate) use ioctl::{inet4_interfaces_from_model, resolve_tiocspgrp};
mod legacy_aio;
pub(crate) mod locks;
pub(crate) use locks::*;
pub(crate) mod lookup;
mod mount;
pub(crate) mod notify;
mod pathres;
pub(crate) mod pipe;
pub(crate) mod proc_synthetic;
pub(crate) use proc_synthetic::*;
mod sendfile;
mod stat;
mod state;
mod xattr;
pub(in crate::dispatch) use lookup::{LookupIntent, LookupTarget};
pub(crate) use pipe::*;
pub use state::StdioSink;
use state::*;
pub(super) use state::{FsState, RuntimeIo, host_fd_offset};
pub(crate) use state::{LegacyAioContextId, MountRetirement, SplicePushback};

pub(super) fn vfs_md_to_rootfs_md_helper(path: &str, md: &crate::vfs::Metadata) -> RootFsMetadata {
    vfs_md_to_rootfs_md(path, md)
}

pub(super) fn get_last_error() -> i32 {
    carrick_portable::errno()
}

/// Derive a stable opaque Carrick stream identity from a host fd, used to
/// stamp BOTH ends of a freshly-created pipe with one shared FASYNC join key.
/// Include both host device and inode: inode numbers are only unique within a
/// device, and Carrick adopts streams from devfs and several filesystems. The
/// value is read before fork and copied to the other pipe end, so both ends
/// retain one Linux identity even though BSD assigns them different inodes.
/// Returns `0` if fstat fails; `0` is never a valid armed FASYNC key.
fn host_inode_pipe_id(host_fd: i32) -> u64 {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(host_fd, &mut st) } != 0 {
        return 0;
    }
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in (st.st_dev as u64)
        .to_le_bytes()
        .into_iter()
        .chain((st.st_ino as u64).to_le_bytes())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    if hash == 0 { 1 } else { hash }
}

fn host_pipe_readable_bytes(host_fd: i32) -> Result<usize, LinuxErrno> {
    let mut readable: libc::c_int = 0;
    let rc = unsafe { libc::ioctl(host_fd, libc::FIONREAD, &mut readable) };
    rc.host_syscall_errno()?;
    usize::try_from(readable).map_err(|_| LINUX_EINVAL)
}

/// The readable PREFIX of a gather list, plus whether the walk stopped on an
/// unreadable segment.
///
/// `writev` is not all-or-nothing on Linux: the kernel copies segments in order
/// and stops at the first one it cannot read, returning the bytes it already
/// transferred. Only a fault with ZERO bytes transferred is `EFAULT`.
struct GatheredIovecBytes {
    bytes: Vec<u8>,
    faulted: bool,
}

fn gather_bounded_iovec_bytes(
    memory: &impl CurrentMmMemory,
    iovecs: &[LinuxIovec],
) -> Result<Option<GatheredIovecBytes>, LinuxErrno> {
    let mut total = 0usize;
    for iovec in iovecs {
        let len = usize::try_from(iovec.iov_len).map_err(|_| LINUX_EINVAL)?;
        total = total.checked_add(len).ok_or(LINUX_EINVAL)?;
        if total > crate::dispatch::MAX_RW_COUNT {
            return Ok(None);
        }
    }

    let mut bytes = Vec::with_capacity(total);
    let mut faulted = false;
    for iovec in iovecs {
        let len = usize::try_from(iovec.iov_len).map_err(|_| LINUX_EINVAL)?;
        // A zero-length segment is never dereferenced, so a `{NULL, 0}` entry
        // must be skipped rather than faulted.
        if len == 0 {
            continue;
        }
        // Stop at the first unreadable segment and keep what came before it.
        // Returning EFAULT for the whole call discards a transfer Linux would
        // have performed (LTP `writev07` writes 4x64 bytes with the SECOND
        // iovec on a PROT_NONE page and requires the return value 64, the file
        // content, and the advanced offset).
        let Ok(chunk) = memory.read_bytes(iovec.iov_base, len) else {
            faulted = true;
            break;
        };
        bytes.extend_from_slice(&chunk);
    }
    Ok(Some(GatheredIovecBytes { bytes, faulted }))
}

enum PwritevPayloads {
    Borrowed(Vec<libc::iovec>),
    Staged(Vec<Vec<u8>>),
}

fn prepare_pwritev_payloads(
    memory: &impl CurrentMmMemory,
    iovecs: &[LinuxIovec],
) -> Result<PwritevPayloads, LinuxErrno> {
    let mut borrowed_iovecs = Vec::with_capacity(iovecs.len());
    let mut all_borrowed = true;
    for iovec in iovecs {
        let iov_len = usize::try_from(iovec.iov_len).map_err(|_| LINUX_EINVAL)?;
        if iov_len == 0 {
            continue;
        }
        let Some(ptr) = memory.host_ptr_for_read(iovec.iov_base, iov_len) else {
            all_borrowed = false;
            break;
        };
        borrowed_iovecs.push(libc::iovec {
            iov_base: ptr as *mut libc::c_void,
            iov_len,
        });
    }
    if all_borrowed {
        return Ok(PwritevPayloads::Borrowed(borrowed_iovecs));
    }

    let mut staged_iovecs = Vec::with_capacity(iovecs.len());
    let mut faulted = false;
    for iovec in iovecs {
        let iov_len = usize::try_from(iovec.iov_len).map_err(|_| LINUX_EINVAL)?;
        // A zero-length iovec segment is permitted and must NOT fault, even
        // with a NULL/invalid base.
        if iov_len == 0 {
            staged_iovecs.push(Vec::new());
            continue;
        }
        let Ok(bytes) = memory.read_bytes(iovec.iov_base, iov_len) else {
            faulted = true;
            break;
        };
        staged_iovecs.push(bytes);
    }
    if faulted {
        return Err(LINUX_EFAULT);
    }
    Ok(PwritevPayloads::Staged(staged_iovecs))
}

struct PreparedReadvTargets {
    host_iovecs: Vec<libc::iovec>,
    guest_ranges: Vec<(u64, usize)>,
}

fn prepare_readv_targets(
    memory: &mut impl CurrentMmMemory,
    iovecs: &[LinuxIovec],
) -> Result<Option<PreparedReadvTargets>, LinuxErrno> {
    let mut borrowed_iovecs = Vec::with_capacity(iovecs.len());
    let mut guest_ranges = Vec::with_capacity(iovecs.len());
    for iovec in iovecs {
        let iov_len = usize::try_from(iovec.iov_len).map_err(|_| LINUX_EINVAL)?;
        if iov_len == 0 {
            continue;
        }
        let Some(ptr) = memory.host_ptr_for_write(iovec.iov_base, iov_len) else {
            return Ok(None);
        };
        borrowed_iovecs.push(libc::iovec {
            iov_base: ptr as *mut libc::c_void,
            iov_len,
        });
        guest_ranges.push((iovec.iov_base, iov_len));
    }
    Ok(Some(PreparedReadvTargets {
        host_iovecs: borrowed_iovecs,
        guest_ranges,
    }))
}

/// Linux path-length limits enforced at resolution time: NAME_MAX (255) per
/// component, PATH_MAX (4096) for the whole path. Either overflow →
/// ENAMETOOLONG. (`PATH_MAX` includes the NUL, so the usable length is 4095.)
pub(super) fn check_path_length(path: &str) -> Result<(), LinuxErrno> {
    const NAME_MAX: usize = 255;
    const PATH_MAX: usize = 4096;
    if path.len() >= PATH_MAX {
        return Err(LINUX_ENAMETOOLONG);
    }
    for component in path.split('/') {
        if component.len() > NAME_MAX {
            return Err(LINUX_ENAMETOOLONG);
        }
    }
    Ok(())
}

fn path_is_under_or_equal(path: &str, root: &str) -> bool {
    let path = path.trim_end_matches('/');
    let root = root.trim_end_matches('/');
    if root.is_empty() || root == "/" {
        return true;
    }
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Host passthrough for tee(2). On Linux the guest pipes are real host kernel
/// pipes, so the host tee(2) gives exact zero-consume semantics; on hosts
/// without tee(2) (macOS/BSD) `SyscallDispatcher::userspace_tee` emulates it.
#[cfg(target_os = "linux")]
fn tee_host_passthrough(
    in_fd: HostFd,
    out_fd: HostFd,
    count: usize,
    flags: LinuxSpliceFlags,
) -> Result<DispatchOutcome, DispatchError> {
    // Raw escape at the libc boundary: Linux SPLICE_F_* values are identical
    // to the guest's, so the bits pass straight through.
    let n = unsafe {
        libc::tee(
            in_fd.get(),
            out_fd.get(),
            count,
            flags.bits() as libc::c_uint,
        )
    };
    Ok(DispatchOutcome::returned_len_or_errno(
        n.host_syscall_errno()?,
    ))
}
use super::fd_table::is_anon_overlay_path;

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

impl SyscallDispatcher {
    #[inline]
    pub(crate) fn invalidate_dentry_host_fd(&self, raw_fd: i32) {
        self.fs.rootfs_vfs.invalidate_host_fd(raw_fd);
    }

    pub(super) fn record_fd_open_path(&self, fd: i32, path: String) {
        self.captured_file_table()
            .write_fd_open_paths()
            .insert(fd, path);
    }

    pub(super) fn lookup_recorded_fd_open_path(&self, fd: i32) -> Option<String> {
        self.captured_file_table()
            .read_fd_open_paths()
            .get(&fd)
            .cloned()
    }

    pub(super) fn write_shared_supported(&self, fd: i32) -> bool {
        let Some(open_file) = self.open_file(fd) else {
            return true;
        };
        let Some(open) = open_file.description.read() else {
            return true;
        };
        matches!(
            &*open,
            OpenDescription::EventFd { .. }
                | OpenDescription::PipeWriter { .. }
                // PipeReader is shared-safe: write dispatch on a pipe read end returns
                // Linux EBADF immediately without performing mutable or legacy-only state transitions.
                | OpenDescription::PipeReader { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::InMemorySocket { .. }
                | OpenDescription::HostFile { .. }
                // In-memory regular files (incl. the unnamed O_TMPFILE inode and
                // overlay-backed `SyntheticFile`s) carry their `contents`/`offset`
                // behind the description's own `RwLock`, and the overlay backend
                // is interior-mutable (`set_file_contents(&self, …)`). The `write`
                // handler's File arm is therefore safe on the multi-threaded shared
                // path. Without this, a write(2) to such an fd from a *threaded*
                // guest (e.g. CPython) fell through `dispatch_threaded_shared` →
                // ENOSYS — `tempfile.TemporaryFile()` (O_TMPFILE) writes failed
                // only under multithreading, surfacing as 58 ERRORs in test_csv.
                | OpenDescription::File { .. }
                | OpenDescription::SyntheticFile { .. }
                | OpenDescription::SyntheticDevice { .. }
        )
    }

    fn record_unimplemented_virtual_file(
        reporter: &CompatReporter,
        path: &str,
    ) -> Option<DispatchOutcome> {
        if path.starts_with("/proc/") {
            reporter.record(CompatEvent::proc_read_unimplemented(path.to_owned()));
            Some(DispatchOutcome::errno(LINUX_ENOENT))
        } else if path.starts_with("/sys/") {
            // /sys paths that are synthesized must not be recorded as unimplemented;
            // they are handled by the synthetic open path before reaching ENOENT.
            if crate::vfs::sys::synthetic_file(path).is_some() {
                return None;
            }
            reporter.record(CompatEvent::sys_read_unimplemented(path.to_owned()));
            Some(DispatchOutcome::errno(LINUX_ENOENT))
        } else {
            None
        }
    }

    pub(super) fn fd_is_valid(&self, fd: i32) -> bool {
        (is_stdio_fd(fd) && !self.stdio_is_closed(fd)) || self.fd_table_contains(fd)
    }

    /// True if `fd` was opened with `O_PATH`. Such a descriptor names a
    /// filesystem location but is not "open" for I/O: read/write/fchmod/fchown/
    /// ioctl/fgetxattr must all fail with EBADF (LTP open13). The flag is
    /// preserved in the description's status_flags at open time.
    pub(super) fn fd_is_o_path(&self, fd: i32) -> bool {
        self.open_file(fd).is_some_and(|of| {
            LinuxOpenFlags::from_bits_truncate(of.description.common().status_flags())
                .contains(LinuxOpenFlags::PATH)
        })
    }

    /// True iff `fd` is a `memfd_secret(2)` description. Secret memory has no
    /// file read/write methods, so the read/write/pread/readv/… family and
    /// splice/sendfile/copy_file_range all fail EINVAL on it — the only data
    /// path is a MAP_SHARED mapping. (memfdsecret probe; LTP splice07's
    /// "memfd secret" rows.)
    pub(super) fn fd_is_secretmem(&self, fd: i32) -> bool {
        self.open_file(fd)
            .is_some_and(|of| of.description.common().secretmem())
    }

    /// `EFBIG` iff growing a file to `length` would exceed this process's
    /// `RLIMIT_FSIZE` soft limit.
    ///
    /// truncate(2)/ftruncate(2): "EFBIG — the argument `length` is larger than
    /// the maximum file size", and getrlimit(2) defines RLIMIT_FSIZE as that
    /// maximum. carrick consulted no limit at all, so LTP truncate03's
    /// `{ TEST_FILE3, MAX_FSIZE*2, EFBIG }` case simply succeeded.
    ///
    /// DELIBERATE DIVERGENCE, stated plainly: Linux also generates SIGXFSZ
    /// alongside the errno. carrick returns the errno only. Raising a signal
    /// whose default disposition terminates the process is not something to
    /// add speculatively; it is tracked separately and gated on a probe that
    /// observes what the Docker oracle actually delivers.
    fn rlimit_fsize_errno(&self, length: i64) -> Option<LinuxErrno> {
        let limit = self
            .effective_resource_limit(carrick_abi::LINUX_RLIMIT_FSIZE)
            .rlim_cur;
        if limit == carrick_abi::LINUX_RLIM_INFINITY {
            return None;
        }
        (length as u64 > limit).then_some(crate::linux_abi::LINUX_EFBIG)
    }

    fn truncate(
        &self,
        context: &crate::kernel::KernelContext,
        pathname: GuestPtr,
        length: u64,
        memory: &impl CurrentMmMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let length = i64::from_ne_bytes(length.to_ne_bytes());
        if length < 0 {
            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
        }
        let path = read_guest_c_string(memory, pathname.0)?;
        if path.is_empty() {
            return Ok(DispatchOutcome::errno(LINUX_ENOENT));
        }
        let resolved = self.resolve_at_path(LINUX_AT_FDCWD, &path)?;
        let resolved = match self.canonicalize_following(&resolved) {
            Ok(resolved) => resolved,
            Err(errno) => return Ok(DispatchOutcome::errno(errno)),
        };
        if self.is_synthetic_virtual_path(context, &resolved) {
            return Ok(DispatchOutcome::errno(LINUX_EROFS));
        }
        // Layered metadata (overlay/disk first, then rootfs) — not rootfs-only,
        // so guest-created files are seen too.
        let kind = match self.layered_metadata(&resolved) {
            Ok(md) => md.kind,
            Err(errno) => return Ok(DispatchOutcome::errno(errno)),
        };
        if kind == RootFsEntryKind::Directory {
            return Ok(DispatchOutcome::errno(LINUX_EISDIR));
        }
        // DAC: truncating a file writes it, so a caller without write permission
        // is EACCES (truncate03 sets euid to nobody and truncates a 0444 file).
        // Root bypasses; `--fs memory` (no real owner/mode) falls through.
        if let Some(errno) = self.may_write(&resolved) {
            return Ok(DispatchOutcome::errno(errno));
        }
        if let Some(errno) = self.rlimit_fsize_errno(length) {
            return Ok(DispatchOutcome::errno(errno));
        }
        // Disk-backed: open the real file and ftruncate it. The whole rootfs
        // is materialised on the cap-std scratch under --fs host, so this
        // works for both rootfs and guest-created files. MemoryBackend has no
        // raw fd → EROFS (path-based truncate stays unsupported in-memory).
        match self.fs.rootfs_vfs.truncate_path(&resolved, length as u64) {
            Ok(()) => Ok(DispatchOutcome::Returned { value: 0 }),
            Err(errno) => Ok(DispatchOutcome::errno(errno)),
        }
    }

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
            dirfd,
            &path,
            flags,
            mode,
            cx.reporter,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn open_at_path_string(
        &self,
        context: &crate::kernel::KernelContext,
        registry: Option<&crate::thread::ThreadRegistry>,
        dirfd: u64,
        path: &str,
        flags: u64,
        mode: u64,
        reporter: &CompatReporter,
    ) -> Result<DispatchOutcome, DispatchError> {
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
                        base: OpenDescriptionBase::new(flags & !LINUX_O_CLOEXEC),
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

    /// When the guest dups a *bare stdio* fd that is the `-t` controlling pty
    /// slave, the duplicate must keep its tty identity. bash's
    /// `initialize_job_control` does `dup(fileno(stderr))`, moves it to a high
    /// fd, and runs `tcgetpgrp`/`tcsetpgrp` on *that* fd — so if the duplicate
    /// lands as a plain (`pty: None`) HostPipe it is classified `TtyFdKind::Other`
    /// and every tty ioctl returns ENOTTY; `tcgetpgrp` then returns -1 and bash
    /// prints "cannot set terminal process group (-1)" / "no job control". Tag it
    /// with the controlling slave role so it flows through the pty passthrough
    /// (TCGETS2 / TIOCGPGRP / TIOCSPGRP / TIOCGWINSZ) to the duplicated host fd.
    /// Non-tty stdio (a pipe/file redirect) returns `None` and stays a plain pipe.
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

    /// Try to satisfy an open via the VFS mount table. Returns
    /// `Installed(fd)` when a mount handled it, `Errno(e)` when a
    /// mount explicitly failed, and `FallThrough` when no mount
    /// claimed the path (or the claiming mount returned ENOSYS). The
    /// caller wraps the legacy lookup chain inside `FallThrough`.
    fn try_vfs_open(
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
                        base: OpenDescriptionBase::new(status_flags as u64),
                        writable: !is_read_end,
                    }
                } else {
                    OpenDescription::HostPipe {
                        // A VFS host stream (e.g. /dev/null, a chardev) has no
                        // separate pipe peer; the host inode is a unique id.
                        pipe_id: host_inode_pipe_id(host_fd),
                        host_fd: HostFdRef::new(host_fd),
                        is_read_end,
                        base: OpenDescriptionBase::new(status_flags as u64),
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
                        base: OpenDescriptionBase::new(status),
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
                        base: OpenDescriptionBase::new(status),
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
                        base: OpenDescriptionBase::new(status),
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
                        base: OpenDescriptionBase::new(status),
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
                        base: OpenDescriptionBase::new(status),
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

    // === Normalized shim-wrappers ===
    // Thin adapters giving each remaining legacy handler the uniform
    // SyscallCtx<M> contract so it can live in the `dispatch_fs`
    // table. The inner fns are unchanged (already tested); these forward
    // `ctx.request` (Copy) and `ctx.memory`. Once every syscall has a
    // wrapper the legacy match in `dispatch()` is deleted and the macro
    // table becomes the single authoritative syscall registry.

    pub(in crate::dispatch) fn host_file_fd_for_flush(
        &self,
        fd: i32,
    ) -> Result<Option<i32>, LinuxErrno> {
        let Some(open_file) = self.open_file(fd) else {
            return if is_stdio_fd(fd) {
                Ok(None)
            } else {
                Err(LINUX_EBADF)
            };
        };
        let Some(open) = open_file.description.read() else {
            return Ok(None);
        };
        Ok(match &*open {
            OpenDescription::HostFile { host_fd, .. } => Some(host_fd.raw()),
            _ => None,
        })
    }

    fn host_pipe_read_end_for_pipe_id(&self, pipe_id: u64) -> Option<(i32, HostFd)> {
        let files = self.captured_file_table();
        let table = files.read_open_files();
        for (fd, other) in table.iter() {
            let Some(other_open) = other.description.read() else {
                continue;
            };
            if let OpenDescription::HostPipe {
                host_fd,
                is_read_end: true,
                pipe_id: other_pipe_id,
                ..
            } = &*other_open
                && *other_pipe_id == pipe_id
            {
                return Some((*fd, host_fd.view()));
            }
        }
        None
    }

    /// The host fd backing the WRITE end of the pipe object identified by
    /// `pipe_id`, if one is currently open. Symmetric to
    /// [`Self::host_pipe_read_end_for_pipe_id`]; the userspace `tee` uses it to
    /// restore the source pipe after peeking its buffered bytes on hosts that
    /// lack `tee(2)`.
    fn host_pipe_write_end_for_pipe_id(&self, pipe_id: u64) -> Option<HostFd> {
        if pipe_id == 0 {
            return None;
        }
        let files = self.captured_file_table();
        let table = files.read_open_files();
        for (_fd, other) in table.iter() {
            let Some(other_open) = other.description.read() else {
                continue;
            };
            if let OpenDescription::HostPipe {
                host_fd,
                is_read_end: false,
                pipe_id: other_pipe_id,
                ..
            } = &*other_open
                && *other_pipe_id == pipe_id
            {
                return Some(host_fd.view());
            }
        }
        None
    }

    /// True iff `fd` refers to a genuine pipe end — an anonymous pipe, a FIFO,
    /// or a pty — as opposed to a char device (e.g. `/dev/zero`, which carrick
    /// also models as a `HostPipe`), a socket, or a regular file. splice(2)
    /// requires at least one of its two fds to be a genuine pipe; a char-device
    /// `HostPipe` must NOT satisfy that requirement (splice07).
    fn is_genuine_pipe(&self, fd: i32) -> bool {
        let Some(open_file) = self.open_file(fd) else {
            return false;
        };
        let Some(open) = open_file.description.read() else {
            return false;
        };
        match &*open {
            OpenDescription::PipeReader { .. } | OpenDescription::PipeWriter { .. } => true,
            OpenDescription::HostPipe {
                write_kind, pty, ..
            } => pty.is_some() || *write_kind == HostWriteKind::PipeLike,
            _ => false,
        }
    }

    /// True iff `fd` is a splice/tee SOURCE that is not open for reading, so
    /// splice(2) must reject it with EBADF: an `O_PATH` descriptor, a
    /// write-only regular file, or the write end of a one-way pipe (splice03's
    /// write-only case, splice07's `O_PATH`/pipe-write-end sources).
    fn splice_source_not_readable(&self, fd: i32) -> bool {
        if self.fd_is_o_path(fd) {
            return true;
        }
        let Some(open_file) = self.open_file(fd) else {
            return false;
        };
        let Some(open) = open_file.description.read() else {
            return false;
        };
        match &*open {
            OpenDescription::File { .. }
            | OpenDescription::SyntheticFile { .. }
            | OpenDescription::HostFile { .. }
            | OpenDescription::SyntheticDevice { .. } => {
                open_file.description.common().status_flags() & LINUX_O_ACCMODE == LINUX_O_WRONLY
            }
            OpenDescription::PipeWriter { .. } => true,
            OpenDescription::HostPipe {
                is_read_end,
                pty,
                bidirectional,
                ..
            } => pty.is_none() && !*bidirectional && !*is_read_end,
            _ => false,
        }
    }

    /// tee(2) for in-memory anonymous pipes: duplicate up to `count` bytes from
    /// the source pipe's buffer to the destination pipe WITHOUT consuming or
    /// reordering the source.
    #[allow(clippy::too_many_arguments)]
    fn in_memory_tee(
        &self,
        in_fd: i32,
        in_pipe: &PipeRef,
        in_status_flags: u64,
        out_fd: i32,
        out_pipe: &PipeRef,
        out_status_flags: u64,
        count: usize,
        splice_flags: LinuxSpliceFlags,
    ) -> Result<DispatchOutcome, DispatchError> {
        let in_nonblocking = splice_flags.contains(LinuxSpliceFlags::NONBLOCK)
            || (in_status_flags & LINUX_O_NONBLOCK != 0);
        let out_nonblocking = splice_flags.contains(LinuxSpliceFlags::NONBLOCK)
            || (out_status_flags & LINUX_O_NONBLOCK != 0);

        match pipe::tee_in_memory_pipes(in_pipe, out_pipe, count) {
            pipe::InMemoryTeeOutcome::SamePipe => Ok(DispatchOutcome::errno(LINUX_EINVAL)),
            pipe::InMemoryTeeOutcome::BrokenPipe => Ok(DispatchOutcome::errno(LINUX_EPIPE)),
            pipe::InMemoryTeeOutcome::Eof => Ok(DispatchOutcome::Returned { value: 0 }),
            pipe::InMemoryTeeOutcome::SourceWouldBlock => {
                let Some(host_fd) = in_pipe.read_poll_fd() else {
                    return Ok(DispatchOutcome::errno(linux_errno::EMFILE));
                };
                Ok(self.splice_host_output_wait(
                    in_fd,
                    host_fd.raw(),
                    libc::POLLIN,
                    Some(host_fd),
                    in_nonblocking,
                ))
            }
            pipe::InMemoryTeeOutcome::DestWouldBlock => {
                let Some(host_fd) = out_pipe.write_poll_fd() else {
                    return Ok(DispatchOutcome::errno(linux_errno::EMFILE));
                };
                Ok(self.splice_host_output_wait(
                    out_fd,
                    host_fd.raw(),
                    libc::POLLIN,
                    Some(host_fd),
                    out_nonblocking,
                ))
            }
            pipe::InMemoryTeeOutcome::Transferred(written) => {
                Ok(DispatchOutcome::returned_len_or_errno(written))
            }
        }
    }

    /// tee(2): duplicate up to `count` bytes from the source pipe's read end to
    /// the destination pipe's write end WITHOUT consuming the source. On a Linux
    /// host the real `tee(2)` is exact; elsewhere (macOS/BSD lack `tee(2)`) fall
    /// back to a userspace peek-and-copy.
    fn host_tee(
        &self,
        in_read: HostFd,
        in_pipe_id: u64,
        out_write: HostFd,
        count: usize,
        flags: LinuxSpliceFlags,
    ) -> Result<DispatchOutcome, DispatchError> {
        #[cfg(target_os = "linux")]
        {
            let _ = in_pipe_id;
            tee_host_passthrough(in_read, out_write, count, flags)
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.userspace_tee(in_read, in_pipe_id, out_write, count, flags)
        }
    }

    /// Userspace `tee(2)` for hosts without the syscall: drain the source pipe's
    /// currently-buffered bytes, write them back through the source's write end
    /// to restore it (FIFO order is preserved because the pipe is momentarily
    /// emptied first), then copy up to `count` of them into the destination
    /// pipe. The restore runs before the copy so a short/failed destination
    /// write still leaves the non-consumed source intact.
    #[cfg(not(target_os = "linux"))]
    fn userspace_tee(
        &self,
        in_read: HostFd,
        in_pipe_id: u64,
        out_write: HostFd,
        count: usize,
        flags: LinuxSpliceFlags,
    ) -> Result<DispatchOutcome, DispatchError> {
        let nonblock = flags.contains(LinuxSpliceFlags::NONBLOCK);
        let avail = host_pipe_readable_bytes(in_read.get()).unwrap_or(0);
        if avail == 0 {
            // Nothing buffered: a non-blocking tee is EAGAIN; a blocking tee
            // would wait for the writer, which this path does not park for under
            // the dispatcher lock, so report 0 (empty/writer-closed) instead.
            return Ok(if nonblock {
                DispatchOutcome::errno(LINUX_EAGAIN)
            } else {
                DispatchOutcome::Returned { value: 0 }
            });
        }
        // Drain the whole buffer so the writeback restores it in FIFO order.
        let mut buf = vec![0u8; avail];
        let n = unsafe {
            // BLOCKING-IO-OK: HostPipe fds are adopted O_NONBLOCK and `avail`
            // was measured immediately before the read.
            libc::read(
                in_read.get(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                avail,
            )
        };
        let n = n.host_syscall_errno()?;
        if n <= 0 {
            return Ok(if nonblock {
                DispatchOutcome::errno(LINUX_EAGAIN)
            } else {
                DispatchOutcome::Returned { value: 0 }
            });
        }
        buf.truncate(n as usize);
        // Restore the source: write the drained bytes back via its write end. The
        // pipe was just emptied, so a non-blocking write of `n <= capacity`
        // completes in full and preserves order. If no write end is open (the
        // source's writer was closed) the source is consumed — a best-effort
        // fallback; tee01 keeps the source write end open.
        if let Some(write_fd) = self.host_pipe_write_end_for_pipe_id(in_pipe_id) {
            let mut off = 0usize;
            while off < buf.len() {
                let w = unsafe {
                    // BLOCKING-IO-OK: the source pipe was just drained, so this
                    // bounded restore writes back into known room.
                    libc::write(
                        write_fd.get(),
                        buf[off..].as_ptr().cast::<libc::c_void>(),
                        buf.len() - off,
                    )
                };
                match w.host_syscall_errno() {
                    Ok(c) if c > 0 => off += c as usize,
                    _ => break,
                }
            }
        }
        // Copy up to `count` bytes into the destination pipe.
        let copy_len = count.min(buf.len());
        let mut written = 0usize;
        while written < copy_len {
            let w = unsafe {
                // BLOCKING-IO-OK: HostPipe fds are adopted O_NONBLOCK; a full
                // destination returns EAGAIN and is handled below.
                libc::write(
                    out_write.get(),
                    buf[written..copy_len].as_ptr().cast::<libc::c_void>(),
                    copy_len - written,
                )
            };
            match w.host_syscall_errno() {
                Ok(c) if c > 0 => written += c as usize,
                // A full destination with nothing copied yet is EAGAIN under
                // SPLICE_F_NONBLOCK; otherwise report whatever landed.
                Err(e) if e == LINUX_EAGAIN && written == 0 && nonblock => {
                    return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                }
                _ => break,
            }
        }
        Ok(DispatchOutcome::returned_len_or_errno(written))
    }

    fn host_pipe_splice_staging_target(&self, fd: i32) -> Option<(i32, usize)> {
        let (pipe_id, capacity) = {
            let open_file = self.open_file(fd)?;
            let open = open_file.description.read()?;
            match &*open {
                OpenDescription::HostPipe {
                    base,
                    is_read_end: false,
                    pipe_id,
                    pty: None,
                    bidirectional: false,
                    ..
                } if *pipe_id != 0 => (*pipe_id, base.pipe_capacity()),
                _ => return None,
            }
        };
        let (read_fd, _) = self.host_pipe_read_end_for_pipe_id(pipe_id)?;
        let capacity = usize::try_from(capacity).ok()?;
        let queued = self.host_pipe_read_end_buffered_bytes(pipe_id);
        Some((read_fd, capacity.saturating_sub(queued)))
    }

    /// Room in a pipe destination, in bytes — `None` when `fd` is not a
    /// pipe. Uses the same accounting the write path applies
    /// ([`super::host_pipe_write_room`]), so a `splice(2)`/`vmsplice(2)` that bounds
    /// its transfer window by this value never hands the writer more than the pipe can take.
    /// Unlike [`Self::host_pipe_splice_staging_target`] this accepts any pipe
    /// write end, including in-memory pipes, pty, and bidirectional ends.
    fn splice_pipe_write_room(&self, fd: i32) -> Option<usize> {
        let open_file = self.open_file(fd)?;
        let open = open_file.description.read()?;
        match &*open {
            OpenDescription::PipeWriter { pipe, .. } => {
                let state = pipe.state.lock();
                Some(state.capacity.saturating_sub(state.buffer.len()))
            }
            OpenDescription::HostPipe {
                base,
                pipe_id,
                is_read_end,
                bidirectional,
                host_fd,
                ..
            } => {
                let (capacity, queued) = self.host_pipe_capacity_state(
                    base,
                    *pipe_id,
                    *is_read_end,
                    *bidirectional,
                    host_fd.raw(),
                )?;
                super::host_pipe_write_room(capacity, queued)
            }
            _ => None,
        }
    }

    pub(in crate::dispatch) fn host_pipe_capacity_state(
        &self,
        base: &OpenDescriptionBase,
        pipe_id: u64,
        is_read_end: bool,
        bidirectional: bool,
        host_fd: i32,
    ) -> Option<(i64, usize)> {
        let queued = if is_read_end || bidirectional {
            host_pipe_readable_bytes(host_fd).ok().unwrap_or(0)
        } else {
            self.host_pipe_read_end_buffered_bytes(pipe_id)
        };
        Some((base.pipe_capacity(), queued))
    }

    pub(in crate::dispatch) fn host_pipe_capacity_room(
        &self,
        pipe_capacity: i64,
        pipe_id: u64,
        is_read_end: bool,
        bidirectional: bool,
        host_fd: i32,
    ) -> Option<usize> {
        let queued = if is_read_end || bidirectional {
            host_pipe_readable_bytes(host_fd).ok().unwrap_or(0)
        } else {
            self.host_pipe_read_end_buffered_bytes(pipe_id)
        };
        super::host_pipe_write_room(pipe_capacity, queued)
    }

    fn host_pipe_read_end_buffered_bytes(&self, pipe_id: u64) -> usize {
        let files = self.captured_file_table();
        let table = files.read_open_files();
        for other in table.values() {
            let Some(other_open) = other.description.try_read() else {
                continue;
            };
            if let OpenDescription::HostPipe {
                host_fd,
                is_read_end: true,
                pipe_id: other_pipe_id,
                ..
            } = &*other_open
                && *other_pipe_id == pipe_id
            {
                return host_pipe_readable_bytes(host_fd.raw()).ok().unwrap_or(0)
                    + other.description.common().splice_pushback().lock().len();
            }
        }
        0
    }

    pub(super) fn staged_splice_pipe_bytes(&self, guest_fd: i32) -> usize {
        self.open_file(guest_fd).map_or(0, |file| {
            file.description.common().splice_pushback().lock().len()
        })
    }

    pub(super) fn staged_splice_description_bytes(
        &self,
        description: crate::kernel::FileDescriptionId,
    ) -> usize {
        let files = resources::files().unwrap_or_else(|| self.captured_file_table());
        for slot in files.read_open_files().values() {
            if slot.description.id() == description {
                return slot.description.common().splice_pushback().lock().len();
            }
        }
        0
    }

    pub(in crate::dispatch) fn discard_splice_pushback_if_final(&self, guest_fd: i32) {
        let Some(file) = self.open_file(guest_fd) else {
            return;
        };
        if file.description.fd_ref_count() == 1
            && !file
                .description
                .common()
                .splice_pushback()
                .lock()
                .is_empty()
        {
            file.description.clear_splice_pushback();
        }
    }

    /// True iff `fd` refers to a pipe / socket / character device — kinds with
    /// no `->fsync` file op, so `fsync`/`fdatasync` on them is EINVAL on Linux
    /// (e.g. fdatasync02 on `/dev/null`, which carrick serves as a `HostPipe`).
    /// A directory (dir fsync is valid) and synthetic / in-memory files are a
    /// no-op success, so they return false.
    fn fd_lacks_fsync(&self, fd: i32) -> bool {
        self.open_file(fd).is_some_and(|of| {
            matches!(
                of.description.read().as_deref(),
                Some(
                    OpenDescription::HostPipe { .. }
                        | OpenDescription::HostSocket { .. }
                        | OpenDescription::InMemorySocket { .. }
                        | OpenDescription::PipeReader { .. }
                        | OpenDescription::PipeWriter { .. }
                        | OpenDescription::SyntheticDevice { .. }
                )
            )
        })
    }

    /// Deliver a bare-stdio write (fd 1/2 with no `OpenDescription`) to the
    /// run's [`StdioSink`]. Reads the route once so no dispatcher lock is held
    /// across the blocking host or caller write.
    fn write_stdio_sink(&self, fd: i32, bytes: &[u8]) -> DispatchOutcome {
        #[cfg(feature = "trace-io")]
        if !bytes.is_empty() {
            eprintln!(
                "[IODBG] SINKWRITE fd={fd} n={} bytes={:02x?}",
                bytes.len(),
                &bytes[..bytes.len().min(64)]
            );
        }
        match self.io.route() {
            StdioRoute::Captured => {
                match fd {
                    1 => self.io.stdout.lock().extend_from_slice(bytes),
                    2 => self.io.stderr.lock().extend_from_slice(bytes),
                    _ => return DispatchOutcome::errno(LINUX_EBADF),
                }
                DispatchOutcome::returned_len_or_errno(bytes.len())
            }
            // BLOCKING-IO-OK: the inherited stdout/stderr (the user's
            // tty/pipe); blocking here is the correct backpressure.
            StdioRoute::Inherit => match fd {
                1 | 2 => Self::write_all_stdio(fd, bytes),
                _ => DispatchOutcome::errno(LINUX_EBADF),
            },
            // BLOCKING-IO-OK: the embedder's writer runs on this vCPU thread;
            // a blocking writer blocks this guest write, like a full pipe.
            StdioRoute::Piped { stdout, stderr } => {
                let writer = match fd {
                    1 => stdout,
                    2 => stderr,
                    _ => return DispatchOutcome::errno(LINUX_EBADF),
                };
                let mut writer = writer.lock();
                // UFCS: `std::io::Write` is not imported anywhere in this file
                // (no `use std::io` at all) and one call does not earn one.
                match std::io::Write::write_all(&mut *writer, bytes) {
                    Ok(()) => DispatchOutcome::returned_len_or_errno(bytes.len()),
                    Err(error) => DispatchOutcome::errno(crate::host_to_linux_errno(
                        error.raw_os_error().unwrap_or(libc::EIO),
                    )),
                }
            }
        }
    }

    /// Write ALL of `bytes` to an inherited stdio host fd (`StdioSink::Inherit`: the user's tty/pipe),
    /// looping until the whole buffer is queued. The dup2'd stdio pty slave can
    /// be O_NONBLOCK — a line editor that sets stdin non-blocking flips the
    /// SHARED slave description, so stdout/stderr go non-blocking too — and then
    /// a single `write` can short-write or EAGAIN and silently DROP the tail.
    /// That lost busybox ash's post-Enter newline (output ran onto the prompt
    /// line) and the tail of wide `ls` output. Polling for writability on EAGAIN
    /// restores Linux blocking-tty semantics (a tty write completes fully) without
    /// mutating the shared O_NONBLOCK flag the guest may rely on for reads.
    fn write_all_stdio(fd: i32, bytes: &[u8]) -> DispatchOutcome {
        let mut off = 0usize;
        while off < bytes.len() {
            // BLOCKING-IO-OK: a write to the inherited controlling tty/pipe
            // (stdout/stderr); blocking on backpressure is correct, and callers
            // release the route lock before getting here (no dispatcher
            // lock is held across this write).
            // SAFETY: fd is a live inherited stdio fd; we write a sub-slice of `bytes`.
            let n = unsafe {
                libc::write(
                    fd,
                    bytes[off..].as_ptr() as *const libc::c_void,
                    bytes.len() - off,
                )
            };
            if n > 0 {
                off += n as usize;
                continue;
            }
            // SAFETY: reading the thread-local errno after a failed libc call.
            let e = get_last_error();
            if e == libc::EINTR {
                continue;
            }
            if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
                // Wait for the slave to drain, then retry — never drop the tail.
                let mut pfd = libc::pollfd {
                    fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                // SAFETY: single valid pollfd; blocking wait for writability.
                unsafe { libc::poll(&mut pfd, 1, -1) };
                continue;
            }
            // Hard error: report it if nothing was written, else the partial
            // count (matching write(2)).
            if off == 0 {
                return DispatchOutcome::errno(crate::host_to_linux_errno(e));
            }
            break;
        }
        DispatchOutcome::returned_len_or_errno(off)
    }

    fn read_host_pipe_iovecs<M: CurrentMmMemory>(
        memory: &mut M,
        iovecs: &[LinuxIovec],
        host_fd: i32,
        host_fd_owner: Option<HostFdRef>,
        nonblocking: bool,
        authority: WaitFdAuthority,
    ) -> DispatchOutcome {
        let mut total = 0i64;
        for iov in iovecs {
            let len = match usize::try_from(iov.iov_len) {
                Ok(len) => len,
                Err(_) => return DispatchOutcome::errno(LINUX_EINVAL),
            };
            if len == 0 {
                continue;
            }
            match read_host_pipe(
                memory,
                iov.iov_base,
                len,
                host_fd,
                host_fd_owner.clone(),
                nonblocking,
                authority.clone(),
            ) {
                DispatchOutcome::Returned { value } => {
                    total += value;
                    if value == 0 || (value as usize) < len {
                        break;
                    }
                }
                _ if total > 0 => return DispatchOutcome::Returned { value: total },
                other => return other,
            }
        }
        DispatchOutcome::Returned { value: total }
    }

    /// Write `bytes` to a splice/sendfile destination, honoring `off_out`: NULL
    /// (addr 0) writes at the fd's current position; non-NULL pwrites at the
    /// given offset on a regular HostFile and advances `*off_out` (Linux allows
    /// off_out when fd_out is a regular file even though fd_in is a pipe —
    /// test_os.test_splice_offset_out). off_out on a non-regular target → EINVAL.
    ///
    /// The destination is written with `splice(2)`'s PARTIAL contract
    /// ([`Self::write_output_fd_partial`]): a pipe or socket that fills
    /// mid-transfer yields a short count, never a park until every byte lands.
    /// Every caller either re-stages the undelivered tail
    /// ([`Self::restore_splice_pipe_bytes`], [`Self::restore_pipe_bytes`]) or
    /// never consumed it (`vmsplice` gathers from guest memory), so a short
    /// count loses nothing.
    fn splice_write_out<M: CurrentMmMemory>(
        &self,
        out_fd: i32,
        off_out_addr: u64,
        bytes: &[u8],
        memory: &mut M,
        tid: crate::thread::ThreadId,
        nonblocking: bool,
    ) -> DispatchOutcome {
        if off_out_addr == 0 {
            if let Some(open_file) = self.open_file(out_fd) {
                if let Some(open) = open_file.description.read()
                    && let OpenDescription::SyntheticDevice {
                        kind:
                            crate::vfs::SyntheticDeviceKind::Null
                            | crate::vfs::SyntheticDeviceKind::Zero,
                        ..
                    } = &*open
                {
                    let flags = open_file.description.common().status_flags();
                    return if flags & LINUX_O_ACCMODE == LINUX_O_RDONLY {
                        DispatchOutcome::errno(LINUX_EBADF)
                    } else if LinuxOpenFlags::from_bits_truncate(flags)
                        .contains(LinuxOpenFlags::APPEND)
                    {
                        DispatchOutcome::errno(LINUX_EINVAL)
                    } else {
                        DispatchOutcome::returned_len_or_errno(bytes.len())
                    };
                }
            }
            return match self.write_output_fd_partial(out_fd, bytes, tid) {
                // The destination could not take a single byte. A blocking
                // `splice(2)` waits for room; the partial write path reports
                // that as `EAGAIN` because it asked non-blocking, so restore
                // the guest's own blocking mode here.
                DispatchOutcome::Errno { errno } if errno == LINUX_EAGAIN && !nonblocking => {
                    self.splice_output_would_block(out_fd, false)
                }
                other => other,
            };
        }
        let out_off = match read_u64(memory, off_out_addr) {
            Ok(v) => v,
            Err(errno) => return DispatchOutcome::errno(errno),
        };
        let host_fd = match self.open_file(out_fd).as_ref() {
            Some(of) => match of.description.read().as_deref() {
                Some(OpenDescription::HostFile {
                    host_fd,
                    writable: true,
                    ..
                }) => host_fd.raw(),
                Some(OpenDescription::HostFile { .. }) => {
                    return DispatchOutcome::errno(LINUX_EBADF);
                }
                _ => return DispatchOutcome::errno(LINUX_EINVAL),
            },
            None => return DispatchOutcome::errno(LINUX_EBADF),
        };
        let n = unsafe {
            libc::pwrite(
                host_fd,
                bytes.as_ptr() as *const _,
                bytes.len(),
                out_off as libc::off_t,
            )
        };
        let n = match n.host_syscall_errno() {
            Ok(value) => value as usize,
            Err(errno) => return DispatchOutcome::errno(errno),
        };
        if memory
            .write_bytes(off_out_addr, &(out_off + n as u64).to_ne_bytes())
            .is_err()
        {
            return DispatchOutcome::errno(LINUX_EFAULT);
        }
        DispatchOutcome::returned_len_or_errno(n)
    }

    /// Pull up to `count` bytes off a `splice(2)` SOURCE pipe.
    ///
    /// `Ok(Ok(bytes))` is the transfer (empty = EOF, the writers are gone).
    /// `Ok(Err(outcome))` is "nothing available": `EAGAIN` for a non-blocking
    /// splice, a `WaitOnFds` readiness park for a blocking one — the same
    /// classification `blocking_io`/`read_host_pipe` apply to every other host
    /// read. carrick's host pipe fds are FORCED `O_NONBLOCK` at creation, so a
    /// bare `read` here surfaced a host `EAGAIN` verbatim and a blocking guest
    /// `splice` on an empty pipe failed instead of waiting.
    fn take_splice_pipe_bytes(
        &self,
        guest_fd: i32,
        host_fd: HostFd,
        host_fd_owner: Option<HostFdRef>,
        count: usize,
        nonblocking: bool,
    ) -> Result<Result<Vec<u8>, DispatchOutcome>, DispatchError> {
        let buf = self.take_staged_splice_pipe_bytes(guest_fd, count)?;
        // A pipe read returns the bytes already available without waiting to
        // fill the caller's whole buffer. The staged queue is the front of this
        // host pipe's logical byte stream, so do not probe the empty host fd
        // after consuming a short staged prefix (that would turn readable data
        // into EAGAIN and lose the prefix).
        if !buf.is_empty() {
            return Ok(Ok(buf));
        }

        let mut buf = vec![0; count];
        // BLOCKING-IO-OK: the host fd is O_NONBLOCK by construction; EAGAIN is
        // classified below rather than reaching the guest raw.
        let n = unsafe {
            libc::read(
                host_fd.get(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                count,
            )
        };
        let n = match n.host_syscall_errno() {
            Ok(n) => n,
            // EINTR is carrick's own machinery (the SIGURG vCPU kick), never
            // the guest's: route it through readiness like `read_host_pipe`.
            Err(errno) if errno == LINUX_EAGAIN || errno == LINUX_EINTR => {
                return Ok(Err(super::would_block_outcome(
                    host_fd.get(),
                    libc::POLLIN,
                    nonblocking,
                    host_fd_owner,
                    WaitFdAuthority::logical(
                        self.captured_slot_authority(guest_fd).ok_or(LINUX_EBADF)?,
                    ),
                )));
            }
            Err(errno) => return Err(DispatchError::Errno(errno)),
        };
        buf.truncate(n as usize);
        Ok(Ok(buf))
    }

    fn take_staged_splice_pipe_bytes(
        &self,
        guest_fd: i32,
        count: usize,
    ) -> Result<Vec<u8>, DispatchError> {
        let file = self
            .open_file(guest_fd)
            .ok_or(DispatchError::Errno(LINUX_EBADF))?;
        let mut queue = file.description.common().splice_pushback().lock();
        let bytes = queue.take_vec(count);
        Ok(bytes)
    }

    /// Stage `bytes` on an open description directly, for callers that must not
    /// touch the file table (see `dispatch::pty_registry`).
    pub(super) fn stage_splice_bytes_for_description(
        &self,
        description: &crate::kernel::FileDescription,
        bytes: Vec<u8>,
    ) {
        if bytes.is_empty() {
            return;
        }
        description
            .common()
            .splice_pushback()
            .lock()
            .push_back_owned(bytes);
        self.notify_inmem_epoll();
    }

    pub(super) fn stage_splice_pipe_bytes_owned(&self, guest_fd: i32, bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        let Some(file) = self.open_file(guest_fd) else {
            return;
        };
        file.description
            .common()
            .splice_pushback()
            .lock()
            .push_back_owned(bytes);
        // The payload is userspace-resident rather than in the host pipe, so a
        // host kqueue/poll edge cannot announce it. Wake epoll instances to
        // force their level-readiness recompute.
        self.notify_inmem_epoll();
    }

    /// Push an undelivered `splice(2)` tail back onto the FRONT of an
    /// in-memory pipe, the [`Self::restore_splice_pipe_bytes`] twin for the
    /// legacy `PipeReader` source. A short destination write must leave the
    /// source byte stream exactly as it found it minus what was delivered.
    fn restore_pipe_bytes(pipe: &PipeRef, bytes: &[u8]) {
        pipe::restore_pipe_bytes(pipe, bytes);
    }

    /// The destination's readiness park for a blocking `splice`/`vmsplice`
    /// whose output could not take a single byte. Nothing has been consumed
    /// when this is reached, so the runtime re-dispatches the whole call after
    /// the wait; a non-blocking caller gets `EAGAIN` instead.
    fn splice_output_would_block(&self, fd: i32, nonblocking: bool) -> DispatchOutcome {
        let target = self.open_file(fd).and_then(|file| {
            let open = file.description.read()?;
            match &*open {
                OpenDescription::HostPipe { host_fd, .. }
                | OpenDescription::HostSocket { host_fd, .. } => {
                    Some((host_fd.raw(), libc::POLLOUT, Some(host_fd.clone())))
                }
                OpenDescription::PipeWriter { pipe, .. } => {
                    let host_fd = pipe.write_poll_fd()?;
                    Some((host_fd.raw(), libc::POLLIN, Some(host_fd)))
                }
                _ => None,
            }
        });
        match target {
            Some((host_fd, events, owner)) => {
                self.splice_host_output_wait(fd, host_fd, events, owner, nonblocking)
            }
            // No readiness source to park on: report the condition rather than
            // parking on nothing.
            None => DispatchOutcome::errno(LINUX_EAGAIN),
        }
    }

    fn splice_host_output_wait(
        &self,
        fd: i32,
        host_fd: i32,
        events: i16,
        owner: Option<HostFdRef>,
        nonblocking: bool,
    ) -> DispatchOutcome {
        let Some(authority) = self.captured_slot_authority(fd) else {
            return DispatchOutcome::errno(LINUX_EBADF);
        };
        super::would_block_outcome(
            host_fd,
            events,
            nonblocking,
            owner,
            WaitFdAuthority::logical(authority),
        )
    }

    fn restore_splice_pipe_bytes(&self, guest_fd: i32, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let Some(file) = self.open_file(guest_fd) else {
            return;
        };
        file.description
            .common()
            .splice_pushback()
            .lock()
            .push_front(bytes);
    }

    fn write_output_fd(
        &self,
        fd: i32,
        bytes: &[u8],
        tid: crate::thread::ThreadId,
    ) -> DispatchOutcome {
        self.write_output_fd_inner(fd, bytes, tid, false)
    }

    /// `splice(2)` flavour of [`Self::write_output_fd`]: the destination is
    /// written with non-blocking semantics, so a pipe that fills mid-transfer
    /// yields a SHORT count (or `EAGAIN` when nothing moved) instead of parking
    /// until every byte is delivered.
    ///
    /// `write(2)` must deliver the whole buffer and may block to do it;
    /// `splice(2)` explicitly may transfer fewer bytes than requested and
    /// leaves the loop to the caller. Using the `write(2)` contract for splice
    /// deadlocks whenever the only reader is the same single-threaded guest —
    /// it cannot drain the pipe until the splice it is blocked in returns.
    fn write_output_fd_partial(
        &self,
        fd: i32,
        bytes: &[u8],
        tid: crate::thread::ThreadId,
    ) -> DispatchOutcome {
        self.write_output_fd_inner(fd, bytes, tid, true)
    }

    fn write_output_fd_inner(
        &self,
        fd: i32,
        bytes: &[u8],
        tid: crate::thread::ThreadId,
        partial_ok: bool,
    ) -> DispatchOutcome {
        let nonblocking = partial_ok || self.io_is_nonblocking(fd, 0);
        // Mirror `write`/`writev`: any fd present in `open_files` (e.g.
        // after a dup3 over stdio) takes precedence over the built-in
        // stdout/stderr buffers. Without this, `busybox cat`'s
        // `sendfile(1, infile, ...)` writes the file contents to the
        // dispatcher's internal stdout instead of the pipe write end.
        if let Some(open_file) = self.open_file(fd) {
            // Regular-file destinations need the overlay writeback to happen
            // AFTER the description borrow is dropped, so use the same
            // collect-then-write pattern as `write`. Non-file arms return
            // directly. This is what makes splice/copy_file_range/sendfile to a
            // regular file (off_out at the fd's current position) work, matching
            // real Linux (splice pipe->file).
            let outcome: DispatchOutcome;
            let writeback: Option<(String, usize, usize)>;
            {
                let Some(mut open) = open_file.description.write() else {
                    return DispatchOutcome::errno(LINUX_EBADF);
                };
                match &mut *open {
                    OpenDescription::PipeWriter { pipe, .. } => {
                        let flags = if nonblocking {
                            open_file.description.common().status_flags() | LINUX_O_NONBLOCK
                        } else {
                            open_file.description.common().status_flags()
                        };
                        let Some(wait_authority) = self
                            .captured_slot_authority(fd)
                            .map(WaitFdAuthority::logical)
                        else {
                            return DispatchOutcome::errno(LINUX_EBADF);
                        };
                        return write_pipe(bytes, pipe, flags, fd, wait_authority, || false);
                    }
                    OpenDescription::HostPipe {
                        base,
                        host_fd,
                        is_read_end,
                        pipe_id,
                        pty,
                        bidirectional,
                        write_kind,
                        stdio_stream,
                        ..
                    } => {
                        if let Some(stream) = *stdio_stream {
                            if stream == 0 {
                                return DispatchOutcome::errno(LINUX_EBADF);
                            }
                            if !self.io.inherits_host_stdio() {
                                drop(open);
                                return self.write_stdio_sink(stream, bytes);
                            }
                        }
                        // pty ends and O_RDWR FIFOs are bidirectional; only real
                        // one-way pipe ends are gated by is_read_end.
                        #[cfg(feature = "trace-tty")]
                        if bytes.contains(&0x0a) {
                            let hf = host_fd.raw();
                            let tt = unsafe { libc::isatty(hf) };
                            eprintln!(
                                "[PTYWR2DBG-streamed] guest_fd={fd} desc_host_fd={hf} isatty={tt} pty={:?} is_read_end={is_read_end}",
                                pty.as_ref().map(|r| r.is_master)
                            );
                        }
                        return if *is_read_end && pty.is_none() && !*bidirectional {
                            DispatchOutcome::errno(LINUX_EBADF)
                        } else {
                            let (bytes_to_write, consumed_count) = if let Some(PtyRole {
                                index,
                                is_master: true,
                            }) = pty
                            {
                                let orig_len = bytes.len();
                                let forwarded = crate::kernel::tty::process_master_write(
                                    crate::kernel::tty::TtyKey::Pty(*index),
                                    host_fd.raw(),
                                    bytes,
                                );
                                let consumed = orig_len - forwarded.len();
                                (forwarded, consumed)
                            } else {
                                (bytes.to_vec(), 0)
                            };
                            if bytes_to_write.is_empty() && consumed_count > 0 {
                                return DispatchOutcome::returned_len_or_errno(consumed_count);
                            }
                            let Some(wait_authority) = self
                                .captured_slot_authority(fd)
                                .map(WaitFdAuthority::logical)
                            else {
                                return DispatchOutcome::errno(LINUX_EBADF);
                            };
                            let res = write_host_pipe_owned(
                                bytes_to_write,
                                HostPipeWriteTarget {
                                    host_fd: host_fd.raw(),
                                    host_fd_owner: Some(host_fd.clone()),
                                    nonblocking,
                                    write_kind: *write_kind,
                                    pipe_state: self.host_pipe_capacity_state(
                                        base,
                                        *pipe_id,
                                        *is_read_end,
                                        *bidirectional,
                                        host_fd.raw(),
                                    ),
                                    tid,
                                    sigpipe_on_epipe: true,
                                    authority: wait_authority,
                                },
                            );
                            match res {
                                DispatchOutcome::Returned { value } => {
                                    let total = usize::try_from(value)
                                        .ok()
                                        .and_then(|v| v.checked_add(consumed_count));
                                    match total {
                                        Some(t) => DispatchOutcome::returned_len_or_errno(t),
                                        None => DispatchOutcome::errno(LINUX_EOVERFLOW),
                                    }
                                }
                                other => {
                                    if consumed_count > 0 {
                                        DispatchOutcome::returned_len_or_errno(consumed_count)
                                    } else {
                                        other
                                    }
                                }
                            }
                        };
                    }
                    OpenDescription::HostSocket { host_fd, .. } => {
                        let Some(wait_authority) = self
                            .captured_slot_authority(fd)
                            .map(WaitFdAuthority::logical)
                        else {
                            return DispatchOutcome::errno(LINUX_EBADF);
                        };
                        return write_host_pipe_owned(
                            bytes.to_vec(),
                            HostPipeWriteTarget {
                                host_fd: host_fd.raw(),
                                host_fd_owner: Some(host_fd.clone()),
                                nonblocking,
                                write_kind: HostWriteKind::SocketLike,
                                pipe_state: None,
                                tid,
                                sigpipe_on_epipe: false,
                                authority: wait_authority,
                            },
                        );
                    }
                    OpenDescription::InMemorySocket { socket, .. } => {
                        let socket = Arc::clone(socket);
                        return match socket.send_stream(bytes, Vec::new()) {
                            Ok(written) => {
                                self.notify_inmem_epoll();
                                DispatchOutcome::returned_len_or_errno(written)
                            }
                            Err(errno) => DispatchOutcome::errno(errno),
                        };
                    }
                    OpenDescription::HostFile {
                        host_fd, writable, ..
                    } => {
                        if !*writable {
                            return DispatchOutcome::errno(LINUX_EBADF);
                        }
                        if LinuxOpenFlags::from_bits_truncate(
                            open_file.description.common().status_flags(),
                        )
                        .contains(LinuxOpenFlags::APPEND)
                        {
                            // Let the HOST kernel perform the append. Linux's
                            // O_APPEND seeks to end and writes as ONE atomic
                            // operation; emulating it as `lseek(SEEK_END)` then
                            // a separate `write` is a race, because anything
                            // touching the shared open description in between
                            // moves the write. A concurrent reader that seeks
                            // to the start sends the append to offset 0, which
                            // is how Go build-cache archives lost their
                            // `!<arch>\n` magic under a parallel `go build`.
                            // Darwin honours O_APPEND natively, so ensure the
                            // description carries it rather than approximating
                            // the offset ourselves.
                            let current = unsafe { libc::fcntl(host_fd.raw(), libc::F_GETFL, 0) };
                            if current >= 0 && current & libc::O_APPEND == 0 {
                                unsafe {
                                    libc::fcntl(
                                        host_fd.raw(),
                                        libc::F_SETFL,
                                        current | libc::O_APPEND,
                                    )
                                };
                            }
                        }
                        let Some(wait_authority) = self
                            .captured_slot_authority(fd)
                            .map(WaitFdAuthority::logical)
                        else {
                            return DispatchOutcome::errno(LINUX_EBADF);
                        };
                        return write_host_pipe(
                            bytes,
                            HostPipeWriteTarget {
                                host_fd: host_fd.raw(),
                                host_fd_owner: Some(host_fd.clone()),
                                nonblocking,
                                write_kind: HostWriteKind::RegularFile,
                                pipe_state: None,
                                tid,
                                sigpipe_on_epipe: false,
                                authority: wait_authority,
                            },
                        );
                    }
                    OpenDescription::File {
                        path,
                        contents,
                        offset,
                        writable,
                        metadata,
                        ..
                    } => {
                        if !*writable {
                            return DispatchOutcome::errno(LINUX_EBADF);
                        }
                        let write_offset = *offset;
                        let written = match write_into_file_contents(contents, offset, bytes) {
                            Ok(n) => n,
                            Err(errno) => return DispatchOutcome::errno(errno),
                        };
                        let cur_len = match contents.len() {
                            Ok(l) => l,
                            Err(errno) if written == 0 => return DispatchOutcome::errno(errno),
                            Err(_) => *offset as u64,
                        };
                        metadata.size = usize::try_from(cur_len).unwrap_or(metadata.size);
                        outcome = DispatchOutcome::returned_len_or_errno(written);
                        writeback = (!is_anon_overlay_path(path)).then(|| {
                            (
                                path.clone(),
                                write_offset,
                                usize::try_from(cur_len).unwrap_or(0),
                            )
                        });
                    }
                    _ => return DispatchOutcome::errno(LINUX_EBADF),
                }
            }
            if let Some((path, offset, final_size)) = writeback {
                let _ = self
                    .fs
                    .rootfs_vfs
                    .overlay
                    .write_file_range(&path, offset, bytes, final_size);
            }
            return outcome;
        }
        self.write_stdio_sink(fd, bytes)
    }

    /// Linux clears a regular file's set-user-ID (and set-group-ID, when the
    /// file is group-executable) bits on chown — a security measure so a
    /// chowned setuid binary can't grant the new owner's privileges. setgid
    /// without group-exec is a mandatory-locking marker and is left alone.
    fn clear_setid_on_chown(&self, path: &str) {
        let Some(real) = self.fs.rootfs_vfs.overlay.real_stat(path, false) else {
            return;
        };
        if !matches!(real.kind, RootFsEntryKind::File) {
            return;
        }
        let mut mode = real.mode;
        let mut changed = false;
        if mode & 0o4000 != 0 {
            mode &= !0o4000;
            changed = true;
        }
        if mode & 0o2000 != 0 && mode & 0o0010 != 0 {
            mode &= !0o2000;
            changed = true;
        }
        if changed {
            let _ = self.fs.rootfs_vfs.set_mode(path, mode);
        }
    }

    /// Apply atime/mtime to an *open fd* — the `futimens(fd, …)` path.
    /// For a host-backed file we drive `futimens(2)` on the live host fd so a
    /// subsequent fstat/statx (which both read live on-disk times) observes
    /// the set value. For an in-memory `File`, we route through the overlay by
    /// path. `None` entries are UTIME_OMIT (left untouched).
    fn set_fd_times(
        &self,
        fd: i32,
        atime: Option<(i64, i64)>,
        mtime: Option<(i64, i64)>,
    ) -> DispatchOutcome {
        let Some(open_file) = self.open_file(fd) else {
            return DispatchOutcome::errno(LINUX_EBADF);
        };
        let Some(open) = open_file.description.read() else {
            return DispatchOutcome::errno(LINUX_EBADF);
        };
        match &*open {
            OpenDescription::HostFile {
                host_fd, metadata, ..
            } => {
                let to_ts = |t: Option<(i64, i64)>| match t {
                    Some((sec, nsec)) => libc::timespec {
                        tv_sec: sec as libc::time_t,
                        tv_nsec: nsec as libc::c_long,
                    },
                    None => libc::timespec {
                        tv_sec: 0,
                        tv_nsec: libc::UTIME_OMIT,
                    },
                };
                let times = [to_ts(atime), to_ts(mtime)];
                let rc = unsafe { libc::futimens(host_fd.raw(), times.as_ptr()) };
                if rc < 0 {
                    // Best-effort: don't abort the caller on a failed
                    // timestamp set (see the path-branch rationale).
                    let e = std::io::Error::last_os_error();
                    crate::probes::fs_op(
                        "set_fd_times:futimens_err_besteffort",
                        &format!("fd={fd} {e}"),
                        e.raw_os_error().unwrap_or(0),
                    );
                } else {
                    let p = metadata.path.to_string_lossy();
                    if !p.is_empty() && !p.starts_with("/__carrick_") {
                        self.fs.rootfs_vfs.notify_inode_changed(&p, None);
                    }
                    self.invalidate_dentry_host_fd(host_fd.raw());
                }
                DispatchOutcome::Returned { value: 0 }
            }
            OpenDescription::File { metadata, .. }
            | OpenDescription::Directory { metadata, .. } => {
                let path = metadata.path.to_string_lossy().into_owned();
                drop(open);
                if let Some(m) = self.fs.vfs_mounts.resolve(&path) {
                    return match m.vfs.set_times(&m.full_path, atime, mtime, false) {
                        Ok(()) => {
                            self.fs.rootfs_vfs.notify_inode_changed(&path, None);
                            DispatchOutcome::Returned { value: 0 }
                        }
                        Err(errno) => DispatchOutcome::errno(errno),
                    };
                }
                // fd-based futimens: the descriptor already refers to the
                // resolved inode, so never re-follow (nofollow = false).
                match self.fs.rootfs_vfs.set_times(&path, atime, mtime, false) {
                    Ok(()) | Err(crate::fs_backend::BackendError::Unsupported) => {
                        DispatchOutcome::Returned { value: 0 }
                    }
                    Err(_) => DispatchOutcome::errno(LINUX_EROFS),
                }
            }
            // Directories, synthetic /proc files, pipes, sockets, anon_inode
            // fds: accept as a no-op (matches Linux's permissive behaviour for
            // the cases tooling actually exercises; we can't persist times for
            // the non-file kinds).
            _ => DispatchOutcome::Returned { value: 0 },
        }
    }

    fn openat2_checked_path<'a>(
        &self,
        context: &crate::kernel::KernelContext,
        dirfd: u64,
        path: &'a str,
        resolve: u64,
    ) -> Result<std::borrow::Cow<'a, str>, LinuxErrno> {
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

    pub(super) fn openat2_anchor_for_dirfd(&self, dirfd: u64) -> Result<String, LinuxErrno> {
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

    pub(super) fn resolve_at_path(&self, dirfd: u64, path: &str) -> Result<String, LinuxErrno> {
        // Cache only AT_FDCWD absolute paths: their resolution is independent of
        // the cwd and of any dirfd, so the guest path string alone is a complete
        // key. (Relative / dirfd-anchored paths would need those in the key; they
        // are rare in the syscall-bound hot loops this targets.) The cache is
        // validated against a fork-coherent generation bumped on structural fs
        // mutations, so a create/delete/rename/symlink correctly invalidates it.
        // Only successful resolutions are cached; errors re-resolve.
        // Build a cache key when the resolution is fully determined by the
        // guest path plus (for a relative path) the cwd:
        //   - absolute path      -> the path itself (cwd/dirfd irrelevant)
        //   - AT_FDCWD + relative -> cwd + '\0' + path, so a later chdir keys a
        //     different entry rather than serving a stale one (LTP fuzzy-sync
        //     tests chdir into their tmpdir and pass a relative name).
        // A relative path through a REAL dirfd depends on that fd's directory,
        // so it is not keyed here.
        let is_atfdcwd = (dirfd as i32) as i64 as u64 == LINUX_AT_FDCWD;
        let fs_context = self.captured_fs_context();
        let cache_key: Option<String> = if std::path::Path::new(path).is_absolute() {
            match fs_context.chroot_root().as_deref() {
                Some(root) if root != "/" => Some(format!("{root}\u{0}{path}")),
                _ => Some(path.to_owned()),
            }
        } else if is_atfdcwd {
            Some(format!("{}\u{0}{}", fs_context.cwd(), path))
        } else {
            None
        };
        // Sample the generation at ENTRY, before reading any fs state: a new
        // entry is stamped with this, so a mutation racing our resolve (which
        // bumps to a higher generation) leaves the entry born stale.
        let gen_at_entry = crate::fs_resolve_cache::current_generation();
        if let Some(ref key) = cache_key {
            // Validate the lookup against the FRESH current generation (read
            // now, not `gen_at_entry`) so a mutation between entry and here also
            // invalidates.
            if let Some(hit) = self
                .fs
                .resolve_cache
                .get(key, crate::fs_resolve_cache::current_generation())
            {
                // Still enforce DAC search permission per call — it depends on
                // live creds, not the path structure (a no-op for root, the hot
                // case). The resolution itself is what the cache elides.
                self.check_search_access(&hit)?;
                return Ok(hit);
            }
        }
        let resolved = match self.resolve_at_path_inner(dirfd, path) {
            Ok(resolved) => resolved,
            Err(errno) => {
                // Linux checks search (x) permission on EACH directory as it
                // descends, so a no-search-permission prefix reports EACCES
                // BEFORE a deeper ENOTDIR/ENOENT is discovered. carrick resolves
                // the whole path as host-root first (finding the deeper error),
                // so re-run the guest DAC search check on the input's directory
                // prefix and let an EACCES there take precedence (pathconf02:
                // abs_path = <mode-0 tmpdir>/testfile/testfile_1). No-op for root.
                if (errno == LINUX_ENOTDIR || errno == LINUX_ENOENT)
                    && let Some(abs) = self.absolute_input_path(dirfd, path)
                {
                    self.check_search_access(&abs)?;
                }
                return Err(errno);
            }
        };
        self.check_search_access(&resolved)?;
        if let Some(key) = cache_key {
            self.fs
                .resolve_cache
                .put(key, resolved.clone(), gen_at_entry);
        }
        Ok(resolved)
    }

    /// The lexical absolute form of a guest input path (anchor + path, ".."
    /// collapsed), WITHOUT existence/symlink resolution — used to run the DAC
    /// search-permission walk on a path whose full resolution already failed.
    /// `None` when the dirfd anchor can't be determined (not a directory fd).
    fn absolute_input_path(&self, dirfd: u64, path: &str) -> Option<String> {
        let dirfd = (dirfd as i32) as i64 as u64;
        let fs_context = self.captured_fs_context();
        let (anchor, path) = if Path::new(path).is_absolute() {
            match fs_context.chroot_root().as_deref() {
                Some(root) if root != "/" => (root.to_owned(), path.trim_start_matches('/')),
                _ => ("/".to_string(), path),
            }
        } else if dirfd == LINUX_AT_FDCWD {
            (fs_context.cwd(), path)
        } else {
            match self.open_file(dirfd as i32)?.description.read().as_deref() {
                Some(OpenDescription::Directory { path: dir, .. }) => (dir.clone(), path),
                _ => return None,
            }
        };
        Some(join_rootfs_path(&anchor, path))
    }

    /// Linux DAC search-permission check: resolving a path requires search
    /// (execute) permission on EVERY directory component leading to the final
    /// name. carrick runs every guest op as host-root, so the host kernel never
    /// enforces this — but when the guest has dropped to a non-root euid we
    /// must, or a no-search-permission component wrongly succeeds (lstat02,
    /// stat03, truncate03, readlink03, … all assert EACCES here). Root (euid 0)
    /// holds CAP_DAC_OVERRIDE and is exempt, which is also the hot path: the
    /// overwhelming majority of guests run as root, so this returns immediately.
    fn check_search_access(&self, abs: &str) -> Result<(), LinuxErrno> {
        let creds = self.cred_snapshot();
        // fsuid, not euid: setfsuid(2) moves every file-access check onto the
        // fsuid, and capabilities(7) drops CAP_DAC_READ_SEARCH on an fsuid
        // 0 -> nonzero transition. This function already selected its
        // permission class from `creds.fsuid` below while bypassing on
        // `creds.euid` — two identities in one check, so a process that had
        // dropped only its fsuid searched as root.
        if creds.fsuid.is_root() {
            return Ok(());
        }
        let trimmed = abs.trim_end_matches('/');
        let parent = match trimmed.rsplit_once('/') {
            Some((p, _)) if !p.is_empty() => p,
            _ => return Ok(()),
        };
        let mut prefix = String::new();
        for comp in parent.split('/').filter(|c| !c.is_empty()) {
            prefix.push('/');
            prefix.push_str(comp);
            // A missing or non-directory component is ENOENT/ENOTDIR, surfaced
            // by the existence checks elsewhere — not our concern here.
            let Ok(md) = self.layered_metadata(&prefix) else {
                return Ok(());
            };
            if md.kind != RootFsEntryKind::Directory {
                return Ok(());
            }
            let (uid, gid) = self
                .fs
                .rootfs_vfs
                .overlay
                .get_owner(&prefix)
                .unwrap_or((carrick_abi::NsUid::ROOT, carrick_abi::NsGid::ROOT));
            // Pick the permission class: owner, then group, else other. (carrick
            // tracks the primary fsgid, not the full supplementary set — a close
            // approximation that the LTP search-permission cases exercise.)
            let x_bit = if creds.fsuid == uid {
                0o100
            } else if creds.fsgid == gid {
                0o010
            } else {
                0o001
            };
            if md.mode & x_bit == 0 {
                return Err(LINUX_EACCES);
            }
        }
        Ok(())
    }

    pub(super) fn check_directory_search_access(&self, abs: &str) -> Result<(), LinuxErrno> {
        let creds = self.cred_snapshot();
        // fsuid — same rule as `check_search_access`.
        if creds.fsuid.is_root() {
            return Ok(());
        }
        let md = self.layered_metadata(abs)?;
        if md.kind != RootFsEntryKind::Directory {
            return Ok(());
        }
        let (uid, gid) = self
            .fs
            .rootfs_vfs
            .overlay
            .get_owner(abs)
            .unwrap_or((carrick_abi::NsUid::ROOT, carrick_abi::NsGid::ROOT));
        let x_bit = if creds.fsuid == uid {
            0o100
        } else if creds.fsgid == gid {
            0o010
        } else {
            0o001
        };
        if md.mode & x_bit == 0 {
            return Err(LINUX_EACCES);
        }
        Ok(())
    }

    fn resolve_at_path_inner(&self, dirfd: u64, path: &str) -> Result<String, LinuxErrno> {
        // dirfd is an `int` in the kernel ABI: only the low 32 bits are
        // meaningful, and AT_FDCWD (-100) may arrive zero-extended (0xFFFFFF9C)
        // or sign-extended (0xFFFF..FF9C) depending on how the guest libc
        // widened it. Canonicalise via i32 so AT_FDCWD is recognised either
        // way (coreutils `ln` passed the zero-extended form → symlinkat/linkat
        // wrongly treated it as a real fd → EBADF).
        let dirfd = (dirfd as i32) as i64 as u64;
        if path.is_empty() {
            return Ok(path.to_owned());
        }
        // `/dev/fd/N` and `/dev/std{in,out,err}` are Linux symlinks into
        // `/proc/self/fd`; rewrite to that so the magic-fd machinery (open → dup
        // N) serves them. The rewritten path is absolute, so it re-resolves
        // independently of `dirfd`. (Fixes bash process substitution `<(...)`.)
        if let Some(rewritten) = rewrite_dev_fd_alias(path) {
            return self.resolve_at_path(dirfd, &rewritten);
        }
        // ENAMETOOLONG: Linux rejects any single component > NAME_MAX (255) and
        // any total path > PATH_MAX (4096) at resolution time. carrick lacked
        // these limits, so a too-long path SUCCEEDED instead of failing
        // (LTP lstat02/stat03/truncate03/open13/… "returned 0, expected -1").
        check_path_length(path)?;
        // The anchor directory a relative path resolves against (already a real,
        // symlink-free path): "/" for an absolute path, the cwd for AT_FDCWD, else
        // the dirfd's directory.
        let fs_context = self.captured_fs_context();
        let (anchor, path) = if Path::new(path).is_absolute() {
            match fs_context.chroot_root().as_deref() {
                Some(root) if root != "/" => (root.to_owned(), path.trim_start_matches('/')),
                _ => ("/".to_string(), path),
            }
        } else if dirfd == LINUX_AT_FDCWD {
            (fs_context.cwd(), path)
        } else {
            match self.open_file(dirfd as i32).as_ref() {
                Some(open_file) => match open_file.description.read().as_deref() {
                    Some(OpenDescription::Directory { path: dir, .. }) => {
                        // A relative *at op through a dirfd whose directory has
                        // since been removed (rmdir) resolves to ENOENT on Linux:
                        // the open fd persists but its path no longer exists.
                        // carrick keeps the Directory description cached, so
                        // re-verify the anchor still exists in the layered view
                        // (symlinkat01/linkat01 deldirfd cases → ENOENT).
                        if self.layered_metadata(dir).is_err() {
                            return Err(LINUX_ENOENT);
                        }
                        (dir.clone(), path)
                    }
                    _ => return Err(LINUX_ENOTDIR),
                },
                // A valid fd that isn't in the table (e.g. a stdio fd) is still a
                // non-directory, so a relative path can't be anchored to it →
                // ENOTDIR; only a genuinely-invalid fd is EBADF (statx03 uses
                // dfd=1 → ENOTDIR, dfd=-1 → EBADF).
                None if self.fd_is_valid(dirfd as i32) => return Err(LINUX_ENOTDIR),
                None => return Err(LINUX_EBADF),
            }
        };
        // A ".." component must be applied AFTER following any preceding symlink
        // (Linux: "a/.." with a -> b/c lands in b, not lexically at the parent of
        // a). join_rootfs_path collapses ".." LEXICALLY, before symlink
        // resolution, so it gets this wrong. Take a symlink-aware walk only when a
        // ".." is present; the (overwhelmingly common) no-".." path keeps the
        // cheap lexical join + the existing intermediate-symlink rewrite, so the
        // hot path is unchanged. (Go os TestRootConsistency*/dotdot_in_path_after_symlink.)
        if path.split('/').any(|c| c == "..") || anchor.split('/').any(|c| c == "..") {
            return self.resolve_dotdot_symlink_aware(&anchor, path);
        }
        let abs = join_rootfs_path(&anchor, path);
        // Fast path: ONE kernel-walked openat+F_GETPATH of the PARENT chain
        // replaces both per-component O(K²) passes below (validate_intermediate_
        // dirs + resolve_intermediate_symlinks) for the common case — every
        // intermediate exists, is a directory, and involves no symlink or
        // Unicode-alias redirection. Anything non-trivial → the exact slow path.
        match self.fs.rootfs_vfs.overlay.validate_parents_fast(&abs) {
            crate::fs_backend::ParentResolve::AllDirsNoSymlink => return Ok(abs),
            crate::fs_backend::ParentResolve::NotDir => return Err(LINUX_ENOTDIR),
            crate::fs_backend::ParentResolve::Slow => {}
        }
        // ELOOP: Linux caps the CUMULATIVE symlinks followed across the whole path
        // at MAXSYMLINKS (40). carrick's per-component resolvers each cap at 40 but
        // don't share a budget, so a path stacking many shallow intermediate
        // symlinks (LTP stat03/lstat02/truncate03 build `test_eloop -> ../test_eloop`
        // repeated ~43×) would otherwise resolve to a directory instead of failing.
        // Surface the overflow here, on the slow (symlink-bearing) path only.
        if self.symlink_follow_budget_exceeded(&abs) {
            return Err(crate::linux_abi::LINUX_ELOOP);
        }
        // ENOTDIR: an existing intermediate component that is not a directory
        // can't be traversed. carrick previously let the final lookup return
        // ENOENT (or leniently resolved through it). Synthesize ENOTDIR here so
        // `stat("/etc/passwd/foo")` & co match Linux (lstat02/stat03/…).
        self.validate_intermediate_dirs(&abs)?;
        // Collapse intermediate (non-final) directory symlinks so the returned
        // path is symlink-free in its parent chain. Downstream consumers
        // (real_stat via cap-std, layered_metadata, canonicalize_following's
        // final-component follow) cannot traverse an intermediate symlink whose
        // target is absolute (cap-std treats an absolute target as a sandbox
        // escape), so `stat("/link/f")` where `/link -> /realdir` would wrongly
        // return ENOENT. Rewriting to `/realdir/f` matches Linux path
        // resolution. The final component is intentionally NOT followed here —
        // each caller decides lstat-vs-stat semantics (AT_SYMLINK_NOFOLLOW).
        Ok(self.resolve_intermediate_symlinks(&abs))
    }

    /// Resolve a path containing ".." components symlink-AWARE: walk left to
    /// right, FOLLOWING each intermediate symlink before applying "..", so
    /// "a/../c" with `a -> b/c` lands in `b` (then `b/c`), matching Linux — not
    /// the lexical `/c` that `join_rootfs_path` would produce. The FINAL component
    /// is NOT followed (the caller decides lstat-vs-stat). A non-directory
    /// intermediate is ENOTDIR; a symlink cycle propagates ELOOP; a missing
    /// intermediate propagates ENOENT before any later `..` can collapse it.
    /// Only invoked when a ".." is actually present.
    fn resolve_dotdot_symlink_aware(&self, anchor: &str, path: &str) -> Result<String, LinuxErrno> {
        let mut all: Vec<&str> = Vec::new();
        if !Path::new(path).is_absolute() {
            all.extend(anchor.split('/').filter(|c| !c.is_empty() && *c != "."));
        }
        all.extend(path.split('/').filter(|c| !c.is_empty() && *c != "."));

        // `base` is the resolved, symlink-free prefix so far (no trailing slash;
        // empty string == root).
        let mut base = String::new();
        let last = all.len().saturating_sub(1);
        for (i, comp) in all.iter().enumerate() {
            if *comp == ".." {
                // Climb one resolved component (never above root).
                match base.rfind('/') {
                    Some(pos) => base.truncate(pos),
                    None => base.clear(),
                }
                continue;
            }
            let mut candidate = base.clone();
            candidate.push('/');
            candidate.push_str(comp);
            if i == last {
                // Final component: leave it unfollowed for the caller.
                base = candidate;
                break;
            }
            match self.layered_lstat(&candidate) {
                Ok(md) if md.kind == RootFsEntryKind::Symlink => {
                    match self.canonicalize_following(&candidate) {
                        Ok(target) if self.path_is_directory(&target) => {
                            base = target.trim_end_matches('/').to_owned();
                        }
                        // Symlink to a non-directory can't be traversed as an
                        // intermediate; ELOOP/other errors propagate.
                        Ok(_) => return Err(LINUX_ENOTDIR),
                        Err(e) => return Err(e),
                    }
                }
                // A real directory intermediate: descend.
                Ok(md) if md.kind == RootFsEntryKind::Directory => base = candidate,
                // An existing non-directory intermediate (regular file, device,
                // FIFO) can't be traversed → ENOTDIR.
                Ok(_) => return Err(LINUX_ENOTDIR),
                // A missing or otherwise inaccessible intermediate stops path
                // resolution immediately. In particular, `missing/..` is ENOENT
                // on Linux; it must not collapse back to the parent.
                Err(errno) => return Err(errno),
            }
        }
        Ok(if base.is_empty() {
            "/".to_owned()
        } else {
            base
        })
    }

    /// Rewrite `abs` so every intermediate (non-final) directory-symlink
    /// component is replaced by its resolved target, leaving the final
    /// component untouched. Best-effort: a component that doesn't resolve to a
    /// directory (dangling/non-dir symlink, ELOOP) leaves the path from that
    /// point unchanged, so the downstream lookup surfaces the correct
    /// ENOENT/ENOTDIR. Bounded by `canonicalize_following`'s own ELOOP guard.
    fn resolve_intermediate_symlinks(&self, abs: &str) -> String {
        let comps: Vec<&str> = abs.split('/').filter(|c| !c.is_empty()).collect();
        if comps.len() < 2 {
            return abs.to_owned();
        }
        let mut base = String::new();
        for comp in &comps[..comps.len() - 1] {
            let mut candidate = base.clone();
            candidate.push('/');
            candidate.push_str(comp);
            match self.layered_lstat(&candidate) {
                Ok(md) if md.kind == RootFsEntryKind::Symlink => {
                    match self.canonicalize_following(&candidate) {
                        Ok(target) if self.path_is_directory(&target) => {
                            base = target.trim_end_matches('/').to_owned();
                        }
                        // Unresolvable/non-dir symlink intermediate: stop
                        // rewriting; leave the rest for the downstream lookup.
                        _ => return abs.to_owned(),
                    }
                }
                // Plain directory (or not-yet-statable): keep walking.
                _ => {
                    base = candidate;
                }
            }
        }
        if let Some(name) = comps.last() {
            base.push('/');
            base.push_str(name);
        }
        if base.is_empty() {
            "/".to_owned()
        } else {
            base
        }
    }

    /// Walk the intermediate (non-final) components of an already-joined
    /// absolute guest path; if any EXISTING intermediate is a non-directory
    /// (regular file / char device), traversing it is ENOTDIR. A missing
    /// intermediate is left alone — the final lookup surfaces ENOENT, which is
    /// correct. Symlink intermediates are followed by the downstream resolver,
    /// so they're not flagged here. Cheap: short-circuits at the first missing
    /// component (so a fresh deep path costs one lookup).
    fn validate_intermediate_dirs(&self, abs: &str) -> Result<(), LinuxErrno> {
        let comps: Vec<&str> = abs.split('/').filter(|c| !c.is_empty()).collect();
        if comps.len() < 2 {
            return Ok(()); // no intermediates
        }
        let mut prefix = String::new();
        for comp in &comps[..comps.len() - 1] {
            prefix.push('/');
            prefix.push_str(comp);
            match self.layered_lstat(&prefix) {
                Ok(md) => match md.kind {
                    RootFsEntryKind::Directory => {}
                    // A symlink intermediate is traversable IFF it resolves to a
                    // directory (Linux follows it). Resolve through the layered
                    // VFS — this handles an absolute in-rootfs target (e.g.
                    // `/tmp/sm_link -> /tmp/sm_real`) that a single-backend
                    // cap-std follow can't (it treats absolute as a sandbox
                    // escape). A symlink to a non-directory (or a dangling one)
                    // is ENOTDIR, matching Linux.
                    RootFsEntryKind::Symlink => match self.canonicalize_following(&prefix) {
                        Ok(target) if self.path_is_directory(&target) => {}
                        // A self-referential / over-deep intermediate symlink is
                        // a CYCLE → ELOOP, not ENOTDIR. canonicalize_following
                        // caps at 40 hops and returns ELOOP; propagate it rather
                        // than collapsing to the non-dir ENOTDIR below
                        // (lstat02/stat03/truncate03/readlink03 assert ELOOP on
                        // an intermediate self-linking component).
                        Err(e) if e == crate::linux_abi::LINUX_ELOOP => return Err(e),
                        _ => return Err(LINUX_ENOTDIR),
                    },
                    // A regular file / char device can't be a path component.
                    _ => return Err(LINUX_ENOTDIR),
                },
                // Intermediate doesn't exist (or isn't statable) → stop; the
                // final resolution returns ENOENT as Linux does.
                Err(_) => return Ok(()),
            }
        }
        Ok(())
    }

    /// Shared core of fchmodat / fchmodat2: resolve `pathname` against `dirfd`,
    /// then apply `mode` (with the setgid-clear rule) to the writable backend.
    /// Synthetic /proc /sys paths and the in-memory backend accept it as a
    /// no-op success as long as the path exists. Flag handling differs between
    /// the two callers, so it stays in the syscall wrappers.
    fn chmod_at(
        &self,
        context: &crate::kernel::KernelContext,
        dirfd: u64,
        pathname: u64,
        mode: u64,
        memory: &impl CurrentMmMemory,
    ) -> Result<DispatchOutcome, DispatchError> {
        let path = read_guest_c_string(memory, pathname)?;
        if path.is_empty() {
            return Ok(DispatchOutcome::errno(LINUX_ENOENT));
        }
        let resolved = self.resolve_at_path(dirfd, &path)?;
        // chmod(2) FOLLOWS a final symlink — it changes the TARGET's mode, not
        // the link's (test_posix.test_chmod_dir_symlink). resolve_at_path stops
        // at the link itself, so dereference it here. (fchmodat2's advisory
        // AT_SYMLINK_NOFOLLOW stays unmodeled on the disk-authoritative backend;
        // a dangling/failed follow falls back to the link path unchanged.)
        let resolved = self.canonicalize_following(&resolved).unwrap_or(resolved);
        if self.is_synthetic_virtual_path(context, &resolved) {
            return Ok(DispatchOutcome::Returned { value: 0 });
        }
        if let Err(errno) = self.layered_metadata(&resolved) {
            return Ok(DispatchOutcome::errno(errno));
        }
        if let Some(errno) = self.chmod_permission_errno(&resolved) {
            return Ok(DispatchOutcome::errno(errno));
        }
        let mode = self.maybe_clear_setgid(&resolved, (mode & 0o7777) as u32);
        if let Some(m) = self.fs.vfs_mounts.resolve(&resolved) {
            return match m.vfs.chmod(&m.full_path, mode) {
                Ok(()) => {
                    self.inotify_attrib(&resolved);
                    self.dnotify_attrib(context, &resolved);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            };
        }
        match self.fs.rootfs_vfs.set_mode(&resolved, mode) {
            Ok(()) | Err(crate::fs_backend::BackendError::Unsupported) => {
                self.inotify_attrib(&resolved);
                self.dnotify_attrib(context, &resolved);
                Ok(DispatchOutcome::Returned { value: 0 })
            }
            Err(_) => Ok(DispatchOutcome::Returned { value: 0 }),
        }
    }

    /// Linux clears the setgid bit (S_ISGID) on a chmod by an UNPRIVILEGED
    /// process whose effective gid doesn't match the file's group — so a
    /// non-owner-group user can't make a file setgid to a group it isn't in
    /// (chmod05/fchmod05). Root (euid==0) keeps the bit. carrick tracks only the
    /// effective gid (not supplementary groups), which is what the LTP tests
    /// exercise. Returns the mode to actually apply.
    fn maybe_clear_setgid(&self, path: &str, mode: u32) -> u32 {
        const S_ISGID: u32 = 0o2000;
        if mode & S_ISGID == 0 {
            return mode;
        }
        let creds = self.cred_snapshot();
        if creds.euid.is_root() {
            return mode;
        }
        let file_gid = self
            .fs
            .rootfs_vfs
            .overlay
            .get_owner(path)
            .map(|(_, g)| g)
            .unwrap_or(carrick_abi::NsGid::ROOT);
        if file_gid != creds.egid {
            return mode & !S_ISGID;
        }
        mode
    }

    fn chown_uid_arg(arg: u64) -> Option<carrick_abi::NsUid> {
        let value = arg as u32;
        (value != u32::MAX).then_some(carrick_abi::NsUid::new(value))
    }

    fn chown_gid_arg(arg: u64) -> Option<carrick_abi::NsGid> {
        let value = arg as u32;
        (value != u32::MAX).then_some(carrick_abi::NsGid::new(value))
    }

    /// Stamp the owner (and, when inherited, the setgid bit) on a freshly
    /// created special node (mknod FIFO/device/socket), mirroring mkdirat's
    /// rule: a new inode's group is the creator's egid, UNLESS the parent
    /// directory is setgid (S_ISGID), in which case it inherits the parent's
    /// group but preserves its requested mode. Unlike a newly created directory,
    /// a non-directory node does not acquire S_ISGID from its parent. Without
    /// this the host assigns its own gid and a later stat reports the wrong
    /// st_gid (LTP mknod08 expects st_gid == the process egid because the parent
    /// isn't setgid).
    /// Record the creating process as the owner of a just-created node, with
    /// Linux's setgid-parent gid inheritance. Called by every path that
    /// materialises a new node — `openat(O_CREAT)`, `mknod`, and `bind(2)` on an
    /// AF_UNIX socket (`dispatch::net`), which is why this is `pub(super)`.
    pub(super) fn stamp_new_node_owner(&self, path: &str, node_mode: u32) {
        const S_ISGID: u32 = 0o2000;
        let creds = self.cred_snapshot();
        let mut owner_gid = creds.egid;
        let mut inherited_gid = false;
        if let Some(parent) = Path::new(path).parent() {
            let parent_str = display_rootfs_path(parent);
            if let Ok(pmd) = self.layered_metadata(&parent_str)
                && pmd.mode & S_ISGID != 0
                && let Some((_, pgid)) = self.fs.rootfs_vfs.overlay.get_owner(&parent_str)
            {
                owner_gid = pgid;
                inherited_gid = true;
                let _ = self.fs.rootfs_vfs.set_mode(path, node_mode);
            }
        }
        if !creds.euid.is_root() || !owner_gid.is_root() || inherited_gid {
            let _ = self
                .fs
                .rootfs_vfs
                .set_owner(path, Some(creds.euid), Some(owner_gid));
        }
    }

    fn chown_permission_errno(
        &self,
        uid: Option<carrick_abi::NsUid>,
        gid: Option<carrick_abi::NsGid>,
    ) -> Option<LinuxErrno> {
        let creds = self.cred_snapshot();
        if creds.euid.is_root() {
            return None;
        }
        if uid.is_some() {
            return Some(LINUX_EPERM);
        }
        if gid.is_some_and(|gid| gid != creds.egid) {
            return Some(LINUX_EPERM);
        }
        None
    }

    /// chmod(2)/fchmod(2) permission: only the file owner or a process with
    /// CAP_FOWNER (modeled as euid==0) may change a file's mode; everyone else
    /// gets EPERM (Linux fs/attr.c chmod_common -> inode_owner_or_capable). When
    /// the backend can't supply an owner (the in-memory backend has no real
    /// owner/mode), we don't enforce — matching the legacy root model used
    /// elsewhere on that backend (and mirroring `maybe_clear_setgid`'s lookup).
    fn chmod_permission_errno(&self, path: &str) -> Option<LinuxErrno> {
        let creds = self.cred_snapshot();
        if creds.euid.is_root() {
            return None;
        }
        match self.fs.rootfs_vfs.overlay.get_owner(path) {
            Some((owner_uid, _)) if owner_uid != creds.euid => Some(LINUX_EPERM),
            _ => None,
        }
    }

    /// Apply chown to the file backing an fd, recording the guest-visible owner
    /// on the backend (durable via xattr on `--fs host`). Shared by `fchown` and
    /// `fchownat(..., AT_EMPTY_PATH)` so both record the owner identically.
    /// `fd` must already be validated by the caller.
    fn fchown_by_fd(
        &self,
        context: &crate::kernel::KernelContext,
        fd: i32,
        uid: Option<carrick_abi::NsUid>,
        gid: Option<carrick_abi::NsGid>,
    ) -> DispatchOutcome {
        let (path, raw_host_fd) = self
            .open_file(fd)
            .and_then(|of| match of.description.read().as_deref() {
                Some(OpenDescription::HostFile {
                    metadata, host_fd, ..
                }) => Some((
                    Some(metadata.path.to_string_lossy().into_owned()),
                    Some(host_fd.raw()),
                )),
                Some(
                    OpenDescription::File { metadata, .. }
                    | OpenDescription::Directory { metadata, .. },
                ) => Some((Some(metadata.path.to_string_lossy().into_owned()), None)),
                _ => None,
            })
            .unwrap_or((None, None));
        if let Some(path) = path {
            if let Some(errno) = self.chown_permission_errno(uid, gid) {
                return DispatchOutcome::errno(errno);
            }
            if let Some(m) = self.fs.vfs_mounts.resolve(&path) {
                if let Err(errno) = m.vfs.chown(&m.full_path, uid, gid, false) {
                    return DispatchOutcome::errno(errno);
                }
            } else {
                let _ = self.fs.rootfs_vfs.set_owner(&path, uid, gid);
            }
            self.clear_setid_on_chown(&path);
            self.dnotify_attrib(context, &path);
        }
        if let Some(raw_fd) = raw_host_fd {
            self.fs.rootfs_vfs.fset_owner(raw_fd, uid, gid);
        }
        DispatchOutcome::Returned { value: 0 }
    }

    /// Linux raises SIGPIPE on the writing thread when a write hits a broken
    /// pipe (the read end is closed → EPIPE), in addition to returning EPIPE
    /// (LTP write05). Mark it pending so the runtime delivers it per the
    /// disposition: a handler runs, SIG_DFL terminates, a blocked SIGPIPE stays
    /// pending. Skip the mark when SIGPIPE is ignored (the common case for
    /// pipe/socket-heavy programs) so we don't queue a signal that's discarded.
    pub(crate) fn raise_sigpipe_on_epipe<M: CurrentMmMemory>(
        &self,
        cx: &SyscallCtx<M>,
        outcome: DispatchOutcome,
    ) -> DispatchOutcome {
        if matches!(&outcome, DispatchOutcome::Errno { errno } if *errno == LINUX_EPIPE)
            && !self.signal_is_ignored(cx.kernel, LINUX_SIGPIPE)
        {
            let tid = Self::ctx_tid(cx);
            self.mark_signal_pending(cx.kernel, tid, LINUX_SIGPIPE);
        }
        outcome
    }

    /// The RLIMIT_FSIZE soft cap the guest set via setrlimit/prlimit64, or
    /// `None` when unset / RLIM_INFINITY. A write whose bytes would land past
    /// this offset is EFBIG + SIGXFSZ on Linux (llseek01). Stored in the
    /// per-process override table (RLIMIT_FSIZE == resource 1).
    fn fsize_soft_limit(&self) -> Option<u64> {
        let limit = self.task_rlimits().get(carrick_abi::LinuxResource::Fsize);
        (limit.rlim_cur != LINUX_RLIM_INFINITY).then_some(limit.rlim_cur)
    }

    /// Enforce RLIMIT_FSIZE for a regular-file write starting at `offset` that
    /// would carry `len` bytes. Returns the permitted prefix length, or EFBIG
    /// (after queuing SIGXFSZ) when the write starts at or beyond the soft cap.
    /// A straddling write is truncated to the cap, as Linux requires.
    fn fsize_write_len<M: CurrentMmMemory>(
        &self,
        cx: &SyscallCtx<M>,
        offset: u64,
        len: usize,
    ) -> Result<usize, LinuxErrno> {
        if len == 0 {
            return Ok(0);
        }
        let Some(limit) = self.fsize_soft_limit() else {
            return Ok(len);
        };
        if offset >= limit {
            if !self.signal_is_ignored(cx.kernel, LINUX_SIGXFSZ) {
                self.mark_signal_pending(cx.kernel, Self::ctx_tid(cx), LINUX_SIGXFSZ);
            }
            return Err(LINUX_EFBIG);
        }
        Ok(len.min((limit - offset) as usize))
    }

    /// The root bypass shared by [`Self::guest_can_modify_dir`] and
    /// [`Self::guest_sticky_delete_ok`], for callers to test BEFORE paying the
    /// existence probe those checks are conditioned on: for the default root
    /// guest the probe was a full host path walk per `unlink`/`mkdir` whose
    /// answer was then discarded.
    pub(super) fn guest_dac_root_bypass(&self) -> bool {
        self.cred_snapshot().euid.is_root()
    }

    /// Linux DAC: may the calling guest create/remove an entry in directory
    /// `dir_path`? It needs WRITE + EXECUTE (search) on the directory for its
    /// permission class (owner/group/other), evaluated against the
    /// guest-tracked mode + owner xattrs and the guest fs-uid/gid. Root (euid 0
    /// = CAP_DAC_OVERRIDE) always passes; an unknown mode/owner fails OPEN so a
    /// directory carrick has no record for is never wrongly denied. Only bites
    /// when a guest drops to a non-root euid — the default root guest (incl. the
    /// apt/python demos) is unaffected.
    pub(super) fn guest_can_modify_dir(&self, dir_path: &str) -> bool {
        let creds = self.cred_snapshot();
        if creds.euid.is_root() {
            return true;
        }
        let Ok(md) = self.layered_metadata(dir_path) else {
            return true;
        };
        let mode = md.mode & 0o7777;
        let (ouid, ogid) = self
            .fs
            .rootfs_vfs
            .overlay
            .get_owner(dir_path)
            .unwrap_or((carrick_abi::NsUid::ROOT, carrick_abi::NsGid::ROOT));
        let class_bits = if creds.fsuid == ouid {
            mode >> 6
        } else if creds.fsgid == ogid {
            mode >> 3
        } else {
            mode
        } & 0o7;
        // Need both write (2) and execute/search (1).
        class_bits & 0o3 == 0o3
    }

    /// Linux sticky-bit (S_ISVTX) protection for removing `entry_path` from its
    /// parent `dir_path`: in a sticky directory an unprivileged caller may
    /// remove an entry only if it owns the entry OR owns the directory; else
    /// EPERM (LTP rmdir03 case 2). Returns true (allowed) for root, a
    /// non-sticky dir, or unknown ownership (fail open).
    pub(super) fn guest_sticky_delete_ok(&self, dir_path: &str, entry_path: &str) -> bool {
        const S_ISVTX: u32 = 0o1000;
        let creds = self.cred_snapshot();
        if creds.euid.is_root() {
            return true;
        }
        let Ok(md) = self.layered_metadata(dir_path) else {
            return true;
        };
        if md.mode & S_ISVTX == 0 {
            return true; // not sticky → no extra restriction
        }
        let dir_owner = self.fs.rootfs_vfs.overlay.get_owner(dir_path).map(|o| o.0);
        let entry_owner = self
            .fs
            .rootfs_vfs
            .overlay
            .get_owner(entry_path)
            .map(|o| o.0);
        // Allowed only if the caller owns the entry or the directory.
        entry_owner == Some(creds.fsuid) || dir_owner == Some(creds.fsuid)
    }
}

impl SyscallDispatcher {
    define_syscall! {

        fn io_setup(this, cx, nr_events: u64, ctxp: GuestPtr) {
            legacy_aio::io_setup(this, cx, nr_events, ctxp)
        }

        fn io_destroy(this, _cx, raw_ctx: u64) {
            legacy_aio::io_destroy(this, raw_ctx)
        }

        fn io_submit(this, cx, raw_ctx: u64, raw_count: u64, iocbpp: GuestPtr) {
            legacy_aio::io_submit(this, cx, raw_ctx, raw_count, iocbpp)
        }

        fn io_cancel(this, cx, raw_ctx: u64, iocb: GuestPtr, result: GuestPtr) {
            legacy_aio::io_cancel(this, cx, raw_ctx, iocb, result)
        }

        fn io_getevents(this, cx, raw_ctx: u64, min_nr: u64, nr: u64, events: GuestPtr, _timeout: GuestPtr) {
            legacy_aio::io_getevents(this, cx, raw_ctx, min_nr, nr, events)
        }

        fn faccessat(this, cx, dirfd: u64, pathname: GuestPtr, mode: u64) {

            // Linux's `faccessat` (syscall 48) takes only (dirfd, pathname, mode).
            // The 4-arg form with flags is `faccessat2` (syscall 439). We were
            // erroneously reading x3 as flags here, which is whatever uninit
            // register state the caller had — making glibc see EINVAL for normal
            // access(F_OK)-style calls and abort with "stack smashing detected".
            this.access_at(cx.kernel, dirfd, pathname.0, mode, 0, &*cx.memory)

        }

        fn faccessat2(this, cx, dirfd: u64, pathname: GuestPtr, mode: u64, flags: u64) {

            this.access_at(cx.kernel, dirfd, pathname.0, mode, flags, &*cx.memory)

        }

        fn pipe2(this, cx, pipefd: GuestPtr, flags: u64) {

            let address = pipefd.0;
            let memory = &mut *cx.memory;
            // Accept O_DIRECT as a no-op flag. Real Linux uses it to request
            // packet-mode pipes (each write becomes a discrete packet, reads
            // truncate at packet boundaries). Darwin pipes don't have that
            // semantic, but apps using it for a single-byte signal stream or a
            // 3-byte-write/big-buffer-read pattern work identically against a
            // regular pipe — and rejecting the flag breaks every Linux app that
            // probes for packet-mode availability. The probe `pipeextra` only
            // exercises the regular-pipe-compatible subset.
            // O_DIRECT is arch-specific. aarch64/arm: 0o200000 (0x10000).
            // The asm-generic value 0o40000 is NOT what musl/glibc ship for
            // aarch64 — checking the wrong value silently rejects every
            // O_DIRECT pipe2 call (the bit's still present in the flags).
            if LinuxPipe2Flags::from_bits(flags).is_none() {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }

            let nonblock = flags & LINUX_O_NONBLOCK;
            let fd_flags = linux_fd_flags_from_open_flags(flags);

            let pipe_id = next_pipe_id();
            let pipe = Arc::new(PipeInner::new(pipe_id, DEFAULT_PIPE_CAPACITY));

            let mut read_base = OpenDescriptionBase::new(LINUX_O_RDONLY | nonblock);
            read_base.set_pipe_capacity_cell(Arc::clone(&pipe.capacity_cell));
            let mut write_base = OpenDescriptionBase::new(LINUX_O_WRONLY | nonblock);
            write_base.set_pipe_capacity_cell(Arc::clone(&pipe.capacity_cell));

            let read_open = OpenFile::from_open_description_with_status_flags(
                Arc::new(RwLock::new(OpenDescription::PipeReader {
                    base: read_base,
                    pipe: Arc::clone(&pipe),
                })),
                LINUX_O_RDONLY | nonblock,
                fd_flags,
            );
            let write_open = OpenFile::from_open_description_with_status_flags(
                Arc::new(RwLock::new(OpenDescription::PipeWriter {
                    base: write_base,
                    pipe,
                })),
                LINUX_O_WRONLY | nonblock,
                fd_flags,
            );
            let Ok((read_fd, write_fd)) = this.install_fd_pair_at_or_above(3, read_open, write_open)
            else {
                return Ok(DispatchOutcome::errno(linux_errno::EMFILE));
            };
            let pair = LinuxFdPair { read_fd, write_fd };
            if write_kernel_struct_raw(memory, address, &pair).is_err() {
                let removed = {
                    let files = this.captured_file_table();
                    let mut table = files.write_open_files();
                    [table.remove(&read_fd), table.remove(&write_fd)]
                };
                for open_file in removed.into_iter().flatten() {
                    this.close_open_file_and_free_pty(&open_file);
                }
                this.note_fd_closed(read_fd);
                this.note_fd_closed(write_fd);
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }

            Ok(DispatchOutcome::Returned { value: 0 })

        }

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



        fn fallocate(this, cx, fd: Fd, mode: u64, offset: u64, len: u64) {

            let fd: Fd = fd;
            let offset = i64::from_ne_bytes(offset.to_ne_bytes());
            let length = i64::from_ne_bytes(len.to_ne_bytes());
            if mode & !LINUX_FALLOC_FL_SUPPORTED != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if length <= 0 || offset < 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // The resulting file size (offset + len) must fit the off_t maximum;
            // overflowing the max LFS file size is EFBIG on Linux, not the EINVAL
            // a too-large host ftruncate would yield (fallocate02 cases 7-8 pass
            // offset/len ≈ LLONG_MAX so offset+len overflows i64).
            if offset.checked_add(length).is_none() {
                return Ok(DispatchOutcome::errno(LINUX_EFBIG));
            }
            if is_stdio_fd(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
            }
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            // Only mode-0 (default allocation) is implemented as a real grow;
            // FALLOC_FL_KEEP_SIZE preallocates without changing the apparent
            // size, which on a tmpfs/host-backed file is a no-op success.
            let grow = mode & LINUX_FALLOC_FL_KEEP_SIZE == 0;
            let new_size = (offset as u64).saturating_add(length as u64);
            // Snapshot the writeback path/contents in a scope so the borrow
            // drops before we touch this.fs.rootfs_vfs.overlay (mirrors ftruncate).
            let writeback: Option<(String, Vec<u8>)>;
            let outcome: DispatchOutcome;
            {
                let Some(mut open) = open_file.description.write() else {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                };
                match &mut *open {
                    OpenDescription::File {
                        path,
                        contents,
                        metadata,
                        writable,
                        ..
                    } if grow => {
                        if !*writable {
                            return Ok(DispatchOutcome::errno(LINUX_EBADF));
                        }
                        // memfd seals: an allocating (non-KEEP_SIZE) fallocate is
                        // blocked only by F_SEAL_GROW when it extends the file —
                        // F_SEAL_WRITE does NOT block a pure grow (memfd_create01
                        // seals WRITE then grows via fallocate successfully).
                        let cur_len = match contents.len() {
                            Ok(l) => l,
                            Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                        };
                        if matches!(
                            open_file
                                .description
                                .common()
                                .seals()
                                .and_then(carrick_abi::LinuxMemfdSeals::from_bits),
                            Some(s) if s.contains(carrick_abi::LinuxMemfdSeals::GROW)
                        ) && new_size > cur_len
                        {
                            return Ok(DispatchOutcome::errno(LINUX_EPERM));
                        }
                        if !contents.accepts_len(new_size) {
                            return Ok(DispatchOutcome::errno(LINUX_EFBIG));
                        }
                        if new_size > cur_len {
                            if let Err(errno) = contents.resize(new_size) {
                                return Ok(DispatchOutcome::errno(errno));
                            }
                            let confirmed_len = match contents.len() {
                                Ok(l) => l,
                                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                            };
                            metadata.size = usize::try_from(confirmed_len).unwrap_or(metadata.size);
                        }
                        // Sync the grown contents to the overlay backing so a
                        // later fstat of the path agrees. Anonymous files
                        // (memfd, O_TMPFILE) have no overlay path to sync.
                        let writeback_vec = if !is_anon_overlay_path(path) {
                            let mut vec = vec![0u8; metadata.size];
                            if let Err(errno) = contents.read_at(0, &mut vec) {
                                return Ok(DispatchOutcome::errno(errno));
                            }
                            Some((path.clone(), vec))
                        } else {
                            None
                        };
                        writeback = writeback_vec;
                        outcome = DispatchOutcome::Returned { value: 0 };
                    }
                    OpenDescription::File {
                        contents, writable, ..
                    } => {
                        if !*writable {
                            return Ok(DispatchOutcome::errno(LINUX_EBADF));
                        }
                        // A hole punch modifies content, so F_SEAL_WRITE blocks it
                        // (memfd_create01 check_mfd_non_writeable). A plain
                        // KEEP_SIZE preallocate changes nothing and is unaffected.
                        if mode & LINUX_FALLOC_FL_PUNCH_HOLE != 0 {
                            if let Err(errno) = memfd_seal_write_check(
                                open_file.description.common().seals(),
                                0,
                                0,
                                0,
                            ) {
                                return Ok(DispatchOutcome::errno(errno));
                            }
                            // The punched range reads back as zeros; the
                            // apparent size never changes (KEEP_SIZE is
                            // mandatory with PUNCH_HOLE).
                            let cur_len = match contents.len() {
                                Ok(l) => l,
                                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                            };
                            let start = (offset as u64).min(cur_len);
                            let end = (offset as u64).saturating_add(length as u64).min(cur_len);
                            if end > start {
                                let zero_chunk = [0u8; 4096];
                                let mut cur = start;
                                while cur < end {
                                    let chunk_len = ((end - cur) as usize).min(zero_chunk.len());
                                    match contents.write_at(cur, &zero_chunk[..chunk_len]) {
                                        Ok(0) => break,
                                        Ok(n) => cur += n as u64,
                                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                                    }
                                }
                            }
                        }
                        // KEEP_SIZE: don't change apparent size.
                        writeback = None;
                        outcome = DispatchOutcome::Returned { value: 0 };
                    }
                    OpenDescription::HostFile {
                        host_fd, writable, ..
                    } => {
                        if !*writable {
                            return Ok(DispatchOutcome::errno(LINUX_EBADF));
                        }
                        // Real fd into the cap-std scratch: grow with ftruncate
                        // (the change is visible across fork). KEEP_SIZE → no-op.
                        if grow {
                            let mut st: libc::stat = unsafe { core::mem::zeroed() };
                            if let Err(errno) =
                                (unsafe { libc::fstat(host_fd.raw(), &mut st) }).host_syscall_errno()
                            {
                                return Ok(DispatchOutcome::errno(errno));
                            }
                            if new_size > st.st_size as u64 {
                                if let Err(errno) = (unsafe {
                                    libc::ftruncate(host_fd.raw(), new_size as libc::off_t)
                                })
                                .host_syscall_errno()
                                {
                                    return Ok(DispatchOutcome::errno(errno));
                                }
                                this.invalidate_dentry_host_fd(host_fd.raw());
                            }
                        }
                        writeback = None;
                        outcome = DispatchOutcome::Returned { value: 0 };
                    }
                    OpenDescription::SyntheticFile { .. } => {
                        return Ok(DispatchOutcome::errno(LINUX_EROFS));
                    }
                    OpenDescription::InMemoryFile {
                        path,
                        contents,
                        writable,
                        max_size,
                        ..
                    } => {
                        if !*writable {
                            return Ok(DispatchOutcome::errno(LINUX_EBADF));
                        }
                        if new_size as usize > *max_size {
                            return Ok(DispatchOutcome::errno(LINUX_EFBIG));
                        }
                        let mut data = contents.write();
                        if (new_size as usize) > data.len() {
                            data.set_len(new_size as usize);
                            this.fs.rootfs_vfs.notify_inode_changed(path, None);
                        }
                        writeback = None;
                        outcome = DispatchOutcome::Returned { value: 0 };
                    }
                    OpenDescription::Directory { .. } => {
                        return Ok(DispatchOutcome::errno(LINUX_EISDIR));
                    }
                    _ => {
                        return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
                    }
                }
            }
            if let Some((path, contents)) = writeback {
                let _ = this
                    .fs
                    .rootfs_vfs
                    .set_file_contents(&path, contents);
            }
            Ok(outcome)

        }

        fn ftruncate(this, cx, fd: Fd, length: u64) {

            let fd: Fd = fd;
            let length = i64::from_ne_bytes(length.to_ne_bytes());
            if length < 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if is_stdio_fd(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            // RLIMIT_FSIZE caps the resulting file size — see
            // `rlimit_fsize_errno`. Checked after EBADF so an invalid fd still
            // reports EBADF, matching Linux's argument-validation order.
            if let Some(errno) = this.rlimit_fsize_errno(length) {
                return Ok(DispatchOutcome::errno(errno));
            }
            // Snapshot the path + new contents in a scope so the borrow drops
            // before we touch this.fs.rootfs_vfs.overlay.
            let writeback: Option<(String, Vec<u8>)>;
            let outcome: DispatchOutcome;
            {
                let Some(mut open) = open_file.description.write() else {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                };
                match &mut *open {
                    OpenDescription::File {
                        path,
                        contents,
                        offset,
                        writable,
                        metadata,
                        ..
                    } => {
                        if !*writable {
                            // RO fd is a valid fd opened the wrong way → EINVAL,
                            // not EBADF (ftruncate03). EBADF is for an invalid fd
                            // (handled by open_file→None above).
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                        if !contents.accepts_len(length as u64) {
                            return Ok(DispatchOutcome::errno(LINUX_EFBIG));
                        }
                        let cur_len = match contents.len() {
                            Ok(l) => l,
                            Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                        };
                        let new_len = length as usize;
                        // memfd resize seals: F_SEAL_SHRINK blocks shrink,
                        // F_SEAL_GROW blocks grow (memfd_create01).
                        if let Err(errno) = memfd_seal_resize_check(
                            open_file.description.common().seals(),
                            new_len,
                            usize::try_from(cur_len).unwrap_or(usize::MAX),
                        ) {
                            return Ok(DispatchOutcome::errno(errno));
                        }
                        if let Err(errno) = contents.resize(length as u64) {
                            return Ok(DispatchOutcome::errno(errno));
                        }
                        if *offset > new_len {
                            *offset = new_len;
                        }
                        let confirmed_len = match contents.len() {
                            Ok(l) => l,
                            Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                        };
                        metadata.size = usize::try_from(confirmed_len).unwrap_or(new_len);
                        let writeback_vec = if !is_anon_overlay_path(path) {
                            let mut vec = vec![0u8; metadata.size];
                            if let Err(errno) = contents.read_at(0, &mut vec) {
                                return Ok(DispatchOutcome::errno(errno));
                            }
                            Some((path.clone(), vec))
                        } else {
                            None
                        };
                        writeback = writeback_vec;
                        outcome = DispatchOutcome::Returned { value: 0 };
                    }
                    OpenDescription::InMemoryFile {
                        path,
                        contents,
                        offset,
                        writable,
                        max_size,
                        ..
                    } => {
                        if !*writable {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                        if length as usize > *max_size {
                            return Ok(DispatchOutcome::errno(LINUX_EFBIG));
                        }
                        let new_len = length as usize;
                        let mut data = contents.write();
                        data.set_len(new_len);
                        if *offset > new_len {
                            *offset = new_len;
                        }
                        this.fs.rootfs_vfs.notify_inode_changed(path, None);
                        writeback = None;
                        outcome = DispatchOutcome::Returned { value: 0 };
                    }
                    OpenDescription::HostFile {
                        host_fd, writable, ..
                    } => {
                        if !*writable {
                            // RO fd → EINVAL (ftruncate03), not EBADF.
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                        // Real fd: ftruncate the kernel file directly (the
                        // change is visible across fork).
                        if let Err(errno) =
                            (unsafe { libc::ftruncate(host_fd.raw(), length as libc::off_t) })
                                .host_syscall_errno()
                        {
                            return Ok(DispatchOutcome::errno(errno));
                        }
                        this.invalidate_dentry_host_fd(host_fd.raw());
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    OpenDescription::SyntheticFile { .. } => {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    OpenDescription::Directory { .. } => {
                        return Ok(DispatchOutcome::errno(LINUX_EISDIR));
                    }
                    _ => {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                }
            }
            if let Some((path, contents)) = writeback {
                let _ = this
                    .fs
                    .rootfs_vfs
                    .set_file_contents(&path, contents);
            }
            Ok(outcome)

        }

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
                arg0,
                path.as_ref(),
                flags,
                mode,
                cx.reporter,
            )

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

        fn lseek(this, cx, fd: Fd, offset: u64, whence: u64) {
            let fd: Fd = fd;
            let offset = offset as i64;
            let Some(open_file) = this.open_file(fd.0) else {
                // lseek on stdio with no OpenDescription is, on Linux, a
                // valid call on an unseekable pipe/tty — kernel returns
                // ESPIPE, not EBADF. Returning EBADF confuses glibc's
                // ftell/fclose path into reporting "write error: Bad
                // file descriptor" after every successful write. BUT a
                // stdio fd the guest explicitly closed is genuinely closed:
                // lseek on it is EBADF, not ESPIPE.
                if is_stdio_fd(fd.0) && !this.stdio_is_closed(fd.0) {
                    return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
                }
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let Some(mut open) = open_file.description.write() else {
                if is_stdio_fd(fd.0) && !this.stdio_is_closed(fd.0) {
                    return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
                }
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };

            // HostFile: the kernel owns the offset — delegate straight to
            // libc::lseek on the real fd.
            if let OpenDescription::HostFile { host_fd, .. } = &*open {
                let host_whence = match whence {
                    LINUX_SEEK_SET => libc::SEEK_SET,
                    LINUX_SEEK_CUR => libc::SEEK_CUR,
                    LINUX_SEEK_END => libc::SEEK_END,
                    // SEEK_DATA/SEEK_HOLE: macOS supports them but SWAPS the
                    // numbers (Linux DATA=3/HOLE=4, macOS DATA=4/HOLE=3), so
                    // translate for sparse-file hole queries (test_fs_holes).
                    LINUX_SEEK_DATA => 4, // LINUX_SEEK_DATA -> macOS SEEK_DATA
                    LINUX_SEEK_HOLE => 3, // LINUX_SEEK_HOLE -> macOS SEEK_HOLE
                    _ => {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                };
                // Linux answers ENXIO for a negative SEEK_DATA/SEEK_HOLE offset
                // (oracle `seekholemap`); macOS would say EINVAL, so decide here.
                if (whence == LINUX_SEEK_DATA || whence == LINUX_SEEK_HOLE) && offset < 0 {
                    return Ok(DispatchOutcome::errno(LINUX_ENXIO));
                }
                let r = match (unsafe {
                    libc::lseek(host_fd.raw(), offset as libc::off_t, host_whence)
                })
                .host_syscall_errno()
                {
                    Ok(r) => r,
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                };
                return Ok(DispatchOutcome::returned_offset_or_errno(r));
            }

            // A CHARACTER device (/dev/null, /dev/zero, /dev/full, /dev/random,
            // /dev/urandom) is backed by a host fd but lands here as a HostPipe
            // (the open path keeps devices as streams). Such devices ARE
            // seekable on Linux — lseek returns 0/the offset, never ESPIPE — and
            // Python's io.open("/dev/null","r+") requires seekable(). Delegate to
            // the host lseek when the backing fd is a char device; genuine
            // pipes/fifos (S_IFIFO) fall through to the ESPIPE branch below.
            if let OpenDescription::HostPipe { host_fd, .. } = &*open {
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(host_fd.raw(), &mut st) } == 0
                    && (st.st_mode & libc::S_IFMT) == libc::S_IFCHR
                {
                    let host_whence = match whence {
                        LINUX_SEEK_SET => libc::SEEK_SET,
                        LINUX_SEEK_CUR => libc::SEEK_CUR,
                        LINUX_SEEK_END => libc::SEEK_END,
                        _ => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                    };
                    let r = match (unsafe {
                        libc::lseek(host_fd.raw(), offset as libc::off_t, host_whence)
                    })
                    .host_syscall_errno()
                    {
                        Ok(r) => r,
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    };
                    return Ok(DispatchOutcome::returned_offset_or_errno(r));
                }
            }

            // A directory lists lazily; a SEEK_END that needs the entry
            // count must take the listing first.
            if whence == LINUX_SEEK_END
                && let OpenDescription::Directory {
                    listing,
                    path,
                    trusted_host_dir,
                    ..
                } = &mut *open
                && matches!(listing, DirListing::Pending)
            {
                let visible_self = proc_visible_self(cx.kernel);
                let is_self_fd = is_proc_self_fd_dir(path, visible_self);
                let is_self_fdinfo = is_proc_self_fdinfo_dir(path, visible_self);
                if is_self_fd || is_self_fdinfo {
                    *listing = DirListing::Fixed(this.proc_self_fd_entries(path, is_self_fdinfo));
                } else {
                    *listing = DirListing::Loaded(
                        this.list_directory_entries(path, trusted_host_dir.as_ref()),
                    );
                }
            }

            let (current, end) = match &mut *open {
                OpenDescription::Closed { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                OpenDescription::File {
                    contents,
                    offset: file_offset,
                    ..
                } => {
                    if whence == LINUX_SEEK_DATA || whence == LINUX_SEEK_HOLE {
                        match contents {
                            FileContents::HostBacked { fd } => {
                                use std::os::fd::AsRawFd;
                                if offset < 0 {
                                    return Ok(DispatchOutcome::errno(LINUX_ENXIO));
                                }
                                let host_whence = match whence {
                                    LINUX_SEEK_DATA => 4,
                                    LINUX_SEEK_HOLE => 3,
                                    _ => unreachable!(),
                                };
                                let r = match (unsafe {
                                    libc::lseek(fd.as_raw_fd(), offset as libc::off_t, host_whence)
                                })
                                .host_syscall_errno()
                                {
                                    Ok(r) => r,
                                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                                };
                                *file_offset = r as usize;
                                return Ok(DispatchOutcome::returned_offset_or_errno(r));
                            }
                            FileContents::Dense(_) | FileContents::RootFsBacked { .. } => {
                                if offset < 0 {
                                    return Ok(DispatchOutcome::errno(LINUX_ENXIO));
                                }
                                let file_size = match contents.len() {
                                    Ok(l) => l as usize,
                                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                                };
                                if (offset as usize) >= file_size {
                                    return Ok(DispatchOutcome::errno(LINUX_ENXIO));
                                }
                                let next = if whence == LINUX_SEEK_DATA {
                                    offset
                                } else {
                                    file_size as i64
                                };
                                *file_offset = next as usize;
                                return Ok(DispatchOutcome::returned_offset_or_errno(next));
                            }
                        }
                    }
                    let file_size = match contents.len() {
                        Ok(l) => l as i64,
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    };
                    (*file_offset as i64, file_size)
                }
                OpenDescription::SyntheticFile {
                    contents,
                    offset: file_offset,
                    ..
                } => {
                    if whence == LINUX_SEEK_DATA || whence == LINUX_SEEK_HOLE {
                        if offset < 0 {
                            return Ok(DispatchOutcome::errno(LINUX_ENXIO));
                        }
                        let file_size = contents.len();
                        if (offset as usize) >= file_size {
                            return Ok(DispatchOutcome::errno(LINUX_ENXIO));
                        }
                        let next = if whence == LINUX_SEEK_DATA {
                            offset
                        } else {
                            file_size as i64
                        };
                        *file_offset = next as usize;
                        return Ok(DispatchOutcome::returned_offset_or_errno(next));
                    }
                    (*file_offset as i64, contents.len() as i64)
                }
                OpenDescription::InMemoryFile {
                    contents,
                    offset: file_offset,
                    ..
                } => {
                    if whence == LINUX_SEEK_DATA || whence == LINUX_SEEK_HOLE {
                        if offset < 0 {
                            return Ok(DispatchOutcome::errno(LINUX_ENXIO));
                        }
                        let file_size = contents.read().len();
                        if (offset as usize) >= file_size {
                            return Ok(DispatchOutcome::errno(LINUX_ENXIO));
                        }
                        let next = if whence == LINUX_SEEK_DATA {
                            offset
                        } else {
                            file_size as i64
                        };
                        *file_offset = next as usize;
                        return Ok(DispatchOutcome::returned_offset_or_errno(next));
                    }
                    (*file_offset as i64, contents.read().len() as i64)
                }
                OpenDescription::Directory {
                    listing, offset, ..
                } => {
                    if whence == LINUX_SEEK_DATA || whence == LINUX_SEEK_HOLE {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    (
                        *offset as i64,
                        listing.entries().map_or(0, |entries| entries.len()) as i64,
                    )
                }
                OpenDescription::SyntheticDevice { .. } => {
                    return match whence {
                        LINUX_SEEK_SET | LINUX_SEEK_CUR | LINUX_SEEK_END => {
                            if offset < 0 {
                                Ok(DispatchOutcome::errno(LINUX_EINVAL))
                            } else {
                                Ok(DispatchOutcome::Returned { value: 0 })
                            }
                        }
                        _ => Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                    };
                }
                // Linux returns ESPIPE for lseek on a pipe / socket / tty
                // (the kernel's POSIX answer for "unseekable stream") and
                // EINVAL only for nonsensical arg combinations. Returning
                // EINVAL here made dpkg-query's ftell() retry-loop spin
                // forever because POSIX says "EINVAL is recoverable" while
                // ESPIPE means "give up, it's a stream".
                OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::InMemorySocket { .. }
                | OpenDescription::SignalFd { .. }
                // A perf event fd is an unseekable stream (verified ESPIPE
                // against the Docker oracle).
                | OpenDescription::PerfEvent { .. }
                | OpenDescription::FsContext { .. }
                | OpenDescription::Mqueue { .. }
                | OpenDescription::BpfMap { .. }
                | OpenDescription::BpfProg { .. }
                | OpenDescription::Netlink { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
                }
                // HostFile is handled by the early libc::lseek above.
                OpenDescription::HostFile { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Inotify { .. }
                | OpenDescription::Fanotify { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
            };
            let next = match whence {
                LINUX_SEEK_SET => offset,
                LINUX_SEEK_CUR => current.saturating_add(offset),
                LINUX_SEEK_END => end.saturating_add(offset),
                _ => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
            };
            if next < 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }

            match &mut *open {
                OpenDescription::Closed { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                OpenDescription::File { offset, .. }
                | OpenDescription::Directory { offset, .. }
                | OpenDescription::SyntheticFile { offset, .. }
                | OpenDescription::InMemoryFile { offset, .. } => *offset = next as usize,
                OpenDescription::HostFile { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Inotify { .. }
                | OpenDescription::Fanotify { .. }
                | OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::InMemorySocket { .. }
                | OpenDescription::SignalFd { .. }
                | OpenDescription::SyntheticDevice { .. }
                | OpenDescription::PerfEvent { .. }
                | OpenDescription::FsContext { .. }
                | OpenDescription::Mqueue { .. }
                | OpenDescription::BpfMap { .. }
                | OpenDescription::BpfProg { .. }
                | OpenDescription::Netlink { .. } => {}
            }
            // A rewind drops a read-time snapshot so the next getdents64
            // lists a FRESH view (Linux re-reads the directory after
            // rewinddir). A synthetic mount's fixed listing replays.
            let visible_self = proc_visible_self(cx.kernel);
            if next == 0
                && let OpenDescription::Directory { listing, path, .. } = &mut *open
                && (matches!(listing, DirListing::Loaded(_))
                    || is_proc_self_fd_dir(path, visible_self)
                    || is_proc_self_fdinfo_dir(path, visible_self))
            {
                *listing = DirListing::Pending;
            }
            Ok(DispatchOutcome::returned_offset_or_errno(next))

        }

        fn read(this, cx, fd: Fd, buf: GuestPtr, count: u64) {

            let fd: Fd = fd;
            // An O_PATH descriptor is not open for I/O (open13 → EBADF).
            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            if this.io_uring_description(fd.0).is_some() {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // memfd_secret: no file read method → EINVAL (memfdsecret probe).
            if this.fd_is_secretmem(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if this.fd_is_controlling_tty(cx.kernel, fd.0)
                && cx.kernel.kernel().tty_caller_is_background(cx.kernel)
            {
                let tid = Self::ctx_tid(cx);
                let orphaned = cx.kernel.kernel().caller_process_group_is_orphaned(cx.kernel);
                let ign_ttin = this.signal_is_ignored(cx.kernel, crate::linux_abi::LINUX_SIGTTIN);
                let blk_ttin = this.signal_blocked(cx.kernel, tid, crate::linux_abi::LINUX_SIGTTIN);
                if orphaned || ign_ttin || blk_ttin {
                    return Ok(DispatchOutcome::errno(carrick_abi::LINUX_EIO));
                }
                if let Ok(signal) = crate::kernel::LinuxSignal::for_signal_number(crate::linux_abi::LINUX_SIGTTIN) {
                    cx.kernel.kernel().post_signal_to_process_group(
                        cx.kernel.container().id(),
                        cx.kernel.task().process_group(),
                        signal,
                    );
                }
                return Ok(DispatchOutcome::errno(LINUX_EINTR));
            }
            let address = buf.0;
            let length =
                usize::try_from(count).map_err(|_| DispatchError::LengthTooLarge(count))?;
            // Calling thread id (for signalfd drain). Taken before borrowing
            // cx.memory mutably below.
            let tid = Self::ctx_tid(cx);
            let memory = &mut *cx.memory;
            // Guest's intended blocking mode for this fd; passed to the host-fd
            // read helper so a blocking-mode fd hands off to the lockless kqueue
            // wait on EAGAIN instead of blocking under the dispatcher lock. (read has no
            // per-call non-blocking flag.) Computed before the open_files borrow.
            let nonblocking = this.io_is_nonblocking(fd.0, 0);
            // inotify IN_ACCESS: a read(2) against a watched regular file emits
            // IN_ACCESS on that file. The kernel reports it per read syscall,
            // independent of bytes returned. Fast-exits when nothing is watched.
            this.inotify_emit_for_fd(fd.0, carrick_abi::LINUX_IN_ACCESS);
            // fanotify FAN_ACCESS: same operation, one event. fanotify has no
            // self/child split — the registry decides whether an inode mark or
            // an FAN_EVENT_ON_CHILD directory mark receives it.
            this.fanotify_emit_for_fd(
                cx.kernel,
                fd.0,
                carrick_abi::LinuxFanotifyEvents::ACCESS,
            );
            // A stdio fd the guest explicitly closed (and did not reopen) is a
            // genuinely closed descriptor: read is EBADF, not a host-stdin read.
            if this.stdio_is_closed(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // fd 0 with no explicit OpenDescription: read from host stdin.
            // This is what makes `read` against the guest's stdin pick up
            // input from the user's terminal (or whatever the carrick host
            // process's stdin is — file, pipe, or terminal).
            if fd.0 == 0 && !this.fd_table_contains(0) {
                crate::dispatch::net::set_host_nonblocking(0);
                return Ok(read_host_pipe(
                    memory,
                    address,
                    length,
                    0,
                    None,
                    nonblocking,
                    WaitFdAuthority::internal(InternalWaitKind::CarrierControl),
                ));
            }
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let Some(mut open) = open_file.description.write() else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            // read() on a regular file opened write-only (O_WRONLY) → EBADF
            // (open09/creat01 read a creat()'d write-only fd). Only regular-file
            // descriptions carry O_ACCMODE semantics; pipes/sockets/eventfds and
            // the like have their own readability rules handled per-branch.
            if matches!(
                &*open,
                OpenDescription::File { .. }
                    | OpenDescription::SyntheticFile { .. }
                    | OpenDescription::InMemoryFile { .. }
                    | OpenDescription::HostFile { .. }
            ) && open_file.description.common().status_flags() & LINUX_O_ACCMODE == LINUX_O_WRONLY
            {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            let (read_len, bytes) = match &mut *open {
                OpenDescription::Closed { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                OpenDescription::File {
                    contents, offset, ..
                } => {
                    let mut buf = vec![0u8; length];
                    match contents.read_at(*offset as u64, &mut buf) {
                        Ok(read_len) => {
                            *offset += read_len;
                            buf.truncate(read_len);
                            (read_len, buf)
                        }
                        Err(errno) => {
                            drop(open);
                            return Ok(DispatchOutcome::errno(errno));
                        }
                    }
                }
                OpenDescription::InMemoryFile {
                    contents,
                    offset,
                    ..
                } => {
                    let data = contents.read();
                    let bytes = data.read_range(*offset, length);
                    let read_len = bytes.len();
                    *offset += read_len;
                    (read_len, bytes)
                }
                OpenDescription::SyntheticFile {
                    path,
                    contents,
                    offset,
                    ..
                } => {
                    // `/proc/<pid>/mem` for the guest's own process is a synthetic
                    // file whose reads translate the file offset as a GUEST VIRTUAL
                    // ADDRESS and return that process's memory there (debuggers +
                    // LTP read their own mappings this way). An unmapped VA is EIO,
                    // like Linux. Every OTHER synthetic file serves its precomputed
                    // byte blob.
                    //
                    // `memory` is the CALLER's address space, so the predicate
                    // must reject a peer's pid — otherwise this arm answers
                    // `/proc/<peer>/mem` with the reader's own bytes. The open
                    // side refuses a peer first; this is the second gate on the
                    // same invariant, kept because the two are reached
                    // independently (an fd can outlive the check that made it).
                    let self_pid = crate::vfs::proc::self_linux_pid(
                        this.synthetic_proc_identity(cx.kernel),
                    );
                    if crate::vfs::proc::is_proc_self_mem_path(path, self_pid) {
                        let va = *offset as u64;
                        // Secret memory (memfd_secret mappings) is invisible
                        // to the kernel's view of the process: a read that
                        // touches a live secretmem mapping fails EIO
                        // (memfdsecret probe `procmem_hidden`).
                        if length > 0 && this.range_touches_secretmem(va, length as u64) {
                            drop(open);
                            return Ok(DispatchOutcome::errno(carrick_abi::LINUX_EIO));
                        }
                        match memory.read_bytes(va, length) {
                            Ok(bytes) => {
                                let read_len = bytes.len();
                                *offset += read_len;
                                (read_len, bytes)
                            }
                            Err(_) => {
                                drop(open);
                                return Ok(DispatchOutcome::errno(carrick_abi::LINUX_EIO));
                            }
                        }
                    } else if crate::vfs::proc::is_proc_self_pagemap_path(path, self_pid) {
                        let present = (1u64 << 63).to_le_bytes();
                        let mut bytes = vec![0u8; length];
                        for (i, byte) in bytes.iter_mut().enumerate() {
                            *byte = present[(*offset + i) % present.len()];
                        }
                        *offset += bytes.len();
                        (bytes.len(), bytes)
                    } else {
                        let remaining: &[u8] = contents.get(*offset..).unwrap_or(&[]);
                        let read_len = remaining.len().min(length);
                        let bytes = remaining[..read_len].to_vec();
                        *offset += read_len;
                        (read_len, bytes)
                    }
                }
                OpenDescription::SyntheticDevice { kind, .. } => {
                    let (read_len, bytes) = match kind {
                        crate::vfs::SyntheticDeviceKind::Null => (0, Vec::new()),
                        crate::vfs::SyntheticDeviceKind::Zero
                        | crate::vfs::SyntheticDeviceKind::Full => {
                            (length, vec![0u8; length])
                        }
                        crate::vfs::SyntheticDeviceKind::Random
                        | crate::vfs::SyntheticDeviceKind::Urandom => {
                            let mut buf = vec![0u8; length];
                            unsafe {
                                libc::arc4random_buf(buf.as_mut_ptr().cast(), length);
                            }
                            (length, buf)
                        }
                    };
                    (read_len, bytes)
                }
                OpenDescription::EventFd {
                    state,
                    semaphore,
                    ..
                } => {
                    let state = Arc::clone(state);
                    let semaphore = *semaphore;
                    let nonblocking = LinuxOpenFlags::from_bits_truncate(
                        open_file.description.common().status_flags(),
                    )
                    .contains(LinuxOpenFlags::NONBLOCK);
                    drop(open);
                    return Ok(read_eventfd(
                        memory,
                        address,
                        length,
                        &state,
                        semaphore,
                        nonblocking,
                        WaitFdAuthority::logical(
                            this.captured_slot_authority(fd.0).ok_or(LINUX_EBADF)?,
                        ),
                    ));
                }
                OpenDescription::TimerFd { state, .. } => {
                    let state = Arc::clone(state);
                    let nonblocking =
                        open_file.description.common().status_flags() & LINUX_TFD_NONBLOCK != 0;
                    drop(open);
                    return Ok(read_timerfd(memory, address, length, &state, nonblocking));
                }
                OpenDescription::Inotify { state, .. } => {
                    let state = Arc::clone(state);
                    let nonblocking =
                        open_file.description.common().status_flags() & LINUX_O_NONBLOCK != 0;
                    drop(open);
                    // Drain queued inotify_event records into the guest buffer.
                    // used non-blocking + epoll; a true blocking wait on the
                    // backing readiness poll fd parks via would_block_outcome.
                    return Ok(match state.read_records(length) {
                        Ok(bytes) if bytes.is_empty() => super::would_block_outcome(
                            state.poll_fd(),
                            libc::POLLIN,
                            nonblocking,
                            None,
                            WaitFdAuthority::logical(
                                this.captured_slot_authority(fd.0).ok_or(LINUX_EBADF)?,
                            ),
                        ),
                        Ok(bytes) => {
                            if memory.write_bytes(address, &bytes).is_err() {
                                DispatchOutcome::errno(LINUX_EFAULT)
                            } else {
                                DispatchOutcome::returned_len_or_errno(bytes.len())
                            }
                        }
                        Err(errno) => DispatchOutcome::errno(errno),
                    });
                }
                OpenDescription::Fanotify { group, .. } => {
                    let group = Arc::clone(group);
                    // Linux mirrors FAN_NONBLOCK into status_flags at init, and F_SETFL
                    // mutates status_flags; status_flags is authoritative for nonblocking.
                    let _ = group.init_nonblocking();
                    let nonblocking =
                        open_file.description.common().status_flags() & LINUX_O_NONBLOCK != 0;
                    drop(open);
                    return notify::read_fanotify(
                        this,
                        notify::ReadFanotifyRequest {
                            context: cx.kernel,
                            registry: cx.thread.as_ref().map(|thread| thread.registry),
                            reporter: cx.reporter,
                            memory,
                            address,
                            length,
                            group: &group,
                            nonblocking,
                            guest_fd: fd.0,
                        },
                    );
                }
                OpenDescription::PipeReader { pipe, .. } => {
                    let pipe = Arc::clone(pipe);
                    let flags = open_file.description.common().status_flags();
                    drop(open);
                    let Some(wait_authority) = this
                        .captured_slot_authority(fd.0)
                        .map(WaitFdAuthority::logical)
                    else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    return Ok(read_pipe(
                        memory,
                        address,
                        length,
                        &pipe,
                        flags,
                        fd.0,
                        wait_authority,
                    ));
                }
                OpenDescription::HostPipe {
                    host_fd,
                    is_read_end,
                    pty,
                    bidirectional,
                    ..
                } => {
                    // pty ends and O_RDWR FIFOs are bidirectional; only real
                    // one-way pipe ends are gated by is_read_end.
                    if !*is_read_end && pty.is_none() && !*bidirectional {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    let host_fd_raw = host_fd.raw();
                    let host_fd_owner = host_fd.clone();
                    let pty_role = *pty;
                    drop(open);
                    let staged = this.take_staged_splice_pipe_bytes(fd.0, length)?;
                    if !staged.is_empty() {
                        if memory.write_bytes(address, &staged).is_err() {
                            this.restore_splice_pipe_bytes(fd.0, &staged);
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                        return Ok(DispatchOutcome::returned_len_or_errno(staged.len()));
                    }
                    let outcome = read_host_pipe(
                        memory,
                        address,
                        length,
                        host_fd_raw,
                        Some(host_fd_owner),
                        nonblocking,
                        WaitFdAuthority::logical(
                            this.captured_slot_authority(fd.0).ok_or(LINUX_EBADF)?,
                        ),
                    );
                    // Darwin reports EOF when the last pty slave closes;
                    // Linux's master read contract is EIO after any rescued
                    // tail has drained. Keep ordinary pipes and slave EOFs
                    // untouched.
                    return Ok(match (pty_role, outcome) {
                        (
                            Some(crate::vfs::PtyRole {
                                is_master: true, ..
                            }),
                            DispatchOutcome::Returned { value: 0 },
                        ) => DispatchOutcome::errno(crate::linux_abi::LINUX_EIO),
                        (_, outcome) => outcome,
                    });
                }
                OpenDescription::Directory { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EISDIR));
                }
                OpenDescription::SignalFd { mask, .. } => {
                    let mask = *mask;
                    drop(open);
                    // Drain pending signals matching the fd's mask into
                    // signalfd_siginfo records (empty → EAGAIN, like inotify).
                    return Ok(this.read_signalfd(cx.kernel, memory, address, length, mask, tid));
                }
                OpenDescription::PerfEvent { state, .. } => {
                    let state = Arc::clone(state);
                    drop(open);
                    // Report the counter in the attr.read_format layout; a
                    // short buffer is ENOSPC. Reads never drain the value.
                    return Ok(this.read_perf_event(memory, address, length, &state));
                }
                // read() on an fs context (the kernel's fsconfig error-log
                // channel) is unimplemented — EINVAL, documented in
                // `dispatch/mount_api.rs`.
                OpenDescription::FsContext { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                OpenDescription::PipeWriter { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Mqueue { .. }
                | OpenDescription::BpfMap { .. }
                | OpenDescription::BpfProg { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                OpenDescription::HostSocket { host_fd, .. } => {
                    return Ok(read_host_pipe(
                        memory,
                        address,
                        length,
                        host_fd.raw(),
                        Some(host_fd.clone()),
                        nonblocking,
                        WaitFdAuthority::logical(
                            this.captured_slot_authority(fd.0).ok_or(LINUX_EBADF)?,
                        ),
                    ));
                }
                OpenDescription::InMemorySocket { socket, .. } => {
                    let socket = Arc::clone(socket);
                    drop(open);
                    let mut buf = vec![0u8; length];
                    match socket.recv_stream(&mut buf, 0) {
                        Ok((read_len, _)) => {
                            if read_len > 0 {
                                if memory.write_bytes(address, &buf[..read_len]).is_err() {
                                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                                }
                                return Ok(DispatchOutcome::returned_len_or_errno(read_len));
                            } else {
                                return Ok(DispatchOutcome::Returned { value: 0 });
                            }
                        }
                        Err(LINUX_EAGAIN) => return Ok(DispatchOutcome::errno(LINUX_EAGAIN)),
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    }
                }
                // Netlink: drain whatever a prior dump request queued. A bare
                // read(2) is rare on netlink sockets (recvmsg is the norm), but
                // model it as draining the synthetic response so it doesn't
                // wedge a caller.
                OpenDescription::Netlink { recv_queue, .. } => {
                    return Ok(net::drain_netlink_queue(
                        memory, address, length, recv_queue,
                    ));
                }
                // Real host file: libc::read advances the kernel offset
                // (shared across fork). read_host_pipe is just a
                // memory-into-guest read(2) wrapper.
                OpenDescription::HostFile { host_fd, .. } => {
                    return Ok(read_host_pipe(
                        memory,
                        address,
                        length,
                        host_fd.raw(),
                        Some(host_fd.clone()),
                        nonblocking,
                        WaitFdAuthority::logical(
                            this.captured_slot_authority(fd.0).ok_or(LINUX_EBADF)?,
                        ),
                    ));
                }
            };
            memory.write_bytes(address, &bytes)?;
            Ok(DispatchOutcome::returned_len_or_errno(read_len))

        }

        fn readv(this, cx, fd: Fd, iov: GuestPtr, vlen: u64) {

            let fd: Fd = fd;
            // memfd_secret: no file read method → EINVAL (memfdsecret probe).
            if this.fd_is_secretmem(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let iov = iov.0;
            let iovcnt =
                usize::try_from(vlen).map_err(|_| DispatchError::LengthTooLarge(vlen))?;
            let tid = cx.tid();
            let memory = &mut *cx.memory;
            let iovecs = read_iovecs(memory, iov, iovcnt)?;
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let nonblocking = this.io_is_nonblocking(fd.0, 0);
            let Some(mut open) = open_file.description.write() else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            // readv() on a regular file opened write-only (O_WRONLY) → EBADF.
            if matches!(
                &*open,
                OpenDescription::File { .. }
                    | OpenDescription::SyntheticFile { .. }
                    | OpenDescription::HostFile { .. }
            ) && open_file.description.common().status_flags() & LINUX_O_ACCMODE == LINUX_O_WRONLY
            {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // Real host file: readv via the kernel fd (advances the shared
            // offset). Fill each iovec sequentially.
            if let OpenDescription::HostFile { host_fd, .. } = &*open {
                let hfd = host_fd.raw();
                if let Some(targets) = prepare_readv_targets(memory, &iovecs)? {
                    if targets.host_iovecs.is_empty() {
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    let iovcnt =
                        i32::try_from(targets.host_iovecs.len()).map_err(|_| LINUX_EINVAL)?;
                    let n = {
                        let _host_write = carrick_guest_mem::HostWriteGuard::new(
                            memory,
                            &targets.guest_ranges,
                        );
                        unsafe { libc::readv(hfd, targets.host_iovecs.as_ptr(), iovcnt) }
                    };
                    let n = n.host_syscall_errno()?;
                    return Ok(DispatchOutcome::returned_isize_or_errno(n));
                }
                let mut total = 0i64;
                for iov in &iovecs {
                    let len = usize::try_from(iov.iov_len)
                        .map_err(|_| DispatchError::LengthTooLarge(iov.iov_len))?;
                    if len == 0 {
                        continue;
                    }
                    match read_host_pipe(
                        memory,
                        iov.iov_base,
                        len,
                        hfd,
                        None,
                        /*nonblocking=*/ false,
                        WaitFdAuthority::internal(InternalWaitKind::CarrierControl),
                    ) {
                        DispatchOutcome::Returned { value } => {
                            total += value;
                            if (value as usize) < len {
                                break;
                            }
                        }
                        other => return Ok(other),
                    }
                }
                return Ok(DispatchOutcome::Returned { value: total });
            }
            match &*open {
                OpenDescription::HostPipe {
                    host_fd,
                    is_read_end,
                    pty,
                    bidirectional,
                    ..
                } => {
                    if !*is_read_end && pty.is_none() && !*bidirectional {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    let hfd = host_fd.raw();
                    let owner = Some(host_fd.clone());
                    let pty_role = *pty;
                    drop(open);
                    let staged_capacity = iovecs.iter().try_fold(0usize, |total, iovec| {
                        usize::try_from(iovec.iov_len)
                            .ok()
                            .and_then(|length| total.checked_add(length))
                    });
                    let Some(staged_capacity) = staged_capacity else {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    };
                    let staged = this.take_staged_splice_pipe_bytes(
                        fd.0,
                        staged_capacity.min(crate::dispatch::MAX_RW_COUNT),
                    )?;
                    if !staged.is_empty() {
                        let read_len = read_from_contents_at(memory, &staged, 0, &iovecs)?;
                        if read_len < staged.len() {
                            this.restore_splice_pipe_bytes(fd.0, &staged[read_len..]);
                        }
                        return Ok(DispatchOutcome::returned_len_or_errno(read_len));
                    }
                    let outcome = Self::read_host_pipe_iovecs(
                        memory,
                        &iovecs,
                        hfd,
                        owner,
                        nonblocking,
                        WaitFdAuthority::logical(
                            this.captured_slot_authority(fd.0).ok_or(LINUX_EBADF)?,
                        ),
                    );
                    return Ok(match (pty_role, outcome) {
                        (
                            Some(crate::vfs::PtyRole {
                                is_master: true, ..
                            }),
                            DispatchOutcome::Returned { value: 0 },
                        ) => DispatchOutcome::errno(crate::linux_abi::LINUX_EIO),
                        (_, outcome) => outcome,
                    });
                }
                OpenDescription::HostSocket { host_fd, .. } => {
                    let hfd = host_fd.raw();
                    let owner = Some(host_fd.clone());
                    drop(open);
                    return Ok(Self::read_host_pipe_iovecs(
                        memory,
                        &iovecs,
                        hfd,
                        owner,
                        nonblocking,
                        WaitFdAuthority::logical(
                            this.captured_slot_authority(fd.0).ok_or(LINUX_EBADF)?,
                        ),
                    ));
                }
                OpenDescription::InMemorySocket { socket, .. } => {
                    let socket = Arc::clone(socket);
                    drop(open);
                    let mut total = 0i64;
                    for iov in &iovecs {
                        let len = usize::try_from(iov.iov_len)
                            .map_err(|_| DispatchError::LengthTooLarge(iov.iov_len))?;
                        if len == 0 {
                            continue;
                        }
                        let mut buf = vec![0u8; len];
                        match socket.recv_stream(&mut buf, 0) {
                            Ok((read_len, _)) => {
                                if read_len > 0 {
                                    if memory.write_bytes(iov.iov_base, &buf[..read_len]).is_err() {
                                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                                    }
                                    total += read_len as i64;
                                    if read_len < len {
                                        break;
                                    }
                                } else {
                                    break;
                                }
                            }
                            Err(LINUX_EAGAIN) if total > 0 => break,
                            Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                        }
                    }
                    return Ok(DispatchOutcome::Returned { value: total });
                }
                OpenDescription::PipeReader { pipe, .. } => {
                    let pipe = Arc::clone(pipe);
                    let flags = open_file.description.common().status_flags();
                    drop(open);
                    let mut total = 0i64;
                    for iov in &iovecs {
                        let len = usize::try_from(iov.iov_len)
                            .map_err(|_| DispatchError::LengthTooLarge(iov.iov_len))?;
                        if len == 0 {
                            continue;
                        }
                        let Some(wait_authority) = this
                            .captured_slot_authority(fd.0)
                            .map(WaitFdAuthority::logical)
                        else {
                            if total > 0 {
                                break;
                            }
                            return Ok(DispatchOutcome::errno(LINUX_EBADF));
                        };
                        match read_pipe(
                            memory,
                            iov.iov_base,
                            len,
                            &pipe,
                            flags,
                            fd.0,
                            wait_authority,
                        ) {
                            DispatchOutcome::Returned { value } => {
                                total += value;
                                if (value as usize) < len {
                                    break;
                                }
                            }
                            other => return Ok(other),
                        }
                    }
                    return Ok(DispatchOutcome::Returned { value: total });
                }
                _ => {}
            }
            let read_len = match &mut *open {
                OpenDescription::Closed { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                OpenDescription::File {
                    contents, offset, ..
                } => {
                    let read_len = read_from_file_contents_at(memory, contents, *offset, &iovecs)?;
                    *offset += read_len;
                    read_len
                }
                OpenDescription::SyntheticFile {
                    contents, offset, ..
                } => {
                    let read_len = read_from_contents_at(memory, contents, *offset, &iovecs)?;
                    *offset += read_len;
                    read_len
                }
                OpenDescription::InMemoryFile {
                    contents, offset, ..
                } => {
                    let data = contents.read();
                    let read_len = read_from_sparse_buffer_at(memory, &data, *offset, &iovecs)?;
                    *offset += read_len;
                    read_len
                }
                OpenDescription::SyntheticDevice { kind, .. } => {
                    read_from_synthetic_device_iovecs(memory, *kind, &iovecs)?
                }
                OpenDescription::HostFile { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                // readv on a directory is EISDIR (readv02). Other non-regular
                // fds keep EINVAL here (readv on a pipe/socket reading at the
                // current offset is a separate, untested path).
                OpenDescription::Directory { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EISDIR));
                }
                OpenDescription::PipeWriter { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Inotify { .. }
                | OpenDescription::Fanotify { .. }
                | OpenDescription::PipeReader { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::InMemorySocket { .. }
                | OpenDescription::SignalFd { .. }
                | OpenDescription::PerfEvent { .. }
                | OpenDescription::FsContext { .. }
                | OpenDescription::Mqueue { .. }
                | OpenDescription::BpfMap { .. }
                | OpenDescription::BpfProg { .. }
                | OpenDescription::Netlink { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
            };
            Ok(DispatchOutcome::returned_len_or_errno(read_len))

        }

        fn pread64(this, cx, fd: Fd, buf: GuestPtr, count: u64, offset: u64) {

            let fd: Fd = fd;
            // An O_PATH descriptor is not open for I/O (open13 → EBADF).
            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // memfd_secret: no file read method → EINVAL (memfdsecret probe).
            if this.fd_is_secretmem(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let buffer = buf.0;
            let length =
                usize::try_from(count).map_err(|_| DispatchError::LengthTooLarge(count))?;
            let offset =
                usize::try_from(offset).map_err(|_| DispatchError::LengthTooLarge(offset))?;
            let memory = &mut *cx.memory;
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let Some(open) = open_file.description.read() else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            // pread reads the fd, so a regular file descriptor not open for reading
            // (O_WRONLY) is EBADF (pread02 "not open for reading" case), exactly
            // as the kernel rejects it before touching the data. Non-seekable
            // descriptions (pipes, sockets, FIFOs) return ESPIPE on positional read.
            if matches!(&*open, OpenDescription::HostFile { .. })
                && open_file.description.common().status_flags() & LINUX_O_ACCMODE == LINUX_O_WRONLY
            {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // Real host file: positional read via libc::pread (doesn't
            // disturb the shared kernel offset).
            if let OpenDescription::HostFile { host_fd, .. } = &*open {
                let length = length.min(crate::dispatch::MAX_RW_COUNT);
                let mut buf = vec![0u8; length];
                let n = unsafe {
                    libc::pread(
                        host_fd.raw(),
                        buf.as_mut_ptr() as *mut _,
                        length,
                        offset as libc::off_t,
                    )
                };
                let n = match n.host_syscall_errno() {
                    Ok(value) => value as usize,
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                };
                if n > 0 && memory.write_bytes(buffer, &buf[..n]).is_err() {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                return Ok(DispatchOutcome::returned_len_or_errno(n));
            }
            let bytes = match &*open {
                OpenDescription::Closed { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                OpenDescription::File { contents, .. } => {
                    let mut buf = vec![0u8; length];
                    match contents.read_at(offset as u64, &mut buf) {
                        Ok(n) => {
                            buf.truncate(n);
                            buf
                        }
                        Err(errno) => {
                            drop(open);
                            return Ok(DispatchOutcome::errno(errno));
                        }
                    }
                }
                OpenDescription::SyntheticFile { contents, .. } => contents
                    .get(offset..)
                    .unwrap_or_default()
                    .iter()
                    .take(length)
                    .copied()
                    .collect(),
                OpenDescription::InMemoryFile { contents, .. } => contents
                    .read()
                    .read_range(offset, length),
                OpenDescription::SyntheticDevice { kind, .. } => {
                    match kind {
                        crate::vfs::SyntheticDeviceKind::Null => Vec::new(),
                        crate::vfs::SyntheticDeviceKind::Zero
                        | crate::vfs::SyntheticDeviceKind::Full => vec![0u8; length],
                        crate::vfs::SyntheticDeviceKind::Random
                        | crate::vfs::SyntheticDeviceKind::Urandom => {
                            let mut buf = vec![0u8; length];
                            unsafe {
                                libc::arc4random_buf(buf.as_mut_ptr().cast(), length);
                            }
                            buf
                        }
                    }
                }
                OpenDescription::HostFile { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                OpenDescription::Directory { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EISDIR));
                }
                OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Inotify { .. }
                | OpenDescription::Fanotify { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::SignalFd { .. }
                | OpenDescription::PerfEvent { .. }
                | OpenDescription::FsContext { .. }
                | OpenDescription::Mqueue { .. }
                | OpenDescription::BpfMap { .. }
                | OpenDescription::BpfProg { .. }
                | OpenDescription::Netlink { .. }
                | OpenDescription::InMemorySocket { .. } => {
                    // Positional read on a non-seekable fd (pipe/socket/anon) is
                    // ESPIPE on Linux; a directory is EISDIR (above). pread02.
                    return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
                }
            };
            let read_len = bytes.len();
            if read_len > 0 {
                memory.write_bytes(buffer, &bytes)?;
            }
            Ok(DispatchOutcome::returned_len_or_errno(read_len))

        }

        fn preadv(this, cx, fd: Fd, iov: GuestPtr, vlen: u64, pos_l: u64, pos_h: u64, rwf: u64) {

            let fd: Fd = fd;
            // memfd_secret: no file read method → EINVAL (memfdsecret probe).
            if this.fd_is_secretmem(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let iov = iov.0;
            let iovcnt =
                usize::try_from(vlen).map_err(|_| DispatchError::LengthTooLarge(vlen))?;
            let offset =
                usize::try_from(pos_l).map_err(|_| DispatchError::LengthTooLarge(pos_l))?;
            // preadv2 (canonical 286) treats offset == -1 as "use (and advance)
            // the current file offset" — readv semantics. Plain preadv (69) has
            // no such case, and would hand -1 straight to the host preadv → EINVAL
            // (the preadv201 failure). The trailing RWF_* flags arg (raw_args[5])
            // is advisory for our host-file backing; RWF_HIPRI is a priority hint
            // here, so preadv2(off, RWF_HIPRI) reads like preadv.
            let is_preadv2 = cx.number() == 286;
            let read_at_current = is_preadv2 && (pos_l as i64) == -1;
            // preadv2's RWF_* flags: any bit outside RWF_SUPPORTED is rejected by
            // Linux's kiocb_set_rw_flags() with EOPNOTSUPP (preadv202 passes
            // flag=-1 and expects EOPNOTSUPP, NOT EINVAL). RWF_NOWAIT on our
            // buffered host backing likewise cannot be honored → EOPNOTSUPP. The
            // known-but-advisory bits (HIPRI/DSYNC/SYNC/APPEND) are accepted.
            if is_preadv2
                && rwf
                    & !(crate::linux_abi::LINUX_RWF_SUPPORTED
                        & !crate::linux_abi::LINUX_RWF_NOWAIT)
                    != 0
            {
                return Ok(DispatchOutcome::errno(LINUX_EOPNOTSUPP));
            }
            let memory = &mut *cx.memory;
            let iovecs = read_iovecs(memory, iov, iovcnt)?;
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let Some(open) = open_file.description.read() else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            // preadv reads the fd, so a regular file descriptor not open for reading
            // (O_WRONLY) is EBADF (preadv02 "not open for reading" case), exactly
            // as the kernel rejects it before touching the data. Non-seekable
            // descriptions (pipes, sockets, FIFOs) return ESPIPE on positional read.
            if matches!(&*open, OpenDescription::HostFile { .. })
                && open_file.description.common().status_flags() & LINUX_O_ACCMODE == LINUX_O_WRONLY
            {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // Real host file: positional readv via libc::pread per iovec
            // (kernel offset untouched).
            if let OpenDescription::HostFile { host_fd, .. } = &*open {
                let hfd = host_fd.raw();
                if let Some(targets) = prepare_readv_targets(memory, &iovecs)? {
                    if targets.host_iovecs.is_empty() {
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    let iovcnt =
                        i32::try_from(targets.host_iovecs.len()).map_err(|_| LINUX_EINVAL)?;
                    let n = {
                        let _host_write = carrick_guest_mem::HostWriteGuard::new(
                            memory,
                            &targets.guest_ranges,
                        );
                        unsafe {
                            if read_at_current {
                                libc::readv(hfd, targets.host_iovecs.as_ptr(), iovcnt)
                            } else {
                                libc::preadv(
                                    hfd,
                                    targets.host_iovecs.as_ptr(),
                                    iovcnt,
                                    offset as libc::off_t,
                                )
                            }
                        }
                    };
                    let n = n.host_syscall_errno()?;
                    return Ok(DispatchOutcome::returned_isize_or_errno(n));
                }
                let mut total = 0i64;
                let mut cur = offset;
                for iov in &iovecs {
                    let len = usize::try_from(iov.iov_len)
                        .map_err(|_| DispatchError::LengthTooLarge(iov.iov_len))?;
                    if len == 0 {
                        continue;
                    }
                    let mut buf = vec![0u8; len];
                    // BLOCKING-IO-OK: hfd is an OpenDescription::HostFile (the
                    // `if let HostFile` arm above; stdio returned ESPIPE earlier) —
                    // a regular host file, never a pipe/socket/tty — so this read
                    // cannot block the vCPU waiting on a peer.
                    let n = unsafe {
                        if read_at_current {
                            libc::read(hfd, buf.as_mut_ptr() as *mut _, len)
                        } else {
                            libc::pread(hfd, buf.as_mut_ptr() as *mut _, len, cur as libc::off_t)
                        }
                    };
                    let n = match n.host_syscall_errno() {
                        Ok(value) => value as usize,
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    };
                    if n > 0 && memory.write_bytes(iov.iov_base, &buf[..n]).is_err() {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                    total += n as i64;
                    cur += n;
                    if n < len {
                        break;
                    }
                }
                return Ok(DispatchOutcome::Returned { value: total });
            }
            let read_len = match &*open {
                OpenDescription::Closed { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                OpenDescription::File { contents, .. } => {
                    read_from_file_contents_at(memory, contents, offset, &iovecs)?
                }
                OpenDescription::SyntheticFile { contents, .. } => {
                    read_from_contents_at(memory, contents, offset, &iovecs)?
                }
                OpenDescription::InMemoryFile { contents, .. } => {
                    let data = contents.read();
                    read_from_sparse_buffer_at(memory, &data, offset, &iovecs)?
                }
                OpenDescription::SyntheticDevice { kind, .. } => {
                    read_from_synthetic_device_iovecs(memory, *kind, &iovecs)?
                }
                OpenDescription::HostFile { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                OpenDescription::Directory { .. } => {
                    return Ok(DispatchOutcome::errno(LINUX_EISDIR));
                }
                OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Inotify { .. }
                | OpenDescription::Fanotify { .. }
                | OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::SignalFd { .. }
                | OpenDescription::PerfEvent { .. }
                | OpenDescription::FsContext { .. }
                | OpenDescription::Mqueue { .. }
                | OpenDescription::BpfMap { .. }
                | OpenDescription::BpfProg { .. }
                | OpenDescription::Netlink { .. }
                | OpenDescription::InMemorySocket { .. } => {
                    // Positional read on a non-seekable fd → ESPIPE; directory →
                    // EISDIR (above). preadv02.
                    return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
                }
            };
            Ok(DispatchOutcome::returned_len_or_errno(read_len))

        }

        fn pwrite64(this, cx, fd: Fd, buf: GuestPtr, count: u64, offset: u64) {

            let fd: Fd = fd;
            // An O_PATH descriptor is not open for I/O (open13 → EBADF).
            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // memfd_secret: no file write method → EINVAL (memfdsecret probe).
            if this.fd_is_secretmem(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let address = buf.0;
            let length =
                usize::try_from(count).map_err(|_| DispatchError::LengthTooLarge(count))?;
            let offset = i64::from_ne_bytes(offset.to_ne_bytes());
            if offset < 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // A zero-length write never accesses the buffer — `pwrite(fd, NULL,
            // 0)` returns 0, NOT EFAULT (Linux checks count before touching the
            // buffer; LTP pwrite03). Only read guest memory when count > 0.
            let bytes = if length == 0 {
                Vec::new()
            } else {
                match (*cx.memory).read_bytes(address, length) {
                    Ok(b) => b,
                    Err(_) => {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                }
            };
            if is_stdio_fd(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
            }
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let Some(open) = open_file.description.read() else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            // An O_APPEND fd forces EVERY write to EOF, ignoring the supplied
            // offset (pwrite04). macOS pwrite() on an O_APPEND fd returns EINVAL,
            // so seek-to-end then write() instead (matching the plain write()
            // append path).
            let is_append = LinuxOpenFlags::from_bits_truncate(
                open_file.description.common().status_flags(),
            )
            .contains(LinuxOpenFlags::APPEND);
            if let OpenDescription::SyntheticDevice { kind, .. } = &*open {
                match kind {
                    crate::vfs::SyntheticDeviceKind::Full => {
                        return Ok(DispatchOutcome::errno(LINUX_ENOSPC));
                    }
                    _ => {
                        return Ok(DispatchOutcome::returned_len_or_errno(length));
                    }
                }
            }
            // Real host file: positional write via libc::pwrite (visible
            // across fork; kernel offset untouched).
            if let OpenDescription::HostFile {
                host_fd, writable, ..
            } = &*open
            {
                if !*writable {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                let n = unsafe {
                    if is_append {
                        // O_APPEND writes at EOF regardless of the offset, but
                        // pwrite MUST leave the file offset untouched (pwrite04
                        // checks lseek(SEEK_CUR) is unchanged). Save the offset,
                        // seek to EOF, write, then restore. (The write goes
                        // through write(), not pwrite(), which macOS rejects with
                        // EINVAL on an O_APPEND fd.)
                        let saved = libc::lseek(host_fd.raw(), 0, libc::SEEK_CUR);
                        libc::lseek(host_fd.raw(), 0, libc::SEEK_END);
                        // BLOCKING-IO-OK: HostFile fds are adopted O_NONBLOCK;
                        // regular-file writes do not park on pipe/socket wait.
                        let w = libc::write(host_fd.raw(), bytes.as_ptr() as *const _, length);
                        if saved >= 0 {
                            libc::lseek(host_fd.raw(), saved, libc::SEEK_SET);
                        }
                        w
                    } else {
                        libc::pwrite(
                            host_fd.raw(),
                            bytes.as_ptr() as *const _,
                            length,
                            offset as libc::off_t,
                        )
                    }
                };
                let n = n.host_syscall_errno()?;
                if n > 0 {
                    this.invalidate_dentry_host_fd(host_fd.raw());
                }
                return Ok(DispatchOutcome::returned_isize_or_errno(n));
            }
            // In-memory File (memfd / O_TMPFILE fallback): positional write into
            // the cached contents, honoring memfd write/grow seals. Previously an
            // unconditional EBADF (memfd_create01 CHECK_MFD_*_BY_WRITE pwrites).
            let is_inmem_file = matches!(&*open, OpenDescription::File { .. } | OpenDescription::InMemoryFile { .. });
            drop(open);
            if is_inmem_file {
                let Some(mut open) = open_file.description.write() else {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                };
                if let OpenDescription::InMemoryFile {
                    path,
                    contents,
                    writable,
                    max_size,
                    ..
                } = &mut *open
                {
                    if !*writable {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    let mut data = contents.write();
                    let write_at = if is_append {
                        data.len()
                    } else {
                        offset as usize
                    };
                    let end = match write_at.checked_add(bytes.len()) {
                        Some(e) => e,
                        None => return Ok(DispatchOutcome::errno(LINUX_EFBIG)),
                    };
                    if end > *max_size {
                        return Ok(DispatchOutcome::errno(LINUX_EFBIG));
                    }
                    if data.write_range(write_at, &bytes).is_err() {
                        return Ok(DispatchOutcome::errno(LINUX_EFBIG));
                    }
                    this.fs.rootfs_vfs.notify_inode_changed(path, None);
                    return Ok(DispatchOutcome::returned_len_or_errno(bytes.len()));
                }
                if let OpenDescription::File {
                    path,
                    contents,
                    writable,
                    metadata,
                    ..
                } = &mut *open
                {
                    if !*writable {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    let cur_len = match contents.len() {
                        Ok(l) => l as usize,
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    };
                    let write_at = if is_append {
                        cur_len
                    } else {
                        offset as usize
                    };
                    if let Err(errno) = memfd_seal_write_check(
                        open_file.description.common().seals(),
                        write_at,
                        bytes.len(),
                        cur_len,
                    ) {
                        return Ok(DispatchOutcome::errno(errno));
                    }
                    let mut off = write_at;
                    let written = match write_into_file_contents(contents, &mut off, &bytes) {
                        Ok(n) => n,
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    };
                    let new_len = match contents.len() {
                        Ok(l) => l as usize,
                        Err(errno) if written == 0 => return Ok(DispatchOutcome::errno(errno)),
                        Err(_) => cur_len.max(write_at.saturating_add(written)),
                    };
                    metadata.size = new_len;
                    let writeback = (!is_anon_overlay_path(path)).then(|| (path.clone(), new_len));
                    drop(open);
                    if let Some((path, final_size)) = writeback {
                        let _ = this
                            .fs
                            .rootfs_vfs
                            .write_file_range(&path, write_at, &bytes[..written], final_size);
                    }
                    return Ok(DispatchOutcome::returned_len_or_errno(written));
                }
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            let Some(open) = open_file.description.read() else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let errno = match &*open {
                OpenDescription::Closed { .. }
                | OpenDescription::File { .. }
                | OpenDescription::InMemoryFile { .. }
                | OpenDescription::SyntheticFile { .. } => LINUX_EBADF,
                OpenDescription::HostFile { writable, .. } if !*writable => LINUX_EBADF,
                OpenDescription::HostFile { .. } => LINUX_EINVAL,
                OpenDescription::Directory { .. } => LINUX_EISDIR,
                // A pipe end is ESPIPE for pwrite/pread regardless of its
                // direction: Linux refuses positional I/O on an unseekable
                // description before it looks at the open mode (oracle line
                // `pwrite_pipe_read_end_espipe` in `pipeextra`).
                OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::SignalFd { .. }
                | OpenDescription::PerfEvent { .. }
                | OpenDescription::FsContext { .. }
                | OpenDescription::Mqueue { .. }
                | OpenDescription::BpfMap { .. }
                | OpenDescription::BpfProg { .. }
                | OpenDescription::Netlink { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Inotify { .. }
                | OpenDescription::SyntheticDevice { .. }
                | OpenDescription::Fanotify { .. }
                | OpenDescription::InMemorySocket { .. } => LINUX_ESPIPE,
            };
            Ok(DispatchOutcome::errno(errno))

        }

        fn pwritev(this, cx, fd: Fd, iov: GuestPtr, vlen: u64, pos_l: u64, pos_h: u64, rwf: u64) {

            let fd: Fd = fd;
            // memfd_secret: no file write method → EINVAL (memfdsecret probe).
            if this.fd_is_secretmem(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let iov = iov.0;
            let iovcnt =
                usize::try_from(vlen).map_err(|_| DispatchError::LengthTooLarge(vlen))?;
            let offset = i64::from_ne_bytes(pos_l.to_ne_bytes());
            // pwritev2 (canonical 287) treats offset == -1 as "use (and advance)
            // the current file offset" — writev semantics. Plain pwritev (70) has
            // no such case. The trailing RWF_* flags arg is advisory for our
            // host-file backing; RWF_HIPRI writes like pwritev.
            let is_pwritev2 = cx.number() == 287;
            let write_at_current = is_pwritev2 && offset == -1;
            // pwritev2's RWF_* flags: any bit outside RWF_SUPPORTED is rejected by
            // Linux's kiocb_set_rw_flags() with EOPNOTSUPP (pwritev202 passes
            // flag=-1 and expects EOPNOTSUPP, NOT EINVAL). RWF_NOWAIT on our
            // buffered host backing likewise cannot be honored → EOPNOTSUPP. The
            // known-but-advisory bits (HIPRI/DSYNC/SYNC/APPEND) are accepted.
            if is_pwritev2
                && rwf
                    & !(crate::linux_abi::LINUX_RWF_SUPPORTED
                        & !crate::linux_abi::LINUX_RWF_NOWAIT)
                    != 0
            {
                return Ok(DispatchOutcome::errno(LINUX_EOPNOTSUPP));
            }
            let memory = &*cx.memory;
            let iovecs = read_iovecs(memory, iov, iovcnt)?;
            if offset < 0 && !write_at_current {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let payloads = match prepare_pwritev_payloads(memory, &iovecs) {
                Ok(payloads) => payloads,
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            };
            if is_stdio_fd(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
            }
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let Some(open) = open_file.description.read() else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            // An O_APPEND fd writes at EOF regardless of the offset, but pwritev
            // (like pwrite) MUST leave the file offset untouched. Save the
            // offset, seek to EOF, then write via writev()/write() (macOS rejects
            // pwritev() on an O_APPEND fd with EINVAL), and restore the offset
            // afterward.
            let is_append = LinuxOpenFlags::from_bits_truncate(
                open_file.description.common().status_flags(),
            )
            .contains(LinuxOpenFlags::APPEND);
            if let OpenDescription::SyntheticDevice { kind, .. } = &*open {
                match kind {
                    crate::vfs::SyntheticDeviceKind::Full => {
                        return Ok(DispatchOutcome::errno(LINUX_ENOSPC));
                    }
                    _ => {
                        let mut total = 0i64;
                        for iov in &iovecs {
                            total += iov.iov_len as i64;
                        }
                        return Ok(DispatchOutcome::Returned { value: total });
                    }
                }
            }
            if let OpenDescription::InMemoryFile {
                contents,
                writable,
                offset: current_offset,
                max_size,
                ..
            } = &*open
            {
                if !*writable {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                let mut data = contents.write();
                let mut cur = if is_append {
                    data.len()
                } else if write_at_current {
                    *current_offset
                } else {
                    offset as usize
                };
                let mut total = 0i64;
                if let PwritevPayloads::Borrowed(borrowed_iovecs) = &payloads {
                    for iov in borrowed_iovecs {
                        let len = iov.iov_len;
                        if len == 0 {
                            continue;
                        }
                        let buf = unsafe { std::slice::from_raw_parts(iov.iov_base as *const u8, len) };
                        let end = match cur.checked_add(len) {
                            Some(e) => e,
                            None => {
                                if total > 0 {
                                    break;
                                }
                                return Ok(DispatchOutcome::errno(LINUX_EFBIG));
                            }
                        };
                        if end > *max_size {
                            if total > 0 {
                                break;
                            }
                            return Ok(DispatchOutcome::errno(LINUX_EFBIG));
                        }
                        if data.write_range(cur, buf).is_err() {
                            if total > 0 {
                                break;
                            }
                            return Ok(DispatchOutcome::errno(LINUX_EFBIG));
                        }
                        cur = end;
                        total += len as i64;
                    }
                } else if let PwritevPayloads::Staged(staged_iovecs) = &payloads {
                    for buf in staged_iovecs {
                        let len = buf.len();
                        if len == 0 {
                            continue;
                        }
                        let end = match cur.checked_add(len) {
                            Some(e) => e,
                            None => {
                                if total > 0 {
                                    break;
                                }
                                return Ok(DispatchOutcome::errno(LINUX_EFBIG));
                            }
                        };
                        if end > *max_size {
                            if total > 0 {
                                break;
                            }
                            return Ok(DispatchOutcome::errno(LINUX_EFBIG));
                        }
                        if data.write_range(cur, buf).is_err() {
                            if total > 0 {
                                break;
                            }
                            return Ok(DispatchOutcome::errno(LINUX_EFBIG));
                        }
                        cur = end;
                        total += len as i64;
                    }
                }
                drop(data);
                if write_at_current {
                    drop(open);
                    if let Some(mut open_write) = open_file.description.write() {
                        if let OpenDescription::InMemoryFile { offset: off, .. } = &mut *open_write {
                            *off = cur;
                        }
                    }
                }
                return Ok(DispatchOutcome::Returned { value: total });
            }
            // Real host file: positional writev via libc::pwrite per iovec.
            if let OpenDescription::HostFile {
                host_fd, writable, ..
            } = &*open
            {
                if !*writable {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                let hfd = host_fd.raw();
                let saved_offset =
                    is_append.then(|| unsafe { libc::lseek(hfd, 0, libc::SEEK_CUR) });
                if is_append {
                    unsafe { libc::lseek(hfd, 0, libc::SEEK_END) };
                }
                let restore_offset = |saved: Option<i64>| {
                    if let Some(s) = saved
                        && s >= 0
                    {
                        unsafe { libc::lseek(hfd, s, libc::SEEK_SET) };
                    }
                };
                let at_current = write_at_current || is_append;
                if let PwritevPayloads::Borrowed(borrowed_iovecs) = &payloads {
                    if borrowed_iovecs.is_empty() {
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    let iovcnt =
                        i32::try_from(borrowed_iovecs.len()).map_err(|_| LINUX_EINVAL)?;
                    let n = unsafe {
                        if at_current {
                            libc::writev(hfd, borrowed_iovecs.as_ptr(), iovcnt)
                        } else {
                            libc::pwritev(
                                hfd,
                                borrowed_iovecs.as_ptr(),
                                iovcnt,
                                offset as libc::off_t,
                            )
                        }
                    };
                    restore_offset(saved_offset);
                    let n = n.host_syscall_errno()?;
                    if n > 0 {
                        this.invalidate_dentry_host_fd(hfd);
                    }
                    return Ok(DispatchOutcome::returned_isize_or_errno(n));
                }
                let mut total = 0i64;
                let mut cur = offset;
                let PwritevPayloads::Staged(staged_iovecs) = &payloads else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                for buf in staged_iovecs {
                    if buf.is_empty() {
                        continue;
                    }
                    let len = buf.len();
                    // BLOCKING-IO-OK: hfd is an OpenDescription::HostFile (the
                    // `if let HostFile` arm above; stdio returned ESPIPE earlier) —
                    // a regular host file, never a pipe/socket/tty — so this write
                    // cannot block the vCPU waiting on a peer.
                    let n = unsafe {
                        if at_current {
                            libc::write(hfd, buf.as_ptr() as *const _, len)
                        } else {
                            libc::pwrite(hfd, buf.as_ptr() as *const _, len, cur as libc::off_t)
                        }
                    };
                    let n = n.host_syscall_errno()?;
                    total += n as i64;
                    cur += n as i64;
                    if (n as usize) < len {
                        break;
                    }
                }
                restore_offset(saved_offset);
                if total > 0 {
                    this.invalidate_dentry_host_fd(hfd);
                }
                return Ok(DispatchOutcome::Returned { value: total });
            }
            let errno = match &*open {
                OpenDescription::Closed { .. }
                | OpenDescription::File { .. }
                | OpenDescription::InMemoryFile { .. }
                | OpenDescription::SyntheticFile { .. } => LINUX_EBADF,
                OpenDescription::HostFile { writable, .. } if !*writable => LINUX_EBADF,
                OpenDescription::HostFile { .. } => LINUX_EINVAL,
                OpenDescription::Directory { .. } => LINUX_EISDIR,
                // Same rule as `pwrite64`: any pipe end is ESPIPE for positional
                // I/O (oracle `pipeblockedge` line `pwritev2_pipe_espipe`).
                OpenDescription::PipeReader { .. }
                | OpenDescription::PipeWriter { .. }
                | OpenDescription::HostPipe { .. }
                | OpenDescription::EventFd { .. }
                | OpenDescription::TimerFd { .. }
                | OpenDescription::HostSocket { .. }
                | OpenDescription::SignalFd { .. }
                | OpenDescription::PerfEvent { .. }
                | OpenDescription::FsContext { .. }
                | OpenDescription::Mqueue { .. }
                | OpenDescription::BpfMap { .. }
                | OpenDescription::BpfProg { .. }
                | OpenDescription::Netlink { .. }
                | OpenDescription::Epoll { .. }
                | OpenDescription::Pidfd { .. }
                | OpenDescription::Inotify { .. }
                | OpenDescription::SyntheticDevice { .. }
                | OpenDescription::Fanotify { .. }
                | OpenDescription::InMemorySocket { .. } => LINUX_ESPIPE,
            };
            Ok(DispatchOutcome::errno(errno))

        }

        fn sendfile(this, cx, out_fd: Fd, in_fd: Fd, offset: GuestPtr, count: u64) {
            let tid = cx.tid();

            let out_fd: Fd = out_fd;
            let in_fd: Fd = in_fd;
            let offset_address = offset.0;
            let count =
                usize::try_from(count).map_err(|_| DispatchError::LengthTooLarge(count))?;
            let memory = &mut *cx.memory;
            if count == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }

            // in_fd must be READABLE — sendfile reads the source from it. An
            // O_WRONLY in_fd → EBADF (LTP sendfile03 case 4). A bad in_fd is
            // caught as EBADF by sendfile_offset below; out_fd writability is
            // enforced on the write path (sendfile03 case 2 already passes).
            if let Some(in_file) = this.open_file(in_fd.0)
                && in_file.description.common().status_flags() & LINUX_O_ACCMODE == LINUX_O_WRONLY
            {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }

            // memfd_secret cannot be a sendfile endpoint (no file read/write
            // methods) → EINVAL (memfd_secret(2)).
            if this.fd_is_secretmem(in_fd.0) || this.fd_is_secretmem(out_fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }

            let mut offset = this.sendfile_offset(in_fd.0, offset_address, memory)??;

            // Darwin-native fast path: a regular file -> socket uses macOS
            // sendfile(2) (BSD-style, in-kernel, zero-copy). It honors socket
            // backpressure by returning a partial `len` + EAGAIN, which Go's
            // netpoller drives via EPOLLOUT — so a large transfer does NOT hang
            // the way a userspace read-into-buffer-then-write does. Non-socket
            // destinations and in-memory file sources fall through to the buffer
            // path below.
            if let (Some(file_fd), Some(sock_fd)) =
                (this.regular_host_file_fd(in_fd.0), this.host_socket_fd(out_fd.0))
            {
                // SAFETY: both are live host fds owned by these guest fds. The
                // portable wrapper hides the Darwin (6-arg, in/out len) vs Linux
                // (4-arg, swapped fds) signature: returns bytes sent, or -1
                // (errno set), so `host_syscall_errno()` below still works.
                let rc = unsafe {
                    carrick_portable::sendfile_to_socket(
                        file_fd.get(),
                        sock_fd.get(),
                        offset as i64,
                        count,
                    )
                };
                let sent = rc.max(0) as usize;
                let advance_and_return = |offset: usize,
                                          sent: usize,
                                          memory: &mut dyn CurrentMmMemory|
                 -> Result<DispatchOutcome, DispatchError> {
                    let new_off = offset.saturating_add(sent);
                    if offset_address == 0 {
                        // macOS sendfile takes an explicit `offset` and does NOT
                        // advance the file's kernel offset; do it so a follow-up
                        // read/sendfile (no explicit offset) continues correctly.
                        unsafe { libc::lseek(file_fd.get(), new_off as libc::off_t, libc::SEEK_SET) };
                    } else if memory
                        .write_bytes(offset_address, &(new_off as u64).to_ne_bytes())
                        .is_err()
                    {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                    Ok(DispatchOutcome::returned_len_or_errno(sent))
                };
                match (rc as i64).host_syscall_errno() {
                    Ok(_) => return advance_and_return(offset, sent, memory),
                    Err(e) if e == LINUX_EAGAIN => {
                        if sent > 0 {
                            // Partial transfer before the socket filled: report it
                            // (Go advances and loops).
                            return advance_and_return(offset, sent, memory);
                        }
                        return Ok(if this.io_is_nonblocking(out_fd.0, 0) {
                            DispatchOutcome::errno(LINUX_EAGAIN)
                        } else {
                            DispatchOutcome::WaitOnFds {
                                fds: match WaitFds::raw_one(sock_fd.get(), libc::POLLOUT)
                                    .with_guest_slots(
                                        &this.captured_file_table(),
                                        [in_fd.0, out_fd.0],
                                    )
                                {
                                    Ok(fds) => fds,
                                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                                },
                                timeout: None,
                                sig_mask: carrick_abi::WaitSigMask::NONE,
                                completion: FdWaitCompletion::Fd {
                                    on_timeout: LINUX_EAGAIN.guest_retval(),
                                },
                            }
                        });
                    }
                    // FreeBSD sendfile(2) only supports STREAM sockets; an AF_UNIX
                    // (especially DGRAM) out_fd is rejected with EINVAL. Linux
                    // sendfile handles any socket destination, so fall through to the
                    // buffer path below (read in_fd, then write_output_fd, which
                    // honours the socket's EAGAIN/ENOBUFS backpressure) when the host
                    // sendfile rejects the destination outright with nothing sent
                    // (LTP sendfile07 sendfiles to a full non-blocking AF_UNIX fd).
                    Err(e) if e == LINUX_EINVAL && sent == 0 => {}
                    Err(e) => return Ok(DispatchOutcome::errno(e)),
                }
            }

            let bytes = this.sendfile_bytes(in_fd.0, offset, count)?;
            let outcome = this.complete_wait_fd_authority(
                this.write_output_fd(out_fd.0, &bytes, tid),
                &this.captured_file_table(),
                [in_fd.0, out_fd.0],
            );
            let DispatchOutcome::Returned { value } = outcome else {
                return Ok(outcome);
            };
            let written = usize::try_from(value).unwrap_or(0);
            offset = offset.saturating_add(written);
            if offset_address == 0 {
                if let Some(open_file) = this.open_file(in_fd.0)
                    && let Some(mut open) = open_file.description.write()
                {
                    match &mut *open {
                        OpenDescription::File {
                            offset: current, ..
                        }
                        | OpenDescription::SyntheticFile {
                            offset: current, ..
                        } => *current = offset,
                        // HostFile reads via `pread` (sendfile_bytes), which does
                        // NOT advance the kernel offset; advance it explicitly so a
                        // follow-up sendfile/read with no explicit offset continues
                        // past what we just sent. Without this, busybox `cat` —
                        // which copies a file with `sendfile(out, file, NULL, n)` in
                        // a `while (n > 0)` loop — re-sends offset 0 forever.
                        OpenDescription::HostFile { host_fd, .. } => {
                            // SAFETY: host_fd is a live regular-file fd owned by
                            // this guest fd; lseek to an absolute position is benign.
                            unsafe {
                                libc::lseek(host_fd.raw(), offset as libc::off_t, libc::SEEK_SET);
                            }
                        }
                        _ => {}
                    }
                }
            } else if memory
                .write_bytes(offset_address, &(offset as u64).to_ne_bytes())
                .is_err()
            {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }

            Ok(DispatchOutcome::Returned { value })

        }

        fn copy_file_range(this, cx, fd_in: Fd, off_in: GuestPtr, fd_out: Fd, off_out: GuestPtr, len: u64, flags: u64) {

            // Linux currently defines no copy_file_range flags. Reject unknown
            // bits before inspecting length or endpoints.
            if flags != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let tid = cx.tid();
            let in_fd: Fd = fd_in;
            let off_in_addr = off_in.0;
            let out_fd: Fd = fd_out;
            let off_out_addr = off_out.0;
            // Callers (coreutils `cat`) pass len = SSIZE_MAX and loop until EOF,
            // so cap each call to a bounded chunk rather than trying to allocate
            // a multi-exabyte buffer. A short return is legal for copy_file_range.
            let requested = usize::try_from(len).unwrap_or(usize::MAX);
            let memory = &mut *cx.memory;
            let count = requested.min(8 * 1024 * 1024);
            if count == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }

            // memfd_secret cannot be a copy_file_range endpoint (no file
            // read/write methods) → EINVAL (memfd_secret(2)).
            if this.fd_is_secretmem(in_fd.0) || this.fd_is_secretmem(out_fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }

            let in_offset = this.sendfile_offset(in_fd.0, off_in_addr, memory)??;
            // copy_file_range onto the SAME file with OVERLAPPING ranges must fail
            // EINVAL (Linux). Go's io.Copy(f, f) self-copy hits exactly this: fd_in
            // == fd_out, NULL/NULL offsets → identical (thus overlapping) ranges.
            // Without this carrick copied the bytes and returned a success count, so
            // Go's zero-copy hook recorded handled=true and skipped its generic
            // doubling fallback (TestCopyFile/CopyFileItself). Reject ONLY when the
            // fds are the same file AND the per-round ranges overlap — distinct
            // files and non-overlapping self-copies are untouched. Resolve the out
            // offset only in this branch to avoid touching the out fd on the common
            // cross-file path. Sits above the Darwin clone fast path so it can't
            // mis-handle an overlapping self-copy either.
            if this.copy_same_file(in_fd.0, out_fd.0) {
                let out_offset = this.sendfile_offset(out_fd.0, off_out_addr, memory)??;
                let in_end = in_offset.saturating_add(count);
                let out_end = out_offset.saturating_add(count);
                if in_offset < out_end && out_offset < in_end {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
            }
            #[cfg(target_os = "macos")]
            if let Some(outcome) = this.try_darwin_copyfile_range_fast_path(
                in_fd.0,
                in_offset,
                off_in_addr,
                out_fd.0,
                off_out_addr,
                count,
            )? {
                return Ok(outcome);
            }
            let bytes = this.sendfile_bytes(in_fd.0, in_offset, count)?;
            if bytes.is_empty() {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }

            // Write side. off_out == NULL → write at out_fd's current position
            // (the common case: cat to a pipe/stdout). Non-NULL → pwrite at the
            // given offset on a real host fd and advance *off_out.
            let written = if off_out_addr == 0 {
                let outcome = this.complete_wait_fd_authority(
                    this.write_output_fd(out_fd.0, &bytes, tid),
                    &this.captured_file_table(),
                    [in_fd.0, out_fd.0],
                );
                let DispatchOutcome::Returned { value } = outcome else {
                    return Ok(outcome);
                };
                usize::try_from(value).unwrap_or(0)
            } else {
                let out_off = read_u64(memory, off_out_addr)?;
                let host_fd = match this.open_file(out_fd.0).as_ref() {
                    Some(of) => match of.description.read().as_deref() {
                        Some(OpenDescription::HostFile {
                            host_fd,
                            writable: true,
                            ..
                        }) => host_fd.raw(),
                        Some(OpenDescription::HostFile { .. }) => {
                            return Ok(DispatchOutcome::errno(LINUX_EBADF));
                        }
                        _ => {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                    },
                    None => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                };
                let n = unsafe {
                    libc::pwrite(
                        host_fd,
                        bytes.as_ptr() as *const _,
                        bytes.len(),
                        out_off as libc::off_t,
                    )
                };
                let n = match n.host_syscall_errno() {
                    Ok(value) => value as usize,
                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                };
                if memory
                    .write_bytes(off_out_addr, &(out_off + n as u64).to_ne_bytes())
                    .is_err()
                {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                n
            };

            // Advance the input offset (pointer or the fd's own position).
            let new_in = in_offset.saturating_add(written);
            if off_in_addr == 0 {
                if let Some(of) = this.open_file(in_fd.0).as_ref()
                    && let Some(mut open) = of.description.write()
                {
                    match &mut *open {
                        OpenDescription::File { offset, .. }
                        | OpenDescription::SyntheticFile { offset, .. } => *offset = new_in,
                        OpenDescription::HostFile { host_fd, .. } => {
                            unsafe {
                                libc::lseek(host_fd.raw(), new_in as libc::off_t, libc::SEEK_SET)
                            };
                        }
                        _ => {}
                    }
                }
            } else if memory
                .write_bytes(off_in_addr, &(new_in as u64).to_ne_bytes())
                .is_err()
            {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }

            Ok(DispatchOutcome::returned_len_or_errno(written))

        }

        fn tee(this, cx, fd_in: Fd, fd_out: Fd, len: u64, flags: u64) {

            // tee(2) duplicates up to `len` bytes of pipe data from fd_in to
            // fd_out WITHOUT consuming the source.
            let _ = cx;
            // `from_bits` rejects exactly the historical `& !SUPPORTED` set:
            // the type's full set IS the supported set.
            let Some(splice_flags) = LinuxSpliceFlags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };

            // Check if both ends are HostPipe
            if let Some((in_fd, in_pipe)) = this.host_pipe_end(fd_in.0, true) {
                let Some((out_fd, out_pipe)) = this.host_pipe_end(fd_out.0, false) else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                if in_pipe != 0 && in_pipe == out_pipe {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                let count = usize::try_from(len).map_err(|_| DispatchError::LengthTooLarge(len))?;
                if count == 0 {
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                return this.host_tee(in_fd, in_pipe, out_fd, count, splice_flags);
            }


            // Check if both ends are in-memory pipes
            if let Some((in_pipe, in_status_flags)) = this.pipe_reader(fd_in.0) {
                let Some((out_pipe, out_status_flags)) = this.pipe_writer(fd_out.0) else {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                };
                if Arc::ptr_eq(&in_pipe, &out_pipe) || in_pipe.pipe_id() == out_pipe.pipe_id() {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                let count = usize::try_from(len).map_err(|_| DispatchError::LengthTooLarge(len))?;
                if count == 0 {
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                let outcome = this.in_memory_tee(
                    fd_in.0,
                    &in_pipe,
                    in_status_flags,
                    fd_out.0,
                    &out_pipe,
                    out_status_flags,
                    count,
                    splice_flags,
                )?;
                return Ok(this.raise_sigpipe_on_epipe(cx, outcome));
            }

            // Non-pipe fds, wrong pipe ends, or mixed pairs are rejected with EINVAL.
            Ok(DispatchOutcome::errno(LINUX_EINVAL))

        }

        fn splice(this, cx, fd_in: Fd, off_in: GuestPtr, fd_out: Fd, off_out: GuestPtr, len: u64, flags: u64) {

            let tid = cx.tid();
            let in_fd: Fd = fd_in;
            let off_in_address = off_in.0;
            let out_fd: Fd = fd_out;
            let off_out_address = off_out.0;
            let count =
                usize::try_from(len).map_err(|_| DispatchError::LengthTooLarge(len))?;
            let memory = &mut *cx.memory;
            // `from_bits` rejects exactly the historical `& !SUPPORTED` set:
            // the type's full set IS the supported set.
            let Some(splice_flags) = LinuxSpliceFlags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            // A closed/negative fd_in is EBADF before any routing — the
            // file→pipe fallthrough otherwise read an empty byte stream from
            // the dead fd and "spliced" 0 bytes (LTP splice03 badfd case).
            if in_fd.0 < 0 || (in_fd.0 > 2 && this.open_file(in_fd.0).is_none()) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // splice(2) reads from fd_in, so a source not open for reading — an
            // O_PATH descriptor, a write-only file, or the write end of a pipe —
            // is EBADF, decided ahead of the pipe-vs-pipe routing (splice03's
            // write-only fd_in, splice07's O_PATH / pipe-write-end sources).
            if this.splice_source_not_readable(in_fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // fd_out must be open for WRITING, and Linux decides that before
            // the one-end-must-be-a-pipe rule: the oracle's splice07 matrix
            // answers EBADF for every non-writable destination (O_PATH file,
            // directory, /dev/zero, /proc/self/maps, a pipe READ end, an
            // inotify fd) and EINVAL only for writable-but-unspliceable ones
            // (eventfd/signalfd/timerfd/epoll/pidfd/memfd/sockets/regular
            // file). carrick reached the pipe rule first and answered EINVAL
            // for the whole tail.
            if let Some(errno) = this.splice_output_errno(out_fd.0)
                && errno == LINUX_EBADF
            {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // splice(2) requires at least ONE end to be a genuine pipe; a
            // char-device HostPipe (e.g. /dev/zero) does NOT count. When neither
            // fd is a genuine pipe the call is EINVAL, resolved BEFORE any read so
            // a char-device or socket source is never drained (splice07
            // /dev/zero->file & socket->file/socket, splice03 file->file).
            if !this.is_genuine_pipe(in_fd.0) && !this.is_genuine_pipe(out_fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // An `io_uring` ring is an anonymous inode with no splice file
            // operations, so Linux answers EINVAL for either end. carrick backs
            // the ring fd with a plain `SyntheticFile`, which
            // `splice_source_not_readable` accepts: the call fell through to the
            // file->pipe path, `sendfile_bytes` read the description's empty
            // `contents`, and splice reported a successful 0-byte transfer
            // (splice07 "splice() on io uring -> pipe write end succeeded").
            if this.io_uring_description(in_fd.0).is_some()
                || this.io_uring_description(out_fd.0).is_some()
            {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // memfd_secret cannot be a splice endpoint (secretmem has no
            // splice_read/splice_write): EINVAL even when the other end IS a
            // genuine pipe. Ordered after the EBADF/no-pipe checks so the
            // splice07 "memfd secret" rows keep Linux's error precedence.
            if this.fd_is_secretmem(in_fd.0) || this.fd_is_secretmem(out_fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if count == 0 {
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            // A guest that did not ask for SPLICE_F_NONBLOCK still gets
            // non-blocking behaviour when the DESTINATION fd is O_NONBLOCK,
            // exactly like write(2) on the same fd.
            let out_nonblocking = splice_flags.contains(LinuxSpliceFlags::NONBLOCK)
                || this.fd_is_nonblocking(out_fd.0);
            let complete_wait = |outcome| {
                this.complete_wait_fd_authority(
                    outcome,
                    &this.captured_file_table(),
                    [in_fd.0, out_fd.0],
                )
            };
            // Never hand the destination more than it can take in one go. The
            // write path returns a SHORT count rather than parking (splice(2)'s
            // own contract), and bounding the SOURCE read by the same figure
            // keeps the undelivered tail out of carrick's hands entirely.
            let count = match this.splice_pipe_write_room(out_fd.0) {
                Some(0) => {
                    return Ok(complete_wait(
                        this.splice_output_would_block(out_fd.0, out_nonblocking),
                    ));
                }
                Some(room) => count.min(room),
                None => count,
            };

            if let Some((pipe, status_flags)) = this.pipe_reader(in_fd.0) {
                // A pipe source has no seekable offset → a non-NULL off_in is
                // ESPIPE (splice(2)). off_out IS allowed (honored below) when
                // fd_out is a regular file (test_os.test_splice_offset_out).
                if off_in_address != 0 {
                    return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
                }
                if let Some(errno) = this.splice_output_errno(out_fd.0) {
                    return Ok(DispatchOutcome::errno(errno));
                }
                let bytes = match take_pipe_bytes(&pipe, count) {
                    PipeDrain::Bytes(bytes) => bytes,
                    PipeDrain::Eof => return Ok(DispatchOutcome::Returned { value: 0 }),
                    PipeDrain::WouldBlock => {
                        let in_nonblocking = splice_flags.contains(LinuxSpliceFlags::NONBLOCK)
                            || status_flags & LINUX_O_NONBLOCK != 0;
                        if in_nonblocking {
                            return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                        }
                        return Ok(complete_wait(wait_for_pipe_readable(
                            &pipe,
                            WaitFdAuthority::logical(
                                this.captured_slot_authority(in_fd.0).ok_or(LINUX_EBADF)?,
                            ),
                        )));
                    }
                };
                let outcome = this.splice_write_out(out_fd.0, off_out_address, &bytes, cx.memory, tid, out_nonblocking);
                let DispatchOutcome::Returned { value } = outcome else {
                    Self::restore_pipe_bytes(&pipe, &bytes);
                    return Ok(complete_wait(outcome));
                };
                let written = usize::try_from(value).unwrap_or(0).min(bytes.len());
                if written < bytes.len() {
                    Self::restore_pipe_bytes(&pipe, &bytes[written..]);
                }
                return Ok(DispatchOutcome::returned_len_or_errno(written));
            }

            // Splice OUT of a real host pipe's read end (the fork-safe pipe model;
            // `pipe2`/`fcntl` now hand back HostPipe descriptions, so splice must
            // recognise them just like the legacy in-memory PipeReader above).
            if let Some(host_fd) = this.host_pipe_read_fd(in_fd.0) {
                // A pipe source has no seekable offset → a non-NULL off_in is
                // ESPIPE (splice(2)). off_out IS allowed (honored below) when
                // fd_out is a regular file (test_os.test_splice_offset_out).
                if off_in_address != 0 {
                    return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
                }
                if let Some(errno) = this.splice_output_errno(out_fd.0) {
                    return Ok(DispatchOutcome::errno(errno));
                }
                // A source read that finds nothing waits (or reports EAGAIN)
                // like every other blocking-mode host read; the guest's own
                // O_NONBLOCK on fd_in counts alongside SPLICE_F_NONBLOCK.
                let in_nonblocking = splice_flags.contains(LinuxSpliceFlags::NONBLOCK)
                    || this.fd_is_nonblocking(in_fd.0);
                let host_fd_owner = this.open_file(in_fd.0).and_then(|file| {
                    let open = file.description.read()?;
                    match &*open {
                        OpenDescription::HostPipe { host_fd, .. } => Some(host_fd.clone()),
                        _ => None,
                    }
                });
                let buf = match this.take_splice_pipe_bytes(
                    in_fd.0,
                    host_fd,
                    host_fd_owner,
                    count,
                    in_nonblocking,
                )? {
                    Ok(buf) => buf,
                    Err(outcome) => return Ok(complete_wait(outcome)),
                };
                if buf.is_empty() {
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                let outcome = this.splice_write_out(out_fd.0, off_out_address, &buf, cx.memory, tid, out_nonblocking);
                let DispatchOutcome::Returned { value } = outcome else {
                    this.restore_splice_pipe_bytes(in_fd.0, &buf);
                    return Ok(complete_wait(outcome));
                };
                let written = if value <= 0 {
                    0
                } else {
                    usize::try_from(value).unwrap_or(buf.len()).min(buf.len())
                };
                if written < buf.len() {
                    this.restore_splice_pipe_bytes(in_fd.0, &buf[written..]);
                }
                return Ok(DispatchOutcome::returned_len_or_errno(written));
            }

            // Splice OUT of a host socket (socket -> pipe, and socket -> socket).
            // This is the path Go's `io.Copy(pipe, conn)` takes; without it a
            // socket source fell through to the sendfile path below, which treats
            // `in_fd` as a regular file and fails. The host socket fd is
            // non-blocking, so an empty socket yields EAGAIN — which is exactly
            // what a non-blocking guest (the Go netpoller) expects; a true
            // blocking-wait for an empty socket is the same tracked follow-up as
            // the host-pipe branch above.
            if let Some(host_fd) = this.host_socket_fd(in_fd.0) {
                // A pipe/socket source has no seekable offset → off_in must be
                // NULL. off_out IS allowed (honored below) when fd_out is a
                // regular file (test_os.test_splice_offset_out).
                if off_in_address != 0 {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                if let Some(errno) = this.splice_output_errno(out_fd.0) {
                    return Ok(DispatchOutcome::errno(errno));
                }
                if off_out_address == 0
                    && splice_flags.contains(LinuxSpliceFlags::NONBLOCK)
                    && let Some((pipe_read_fd, room)) =
                        this.host_pipe_splice_staging_target(out_fd.0)
                {
                    if room == 0 {
                        return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                    }
                    let want = count.min(room).min(1 << 20);
                    let mut buf = vec![0u8; want];
                    let n = unsafe {
                        // BLOCKING-IO-OK: MSG_DONTWAIT is passed on this recv.
                        libc::recv(
                            host_fd.get(),
                            buf.as_mut_ptr() as *mut _,
                            want,
                            libc::MSG_DONTWAIT,
                        )
                    };
                    let n = match n.host_syscall_errno() {
                        Ok(v) => v,
                        // A socket that STRUCTURALLY cannot serve as a splice
                        // source — unconnected (ENOTCONN) or a family without a
                        // splice_read op (EOPNOTSUPP) — is EINVAL, matching
                        // Linux's structural check (splice07). Every OTHER recv
                        // error is a genuine transport/nonblocking condition —
                        // EAGAIN (netpoller), ECONNRESET, EPIPE, … — which Linux
                        // propagates verbatim, so surface the real errno.
                        Err(e) if e == LINUX_ENOTCONN || e == LINUX_EOPNOTSUPP => {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                        Err(e) => return Ok(DispatchOutcome::errno(e)),
                    };
                    if n == 0 {
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    buf.truncate(n as usize);
                    let consumed = buf.len();
                    this.stage_splice_pipe_bytes_owned(pipe_read_fd, buf);
                    return Ok(DispatchOutcome::returned_len_or_errno(consumed));
                }
                // PEEK first, then consume EXACTLY what the destination accepts.
                // The destination is typically Go's O_NONBLOCK splice pipe (64 KiB
                // on macOS — F_SETPIPE_SZ is bookkeeping-only here). A plain
                // consuming recv() pulls up to `count` (~RCVBUF) off the socket,
                // but splice_write_out does a single non-blocking write to the
                // pipe; when recv > the pipe's free space the un-written tail —
                // ALREADY removed from the socket — is silently DROPPED and
                // unrecoverable (TestLargeCopyViaNetwork: server saw ~1.9MB of a
                // 10MB sendfile). MSG_PEEK leaves the bytes in the socket; we
                // remove only the prefix that actually reached the destination, so
                // the guest's Go splice loop just makes another pass for the rest.
                let want = count.min(1 << 20);
                let mut buf = vec![0u8; want];
                // Non-blocking peek (MSG_PEEK | MSG_DONTWAIT below): never blocks
                // under the dispatcher lock; EAGAIN is surfaced, not awaited here.
                let n = unsafe {
                    libc::recv(
                        host_fd.get(),
                        buf.as_mut_ptr() as *mut _,
                        want,
                        libc::MSG_PEEK | libc::MSG_DONTWAIT,
                    )
                };
                let n = match n.host_syscall_errno() {
                    Ok(v) => v,
                    // A socket that STRUCTURALLY cannot serve as a splice source —
                    // unconnected (ENOTCONN) or a family without a splice_read op
                    // (EOPNOTSUPP) — is EINVAL, matching Linux's structural check
                    // (splice07 socket-source cases). Every OTHER recv error is a
                    // genuine transport/nonblocking condition — EAGAIN (Go
                    // netpoller), ECONNRESET, EPIPE, … — which Linux propagates
                    // verbatim, so surface the real errno.
                    Err(e) if e == LINUX_ENOTCONN || e == LINUX_EOPNOTSUPP => {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    }
                    Err(e) => return Ok(DispatchOutcome::errno(e)),
                };
                if n == 0 {
                    // EOF: the writer closed; splice reports 0 (Go stops the loop).
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                buf.truncate(n as usize);
                let outcome = this.splice_write_out(out_fd.0, off_out_address, &buf, cx.memory, tid, out_nonblocking);
                let DispatchOutcome::Returned { value } = outcome else {
                    // EAGAIN / WaitOnFds / Errno on the destination — propagate
                    // WITHOUT consuming any socket bytes (the peek left them).
                    return Ok(complete_wait(outcome));
                };
                let written = usize::try_from(value).unwrap_or(0);
                // Now drain EXACTLY `written` bytes from the socket — they are safely
                // in the destination. recv on a stream socket may return short, so
                // loop until `written` are consumed (a single recv could leave a
                // remainder that the next PEEK re-delivers → duplicated bytes).
                let mut consumed = 0usize;
                while consumed < written {
                    // Non-blocking drain (MSG_DONTWAIT below): the bytes are known
                    // to be present (we just peeked them), so this never blocks
                    // under the dispatcher lock.
                    let cn = unsafe {
                        libc::recv(
                            host_fd.get(),
                            buf.as_mut_ptr().add(consumed) as *mut _,
                            written - consumed,
                            libc::MSG_DONTWAIT,
                        )
                    };
                    match cn.host_syscall_errno() {
                        Ok(c) if c > 0 => consumed += c as usize,
                        // 0 (peer gone) or EAGAIN: the peeked bytes should be
                        // present, but never spin — stop draining to avoid a hang.
                        _ => break,
                    }
                }
                // `consumed == written` in every normal case (the peeked bytes are
                // present). Report the bytes moved into the destination; the drain
                // above keeps the socket position in lockstep so nothing is lost.
                return Ok(DispatchOutcome::returned_len_or_errno(written));
            }

            match this.fd_is_pipe_writer(out_fd.0) {
                Ok(true) => {}
                // Neither side is a pipe → EINVAL (splice(2)); the pipe-source
                // shapes were all handled above.
                Ok(false) => {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
            }
            // fd_out IS a pipe here, so a non-NULL off_out is ESPIPE.
            if off_out_address != 0 {
                return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
            }

            if let Some(open_file) = this.open_file(in_fd.0)
                && let Some(open) = open_file.description.read()
            {
                if let OpenDescription::SyntheticDevice { kind, .. } = &*open {
                    let kind = *kind;
                    drop(open);

                    if off_in_address != 0 {
                        // Character devices have no seek position, so off_in is not
                        // used or updated, but guest pointer validity is checked.
                        if read_u64(memory, off_in_address).is_err() {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                    }

                    // Bound production by a fixed chunk ceiling (global pipe-room
                    // bounds and full-pipe wait policy already applied above).
                    const SYNTHETIC_SPLICE_CHUNK: usize = 1 << 16; // 64 KiB
                    let count = count.min(SYNTHETIC_SPLICE_CHUNK);

                    let bytes = match kind {
                        crate::vfs::SyntheticDeviceKind::Null => Vec::new(),
                        crate::vfs::SyntheticDeviceKind::Zero
                        | crate::vfs::SyntheticDeviceKind::Full => vec![0u8; count],
                        crate::vfs::SyntheticDeviceKind::Random
                        | crate::vfs::SyntheticDeviceKind::Urandom => {
                            let mut buf = vec![0u8; count];
                            unsafe {
                                libc::arc4random_buf(buf.as_mut_ptr().cast(), count);
                            }
                            buf
                        }
                    };

                    if bytes.is_empty() {
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }

                    let outcome = this.write_output_fd_partial(out_fd.0, &bytes, tid);
                    let DispatchOutcome::Returned { value } = outcome else {
                        return Ok(complete_wait(outcome));
                    };
                    let written = usize::try_from(value).unwrap_or(0).min(bytes.len());
                    return Ok(DispatchOutcome::returned_len_or_errno(written));
                }
            }

            // splice(2) into a pipe moves at most what the pipe can hold and
            // returns a SHORT count; the caller loops. `write_output_fd` below
            // implements write(2) semantics instead — deliver every byte, parking
            // on POLLOUT when the pipe fills — so handing it more than the
            // destination's room deadlocks whenever the only reader is the same
            // single-threaded guest. coreutils `cat` drains its bounce pipe only
            // AFTER this splice returns, so `cat` of any file larger than one
            // pipe-full parked forever. Bound the read window by the room the
            // write path itself accounts for (`host_pipe_write_room`).
            let count = match this.splice_pipe_write_room(out_fd.0) {
                Some(room) if room > 0 => count.min(room),
                // Full pipe (or not a plain one-way host pipe): leave `count`
                // alone. A genuinely full pipe is exactly the case blocking
                // splice(2) is specified to wait out, and the write path's own
                // staging handles it.
                _ => count,
            };
            let mut offset = this.sendfile_offset(in_fd.0, off_in_address, memory)??;
            let bytes = this.sendfile_bytes(in_fd.0, offset, count)?;
            let outcome = match this.write_output_fd_partial(out_fd.0, &bytes, tid) {
                // Nothing moved: the destination pipe is full. SPLICE_F_NONBLOCK
                // reports EAGAIN; a blocking splice(2) must wait for room. Waiting
                // is safe in exactly this case — a full pipe can only be drained by
                // a DIFFERENT thread, so the write(2)-semantics path cannot
                // self-deadlock the way it does on a partially-filled pipe.
                DispatchOutcome::Errno { errno } if errno == LINUX_EAGAIN => {
                    if splice_flags.contains(LinuxSpliceFlags::NONBLOCK) {
                        return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                    }
                    this.write_output_fd(out_fd.0, &bytes, tid)
                }
                other => other,
            };
            let DispatchOutcome::Returned { value } = outcome else {
                return Ok(complete_wait(outcome));
            };
            let written = usize::try_from(value).unwrap_or(0);
            offset = offset.saturating_add(written);
            if off_in_address == 0 {
                if let Some(open_file) = this.open_file(in_fd.0)
                    && let Some(mut open) = open_file.description.write()
                {
                    match &mut *open {
                        OpenDescription::File {
                            offset: current, ..
                        }
                        | OpenDescription::SyntheticFile {
                            offset: current, ..
                        } => *current = offset,
                        // Same contract as `sendfile`: HostFile reads via `pread`
                        // (sendfile_bytes), which does NOT advance the kernel
                        // offset, and `sendfile_offset` reads that offset back
                        // with `lseek(SEEK_CUR)`. Advance it explicitly or the
                        // next iteration re-reads the same window. Without this,
                        // coreutils `cat` — which drains a file through a pipe
                        // with `splice(file, NULL, pipe, NULL, n)` in a loop —
                        // re-sends offset 0 forever and never reaches EOF.
                        OpenDescription::HostFile { host_fd, .. } => {
                            // SAFETY: host_fd is a live regular-file fd owned by
                            // this guest fd; lseek to an absolute position is benign.
                            unsafe {
                                libc::lseek(host_fd.raw(), offset as libc::off_t, libc::SEEK_SET);
                            }
                        }
                        _ => {}
                    }
                }
            } else if memory
                .write_bytes(off_in_address, &(offset as u64).to_ne_bytes())
                .is_err()
            {
                return Ok(DispatchOutcome::errno(LINUX_EFAULT));
            }

            Ok(DispatchOutcome::Returned { value })

        }

        fn vmsplice(this, cx, fd: Fd, iov: GuestPtr, nr_segs: u64, flags: u64) {

            // vmsplice(2): fd must be a pipe; the pipe END selects the direction —
            // the WRITE end gathers user pages into the pipe, the READ end extracts
            // pipe bytes into user pages. SPLICE_F_GIFT/MOVE/MORE are advisory hints
            // for our copy-based path (no zero-copy page stealing); SPLICE_F_NONBLOCK
            // forces EAGAIN rather than blocking. A valid non-pipe fd is EINVAL; a
            // bad fd is EBADF.
            // `from_bits` rejects exactly the historical `& !SUPPORTED` set:
            // the type's full set IS the supported set.
            let Some(splice_flags) = LinuxSpliceFlags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            let tid = cx.tid();
            let nr =
                usize::try_from(nr_segs).map_err(|_| DispatchError::LengthTooLarge(nr_segs))?;
            let memory = &mut *cx.memory;
            let iovecs = read_iovecs(memory, iov.0, nr)?;
            // SPLICE_F_NONBLOCK *or* an O_NONBLOCK pipe: vmsplice(2) blocks
            // only when both say it may.
            let nonblocking = splice_flags.contains(LinuxSpliceFlags::NONBLOCK)
                || this.fd_is_nonblocking(fd.0);

            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };

            enum VmDir {
                Write,
                /// Borrowed [`HostFd`] view + the owned handle keeping it live
                /// across the wait (mirrors the blocking-read plumbing).
                ReadHost(HostFd, Option<HostFdRef>),
                ReadMem,
            }
            let dir = {
                let Some(open) = open_file.description.read() else {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                };
                match &*open {
                    OpenDescription::HostPipe {
                        host_fd,
                        is_read_end,
                        ..
                    } => {
                        if *is_read_end {
                            VmDir::ReadHost(host_fd.view(), Some(host_fd.clone()))
                        } else {
                            VmDir::Write
                        }
                    }
                    OpenDescription::PipeWriter { .. } => VmDir::Write,
                    OpenDescription::PipeReader { .. } => VmDir::ReadMem,
                    // vmsplice(2): a valid fd that does not refer to a pipe is
                    // EBADF ("fd either not valid, or doesn't refer to a
                    // pipe"), NOT EINVAL — LTP vmsplice02's file-fd case.
                    _ => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                }
            };

            match dir {
                VmDir::Write => {
                    // vmsplice(2) into a pipe moves AT MOST what the pipe can
                    // hold and reports a SHORT count; the caller loops. Bound
                    // the gather by the destination's room so the transfer is
                    // a single non-blocking write. Without the bound, LTP
                    // `vmsplice01` handed 128 KiB to a 64 KiB pipe, the
                    // full-delivery write path parked on POLLOUT for the
                    // remainder, and the only reader could not run until this
                    // call returned — a hang until the 30 s test timeout.
                    let room = this.splice_pipe_write_room(fd.0);
                    if room == Some(0) {
                        return Ok(this.splice_output_would_block(fd.0, nonblocking));
                    }
                    let (bytes, faulted) = match gather_bounded_iovec_bytes(memory, &iovecs) {
                        Ok(Some(gathered)) => (gathered.bytes, gathered.faulted),
                        Ok(None) => return Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    };
                    if bytes.is_empty() {
                        // Same partial-transfer rule as `writev`: EFAULT only
                        // when the emptiness is a fault, not a zero-length list.
                        return if faulted {
                            Ok(DispatchOutcome::errno(LINUX_EFAULT))
                        } else {
                            Ok(DispatchOutcome::Returned { value: 0 })
                        };
                    }
                    let bytes = &bytes[..room.map_or(bytes.len(), |room| bytes.len().min(room))];
                    Ok(this.splice_write_out(fd.0, 0, bytes, memory, tid, nonblocking))
                }
                VmDir::ReadHost(hfd, owner) => Ok(Self::read_host_pipe_iovecs(
                    memory,
                    &iovecs,
                    hfd.get(),
                    owner,
                    nonblocking,
                    WaitFdAuthority::logical(
                        this.captured_slot_authority(fd.0).ok_or(LINUX_EBADF)?,
                    ),
                )),
                VmDir::ReadMem => {
                    let Some((pipe, status_flags)) = this.pipe_reader(fd.0) else {
                        return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                    };
                    let want: usize = iovecs
                        .iter()
                        .map(|v| usize::try_from(v.iov_len).unwrap_or(0))
                        .sum();
                    if want == 0 {
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    let bytes = match take_pipe_bytes(&pipe, want) {
                        PipeDrain::Bytes(bytes) => bytes,
                        PipeDrain::Eof => return Ok(DispatchOutcome::Returned { value: 0 }),
                        PipeDrain::WouldBlock => {
                            if nonblocking || status_flags & LINUX_O_NONBLOCK != 0 {
                                return Ok(DispatchOutcome::errno(LINUX_EAGAIN));
                            }
                            let wait = wait_for_pipe_readable(
                                &pipe,
                                WaitFdAuthority::logical(
                                    this.captured_slot_authority(fd.0).ok_or(LINUX_EBADF)?,
                                ),
                            );
                            return Ok(this.complete_wait_fd_authority(
                                wait,
                                &this.captured_file_table(),
                                [fd.0],
                            ));
                        }
                    };
                    let mut off = 0usize;
                    for v in &iovecs {
                        if off >= bytes.len() {
                            break;
                        }
                        let len =
                            usize::try_from(v.iov_len).unwrap_or(0).min(bytes.len() - off);
                        if len == 0 {
                            continue;
                        }
                        if memory
                            .write_bytes(v.iov_base, &bytes[off..off + len])
                            .is_err()
                        {
                            return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                        }
                        off += len;
                    }
                    Ok(DispatchOutcome::returned_len_or_errno(off))
                }
            }
        }

        fn sync(this, cx) {

            unsafe {
                libc::sync();
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn syncfs(this, cx, fd: Fd) {

            let fd: Fd = fd;
            if !this.fd_is_valid(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            let host_fd = this.host_file_fd_for_flush(fd.0)?;
            if let Some(host_fd) = host_fd
                && let Err(errno) = flush_host_fd(host_fd) {
                    return Ok(DispatchOutcome::errno(errno));
                }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn sys_setxattr_path(this, cx, path: GuestPtr, name: GuestPtr, value: GuestPtr, size: u64, flags: u64) {

            this.setxattr(cx.memory, XattrTarget::Path { path, follow: true }, name, value, size, flags)

        }

        fn sys_lsetxattr_path(this, cx, path: GuestPtr, name: GuestPtr, value: GuestPtr, size: u64, flags: u64) {

            this.setxattr(cx.memory, XattrTarget::Path { path, follow: false }, name, value, size, flags)

        }

        fn sys_setxattr_fd(this, cx, fd: Fd, name: GuestPtr, value: GuestPtr, size: u64, flags: u64) {

            // An O_PATH descriptor is not open for I/O — fd-based xattr ops on it
            // are EBADF (LTP open13 issues fgetxattr on an O_PATH fd).
            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            this.setxattr(cx.memory, XattrTarget::Fd(fd), name, value, size, flags)

        }

        fn sys_getxattr_path(this, cx, path: GuestPtr, name: GuestPtr, value: GuestPtr, size: u64) {

            this.getxattr(cx.memory, XattrTarget::Path { path, follow: true }, name, value, size)

        }

        fn sys_lgetxattr_path(this, cx, path: GuestPtr, name: GuestPtr, value: GuestPtr, size: u64) {

            this.getxattr(cx.memory, XattrTarget::Path { path, follow: false }, name, value, size)

        }

        fn sys_getxattr_fd(this, cx, fd: Fd, name: GuestPtr, value: GuestPtr, size: u64) {

            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            this.getxattr(cx.memory, XattrTarget::Fd(fd), name, value, size)

        }

        fn sys_listxattr_path(this, cx, path: GuestPtr, list: GuestPtr, size: u64) {

            this.listxattr(cx.memory, XattrTarget::Path { path, follow: true }, list, size)

        }

        fn sys_llistxattr_path(this, cx, path: GuestPtr, list: GuestPtr, size: u64) {

            this.listxattr(cx.memory, XattrTarget::Path { path, follow: false }, list, size)

        }

        fn sys_listxattr_fd(this, cx, fd: Fd, list: GuestPtr, size: u64) {

            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            this.listxattr(cx.memory, XattrTarget::Fd(fd), list, size)

        }

        fn sys_removexattr_path(this, cx, path: GuestPtr, name: GuestPtr) {

            this.removexattr(cx.memory, XattrTarget::Path { path, follow: true }, name)

        }

        fn sys_lremovexattr_path(this, cx, path: GuestPtr, name: GuestPtr) {

            this.removexattr(cx.memory, XattrTarget::Path { path, follow: false }, name)

        }

        fn sys_removexattr_fd(this, cx, fd: Fd, name: GuestPtr) {

            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            this.removexattr(cx.memory, XattrTarget::Fd(fd), name)

        }

        fn sys_truncate(this, cx, path: GuestPtr, length: u64) {

            this.truncate(cx.kernel, path, length, &*cx.memory)

        }

        fn fsync(this, cx, fd: Fd) {

            let fd: Fd = fd;
            match this.host_file_fd_for_flush(fd.0) {
                Ok(Some(host_fd)) => {
                    if let Err(errno) = flush_host_fd(host_fd) {
                        return Ok(DispatchOutcome::errno(errno));
                    }
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                // Non-HostFile: a pipe/socket/char device has no ->fsync op
                // (EINVAL); a directory / synthetic / in-memory file is a no-op.
                Ok(None) if this.fd_lacks_fsync(fd.0) => Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                Ok(None) => Ok(DispatchOutcome::Returned { value: 0 }),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }

        }

        /// `sync_file_range(fd, offset, nbytes, flags)` (advisory range flush).
        /// macOS has no equivalent, so it's a validating best-effort flush.
        /// Validation order matches Linux (LTP sync_file_range01): unknown
        /// flags / negative offset / negative nbytes (or offset+nbytes
        /// overflow) → EINVAL; bad fd → EBADF; a pipe/socket/anon fd (no page
        /// cache range) → ESPIPE; a regular file → best-effort fsync, return 0.
        fn sync_file_range(this, cx, fd: Fd, offset: u64, nbytes: u64, flags: u64) {
            let fd: Fd = fd;
            // SYNC_FILE_RANGE_WAIT_BEFORE(1) | WRITE(2) | WAIT_AFTER(4).
            const VALID_FLAGS: u64 = 0x1 | 0x2 | 0x4;
            if flags & !VALID_FLAGS != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let offset_i = offset as i64;
            let nbytes_i = nbytes as i64;
            if offset_i < 0 || nbytes_i < 0 || offset_i.checked_add(nbytes_i).is_none() {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            // A character device/pipe/socket/eventfd/timerfd/epoll/pidfd/
            // inotify/signalfd/netlink fd has no page-cache range to sync →
            // ESPIPE.
            let is_special = matches!(
                open_file.description.read().as_deref(),
                Some(
                    OpenDescription::SyntheticDevice { .. }
                        | OpenDescription::HostPipe { .. }
                        | OpenDescription::HostSocket { .. }
                        | OpenDescription::PipeReader { .. }
                        | OpenDescription::PipeWriter { .. }
                        | OpenDescription::EventFd { .. }
                        | OpenDescription::TimerFd { .. }
                        | OpenDescription::Epoll { .. }
                        | OpenDescription::Pidfd { .. }
                        | OpenDescription::Inotify { .. }
                        | OpenDescription::Fanotify { .. }
                        | OpenDescription::SignalFd { .. }
                        | OpenDescription::FsContext { .. }
                        | OpenDescription::Mqueue { .. }
                        | OpenDescription::BpfMap { .. }
                        | OpenDescription::BpfProg { .. }
                        | OpenDescription::Netlink { .. }
                )
            );
            if is_special {
                return Ok(DispatchOutcome::errno(LINUX_ESPIPE));
            }
            // Regular / synthetic / in-memory file: best-effort flush a real
            // host fd; otherwise a no-op (the range-cache effect isn't observable).
            if let Ok(Some(host_fd)) = this.host_file_fd_for_flush(fd.0) {
                let _ = flush_host_fd(host_fd);
            }
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        /// `cachestat(fd, cstat_range, cstat, flags)`: page-cache stats for a
        /// file range. macOS exposes no per-page cache map, so carrick reports
        /// every in-range, in-file page as cached (nr_cache) and nothing
        /// evicted/dirty/in-writeback — which for a populated file matches
        /// Linux's observable result and the LTP cachestat02 invariant
        /// `nr_cache + nr_evicted == num_pages`. flags!=0 → EINVAL; bad/
        /// non-cache-backed fd → EBADF; bad pointers → EFAULT. Was ENOSYS.
        fn cachestat(this, cx, fd: Fd, cstat_range: GuestPtr, cstat: GuestPtr, flags: u64) {
            let fd: Fd = fd;
            if flags != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let Some(open_file) = this.open_file(fd.0) else {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            };
            let file_size: u64 = {
                let Some(open) = open_file.description.read() else {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                };
                match &*open {
                    OpenDescription::HostFile { host_fd, .. } => {
                        let mut st: libc::stat = unsafe { core::mem::zeroed() };
                        if unsafe { libc::fstat(host_fd.raw(), &mut st) } != 0 {
                            return Ok(DispatchOutcome::errno(LINUX_EBADF));
                        }
                        st.st_size.max(0) as u64
                    }
                    OpenDescription::File { contents, .. } => match contents.len() {
                        Ok(len) => len,
                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                    },
                    OpenDescription::SyntheticFile { contents, .. } => contents.len() as u64,
                    // cachestat needs a page-cache-backed fd (regular file /
                    // shmem); anything else has no cache → EBADF.
                    _ => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                }
            };
            let memory = &mut *cx.memory;
            let range = memory.read_bytes(cstat_range.0, 16)?;
            let off = u64::from_le_bytes(range[0..8].try_into().unwrap_or([0; 8]));
            let len = u64::from_le_bytes(range[8..16].try_into().unwrap_or([0; 8]));
            let page = crate::linux_abi::LINUX_PAGE_SIZE;
            let end = off.saturating_add(len).min(file_size);
            let nr_cache = if off >= end {
                0u64
            } else {
                end.div_ceil(page) - off / page
            };
            // struct cachestat: nr_cache, nr_dirty, nr_writeback, nr_evicted,
            // nr_recently_evicted (5 × u64). Only nr_cache is non-zero.
            let mut cs = [0u8; 40];
            cs[0..8].copy_from_slice(&nr_cache.to_le_bytes());
            memory.write_bytes(cstat.0, &cs)?;
            Ok(DispatchOutcome::Returned { value: 0 })
        }

        fn fdatasync(this, cx, fd: Fd) {

            let fd: Fd = fd;
            match this.host_file_fd_for_flush(fd.0) {
                Ok(Some(host_fd)) => {
                    if let Err(errno) = flush_host_fd(host_fd) {
                        return Ok(DispatchOutcome::errno(errno));
                    }
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                // fdatasync02: /dev/null (a char device) → EINVAL; regular files
                // flush, directories / synthetic files no-op.
                Ok(None) if this.fd_lacks_fsync(fd.0) => Ok(DispatchOutcome::errno(LINUX_EINVAL)),
                Ok(None) => Ok(DispatchOutcome::Returned { value: 0 }),
                Err(errno) => Ok(DispatchOutcome::errno(errno)),
            }

        }

        fn write(this, cx, fd: Fd, buf: GuestPtr, count: u64) {

            let fd = fd.0;
            // An O_PATH descriptor is not open for I/O (open13 → EBADF).
            if this.fd_is_o_path(fd) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            if this.io_uring_description(fd).is_some() {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // memfd_secret: no file write method → EINVAL (memfdsecret probe).
            if this.fd_is_secretmem(fd) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if this.fd_is_controlling_tty(cx.kernel, fd)
                && cx.kernel.kernel().tty_caller_is_background(cx.kernel)
            {
                let host_fd_opt = match this.pty_info(fd) {
                    Some((_, host_fd)) => Some(host_fd),
                    None if is_stdio_fd(fd) && !this.stdio_is_closed(fd) => Some(fd),
                    _ => None,
                };
                let tostop = if let Some(hfd) = host_fd_opt {
                    let mut termios: libc::termios = unsafe { std::mem::zeroed() };
                    let rc = unsafe { libc::tcgetattr(hfd, &mut termios) };
                    rc == 0 && (termios.c_lflag & libc::TOSTOP) != 0
                } else {
                    false
                };
                if tostop {
                    let tid = Self::ctx_tid(cx);
                    let ign_ttou = this.signal_is_ignored(cx.kernel, crate::linux_abi::LINUX_SIGTTOU);
                    let blk_ttou = this.signal_blocked(cx.kernel, tid, crate::linux_abi::LINUX_SIGTTOU);
                    if !ign_ttou && !blk_ttou {
                        let orphaned = cx.kernel.kernel().caller_process_group_is_orphaned(cx.kernel);
                        if orphaned {
                            return Ok(DispatchOutcome::errno(carrick_abi::LINUX_EIO));
                        }
                        if let Ok(signal) = crate::kernel::LinuxSignal::for_signal_number(crate::linux_abi::LINUX_SIGTTOU) {
                            cx.kernel.kernel().post_signal_to_process_group(
                                cx.kernel.container().id(),
                                cx.kernel.task().process_group(),
                                signal,
                            );
                        }
                        return Ok(DispatchOutcome::errno(LINUX_EINTR));
                    }
                }
            }
            let address = buf.0;
            let length =
                usize::try_from(count).map_err(|_| DispatchError::LengthTooLarge(count))?;
            // A zero-length write never accesses the buffer (write(fd, NULL, 0)
            // returns 0, not EFAULT) — only read guest memory when count > 0.
            let mut bytes = if length == 0 {
                Vec::new()
            } else {
                match (*cx.memory).read_bytes(address, length) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                }
            };

            let nonblocking = this.io_is_nonblocking(fd, 0);

            // inotify IN_MODIFY: a non-empty write(2) to a watched regular file
            // emits IN_MODIFY on it. A zero-length write touches nothing and
            // generates no event, matching Linux. Fast-exits when unwatched.
            if length > 0 {
                this.inotify_emit_for_fd(fd, carrick_abi::LINUX_IN_MODIFY);
                this.fanotify_emit_for_fd(
                    cx.kernel,
                    fd,
                    carrick_abi::LinuxFanotifyEvents::MODIFY,
                );
            }

            #[cfg(feature = "trace-io")]
            if !bytes.is_empty() {
                let has = this.open_file(fd).is_some();
                eprintln!(
                    "[WRDBG] guest_fd={fd} in_table={has} n={} bytes={:02x?}",
                    bytes.len(),
                    &bytes[..bytes.len().min(48)]
                );
            }

            // Check open_files FIRST: dup3 may have redirected fd 1/2 to
            // a pipe, an eventfd, or some other resource. Only after we've
            // confirmed there's no open description do we fall back to the
            // dispatcher's built-in stdout/stderr buffers.
            if let Some(open_file) = this.open_file(fd) {
                // Take an inner scope so the borrow on the description ends
                // before we touch this.fs.rootfs_vfs.overlay (writable File path below).
                enum FileWriteback {
                    Range {
                        path: String,
                        offset: usize,
                        bytes: Vec<u8>,
                        final_size: usize,
                    },
                }
                let outcome: DispatchOutcome;
                let writeback: Option<FileWriteback>;
                {
                    let Some(mut open) = open_file.description.write() else {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    };
                    match &mut *open {
                        OpenDescription::SyntheticDevice { kind, .. } => {
                            match kind {
                                crate::vfs::SyntheticDeviceKind::Full => {
                                    return Ok(DispatchOutcome::errno(LINUX_ENOSPC));
                                }
                                _ => {
                                    return Ok(DispatchOutcome::returned_len_or_errno(
                                        bytes.len(),
                                    ));
                                }
                            }
                        }
                        OpenDescription::EventFd { state, .. } => {
                            return Ok(write_eventfd(this, &bytes, state));
                        }
                        OpenDescription::PipeWriter { pipe, .. } => {
                            let pipe = Arc::clone(pipe);
                            let flags = open_file.description.common().status_flags();
                            let tid = cx.tid();
                            drop(open);
                            let Some(wait_authority) = this
                                .captured_slot_authority(fd)
                                .map(WaitFdAuthority::logical)
                            else {
                                return Ok(DispatchOutcome::errno(LINUX_EBADF));
                            };
                            let outcome = write_pipe(
                                &bytes,
                                &pipe,
                                flags,
                                fd,
                                wait_authority,
                                || {
                                    this.has_deliverable_dispatch_pending_for_wait(
                                        cx.kernel,
                                        tid,
                                        carrick_abi::WaitSigMask::NONE,
                                    )
                                },
                            );
                            if let DispatchOutcome::Returned { value } = outcome {
                                if value > 0 {
                                    this.notify_inmem_epoll();
                                    this.fasync_notify_after_write(cx.kernel, fd, value);
                                }
                            }
                            return Ok(this.raise_sigpipe_on_epipe(cx, outcome));
                        }
                        OpenDescription::HostPipe {
                            base,
                            host_fd,
                            is_read_end,
                            pipe_id,
                            pty,
                            bidirectional,
                            write_kind,
                            stdio_stream,
                            ..
                        } => {
                            if let Some(stream) = *stdio_stream {
                                if stream == 0 {
                                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                                }
                                if !this.io.inherits_host_stdio() {
                                    drop(open);
                                    return Ok(this.write_stdio_sink(stream, &bytes));
                                }
                            }
                            // pty ends and O_RDWR FIFOs are bidirectional; only
                            // real one-way pipe ends are gated by is_read_end.
                            #[cfg(feature = "trace-tty")]
                            if bytes.contains(&0x0a) {
                                let hf = host_fd.raw();
                                let tt = unsafe { libc::isatty(hf) };
                                eprintln!(
                                    "[PTYWRDBG] guest_fd={fd} desc_host_fd={hf} isatty={tt} pty={:?} is_read_end={is_read_end} bidir={bidirectional}",
                                    pty.as_ref().map(|r| r.is_master)
                                );
                            }
                            if *is_read_end && pty.is_none() && !*bidirectional {
                                return Ok(DispatchOutcome::errno(LINUX_EBADF));
                            }
                            let (bytes_to_write, consumed_count) = if let Some(PtyRole { index, is_master: true }) = pty {
                                let orig_len = bytes.len();
                                let forwarded = crate::kernel::tty::process_master_write(
                                    crate::kernel::tty::TtyKey::Pty(*index),
                                    host_fd.raw(),
                                    &bytes,
                                );
                                let consumed = orig_len - forwarded.len();
                                (forwarded, consumed)
                            } else {
                                (bytes, 0)
                            };
                            let out = if bytes_to_write.is_empty() && consumed_count > 0 {
                                DispatchOutcome::returned_len_or_errno(consumed_count)
                            } else {
                                let Some(wait_authority) = this
                                    .captured_slot_authority(fd)
                                    .map(WaitFdAuthority::logical)
                                else {
                                    drop(open);
                                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                                };
                                let res = write_host_pipe_owned(
                                    bytes_to_write,
                                    HostPipeWriteTarget {
                                        host_fd: host_fd.raw(),
                                        host_fd_owner: Some(host_fd.clone()),
                                        nonblocking,
                                        write_kind: *write_kind,
                                        pipe_state: this.host_pipe_capacity_state(
                                            base,
                                            *pipe_id,
                                            *is_read_end,
                                            *bidirectional,
                                            host_fd.raw(),
                                        ),
                                        tid: cx.tid(),
                                        sigpipe_on_epipe: true,
                                        authority: wait_authority,
                                    },
                                );
                                match res {
                                    DispatchOutcome::Returned { value } => {
                                        let total = usize::try_from(value)
                                            .ok()
                                            .and_then(|v| v.checked_add(consumed_count));
                                        match total {
                                            Some(t) => DispatchOutcome::returned_len_or_errno(t),
                                            None => DispatchOutcome::errno(LINUX_EOVERFLOW),
                                        }
                                    }
                                    other => {
                                        if consumed_count > 0 {
                                            DispatchOutcome::returned_len_or_errno(consumed_count)
                                        } else {
                                            other
                                        }
                                    }
                                }
                            };
                            // Signal-driven I/O: a write that added bytes makes the
                            // pipe's read end readable — the FASYNC readiness edge.
                            // Deliver the read end's owner signal (default SIGIO)
                            // via the fork-coherent registry (LTP fcntl31).
                            let written = match &out {
                                DispatchOutcome::Returned { value } => *value,
                                _ => 0,
                            };
                            let key_fd = fd;
                            drop(open);
                            this.fasync_notify_after_write(cx.kernel, key_fd, written);
                            return Ok(this.raise_sigpipe_on_epipe(cx, out));
                        }
                        OpenDescription::HostSocket { host_fd, .. } => {
                            // write(2) on a connected socket maps directly to a
                            // host write(2). Unconnected sockets will surface
                            // their own ENOTCONN via the host.
                            let Some(wait_authority) = this
                                .captured_slot_authority(fd)
                                .map(WaitFdAuthority::logical)
                            else {
                                drop(open);
                                return Ok(DispatchOutcome::errno(LINUX_EBADF));
                            };
                            let out = write_host_pipe_owned(
                                bytes,
                                HostPipeWriteTarget {
                                    host_fd: host_fd.raw(),
                                    host_fd_owner: Some(host_fd.clone()),
                                    nonblocking,
                                    write_kind: HostWriteKind::SocketLike,
                                    pipe_state: None,
                                    tid: cx.tid(),
                                    sigpipe_on_epipe: false,
                                    authority: wait_authority,
                                },
                            );
                            // Signal-driven I/O readiness edge on the socket peer.
                            let written = match &out {
                                DispatchOutcome::Returned { value } => *value,
                                _ => 0,
                            };
                            let key_fd = fd;
                            drop(open);
                            this.fasync_notify_after_write(cx.kernel, key_fd, written);
                            return Ok(out);
                        }
                        OpenDescription::InMemorySocket { socket, .. } => {
                            let socket = Arc::clone(socket);
                            drop(open);
                            match socket.send_stream(&bytes, Vec::new()) {
                                Ok(written) => {
                                    this.notify_inmem_epoll();
                                    return Ok(DispatchOutcome::returned_len_or_errno(
                                        written,
                                    ));
                                }
                                Err(LINUX_EPIPE) => {
                                    let outcome = DispatchOutcome::errno(LINUX_EPIPE);
                                    return Ok(this.raise_sigpipe_on_epipe(cx, outcome));
                                }
                                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                            }
                        }
                        OpenDescription::HostFile {
                            host_fd, writable, ..
                        } => {
                            if !*writable {
                                return Ok(DispatchOutcome::errno(LINUX_EBADF));
                            }
                            // O_APPEND: seek to EOF before writing so `>>` and
                            // log appends don't overwrite from offset 0. (The
                            // host fd isn't opened O_APPEND, so we emulate the
                            // seek-then-write; single-writer, which covers the
                            // shell/dpkg append cases.)
                            if LinuxOpenFlags::from_bits_truncate(
                                open_file.description.common().status_flags(),
                            )
                            .contains(LinuxOpenFlags::APPEND)
                            {
                                unsafe { libc::lseek(host_fd.raw(), 0, libc::SEEK_END) };
                            }
                            // The offset lives in the host kernel; read it back
                            // (post-append reposition) before applying the
                            // guest's RLIMIT_FSIZE cap.
                            if this.fsize_soft_limit().is_some() {
                                let pos = unsafe { libc::lseek(host_fd.raw(), 0, libc::SEEK_CUR) };
                                if pos >= 0 {
                                    match this.fsize_write_len(cx, pos as u64, bytes.len()) {
                                        Ok(len) => bytes.truncate(len),
                                        Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                                    }
                                }
                            }
                            // libc::write to the real fd: advances the
                            // kernel offset and is visible across fork.
                            let Some(wait_authority) = this
                                .captured_slot_authority(fd)
                                .map(WaitFdAuthority::logical)
                            else {
                                drop(open);
                                return Ok(DispatchOutcome::errno(LINUX_EBADF));
                            };
                            let out = write_host_pipe_owned(
                                bytes,
                                HostPipeWriteTarget {
                                    host_fd: host_fd.raw(),
                                    host_fd_owner: Some(host_fd.clone()),
                                    nonblocking,
                                    write_kind: HostWriteKind::RegularFile,
                                    pipe_state: None,
                                    tid: cx.tid(),
                                    sigpipe_on_epipe: false,
                                    authority: wait_authority,
                                },
                            );
                            if let DispatchOutcome::Returned { value } = out && value > 0 {
                                this.invalidate_dentry_host_fd(host_fd.raw());
                            }
                            return Ok(out);
                        }
                        OpenDescription::InMemoryFile {
                            path,
                            contents,
                            offset,
                            writable,
                            max_size,
                            ..
                        } => {
                            if !*writable {
                                return Ok(DispatchOutcome::errno(LINUX_EBADF));
                            }
                            let write_offset = if LinuxOpenFlags::from_bits_truncate(
                                open_file.description.common().status_flags(),
                            )
                            .contains(LinuxOpenFlags::APPEND)
                            {
                                contents.read().len()
                            } else {
                                *offset
                            };
                            match this.fsize_write_len(cx, write_offset as u64, bytes.len()) {
                                Ok(len) => bytes.truncate(len),
                                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                            }
                            let end = match write_offset.checked_add(bytes.len()) {
                                Some(e) => e,
                                None => return Ok(DispatchOutcome::errno(LINUX_EFBIG)),
                            };
                            if end > *max_size {
                                return Ok(DispatchOutcome::errno(LINUX_EFBIG));
                            }
                            let mut data = contents.write();
                            if data.write_range(write_offset, &bytes).is_err() {
                                return Ok(DispatchOutcome::errno(LINUX_EFBIG));
                            }
                            *offset = end;
                            this.fs.rootfs_vfs.notify_inode_changed(path, None);
                            outcome = DispatchOutcome::returned_len_or_errno(bytes.len());
                            writeback = None;
                        }
                        OpenDescription::File {
                            path,
                            contents,
                            offset,
                            writable,
                            metadata,
                            ..
                        } => {
                            if !*writable {
                                return Ok(DispatchOutcome::errno(LINUX_EBADF));
                            }
                            let cur_len = match contents.len() {
                                Ok(l) => l as usize,
                                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                            };
                            // memfd write seals: F_SEAL_WRITE → EPERM; F_SEAL_GROW
                            // → EPERM when the write would extend the file.
                            if let Err(errno) = memfd_seal_write_check(
                                open_file.description.common().seals(),
                                *offset,
                                bytes.len(),
                                cur_len,
                            ) {
                                return Ok(DispatchOutcome::errno(errno));
                            }
                            match this.fsize_write_len(cx, *offset as u64, bytes.len()) {
                                Ok(len) => bytes.truncate(len),
                                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                            }
                            let write_offset = *offset;
                            let written = match write_into_file_contents(contents, offset, &bytes) {
                                Ok(n) => n,
                                Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                            };
                            bytes.truncate(written);
                            let new_len = match contents.len() {
                                Ok(l) => l as usize,
                                Err(errno) if written == 0 => {
                                    return Ok(DispatchOutcome::errno(errno));
                                }
                                Err(_) => cur_len.max(write_offset.saturating_add(written)),
                            };
                            metadata.size = new_len;
                            outcome = DispatchOutcome::returned_len_or_errno(written);
                            writeback = (!is_anon_overlay_path(path)).then(|| {
                                FileWriteback::Range {
                                    path: path.clone(),
                                    offset: write_offset,
                                    bytes,
                                    final_size: new_len,
                                }
                            });
                        }
                        OpenDescription::SyntheticFile { path, .. }
                            if crate::vfs::proc::is_userns_map_path(path) =>
                        {
                            // Writing /proc/self/{uid_map,gid_map,setgroups}:
                            // the user-namespace map writers enforce the
                            // write-once / setgroups-gate / ≤5-line rules
                            // (docs/namespaces-design.md §4.3).
                            // The map named by /proc/self/uid_map is the
                            // CALLER's own, and the privilege verdict is read
                            // from the caller's own capability set — both off
                            // its task, so one guest process cannot rewrite
                            // another's maps.
                            let task = cx.kernel.task();
                            let privileged = task.caps().is_map_write_privileged();
                            let result = task.with_user_ns(|ns| {
                                crate::vfs::proc::write_userns_map(ns, privileged, path, &bytes)
                            });
                            return Ok(match result {
                                Ok(n) => DispatchOutcome::returned_len_or_errno(n),
                                Err(errno) => DispatchOutcome::errno(errno),
                            });
                        }
                        OpenDescription::SyntheticFile { path, .. }
                            if crate::vfs::proc::is_writable_tunable_path(path) =>
                        {
                            // oom_score_adj PERSISTS the value (per-process,
                            // fork-inherited): tst_test's OOM protection
                            // (tst_memutils.c) writes -1000 to /proc/<pid>/oom_score_adj
                            // then reads it back, and every test that enables it TBROKs
                            // in setup otherwise. The rest (oom_adj/loginuid/
                            // timerslack_ns) carrick has no live state for, so
                            // accept-and-ignore.
                            //
                            // The VFS parses and validates; applying it is the
                            // dispatcher's job because only here is it known
                            // which backend owns per-process state. The write
                            // may name ANOTHER process, so it cannot be routed
                            // to "the current one" — LTP writes the library
                            // process's file from the test child.
                            let parsed =
                                crate::vfs::proc::parse_tunable_write(path, &bytes);
                            return Ok(match parsed {
                                Err(errno) => DispatchOutcome::errno(errno),
                                Ok(crate::vfs::proc::TunableWrite::Ignored) => {
                                    DispatchOutcome::returned_len_or_errno(bytes.len())
                                }
                                Ok(crate::vfs::proc::TunableWrite::OomScoreAdj {
                                    pid,
                                    value,
                                }) => {
                                    let target = match pid {
                                        Some(pid) => crate::namespace::pid::ns_to_kernel_for(
                                            cx.kernel, pid,
                                        ),
                                        None => u32::try_from(cx.kernel.task().key().id.raw()).ok(),
                                    };
                                    match this.hvpatch_process() {
                                        Some(process) => {
                                            if target.is_some_and(|target| process
                                                .kernel_graph()
                                                .registry()
                                                .set_oom_score_adj(target, value)
                                            ) {
                                                DispatchOutcome::returned_len_or_errno(bytes.len())
                                            } else {
                                                // The process exited between
                                                // open(2) and write(2).
                                                DispatchOutcome::errno(LINUX_ESRCH)
                                            }
                                        }
                                        None => {
                                            crate::vfs::proc::set_single_process_oom_score_adj(
                                                value,
                                            );
                                            DispatchOutcome::returned_len_or_errno(bytes.len())
                                        }
                                    }
                                }
                            });
                        }
                        // write(2) on a perf event fd is EINVAL (verified
                        // against the Docker oracle), not EBADF.
                        OpenDescription::PerfEvent { .. } => {
                            return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                        }
                        _ => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                    }
                }
                if let Some(FileWriteback::Range {
                    path,
                    offset,
                    bytes,
                    final_size,
                }) = writeback
                {
                    let _ = this
                        .fs
                        .rootfs_vfs
                        .write_file_range(&path, offset, &bytes, final_size);
                }
                return Ok(outcome);
            }
            // A stdio fd the guest explicitly closed (and did not reopen) is
            // genuinely closed: write is EBADF, not a host-stream/buffer write.
            if this.stdio_is_closed(fd) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // Bare stdio goes to the run's sink exactly like writev does —
            // never buffered when the sink is live: busybox ash writes its
            // post-Enter newline to fd 2 via write(2), and buffering it left
            // the newline stuck until exit.
            Ok(this.write_stdio_sink(fd, &bytes))

        }

        fn writev(this, cx, fd: Fd, iov: GuestPtr, vlen: u64) {

            let fd = fd.0;
            // memfd_secret: no file write method → EINVAL (memfdsecret probe).
            if this.fd_is_secretmem(fd) {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let iov = iov.0;
            let iovcnt =
                usize::try_from(vlen).map_err(|_| DispatchError::LengthTooLarge(vlen))?;
            let memory = &*cx.memory;
            let iovecs = read_iovecs(memory, iov, iovcnt)?;
            // A stdio fd the guest explicitly closed (and did not reopen) is
            // genuinely closed: writev is EBADF, not a host-stream/buffer write.
            if this.stdio_is_closed(fd) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            let nonblocking = this.io_is_nonblocking(fd, 0);

            struct HostWritevTarget {
                host_fd: i32,
                host_fd_owner: Option<HostFdRef>,
                write_kind: HostWriteKind,
                pipe_state: Option<(i64, usize)>,
                sigpipe_on_epipe: bool,
                append: bool,
            }

            let host_target = if let Some(open_file) = this.open_file(fd) {
                let open = open_file.description.read();
                match open.as_deref() {
                    Some(OpenDescription::HostPipe {
                        base,
                        host_fd,
                        is_read_end,
                        pipe_id,
                        pty,
                        bidirectional,
                        write_kind,
                        ..
                    }) => {
                        // pty ends and O_RDWR FIFOs are bidirectional; only
                        // real one-way pipe ends gate on is_read_end.
                        if *is_read_end && pty.is_none() && !*bidirectional {
                            return Ok(DispatchOutcome::errno(LINUX_EBADF));
                        }
                        Some(HostWritevTarget {
                            host_fd: host_fd.raw(),
                            host_fd_owner: Some(host_fd.clone()),
                            write_kind: *write_kind,
                            pipe_state: this.host_pipe_capacity_state(
                                base,
                                *pipe_id,
                                *is_read_end,
                                *bidirectional,
                                host_fd.raw(),
                            ),
                            sigpipe_on_epipe: true,
                            append: false,
                        })
                    }
                    Some(OpenDescription::HostSocket { host_fd, .. }) => Some(HostWritevTarget {
                        host_fd: host_fd.raw(),
                        host_fd_owner: Some(host_fd.clone()),
                        write_kind: HostWriteKind::SocketLike,
                        pipe_state: None,
                        sigpipe_on_epipe: false,
                        append: false,
                    }),
                    Some(OpenDescription::HostFile {
                        host_fd, writable, ..
                    }) => {
                        if !*writable {
                            return Ok(DispatchOutcome::errno(LINUX_EBADF));
                        }
                        Some(HostWritevTarget {
                            host_fd: host_fd.raw(),
                            host_fd_owner: Some(host_fd.clone()),
                            write_kind: HostWriteKind::RegularFile,
                            pipe_state: None,
                            sigpipe_on_epipe: false,
                            append: LinuxOpenFlags::from_bits_truncate(
                                open_file.description.common().status_flags(),
                            )
                            .contains(LinuxOpenFlags::APPEND),
                        })
                    }
                    _ => None,
                }
            } else {
                None
            };

            if let Some(target) = host_target
                && let Some(GatheredIovecBytes { bytes, faulted }) =
                    gather_bounded_iovec_bytes(memory, &iovecs)?
            {
                if bytes.is_empty() {
                    // Nothing transferable: EFAULT only if the emptiness came
                    // from an unreadable segment. An all-zero-length list is a
                    // legitimate 0-byte write.
                    return if faulted {
                        Ok(DispatchOutcome::errno(LINUX_EFAULT))
                    } else {
                        Ok(DispatchOutcome::Returned { value: 0 })
                    };
                }
                if target.append {
                    unsafe { libc::lseek(target.host_fd, 0, libc::SEEK_END) };
                }
                let Some(wait_authority) = this
                    .captured_slot_authority(fd)
                    .map(WaitFdAuthority::logical)
                else {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                };
                let outcome = write_host_pipe_owned(
                    bytes,
                    HostPipeWriteTarget {
                        host_fd: target.host_fd,
                        host_fd_owner: target.host_fd_owner.clone(),
                        nonblocking,
                        write_kind: target.write_kind,
                        pipe_state: target.pipe_state,
                        tid: cx.tid(),
                        sigpipe_on_epipe: target.sigpipe_on_epipe,
                        authority: wait_authority,
                    },
                );
                if let DispatchOutcome::Returned { value } = outcome && value > 0 {
                    this.invalidate_dentry_host_fd(target.host_fd);
                }
                return if target.sigpipe_on_epipe {
                    Ok(this.raise_sigpipe_on_epipe(cx, outcome))
                } else {
                    Ok(outcome)
                };
            }

            let mut total = 0usize;
            for iovec in iovecs {
                let iov_base = iovec.iov_base;
                let iov_len = usize::try_from(iovec.iov_len)
                    .map_err(|_| DispatchError::LengthTooLarge(iovec.iov_len))?;
                // A zero-length iovec is a no-op regardless of its base — Linux
                // never dereferences it, so a {NULL, 0} entry must be skipped,
                // not EFAULTed (LTP writev01 "NULL and zero length iovec").
                if iov_len == 0 {
                    continue;
                }
                let mut bytes = match memory.read_bytes(iov_base, iov_len) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        // Bytes already written are already visible in the
                        // file, so reporting EFAULT here would both lose the
                        // count Linux returns AND leave the guest believing
                        // nothing was written. Report the short count instead;
                        // EFAULT is correct only when nothing moved.
                        if total > 0 {
                            break;
                        }
                        return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                    }
                };
                // Mirror `write`: check open_files FIRST so post-dup3
                // redirects (eg `dup3(pipe_write, 1)`) actually plumb
                // through the redirected description rather than the
                // built-in stdout buffer.
                if let Some(open_file) = this.open_file(fd) {
                    enum FileWriteback {
                        Range {
                            path: String,
                            offset: usize,
                            bytes: Vec<u8>,
                            final_size: usize,
                        },
                    }
                    let outcome: DispatchOutcome;
                    let writeback: Option<FileWriteback>;
                    {
                        let Some(mut open) = open_file.description.write() else {
                            return Ok(DispatchOutcome::errno(LINUX_EBADF));
                        };
                        match &mut *open {
                            OpenDescription::SyntheticDevice { kind, .. } => {
                                match kind {
                                    crate::vfs::SyntheticDeviceKind::Full => {
                                        return Ok(DispatchOutcome::errno(LINUX_ENOSPC));
                                    }
                                    _ => {
                                        outcome = DispatchOutcome::returned_len_or_errno(
                                            bytes.len(),
                                        );
                                        writeback = None;
                                    }
                                }
                            }
                            OpenDescription::PipeWriter { pipe, .. } => {
                                let Some(wait_authority) = this
                                    .captured_slot_authority(fd)
                                    .map(WaitFdAuthority::logical)
                                else {
                                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                                };
                                let tid = cx.tid();
                                outcome = write_pipe(
                                    &bytes,
                                    pipe,
                                    open_file.description.common().status_flags(),
                                    fd,
                                    wait_authority,
                                    || {
                                        this.has_deliverable_dispatch_pending_for_wait(
                                            cx.kernel,
                                            tid,
                                            carrick_abi::WaitSigMask::NONE,
                                        )
                                    },
                                );
                                writeback = None;
                            }
                            OpenDescription::HostPipe {
                                base,
                                host_fd,
                                is_read_end,
                                pipe_id,
                                pty,
                                bidirectional,
                                write_kind,
                                stdio_stream,
                                ..
                            } => {
                                if let Some(stream) = *stdio_stream {
                                    if stream == 0 {
                                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                                    }
                                    if !this.io.inherits_host_stdio() {
                                        drop(open);
                                        return Ok(this.write_stdio_sink(stream, &bytes));
                                    }
                                }
                                // pty ends and O_RDWR FIFOs are bidirectional;
                                // only real one-way pipe ends gate on is_read_end.
                                if *is_read_end && pty.is_none() && !*bidirectional {
                                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                                }
                                let (bytes_to_write, consumed_count) = if let Some(PtyRole { index, is_master: true }) = pty {
                                    let orig_len = bytes.len();
                                    let forwarded = crate::kernel::tty::process_master_write(
                                        crate::kernel::tty::TtyKey::Pty(*index),
                                        host_fd.raw(),
                                        &bytes,
                                    );
                                    let consumed = orig_len - forwarded.len();
                                    (forwarded, consumed)
                                } else {
                                    (bytes, 0)
                                };
                                outcome = if bytes_to_write.is_empty() && consumed_count > 0 {
                                    DispatchOutcome::returned_len_or_errno(consumed_count)
                                } else {
                                    let Some(wait_authority) = this
                                        .captured_slot_authority(fd)
                                        .map(WaitFdAuthority::logical)
                                    else {
                                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                                    };
                                    let res = write_host_pipe_owned(
                                        bytes_to_write,
                                        HostPipeWriteTarget {
                                            host_fd: host_fd.raw(),
                                            host_fd_owner: Some(host_fd.clone()),
                                            nonblocking,
                                            write_kind: *write_kind,
                                            pipe_state: this.host_pipe_capacity_state(
                                                base,
                                                *pipe_id,
                                                *is_read_end,
                                                *bidirectional,
                                                host_fd.raw(),
                                            ),
                                            tid: cx.tid(),
                                            sigpipe_on_epipe: true,
                                            authority: wait_authority,
                                        },
                                    );
                                    match res {
                                        DispatchOutcome::Returned { value } => {
                                            let total = usize::try_from(value)
                                                .ok()
                                                .and_then(|v| v.checked_add(consumed_count));
                                            match total {
                                                Some(t) => DispatchOutcome::returned_len_or_errno(t),
                                                None => DispatchOutcome::errno(LINUX_EOVERFLOW),
                                            }
                                        }
                                        other => {
                                            if consumed_count > 0 {
                                                DispatchOutcome::returned_len_or_errno(consumed_count)
                                            } else {
                                                other
                                            }
                                        }
                                    }
                                };
                                writeback = None;
                            }
                            OpenDescription::HostSocket { host_fd, .. } => {
                                let Some(wait_authority) = this
                                    .captured_slot_authority(fd)
                                    .map(WaitFdAuthority::logical)
                                else {
                                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                                };
                                outcome = write_host_pipe_owned(
                                    bytes,
                                    HostPipeWriteTarget {
                                        host_fd: host_fd.raw(),
                                        host_fd_owner: Some(host_fd.clone()),
                                        nonblocking,
                                        write_kind: HostWriteKind::SocketLike,
                                        pipe_state: None,
                                        tid: cx.tid(),
                                        sigpipe_on_epipe: false,
                                        authority: wait_authority,
                                    },
                                );
                                writeback = None;
                            }
                            OpenDescription::InMemorySocket { socket, .. } => {
                                let socket = Arc::clone(socket);
                                match socket.send_stream(&bytes, Vec::new()) {
                                    Ok(written) => {
                                        this.notify_inmem_epoll();
                                        outcome = DispatchOutcome::returned_len_or_errno(written);
                                    }
                                    Err(LINUX_EPIPE) => {
                                        outcome = DispatchOutcome::errno(LINUX_EPIPE);
                                    }
                                    Err(errno) => {
                                        outcome = DispatchOutcome::errno(errno);
                                    }
                                }
                                writeback = None;
                            }
                            OpenDescription::HostFile {
                                host_fd, writable, ..
                            } => {
                                if !*writable {
                                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                                }
                                // Mirror `write`(64): O_APPEND seeks to EOF, then
                                // libc::write to the real fd advances the shared
                                // kernel offset (visible across fork and to the
                                // readv that follows).
                                if LinuxOpenFlags::from_bits_truncate(
                                    open_file.description.common().status_flags(),
                                )
                                .contains(LinuxOpenFlags::APPEND)
                                {
                                    unsafe { libc::lseek(host_fd.raw(), 0, libc::SEEK_END) };
                                }
                                let Some(wait_authority) = this
                                    .captured_slot_authority(fd)
                                    .map(WaitFdAuthority::logical)
                                else {
                                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                                };
                                outcome = write_host_pipe_owned(
                                    bytes,
                                    HostPipeWriteTarget {
                                        host_fd: host_fd.raw(),
                                        host_fd_owner: Some(host_fd.clone()),
                                        nonblocking,
                                        write_kind: HostWriteKind::RegularFile,
                                        pipe_state: None,
                                        tid: cx.tid(),
                                        sigpipe_on_epipe: false,
                                        authority: wait_authority,
                                    },
                                );
                                if let DispatchOutcome::Returned { value } = outcome && value > 0 {
                                    this.invalidate_dentry_host_fd(host_fd.raw());
                                }
                                writeback = None;
                            }
                            OpenDescription::InMemoryFile {
                                path,
                                contents,
                                offset,
                                writable,
                                max_size,
                                ..
                            } => {
                                if !*writable {
                                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                                }
                                let mut data = contents.write();
                                let write_offset = if LinuxOpenFlags::from_bits_truncate(
                                    open_file.description.common().status_flags(),
                                )
                                .contains(LinuxOpenFlags::APPEND)
                                {
                                    data.len()
                                } else {
                                    *offset
                                };
                                let end = match write_offset.checked_add(bytes.len()) {
                                    Some(e) => e,
                                    None => return Ok(DispatchOutcome::errno(LINUX_EFBIG)),
                                };
                                if end > *max_size {
                                    return Ok(DispatchOutcome::errno(LINUX_EFBIG));
                                }
                                if data.write_range(write_offset, &bytes).is_err() {
                                    return Ok(DispatchOutcome::errno(LINUX_EFBIG));
                                }
                                *offset = end;
                                this.fs.rootfs_vfs.notify_inode_changed(path, None);
                                outcome = DispatchOutcome::returned_len_or_errno(bytes.len());
                                writeback = None;
                            }
                            OpenDescription::File {
                                path,
                                contents,
                                offset,
                                writable,
                                metadata,
                                ..
                            } => {
                                if !*writable {
                                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                                }
                                let cur_len = match contents.len() {
                                    Ok(l) => l as usize,
                                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                                };
                                if let Err(errno) = memfd_seal_write_check(
                                    open_file.description.common().seals(),
                                    *offset,
                                    bytes.len(),
                                    cur_len,
                                ) {
                                    return Ok(DispatchOutcome::errno(errno));
                                }
                                let write_offset = *offset;
                                let written = match write_into_file_contents(contents, offset, &bytes) {
                                    Ok(n) => n,
                                    Err(errno) => return Ok(DispatchOutcome::errno(errno)),
                                };
                                bytes.truncate(written);
                                let new_len = match contents.len() {
                                    Ok(l) => l as usize,
                                    Err(errno) if written == 0 => {
                                        return Ok(DispatchOutcome::errno(errno));
                                    }
                                    Err(_) => cur_len.max(write_offset.saturating_add(written)),
                                };
                                metadata.size = new_len;
                                outcome = DispatchOutcome::returned_len_or_errno(written);
                                writeback = (!is_anon_overlay_path(path)).then(|| {
                                    FileWriteback::Range {
                                        path: path.clone(),
                                        offset: write_offset,
                                        bytes,
                                        final_size: new_len,
                                    }
                                });
                            }
                            _ => return Ok(DispatchOutcome::errno(LINUX_EBADF)),
                        }
                    }
                    if let Some(FileWriteback::Range {
                        path,
                        offset,
                        bytes,
                        final_size,
                    }) = writeback
                    {
                        let _ = this
                            .fs
                            .rootfs_vfs
                            .write_file_range(&path, offset, &bytes, final_size);
                    }
                    let DispatchOutcome::Returned { value } = outcome else {
                        // EAGAIN/EPIPE on this iovec. writev(2) is atomic across
                        // iovecs: if EARLIER iovecs were already written (total >
                        // 0), return that short count — NOT the error, which
                        // would discard bytes already sent and make the caller
                        // re-send from offset 0 (libuv's stream flow control then
                        // never completes a write: ipc_heavy_traffic_deadlock_bug,
                        // bw stuck at 0). Only surface the error when nothing has
                        // been written yet.
                        //
                        // For EPIPE specifically with nothing written: a broken
                        // pipe/socket (read end closed) → EPIPE AND a SIGPIPE on
                        // the writer, same as write(2) (busybox `yes | head`
                        // wants exit 141, write05).
                        if total > 0 {
                            return Ok(DispatchOutcome::returned_len_or_errno(total));
                        }
                        return Ok(this.raise_sigpipe_on_epipe(cx, outcome));
                    };
                    total = total
                        .checked_add(value as usize)
                        .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
                    // A SHORT write on this iovec (host send buffer full) ends the
                    // writev: the rest of this iovec and all later iovecs are
                    // unsent. Returning the partial `total` is correct writev(2)
                    // semantics; continuing would write a later iovec AFTER an
                    // unfilled earlier one — a gap/reorder in the byte stream.
                    if (value as usize) < iov_len {
                        return Ok(DispatchOutcome::returned_len_or_errno(total));
                    }
                    continue;
                }
                // Full write loop per iovec — never drop the tail on an
                // O_NONBLOCK slave; a hard error ends the writev.
                match this.write_stdio_sink(fd, &bytes) {
                    DispatchOutcome::Returned { value } => {
                        total = total
                            .checked_add(value as usize)
                            .ok_or(DispatchError::LengthTooLarge(u64::MAX))?;
                    }
                    other => return Ok(other),
                }
            }

            Ok(DispatchOutcome::returned_len_or_errno(total))

        }

        fn fchmod(this, cx, fd: Fd, mode: u64) {

            let fd: Fd = fd;
            if !this.fd_is_valid(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // An O_PATH descriptor is not open for I/O (open13 → EBADF).
            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            let mode = (mode & 0o7777) as u32;
            // Resolve the fd to its path and route through the backend's set_mode,
            // so the guest-visible mode lands in the carrick mode xattr (what
            // fstat reports) — not just the real fd's mode, which could be the
            // forced-owner-accessible value. Previously this called libc::fchmod
            // directly, so fstat kept reporting the stale creation-time mode.
            let path = this
                .open_file(fd.0)
                .and_then(|of| match of.description.read().as_deref() {
                    Some(
                        OpenDescription::HostFile { metadata, .. }
                        | OpenDescription::File { metadata, .. }
                        | OpenDescription::Directory { metadata, .. },
                    ) => Some(metadata.path.to_string_lossy().into_owned()),
                    _ => None,
                });
            if let Some(path) = path {
                if let Some(errno) = this.chmod_permission_errno(&path) {
                    return Ok(DispatchOutcome::errno(errno));
                }
                let mode = this.maybe_clear_setgid(&path, mode);
                if let Some(m) = this.fs.vfs_mounts.resolve(&path) {
                    if let Err(errno) = m.vfs.chmod(&m.full_path, mode) {
                        return Ok(DispatchOutcome::errno(errno));
                    }
                } else {
                    let _ = this.fs.rootfs_vfs.set_mode(&path, mode);
                }
                // Refresh THIS fd's cached metadata so a subsequent fstat on it
                // sees the new mode. A Directory/File fstat reads the cached
                // metadata (only HostFile re-reads the live xattr), so without
                // this an fchmod(dirfd)+fstat(dirfd) reported the stale
                // open-time mode (LTP fchmod04/05). metadata.mode holds the
                // permission bits; the type comes from `kind`.
                if let Some(of) = this.open_file(fd.0) {
                    if let Some(mut open) = of.description.write() {
                        match &mut *open {
                            OpenDescription::Directory { metadata, .. }
                            | OpenDescription::File { metadata, .. } => {
                                metadata.mode = mode;
                            }
                            OpenDescription::HostFile { host_fd, metadata, .. } => {
                                metadata.mode = mode;
                                this.fs.rootfs_vfs.fset_mode(host_fd.raw(), mode);
                            }
                            _ => {}
                        }
                    }
                }
                // inotify IN_ATTRIB (chmod is a metadata change).
                this.inotify_attrib(&path);
                this.dnotify_attrib_for_tid(cx.kernel, &path, Some(cx.tid()));
            }
            Ok(DispatchOutcome::Returned { value: 0 })

        }

        fn fchown(this, cx, fd: Fd, owner: u64, group: u64) {

            let fd: Fd = fd;
            if !this.fd_is_valid(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            // An O_PATH descriptor is not open for I/O (open13 → EBADF).
            if this.fd_is_o_path(fd.0) {
                return Ok(DispatchOutcome::errno(LINUX_EBADF));
            }
            let uid = Self::chown_uid_arg(owner);
            let gid = Self::chown_gid_arg(group);
            Ok(this.fchown_by_fd(cx.kernel, fd.0, uid, gid))

        }

        fn fchownat(this, cx, dirfd: u64, pathname: GuestPtr, owner: u64, group: u64, flags: u64) {

            let pathname = pathname.0;
            let Some(at_flags) = carrick_abi::LinuxAtFlags::from_bits(flags) else {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            };
            if at_flags.bits() & !(LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH) != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            let path = read_guest_c_string(&*cx.memory, pathname)?;
            if path.is_empty() {
                if !at_flags.contains(carrick_abi::LinuxAtFlags::EMPTY_PATH) {
                    return Ok(DispatchOutcome::errno(LINUX_ENOENT));
                }
                if dirfd == LINUX_AT_FDCWD {
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                if !this.fd_is_valid(dirfd as i32) {
                    return Ok(DispatchOutcome::errno(LINUX_EBADF));
                }
                // AT_EMPTY_PATH operates on the fd ITSELF — record the owner like
                // fchown (was a silent no-op success that never set_owner'd).
                let uid = Self::chown_uid_arg(owner);
                let gid = Self::chown_gid_arg(group);
                return Ok(this.fchown_by_fd(cx.kernel, dirfd as i32, uid, gid));
            }
            let uid = Self::chown_uid_arg(owner);
            let gid = Self::chown_gid_arg(group);
            let resolved = this.resolve_at_path(dirfd, &path)?;
            let nofollow = at_flags.contains(carrick_abi::LinuxAtFlags::SYMLINK_NOFOLLOW);
            if this.fs.vfs_mounts.resolve(&resolved).is_some() {
                let lookup = {
                    if let Some(m) = this.fs.vfs_mounts.resolve(&resolved) {
                        if nofollow {
                            m.vfs.lookup_nofollow(&m.full_path)
                        } else {
                            m.vfs.lookup(&m.full_path)
                        }
                    } else {
                        Err(LINUX_ENOENT)
                    }
                };
                if let Err(errno) = lookup {
                    return Ok(DispatchOutcome::errno(errno));
                }
                if let Some(errno) = this.chown_permission_errno(uid, gid) {
                    return Ok(DispatchOutcome::errno(errno));
                }
                let result = {
                    if let Some(m) = this.fs.vfs_mounts.resolve(&resolved) {
                        m.vfs.chown(&m.full_path, uid, gid, nofollow)
                    } else {
                        Err(LINUX_ENOENT)
                    }
                };
                return match result {
                    Ok(()) => {
                        this.clear_setid_on_chown(&resolved);
                        Ok(DispatchOutcome::Returned { value: 0 })
                    }
                    Err(errno) => Ok(DispatchOutcome::errno(errno)),
                };
            }
            // Layered presence check: overlay first (tombstones become ENOENT),
            // synthetic /proc and /sys are no-op success, rootfs is no-op
            // success (tmpfs semantics). Record the guest-visible owner on the
            // backend (durably, via xattr on --fs host) so a later stat reports it.
            let lookup = if nofollow {
                this.layered_lstat(&resolved).map(|_| ())
            } else {
                this.layered_metadata(&resolved).map(|_| ())
            };
            match lookup {
                Ok(_) => {
                    if let Some(errno) = this.chown_permission_errno(uid, gid) {
                        return Ok(DispatchOutcome::errno(errno));
                    }
                    let target_path = if nofollow {
                        resolved.clone()
                    } else {
                        this.canonicalize_following(&resolved)
                            .unwrap_or_else(|_| resolved.clone())
                    };
                    let _ = this.fs.rootfs_vfs.set_owner(
                        &target_path,
                        uid,
                        gid,
                    );
                    this.clear_setid_on_chown(&target_path);
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                Err(errno) => {
                    if this.is_synthetic_virtual_path(cx.kernel, &resolved)
                    {
                        Ok(DispatchOutcome::Returned { value: 0 })
                    } else {
                        Ok(DispatchOutcome::errno(errno))
                    }
                }
            }

        }

        fn fchmodat(this, cx, dirfd: u64, pathname: GuestPtr, mode: u64, flags: u64) {

            // The fchmodat syscall (nr 53) is SYSCALL_DEFINE3 in Linux: it takes
            // only (dirfd, path, mode) and IGNORES the 4th register. glibc's
            // AT_SYMLINK_NOFOLLOW path still leaves the flag in that register —
            // `apt-get update` issues fchmodat(AT_FDCWD, path, 0644, 0x100) on
            // every downloaded index — and the real kernel silently ignores it.
            // Rejecting non-zero flags here made every apt download chmod fail
            // ("chmod 0644 of file … failed - 201::URIDone"). Only fchmodat2 (452)
            // validates the flags.
            let _ = flags;
            this.chmod_at(cx.kernel, dirfd, pathname.0, mode, &*cx.memory)

        }

        fn fchmodat2(this, cx, dirfd: u64, pathname: GuestPtr, mode: u64, flags: u64) {

            // fchmodat2 (nr 452) carries a REAL flags argument: only
            // AT_SYMLINK_NOFOLLOW is valid (fchmodat2_02 passes -1 → EINVAL).
            if flags & !LINUX_AT_SYMLINK_NOFOLLOW != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            if flags & LINUX_AT_SYMLINK_NOFOLLOW != 0 {
                // Linux cannot change a SYMLINK's mode — no filesystem it ships
                // implements it — so `fchmodat2(..., AT_SYMLINK_NOFOLLOW)` on a
                // symlink is EOPNOTSUPP. On anything else the flag is a no-op,
                // because there is no link to avoid following. Treating the flag
                // as purely advisory instead silently chmod'd the link's TARGET,
                // which is the one thing the caller asked not to happen (Go's
                // `TestFchmodat`, measured against the Docker oracle:
                // `fchmodat2(symlink, AT_SYMLINK_NOFOLLOW)` = -1/EOPNOTSUPP there
                // and 0 here).
                let path = read_guest_c_string(&*cx.memory, pathname.0)?;
                if !path.is_empty() {
                    let resolved = this.resolve_at_path(dirfd, &path)?;
                    if this
                        .layered_lstat(&resolved)
                        .is_ok_and(|md| md.kind == RootFsEntryKind::Symlink)
                    {
                        return Ok(DispatchOutcome::errno(LINUX_EOPNOTSUPP));
                    }
                }
            }
            this.chmod_at(cx.kernel, dirfd, pathname.0, mode, &*cx.memory)

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
                base: OpenDescriptionBase::new(0),
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
                base: OpenDescriptionBase::new(0),
                writable: true,
            };
            let fd_flags = if flags & LINUX_O_CLOEXEC != 0 {
                LINUX_FD_CLOEXEC
            } else {
                0
            };
            Ok(this.install_fd_with_common(description, common, fd_flags))
        }

        fn utimensat(this, cx, dirfd: u64, pathname: GuestPtr, times: GuestPtr, flags: u64) {

            let pathname = pathname.0;
            let times = times.0;
            let memory = &*cx.memory;
            if flags & !LINUX_AT_SYMLINK_NOFOLLOW != 0 {
                return Ok(DispatchOutcome::errno(LINUX_EINVAL));
            }
            // `times == NULL` means "set both to now"; otherwise read the two
            // timespecs and resolve UTIME_NOW/UTIME_OMIT into concrete
            // (sec, nsec) pairs or `None` (omit) for the backend.
            #[allow(clippy::type_complexity)]
            let (atime_set, mtime_set): (Option<(i64, i64)>, Option<(i64, i64)>);
            let clock = Arc::clone(cx.kernel.task().container().clock());
            if times != 0 {
                let atime = read_timespec(memory, times)?;
                let mtime_address = times
                    .checked_add(core::mem::size_of::<LinuxTimespec>() as u64)
                    .ok_or(DispatchError::LengthTooLarge(times))?;
                let mtime = read_timespec(memory, mtime_address)?;
                if !linux_utimensat_timespec_is_valid(atime)
                    || !linux_utimensat_timespec_is_valid(mtime)
                {
                    return Ok(DispatchOutcome::errno(LINUX_EINVAL));
                }
                atime_set = resolve_utimensat_timespec(&clock, atime);
                mtime_set = resolve_utimensat_timespec(&clock, mtime);
            } else {
                // NULL → set both to the current wall-clock time.
                let now = now_realtime_timespec(&clock);
                atime_set = Some(now);
                mtime_set = Some(now);
            }

            if pathname == 0 {
                // `futimens(fd, times)` lowers to `utimensat(fd, NULL, times, 0)`
                // in musl/glibc: set the times of the *open fd itself*. (This is
                // distinct from the AT_EMPTY_PATH form, which carries an empty —
                // not NULL — path.)
                if dirfd == LINUX_AT_FDCWD {
                    return Ok(DispatchOutcome::errno(LINUX_EFAULT));
                }
                if atime_set.is_none() && mtime_set.is_none() {
                    // Both UTIME_OMIT: nothing to persist; just validate the fd.
                    if !this.fd_is_valid(dirfd as i32) {
                        return Ok(DispatchOutcome::errno(LINUX_EBADF));
                    }
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                return Ok(this.set_fd_times(dirfd as i32, atime_set, mtime_set));
            }

            let path = read_guest_c_string(memory, pathname)?;
            if path.is_empty() {
                return Ok(DispatchOutcome::errno(LINUX_ENOENT));
            }
            let path = match this.resolve_at_path(dirfd, &path) {
                Ok(path) => path,
                Err(errno) => {
                    crate::probes::fs_op("utimensat:resolve_err", &path, errno.get());
                    return Ok(DispatchOutcome::errno(errno));
                }
            };
            // Without AT_SYMLINK_NOFOLLOW, utime()/utimensat FOLLOWS a trailing
            // symlink to its target and updates THAT file's times: a dangling
            // target is ENOENT and a symlink cycle is ELOOP (utime07). Only when
            // the final component is genuinely a symlink — plain paths and
            // synthetic /proc entries are left untouched for the checks below,
            // and resolve_at_path already leaves the final component unfollowed.
            let path = if flags & LINUX_AT_SYMLINK_NOFOLLOW == 0
                && matches!(
                    this.layered_lstat(&path),
                    Ok(md) if md.kind == RootFsEntryKind::Symlink
                ) {
                match this.canonicalize_following(&path) {
                    Ok(resolved) => resolved,
                    Err(errno) => {
                        crate::probes::fs_op("utimensat:follow_err", &path, errno.get());
                        return Ok(DispatchOutcome::errno(errno));
                    }
                }
            } else {
                path
            };
            let exists = if flags & LINUX_AT_SYMLINK_NOFOLLOW != 0 {
                this.layered_lstat(&path).map(|_| ())
            } else {
                this.layered_metadata(&path).map(|_| ())
            };
            match exists {
                Ok(_) => {}
                Err(errno) => {
                    if this.is_synthetic_virtual_path(cx.kernel, &path) {
                        return Ok(DispatchOutcome::Returned { value: 0 });
                    }
                    crate::probes::fs_op("utimensat:meta_err", &path, errno.get());
                    return Ok(DispatchOutcome::errno(errno));
                }
            }
            if atime_set.is_none() && mtime_set.is_none() {
                // Both UTIME_OMIT: nothing to persist.
                return Ok(DispatchOutcome::Returned { value: 0 });
            }
            if let Some(m) = this.fs.vfs_mounts.resolve(&path) {
                return match m.vfs.set_times(
                    &m.full_path,
                    atime_set,
                    mtime_set,
                    flags & LINUX_AT_SYMLINK_NOFOLLOW != 0,
                ) {
                    Ok(()) => {
                        this.fs.rootfs_vfs.notify_inode_changed(&path, None);
                        Ok(DispatchOutcome::Returned { value: 0 })
                    }
                    Err(errno) => Ok(DispatchOutcome::errno(errno)),
                };
            }
            // Persist atime/mtime to the materialised host file (disk-backed
            // overlay). A subsequent stat reads real disk metadata via
            // real_stat and will report the set mtime. MemoryBackend returns
            // Unsupported; accept as a no-op so in-memory guests don't fail.
            match this
                .fs
                .rootfs_vfs
                .set_times(
                    &path,
                    atime_set,
                    mtime_set,
                    flags & LINUX_AT_SYMLINK_NOFOLLOW != 0,
                )
            {
                Ok(()) => {
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                Err(crate::fs_backend::BackendError::Unsupported) => {
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
                // Best-effort timestamps: a successful set above persists real
                // mtime (apt's pkgcache x-ref relies on that), but a FAILURE to
                // set times must NOT abort the caller. Linux tools like dpkg treat
                // utimensat failure on a file they just wrote as fatal ("error
                // setting timestamps … Read-only file system"); returning EROFS
                // there breaks `dpkg --unpack` of any package with shared libs.
                // The file content is already correct; timestamps are cosmetic.
                Err(e) => {
                    crate::probes::fs_op("utimensat:set_times_err_besteffort", &path, 0);
                    let _ = e;
                    Ok(DispatchOutcome::Returned { value: 0 })
                }
            }

        }

    }
}

#[cfg(test)]
#[path = "fs/tests.rs"]
mod tests;
