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
pub(in crate::dispatch::fs) use super::LinuxPipe2Flags;
pub(in crate::dispatch::fs) use super::LinuxSpliceFlags;
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
mod attr;
mod close_dup;
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
mod open;
mod pathres;
pub(crate) mod pipe;
pub(crate) mod proc_synthetic;
pub(crate) use proc_synthetic::*;
mod sendfile;
mod stat;
mod state;
mod transfer;
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

/// Linux pipe2 / fcntl(F_SETOWN/F_SETFL) coordinates FASYNC signals across BOTH
/// ends of an anonymous pipe. To let the write end know which read end to wake
/// (and vice-versa) even after either end has been duplicated or forked into
/// a child process, Carrick generates a 64-bit pipe identity from the host
/// device and inode numbers assigned by the kernel on the first fstat. We
/// stamp BOTH ends of a freshly-created pipe with one shared FASYNC join key.
/// Include both host device and inode: inode numbers are only unique within a
/// device, and Carrick adopts streams from devfs and several filesystems. The
/// value is read before fork and copied to the other pipe end, so both ends
/// retain one Linux identity even though BSD assigns them different inodes.
/// Returns `0` if fstat fails; `0` is never a valid armed FASYNC key.
pub(super) fn host_inode_pipe_id(host_fd: i32) -> u64 {
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

pub(super) fn host_pipe_readable_bytes(host_fd: i32) -> Result<usize, LinuxErrno> {
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
pub(super) struct GatheredIovecBytes {
    pub(super) bytes: Vec<u8>,
    pub(super) faulted: bool,
}

pub(super) fn gather_bounded_iovec_bytes(
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

pub(super) fn path_is_under_or_equal(path: &str, root: &str) -> bool {
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

use super::fd_table::is_anon_overlay_path;

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

    pub(super) fn host_pipe_read_end_for_pipe_id(&self, pipe_id: u64) -> Option<(i32, HostFd)> {
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
    pub(super) fn host_pipe_write_end_for_pipe_id(&self, pipe_id: u64) -> Option<HostFd> {
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

    pub(super) fn host_pipe_read_end_buffered_bytes(&self, pipe_id: u64) -> usize {
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
    pub(super) fn write_stdio_sink(&self, fd: i32, bytes: &[u8]) -> DispatchOutcome {
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

    pub(super) fn read_host_pipe_iovecs<M: CurrentMmMemory>(
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

    }
}

#[cfg(test)]
#[path = "fs/tests.rs"]
mod tests;
