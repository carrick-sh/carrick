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
pub(in crate::dispatch::fs) use crate::linux_abi::{
    LINUX_ELOOP, LINUX_ENOSPC, LINUX_ENXIO, LINUX_EOVERFLOW, LINUX_SEEK_DATA, LINUX_SEEK_HOLE,
};
pub(in crate::dispatch::fs) use crate::vfs::PtyRole;

// Preserve use of parent and abi imports across the submodule split.
const _: () = {
    let _ = (
        LINUX_SEEK_CUR,
        LINUX_SEEK_END,
        LINUX_SEEK_SET,
        LINUX_SIGXFSZ,
        LINUX_ENOSPC,
        LINUX_ENXIO,
        LINUX_EOVERFLOW,
        LINUX_SEEK_DATA,
        LINUX_SEEK_HOLE,
    );
};

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
mod rw;
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


    }
}

#[cfg(test)]
#[path = "fs/tests.rs"]
mod tests;
