//! Unified virtual filesystem layer for carrick.
//!
//! Today carrick reaches into four separate code paths for filesystem
//! syscalls:
//!
//! 1. **`/proc/*`** — synthetic files owned by [`proc::ProcVfs`].
//! 2. **`/sys/*`** — synthetic files owned by [`sys::SysVfs`].
//! 3. **`/dev/*`** — `host_dev_passthrough()` returns a macOS path
//!    that the dispatcher opens via raw `libc::open` and wraps as a
//!    `HostPipe`.
//! 4. **`/` (rootfs + writes)** — read-only [`crate::rootfs::RootFs`]
//!    from the OCI image, plus a writable overlay implemented by the
//!    [`crate::fs_backend::FsBackend`] trait.
//!
//! This module defines a single [`Vfs`] trait that all four surfaces
//! will eventually implement, and a [`mount::VfsMounts`] table that
//! routes `path`-based syscalls to the longest-prefix-matching mount.
//!
//! Migration is planned in four PRs (see `memory/plan_vfs_refactor.md`):
//!
//! 1. **Scaffold (this commit).** Trait + mount table + tests; nothing
//!    in the dispatcher consults `Vfs` yet.
//! 2. **`DevVfs`** — moves chardev passthrough behind the trait.
//! 3. **`ProcVfs` + `SysVfs`** — moves the synthetic generators behind
//!    sub-mountable Vfs implementations.
//! 4. **`RootFsVfs`** — subsumes the immutable rootfs + writable
//!    overlay split; every dispatcher fs syscall flows through the
//!    Vfs after this lands.
//!
//! Step 1 landed the path-level trait + mount table. Step 2 (this
//! revision) adds the `open` method and a [`VfsHandle`] discriminated
//! union that the dispatcher converts to its own `OpenDescription`
//! enum. `DevVfs` is the first concrete user of `open`.

pub mod bind;
pub mod dev;
pub mod devpts;
pub mod etc_services;
pub mod mount;
pub mod proc;
pub mod resolvconf;
pub mod rootfs;
pub mod sys;

pub use bind::BindVfs;
pub use dev::DevVfs;
pub use devpts::{DevptsVfs, PtyRole, PtyTable};
pub use etc_services::EtcServicesVfs;
pub use mount::VfsMounts;
pub use proc::{ProcMapsEntry, ProcVfs, SyntheticProcContext};
pub use resolvconf::ResolvConfVfs;
pub use rootfs::RootFsVfs;
pub use sys::SysVfs;

/// Maximum size Carrick will materialize as a `Vec<u8>` for memory-backed
/// regular files. Larger files need a host-backed fd so growth remains sparse.
pub const MAX_IN_MEMORY_FILE_SIZE: u64 = 512 * 1024 * 1024;

pub(crate) fn is_synthetic_virtual_file(path: &str, ctx: &SyntheticProcContext) -> bool {
    proc::synthetic_file(path, ctx).is_some() || sys::synthetic_file(path).is_some()
}

use std::path::PathBuf;

/// Linux errno code reported by a [`Vfs`] failure. Plain `i32` matches
/// the dispatcher's existing error pipeline (e.g. the `LINUX_ENOENT`
/// constants in `dispatch.rs`), so leaf-level mounts can return raw
/// errno values without going through a translation layer.
pub type VfsError = i32;

/// Kind of an entry at a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
    Symlink,
    CharDevice,
    /// Named pipe (FIFO). Maps to/from [`crate::rootfs::RootFsEntryKind::Fifo`].
    Fifo,
    /// AF_UNIX socket node materialised by `bind(2)`. Maps to/from
    /// [`crate::rootfs::RootFsEntryKind::Socket`].
    Socket,
}

/// Per-entry metadata. Mode is the permission bits only (the
/// kind-of-file bits like `S_IFREG` are derived from [`EntryKind`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    pub kind: EntryKind,
    pub mode: u32,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    pub mtime_secs: i64,
    pub mtime_nanos: u32,
}

/// One entry returned by [`Vfs::readdir`]. Name only (the caller pairs
/// each with [`Vfs::lookup`] when it needs the metadata).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEnt {
    pub name: String,
    pub kind: EntryKind,
}

/// Open flags normalised away from Linux's bit layout. Mounts that
/// only care about read/write distinctions don't have to decode the
/// raw Linux O_* bits themselves; the dispatcher does that once
/// before handing flags to the Vfs.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenFlags {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub excl: bool,
    pub trunc: bool,
    pub append: bool,
    pub directory: bool,
    pub nofollow: bool,
    pub nonblock: bool,
    pub cloexec: bool,
    /// Mode bits for `O_CREAT`. Ignored otherwise.
    pub mode: u32,
}

/// What a successful [`Vfs::open`] returns. Each variant carries
/// just enough information for the dispatcher to construct its own
/// `OpenDescription` without the Vfs needing to know about that
/// private enum. New variants are added per migration step:
///
/// * Step 2 (DevVfs): [`HostFd`](VfsHandle::HostFd) — a real macOS fd
///   that the dispatcher will wrap as a `HostPipe` description.
/// * Step 3 (ProcVfs/SysVfs): a `Bytes` variant for synthetic files.
/// * Step 4 (RootFsVfs): variants for overlay-backed regular files
///   and directories.
/// * devpts Phase A: [`Directory`](VfsHandle::Directory) — a synthetic
///   directory listing served entirely from `Vec<DirEnt>` in memory,
///   for mounts like `/dev` that own their own listing rather than
///   delegating to the rootfs layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VfsHandle {
    /// A host fd that the dispatcher should route I/O through via the
    /// `HostPipe` `OpenDescription` variant. `is_read_end` controls
    /// which direction the dispatcher treats as live; for chardevs
    /// like `/dev/null` that are effectively bidirectional, set it to
    /// `!write_requested`.
    HostFd {
        host_fd: i32,
        is_read_end: bool,
        status_flags: u32,
    },
    /// In-memory bytes. Used by ProcVfs/SysVfs for the synthetic
    /// `/proc/*` and `/sys/*` files; the dispatcher converts this to
    /// an `OpenDescription::SyntheticFile`.
    Bytes {
        path: String,
        contents: Vec<u8>,
        status_flags: u32,
    },
    /// A pty end backed by a host fd. The dispatcher converts this to a
    /// `HostPipe` open-description tagged with `PtyRole` so the ioctl
    /// handler treats it as a tty.
    Pty {
        host_fd: i32,
        pts_index: u32,
        is_master: bool,
        status_flags: u32,
    },
    /// A synthetic directory backed by a `Vec<DirEnt>`. The dispatcher
    /// converts this to an `OpenDescription::Directory` so `getdents64`
    /// can serve the listing. Used by `DevVfs` for `/dev` so that
    /// `ls /dev` shows the synthetic device entries rather than the
    /// (typically empty) `/dev` in the OCI image layer.
    Directory {
        path: String,
        entries: Vec<DirEnt>,
        status_flags: u32,
    },
}

/// Live dispatcher state that some VFS mounts need at `open` time
/// (e.g. `/proc/self/maps` reflecting the loaded address space).
/// Threading this through `Vfs::open` keeps the trait independent of
/// the dispatcher's internal struct.
#[derive(Default)]
pub struct OpenContext<'a> {
    pub executable_path: Option<&'a str>,
    pub argv: Option<&'a [String]>,
    pub address_space_regions: Option<&'a [ProcMapsEntry]>,
    pub brk_current: u64,
    pub mmap_next: u64,
}

/// The path-and-metadata surface of a single mount point. Open-side
/// operations (returning per-fd state) land in step 2 of the
/// migration plan — for now the dispatcher continues to drive its
/// `OpenDescription` table directly.
///
/// Every method takes the *full* absolute path the dispatcher
/// resolved; the mount table strips the prefix only for callers that
/// ask for it via [`VfsMounts::resolve_relative`]. This keeps the
/// `ProcVfs`/`SysVfs` implementations simple — they already know
/// they live under `/proc` / `/sys`.
pub trait Vfs: Send + Sync {
    fn lookup(&self, path: &str) -> Result<Metadata, VfsError>;

    fn readlink(&self, _path: &str) -> Result<PathBuf, VfsError> {
        Err(crate::linux_abi::LINUX_EINVAL)
    }

    fn readdir(&self, _path: &str) -> Result<Vec<DirEnt>, VfsError> {
        Err(crate::linux_abi::LINUX_ENOTDIR)
    }

    /// Open `path`. Returns a [`VfsHandle`] variant that the
    /// dispatcher converts into its own per-fd state. Default impl
    /// returns ENOSYS so mounts that don't support `open` don't have
    /// to implement it explicitly.
    fn open(
        &self,
        _path: &str,
        _flags: OpenFlags,
        _ctx: &OpenContext<'_>,
    ) -> Result<VfsHandle, VfsError> {
        Err(crate::linux_abi::LINUX_ENOSYS)
    }

    fn mkdir(&self, _path: &str, _mode: u32) -> Result<(), VfsError> {
        Err(crate::linux_abi::LINUX_EROFS)
    }

    fn unlink(&self, _path: &str) -> Result<(), VfsError> {
        Err(crate::linux_abi::LINUX_EROFS)
    }

    fn rmdir(&self, _path: &str) -> Result<(), VfsError> {
        Err(crate::linux_abi::LINUX_EROFS)
    }

    fn rename(&self, _from: &str, _to: &str) -> Result<(), VfsError> {
        Err(crate::linux_abi::LINUX_EROFS)
    }

    fn symlink(&self, _target: &str, _link: &str) -> Result<(), VfsError> {
        Err(crate::linux_abi::LINUX_EROFS)
    }

    fn link(&self, _from: &str, _to: &str) -> Result<(), VfsError> {
        Err(crate::linux_abi::LINUX_EROFS)
    }

    fn chmod(&mut self, _path: &str, _mode: u32) -> Result<(), VfsError> {
        Err(crate::linux_abi::LINUX_EROFS)
    }

    fn truncate(&mut self, _path: &str, _len: u64) -> Result<(), VfsError> {
        Err(crate::linux_abi::LINUX_EROFS)
    }

    /// Human-readable name for diagnostics / `--fs` reporting.
    /// Read an entire file's bytes by absolute guest path. Used by the initial
    /// ELF exec loader (`read_exec_file`), which runs before the guest has any
    /// fds and so cannot go through the normal `open`/`read` fd path. Default:
    /// unsupported (only backends that can serve an executable — e.g. a `-v`
    /// bind mount — implement it).
    fn read_file(&self, _path: &str) -> Result<Vec<u8>, VfsError> {
        Err(crate::linux_abi::LINUX_ENOSYS)
    }

    fn name(&self) -> &'static str {
        "vfs"
    }
}
