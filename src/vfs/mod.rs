//! Unified virtual filesystem layer for carrick.
//!
//! Today carrick reaches into four separate code paths for filesystem
//! syscalls:
//!
//! 1. **`/proc/*`** — hardcoded `match` arms in
//!    `synthetic_proc_file()` (`dispatch.rs:8321`).
//! 2. **`/sys/*`** — hardcoded `match` arms in
//!    `synthetic_sys_file()`.
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
//! For step 1, only the path-level operations are on the trait. The
//! `open` method that produces an `OpenDescription` is deferred to
//! step 2, where `DevVfs` is the first concrete user.

pub mod mount;

pub use mount::VfsMounts;

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
pub trait Vfs: Send {
    fn lookup(&self, path: &str) -> Result<Metadata, VfsError>;

    fn readlink(&self, _path: &str) -> Result<PathBuf, VfsError> {
        Err(crate::dispatch::LINUX_EINVAL)
    }

    fn readdir(&self, _path: &str) -> Result<Vec<DirEnt>, VfsError> {
        Err(crate::dispatch::LINUX_ENOTDIR)
    }

    fn mkdir(&mut self, _path: &str, _mode: u32) -> Result<(), VfsError> {
        Err(crate::dispatch::LINUX_EROFS)
    }

    fn unlink(&mut self, _path: &str) -> Result<(), VfsError> {
        Err(crate::dispatch::LINUX_EROFS)
    }

    fn rmdir(&mut self, _path: &str) -> Result<(), VfsError> {
        Err(crate::dispatch::LINUX_EROFS)
    }

    fn rename(&mut self, _from: &str, _to: &str) -> Result<(), VfsError> {
        Err(crate::dispatch::LINUX_EROFS)
    }

    fn symlink(&mut self, _target: &str, _link: &str) -> Result<(), VfsError> {
        Err(crate::dispatch::LINUX_EROFS)
    }

    fn link(&mut self, _from: &str, _to: &str) -> Result<(), VfsError> {
        Err(crate::dispatch::LINUX_EROFS)
    }

    fn chmod(&mut self, _path: &str, _mode: u32) -> Result<(), VfsError> {
        Err(crate::dispatch::LINUX_EROFS)
    }

    fn truncate(&mut self, _path: &str, _len: u64) -> Result<(), VfsError> {
        Err(crate::dispatch::LINUX_EROFS)
    }

    /// Human-readable name for diagnostics / `--fs` reporting.
    fn name(&self) -> &'static str {
        "vfs"
    }
}
