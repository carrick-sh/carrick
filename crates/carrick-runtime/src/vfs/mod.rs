//! Unified virtual filesystem layer for carrick.
//!
//! # Theory of operation
//!
//! Every guest filesystem syscall — `openat`, `stat`/`statx`, `readlinkat`,
//! `getdents64`, `unlinkat`, `mkdirat`, `renameat2`, `symlinkat`, `linkat`,
//! `fchmodat`, `utimensat`, … — resolves an absolute guest path and then asks
//! one question: *who owns this path?* The answer is a [`Vfs`] implementation.
//! This module is the routing layer that turns a path into the mount that
//! serves it, plus the trait every mount implements and the small set of
//! value types ([`Metadata`], [`DirEnt`], [`OpenFlags`], [`VfsHandle`]) that
//! cross the dispatcher↔mount boundary.
//!
//! The mental model is a stripped-down Linux mount table. [`mount::VfsMounts`]
//! holds `(mount_point, Box<dyn Vfs>)` pairs and routes each path to the
//! **longest-prefix-matching** mount on component boundaries (so `/proc-foo`
//! does *not* route to a `/proc` mount). The dispatcher installs the special
//! and synthetic surfaces into this table at guest setup (`dispatch/fs/state.rs`):
//!
//! * `/proc` → [`ProcVfs`] — synthetic procfs rendered from live dispatcher state.
//! * `/sys` → [`SysVfs`] — synthetic sysfs (CPU topology, cgroup stubs, …).
//! * `/dev` → [`DevVfs`] — passthrough to macOS's same-named char devices
//!   (`/dev/null`, `/dev/zero`, `/dev/urandom`, …) plus the guest tty.
//! * `/dev/pts` → [`DevptsVfs`] — real macOS ptys behind a guest pts index.
//! * `/etc/resolv.conf` → [`ResolvConfVfs`] and `/etc/services` →
//!   [`EtcServicesVfs`] — single-file mounts that inject host-derived config
//!   the OCI scratch lacks (the `docker run --net host` contract).
//! * `/dev/shm` and any `-v` bind → [`BindVfs`] — a host directory exposed at
//!   a guest path with Linux errno translation.
//!
//! ## The `/` mount is special: it is NOT in the table
//!
//! There is no `/` entry in [`mount::VfsMounts`]. The rootfs is the *fallback*:
//! when [`VfsMounts::resolve`] returns `None`, the path is served by the
//! dispatcher's [`RootFsVfs`] field (`fs.rootfs_vfs`) — the immutable OCI
//! rootfs ([`crate::rootfs::RootFs`]) with a writable overlay
//! ([`crate::fs_backend::FsBackend`]) layered on top. This split is deliberate:
//! the synthetic/special mounts are few, small, and side-effect-light, so a
//! trait object behind a longest-prefix walk is cheap; the `/` mount is the
//! hot path touched by nearly every fs syscall, so the dispatcher still reaches
//! into `rootfs_vfs.rootfs` and `rootfs_vfs.overlay` directly (and through
//! [`RootFsVfs::open_for_dispatch`]) rather than paying trait-object dispatch
//! on every lookup. `RootFsVfs` also *implements* [`Vfs`], and its trait
//! methods consult exactly the same overlay+rootfs state, so the two access
//! paths are byte-identical; the direct-field access is a performance and
//! incrementality choice, not a correctness fork.
//!
//! ## Errno-native, path-native interface
//!
//! Two design choices keep the trait thin:
//!
//! * Failures are raw Linux errno [`i32`] ([`VfsError`]), the same currency
//!   the dispatcher's error pipeline already speaks — no per-mount translation
//!   layer. A read-only mount returns `EROFS` from the mutating defaults; an
//!   absent path returns `ENOENT`; an unimplemented op returns `ENOSYS`.
//! * Every method receives the **full absolute guest path** the dispatcher
//!   resolved, not a mount-relative tail. Mounts like `ProcVfs`/`SysVfs`
//!   already know they live under `/proc`/`/sys` and match on the whole path,
//!   so stripping the prefix would only churn allocations. Backends that
//!   prefer the relative form ask for it explicitly via
//!   [`VfsMounts::resolve_relative`].
//!
//! ## Open returns a handle, not an fd
//!
//! [`Vfs::open`] returns a [`VfsHandle`] discriminated union — a host fd, an
//! in-memory byte blob, a synthetic directory listing, or a pty end — that
//! the dispatcher converts into its own private `OpenDescription`. This keeps
//! the trait independent of the dispatcher's fd-table internals: a mount
//! describes *what kind of thing* it opened; the dispatcher owns how that
//! becomes a guest fd. Live state a mount needs at open time (the loaded
//! address space for `/proc/self/maps`, argv/environ/auxv, signal masks) is
//! threaded through [`OpenContext`] rather than coupling the trait to the
//! dispatcher struct.
//!
//! ## History
//!
//! This layer was introduced by the VFS refactor (`memory/plan_vfs_refactor.md`):
//! before it, the dispatcher reached into four ad-hoc code paths — inline
//! `/proc`/`/sys` generators, a `host_dev_passthrough()` + raw `libc::open`
//! block for `/dev`, and the rootfs/overlay pair — with no common contract.
//! The refactor unified all of them behind [`Vfs`] + the mount table; the only
//! surviving direct-access path is the `/` rootfs hot path described above.

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

#[derive(Debug)]
pub struct WatchFd {
    pub host_fd: i32,
    pub name: Option<Vec<u8>>,
    pub scan_dir: Option<PathBuf>,
}

impl WatchFd {
    pub(crate) fn unnamed(host_fd: i32) -> Self {
        Self {
            host_fd,
            name: None,
            scan_dir: None,
        }
    }

    pub(crate) fn named(host_fd: i32, name: Vec<u8>) -> Self {
        Self {
            host_fd,
            name: Some(name),
            scan_dir: None,
        }
    }

    pub(crate) fn scanning_directory(host_fd: i32, host_path: PathBuf) -> Self {
        Self {
            host_fd,
            name: None,
            scan_dir: Some(host_path),
        }
    }
}

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

/// What a successful [`Vfs::open`] returns. Each variant carries just
/// enough information for the dispatcher to construct its own private
/// `OpenDescription` *without* the mount needing to know about that enum —
/// the variant names *what kind of thing* was opened, and the dispatcher
/// owns the fd-table bookkeeping. Which mount returns which variant:
///
/// * [`HostFd`](VfsHandle::HostFd) — a real macOS fd, returned by [`DevVfs`]
///   for char-device passthrough; the dispatcher wraps it as a `HostPipe`.
/// * [`Bytes`](VfsHandle::Bytes) — an in-memory blob, returned by the
///   synthetic mounts ([`ProcVfs`], [`SysVfs`], [`ResolvConfVfs`],
///   [`EtcServicesVfs`]); becomes `OpenDescription::SyntheticFile`.
/// * [`Pty`](VfsHandle::Pty) — a master/slave pty end, returned by [`DevVfs`]
///   (`/dev/ptmx`, `/dev/tty`) and [`DevptsVfs`] (`/dev/pts/N`); becomes a
///   `HostPipe` tagged with [`PtyRole`] so the ioctl handler treats it as a tty.
/// * [`Directory`](VfsHandle::Directory) — a synthetic listing served entirely
///   from a `Vec<DirEnt>` in memory, returned by [`DevVfs`] for `/dev` so
///   `ls /dev` shows the device nodes rather than the (typically empty) `/dev`
///   in the OCI image layer. The rootfs `/` mount serves its directories
///   through [`RootFsVfs::open_for_dispatch`] instead, not this variant.
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
    /// Guest environment (`KEY=VALUE`, opaque bytes) for `/proc/self/environ`.
    pub environ: Option<&'a [Vec<u8>]>,
    /// The guest's currently-open fd numbers, for the `/proc/self/fd` directory
    /// listing. A snapshot — the listing only needs the numbers, not live state.
    pub open_fds: Option<&'a [i32]>,
    /// The serialized ELF auxv byte image, for `/proc/self/auxv`.
    pub auxv: Option<&'a [u8]>,
    pub address_space_regions: Option<&'a [ProcMapsEntry]>,
    pub brk_current: u64,
    pub mmap_next: u64,
    pub euid: u32,
    pub egid: u32,
    /// Signal-disposition masks for `/proc/<pid>/status` (bit `signum-1`):
    /// ignored (SigIgn), caught/handled (SigCgt), shared-pending (ShdPnd).
    pub sig_ignored: u64,
    pub sig_caught: u64,
    pub sig_shdpnd: u64,
}

/// One mount's view of the filesystem: path metadata ([`lookup`](Vfs::lookup),
/// [`readlink`](Vfs::readlink), [`readdir`](Vfs::readdir)), the open side
/// ([`open`](Vfs::open), returning a [`VfsHandle`]), and the mutating ops
/// (`mkdir`/`unlink`/`rename`/`chmod`/…). Almost every method has a default
/// body so a mount only overrides what it actually supports: read-only mounts
/// inherit `EROFS` for the mutators, metadata-only mounts inherit `ENOSYS`
/// for [`open`](Vfs::open), and so on. This is why a single-file synthetic
/// mount like [`ResolvConfVfs`] can be a handful of methods.
///
/// Every method takes the *full* absolute path the dispatcher resolved; the
/// mount table strips the prefix only for callers that ask for it via
/// [`VfsMounts::resolve_relative`]. This keeps the `ProcVfs`/`SysVfs`
/// implementations simple — they already know they live under `/proc` / `/sys`
/// and match on the whole path.
///
/// The trait is `Send + Sync` because the mount table is shared across the
/// guest's per-thread vCPUs; mounts that hold mutable host state (the pty
/// table, the writable overlay) carry their own interior locking.
pub trait Vfs: Send + Sync {
    fn lookup(&self, path: &str) -> Result<Metadata, VfsError>;

    fn lookup_nofollow(&self, path: &str) -> Result<Metadata, VfsError> {
        self.lookup(path)
    }

    fn real_stat(&self, _path: &str, _follow: bool) -> Option<crate::fs_backend::RealStat> {
        None
    }

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

    fn watch_fd(&self, _path: &str) -> Result<i32, VfsError> {
        Err(crate::linux_abi::LINUX_ENOSYS)
    }

    fn watch_fds(&self, path: &str) -> Result<Vec<WatchFd>, VfsError> {
        self.watch_fd(path)
            .map(|host_fd| vec![WatchFd::unnamed(host_fd)])
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

    fn chmod(&self, _path: &str, _mode: u32) -> Result<(), VfsError> {
        Err(crate::linux_abi::LINUX_EROFS)
    }

    fn create_socket(&self, _path: &str, _mode: u32) -> Result<(), VfsError> {
        Err(crate::linux_abi::LINUX_EROFS)
    }

    fn chown(
        &self,
        _path: &str,
        _uid: Option<u32>,
        _gid: Option<u32>,
        _nofollow: bool,
    ) -> Result<(), VfsError> {
        Err(crate::linux_abi::LINUX_EROFS)
    }

    fn set_times(
        &self,
        _path: &str,
        _atime: Option<(i64, i64)>,
        _mtime: Option<(i64, i64)>,
        _nofollow: bool,
    ) -> Result<(), VfsError> {
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
