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
//! This layer was introduced by the VFS refactor:
//! before it, the dispatcher reached into four ad-hoc code paths — inline
//! `/proc`/`/sys` generators, a `host_dev_passthrough()` + raw `libc::open`
//! block for `/dev`, and the rootfs/overlay pair — with no common contract.
//! The refactor unified all of them behind [`Vfs`] + the mount table; the only
//! surviving direct-access path is the `/` rootfs hot path described above.

use carrick_abi::{NsGid, NsUid};

pub mod bind;
pub mod dentry;
pub mod dev;
pub mod devpts;
pub mod etc_services;
pub mod mount;
pub mod proc;
pub mod resolvconf;
pub mod rootfs;
pub mod sparse_buffer;
pub mod sys;

pub use bind::BindVfs;
pub use dentry::{DentryCache, InodeIdentity};
pub use dev::DevVfs;
pub use devpts::{DevptsVfs, PtyRole, PtyTable};
pub use etc_services::EtcServicesVfs;
pub use mount::VfsMounts;
pub use proc::{
    GuestMemoryRange, GuestReportedArch, ProcMapSharing, ProcMapsEntry, ProcVfs,
    SyntheticProcContext, SyntheticProcIdentity, SyntheticProcProcess, SyntheticProcThread,
    SyntheticProcZombie,
};
pub use resolvconf::{HostResolverLaunchError, HostResolverSnapshot, ResolvConfVfs};
pub use rootfs::RootFsVfs;
pub use sparse_buffer::SparseBuffer;
pub use sys::SysVfs;

/// Maximum size Carrick will materialize as a `Vec<u8>` for memory-backed
/// regular files. Larger files need a host-backed fd so growth remains sparse.
pub const MAX_IN_MEMORY_FILE_SIZE: u64 = 512 * 1024 * 1024;

pub(crate) fn is_synthetic_virtual_file(path: &str, ctx: &SyntheticProcContext) -> bool {
    may_be_synthetic_virtual_path(path)
        && (proc::synthetic_file(path, ctx).is_some() || sys::synthetic_file(path).is_some())
}

/// Whether `path` can name a synthetic `/proc` or `/sys` object at all. Every
/// synthetic file, directory and magic link lives under one of those two
/// roots, so a caller that only needs to CLASSIFY a path checks this before
/// assembling a [`SyntheticProcContext`] — that assembly snapshots the address
/// space, walks the task graph and reads `/etc/passwd`+`/etc/group` from the
/// rootfs, which was ~7 host `openat`s per guest `unlink` of an ordinary file.
pub(crate) fn may_be_synthetic_virtual_path(path: &str) -> bool {
    path.starts_with("/proc") || path.starts_with("/sys")
}

use std::path::PathBuf;

/// Linux errno reported by a [`Vfs`] failure. The typed
/// [`LinuxErrno`](crate::linux_abi::LinuxErrno)
/// matches the dispatcher's error pipeline (the `LINUX_E*` constants and
/// `DispatchError::Errno`), so leaf-level mounts return typed errno values
/// with no translation layer.
pub type VfsError = crate::linux_abi::LinuxErrno;

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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyntheticDeviceKind {
    Null,
    Zero,
    Full,
    Random,
    Urandom,
}

impl SyntheticDeviceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Null => "/dev/null",
            Self::Zero => "/dev/zero",
            Self::Full => "/dev/full",
            Self::Random => "/dev/random",
            Self::Urandom => "/dev/urandom",
        }
    }

    pub const fn rdev(self) -> u64 {
        // Standard Linux character device major 1, minors:
        // 3: /dev/null, 5: /dev/zero, 7: /dev/full, 8: /dev/random, 9: /dev/urandom
        match self {
            Self::Null => (1 << 8) | 3,
            Self::Zero => (1 << 8) | 5,
            Self::Full => (1 << 8) | 7,
            Self::Random => (1 << 8) | 8,
            Self::Urandom => (1 << 8) | 9,
        }
    }
}

/// What a successful [`Vfs::open`] returns. Each variant carries just
/// enough information for the dispatcher to construct its own private
/// `OpenDescription` *without* the mount needing to know about that enum —
/// the variant names *what kind of thing* was opened, and the dispatcher
/// owns the fd-table bookkeeping. Which mount returns which variant:
///
/// * [`HostFd`](VfsHandle::HostFd) — a real macOS fd, returned by [`DevVfs`]
///   for char-device passthrough; the dispatcher wraps it as a `HostPipe`.
/// * [`SyntheticDevice`](VfsHandle::SyntheticDevice) — an in-memory synthetic
///   device (`/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`);
///   the dispatcher serves I/O without passing to host libc.
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
#[derive(Debug, Clone)]
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
    /// An in-memory synthetic character device (`/dev/null`, `/dev/zero`, etc.).
    SyntheticDevice {
        kind: SyntheticDeviceKind,
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
    /// A writable or read-only in-memory regular file backed by a shared buffer.
    /// The dispatcher routes reads, writes, truncates and memory-mapping directly
    /// to `contents`.
    InMemoryFile {
        path: String,
        contents: std::sync::Arc<parking_lot::RwLock<SparseBuffer>>,
        status_flags: u32,
        writable: bool,
        max_size: usize,
    },
}

impl PartialEq for VfsHandle {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::HostFd {
                    host_fd: h1,
                    is_read_end: r1,
                    status_flags: s1,
                },
                Self::HostFd {
                    host_fd: h2,
                    is_read_end: r2,
                    status_flags: s2,
                },
            ) => h1 == h2 && r1 == r2 && s1 == s2,
            (
                Self::SyntheticDevice {
                    kind: k1,
                    status_flags: s1,
                },
                Self::SyntheticDevice {
                    kind: k2,
                    status_flags: s2,
                },
            ) => k1 == k2 && s1 == s2,
            (
                Self::Bytes {
                    path: p1,
                    contents: c1,
                    status_flags: s1,
                },
                Self::Bytes {
                    path: p2,
                    contents: c2,
                    status_flags: s2,
                },
            ) => p1 == p2 && c1 == c2 && s1 == s2,
            (
                Self::Pty {
                    host_fd: h1,
                    pts_index: i1,
                    is_master: m1,
                    status_flags: s1,
                },
                Self::Pty {
                    host_fd: h2,
                    pts_index: i2,
                    is_master: m2,
                    status_flags: s2,
                },
            ) => h1 == h2 && i1 == i2 && m1 == m2 && s1 == s2,
            (
                Self::Directory {
                    path: p1,
                    entries: e1,
                    status_flags: s1,
                },
                Self::Directory {
                    path: p2,
                    entries: e2,
                    status_flags: s2,
                },
            ) => p1 == p2 && e1 == e2 && s1 == s2,
            (
                Self::InMemoryFile {
                    path: p1,
                    contents: c1,
                    status_flags: s1,
                    writable: w1,
                    max_size: m1,
                },
                Self::InMemoryFile {
                    path: p2,
                    contents: c2,
                    status_flags: s2,
                    writable: w2,
                    max_size: m2,
                },
            ) => p1 == p2 && std::sync::Arc::ptr_eq(c1, c2) && s1 == s2 && w1 == w2 && m1 == m2,
            _ => false,
        }
    }
}

impl Eq for VfsHandle {}

/// Live dispatcher state that some VFS mounts need at `open` time
/// (e.g. `/proc/self/maps` reflecting the loaded address space).
/// Threading this through `Vfs::open` keeps the trait independent of
/// the dispatcher's internal struct.
use std::borrow::Cow;
use std::cell::OnceCell;

pub enum LazyProvider<'a, T> {
    Ref(&'a (dyn Fn() -> T + 'a)),
    Boxed(Box<dyn Fn() -> T + 'a>),
}

pub struct LazyField<'a, T> {
    cell: OnceCell<T>,
    provider: Option<LazyProvider<'a, T>>,
}

impl<'a, T> Default for LazyField<'a, T> {
    fn default() -> Self {
        Self {
            cell: OnceCell::new(),
            provider: None,
        }
    }
}

impl<'a, T: std::fmt::Debug> std::fmt::Debug for LazyField<'a, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyField")
            .field("cell", &self.cell)
            .finish()
    }
}

impl<'a, T> LazyField<'a, T> {
    pub fn new(provider: &'a (dyn Fn() -> T + 'a)) -> Self {
        Self {
            cell: OnceCell::new(),
            provider: Some(LazyProvider::Ref(provider)),
        }
    }

    pub fn new_boxed(provider: Box<dyn Fn() -> T + 'a>) -> Self {
        Self {
            cell: OnceCell::new(),
            provider: Some(LazyProvider::Boxed(provider)),
        }
    }

    pub fn from_value(value: T) -> Self {
        let cell = OnceCell::new();
        let _ = cell.set(value);
        Self {
            cell,
            provider: None,
        }
    }

    pub fn get(&self) -> Option<&T> {
        if let Some(val) = self.cell.get() {
            return Some(val);
        }
        if let Some(ref provider) = self.provider {
            let val = match provider {
                LazyProvider::Ref(f) => f(),
                LazyProvider::Boxed(f) => f(),
            };
            let _ = self.cell.set(val);
            return self.cell.get();
        }
        None
    }
}

impl<'a, T> From<T> for LazyField<'a, T> {
    fn from(val: T) -> Self {
        Self::from_value(val)
    }
}

impl<'a> LazyField<'a, Option<Cow<'a, str>>> {
    pub fn from_borrowed_str(s: &'a str) -> Self {
        Self::from_value(Some(Cow::Borrowed(s)))
    }
}

impl<'a, T: Clone> LazyField<'a, Option<Cow<'a, [T]>>> {
    pub fn from_slice(s: &'a [T]) -> Self {
        Self::from_value(Some(Cow::Borrowed(s)))
    }
}

#[derive(Debug, Clone, Default)]
pub struct OpenContextMemorySnapshot<'a> {
    pub auxv: Cow<'a, [u8]>,
    pub address_space_regions: Option<Cow<'a, [ProcMapsEntry]>>,
    pub locked_memory: Cow<'a, [GuestMemoryRange]>,
    pub brk_current: u64,
    pub mmap_next: u64,
    pub heap_base: u64,
}

/// Live dispatcher state that some VFS mounts need at `open` time
/// (e.g. `/proc/self/maps` reflecting the loaded address space).
/// Threading this through `Vfs::open` keeps the trait independent of
/// the dispatcher's internal struct. Fields that are expensive to compute
/// are held lazily behind [`LazyField`] providers.
#[derive(Default)]
pub struct OpenContext<'a> {
    pub timerslack_ns: u64,
    pub guest_arch: GuestReportedArch,
    pub native_guest_va: bool,
    pub ruid: NsUid,
    pub euid: NsUid,
    pub suid: NsUid,
    pub rgid: NsGid,
    pub egid: NsGid,
    pub sgid: NsGid,
    pub runtime_endpoint_container: Option<carrick_hal::ContainerId>,
    pub identity: Option<SyntheticProcIdentity>,

    pub executable_path: LazyField<'a, Option<Cow<'a, str>>>,
    pub argv: LazyField<'a, Option<Cow<'a, [String]>>>,
    pub task_comm: LazyField<'a, Option<Cow<'a, str>>>,
    pub guest_hostname: LazyField<'a, Option<Cow<'a, str>>>,
    pub environ: LazyField<'a, Option<Cow<'a, [Vec<u8>]>>>,
    pub open_fds: LazyField<'a, Option<Cow<'a, [i32]>>>,
    pub network: LazyField<'a, Option<Cow<'a, carrick_spec::NetworkNamespaceSpec>>>,
    pub(crate) network_model: LazyField<'a, Option<crate::network::model::LinuxNetworkModel>>,
    pub groups: LazyField<'a, Option<Cow<'a, [NsGid]>>>,
    pub signals: LazyField<'a, (u64, u64, u64)>,
    pub oom_score_adj: LazyField<'a, Option<Cow<'a, std::collections::BTreeMap<u32, i32>>>>,
    pub creds_ns: LazyField<'a, Option<crate::namespace::process::ProcessCredsNs>>,
    pub processes: LazyField<'a, Option<Cow<'a, [SyntheticProcProcess]>>>,
    pub threads: LazyField<'a, Option<Cow<'a, [SyntheticProcThread]>>>,
    pub zombies: LazyField<'a, Option<Cow<'a, [SyntheticProcZombie]>>>,
    pub sysvipc_shm: LazyField<'a, Option<Cow<'a, str>>>,
    pub sysvipc_sem: LazyField<'a, Option<Cow<'a, str>>>,
    pub sysvipc_msg: LazyField<'a, Option<Cow<'a, str>>>,
    pub mem: LazyField<'a, OpenContextMemorySnapshot<'a>>,
}

impl<'a> OpenContext<'a> {
    pub fn executable_path(&self) -> Option<&str> {
        self.executable_path.get().and_then(|opt| opt.as_deref())
    }

    pub fn argv(&self) -> Option<&[String]> {
        self.argv.get().and_then(|opt| opt.as_deref())
    }

    pub fn task_comm(&self) -> Option<&str> {
        self.task_comm.get().and_then(|opt| opt.as_deref())
    }

    pub fn guest_hostname(&self) -> Option<&str> {
        self.guest_hostname.get().and_then(|opt| opt.as_deref())
    }

    pub fn environ(&self) -> Option<&[Vec<u8>]> {
        self.environ.get().and_then(|opt| opt.as_deref())
    }

    pub fn open_fds(&self) -> Option<&[i32]> {
        self.open_fds.get().and_then(|opt| opt.as_deref())
    }

    pub fn network(&self) -> Option<&carrick_spec::NetworkNamespaceSpec> {
        self.network.get().and_then(|opt| opt.as_deref())
    }

    pub(crate) fn network_model(&self) -> Option<&crate::network::model::LinuxNetworkModel> {
        self.network_model.get().and_then(|opt| opt.as_ref())
    }

    pub fn groups(&self) -> Option<&[NsGid]> {
        self.groups.get().and_then(|opt| opt.as_deref())
    }

    pub fn sig_ignored(&self) -> u64 {
        self.signals.get().map(|s| s.0).unwrap_or(0)
    }

    pub fn sig_caught(&self) -> u64 {
        self.signals.get().map(|s| s.1).unwrap_or(0)
    }

    pub fn sig_shdpnd(&self) -> u64 {
        self.signals.get().map(|s| s.2).unwrap_or(0)
    }

    pub fn oom_score_adj(&self) -> Option<&std::collections::BTreeMap<u32, i32>> {
        self.oom_score_adj.get().and_then(|opt| opt.as_deref())
    }

    pub fn creds_ns(&self) -> Option<&crate::namespace::process::ProcessCredsNs> {
        self.creds_ns.get().and_then(|opt| opt.as_ref())
    }

    pub fn processes(&self) -> Option<&[SyntheticProcProcess]> {
        self.processes.get().and_then(|opt| opt.as_deref())
    }

    pub fn threads(&self) -> Option<&[SyntheticProcThread]> {
        self.threads.get().and_then(|opt| opt.as_deref())
    }

    pub fn zombies(&self) -> Option<&[SyntheticProcZombie]> {
        self.zombies.get().and_then(|opt| opt.as_deref())
    }

    pub fn sysvipc_shm(&self) -> Option<&str> {
        self.sysvipc_shm.get().and_then(|opt| opt.as_deref())
    }

    pub fn sysvipc_sem(&self) -> Option<&str> {
        self.sysvipc_sem.get().and_then(|opt| opt.as_deref())
    }

    pub fn sysvipc_msg(&self) -> Option<&str> {
        self.sysvipc_msg.get().and_then(|opt| opt.as_deref())
    }

    pub fn auxv(&self) -> Option<&[u8]> {
        self.mem.get().map(|m| m.auxv.as_ref())
    }

    pub fn address_space_regions(&self) -> Option<&[ProcMapsEntry]> {
        self.mem
            .get()
            .and_then(|m| m.address_space_regions.as_deref())
    }

    pub fn locked_memory(&self) -> Option<&[GuestMemoryRange]> {
        self.mem.get().map(|m| m.locked_memory.as_ref())
    }

    pub fn brk_current(&self) -> u64 {
        self.mem.get().map(|m| m.brk_current).unwrap_or(0)
    }

    pub fn mmap_next(&self) -> u64 {
        self.mem.get().map(|m| m.mmap_next).unwrap_or(0)
    }

    pub fn heap_base(&self) -> u64 {
        self.mem.get().map(|m| m.heap_base).unwrap_or(0)
    }

    pub fn with_open_fds(mut self, fds: &'a [i32]) -> Self {
        self.open_fds = LazyField::from_slice(fds);
        self
    }
}

impl<'a> std::fmt::Debug for OpenContext<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenContext")
            .field("timerslack_ns", &self.timerslack_ns)
            .field("guest_arch", &self.guest_arch)
            .field("ruid", &self.ruid)
            .field("euid", &self.euid)
            .finish()
    }
}

impl<'a> From<&'a SyntheticProcContext> for OpenContext<'a> {
    fn from(ctx: &'a SyntheticProcContext) -> Self {
        OpenContext {
            timerslack_ns: ctx.timerslack_ns,
            guest_arch: ctx.guest_arch,
            native_guest_va: ctx.native_guest_va,
            ruid: ctx.ruid,
            euid: ctx.euid,
            suid: ctx.suid,
            rgid: ctx.rgid,
            egid: ctx.egid,
            sgid: ctx.sgid,
            runtime_endpoint_container: ctx.runtime_endpoint_container,
            identity: ctx.identity,
            executable_path: LazyField::from_value(Some(Cow::Borrowed(&ctx.executable_path))),
            argv: LazyField::from_value(Some(Cow::Borrowed(&ctx.argv))),
            task_comm: LazyField::from_value(Some(Cow::Borrowed(&ctx.task_comm))),
            guest_hostname: LazyField::from_value(Some(Cow::Borrowed(&ctx.guest_hostname))),
            environ: LazyField::from_value(Some(Cow::Borrowed(&ctx.environ))),
            open_fds: LazyField::from_value(Some(Cow::Borrowed(&ctx.open_fds))),
            network: LazyField::from_value(Some(Cow::Borrowed(&ctx.network))),
            network_model: LazyField::from_value(ctx.network_model.clone()),
            groups: LazyField::from_value(Some(Cow::Borrowed(&ctx.groups))),
            signals: LazyField::from_value((ctx.sig_ignored, ctx.sig_caught, ctx.sig_shdpnd)),
            oom_score_adj: LazyField::from_value(Some(Cow::Borrowed(&ctx.oom_score_adj))),
            creds_ns: LazyField::from_value(Some(ctx.creds_ns.clone())),
            processes: LazyField::from_value(ctx.processes.as_deref().map(Cow::Borrowed)),
            threads: LazyField::from_value(ctx.threads.as_deref().map(Cow::Borrowed)),
            zombies: LazyField::from_value(ctx.zombies.as_deref().map(Cow::Borrowed)),
            sysvipc_shm: LazyField::from_value(Some(Cow::Borrowed(&ctx.sysvipc_shm))),
            sysvipc_sem: LazyField::from_value(Some(Cow::Borrowed(&ctx.sysvipc_sem))),
            sysvipc_msg: LazyField::from_value(Some(Cow::Borrowed(&ctx.sysvipc_msg))),
            mem: LazyField::from_value(OpenContextMemorySnapshot {
                auxv: Cow::Borrowed(&ctx.auxv),
                address_space_regions: ctx.address_space_regions.as_deref().map(Cow::Borrowed),
                locked_memory: Cow::Borrowed(&ctx.locked_memory),
                brk_current: ctx.brk_current,
                mmap_next: ctx.mmap_next,
                heap_base: ctx.heap_base,
            }),
        }
    }
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
    fn native_reexec_bind_mount(&self) -> Option<bind::NativeReexecBindMountV1> {
        None
    }

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

    /// Archive-only bounded enumeration. Implementations must stop after at
    /// most `limit + 1` entries; the ordinary `readdir` contract remains
    /// unchanged for guest getdents. Mounts that do not implement this
    /// capability fail closed instead of falling back to unbounded allocation.
    fn readdir_bounded(&self, _path: &str, _limit: usize) -> Result<Vec<DirEnt>, VfsError> {
        Err(crate::linux_abi::LINUX_ENOSYS)
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

    /// True for single-file synthetic INJECTIONS that are merely defaults the
    /// guest may override: a guest unlink/write/rename of the path detaches the
    /// injection and falls through to the writable rootfs/overlay. Read-only
    /// synthetic surfaces that are NOT guest-owned (/proc, /sys, /dev) return false.
    fn overridable(&self) -> bool {
        false
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

    /// Error returned when this mount cannot service setxattr. Mounts may
    /// distinguish an immutable filesystem (EROFS) from an unsupported xattr
    /// operation/namespace (EOPNOTSUPP) without adding an xattr data API.
    fn setxattr_unsupported_errno(&self) -> crate::linux_abi::LinuxErrno {
        crate::linux_abi::LINUX_ENOTSUP
    }

    fn create_socket(&self, _path: &str, _mode: u32) -> Result<(), VfsError> {
        Err(crate::linux_abi::LINUX_EROFS)
    }

    fn chown(
        &self,
        _path: &str,
        _uid: Option<carrick_abi::NsUid>,
        _gid: Option<carrick_abi::NsGid>,
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
