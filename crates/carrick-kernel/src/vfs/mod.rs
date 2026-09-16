//! The kernel-view filesystems: the synthetic surfaces that render Carrick's
//! own kernel state rather than storing bytes — `/proc` ([`proc::ProcVfs`]),
//! `/sys` ([`sys::SysVfs`]), `/dev` ([`dev::DevVfs`]) and `/dev/pts`
//! ([`devpts::DevptsVfs`]). They implement `carrick_vfs::Vfs` from above.
//!
//! The filesystem MODEL they plug into — the [`Vfs`](carrick_vfs::Vfs) trait,
//! the mount table, the dentry cache, the writable backends, the OCI rootfs and
//! its layer cache — lives in `carrick-vfs`, which names none of the kernel
//! state these four render.

pub mod dev;
pub mod devpts;
pub mod proc;
pub mod sys;

pub use dev::{DevVfs, VirtualConsole};
pub use devpts::{DevptsVfs, PtyRole, PtyTable};
pub use proc::{ProcVfs, SyntheticProcContext};
pub use sys::SysVfs;

/// Whether `path` names a synthetic `/proc` or `/sys` object that actually
/// exists for this caller. Answering it needs both renderers, so it lives here
/// rather than below the kernel-view split.
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
