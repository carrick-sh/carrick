//! The kernel-view filesystems: the synthetic surfaces that render Carrick's
//! own kernel state rather than storing bytes. The filesystem model they
//! implement — the [`Vfs`](carrick_vfs::Vfs) trait, the mount table, the dentry
//! cache, the backends and the rootfs — lives in `carrick-vfs`.

pub mod dev;
pub mod devpts;
pub mod proc;
pub mod sys;
