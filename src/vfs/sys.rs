//! `/sys` mount.
//!
//! Wraps `synthetic_sys_file` from `dispatch.rs`. Same shape as
//! [`super::proc::ProcVfs`] but with no context dependency — the
//! `/sys` entries are all static bytes.

use crate::linux_abi::{LINUX_EACCES, LINUX_ENOENT, LINUX_ENOTDIR};

use super::{
    EntryKind, Metadata, OpenContext, OpenFlags, Vfs, VfsError, VfsHandle,
};

pub struct SysVfs;

impl SysVfs {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SysVfs {
    fn default() -> Self {
        Self::new()
    }
}

impl Vfs for SysVfs {
    fn lookup(&self, path: &str) -> Result<Metadata, VfsError> {
        if path == "/sys" {
            return Ok(Metadata {
                kind: EntryKind::Directory,
                mode: 0o555,
                size: 0,
                uid: 0,
                gid: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
            });
        }
        if crate::dispatch::synthetic_sys_file(path).is_some() {
            return Ok(Metadata {
                kind: EntryKind::File,
                mode: 0o444,
                size: 0,
                uid: 0,
                gid: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
            });
        }
        Err(LINUX_ENOENT)
    }

    fn readdir(&self, path: &str) -> Result<Vec<super::DirEnt>, VfsError> {
        if path != "/sys" {
            return Err(LINUX_ENOTDIR);
        }
        Err(LINUX_ENOTDIR)
    }

    fn open(
        &mut self,
        path: &str,
        flags: OpenFlags,
        _ctx: &OpenContext<'_>,
    ) -> Result<VfsHandle, VfsError> {
        let Some(contents) = crate::dispatch::synthetic_sys_file(path) else {
            return Err(crate::linux_abi::LINUX_ENOSYS);
        };
        if flags.write {
            return Err(LINUX_EACCES);
        }
        Ok(VfsHandle::Bytes {
            path: path.to_string(),
            contents,
            status_flags: 0,
        })
    }

    fn name(&self) -> &'static str {
        "sys"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_root_returns_directory() {
        let v = SysVfs::new();
        let md = v.lookup("/sys").unwrap();
        assert_eq!(md.kind, EntryKind::Directory);
    }

    #[test]
    fn lookup_cpu_online_returns_file() {
        let v = SysVfs::new();
        let md = v.lookup("/sys/devices/system/cpu/online").unwrap();
        assert_eq!(md.kind, EntryKind::File);
    }

    #[test]
    fn lookup_unknown_sys_is_enoent() {
        let v = SysVfs::new();
        assert_eq!(v.lookup("/sys/no-such"), Err(LINUX_ENOENT));
    }

    #[test]
    fn open_cgroup_controllers_returns_bytes() {
        let mut v = SysVfs::new();
        let h = v
            .open(
                "/sys/fs/cgroup/cgroup.controllers",
                OpenFlags {
                    read: true,
                    ..Default::default()
                },
                &OpenContext::default(),
            )
            .unwrap();
        assert!(matches!(h, VfsHandle::Bytes { .. }));
    }

    #[test]
    fn open_write_is_eacces() {
        let mut v = SysVfs::new();
        let result = v.open(
            "/sys/devices/system/cpu/online",
            OpenFlags {
                write: true,
                ..Default::default()
            },
            &OpenContext::default(),
        );
        assert_eq!(result, Err(LINUX_EACCES));
    }
}
