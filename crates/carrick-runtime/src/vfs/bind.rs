use std::ffi::CString;
use std::path::{Path, PathBuf};

use crate::dispatch::macos_to_linux_errno;
use crate::linux_abi::{LINUX_EINVAL, LINUX_EROFS, LINUX_ENOENT};
use super::{DirEnt, EntryKind, Metadata, OpenContext, OpenFlags, Vfs, VfsError, VfsHandle};

pub struct BindVfs {
    mount_point: String,
    host_path: PathBuf,
    readonly: bool,
}

impl BindVfs {
    pub fn new(mount_point: impl Into<String>, host_path: impl Into<PathBuf>, readonly: bool) -> Self {
        Self {
            mount_point: mount_point.into(),
            host_path: host_path.into(),
            readonly,
        }
    }

    fn to_host(&self, guest_path: &str) -> Result<PathBuf, VfsError> {
        let relative = if guest_path == self.mount_point {
            Path::new("")
        } else if let Some(stripped) = guest_path.strip_prefix(&self.mount_point) {
            let stripped = stripped.strip_prefix('/').unwrap_or(stripped);
            Path::new(stripped)
        } else {
            return Err(LINUX_ENOENT);
        };
        Ok(self.host_path.join(relative))
    }
}

fn map_io_error(e: std::io::Error) -> VfsError {
    let raw = e.raw_os_error().unwrap_or(libc::EIO);
    macos_to_linux_errno(raw)
}

fn host_open_errno() -> i32 {
    let raw = unsafe { *libc::__error() };
    macos_to_linux_errno(raw)
}

impl Vfs for BindVfs {
    fn lookup(&self, path: &str) -> Result<Metadata, VfsError> {
        let host = self.to_host(path)?;
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(&host).map_err(map_io_error)?;
        let kind = if meta.is_dir() {
            EntryKind::Directory
        } else if meta.is_symlink() {
            EntryKind::Symlink
        } else {
            EntryKind::File
        };
        Ok(Metadata {
            kind,
            mode: meta.mode() & 0o7777,
            size: meta.len(),
            uid: meta.uid(),
            gid: meta.gid(),
            mtime_secs: meta.mtime(),
            mtime_nanos: meta.mtime_nsec() as u32,
        })
    }

    fn readlink(&self, path: &str) -> Result<PathBuf, VfsError> {
        let host = self.to_host(path)?;
        std::fs::read_link(&host).map_err(map_io_error)
    }

    fn readdir(&self, path: &str) -> Result<Vec<DirEnt>, VfsError> {
        let host = self.to_host(path)?;
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(&host).map_err(map_io_error)? {
            let entry = entry.map_err(map_io_error)?;
            let file_type = entry.file_type().map_err(map_io_error)?;
            let kind = if file_type.is_dir() {
                EntryKind::Directory
            } else if file_type.is_symlink() {
                EntryKind::Symlink
            } else {
                EntryKind::File
            };
            entries.push(DirEnt {
                name: entry.file_name().to_string_lossy().into_owned(),
                kind,
            });
        }
        Ok(entries)
    }

    fn open(
        &self,
        path: &str,
        flags: OpenFlags,
        _ctx: &OpenContext<'_>,
    ) -> Result<VfsHandle, VfsError> {
        let host = self.to_host(path)?;
        if host.is_dir() {
            let entries = self.readdir(path)?;
            return Ok(VfsHandle::Directory {
                path: path.to_owned(),
                entries,
                status_flags: 0,
            });
        }

        if self.readonly && flags.write {
            return Err(LINUX_EROFS);
        }

        let mut host_flags = if flags.read && flags.write {
            libc::O_RDWR
        } else if flags.write {
            libc::O_WRONLY
        } else {
            libc::O_RDONLY
        };
        if flags.nonblock {
            host_flags |= libc::O_NONBLOCK;
        }
        if flags.append {
            host_flags |= libc::O_APPEND;
        }
        if flags.create {
            host_flags |= libc::O_CREAT;
        }
        if flags.excl {
            host_flags |= libc::O_EXCL;
        }
        if flags.trunc {
            host_flags |= libc::O_TRUNC;
        }

        let cpath = CString::new(host.to_string_lossy().as_ref()).map_err(|_| LINUX_EINVAL)?;
        // SAFETY: host path as NUL-terminated string
        let host_fd = unsafe { libc::open(cpath.as_ptr(), host_flags, flags.mode as libc::c_int) };
        if host_fd < 0 {
            return Err(host_open_errno());
        }

        let status_flags = if flags.nonblock {
            crate::linux_abi::LINUX_O_NONBLOCK as u32
        } else {
            0
        };

        Ok(VfsHandle::HostFd {
            host_fd,
            is_read_end: !flags.write,
            status_flags,
        })
    }

    fn mkdir(&self, path: &str, mode: u32) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let host = self.to_host(path)?;
        std::fs::create_dir(&host).map_err(map_io_error)?;
        // Set mode since std::fs::create_dir doesn't take mode
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&host, std::fs::Permissions::from_mode(mode));
        Ok(())
    }

    fn unlink(&self, path: &str) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let host = self.to_host(path)?;
        std::fs::remove_file(&host).map_err(map_io_error)
    }

    fn rmdir(&self, path: &str) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let host = self.to_host(path)?;
        std::fs::remove_dir(&host).map_err(map_io_error)
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let host_from = self.to_host(from)?;
        let host_to = self.to_host(to)?;
        std::fs::rename(&host_from, &host_to).map_err(map_io_error)
    }

    fn symlink(&self, target: &str, link: &str) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let host_link = self.to_host(link)?;
        std::os::unix::fs::symlink(target, &host_link).map_err(map_io_error)
    }

    fn link(&self, from: &str, to: &str) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let host_from = self.to_host(from)?;
        let host_to = self.to_host(to)?;
        std::fs::hard_link(&host_from, &host_to).map_err(map_io_error)
    }

    fn chmod(&mut self, path: &str, mode: u32) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let host = self.to_host(path)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&host, std::fs::Permissions::from_mode(mode)).map_err(map_io_error)
    }

    fn truncate(&mut self, path: &str, len: u64) -> Result<(), VfsError> {
        if self.readonly {
            return Err(LINUX_EROFS);
        }
        let host = self.to_host(path)?;
        let file = std::fs::OpenOptions::new().write(true).open(&host).map_err(map_io_error)?;
        file.set_len(len).map_err(map_io_error)
    }

    fn name(&self) -> &'static str {
        "bind"
    }
}
