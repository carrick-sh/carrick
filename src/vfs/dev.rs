//! `/dev` mount: passthrough to macOS's same-named character devices.
//!
//! Replaces the inline `host_dev_passthrough` + `libc::open` block
//! that used to live in `dispatch.rs::open_at`. The dispatcher now
//! resolves `/dev/null` etc. through this Vfs and wraps the resulting
//! `HostFd` into its existing `HostPipe` open-description.

use std::ffi::CString;

use crate::dispatch::linux_errno;
use crate::linux_abi::{LINUX_ENOENT, LINUX_ENOTDIR};

use super::{DirEnt, EntryKind, Metadata, OpenContext, OpenFlags, Vfs, VfsError, VfsHandle};

/// macOS character devices that have the same name and semantics as
/// their Linux counterparts. `/dev/full` is mapped to `/dev/null`
/// because macOS lacks a "always-ENOSPC-on-write" device — the
/// closest available approximation discards writes, which is fine
/// for the apt/dpkg paths that probe `/dev/full` to detect the
/// device's existence.
const PASSTHROUGHS: &[(&str, &str)] = &[
    ("/dev/null", "/dev/null"),
    ("/dev/zero", "/dev/zero"),
    ("/dev/random", "/dev/random"),
    ("/dev/urandom", "/dev/urandom"),
    ("/dev/full", "/dev/null"),
    ("/dev/tty", "/dev/tty"),
];

pub struct DevVfs;

impl DevVfs {
    pub fn new() -> Self {
        Self
    }

    fn host_path_for(guest: &str) -> Option<&'static str> {
        PASSTHROUGHS
            .iter()
            .find(|(g, _)| *g == guest)
            .map(|(_, h)| *h)
    }
}

impl Default for DevVfs {
    fn default() -> Self {
        Self::new()
    }
}

impl Vfs for DevVfs {
    fn lookup(&self, path: &str) -> Result<Metadata, VfsError> {
        if path == "/dev" {
            return Ok(Metadata {
                kind: EntryKind::Directory,
                mode: 0o755,
                size: 0,
                uid: 0,
                gid: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
            });
        }
        if Self::host_path_for(path).is_some() {
            return Ok(Metadata {
                kind: EntryKind::CharDevice,
                mode: 0o666,
                size: 0,
                uid: 0,
                gid: 0,
                mtime_secs: 0,
                mtime_nanos: 0,
            });
        }
        Err(LINUX_ENOENT)
    }

    fn readdir(&self, path: &str) -> Result<Vec<DirEnt>, VfsError> {
        if path != "/dev" {
            return Err(LINUX_ENOTDIR);
        }
        Ok(PASSTHROUGHS
            .iter()
            .map(|(guest, _)| DirEnt {
                // INVARIANT: every PASSTHROUGHS guest path is a "/dev/*" literal
                // by construction, so strip_prefix("/dev/") is always Some.
                #[allow(clippy::expect_used)]
                name: guest
                    .strip_prefix("/dev/")
                    .expect("PASSTHROUGHS entries are /dev/* by construction")
                    .to_string(),
                kind: EntryKind::CharDevice,
            })
            .collect())
    }

    fn open(
        &self,
        path: &str,
        flags: OpenFlags,
        _ctx: &OpenContext<'_>,
    ) -> Result<VfsHandle, VfsError> {
        let host_path = Self::host_path_for(path).ok_or(LINUX_ENOENT)?;

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

        let cpath = CString::new(host_path).map_err(|_| crate::linux_abi::LINUX_EINVAL)?;
        // SAFETY: cpath is a valid NUL-terminated C string.
        let host_fd = unsafe { libc::open(cpath.as_ptr(), host_flags) };
        if host_fd < 0 {
            return Err(host_open_errno());
        }

        // For chardevs that are effectively bidirectional (null, zero,
        // urandom, full), use `is_read_end = !write_requested` so the
        // dispatcher's HostPipe routes read/write to the appropriate
        // syscall regardless of how the guest opened the fd.
        let is_read_end = !flags.write;
        let status_flags = if flags.nonblock {
            crate::linux_abi::LINUX_O_NONBLOCK as u32
        } else {
            0
        };

        Ok(VfsHandle::HostFd {
            host_fd,
            is_read_end,
            status_flags,
        })
    }

    fn name(&self) -> &'static str {
        "dev"
    }
}

fn host_open_errno() -> i32 {
    // SAFETY: __error returns a valid thread-local int*.
    let raw = unsafe { *libc::__error() };
    if raw == libc::ENOENT {
        LINUX_ENOENT
    } else if raw == libc::EACCES {
        crate::linux_abi::LINUX_EACCES
    } else if raw == libc::EMFILE {
        linux_errno::EMFILE
    } else {
        // Defer to the dispatcher's full translation table for
        // anything else.
        crate::dispatch::macos_to_linux_errno(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_known_devs() {
        let v = DevVfs::new();
        for (guest, _) in PASSTHROUGHS {
            let md = v.lookup(guest).expect(guest);
            assert_eq!(md.kind, EntryKind::CharDevice, "{}", guest);
            assert_eq!(md.mode, 0o666, "{}", guest);
        }
        let md = v.lookup("/dev").unwrap();
        assert_eq!(md.kind, EntryKind::Directory);
        assert_eq!(md.mode, 0o755);
    }

    #[test]
    fn lookup_unknown_dev_is_enoent() {
        let v = DevVfs::new();
        assert_eq!(v.lookup("/dev/sda1"), Err(LINUX_ENOENT));
        assert_eq!(v.lookup("/dev/loop0"), Err(LINUX_ENOENT));
    }

    #[test]
    fn readdir_lists_all_passthroughs() {
        let v = DevVfs::new();
        let entries = v.readdir("/dev").unwrap();
        let names: std::collections::BTreeSet<_> = entries.iter().map(|e| e.name.clone()).collect();
        let expected: std::collections::BTreeSet<_> =
            ["null", "zero", "random", "urandom", "full", "tty"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        assert_eq!(names, expected);
        for e in &entries {
            assert_eq!(e.kind, EntryKind::CharDevice);
        }
    }

    #[test]
    fn readdir_on_non_dev_is_enotdir() {
        let v = DevVfs::new();
        assert_eq!(v.readdir("/dev/null"), Err(LINUX_ENOTDIR));
        assert_eq!(v.readdir("/etc"), Err(LINUX_ENOTDIR));
    }

    #[test]
    fn open_null_returns_a_real_host_fd() {
        let mut v = DevVfs::new();
        let h = v
            .open(
                "/dev/null",
                OpenFlags {
                    read: true,
                    ..Default::default()
                },
                &OpenContext::default(),
            )
            .unwrap();
        match h {
            VfsHandle::HostFd {
                host_fd,
                is_read_end,
                ..
            } => {
                assert!(host_fd >= 0);
                assert!(is_read_end);
                // Close to avoid leaking the fd.
                unsafe { libc::close(host_fd) };
            }
            other => panic!("expected HostFd, got {:?}", other),
        }
    }

    #[test]
    fn open_zero_for_write_marks_is_read_end_false() {
        let mut v = DevVfs::new();
        let h = v
            .open(
                "/dev/zero",
                OpenFlags {
                    write: true,
                    ..Default::default()
                },
                &OpenContext::default(),
            )
            .unwrap();
        match h {
            VfsHandle::HostFd {
                host_fd,
                is_read_end,
                ..
            } => {
                assert!(host_fd >= 0);
                assert!(!is_read_end);
                unsafe { libc::close(host_fd) };
            }
            other => panic!("expected HostFd, got {:?}", other),
        }
    }

    #[test]
    fn open_full_aliases_to_null() {
        // /dev/full is mapped to /dev/null on macOS; open should
        // succeed regardless.
        let mut v = DevVfs::new();
        let h = v
            .open(
                "/dev/full",
                OpenFlags {
                    write: true,
                    ..Default::default()
                },
                &OpenContext::default(),
            )
            .unwrap();
        match h {
            VfsHandle::HostFd { host_fd, .. } => {
                assert!(host_fd >= 0);
                unsafe { libc::close(host_fd) };
            }
            other => panic!("expected HostFd, got {:?}", other),
        }
    }

    #[test]
    fn open_unknown_is_enoent() {
        let mut v = DevVfs::new();
        assert_eq!(
            v.open(
                "/dev/sda1",
                OpenFlags {
                    read: true,
                    ..Default::default()
                },
                &OpenContext::default(),
            ),
            Err(LINUX_ENOENT)
        );
    }

    #[test]
    fn open_nonblock_sets_status_flag() {
        let mut v = DevVfs::new();
        let h = v
            .open(
                "/dev/null",
                OpenFlags {
                    read: true,
                    nonblock: true,
                    ..Default::default()
                },
                &OpenContext::default(),
            )
            .unwrap();
        match h {
            VfsHandle::HostFd {
                host_fd,
                status_flags,
                ..
            } => {
                assert!(host_fd >= 0);
                assert_ne!(
                    status_flags & (crate::linux_abi::LINUX_O_NONBLOCK as u32),
                    0
                );
                unsafe { libc::close(host_fd) };
            }
            other => panic!("expected HostFd, got {:?}", other),
        }
    }
}
