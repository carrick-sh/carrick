//! `/dev` mount: passthrough to macOS's same-named character devices.
//!
//! Replaces the inline `host_dev_passthrough` + `libc::open` block
//! that used to live in `dispatch.rs::open_at`. The dispatcher now
//! resolves `/dev/null` etc. through this Vfs and wraps the resulting
//! `HostFd` into its existing `HostPipe` open-description.

use std::ffi::CString;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::dispatch::linux_errno;
use crate::linux_abi::{LINUX_ENOENT, LINUX_ENOTDIR};

use super::devpts::{PtyTable, open_master};
use super::{
    DirEnt, EntryKind, Metadata, OpenContext, OpenFlags, SyntheticDeviceKind, Vfs, VfsError,
    VfsHandle,
};

/// Standard Linux character devices served purely in memory.
const SYNTHETIC_DEVICES: &[(&str, SyntheticDeviceKind)] = &[
    ("/dev/null", SyntheticDeviceKind::Null),
    ("/dev/zero", SyntheticDeviceKind::Zero),
    ("/dev/random", SyntheticDeviceKind::Random),
    ("/dev/urandom", SyntheticDeviceKind::Urandom),
    ("/dev/full", SyntheticDeviceKind::Full),
];
// NOTE: `/dev/tty` is handled specially (not a synthetic device): it must
// resolve to the GUEST's controlling terminal — the `carrick run -t` pty
// slave — not carrick's own host /dev/tty. See `open`.

pub struct DevVfs {
    pty_table: Arc<Mutex<PtyTable>>,
}

impl DevVfs {
    pub fn new(pty_table: Arc<Mutex<PtyTable>>) -> Self {
        Self { pty_table }
    }

    fn synthetic_kind(guest: &str) -> Option<SyntheticDeviceKind> {
        SYNTHETIC_DEVICES
            .iter()
            .find(|(g, _)| *g == guest)
            .map(|(_, k)| *k)
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
        if path == "/dev/ptmx" || path == "/dev/tty" {
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
        if Self::synthetic_kind(path).is_some() {
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
        let mut entries: Vec<DirEnt> = SYNTHETIC_DEVICES
            .iter()
            .map(|(guest, _)| DirEnt {
                // INVARIANT: every SYNTHETIC_DEVICES guest path is a "/dev/*" literal
                // by construction, so strip_prefix("/dev/") is always Some.
                #[allow(clippy::expect_used)]
                name: guest
                    .strip_prefix("/dev/")
                    .expect("SYNTHETIC_DEVICES entries are /dev/* by construction")
                    .to_string(),
                kind: EntryKind::CharDevice,
            })
            .collect();
        entries.push(DirEnt {
            name: "ptmx".to_string(),
            kind: EntryKind::CharDevice,
        });
        // /dev/tty is a node (the controlling terminal), handled specially in
        // open() rather than as a synthetic device.
        entries.push(DirEnt {
            name: "tty".to_string(),
            kind: EntryKind::CharDevice,
        });
        entries.push(DirEnt {
            name: "pts".to_string(),
            kind: EntryKind::Directory,
        });
        Ok(entries)
    }

    fn open(
        &self,
        path: &str,
        flags: OpenFlags,
        _ctx: &OpenContext<'_>,
    ) -> Result<VfsHandle, VfsError> {
        if path == "/dev" {
            if !flags.directory && flags.write {
                return Err(crate::linux_abi::LINUX_EISDIR);
            }
            let entries = self.readdir(path)?;
            let status_flags = if flags.nonblock {
                crate::linux_abi::LINUX_O_NONBLOCK as u32
            } else {
                0
            };
            return Ok(VfsHandle::Directory {
                path: path.to_string(),
                entries,
                status_flags,
            });
        }

        if path == "/dev/ptmx" {
            let mut table = self.pty_table.lock();
            let (master_fd, slave_name) =
                open_master(flags.nonblock).map_err(crate::host_to_linux_errno)?;
            let index = table.insert(slave_name, 1);
            let status_flags = if flags.nonblock {
                crate::linux_abi::LINUX_O_NONBLOCK as u32
            } else {
                0
            };
            return Ok(VfsHandle::Pty {
                host_fd: master_fd,
                pts_index: index,
                is_master: true,
                status_flags,
            });
        }

        if path == "/dev/tty" {
            // The guest's controlling terminal is the `carrick run -t` pty
            // slave (registered as a pts in the table).
            let table = self.pty_table.lock();
            let index = table.controlling().ok_or(crate::linux_abi::LINUX_ENXIO)?;
            let slave_name = table
                .slave_name(index)
                .ok_or(crate::linux_abi::LINUX_ENXIO)?;
            drop(table);
            let mut oflag = if flags.read && flags.write {
                libc::O_RDWR
            } else if flags.write {
                libc::O_WRONLY
            } else {
                libc::O_RDONLY
            };
            oflag |= libc::O_NOCTTY;
            if flags.nonblock {
                oflag |= libc::O_NONBLOCK;
            }
            let cpath =
                CString::new(slave_name.clone()).map_err(|_| crate::linux_abi::LINUX_EINVAL)?;
            // SAFETY: cpath is a valid NUL-terminated path to the host slave pty.
            let host_fd = unsafe { libc::open(cpath.as_ptr(), oflag) };
            if host_fd < 0 {
                return Err(host_open_errno());
            }
            let status_flags = if flags.nonblock {
                crate::linux_abi::LINUX_O_NONBLOCK as u32
            } else {
                0
            };
            return Ok(VfsHandle::Pty {
                host_fd,
                pts_index: index,
                is_master: false,
                status_flags,
            });
        }

        if let Some(kind) = Self::synthetic_kind(path) {
            let status_flags = if flags.nonblock {
                crate::linux_abi::LINUX_O_NONBLOCK as u32
            } else {
                0
            };
            return Ok(VfsHandle::SyntheticDevice { kind, status_flags });
        }

        Err(LINUX_ENOENT)
    }

    fn name(&self) -> &'static str {
        "dev"
    }
}

pub(crate) fn host_open_errno() -> crate::linux_abi::LinuxErrno {
    let raw = carrick_portable::errno();

    if raw == libc::ENOENT {
        LINUX_ENOENT
    } else if raw == libc::EACCES {
        crate::linux_abi::LINUX_EACCES
    } else if raw == libc::EMFILE {
        linux_errno::EMFILE
    } else {
        // Defer to the dispatcher's full translation table for
        // anything else.
        crate::host_to_linux_errno(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dev() -> DevVfs {
        DevVfs::new(Arc::new(Mutex::new(PtyTable::new())))
    }

    #[test]
    fn lookup_known_devs() {
        let v = make_dev();
        for (guest, _) in SYNTHETIC_DEVICES {
            let md = v.lookup(guest).expect(guest);
            assert_eq!(md.kind, EntryKind::CharDevice, "{}", guest);
            assert_eq!(md.mode, 0o666, "{}", guest);
        }
        let md = v.lookup("/dev").unwrap();
        assert_eq!(md.kind, EntryKind::Directory);
        assert_eq!(md.mode, 0o755);
    }

    #[test]
    fn lookup_ptmx() {
        let v = make_dev();
        let md = v.lookup("/dev/ptmx").unwrap();
        assert_eq!(md.kind, EntryKind::CharDevice);
        assert_eq!(md.mode, 0o666);
    }

    #[test]
    fn lookup_unknown_dev_is_enoent() {
        let v = make_dev();
        assert_eq!(v.lookup("/dev/sda1"), Err(LINUX_ENOENT));
        assert_eq!(v.lookup("/dev/loop0"), Err(LINUX_ENOENT));
    }

    #[test]
    fn readdir_lists_all_passthroughs() {
        let v = make_dev();
        let entries = v.readdir("/dev").unwrap();
        let names: std::collections::BTreeSet<_> = entries.iter().map(|e| e.name.clone()).collect();
        let expected: std::collections::BTreeSet<_> = [
            "null", "zero", "random", "urandom", "full", "tty", "ptmx", "pts",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(names, expected);
        // "pts" is a directory; all others are character devices.
        for e in &entries {
            if e.name == "pts" {
                assert_eq!(e.kind, EntryKind::Directory, "pts should be a directory");
            } else {
                assert_eq!(
                    e.kind,
                    EntryKind::CharDevice,
                    "{} should be CharDevice",
                    e.name
                );
            }
        }
    }

    #[test]
    fn readdir_on_non_dev_is_enotdir() {
        let v = make_dev();
        assert_eq!(v.readdir("/dev/null"), Err(LINUX_ENOTDIR));
        assert_eq!(v.readdir("/etc"), Err(LINUX_ENOTDIR));
    }

    #[test]
    fn open_synthetic_devices_returns_synthetic_handle() {
        let v = make_dev();
        for (guest, expected_kind) in SYNTHETIC_DEVICES {
            let h = v
                .open(
                    guest,
                    OpenFlags {
                        read: true,
                        write: true,
                        ..Default::default()
                    },
                    &OpenContext::default(),
                )
                .unwrap();
            match h {
                VfsHandle::SyntheticDevice { kind, status_flags } => {
                    assert_eq!(kind, *expected_kind, "path: {guest}");
                    assert_eq!(status_flags, 0);
                }
                other => panic!("expected SyntheticDevice for {guest}, got {:?}", other),
            }
        }
    }

    #[test]
    fn open_unknown_is_enoent() {
        let v = make_dev();
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
        let v = make_dev();
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
            VfsHandle::SyntheticDevice { status_flags, .. } => {
                assert_ne!(
                    status_flags & (crate::linux_abi::LINUX_O_NONBLOCK as u32),
                    0
                );
            }
            other => panic!("expected SyntheticDevice, got {:?}", other),
        }
    }

    #[test]
    fn dev_ptmx_open_allocates_pty() {
        let table = Arc::new(Mutex::new(PtyTable::new()));
        let dev = DevVfs::new(Arc::clone(&table));
        assert_eq!(dev.lookup("/dev/ptmx").unwrap().kind, EntryKind::CharDevice);
        let h = dev
            .open(
                "/dev/ptmx",
                OpenFlags {
                    read: true,
                    write: true,
                    ..Default::default()
                },
                &OpenContext::default(),
            )
            .unwrap();
        match h {
            VfsHandle::Pty {
                is_master,
                pts_index,
                host_fd,
                ..
            } => {
                assert!(is_master);
                assert_eq!(pts_index, 0);
                assert!(table.lock().slave_name(0).is_some());
                unsafe { libc::close(host_fd) };
            }
            other => panic!("expected Pty, got {:?}", other),
        }
    }
}
