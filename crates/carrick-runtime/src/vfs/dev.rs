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
];
// NOTE: `/dev/tty` is handled specially (not a host passthrough): it must
// resolve to the GUEST's controlling terminal — the `carrick run -t` pty
// slave — not carrick's own host /dev/tty. See `open`.

pub struct DevVfs {
    pty_table: Arc<Mutex<PtyTable>>,
}

impl DevVfs {
    pub fn new(pty_table: Arc<Mutex<PtyTable>>) -> Self {
        Self { pty_table }
    }

    fn host_path_for(guest: &str) -> Option<&'static str> {
        PASSTHROUGHS
            .iter()
            .find(|(g, _)| *g == guest)
            .map(|(_, h)| *h)
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
        let mut entries: Vec<DirEnt> = PASSTHROUGHS
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
            .collect();
        entries.push(DirEnt {
            name: "ptmx".to_string(),
            kind: EntryKind::CharDevice,
        });
        // /dev/tty is a node (the controlling terminal), handled specially in
        // open() rather than as a host passthrough.
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
        // Opening the /dev directory itself: return a synthetic directory
        // listing so `getdents64` / `ls /dev` shows the device entries.
        if path == "/dev" {
            let entries = self.readdir("/dev").unwrap_or_default();
            return Ok(VfsHandle::Directory {
                path: "/dev".to_string(),
                entries,
                status_flags: 0,
            });
        }

        if path == "/dev/ptmx" {
            // Hold the table lock across open_master (ptsname isn't thread-safe).
            let mut table = self.pty_table.lock();
            let (master_fd, slave_name) =
                open_master(flags.nonblock).map_err(crate::dispatch::macos_to_linux_errno)?;
            let index = table.insert(slave_name, std::process::id());
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
            // slave (registered as a pts in the table). Open a fresh fd to it
            // and present it as a pty so termios/winsize/pgrp ioctls work.
            // With no controlling terminal (non-interactive), Linux returns
            // ENXIO.
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
            if std::env::var_os("CARRICK_TTY_DBG").is_some() {
                let tt = unsafe { libc::isatty(host_fd) };
                eprintln!(
                    "[DEVTTYDBG] open(/dev/tty -> {slave_name}) host_fd={host_fd} isatty={tt} oflag=0x{oflag:x}"
                );
            }
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

pub(crate) fn host_open_errno() -> i32 {
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

    fn make_dev() -> DevVfs {
        DevVfs::new(Arc::new(Mutex::new(PtyTable::new())))
    }

    #[test]
    fn lookup_known_devs() {
        let v = make_dev();
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
    fn open_null_returns_a_real_host_fd() {
        let v = make_dev();
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
        let v = make_dev();
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
        let v = make_dev();
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
