//! `/proc` mount.
//!
//! Wraps the existing `synthetic_proc_file` registry that lives in
//! `dispatch.rs`. Step 3 of the VFS migration plan deliberately
//! *delegates* rather than copying the per-file generators so the
//! risk of accidentally diverging the byte output is zero. Future
//! cleanup can lift the generators into this module.

use crate::dispatch::SyntheticProcContext;
use crate::linux_abi::{LINUX_EACCES, LINUX_ENOENT, LINUX_ENOTDIR};

use super::{DirEnt, EntryKind, Metadata, OpenContext, OpenFlags, Vfs, VfsError, VfsHandle};

/// `(., .., <tid>...)` entries for a `/proc/<pid>/task/` (optionally
/// trailing-slashed) path, or `None` if the path isn't a task dir we serve.
fn proc_task_dir_entries(path: &str) -> Option<Vec<DirEnt>> {
    let p = path.strip_suffix('/').unwrap_or(path);
    let pid: u32 = p.strip_prefix("/proc/")?.strip_suffix("/task")?.parse().ok()?;
    let tids = crate::dispatch::synthetic_proc_task_dir(pid)?;
    let mut entries = vec![
        DirEnt {
            name: ".".to_string(),
            kind: EntryKind::Directory,
        },
        DirEnt {
            name: "..".to_string(),
            kind: EntryKind::Directory,
        },
    ];
    entries.extend(tids.into_iter().map(|t| DirEnt {
        name: t,
        kind: EntryKind::Directory,
    }));
    Some(entries)
}

pub struct ProcVfs;

impl ProcVfs {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ProcVfs {
    fn default() -> Self {
        Self::new()
    }
}

impl Vfs for ProcVfs {
    fn lookup(&self, path: &str) -> Result<Metadata, VfsError> {
        if path == "/proc" || proc_task_dir_entries(path).is_some() {
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
        // ProcVfs is path-aware but stateless from a metadata
        // perspective: any path the synthetic registry knows about is
        // a regular file. We use a default context to peek (most
        // entries don't actually look at the context fields).
        let dummy_ctx = SyntheticProcContext {
            executable_path: String::new(),
            address_space_regions: None,
            brk_current: 0,
            mmap_next: 0,
        };
        if crate::dispatch::synthetic_proc_file(path, &dummy_ctx).is_some() {
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
        if path != "/proc" {
            return Err(LINUX_ENOTDIR);
        }
        // Listing the entire /proc registry as one flat dir is out of
        // scope for this commit (entries live in nested directories
        // like /proc/self/, /proc/sys/kernel/). The dispatcher's
        // legacy readdir path still synthesises proc layouts; this
        // method returning ENOTDIR forces fall-through, preserving
        // current behaviour.
        Err(LINUX_ENOTDIR)
    }

    fn open(
        &self,
        path: &str,
        flags: OpenFlags,
        ctx: &OpenContext<'_>,
    ) -> Result<VfsHandle, VfsError> {
        // `/proc/<pid>/task/` directory: list the process's thread tids.
        if let Some(entries) = proc_task_dir_entries(path) {
            return Ok(VfsHandle::Directory {
                path: path.to_string(),
                entries,
                status_flags: 0,
            });
        }
        // Build a SyntheticProcContext from the OpenContext.
        let synth_ctx = SyntheticProcContext {
            executable_path: ctx.executable_path.unwrap_or("").to_owned(),
            address_space_regions: ctx.address_space_regions.map(|regions| regions.to_vec()),
            brk_current: ctx.brk_current,
            mmap_next: ctx.mmap_next,
        };
        let Some(contents) = crate::dispatch::synthetic_proc_file(path, &synth_ctx) else {
            // Unknown /proc path: defer to the dispatcher's legacy
            // openat fallthrough (rootfs-backed directory entries
            // like /proc itself and /proc/self/). Returning ENOSYS
            // signals "I don't handle this".
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
        "proc"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_root_returns_directory() {
        let v = ProcVfs::new();
        let md = v.lookup("/proc").unwrap();
        assert_eq!(md.kind, EntryKind::Directory);
        assert_eq!(md.mode, 0o555);
    }

    #[test]
    fn lookup_known_file_returns_file() {
        let v = ProcVfs::new();
        let md = v.lookup("/proc/cpuinfo").unwrap();
        assert_eq!(md.kind, EntryKind::File);
        assert_eq!(md.mode, 0o444);
    }

    #[test]
    fn lookup_unknown_proc_is_enoent() {
        let v = ProcVfs::new();
        assert_eq!(v.lookup("/proc/no-such"), Err(LINUX_ENOENT));
    }

    #[test]
    fn open_cpuinfo_returns_bytes() {
        let mut v = ProcVfs::new();
        let h = v
            .open(
                "/proc/cpuinfo",
                OpenFlags {
                    read: true,
                    ..Default::default()
                },
                &OpenContext::default(),
            )
            .unwrap();
        match h {
            VfsHandle::Bytes { path, contents, .. } => {
                assert_eq!(path, "/proc/cpuinfo");
                assert!(!contents.is_empty());
                let s = String::from_utf8_lossy(&contents);
                assert!(s.contains("processor"));
            }
            _ => panic!("expected Bytes variant, got {:?}", h),
        }
    }

    #[test]
    fn open_write_is_eacces() {
        let mut v = ProcVfs::new();
        let result = v.open(
            "/proc/cpuinfo",
            OpenFlags {
                write: true,
                ..Default::default()
            },
            &OpenContext::default(),
        );
        assert_eq!(result, Err(LINUX_EACCES));
    }

    #[test]
    fn open_self_cmdline_uses_executable_path() {
        let mut v = ProcVfs::new();
        let h = v
            .open(
                "/proc/self/cmdline",
                OpenFlags {
                    read: true,
                    ..Default::default()
                },
                &OpenContext {
                    executable_path: Some("/usr/bin/test-exe"),
                    ..Default::default()
                },
            )
            .unwrap();
        match h {
            VfsHandle::Bytes { contents, .. } => {
                let s = String::from_utf8_lossy(&contents);
                assert!(s.contains("test-exe"), "cmdline = {:?}", s);
            }
            _ => panic!("expected Bytes variant"),
        }
    }
}
