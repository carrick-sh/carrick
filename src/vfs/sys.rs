//! `/sys` mount.
//!
//! Owns Carrick's synthetic sysfs registry and renderers.

use crate::linux_abi::{LINUX_EACCES, LINUX_ENOENT, LINUX_ENOTDIR};

use super::{EntryKind, Metadata, OpenContext, OpenFlags, Vfs, VfsError, VfsHandle};

pub(crate) fn synthetic_file(path: &str) -> Option<Vec<u8>> {
    match path {
        "/sys/devices/system/cpu/online" => Some(synthetic_sys_cpu_online().to_vec()),
        "/sys/devices/system/cpu/possible" => Some(synthetic_sys_cpu_possible().to_vec()),
        "/sys/devices/system/cpu/present" => Some(synthetic_sys_cpu_present().to_vec()),
        "/sys/devices/system/cpu/kernel_max" => Some(synthetic_sys_cpu_kernel_max().to_vec()),
        "/sys/devices/system/cpu/cpu0/online" => Some(synthetic_sys_cpu0_online().to_vec()),
        "/sys/devices/system/cpu/cpu0/topology/physical_package_id" => {
            Some(synthetic_sys_cpu0_physical_package_id().to_vec())
        }
        "/sys/devices/system/cpu/cpu0/topology/core_id" => {
            Some(synthetic_sys_cpu0_core_id().to_vec())
        }
        "/sys/devices/system/cpu/cpu0/topology/thread_siblings_list" => {
            Some(synthetic_sys_cpu0_thread_siblings_list().to_vec())
        }
        "/sys/devices/system/cpu/cpu0/topology/core_siblings_list" => {
            Some(synthetic_sys_cpu0_core_siblings_list().to_vec())
        }
        "/sys/devices/system/cpu/cpufreq/policy0/scaling_cur_freq" => {
            Some(synthetic_sys_cpufreq_scaling_cur_freq().to_vec())
        }
        "/sys/devices/system/cpu/cpufreq/policy0/scaling_max_freq" => {
            Some(synthetic_sys_cpufreq_scaling_max_freq().to_vec())
        }
        "/sys/devices/system/cpu/cpufreq/policy0/scaling_min_freq" => {
            Some(synthetic_sys_cpufreq_scaling_min_freq().to_vec())
        }
        "/sys/kernel/mm/transparent_hugepage/enabled" => Some(synthetic_sys_thp_enabled().to_vec()),
        "/sys/kernel/mm/transparent_hugepage/defrag" => Some(synthetic_sys_thp_defrag().to_vec()),
        "/sys/kernel/random/uuid" => Some(synthetic_sys_random_uuid().to_vec()),
        "/sys/kernel/random/boot_id" => Some(synthetic_sys_random_boot_id().to_vec()),
        "/sys/fs/cgroup/cgroup.controllers" => Some(synthetic_sys_cgroup_controllers().to_vec()),
        _ => None,
    }
}

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
        if synthetic_file(path).is_some() {
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
        &self,
        path: &str,
        flags: OpenFlags,
        _ctx: &OpenContext<'_>,
    ) -> Result<VfsHandle, VfsError> {
        let Some(contents) = synthetic_file(path) else {
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

fn synthetic_sys_cpu_online() -> &'static [u8] {
    b"0\n"
}

fn synthetic_sys_cpu_possible() -> &'static [u8] {
    b"0\n"
}

fn synthetic_sys_cpu_present() -> &'static [u8] {
    b"0\n"
}

fn synthetic_sys_cpu_kernel_max() -> &'static [u8] {
    b"0\n"
}

fn synthetic_sys_cpu0_online() -> &'static [u8] {
    b"1\n"
}

fn synthetic_sys_cpu0_physical_package_id() -> &'static [u8] {
    b"0\n"
}

fn synthetic_sys_cpu0_core_id() -> &'static [u8] {
    b"0\n"
}

fn synthetic_sys_cpu0_thread_siblings_list() -> &'static [u8] {
    b"0\n"
}

fn synthetic_sys_cpu0_core_siblings_list() -> &'static [u8] {
    b"0\n"
}

fn synthetic_sys_cpufreq_scaling_cur_freq() -> &'static [u8] {
    b"2400000\n"
}

fn synthetic_sys_cpufreq_scaling_max_freq() -> &'static [u8] {
    b"2400000\n"
}

fn synthetic_sys_cpufreq_scaling_min_freq() -> &'static [u8] {
    b"600000\n"
}

fn synthetic_sys_thp_enabled() -> &'static [u8] {
    b"always [madvise] never\n"
}

fn synthetic_sys_thp_defrag() -> &'static [u8] {
    b"always defer defer+madvise [madvise] never\n"
}

fn synthetic_sys_random_uuid() -> &'static [u8] {
    b"00000000-0000-4000-8000-000000000000\n"
}

fn synthetic_sys_random_boot_id() -> &'static [u8] {
    b"00000000-0000-4000-8000-000000000000\n"
}

fn synthetic_sys_cgroup_controllers() -> &'static [u8] {
    b"\n"
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
        let v = SysVfs::new();
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
        let v = SysVfs::new();
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

    #[test]
    fn sys_registry_renders_kernel_random_files() {
        let boot_id = synthetic_file("/sys/kernel/random/boot_id").unwrap();
        assert_eq!(
            String::from_utf8(boot_id).unwrap(),
            "00000000-0000-4000-8000-000000000000\n"
        );
    }
}
