//! `/sys` mount.
//!
//! Owns Carrick's synthetic sysfs registry and renderers.

use crate::linux_abi::{LINUX_EACCES, LINUX_ENOENT, LINUX_ENOTDIR};

use super::{EntryKind, Metadata, OpenContext, OpenFlags, Vfs, VfsError, VfsHandle};

pub(crate) fn synthetic_file(path: &str) -> Option<Vec<u8>> {
    match path {
        "/sys/devices/system/cpu/online" => Some(synthetic_sys_cpu_online()),
        "/sys/devices/system/cpu/possible" => Some(synthetic_sys_cpu_possible()),
        "/sys/devices/system/cpu/present" => Some(synthetic_sys_cpu_present()),
        "/sys/devices/system/cpu/kernel_max" => Some(synthetic_sys_cpu_kernel_max()),
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

/// Per-interface attribute files Carrick synthesizes under
/// `/sys/class/net/<if>/`. Kept sorted for a stable `readdir`.
const NET_ATTRS: &[&str] = &[
    "address",
    "carrier",
    "flags",
    "ifindex",
    "mtu",
    "operstate",
    "type",
];

struct NetIface {
    name: String,
    index: u32,
    mac: [u8; 6],
    mac_len: usize,
    flags: u32,
    is_loopback: bool,
}

/// Enumerate host interfaces via `getifaddrs(3)`, one entry per `AF_LINK`
/// record (which carries the name, index, MAC, and flags). Backs the synthetic
/// `/sys/class/net` tree.
#[cfg(target_os = "macos")]
fn net_interfaces() -> Vec<NetIface> {
    let mut out = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates a list we free with freeifaddrs below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 || head.is_null() {
        return out;
    }
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: cur is a non-null node in the getifaddrs list.
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null() && (unsafe { (*ifa.ifa_addr).sa_family } as i32) == libc::AF_LINK
        {
            // SAFETY: an AF_LINK ifa_addr is a sockaddr_dl.
            let sdl = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_dl) };
            let nlen = sdl.sdl_nlen as usize;
            let alen = (sdl.sdl_alen as usize).min(6);
            let name: String = sdl
                .sdl_data
                .iter()
                .take(nlen)
                .map(|&c| c as u8 as char)
                .collect();
            let mut mac = [0u8; 6];
            for (i, slot) in mac.iter_mut().enumerate().take(alen) {
                if let Some(&c) = sdl.sdl_data.get(nlen + i) {
                    *slot = c as u8;
                }
            }
            let flags = ifa.ifa_flags as i32;
            out.push(NetIface {
                name,
                index: sdl.sdl_index as u32,
                mac,
                mac_len: alen,
                flags: ifa.ifa_flags as u32,
                is_loopback: flags & libc::IFF_LOOPBACK != 0,
            });
        }
        cur = ifa.ifa_next;
    }
    // SAFETY: free the list getifaddrs allocated.
    unsafe { libc::freeifaddrs(head) };
    out
}

#[cfg(not(target_os = "macos"))]
fn net_interfaces() -> Vec<NetIface> {
    Vec::new()
}

/// Render `/sys/class/net/<if>/<attr>` for a live interface, or `None` if the
/// path isn't a recognized attribute of a present interface.
fn synthetic_net_file(path: &str) -> Option<Vec<u8>> {
    let rest = path.strip_prefix("/sys/class/net/")?;
    let (ifname, attr) = rest.split_once('/')?;
    let iface = net_interfaces().into_iter().find(|i| i.name == ifname)?;
    let running = iface.flags as i32 & libc::IFF_RUNNING != 0;
    let body = match attr {
        "ifindex" => format!("{}\n", iface.index),
        "address" => {
            if iface.mac_len == 0 {
                "00:00:00:00:00:00\n".to_string()
            } else {
                let octets: Vec<String> = iface.mac[..iface.mac_len]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                format!("{}\n", octets.join(":"))
            }
        }
        "operstate" => if running { "up\n" } else { "down\n" }.to_string(),
        "carrier" => if running { "1\n" } else { "0\n" }.to_string(),
        "flags" => format!("0x{:x}\n", iface.flags),
        // ARPHRD_LOOPBACK (772) vs ARPHRD_ETHER (1); default MTU by type.
        "type" => if iface.is_loopback { "772\n" } else { "1\n" }.to_string(),
        "mtu" => if iface.is_loopback {
            "16384\n"
        } else {
            "1500\n"
        }
        .to_string(),
        _ => return None,
    };
    Some(body.into_bytes())
}

/// Classify a `/sys/class[/net[/<if>[/<attr>]]]` path, or `None` if it isn't a
/// recognized node.
fn net_path_kind(path: &str) -> Option<EntryKind> {
    if path == "/sys/class" || path == "/sys/class/net" {
        return Some(EntryKind::Directory);
    }
    let rest = path.strip_prefix("/sys/class/net/")?;
    match rest.split_once('/') {
        None => net_interfaces()
            .iter()
            .any(|i| i.name == rest)
            .then_some(EntryKind::Directory),
        Some((ifname, attr)) => (NET_ATTRS.contains(&attr)
            && net_interfaces().iter().any(|i| i.name == ifname))
        .then_some(EntryKind::File),
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
        if let Some(kind) = net_path_kind(path) {
            let mode = if kind == EntryKind::Directory {
                0o555
            } else {
                0o444
            };
            return Ok(Metadata {
                kind,
                mode,
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
        // /sys/class -> ["net"]; /sys/class/net -> interface names;
        // /sys/class/net/<if> -> the per-interface attribute files.
        if path == "/sys/class" {
            return Ok(vec![super::DirEnt {
                name: "net".to_string(),
                kind: EntryKind::Directory,
            }]);
        }
        if path == "/sys/class/net" {
            return Ok(net_interfaces()
                .into_iter()
                .map(|i| super::DirEnt {
                    name: i.name,
                    kind: EntryKind::Directory,
                })
                .collect());
        }
        if let Some(rest) = path.strip_prefix("/sys/class/net/")
            && !rest.contains('/')
            && net_interfaces().iter().any(|i| i.name == rest)
        {
            return Ok(NET_ATTRS
                .iter()
                .map(|a| super::DirEnt {
                    name: (*a).to_string(),
                    kind: EntryKind::File,
                })
                .collect());
        }
        Err(LINUX_ENOTDIR)
    }

    fn open(
        &self,
        path: &str,
        flags: OpenFlags,
        _ctx: &OpenContext<'_>,
    ) -> Result<VfsHandle, VfsError> {
        let Some(contents) = synthetic_file(path).or_else(|| synthetic_net_file(path)) else {
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

/// CPU range list for `online`/`possible`/`present`: `"0-9\n"` for 10 CPUs,
/// `"0\n"` for a uniprocessor — the format the kernel uses and that `nproc`,
/// `lscpu`, and `sysconf(_SC_NPROCESSORS_*)` parse. Derived from the
/// Linux-visible CPU count so it agrees with `sched_getaffinity`/`/proc/cpuinfo`.
fn cpu_range_list() -> Vec<u8> {
    let ncpu = crate::host_facts::logical_cpu_count();
    if ncpu <= 1 {
        b"0\n".to_vec()
    } else {
        format!("0-{}\n", ncpu - 1).into_bytes()
    }
}

fn synthetic_sys_cpu_online() -> Vec<u8> {
    cpu_range_list()
}

fn synthetic_sys_cpu_possible() -> Vec<u8> {
    cpu_range_list()
}

fn synthetic_sys_cpu_present() -> Vec<u8> {
    cpu_range_list()
}

fn synthetic_sys_cpu_kernel_max() -> Vec<u8> {
    // Highest CPU index the kernel could ever support (CONFIG_NR_CPUS-1).
    format!("{}\n", crate::host_facts::logical_cpu_count().max(1) - 1).into_bytes()
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

    #[cfg(target_os = "macos")]
    #[test]
    fn sys_class_net_lists_and_renders_loopback() {
        let v = SysVfs::new();
        // /sys/class/net is a directory listing the host interfaces; loopback
        // ("lo") is always present.
        assert_eq!(
            v.lookup("/sys/class/net").unwrap().kind,
            EntryKind::Directory
        );
        let ifaces = v.readdir("/sys/class/net").unwrap();
        assert!(!ifaces.is_empty(), "host interfaces should be listed");
        // Interface names mirror the host's getifaddrs view (the same source
        // carrick's netlink uses), so find the loopback by its type (772 =
        // ARPHRD_LOOPBACK) rather than hard-coding a name.
        let lo = ifaces
            .iter()
            .map(|d| d.name.clone())
            .find(|n| {
                synthetic_net_file(&format!("/sys/class/net/{n}/type")) == Some(b"772\n".to_vec())
            })
            .expect("a loopback interface");
        // It's a directory whose attribute files exist and render.
        assert_eq!(
            v.lookup(&format!("/sys/class/net/{lo}")).unwrap().kind,
            EntryKind::Directory
        );
        assert_eq!(
            v.lookup(&format!("/sys/class/net/{lo}/ifindex"))
                .unwrap()
                .kind,
            EntryKind::File
        );
        let attrs = v.readdir(&format!("/sys/class/net/{lo}")).unwrap();
        assert!(attrs.iter().any(|d| d.name == "operstate"));
        assert!(attrs.iter().any(|d| d.name == "address"));
        assert!(
            synthetic_net_file(&format!("/sys/class/net/{lo}/ifindex"))
                .unwrap()
                .len()
                > 1
        );
        // An interface that doesn't exist is ENOENT.
        assert_eq!(
            v.lookup("/sys/class/net/definitely-not-a-nic"),
            Err(LINUX_ENOENT)
        );
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
