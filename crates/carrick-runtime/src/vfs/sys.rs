//! `/sys` mount: a synthetic sysfs rendered on demand.
//!
//! # Theory of operation
//!
//! Sibling to the `/proc` mount (see [`super::proc`]): carrick has no Linux
//! kernel and so fabricates the slice of `/sys` that real software reads. Two
//! kinds of content live here:
//!
//! * **Fixed attribute files** (`synthetic_file`) — a flat path→bytes table
//!   for the kernel knobs programs probe at startup: CPU topology and online
//!   masks under `/sys/devices/system/cpu/*` (the runtime reports a real CPU
//!   count), cpufreq scaling values, transparent-hugepage policy, a per-boot
//!   random UUID, and the cgroup-v2 controller list. Values are plausible
//!   constants or host-derived facts, not live kernel state.
//! * **The `/sys/class/net` tree** — a small synthetic directory hierarchy
//!   (`class` → `net` → per-interface dirs → per-attribute files) rendered from
//!   the active Linux network model when the runtime has one, otherwise from
//!   the host's live network interfaces. Guests that enumerate interfaces via
//!   sysfs therefore see the same `lo`/`ethN` model as procfs and rtnetlink.
//!
//! Like `/proc`, `/sys` is read-only here: the [`Vfs`] mutator defaults return
//! their errors, and `open` for write is refused. The bar is the same — the
//! programs we run parse it and behave as they do under Docker — not bit-exact
//! sysfs emulation.

use crate::linux_abi::{LINUX_EACCES, LINUX_ENOENT, LINUX_ENOTDIR};

use super::{EntryKind, Metadata, OpenContext, OpenFlags, Vfs, VfsError, VfsHandle};
use crate::network::model::LinuxNetworkLink;
use carrick_abi::LINUX_IFF_RUNNING;

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

/// Render `/sys/class/net/<if>/<attr>` from the namespace's link, or `None` if
/// the path is not a recognized attribute of a link this namespace has.
///
/// Every value comes from the link the namespace holds. It used to come from a
/// live `getifaddrs(3)` walk with no name mapping at all, so a guest reading
/// `/sys/class/net` saw the Mac's own `en0`, `awdl0`, `bridge0` and `utun*`
/// while the rtnetlink dump it had just read advertised `lo` and `eth0` — and
/// `/sys/class/net/eth0/address`, the standard way to read a MAC on Linux, was
/// ENOENT.
fn synthetic_net_file_from_links(path: &str, links: &[LinuxNetworkLink]) -> Option<Vec<u8>> {
    let rest = path.strip_prefix("/sys/class/net/")?;
    let (ifname, attr) = rest.split_once('/')?;
    let link = links.iter().find(|link| link.name == ifname)?;
    let running = link.flags & LINUX_IFF_RUNNING != 0;
    let body = match attr {
        "ifindex" => format!("{}\n", link.index),
        "address" => {
            if link.hw_addr.is_empty() {
                "00:00:00:00:00:00\n".to_string()
            } else {
                let octets: Vec<String> = link
                    .hw_addr
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                format!("{}\n", octets.join(":"))
            }
        }
        "operstate" => if running { "up\n" } else { "down\n" }.to_string(),
        "carrier" => if running { "1\n" } else { "0\n" }.to_string(),
        "flags" => format!("0x{:x}\n", link.flags),
        "type" => format!("{}\n", link.arphrd),
        "mtu" => format!("{}\n", link.mtu),
        _ => return None,
    };
    Some(body.into_bytes())
}

fn net_path_kind_from_links(path: &str, links: &[LinuxNetworkLink]) -> Option<EntryKind> {
    if path == "/sys/class" || path == "/sys/class/net" {
        return Some(EntryKind::Directory);
    }
    let rest = path.strip_prefix("/sys/class/net/")?;
    match rest.split_once('/') {
        None => links
            .iter()
            .any(|link| link.name == rest)
            .then_some(EntryKind::Directory),
        Some((ifname, attr)) => (NET_ATTRS.contains(&attr)
            && links.iter().any(|link| link.name == ifname))
        .then_some(EntryKind::File),
    }
}

fn synthetic_dir_entries(path: &str) -> Option<Vec<super::DirEnt>> {
    let entries: &[(&str, EntryKind)] = match path {
        "/sys/kernel" => &[
            ("mm", EntryKind::Directory),
            ("random", EntryKind::Directory),
        ],
        "/sys/kernel/mm" => &[
            ("hugepages", EntryKind::Directory),
            ("transparent_hugepage", EntryKind::Directory),
        ],
        "/sys/kernel/mm/hugepages" => &[],
        "/sys/kernel/mm/transparent_hugepage" => {
            &[("enabled", EntryKind::File), ("defrag", EntryKind::File)]
        }
        "/sys/kernel/random" => &[("uuid", EntryKind::File), ("boot_id", EntryKind::File)],
        _ => return None,
    };
    Some(
        entries
            .iter()
            .map(|(name, kind)| super::DirEnt {
                name: (*name).to_string(),
                kind: *kind,
            })
            .collect(),
    )
}

/// The `/sys` mount.
///
/// It holds the network NAMESPACE, not a copy of its contents: `/sys/class/net`
/// is a view of whatever that namespace currently describes, so a republication
/// (the run's own model replacing the boot-time host mirror) reaches the mount
/// without remounting it. That is why there is no longer a
/// `SysVfs::from_network_model` beside `SysVfs::new` — a second constructor was
/// a second source, and the model-less one was the DEFAULT mount, which is how
/// `ls /sys/class/net` came to list `awdl0` and `utun0` on the shipping lane.
pub struct SysVfs {
    net_ns: std::sync::Arc<crate::kernel::NetNs>,
}

impl SysVfs {
    pub fn new() -> Self {
        Self {
            net_ns: std::sync::Arc::clone(crate::kernel::root_net_ns()),
        }
    }

    /// A `/sys` rendering a namespace other than the carrier's root — the shape
    /// a per-task mount takes once `unshare(CLONE_NEWNET)` is honoured, and the
    /// only way a test can assert on a view without republishing the root's.
    #[cfg(test)]
    fn in_namespace(net_ns: std::sync::Arc<crate::kernel::NetNs>) -> Self {
        Self { net_ns }
    }

    fn synthetic_net_file(&self, path: &str) -> Option<Vec<u8>> {
        synthetic_net_file_from_links(path, &self.net_ns.view().links)
    }

    fn net_path_kind(&self, path: &str) -> Option<EntryKind> {
        net_path_kind_from_links(path, &self.net_ns.view().links)
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
        if synthetic_dir_entries(path).is_some() {
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
        if let Some(kind) = self.net_path_kind(path) {
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
        if let Some(entries) = synthetic_dir_entries(path) {
            return Ok(entries);
        }
        // /sys/class -> ["net"]; /sys/class/net -> interface names;
        // /sys/class/net/<if> -> the per-interface attribute files.
        if path == "/sys/class" {
            return Ok(vec![super::DirEnt {
                name: "net".to_string(),
                kind: EntryKind::Directory,
            }]);
        }
        if path == "/sys/class/net" {
            return Ok(self
                .net_ns
                .view()
                .links
                .iter()
                .map(|link| super::DirEnt {
                    name: link.name.clone(),
                    kind: EntryKind::Directory,
                })
                .collect());
        }
        if let Some(rest) = path.strip_prefix("/sys/class/net/")
            && !rest.contains('/')
            && self
                .net_ns
                .view()
                .links
                .iter()
                .any(|link| link.name == rest)
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
        let Some(contents) = synthetic_file(path).or_else(|| self.synthetic_net_file(path)) else {
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
    fn hugepages_directory_matches_ltp_probe_path() {
        let v = SysVfs::new();
        assert_eq!(
            v.lookup("/sys/kernel/mm/hugepages").unwrap().kind,
            EntryKind::Directory
        );
        let mm_entries = v.readdir("/sys/kernel/mm").unwrap();
        assert!(mm_entries.iter().any(|entry| entry.name == "hugepages"));
        assert!(v.readdir("/sys/kernel/mm/hugepages").unwrap().is_empty());
    }

    #[test]
    fn lookup_unknown_sys_is_enoent() {
        let v = SysVfs::new();
        assert_eq!(v.lookup("/sys/no-such"), Err(LINUX_ENOENT));
    }

    /// The DEFAULT `/sys` mount — the one the shipping `--net host` lane uses —
    /// shows a Linux namespace, not the Mac.
    ///
    /// Red before this change: `SysVfs::new()` carried no network model and fell
    /// back to a raw `getifaddrs(3)` walk with no name mapping, so `ls
    /// /sys/class/net` listed `anpi0 ap1 awdl0 bridge0 en0 gif0 llw0 lo0 stf0
    /// utun0...` where Docker lists exactly `eth0 lo`. It was self-contradictory
    /// as well as wrong: the rtnetlink dump the same guest read advertised
    /// `eth0` with a hardware address while `/sys/class/net/eth0/address` — the
    /// standard way to read a MAC on Linux — was ENOENT, and
    /// `/sys/class/net/en0/address` returned the Mac's real one.
    #[test]
    fn default_sys_class_net_shows_a_linux_namespace_not_the_host() {
        let v = SysVfs::new();
        let names = v
            .readdir("/sys/class/net")
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect::<Vec<_>>();

        assert!(names.contains(&"lo".to_string()), "{names:?}");
        assert!(
            names.iter().all(|name| name == "lo"
                || name
                    .strip_prefix("eth")
                    .is_some_and(|n| n.parse::<u32>().is_ok())),
            "only Linux link names may reach the guest: {names:?}"
        );
        for host_only in ["en0", "lo0", "awdl0", "utun0", "bridge0"] {
            assert_eq!(
                v.lookup(&format!("/sys/class/net/{host_only}")),
                Err(LINUX_ENOENT),
                "{host_only} is the Mac's, not the guest's"
            );
        }

        // ARPHRD_LOOPBACK, and Linux's loopback MTU — macOS `lo0` reports 16384,
        // which is what the host-derived renderer printed.
        assert_eq!(
            synthetic_net_file_from_links("/sys/class/net/lo/type", &v.net_ns.view().links),
            Some(b"772\n".to_vec())
        );
        assert_eq!(
            synthetic_net_file_from_links("/sys/class/net/lo/mtu", &v.net_ns.view().links),
            Some(b"65536\n".to_vec())
        );
    }

    /// A `/sys` mounted in a namespace renders THAT namespace, and every
    /// attribute comes from the link the namespace holds — so `/sys` cannot
    /// disagree with the rtnetlink dump built from the same object.
    #[test]
    fn sys_class_net_renders_the_namespace_it_is_mounted_in() {
        let mut network = carrick_spec::NetworkNamespaceSpec::bridge_default(
            Some("web".to_string()),
            Vec::new(),
            Vec::new(),
        );
        network.attachments = vec![
            carrick_spec::NetworkAttachmentSpec::bridge_default(
                carrick_spec::BridgeId::new("front"),
                Some("web".to_string()),
                vec!["web-front".to_string()],
                Some(std::net::Ipv4Addr::new(172, 31, 0, 44)),
            ),
            carrick_spec::NetworkAttachmentSpec::bridge_default(
                carrick_spec::BridgeId::new("back"),
                Some("web".to_string()),
                vec!["web-back".to_string()],
                Some(std::net::Ipv4Addr::new(172, 32, 0, 44)),
            ),
        ];
        network.bridge_id = network.attachments[0].bridge_id.clone();
        network.ipv4 = network.attachments[0].ipv4;
        network.gateway_v4 = network.attachments[0].gateway_v4;
        let model = crate::network::model::LinuxNetworkModel::from_spec(&network);
        let namespace = std::sync::Arc::new(crate::kernel::NetNs::from_model(
            crate::namespace::process::alloc_ns_id(),
            model,
        ));
        let v = SysVfs::in_namespace(std::sync::Arc::clone(&namespace));

        let names = v
            .readdir("/sys/class/net")
            .unwrap()
            .into_iter()
            .map(|entry| entry.name)
            .collect::<Vec<_>>();
        assert_eq!(names, vec!["lo", "eth0", "eth1"]);
        let ifindex = v
            .open(
                "/sys/class/net/eth1/ifindex",
                OpenFlags::default(),
                &OpenContext::default(),
            )
            .unwrap();
        let VfsHandle::Bytes { contents, .. } = ifindex else {
            panic!("ifindex should open as synthetic bytes");
        };
        assert_eq!(String::from_utf8(contents).unwrap(), "3\n");
        assert_eq!(
            v.lookup("/sys/class/net/en0"),
            Err(LINUX_ENOENT),
            "a namespace-backed sysfs must not leak host interface names"
        );

        // The MAC `/sys` reports is the one the namespace assigned, which is the
        // one rtnetlink advertises in `IFLA_ADDRESS`. They were computed
        // separately before, which is how `eth0` came to have a MAC over netlink
        // and no `address` file at all.
        let address = v
            .open(
                "/sys/class/net/eth1/address",
                OpenFlags::default(),
                &OpenContext::default(),
            )
            .unwrap();
        let VfsHandle::Bytes { contents, .. } = address else {
            panic!("address should open as synthetic bytes");
        };
        assert_eq!(String::from_utf8(contents).unwrap(), "02:00:00:00:00:03\n");
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
