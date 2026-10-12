//! The Proxmox hosts a KVM clone controller may run on. Selection is by the
//! host's own `/etc/hostname` and fails closed: an unknown host never borrows
//! another site's node, storage, bridge or protected-VM set.

use super::ScalerError;

/// How admission measures free space on the clone storage before booting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Headroom {
    /// LVM thin pool `vg/lv`: data headroom and metadata use from `lvs`.
    LvmThin { pool: &'static str },
    /// A PVE directory storage: available bytes from the PVE storage status API.
    Directory,
}

/// How a clone (and the template while it is built) gets its IPv4 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Network {
    /// The bridge's LAN serves DHCP and DNS.
    Dhcp,
    /// A private bridge with no DHCP server: VMID `v` (300-349) gets
    /// `subnet.(v - 200)/24`, with the bridge's gateway and a public resolver
    /// (the guest firewall rejects private destinations except DNS/DHCP, so
    /// no host service or host firewall rule is needed).
    Static {
        subnet: [u8; 3],
        gateway: u8,
        nameserver: &'static str,
    },
}

/// One Proxmox host's clone placement. Template 300 and clone VMIDs 308-349
/// in pool `carrick-ci` are the same on every site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Site {
    /// `/etc/hostname`, which is also the PVE node name.
    pub node: &'static str,
    /// Name on the node's PVE certificate; resolved to 127.0.0.1.
    pub api_host: &'static str,
    /// Storage holding template 300 and its linked clones.
    pub storage: &'static str,
    pub headroom: Headroom,
    /// Bridge the template's (and so every clone's) `net0` must use.
    pub bridge: &'static str,
    pub network: Network,
    pub cores: u32,
    pub memory_mib: u64,
    pub disk_gib: u32,
    /// VMs the scoped token must hold no rights over (read-only proof).
    pub protected: &'static [u16],
}

pub(super) const WILLOW: Site = Site {
    node: "willow",
    api_host: "willow.atxconsulting.com",
    storage: "local-lvm",
    headroom: Headroom::LvmThin { pool: "pve/data" },
    bridge: "vmbr0",
    network: Network::Dhcp,
    cores: 2,
    memory_mib: 4096,
    disk_gib: 64,
    protected: &[105],
};

/// The dedicated Contabo host (issue #287): NAT bridge `vmbr1` (no DHCP),
/// directory storage, and the agent-worker VMs/template protected.
pub(super) const CONTABO: Site = Site {
    node: "m28112",
    api_host: "m28112.contaboserver.net",
    storage: "local",
    headroom: Headroom::Directory,
    bridge: "vmbr1",
    network: Network::Static {
        subnet: [10, 77, 0],
        gateway: 1,
        nameserver: "1.1.1.1",
    },
    cores: 8,
    memory_mib: 16384,
    disk_gib: 100,
    protected: &[101, 102, 103, 104, 9000],
};

pub(super) const SITES: [Site; 2] = [WILLOW, CONTABO];

impl Site {
    pub(super) fn for_hostname(hostname: &str) -> Result<Site, ScalerError> {
        let hostname = hostname.trim();
        SITES
            .into_iter()
            .find(|site| site.node == hostname)
            .ok_or(ScalerError::Guard(
                "controller host is not a known KVM clone site",
            ))
    }
    pub(super) fn local() -> Result<Site, ScalerError> {
        Self::for_hostname(&std::fs::read_to_string("/etc/hostname")?)
    }
    pub(super) fn api_url(&self, path: &str) -> String {
        format!("https://{}:8006/api2/json{path}", self.api_host)
    }
    pub(super) fn api_resolve(&self) -> String {
        format!("{}:8006:127.0.0.1", self.api_host)
    }
    pub(super) fn qemu(&self, vmid: u16) -> String {
        format!("/nodes/{}/qemu/{vmid}", self.node)
    }
    pub(super) fn task_prefix(&self) -> String {
        format!("UPID:{}:", self.node)
    }
    /// Cloud-init `ipconfig0` for VMID `vmid` (template 300 or a clone).
    pub(super) fn ipconfig(&self, vmid: u16) -> Result<String, ScalerError> {
        match self.network {
            Network::Dhcp => Ok("ip=dhcp".into()),
            Network::Static {
                subnet: [a, b, c],
                gateway,
                ..
            } => {
                if !(300..=349).contains(&vmid) {
                    return Err(ScalerError::Guard("static address outside CI VMIDs"));
                }
                let host = vmid - 200;
                Ok(format!("ip={a}.{b}.{c}.{host}/24,gw={a}.{b}.{c}.{gateway}"))
            }
        }
    }
    /// A private bridge shared with other VMs: the template's `net0` must
    /// carry the PVE VM firewall (inherited by every linked clone) that
    /// admits only the gateway on that subnet. The in-guest firewall alone
    /// is not enough, because a job could undo it.
    pub(super) fn isolates_bridge(&self) -> bool {
        matches!(self.network, Network::Static { .. })
    }
    /// Cloud-init `nameserver`, only where the bridge does not provide one.
    pub(super) fn nameserver(&self) -> Option<&'static str> {
        match self.network {
            Network::Dhcp => None,
            Network::Static { nameserver, .. } => Some(nameserver),
        }
    }
    /// The template builder's inputs, one `SITE_NAME=value` per line. Every
    /// value is a bare token (no quoting needed); the script validates each.
    pub(super) fn shell_env(&self) -> Result<String, ScalerError> {
        let disk_format = match self.headroom {
            Headroom::LvmThin { .. } => "raw",
            Headroom::Directory => "qcow2",
        };
        Ok(format!(
            "SITE_NODE={}\nSITE_API_HOST={}\nSITE_STORAGE={}\nSITE_DISK_FORMAT={disk_format}\nSITE_BRIDGE={}\nSITE_CORES={}\nSITE_MEMORY_MIB={}\nSITE_DISK_GIB={}\nSITE_TEMPLATE_IPCONFIG={}\nSITE_NAMESERVER={}\nSITE_VM_FIREWALL={}\n",
            self.node,
            self.api_host,
            self.storage,
            self.bridge,
            self.cores,
            self.memory_mib,
            self.disk_gib,
            self.ipconfig(300)?,
            self.nameserver().unwrap_or("none"),
            u8::from(self.isolates_bridge()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn willow_row_is_pinned_to_the_pre_site_constants() {
        // Exactly the values live.rs hard-coded before sites existed.
        assert_eq!(
            WILLOW,
            Site {
                node: "willow",
                api_host: "willow.atxconsulting.com",
                storage: "local-lvm",
                headroom: Headroom::LvmThin { pool: "pve/data" },
                bridge: "vmbr0",
                network: Network::Dhcp,
                cores: 2,
                memory_mib: 4096,
                disk_gib: 64,
                protected: &[105],
            }
        );
        assert_eq!(WILLOW.ipconfig(308).unwrap(), "ip=dhcp");
        assert_eq!(WILLOW.nameserver(), None);
        assert_eq!(
            WILLOW.api_url("/pools/carrick-ci"),
            "https://willow.atxconsulting.com:8006/api2/json/pools/carrick-ci"
        );
        assert_eq!(
            WILLOW.api_resolve(),
            "willow.atxconsulting.com:8006:127.0.0.1"
        );
        assert_eq!(WILLOW.qemu(300), "/nodes/willow/qemu/300");
        assert_eq!(WILLOW.task_prefix(), "UPID:willow:");
    }
    #[test]
    fn contabo_row_is_pinned() {
        assert_eq!(
            CONTABO,
            Site {
                node: "m28112",
                api_host: "m28112.contaboserver.net",
                storage: "local",
                headroom: Headroom::Directory,
                bridge: "vmbr1",
                network: Network::Static {
                    subnet: [10, 77, 0],
                    gateway: 1,
                    nameserver: "1.1.1.1",
                },
                cores: 8,
                memory_mib: 16384,
                disk_gib: 100,
                protected: &[101, 102, 103, 104, 9000],
            }
        );
        assert_eq!(
            CONTABO.ipconfig(300).unwrap(),
            "ip=10.77.0.100/24,gw=10.77.0.1"
        );
        assert_eq!(
            CONTABO.ipconfig(349).unwrap(),
            "ip=10.77.0.149/24,gw=10.77.0.1"
        );
        // Static addresses never reach the agent workers (.11-.14) or leave
        // the CI VMID range.
        assert!(CONTABO.ipconfig(299).is_err() && CONTABO.ipconfig(350).is_err());
        assert_eq!(CONTABO.nameserver(), Some("1.1.1.1"));
        assert!(CONTABO.isolates_bridge() && !WILLOW.isolates_bridge());
        assert_eq!(CONTABO.qemu(308), "/nodes/m28112/qemu/308");
    }
    #[test]
    fn template_builder_inputs_are_bare_tokens() {
        assert_eq!(
            WILLOW.shell_env().unwrap(),
            "SITE_NODE=willow\nSITE_API_HOST=willow.atxconsulting.com\nSITE_STORAGE=local-lvm\nSITE_DISK_FORMAT=raw\nSITE_BRIDGE=vmbr0\nSITE_CORES=2\nSITE_MEMORY_MIB=4096\nSITE_DISK_GIB=64\nSITE_TEMPLATE_IPCONFIG=ip=dhcp\nSITE_NAMESERVER=none\nSITE_VM_FIREWALL=0\n"
        );
        for site in SITES {
            for line in site.shell_env().unwrap().lines() {
                let (_, value) = line.split_once('=').unwrap();
                assert!(
                    !value.is_empty()
                        && value
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-._=/,".contains(&b)),
                    "{line:?}"
                );
            }
        }
    }
    #[test]
    fn site_selection_fails_closed_on_an_unknown_host() {
        assert_eq!(Site::for_hostname("willow\n").unwrap(), WILLOW);
        assert_eq!(Site::for_hostname("m28112").unwrap(), CONTABO);
        for host in [
            "",
            "Willow",
            "willow2",
            "carrick-ctb-w1",
            "m28112.contaboserver.net",
        ] {
            assert!(
                matches!(Site::for_hostname(host), Err(ScalerError::Guard(_))),
                "{host:?} selected a site"
            );
        }
    }
    #[test]
    fn site_nodes_are_unique_and_never_protect_the_clone_range() {
        for (i, a) in SITES.iter().enumerate() {
            for b in &SITES[i + 1..] {
                assert_ne!(a.node, b.node);
            }
            assert!(a.protected.iter().all(|id| !(300..=349).contains(id)));
        }
    }
}
