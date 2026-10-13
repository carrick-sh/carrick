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
        /// The host's own public IPv4 addresses: a clone reaching them would
        /// land on host services, so the VM firewall drops them too.
        host_public: &'static str,
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
    /// CA that signs the API certificate, when the system store does not
    /// (a PVE cluster CA). `None` = system trust (Willow's ACME certificate).
    pub api_ca: Option<&'static str>,
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
    api_ca: None,
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
    node: "carrick-ctb",
    api_host: "carrick-ctb.turkey-moth.ts.net",
    api_ca: Some("/etc/pve/pve-root-ca.pem"),
    storage: "local",
    headroom: Headroom::Directory,
    bridge: "vmbr1",
    network: Network::Static {
        subnet: [10, 77, 0],
        gateway: 1,
        nameserver: "1.1.1.1",
        host_public: "154.38.161.112",
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
            // `/etc/hostname` holds the short node name (Willow) or the
            // node's FQDN, which is its certificate name (Contabo). Nothing
            // else matches: no prefix or suffix comparison.
            .find(|site| site.node == hostname || site.api_host == hostname)
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
    /// A private bridge shared with other VMs: template 300 and every clone
    /// must carry [`Site::vm_firewall`] on `net0`. The in-guest firewall
    /// alone is not enough, because a job with root in the clone could undo it.
    pub(super) fn isolates_bridge(&self) -> bool {
        matches!(self.network, Network::Static { .. })
    }
    /// Whether template 300 and its clones may take part in KSM page
    /// merging. A site whose clones share the host with other VMs that hold
    /// credentials (the isolating sites) keeps them out: cross-VM page
    /// deduplication is a timing side channel. The PVE default (`1`) stays
    /// on other sites.
    pub(super) fn allows_ksm(&self) -> bool {
        !self.isolates_bridge()
    }
    /// The PVE VM firewall for an isolating site, as an exact rule list that
    /// the template builder writes and the controller verifies. Default
    /// deny both ways; in: SSH from the gateway only; out: IPv4 except the
    /// blocked set (RFC 1918, link-local, shared address space 100.64/10 and
    /// the host's own public addresses, which covers the gateway, the agent
    /// workers and every host service); IPv6 falls to the DROP policy.
    pub(super) fn vm_firewall(&self) -> Option<[FirewallRule; 3]> {
        if !self.isolates_bridge() {
            return None;
        }
        Some([
            FirewallRule {
                direction: "in",
                action: "ACCEPT",
                source: Some(GATEWAY_PLACEHOLDER),
                dest: None,
                proto: Some("tcp"),
                dport: Some("22"),
                comment: "controller SSH from the host",
            },
            FirewallRule {
                direction: "out",
                action: "DROP",
                source: None,
                dest: Some(BLOCKED_PLACEHOLDER),
                proto: None,
                dport: None,
                comment: "no private, shared, link-local or host destination",
            },
            FirewallRule {
                direction: "out",
                action: "ACCEPT",
                source: None,
                dest: Some("0.0.0.0/0"),
                proto: None,
                dport: None,
                comment: "remaining IPv4 through the NAT gateway",
            },
        ])
    }
    /// The gateway address of a static site, for [`FirewallRule::source`].
    pub(super) fn gateway(&self) -> Option<String> {
        match self.network {
            Network::Dhcp => None,
            Network::Static {
                subnet: [a, b, c],
                gateway,
                ..
            } => Some(format!("{a}.{b}.{c}.{gateway}")),
        }
    }
    /// The outbound DROP destinations of a static site.
    pub(super) fn blocked(&self) -> Option<String> {
        match self.network {
            Network::Dhcp => None,
            Network::Static { host_public, .. } => {
                Some(format!("{PRIVATE_V4},{SHARED_V4},{host_public}"))
            }
        }
    }
    /// `/etc/pve/firewall/<vmid>.fw` for an isolating site.
    /// The static IPv4 address of VMID `vmid` on a static site.
    pub(super) fn static_address(&self, vmid: u16) -> Result<Option<String>, ScalerError> {
        match self.network {
            Network::Dhcp => Ok(None),
            Network::Static {
                subnet: [a, b, c], ..
            } => {
                if !(300..=349).contains(&vmid) {
                    return Err(ScalerError::Guard("static address outside CI VMIDs"));
                }
                Ok(Some(format!("{a}.{b}.{c}.{}", vmid - 200)))
            }
        }
    }
    /// `/etc/pve/firewall/<vmid>.fw` for VMID `vmid` on an isolating site.
    /// PVE fills a VM's `ipfilter` set only from an explicit
    /// `ipfilter-net0` ipset (cloud-init addresses are added only for
    /// containers), so the file names the VM's own address; the controller
    /// rewrites it for each clone, which inherits the template's.
    pub(super) fn vm_firewall_file(&self, vmid: u16) -> Result<Option<String>, ScalerError> {
        let (Some(rules), Some(gateway), Some(blocked), Some(address)) = (
            self.vm_firewall(),
            self.gateway(),
            self.blocked(),
            self.static_address(vmid)?,
        ) else {
            return Ok(None);
        };
        let mut file = format!(
            "[OPTIONS]\nenable: 1\npolicy_in: DROP\npolicy_out: DROP\nipfilter: 1\nmacfilter: 1\n\n[IPSET {IPFILTER_SET}]\n{address}\n\n[RULES]\n"
        );
        for rule in rules {
            file.push_str(&rule.render(&gateway, &blocked));
            file.push('\n');
        }
        Ok(Some(file))
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
            "SITE_NODE={}\nSITE_API_HOST={}\nSITE_STORAGE={}\nSITE_DISK_FORMAT={disk_format}\nSITE_BRIDGE={}\nSITE_CORES={}\nSITE_MEMORY_MIB={}\nSITE_DISK_GIB={}\nSITE_TEMPLATE_IPCONFIG={}\nSITE_NAMESERVER={}\nSITE_VM_FIREWALL={}\nSITE_API_CA={}\nSITE_ALLOW_KSM={}\n",
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
            self.api_ca.unwrap_or("system"),
            u8::from(self.allows_ksm()),
        ))
    }
}

/// `source` value meaning "this site's gateway address".
pub(super) const GATEWAY_PLACEHOLDER: &str = "gateway";
/// The ipset PVE consults for `net0`'s `ipfilter`.
pub(super) const IPFILTER_SET: &str = "ipfilter-net0";
/// `dest` value meaning "this site's blocked destination set".
pub(super) const BLOCKED_PLACEHOLDER: &str = "blocked";
/// Every RFC 1918 and IPv4 link-local range: covers the bridge subnet, the
/// gateway and any host-side private address.
pub(super) const PRIVATE_V4: &str = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16";
/// RFC 6598 shared address space (carrier-grade NAT).
pub(super) const SHARED_V4: &str = "100.64.0.0/10";

/// One PVE firewall rule, in the fields the PVE rules API reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FirewallRule {
    pub direction: &'static str,
    pub action: &'static str,
    pub source: Option<&'static str>,
    pub dest: Option<&'static str>,
    pub proto: Option<&'static str>,
    pub dport: Option<&'static str>,
    pub comment: &'static str,
}
impl FirewallRule {
    fn resolve(field: Option<&'static str>, gateway: &str, blocked: &str) -> Option<String> {
        field.map(|value| match value {
            GATEWAY_PLACEHOLDER => gateway.to_owned(),
            BLOCKED_PLACEHOLDER => blocked.to_owned(),
            value => value.to_owned(),
        })
    }
    pub(super) fn source(&self, gateway: &str, blocked: &str) -> Option<String> {
        Self::resolve(self.source, gateway, blocked)
    }
    pub(super) fn dest(&self, gateway: &str, blocked: &str) -> Option<String> {
        Self::resolve(self.dest, gateway, blocked)
    }
    fn render(&self, gateway: &str, blocked: &str) -> String {
        let mut line = format!("{} {}", self.direction.to_uppercase(), self.action);
        if let Some(source) = self.source(gateway, blocked) {
            line.push_str(&format!(" -source {source}"));
        }
        if let Some(dest) = self.dest(gateway, blocked) {
            line.push_str(&format!(" -dest {dest}"));
        }
        if let Some(proto) = self.proto {
            line.push_str(&format!(" -p {proto}"));
        }
        if let Some(dport) = self.dport {
            line.push_str(&format!(" -dport {dport}"));
        }
        line.push_str(&format!(" -log nolog # {}", self.comment));
        line
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
                api_ca: None,
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
                node: "carrick-ctb",
                api_host: "carrick-ctb.turkey-moth.ts.net",
                api_ca: Some("/etc/pve/pve-root-ca.pem"),
                storage: "local",
                headroom: Headroom::Directory,
                bridge: "vmbr1",
                network: Network::Static {
                    subnet: [10, 77, 0],
                    gateway: 1,
                    nameserver: "1.1.1.1",
                    host_public: "154.38.161.112",
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
        assert!(!CONTABO.allows_ksm() && WILLOW.allows_ksm());
        assert_eq!(WILLOW.vm_firewall_file(300).unwrap(), None);
        assert_eq!(CONTABO.static_address(308).unwrap().unwrap(), "10.77.0.108");
        assert!(CONTABO.vm_firewall_file(350).is_err());
        assert_eq!(
            CONTABO.vm_firewall_file(300).unwrap().unwrap(),
            "[OPTIONS]\nenable: 1\npolicy_in: DROP\npolicy_out: DROP\nipfilter: 1\nmacfilter: 1\n\n[IPSET ipfilter-net0]\n10.77.0.100\n\n[RULES]\n\
IN ACCEPT -source 10.77.0.1 -p tcp -dport 22 -log nolog # controller SSH from the host\n\
OUT DROP -dest 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,100.64.0.0/10,154.38.161.112 -log nolog # no private, shared, link-local or host destination\n\
OUT ACCEPT -dest 0.0.0.0/0 -log nolog # remaining IPv4 through the NAT gateway\n"
        );
        assert_eq!(CONTABO.qemu(308), "/nodes/carrick-ctb/qemu/308");
    }
    #[test]
    fn template_builder_inputs_are_bare_tokens() {
        assert_eq!(
            WILLOW.shell_env().unwrap(),
            "SITE_NODE=willow\nSITE_API_HOST=willow.atxconsulting.com\nSITE_STORAGE=local-lvm\nSITE_DISK_FORMAT=raw\nSITE_BRIDGE=vmbr0\nSITE_CORES=2\nSITE_MEMORY_MIB=4096\nSITE_DISK_GIB=64\nSITE_TEMPLATE_IPCONFIG=ip=dhcp\nSITE_NAMESERVER=none\nSITE_VM_FIREWALL=0\nSITE_API_CA=system\nSITE_ALLOW_KSM=1\n"
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
        assert_eq!(Site::for_hostname("carrick-ctb").unwrap(), CONTABO);
        // Contabo's /etc/hostname may hold the FQDN (its Tailscale name).
        assert_eq!(
            Site::for_hostname("carrick-ctb.turkey-moth.ts.net\n").unwrap(),
            CONTABO
        );
        for host in [
            "",
            "Willow",
            "willow2",
            "carrick-ctb-w1",
            "carrick-ctb.evil.example",
            "turkey-moth.ts.net",
            "carrick-ctb.turkey-moth.ts.net.evil",
            // The pre-rename node name no longer selects a site.
            "m28112",
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
