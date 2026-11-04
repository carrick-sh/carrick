//! The Proxmox hosts a KVM clone controller may run on: Willow (DHCP LAN,
//! LVM thin pool, KVM clones only), Contabo and carrick-hz (private NAT
//! bridges with static addresses, KVM and agent clones). Selection is by the
//! host's own `/etc/hostname` and fails closed: an unknown host never borrows
//! another site's node, storage, bridge or protected-VM set.

use super::ScalerError;

/// The only agent base images admitted by the agent-site rollout contract
/// (the same blue/green slots on every site that has an agent template).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentTemplate {
    Blue,
    Green,
}
impl AgentTemplate {
    pub fn vmid(self) -> u16 {
        match self {
            Self::Blue => 9000,
            Self::Green => 9001,
        }
    }
}
impl TryFrom<u16> for AgentTemplate {
    type Error = ScalerError;
    fn try_from(vmid: u16) -> Result<Self, Self::Error> {
        match vmid {
            9000 => Ok(Self::Blue),
            9001 => Ok(Self::Green),
            _ => Err(ScalerError::Guard("unapproved agent template VMID")),
        }
    }
}

/// How admission measures free space on the clone storage before booting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Headroom {
    /// LVM thin pool `vg/lv`: data headroom and metadata use from `lvs`.
    LvmThin { pool: &'static str },
    /// A PVE directory storage: available bytes from the PVE storage status API.
    Directory,
    /// A PVE `zfspool` storage: available bytes from the same PVE storage
    /// status API as [`Headroom::Directory`]. Disks are zvols, so the
    /// template's disk format is `raw`.
    ZfsPool,
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
    pub lane: super::CloneLane,
    /// The agent base image this site clones agent VMs from. `None` = the
    /// site runs KVM clones only and [`Site::for_lane`] refuses the agent
    /// lane there; any site with a template (Contabo, carrick-hz) admits it.
    pub agent_template: Option<AgentTemplate>,
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
    /// DHCP (Willow) or a private static bridge (Contabo, carrick-hz).
    pub network: Network,
    pub cores: u32,
    pub memory_mib: u64,
    pub disk_gib: u32,
    /// VMs the scoped token must hold no rights over (read-only proof).
    pub protected: &'static [u16],
}

pub(super) const WILLOW: Site = Site {
    lane: super::CloneLane::Kvm,
    agent_template: None,
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
    lane: super::CloneLane::Kvm,
    agent_template: Some(AgentTemplate::Blue),
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
    protected: &[101, 102, 103, 104, 9000, 9001],
};

/// The Hetzner host carrick-hz (issue #1591): Contabo's layout on its own
/// /24 behind NAT bridge `vmbr1` (no DHCP), with clones on PVE `zfspool`
/// storage `tank-vm` (sparse ZFS dataset `tank/vm`). No fixed worker VMs
/// live here, so only the agent template slots are protected. The PVE node
/// certificate's only name is `DNS:carrick-hz`.
pub(super) const HETZNER: Site = Site {
    lane: super::CloneLane::Kvm,
    agent_template: Some(AgentTemplate::Blue),
    node: "carrick-hz",
    api_host: "carrick-hz",
    api_ca: Some("/etc/pve/pve-root-ca.pem"),
    storage: "tank-vm",
    headroom: Headroom::ZfsPool,
    bridge: "vmbr1",
    network: Network::Static {
        subnet: [10, 78, 0],
        gateway: 1,
        nameserver: "1.1.1.1",
        host_public: "2.29.243.212",
    },
    cores: 8,
    memory_mib: 16384,
    disk_gib: 100,
    protected: &[9000, 9001],
};

pub(super) const SITES: [Site; 3] = [WILLOW, CONTABO, HETZNER];

impl Site {
    pub(super) fn template(&self) -> Result<u16, ScalerError> {
        match self.lane {
            super::CloneLane::Kvm => Ok(300),
            super::CloneLane::Agent => self
                .agent_template
                .map(AgentTemplate::vmid)
                .ok_or(ScalerError::Guard("site has no agent template")),
        }
    }
    /// Builder override: approved inactive slots are allowed only on an agent site.
    pub(super) fn with_template(mut self, vmid: Option<u16>) -> Result<Self, ScalerError> {
        if let Some(vmid) = vmid {
            if self.lane != super::CloneLane::Agent || self.agent_template.is_none() {
                return Err(ScalerError::Guard("template override requires agent site"));
            }
            self.agent_template = Some(AgentTemplate::try_from(vmid)?);
        }
        Ok(self)
    }

    /// The site's row re-read from [`SITES`] for `lane`. The agent lane is
    /// admitted only where that table row names an agent template, so a
    /// caller's copy cannot confer agent eligibility on a KVM-only site.
    pub(super) fn for_lane(self, lane: super::CloneLane) -> Result<Self, ScalerError> {
        let mut site = Self::for_hostname(self.node)?;
        if lane == super::CloneLane::Agent {
            if site.agent_template.is_none() {
                return Err(ScalerError::Guard(
                    "agent clones require a site with an agent template",
                ));
            }
            site.cores = 8;
            site.memory_mib = 20480;
        }
        site.agent_template = self.agent_template;
        site.lane = lane;
        Ok(site)
    }

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
                gateway,
                subnet: [a, b, c],
                ..
            } => {
                let address = self
                    .static_address(vmid)?
                    .ok_or(ScalerError::Guard("missing static address"))?;
                Ok(format!("ip={address}/24,gw={a}.{b}.{c}.{gateway}"))
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
                if !(300..=349).contains(&vmid)
                    && AgentTemplate::try_from(vmid).is_err()
                    && vmid != 9501
                {
                    return Err(ScalerError::Guard("static address outside CI VMIDs"));
                }
                Ok(Some(format!(
                    "{a}.{b}.{c}.{}",
                    if vmid == 9501 {
                        152 // Reserved qualification clone, outside controller identities.
                    } else if AgentTemplate::try_from(vmid).is_ok() {
                        150 + vmid - 9000
                    } else {
                        vmid - 200
                    }
                )))
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
            // Thin LVs and zvols are block devices: raw disks only.
            Headroom::LvmThin { .. } | Headroom::ZfsPool => "raw",
            Headroom::Directory => "qcow2",
        };
        Ok(format!(
            "SITE_NODE={}\nSITE_API_HOST={}\nSITE_STORAGE={}\nSITE_DISK_FORMAT={disk_format}\nSITE_BRIDGE={}\nSITE_CORES={}\nSITE_MEMORY_MIB={}\nSITE_DISK_GIB={}\nSITE_TEMPLATE_IPCONFIG={}\nSITE_NAMESERVER={}\nSITE_VM_FIREWALL={}\nSITE_API_CA={}\nSITE_ALLOW_KSM={}\nSITE_TEMPLATE_VMID={}\n",
            self.node,
            self.api_host,
            self.storage,
            self.bridge,
            self.cores,
            self.memory_mib,
            self.disk_gib,
            self.ipconfig(self.template()?)?,
            self.nameserver().unwrap_or("none"),
            u8::from(self.isolates_bridge()),
            self.api_ca.unwrap_or("system"),
            u8::from(self.allows_ksm()),
            self.template()?,
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
    fn qualification_clone_has_its_own_ipfilter_address() {
        let site = CONTABO.for_lane(super::super::CloneLane::Agent).unwrap();
        assert_eq!(
            site.ipconfig(9501).unwrap(),
            "ip=10.77.0.152/24,gw=10.77.0.1"
        );
        assert!(
            site.vm_firewall_file(9501)
                .unwrap()
                .unwrap()
                .contains("[IPSET ipfilter-net0]\n10.77.0.152\n")
        );
    }

    #[test]
    fn builder_selects_only_approved_agent_template_slots() {
        let site = CONTABO.for_lane(super::super::CloneLane::Agent).unwrap();
        for (vmid, address) in [(9000, "10.77.0.150"), (9001, "10.77.0.151")] {
            let target = site.with_template(Some(vmid)).unwrap();
            assert_eq!(target.template().unwrap(), vmid);
            assert!(
                target
                    .shell_env()
                    .unwrap()
                    .contains(&format!("SITE_TEMPLATE_VMID={vmid}\n"))
            );
            assert!(
                target
                    .vm_firewall_file(vmid)
                    .unwrap()
                    .unwrap()
                    .contains(address)
            );
        }
        for vmid in [300, 308, 8999, 9002, u16::MAX] {
            assert!(site.with_template(Some(vmid)).is_err());
        }
        assert!(CONTABO.with_template(Some(9000)).is_err());
        assert!(WILLOW.for_lane(super::super::CloneLane::Agent).is_err());
    }

    #[test]
    fn willow_row_is_pinned_to_the_pre_site_constants() {
        // Exactly the values live.rs hard-coded before sites existed.
        assert_eq!(
            WILLOW,
            Site {
                lane: super::super::CloneLane::Kvm,
                agent_template: None,
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
                lane: super::super::CloneLane::Kvm,
                agent_template: Some(AgentTemplate::Blue),
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
                protected: &[101, 102, 103, 104, 9000, 9001],
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
    fn agent_lane_uses_approved_contabo_resources_and_template_firewall_address() {
        let site = CONTABO.for_lane(super::super::CloneLane::Agent).unwrap();
        let env = site.shell_env().unwrap();
        for line in [
            "SITE_TEMPLATE_VMID=9000",
            "SITE_CORES=8",
            "SITE_MEMORY_MIB=20480",
            "SITE_ALLOW_KSM=0",
            "SITE_VM_FIREWALL=1",
            "SITE_TEMPLATE_IPCONFIG=ip=10.77.0.150/24,gw=10.77.0.1",
        ] {
            assert!(env.lines().any(|actual| actual == line), "{line}");
        }
        assert_eq!(
            site.for_lane(super::super::CloneLane::Kvm).unwrap(),
            CONTABO
        );
        assert_eq!(site.cores, 8);
        assert_eq!(site.memory_mib, 20480);
        assert_eq!(site.template().unwrap(), 9000);
        assert_eq!(site.protected, &[101, 102, 103, 104, 9000, 9001]);
        assert_eq!(site.static_address(9001).unwrap().unwrap(), "10.77.0.151");
        assert!(
            site.vm_firewall_file(9001)
                .unwrap()
                .unwrap()
                .contains("10.77.0.151")
        );
        assert!(WILLOW.for_lane(super::super::CloneLane::Agent).is_err());
    }
    #[test]
    fn template_builder_inputs_are_bare_tokens() {
        assert_eq!(
            WILLOW.shell_env().unwrap(),
            "SITE_NODE=willow\nSITE_API_HOST=willow.atxconsulting.com\nSITE_STORAGE=local-lvm\nSITE_DISK_FORMAT=raw\nSITE_BRIDGE=vmbr0\nSITE_CORES=2\nSITE_MEMORY_MIB=4096\nSITE_DISK_GIB=64\nSITE_TEMPLATE_IPCONFIG=ip=dhcp\nSITE_NAMESERVER=none\nSITE_VM_FIREWALL=0\nSITE_API_CA=system\nSITE_ALLOW_KSM=1\nSITE_TEMPLATE_VMID=300\n"
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
            // carrick-hz matches only its exact node name.
            "Carrick-hz",
            "carrick-h",
            "carrick-hz2",
            "carrick-hz.",
            "carrick-hz.evil.example",
            "hz",
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
                // No name selects two sites (carrick-hz's node is its API host).
                for name in [a.node, a.api_host] {
                    assert!(name != b.node && name != b.api_host, "{name}");
                }
            }
            assert!(a.protected.iter().all(|id| !(300..=349).contains(id)));
        }
    }
    #[test]
    fn hetzner_row_is_pinned_and_selected_by_its_node_name() {
        assert_eq!(
            HETZNER,
            Site {
                lane: super::super::CloneLane::Kvm,
                agent_template: Some(AgentTemplate::Blue),
                node: "carrick-hz",
                api_host: "carrick-hz",
                api_ca: Some("/etc/pve/pve-root-ca.pem"),
                storage: "tank-vm",
                headroom: Headroom::ZfsPool,
                bridge: "vmbr1",
                network: Network::Static {
                    subnet: [10, 78, 0],
                    gateway: 1,
                    nameserver: "1.1.1.1",
                    host_public: "2.29.243.212",
                },
                cores: 8,
                memory_mib: 16384,
                disk_gib: 100,
                protected: &[9000, 9001],
            }
        );
        assert_eq!(Site::for_hostname("carrick-hz").unwrap(), HETZNER);
        assert_eq!(Site::for_hostname("carrick-hz\n").unwrap(), HETZNER);
        assert_eq!(
            HETZNER.api_url("/pools/carrick-ci"),
            "https://carrick-hz:8006/api2/json/pools/carrick-ci"
        );
        assert_eq!(HETZNER.api_resolve(), "carrick-hz:8006:127.0.0.1");
        assert_eq!(HETZNER.qemu(308), "/nodes/carrick-hz/qemu/308");
        assert_eq!(HETZNER.task_prefix(), "UPID:carrick-hz:");
        assert!(HETZNER.isolates_bridge() && !HETZNER.allows_ksm());
        assert_eq!(
            HETZNER.ipconfig(349).unwrap(),
            "ip=10.78.0.149/24,gw=10.78.0.1"
        );
        assert!(HETZNER.ipconfig(299).is_err() && HETZNER.ipconfig(350).is_err());
    }
    #[test]
    fn hetzner_template_builder_inputs_are_pinned() {
        assert_eq!(
            HETZNER.shell_env().unwrap(),
            "SITE_NODE=carrick-hz\nSITE_API_HOST=carrick-hz\nSITE_STORAGE=tank-vm\nSITE_DISK_FORMAT=raw\nSITE_BRIDGE=vmbr1\nSITE_CORES=8\nSITE_MEMORY_MIB=16384\nSITE_DISK_GIB=100\nSITE_TEMPLATE_IPCONFIG=ip=10.78.0.100/24,gw=10.78.0.1\nSITE_NAMESERVER=1.1.1.1\nSITE_VM_FIREWALL=1\nSITE_API_CA=/etc/pve/pve-root-ca.pem\nSITE_ALLOW_KSM=0\nSITE_TEMPLATE_VMID=300\n"
        );
        let agent = HETZNER.for_lane(super::super::CloneLane::Agent).unwrap();
        assert_eq!(
            agent.shell_env().unwrap(),
            "SITE_NODE=carrick-hz\nSITE_API_HOST=carrick-hz\nSITE_STORAGE=tank-vm\nSITE_DISK_FORMAT=raw\nSITE_BRIDGE=vmbr1\nSITE_CORES=8\nSITE_MEMORY_MIB=20480\nSITE_DISK_GIB=100\nSITE_TEMPLATE_IPCONFIG=ip=10.78.0.150/24,gw=10.78.0.1\nSITE_NAMESERVER=1.1.1.1\nSITE_VM_FIREWALL=1\nSITE_API_CA=/etc/pve/pve-root-ca.pem\nSITE_ALLOW_KSM=0\nSITE_TEMPLATE_VMID=9000\n"
        );
        let green = agent.with_template(Some(9001)).unwrap();
        assert!(
            green
                .shell_env()
                .unwrap()
                .contains("SITE_TEMPLATE_IPCONFIG=ip=10.78.0.151/24,gw=10.78.0.1\n")
        );
    }
    #[test]
    fn hetzner_vm_firewall_blocks_its_own_public_address() {
        assert_eq!(
            HETZNER.vm_firewall_file(308).unwrap().unwrap(),
            "[OPTIONS]\nenable: 1\npolicy_in: DROP\npolicy_out: DROP\nipfilter: 1\nmacfilter: 1\n\n[IPSET ipfilter-net0]\n10.78.0.108\n\n[RULES]\n\
IN ACCEPT -source 10.78.0.1 -p tcp -dport 22 -log nolog # controller SSH from the host\n\
OUT DROP -dest 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,100.64.0.0/10,2.29.243.212 -log nolog # no private, shared, link-local or host destination\n\
OUT ACCEPT -dest 0.0.0.0/0 -log nolog # remaining IPv4 through the NAT gateway\n"
        );
        assert!(HETZNER.vm_firewall_file(350).is_err());
    }
    #[test]
    fn agent_lane_requires_a_site_with_an_agent_template() {
        use super::super::CloneLane;
        assert!(matches!(
            WILLOW.for_lane(CloneLane::Agent),
            Err(ScalerError::Guard(
                "agent clones require a site with an agent template"
            ))
        ));
        // A caller's copy cannot make a KVM-only site agent-capable: the rule
        // reads the table row.
        let forged = Site {
            agent_template: Some(AgentTemplate::Blue),
            ..WILLOW
        };
        assert!(forged.for_lane(CloneLane::Agent).is_err());
        for row in [CONTABO, HETZNER] {
            let agent = row.for_lane(CloneLane::Agent).unwrap();
            assert_eq!(agent.lane, CloneLane::Agent);
            assert_eq!(agent.node, row.node);
            assert_eq!(agent.template().unwrap(), 9000);
            assert_eq!((agent.cores, agent.memory_mib), (8, 20480));
            assert_eq!(agent.protected, row.protected);
            assert_eq!(agent.for_lane(CloneLane::Kvm).unwrap(), row);
        }
        assert_eq!(WILLOW.for_lane(CloneLane::Kvm).unwrap(), WILLOW);
    }
}
