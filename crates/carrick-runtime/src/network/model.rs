use carrick_abi::{
    LINUX_ARPHRD_ETHER, LINUX_ARPHRD_LOOPBACK, LINUX_IFF_BROADCAST, LINUX_IFF_LOOPBACK,
    LINUX_IFF_MULTICAST, LINUX_IFF_POINTOPOINT, LINUX_IFF_RUNNING, LINUX_IFF_UP,
    LINUX_RT_SCOPE_HOST, LINUX_RT_SCOPE_LINK, LINUX_RT_SCOPE_UNIVERSE,
};
use carrick_spec::{NetworkMode, NetworkNamespaceSpec};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// What the guest's network namespace looks like: which links exist, what
/// addresses they carry, how packets leave, and who resolves names.
///
/// This is the single description every guest-facing surface renders from —
/// rtnetlink, `/proc/net/*`, `/sys/class/net`, the `SIOC*` ioctls. It carries
/// the full link attributes (type, flags, hardware address) rather than leaving
/// each surface to invent its own, which is how carrick came to advertise
/// `eth0` over rtnetlink while `/sys/class/net/eth0` was ENOENT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinuxNetworkModel {
    pub(crate) links: Vec<LinuxNetworkLink>,
    pub(crate) addresses: Vec<LinuxNetworkAddress>,
    pub(crate) routes: Vec<LinuxNetworkRoute>,
    pub(crate) resolver: LinuxResolverConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinuxNetworkLink {
    pub(crate) index: u32,
    pub(crate) name: String,
    pub(crate) loopback: bool,
    /// `ifi_type`: `ARPHRD_LOOPBACK` or `ARPHRD_ETHER`.
    pub(crate) arphrd: u16,
    /// `ifi_flags`, already in Linux's `IFF_*` numbering.
    pub(crate) flags: u32,
    /// The link's hardware address, empty for a link that has none.
    pub(crate) hw_addr: Vec<u8>,
    /// The link's MTU. Namespace state rather than a per-surface literal
    /// because `/sys/class/net/<if>/mtu` and `SIOCGIFMTU` must agree; the
    /// literal `/sys` used to print for loopback was macOS `lo0`'s 16384, where
    /// a Linux `lo` reports 65536.
    pub(crate) mtu: u32,
}

/// A Linux loopback's MTU. Not a host fact: macOS `lo0` is 16384 and Linux `lo`
/// is 65536, and a guest reading `/sys/class/net/lo/mtu` is asking Linux.
const LOOPBACK_MTU: u32 = 65_536;

/// The MTU of an ethernet link, absent anything better from the wire.
const ETHERNET_MTU: u32 = 1_500;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinuxNetworkAddress {
    pub(crate) addr: IpAddr,
    pub(crate) prefix_len: u8,
    pub(crate) link_name: String,
    /// `ifa_scope` (`rt_scope_t`). Carried rather than recomputed per surface
    /// because glibc's address-selection reads it, and a loopback address
    /// labelled `UNIVERSE` changes which source address a guest picks.
    pub(crate) scope: u8,
}

impl LinuxNetworkLink {
    /// The loopback link every namespace has: index 1, `ARPHRD_LOOPBACK`, no
    /// hardware address.
    pub(crate) fn loopback() -> Self {
        Self {
            index: 1,
            name: "lo".to_string(),
            loopback: true,
            arphrd: LINUX_ARPHRD_LOOPBACK,
            flags: LINUX_IFF_UP | LINUX_IFF_LOOPBACK | LINUX_IFF_RUNNING,
            hw_addr: Vec::new(),
            mtu: LOOPBACK_MTU,
        }
    }

    /// An ethernet uplink with the flags Linux reports for an up, running,
    /// multicast-capable veth — the shape a container's `eth0` has.
    pub(crate) fn uplink(index: u32, name: String, hw_addr: [u8; 6]) -> Self {
        Self {
            index,
            name,
            loopback: false,
            arphrd: LINUX_ARPHRD_ETHER,
            flags: LINUX_IFF_UP | LINUX_IFF_BROADCAST | LINUX_IFF_RUNNING | LINUX_IFF_MULTICAST,
            hw_addr: hw_addr.to_vec(),
            mtu: ETHERNET_MTU,
        }
    }
}

impl LinuxNetworkAddress {
    /// Build an address with the scope Linux assigns it: loopback addresses are
    /// host-scoped, `fe80::/10` is link-scoped, everything else is universe.
    pub(crate) fn new(addr: IpAddr, prefix_len: u8, link_name: String) -> Self {
        let scope = if addr.is_loopback() {
            LINUX_RT_SCOPE_HOST
        } else if matches!(addr, IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80) {
            LINUX_RT_SCOPE_LINK
        } else {
            LINUX_RT_SCOPE_UNIVERSE
        };
        Self {
            addr,
            prefix_len,
            link_name,
            scope,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinuxNetworkRoute {
    pub(crate) destination: Option<IpAddr>,
    pub(crate) destination_prefix_len: u8,
    pub(crate) gateway: Option<IpAddr>,
    pub(crate) link_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinuxResolverConfig {
    pub(crate) nameservers: Vec<IpAddr>,
    pub(crate) search: Vec<String>,
    pub(crate) options: Vec<String>,
}

// The /etc/hosts rendering half of the model is consumed only by the macOS
// `execute` arm today; the `cfg_attr(dead_code)` allowances come off when the
// non-macOS run path renders container hosts files too (M0.8+).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(
        feature = "platform-linux",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ),
    allow(dead_code)
)]
pub(crate) struct LinuxHostsConfig {
    pub(crate) entries: Vec<LinuxHostsEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    any(
        feature = "platform-linux",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ),
    allow(dead_code)
)]
pub(crate) struct LinuxHostsEntry {
    pub(crate) addr: String,
    pub(crate) names: Vec<String>,
}

impl LinuxNetworkModel {
    pub(crate) fn from_spec(spec: &NetworkNamespaceSpec) -> Self {
        if spec.mode != NetworkMode::Bridge {
            return Self::loopback_only(spec);
        }

        let attachments = spec.effective_attachments();
        let mut links = vec![LinuxNetworkLink::loopback()];
        links.extend(attachments.iter().enumerate().map(|(idx, _attachment)| {
            let index = (idx + 2) as u32;
            LinuxNetworkLink::uplink(index, format!("eth{idx}"), [0x02, 0, 0, 0, 0, index as u8])
        }));

        // Loopback carries 127.0.0.1/8 and ::1/128; the uplinks carry IPv4 only
        // — the exact address set the Docker oracle's netns has. This used to
        // fabricate a link-local `fe80::1/64` per uplink, justified by "Docker
        // attaches a link-local IPv6 to every veth even in an IPv4-only
        // bridge". That is false for the oracle, and measurably so: the
        // container's `/proc/net/if_inet6` holds exactly one row, `::1/128` on
        // `lo`, because Docker's default bridge leaves IPv6 disabled in the
        // netns.
        //
        // The fabrication was guest-visible and wrong in both directions.
        // libuv's `tcp_connect6_link_local` skips on Linux precisely because no
        // enumerated interface carries an `fe80::` address; carrick advertised
        // one, so the guest ran a test real Linux declines — an inversion,
        // which is just as much a parity failure as a missing pass. It also
        // carried `udp_multicast_join6` past the same interface check. Now that
        // the address list is the only description of what a link carries,
        // there is no bool left to fabricate.
        let mut addresses = vec![
            LinuxNetworkAddress::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8, "lo".to_string()),
            LinuxNetworkAddress::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 128, "lo".to_string()),
        ];
        addresses.extend(attachments.iter().enumerate().map(|(idx, attachment)| {
            LinuxNetworkAddress::new(IpAddr::V4(attachment.ipv4), 24, format!("eth{idx}"))
        }));

        let primary_gateway = attachments
            .first()
            .map_or(spec.gateway_v4, |attachment| attachment.gateway_v4);
        let mut routes = vec![LinuxNetworkRoute {
            destination: None,
            destination_prefix_len: 0,
            gateway: Some(IpAddr::V4(primary_gateway)),
            link_name: "eth0".to_string(),
        }];
        routes.extend(
            attachments
                .iter()
                .enumerate()
                .map(|(idx, attachment)| LinuxNetworkRoute {
                    destination: Some(IpAddr::V4(v4_prefix_24(attachment.ipv4))),
                    destination_prefix_len: 24,
                    gateway: None,
                    link_name: format!("eth{idx}"),
                }),
        );

        Self {
            links,
            addresses,
            routes,
            resolver: resolver_from_spec(spec),
        }
    }

    pub(crate) fn has_resolver_config(&self) -> bool {
        !self.resolver.nameservers.is_empty()
            || !self.resolver.search.is_empty()
            || !self.resolver.options.is_empty()
    }

    pub(crate) fn render_proc_net_dev(&self) -> Vec<u8> {
        let mut out = String::from(
            "Inter-|   Receive                                                |  Transmit\n \
face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n",
        );
        for link in &self.links {
            out.push_str(&format!(
                "{:>6}: 0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0\n",
                link.name
            ));
        }
        out.into_bytes()
    }

    pub(crate) fn render_proc_net_route(&self) -> Vec<u8> {
        let mut out = String::from(
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n",
        );
        for route in &self.routes {
            let destination = match route.destination {
                Some(IpAddr::V4(addr)) => addr,
                Some(IpAddr::V6(_)) => continue,
                None => Ipv4Addr::UNSPECIFIED,
            };
            let gateway = match route.gateway {
                Some(IpAddr::V4(addr)) => addr,
                Some(IpAddr::V6(_)) => continue,
                None => Ipv4Addr::UNSPECIFIED,
            };
            let flags = if route.gateway.is_some() {
                "0003"
            } else {
                "0001"
            };
            out.push_str(&format!(
                "{}\t{}\t{}\t{flags}\t0\t0\t0\t{}\t0\t0\t0\n",
                route.link_name,
                proc_net_route_hex_v4(destination),
                proc_net_route_hex_v4(gateway),
                proc_net_route_hex_v4_mask(route.destination_prefix_len),
            ));
        }
        out.into_bytes()
    }

    pub(crate) fn render_resolv_conf(&self) -> Vec<u8> {
        let mut out = String::new();
        for server in &self.resolver.nameservers {
            out.push_str("nameserver ");
            out.push_str(&server.to_string());
            out.push('\n');
        }
        if !self.resolver.search.is_empty() {
            out.push_str("search ");
            out.push_str(&self.resolver.search.join(" "));
            out.push('\n');
        }
        if !self.resolver.options.is_empty() {
            out.push_str("options ");
            out.push_str(&self.resolver.options.join(" "));
            out.push('\n');
        }
        out.into_bytes()
    }

    // See `LinuxHostsConfig`: macOS-arm-only consumer today.
    #[cfg_attr(
        any(
            feature = "platform-linux",
            feature = "platform-freebsd",
            feature = "platform-netbsd"
        ),
        allow(dead_code)
    )]
    pub(crate) fn hosts_config<I>(
        &self,
        spec: &NetworkNamespaceSpec,
        service_entries: I,
        extra_hosts: &[String],
        guest_hostname: &str,
    ) -> LinuxHostsConfig
    where
        I: IntoIterator<Item = (IpAddr, Vec<String>)>,
    {
        let host_gateway =
            (spec.mode == NetworkMode::Bridge).then(|| self.primary_gateway_v4(spec));
        let parsed_extra_hosts = extra_hosts
            .iter()
            .filter_map(|entry| parse_extra_host(entry, host_gateway))
            .collect::<Vec<_>>();

        let mut entries = vec![
            LinuxHostsEntry {
                addr: "127.0.0.1".to_string(),
                names: vec!["localhost".to_string()],
            },
            LinuxHostsEntry {
                addr: "::1".to_string(),
                names: vec![
                    "localhost".to_string(),
                    "ip6-localhost".to_string(),
                    "ip6-loopback".to_string(),
                ],
            },
            LinuxHostsEntry {
                addr: "ff02::1".to_string(),
                names: vec!["ip6-allnodes".to_string()],
            },
            LinuxHostsEntry {
                addr: "ff02::2".to_string(),
                names: vec!["ip6-allrouters".to_string()],
            },
        ];

        if spec.mode == NetworkMode::Bridge {
            let mut wrote_bridge_entry = false;
            for (addr, names) in service_entries {
                if names.is_empty() {
                    continue;
                }
                entries.push(LinuxHostsEntry {
                    addr: addr.to_string(),
                    names,
                });
                wrote_bridge_entry = true;
            }
            if !wrote_bridge_entry {
                let mut names = Vec::new();
                if let Some(name) = &spec.container_name {
                    names.push(name.clone());
                }
                names.extend(spec.aliases.iter().cloned());
                if names.is_empty() {
                    names.push(guest_hostname.to_string());
                }
                entries.push(LinuxHostsEntry {
                    addr: self.primary_ipv4_address(spec).to_string(),
                    names,
                });
            }

            let explicit_names = parsed_extra_hosts
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>();
            let gateway_names = ["host.docker.internal", "gateway.docker.internal"]
                .into_iter()
                .filter(|name| !explicit_names.contains(name))
                .map(str::to_string)
                .collect::<Vec<_>>();
            if !gateway_names.is_empty() {
                entries.push(LinuxHostsEntry {
                    addr: self.primary_gateway_v4(spec).to_string(),
                    names: gateway_names,
                });
            }
        } else {
            entries.push(LinuxHostsEntry {
                addr: "127.0.1.1".to_string(),
                names: vec![guest_hostname.to_string()],
            });
        }

        entries.extend(
            parsed_extra_hosts
                .into_iter()
                .map(|(name, addr)| LinuxHostsEntry {
                    addr,
                    names: vec![name],
                }),
        );

        LinuxHostsConfig { entries }
    }

    // See `LinuxHostsConfig`: macOS-arm-only consumer today.
    #[cfg_attr(
        any(
            feature = "platform-linux",
            feature = "platform-freebsd",
            feature = "platform-netbsd"
        ),
        allow(dead_code)
    )]
    fn primary_ipv4_address(&self, spec: &NetworkNamespaceSpec) -> Ipv4Addr {
        self.addresses
            .iter()
            .find_map(|addr| {
                if addr.link_name == "eth0"
                    && let IpAddr::V4(v4) = addr.addr
                {
                    Some(v4)
                } else {
                    None
                }
            })
            .unwrap_or(spec.ipv4)
    }

    // See `LinuxHostsConfig`: macOS-arm-only consumer today.
    #[cfg_attr(
        any(
            feature = "platform-linux",
            feature = "platform-freebsd",
            feature = "platform-netbsd"
        ),
        allow(dead_code)
    )]
    fn primary_gateway_v4(&self, spec: &NetworkNamespaceSpec) -> Ipv4Addr {
        self.routes
            .iter()
            .find_map(|route| {
                if route.destination.is_none()
                    && route.link_name == "eth0"
                    && let Some(IpAddr::V4(v4)) = route.gateway
                {
                    Some(v4)
                } else {
                    None
                }
            })
            .unwrap_or(spec.gateway_v4)
    }

    fn loopback_only(spec: &NetworkNamespaceSpec) -> Self {
        Self {
            resolver: resolver_from_spec(spec),
            ..Self::isolated()
        }
    }

    /// A namespace with nothing but loopback — `--net none`, and the fallback
    /// when a host-wire probe finds no usable uplink.
    ///
    /// Loopback carries `127.0.0.1/8` AND `::1/128`, which is what a Docker
    /// container's `lo` carries in every network mode. `::1` used to be
    /// expressed here as a `has_ipv6: true` bool that only `/proc/net/if_inet6`
    /// consulted, so `/proc` reported a `::1` the rtnetlink dump — built from
    /// this same address list — did not. One list now answers both.
    pub(crate) fn isolated() -> Self {
        Self {
            links: vec![LinuxNetworkLink::loopback()],
            addresses: vec![
                LinuxNetworkAddress::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8, "lo".to_string()),
                LinuxNetworkAddress::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 128, "lo".to_string()),
            ],
            routes: vec![LinuxNetworkRoute {
                destination: Some(IpAddr::V4(v4_prefix_8(Ipv4Addr::LOCALHOST))),
                destination_prefix_len: 8,
                gateway: None,
                link_name: "lo".to_string(),
            }],
            resolver: LinuxResolverConfig {
                nameservers: Vec::new(),
                search: Vec::new(),
                options: Vec::new(),
            },
        }
    }

    /// The `--net host` view: the guest shares the host's connectivity, so the
    /// namespace MIRRORS the host's wire — one loopback and one uplink, named
    /// and indexed the way Linux names and indexes them.
    ///
    /// This is the host→Linux mapping every surface is being moved onto. There
    /// were four independently written ones (`dispatch/net/support.rs` for
    /// rtnetlink, `dispatch/fs.rs` for `SIOCGIFCONF`, `vfs/proc.rs` for
    /// `/proc/net/*`, `vfs/sys.rs` for `/sys/class/net`) selecting the uplink by
    /// three different rules and disagreeing with each other in the guest:
    /// rtnetlink advertised an `eth0` with a hardware address while
    /// `/sys/class/net/eth0/address` was ENOENT, because `/sys` was listing the
    /// Mac's own `en0`/`awdl0`/`utun*` instead. The first two of those are gone;
    /// `dispatch/fs.rs` and `vfs/proc.rs` still have theirs.
    ///
    /// The ranking below is the one `dispatch/net/support.rs` used, kept
    /// bit-for-bit so the surfaces already agreeing keep agreeing: up+running
    /// first, then carrying IPv4, then a familiar physical name, then the name.
    ///
    /// It runs ONCE, when the namespace is created, not per guest syscall. That
    /// is the substantive change: a namespace's interface set changes only when
    /// someone changes it, whereas re-deriving from `getifaddrs(3)` on every
    /// call meant the guest's `eth0` address moved underneath a running program
    /// when the Mac renewed a DHCP lease or raised a VPN `utun`.
    pub(crate) fn host_mirror(wire: &HostWireSnapshot) -> Self {
        let Some(uplink) = wire.uplink() else {
            // No usable host uplink: loopback only, which is at least a
            // coherent namespace. `glibc`'s AI_ADDRCONFIG will then discard
            // IPv4 answers, so the fallback is deliberately visible rather
            // than silently synthesising an address the host does not own.
            return Self::isolated();
        };

        let links = vec![
            LinuxNetworkLink::loopback(),
            LinuxNetworkLink {
                index: 2,
                name: "eth0".to_string(),
                loopback: false,
                arphrd: LINUX_ARPHRD_ETHER,
                flags: uplink.flags,
                hw_addr: uplink.hw_addr.clone(),
                mtu: ETHERNET_MTU,
            },
        ];

        // Loopback carries `127.0.0.1/8` and `::1/128` only. macOS `lo0` also
        // has `fe80::1%lo0`, which a Linux loopback does not, and libuv's
        // `tcp_connect6_link_local` skips precisely on "is there ANY fe80::
        // address" — so passing it through made the guest RUN a test real Linux
        // declines.
        //
        // The uplink carries IPv4 only. The host's IPv6 addresses are the MAC's,
        // not the guest's: carrick answers an IPv6 multicast join on them with
        // EADDRNOTAVAIL, so `udp_multicast_join6` RAN and failed where Linux
        // skips with "No external IPv6 interface available".
        let mut addresses = vec![LinuxNetworkAddress::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8,
            "lo".to_string(),
        )];
        if wire.loopback_has_v6_localhost {
            addresses.push(LinuxNetworkAddress::new(
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                128,
                "lo".to_string(),
            ));
        }
        addresses.extend(uplink.v4_addresses.iter().map(|(addr, prefix_len)| {
            LinuxNetworkAddress::new(IpAddr::V4(*addr), *prefix_len, "eth0".to_string())
        }));

        // One connected route per address — the network it sits on, via its
        // interface. `ip route` and Go's route enumeration expect at least the
        // loopback route.
        let routes = addresses
            .iter()
            .filter(|address| address.prefix_len != 0)
            .filter_map(|address| match address.addr {
                IpAddr::V4(v4) => Some(LinuxNetworkRoute {
                    destination: Some(IpAddr::V4(mask_v4(v4, address.prefix_len))),
                    destination_prefix_len: address.prefix_len,
                    gateway: None,
                    link_name: address.link_name.clone(),
                }),
                IpAddr::V6(_) => None,
            })
            .collect();

        Self {
            links,
            addresses,
            routes,
            resolver: LinuxResolverConfig {
                nameservers: Vec::new(),
                search: Vec::new(),
                options: Vec::new(),
            },
        }
    }

    /// The link with this guest name, if the namespace has one.
    pub(crate) fn link_by_name(&self, name: &str) -> Option<&LinuxNetworkLink> {
        self.links.iter().find(|link| link.name == name)
    }

    /// Whether a link carries an address of the given family — what the
    /// surfaces that report presence rather than addresses
    /// (`/proc/net/if_inet6`, `/proc/net/dev_mcast`) need.
    ///
    /// Derived from the address list rather than stored, so it cannot disagree
    /// with the addresses the same namespace hands out. The pair of `has_ipv4`/
    /// `has_ipv6` bools this replaces could, and did: they were set by hand at
    /// every construction site and one of them fabricated IPv6 on a link that
    /// carried no IPv6 address.
    pub(crate) fn link_carries(&self, link_name: &str, v6: bool) -> bool {
        self.addresses
            .iter()
            .any(|address| address.link_name == link_name && address.addr.is_ipv6() == v6)
    }
}

impl LinuxHostsConfig {
    // See `LinuxHostsConfig`: macOS-arm-only consumer today.
    #[cfg_attr(
        any(
            feature = "platform-linux",
            feature = "platform-freebsd",
            feature = "platform-netbsd"
        ),
        allow(dead_code)
    )]
    pub(crate) fn render(&self) -> String {
        let mut out = String::new();
        for entry in &self.entries {
            if entry.names.is_empty() {
                continue;
            }
            out.push_str(&entry.addr);
            out.push('\t');
            out.push_str(&entry.names.join(" "));
            out.push('\n');
        }
        out
    }
}

fn resolver_from_spec(spec: &NetworkNamespaceSpec) -> LinuxResolverConfig {
    let nameservers = if spec.dns_servers.is_empty() && spec.mode == NetworkMode::Bridge {
        vec![IpAddr::V4(spec.gateway_v4)]
    } else {
        spec.dns_servers.clone()
    };
    LinuxResolverConfig {
        nameservers,
        search: spec.dns_search.clone(),
        options: spec.dns_options.clone(),
    }
}

pub(crate) fn v4_prefix_24(addr: Ipv4Addr) -> Ipv4Addr {
    let [a, b, c, _] = addr.octets();
    Ipv4Addr::new(a, b, c, 0)
}

pub(crate) fn v4_prefix_8(addr: Ipv4Addr) -> Ipv4Addr {
    let [a, _, _, _] = addr.octets();
    Ipv4Addr::new(a, 0, 0, 0)
}

fn proc_net_route_hex_v4(addr: Ipv4Addr) -> String {
    let octets = addr.octets();
    format!(
        "{:02X}{:02X}{:02X}{:02X}",
        octets[3], octets[2], octets[1], octets[0]
    )
}

fn proc_net_route_hex_v4_mask(prefix_len: u8) -> String {
    let prefix = prefix_len.min(32);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    proc_net_route_hex_v4(Ipv4Addr::from(mask))
}

// See `LinuxHostsConfig`: macOS-arm-only consumer today.
#[cfg_attr(
    any(
        feature = "platform-linux",
        feature = "platform-freebsd",
        feature = "platform-netbsd"
    ),
    allow(dead_code)
)]
fn parse_extra_host(entry: &str, host_gateway: Option<Ipv4Addr>) -> Option<(String, String)> {
    let (name, addr) = entry.split_once('=').or_else(|| entry.split_once(':'))?;
    let name = name.trim();
    let addr = addr.trim();
    if name.is_empty() || addr.is_empty() {
        return None;
    }
    if addr == "host-gateway" {
        return host_gateway.map(|gateway| (name.to_string(), gateway.to_string()));
    }
    Some((name.to_string(), addr.to_string()))
}

/// What the HOST's network stack can actually do, read once per network
/// namespace.
///
/// This is the one question Darwin genuinely owns here: which links exist on
/// the wire, which is up and carrying IPv4, and what hardware address it has.
/// It is a CAPABILITY probe, not a view — the guest never sees a
/// `HostWireSnapshot`, only the [`LinuxNetworkModel`] that
/// [`LinuxNetworkModel::host_mirror`] derives from it. Keeping the two apart is
/// what stops the Mac's `awdl0`, `utun*` and IPv6 addresses reaching a guest
/// that has no business knowing they exist.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct HostWireSnapshot {
    pub(crate) interfaces: Vec<HostWireInterface>,
    /// Whether the host's loopback carries `::1`. Mirrored rather than assumed,
    /// so a host with IPv6 disabled does not hand the guest a `::1` it cannot
    /// bind — the guest's `lo` IS the host's `lo0` on this lane.
    pub(crate) loopback_has_v6_localhost: bool,
}

/// One host link, carrying only what the mapping needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct HostWireInterface {
    pub(crate) name: String,
    /// Linux `IFF_*`, already translated out of Darwin's numbering.
    pub(crate) flags: u32,
    pub(crate) hw_addr: Vec<u8>,
    pub(crate) v4_addresses: Vec<(Ipv4Addr, u8)>,
    pub(crate) loopback: bool,
}

impl HostWireSnapshot {
    /// The ONE `getifaddrs(3)` on the guest-facing path.
    ///
    /// Every other caller was answering a namespace question with it; this one
    /// asks a wire question, at namespace creation, and its answer then lives in
    /// the namespace.
    pub(crate) fn probe() -> Self {
        let mut snapshot = Self::default();
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: getifaddrs allocates a list we free via freeifaddrs below.
        if unsafe { libc::getifaddrs(&mut head) } != 0 || head.is_null() {
            return snapshot;
        }
        let mut cur = head;
        while !cur.is_null() {
            // SAFETY: `cur` is a valid node for the duration of this iteration.
            let ifa = unsafe { &*cur };
            cur = ifa.ifa_next;
            if ifa.ifa_name.is_null() || ifa.ifa_addr.is_null() {
                continue;
            }
            // SAFETY: ifa_name is a NUL-terminated C string owned by the list.
            let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
                .to_string_lossy()
                .into_owned();
            let loopback = ifa.ifa_flags & (libc::IFF_LOOPBACK as u32) != 0;
            let flags = linux_iff_flags(ifa.ifa_flags);
            // SAFETY: ifa_addr points at a sockaddr whose sa_family selects the type.
            let family = unsafe { (*ifa.ifa_addr).sa_family } as i32;

            if family == libc::AF_INET6 {
                // SAFETY: an AF_INET6 sockaddr is a sockaddr_in6.
                let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                if loopback && sin6.sin6_addr.s6_addr == Ipv6Addr::LOCALHOST.octets() {
                    snapshot.loopback_has_v6_localhost = true;
                }
                continue;
            }

            let entry = snapshot.entry(&name);
            entry.loopback = loopback;
            entry.flags = flags;
            match family {
                carrick_portable::AF_LINK => {
                    // The link-layer record carries the hardware address. The
                    // sockaddr shape differs: Darwin `AF_LINK` is a
                    // `sockaddr_dl`, Linux `AF_PACKET` a `sockaddr_ll`.
                    #[cfg(carrick_bsd)]
                    {
                        // SAFETY: an AF_LINK sockaddr is a sockaddr_dl.
                        let dl = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_dl) };
                        let nlen = dl.sdl_nlen as usize;
                        let alen = dl.sdl_alen as usize;
                        if alen > 0 && nlen + alen <= dl.sdl_data.len() {
                            entry.hw_addr = dl.sdl_data[nlen..nlen + alen]
                                .iter()
                                .map(|&c| c as u8)
                                .collect();
                        }
                    }
                    #[cfg(carrick_linux)]
                    {
                        // SAFETY: an AF_PACKET sockaddr is a sockaddr_ll.
                        let ll = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_ll) };
                        let alen = (ll.sll_halen as usize).min(ll.sll_addr.len());
                        entry.hw_addr = ll.sll_addr[..alen].to_vec();
                    }
                }
                libc::AF_INET => {
                    // SAFETY: an AF_INET sockaddr is a sockaddr_in.
                    let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                    let addr = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                    let prefix_len = if ifa.ifa_netmask.is_null() {
                        32
                    } else {
                        // SAFETY: the netmask sockaddr is a sockaddr_in.
                        let m = unsafe { &*(ifa.ifa_netmask as *const libc::sockaddr_in) };
                        prefix_len_from_mask(&m.sin_addr.s_addr.to_ne_bytes())
                    };
                    entry.v4_addresses.push((addr, prefix_len));
                }
                _ => {}
            }
        }
        // SAFETY: free the list getifaddrs allocated.
        unsafe { libc::freeifaddrs(head) };
        snapshot
    }

    fn entry(&mut self, name: &str) -> &mut HostWireInterface {
        let idx = match self.interfaces.iter().position(|i| i.name == name) {
            Some(idx) => idx,
            None => {
                self.interfaces.push(HostWireInterface {
                    name: name.to_string(),
                    ..HostWireInterface::default()
                });
                self.interfaces.len() - 1
            }
        };
        &mut self.interfaces[idx]
    }

    /// Which host link becomes the guest's `eth0`.
    ///
    /// Darwin's primary links are normally `en*`, but FreeBSD commonly uses
    /// `vtnet*`, `em*` or `igb*` and Linux uses `eth*`. Restricting the uplink
    /// to Darwin names made a FreeBSD guest appear loopback-only, and glibc's
    /// AI_ADDRCONFIG then discarded every IPv4 DNS answer — so the ranking
    /// prefers familiar physical names but falls back to any non-loopback link.
    /// Being up, running and carrying IPv4 outranks the name.
    fn uplink(&self) -> Option<&HostWireInterface> {
        self.interfaces
            .iter()
            .filter(|iface| !iface.loopback)
            .min_by_key(|iface| {
                let name = iface.name.as_str();
                let active = iface.flags & (LINUX_IFF_UP | LINUX_IFF_RUNNING)
                    == (LINUX_IFF_UP | LINUX_IFF_RUNNING);
                let has_v4 = !iface.v4_addresses.is_empty();
                let rank = if name
                    .strip_prefix("en")
                    .is_some_and(|suffix| suffix.starts_with(|c: char| c.is_ascii_digit()))
                {
                    0
                } else if ["eth", "vtnet", "em", "igb", "re", "ix"]
                    .iter()
                    .any(|prefix| name.starts_with(prefix))
                {
                    1
                } else {
                    2
                };
                (!active, !has_v4, rank, name)
            })
    }
}

/// Darwin/BSD interface flags -> Linux `IFF_*`. The bit positions differ, so
/// copying the raw word would tell the guest a link is `IFF_PROMISC` where the
/// host meant `IFF_RUNNING`.
fn linux_iff_flags(host: u32) -> u32 {
    let mut out = 0;
    for (host_bit, linux_bit) in [
        (libc::IFF_UP, LINUX_IFF_UP),
        (libc::IFF_BROADCAST, LINUX_IFF_BROADCAST),
        (libc::IFF_LOOPBACK, LINUX_IFF_LOOPBACK),
        (libc::IFF_POINTOPOINT, LINUX_IFF_POINTOPOINT),
        (libc::IFF_RUNNING, LINUX_IFF_RUNNING),
        (libc::IFF_MULTICAST, LINUX_IFF_MULTICAST),
    ] {
        if host & (host_bit as u32) != 0 {
            out |= linux_bit;
        }
    }
    out
}

/// The CIDR prefix length of a netmask, counted across its raw address octets.
fn prefix_len_from_mask(bytes: &[u8]) -> u8 {
    bytes.iter().map(|b| b.count_ones() as u8).sum()
}

/// Mask an IPv4 address down to its network prefix.
fn mask_v4(addr: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let prefix = prefix_len.min(32);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ipv4Addr::from(u32::from(addr) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_spec::{BridgeId, NetworkAttachmentSpec, NetworkMode, NetworkNamespaceSpec};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn bridge_model_has_loopback_primary_link_default_and_connected_routes() {
        let spec =
            NetworkNamespaceSpec::bridge_default(Some("web".to_string()), Vec::new(), Vec::new());

        let model = LinuxNetworkModel::from_spec(&spec);

        assert_eq!(
            model.links,
            vec![
                LinuxNetworkLink::loopback(),
                LinuxNetworkLink::uplink(2, "eth0".to_string(), [0x02, 0, 0, 0, 0, 2]),
            ]
        );
        // The uplink carries IPv4 ONLY. Measured against the conformance oracle
        // container: its `/proc/net/if_inet6` has exactly one row, `::1/128` on
        // `lo`, because Docker's default bridge leaves IPv6 disabled in the
        // netns, so a veth carries no `fe80::`. This used to be a `has_ipv6`
        // bool set by hand at every construction site; now the address list is
        // the only statement of what a link carries, so there is nothing left
        // to set wrong.
        assert!(
            !model.link_carries("eth0", true),
            "an uplink must carry no IPv6 address: {:?}",
            model.addresses
        );
        assert!(model.addresses.iter().any(|addr| addr
            == &LinuxNetworkAddress::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8, "lo".to_string())));
        assert!(
            model.addresses.iter().any(|addr| addr
                == &LinuxNetworkAddress::new(IpAddr::V4(spec.ipv4), 24, "eth0".to_string()))
        );
        assert!(model.routes.iter().any(|route| route
            == &LinuxNetworkRoute {
                destination: None,
                destination_prefix_len: 0,
                gateway: Some(IpAddr::V4(spec.gateway_v4)),
                link_name: "eth0".to_string(),
            }));
        assert!(model.routes.iter().any(|route| route
            == &LinuxNetworkRoute {
                destination: Some(IpAddr::V4(v4_prefix_24(spec.ipv4))),
                destination_prefix_len: 24,
                gateway: None,
                link_name: "eth0".to_string(),
            }));
    }

    #[test]
    fn bridge_model_exposes_each_attachment_as_stable_eth_index() {
        let mut spec =
            NetworkNamespaceSpec::bridge_default(Some("api".to_string()), Vec::new(), Vec::new());
        spec.attachments = vec![
            NetworkAttachmentSpec::bridge_default(
                BridgeId::new("front"),
                Some("api".to_string()),
                Vec::new(),
                Some(Ipv4Addr::new(172, 31, 0, 44)),
            ),
            NetworkAttachmentSpec::bridge_default(
                BridgeId::new("back"),
                Some("api".to_string()),
                Vec::new(),
                Some(Ipv4Addr::new(172, 32, 0, 44)),
            ),
        ];
        spec.bridge_id = spec.attachments[0].bridge_id.clone();
        spec.ipv4 = spec.attachments[0].ipv4;
        spec.gateway_v4 = spec.attachments[0].gateway_v4;

        let model = LinuxNetworkModel::from_spec(&spec);

        assert_eq!(
            model
                .links
                .iter()
                .map(|link| (link.index, link.name.as_str()))
                .collect::<Vec<_>>(),
            vec![(1, "lo"), (2, "eth0"), (3, "eth1")]
        );
        assert!(model.addresses.iter().any(|addr| addr
            == &LinuxNetworkAddress::new(
                IpAddr::V4(Ipv4Addr::new(172, 32, 0, 44)),
                24,
                "eth1".to_string()
            )));
        assert!(model.routes.iter().any(|route| route
            == &LinuxNetworkRoute {
                destination: Some(IpAddr::V4(Ipv4Addr::new(172, 32, 0, 0))),
                destination_prefix_len: 24,
                gateway: None,
                link_name: "eth1".to_string(),
            }));
    }

    #[test]
    fn non_bridge_modes_do_not_synthesize_bridge_links() {
        for spec in [
            NetworkNamespaceSpec::default(),
            NetworkNamespaceSpec::none(),
        ] {
            let model = LinuxNetworkModel::from_spec(&spec);

            assert!(spec.mode != NetworkMode::Bridge);
            assert_eq!(
                model
                    .links
                    .iter()
                    .map(|link| link.name.as_str())
                    .collect::<Vec<_>>(),
                vec!["lo"]
            );
            assert!(model.links.iter().all(|link| !link.name.starts_with("eth")));
        }
    }

    #[test]
    fn resolver_model_uses_bridge_gateway_and_preserves_overrides() {
        let bridge =
            NetworkNamespaceSpec::bridge_default(Some("web".to_string()), Vec::new(), Vec::new());
        let bridge_model = LinuxNetworkModel::from_spec(&bridge);
        assert_eq!(
            bridge_model.resolver.nameservers,
            vec![IpAddr::V4(bridge.gateway_v4)]
        );

        let spec = NetworkNamespaceSpec {
            dns_servers: vec!["1.1.1.1".parse().unwrap(), "9.9.9.9".parse().unwrap()],
            dns_search: vec!["example.test".to_string()],
            dns_options: vec!["ndots:2".to_string()],
            ..Default::default()
        };
        let model = LinuxNetworkModel::from_spec(&spec);

        assert_eq!(model.resolver.nameservers, spec.dns_servers);
        assert_eq!(model.resolver.search, vec!["example.test"]);
        assert_eq!(model.resolver.options, vec!["ndots:2"]);
    }

    #[test]
    fn hosts_model_uses_primary_address_gateway_and_extra_host_overrides() {
        let mut spec =
            NetworkNamespaceSpec::bridge_default(Some("web".to_string()), Vec::new(), Vec::new());
        spec.attachments = vec![
            NetworkAttachmentSpec::bridge_default(
                BridgeId::new("front"),
                Some("web".to_string()),
                vec!["web-front".to_string()],
                Some(Ipv4Addr::new(172, 31, 0, 44)),
            ),
            NetworkAttachmentSpec::bridge_default(
                BridgeId::new("back"),
                Some("web".to_string()),
                vec!["web-back".to_string()],
                Some(Ipv4Addr::new(172, 32, 0, 44)),
            ),
        ];
        spec.bridge_id = spec.attachments[0].bridge_id.clone();
        spec.ipv4 = spec.attachments[0].ipv4;
        spec.gateway_v4 = spec.attachments[0].gateway_v4;
        let model = LinuxNetworkModel::from_spec(&spec);

        let hosts = model
            .hosts_config(
                &spec,
                [(Ipv4Addr::new(172, 33, 0, 9).into(), vec!["db".to_string()])],
                &["host.docker.internal:10.12.0.7".to_string()],
                "carrick",
            )
            .render();

        assert!(
            hosts.contains("127.0.0.1\tlocalhost\n"),
            "localhost entry missing: {hosts}"
        );
        assert!(
            hosts.contains("172.33.0.9\tdb\n"),
            "service entries should be rendered by the model: {hosts}"
        );
        assert!(
            hosts.contains("172.31.0.1\tgateway.docker.internal\n"),
            "unoverridden gateway name should use the primary model gateway: {hosts}"
        );
        assert!(
            hosts.contains("10.12.0.7\thost.docker.internal\n"),
            "explicit extra host should override generated gateway name: {hosts}"
        );
        assert!(
            !hosts.contains("172.31.0.1\thost.docker.internal"),
            "overridden host gateway name should not be generated: {hosts}"
        );
    }
}
