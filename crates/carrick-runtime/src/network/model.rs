use carrick_spec::{NetworkMode, NetworkNamespaceSpec};
use std::net::{IpAddr, Ipv4Addr};

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
    pub(crate) has_ipv4: bool,
    pub(crate) has_ipv6: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinuxNetworkAddress {
    pub(crate) addr: IpAddr,
    pub(crate) prefix_len: u8,
    pub(crate) link_name: String,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinuxHostsConfig {
    pub(crate) entries: Vec<LinuxHostsEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
        let mut links = vec![LinuxNetworkLink {
            index: 1,
            name: "lo".to_string(),
            loopback: true,
            has_ipv4: true,
            has_ipv6: true,
        }];
        links.extend(
            attachments
                .iter()
                .enumerate()
                .map(|(idx, _attachment)| LinuxNetworkLink {
                    index: (idx + 2) as u32,
                    name: format!("eth{idx}"),
                    loopback: false,
                    has_ipv4: true,
                    has_ipv6: false,
                }),
        );

        let mut addresses = vec![LinuxNetworkAddress {
            addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            prefix_len: 8,
            link_name: "lo".to_string(),
        }];
        addresses.extend(attachments.iter().enumerate().map(|(idx, attachment)| {
            LinuxNetworkAddress {
                addr: IpAddr::V4(attachment.ipv4),
                prefix_len: 24,
                link_name: format!("eth{idx}"),
            }
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
            links: vec![LinuxNetworkLink {
                index: 1,
                name: "lo".to_string(),
                loopback: true,
                has_ipv4: true,
                has_ipv6: true,
            }],
            addresses: vec![LinuxNetworkAddress {
                addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                prefix_len: 8,
                link_name: "lo".to_string(),
            }],
            routes: vec![LinuxNetworkRoute {
                destination: Some(IpAddr::V4(v4_prefix_8(Ipv4Addr::LOCALHOST))),
                destination_prefix_len: 8,
                gateway: None,
                link_name: "lo".to_string(),
            }],
            resolver: resolver_from_spec(spec),
        }
    }
}

impl LinuxHostsConfig {
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
                LinuxNetworkLink {
                    index: 1,
                    name: "lo".to_string(),
                    loopback: true,
                    has_ipv4: true,
                    has_ipv6: true,
                },
                LinuxNetworkLink {
                    index: 2,
                    name: "eth0".to_string(),
                    loopback: false,
                    has_ipv4: true,
                    has_ipv6: false,
                },
            ]
        );
        assert!(model.addresses.iter().any(|addr| addr
            == &LinuxNetworkAddress {
                addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                prefix_len: 8,
                link_name: "lo".to_string(),
            }));
        assert!(model.addresses.iter().any(|addr| addr
            == &LinuxNetworkAddress {
                addr: IpAddr::V4(spec.ipv4),
                prefix_len: 24,
                link_name: "eth0".to_string(),
            }));
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
            == &LinuxNetworkAddress {
                addr: IpAddr::V4(Ipv4Addr::new(172, 32, 0, 44)),
                prefix_len: 24,
                link_name: "eth1".to_string(),
            }));
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
