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
}
