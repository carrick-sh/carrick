use carrick_spec::{
    NetworkMode, NetworkNamespaceId, NetworkNamespaceSpec, PortMapping, PortProtocol,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub(crate) mod dns;
pub(crate) mod model;
pub mod socket_namespace;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkCapabilities {
    pub same_bridge_ip_connectivity: bool,
    pub multi_network_attachments: bool,
    pub embedded_dns: bool,
    pub outbound_connectivity: bool,
    pub published_ports: bool,
    pub published_udp_ports: bool,
    pub kernel_datapath: bool,
    pub host_routable_container_ips: bool,
    pub packet_level_isolation: bool,
    pub raw_socket_support: bool,
    pub multicast_or_broadcast: bool,
    pub netfilter: bool,
    pub pf_nat: bool,
    pub pf_rdr: bool,
    pub network_extension_policy: bool,
    pub guest_created_network_namespaces: bool,
    pub requires_privilege: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkLeaseId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkLease {
    pub id: NetworkLeaseId,
}

/// A socket address as observed by the Linux guest namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GuestSocketAddr(pub SocketAddr);

/// A socket address Carrick passes to, or reads from, the host networking stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HostSocketAddr(pub SocketAddr);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkHostsEntry {
    pub addr: IpAddr,
    pub names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindTarget {
    Host(HostSocketAddr),
    Unchanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectTarget {
    Host(HostSocketAddr),
    Unchanged,
    Denied(i32),
}

pub trait NetworkProvider: Send + Sync {
    fn capabilities(&self) -> NetworkCapabilities;
    fn create_namespace(&self, spec: &NetworkNamespaceSpec) -> Result<NetworkLease, String>;
    fn destroy_namespace(&self, lease_id: NetworkLeaseId) -> Result<(), String>;
    fn publish_port(&self, lease_id: NetworkLeaseId, mapping: PortMapping) -> Result<(), String>;
    fn materialize_bind(
        &self,
        namespace_id: Option<&NetworkNamespaceId>,
        requested: GuestSocketAddr,
        protocol: PortProtocol,
    ) -> Result<BindTarget, String>;
    fn resolve_connect(
        &self,
        namespace_id: Option<&NetworkNamespaceId>,
        requested: GuestSocketAddr,
        protocol: PortProtocol,
    ) -> Result<ConnectTarget, String>;
    fn record_socket_addresses(
        &self,
        _namespace_id: Option<&NetworkNamespaceId>,
        _guest_fd: i32,
        _guest_local: Option<GuestSocketAddr>,
        _host_local: Option<HostSocketAddr>,
        _guest_peer: Option<GuestSocketAddr>,
        _protocol: PortProtocol,
    ) -> Result<(), String> {
        Ok(())
    }
    fn guest_visible_local_addr(&self, _guest_fd: i32) -> Result<Option<GuestSocketAddr>, String> {
        Ok(None)
    }
    fn guest_visible_peer_addr(&self, _guest_fd: i32) -> Result<Option<GuestSocketAddr>, String> {
        Ok(None)
    }
    fn translate_recv_addr(
        &self,
        _host_addr: HostSocketAddr,
        _protocol: PortProtocol,
    ) -> Result<Option<GuestSocketAddr>, String> {
        Ok(None)
    }
    fn prepare_listen(
        &self,
        _namespace_id: Option<&NetworkNamespaceId>,
        _guest_local: Option<GuestSocketAddr>,
        _host_local: Option<HostSocketAddr>,
        _protocol: PortProtocol,
        _reuse_port: bool,
    ) -> Result<(), i32> {
        Ok(())
    }
    fn guest_hosts_entries(
        &self,
        _spec: &NetworkNamespaceSpec,
    ) -> Result<Vec<NetworkHostsEntry>, String> {
        Ok(Vec::new())
    }
    fn resolve_dns_name(
        &self,
        _spec: &NetworkNamespaceSpec,
        _name: &str,
    ) -> Result<Vec<Ipv4Addr>, String> {
        Ok(Vec::new())
    }
}

#[derive(Debug, Default)]
pub struct HostNetworkProvider;

impl NetworkProvider for HostNetworkProvider {
    fn capabilities(&self) -> NetworkCapabilities {
        NetworkCapabilities {
            same_bridge_ip_connectivity: false,
            multi_network_attachments: false,
            embedded_dns: false,
            outbound_connectivity: true,
            published_ports: false,
            published_udp_ports: false,
            kernel_datapath: true,
            host_routable_container_ips: false,
            packet_level_isolation: false,
            raw_socket_support: false,
            multicast_or_broadcast: false,
            netfilter: false,
            pf_nat: false,
            pf_rdr: false,
            network_extension_policy: false,
            guest_created_network_namespaces: false,
            requires_privilege: false,
        }
    }

    fn create_namespace(&self, _spec: &NetworkNamespaceSpec) -> Result<NetworkLease, String> {
        Ok(NetworkLease {
            id: NetworkLeaseId(0),
        })
    }

    fn destroy_namespace(&self, _lease_id: NetworkLeaseId) -> Result<(), String> {
        Ok(())
    }

    fn publish_port(&self, _lease_id: NetworkLeaseId, _mapping: PortMapping) -> Result<(), String> {
        Ok(())
    }

    fn materialize_bind(
        &self,
        _namespace_id: Option<&NetworkNamespaceId>,
        _requested: GuestSocketAddr,
        _protocol: PortProtocol,
    ) -> Result<BindTarget, String> {
        Ok(BindTarget::Unchanged)
    }

    fn resolve_connect(
        &self,
        _namespace_id: Option<&NetworkNamespaceId>,
        _requested: GuestSocketAddr,
        _protocol: PortProtocol,
    ) -> Result<ConnectTarget, String> {
        Ok(ConnectTarget::Unchanged)
    }
}

#[derive(Debug, Default)]
pub struct NoNetworkProvider;

impl NetworkProvider for NoNetworkProvider {
    fn capabilities(&self) -> NetworkCapabilities {
        NetworkCapabilities {
            same_bridge_ip_connectivity: false,
            multi_network_attachments: false,
            embedded_dns: false,
            outbound_connectivity: false,
            published_ports: false,
            published_udp_ports: false,
            kernel_datapath: false,
            host_routable_container_ips: false,
            packet_level_isolation: true,
            raw_socket_support: false,
            multicast_or_broadcast: false,
            netfilter: false,
            pf_nat: false,
            pf_rdr: false,
            network_extension_policy: false,
            guest_created_network_namespaces: false,
            requires_privilege: false,
        }
    }

    fn create_namespace(&self, _spec: &NetworkNamespaceSpec) -> Result<NetworkLease, String> {
        Ok(NetworkLease {
            id: NetworkLeaseId(0),
        })
    }

    fn destroy_namespace(&self, _lease_id: NetworkLeaseId) -> Result<(), String> {
        Ok(())
    }

    fn publish_port(&self, _lease_id: NetworkLeaseId, _mapping: PortMapping) -> Result<(), String> {
        Err("network mode none does not support published ports".to_string())
    }

    fn materialize_bind(
        &self,
        _namespace_id: Option<&NetworkNamespaceId>,
        _requested: GuestSocketAddr,
        _protocol: PortProtocol,
    ) -> Result<BindTarget, String> {
        Err("network mode none does not support IPv4 bind".to_string())
    }

    fn resolve_connect(
        &self,
        _namespace_id: Option<&NetworkNamespaceId>,
        _requested: GuestSocketAddr,
        _protocol: PortProtocol,
    ) -> Result<ConnectTarget, String> {
        Ok(ConnectTarget::Denied(carrick_abi::LINUX_ENETUNREACH))
    }
}

pub fn select_provider(spec: &NetworkNamespaceSpec) -> Box<dyn NetworkProvider> {
    match spec.mode {
        NetworkMode::Host => Box::<HostNetworkProvider>::default(),
        NetworkMode::Bridge => Box::new(socket_namespace::SocketNamespaceProvider::new()),
        NetworkMode::None => Box::<NoNetworkProvider>::default(),
    }
}

pub struct RuntimeNetwork {
    pub spec: NetworkNamespaceSpec,
    pub(crate) model: model::LinuxNetworkModel,
    pub provider: Box<dyn NetworkProvider>,
    pub lease: NetworkLease,
}

impl RuntimeNetwork {
    pub fn create(spec: &NetworkNamespaceSpec) -> Result<Self, String> {
        let model = model::LinuxNetworkModel::from_spec(spec);
        let provider = select_provider(spec);
        let lease = provider.create_namespace(spec)?;
        for mapping in &spec.published_ports {
            provider.publish_port(lease.id, mapping.clone())?;
        }
        Ok(Self {
            spec: spec.clone(),
            model,
            provider,
            lease,
        })
    }

    pub fn host_default() -> Self {
        let spec = NetworkNamespaceSpec::default();
        let model = model::LinuxNetworkModel::from_spec(&spec);
        Self {
            spec,
            model,
            provider: Box::<HostNetworkProvider>::default(),
            lease: NetworkLease {
                id: NetworkLeaseId(0),
            },
        }
    }

    pub fn guest_hosts_entries(&self) -> Result<Vec<NetworkHostsEntry>, String> {
        self.provider.guest_hosts_entries(&self.spec)
    }

    pub fn resolve_dns_name(&self, name: &str) -> Result<Vec<Ipv4Addr>, String> {
        self.provider.resolve_dns_name(&self.spec, name)
    }
}

impl Drop for RuntimeNetwork {
    fn drop(&mut self) {
        let _ = self.provider.destroy_namespace(self.lease.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_provider_reports_host_capabilities() {
        let provider = select_provider(&NetworkNamespaceSpec::default());
        let caps = provider.capabilities();
        assert!(caps.kernel_datapath);
        assert!(caps.outbound_connectivity);
        assert!(!caps.same_bridge_ip_connectivity);
        assert!(!caps.multi_network_attachments);
        assert!(!caps.embedded_dns);
        assert!(!caps.published_udp_ports);
        assert!(!caps.host_routable_container_ips);
        assert!(!caps.netfilter);
        assert!(!caps.pf_nat);
        assert!(!caps.pf_rdr);
        assert!(!caps.network_extension_policy);
        assert!(!caps.guest_created_network_namespaces);
        assert!(!caps.requires_privilege);
    }

    #[test]
    fn bridge_provider_creates_nonzero_lease() {
        let network = RuntimeNetwork::create(&NetworkNamespaceSpec::bridge_default(
            Some("web".to_string()),
            Vec::new(),
            Vec::new(),
        ))
        .expect("create bridge network");
        assert_eq!(network.lease.id, NetworkLeaseId(1));
        assert_eq!(network.spec.mode, NetworkMode::Bridge);
        assert_eq!(
            network
                .model
                .links
                .iter()
                .map(|link| link.name.as_str())
                .collect::<Vec<_>>(),
            vec!["lo", "eth0"]
        );
    }

    #[test]
    fn bridge_provider_reports_v1_socket_capability_boundaries() {
        let provider = select_provider(&NetworkNamespaceSpec::bridge_default(
            Some("web".to_string()),
            Vec::new(),
            Vec::new(),
        ));
        let caps = provider.capabilities();

        assert!(caps.same_bridge_ip_connectivity);
        assert!(caps.multi_network_attachments);
        assert!(caps.embedded_dns);
        assert!(caps.outbound_connectivity);
        assert!(caps.published_ports);
        assert!(caps.published_udp_ports);
        assert!(!caps.kernel_datapath);
        assert!(!caps.host_routable_container_ips);
        assert!(!caps.packet_level_isolation);
        assert!(!caps.raw_socket_support);
        assert!(!caps.multicast_or_broadcast);
        assert!(!caps.netfilter);
        assert!(!caps.pf_nat);
        assert!(!caps.pf_rdr);
        assert!(!caps.network_extension_policy);
        assert!(!caps.guest_created_network_namespaces);
        assert!(!caps.requires_privilege);
    }

    #[test]
    fn network_mode_none_denies_ipv4_connects() {
        let network = RuntimeNetwork::create(&NetworkNamespaceSpec::none()).unwrap();
        let target = GuestSocketAddr("203.0.113.1:80".parse().unwrap());

        assert_eq!(
            network
                .provider
                .resolve_connect(None, target, PortProtocol::Tcp)
                .unwrap(),
            ConnectTarget::Denied(carrick_abi::LINUX_ENETUNREACH)
        );
        assert!(!network.provider.capabilities().outbound_connectivity);
    }
}
