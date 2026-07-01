use carrick_spec::{
    NetworkMode, NetworkNamespaceId, NetworkNamespaceSpec, PortMapping, PortProtocol,
};
use std::net::SocketAddr;

pub mod socket_namespace;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkCapabilities {
    pub same_bridge_ip_connectivity: bool,
    pub outbound_connectivity: bool,
    pub published_ports: bool,
    pub kernel_datapath: bool,
    pub host_routable_container_ips: bool,
    pub packet_level_isolation: bool,
    pub raw_socket_support: bool,
    pub multicast_or_broadcast: bool,
    pub requires_privilege: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkLeaseId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkLease {
    pub id: NetworkLeaseId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindTarget {
    Host(SocketAddr),
    Unchanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectTarget {
    Host(SocketAddr),
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
        requested: SocketAddr,
        protocol: PortProtocol,
    ) -> Result<BindTarget, String>;
    fn resolve_connect(
        &self,
        namespace_id: Option<&NetworkNamespaceId>,
        requested: SocketAddr,
        protocol: PortProtocol,
    ) -> Result<ConnectTarget, String>;
}

#[derive(Debug, Default)]
pub struct HostNetworkProvider;

impl NetworkProvider for HostNetworkProvider {
    fn capabilities(&self) -> NetworkCapabilities {
        NetworkCapabilities {
            same_bridge_ip_connectivity: false,
            outbound_connectivity: true,
            published_ports: false,
            kernel_datapath: true,
            host_routable_container_ips: false,
            packet_level_isolation: false,
            raw_socket_support: false,
            multicast_or_broadcast: false,
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
        _requested: SocketAddr,
        _protocol: PortProtocol,
    ) -> Result<BindTarget, String> {
        Ok(BindTarget::Unchanged)
    }

    fn resolve_connect(
        &self,
        _namespace_id: Option<&NetworkNamespaceId>,
        _requested: SocketAddr,
        _protocol: PortProtocol,
    ) -> Result<ConnectTarget, String> {
        Ok(ConnectTarget::Unchanged)
    }
}

pub fn select_provider(spec: &NetworkNamespaceSpec) -> Box<dyn NetworkProvider> {
    match spec.mode {
        NetworkMode::Host => Box::<HostNetworkProvider>::default(),
        NetworkMode::Bridge => Box::new(socket_namespace::SocketNamespaceProvider::new()),
    }
}

pub struct RuntimeNetwork {
    pub spec: NetworkNamespaceSpec,
    pub provider: Box<dyn NetworkProvider>,
    pub lease: NetworkLease,
}

impl RuntimeNetwork {
    pub fn create(spec: &NetworkNamespaceSpec) -> Result<Self, String> {
        let provider = select_provider(spec);
        let lease = provider.create_namespace(spec)?;
        for mapping in &spec.published_ports {
            provider.publish_port(lease.id, mapping.clone())?;
        }
        Ok(Self {
            spec: spec.clone(),
            provider,
            lease,
        })
    }

    pub fn host_default() -> Self {
        Self {
            spec: NetworkNamespaceSpec::default(),
            provider: Box::<HostNetworkProvider>::default(),
            lease: NetworkLease {
                id: NetworkLeaseId(0),
            },
        }
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
        assert!(!caps.host_routable_container_ips);
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
    }
}
