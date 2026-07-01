use super::{
    BindTarget, ConnectTarget, NetworkCapabilities, NetworkLease, NetworkLeaseId, NetworkProvider,
};
use carrick_spec::{NetworkNamespaceId, NetworkNamespaceSpec, PortMapping};
use std::net::SocketAddr;

#[derive(Debug, Default)]
pub struct SocketNamespaceProvider;

impl SocketNamespaceProvider {
    pub fn new() -> Self {
        Self
    }
}

impl NetworkProvider for SocketNamespaceProvider {
    fn capabilities(&self) -> NetworkCapabilities {
        NetworkCapabilities {
            same_bridge_ip_connectivity: true,
            outbound_connectivity: true,
            published_ports: true,
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
            id: NetworkLeaseId(1),
        })
    }

    fn destroy_namespace(&self, _lease_id: NetworkLeaseId) -> Result<(), String> {
        Ok(())
    }

    fn publish_port(
        &self,
        _lease_id: NetworkLeaseId,
        _mapping: PortMapping,
    ) -> Result<(), String> {
        Ok(())
    }

    fn materialize_bind(
        &self,
        _namespace_id: Option<&NetworkNamespaceId>,
        _requested: SocketAddr,
    ) -> Result<BindTarget, String> {
        Ok(BindTarget::Unchanged)
    }

    fn resolve_connect(
        &self,
        _namespace_id: Option<&NetworkNamespaceId>,
        _requested: SocketAddr,
    ) -> Result<ConnectTarget, String> {
        Ok(ConnectTarget::Unchanged)
    }
}
