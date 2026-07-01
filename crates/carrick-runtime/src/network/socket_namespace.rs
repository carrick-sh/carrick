use super::{
    BindTarget, ConnectTarget, NetworkCapabilities, NetworkLease, NetworkLeaseId, NetworkProvider,
};
use carrick_spec::{BridgeId, NetworkNamespaceId, NetworkNamespaceSpec, PortMapping, PortProtocol};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Mutex;

#[derive(Debug, Default)]
pub struct SocketNamespaceProvider {
    registry: Mutex<HashMap<VirtualEndpoint, SocketAddr>>,
    namespaces: Mutex<HashMap<NetworkNamespaceId, NetworkNamespaceSpec>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct VirtualEndpoint {
    bridge_id: BridgeId,
    addr: SocketAddr,
    protocol: PortProtocol,
}

impl SocketNamespaceProvider {
    pub fn new() -> Self {
        Self {
            registry: Mutex::new(HashMap::new()),
            namespaces: Mutex::new(HashMap::new()),
        }
    }

    pub fn register_virtual_endpoint(
        &self,
        bridge_id: BridgeId,
        _namespace_id: NetworkNamespaceId,
        virtual_addr: SocketAddr,
        protocol: PortProtocol,
        host_addr: SocketAddr,
    ) -> Result<(), String> {
        let key = VirtualEndpoint {
            bridge_id,
            addr: virtual_addr,
            protocol,
        };
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| "socket namespace registry lock poisoned".to_string())?;
        registry.insert(key, host_addr);
        Ok(())
    }

    pub fn resolve_registered_connect(
        &self,
        bridge_id: &BridgeId,
        virtual_addr: SocketAddr,
        protocol: PortProtocol,
    ) -> Result<Option<SocketAddr>, String> {
        let key = VirtualEndpoint {
            bridge_id: bridge_id.clone(),
            addr: virtual_addr,
            protocol,
        };
        let registry = self
            .registry
            .lock()
            .map_err(|_| "socket namespace registry lock poisoned".to_string())?;
        Ok(registry.get(&key).copied())
    }

    pub fn materialize_bridge_bind(
        &self,
        spec: &NetworkNamespaceSpec,
        requested: SocketAddr,
        protocol: PortProtocol,
    ) -> Result<BindTarget, String> {
        match requested.ip() {
            IpAddr::V4(ip) if ip == spec.ipv4 || ip == Ipv4Addr::UNSPECIFIED => {
                let host = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
                if let Some(namespace_id) = spec.namespace_id.clone() {
                    let virtual_ip = if ip == Ipv4Addr::UNSPECIFIED {
                        spec.ipv4
                    } else {
                        ip
                    };
                    self.register_virtual_endpoint(
                        spec.bridge_id.clone(),
                        namespace_id,
                        SocketAddr::new(IpAddr::V4(virtual_ip), requested.port()),
                        protocol,
                        host,
                    )?;
                }
                Ok(BindTarget::Host(host))
            }
            IpAddr::V4(ip) if ip == Ipv4Addr::LOCALHOST => Ok(BindTarget::Unchanged),
            _ => Err(format!(
                "address is not assigned to network namespace: {requested}"
            )),
        }
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

    fn create_namespace(&self, spec: &NetworkNamespaceSpec) -> Result<NetworkLease, String> {
        if let Some(namespace_id) = spec.namespace_id.clone() {
            let mut namespaces = self
                .namespaces
                .lock()
                .map_err(|_| "socket namespace registry lock poisoned".to_string())?;
            namespaces.insert(namespace_id, spec.clone());
        }
        Ok(NetworkLease {
            id: NetworkLeaseId(1),
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
        namespace_id: Option<&NetworkNamespaceId>,
        requested: SocketAddr,
        protocol: PortProtocol,
    ) -> Result<BindTarget, String> {
        let Some(namespace_id) = namespace_id else {
            return Ok(BindTarget::Unchanged);
        };
        let spec = {
            let namespaces = self
                .namespaces
                .lock()
                .map_err(|_| "socket namespace registry lock poisoned".to_string())?;
            namespaces.get(namespace_id).cloned()
        };
        let Some(spec) = spec else {
            return Ok(BindTarget::Unchanged);
        };
        self.materialize_bridge_bind(&spec, requested, protocol)
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

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_spec::{BridgeId, NetworkNamespaceId, PortProtocol};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn provider_with_endpoint() -> SocketNamespaceProvider {
        let provider = SocketNamespaceProvider::new();
        provider
            .register_virtual_endpoint(
                BridgeId::new("carrick0"),
                NetworkNamespaceId::new("a"),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 31, 0, 2)), 80),
                PortProtocol::Tcp,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 49152),
            )
            .expect("register endpoint");
        provider
    }

    #[test]
    fn resolves_same_bridge_virtual_endpoint() {
        let provider = provider_with_endpoint();
        let target = provider
            .resolve_registered_connect(
                &BridgeId::new("carrick0"),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 31, 0, 2)), 80),
                PortProtocol::Tcp,
            )
            .expect("lookup")
            .expect("registered target");
        assert_eq!(
            target,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 49152)
        );
    }

    #[test]
    fn does_not_resolve_different_bridge_virtual_endpoint() {
        let provider = provider_with_endpoint();
        let target = provider
            .resolve_registered_connect(
                &BridgeId::new("carrick1"),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 31, 0, 2)), 80),
                PortProtocol::Tcp,
            )
            .expect("lookup");
        assert!(target.is_none());
    }

    #[test]
    fn materialize_bind_maps_container_ip_to_loopback() {
        let spec = NetworkNamespaceSpec::bridge_default(None, Vec::new(), Vec::new());
        let provider = SocketNamespaceProvider::new();
        provider.create_namespace(&spec).expect("namespace");
        let requested = SocketAddr::new(IpAddr::V4(spec.ipv4), 80);
        let target = provider
            .materialize_bridge_bind(&spec, requested, PortProtocol::Tcp)
            .expect("bind target");
        match target {
            BindTarget::Host(host) => {
                assert_eq!(host.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
                assert_eq!(host.port(), 0);
            }
            other => panic!("expected host bind target, got {other:?}"),
        }
    }

    #[test]
    fn materialize_bind_rejects_foreign_container_ip() {
        let spec = NetworkNamespaceSpec::bridge_default(None, Vec::new(), Vec::new());
        let provider = SocketNamespaceProvider::new();
        let requested = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 31, 0, 99)), 80);
        let err = provider
            .materialize_bridge_bind(&spec, requested, PortProtocol::Tcp)
            .expect_err("foreign address should fail");
        assert!(err.contains("address is not assigned"));
    }
}
