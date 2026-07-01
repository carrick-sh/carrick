use super::{
    BindTarget, ConnectTarget, NetworkCapabilities, NetworkLease, NetworkLeaseId, NetworkProvider,
};
use carrick_spec::{BridgeId, NetworkNamespaceId, NetworkNamespaceSpec, PortMapping, PortProtocol};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug)]
pub struct SocketNamespaceProvider {
    registry: Arc<Mutex<HashMap<VirtualEndpoint, SocketAddr>>>,
    namespaces: Mutex<HashMap<NetworkNamespaceId, NetworkNamespaceSpec>>,
    socket_addrs: Mutex<HashMap<i32, SocketAddressState>>,
    published_tcp: Mutex<HashMap<NetworkLeaseId, Vec<PublishedTcpProxy>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct VirtualEndpoint {
    bridge_id: BridgeId,
    addr: SocketAddr,
    protocol: PortProtocol,
}

#[derive(Debug, Clone, Default)]
struct SocketAddressState {
    guest_local: Option<SocketAddr>,
    _host_local: Option<SocketAddr>,
    guest_peer: Option<SocketAddr>,
}

#[derive(Debug)]
struct PublishedTcpProxy {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for PublishedTcpProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Default for SocketNamespaceProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SocketNamespaceProvider {
    pub fn new() -> Self {
        Self {
            registry: Arc::new(Mutex::new(HashMap::new())),
            namespaces: Mutex::new(HashMap::new()),
            socket_addrs: Mutex::new(HashMap::new()),
            published_tcp: Mutex::new(HashMap::new()),
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

    pub fn resolve_bridge_connect(
        &self,
        spec: &NetworkNamespaceSpec,
        requested: SocketAddr,
        protocol: PortProtocol,
    ) -> Result<ConnectTarget, String> {
        if let Some(host) = self.resolve_registered_connect(&spec.bridge_id, requested, protocol)? {
            return Ok(ConnectTarget::Host(host));
        }

        match requested.ip() {
            IpAddr::V4(ip) if ip.octets()[0] == 172 && ip.octets()[1] == 31 => {
                Ok(ConnectTarget::Denied(carrick_abi::LINUX_ECONNREFUSED))
            }
            _ => Ok(ConnectTarget::Unchanged),
        }
    }

    pub fn record_socket_addresses(
        &self,
        guest_fd: i32,
        guest_local: Option<SocketAddr>,
        host_local: Option<SocketAddr>,
        guest_peer: Option<SocketAddr>,
        protocol: PortProtocol,
    ) -> Result<(), String> {
        let mut socket_addrs = self
            .socket_addrs
            .lock()
            .map_err(|_| "socket address registry lock poisoned".to_string())?;
        socket_addrs.insert(
            guest_fd,
            SocketAddressState {
                guest_local,
                _host_local: host_local,
                guest_peer,
            },
        );
        drop(socket_addrs);

        if let (Some(guest), Some(host)) = (guest_local, host_local) {
            let endpoints = {
                let namespaces = self
                    .namespaces
                    .lock()
                    .map_err(|_| "socket namespace registry lock poisoned".to_string())?;
                namespaces
                    .iter()
                    .filter_map(|(namespace_id, spec)| {
                        let IpAddr::V4(guest_ip) = guest.ip() else {
                            return None;
                        };
                        if guest_ip == spec.ipv4 || guest_ip == Ipv4Addr::UNSPECIFIED {
                            let virtual_ip = if guest_ip == Ipv4Addr::UNSPECIFIED {
                                spec.ipv4
                            } else {
                                guest_ip
                            };
                            Some((
                                spec.bridge_id.clone(),
                                namespace_id.clone(),
                                SocketAddr::new(IpAddr::V4(virtual_ip), guest.port()),
                            ))
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            };
            for (bridge_id, namespace_id, virtual_addr) in endpoints {
                self.register_virtual_endpoint(
                    bridge_id,
                    namespace_id,
                    virtual_addr,
                    protocol,
                    host,
                )?;
            }
        }
        Ok(())
    }

    pub fn guest_visible_local_addr(&self, guest_fd: i32) -> Result<Option<SocketAddr>, String> {
        let socket_addrs = self
            .socket_addrs
            .lock()
            .map_err(|_| "socket address registry lock poisoned".to_string())?;
        Ok(socket_addrs.get(&guest_fd).and_then(|s| s.guest_local))
    }

    pub fn guest_visible_peer_addr(&self, guest_fd: i32) -> Result<Option<SocketAddr>, String> {
        let socket_addrs = self
            .socket_addrs
            .lock()
            .map_err(|_| "socket address registry lock poisoned".to_string())?;
        Ok(socket_addrs.get(&guest_fd).and_then(|s| s.guest_peer))
    }

    fn first_namespace_spec(&self) -> Result<NetworkNamespaceSpec, String> {
        let namespaces = self
            .namespaces
            .lock()
            .map_err(|_| "socket namespace registry lock poisoned".to_string())?;
        namespaces
            .values()
            .next()
            .cloned()
            .ok_or_else(|| "no network namespace exists for published port".to_string())
    }

    fn publish_tcp(&self, lease_id: NetworkLeaseId, mapping: PortMapping) -> Result<(), String> {
        let spec = self.first_namespace_spec()?;
        let host_ip = mapping.host_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let host_port = mapping.host_port.unwrap_or(0);
        let listener = TcpListener::bind(SocketAddr::new(host_ip, host_port))
            .map_err(|e| format!("failed to bind published TCP port {host_ip}:{host_port}: {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("failed to configure published TCP listener: {e}"))?;
        let stop = Arc::new(AtomicBool::new(false));
        let target = VirtualEndpoint {
            bridge_id: spec.bridge_id,
            addr: SocketAddr::new(IpAddr::V4(spec.ipv4), mapping.container_port),
            protocol: PortProtocol::Tcp,
        };
        let registry = Arc::clone(&self.registry);
        let thread_stop = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("carrick-bridge-publish-tcp".to_string())
            .spawn(move || published_tcp_accept_loop(listener, registry, target, thread_stop))
            .map_err(|e| format!("failed to start published TCP proxy: {e}"))?;
        let mut published_tcp = self
            .published_tcp
            .lock()
            .map_err(|_| "published TCP registry lock poisoned".to_string())?;
        published_tcp
            .entry(lease_id)
            .or_default()
            .push(PublishedTcpProxy {
                stop,
                handle: Some(handle),
            });
        Ok(())
    }
}

fn published_tcp_accept_loop(
    listener: TcpListener,
    registry: Arc<Mutex<HashMap<VirtualEndpoint, SocketAddr>>>,
    target: VirtualEndpoint,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((inbound, _)) => {
                let target_addr = registry
                    .lock()
                    .ok()
                    .and_then(|registry| registry.get(&target).copied());
                if let Some(target_addr) = target_addr {
                    let _ = thread::Builder::new()
                        .name("carrick-bridge-publish-tcp-stream".to_string())
                        .spawn(move || {
                            let _ = proxy_tcp_stream(inbound, target_addr);
                        });
                }
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn proxy_tcp_stream(mut inbound: TcpStream, target: SocketAddr) -> io::Result<()> {
    let mut outbound = TcpStream::connect(target)?;
    let mut inbound_clone = inbound.try_clone()?;
    let mut outbound_clone = outbound.try_clone()?;
    let left = thread::spawn(move || io::copy(&mut inbound_clone, &mut outbound));
    let right = thread::spawn(move || io::copy(&mut outbound_clone, &mut inbound));
    let _ = left.join();
    let _ = right.join();
    Ok(())
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

    fn publish_port(&self, lease_id: NetworkLeaseId, mapping: PortMapping) -> Result<(), String> {
        match mapping.protocol {
            PortProtocol::Tcp => self.publish_tcp(lease_id, mapping),
            PortProtocol::Udp => Err(format!(
                "published UDP ports are not supported by the socket namespace provider: {}",
                mapping.container_port
            )),
        }
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
        namespace_id: Option<&NetworkNamespaceId>,
        requested: SocketAddr,
        protocol: PortProtocol,
    ) -> Result<ConnectTarget, String> {
        let Some(namespace_id) = namespace_id else {
            return Ok(ConnectTarget::Unchanged);
        };
        let spec = {
            let namespaces = self
                .namespaces
                .lock()
                .map_err(|_| "socket namespace registry lock poisoned".to_string())?;
            namespaces.get(namespace_id).cloned()
        };
        let Some(spec) = spec else {
            return Ok(ConnectTarget::Unchanged);
        };
        self.resolve_bridge_connect(&spec, requested, protocol)
    }

    fn record_socket_addresses(
        &self,
        guest_fd: i32,
        guest_local: Option<SocketAddr>,
        host_local: Option<SocketAddr>,
        guest_peer: Option<SocketAddr>,
        protocol: PortProtocol,
    ) -> Result<(), String> {
        self.record_socket_addresses(guest_fd, guest_local, host_local, guest_peer, protocol)
    }

    fn guest_visible_local_addr(&self, guest_fd: i32) -> Result<Option<SocketAddr>, String> {
        self.guest_visible_local_addr(guest_fd)
    }

    fn guest_visible_peer_addr(&self, guest_fd: i32) -> Result<Option<SocketAddr>, String> {
        self.guest_visible_peer_addr(guest_fd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_spec::{BridgeId, NetworkNamespaceId, PortMapping, PortProtocol};
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::thread;

    fn free_loopback_port() -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve port");
        listener.local_addr().expect("local addr").port()
    }

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

    #[test]
    fn bridge_connect_to_registered_peer_rewrites_to_loopback() {
        let spec = NetworkNamespaceSpec::bridge_default(None, Vec::new(), Vec::new());
        let provider = SocketNamespaceProvider::new();
        provider.create_namespace(&spec).expect("namespace");
        let peer = SocketAddr::new(IpAddr::V4(spec.ipv4), 8080);
        provider
            .register_virtual_endpoint(
                spec.bridge_id.clone(),
                spec.namespace_id.clone().unwrap(),
                peer,
                PortProtocol::Tcp,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50080),
            )
            .expect("register");

        let target = provider
            .resolve_bridge_connect(&spec, peer, PortProtocol::Tcp)
            .expect("resolve");
        assert_eq!(
            target,
            ConnectTarget::Host(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50080))
        );
    }

    #[test]
    fn records_guest_visible_local_address_for_rewritten_bind() {
        let provider = SocketNamespaceProvider::new();
        let guest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 31, 0, 2)), 80);
        let host = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50080);
        provider
            .record_socket_addresses(7, Some(guest), Some(host), None, PortProtocol::Tcp)
            .expect("record");
        let visible = provider.guest_visible_local_addr(7).expect("visible addr");
        assert_eq!(visible, Some(guest));
    }

    #[test]
    fn publish_tcp_forwards_after_container_endpoint_registers() {
        let host_port = free_loopback_port();
        let mapping = PortMapping {
            host_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            host_port: Some(host_port),
            container_port: 8080,
            protocol: PortProtocol::Tcp,
        };
        let spec = NetworkNamespaceSpec::bridge_default(None, Vec::new(), vec![mapping.clone()]);
        let provider = SocketNamespaceProvider::new();
        let lease = provider.create_namespace(&spec).expect("namespace");
        provider.publish_port(lease.id, mapping).expect("publish");

        let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("target bind");
        let target_addr = target_listener.local_addr().expect("target addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = target_listener.accept().expect("target accept");
            let mut buf = [0_u8; 4];
            stream.read_exact(&mut buf).expect("read ping");
            stream.write_all(b"ok").expect("write ok");
        });
        let peer = SocketAddr::new(IpAddr::V4(spec.ipv4), 8080);
        provider
            .register_virtual_endpoint(
                spec.bridge_id.clone(),
                spec.namespace_id.clone().expect("namespace id"),
                peer,
                PortProtocol::Tcp,
                target_addr,
            )
            .expect("register");

        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, host_port)).expect("connect");
        client.write_all(b"ping").expect("write ping");
        let mut reply = [0_u8; 2];
        client.read_exact(&mut reply).expect("read reply");
        server.join().expect("server thread");

        assert_eq!(&reply, b"ok");
    }
}
