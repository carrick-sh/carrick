use super::{
    BindTarget, ConnectTarget, GuestSocketAddr, HostSocketAddr, NetworkCapabilities,
    NetworkHostsEntry, NetworkLease, NetworkLeaseId, NetworkProvider,
};
use carrick_spec::{
    BridgeId, NetworkAttachmentSpec, NetworkNamespaceId, NetworkNamespaceSpec, PortMapping,
    PortProtocol,
};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug)]
pub struct SocketNamespaceProvider {
    registry: Arc<Mutex<HashMap<VirtualEndpoint, HostSocketAddr>>>,
    tcp_listeners: Mutex<HashMap<VirtualEndpoint, ListenerReservation>>,
    endpoint_dir: Arc<PathBuf>,
    owned_endpoint_files: Mutex<Vec<OwnedEndpointFile>>,
    namespaces: Mutex<HashMap<NetworkNamespaceId, NetworkNamespaceSpec>>,
    socket_addrs: Mutex<HashMap<i32, SocketAddressState>>,
    published_tcp: Mutex<HashMap<NetworkLeaseId, Vec<PublishedTcpProxy>>>,
    published_udp: Mutex<HashMap<NetworkLeaseId, Vec<PublishedUdpProxy>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct VirtualEndpoint {
    scope: EndpointScope,
    addr: GuestSocketAddr,
    protocol: PortProtocol,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum EndpointScope {
    Bridge(BridgeId),
    Namespace(NetworkNamespaceId),
}

#[derive(Debug, Clone, Default)]
struct SocketAddressState {
    guest_local: Option<GuestSocketAddr>,
    _host_local: Option<HostSocketAddr>,
    guest_peer: Option<GuestSocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnedEndpointFile {
    path: PathBuf,
    contents: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NamespaceFile {
    Live(String),
    Stale(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ListenerReservation {
    host_addr: HostSocketAddr,
    reuse_port: bool,
}

#[derive(Debug)]
struct PublishedTcpProxy {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

#[derive(Debug)]
struct PublishedUdpProxy {
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

impl Drop for PublishedUdpProxy {
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
        let endpoint_dir = shared_endpoint_dir();
        let _ = fs::create_dir_all(&endpoint_dir);
        Self {
            registry: Arc::new(Mutex::new(HashMap::new())),
            tcp_listeners: Mutex::new(HashMap::new()),
            endpoint_dir: Arc::new(endpoint_dir),
            owned_endpoint_files: Mutex::new(Vec::new()),
            namespaces: Mutex::new(HashMap::new()),
            socket_addrs: Mutex::new(HashMap::new()),
            published_tcp: Mutex::new(HashMap::new()),
            published_udp: Mutex::new(HashMap::new()),
        }
    }

    pub fn register_virtual_endpoint(
        &self,
        bridge_id: BridgeId,
        namespace_id: NetworkNamespaceId,
        virtual_addr: GuestSocketAddr,
        protocol: PortProtocol,
        host_addr: HostSocketAddr,
    ) -> Result<(), String> {
        let key = VirtualEndpoint {
            scope: endpoint_scope(bridge_id, namespace_id, virtual_addr),
            addr: virtual_addr,
            protocol,
        };
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| "socket namespace registry lock poisoned".to_string())?;
        registry.insert(key.clone(), host_addr);
        drop(registry);
        self.write_endpoint_file(&key, host_addr)?;
        Ok(())
    }

    fn register_service_names(&self, spec: &NetworkNamespaceSpec) -> Result<(), String> {
        for attachment in effective_attachments(spec) {
            let names = service_names_for(attachment.container_name.as_ref(), &attachment.aliases);
            for name in names {
                let path = service_name_path(
                    &self.endpoint_dir,
                    &attachment.bridge_id,
                    &name,
                    attachment.ipv4,
                );
                let contents = encode_service_name(attachment.ipv4, &name);
                fs::create_dir_all(&*self.endpoint_dir).map_err(|e| {
                    format!("failed to create socket namespace endpoint directory: {e}")
                })?;
                fs::write(&path, &contents)
                    .map_err(|e| format!("failed to record socket namespace service name: {e}"))?;
                self.track_owned_file(path, contents)?;
            }
        }
        Ok(())
    }

    fn service_hosts_entries(
        &self,
        spec: &NetworkNamespaceSpec,
    ) -> Result<Vec<NetworkHostsEntry>, String> {
        let mut entries = Vec::new();
        let prefixes = effective_attachments(spec)
            .into_iter()
            .map(|attachment| format!("service-{}-", attachment.bridge_id.as_str()))
            .collect::<Vec<_>>();
        let Ok(dir) = fs::read_dir(&*self.endpoint_dir) else {
            return Ok(entries);
        };
        for entry in dir.flatten() {
            let file_name = entry.file_name();
            let Some(file_name) = file_name.to_str() else {
                continue;
            };
            if !prefixes.iter().any(|prefix| file_name.starts_with(prefix)) {
                continue;
            }
            let Some(raw) = read_live_namespace_file(&entry.path()) else {
                continue;
            };
            if let Some((addr, name)) = decode_service_name(&raw) {
                entries.push(NetworkHostsEntry {
                    addr: IpAddr::V4(addr),
                    names: vec![name],
                });
            }
        }
        entries.sort_by(|a, b| {
            a.addr
                .to_string()
                .cmp(&b.addr.to_string())
                .then_with(|| a.names.cmp(&b.names))
        });
        entries.dedup();
        Ok(entries)
    }

    fn resolve_service_name(
        &self,
        spec: &NetworkNamespaceSpec,
        query_name: &str,
    ) -> Result<Vec<Ipv4Addr>, String> {
        let query_name = query_name.trim_end_matches('.');
        if query_name.is_empty() {
            return Ok(Vec::new());
        }
        let bridge_ids = effective_attachments(spec)
            .into_iter()
            .map(|attachment| attachment.bridge_id)
            .collect::<Vec<_>>();
        let mut addrs = Vec::new();
        for bridge_id in bridge_ids {
            let Ok(dir) = fs::read_dir(&*self.endpoint_dir) else {
                continue;
            };
            let prefix = service_name_path_prefix(&bridge_id, query_name);
            for entry in dir.flatten() {
                let file_name = entry.file_name();
                let Some(file_name) = file_name.to_str() else {
                    continue;
                };
                if !file_name.starts_with(&prefix) {
                    continue;
                }
                let Some(raw) = read_live_namespace_file(&entry.path()) else {
                    continue;
                };
                if let Some((addr, _)) = decode_service_name(&raw)
                    && !addrs.contains(&addr)
                {
                    addrs.push(addr);
                }
            }
        }
        addrs.sort_unstable();
        Ok(addrs)
    }

    pub fn resolve_registered_connect(
        &self,
        bridge_id: &BridgeId,
        virtual_addr: GuestSocketAddr,
        protocol: PortProtocol,
    ) -> Result<Option<HostSocketAddr>, String> {
        let key = VirtualEndpoint {
            scope: EndpointScope::Bridge(bridge_id.clone()),
            addr: virtual_addr,
            protocol,
        };
        self.resolve_registered_endpoint(&key)
    }

    fn resolve_registered_namespace_connect(
        &self,
        namespace_id: &NetworkNamespaceId,
        virtual_addr: GuestSocketAddr,
        protocol: PortProtocol,
    ) -> Result<Option<HostSocketAddr>, String> {
        let key = VirtualEndpoint {
            scope: EndpointScope::Namespace(namespace_id.clone()),
            addr: virtual_addr,
            protocol,
        };
        self.resolve_registered_endpoint(&key)
    }

    fn resolve_registered_endpoint(
        &self,
        key: &VirtualEndpoint,
    ) -> Result<Option<HostSocketAddr>, String> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| "socket namespace registry lock poisoned".to_string())?;
        if let Some(host) = registry.get(key).copied() {
            return Ok(Some(host));
        }
        drop(registry);
        Ok(read_endpoint_file(&self.endpoint_dir, key))
    }

    pub fn materialize_bridge_bind(
        &self,
        spec: &NetworkNamespaceSpec,
        requested: GuestSocketAddr,
        protocol: PortProtocol,
    ) -> Result<BindTarget, String> {
        let IpAddr::V4(ip) = requested.0.ip() else {
            return Err(format!(
                "address is not assigned to network namespace: {}",
                requested.0
            ));
        };
        let attachments = effective_attachments(spec);
        let selected = if ip == Ipv4Addr::UNSPECIFIED {
            attachments
        } else if ip.is_loopback() {
            attachments.into_iter().take(1).collect()
        } else {
            attachments
                .into_iter()
                .filter(|attachment| attachment.ipv4 == ip)
                .collect()
        };
        if selected.is_empty() {
            return Err(format!(
                "address is not assigned to network namespace: {}",
                requested.0
            ));
        }
        match requested.0.ip() {
            IpAddr::V4(ip) => {
                let host = HostSocketAddr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
                if let Some(namespace_id) = spec.namespace_id.clone() {
                    for attachment in selected {
                        let virtual_ip = if ip == Ipv4Addr::UNSPECIFIED {
                            attachment.ipv4
                        } else {
                            ip
                        };
                        self.register_virtual_endpoint(
                            attachment.bridge_id,
                            namespace_id.clone(),
                            GuestSocketAddr(SocketAddr::new(
                                IpAddr::V4(virtual_ip),
                                requested.0.port(),
                            )),
                            protocol,
                            host,
                        )?;
                    }
                }
                Ok(BindTarget::Host(host))
            }
            _ => Err(format!(
                "address is not assigned to network namespace: {}",
                requested.0
            )),
        }
    }

    pub fn resolve_bridge_connect(
        &self,
        spec: &NetworkNamespaceSpec,
        requested: GuestSocketAddr,
        protocol: PortProtocol,
    ) -> Result<ConnectTarget, String> {
        if requested.0.ip().is_loopback() {
            if let Some(namespace_id) = spec.namespace_id.as_ref()
                && let Some(host) =
                    self.resolve_registered_namespace_connect(namespace_id, requested, protocol)?
            {
                return Ok(ConnectTarget::Host(host));
            }
            return Ok(ConnectTarget::Denied(carrick_abi::LINUX_ECONNREFUSED));
        }
        for attachment in effective_attachments(spec) {
            if let Some(host) =
                self.resolve_registered_connect(&attachment.bridge_id, requested, protocol)?
            {
                return Ok(ConnectTarget::Host(host));
            }
        }
        if let IpAddr::V4(ip) = requested.0.ip()
            && effective_attachments(spec)
                .into_iter()
                .any(|attachment| ip == attachment.gateway_v4)
        {
            return Ok(ConnectTarget::Host(HostSocketAddr(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                requested.0.port(),
            ))));
        }

        match requested.0.ip() {
            IpAddr::V4(ip) if ip.octets()[0] == 172 && ip.octets()[1] == 31 => {
                Ok(ConnectTarget::Denied(carrick_abi::LINUX_ECONNREFUSED))
            }
            _ => Ok(ConnectTarget::Unchanged),
        }
    }

    pub fn record_socket_addresses(
        &self,
        namespace_id: Option<&NetworkNamespaceId>,
        guest_fd: i32,
        guest_local: Option<GuestSocketAddr>,
        host_local: Option<HostSocketAddr>,
        guest_peer: Option<GuestSocketAddr>,
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
                let guest_ip = match guest.0.ip() {
                    IpAddr::V4(ip) => ip,
                    IpAddr::V6(_) => return Ok(()),
                };
                if guest_ip.is_loopback() {
                    namespace_id
                        .and_then(|namespace_id| {
                            namespaces.get(namespace_id).map(|spec| {
                                let bridge_id = effective_attachments(spec)
                                    .into_iter()
                                    .next()
                                    .map(|attachment| attachment.bridge_id)
                                    .unwrap_or_else(|| spec.bridge_id.clone());
                                (
                                    bridge_id,
                                    namespace_id.clone(),
                                    GuestSocketAddr(SocketAddr::new(
                                        IpAddr::V4(guest_ip),
                                        guest.0.port(),
                                    )),
                                )
                            })
                        })
                        .into_iter()
                        .collect::<Vec<_>>()
                } else {
                    let namespace_specs = namespace_id
                        .and_then(|namespace_id| {
                            namespaces
                                .get(namespace_id)
                                .map(|spec| vec![(namespace_id.clone(), spec.clone())])
                        })
                        .unwrap_or_else(|| {
                            namespaces
                                .iter()
                                .map(|(namespace_id, spec)| (namespace_id.clone(), spec.clone()))
                                .collect()
                        });
                    namespace_specs
                        .into_iter()
                        .flat_map(|(namespace_id, spec)| {
                            effective_attachments(&spec)
                                .into_iter()
                                .filter_map(move |attachment| {
                                    if guest_ip == attachment.ipv4
                                        || guest_ip == Ipv4Addr::UNSPECIFIED
                                    {
                                        let virtual_ip = if guest_ip == Ipv4Addr::UNSPECIFIED {
                                            attachment.ipv4
                                        } else {
                                            guest_ip
                                        };
                                        Some((
                                            attachment.bridge_id,
                                            namespace_id.clone(),
                                            GuestSocketAddr(SocketAddr::new(
                                                IpAddr::V4(virtual_ip),
                                                guest.0.port(),
                                            )),
                                        ))
                                    } else {
                                        None
                                    }
                                })
                        })
                        .collect::<Vec<_>>()
                }
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

    pub fn guest_visible_local_addr(
        &self,
        guest_fd: i32,
    ) -> Result<Option<GuestSocketAddr>, String> {
        let socket_addrs = self
            .socket_addrs
            .lock()
            .map_err(|_| "socket address registry lock poisoned".to_string())?;
        Ok(socket_addrs.get(&guest_fd).and_then(|s| s.guest_local))
    }

    pub fn guest_visible_peer_addr(
        &self,
        guest_fd: i32,
    ) -> Result<Option<GuestSocketAddr>, String> {
        let socket_addrs = self
            .socket_addrs
            .lock()
            .map_err(|_| "socket address registry lock poisoned".to_string())?;
        Ok(socket_addrs.get(&guest_fd).and_then(|s| s.guest_peer))
    }

    pub fn translate_host_source(
        &self,
        host_addr: HostSocketAddr,
        protocol: PortProtocol,
    ) -> Result<Option<GuestSocketAddr>, String> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| "socket namespace registry lock poisoned".to_string())?;
        Ok(registry.iter().find_map(|(endpoint, host)| {
            (*host == host_addr && endpoint.protocol == protocol).then_some(endpoint.addr)
        }))
        .and_then(|resolved| {
            if resolved.is_some() {
                return Ok(resolved);
            }
            let Some(guest_addr) =
                read_reverse_endpoint_file(&self.endpoint_dir, host_addr, protocol)
            else {
                return Ok(None);
            };
            let namespaces = self
                .namespaces
                .lock()
                .map_err(|_| "socket namespace registry lock poisoned".to_string())?;
            let verified = namespaces.values().any(|spec| {
                let Some(namespace_id) = spec.namespace_id.clone() else {
                    return false;
                };
                effective_attachments(spec).into_iter().any(|attachment| {
                    let endpoint = VirtualEndpoint {
                        scope: endpoint_scope(
                            attachment.bridge_id,
                            namespace_id.clone(),
                            guest_addr,
                        ),
                        addr: guest_addr,
                        protocol,
                    };
                    read_endpoint_file(&self.endpoint_dir, &endpoint) == Some(host_addr)
                })
            });
            Ok(verified.then_some(guest_addr))
        })
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
        let listener =
            TcpListener::bind(SocketAddr::new(host_ip, host_port)).map_err(|e| match e.kind() {
                io::ErrorKind::AddrInUse => {
                    format!("published TCP port {host_ip}:{host_port} is already in use")
                }
                _ => format!("failed to bind published TCP port {host_ip}:{host_port}: {e}"),
            })?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("failed to configure published TCP listener: {e}"))?;
        let stop = Arc::new(AtomicBool::new(false));
        let target = VirtualEndpoint {
            scope: EndpointScope::Bridge(spec.bridge_id),
            addr: GuestSocketAddr(SocketAddr::new(
                IpAddr::V4(spec.ipv4),
                mapping.container_port,
            )),
            protocol: PortProtocol::Tcp,
        };
        let registry = Arc::clone(&self.registry);
        let endpoint_dir = Arc::clone(&self.endpoint_dir);
        let thread_stop = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("carrick-bridge-publish-tcp".to_string())
            .spawn(move || {
                published_tcp_accept_loop(listener, registry, endpoint_dir, target, thread_stop)
            })
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

    fn publish_udp(&self, lease_id: NetworkLeaseId, mapping: PortMapping) -> Result<(), String> {
        let spec = self.first_namespace_spec()?;
        let host_ip = mapping.host_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let host_port = mapping.host_port.unwrap_or(0);
        let socket =
            UdpSocket::bind(SocketAddr::new(host_ip, host_port)).map_err(|e| match e.kind() {
                io::ErrorKind::AddrInUse => {
                    format!("published UDP port {host_ip}:{host_port} is already in use")
                }
                _ => format!("failed to bind published UDP port {host_ip}:{host_port}: {e}"),
            })?;
        socket
            .set_nonblocking(true)
            .map_err(|e| format!("failed to configure published UDP listener: {e}"))?;
        let stop = Arc::new(AtomicBool::new(false));
        let target = VirtualEndpoint {
            scope: EndpointScope::Bridge(spec.bridge_id),
            addr: GuestSocketAddr(SocketAddr::new(
                IpAddr::V4(spec.ipv4),
                mapping.container_port,
            )),
            protocol: PortProtocol::Udp,
        };
        let gateway_v4 = spec.gateway_v4;
        let registry = Arc::clone(&self.registry);
        let endpoint_dir = Arc::clone(&self.endpoint_dir);
        let thread_stop = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("carrick-bridge-publish-udp".to_string())
            .spawn(move || {
                published_udp_loop(
                    socket,
                    registry,
                    endpoint_dir,
                    target,
                    gateway_v4,
                    thread_stop,
                )
            })
            .map_err(|e| format!("failed to start published UDP proxy: {e}"))?;
        let mut published_udp = self
            .published_udp
            .lock()
            .map_err(|_| "published UDP registry lock poisoned".to_string())?;
        published_udp
            .entry(lease_id)
            .or_default()
            .push(PublishedUdpProxy {
                stop,
                handle: Some(handle),
            });
        Ok(())
    }

    fn write_endpoint_file(
        &self,
        endpoint: &VirtualEndpoint,
        host_addr: HostSocketAddr,
    ) -> Result<(), String> {
        let paths = write_endpoint_file(&self.endpoint_dir, endpoint, host_addr)?;
        let mut owned = self
            .owned_endpoint_files
            .lock()
            .map_err(|_| "owned endpoint registry lock poisoned".to_string())?;
        for (path, contents) in paths {
            if !owned.iter().any(|entry| entry.path == path) {
                owned.push(OwnedEndpointFile { path, contents });
            }
        }
        Ok(())
    }

    fn track_owned_file(&self, path: PathBuf, contents: String) -> Result<(), String> {
        let mut owned = self
            .owned_endpoint_files
            .lock()
            .map_err(|_| "owned endpoint registry lock poisoned".to_string())?;
        if let Some(entry) = owned.iter_mut().find(|entry| entry.path == path) {
            entry.contents = contents;
        } else {
            owned.push(OwnedEndpointFile { path, contents });
        }
        Ok(())
    }

    fn prepare_tcp_listen(
        &self,
        namespace_id: Option<&NetworkNamespaceId>,
        guest_local: Option<GuestSocketAddr>,
        host_local: Option<HostSocketAddr>,
        reuse_port: bool,
    ) -> Result<(), i32> {
        let Some(namespace_id) = namespace_id else {
            return Ok(());
        };
        let (Some(guest_local), Some(host_local)) = (guest_local, host_local) else {
            return Ok(());
        };
        let spec = {
            let namespaces = self
                .namespaces
                .lock()
                .map_err(|_| carrick_abi::LINUX_EADDRINUSE)?;
            namespaces.get(namespace_id).cloned()
        };
        let Some(spec) = spec else {
            return Ok(());
        };
        let IpAddr::V4(guest_ip) = guest_local.0.ip() else {
            return Ok(());
        };
        let attachments = effective_attachments(&spec);
        let selected = if guest_ip == Ipv4Addr::UNSPECIFIED {
            attachments
        } else if guest_ip.is_loopback() {
            attachments.into_iter().take(1).collect()
        } else {
            attachments
                .into_iter()
                .filter(|attachment| attachment.ipv4 == guest_ip)
                .collect()
        };
        if selected.is_empty() {
            return Ok(());
        }
        let reservation = ListenerReservation {
            host_addr: host_local,
            reuse_port,
        };
        let endpoints = selected
            .into_iter()
            .map(|attachment| {
                let virtual_ip = if guest_ip == Ipv4Addr::UNSPECIFIED {
                    attachment.ipv4
                } else {
                    guest_ip
                };
                let virtual_addr = GuestSocketAddr(SocketAddr::new(
                    IpAddr::V4(virtual_ip),
                    guest_local.0.port(),
                ));
                VirtualEndpoint {
                    scope: endpoint_scope(attachment.bridge_id, namespace_id.clone(), virtual_addr),
                    addr: virtual_addr,
                    protocol: PortProtocol::Tcp,
                }
            })
            .collect::<Vec<_>>();
        {
            let mut listeners = self
                .tcp_listeners
                .lock()
                .map_err(|_| carrick_abi::LINUX_EADDRINUSE)?;
            for endpoint in &endpoints {
                if let Some(existing) = listeners.get(endpoint)
                    && !(existing.reuse_port && reuse_port)
                {
                    return Err(carrick_abi::LINUX_EADDRINUSE);
                }
            }
            for endpoint in &endpoints {
                listeners.insert(endpoint.clone(), reservation);
            }
        }
        let contents = encode_listener_reservation(reservation);
        fs::create_dir_all(&*self.endpoint_dir).map_err(|_| carrick_abi::LINUX_EADDRINUSE)?;
        for endpoint in endpoints {
            let path = listener_path(&self.endpoint_dir, &endpoint);
            fs::write(&path, &contents).map_err(|_| carrick_abi::LINUX_EADDRINUSE)?;
            self.track_owned_file(path, contents.clone())
                .map_err(|_| carrick_abi::LINUX_EADDRINUSE)?;
        }
        Ok(())
    }
}

fn shared_endpoint_dir() -> PathBuf {
    std::env::temp_dir().join("carrick-netns-socket-bridge")
}

fn endpoint_path(endpoint_dir: &Path, endpoint: &VirtualEndpoint) -> PathBuf {
    let protocol = match endpoint.protocol {
        PortProtocol::Tcp => "tcp",
        PortProtocol::Udp => "udp",
    };
    let ip = endpoint.addr.0.ip().to_string().replace(':', "_");
    let scope = endpoint_scope_path_component(&endpoint.scope);
    endpoint_dir.join(format!(
        "{scope}-{ip}-{}-{protocol}",
        endpoint.addr.0.port()
    ))
}

fn reverse_endpoint_path(
    endpoint_dir: &Path,
    host_addr: HostSocketAddr,
    protocol: PortProtocol,
) -> PathBuf {
    let protocol = match protocol {
        PortProtocol::Tcp => "tcp",
        PortProtocol::Udp => "udp",
    };
    let ip = host_addr.0.ip().to_string().replace(':', "_");
    endpoint_dir.join(format!("reverse-{ip}-{}-{protocol}", host_addr.0.port()))
}

fn listener_path(endpoint_dir: &Path, endpoint: &VirtualEndpoint) -> PathBuf {
    let ip = endpoint.addr.0.ip().to_string().replace(':', "_");
    let scope = endpoint_scope_path_component(&endpoint.scope);
    endpoint_dir.join(format!(
        "listen-{scope}-{ip}-{}-tcp",
        endpoint.addr.0.port()
    ))
}

fn service_name_path(
    endpoint_dir: &Path,
    bridge_id: &BridgeId,
    name: &str,
    addr: Ipv4Addr,
) -> PathBuf {
    let addr = addr.to_string().replace('.', "_");
    endpoint_dir.join(format!(
        "{}addr-{addr}",
        service_name_path_prefix(bridge_id, name)
    ))
}

fn service_name_path_prefix(bridge_id: &BridgeId, name: &str) -> String {
    format!("service-{}-{}-", bridge_id.as_str(), hex_name(name))
}

fn endpoint_scope(
    bridge_id: BridgeId,
    namespace_id: NetworkNamespaceId,
    virtual_addr: GuestSocketAddr,
) -> EndpointScope {
    if virtual_addr.0.ip().is_loopback() {
        EndpointScope::Namespace(namespace_id)
    } else {
        EndpointScope::Bridge(bridge_id)
    }
}

fn endpoint_scope_path_component(scope: &EndpointScope) -> String {
    match scope {
        EndpointScope::Bridge(bridge) => format!("bridge-{}", hex_name(bridge.as_str())),
        EndpointScope::Namespace(namespace) => format!("ns-{}", hex_name(namespace.as_str())),
    }
}

fn hex_name(name: &str) -> String {
    let mut encoded = String::with_capacity(name.len() * 2);
    for byte in name.as_bytes() {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn service_names_for(container_name: Option<&String>, aliases: &[String]) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(name) = container_name
        && !name.is_empty()
    {
        names.push(name.clone());
    }
    for alias in aliases {
        if !alias.is_empty() && !names.iter().any(|name| name == alias) {
            names.push(alias.clone());
        }
    }
    names
}

fn effective_attachments(spec: &NetworkNamespaceSpec) -> Vec<NetworkAttachmentSpec> {
    spec.effective_attachments()
}

fn encode_service_name(addr: Ipv4Addr, name: &str) -> String {
    format!("{addr}\nname={name}\npid={}\n", std::process::id())
}

fn decode_service_name(raw: &str) -> Option<(Ipv4Addr, String)> {
    let addr = raw.lines().next()?.trim().parse().ok()?;
    let name = raw
        .lines()
        .find_map(|line| line.strip_prefix("name="))?
        .to_string();
    Some((addr, name))
}

fn encode_listener_reservation(reservation: ListenerReservation) -> String {
    format!(
        "{}\nreuse_port={}\npid={}\n",
        reservation.host_addr.0,
        i32::from(reservation.reuse_port),
        std::process::id()
    )
}

fn write_endpoint_file(
    endpoint_dir: &Path,
    endpoint: &VirtualEndpoint,
    host_addr: HostSocketAddr,
) -> Result<Vec<(PathBuf, String)>, String> {
    fs::create_dir_all(endpoint_dir)
        .map_err(|e| format!("failed to create socket namespace endpoint directory: {e}"))?;
    let path = endpoint_path(endpoint_dir, endpoint);
    let contents = format!("{}\npid={}\n", host_addr.0, std::process::id());
    fs::write(&path, &contents)
        .map_err(|e| format!("failed to record socket namespace endpoint: {e}"))?;
    let reverse_path = reverse_endpoint_path(endpoint_dir, host_addr, endpoint.protocol);
    let reverse_contents = format!("{}\npid={}\n", endpoint.addr.0, std::process::id());
    fs::write(&reverse_path, &reverse_contents)
        .map_err(|e| format!("failed to record socket namespace reverse endpoint: {e}"))?;
    Ok(vec![(path, contents), (reverse_path, reverse_contents)])
}

fn remove_endpoint_files(files: Vec<(PathBuf, String)>) {
    for (path, expected_contents) in files {
        match fs::read_to_string(&path) {
            Ok(contents) if contents == expected_contents => {
                let _ = fs::remove_file(path);
            }
            _ => {}
        }
    }
}

fn read_endpoint_file(endpoint_dir: &Path, endpoint: &VirtualEndpoint) -> Option<HostSocketAddr> {
    let path = endpoint_path(endpoint_dir, endpoint);
    match read_namespace_file(&path)? {
        NamespaceFile::Live(raw) => raw.lines().next()?.trim().parse().ok().map(HostSocketAddr),
        NamespaceFile::Stale(raw) => {
            if let Ok(host_addr) = raw.lines().next()?.trim().parse::<SocketAddr>() {
                let reverse_path = reverse_endpoint_path(
                    endpoint_dir,
                    HostSocketAddr(host_addr),
                    endpoint.protocol,
                );
                let _ = read_namespace_file(&reverse_path);
            }
            None
        }
    }
}

fn read_reverse_endpoint_file(
    endpoint_dir: &Path,
    host_addr: HostSocketAddr,
    protocol: PortProtocol,
) -> Option<GuestSocketAddr> {
    let path = reverse_endpoint_path(endpoint_dir, host_addr, protocol);
    let raw = read_live_namespace_file(&path)?;
    raw.lines().next()?.trim().parse().ok().map(GuestSocketAddr)
}

fn read_live_namespace_file(path: &Path) -> Option<String> {
    match read_namespace_file(path)? {
        NamespaceFile::Live(raw) => Some(raw),
        NamespaceFile::Stale(_) => None,
    }
}

fn read_namespace_file(path: &Path) -> Option<NamespaceFile> {
    let raw = fs::read_to_string(path).ok()?;
    let owner_pid = raw.lines().find_map(|line| line.strip_prefix("pid="))?;
    let owner_pid = owner_pid.parse::<i32>().ok()?;
    if process_is_alive(owner_pid) {
        return Some(NamespaceFile::Live(raw));
    }
    let _ = fs::remove_file(path);
    Some(NamespaceFile::Stale(raw))
}

fn process_is_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

fn published_tcp_accept_loop(
    listener: TcpListener,
    registry: Arc<Mutex<HashMap<VirtualEndpoint, HostSocketAddr>>>,
    endpoint_dir: Arc<PathBuf>,
    target: VirtualEndpoint,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((inbound, _)) => {
                let target_addr = registry
                    .lock()
                    .ok()
                    .and_then(|registry| registry.get(&target).copied())
                    .or_else(|| read_endpoint_file(&endpoint_dir, &target));
                if let Some(target_addr) = target_addr {
                    let _ = thread::Builder::new()
                        .name("carrick-bridge-publish-tcp-stream".to_string())
                        .spawn(move || {
                            let _ = proxy_tcp_stream(inbound, target_addr.0);
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

fn published_udp_loop(
    socket: UdpSocket,
    registry: Arc<Mutex<HashMap<VirtualEndpoint, HostSocketAddr>>>,
    endpoint_dir: Arc<PathBuf>,
    target: VirtualEndpoint,
    gateway_v4: Ipv4Addr,
    stop: Arc<AtomicBool>,
) {
    let mut request = vec![0_u8; 65_535];
    let mut response = vec![0_u8; 65_535];
    while !stop.load(Ordering::SeqCst) {
        match socket.recv_from(&mut request) {
            Ok((request_len, source)) => {
                let target_addr = registry
                    .lock()
                    .ok()
                    .and_then(|registry| registry.get(&target).copied())
                    .or_else(|| read_endpoint_file(&endpoint_dir, &target));
                let Some(target_addr) = target_addr else {
                    continue;
                };
                let Ok(outbound) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) else {
                    continue;
                };
                let Ok(outbound_addr) = outbound.local_addr() else {
                    continue;
                };
                let reply_endpoint = VirtualEndpoint {
                    scope: target.scope.clone(),
                    addr: GuestSocketAddr(SocketAddr::new(
                        IpAddr::V4(gateway_v4),
                        outbound_addr.port(),
                    )),
                    protocol: PortProtocol::Udp,
                };
                let owned_reply_files = write_endpoint_file(
                    &endpoint_dir,
                    &reply_endpoint,
                    HostSocketAddr(outbound_addr),
                )
                .unwrap_or_default();
                let _ = outbound.set_read_timeout(Some(Duration::from_secs(2)));
                if outbound
                    .send_to(&request[..request_len], target_addr.0)
                    .is_err()
                {
                    remove_endpoint_files(owned_reply_files);
                    continue;
                }
                if let Ok((response_len, _)) = outbound.recv_from(&mut response) {
                    let _ = socket.send_to(&response[..response_len], source);
                }
                remove_endpoint_files(owned_reply_files);
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

impl NetworkProvider for SocketNamespaceProvider {
    fn capabilities(&self) -> NetworkCapabilities {
        NetworkCapabilities {
            same_bridge_ip_connectivity: true,
            multi_network_attachments: true,
            embedded_dns: true,
            outbound_connectivity: true,
            published_ports: true,
            published_udp_ports: true,
            kernel_datapath: false,
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

    fn create_namespace(&self, spec: &NetworkNamespaceSpec) -> Result<NetworkLease, String> {
        if let Some(namespace_id) = spec.namespace_id.clone() {
            let mut namespaces = self
                .namespaces
                .lock()
                .map_err(|_| "socket namespace registry lock poisoned".to_string())?;
            namespaces.insert(namespace_id, spec.clone());
        }
        self.register_service_names(spec)?;
        Ok(NetworkLease {
            id: NetworkLeaseId(1),
        })
    }

    fn destroy_namespace(&self, lease_id: NetworkLeaseId) -> Result<(), String> {
        if let Ok(mut published_tcp) = self.published_tcp.lock() {
            published_tcp.remove(&lease_id);
        }
        if let Ok(mut published_udp) = self.published_udp.lock() {
            published_udp.remove(&lease_id);
        }
        if let Ok(mut registry) = self.registry.lock() {
            registry.clear();
        }
        if let Ok(mut listeners) = self.tcp_listeners.lock() {
            listeners.clear();
        }
        if let Ok(mut namespaces) = self.namespaces.lock() {
            namespaces.clear();
        }
        if let Ok(mut socket_addrs) = self.socket_addrs.lock() {
            socket_addrs.clear();
        }
        if let Ok(mut owned) = self.owned_endpoint_files.lock() {
            for entry in owned.drain(..) {
                match fs::read_to_string(&entry.path) {
                    Ok(contents) if contents == entry.contents => {}
                    Ok(_) => continue,
                    Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                    Err(err) => {
                        return Err(format!(
                            "failed to read socket namespace endpoint {}: {err}",
                            entry.path.display()
                        ));
                    }
                }
                match fs::remove_file(&entry.path) {
                    Ok(()) => {}
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                    Err(err) => {
                        return Err(format!(
                            "failed to remove socket namespace endpoint {}: {err}",
                            entry.path.display()
                        ));
                    }
                }
            }
        }
        let _ = fs::remove_dir(&*self.endpoint_dir);
        Ok(())
    }

    fn publish_port(&self, lease_id: NetworkLeaseId, mapping: PortMapping) -> Result<(), String> {
        match mapping.protocol {
            PortProtocol::Tcp => self.publish_tcp(lease_id, mapping),
            PortProtocol::Udp => self.publish_udp(lease_id, mapping),
        }
    }

    fn materialize_bind(
        &self,
        namespace_id: Option<&NetworkNamespaceId>,
        requested: GuestSocketAddr,
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
        requested: GuestSocketAddr,
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
        namespace_id: Option<&NetworkNamespaceId>,
        guest_fd: i32,
        guest_local: Option<GuestSocketAddr>,
        host_local: Option<HostSocketAddr>,
        guest_peer: Option<GuestSocketAddr>,
        protocol: PortProtocol,
    ) -> Result<(), String> {
        self.record_socket_addresses(
            namespace_id,
            guest_fd,
            guest_local,
            host_local,
            guest_peer,
            protocol,
        )
    }

    fn guest_visible_local_addr(&self, guest_fd: i32) -> Result<Option<GuestSocketAddr>, String> {
        self.guest_visible_local_addr(guest_fd)
    }

    fn guest_visible_peer_addr(&self, guest_fd: i32) -> Result<Option<GuestSocketAddr>, String> {
        self.guest_visible_peer_addr(guest_fd)
    }

    fn translate_recv_addr(
        &self,
        host_addr: HostSocketAddr,
        protocol: PortProtocol,
    ) -> Result<Option<GuestSocketAddr>, String> {
        self.translate_host_source(host_addr, protocol)
    }

    fn prepare_listen(
        &self,
        namespace_id: Option<&NetworkNamespaceId>,
        guest_local: Option<GuestSocketAddr>,
        host_local: Option<HostSocketAddr>,
        protocol: PortProtocol,
        reuse_port: bool,
    ) -> Result<(), i32> {
        if protocol != PortProtocol::Tcp {
            return Ok(());
        }
        self.prepare_tcp_listen(namespace_id, guest_local, host_local, reuse_port)
    }

    fn guest_hosts_entries(
        &self,
        spec: &NetworkNamespaceSpec,
    ) -> Result<Vec<NetworkHostsEntry>, String> {
        self.service_hosts_entries(spec)
    }

    fn resolve_dns_name(
        &self,
        spec: &NetworkNamespaceSpec,
        name: &str,
    ) -> Result<Vec<Ipv4Addr>, String> {
        self.resolve_service_name(spec, name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_spec::{
        BridgeId, NetworkAttachmentSpec, NetworkNamespaceId, PortMapping, PortProtocol,
    };
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::thread;

    fn free_loopback_port() -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve port");
        listener.local_addr().expect("local addr").port()
    }

    fn guest(addr: SocketAddr) -> GuestSocketAddr {
        GuestSocketAddr(addr)
    }

    fn host(addr: SocketAddr) -> HostSocketAddr {
        HostSocketAddr(addr)
    }

    fn provider_with_endpoint() -> SocketNamespaceProvider {
        let provider = SocketNamespaceProvider::new();
        provider
            .register_virtual_endpoint(
                BridgeId::new("carrick0"),
                NetworkNamespaceId::new("a"),
                guest(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(172, 31, 0, 2)),
                    80,
                )),
                PortProtocol::Tcp,
                host(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 49152)),
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
                guest(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(172, 31, 0, 2)),
                    80,
                )),
                PortProtocol::Tcp,
            )
            .expect("lookup")
            .expect("registered target");
        assert_eq!(
            target,
            host(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 49152))
        );
    }

    #[test]
    fn bridge_gateway_connects_to_host_loopback() {
        let provider = SocketNamespaceProvider::new();
        let spec =
            NetworkNamespaceSpec::bridge_default(Some("web".to_string()), Vec::new(), Vec::new());
        let requested = SocketAddr::new(IpAddr::V4(spec.gateway_v4), 8080);

        let resolved = provider
            .resolve_bridge_connect(&spec, guest(requested), PortProtocol::Tcp)
            .expect("resolve gateway host connect");

        assert_eq!(
            resolved,
            ConnectTarget::Host(host(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)))
        );
    }

    #[test]
    fn does_not_resolve_different_bridge_virtual_endpoint() {
        let provider = provider_with_endpoint();
        let target = provider
            .resolve_registered_connect(
                &BridgeId::new("carrick1"),
                guest(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(172, 31, 0, 2)),
                    80,
                )),
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
            .materialize_bridge_bind(&spec, guest(requested), PortProtocol::Tcp)
            .expect("bind target");
        match target {
            BindTarget::Host(host) => {
                assert_eq!(host.0.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
                assert_eq!(host.0.port(), 0);
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
            .materialize_bridge_bind(&spec, guest(requested), PortProtocol::Tcp)
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
                guest(peer),
                PortProtocol::Tcp,
                host(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50080)),
            )
            .expect("register");

        let target = provider
            .resolve_bridge_connect(&spec, guest(peer), PortProtocol::Tcp)
            .expect("resolve");
        assert_eq!(
            target,
            ConnectTarget::Host(host(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                50080
            )))
        );
    }

    #[test]
    fn multi_network_bind_and_connect_use_the_matching_attachment_bridge() {
        let suffix = std::process::id();
        let backend = BridgeId::new(format!("test-bind-backend-{suffix}"));
        let frontend = BridgeId::new(format!("test-bind-frontend-{suffix}"));
        let mut web_spec = NetworkNamespaceSpec::bridge_default(
            Some("web".to_string()),
            vec!["web".to_string()],
            Vec::new(),
        );
        web_spec.bridge_id = backend.clone();
        web_spec.namespace_id = Some(NetworkNamespaceId::new(format!("web-ns-{suffix}")));
        web_spec.ipv4 = Ipv4Addr::new(172, 31, 10, 9);
        web_spec.attachments = vec![
            NetworkAttachmentSpec::bridge_default(
                backend,
                Some("web".to_string()),
                vec!["web-backend".to_string()],
                Some(Ipv4Addr::new(172, 31, 10, 9)),
            ),
            NetworkAttachmentSpec::bridge_default(
                frontend.clone(),
                Some("web".to_string()),
                vec!["web-frontend".to_string()],
                Some(Ipv4Addr::new(172, 31, 20, 9)),
            ),
        ];
        let mut cache_spec = NetworkNamespaceSpec::bridge_default(
            Some("cache".to_string()),
            vec!["cache".to_string()],
            Vec::new(),
        );
        cache_spec.bridge_id = frontend;
        cache_spec.namespace_id = Some(NetworkNamespaceId::new(format!("cache-ns-{suffix}")));
        cache_spec.ipv4 = Ipv4Addr::new(172, 31, 20, 10);
        cache_spec.attachments = vec![NetworkAttachmentSpec::bridge_default(
            cache_spec.bridge_id.clone(),
            Some("cache".to_string()),
            vec!["cache".to_string()],
            Some(cache_spec.ipv4),
        )];
        let provider = SocketNamespaceProvider::new();
        provider.create_namespace(&web_spec).expect("web namespace");
        provider
            .create_namespace(&cache_spec)
            .expect("cache namespace");
        let guest_listener = guest(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(172, 31, 20, 9)),
            8080,
        ));

        assert_eq!(
            provider
                .materialize_bridge_bind(&web_spec, guest_listener, PortProtocol::Tcp)
                .expect("bind frontend attachment"),
            BindTarget::Host(host(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)))
        );
        provider
            .record_socket_addresses(
                web_spec.namespace_id.as_ref(),
                7,
                Some(guest_listener),
                Some(host(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    51080,
                ))),
                None,
                PortProtocol::Tcp,
            )
            .expect("record frontend listener");

        let target = provider
            .resolve_bridge_connect(&cache_spec, guest_listener, PortProtocol::Tcp)
            .expect("resolve frontend endpoint");

        assert_eq!(
            target,
            ConnectTarget::Host(host(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                51080
            )))
        );
    }

    #[test]
    fn multi_network_wildcard_listen_reserves_each_attachment_bridge_port() {
        let suffix = std::process::id();
        let backend = BridgeId::new(format!("test-listen-backend-{suffix}"));
        let frontend = BridgeId::new(format!("test-listen-frontend-{suffix}"));
        let mut web_spec = NetworkNamespaceSpec::bridge_default(
            Some("web".to_string()),
            vec!["web".to_string()],
            Vec::new(),
        );
        web_spec.bridge_id = backend.clone();
        web_spec.namespace_id = Some(NetworkNamespaceId::new(format!("web-ns-{suffix}")));
        web_spec.ipv4 = Ipv4Addr::new(172, 31, 10, 9);
        web_spec.attachments = vec![
            NetworkAttachmentSpec::bridge_default(
                backend,
                Some("web".to_string()),
                vec!["web-backend".to_string()],
                Some(Ipv4Addr::new(172, 31, 10, 9)),
            ),
            NetworkAttachmentSpec::bridge_default(
                frontend.clone(),
                Some("web".to_string()),
                vec!["web-frontend".to_string()],
                Some(Ipv4Addr::new(172, 31, 20, 9)),
            ),
        ];
        let mut cache_spec = NetworkNamespaceSpec::bridge_default(
            Some("cache".to_string()),
            vec!["cache".to_string()],
            Vec::new(),
        );
        cache_spec.bridge_id = frontend;
        cache_spec.namespace_id = Some(NetworkNamespaceId::new(format!("cache-ns-{suffix}")));
        cache_spec.ipv4 = Ipv4Addr::new(172, 31, 20, 10);
        cache_spec.attachments = vec![NetworkAttachmentSpec::bridge_default(
            cache_spec.bridge_id.clone(),
            Some("cache".to_string()),
            vec!["cache".to_string()],
            Some(cache_spec.ipv4),
        )];
        let provider = SocketNamespaceProvider::new();
        provider.create_namespace(&web_spec).expect("web namespace");
        provider
            .create_namespace(&cache_spec)
            .expect("cache namespace");
        let guest_listener = guest(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080));
        let host_listener = host(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 51080));

        provider
            .prepare_tcp_listen(
                web_spec.namespace_id.as_ref(),
                Some(guest_listener),
                Some(host_listener),
                false,
            )
            .expect("reserve wildcard listener");

        let duplicate_frontend = provider.prepare_tcp_listen(
            web_spec.namespace_id.as_ref(),
            Some(guest(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(172, 31, 20, 9)),
                8080,
            ))),
            Some(host(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                51081,
            ))),
            false,
        );

        assert_eq!(duplicate_frontend, Err(carrick_abi::LINUX_EADDRINUSE));
    }

    #[test]
    fn multi_network_wildcard_recording_is_scoped_to_owning_namespace() {
        let suffix = std::process::id();
        let bridge = BridgeId::new(format!("test-wildcard-record-{suffix}"));
        let mut web_spec = NetworkNamespaceSpec::bridge_default(
            Some("web".to_string()),
            vec!["web".to_string()],
            Vec::new(),
        );
        web_spec.bridge_id = bridge.clone();
        web_spec.namespace_id = Some(NetworkNamespaceId::new(format!("web-ns-{suffix}")));
        web_spec.ipv4 = Ipv4Addr::new(172, 31, 30, 9);
        web_spec.attachments = vec![NetworkAttachmentSpec::bridge_default(
            web_spec.bridge_id.clone(),
            Some("web".to_string()),
            vec!["web".to_string()],
            Some(web_spec.ipv4),
        )];
        let mut cache_spec = NetworkNamespaceSpec::bridge_default(
            Some("cache".to_string()),
            vec!["cache".to_string()],
            Vec::new(),
        );
        cache_spec.bridge_id = bridge;
        cache_spec.namespace_id = Some(NetworkNamespaceId::new(format!("cache-ns-{suffix}")));
        cache_spec.ipv4 = Ipv4Addr::new(172, 31, 30, 10);
        cache_spec.attachments = vec![NetworkAttachmentSpec::bridge_default(
            cache_spec.bridge_id.clone(),
            Some("cache".to_string()),
            vec!["cache".to_string()],
            Some(cache_spec.ipv4),
        )];
        let provider = SocketNamespaceProvider::new();
        provider.create_namespace(&web_spec).expect("web namespace");
        provider
            .create_namespace(&cache_spec)
            .expect("cache namespace");
        let host_listener = host(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 51080));

        provider
            .record_socket_addresses(
                web_spec.namespace_id.as_ref(),
                7,
                Some(guest(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    8080,
                ))),
                Some(host_listener),
                None,
                PortProtocol::Tcp,
            )
            .expect("record wildcard listener");

        let web_target = provider
            .resolve_bridge_connect(
                &cache_spec,
                guest(SocketAddr::new(IpAddr::V4(web_spec.ipv4), 8080)),
                PortProtocol::Tcp,
            )
            .expect("resolve web endpoint");
        let cache_target = provider
            .resolve_bridge_connect(
                &cache_spec,
                guest(SocketAddr::new(IpAddr::V4(cache_spec.ipv4), 8080)),
                PortProtocol::Tcp,
            )
            .expect("resolve cache endpoint");

        assert_eq!(web_target, ConnectTarget::Host(host_listener));
        assert_eq!(
            cache_target,
            ConnectTarget::Denied(carrick_abi::LINUX_ECONNREFUSED)
        );
    }

    #[test]
    fn bridge_loopback_endpoint_is_visible_inside_same_namespace() {
        let mut spec =
            NetworkNamespaceSpec::bridge_default(Some("db".to_string()), Vec::new(), Vec::new());
        spec.namespace_id = Some(NetworkNamespaceId::new("db-ns"));
        let provider = SocketNamespaceProvider::new();
        provider.create_namespace(&spec).expect("namespace");
        let guest_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5432);
        let host_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50032);
        provider
            .record_socket_addresses(
                spec.namespace_id.as_ref(),
                7,
                Some(guest(guest_addr)),
                Some(host(host_addr)),
                None,
                PortProtocol::Tcp,
            )
            .expect("record loopback endpoint");

        let target = provider
            .resolve_bridge_connect(&spec, guest(guest_addr), PortProtocol::Tcp)
            .expect("resolve");

        assert_eq!(target, ConnectTarget::Host(host(host_addr)));
    }

    #[test]
    fn bridge_loopback_endpoint_is_not_visible_to_different_namespace() {
        let bridge = BridgeId::new("loopback-test");
        let mut owner =
            NetworkNamespaceSpec::bridge_default(Some("db".to_string()), Vec::new(), Vec::new());
        owner.bridge_id = bridge.clone();
        owner.namespace_id = Some(NetworkNamespaceId::new("db-ns"));
        let mut peer =
            NetworkNamespaceSpec::bridge_default(Some("web".to_string()), Vec::new(), Vec::new());
        peer.bridge_id = bridge;
        peer.namespace_id = Some(NetworkNamespaceId::new("web-ns"));
        let provider = SocketNamespaceProvider::new();
        provider.create_namespace(&owner).expect("owner namespace");
        provider.create_namespace(&peer).expect("peer namespace");
        let guest_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5432);
        let host_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50033);
        provider
            .record_socket_addresses(
                owner.namespace_id.as_ref(),
                7,
                Some(guest(guest_addr)),
                Some(host(host_addr)),
                None,
                PortProtocol::Tcp,
            )
            .expect("record loopback endpoint");

        let target = provider
            .resolve_bridge_connect(&peer, guest(guest_addr), PortProtocol::Tcp)
            .expect("resolve");

        assert_eq!(
            target,
            ConnectTarget::Denied(carrick_abi::LINUX_ECONNREFUSED)
        );
    }

    #[test]
    fn records_guest_visible_local_address_for_rewritten_bind() {
        let provider = SocketNamespaceProvider::new();
        let guest_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 31, 0, 2)), 80);
        let host_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50080);
        provider
            .record_socket_addresses(
                None,
                7,
                Some(guest(guest_addr)),
                Some(host(host_addr)),
                None,
                PortProtocol::Tcp,
            )
            .expect("record");
        let visible = provider.guest_visible_local_addr(7).expect("visible addr");
        assert_eq!(visible, Some(guest(guest_addr)));
    }

    #[test]
    fn destroy_namespace_removes_fork_coherent_endpoint_files() {
        let spec = NetworkNamespaceSpec::bridge_default(None, Vec::new(), Vec::new());
        let provider = SocketNamespaceProvider::new();
        let lease = provider.create_namespace(&spec).expect("namespace");
        let peer = VirtualEndpoint {
            scope: EndpointScope::Bridge(spec.bridge_id.clone()),
            addr: guest(SocketAddr::new(IpAddr::V4(spec.ipv4), 8080)),
            protocol: PortProtocol::Tcp,
        };
        provider
            .register_virtual_endpoint(
                spec.bridge_id.clone(),
                spec.namespace_id.clone().expect("namespace id"),
                peer.addr,
                peer.protocol,
                host(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50080)),
            )
            .expect("register endpoint");
        let endpoint_file = endpoint_path(&provider.endpoint_dir, &peer);
        assert!(
            endpoint_file.exists(),
            "endpoint file must exist before cleanup"
        );

        provider
            .destroy_namespace(lease.id)
            .expect("destroy namespace");

        assert!(
            !endpoint_file.exists(),
            "destroy_namespace must remove owned socket namespace endpoint file"
        );
    }

    #[test]
    fn translate_host_source_reads_fork_coherent_endpoint_files() {
        let spec = NetworkNamespaceSpec::bridge_default(None, Vec::new(), Vec::new());
        let writer = SocketNamespaceProvider::new();
        let reader = SocketNamespaceProvider::new();
        reader.create_namespace(&spec).expect("reader namespace");
        let guest_addr = guest(SocketAddr::new(IpAddr::V4(spec.ipv4), 49152));
        let host_addr = host(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            free_loopback_port(),
        ));

        writer
            .register_virtual_endpoint(
                spec.bridge_id.clone(),
                spec.namespace_id.clone().expect("namespace id"),
                guest_addr,
                PortProtocol::Tcp,
                host_addr,
            )
            .expect("register endpoint");

        let translated = reader
            .translate_host_source(host_addr, PortProtocol::Tcp)
            .expect("translate")
            .expect("fork coherent source translation");
        assert_eq!(translated, guest_addr);

        writer
            .destroy_namespace(NetworkLeaseId(1))
            .expect("writer cleanup");
        reader
            .destroy_namespace(NetworkLeaseId(1))
            .expect("reader cleanup");
    }

    #[test]
    fn stale_endpoint_file_reclaims_reverse_record() {
        let provider = SocketNamespaceProvider::new();
        let peer = VirtualEndpoint {
            scope: EndpointScope::Bridge(BridgeId::new("stale-pair")),
            addr: guest(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(172, 31, 42, 9)),
                8080,
            )),
            protocol: PortProtocol::Tcp,
        };
        let host_addr = host(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            free_loopback_port(),
        ));
        let endpoint_file = endpoint_path(&provider.endpoint_dir, &peer);
        let reverse_file = reverse_endpoint_path(&provider.endpoint_dir, host_addr, peer.protocol);
        fs::create_dir_all(&*provider.endpoint_dir).expect("endpoint dir");
        fs::write(&endpoint_file, format!("{}\npid=0\n", host_addr.0)).expect("endpoint file");
        fs::write(&reverse_file, format!("{}\npid=0\n", peer.addr.0)).expect("reverse file");

        let resolved = provider
            .resolve_registered_connect(&BridgeId::new("stale-pair"), peer.addr, peer.protocol)
            .expect("resolve stale endpoint");

        assert_eq!(resolved, None);
        assert!(
            !endpoint_file.exists(),
            "stale endpoint file should be reclaimed"
        );
        assert!(
            !reverse_file.exists(),
            "paired reverse endpoint file should be reclaimed"
        );
    }

    #[test]
    fn publish_tcp_conflict_reports_stable_error() {
        let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("occupy host port");
        let host_port = occupied.local_addr().expect("occupied addr").port();
        let mapping = PortMapping {
            host_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            host_port: Some(host_port),
            container_port: 8081,
            protocol: PortProtocol::Tcp,
        };
        let spec = NetworkNamespaceSpec::bridge_default(None, Vec::new(), vec![mapping.clone()]);
        let provider = SocketNamespaceProvider::new();
        let lease = provider.create_namespace(&spec).expect("namespace");

        let err = provider
            .publish_port(lease.id, mapping)
            .expect_err("occupied published host port should fail");

        assert_eq!(
            err,
            format!("published TCP port 127.0.0.1:{host_port} is already in use")
        );
    }

    #[test]
    fn destroy_namespace_releases_published_tcp_port() {
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

        provider
            .destroy_namespace(lease.id)
            .expect("destroy namespace");

        let _listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, host_port)).expect("published port released");
    }

    #[test]
    fn publish_tcp_forwards_after_container_endpoint_registers() {
        let host_port = free_loopback_port();
        let container_port = 8081;
        let mapping = PortMapping {
            host_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            host_port: Some(host_port),
            container_port,
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
        let peer = SocketAddr::new(IpAddr::V4(spec.ipv4), container_port);
        provider
            .register_virtual_endpoint(
                spec.bridge_id.clone(),
                spec.namespace_id.clone().expect("namespace id"),
                guest(peer),
                PortProtocol::Tcp,
                host(target_addr),
            )
            .expect("register");

        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, host_port)).expect("connect");
        client.write_all(b"ping").expect("write ping");
        let mut reply = [0_u8; 2];
        client.read_exact(&mut reply).expect("read reply");
        server.join().expect("server thread");

        assert_eq!(&reply, b"ok");
    }

    #[test]
    fn publish_tcp_forwards_from_fork_coherent_endpoint_file() {
        let host_port = free_loopback_port();
        let container_port = 8082;
        let mapping = PortMapping {
            host_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            host_port: Some(host_port),
            container_port,
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
        let peer = VirtualEndpoint {
            scope: EndpointScope::Bridge(spec.bridge_id.clone()),
            addr: guest(SocketAddr::new(IpAddr::V4(spec.ipv4), container_port)),
            protocol: PortProtocol::Tcp,
        };
        provider
            .write_endpoint_file(&peer, host(target_addr))
            .expect("write endpoint file");
        {
            let registry = provider.registry.lock().expect("registry");
            assert!(
                !registry.contains_key(&peer),
                "test must exercise the fork-coherent endpoint path"
            );
        }

        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, host_port)).expect("connect");
        client.write_all(b"ping").expect("write ping");
        let mut reply = [0_u8; 2];
        client.read_exact(&mut reply).expect("read reply");
        server.join().expect("server thread");

        assert_eq!(&reply, b"ok");
    }

    #[test]
    fn publish_udp_conflict_reports_stable_error() {
        let occupied = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("occupy host port");
        let host_port = occupied.local_addr().expect("occupied addr").port();
        let mapping = PortMapping {
            host_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            host_port: Some(host_port),
            container_port: 8081,
            protocol: PortProtocol::Udp,
        };
        let spec = NetworkNamespaceSpec::bridge_default(None, Vec::new(), vec![mapping.clone()]);
        let provider = SocketNamespaceProvider::new();
        let lease = provider.create_namespace(&spec).expect("namespace");

        let err = provider
            .publish_port(lease.id, mapping)
            .expect_err("occupied published UDP host port should fail");

        assert_eq!(
            err,
            format!("published UDP port 127.0.0.1:{host_port} is already in use")
        );
    }

    #[test]
    fn destroy_namespace_releases_published_udp_port() {
        let occupied = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve port");
        let host_port = occupied.local_addr().expect("occupied addr").port();
        drop(occupied);
        let mapping = PortMapping {
            host_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            host_port: Some(host_port),
            container_port: 8080,
            protocol: PortProtocol::Udp,
        };
        let spec = NetworkNamespaceSpec::bridge_default(None, Vec::new(), vec![mapping.clone()]);
        let provider = SocketNamespaceProvider::new();
        let lease = provider.create_namespace(&spec).expect("namespace");
        provider.publish_port(lease.id, mapping).expect("publish");

        provider
            .destroy_namespace(lease.id)
            .expect("destroy namespace");

        let _socket =
            UdpSocket::bind((Ipv4Addr::LOCALHOST, host_port)).expect("published port released");
    }

    #[test]
    fn publish_udp_forwards_after_container_endpoint_registers() {
        let occupied = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve port");
        let host_port = occupied.local_addr().expect("occupied addr").port();
        drop(occupied);
        let container_port = 8081;
        let mapping = PortMapping {
            host_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            host_port: Some(host_port),
            container_port,
            protocol: PortProtocol::Udp,
        };
        let spec = NetworkNamespaceSpec::bridge_default(None, Vec::new(), vec![mapping.clone()]);
        let provider = SocketNamespaceProvider::new();
        let lease = provider.create_namespace(&spec).expect("namespace");
        provider.publish_port(lease.id, mapping).expect("publish");

        let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("target bind");
        target
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("target timeout");
        let target_addr = target.local_addr().expect("target addr");
        let server = thread::spawn(move || {
            let mut buf = [0_u8; 8];
            let (n, peer) = target.recv_from(&mut buf).expect("target recv");
            assert_eq!(&buf[..n], b"ping");
            target.send_to(b"ok", peer).expect("target reply");
        });
        let peer = SocketAddr::new(IpAddr::V4(spec.ipv4), container_port);
        provider
            .register_virtual_endpoint(
                spec.bridge_id.clone(),
                spec.namespace_id.clone().expect("namespace id"),
                guest(peer),
                PortProtocol::Udp,
                host(target_addr),
            )
            .expect("register");

        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("client bind");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("client timeout");
        client
            .send_to(b"ping", (Ipv4Addr::LOCALHOST, host_port))
            .expect("send ping");
        let mut reply = [0_u8; 8];
        let (n, _) = client.recv_from(&mut reply).expect("read reply");
        server.join().expect("server thread");

        assert_eq!(&reply[..n], b"ok");
    }

    #[test]
    fn service_names_are_visible_from_separate_provider_instance() {
        let mut spec = NetworkNamespaceSpec::bridge_default(
            Some("db".to_string()),
            vec!["postgres".to_string()],
            Vec::new(),
        );
        spec.bridge_id = BridgeId::new(format!("test-service-{}", std::process::id()));
        let writer = SocketNamespaceProvider::new();
        writer.create_namespace(&spec).expect("create namespace");

        let reader = SocketNamespaceProvider::new();
        let entries = reader
            .guest_hosts_entries(&spec)
            .expect("read service hosts entries");

        assert!(entries.iter().any(|entry| {
            entry.addr == IpAddr::V4(spec.ipv4) && entry.names == vec!["db".to_string()]
        }));
        assert!(entries.iter().any(|entry| {
            entry.addr == IpAddr::V4(spec.ipv4) && entry.names == vec!["postgres".to_string()]
        }));
    }

    #[test]
    fn multi_network_service_names_are_visible_on_each_attached_bridge() {
        let suffix = std::process::id();
        let backend = BridgeId::new(format!("test-multi-backend-{suffix}"));
        let frontend = BridgeId::new(format!("test-multi-frontend-{suffix}"));
        let mut web_spec = NetworkNamespaceSpec::bridge_default(
            Some("web".to_string()),
            vec!["api".to_string()],
            Vec::new(),
        );
        web_spec.bridge_id = backend.clone();
        web_spec.ipv4 = Ipv4Addr::new(172, 31, 10, 9);
        web_spec.attachments = vec![
            NetworkAttachmentSpec::bridge_default(
                backend,
                Some("web".to_string()),
                vec!["api-backend".to_string()],
                Some(Ipv4Addr::new(172, 31, 10, 9)),
            ),
            NetworkAttachmentSpec::bridge_default(
                frontend.clone(),
                Some("web".to_string()),
                vec!["api-frontend".to_string()],
                Some(Ipv4Addr::new(172, 31, 20, 9)),
            ),
        ];
        let mut cache_spec = NetworkNamespaceSpec::bridge_default(
            Some("cache".to_string()),
            vec!["cache".to_string()],
            Vec::new(),
        );
        cache_spec.bridge_id = frontend;

        let writer = SocketNamespaceProvider::new();
        writer
            .create_namespace(&web_spec)
            .expect("create web namespace");

        let reader = SocketNamespaceProvider::new();
        let entries = reader
            .guest_hosts_entries(&cache_spec)
            .expect("read frontend service hosts entries");

        assert!(entries.iter().any(|entry| {
            entry.addr == IpAddr::V4(Ipv4Addr::new(172, 31, 20, 9))
                && entry.names == vec!["web".to_string()]
        }));
        assert!(entries.iter().any(|entry| {
            entry.addr == IpAddr::V4(Ipv4Addr::new(172, 31, 20, 9))
                && entry.names == vec!["api-frontend".to_string()]
        }));
        assert!(!entries.iter().any(|entry| {
            entry.addr == IpAddr::V4(Ipv4Addr::new(172, 31, 10, 9))
                && entry.names == vec!["api-backend".to_string()]
        }));
    }

    #[test]
    fn multi_network_dns_name_lookup_is_scoped_to_shared_bridges() {
        let suffix = std::process::id();
        let backend = BridgeId::new(format!("test-dns-backend-{suffix}"));
        let frontend = BridgeId::new(format!("test-dns-frontend-{suffix}"));
        let mut web_spec = NetworkNamespaceSpec::bridge_default(
            Some("web".to_string()),
            vec!["api".to_string()],
            Vec::new(),
        );
        web_spec.bridge_id = backend.clone();
        web_spec.ipv4 = Ipv4Addr::new(172, 31, 10, 9);
        web_spec.attachments = vec![
            NetworkAttachmentSpec::bridge_default(
                backend,
                Some("web".to_string()),
                vec!["app".to_string()],
                Some(Ipv4Addr::new(172, 31, 10, 9)),
            ),
            NetworkAttachmentSpec::bridge_default(
                frontend.clone(),
                Some("web".to_string()),
                vec!["api".to_string()],
                Some(Ipv4Addr::new(172, 31, 20, 9)),
            ),
        ];
        let mut cache_spec = NetworkNamespaceSpec::bridge_default(
            Some("cache".to_string()),
            vec!["cache".to_string()],
            Vec::new(),
        );
        cache_spec.bridge_id = frontend;

        let provider = SocketNamespaceProvider::new();
        provider
            .create_namespace(&web_spec)
            .expect("create web namespace");

        assert_eq!(
            provider
                .resolve_dns_name(&cache_spec, "web")
                .expect("resolve web"),
            vec![Ipv4Addr::new(172, 31, 20, 9)]
        );
        assert_eq!(
            provider
                .resolve_dns_name(&cache_spec, "api.")
                .expect("resolve api"),
            vec![Ipv4Addr::new(172, 31, 20, 9)]
        );
        assert!(
            provider
                .resolve_dns_name(&cache_spec, "app")
                .expect("resolve app")
                .is_empty()
        );
    }

    #[test]
    fn dns_service_alias_returns_multiple_same_bridge_records() {
        let suffix = std::process::id();
        let bridge = BridgeId::new(format!("test-dns-scale-{suffix}"));
        let mut api_one = NetworkNamespaceSpec::bridge_default(
            Some("api-1".to_string()),
            vec!["api".to_string()],
            Vec::new(),
        );
        api_one.bridge_id = bridge.clone();
        api_one.ipv4 = Ipv4Addr::new(172, 31, 40, 10);
        let mut api_two = NetworkNamespaceSpec::bridge_default(
            Some("api-2".to_string()),
            vec!["api".to_string()],
            Vec::new(),
        );
        api_two.bridge_id = bridge.clone();
        api_two.ipv4 = Ipv4Addr::new(172, 31, 40, 11);
        let mut client = NetworkNamespaceSpec::bridge_default(
            Some("client".to_string()),
            Vec::new(),
            Vec::new(),
        );
        client.bridge_id = bridge;

        let api_one_provider = SocketNamespaceProvider::new();
        let api_one_lease = api_one_provider
            .create_namespace(&api_one)
            .expect("api one namespace");
        let api_two_provider = SocketNamespaceProvider::new();
        let api_two_lease = api_two_provider
            .create_namespace(&api_two)
            .expect("api two namespace");
        let reader = SocketNamespaceProvider::new();

        let mut addrs = reader
            .resolve_dns_name(&client, "api")
            .expect("resolve api");
        addrs.sort_unstable();

        assert_eq!(
            addrs,
            vec![
                Ipv4Addr::new(172, 31, 40, 10),
                Ipv4Addr::new(172, 31, 40, 11)
            ]
        );

        api_one_provider
            .destroy_namespace(api_one_lease.id)
            .expect("api one cleanup");
        api_two_provider
            .destroy_namespace(api_two_lease.id)
            .expect("api two cleanup");
    }

    #[test]
    fn multi_network_guest_hosts_entries_include_all_attached_bridges() {
        let suffix = std::process::id();
        let backend = BridgeId::new(format!("test-hosts-backend-{suffix}"));
        let frontend = BridgeId::new(format!("test-hosts-frontend-{suffix}"));
        let mut db_spec = NetworkNamespaceSpec::bridge_default(
            Some("db".to_string()),
            vec!["database".to_string()],
            Vec::new(),
        );
        db_spec.bridge_id = backend.clone();
        db_spec.ipv4 = Ipv4Addr::new(172, 31, 10, 11);
        db_spec.attachments = vec![NetworkAttachmentSpec::bridge_default(
            db_spec.bridge_id.clone(),
            Some("db".to_string()),
            vec!["database".to_string()],
            Some(db_spec.ipv4),
        )];
        let mut cache_spec = NetworkNamespaceSpec::bridge_default(
            Some("cache".to_string()),
            vec!["redis".to_string()],
            Vec::new(),
        );
        cache_spec.bridge_id = frontend.clone();
        cache_spec.ipv4 = Ipv4Addr::new(172, 31, 20, 12);
        cache_spec.attachments = vec![NetworkAttachmentSpec::bridge_default(
            cache_spec.bridge_id.clone(),
            Some("cache".to_string()),
            vec!["redis".to_string()],
            Some(cache_spec.ipv4),
        )];
        let mut web_spec = NetworkNamespaceSpec::bridge_default(
            Some("web".to_string()),
            vec!["web".to_string()],
            Vec::new(),
        );
        web_spec.bridge_id = backend.clone();
        web_spec.ipv4 = Ipv4Addr::new(172, 31, 10, 9);
        web_spec.attachments = vec![
            NetworkAttachmentSpec::bridge_default(
                backend,
                Some("web".to_string()),
                vec!["web-backend".to_string()],
                Some(Ipv4Addr::new(172, 31, 10, 9)),
            ),
            NetworkAttachmentSpec::bridge_default(
                frontend,
                Some("web".to_string()),
                vec!["web-frontend".to_string()],
                Some(Ipv4Addr::new(172, 31, 20, 9)),
            ),
        ];

        let writer = SocketNamespaceProvider::new();
        writer.create_namespace(&db_spec).expect("db namespace");
        writer
            .create_namespace(&cache_spec)
            .expect("cache namespace");

        let reader = SocketNamespaceProvider::new();
        let entries = reader
            .guest_hosts_entries(&web_spec)
            .expect("read web hosts entries");

        assert!(entries.iter().any(|entry| {
            entry.addr == IpAddr::V4(Ipv4Addr::new(172, 31, 10, 11))
                && entry.names == vec!["db".to_string()]
        }));
        assert!(entries.iter().any(|entry| {
            entry.addr == IpAddr::V4(Ipv4Addr::new(172, 31, 20, 12))
                && entry.names == vec!["cache".to_string()]
        }));
    }

    #[test]
    fn translates_peer_source_from_different_bridge_namespace() {
        let bridge = BridgeId::new(format!("test-peer-{}", std::process::id()));
        let mut client_spec =
            NetworkNamespaceSpec::bridge_default(Some("web".to_string()), Vec::new(), Vec::new());
        client_spec.bridge_id = bridge.clone();
        let mut server_spec =
            NetworkNamespaceSpec::bridge_default(Some("db".to_string()), Vec::new(), Vec::new());
        server_spec.bridge_id = bridge;

        let writer = SocketNamespaceProvider::new();
        writer
            .create_namespace(&client_spec)
            .expect("create client namespace");
        let host_source = host(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 49152));
        let guest_source = guest(SocketAddr::new(IpAddr::V4(client_spec.ipv4), 34567));
        writer
            .record_socket_addresses(
                client_spec.namespace_id.as_ref(),
                10,
                Some(guest_source),
                Some(host_source),
                None,
                PortProtocol::Tcp,
            )
            .expect("record client source");

        let reader = SocketNamespaceProvider::new();
        reader
            .create_namespace(&server_spec)
            .expect("create server namespace");

        assert_eq!(
            reader
                .translate_host_source(host_source, PortProtocol::Tcp)
                .expect("translate host source"),
            Some(guest_source)
        );
    }

    #[test]
    fn translates_peer_source_registered_on_attachment_bridge() {
        let suffix = std::process::id();
        let primary = BridgeId::new(format!("test-peer-primary-{suffix}"));
        let attached = BridgeId::new(format!("test-peer-attached-{suffix}"));
        let mut client_spec =
            NetworkNamespaceSpec::bridge_default(Some("web".to_string()), Vec::new(), Vec::new());
        client_spec.bridge_id = primary.clone();
        client_spec.ipv4 = Ipv4Addr::new(172, 31, 70, 10);
        client_spec.attachments = vec![
            NetworkAttachmentSpec::bridge_default(
                primary.clone(),
                Some("web".to_string()),
                Vec::new(),
                Some(Ipv4Addr::new(172, 31, 70, 10)),
            ),
            NetworkAttachmentSpec::bridge_default(
                attached.clone(),
                Some("web".to_string()),
                Vec::new(),
                Some(Ipv4Addr::new(172, 31, 70, 20)),
            ),
        ];
        let mut server_spec =
            NetworkNamespaceSpec::bridge_default(Some("db".to_string()), Vec::new(), Vec::new());
        server_spec.bridge_id = primary;
        server_spec.attachments = vec![
            NetworkAttachmentSpec::bridge_default(
                server_spec.bridge_id.clone(),
                Some("db".to_string()),
                Vec::new(),
                Some(Ipv4Addr::new(172, 31, 70, 30)),
            ),
            NetworkAttachmentSpec::bridge_default(
                attached,
                Some("db".to_string()),
                Vec::new(),
                Some(Ipv4Addr::new(172, 31, 70, 40)),
            ),
        ];

        let writer = SocketNamespaceProvider::new();
        writer
            .create_namespace(&client_spec)
            .expect("create client namespace");
        let host_source = host(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 49153));
        let guest_source = guest(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(172, 31, 70, 20)),
            34568,
        ));
        writer
            .record_socket_addresses(
                client_spec.namespace_id.as_ref(),
                10,
                Some(guest_source),
                Some(host_source),
                None,
                PortProtocol::Tcp,
            )
            .expect("record client source");

        let reader = SocketNamespaceProvider::new();
        reader
            .create_namespace(&server_spec)
            .expect("create server namespace");

        assert_eq!(
            reader
                .translate_host_source(host_source, PortProtocol::Tcp)
                .expect("translate host source"),
            Some(guest_source)
        );
    }
}
