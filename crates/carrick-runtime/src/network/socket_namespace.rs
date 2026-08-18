use super::{
    BindTarget, ConnectTarget, GuestSocketAddr, HostSocketAddr, NetworkCapabilities,
    NetworkHostsEntry, NetworkLease, NetworkLeaseId, NetworkProvider,
};
use carrick_spec::{
    BridgeId, NetworkAttachmentSpec, NetworkNamespaceId, NetworkNamespaceSpec, PortMapping,
    PortProtocol,
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug)]
pub struct SocketNamespaceProvider {
    /// Outer fork exclusion for publication helpers. Helpers acquire this
    /// before the registry so a host-fork owner can prove no unregistered
    /// helper will leave the child's copied registry mutex locked.
    fork_gate: Arc<Mutex<()>>,
    registry: Arc<Mutex<HashMap<VirtualEndpoint, HostSocketAddr>>>,
    tcp_listeners: Mutex<HashMap<VirtualEndpoint, ListenerReservation>>,
    endpoint_dir: Arc<PathBuf>,
    next_lease_id: AtomicU64,
    owned_endpoint_files: Mutex<HashMap<NetworkLeaseId, Vec<OwnedEndpointFile>>>,
    namespaces: Mutex<HashMap<NetworkNamespaceId, NetworkNamespaceSpec>>,
    namespace_leases: Mutex<HashMap<NetworkNamespaceId, NetworkLeaseId>>,
    lease_specs: Mutex<HashMap<NetworkLeaseId, NetworkNamespaceSpec>>,
    socket_addrs: Mutex<HashMap<i32, SocketAddressState>>,
    fork_tracked_fds: Arc<Mutex<HashSet<RawFd>>>,
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
    Bridge {
        bridge: BridgeId,
        realm: BridgeRealm,
    },
    Namespace(NetworkNamespaceId),
}

/// Who is entitled to mean a bridge address.
///
/// The endpoint namespace is machine-global, and a bridge endpoint used to be
/// keyed by `(bridge id, guest addr, protocol)` alone. Every one of those is a
/// compile-time constant for an unnamed container on the default bridge
/// (`carrick0`, `172.31.0.2`), so two concurrent `carrick run -p ...` instances
/// wrote and read the *same* record: an inbound connection to one instance's
/// published host port was proxied into the *other* instance's container
/// listener, silently, with no diagnostic. The realm restores the missing
/// component of the key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum BridgeRealm {
    /// A name-derived address. Intentionally visible machine-wide: this is what
    /// makes two separate `carrick run --name db` / `--name web` processes reach
    /// each other on the default bridge, which is a shipped, conformance-tested
    /// feature (`conformance_bridge_compose_pair`).
    Shared,
    /// The `172.31.0.0/24` placeholder handed to a container with no name. It is
    /// not an address anyone allocated, so the only processes that can
    /// meaningfully mean it are one instance and its fork children.
    Private(NetworkNamespaceId),
}

#[derive(Debug, Clone, Default)]
struct SocketAddressState {
    lease_id: Option<NetworkLeaseId>,
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
    /// Host pid that spawned the proxy thread. A raw run forks host processes
    /// (carrier/supervisor), and the child inherits this struct while the
    /// pthread only exists in the parent; joining there aborts the whole run
    /// with ESRCH during shutdown. Drop only joins in the owning process.
    owner: u32,
}

#[derive(Debug)]
struct PublishedUdpProxy {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    /// See [`PublishedTcpProxy::owner`].
    owner: u32,
}

/// Where a published-UDP relay publishes the transient endpoint that lets the
/// guest recognise a reply's source.
///
/// The realm must be derived from the *gateway* address the record is keyed on,
/// not from the container address of the relay's target: `translate_host_source`
/// re-derives it from the gateway address it reads back, and for a named
/// container (shared realm, gateway inside the private range) the writer and the
/// verifier would otherwise look in two different directories.
#[derive(Debug, Clone)]
struct UdpReplyEndpoint {
    scope: EndpointScope,
    gateway_v4: Ipv4Addr,
}

/// What a published-port relay forwards to: the container endpoint it looks up,
/// and the namespace that owns it.
///
/// The namespace travels with the endpoint because it is what decides whether a
/// record found at that path is this container's -- see [`RecordTrust`]. It is
/// taken from the relay's own lease's spec at `publish_port` time, i.e. in the
/// root process before any guest fork, so it is the same value every fork child
/// stamps onto the records it publishes.
#[derive(Debug, Clone)]
struct RelayTarget {
    endpoint: VirtualEndpoint,
    namespace_id: Option<NetworkNamespaceId>,
}

impl RelayTarget {
    /// A relay with no namespace of its own can make no ownership claim, so it
    /// narrows nothing. Such a spec cannot register an endpoint in the first
    /// place (`materialize_bridge_bind` and `prepare_tcp_listen` both require the
    /// id), so it has no records to protect.
    fn trust(&self) -> RecordTrust<'_> {
        match self.namespace_id.as_ref() {
            Some(namespace_id) => RecordTrust::OwnNamespaceOnly(namespace_id),
            None => RecordTrust::AnyNamespace,
        }
    }
}

#[derive(Clone)]
struct BridgeHelperForkState {
    fork_gate: Arc<Mutex<()>>,
    tracked_fds: Arc<Mutex<HashSet<RawFd>>>,
}

#[derive(Debug)]
struct ForkTrackedSocket<T: AsRawFd> {
    socket: std::mem::ManuallyDrop<T>,
    raw_fd: RawFd,
    fork_gate: Arc<Mutex<()>>,
    tracked_fds: Arc<Mutex<HashSet<RawFd>>>,
}

impl<T: AsRawFd> ForkTrackedSocket<T> {
    #[cfg(test)]
    fn new(
        socket: T,
        fork_gate: &Arc<Mutex<()>>,
        tracked_fds: &Arc<Mutex<HashSet<RawFd>>>,
    ) -> Self {
        let _fork_gate = fork_gate.lock().unwrap_or_else(|p| p.into_inner());
        Self::new_under_fork_gate(socket, fork_gate, tracked_fds)
    }

    /// Publish ownership while the caller retains `fork_gate` from before the
    /// fd-producing bind/accept/connect/clone operation. This closes the only
    /// window in which a fork child could inherit a live but untracked helper
    /// descriptor.
    fn new_under_fork_gate(
        socket: T,
        fork_gate: &Arc<Mutex<()>>,
        tracked_fds: &Arc<Mutex<HashSet<RawFd>>>,
    ) -> Self {
        let raw_fd = socket.as_raw_fd();
        tracked_fds
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(raw_fd);
        Self {
            socket: std::mem::ManuallyDrop::new(socket),
            raw_fd,
            fork_gate: Arc::clone(fork_gate),
            tracked_fds: Arc::clone(tracked_fds),
        }
    }

    fn as_socket(&self) -> &T {
        // SAFETY: `socket` stays initialized until `Drop`, which requires
        // `&mut self` and manually drops it exactly once after all borrows end.
        unsafe { &*(&self.socket as *const std::mem::ManuallyDrop<T>).cast::<T>() }
    }

    fn as_socket_mut(&mut self) -> &mut T {
        // SAFETY: same invariant as `as_socket`, but with exclusive access.
        unsafe { &mut *(&mut self.socket as *mut std::mem::ManuallyDrop<T>).cast::<T>() }
    }

    /// Change only the Rust owner type while preserving the exact open fd and
    /// its continuously-published fork tracking (e.g. socket2::Socket ->
    /// TcpStream after a nonblocking connect completes).
    fn map_preserving_fd<U: AsRawFd>(self, map: impl FnOnce(T) -> U) -> ForkTrackedSocket<U> {
        let mut this = std::mem::ManuallyDrop::new(self);
        let socket = unsafe { std::mem::ManuallyDrop::take(&mut this.socket) };
        let raw_fd = this.raw_fd;
        let fork_gate = unsafe { std::ptr::read(&this.fork_gate) };
        let tracked_fds = unsafe { std::ptr::read(&this.tracked_fds) };
        let socket = map(socket);
        debug_assert_eq!(socket.as_raw_fd(), raw_fd);
        ForkTrackedSocket {
            socket: std::mem::ManuallyDrop::new(socket),
            raw_fd,
            fork_gate,
            tracked_fds,
        }
    }
}

impl<T: AsRawFd> std::ops::Deref for ForkTrackedSocket<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.as_socket()
    }
}

impl<T: AsRawFd> std::ops::DerefMut for ForkTrackedSocket<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_socket_mut()
    }
}

impl<T: AsRawFd + io::Read> io::Read for ForkTrackedSocket<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.as_socket_mut().read(buf)
    }
}

impl<T: AsRawFd + io::Write> io::Write for ForkTrackedSocket<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.as_socket_mut().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.as_socket_mut().flush()
    }
}

impl<T: AsRawFd> Drop for ForkTrackedSocket<T> {
    fn drop(&mut self) {
        let _fork_gate = self.fork_gate.lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: `socket` is initialized in `new_under_fork_gate` and this is
        // the only place it is manually dropped.
        unsafe {
            std::mem::ManuallyDrop::drop(&mut self.socket);
        }
        self.tracked_fds
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.raw_fd);
    }
}

impl Drop for PublishedTcpProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            // A fork-inherited handle names a pthread that exists only in the
            // owning process; joining it here returns ESRCH and std panics.
            if std::process::id() == self.owner {
                let _ = handle.join();
            }
        }
    }
}

impl Drop for PublishedUdpProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            if std::process::id() == self.owner {
                let _ = handle.join();
            }
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
        Self::rooted_at(shared_endpoint_dir())
    }

    /// Build a provider over an explicit namespace root.
    ///
    /// Test-only, and there is deliberately no environment override for it: the
    /// production root has to be a single machine-global directory or
    /// cross-instance service resolution stops working. The unit tests need it
    /// because `shared_endpoint_dir` gives each test *process* a private
    /// subdirectory -- which is what keeps two concurrent `cargo test` runs from
    /// aliasing each other, but also means no test could otherwise model two
    /// instances sharing one namespace, i.e. the exact layout this module's
    /// aliasing bugs live in.
    #[cfg(test)]
    fn with_endpoint_root(root: &Path) -> Self {
        Self::rooted_at(root.to_path_buf())
    }

    fn rooted_at(endpoint_dir: PathBuf) -> Self {
        // Force this process's identity here, before the provider can publish
        // anything and -- crucially -- before the guest boots and forks. Every
        // fork child then inherits the value already stored, so a child's
        // publications are accepted by its parent's relay.
        let _ = instance_id();
        let _ = fs::create_dir_all(&endpoint_dir);
        Self {
            fork_gate: Arc::new(Mutex::new(())),
            registry: Arc::new(Mutex::new(HashMap::new())),
            tcp_listeners: Mutex::new(HashMap::new()),
            endpoint_dir: Arc::new(endpoint_dir),
            next_lease_id: AtomicU64::new(1),
            owned_endpoint_files: Mutex::new(HashMap::new()),
            namespaces: Mutex::new(HashMap::new()),
            namespace_leases: Mutex::new(HashMap::new()),
            lease_specs: Mutex::new(HashMap::new()),
            socket_addrs: Mutex::new(HashMap::new()),
            fork_tracked_fds: Arc::new(Mutex::new(HashSet::new())),
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
            scope: endpoint_scope(bridge_id, namespace_id.clone(), virtual_addr),
            addr: virtual_addr,
            protocol,
        };
        let mut registry = self
            .registry
            .lock()
            .map_err(|_| "socket namespace registry lock poisoned".to_string())?;
        registry.insert(key.clone(), host_addr);
        drop(registry);
        if let Some(lease_id) = self.lease_for_namespace(&namespace_id)? {
            self.write_endpoint_file_for_lease(lease_id, &key, Some(&namespace_id), host_addr)?;
        } else {
            self.write_endpoint_file(&key, Some(&namespace_id), host_addr)?;
        }
        Ok(())
    }

    fn register_service_names(
        &self,
        lease_id: NetworkLeaseId,
        spec: &NetworkNamespaceSpec,
    ) -> Result<(), String> {
        for attachment in effective_attachments(spec) {
            let names = service_names_for(attachment.container_name.as_ref(), &attachment.aliases);
            for name in names {
                let dir = service_name_dir(&self.endpoint_dir, &attachment.bridge_id, &name);
                let path = service_record_path(&dir, attachment.ipv4);
                let contents = encode_service_name(attachment.ipv4, &name);
                write_record(&dir, &path, &contents)
                    .map_err(|e| format!("failed to record socket namespace service name: {e}"))?;
                self.track_owned_file(lease_id, path, contents)?;
            }
        }
        Ok(())
    }

    fn service_hosts_entries(
        &self,
        spec: &NetworkNamespaceSpec,
    ) -> Result<Vec<NetworkHostsEntry>, String> {
        let mut entries = Vec::new();
        let mut visited = HashSet::new();
        for attachment in effective_attachments(spec) {
            if !visited.insert(attachment.bridge_id.clone()) {
                continue;
            }
            // Scoped to this bridge's shard: unrelated bridges' records -- and
            // any litter they carry -- are never even enumerated.
            let shard = service_bridge_dir(&self.endpoint_dir, &attachment.bridge_id);
            let Ok(names) = fs::read_dir(&shard) else {
                continue;
            };
            for name_dir in names.flatten() {
                let Ok(records) = fs::read_dir(name_dir.path()) else {
                    continue;
                };
                for record in records.flatten() {
                    let Some(raw) = read_live_namespace_file(&record.path()) else {
                        continue;
                    };
                    if let Some((addr, name)) = decode_service_name(&raw) {
                        entries.push(NetworkHostsEntry {
                            addr: IpAddr::V4(addr),
                            names: vec![name],
                        });
                    }
                }
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
        let mut addrs = Vec::new();
        let mut visited = HashSet::new();
        for attachment in effective_attachments(spec) {
            if !visited.insert(attachment.bridge_id.clone()) {
                continue;
            }
            // The read_dir scope is exactly the query scope: the directory
            // enumerated here holds only the records of this (bridge, name),
            // which is the fan-out one DNS answer needs and nothing else.
            let dir = service_name_dir(&self.endpoint_dir, &attachment.bridge_id, query_name);
            let Ok(records) = fs::read_dir(&dir) else {
                continue;
            };
            for record in records.flatten() {
                let Some(raw) = read_live_namespace_file(&record.path()) else {
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
        namespace_id: Option<&NetworkNamespaceId>,
        virtual_addr: GuestSocketAddr,
        protocol: PortProtocol,
    ) -> Result<Option<HostSocketAddr>, String> {
        let key = VirtualEndpoint {
            scope: bridge_scope(bridge_id.clone(), namespace_id, virtual_addr),
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
        Ok(read_endpoint_file(&self.fork_gate, &self.endpoint_dir, key))
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
            if let Some(host) = self.resolve_registered_connect(
                &attachment.bridge_id,
                spec.namespace_id.as_ref(),
                requested,
                protocol,
            )? {
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
        let lease_id = namespace_id
            .map(|namespace_id| self.lease_for_namespace(namespace_id))
            .transpose()?
            .flatten();
        let mut socket_addrs = self
            .socket_addrs
            .lock()
            .map_err(|_| "socket address registry lock poisoned".to_string())?;
        socket_addrs.insert(
            guest_fd,
            SocketAddressState {
                lease_id,
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
        let resolved = {
            let registry = self
                .registry
                .lock()
                .map_err(|_| "socket namespace registry lock poisoned".to_string())?;
            registry.iter().find_map(|(endpoint, host)| {
                (*host == host_addr && endpoint.protocol == protocol).then_some(endpoint.addr)
            })
        };
        Ok(resolved).and_then(|resolved| {
            if resolved.is_some() {
                return Ok(resolved);
            }
            let Some(guest_addr) = read_reverse_endpoint_file(
                &self.fork_gate,
                &self.endpoint_dir,
                host_addr,
                protocol,
            ) else {
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
                    read_endpoint_file(&self.fork_gate, &self.endpoint_dir, &endpoint)
                        == Some(host_addr)
                })
            });
            Ok(verified.then_some(guest_addr))
        })
    }

    fn namespace_spec_for_lease(
        &self,
        lease_id: NetworkLeaseId,
    ) -> Result<NetworkNamespaceSpec, String> {
        let lease_specs = self
            .lease_specs
            .lock()
            .map_err(|_| "socket namespace registry lock poisoned".to_string())?;
        lease_specs.get(&lease_id).cloned().ok_or_else(|| {
            format!(
                "no network namespace exists for published lease {}",
                lease_id.0
            )
        })
    }

    fn publish_tcp(&self, lease_id: NetworkLeaseId, mapping: PortMapping) -> Result<(), String> {
        let spec = self.namespace_spec_for_lease(lease_id)?;
        let host_ip = mapping.host_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let host_port = mapping.host_port.unwrap_or(0);
        let listener = {
            let _fork_gate = self.fork_gate.lock().unwrap_or_else(|p| p.into_inner());
            let listener = TcpListener::bind(SocketAddr::new(host_ip, host_port)).map_err(|e| {
                match e.kind() {
                    io::ErrorKind::AddrInUse => {
                        format!("published TCP port {host_ip}:{host_port} is already in use")
                    }
                    _ => format!("failed to bind published TCP port {host_ip}:{host_port}: {e}"),
                }
            })?;
            ForkTrackedSocket::new_under_fork_gate(
                listener,
                &self.fork_gate,
                &self.fork_tracked_fds,
            )
        };
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("failed to configure published TCP listener: {e}"))?;
        let stop = Arc::new(AtomicBool::new(false));
        let target_addr = GuestSocketAddr(SocketAddr::new(
            IpAddr::V4(spec.ipv4),
            mapping.container_port,
        ));
        let target = RelayTarget {
            endpoint: VirtualEndpoint {
                scope: bridge_scope(spec.bridge_id, spec.namespace_id.as_ref(), target_addr),
                addr: target_addr,
                protocol: PortProtocol::Tcp,
            },
            namespace_id: spec.namespace_id,
        };
        let fork_state = BridgeHelperForkState {
            fork_gate: Arc::clone(&self.fork_gate),
            tracked_fds: Arc::clone(&self.fork_tracked_fds),
        };
        let registry = Arc::clone(&self.registry);
        let endpoint_dir = Arc::clone(&self.endpoint_dir);
        let thread_stop = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("carrick-bridge-publish-tcp".to_string())
            .spawn(move || {
                published_tcp_accept_loop(
                    listener,
                    fork_state,
                    registry,
                    endpoint_dir,
                    target,
                    thread_stop,
                )
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
                owner: std::process::id(),
            });
        Ok(())
    }

    fn publish_udp(&self, lease_id: NetworkLeaseId, mapping: PortMapping) -> Result<(), String> {
        let spec = self.namespace_spec_for_lease(lease_id)?;
        let host_ip = mapping.host_ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let host_port = mapping.host_port.unwrap_or(0);
        let socket = {
            let _fork_gate = self.fork_gate.lock().unwrap_or_else(|p| p.into_inner());
            let socket =
                UdpSocket::bind(SocketAddr::new(host_ip, host_port)).map_err(|e| {
                    match e.kind() {
                        io::ErrorKind::AddrInUse => {
                            format!("published UDP port {host_ip}:{host_port} is already in use")
                        }
                        _ => {
                            format!("failed to bind published UDP port {host_ip}:{host_port}: {e}")
                        }
                    }
                })?;
            ForkTrackedSocket::new_under_fork_gate(socket, &self.fork_gate, &self.fork_tracked_fds)
        };
        socket
            .set_nonblocking(true)
            .map_err(|e| format!("failed to configure published UDP listener: {e}"))?;
        let stop = Arc::new(AtomicBool::new(false));
        let target_addr = GuestSocketAddr(SocketAddr::new(
            IpAddr::V4(spec.ipv4),
            mapping.container_port,
        ));
        let target = RelayTarget {
            endpoint: VirtualEndpoint {
                scope: bridge_scope(
                    spec.bridge_id.clone(),
                    spec.namespace_id.as_ref(),
                    target_addr,
                ),
                addr: target_addr,
                protocol: PortProtocol::Udp,
            },
            namespace_id: spec.namespace_id.clone(),
        };
        // `bridge_realm` ignores the port, so deriving the reply realm once
        // here, from the gateway address, is exact for every datagram.
        let reply = UdpReplyEndpoint {
            scope: bridge_scope(
                spec.bridge_id,
                spec.namespace_id.as_ref(),
                GuestSocketAddr(SocketAddr::new(IpAddr::V4(spec.gateway_v4), 0)),
            ),
            gateway_v4: spec.gateway_v4,
        };
        let fork_state = BridgeHelperForkState {
            fork_gate: Arc::clone(&self.fork_gate),
            tracked_fds: Arc::clone(&self.fork_tracked_fds),
        };
        let registry = Arc::clone(&self.registry);
        let endpoint_dir = Arc::clone(&self.endpoint_dir);
        let thread_stop = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("carrick-bridge-publish-udp".to_string())
            .spawn(move || {
                published_udp_loop(
                    socket,
                    fork_state,
                    registry,
                    endpoint_dir,
                    target,
                    reply,
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
                owner: std::process::id(),
            });
        Ok(())
    }

    fn write_endpoint_file(
        &self,
        endpoint: &VirtualEndpoint,
        namespace_id: Option<&NetworkNamespaceId>,
        host_addr: HostSocketAddr,
    ) -> Result<(), String> {
        self.write_endpoint_file_for_lease(NetworkLeaseId(0), endpoint, namespace_id, host_addr)
    }

    fn write_endpoint_file_for_lease(
        &self,
        lease_id: NetworkLeaseId,
        endpoint: &VirtualEndpoint,
        namespace_id: Option<&NetworkNamespaceId>,
        host_addr: HostSocketAddr,
    ) -> Result<(), String> {
        let paths = write_endpoint_file(
            &self.fork_gate,
            &self.endpoint_dir,
            endpoint,
            namespace_id,
            host_addr,
        )?;
        let mut owned = self
            .owned_endpoint_files
            .lock()
            .map_err(|_| "owned endpoint registry lock poisoned".to_string())?;
        let owned = owned.entry(lease_id).or_default();
        for (path, contents) in paths {
            if !owned.iter().any(|entry| entry.path == path) {
                owned.push(OwnedEndpointFile { path, contents });
            }
        }
        Ok(())
    }

    fn track_owned_file(
        &self,
        lease_id: NetworkLeaseId,
        path: PathBuf,
        contents: String,
    ) -> Result<(), String> {
        let mut owned = self
            .owned_endpoint_files
            .lock()
            .map_err(|_| "owned endpoint registry lock poisoned".to_string())?;
        let owned = owned.entry(lease_id).or_default();
        if let Some(entry) = owned.iter_mut().find(|entry| entry.path == path) {
            entry.contents = contents;
        } else {
            owned.push(OwnedEndpointFile { path, contents });
        }
        Ok(())
    }

    fn lease_for_namespace(
        &self,
        namespace_id: &NetworkNamespaceId,
    ) -> Result<Option<NetworkLeaseId>, String> {
        let leases = self
            .namespace_leases
            .lock()
            .map_err(|_| "socket namespace lease registry lock poisoned".to_string())?;
        Ok(leases.get(namespace_id).copied())
    }

    fn prepare_tcp_listen(
        &self,
        namespace_id: Option<&NetworkNamespaceId>,
        guest_local: Option<GuestSocketAddr>,
        host_local: Option<HostSocketAddr>,
        reuse_port: bool,
    ) -> Result<(), carrick_abi::LinuxErrno> {
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
        let lease_id = self
            .lease_for_namespace(namespace_id)
            .map_err(|_| carrick_abi::LINUX_EADDRINUSE)?;
        let Some(lease_id) = lease_id else {
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
        for endpoint in endpoints {
            let dir = endpoint_scope_dir(&self.endpoint_dir, &endpoint.scope);
            let path = listener_path(&self.endpoint_dir, &endpoint);
            write_record(&dir, &path, &contents).map_err(|_| carrick_abi::LINUX_EADDRINUSE)?;
            self.track_owned_file(lease_id, path, contents.clone())
                .map_err(|_| carrick_abi::LINUX_EADDRINUSE)?;
        }
        Ok(())
    }
}

/// Name prefix of a service-record shard directory in the endpoint namespace.
const SERVICE_SHARD_PREFIX: &str = "svc-";

/// Name prefix of a directory owned in its entirety by a single process, whose
/// pid is the rest of the name.
const PER_PROCESS_DIR_PREFIX: &str = "test-";

/// Name prefix of a private realm directory: `inst-<hex namespace id>`.
///
/// It must not collide with any other prefix the namespace root carries, and in
/// particular must never begin with [`SERVICE_SHARD_PREFIX`] -- the service
/// readers enumerate the root by prefix and a realm dir has to be invisible to
/// them.
const PRIVATE_REALM_PREFIX: &str = "inst-";

/// How many entries of the endpoint namespace one process visits while
/// reclaiming dead-owner litter. The pass runs once, synchronously, before the
/// provider has spawned a helper thread or the guest has forked, so it must have
/// a ceiling: it is paid on the startup path and the directory it walks is
/// machine-global, i.e. its size is not something this process controls.
/// Whatever a run does not reach stays for the next one -- reclamation is
/// incremental, and every run makes progress because a visited dead record is
/// unlinked.
///
/// A run leaks at most a handful of records, so any budget above that keeps the
/// namespace bounded in steady state; the size only decides how fast a backlog
/// drains. Measured against a synthesized 24,219-record backlog on a loaded
/// machine: 27.9 ms for this budget, versus 29 us once the namespace is clean --
/// which is what a run actually pays, the littered case being transient by
/// construction.
const ENDPOINT_RECLAIM_BUDGET: usize = 512;

fn endpoint_namespace_root() -> PathBuf {
    std::env::temp_dir().join("carrick-netns-socket-bridge")
}

fn shared_endpoint_dir() -> PathBuf {
    let dir = endpoint_namespace_root();
    reclaim_stale_endpoint_records_once(&dir);
    // The fork-coherent endpoint namespace is machine-global and its file names
    // are keyed by (scope, guest addr, protocol) only. `bridge_default` derives
    // a constant bridge id and a constant 172.31.0.2 for an unnamed container,
    // so two unit-test processes running at the same time -- two `just ci`
    // invocations, two lanes -- write the *same* endpoint file and cross-wire
    // one suite's published-port relay onto the other suite's target listener:
    // one client gets its reply from the wrong process while its own listener
    // never accepts (a hang in `server.join()`), and the other sees the
    // discarded connection as ECONNRESET. Give the unit tests a process-private
    // subdirectory so no concurrently running test binary can alias them. This
    // keeps coverage identical -- every provider and fork child in the test
    // process resolves the same directory, so the fork-coherence paths still
    // exercise real files -- and it keeps test files out of the directory that
    // real runs scan.
    #[cfg(test)]
    let dir = dir.join(format!("{PER_PROCESS_DIR_PREFIX}{}", std::process::id()));
    dir
}

/// Reclaim dead-owner records in the machine-global endpoint namespace, once
/// per process.
///
/// Every durable record carries its writer's pid, and `read_namespace_file`
/// already unlinks a record whose owner is gone -- but only as a side effect of
/// a lookup that happens to name that exact path. Nothing ever names the
/// records of a run that was SIGKILLed, panicked, or published without a lease,
/// so they accumulate forever (24,219 of them on the machine this was written
/// on, 99.8% dead-owner). This is the pass that visits them.
///
/// It runs from `SocketNamespaceProvider::new`, i.e. in the top-level process
/// before it has spawned a publication helper or booted a guest, so it holds no
/// `fork_gate` (C9: bulk file work under the gate stalls or `EAGAIN`s guest
/// `fork`) and races no thread of its own.
fn reclaim_stale_endpoint_records_once(root: &Path) {
    static SWEPT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    SWEPT.get_or_init(|| {
        reclaim_stale_endpoint_records(root, ENDPOINT_RECLAIM_BUDGET);
    });
}

/// Visit at most `budget` entries of the endpoint namespace rooted at `root`,
/// unlinking every record whose owner is gone. Returns the number visited.
///
/// Safety against concurrently running instances rests entirely on the liveness
/// rule this shares with every lookup (`read_namespace_file` ->
/// `process_is_alive`): a record is removed only when its writer's pid is gone,
/// so a live instance's records are never touched, and the pass is never more
/// aggressive than a lookup already is. Everything else is idempotent: an entry
/// another sweeper removed first reads as absent, an entry being written reads
/// as live or unreadable, and both simply mean "leave it alone".
fn reclaim_stale_endpoint_records(root: &Path, budget: usize) -> usize {
    let mut visited = 0usize;
    let self_pid = std::process::id() as i32;
    let Ok(entries) = fs::read_dir(root) else {
        return visited;
    };
    for entry in entries.flatten() {
        if visited >= budget {
            break;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let is_dir = entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false);
        if !is_dir {
            visited += 1;
            let _ = read_namespace_file(&entry.path());
            continue;
        }
        if let Some(owner) = name
            .strip_prefix(PER_PROCESS_DIR_PREFIX)
            .and_then(|pid| pid.parse::<i32>().ok())
        {
            // A directory owned in its entirety by one pid: one liveness check
            // settles every record inside it, so the walk below needs no reads
            // at all. It still has to be budgeted -- a dead owner's directory
            // can be arbitrarily large, and `remove_dir_all` on the startup
            // path would hand this pass exactly the unbounded cost it exists to
            // remove.
            visited += 1;
            if owner != self_pid && !process_is_alive(owner) {
                visited += remove_tree_within_budget(&entry.path(), budget.saturating_sub(visited));
            }
            continue;
        }
        if let Some(encoded) = name.strip_prefix(PRIVATE_REALM_PREFIX) {
            visited += 1;
            // A private realm belongs to one namespace id, and in practice that
            // id is `anon-<pid>` -- so, exactly like a `test-<pid>` directory,
            // one liveness check settles every record inside it. This is the
            // only thing that reaches the `bridge-`/`listen-` families at all:
            // nothing ever enumerates them by name, so the lazy per-file rule
            // can never visit them, and before realms existed they were
            // unreclaimable by construction.
            let owner = unhex_name(encoded)
                .map(NetworkNamespaceId::new)
                .and_then(|id| id.anonymous_owner_pid());
            if let Some(owner) = owner
                && owner != self_pid
                && !process_is_alive(owner)
            {
                visited += remove_tree_within_budget(&entry.path(), budget.saturating_sub(visited));
                continue;
            }
            // A realm whose id is not pid-derived (a caller that set an explicit
            // `network_namespace_id` and still landed on a placeholder address)
            // falls back to the same per-file rule as everything else. No new
            // liveness predicate is introduced.
            visited += reclaim_records_under(&entry.path(), budget.saturating_sub(visited));
            // Succeeds only while the realm is empty, so a realm another
            // instance is still publishing into is left in place; a writer that
            // loses that race re-creates the directory and retries.
            let _ = fs::remove_dir(entry.path());
            continue;
        }
        if name.starts_with(SERVICE_SHARD_PREFIX) {
            visited += 1;
            visited += reclaim_records_under(&entry.path(), budget.saturating_sub(visited));
            // Succeeds only while the shard is empty, so a shard another
            // instance is still publishing into is left in place.
            let _ = fs::remove_dir(entry.path());
        }
    }
    visited
}

fn reclaim_records_under(dir: &Path, budget: usize) -> usize {
    let mut visited = 0usize;
    let Ok(entries) = fs::read_dir(dir) else {
        return visited;
    };
    for entry in entries.flatten() {
        if visited >= budget {
            break;
        }
        visited += 1;
        if entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
            visited += reclaim_records_under(&entry.path(), budget.saturating_sub(visited));
            let _ = fs::remove_dir(entry.path());
            continue;
        }
        let _ = read_namespace_file(&entry.path());
    }
    visited
}

/// Remove a subtree whose owner has already been proven gone, visiting at most
/// `budget` entries. What it cannot reach stays for the next pass, which will
/// re-derive the same verdict from the same dead pid.
fn remove_tree_within_budget(dir: &Path, budget: usize) -> usize {
    let mut visited = 0usize;
    let Ok(entries) = fs::read_dir(dir) else {
        return visited;
    };
    for entry in entries.flatten() {
        if visited >= budget {
            break;
        }
        visited += 1;
        if entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
            visited += remove_tree_within_budget(&entry.path(), budget.saturating_sub(visited));
            let _ = fs::remove_dir(entry.path());
            continue;
        }
        let _ = fs::remove_file(entry.path());
    }
    let _ = fs::remove_dir(dir);
    visited
}

/// Write one durable record, creating its directory first.
///
/// The write is a temp-file-plus-`rename`, not an `fs::write`. `fs::write` is
/// `O_TRUNC` + `write`, which publishes an **empty** file for the window between
/// the two: a concurrent reader that lands in it finds no `pid=` line, decides
/// there is no such endpoint, and drops a connection that should have been
/// forwarded (or answers a DNS query with nothing). `rename` is atomic, so a
/// reader observes either the complete old record or the complete new one and
/// never a partial. That window is independent of any cross-instance aliasing --
/// it is reachable by one instance republishing over its own record -- and it
/// has to be closed before any content-based check on a record can be sound.
///
/// The temp name carries the writer's pid so a crashed writer's leftover is
/// reclaimable by the same liveness rule as every other record, and a counter so
/// two threads of one process cannot collide.
///
/// The reclaim pass removes a record directory once it is empty, so a writer
/// that loses that race re-creates the directory and retries rather than failing
/// the guest's `create_namespace`.
fn write_record(dir: &Path, path: &Path, contents: &str) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    match write_record_once(dir, path, contents) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(dir)?;
            write_record_once(dir, path, contents)
        }
        other => other,
    }
}

fn write_record_once(dir: &Path, path: &Path, contents: &str) -> io::Result<()> {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let temp = dir.join(format!(
        ".carrick-tmp-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&temp, contents)?;
    match fs::rename(&temp, path) {
        Ok(()) => Ok(()),
        Err(err) => {
            let _ = fs::remove_file(&temp);
            Err(err)
        }
    }
}

/// Remove `path` only if it still holds exactly `expected`.
///
/// Every unlink in this module is a *reclamation* of a record whose owner was
/// observed dead, decided from bytes that were read earlier. Between the read
/// and the unlink the owner's successor can rename a live record into the same
/// path, and unlinking then destroys a live publication -- the record is gone,
/// but the process that owns the socket is very much alive and will never write
/// it again. Re-reading and comparing first makes the unlink conditional on the
/// bytes the decision was actually made from.
fn remove_record_if_unchanged(path: &Path, expected: &str) -> bool {
    match fs::read_to_string(path) {
        Ok(current) if current == expected => fs::remove_file(path).is_ok(),
        _ => false,
    }
}

fn endpoint_path(endpoint_dir: &Path, endpoint: &VirtualEndpoint) -> PathBuf {
    let protocol = match endpoint.protocol {
        PortProtocol::Tcp => "tcp",
        PortProtocol::Udp => "udp",
    };
    let ip = endpoint.addr.0.ip().to_string().replace(':', "_");
    let scope = endpoint_scope_path_component(&endpoint.scope);
    endpoint_scope_dir(endpoint_dir, &endpoint.scope).join(format!(
        "{scope}-{ip}-{}-{protocol}",
        endpoint.addr.0.port()
    ))
}

/// Reverse records stay at the namespace root, in every realm.
///
/// Their key is a *real host socket address*, which is globally unique while the
/// socket is live -- it cannot alias the way a placeholder guest address does.
/// Keeping them shared is also required: translating a peer address on every
/// accept/recvfrom has to find the record of whichever instance owns that host
/// port, which is frequently not this one.
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

/// Listener reservations follow their endpoint into its realm: they are keyed by
/// the same `VirtualEndpoint`, so an unnamed container's `EADDRINUSE` bookkeeping
/// stays as private as the endpoint it reserves.
fn listener_path(endpoint_dir: &Path, endpoint: &VirtualEndpoint) -> PathBuf {
    let ip = endpoint.addr.0.ip().to_string().replace(':', "_");
    let scope = endpoint_scope_path_component(&endpoint.scope);
    endpoint_scope_dir(endpoint_dir, &endpoint.scope).join(format!(
        "listen-{scope}-{ip}-{}-tcp",
        endpoint.addr.0.port()
    ))
}

/// Directory holding every service (DNS / `/etc/hosts`) record of one bridge.
///
/// Service records used to be flat files named `service-<bridge>-<name>-addr-…`
/// in the one machine-global directory, so both readers had to `read_dir` the
/// whole namespace -- every other bridge's records, every other instance's
/// records and all the litter -- and then throw away everything that did not
/// match their prefix. Sharding turns that prefix filter into the path itself.
fn service_bridge_dir(endpoint_dir: &Path, bridge_id: &BridgeId) -> PathBuf {
    endpoint_dir.join(format!(
        "{SERVICE_SHARD_PREFIX}{}",
        hex_name(bridge_id.as_str())
    ))
}

/// Directory holding the records of one (bridge, name) pair. One name may hold
/// several records -- two containers can share an alias -- so the fan-out stays
/// one file per address, which is also what keeps each record independently
/// owned and independently reclaimable.
fn service_name_dir(endpoint_dir: &Path, bridge_id: &BridgeId, name: &str) -> PathBuf {
    service_bridge_dir(endpoint_dir, bridge_id).join(hex_name(name))
}

fn service_record_path(name_dir: &Path, addr: Ipv4Addr) -> PathBuf {
    name_dir.join(format!("addr-{}", addr.to_string().replace('.', "_")))
}

/// The ONE decision that partitions bridge endpoints into "anyone on this
/// machine may resolve this" and "only my own instance may". Pure, and called
/// with the same inputs by the publisher and by every resolver, so the registry
/// key and the file path can never disagree about which realm a record is in.
///
/// The rule is the address: `carrick_spec::is_bridge_placeholder_ipv4` is true
/// only inside `172.31.0.0/24`, which no container *name* can ever hash into
/// (proved by `unnamed_container_address_is_disjoint_from_every_named_one`) and
/// which `--ip` refuses. So an address in it means "nothing was allocated, here
/// is a placeholder" -- there is no DNS record for it, no user can name it, and
/// the set of processes that can meaningfully mean it is exactly one run and
/// its fork children.
///
/// **This is the one behaviour change.** Two concurrent *unnamed* containers
/// stop being able to reach each other at `172.31.0.2`. They alias today, and
/// that aliasing IS the cross-wire being removed -- there was never a
/// well-defined "other container" at that address, only whichever instance
/// wrote the record last. Docker gives each container a distinct address; giving
/// carrick real per-container addresses is IPAM work, scheduled separately.
///
/// `namespace_id` is `Option` because two callers -- the published-port relays'
/// target and `resolve_registered_connect` -- can be handed a spec that never
/// named a namespace. Such a spec cannot register an endpoint at all
/// (`materialize_bridge_bind` and `prepare_tcp_listen` both require the id), so
/// it has no records of its own to find; `Shared` keeps its lookups exactly
/// where they are today rather than inventing an identity for it.
///
/// It must never be a `getpid()`-at-use decision: `namespace_id` is sampled once
/// at spec build, before any fork, so a forked child derives its parent's realm.
fn bridge_realm(namespace_id: Option<&NetworkNamespaceId>, guest_ip: IpAddr) -> BridgeRealm {
    match (guest_ip, namespace_id) {
        (IpAddr::V4(ip), Some(namespace_id)) if carrick_spec::is_bridge_placeholder_ipv4(ip) => {
            BridgeRealm::Private(namespace_id.clone())
        }
        _ => BridgeRealm::Shared,
    }
}

fn bridge_scope(
    bridge_id: BridgeId,
    namespace_id: Option<&NetworkNamespaceId>,
    virtual_addr: GuestSocketAddr,
) -> EndpointScope {
    EndpointScope::Bridge {
        realm: bridge_realm(namespace_id, virtual_addr.0.ip()),
        bridge: bridge_id,
    }
}

fn endpoint_scope(
    bridge_id: BridgeId,
    namespace_id: NetworkNamespaceId,
    virtual_addr: GuestSocketAddr,
) -> EndpointScope {
    if virtual_addr.0.ip().is_loopback() {
        EndpointScope::Namespace(namespace_id)
    } else {
        bridge_scope(bridge_id, Some(&namespace_id), virtual_addr)
    }
}

/// The directory a record of `scope` lives in, relative to the namespace root.
///
/// A private realm is a *subdirectory* rather than a filename prefix because
/// that is the variant reclamation can use: every private realm id is
/// `anon-<pid>` in practice, so `inst-<hex anon-pid>/` is decidable as a whole
/// directory with one liveness check -- reaching the `bridge-`/`listen-` record
/// families that the per-file lazy rule can never reach, because nothing ever
/// enumerates them by name.
fn endpoint_scope_dir(endpoint_dir: &Path, scope: &EndpointScope) -> PathBuf {
    match scope {
        EndpointScope::Bridge {
            realm: BridgeRealm::Private(namespace_id),
            ..
        } => endpoint_dir.join(format!(
            "{PRIVATE_REALM_PREFIX}{}",
            hex_name(namespace_id.as_str())
        )),
        _ => endpoint_dir.to_path_buf(),
    }
}

fn endpoint_scope_path_component(scope: &EndpointScope) -> String {
    match scope {
        EndpointScope::Bridge { bridge, .. } => format!("bridge-{}", hex_name(bridge.as_str())),
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

/// Inverse of [`hex_name`]. Only reclamation needs it: it reads a realm id back
/// out of a directory name to ask whether that instance is still alive.
fn unhex_name(encoded: &str) -> Option<String> {
    if !encoded.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(encoded.len() / 2);
    for pair in encoded.as_bytes().chunks(2) {
        let pair = std::str::from_utf8(pair).ok()?;
        bytes.push(u8::from_str_radix(pair, 16).ok()?);
    }
    String::from_utf8(bytes).ok()
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

/// This process's identity, minted once and inherited across `fork`.
///
/// **Diagnostic only — nothing is admitted or refused on it.** Record ownership
/// is decided by `ns=` (see [`RecordTrust`]), because the namespace is the real
/// boundary: `carrick exec` runs as a separate *process* that legitimately
/// shares its container's namespace. What this adds over `pid=` is that a pid is
/// reused by the OS, so mixing in a monotonic timestamp lets a human reading a
/// record (or an `NSREJECT` ring entry) tell a recycled pid's stale record from
/// a live one, and tell one process family's publications from another's.
///
/// It is process-global rather than per-provider so a fork child compares equal
/// to its parent, and forcing it from `SocketNamespaceProvider::new` -- before
/// the guest boots -- means the value is already set when `fork()` copies it.
fn instance_id() -> u128 {
    static INSTANCE: std::sync::OnceLock<u128> = std::sync::OnceLock::new();
    *INSTANCE.get_or_init(|| {
        let pid = u128::from(std::process::id());
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        (pid << 96) | (nanos & ((1 << 96) - 1))
    })
}

/// The record's own name for itself: its path relative to the namespace root.
///
/// A reader computes a path from the tuple it is asking about and then reads
/// whatever is there. `key=` closes that loop by making the record state which
/// tuple it believes it answers, so a path-scheme bug, a build-skew record or a
/// half-migrated directory is caught as a mismatch instead of being served as if
/// it were the right answer. It costs one string compare on bytes the reader has
/// already read: no extra syscall, and an O(1) read stays O(1).
fn record_key(endpoint_dir: &Path, path: &Path) -> String {
    path.strip_prefix(endpoint_dir)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

/// The namespace a record was published for, hex-encoded so an arbitrary
/// container id or `--name` cannot inject a newline into the record format.
///
/// This is the field record ownership is decided on: it says *which container's*
/// listener the record describes, which is what a published-port relay actually
/// needs to know. Process identity would be the wrong question -- see
/// [`RecordTrust`].
fn record_namespace_field(namespace_id: Option<&NetworkNamespaceId>) -> String {
    match namespace_id {
        Some(namespace_id) => format!("ns={}\n", hex_name(namespace_id.as_str())),
        None => String::new(),
    }
}

fn encode_endpoint_record(
    endpoint_dir: &Path,
    path: &Path,
    addr: SocketAddr,
    namespace_id: Option<&NetworkNamespaceId>,
) -> String {
    format!(
        "{addr}\npid={}\ninstance={:032x}\n{}key={}\n",
        std::process::id(),
        instance_id(),
        record_namespace_field(namespace_id),
        record_key(endpoint_dir, path)
    )
}

fn record_field<'a>(raw: &'a str, field: &str) -> Option<&'a str> {
    raw.lines()
        .find_map(|line| line.strip_prefix(field))
        .map(str::trim)
}

/// Does this record claim to answer the tuple the reader asked about?
///
/// A record with no `key=` at all makes no claim -- it predates the field, and
/// its own path is the only thing that placed it -- so it is accepted. Only a
/// record that names a *different* key is rejected, because that can only come
/// from a genuine disagreement about where records live.
fn record_key_matches(endpoint_dir: &Path, path: &Path, raw: &str) -> bool {
    match record_field(raw, "key=") {
        Some(claimed) => claimed == record_key(endpoint_dir, path),
        None => true,
    }
}

/// Was this record published for `owner`'s container?
///
/// A record with no `ns=` at all makes no claim -- it predates the field -- so
/// it is accepted, exactly as for `key=`. Only a record that names a *different*
/// namespace is a genuine disagreement about whose listener it describes.
fn record_namespace_matches(raw: &str, owner: &NetworkNamespaceId) -> bool {
    match record_field(raw, "ns=") {
        Some(claimed) => claimed == hex_name(owner.as_str()),
        None => true,
    }
}

fn write_endpoint_file(
    fork_gate: &Arc<Mutex<()>>,
    endpoint_dir: &Path,
    endpoint: &VirtualEndpoint,
    namespace_id: Option<&NetworkNamespaceId>,
    host_addr: HostSocketAddr,
) -> Result<Vec<(PathBuf, String)>, String> {
    let _fork_gate = fork_gate.lock().unwrap_or_else(|p| p.into_inner());
    let scope_dir = endpoint_scope_dir(endpoint_dir, &endpoint.scope);
    let path = endpoint_path(endpoint_dir, endpoint);
    let contents = encode_endpoint_record(endpoint_dir, &path, host_addr.0, namespace_id);
    write_record(&scope_dir, &path, &contents)
        .map_err(|e| format!("failed to record socket namespace endpoint: {e}"))?;
    let reverse_path = reverse_endpoint_path(endpoint_dir, host_addr, endpoint.protocol);
    let reverse_contents =
        encode_endpoint_record(endpoint_dir, &reverse_path, endpoint.addr.0, namespace_id);
    write_record(endpoint_dir, &reverse_path, &reverse_contents)
        .map_err(|e| format!("failed to record socket namespace reverse endpoint: {e}"))?;
    Ok(vec![(path, contents), (reverse_path, reverse_contents)])
}

fn remove_endpoint_files(fork_gate: &Arc<Mutex<()>>, files: Vec<(PathBuf, String)>) {
    let _fork_gate = fork_gate.lock().unwrap_or_else(|p| p.into_inner());
    for (path, expected_contents) in files {
        remove_record_if_unchanged(&path, &expected_contents);
    }
}

/// Whose records a reader is willing to be answered by.
///
/// The boundary is the **namespace**, not the process. An endpoint record
/// describes a particular container's listener, and the set of processes
/// entitled to publish that is exactly the set sharing its namespace id: the run
/// process, every guest fork child, and a `carrick exec` -- which is a separate
/// process handed the container's namespace id
/// (`carrick-cli/src/lifecycle.rs:1187`). Two different instances never share
/// one, so this separates them without splitting a container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordTrust<'a> {
    /// Any live instance's record may answer. This is the guest-facing rule and
    /// the reason the endpoint namespace is machine-global at all: a container
    /// resolving `db` must reach the `db` a *different* `carrick run` process
    /// published.
    AnyNamespace,
    /// Only a record published for this namespace may answer. Used by the
    /// published-port relays, whose target is derived from their own lease's
    /// spec.
    OwnNamespaceOnly(&'a NetworkNamespaceId),
}

fn read_endpoint_file(
    fork_gate: &Arc<Mutex<()>>,
    endpoint_dir: &Path,
    endpoint: &VirtualEndpoint,
) -> Option<HostSocketAddr> {
    read_endpoint_file_trusting(fork_gate, endpoint_dir, endpoint, RecordTrust::AnyNamespace)
}

fn read_endpoint_file_trusting(
    fork_gate: &Arc<Mutex<()>>,
    endpoint_dir: &Path,
    endpoint: &VirtualEndpoint,
    trust: RecordTrust<'_>,
) -> Option<HostSocketAddr> {
    let _fork_gate = fork_gate.lock().unwrap_or_else(|p| p.into_inner());
    let path = endpoint_path(endpoint_dir, endpoint);
    match read_namespace_file(&path)? {
        NamespaceFile::Live(raw) => {
            if !record_key_matches(endpoint_dir, &path, &raw) {
                warn_rejected_record("key", &path);
                return None;
            }
            if let RecordTrust::OwnNamespaceOnly(owner) = trust
                && !record_namespace_matches(&raw, owner)
            {
                warn_rejected_record("namespace", &path);
                return None;
            }
            raw.lines().next()?.trim().parse().ok().map(HostSocketAddr)
        }
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

/// A record was refused for claiming to be something else. Guest-facing paths
/// stay silent and surface `ECONNREFUSED` as Linux would, so this is the only
/// place the condition is visible; say it once per process on stderr (a
/// per-connection message would be a flood), and put every occurrence in the
/// always-on event ring where a core or a live `lldb` picks it up.
fn warn_rejected_record(reason: &str, path: &Path) {
    static WARNED: AtomicBool = AtomicBool::new(false);
    crate::event_ring::rec(
        crate::event_ring::NSREJECT,
        crate::event_ring::path_hash(path.as_os_str().as_encoded_bytes()),
        crate::event_ring::path_hash(reason.as_bytes()),
        std::process::id() as i32,
    );
    if !WARNED.swap(true, Ordering::SeqCst) {
        eprintln!(
            "carrick: refused a socket-namespace record that belongs to another {reason}: {}",
            path.display()
        );
    }
}

fn read_reverse_endpoint_file(
    fork_gate: &Arc<Mutex<()>>,
    endpoint_dir: &Path,
    host_addr: HostSocketAddr,
    protocol: PortProtocol,
) -> Option<GuestSocketAddr> {
    let _fork_gate = fork_gate.lock().unwrap_or_else(|p| p.into_inner());
    let path = reverse_endpoint_path(endpoint_dir, host_addr, protocol);
    let raw = read_live_namespace_file(&path)?;
    if !record_key_matches(endpoint_dir, &path, &raw) {
        warn_rejected_record("key", &path);
        return None;
    }
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
    // Reclaim, but only the bytes this verdict was reached from: the dead
    // owner's successor may have renamed a live record in while this read was
    // off the CPU, and unlinking that would destroy a live publication.
    remove_record_if_unchanged(path, &raw);
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

fn connect_tracked_tcp(
    target: SocketAddr,
    fork_gate: &Arc<Mutex<()>>,
    fork_tracked_fds: &Arc<Mutex<HashSet<RawFd>>>,
) -> io::Result<ForkTrackedSocket<TcpStream>> {
    let socket = {
        let _fork_gate = fork_gate.lock().unwrap_or_else(|p| p.into_inner());
        let domain = if target.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_nonblocking(true)?;
        ForkTrackedSocket::new_under_fork_gate(socket, fork_gate, fork_tracked_fds)
    };

    let address = SockAddr::from(target);
    if let Err(error) = socket.connect(&address) {
        let raw = error.raw_os_error();
        if !matches!(
            raw,
            Some(libc::EINPROGRESS) | Some(libc::EALREADY) | Some(libc::EWOULDBLOCK)
        ) {
            return Err(error);
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let now = std::time::Instant::now();
            if now >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "bridge TCP target connect timed out",
                ));
            }
            let remaining_ms = deadline
                .saturating_duration_since(now)
                .as_millis()
                .clamp(1, i32::MAX as u128) as i32;
            let mut pollfd = libc::pollfd {
                fd: socket.as_raw_fd(),
                events: libc::POLLOUT,
                revents: 0,
            };
            let rc = unsafe { libc::poll(&mut pollfd, 1, remaining_ms) };
            if rc < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(error);
            }
            if rc == 0 {
                continue;
            }
            if let Some(error) = socket.take_error()? {
                return Err(error);
            }
            break;
        }
    }
    socket.set_nonblocking(false)?;
    Ok(socket.map_preserving_fd(Into::into))
}

/// Serve a published host port by proxying each inbound connection to whatever
/// currently backs `target` inside this container.
///
/// The registry lookup usually misses: the guest listener is bound by a *forked*
/// descendant, whose `register_virtual_endpoint` landed in its own
/// copy-on-write copy of the registry and is invisible here. The durable record
/// is the only channel, which is exactly why that record must not be ambiguous.
///
/// The relay demands the record have been published for its **own namespace**
/// (`RecordTrust::OwnNamespaceOnly`). A record describes one container's
/// listener, and the processes entitled to publish that container's listener are
/// exactly those sharing its namespace id -- the run process and every guest
/// fork child, *and* a `carrick exec`, which is a separate process handed the
/// same id (`carrick-cli/src/lifecycle.rs:1187` matches `:389`). So a port
/// published by `carrick run -p 8080:80` is served when the listener is bound by
/// an `exec`ed command rather than by the container's own entrypoint, which is
/// what Docker does and what a process-identity check would have broken. A
/// record from a *different* namespace is another container's and is refused:
/// refusing is what the guest would see anyway if that peer were not running,
/// while serving it would send this user's traffic into another user's
/// container.
///
/// Deliberately out of scope here: two concurrent instances given the same
/// `--name` share a namespace id *and* a name-derived address, so this check
/// cannot separate them -- and should not try, because that is a name-uniqueness
/// problem. The fix is an `O_EXCL` claim refusing a second container while a
/// live one holds the name, tracked as a follow-on; see
/// `docs/superpowers/specs/2026-07-25-published-port-crosswiring-design.md` §9.2.
fn published_tcp_accept_loop(
    listener: ForkTrackedSocket<TcpListener>,
    fork_state: BridgeHelperForkState,
    registry: Arc<Mutex<HashMap<VirtualEndpoint, HostSocketAddr>>>,
    endpoint_dir: Arc<PathBuf>,
    target: RelayTarget,
    stop: Arc<AtomicBool>,
) {
    let fork_gate = &fork_state.fork_gate;
    let fork_tracked_fds = &fork_state.tracked_fds;
    while !stop.load(Ordering::SeqCst) {
        let accepted = {
            let _fork_gate = fork_gate.lock().unwrap_or_else(|p| p.into_inner());
            listener.accept().map(|(inbound, peer)| {
                (
                    ForkTrackedSocket::new_under_fork_gate(inbound, fork_gate, fork_tracked_fds),
                    peer,
                )
            })
        };
        match accepted {
            Ok((inbound, _)) => {
                let target_addr = {
                    let _fork_gate = fork_gate.lock().unwrap_or_else(|p| p.into_inner());
                    registry
                        .lock()
                        .ok()
                        .and_then(|registry| registry.get(&target.endpoint).copied())
                }
                .or_else(|| {
                    read_endpoint_file_trusting(
                        fork_gate,
                        &endpoint_dir,
                        &target.endpoint,
                        target.trust(),
                    )
                });
                // Create and publish the fd while fork is excluded, then leave
                // the gate before the bounded nonblocking network operation.
                let connected = target_addr.and_then(|target_addr| {
                    connect_tracked_tcp(target_addr.0, fork_gate, fork_tracked_fds).ok()
                });
                if let Some(outbound) = connected {
                    let stream_fork_state = fork_state.clone();
                    let _ = thread::Builder::new()
                        .name("carrick-bridge-publish-tcp-stream".to_string())
                        .spawn(move || {
                            let _ = proxy_tcp_stream(inbound, outbound, stream_fork_state);
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

fn proxy_tcp_stream(
    mut inbound: ForkTrackedSocket<TcpStream>,
    mut outbound: ForkTrackedSocket<TcpStream>,
    fork_state: BridgeHelperForkState,
) -> io::Result<()> {
    // The relay copies each direction with blocking reads and writes, so both
    // descriptors must be in blocking mode before any copying starts. They are
    // not blocking by construction: on BSD-derived hosts (macOS, FreeBSD,
    // NetBSD) `accept()` inherits O_NONBLOCK from the listener, and the
    // published TCP listener is deliberately nonblocking so its accept loop can
    // observe `stop`. A nonblocking descriptor would turn the very first
    // `EAGAIN` -- i.e. "the peer has not sent anything yet" -- into a spurious
    // end-of-stream, half-closing a live connection and abortively resetting it
    // once the unread peer data is discarded on close. Clearing the flag before
    // the `try_clone` calls also covers the cloned halves, which share the
    // underlying file description and therefore its status flags.
    inbound.set_nonblocking(false)?;
    outbound.set_nonblocking(false)?;
    let fork_gate = &fork_state.fork_gate;
    let fork_tracked_fds = &fork_state.tracked_fds;
    let (mut inbound_clone, mut outbound_clone) = {
        let _fork_gate = fork_gate.lock().unwrap_or_else(|p| p.into_inner());
        let inbound_clone = inbound.try_clone()?;
        let outbound_clone = match outbound.try_clone() {
            Ok(clone) => clone,
            Err(error) => {
                // The first clone is not yet published; close it while fork is
                // still excluded so no child can inherit an untracked fd.
                drop(inbound_clone);
                return Err(error);
            }
        };
        (
            ForkTrackedSocket::new_under_fork_gate(inbound_clone, fork_gate, fork_tracked_fds),
            ForkTrackedSocket::new_under_fork_gate(outbound_clone, fork_gate, fork_tracked_fds),
        )
    };
    let left = thread::spawn(move || {
        let copied = io::copy(&mut inbound_clone, &mut outbound);
        let _ = outbound.shutdown(std::net::Shutdown::Write);
        copied
    });
    let right = thread::spawn(move || {
        let copied = io::copy(&mut outbound_clone, &mut inbound);
        let _ = inbound.shutdown(std::net::Shutdown::Write);
        copied
    });
    let _ = left.join();
    let _ = right.join();
    Ok(())
}

fn published_udp_loop(
    socket: ForkTrackedSocket<UdpSocket>,
    fork_state: BridgeHelperForkState,
    registry: Arc<Mutex<HashMap<VirtualEndpoint, HostSocketAddr>>>,
    endpoint_dir: Arc<PathBuf>,
    target: RelayTarget,
    reply: UdpReplyEndpoint,
    stop: Arc<AtomicBool>,
) {
    let fork_gate = &fork_state.fork_gate;
    let fork_tracked_fds = &fork_state.tracked_fds;
    let mut request = vec![0_u8; 65_535];
    let mut response = vec![0_u8; 65_535];
    while !stop.load(Ordering::SeqCst) {
        match socket.recv_from(&mut request) {
            Ok((request_len, source)) => {
                let target_addr = {
                    let _fork_gate = fork_gate.lock().unwrap_or_else(|p| p.into_inner());
                    registry
                        .lock()
                        .ok()
                        .and_then(|registry| registry.get(&target.endpoint).copied())
                }
                .or_else(|| {
                    read_endpoint_file_trusting(
                        fork_gate,
                        &endpoint_dir,
                        &target.endpoint,
                        target.trust(),
                    )
                });
                let Some(target_addr) = target_addr else {
                    continue;
                };
                let outbound = {
                    let _fork_gate = fork_gate.lock().unwrap_or_else(|p| p.into_inner());
                    UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                        .ok()
                        .map(|outbound| {
                            ForkTrackedSocket::new_under_fork_gate(
                                outbound,
                                fork_gate,
                                fork_tracked_fds,
                            )
                        })
                };
                let Some(outbound) = outbound else {
                    continue;
                };
                let Ok(outbound_addr) = outbound.local_addr() else {
                    continue;
                };
                let reply_endpoint = VirtualEndpoint {
                    scope: reply.scope.clone(),
                    addr: GuestSocketAddr(SocketAddr::new(
                        IpAddr::V4(reply.gateway_v4),
                        outbound_addr.port(),
                    )),
                    protocol: PortProtocol::Udp,
                };
                let owned_reply_files = write_endpoint_file(
                    fork_gate,
                    &endpoint_dir,
                    &reply_endpoint,
                    target.namespace_id.as_ref(),
                    HostSocketAddr(outbound_addr),
                )
                .unwrap_or_default();
                let _ = outbound.set_read_timeout(Some(Duration::from_secs(2)));
                if outbound
                    .send_to(&request[..request_len], target_addr.0)
                    .is_err()
                {
                    remove_endpoint_files(fork_gate, owned_reply_files);
                    continue;
                }
                if let Ok((response_len, _)) = outbound.recv_from(&mut response) {
                    let _ = socket.send_to(&response[..response_len], source);
                }
                remove_endpoint_files(fork_gate, owned_reply_files);
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
    fn try_fork_guard(&self) -> Option<super::NetworkForkGuard<'_>> {
        match self.fork_gate.try_lock() {
            Ok(guard) => Some(super::NetworkForkGuard::real(guard)),
            Err(std::sync::TryLockError::WouldBlock) => None,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                Some(super::NetworkForkGuard::real(poisoned.into_inner()))
            }
        }
    }

    fn after_fork_child(&self) {
        // The publication pthreads do not survive fork. Close every inherited
        // helper socket immediately, then leak the copied JoinHandles rather
        // than joining vanished threads. The child must also relinquish all
        // durable endpoint-file ownership so its eventual provider Drop cannot
        // remove publications still served and owned by the parent.
        {
            let _fork_gate = self.fork_gate.lock().unwrap_or_else(|p| p.into_inner());
            let mut tracked_fds = self
                .fork_tracked_fds
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            for fd in tracked_fds.drain() {
                unsafe {
                    libc::close(fd);
                }
            }
        }

        let mut tcp = self.published_tcp.lock().unwrap_or_else(|p| p.into_inner());
        for proxy in tcp.values_mut().flat_map(|proxies| proxies.iter_mut()) {
            if let Some(handle) = proxy.handle.take() {
                std::mem::forget(handle);
            }
        }
        tcp.clear();
        drop(tcp);

        let mut udp = self.published_udp.lock().unwrap_or_else(|p| p.into_inner());
        for proxy in udp.values_mut().flat_map(|proxies| proxies.iter_mut()) {
            if let Some(handle) = proxy.handle.take() {
                std::mem::forget(handle);
            }
        }
        udp.clear();
        drop(udp);

        self.owned_endpoint_files
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
    }

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
        let lease_id = NetworkLeaseId(self.next_lease_id.fetch_add(1, Ordering::SeqCst));
        self.register_service_names(lease_id, spec)?;
        let mut lease_specs = self
            .lease_specs
            .lock()
            .map_err(|_| "socket namespace lease registry lock poisoned".to_string())?;
        lease_specs.insert(lease_id, spec.clone());
        drop(lease_specs);
        if let Some(namespace_id) = spec.namespace_id.clone() {
            let mut namespaces = self
                .namespaces
                .lock()
                .map_err(|_| "socket namespace registry lock poisoned".to_string())?;
            namespaces.insert(namespace_id.clone(), spec.clone());
            drop(namespaces);
            let mut namespace_leases = self
                .namespace_leases
                .lock()
                .map_err(|_| "socket namespace lease registry lock poisoned".to_string())?;
            namespace_leases.insert(namespace_id, lease_id);
        }
        Ok(NetworkLease { id: lease_id })
    }

    fn destroy_namespace(&self, lease_id: NetworkLeaseId) -> Result<(), String> {
        if let Ok(mut published_tcp) = self.published_tcp.lock() {
            published_tcp.remove(&lease_id);
        }
        if let Ok(mut published_udp) = self.published_udp.lock() {
            published_udp.remove(&lease_id);
        }
        if let Ok(mut lease_specs) = self.lease_specs.lock() {
            lease_specs.remove(&lease_id);
        }
        let mut removed_paths = HashSet::new();
        if let Ok(mut owned) = self.owned_endpoint_files.lock()
            && let Some(entries) = owned.remove(&lease_id)
        {
            for entry in entries {
                removed_paths.insert(entry.path.clone());
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
        if let Ok(mut registry) = self.registry.lock() {
            registry.retain(|endpoint, host_addr| {
                !removed_paths.contains(&endpoint_path(&self.endpoint_dir, endpoint))
                    && !removed_paths.contains(&reverse_endpoint_path(
                        &self.endpoint_dir,
                        *host_addr,
                        endpoint.protocol,
                    ))
            });
        }
        if let Ok(mut listeners) = self.tcp_listeners.lock() {
            listeners.retain(|endpoint, _| {
                !removed_paths.contains(&listener_path(&self.endpoint_dir, endpoint))
            });
        }
        let mut removed_namespaces = HashSet::new();
        if let Ok(mut namespace_leases) = self.namespace_leases.lock() {
            namespace_leases.retain(|namespace_id, owner| {
                if *owner == lease_id {
                    removed_namespaces.insert(namespace_id.clone());
                    false
                } else {
                    true
                }
            });
        }
        if let Ok(mut namespaces) = self.namespaces.lock() {
            namespaces.retain(|namespace_id, _| !removed_namespaces.contains(namespace_id));
        }
        if let Ok(mut socket_addrs) = self.socket_addrs.lock() {
            socket_addrs.retain(|_, state| state.lease_id != Some(lease_id));
        }
        // Deliberately does NOT remove the namespace root. `fs::remove_dir`
        // succeeds the moment the directory is empty, and the directory is
        // machine-global: a concurrent instance that has published nothing yet,
        // or whose records were just reclaimed, would have the root pulled out
        // from under it. Its writers re-create it, but its two `read_dir`
        // service scans would silently return empty in between -- a transient
        // DNS/`/etc/hosts` miss with no error anywhere. The root is now
        // reclaimed by the once-per-process pass instead.
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
    ) -> Result<(), carrick_abi::LinuxErrno> {
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
    use std::os::fd::{AsRawFd, RawFd};
    use std::thread;

    #[cfg(target_os = "freebsd")]
    static FORK_SOCKET_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn free_loopback_port() -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve port");
        listener.local_addr().expect("local addr").port()
    }

    fn guest(addr: SocketAddr) -> GuestSocketAddr {
        GuestSocketAddr(addr)
    }

    /// The namespace id `RuntimeNetwork::create` mints for this process.
    fn this_instance_namespace() -> NetworkNamespaceId {
        NetworkNamespaceId::anonymous(std::process::id())
    }

    /// A spec shaped exactly like the one `carrick run -p ... <image>` builds
    /// with no `--name`: the default bridge, the `172.31.0.2` placeholder, and
    /// an instance-unique namespace id minted before any fork. That is the shape
    /// the published-port cross-wiring lived in, so it is the shape these tests
    /// exercise.
    fn unnamed_bridge_spec(published_ports: Vec<PortMapping>) -> NetworkNamespaceSpec {
        let mut spec = NetworkNamespaceSpec::bridge_default(None, Vec::new(), published_ports);
        spec.namespace_id = Some(this_instance_namespace());
        spec
    }

    fn reclaim_fixture_root(label: &str) -> PathBuf {
        let root = shared_endpoint_dir().join(format!("reclaim-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("fixture root");
        root
    }

    fn write_fixture_record(path: &Path, owner_pid: i32) {
        fs::create_dir_all(path.parent().expect("record parent")).expect("record dir");
        fs::write(path, format!("172.31.0.9\nname=fixture\npid={owner_pid}\n"))
            .expect("fixture record");
    }

    #[test]
    fn endpoint_reclaim_removes_dead_owner_records_and_keeps_live_ones() {
        let root = reclaim_fixture_root("mixed");
        let live_pid = std::process::id() as i32;
        // `process_is_alive` reports pid <= 0 as gone, so a dead owner is a
        // decidable property here rather than a race against a real exit.
        let dead_pid = 0;

        let live_endpoint = root.join("bridge-6c697665-172.31.0.9-8080-tcp");
        let dead_endpoint = root.join("bridge-64656164-172.31.0.9-8080-tcp");
        let live_reverse = root.join("reverse-127.0.0.1-40001-tcp");
        let dead_reverse = root.join("reverse-127.0.0.1-40002-tcp");
        let dead_listener = root.join("listen-bridge-64656164-172.31.0.9-8080-tcp");
        write_fixture_record(&live_endpoint, live_pid);
        write_fixture_record(&dead_endpoint, dead_pid);
        write_fixture_record(&live_reverse, live_pid);
        write_fixture_record(&dead_reverse, dead_pid);
        write_fixture_record(&dead_listener, dead_pid);

        let bridge = BridgeId::new("reclaim-bridge");
        let live_service = service_record_path(
            &service_name_dir(&root, &bridge, "live"),
            Ipv4Addr::new(172, 31, 0, 9),
        );
        let dead_service = service_record_path(
            &service_name_dir(&root, &bridge, "dead"),
            Ipv4Addr::new(172, 31, 0, 10),
        );
        write_fixture_record(&live_service, live_pid);
        write_fixture_record(&dead_service, dead_pid);

        let dead_owner_dir = root.join(format!("{PER_PROCESS_DIR_PREFIX}0"));
        write_fixture_record(&dead_owner_dir.join("bridge-x-172.31.0.9-1-tcp"), live_pid);
        let self_owner_dir = root.join(format!("{PER_PROCESS_DIR_PREFIX}{live_pid}"));
        write_fixture_record(&self_owner_dir.join("bridge-x-172.31.0.9-1-tcp"), dead_pid);
        // A record with no `pid=` line is not reclaimable by the shared rule and
        // must stay exactly as immortal as it is on the lookup path.
        let unowned = root.join("bridge-756e-172.31.0.9-9999-tcp");
        fs::write(&unowned, "172.31.0.9\n").expect("unowned record");

        let visited = reclaim_stale_endpoint_records(&root, usize::MAX);
        assert!(visited > 0, "reclaim must visit the fixture");

        assert!(live_endpoint.exists(), "live endpoint record must survive");
        assert!(live_reverse.exists(), "live reverse record must survive");
        assert!(live_service.exists(), "live service record must survive");
        assert!(unowned.exists(), "record without an owner must survive");
        assert!(
            self_owner_dir.exists(),
            "this process's own directory must survive"
        );
        assert!(!dead_endpoint.exists(), "dead endpoint must be reclaimed");
        assert!(!dead_reverse.exists(), "dead reverse must be reclaimed");
        assert!(!dead_listener.exists(), "dead listener must be reclaimed");
        assert!(
            !dead_service.exists(),
            "dead service record must be claimed"
        );
        assert!(
            !dead_service.parent().expect("name dir").exists(),
            "an emptied service name directory must not be left behind"
        );
        assert!(
            !dead_owner_dir.exists(),
            "a directory owned entirely by a dead pid must be reclaimed whole"
        );
        assert!(
            service_bridge_dir(&root, &bridge).exists(),
            "a shard still holding a live record must be kept"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn endpoint_reclaim_stops_at_its_budget() {
        let root = reclaim_fixture_root("budget");
        for index in 0..8 {
            write_fixture_record(&root.join(format!("bridge-64-172.31.0.9-{index}-tcp")), 0);
        }

        let visited = reclaim_stale_endpoint_records(&root, 3);
        assert_eq!(visited, 3, "reclaim must stop at its visit budget");
        let remaining = fs::read_dir(&root).expect("root").flatten().count();
        assert_eq!(
            remaining, 5,
            "reclaim must leave everything past the budget for the next process"
        );

        // Successive passes make progress, because a visited dead record is gone.
        assert_eq!(reclaim_stale_endpoint_records(&root, 3), 3);
        assert_eq!(reclaim_stale_endpoint_records(&root, usize::MAX), 2);
        assert_eq!(fs::read_dir(&root).expect("root").flatten().count(), 0);

        let _ = fs::remove_dir_all(&root);
    }

    /// The durable record files exist because a forked guest child cannot see
    /// the parent's in-process registry. Sharding the service records changed
    /// where those files live, so pin the property they exist for: a child must
    /// still resolve what its parent published both before and after the fork.
    #[test]
    fn forked_child_resolves_service_and_endpoint_records_across_the_fork() {
        let suffix = std::process::id();
        let bridge = BridgeId::new(format!("test-forkdns-{suffix}"));
        let mut prefork = NetworkNamespaceSpec::bridge_default(
            Some("prefork".to_string()),
            vec!["shared".to_string()],
            Vec::new(),
        );
        prefork.bridge_id = bridge.clone();
        prefork.ipv4 = Ipv4Addr::new(172, 31, 60, 10);
        prefork.namespace_id = Some(NetworkNamespaceId::new(format!("test-forkdns-a-{suffix}")));
        let mut postfork = NetworkNamespaceSpec::bridge_default(
            Some("postfork".to_string()),
            vec!["shared".to_string()],
            Vec::new(),
        );
        postfork.bridge_id = bridge.clone();
        postfork.ipv4 = Ipv4Addr::new(172, 31, 60, 11);
        postfork.namespace_id = Some(NetworkNamespaceId::new(format!("test-forkdns-b-{suffix}")));

        let provider = SocketNamespaceProvider::new();
        provider
            .create_namespace(&prefork)
            .expect("pre-fork namespace");

        let mut fds = [0i32; 2];
        assert_eq!(
            unsafe { libc::pipe(fds.as_mut_ptr()) },
            0,
            "pipe: {}",
            io::Error::last_os_error()
        );
        let (read_fd, write_fd) = (fds[0], fds[1]);
        let post_endpoint = guest(SocketAddr::new(IpAddr::V4(postfork.ipv4), 5432));
        let post_host = host(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 45432));

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", io::Error::last_os_error());
        if pid == 0 {
            unsafe { libc::close(write_fd) };
            // Block until the parent has published the post-fork records; the
            // child's copy-on-write registry can never learn about them, so a
            // hit here can only have come from the shared files.
            let mut byte = 0u8;
            let read = unsafe { libc::read(read_fd, (&raw mut byte).cast(), 1) };
            let mut code = 0;
            if read != 1 {
                code |= 1;
            }
            if provider.resolve_dns_name(&prefork, "prefork").ok() != Some(vec![prefork.ipv4]) {
                code |= 2;
            }
            if provider.resolve_dns_name(&prefork, "postfork").ok() != Some(vec![postfork.ipv4]) {
                code |= 4;
            }
            if provider.resolve_dns_name(&prefork, "shared").ok()
                != Some(vec![prefork.ipv4, postfork.ipv4])
            {
                code |= 8;
            }
            let hosts = provider.guest_hosts_entries(&prefork).unwrap_or_default();
            if !hosts
                .iter()
                .any(|entry| entry.addr == IpAddr::V4(postfork.ipv4))
                || !hosts
                    .iter()
                    .any(|entry| entry.addr == IpAddr::V4(prefork.ipv4))
            {
                code |= 16;
            }
            if provider
                .resolve_registered_connect(
                    &bridge,
                    postfork.namespace_id.as_ref(),
                    post_endpoint,
                    PortProtocol::Tcp,
                )
                .ok()
                .flatten()
                != Some(post_host)
            {
                code |= 32;
            }
            unsafe { libc::_exit(code) };
        }

        unsafe { libc::close(read_fd) };
        provider
            .create_namespace(&postfork)
            .expect("post-fork namespace");
        provider
            .register_virtual_endpoint(
                bridge.clone(),
                postfork.namespace_id.clone().expect("namespace id"),
                post_endpoint,
                PortProtocol::Tcp,
                post_host,
            )
            .expect("post-fork endpoint");
        assert_eq!(
            unsafe { libc::write(write_fd, [1u8].as_ptr().cast(), 1) },
            1,
            "signal child: {}",
            io::Error::last_os_error()
        );
        unsafe { libc::close(write_fd) };

        let mut status = 0i32;
        assert_eq!(
            unsafe { libc::waitpid(pid, &raw mut status, 0) },
            pid,
            "waitpid: {}",
            io::Error::last_os_error()
        );
        assert!(libc::WIFEXITED(status), "child did not exit normally");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "forked child failed to resolve records across the fork (bitmask)"
        );
    }

    #[test]
    fn endpoint_reclaim_bounds_a_large_dead_owner_directory() {
        let root = reclaim_fixture_root("deadowner");
        let dead_owner_dir = root.join(format!("{PER_PROCESS_DIR_PREFIX}0"));
        for index in 0..12 {
            write_fixture_record(
                &dead_owner_dir.join(format!("bridge-64-172.31.0.9-{index}-tcp")),
                std::process::id() as i32,
            );
        }

        // The owner is gone, so every record inside is reclaimable -- but the
        // pass must still stop, or one dead run's directory could cost the next
        // run an unbounded delete on its startup path.
        let visited = reclaim_stale_endpoint_records(&root, 5);
        assert_eq!(visited, 5, "reclaim must stop at its visit budget");
        assert!(
            dead_owner_dir.exists(),
            "a partially reclaimed directory must be left for the next pass"
        );
        assert_eq!(
            fs::read_dir(&dead_owner_dir)
                .expect("dir")
                .flatten()
                .count(),
            8,
            "reclaim must remove exactly the entries it visited"
        );

        reclaim_stale_endpoint_records(&root, usize::MAX);
        assert!(
            !dead_owner_dir.exists(),
            "an unbounded pass must finish the dead owner's directory"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn service_records_republish_into_a_reclaimed_shard() {
        let mut spec = NetworkNamespaceSpec::bridge_default(
            Some("recycled".to_string()),
            Vec::new(),
            Vec::new(),
        );
        spec.bridge_id = BridgeId::new(format!("test-recycled-{}", std::process::id()));
        spec.namespace_id = Some(NetworkNamespaceId::new(format!(
            "test-recycled-ns-{}",
            std::process::id()
        )));
        let provider = SocketNamespaceProvider::new();
        let lease = provider.create_namespace(&spec).expect("create namespace");
        let shard = service_bridge_dir(&provider.endpoint_dir, &spec.bridge_id);
        assert!(shard.exists(), "service shard must be created on publish");

        provider.destroy_namespace(lease.id).expect("destroy");
        reclaim_stale_endpoint_records(&provider.endpoint_dir, usize::MAX);
        assert!(
            !shard.exists(),
            "an empty shard must be reclaimed with its records"
        );

        provider.create_namespace(&spec).expect("re-create");
        assert_eq!(
            provider
                .resolve_dns_name(&spec, "recycled")
                .expect("resolve republished name"),
            vec![spec.ipv4]
        );
    }

    fn host(addr: SocketAddr) -> HostSocketAddr {
        HostSocketAddr(addr)
    }

    #[cfg(target_os = "freebsd")]
    fn wait_for_fork_tracked_fds(provider: &SocketNamespaceProvider, at_least: usize) {
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        loop {
            let tracked = provider
                .fork_tracked_fds
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .len();
            if tracked >= at_least {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "expected at least {at_least} tracked bridge fds, saw {tracked}"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }

    struct TestDropSignals {
        started: std::sync::mpsc::SyncSender<()>,
        finish: std::sync::mpsc::Receiver<()>,
    }

    struct FakeTrackedSocket {
        raw_fd: RawFd,
        drop_signals: Option<TestDropSignals>,
    }

    impl FakeTrackedSocket {
        fn new(raw_fd: RawFd) -> Self {
            Self {
                raw_fd,
                drop_signals: None,
            }
        }

        fn blocking_drop(
            raw_fd: RawFd,
            started: std::sync::mpsc::SyncSender<()>,
            finish: std::sync::mpsc::Receiver<()>,
        ) -> Self {
            Self {
                raw_fd,
                drop_signals: Some(TestDropSignals { started, finish }),
            }
        }
    }

    impl AsRawFd for FakeTrackedSocket {
        fn as_raw_fd(&self) -> RawFd {
            self.raw_fd
        }
    }

    impl Drop for FakeTrackedSocket {
        fn drop(&mut self) {
            if let Some(signals) = self.drop_signals.take() {
                let _ = signals.started.send(());
                let _ = signals.finish.recv();
            }
        }
    }

    #[test]
    fn fork_tracked_socket_drop_serializes_stale_fd_number_reuse() {
        let fork_gate = Arc::new(Mutex::new(()));
        let fork_tracked_fds = Arc::new(Mutex::new(HashSet::new()));
        let (drop_started_tx, drop_started_rx) = std::sync::mpsc::sync_channel(1);
        let (allow_drop_finish_tx, allow_drop_finish_rx) = std::sync::mpsc::sync_channel(1);
        let (new_owner_started_tx, new_owner_started_rx) = std::sync::mpsc::sync_channel(1);
        let old_owner = ForkTrackedSocket::new(
            FakeTrackedSocket::blocking_drop(41, drop_started_tx, allow_drop_finish_rx),
            &fork_gate,
            &fork_tracked_fds,
        );
        let old_drop = thread::spawn(move || drop(old_owner));
        drop_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("old owner entered drop");
        assert!(
            fork_tracked_fds
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .contains(&41),
            "closing owner must stay tracked until removal finishes"
        );

        let reuse_gate = Arc::clone(&fork_gate);
        let reuse_tracked = Arc::clone(&fork_tracked_fds);
        let reuse_owner = thread::spawn(move || {
            let owner =
                ForkTrackedSocket::new(FakeTrackedSocket::new(41), &reuse_gate, &reuse_tracked);
            new_owner_started_tx
                .send(())
                .expect("report reused fd tracking");
            owner
        });
        assert!(
            new_owner_started_rx
                .recv_timeout(Duration::from_millis(50))
                .is_err(),
            "fd reuse must wait for the old owner to finish close+removal"
        );

        allow_drop_finish_tx.send(()).expect("finish old drop");
        old_drop.join().expect("old owner drop thread");
        new_owner_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("new owner tracked reused fd");
        let new_owner = reuse_owner.join().expect("new owner thread");
        let tracked = fork_tracked_fds
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        assert_eq!(tracked, HashSet::from([41]));
        drop(new_owner);
        assert!(
            fork_tracked_fds
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_empty(),
            "dropping the replacement owner must clear the reused fd"
        );
    }

    #[test]
    fn fork_tracked_socket_drop_serializes_overlapping_removals() {
        let fork_gate = Arc::new(Mutex::new(()));
        let fork_tracked_fds = Arc::new(Mutex::new(HashSet::new()));
        let (first_started_tx, first_started_rx) = std::sync::mpsc::sync_channel(1);
        let (allow_first_finish_tx, allow_first_finish_rx) = std::sync::mpsc::sync_channel(1);
        let (second_finished_tx, second_finished_rx) = std::sync::mpsc::sync_channel(1);
        let first_owner = ForkTrackedSocket::new(
            FakeTrackedSocket::blocking_drop(51, first_started_tx, allow_first_finish_rx),
            &fork_gate,
            &fork_tracked_fds,
        );
        let second_owner =
            ForkTrackedSocket::new(FakeTrackedSocket::new(52), &fork_gate, &fork_tracked_fds);
        let first_drop = thread::spawn(move || drop(first_owner));
        first_started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("first owner entered drop");
        let second_drop = thread::spawn(move || {
            drop(second_owner);
            second_finished_tx
                .send(())
                .expect("report second owner removal");
        });
        assert!(
            second_finished_rx
                .recv_timeout(Duration::from_millis(50))
                .is_err(),
            "overlapping removal must wait behind the in-flight close"
        );
        allow_first_finish_tx.send(()).expect("finish first drop");
        first_drop.join().expect("first drop thread");
        second_finished_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("second owner removed after first finished");
        second_drop.join().expect("second drop thread");
        assert!(
            fork_tracked_fds
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_empty(),
            "overlapping removals must leave no stale tracked fds"
        );
    }

    /// The namespace `provider_with_endpoint` publishes under. Its address is
    /// the unnamed placeholder, so its records live in that namespace's private
    /// realm and every lookup has to name the same namespace to find them.
    fn endpoint_owner_namespace() -> NetworkNamespaceId {
        NetworkNamespaceId::new("a")
    }

    fn provider_with_endpoint() -> SocketNamespaceProvider {
        let provider = SocketNamespaceProvider::new();
        provider
            .register_virtual_endpoint(
                BridgeId::new("carrick0"),
                endpoint_owner_namespace(),
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
                Some(&endpoint_owner_namespace()),
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
                Some(&endpoint_owner_namespace()),
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
        let spec = unnamed_bridge_spec(Vec::new());
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
        let spec = unnamed_bridge_spec(Vec::new());
        let provider = SocketNamespaceProvider::new();
        let requested = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 31, 0, 99)), 80);
        let err = provider
            .materialize_bridge_bind(&spec, guest(requested), PortProtocol::Tcp)
            .expect_err("foreign address should fail");
        assert!(err.contains("address is not assigned"));
    }

    #[test]
    fn bridge_connect_to_registered_peer_rewrites_to_loopback() {
        let spec = unnamed_bridge_spec(Vec::new());
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
        let spec = unnamed_bridge_spec(Vec::new());
        let provider = SocketNamespaceProvider::new();
        let lease = provider.create_namespace(&spec).expect("namespace");
        let peer_addr = guest(SocketAddr::new(IpAddr::V4(spec.ipv4), 8080));
        let peer = VirtualEndpoint {
            scope: bridge_scope(
                spec.bridge_id.clone(),
                spec.namespace_id.as_ref(),
                peer_addr,
            ),
            addr: peer_addr,
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
        let spec = unnamed_bridge_spec(Vec::new());
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
        // A name-derived address, i.e. the shared realm: this pins reclamation
        // of the records that stay machine-visible.
        let peer_addr = guest(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(172, 31, 42, 9)),
            8080,
        ));
        let peer = VirtualEndpoint {
            scope: bridge_scope(BridgeId::new("stale-pair"), None, peer_addr),
            addr: peer_addr,
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
            .resolve_registered_connect(
                &BridgeId::new("stale-pair"),
                None,
                peer.addr,
                peer.protocol,
            )
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
        let spec = unnamed_bridge_spec(vec![mapping.clone()]);
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
        let spec = unnamed_bridge_spec(vec![mapping.clone()]);
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
        let spec = unnamed_bridge_spec(vec![mapping.clone()]);
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
        provider
            .destroy_namespace(lease.id)
            .expect("destroy namespace");
    }

    #[test]
    fn tcp_proxy_propagates_half_close_in_both_directions() {
        let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("target bind");
        let target_addr = target_listener.local_addr().expect("target addr");
        let target = thread::spawn(move || {
            let (mut stream, _) = target_listener.accept().expect("target accept");
            let mut request = Vec::new();
            stream.read_to_end(&mut request).expect("target read EOF");
            assert_eq!(request, b"ping");
            stream.write_all(b"pong").expect("target write response");
            stream
                .shutdown(std::net::Shutdown::Write)
                .expect("target half-close");
        });

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("proxy bind");
        let proxy_addr = proxy_listener.local_addr().expect("proxy addr");
        let fork_gate = Arc::new(Mutex::new(()));
        let fork_tracked_fds = Arc::new(Mutex::new(HashSet::new()));
        let proxy = thread::spawn(move || {
            let (inbound, _) = proxy_listener.accept().expect("proxy accept");
            let outbound = TcpStream::connect(target_addr).expect("proxy connect target");
            proxy_tcp_stream(
                ForkTrackedSocket::new(inbound, &fork_gate, &fork_tracked_fds),
                ForkTrackedSocket::new(outbound, &fork_gate, &fork_tracked_fds),
                BridgeHelperForkState {
                    fork_gate,
                    tracked_fds: fork_tracked_fds,
                },
            )
            .expect("proxy stream");
        });

        let mut client = TcpStream::connect(proxy_addr).expect("client connect");
        client.write_all(b"ping").expect("client write request");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("client half-close");
        let mut response = Vec::new();
        client.read_to_end(&mut response).expect("client read EOF");

        target.join().expect("target thread");
        proxy.join().expect("proxy thread");
        assert_eq!(response, b"pong");
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
        let spec = unnamed_bridge_spec(vec![mapping.clone()]);
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
        let peer_addr = guest(SocketAddr::new(IpAddr::V4(spec.ipv4), container_port));
        let peer = VirtualEndpoint {
            scope: bridge_scope(
                spec.bridge_id.clone(),
                spec.namespace_id.as_ref(),
                peer_addr,
            ),
            addr: peer_addr,
            protocol: PortProtocol::Tcp,
        };
        provider
            .write_endpoint_file(&peer, spec.namespace_id.as_ref(), host(target_addr))
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
        provider
            .destroy_namespace(lease.id)
            .expect("destroy namespace");
        // `write_endpoint_file` records ownership under the reserved lease 0, so
        // release it too and leave no endpoint file behind in the shared
        // fork-coherent directory.
        provider
            .destroy_namespace(NetworkLeaseId(0))
            .expect("release fork-coherent endpoint file");
    }

    /// A published-port relay must keep forwarding client bytes that arrive
    /// after the relay is already running. On BSD-derived hosts `accept()`
    /// inherits `O_NONBLOCK` from the (nonblocking) published listener, so the
    /// accepted descriptor must be put back into blocking mode before the
    /// blocking copy loop reads from it -- otherwise the first read races the
    /// client, returns `EAGAIN`, and the relay mistakes it for end-of-stream.
    #[test]
    fn publish_tcp_forwards_client_bytes_that_arrive_after_the_target_speaks_first() {
        let host_port = free_loopback_port();
        let container_port = 8083;
        let mapping = PortMapping {
            host_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            host_port: Some(host_port),
            container_port,
            protocol: PortProtocol::Tcp,
        };
        let spec = unnamed_bridge_spec(vec![mapping.clone()]);
        let provider = SocketNamespaceProvider::new();
        let lease = provider.create_namespace(&spec).expect("namespace");
        provider.publish_port(lease.id, mapping).expect("publish");

        let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("target bind");
        let target_addr = target_listener.local_addr().expect("target addr");
        // The target speaks first, so the client provably sends nothing until
        // the relay has already started copying in both directions.
        let server = thread::spawn(move || {
            let (mut stream, _) = target_listener.accept().expect("target accept");
            stream.write_all(b"srv").expect("write greeting");
            let mut buf = [0_u8; 4];
            stream.read_exact(&mut buf).expect("read ping");
            assert_eq!(&buf, b"ping");
            stream.write_all(b"ok").expect("write ok");
        });
        provider
            .register_virtual_endpoint(
                spec.bridge_id.clone(),
                spec.namespace_id.clone().expect("namespace id"),
                guest(SocketAddr::new(IpAddr::V4(spec.ipv4), container_port)),
                PortProtocol::Tcp,
                host(target_addr),
            )
            .expect("register");

        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, host_port)).expect("connect");
        let mut greeting = [0_u8; 3];
        client.read_exact(&mut greeting).expect("read greeting");
        assert_eq!(&greeting, b"srv");
        client.write_all(b"ping").expect("write ping");
        let mut reply = [0_u8; 2];
        client.read_exact(&mut reply).expect("read reply");
        server.join().expect("server thread");

        assert_eq!(&reply, b"ok");
        provider
            .destroy_namespace(lease.id)
            .expect("destroy namespace");
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
        let spec = unnamed_bridge_spec(vec![mapping.clone()]);
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
        let spec = unnamed_bridge_spec(vec![mapping.clone()]);
        let provider = SocketNamespaceProvider::new();
        let lease = provider.create_namespace(&spec).expect("namespace");
        provider.publish_port(lease.id, mapping).expect("publish");

        provider
            .destroy_namespace(lease.id)
            .expect("destroy namespace");

        let _socket =
            UdpSocket::bind((Ipv4Addr::LOCALHOST, host_port)).expect("published port released");
    }

    #[cfg(target_os = "freebsd")]
    #[test]
    fn fork_child_closes_published_listener_fds_for_port_release() {
        let _test_lock = FORK_SOCKET_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let tcp_port = free_loopback_port();
        let reserved_udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve udp port");
        let udp_port = reserved_udp.local_addr().expect("udp addr").port();
        drop(reserved_udp);
        let tcp_mapping = PortMapping {
            host_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            host_port: Some(tcp_port),
            container_port: 8080,
            protocol: PortProtocol::Tcp,
        };
        let udp_mapping = PortMapping {
            host_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            host_port: Some(udp_port),
            container_port: 8081,
            protocol: PortProtocol::Udp,
        };
        let spec = unnamed_bridge_spec(vec![tcp_mapping.clone(), udp_mapping.clone()]);
        let provider = SocketNamespaceProvider::new();
        let lease = provider.create_namespace(&spec).expect("namespace");
        provider
            .publish_port(lease.id, tcp_mapping)
            .expect("publish tcp");
        provider
            .publish_port(lease.id, udp_mapping)
            .expect("publish udp");
        wait_for_fork_tracked_fds(&provider, 2);

        let mut ready_pipe = [0; 2];
        assert_eq!(unsafe { libc::pipe(ready_pipe.as_mut_ptr()) }, 0);
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let fork_guard = loop {
            if let Some(guard) = provider.try_fork_guard() {
                break guard;
            }
            assert!(std::time::Instant::now() < deadline, "fork gate timed out");
            thread::yield_now();
        };
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", io::Error::last_os_error());
        if pid == 0 {
            unsafe {
                libc::close(ready_pipe[0]);
            }
            drop(fork_guard);
            provider.after_fork_child();
            let ready = [1_u8];
            let wrote = unsafe { libc::write(ready_pipe[1], ready.as_ptr().cast(), ready.len()) };
            unsafe {
                libc::close(ready_pipe[1]);
            }
            if wrote == 1 {
                thread::sleep(Duration::from_secs(2));
                unsafe { libc::_exit(0) };
            }
            unsafe { libc::_exit(122) };
        }
        drop(fork_guard);
        unsafe {
            libc::close(ready_pipe[1]);
        }
        let mut ready = [0_u8; 1];
        let read = unsafe { libc::read(ready_pipe[0], ready.as_mut_ptr().cast(), ready.len()) };
        unsafe {
            libc::close(ready_pipe[0]);
        }
        assert_eq!(read, 1, "child did not signal fork cleanup readiness");

        provider
            .destroy_namespace(lease.id)
            .expect("destroy namespace");
        let _tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, tcp_port))
            .expect("child released published TCP port");
        let _udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, udp_port))
            .expect("child released published UDP port");

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[cfg(target_os = "freebsd")]
    #[test]
    fn fork_child_closes_active_udp_transient_and_parent_reuses_proxy() {
        let _test_lock = FORK_SOCKET_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let reserved = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve host port");
        let host_port = reserved.local_addr().expect("reserved addr").port();
        drop(reserved);
        let container_port = 8083;
        let mapping = PortMapping {
            host_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            host_port: Some(host_port),
            container_port,
            protocol: PortProtocol::Udp,
        };
        let spec = unnamed_bridge_spec(vec![mapping.clone()]);
        let provider = SocketNamespaceProvider::new();
        let lease = provider.create_namespace(&spec).expect("namespace");
        provider.publish_port(lease.id, mapping).expect("publish");

        let target = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("target bind");
        let target_addr = target.local_addr().expect("target addr");
        let (first_tx, first_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let server = thread::spawn(move || {
            let mut request = [0_u8; 8];
            let (len, peer) = target
                .recv_from(&mut request)
                .expect("first target request");
            assert_eq!(&request[..len], b"one");
            first_tx.send(()).expect("report active UDP transient");
            release_rx.recv().expect("release first UDP response");
            target.send_to(b"one", peer).expect("first target response");
            let (len, peer) = target
                .recv_from(&mut request)
                .expect("second target request");
            assert_eq!(&request[..len], b"two");
            target
                .send_to(b"two", peer)
                .expect("second target response");
        });
        provider
            .register_virtual_endpoint(
                spec.bridge_id.clone(),
                spec.namespace_id.clone().expect("namespace id"),
                guest(SocketAddr::new(IpAddr::V4(spec.ipv4), container_port)),
                PortProtocol::Udp,
                host(target_addr),
            )
            .expect("register UDP target");
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("client bind");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("client timeout");
        client
            .send_to(b"one", (Ipv4Addr::LOCALHOST, host_port))
            .expect("send first published datagram");
        first_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("UDP transient became active");
        wait_for_fork_tracked_fds(&provider, 2);
        let active_fds = provider
            .fork_tracked_fds
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .copied()
            .collect::<Vec<_>>();

        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let fork_guard = loop {
            if let Some(guard) = provider.try_fork_guard() {
                break guard;
            }
            assert!(std::time::Instant::now() < deadline, "fork gate timed out");
            thread::yield_now();
        };
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", io::Error::last_os_error());
        if pid == 0 {
            drop(fork_guard);
            provider.after_fork_child();
            let all_closed = active_fds.iter().all(|fd| {
                let rc = unsafe { libc::fcntl(*fd, libc::F_GETFD) };
                rc == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF)
            });
            unsafe { libc::_exit(if all_closed { 0 } else { 123 }) };
        }
        drop(fork_guard);
        for fd in &active_fds {
            assert!(
                unsafe { libc::fcntl(*fd, libc::F_GETFD) } >= 0,
                "child close changed parent UDP fd {fd}"
            );
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);

        release_tx.send(()).expect("release first response");
        let mut response = [0_u8; 8];
        let (len, _) = client
            .recv_from(&mut response)
            .expect("first proxy response");
        assert_eq!(&response[..len], b"one");
        client
            .send_to(b"two", (Ipv4Addr::LOCALHOST, host_port))
            .expect("reuse published UDP proxy");
        let (len, _) = client
            .recv_from(&mut response)
            .expect("second proxy response");
        assert_eq!(&response[..len], b"two");
        server.join().expect("UDP target thread");
        provider
            .destroy_namespace(lease.id)
            .expect("destroy namespace");
    }

    #[cfg(target_os = "freebsd")]
    #[test]
    fn fork_child_closes_raw_published_stream_fds_without_shutdown() {
        let _test_lock = FORK_SOCKET_TEST_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let host_port = free_loopback_port();
        let container_port = 8082;
        let mapping = PortMapping {
            host_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            host_port: Some(host_port),
            container_port,
            protocol: PortProtocol::Tcp,
        };
        let spec = unnamed_bridge_spec(vec![mapping.clone()]);
        let provider = SocketNamespaceProvider::new();
        let lease = provider.create_namespace(&spec).expect("namespace");
        provider.publish_port(lease.id, mapping).expect("publish");

        let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("target bind");
        let target_addr = target_listener.local_addr().expect("target addr");
        let (accepted_tx, accepted_rx) = std::sync::mpsc::sync_channel(1);
        let (release_target_tx, release_target_rx) = std::sync::mpsc::sync_channel(1);
        let target = thread::spawn(move || {
            let (_stream, _) = target_listener.accept().expect("target accept");
            accepted_tx.send(()).expect("report target accept");
            release_target_rx.recv().expect("release target stream");
        });
        provider
            .register_virtual_endpoint(
                spec.bridge_id.clone(),
                spec.namespace_id.clone().expect("namespace id"),
                guest(SocketAddr::new(IpAddr::V4(spec.ipv4), container_port)),
                PortProtocol::Tcp,
                host(target_addr),
            )
            .expect("register target endpoint");

        let client = TcpStream::connect((Ipv4Addr::LOCALHOST, host_port)).expect("connect");
        accepted_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("target accepted proxy stream");
        wait_for_fork_tracked_fds(&provider, 5);
        let tracked_before_fork = provider
            .fork_tracked_fds
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .copied()
            .collect::<Vec<_>>();

        let mut ready_pipe = [0; 2];
        assert_eq!(unsafe { libc::pipe(ready_pipe.as_mut_ptr()) }, 0);
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let fork_guard = loop {
            if let Some(guard) = provider.try_fork_guard() {
                break guard;
            }
            assert!(std::time::Instant::now() < deadline, "fork gate timed out");
            thread::yield_now();
        };
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", io::Error::last_os_error());
        if pid == 0 {
            unsafe {
                libc::close(ready_pipe[0]);
            }
            drop(fork_guard);
            provider.after_fork_child();
            let all_closed = tracked_before_fork.iter().all(|fd| {
                let rc = unsafe { libc::fcntl(*fd, libc::F_GETFD) };
                rc == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF)
            });
            let ready = [u8::from(all_closed)];
            let wrote = unsafe { libc::write(ready_pipe[1], ready.as_ptr().cast(), ready.len()) };
            unsafe {
                libc::close(ready_pipe[1]);
            }
            if wrote == 1 {
                thread::sleep(Duration::from_secs(2));
                unsafe { libc::_exit(0) };
            }
            unsafe { libc::_exit(122) };
        }
        drop(fork_guard);
        unsafe {
            libc::close(ready_pipe[1]);
        }
        let mut ready = [0_u8; 1];
        let read = unsafe { libc::read(ready_pipe[0], ready.as_mut_ptr().cast(), ready.len()) };
        unsafe {
            libc::close(ready_pipe[0]);
        }
        assert_eq!(read, 1, "child did not signal fork cleanup readiness");
        assert_eq!(
            ready,
            [1],
            "child retained at least one raw bridge stream fd"
        );
        for fd in &tracked_before_fork {
            assert!(
                unsafe { libc::fcntl(*fd, libc::F_GETFD) } >= 0,
                "child close changed the parent's reference for raw fd {fd}"
            );
        }
        drop(client);
        release_target_tx.send(()).expect("release target stream");
        target.join().expect("target thread");

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);

        provider
            .destroy_namespace(lease.id)
            .expect("destroy namespace");
    }

    #[test]
    fn destroy_namespace_keeps_other_leases_alive() {
        let suffix = std::process::id();
        let mut first = NetworkNamespaceSpec::bridge_default(
            Some("api-one".to_string()),
            vec!["api".to_string()],
            Vec::new(),
        );
        first.bridge_id = BridgeId::new(format!("lease-one-{suffix}"));
        first.namespace_id = Some(NetworkNamespaceId::new(format!("lease-one-ns-{suffix}")));
        first.ipv4 = Ipv4Addr::new(172, 31, 80, 10);

        let host_port = free_loopback_port();
        let mapping = PortMapping {
            host_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            host_port: Some(host_port),
            container_port: 8080,
            protocol: PortProtocol::Tcp,
        };
        let mut second = NetworkNamespaceSpec::bridge_default(
            Some("api-two".to_string()),
            vec!["api".to_string()],
            vec![mapping.clone()],
        );
        second.bridge_id = BridgeId::new(format!("lease-two-{suffix}"));
        second.namespace_id = Some(NetworkNamespaceId::new(format!("lease-two-ns-{suffix}")));
        second.ipv4 = Ipv4Addr::new(172, 31, 80, 11);

        let provider = SocketNamespaceProvider::new();
        let first_lease = provider.create_namespace(&first).expect("first namespace");
        let second_lease = provider
            .create_namespace(&second)
            .expect("second namespace");
        provider
            .publish_port(second_lease.id, mapping)
            .expect("publish second namespace port");
        provider
            .record_socket_addresses(
                first.namespace_id.as_ref(),
                10,
                Some(guest(SocketAddr::new(IpAddr::V4(first.ipv4), 49152))),
                Some(host(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    free_loopback_port(),
                ))),
                None,
                PortProtocol::Tcp,
            )
            .expect("record first socket");
        let target_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("target bind");
        let target_addr = target_listener.local_addr().expect("target addr");
        let target = thread::spawn(move || {
            let (mut stream, _) = target_listener.accept().expect("target accept");
            let mut buf = [0_u8; 4];
            stream.read_exact(&mut buf).expect("read ping");
            stream.write_all(b"ok").expect("write ok");
        });
        let second_guest_addr = guest(SocketAddr::new(IpAddr::V4(second.ipv4), 8080));
        provider
            .record_socket_addresses(
                second.namespace_id.as_ref(),
                11,
                Some(second_guest_addr),
                Some(host(target_addr)),
                None,
                PortProtocol::Tcp,
            )
            .expect("record second socket");
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, host_port))
            .expect("connect second published port");
        client.write_all(b"ping").expect("write ping");
        let mut reply = [0_u8; 2];
        client.read_exact(&mut reply).expect("read reply");
        target.join().expect("target thread");
        assert_eq!(&reply, b"ok");

        provider
            .destroy_namespace(first_lease.id)
            .expect("destroy first namespace");

        assert_eq!(
            provider
                .guest_visible_local_addr(10)
                .expect("first socket state"),
            None
        );
        assert_eq!(
            provider
                .guest_visible_local_addr(11)
                .expect("second socket state"),
            Some(second_guest_addr)
        );
        assert_eq!(
            provider
                .resolve_dns_name(&second, "api")
                .expect("resolve second service"),
            vec![second.ipv4]
        );
        assert!(
            UdpSocket::bind((Ipv4Addr::LOCALHOST, host_port)).is_ok(),
            "test must use TCP conflict check"
        );
        assert!(
            TcpListener::bind((Ipv4Addr::LOCALHOST, host_port)).is_err(),
            "destroying another namespace must not release this TCP published port"
        );

        provider
            .destroy_namespace(second_lease.id)
            .expect("destroy second namespace");
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
        let spec = unnamed_bridge_spec(vec![mapping.clone()]);
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
        client_spec.namespace_id = Some(NetworkNamespaceId::new("peer-client-ns"));
        let mut server_spec =
            NetworkNamespaceSpec::bridge_default(Some("db".to_string()), Vec::new(), Vec::new());
        server_spec.bridge_id = bridge;
        server_spec.namespace_id = Some(NetworkNamespaceId::new("peer-server-ns"));

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

    #[cfg(target_os = "freebsd")]
    #[test]
    fn fork_guard_unlocks_registry_and_child_abandons_parent_publications() {
        let mut spec = NetworkNamespaceSpec::bridge_default(
            Some("fork-net".to_string()),
            Vec::new(),
            Vec::new(),
        );
        let namespace_id = NetworkNamespaceId::new(format!("fork-net-{}", std::process::id()));
        spec.namespace_id = Some(namespace_id.clone());
        spec.bridge_id = BridgeId::new(format!("fork-bridge-{}", std::process::id()));
        let provider = SocketNamespaceProvider::new();
        let lease = provider.create_namespace(&spec).expect("create namespace");
        let guest_addr = guest(SocketAddr::new(IpAddr::V4(spec.ipv4), 41000));
        let host_addr = host(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41001));
        provider
            .register_virtual_endpoint(
                spec.bridge_id.clone(),
                namespace_id,
                guest_addr,
                PortProtocol::Tcp,
                host_addr,
            )
            .expect("register durable endpoint");
        let endpoint = VirtualEndpoint {
            scope: bridge_scope(
                spec.bridge_id.clone(),
                spec.namespace_id.as_ref(),
                guest_addr,
            ),
            addr: guest_addr,
            protocol: PortProtocol::Tcp,
        };
        let durable_path = endpoint_path(&provider.endpoint_dir, &endpoint);
        assert!(durable_path.exists());

        // Exercise the exact helper order gate->registry, then retain that
        // thread's JoinHandle in the publication collection across the real
        // fork. The child hook must forget rather than join this vanished
        // pthread, while the parent later retains normal stop/join ownership.
        let helper_gate = Arc::clone(&provider.fork_gate);
        let helper_registry = Arc::clone(&provider.registry);
        let (locked_tx, locked_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let (finish_tx, finish_rx) = std::sync::mpsc::sync_channel(1);
        let handle = thread::spawn(move || {
            {
                let _gate = helper_gate.lock().unwrap_or_else(|p| p.into_inner());
                let _registry = helper_registry.lock().unwrap_or_else(|p| p.into_inner());
                locked_tx.send(()).expect("report helper critical section");
                release_rx.recv().expect("release helper critical section");
            }
            finish_rx.recv().expect("finish parent publication helper");
        });
        let _tracked_listener = ForkTrackedSocket::new(
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("tracked listener"),
            &provider.fork_gate,
            &provider.fork_tracked_fds,
        );
        provider
            .published_tcp
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(lease.id)
            .or_default()
            .push(PublishedTcpProxy {
                stop: Arc::new(AtomicBool::new(false)),
                handle: Some(handle),
                owner: std::process::id(),
            });
        locked_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("helper holds gate and registry");
        assert!(
            provider.try_fork_guard().is_none(),
            "fork guard must not pass a helper in the registry"
        );
        release_tx.send(()).expect("release helper registry access");
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let fork_guard = loop {
            if let Some(guard) = provider.try_fork_guard() {
                break guard;
            }
            assert!(std::time::Instant::now() < deadline, "fork gate timed out");
            thread::yield_now();
        };

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", io::Error::last_os_error());
        if pid == 0 {
            drop(fork_guard);
            provider.after_fork_child();
            let accessible = provider
                .translate_host_source(host_addr, PortProtocol::Tcp)
                .ok()
                .flatten()
                == Some(guest_addr);
            let child_helpers_empty = provider
                .published_tcp
                .lock()
                .map(|published| published.is_empty())
                .unwrap_or(false);
            let child_owns_no_files = provider
                .owned_endpoint_files
                .lock()
                .map(|owned| owned.is_empty())
                .unwrap_or(false);
            let _ = provider.destroy_namespace(lease.id);
            let durable_preserved = durable_path.exists();
            unsafe {
                libc::_exit(
                    if accessible && child_helpers_empty && child_owns_no_files && durable_preserved
                    {
                        0
                    } else {
                        121
                    },
                );
            }
        }
        drop(fork_guard);

        let wait_deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut status = 0;
        loop {
            let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if waited == pid {
                break;
            }
            assert_eq!(waited, 0, "waitpid failed: {}", io::Error::last_os_error());
            if std::time::Instant::now() >= wait_deadline {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    libc::waitpid(pid, &mut status, 0);
                }
                panic!("fork child joined a vanished publication helper");
            }
            thread::sleep(Duration::from_millis(1));
        }
        finish_tx
            .send(())
            .expect("finish parent publication helper");
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        assert!(durable_path.exists(), "child removed parent endpoint file");
        provider
            .destroy_namespace(lease.id)
            .expect("parent destroys namespace");
        assert!(
            !durable_path.exists(),
            "parent retained owned endpoint file"
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
        client_spec.namespace_id = Some(NetworkNamespaceId::new("attachment-client-ns"));
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
        server_spec.namespace_id = Some(NetworkNamespaceId::new("attachment-server-ns"));
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

    // ---------------------------------------------------------------------
    // Published-port cross-wiring: an unnamed container on the default bridge
    // gave every component of the endpoint key a constant value, so two
    // concurrent instances read and wrote the same record.
    // ---------------------------------------------------------------------

    /// A namespace root two providers -- standing in for two instances -- share,
    /// the way every real run shares the machine-global one.
    fn shared_instance_root(label: &str) -> PathBuf {
        let root = shared_endpoint_dir().join(format!("shared-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("shared root");
        root
    }

    /// Two ports that are provably distinct: both listeners are held at once, so
    /// the kernel cannot hand out the same number twice.
    fn two_free_loopback_ports() -> (u16, u16) {
        let first = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve first port");
        let second = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("reserve second port");
        (
            first.local_addr().expect("first addr").port(),
            second.local_addr().expect("second addr").port(),
        )
    }

    fn bridge_endpoint(
        spec: &NetworkNamespaceSpec,
        port: u16,
        protocol: PortProtocol,
    ) -> VirtualEndpoint {
        let addr = guest(SocketAddr::new(IpAddr::V4(spec.ipv4), port));
        VirtualEndpoint {
            scope: bridge_scope(spec.bridge_id.clone(), spec.namespace_id.as_ref(), addr),
            addr,
            protocol,
        }
    }

    fn unnamed_instance_spec(namespace_id: &str) -> NetworkNamespaceSpec {
        let mut spec = NetworkNamespaceSpec::bridge_default(None, Vec::new(), Vec::new());
        spec.namespace_id = Some(NetworkNamespaceId::new(namespace_id));
        spec
    }

    /// Two instances that both got the unnamed placeholder address must not
    /// share its endpoint record. Every component of that key -- bridge
    /// `carrick0`, address `172.31.0.2` -- is a constant, so the namespace id is
    /// the only thing that can separate them, and it separates them in the path
    /// rather than only in the in-process registry (which a fork child's
    /// copy-on-write copy makes useless for this).
    #[test]
    fn unnamed_bridge_endpoints_are_private_per_instance() {
        let root = shared_instance_root("private-realm");
        let spec_a = unnamed_instance_spec("anon-instance-a");
        let spec_b = unnamed_instance_spec("anon-instance-b");
        assert_eq!(
            spec_a.ipv4, spec_b.ipv4,
            "the precondition: two unnamed containers really are handed one address"
        );
        assert_eq!(spec_a.bridge_id, spec_b.bridge_id);

        let instance_a = SocketNamespaceProvider::with_endpoint_root(&root);
        let instance_b = SocketNamespaceProvider::with_endpoint_root(&root);
        let lease_a = instance_a.create_namespace(&spec_a).expect("namespace a");
        instance_b.create_namespace(&spec_b).expect("namespace b");

        let host_a = host(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41001));
        let host_b = host(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 41002));
        let endpoint_a = bridge_endpoint(&spec_a, 8080, PortProtocol::Tcp);
        let endpoint_b = bridge_endpoint(&spec_b, 8080, PortProtocol::Tcp);
        assert_eq!(endpoint_a.addr, endpoint_b.addr);
        instance_a
            .register_virtual_endpoint(
                spec_a.bridge_id.clone(),
                spec_a.namespace_id.clone().expect("namespace id a"),
                endpoint_a.addr,
                PortProtocol::Tcp,
                host_a,
            )
            .expect("register a");
        instance_b
            .register_virtual_endpoint(
                spec_b.bridge_id.clone(),
                spec_b.namespace_id.clone().expect("namespace id b"),
                endpoint_b.addr,
                PortProtocol::Tcp,
                host_b,
            )
            .expect("register b");

        let path_a = endpoint_path(&root, &endpoint_a);
        let path_b = endpoint_path(&root, &endpoint_b);
        assert_ne!(path_a, path_b, "one key for two instances is the defect");
        assert!(path_a.exists() && path_b.exists());
        assert_eq!(
            path_a.parent().expect("realm dir a"),
            root.join(format!(
                "{PRIVATE_REALM_PREFIX}{}",
                hex_name("anon-instance-a")
            ))
        );

        // Resolve from a third provider whose registry is empty, so the answer
        // can only have come from the files -- the same position a published
        // relay is in when the guest listener was bound by a fork child.
        let reader = SocketNamespaceProvider::with_endpoint_root(&root);
        assert_eq!(
            reader
                .resolve_registered_connect(
                    &spec_a.bridge_id,
                    spec_a.namespace_id.as_ref(),
                    endpoint_a.addr,
                    PortProtocol::Tcp,
                )
                .expect("resolve a"),
            Some(host_a)
        );
        assert_eq!(
            reader
                .resolve_registered_connect(
                    &spec_b.bridge_id,
                    spec_b.namespace_id.as_ref(),
                    endpoint_b.addr,
                    PortProtocol::Tcp,
                )
                .expect("resolve b"),
            Some(host_b)
        );

        // A's teardown must not take B's publication with it. Before realms, A's
        // record had already been overwritten by B, so A silently skipped its own
        // cleanup and leaked instead.
        instance_a
            .destroy_namespace(lease_a.id)
            .expect("destroy namespace a");
        assert!(!path_a.exists(), "A must remove its own record");
        assert!(path_b.exists(), "A must not remove B's record");
        let _ = fs::remove_dir_all(&root);
    }

    /// The regression test for the cross-wire itself, in the shape it ships in:
    /// two separate **processes**, each publishing a port for an unnamed
    /// container, sharing one endpoint namespace.
    ///
    /// Every ordering edge is a blocking pipe read or a `waitpid`; nothing
    /// sleeps and nothing retries. Each child publishes its port, records its
    /// container listener, writes one ready byte and blocks. The parent reads
    /// **both** ready bytes before connecting to anything, so both records are
    /// on disk first -- which is what makes the pre-fix failure certain rather
    /// than a race: with one shared key, whichever child wrote last owns it, and
    /// the other child's relay necessarily proxies to the wrong container.
    ///
    /// Each child publishes its container listener with `write_endpoint_file`
    /// rather than `register_virtual_endpoint`, and asserts its own registry
    /// does not hold the key. That is the real shape: the guest listener is
    /// bound by a *forked descendant*, whose registry insert landed in its own
    /// copy-on-write copy, so the relay has nothing in memory and the durable
    /// record is the only channel.
    #[test]
    fn published_relays_of_two_instances_do_not_cross_wire() {
        // Mint this process's instance id before forking, so both children
        // inherit the same one. That is deliberate: it holds the identity check
        // constant so this test can only pass because the *key* separates the
        // two instances, not because their process identities differ.
        let _ = instance_id();
        let root = shared_instance_root("crosswire");
        let (port_a, port_b) = two_free_loopback_ports();
        let instances = [(port_a, *b"AAAA"), (port_b, *b"BBBB")];

        let mut release = [0i32; 2];
        assert_eq!(
            unsafe { libc::pipe(release.as_mut_ptr()) },
            0,
            "release pipe: {}",
            io::Error::last_os_error()
        );
        let (release_read, release_write) = (release[0], release[1]);

        let mut children = Vec::new();
        for (host_port, token) in instances {
            let mut ready = [0i32; 2];
            assert_eq!(
                unsafe { libc::pipe(ready.as_mut_ptr()) },
                0,
                "ready pipe: {}",
                io::Error::last_os_error()
            );
            let (ready_read, ready_write) = (ready[0], ready[1]);
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
            if pid == 0 {
                unsafe {
                    libc::close(ready_read);
                    // The child must not hold the release pipe's write end or
                    // the parent closing its own copy would never be an EOF.
                    libc::close(release_write);
                }
                let code =
                    run_crosswire_instance(&root, host_port, token, ready_write, release_read);
                unsafe { libc::_exit(code) };
            }
            unsafe { libc::close(ready_write) };
            children.push((pid, ready_read));
        }
        unsafe { libc::close(release_read) };

        // Happens-after: both listeners are bound and both records are written.
        for (_, ready_read) in &children {
            let mut byte = 0u8;
            assert_eq!(
                unsafe { libc::read(*ready_read, (&raw mut byte).cast(), 1) },
                1,
                "child never reported ready: {}",
                io::Error::last_os_error()
            );
        }

        let mut served = Vec::new();
        for (host_port, _) in instances {
            let mut client =
                TcpStream::connect((Ipv4Addr::LOCALHOST, host_port)).expect("connect published");
            let mut reply = [0_u8; 4];
            client
                .read_exact(&mut reply)
                .unwrap_or_else(|e| panic!("published port {host_port} served nothing: {e}"));
            served.push(reply);
        }

        unsafe { libc::close(release_write) };
        for (pid, ready_read) in children {
            unsafe { libc::close(ready_read) };
            let mut status = 0i32;
            assert_eq!(
                unsafe { libc::waitpid(pid, &raw mut status, 0) },
                pid,
                "waitpid: {}",
                io::Error::last_os_error()
            );
            assert!(libc::WIFEXITED(status), "instance did not exit normally");
            assert_eq!(
                libc::WEXITSTATUS(status),
                0,
                "instance failed to set itself up (bitmask)"
            );
        }
        let _ = fs::remove_dir_all(&root);

        for (index, (_, token)) in instances.iter().enumerate() {
            assert_eq!(
                &served[index],
                token,
                "published port {} was proxied into the wrong container: served {:?}, expected {:?}",
                instances[index].0,
                String::from_utf8_lossy(&served[index]),
                String::from_utf8_lossy(token)
            );
        }
    }

    /// One instance of the cross-wire harness, running in its own process.
    /// Returns a bitmask so a failure is reported through `waitpid` rather than
    /// by unwinding a panic through a forked child.
    fn run_crosswire_instance(
        root: &Path,
        host_port: u16,
        token: [u8; 4],
        ready_fd: RawFd,
        release_fd: RawFd,
    ) -> i32 {
        let mut code = 0;
        let mapping = PortMapping {
            host_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            host_port: Some(host_port),
            container_port: 8080,
            protocol: PortProtocol::Tcp,
        };
        let mut spec =
            NetworkNamespaceSpec::bridge_default(None, Vec::new(), vec![mapping.clone()]);
        spec.namespace_id = Some(NetworkNamespaceId::anonymous(std::process::id()));
        let provider = SocketNamespaceProvider::with_endpoint_root(root);
        let Ok(lease) = provider.create_namespace(&spec) else {
            return 1;
        };
        if provider.publish_port(lease.id, mapping).is_err() {
            code |= 2;
        }

        let Ok(target_listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)) else {
            return code | 4;
        };
        let Ok(target_addr) = target_listener.local_addr() else {
            return code | 8;
        };
        thread::spawn(move || {
            while let Ok((mut stream, _)) = target_listener.accept() {
                let _ = stream.write_all(&token);
            }
        });

        let endpoint = bridge_endpoint(&spec, 8080, PortProtocol::Tcp);
        if provider
            .write_endpoint_file(&endpoint, spec.namespace_id.as_ref(), host(target_addr))
            .is_err()
        {
            code |= 16;
        }
        if provider
            .registry
            .lock()
            .map(|registry| registry.contains_key(&endpoint))
            .unwrap_or(true)
        {
            // Without this the relay would answer from its own memory and the
            // durable record -- the thing that aliases -- would never be read.
            code |= 32;
        }

        if unsafe { libc::write(ready_fd, [1u8].as_ptr().cast(), 1) } != 1 {
            code |= 64;
        }
        let mut byte = 0u8;
        let _ = unsafe { libc::read(release_fd, (&raw mut byte).cast(), 1) };
        code
    }

    /// The shipped feature realm-qualification must not touch: two separate
    /// `carrick run --name db` / `--name web` processes reaching each other on
    /// the **default** bridge. That is what `conformance_bridge_compose_pair`
    /// exercises end to end, and a scheme that made every instance private would
    /// delete it.
    #[test]
    fn named_bridge_endpoints_stay_shared_across_instances() {
        let root = shared_instance_root("named-shared");
        let mut db = NetworkNamespaceSpec::bridge_default(Some("db".to_string()), vec![], vec![]);
        db.namespace_id = Some(NetworkNamespaceId::new("named-db-ns"));
        let mut web = NetworkNamespaceSpec::bridge_default(Some("web".to_string()), vec![], vec![]);
        web.namespace_id = Some(NetworkNamespaceId::new("named-web-ns"));
        assert_eq!(
            db.bridge_id,
            BridgeId::default_bridge(),
            "the compose pair runs on the default bridge, not a user-declared one"
        );
        assert_ne!(db.ipv4, web.ipv4);

        let db_instance = SocketNamespaceProvider::with_endpoint_root(&root);
        let web_instance = SocketNamespaceProvider::with_endpoint_root(&root);
        db_instance.create_namespace(&db).expect("db namespace");
        web_instance.create_namespace(&web).expect("web namespace");

        let db_endpoint = bridge_endpoint(&db, 5432, PortProtocol::Tcp);
        let db_host = host(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 45432));
        db_instance
            .register_virtual_endpoint(
                db.bridge_id.clone(),
                db.namespace_id.clone().expect("db namespace id"),
                db_endpoint.addr,
                PortProtocol::Tcp,
                db_host,
            )
            .expect("register db endpoint");

        // Byte-identical to the pre-realm layout: at the root, no realm
        // component. Nothing about a named container's storage moved.
        let db_path = endpoint_path(&root, &db_endpoint);
        assert_eq!(db_path.parent().expect("db record parent"), root);
        assert_eq!(
            db_path.file_name().expect("db record name"),
            std::ffi::OsStr::new(&format!(
                "bridge-{}-{}-5432-tcp",
                hex_name(BridgeId::default_bridge().as_str()),
                db.ipv4
            ))
        );

        // A different instance resolves it: address, DNS name and the reverse
        // translation every accept/recvfrom does.
        assert_eq!(
            web_instance
                .resolve_bridge_connect(&web, db_endpoint.addr, PortProtocol::Tcp)
                .expect("web resolves db"),
            ConnectTarget::Host(db_host)
        );
        assert_eq!(
            web_instance
                .resolve_service_name(&web, "db")
                .expect("web resolves the db name"),
            vec![db.ipv4]
        );
        assert_eq!(
            web_instance
                .translate_host_source(db_host, PortProtocol::Tcp)
                .expect("web translates db's host source"),
            Some(db_endpoint.addr)
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// The second aliasing channel: loopback endpoints are scoped by namespace
    /// id alone, and `bridge_default` used to hand every instance the constant
    /// `"default"`, so one guest's `127.0.0.1:9000` was resolvable -- and
    /// connectable -- from a concurrent instance's guest.
    #[test]
    fn loopback_endpoints_are_private_to_their_instance() {
        let root = shared_instance_root("loopback");
        let spec_a = unnamed_instance_spec("loopback-a");
        let spec_b = unnamed_instance_spec("loopback-b");

        let instance_a = SocketNamespaceProvider::with_endpoint_root(&root);
        instance_a.create_namespace(&spec_a).expect("namespace a");
        let loopback = guest(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000));
        let host_a = host(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 49001));
        instance_a
            .register_virtual_endpoint(
                spec_a.bridge_id.clone(),
                spec_a.namespace_id.clone().expect("namespace id a"),
                loopback,
                PortProtocol::Tcp,
                host_a,
            )
            .expect("register loopback a");

        // A fresh process-shaped reader, so the answer comes from the files.
        let reader = SocketNamespaceProvider::with_endpoint_root(&root);
        reader.create_namespace(&spec_a).expect("reader knows a");
        reader.create_namespace(&spec_b).expect("reader knows b");
        assert_eq!(
            reader
                .resolve_bridge_connect(&spec_a, loopback, PortProtocol::Tcp)
                .expect("a resolves its own loopback"),
            ConnectTarget::Host(host_a)
        );
        assert_eq!(
            reader
                .resolve_bridge_connect(&spec_b, loopback, PortProtocol::Tcp)
                .expect("b must not reach a's loopback"),
            ConnectTarget::Denied(carrick_abi::LINUX_ECONNREFUSED)
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// Fork-coherence for the realm-qualified key. The realm is derived from
    /// `namespace_id`, which lives in spec memory `fork()` copies, so a child
    /// must compute the identical path with no communication -- both for a
    /// record its parent published *before* the fork and for one published
    /// *after* it, which the child's copy-on-write registry can never explain.
    #[test]
    fn forked_child_resolves_private_realm_endpoints_across_the_fork() {
        let mut spec = unnamed_bridge_spec(Vec::new());
        spec.namespace_id = Some(NetworkNamespaceId::new(format!(
            "fork-realm-{}",
            std::process::id()
        )));
        spec.bridge_id = BridgeId::new(format!("fork-realm-bridge-{}", std::process::id()));
        assert!(carrick_spec::is_bridge_placeholder_ipv4(spec.ipv4));

        let provider = SocketNamespaceProvider::new();
        let lease = provider.create_namespace(&spec).expect("namespace");
        let prefork = bridge_endpoint(&spec, 7001, PortProtocol::Tcp);
        let prefork_host = host(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 47001));
        // Published without touching the registry, so the child's hit can only
        // come from the file at the realm-qualified path.
        provider
            .write_endpoint_file(&prefork, spec.namespace_id.as_ref(), prefork_host)
            .expect("pre-fork endpoint");
        let postfork = bridge_endpoint(&spec, 7002, PortProtocol::Tcp);
        let postfork_host = host(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 47002));
        let realm_dir = provider.endpoint_dir.join(format!(
            "{PRIVATE_REALM_PREFIX}{}",
            hex_name(spec.namespace_id.as_ref().expect("namespace id").as_str())
        ));

        let mut fds = [0i32; 2];
        assert_eq!(
            unsafe { libc::pipe(fds.as_mut_ptr()) },
            0,
            "pipe: {}",
            io::Error::last_os_error()
        );
        let (read_fd, write_fd) = (fds[0], fds[1]);

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", io::Error::last_os_error());
        if pid == 0 {
            unsafe { libc::close(write_fd) };
            let mut byte = 0u8;
            let mut code = 0;
            if unsafe { libc::read(read_fd, (&raw mut byte).cast(), 1) } != 1 {
                code |= 1;
            }
            if provider
                .resolve_bridge_connect(&spec, prefork.addr, PortProtocol::Tcp)
                .ok()
                != Some(ConnectTarget::Host(prefork_host))
            {
                code |= 2;
            }
            if provider
                .resolve_bridge_connect(&spec, postfork.addr, PortProtocol::Tcp)
                .ok()
                != Some(ConnectTarget::Host(postfork_host))
            {
                code |= 4;
            }
            if endpoint_path(&provider.endpoint_dir, &postfork).parent()
                != Some(realm_dir.as_path())
            {
                code |= 8;
            }
            unsafe { libc::_exit(code) };
        }

        unsafe { libc::close(read_fd) };
        provider
            .register_virtual_endpoint(
                spec.bridge_id.clone(),
                spec.namespace_id.clone().expect("namespace id"),
                postfork.addr,
                PortProtocol::Tcp,
                postfork_host,
            )
            .expect("post-fork endpoint");
        assert_eq!(
            unsafe { libc::write(write_fd, [1u8].as_ptr().cast(), 1) },
            1,
            "signal child: {}",
            io::Error::last_os_error()
        );
        unsafe { libc::close(write_fd) };

        let mut status = 0i32;
        assert_eq!(
            unsafe { libc::waitpid(pid, &raw mut status, 0) },
            pid,
            "waitpid: {}",
            io::Error::last_os_error()
        );
        assert!(libc::WIFEXITED(status), "child did not exit normally");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "forked child lost its parent's private-realm records (bitmask)"
        );
        provider.destroy_namespace(lease.id).expect("destroy");
        provider
            .destroy_namespace(NetworkLeaseId(0))
            .expect("release the registry-free publication");
    }

    /// A private realm is `anon-<pid>`, so one liveness check settles every
    /// record inside it -- reaching the `bridge-`/`listen-` families that
    /// nothing ever enumerates by name and that the per-file rule therefore
    /// could never visit.
    #[test]
    fn a_dead_instances_private_realm_is_reclaimed_whole() {
        let root = reclaim_fixture_root("realm");
        let self_pid = std::process::id() as i32;
        // `process_is_alive` reports pid <= 0 as gone, so "dead" is decidable
        // here rather than a race against a real exit.
        let dead = root.join(format!("{PRIVATE_REALM_PREFIX}{}", hex_name("anon-0")));
        let live = root.join(format!(
            "{PRIVATE_REALM_PREFIX}{}",
            hex_name(&format!("anon-{self_pid}"))
        ));
        let named = root.join(format!("{PRIVATE_REALM_PREFIX}{}", hex_name("explicit-ns")));

        let dead_endpoint = dead.join("bridge-6465616431-172.31.0.2-8080-tcp");
        let dead_listener = dead.join("listen-bridge-6465616431-172.31.0.2-8080-tcp");
        let live_endpoint = live.join("bridge-6c69766531-172.31.0.2-8080-tcp");
        let named_dead = named.join("bridge-6e616d6564-172.31.0.2-8080-tcp");
        write_fixture_record(&dead_endpoint, 0);
        write_fixture_record(&dead_listener, 0);
        write_fixture_record(&live_endpoint, self_pid);
        write_fixture_record(&named_dead, 0);

        assert!(reclaim_stale_endpoint_records(&root, ENDPOINT_RECLAIM_BUDGET) > 0);

        assert!(
            !dead.exists(),
            "a dead instance's realm is decidable as a unit"
        );
        assert!(live_endpoint.exists(), "a live instance keeps its records");
        assert!(
            !named_dead.exists(),
            "a realm whose id is not pid-derived still gets per-file reclamation"
        );
        assert!(!named.exists(), "and its emptied directory is removed");
        let _ = fs::remove_dir_all(&root);
    }

    /// Publishing over a live record must never expose an empty one.
    /// `fs::write` is `O_TRUNC` + `write`: a reader landing between the two
    /// finds no `pid=` line, concludes the endpoint does not exist, and drops a
    /// connection that should have been forwarded. `rename` has no such window,
    /// and the inode changing is the observable proof that the new record was
    /// built elsewhere and moved into place rather than written over the live
    /// one.
    #[test]
    fn a_republished_record_replaces_its_predecessor_atomically() {
        use std::os::unix::fs::MetadataExt;

        let root = reclaim_fixture_root("atomic");
        let path = root.join("bridge-61746f6d69-172.31.9.9-8080-tcp");
        let first = "127.0.0.1:1\npid=1\n";
        let second = "127.0.0.1:2\npid=2\n";

        write_record(&root, &path, first).expect("first publication");
        let first_ino = fs::metadata(&path).expect("first metadata").ino();
        write_record(&root, &path, second).expect("republication");

        assert_ne!(
            first_ino,
            fs::metadata(&path).expect("second metadata").ino(),
            "a republish must rename a complete record into place, not truncate the live one"
        );
        assert_eq!(fs::read_to_string(&path).expect("record"), second);
        let entries: Vec<_> = fs::read_dir(&root)
            .expect("read root")
            .flatten()
            .map(|entry| entry.file_name())
            .collect();
        assert_eq!(entries.len(), 1, "temp files must not survive: {entries:?}");
        let _ = fs::remove_dir_all(&root);
    }

    /// A record states which key it believes it answers. A reader that computed
    /// a path from a tuple and found a record claiming a *different* tuple has
    /// caught a real disagreement -- a path-scheme bug, a build-skew record, a
    /// half-migrated directory -- and must refuse it rather than serve it.
    /// A record with no claim at all is not a disagreement, so it still answers.
    #[test]
    fn a_record_claiming_a_different_key_is_refused() {
        let provider = SocketNamespaceProvider::new();
        let bridge = BridgeId::new(format!("key-check-{}", std::process::id()));
        let addr = guest(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(172, 31, 55, 7)),
            8080,
        ));
        let endpoint = VirtualEndpoint {
            scope: bridge_scope(bridge.clone(), None, addr),
            addr,
            protocol: PortProtocol::Tcp,
        };
        let path = endpoint_path(&provider.endpoint_dir, &endpoint);
        let dir = endpoint_scope_dir(&provider.endpoint_dir, &endpoint.scope);
        let host_addr = host(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 45507));
        let resolve = || {
            provider
                .resolve_registered_connect(&bridge, None, addr, PortProtocol::Tcp)
                .expect("resolve")
        };

        write_record(
            &dir,
            &path,
            &encode_endpoint_record(&provider.endpoint_dir, &path, host_addr.0, None),
        )
        .expect("honest record");
        assert_eq!(resolve(), Some(host_addr));

        let liar = format!(
            "{}\npid={}\ninstance={:032x}\nkey=bridge-6465616462656566-172.31.55.7-8080-tcp\n",
            host_addr.0,
            std::process::id(),
            instance_id()
        );
        write_record(&dir, &path, &liar).expect("mismatched record");
        assert_eq!(resolve(), None, "a record must not answer for another key");

        write_record(
            &dir,
            &path,
            &format!("{}\npid={}\n", host_addr.0, std::process::id()),
        )
        .expect("claimless record");
        assert_eq!(
            resolve(),
            Some(host_addr),
            "a record that makes no claim is placed by its path alone"
        );
        let _ = fs::remove_file(&path);
    }

    struct RelayOutcome {
        served: Vec<u8>,
        dialed: bool,
    }

    /// Drive one published-port relay against a container record seeded with a
    /// chosen identity, and report what it did.
    ///
    /// The seeded container listener answers with a token the moment it is
    /// dialed, so "refused" and "proxied" differ by the bytes the client
    /// receives -- an observable, not a timeout. Whichever way the check breaks,
    /// the test fails with the evidence in hand instead of hanging on a listener
    /// nobody accepts. The record always carries a live owner pid and the
    /// correct `key=`, so the identity fields are the only thing that can decide
    /// the outcome.
    fn drive_relay_with_seeded_record(
        container_port: u16,
        record_namespace: Option<&NetworkNamespaceId>,
        record_instance: u128,
    ) -> RelayOutcome {
        let host_port = free_loopback_port();
        let mapping = PortMapping {
            host_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            host_port: Some(host_port),
            container_port,
            protocol: PortProtocol::Tcp,
        };
        let spec = unnamed_bridge_spec(vec![mapping.clone()]);
        let provider = SocketNamespaceProvider::new();
        let lease = provider.create_namespace(&spec).expect("namespace");
        provider.publish_port(lease.id, mapping).expect("publish");

        let container_listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("container bind");
        let container_addr = container_listener.local_addr().expect("container addr");
        let dialed = Arc::new(AtomicBool::new(false));
        let thread_dialed = Arc::clone(&dialed);
        let acceptor = thread::spawn(move || {
            if let Ok((mut stream, _)) = container_listener.accept() {
                thread_dialed.store(true, Ordering::SeqCst);
                let _ = stream.write_all(b"SERVED");
            }
        });

        let endpoint = bridge_endpoint(&spec, container_port, PortProtocol::Tcp);
        let path = endpoint_path(&provider.endpoint_dir, &endpoint);
        let dir = endpoint_scope_dir(&provider.endpoint_dir, &endpoint.scope);
        let record = format!(
            "{container_addr}\npid={}\ninstance={record_instance:032x}\n{}key={}\n",
            std::process::id(),
            record_namespace_field(record_namespace),
            record_key(&provider.endpoint_dir, &path)
        );
        write_record(&dir, &path, &record).expect("seed record");

        let mut client =
            TcpStream::connect((Ipv4Addr::LOCALHOST, host_port)).expect("connect published");
        let mut served = Vec::new();
        client.read_to_end(&mut served).expect("read to end");
        // The client observing end-of-stream happens strictly after the relay
        // decided what to do with the record, so any dial it would have made has
        // already been accepted by now.
        let outcome = RelayOutcome {
            served,
            dialed: dialed.load(Ordering::SeqCst),
        };

        // Release a still-waiting acceptor so the test owns no blocked thread.
        // If the relay already dialed, the acceptor has returned and closed its
        // listener, so a refused connect here is that case, not a failure.
        let _ = TcpStream::connect(container_addr);
        acceptor.join().expect("acceptor thread");
        let _ = fs::remove_file(&path);
        provider.destroy_namespace(lease.id).expect("destroy");
        outcome
    }

    /// A record published for a *different* namespace describes a different
    /// container's listener, so the relay refuses it. This is the cross-instance
    /// case that survives realm-qualification: two runs whose records can land
    /// on one path, e.g. because they were given the same `--name` and so the
    /// same name-derived address.
    #[test]
    fn published_relay_refuses_a_record_from_another_namespace() {
        let outcome = drive_relay_with_seeded_record(
            8099,
            Some(&NetworkNamespaceId::new("some-other-container")),
            instance_id() ^ 1,
        );
        assert!(
            outcome.served.is_empty(),
            "relay proxied into another namespace's container: {:?}",
            String::from_utf8_lossy(&outcome.served)
        );
        assert!(!outcome.dialed, "relay dialed another namespace's listener");
    }

    /// The `carrick exec` shape, and the reason the check is scoped to the
    /// namespace rather than to the process: a *separate process*, with its own
    /// instance identity, publishing the container listener for the namespace it
    /// was handed. `carrick exec` gets the run's `network_namespace_id`
    /// (`carrick-cli/src/lifecycle.rs:1187` matches `:389`), so a port published
    /// by `carrick run -p 8080:80` must still be served when the listener is
    /// bound by an `exec`ed command rather than the container's entrypoint --
    /// Docker forwards to whatever is listening in the container, whichever
    /// process bound it.
    #[test]
    fn published_relay_serves_an_exec_shaped_record_from_its_own_namespace() {
        let outcome = drive_relay_with_seeded_record(
            8100,
            Some(&this_instance_namespace()),
            // A different instance identity: exec is not a fork child, so it
            // mints its own. Admission must not look at this.
            instance_id() ^ 1,
        );
        assert_eq!(
            outcome.served.as_slice(),
            b"SERVED",
            "relay refused its own container's listener because a sibling process published it"
        );
        assert!(outcome.dialed);
    }

    /// A record with no `ns=` makes no claim -- it predates the field -- so it
    /// is placed by its path alone, the same rule `key=` uses.
    #[test]
    fn published_relay_serves_a_record_that_claims_no_namespace() {
        let outcome = drive_relay_with_seeded_record(8101, None, instance_id());
        assert_eq!(outcome.served.as_slice(), b"SERVED");
        assert!(outcome.dialed);
    }

    /// Reclamation unlinks a record because an earlier read showed its owner
    /// gone. Between that read and the unlink the owner's successor can rename a
    /// live record into the same path, and unlinking *that* destroys a live
    /// publication the owner will never rewrite. The unlink is therefore
    /// conditional on the bytes the verdict was reached from.
    #[test]
    fn a_condemned_record_is_only_unlinked_while_it_still_holds_the_condemned_bytes() {
        let root = reclaim_fixture_root("guarded-unlink");
        let path = root.join("bridge-6775617264-172.31.9.9-8080-tcp");
        let condemned = "127.0.0.1:1\npid=0\n";

        fs::write(&path, condemned).expect("seed condemned record");
        assert!(remove_record_if_unchanged(&path, condemned));
        assert!(!path.exists(), "a still-condemned record is reclaimed");

        fs::write(&path, "127.0.0.1:2\npid=1\n").expect("successor record");
        assert!(!remove_record_if_unchanged(&path, condemned));
        assert!(
            path.exists(),
            "a successor's live record must survive the predecessor's reclamation"
        );
        let _ = fs::remove_dir_all(&root);
    }
}
