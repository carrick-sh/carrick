use carrick_abi::LinuxErrno;
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
    Denied(LinuxErrno),
}

/// Provider-owned exclusion held across a host `fork()`. Host/none providers
/// return a no-op guard; bridge providers pin auxiliary publication helpers
/// outside their registry critical section so the child never inherits it
/// locked by a vanished helper thread.
pub struct NetworkForkGuard<'a> {
    _guard: Option<std::sync::MutexGuard<'a, ()>>,
}

impl NetworkForkGuard<'_> {
    fn no_op() -> Self {
        Self { _guard: None }
    }

    pub(super) fn real(guard: std::sync::MutexGuard<'_, ()>) -> NetworkForkGuard<'_> {
        NetworkForkGuard {
            _guard: Some(guard),
        }
    }
}

/// Identifies ONE socket in the address registry.
///
/// It is the **host** fd, deliberately, and it is a newtype so the domain
/// cannot be confused again. The registry used to be keyed by the guest fd
/// NUMBER, which is wrong in three independent ways: a guest fd number is
/// meaningful only inside one Linux process (and under HVPatch every process
/// shares this one registry), `dup`/`dup2` give one socket several numbers, and
/// — decisively — nothing purged an entry on `close`, so a number handed back
/// out by the kernel inherited the dead socket's address.
///
/// glibc's `rfc3484_sort` does exactly that: it closes an `AF_INET` probe
/// socket and immediately opens an `AF_INET6` one, which lands on the same fd
/// number and was handed the dead socket's `sockaddr_in`. `getaddrinfo` then
/// aborted the guest with
/// `assertion failed: a1->source_addr.sin6_family == PF_INET6`.
///
/// The host fd is the identity the socket's teardown already keys on
/// (`reuseport_leave`/`recverr_close` beside it), it is shared by `dup`ed fds
/// exactly as the address should be, and it is unique while the socket lives.
/// Host fds ARE reused after close, which is precisely why
/// [`NetworkProvider::forget_socket_addresses`] must run when the last
/// reference goes away.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SocketKey(i32);

impl SocketKey {
    /// The ONLY constructor: name the domain at the call site.
    pub fn for_host_fd(host_fd: i32) -> Self {
        Self(host_fd)
    }

    pub fn raw(self) -> i32 {
        self.0
    }
}

pub trait NetworkProvider: Send + Sync {
    fn capabilities(&self) -> NetworkCapabilities;
    /// Nonblocking provider fork exclusion. Returning `None` means the caller
    /// must retry until its absolute fork deadline; the default has no helper
    /// state and therefore succeeds with a no-op guard.
    fn try_fork_guard(&self) -> Option<NetworkForkGuard<'_>> {
        Some(NetworkForkGuard::no_op())
    }
    /// Repair process-local provider state after a host fork. Implementations
    /// must not join vanished inherited helper threads or remove durable files
    /// still owned by the parent process.
    fn after_fork_child(&self) {}
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
        _socket: SocketKey,
        _guest_local: Option<GuestSocketAddr>,
        _host_local: Option<HostSocketAddr>,
        _guest_peer: Option<GuestSocketAddr>,
        _protocol: PortProtocol,
    ) -> Result<(), String> {
        Ok(())
    }
    fn guest_visible_local_addr(
        &self,
        _socket: SocketKey,
    ) -> Result<Option<GuestSocketAddr>, String> {
        Ok(None)
    }
    fn guest_visible_peer_addr(
        &self,
        _socket: SocketKey,
    ) -> Result<Option<GuestSocketAddr>, String> {
        Ok(None)
    }
    /// Drop `socket`'s recorded addresses. MUST be called when the last
    /// reference to the socket goes away, because host fds are reused: an entry
    /// that outlives its socket is handed to whatever opens next.
    fn forget_socket_addresses(&self, _socket: SocketKey) {}
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
    ) -> Result<(), LinuxErrno> {
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

/// Give a bridge namespace an identity no other instance can hold, once, in the
/// process that is about to boot the guest.
///
/// The endpoint namespace is a machine-global directory whose record paths are
/// built from the namespace id, so an id that is a *constant* -- which
/// `NetworkNamespaceSpec::bridge_default` used to hand out as the literal
/// `"default"` -- makes two concurrent runs share one key. The loopback scope is
/// keyed on the id alone, so that constant made one guest's `127.0.0.1:8080`
/// resolvable and connectable from a different instance's guest.
///
/// This is the single defaulting site on purpose. Every other spec builder can
/// now only *narrow* the identity (a container id, a `--name`, the container a
/// `--network container:X` sidecar joins); none can leave it constant, and no
/// future builder can regress it by forgetting to set it.
///
/// It must run here, and it must store what it sampled. `RuntimeNetwork::create`
/// runs in the root host process during run setup, strictly before the guest
/// boots and therefore before any guest `fork`, so the id is frozen into the
/// spec that `fork()` copies. Deriving it from `getpid()` *at use* instead would
/// break fork-coherence outright: a forked child's pid differs from its
/// parent's, so it would compute a different id and stop resolving every record
/// its parent published.
fn instance_scoped_spec(spec: &NetworkNamespaceSpec) -> NetworkNamespaceSpec {
    if spec.mode != NetworkMode::Bridge {
        // Only the bridge provider keys durable state on the id; host/none
        // ignore it, and minting one for them would be a behaviour change with
        // nothing to fix.
        return spec.clone();
    }
    let needs_identity = match spec.namespace_id.as_ref() {
        None => true,
        Some(id) => id.as_str() == NetworkNamespaceId::LEGACY_SHARED,
    };
    if !needs_identity {
        return spec.clone();
    }
    let mut spec = spec.clone();
    spec.namespace_id = Some(NetworkNamespaceId::anonymous(std::process::id()));
    spec
}

impl RuntimeNetwork {
    pub fn create(spec: &NetworkNamespaceSpec) -> Result<Self, String> {
        let spec = instance_scoped_spec(spec);
        debug_assert!(
            spec.mode != NetworkMode::Bridge
                || spec
                    .namespace_id
                    .as_ref()
                    .is_some_and(|id| id.as_str() != NetworkNamespaceId::LEGACY_SHARED),
            "a bridge namespace must carry an instance-unique id before the provider sees it"
        );
        let model = model::LinuxNetworkModel::from_spec(&spec);
        let provider = select_provider(&spec);
        let lease = provider.create_namespace(&spec)?;
        for mapping in &spec.published_ports {
            provider.publish_port(lease.id, mapping.clone())?;
        }
        Ok(Self {
            spec,
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

    /// No spec may reach the socket-namespace provider still carrying a
    /// constant namespace id. The endpoint namespace is machine-global and its
    /// loopback records are keyed on that id alone, so a constant there makes
    /// one guest's `127.0.0.1:<port>` resolvable from a concurrent instance.
    ///
    /// The id must also be *sampled once and stored*: `RuntimeNetwork::create`
    /// runs before the guest boots, so what it stores is what `fork()` copies,
    /// and every fork child derives the same record paths as its parent.
    #[test]
    fn bridge_namespace_is_instance_scoped_before_the_provider_sees_it() {
        let expected = NetworkNamespaceId::anonymous(std::process::id());

        let unnamed = RuntimeNetwork::create(&NetworkNamespaceSpec::bridge_default(
            None,
            Vec::new(),
            Vec::new(),
        ))
        .expect("create bridge network");
        assert_eq!(unnamed.spec.namespace_id.as_ref(), Some(&expected));

        // A persisted or hand-built spec carrying the retired literal is
        // replaced too, so the constant cannot be smuggled back in.
        let mut legacy = NetworkNamespaceSpec::bridge_default(None, Vec::new(), Vec::new());
        legacy.namespace_id = Some(NetworkNamespaceId::new(NetworkNamespaceId::LEGACY_SHARED));
        let legacy = RuntimeNetwork::create(&legacy).expect("create legacy bridge network");
        assert_eq!(legacy.spec.namespace_id.as_ref(), Some(&expected));

        // An identity a caller narrowed on purpose -- a container id, a
        // `--name`, or the container a `--network container:X` sidecar joins --
        // is exactly what `carrick exec` relies on being preserved.
        let mut explicit = NetworkNamespaceSpec::bridge_default(None, Vec::new(), Vec::new());
        explicit.namespace_id = Some(NetworkNamespaceId::new("container-abc"));
        let explicit = RuntimeNetwork::create(&explicit).expect("create explicit bridge network");
        assert_eq!(
            explicit.spec.namespace_id.as_ref(),
            Some(&NetworkNamespaceId::new("container-abc"))
        );
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
