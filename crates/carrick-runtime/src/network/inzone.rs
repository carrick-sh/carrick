//! In-zone loopback TCP registry and connect target resolution.
//!
//! A TCP connection between two guest sockets inside one carrier never touches
//! a host socket: connect pairs with the guest listener's accept queue in
//! memory, and all data, readiness and close semantics are carrick's own.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use carrick_spec::NetworkNamespaceId;

use crate::dispatch::net::unix_pure::PureSocketInner;
use crate::network::GuestSocketAddr;

/// Identity of a guest TCP listener as a connect target inside ONE carrier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct InZoneListenerKey {
    pub scope: InZoneScope,
    pub addr: GuestSocketAddr,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum InZoneScope {
    CarrierHost,
    Namespace(NetworkNamespaceId),
}

#[derive(Debug, Default)]
pub struct InZoneGeneration(AtomicU64);

impl InZoneGeneration {
    pub fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    pub fn bump(&self) -> u64 {
        self.0.fetch_add(1, Ordering::SeqCst)
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InZoneEnqueue {
    Queued,
    BacklogFull,
}

/// One listening guest socket's in-zone accept queue. Owned by the registry
/// (Arc), referenced weakly from the listener's OpenDescription.
pub struct InZoneListener {
    key: InZoneListenerKey,
    backlog: AtomicUsize,
    queue: Mutex<VecDeque<Arc<PureSocketInner>>>,
    wait_queue: Arc<crate::kernel::WaitQueue>,
    generation: InZoneGeneration,
}

impl std::fmt::Debug for InZoneListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InZoneListener")
            .field("key", &self.key)
            .field("backlog", &self.backlog.load(Ordering::SeqCst))
            .field("pending", &self.pending())
            .field("generation", &self.generation.get())
            .finish()
    }
}

impl InZoneListener {
    pub fn new(key: InZoneListenerKey, backlog: usize) -> Self {
        Self {
            key,
            backlog: AtomicUsize::new(backlog),
            queue: Mutex::new(VecDeque::new()),
            wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
            generation: InZoneGeneration::new(),
        }
    }

    pub fn key(&self) -> &InZoneListenerKey {
        &self.key
    }

    pub fn backlog(&self) -> usize {
        self.backlog.load(Ordering::SeqCst)
    }

    pub fn set_backlog(&self, backlog: usize) {
        self.backlog.store(backlog, Ordering::SeqCst);
    }

    pub fn enqueue(&self, server_half: Arc<PureSocketInner>) -> InZoneEnqueue {
        let mut queue = self.queue.lock().unwrap_or_else(|p| p.into_inner());
        if queue.len() >= self.backlog.load(Ordering::SeqCst) {
            return InZoneEnqueue::BacklogFull;
        }
        queue.push_back(server_half);
        drop(queue);
        self.wait_queue.wake_all();
        InZoneEnqueue::Queued
    }

    pub fn dequeue(&self) -> Option<Arc<PureSocketInner>> {
        let mut queue = self.queue.lock().unwrap_or_else(|p| p.into_inner());
        let item = queue.pop_front()?;
        drop(queue);
        self.wait_queue.wake_all();
        Some(item)
    }

    pub fn pending(&self) -> usize {
        self.queue.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn wait_queue(&self) -> Arc<crate::kernel::WaitQueue> {
        Arc::clone(&self.wait_queue)
    }

    pub fn generation(&self) -> u64 {
        self.generation.get()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddrFamily {
    V4,
    V6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InZonePort(u16);

impl InZonePort {
    pub fn new(port: u16) -> Self {
        Self(port)
    }

    pub fn raw(self) -> u16 {
        self.0
    }
}

const EPHEMERAL_PORT_START: u16 = 32768;
const EPHEMERAL_PORT_END: u16 = 60999;

#[derive(Debug, Default)]
pub struct InZoneEphemeralPorts {
    allocated: HashMap<InZoneScope, HashSet<u16>>,
    next_port: HashMap<InZoneScope, u16>,
}

impl InZoneEphemeralPorts {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allocate(
        &mut self,
        scope: &InZoneScope,
        _family: AddrFamily,
        in_use_check: impl Fn(u16) -> bool,
    ) -> Option<InZonePort> {
        let allocated_set = self.allocated.entry(scope.clone()).or_default();
        let next = self
            .next_port
            .entry(scope.clone())
            .or_insert(EPHEMERAL_PORT_START);
        let total = (EPHEMERAL_PORT_END - EPHEMERAL_PORT_START + 1) as usize;
        for _ in 0..total {
            let candidate = *next;
            if *next >= EPHEMERAL_PORT_END {
                *next = EPHEMERAL_PORT_START;
            } else {
                *next += 1;
            }
            if !allocated_set.contains(&candidate) && !in_use_check(candidate) {
                allocated_set.insert(candidate);
                return Some(InZonePort::new(candidate));
            }
        }
        None
    }

    pub fn release(&mut self, scope: &InZoneScope, port: InZonePort) {
        if let Some(set) = self.allocated.get_mut(scope) {
            set.remove(&port.raw());
        }
    }

    pub fn is_in_use(&self, scope: &InZoneScope, port: u16) -> bool {
        self.allocated
            .get(scope)
            .is_some_and(|set| set.contains(&port))
    }
}

/// Per-carrier registry. Lives in `SocketNamespaceProvider` (and the no-op
/// provider gets the same field: in-zone is provider-independent).
#[derive(Debug, Default)]
pub struct InZoneRegistry {
    listeners: Mutex<HashMap<InZoneListenerKey, Vec<Arc<InZoneListener>>>>,
    ephemeral: Mutex<InZoneEphemeralPorts>,
    scope_addresses: Mutex<HashMap<InZoneScope, HashSet<IpAddr>>>,
}

impl InZoneRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, key: InZoneListenerKey, backlog: usize) -> Arc<InZoneListener> {
        let listener = Arc::new(InZoneListener::new(key.clone(), backlog));
        let mut listeners = self.listeners.lock().unwrap_or_else(|p| p.into_inner());
        listeners
            .entry(key)
            .or_default()
            .push(Arc::clone(&listener));
        listener
    }

    pub fn unregister(&self, listener: &Arc<InZoneListener>) {
        let mut listeners = self.listeners.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(group) = listeners.get_mut(listener.key()) {
            group.retain(|l| !Arc::ptr_eq(l, listener));
            if group.is_empty() {
                listeners.remove(listener.key());
            }
        }
        listener.generation.bump();
    }

    pub fn register_scope_address(&self, scope: &InZoneScope, addr: IpAddr) {
        self.scope_addresses
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(scope.clone())
            .or_default()
            .insert(addr);
    }

    pub fn unregister_scope(&self, scope: &InZoneScope) {
        self.scope_addresses
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(scope);
    }

    pub fn is_scope_address(&self, scope: &InZoneScope, addr: &IpAddr) -> bool {
        self.scope_addresses
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(scope)
            .is_some_and(|addrs| addrs.contains(addr))
    }

    /// The listener a guest connect to `target` in `scope` would reach, if any:
    /// exact address match, or a wildcard (0.0.0.0 / ::) listener on that port,
    /// for a loopback or scope-local destination address. Never matches a
    /// destination outside 127/8, ::1 or the scope's own addresses.
    pub fn resolve(
        &self,
        scope: &InZoneScope,
        target: GuestSocketAddr,
    ) -> Option<Arc<InZoneListener>> {
        let target_ip = target.0.ip();
        let target_port = target.0.port();

        // Must be loopback or scope-local address
        if !target_ip.is_loopback() && !self.is_scope_address(scope, &target_ip) {
            return None;
        }

        let listeners = self.listeners.lock().unwrap_or_else(|p| p.into_inner());

        // 1. Exact match
        let exact_key = InZoneListenerKey {
            scope: scope.clone(),
            addr: target,
        };
        if let Some(group) = listeners.get(&exact_key)
            && let Some(best) = group.iter().min_by_key(|l| l.pending())
        {
            return Some(Arc::clone(best));
        }

        // 2. Wildcard match (0.0.0.0 or ::)
        let wildcard_keys = match target.0 {
            SocketAddr::V4(_) => vec![
                InZoneListenerKey {
                    scope: scope.clone(),
                    addr: GuestSocketAddr(SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                        target_port,
                    )),
                },
                InZoneListenerKey {
                    scope: scope.clone(),
                    addr: GuestSocketAddr(SocketAddr::new(
                        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                        target_port,
                    )),
                },
            ],
            SocketAddr::V6(_) => vec![InZoneListenerKey {
                scope: scope.clone(),
                addr: GuestSocketAddr(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    target_port,
                )),
            }],
        };

        for wkey in wildcard_keys {
            if let Some(group) = listeners.get(&wkey)
                && let Some(best) = group.iter().min_by_key(|l| l.pending())
            {
                return Some(Arc::clone(best));
            }
        }

        None
    }

    pub fn allocate_ephemeral(
        &self,
        scope: &InZoneScope,
        family: AddrFamily,
    ) -> Option<InZonePort> {
        let mut ephemeral = self.ephemeral.lock().unwrap_or_else(|p| p.into_inner());
        let listeners = self.listeners.lock().unwrap_or_else(|p| p.into_inner());
        ephemeral.allocate(scope, family, |port| {
            listeners
                .iter()
                .any(|(k, list)| k.scope == *scope && k.addr.0.port() == port && !list.is_empty())
        })
    }

    pub fn release_ephemeral(&self, scope: &InZoneScope, port: InZonePort) {
        self.ephemeral
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .release(scope, port);
    }

    /// `bind` consults this so a host-backed bind cannot take a port an in-zone
    /// client half currently uses (one port space, like Linux).
    pub fn port_in_use(&self, scope: &InZoneScope, port: u16) -> bool {
        if self
            .ephemeral
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_in_use(scope, port)
        {
            return true;
        }
        let listeners = self.listeners.lock().unwrap_or_else(|p| p.into_inner());
        listeners
            .iter()
            .any(|(k, list)| k.scope == *scope && k.addr.0.port() == port && !list.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::net::unix_pure::{LinuxUcred, PureSocketInner};
    use crate::network::{ConnectTarget, GuestSocketAddr, NetworkProvider};
    use carrick_abi::{LINUX_AF_INET, LINUX_IPPROTO_TCP, LINUX_SOCK_STREAM};
    use carrick_spec::{NetworkNamespaceId, PortProtocol};
    use std::sync::Arc;

    #[test]
    fn wildcard_listener_matches_loopback_destination_in_its_scope() {
        let reg = InZoneRegistry::default();
        let scope = InZoneScope::CarrierHost;
        let l = reg.register(
            InZoneListenerKey {
                scope: scope.clone(),
                addr: GuestSocketAddr("0.0.0.0:8080".parse().unwrap()),
            },
            16,
        );
        assert!(Arc::ptr_eq(
            &reg.resolve(&scope, GuestSocketAddr("127.0.0.1:8080".parse().unwrap()))
                .unwrap(),
            &l
        ));
        assert!(Arc::ptr_eq(
            &reg.resolve(&scope, GuestSocketAddr("127.0.1.1:8080".parse().unwrap()))
                .unwrap(),
            &l
        ));
        assert!(
            reg.resolve(&scope, GuestSocketAddr("10.0.0.5:8080".parse().unwrap()))
                .is_none(),
            "not a loopback destination"
        );
        assert!(
            reg.resolve(
                &InZoneScope::Namespace(NetworkNamespaceId::new("other")),
                GuestSocketAddr("127.0.0.1:8080".parse().unwrap())
            )
            .is_none(),
            "another namespace never sees it"
        );
        reg.unregister(&l);
        assert!(
            reg.resolve(&scope, GuestSocketAddr("127.0.0.1:8080".parse().unwrap()))
                .is_none()
        );
    }

    #[test]
    fn backlog_bounds_the_queue_and_dequeue_is_fifo() {
        let reg = InZoneRegistry::default();
        let scope = InZoneScope::CarrierHost;
        let l = reg.register(
            InZoneListenerKey {
                scope,
                addr: GuestSocketAddr("127.0.0.1:1".parse().unwrap()),
            },
            2,
        );
        let halves: Vec<_> = (0..3)
            .map(|_| {
                PureSocketInner::pair_with_family(
                    LINUX_AF_INET,
                    LINUX_SOCK_STREAM,
                    LINUX_IPPROTO_TCP,
                    LinuxUcred::default(),
                    LinuxUcred::default(),
                )
                .1
            })
            .collect();
        assert!(matches!(
            l.enqueue(Arc::clone(&halves[0])),
            InZoneEnqueue::Queued
        ));
        assert!(matches!(
            l.enqueue(Arc::clone(&halves[1])),
            InZoneEnqueue::Queued
        ));
        assert!(matches!(
            l.enqueue(Arc::clone(&halves[2])),
            InZoneEnqueue::BacklogFull
        ));
        assert!(Arc::ptr_eq(&l.dequeue().unwrap(), &halves[0]));
        assert!(Arc::ptr_eq(&l.dequeue().unwrap(), &halves[1]));
        assert!(l.dequeue().is_none());
    }

    #[test]
    fn ephemeral_ports_are_unique_per_scope_and_visible_to_bind() {
        let reg = InZoneRegistry::default();
        let scope = InZoneScope::CarrierHost;
        let a = reg.allocate_ephemeral(&scope, AddrFamily::V4).unwrap();
        let b = reg.allocate_ephemeral(&scope, AddrFamily::V4).unwrap();
        assert_ne!(a, b);
        assert!(reg.port_in_use(&scope, a.raw()));
        reg.release_ephemeral(&scope, a);
        assert!(!reg.port_in_use(&scope, a.raw()));
    }

    #[test]
    fn reuseport_group_gets_the_shortest_queue() {
        let reg = InZoneRegistry::default();
        let scope = InZoneScope::CarrierHost;
        let key = InZoneListenerKey {
            scope: scope.clone(),
            addr: GuestSocketAddr("0.0.0.0:7".parse().unwrap()),
        };
        let a = reg.register(key.clone(), 16);
        let b = reg.register(key, 16);
        for _ in 0..3 {
            let target = reg
                .resolve(&scope, GuestSocketAddr("127.0.0.1:7".parse().unwrap()))
                .unwrap();
            let half = PureSocketInner::pair_with_family(
                LINUX_AF_INET,
                LINUX_SOCK_STREAM,
                LINUX_IPPROTO_TCP,
                LinuxUcred::default(),
                LinuxUcred::default(),
            )
            .1;
            assert!(matches!(target.enqueue(half), InZoneEnqueue::Queued));
        }
        let (pa, pb) = (a.pending(), b.pending());
        assert_eq!(pa + pb, 3);
        assert!(pa.abs_diff(pb) <= 1, "shortest-queue placement: {pa}/{pb}");
    }

    #[test]
    fn provider_resolve_connect_prefers_in_zone_then_falls_through() {
        let provider = crate::network::socket_namespace::SocketNamespaceProvider::new();
        let scope = InZoneScope::CarrierHost;
        let target = GuestSocketAddr("127.0.0.1:9000".parse().unwrap());
        let listener = provider.inzone().register(
            InZoneListenerKey {
                scope,
                addr: target,
            },
            16,
        );

        let resolved = provider
            .resolve_connect(None, target, PortProtocol::Tcp)
            .expect("resolve_connect");
        assert_eq!(resolved, ConnectTarget::InZone { listener, target });

        let other_target = GuestSocketAddr("127.0.0.1:9001".parse().unwrap());
        let fallback = provider
            .resolve_connect(None, other_target, PortProtocol::Tcp)
            .expect("resolve_connect");
        assert_eq!(fallback, ConnectTarget::Unchanged);
    }
}
