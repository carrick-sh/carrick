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
    reuseport: bool,
    ipv6_v6only: bool,
    backlog: AtomicUsize,
    admissions: AtomicUsize,
    queue: Mutex<VecDeque<Arc<PureSocketInner>>>,
    wait_queue: Arc<crate::kernel::WaitQueue>,
    generation: InZoneGeneration,
    /// Monotonic enqueue sequence for ET consumers. Queue depth alone cannot
    /// distinguish a new in-zone arrival from an equally deep host accept
    /// queue, and it can fall when another arrival is accepted.
    arrival_generation: InZoneGeneration,
}

/// One coherent accept-queue sample for an epoll readiness decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenerReadinessSnapshot {
    pub pending: usize,
    pub arrival_generation: u64,
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
    pub fn new(key: InZoneListenerKey, backlog: usize, reuseport: bool, ipv6_v6only: bool) -> Self {
        Self {
            key,
            reuseport,
            ipv6_v6only,
            backlog: AtomicUsize::new(backlog),
            admissions: AtomicUsize::new(0),
            queue: Mutex::new(VecDeque::new()),
            wait_queue: Arc::new(crate::kernel::WaitQueue::new()),
            generation: InZoneGeneration::new(),
            arrival_generation: InZoneGeneration::new(),
        }
    }

    pub fn key(&self) -> &InZoneListenerKey {
        &self.key
    }

    pub fn reuseport(&self) -> bool {
        self.reuseport
    }
    pub fn ipv6_v6only(&self) -> bool {
        self.ipv6_v6only
    }

    pub fn backlog(&self) -> usize {
        self.backlog.load(Ordering::SeqCst)
    }

    pub fn set_backlog(&self, backlog: usize) {
        self.backlog.store(backlog, Ordering::SeqCst);
    }

    pub fn enqueue(&self, server_half: Arc<PureSocketInner>) -> InZoneEnqueue {
        let mut queue = self.queue.lock().unwrap_or_else(|p| p.into_inner());
        if queue.len() + self.admissions.load(Ordering::SeqCst)
            >= self.backlog.load(Ordering::SeqCst)
        {
            return InZoneEnqueue::BacklogFull;
        }
        queue.push_back(server_half);
        self.arrival_generation.bump();
        drop(queue);
        self.wait_queue.wake_all();
        InZoneEnqueue::Queued
    }

    /// Reserve capacity before making a connection visible.  The reservation is
    /// released on every pre-publication error; once it exists, enqueue cannot
    /// fail because concurrent normal enqueues count it as occupied capacity.
    pub fn reserve_admission(self: &Arc<Self>) -> Option<InZoneAdmission> {
        let queue = self.queue.lock().unwrap_or_else(|p| p.into_inner());
        if queue.len() + self.admissions.load(Ordering::SeqCst)
            >= self.backlog.load(Ordering::SeqCst)
        {
            return None;
        }
        self.admissions.fetch_add(1, Ordering::SeqCst);
        Some(InZoneAdmission {
            listener: Arc::clone(self),
            consumed: false,
        })
    }

    fn enqueue_reserved(&self, server_half: Arc<PureSocketInner>) {
        let mut queue = self.queue.lock().unwrap_or_else(|p| p.into_inner());
        self.admissions.fetch_sub(1, Ordering::SeqCst);
        queue.push_back(server_half);
        self.arrival_generation.bump();
        drop(queue);
        self.wait_queue.wake_all();
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

    pub fn readiness_snapshot(&self) -> ListenerReadinessSnapshot {
        let queue = self.queue.lock().unwrap_or_else(|p| p.into_inner());
        ListenerReadinessSnapshot {
            pending: queue.len(),
            arrival_generation: self.arrival_generation.get(),
        }
    }

    pub fn wait_queue(&self) -> Arc<crate::kernel::WaitQueue> {
        Arc::clone(&self.wait_queue)
    }

    pub fn generation(&self) -> u64 {
        self.generation.get()
    }
}

pub struct InZoneAdmission {
    listener: Arc<InZoneListener>,
    consumed: bool,
}

impl InZoneAdmission {
    pub fn enqueue(mut self, server_half: Arc<PureSocketInner>) {
        self.listener.enqueue_reserved(server_half);
        self.consumed = true;
    }
}

impl Drop for InZoneAdmission {
    fn drop(&mut self) {
        if !self.consumed {
            self.listener.admissions.fetch_sub(1, Ordering::SeqCst);
            self.listener.wait_queue.wake_all();
        }
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
pub const EPHEMERAL_PORT_COUNT: usize = (EPHEMERAL_PORT_END - EPHEMERAL_PORT_START + 1) as usize;

fn bindings_overlap(
    left_family: AddrFamily,
    left_addr: IpAddr,
    left_v6only: bool,
    right_family: AddrFamily,
    right_addr: IpAddr,
    right_v6only: bool,
) -> bool {
    if left_family == right_family {
        return left_addr == right_addr
            || left_addr.is_unspecified()
            || right_addr.is_unspecified();
    }
    let dual_stack_v6_overlaps_v4 = |v6: IpAddr, v6only: bool, v4: IpAddr| {
        let IpAddr::V6(v6) = v6 else { return false };
        let IpAddr::V4(v4) = v4 else { return false };
        !v6only
            && (v6.is_unspecified()
                || v4.is_unspecified()
                || v6.to_ipv4_mapped().is_some_and(|mapped| mapped == v4))
    };
    // A dual-stack wildcard aliases every IPv4 endpoint; an IPv4-mapped IPv6
    // bind aliases its exact IPv4 peer. V6ONLY restores independent spaces.
    (left_family == AddrFamily::V6 && dual_stack_v6_overlaps_v4(left_addr, left_v6only, right_addr))
        || (right_family == AddrFamily::V6
            && dual_stack_v6_overlaps_v4(right_addr, right_v6only, left_addr))
}

fn listener_key_overlaps(
    key: &InZoneListenerKey,
    key_v6only: bool,
    scope: &InZoneScope,
    addr: SocketAddr,
    ipv6_v6only: bool,
) -> bool {
    key.scope == *scope
        && key.addr.0.port() == addr.port()
        && bindings_overlap(
            match key.addr.0 {
                SocketAddr::V4(_) => AddrFamily::V4,
                SocketAddr::V6(_) => AddrFamily::V6,
            },
            key.addr.0.ip(),
            key_v6only,
            match addr {
                SocketAddr::V4(_) => AddrFamily::V4,
                SocketAddr::V6(_) => AddrFamily::V6,
            },
            addr.ip(),
            ipv6_v6only,
        )
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct InZonePortBinding {
    family: AddrFamily,
    addr: IpAddr,
    port: InZonePort,
    reuseaddr: bool,
    reuseport: bool,
    ipv6_v6only: bool,
}

/// A reservation is identified by an unforgeable generation, rather than by a
/// port number.  This matters when an explicit bind and an ephemeral connect
/// use the same number: dropping either resource must never release the other.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct InZonePortLease {
    scope: InZoneScope,
    id: u64,
    port: InZonePort,
    /// A pre-existing compatible guest claim made the host collision expected.
    /// Only that admission may replace Darwin's backing with a private carrier.
    host_backing_fallback_allowed: bool,
}

impl InZonePortLease {
    pub fn port(&self) -> InZonePort {
        self.port
    }

    pub fn host_backing_fallback_allowed(&self) -> bool {
        self.host_backing_fallback_allowed
    }
}

#[derive(Debug, Default)]
pub struct InZoneEphemeralPorts {
    allocated: HashMap<InZoneScope, HashMap<u64, InZonePortBinding>>,
    next_port: HashMap<InZoneScope, u16>,
    next_id: u64,
}

impl InZoneEphemeralPorts {
    pub fn new() -> Self {
        Self::default()
    }

    fn next_id(&mut self) -> u64 {
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.next_id
    }

    pub fn allocate(
        &mut self,
        scope: &InZoneScope,
        addr: IpAddr,
        reuseaddr: bool,
        reuseport: bool,
        ipv6_v6only: bool,
        in_use_check: impl Fn(u16) -> bool,
    ) -> Option<InZonePortLease> {
        let family = match addr {
            IpAddr::V4(_) => AddrFamily::V4,
            IpAddr::V6(_) => AddrFamily::V6,
        };
        for _ in 0..EPHEMERAL_PORT_COUNT {
            let candidate = {
                let next = self
                    .next_port
                    .entry(scope.clone())
                    .or_insert(EPHEMERAL_PORT_START);
                let candidate = *next;
                *next = if *next >= EPHEMERAL_PORT_END {
                    EPHEMERAL_PORT_START
                } else {
                    *next + 1
                };
                candidate
            };
            let port = InZonePort::new(candidate);
            let conflicts_with_claim = self.allocated.get(scope).is_some_and(|claims| {
                claims.values().any(|claim| {
                    claim.port == port
                        && bindings_overlap(
                            claim.family,
                            claim.addr,
                            claim.ipv6_v6only,
                            family,
                            addr,
                            ipv6_v6only,
                        )
                        && !((reuseaddr && claim.reuseaddr) || (reuseport && claim.reuseport))
                })
            });
            if !conflicts_with_claim && !in_use_check(candidate) {
                let id = self.next_id();
                self.allocated.entry(scope.clone()).or_default().insert(
                    id,
                    InZonePortBinding {
                        family,
                        addr,
                        port,
                        reuseaddr,
                        reuseport,
                        ipv6_v6only,
                    },
                );
                return Some(InZonePortLease {
                    scope: scope.clone(),
                    id,
                    port,
                    host_backing_fallback_allowed: false,
                });
            }
        }
        None
    }

    pub fn release(&mut self, lease: InZonePortLease) {
        if let Some(set) = self.allocated.get_mut(&lease.scope) {
            set.remove(&lease.id);
        }
    }

    pub fn try_claim_bound(
        &mut self,
        scope: &InZoneScope,
        addr: SocketAddr,
        reuseaddr: bool,
        reuseport: bool,
        ipv6_v6only: bool,
    ) -> Option<InZonePortLease> {
        let family = match addr {
            SocketAddr::V4(_) => AddrFamily::V4,
            SocketAddr::V6(_) => AddrFamily::V6,
        };
        let port = InZonePort::new(addr.port());
        let compatible_existing = self.allocated.get(scope).is_some_and(|claims| {
            claims.values().any(|claim| {
                claim.port == port
                    && bindings_overlap(
                        claim.family,
                        claim.addr,
                        claim.ipv6_v6only,
                        family,
                        addr.ip(),
                        ipv6_v6only,
                    )
                    && reuseaddr
                    && claim.reuseaddr
            })
        });
        let has_conflict = self.allocated.get(scope).is_some_and(|claims| {
            claims.values().any(|claim| {
                claim.port == port
                    && bindings_overlap(
                        claim.family,
                        claim.addr,
                        claim.ipv6_v6only,
                        family,
                        addr.ip(),
                        ipv6_v6only,
                    )
                    && !((reuseaddr && claim.reuseaddr) || (reuseport && claim.reuseport))
            })
        });
        if has_conflict {
            return None;
        }
        let id = self.next_id();
        self.allocated.entry(scope.clone()).or_default().insert(
            id,
            InZonePortBinding {
                family,
                addr: addr.ip(),
                port,
                reuseaddr,
                reuseport,
                ipv6_v6only,
            },
        );
        Some(InZonePortLease {
            scope: scope.clone(),
            id,
            port,
            host_backing_fallback_allowed: compatible_existing,
        })
    }

    pub fn is_in_use(&self, scope: &InZoneScope, port: u16) -> bool {
        self.allocated
            .get(scope)
            .is_some_and(|set| set.values().any(|binding| binding.port.raw() == port))
    }
}

/// Per-carrier registry. Lives in `SocketNamespaceProvider` (and the no-op
/// provider gets the same field: in-zone is provider-independent).
#[derive(Debug, Default)]
pub struct InZoneRegistry {
    listeners: Mutex<HashMap<InZoneListenerKey, Vec<Arc<InZoneListener>>>>,
    pending_listeners: Mutex<HashMap<InZoneListenerKey, Vec<(bool, bool)>>>,
    ephemeral: Mutex<InZoneEphemeralPorts>,
    scope_addresses: Mutex<HashMap<InZoneScope, HashSet<IpAddr>>>,
}

/// Pending listener admission. Dropping before `commit` removes the exact
/// reservation, so every syscall error and description-lifetime race rolls
/// back without a manual cleanup branch.
pub struct InZoneListenerReservation<'a> {
    registry: &'a InZoneRegistry,
    key: InZoneListenerKey,
    reuseport: bool,
    ipv6_v6only: bool,
    active: bool,
}

impl InZoneListenerReservation<'_> {
    pub fn key(&self) -> &InZoneListenerKey {
        &self.key
    }

    pub fn commit(mut self, backlog: usize) -> Arc<InZoneListener> {
        let listener =
            self.registry
                .register(self.key.clone(), backlog, self.reuseport, self.ipv6_v6only);
        self.active = false;
        listener
    }
}

impl Drop for InZoneListenerReservation<'_> {
    fn drop(&mut self) {
        if self.active {
            self.registry
                .cancel_listener_reservation(&self.key, self.reuseport, self.ipv6_v6only);
        }
    }
}

impl InZoneRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reserve_listener(
        &self,
        key: &InZoneListenerKey,
        reuseport: bool,
        ipv6_v6only: bool,
    ) -> bool {
        let listeners = self.listeners.lock().unwrap_or_else(|p| p.into_inner());
        let mut pending = self
            .pending_listeners
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let overlaps = |existing: &InZoneListenerKey, existing_v6only: bool| {
            existing.scope == key.scope
                && existing.addr.0.port() == key.addr.0.port()
                && bindings_overlap(
                    match existing.addr.0 {
                        SocketAddr::V4(_) => AddrFamily::V4,
                        SocketAddr::V6(_) => AddrFamily::V6,
                    },
                    existing.addr.0.ip(),
                    existing_v6only,
                    match key.addr.0 {
                        SocketAddr::V4(_) => AddrFamily::V4,
                        SocketAddr::V6(_) => AddrFamily::V6,
                    },
                    key.addr.0.ip(),
                    ipv6_v6only,
                )
        };
        let active_ok = listeners.iter().all(|(existing, group)| {
            !overlaps(
                existing,
                group.first().is_some_and(|listener| listener.ipv6_v6only()),
            ) || (reuseport && group.iter().all(|listener| listener.reuseport()))
        });
        let pending_ok = pending.iter().all(|(existing, group)| {
            !overlaps(existing, group.first().is_some_and(|(_, v6only)| *v6only))
                || (reuseport
                    && group
                        .iter()
                        .all(|(existing_reuseport, _)| *existing_reuseport))
        });
        if !active_ok || !pending_ok {
            return false;
        }
        pending
            .entry(key.clone())
            .or_default()
            .push((reuseport, ipv6_v6only));
        true
    }

    pub fn reserve_listener_guard(
        &self,
        key: InZoneListenerKey,
        reuseport: bool,
        ipv6_v6only: bool,
    ) -> Option<InZoneListenerReservation<'_>> {
        self.reserve_listener(&key, reuseport, ipv6_v6only)
            .then_some(InZoneListenerReservation {
                registry: self,
                key,
                reuseport,
                ipv6_v6only,
                active: true,
            })
    }

    pub fn cancel_listener_reservation(
        &self,
        key: &InZoneListenerKey,
        reuseport: bool,
        ipv6_v6only: bool,
    ) {
        let _listeners = self.listeners.lock().unwrap_or_else(|p| p.into_inner());
        let mut pending = self
            .pending_listeners
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(group) = pending.get_mut(key) {
            if let Some(index) = group
                .iter()
                .position(|existing| *existing == (reuseport, ipv6_v6only))
            {
                group.swap_remove(index);
            }
            if group.is_empty() {
                pending.remove(key);
            }
        }
    }

    pub fn register(
        &self,
        key: InZoneListenerKey,
        backlog: usize,
        reuseport: bool,
        ipv6_v6only: bool,
    ) -> Arc<InZoneListener> {
        let listener = Arc::new(InZoneListener::new(
            key.clone(),
            backlog,
            reuseport,
            ipv6_v6only,
        ));
        let mut listeners = self.listeners.lock().unwrap_or_else(|p| p.into_inner());
        let mut pending = self
            .pending_listeners
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if let Some(group) = pending.get_mut(&key) {
            if let Some(index) = group
                .iter()
                .position(|existing| *existing == (reuseport, ipv6_v6only))
            {
                group.swap_remove(index);
            }
            if group.is_empty() {
                pending.remove(&key);
            }
        }
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

    /// True only for an endpoint Carrick has authenticated as guest-owned by a
    /// successful/pending guest bind.  This is intentionally narrower than
    /// "loopback": CarrierHost may still reach a real host service there.
    pub fn owns_endpoint(&self, scope: &InZoneScope, target: GuestSocketAddr) -> bool {
        let family = match target.0 {
            SocketAddr::V4(_) => AddrFamily::V4,
            SocketAddr::V6(_) => AddrFamily::V6,
        };
        self.ephemeral
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .allocated
            .get(scope)
            .is_some_and(|claims| {
                claims.values().any(|claim| {
                    claim.port.raw() == target.0.port()
                        && bindings_overlap(
                            claim.family,
                            claim.addr,
                            claim.ipv6_v6only,
                            family,
                            target.0.ip(),
                            false,
                        )
                })
            })
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

        // An IPv4-mapped IPv6 bind aliases its exact IPv4 peer unless the
        // socket was made v6-only.  Bind admission already uses the same
        // overlap rule; connection resolution must use it as well.
        if let SocketAddr::V4(v4) = target.0 {
            let mapped_key = InZoneListenerKey {
                scope: scope.clone(),
                addr: GuestSocketAddr(SocketAddr::new(
                    IpAddr::V6(v4.ip().to_ipv6_mapped()),
                    target_port,
                )),
            };
            if let Some(group) = listeners.get(&mapped_key)
                && let Some(best) = group
                    .iter()
                    .filter(|listener| !listener.ipv6_v6only())
                    .min_by_key(|listener| listener.pending())
            {
                return Some(Arc::clone(best));
            }
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
                && let Some(best) = group
                    .iter()
                    .filter(|listener| {
                        // A v6-only wildcard has a separate IPv4 port space.
                        // It must not receive an IPv4 connect merely because
                        // the in-zone resolver also considers [::] wildcard.
                        !matches!(target.0, SocketAddr::V4(_)) || !listener.ipv6_v6only()
                    })
                    .min_by_key(|listener| listener.pending())
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
    ) -> Option<InZonePortLease> {
        let listeners = self.listeners.lock().unwrap_or_else(|p| p.into_inner());
        let mut ephemeral = self.ephemeral.lock().unwrap_or_else(|p| p.into_inner());
        let addr = match family {
            AddrFamily::V4 => IpAddr::V4(Ipv4Addr::LOCALHOST),
            AddrFamily::V6 => IpAddr::V6(Ipv6Addr::LOCALHOST),
        };
        ephemeral.allocate(scope, addr, false, false, false, |port| {
            listeners
                .iter()
                .any(|(k, list)| k.scope == *scope && k.addr.0.port() == port && !list.is_empty())
        })
    }

    /// Reserve a port-zero bind atomically with its eventual address and
    /// socket-option identity. The host bind runs after this admission, so no
    /// allocator may select the port while its ownership is pending.
    pub fn allocate_ephemeral_for_bind(
        &self,
        scope: &InZoneScope,
        addr: IpAddr,
        reuseaddr: bool,
        reuseport: bool,
        ipv6_v6only: bool,
    ) -> Option<InZonePortLease> {
        let listeners = self.listeners.lock().unwrap_or_else(|p| p.into_inner());
        let mut ephemeral = self.ephemeral.lock().unwrap_or_else(|p| p.into_inner());
        ephemeral.allocate(scope, addr, reuseaddr, reuseport, ipv6_v6only, |port| {
            listeners
                .iter()
                .any(|(k, list)| k.scope == *scope && k.addr.0.port() == port && !list.is_empty())
        })
    }

    pub fn try_claim_bound_port(
        &self,
        scope: &InZoneScope,
        addr: SocketAddr,
        reuseaddr: bool,
        reuseport: bool,
        ipv6_v6only: bool,
    ) -> Option<InZonePortLease> {
        let listeners = self.listeners.lock().unwrap_or_else(|p| p.into_inner());
        let pending = self
            .pending_listeners
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let active_conflict = listeners.iter().any(|(key, group)| {
            listener_key_overlaps(
                key,
                group.first().is_some_and(|listener| listener.ipv6_v6only()),
                scope,
                addr,
                ipv6_v6only,
            ) && !(reuseport && group.iter().all(|listener| listener.reuseport()))
        });
        let pending_conflict = pending.iter().any(|(key, group)| {
            listener_key_overlaps(
                key,
                group.first().is_some_and(|(_, v6only)| *v6only),
                scope,
                addr,
                ipv6_v6only,
            ) && !(reuseport
                && group
                    .iter()
                    .all(|(existing_reuseport, _)| *existing_reuseport))
        });
        if active_conflict || pending_conflict {
            return None;
        }
        self.ephemeral
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .try_claim_bound(scope, addr, reuseaddr, reuseport, ipv6_v6only)
    }

    pub fn release_port(&self, lease: InZonePortLease) {
        self.ephemeral
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .release(lease);
    }

    pub fn release_ephemeral(&self, lease: InZonePortLease) {
        self.release_port(lease);
    }

    /// `bind` consults this so a host-backed bind cannot take a port an in-zone
    /// client half currently uses (one port space, like Linux).
    pub fn port_in_use(&self, scope: &InZoneScope, port: u16) -> bool {
        let listeners = self.listeners.lock().unwrap_or_else(|p| p.into_inner());
        if self
            .ephemeral
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_in_use(scope, port)
        {
            return true;
        }
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
            false,
            false,
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
    fn listener_reservation_rolls_back_on_drop_and_commits_exactly_once() {
        let reg = InZoneRegistry::default();
        let key = InZoneListenerKey {
            scope: InZoneScope::CarrierHost,
            addr: GuestSocketAddr("127.0.0.1:49173".parse().unwrap()),
        };
        let pending = reg
            .reserve_listener_guard(key.clone(), false, false)
            .expect("first listener reservation");
        assert!(
            reg.reserve_listener_guard(key.clone(), false, false)
                .is_none(),
            "a live reservation must exclude an overlapping listener"
        );
        drop(pending);
        let pending = reg
            .reserve_listener_guard(key.clone(), false, false)
            .expect("dropping the transaction must release its reservation");
        let listener = pending.commit(7);
        assert_eq!(listener.key(), &key);
        assert_eq!(listener.backlog(), 7);
        assert!(
            reg.reserve_listener_guard(key.clone(), false, false)
                .is_none(),
            "commit must replace pending admission with one active listener"
        );
        reg.unregister(&listener);
        assert!(reg.reserve_listener_guard(key, false, false).is_some());
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
            false,
            false,
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

    fn readiness_listener() -> Arc<InZoneListener> {
        Arc::new(InZoneListener::new(
            InZoneListenerKey {
                scope: InZoneScope::CarrierHost,
                addr: GuestSocketAddr("127.0.0.1:2".parse().unwrap()),
            },
            4,
            false,
            false,
        ))
    }

    fn server_half() -> Arc<PureSocketInner> {
        PureSocketInner::pair_with_family(
            LINUX_AF_INET,
            LINUX_SOCK_STREAM,
            LINUX_IPPROTO_TCP,
            LinuxUcred::default(),
            LinuxUcred::default(),
        )
        .1
    }

    #[test]
    fn readiness_snapshot_advances_with_direct_enqueue() {
        let listener = readiness_listener();
        assert_eq!(
            listener.readiness_snapshot(),
            ListenerReadinessSnapshot {
                pending: 0,
                arrival_generation: 0,
            }
        );
        assert_eq!(listener.enqueue(server_half()), InZoneEnqueue::Queued);
        assert_eq!(
            listener.readiness_snapshot(),
            ListenerReadinessSnapshot {
                pending: 1,
                arrival_generation: 1,
            }
        );
    }

    #[test]
    fn readiness_snapshot_advances_with_reserved_enqueue() {
        let listener = readiness_listener();
        listener
            .reserve_admission()
            .expect("capacity reservation")
            .enqueue(server_half());
        assert_eq!(
            listener.readiness_snapshot(),
            ListenerReadinessSnapshot {
                pending: 1,
                arrival_generation: 1,
            }
        );
    }

    #[test]
    fn dequeue_changes_pending_without_advancing_arrival_generation() {
        let listener = readiness_listener();
        assert_eq!(listener.enqueue(server_half()), InZoneEnqueue::Queued);
        let before = listener.readiness_snapshot();
        assert!(listener.dequeue().is_some());
        let after = listener.readiness_snapshot();
        assert_eq!(before.pending, 1);
        assert_eq!(after.pending, 0);
        assert_eq!(after.arrival_generation, before.arrival_generation);
    }

    #[test]
    fn ephemeral_ports_are_unique_per_scope_and_visible_to_bind() {
        let reg = InZoneRegistry::default();
        let scope = InZoneScope::CarrierHost;
        let a = reg.allocate_ephemeral(&scope, AddrFamily::V4).unwrap();
        let b = reg.allocate_ephemeral(&scope, AddrFamily::V4).unwrap();
        assert_ne!(a, b);
        assert!(reg.port_in_use(&scope, a.port().raw()));
        reg.release_ephemeral(a.clone());
        assert!(!reg.port_in_use(&scope, a.port().raw()));
    }

    #[test]
    fn reuseport_group_gets_the_shortest_queue() {
        let reg = InZoneRegistry::default();
        let scope = InZoneScope::CarrierHost;
        let key = InZoneListenerKey {
            scope: scope.clone(),
            addr: GuestSocketAddr("0.0.0.0:7".parse().unwrap()),
        };
        let a = reg.register(key.clone(), 16, true, false);
        let b = reg.register(key, 16, true, false);
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
            false,
            false,
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

    #[test]
    fn explicit_port_reservation_is_visible_to_bind_and_releases_cleanly() {
        let reg = InZoneRegistry::default();
        let scope = InZoneScope::CarrierHost;
        assert!(!reg.port_in_use(&scope, 49466));
        let port = reg
            .try_claim_bound_port(
                &scope,
                "127.0.0.1:49466".parse().unwrap(),
                false,
                false,
                false,
            )
            .unwrap();
        assert_eq!(port.port().raw(), 49466);
        assert!(reg.port_in_use(&scope, 49466));
        reg.release_port(port);
        assert!(!reg.port_in_use(&scope, 49466));
    }

    #[test]
    fn opaque_leases_do_not_release_a_newer_claim() {
        let reg = InZoneRegistry::default();
        let scope = InZoneScope::CarrierHost;
        let first = reg
            .try_claim_bound_port(
                &scope,
                "127.0.0.1:49467".parse().unwrap(),
                false,
                true,
                false,
            )
            .unwrap();
        let second = reg
            .try_claim_bound_port(
                &scope,
                "127.0.0.1:49467".parse().unwrap(),
                false,
                true,
                false,
            )
            .unwrap();
        reg.release_port(first);
        assert!(
            reg.port_in_use(&scope, 49467),
            "the second authenticated claim remains"
        );
        reg.release_port(second);
        assert!(!reg.port_in_use(&scope, 49467));
    }

    #[test]
    fn explicit_pending_claim_blocks_ephemeral_allocation_and_rolls_back() {
        let reg = InZoneRegistry::default();
        let scope = InZoneScope::CarrierHost;
        let pending = reg
            .try_claim_bound_port(
                &scope,
                "127.0.0.1:32768".parse().unwrap(),
                false,
                false,
                false,
            )
            .unwrap();
        let allocated = reg.allocate_ephemeral(&scope, AddrFamily::V4).unwrap();
        assert_ne!(allocated.port().raw(), 32768);
        reg.release_port(pending);
        reg.release_port(allocated);
        let recycled = reg.allocate_ephemeral(&scope, AddrFamily::V4).unwrap();
        assert_eq!(
            recycled.port().raw(),
            32770,
            "allocation cursor stays monotonic after rollback"
        );
        reg.release_port(recycled);
    }

    #[test]
    fn v4_and_v6_claims_with_the_same_port_are_independent() {
        let reg = InZoneRegistry::default();
        let scope = InZoneScope::CarrierHost;
        let v4 = reg
            .try_claim_bound_port(
                &scope,
                "127.0.0.1:49468".parse().unwrap(),
                false,
                false,
                false,
            )
            .unwrap();
        let v6 = reg
            .try_claim_bound_port(&scope, "[::1]:49468".parse().unwrap(), false, false, false)
            .unwrap();
        reg.release_port(v4);
        assert!(reg.port_in_use(&scope, 49468));
        reg.release_port(v6);
    }

    #[test]
    fn reuse_requires_opt_in_from_every_conflicting_binding() {
        let reg = InZoneRegistry::default();
        let scope = InZoneScope::CarrierHost;
        let exclusive = reg
            .try_claim_bound_port(
                &scope,
                "127.0.0.1:49469".parse().unwrap(),
                false,
                false,
                false,
            )
            .unwrap();
        assert!(
            reg.try_claim_bound_port(
                &scope,
                "127.0.0.1:49469".parse().unwrap(),
                true,
                false,
                false
            )
            .is_none()
        );
        reg.release_port(exclusive);
        let first_reuse = reg
            .try_claim_bound_port(
                &scope,
                "127.0.0.1:49469".parse().unwrap(),
                false,
                true,
                false,
            )
            .unwrap();
        let second_reuse = reg
            .try_claim_bound_port(
                &scope,
                "127.0.0.1:49469".parse().unwrap(),
                false,
                true,
                false,
            )
            .expect("both bindings opted into reuse");
        reg.release_port(first_reuse);
        reg.release_port(second_reuse);
    }

    #[test]
    fn reuseaddr_allows_only_another_reuseaddr_or_combined_reuseport_binding() {
        let reg = InZoneRegistry::default();
        let scope = InZoneScope::CarrierHost;
        let first = reg
            .try_claim_bound_port(
                &scope,
                "127.0.0.1:49473".parse().unwrap(),
                true,
                false,
                false,
            )
            .unwrap();
        assert!(
            reg.try_claim_bound_port(
                &scope,
                "127.0.0.1:49473".parse().unwrap(),
                false,
                true,
                false
            )
            .is_none()
        );
        let combined = reg
            .try_claim_bound_port(
                &scope,
                "127.0.0.1:49473".parse().unwrap(),
                true,
                true,
                false,
            )
            .expect("both sockets carry SO_REUSEADDR");
        reg.release_port(first);
        reg.release_port(combined);
    }

    #[test]
    fn reuseaddr_bind_cannot_overlap_an_active_listener() {
        let reg = InZoneRegistry::default();
        let scope = InZoneScope::CarrierHost;
        let addr: SocketAddr = "127.0.0.1:49476".parse().unwrap();
        let listener = reg.register(
            InZoneListenerKey {
                scope: scope.clone(),
                addr: GuestSocketAddr(addr),
            },
            8,
            false,
            false,
        );
        assert!(
            reg.try_claim_bound_port(&scope, addr, true, false, false)
                .is_none(),
            "SO_REUSEADDR does not admit a bind after the endpoint is listening",
        );
        reg.unregister(&listener);
        let lease = reg
            .try_claim_bound_port(&scope, addr, true, false, false)
            .expect("closing the listener releases bind admission");
        reg.release_port(lease);
    }

    #[test]
    fn port_zero_bind_admission_keeps_the_actual_wildcard_bind_address() {
        let reg = InZoneRegistry::default();
        let scope = InZoneScope::CarrierHost;
        let lease = reg
            .allocate_ephemeral_for_bind(
                &scope,
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                false,
                false,
                false,
            )
            .unwrap();
        let port = lease.port().raw();
        assert!(reg.owns_endpoint(
            &scope,
            GuestSocketAddr(format!("127.0.0.1:{port}").parse().unwrap())
        ));
        reg.release_port(lease);
    }

    #[test]
    fn port_zero_admission_applies_reuse_intent_before_host_bind() {
        let reg = InZoneRegistry::default();
        let scope = InZoneScope::CarrierHost;
        let first = reg
            .allocate_ephemeral_for_bind(
                &scope,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                true,
                false,
                false,
            )
            .unwrap();
        let same_port =
            std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), first.port().raw());
        let second = reg
            .try_claim_bound_port(&scope, same_port, true, false, false)
            .expect("the pending port-zero claim carries SO_REUSEADDR");
        reg.release_port(first);
        reg.release_port(second);
    }

    #[test]
    fn dual_stack_wildcard_blocks_ipv4_but_v6only_does_not() {
        let reg = InZoneRegistry::default();
        let scope = InZoneScope::CarrierHost;
        let dual = reg
            .try_claim_bound_port(&scope, "[::]:49472".parse().unwrap(), false, false, false)
            .unwrap();
        assert!(
            reg.try_claim_bound_port(
                &scope,
                "127.0.0.1:49472".parse().unwrap(),
                false,
                false,
                false
            )
            .is_none()
        );
        reg.release_port(dual);
        let v6only = reg
            .try_claim_bound_port(&scope, "[::]:49472".parse().unwrap(), false, false, true)
            .unwrap();
        let v4 = reg
            .try_claim_bound_port(
                &scope,
                "127.0.0.1:49472".parse().unwrap(),
                false,
                false,
                false,
            )
            .expect("v6-only wildcard does not own IPv4");
        reg.release_port(v6only);
        reg.release_port(v4);
    }

    #[test]
    fn v6only_wildcard_does_not_resolve_ipv4_connect() {
        let reg = InZoneRegistry::default();
        let scope = InZoneScope::CarrierHost;
        let listener = reg.register(
            InZoneListenerKey {
                scope: scope.clone(),
                addr: GuestSocketAddr("[::]:49477".parse().unwrap()),
            },
            8,
            false,
            true,
        );

        assert!(
            reg.resolve(&scope, GuestSocketAddr("127.0.0.1:49477".parse().unwrap()))
                .is_none(),
            "an IPV6_V6ONLY wildcard must not receive IPv4 connects"
        );
        assert!(Arc::ptr_eq(
            &reg.resolve(&scope, GuestSocketAddr("[::1]:49477".parse().unwrap()))
                .expect("v6 wildcard still accepts IPv6"),
            &listener
        ));
        reg.unregister(&listener);
    }

    #[test]
    fn mapped_v6_listener_resolves_its_ipv4_peer() {
        let reg = InZoneRegistry::default();
        let scope = InZoneScope::CarrierHost;
        let listener = reg.register(
            InZoneListenerKey {
                scope: scope.clone(),
                addr: GuestSocketAddr("[::ffff:127.0.0.1]:49478".parse().unwrap()),
            },
            8,
            false,
            false,
        );

        assert!(Arc::ptr_eq(
            &reg.resolve(&scope, GuestSocketAddr("127.0.0.1:49478".parse().unwrap()))
                .expect("a mapped-v6 listener owns its IPv4 peer"),
            &listener
        ));
        reg.unregister(&listener);
    }

    #[test]
    fn dual_stack_guest_owned_endpoint_refuses_an_ipv4_connect() {
        let reg = InZoneRegistry::default();
        let scope = InZoneScope::CarrierHost;
        let dual = reg
            .try_claim_bound_port(&scope, "[::]:49475".parse().unwrap(), false, false, false)
            .unwrap();
        assert!(reg.owns_endpoint(&scope, GuestSocketAddr("127.0.0.1:49475".parse().unwrap())));
        reg.release_port(dual);
    }

    #[test]
    fn mapped_v6_bind_conflicts_with_its_ipv4_peer() {
        let reg = InZoneRegistry::default();
        let scope = InZoneScope::CarrierHost;
        let mapped = reg
            .try_claim_bound_port(
                &scope,
                "[::ffff:127.0.0.1]:49474".parse().unwrap(),
                false,
                false,
                false,
            )
            .unwrap();
        assert!(
            reg.try_claim_bound_port(
                &scope,
                "127.0.0.1:49474".parse().unwrap(),
                false,
                false,
                false
            )
            .is_none()
        );
        reg.release_port(mapped);
    }
}
