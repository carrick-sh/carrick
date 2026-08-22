//! The guest's network and UTS namespaces, as kernel objects owned by tasks.
//!
//! Both answer questions the host has no standing to answer. Which interfaces
//! exist, which addresses they carry, what the machine is called: on Linux those
//! are properties of a namespace, and two processes in different namespaces get
//! different answers to the same syscall. Darwin has exactly one of each, so
//! every guest-facing surface that reached for `getifaddrs(3)` or
//! `gethostname(3)` was answering a namespace question with a machine answer —
//! and under HVPatch there is only ONE machine behind every guest process at
//! once.
//!
//! The two objects were previously wrong in OPPOSITE directions, which is why
//! they are fixed together:
//!
//! - The network view was carrier-global: one `Arc<RuntimeNetwork>` on the
//!   dispatcher, so no guest process could ever hold a different one. There was
//!   nowhere for `unshare(CLONE_NEWNET)` to write.
//! - The UTS view was fork-COPIED: `ProcState.guest_hostname` was a `String`
//!   the fork path cloned, so a parent's `sethostname` was invisible to its
//!   children. Linux shares one `uts_namespace` across `fork`, and the child
//!   sees the new name.
//!
//! Both land on the same shape, which is Linux's own: the task holds an `Arc` to
//! a namespace OBJECT. `fork` clones the pointer (so the object is shared and a
//! change on either side is visible to both), and `unshare` replaces this task's
//! pointer only (so one process moves and its relatives do not).

use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwap;
use parking_lot::Mutex;

use crate::namespace::{INITIAL_NET_NS, INITIAL_UTS_NS, NsId};
use crate::network::model::{HostWireSnapshot, LinuxNetworkModel};

/// A network namespace: an identity plus the interface/address/route/resolver
/// view every guest-facing network surface renders from.
///
/// [`LinuxNetworkModel`] IS the view — deliberately the same type the container
/// modes already build from the spec, so there is one description of "what the
/// guest's network looks like" rather than one per surface. There were FOUR
/// independently-written host→Linux uplink mappings, and they disagreed with
/// each other in the guest: rtnetlink advertised `eth0` with a hardware address
/// while `/sys/class/net/eth0` was ENOENT, because each surface derived its own
/// answer from its own `getifaddrs` walk. This retires two of them (rtnetlink
/// and `/sys/class/net`); the `SIOC*` ioctls in `dispatch/fs.rs` and the
/// `/proc/net/*` renderers in `vfs/proc.rs` still carry theirs and are the next
/// consumers to move.
///
/// The view sits behind [`ArcSwap`] rather than a lock because reading it is on
/// the guest's syscall path — every `/proc/net` read, every netlink dump — while
/// writing it is rare (namespace setup, and eventually a host route-change
/// event). A lock here would let a writer stall a guest syscall; RCU cannot.
#[derive(Debug)]
pub struct NetNs {
    id: NsId,
    view: ArcSwap<LinuxNetworkModel>,
}

impl NetNs {
    /// A namespace whose view is the one this spec describes — the container
    /// modes, where carrick assigns the addresses and therefore knows them
    /// exactly.
    pub(crate) fn from_model(id: NsId, model: LinuxNetworkModel) -> Self {
        Self {
            id,
            view: ArcSwap::new(Arc::new(model)),
        }
    }

    /// This namespace's id — the number `/proc/<pid>/ns/net` reports, and the
    /// only way to ask whether two tasks are in the SAME namespace.
    pub fn id(&self) -> NsId {
        self.id
    }

    /// The current view, as one coherent snapshot.
    ///
    /// A hazard-pointer load, not a lock: see the type comment. Callers must
    /// take this ONCE and read every field from the result, so a concurrent
    /// republication cannot show them links from one generation and addresses
    /// from the next.
    pub(crate) fn view(&self) -> arc_swap::Guard<Arc<LinuxNetworkModel>> {
        self.view.load()
    }

    /// Publish a new view for every task in this namespace at once.
    pub(crate) fn publish(&self, model: LinuxNetworkModel) {
        self.view.store(Arc::new(model));
    }
}

/// A UTS namespace: the nodename `uname(2)`, `/proc/sys/kernel/hostname` and the
/// `/etc/hosts` self-mapping report. (`setdomainname` is unconditional EPERM and
/// nothing renders a domainname, so there is none to hold yet; it belongs here
/// when there is.)
///
/// A `Mutex` and not `ArcSwap` because the name is a small string read far less
/// often than the network view — `uname` is not a hot path — and because
/// `sethostname` is a plain replacement with no read-modify-write to serialize.
#[derive(Debug)]
pub struct UtsNs {
    id: NsId,
    nodename: Mutex<String>,
}

impl UtsNs {
    pub(crate) fn new(id: NsId, nodename: impl Into<String>) -> Self {
        Self {
            id,
            nodename: Mutex::new(nodename.into()),
        }
    }

    /// This namespace's id — the number `/proc/<pid>/ns/uts` reports, and the
    /// only way to ask whether two tasks share a hostname.
    pub fn id(&self) -> NsId {
        self.id
    }

    pub fn nodename(&self) -> String {
        self.nodename.lock().clone()
    }

    /// Name the namespace. The write is visible to every task in it, including
    /// children forked before the call — which is the whole point, and what the
    /// per-process `String` this replaces could not do.
    ///
    /// Permission is the CALLER's business, not this object's: `sethostname(2)`
    /// needs CAP_SYS_ADMIN in the namespace's user namespace, while run setup
    /// naming the root namespace needs nothing. The guest-facing `sethostname`
    /// is still unconditional EPERM in `dispatch/proc.rs` and gains that check
    /// when it moves onto this.
    pub fn set_nodename(&self, nodename: impl Into<String>) {
        *self.nodename.lock() = nodename.into();
    }
}

/// The set of namespaces a task belongs to — Linux's `nsproxy`.
///
/// One immutable struct replaced wholesale rather than a field per namespace,
/// because `unshare(CLONE_NEWNET | CLONE_NEWUTS)` moves a task into both at once
/// and no reader may observe it half-moved.
#[derive(Debug, Clone)]
pub(crate) struct NsProxy {
    net: Arc<NetNs>,
    uts: Arc<UtsNs>,
}

impl NsProxy {
    pub(crate) fn net(&self) -> &Arc<NetNs> {
        &self.net
    }

    pub(crate) fn uts(&self) -> &Arc<UtsNs> {
        &self.uts
    }

    /// The proxy a task holds after moving into `uts`, keeping every other
    /// namespace it was already in.
    pub(crate) fn entering_uts(&self, uts: Arc<UtsNs>) -> Self {
        Self {
            net: Arc::clone(&self.net),
            uts,
        }
    }

    /// The proxy a task holds after moving into `net`, keeping every other
    /// namespace it was already in.
    pub(crate) fn entering_net(&self, net: Arc<NetNs>) -> Self {
        Self {
            net,
            uts: Arc::clone(&self.uts),
        }
    }
}

impl Default for NsProxy {
    /// A fresh task starts in the ROOT namespaces, which is what Linux does for
    /// everything descended from init and what carrick needs for the root task —
    /// it is created before the run spec has been applied.
    fn default() -> Self {
        Self {
            net: Arc::clone(root_net_ns()),
            uts: Arc::clone(root_uts_ns()),
        }
    }
}

/// The carrier's initial network namespace.
///
/// Carrier-wide, for the same reason [`crate::namespace::process::alloc_ns_id`]
/// is: the ROOT namespace is one identity that every task starts in, not a
/// per-task value. Tasks that leave it hold their own `Arc` and are unaffected
/// by anything published here.
///
/// It seeds itself by MIRRORING the host's wire, because carrick's default lane
/// is `--net host`, where the guest genuinely shares the host's connectivity.
/// That probe is the one legitimate SHAPE for `getifaddrs` — asking the host
/// what the WIRE can do, ONCE, with the answer then living in the namespace and
/// every guest-facing surface reading the namespace. (Two guest-facing
/// `getifaddrs` view derivations remain, in `dispatch/fs.rs` for `SIOC*` and
/// `vfs/proc.rs` for `/proc/net/*`; they move onto this probe next.) The
/// distinction is not academic —
/// re-deriving the view per guest call meant the guest's `eth0` address changed
/// underneath a running daemon when the Mac renewed a DHCP lease or raised a
/// VPN `utun`, so a process that cached its address and one that re-read it
/// disagreed within one program.
pub(crate) fn root_net_ns() -> &'static Arc<NetNs> {
    static ROOT: OnceLock<Arc<NetNs>> = OnceLock::new();
    ROOT.get_or_init(|| {
        Arc::new(NetNs::from_model(
            INITIAL_NET_NS,
            LinuxNetworkModel::host_mirror(&HostWireSnapshot::probe()),
        ))
    })
}

/// The carrier's initial UTS namespace.
///
/// Seeded from the host's own short hostname because that is carrick's
/// `--net host` contract — the guest shares the host's network identity — and
/// then OVERWRITTEN by [`publish_root_nodename`] when the run names itself. The
/// host is the authority for the seed and for nothing after it: every read goes
/// to the namespace, so a guest's `sethostname` sticks and its children see it.
pub(crate) fn root_uts_ns() -> &'static Arc<UtsNs> {
    static ROOT: OnceLock<Arc<UtsNs>> = OnceLock::new();
    ROOT.get_or_init(|| {
        let seed = carrick_host::host_facts::host_short_hostname()
            .unwrap_or(crate::linux_abi::CARRICK_HOSTNAME);
        Arc::new(UtsNs::new(INITIAL_UTS_NS, seed))
    })
}

/// Install the run's own network view into the root namespace, replacing the
/// host mirror the root seeded itself with.
///
/// Called once at run setup for the container modes, where carrick assigns the
/// addresses. Publication rather than construction because the root namespace
/// object is shared: a task that already holds it sees the new view without
/// having to be told.
pub(crate) fn publish_root_net_view(model: LinuxNetworkModel) {
    root_net_ns().publish(model);
}

/// Set the root namespace's nodename to the run's configured hostname
/// (`--hostname`, or the container name), overriding the host-derived seed.
pub(crate) fn publish_root_nodename(nodename: &str) {
    root_uts_ns().set_nodename(nodename);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace::process::alloc_ns_id;
    use crate::network::model::{HostWireInterface, LinuxNetworkLink};
    use carrick_abi::{LINUX_IFF_RUNNING, LINUX_IFF_UP};
    use std::net::{IpAddr, Ipv4Addr};

    fn with_uplink(name: &str) -> LinuxNetworkModel {
        let mut model = LinuxNetworkModel::isolated();
        model.links.push(LinuxNetworkLink::uplink(
            2,
            name.to_string(),
            [0x02, 0, 0, 0, 0, 2],
        ));
        model
    }

    /// Two tasks in different network namespaces get different answers to the
    /// same question. A carrier-global `Arc<RuntimeNetwork>` could not express
    /// this at all, which is why `unshare(CLONE_NEWNET)` had nowhere to write.
    #[test]
    fn two_net_namespaces_answer_the_same_question_differently() {
        let isolated = NetNs::from_model(alloc_ns_id(), LinuxNetworkModel::isolated());
        let connected = NetNs::from_model(alloc_ns_id(), with_uplink("eth0"));

        let names = |ns: &NetNs| {
            ns.view()
                .links
                .iter()
                .map(|link| link.name.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(&isolated), ["lo"]);
        assert_eq!(names(&connected), ["lo", "eth0"]);
        assert_ne!(isolated.id(), connected.id());
    }

    /// Republishing reaches every task already in the namespace without any of
    /// them being touched — what lets the root namespace seed itself from the
    /// host wire before the run spec is known and be corrected afterwards.
    #[test]
    fn republishing_a_view_reaches_holders_of_the_namespace() {
        let ns = Arc::new(NetNs::from_model(
            alloc_ns_id(),
            LinuxNetworkModel::isolated(),
        ));
        let already_holding = Arc::clone(&ns);
        assert_eq!(already_holding.view().links.len(), 1);

        ns.publish(with_uplink("eth0"));

        assert_eq!(already_holding.view().links.len(), 2);
    }

    /// The host mirror names and indexes links the way LINUX does, and hands
    /// the guest none of the Mac's own paraphernalia.
    ///
    /// Every clause here is a shipped defect: `/sys/class/net` listed `awdl0`
    /// and `utun0` while rtnetlink listed `eth0`; the uplink carried the Mac's
    /// IPv6, so libuv RAN `udp_multicast_join6` where Linux skips it; and
    /// loopback carried macOS `lo0`'s `fe80::1`, which no Linux loopback has.
    #[test]
    fn the_host_mirror_shows_a_linux_namespace_not_a_mac() {
        let wire = HostWireSnapshot {
            interfaces: vec![
                HostWireInterface {
                    name: "lo0".to_string(),
                    flags: LINUX_IFF_UP | LINUX_IFF_RUNNING,
                    loopback: true,
                    v4_addresses: vec![(Ipv4Addr::LOCALHOST, 8)],
                    ..HostWireInterface::default()
                },
                HostWireInterface {
                    name: "awdl0".to_string(),
                    flags: LINUX_IFF_UP | LINUX_IFF_RUNNING,
                    v4_addresses: vec![(Ipv4Addr::new(169, 254, 1, 1), 16)],
                    ..HostWireInterface::default()
                },
                HostWireInterface {
                    name: "en0".to_string(),
                    flags: LINUX_IFF_UP | LINUX_IFF_RUNNING,
                    hw_addr: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                    v4_addresses: vec![(Ipv4Addr::new(10, 14, 14, 189), 24)],
                    ..HostWireInterface::default()
                },
            ],
            loopback_has_v6_localhost: true,
        };

        let view = LinuxNetworkModel::host_mirror(&wire);

        assert_eq!(
            view.links
                .iter()
                .map(|link| (link.name.as_str(), link.index))
                .collect::<Vec<_>>(),
            [("lo", 1), ("eth0", 2)],
            "the guest sees a Linux namespace, not the Mac's interface list"
        );
        assert_eq!(
            view.link_by_name("eth0").expect("uplink").hw_addr,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            "the uplink keeps the wire's hardware address"
        );
        assert!(
            !view.link_carries("eth0", true),
            "an uplink must carry no IPv6: {:?}",
            view.addresses
        );
        assert!(
            view.addresses.iter().all(|address| !matches!(
                address.addr,
                IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80
            )),
            "no fe80:: address may reach the guest: {:?}",
            view.addresses
        );
        assert!(
            view.link_carries("lo", true) && view.link_carries("lo", false),
            "loopback keeps 127.0.0.1 and ::1: {:?}",
            view.addresses
        );
        assert!(view.addresses.iter().any(|address| address.addr
            == IpAddr::V4(Ipv4Addr::new(10, 14, 14, 189))
            && address.link_name == "eth0"));
    }

    /// A host with no usable uplink yields a coherent loopback-only namespace
    /// rather than a fabricated address the host does not own.
    #[test]
    fn a_host_with_no_uplink_mirrors_to_loopback_only() {
        let wire = HostWireSnapshot {
            interfaces: vec![HostWireInterface {
                name: "lo0".to_string(),
                flags: LINUX_IFF_UP | LINUX_IFF_RUNNING,
                loopback: true,
                v4_addresses: vec![(Ipv4Addr::LOCALHOST, 8)],
                ..HostWireInterface::default()
            }],
            loopback_has_v6_localhost: false,
        };

        assert_eq!(
            LinuxNetworkModel::host_mirror(&wire)
                .links
                .iter()
                .map(|link| link.name.as_str())
                .collect::<Vec<_>>(),
            ["lo"]
        );
    }
}
