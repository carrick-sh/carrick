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

use std::sync::Arc;

use super::container::Container;

use arc_swap::ArcSwap;
use parking_lot::Mutex;

use crate::namespace::NsId;
use crate::network::model::LinuxNetworkModel;

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
    #[cfg(test)]
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
    /// The container this task is a member of — the slot Linux's `nsproxy`
    /// reserves for `pid_ns_for_children`/`mnt_ns`, generalized to the
    /// kernel-graph object that owns this task's pid-namespace root, rootfs,
    /// clock domain and run identity. Reached only through the task: there is
    /// no static naming "the" container, because a carrier may hold several.
    container: Arc<Container>,
}

impl NsProxy {
    /// The proxy a fresh task holds: this container's initial network and UTS
    /// namespaces (what Linux gives everything descended from its init).
    pub(crate) fn for_container(container: Arc<Container>) -> Self {
        Self {
            net: Arc::clone(container.net_ns()),
            uts: Arc::clone(container.uts_ns()),
            container,
        }
    }

    pub(crate) fn net(&self) -> &Arc<NetNs> {
        &self.net
    }

    pub(crate) fn uts(&self) -> &Arc<UtsNs> {
        &self.uts
    }

    pub(crate) fn container(&self) -> &Arc<Container> {
        &self.container
    }

    /// The proxy a task holds after moving into `uts`, keeping every other
    /// namespace it was already in.
    pub(crate) fn entering_uts(&self, uts: Arc<UtsNs>) -> Self {
        Self {
            net: Arc::clone(&self.net),
            uts,
            container: Arc::clone(&self.container),
        }
    }

    /// The proxy a task holds after moving into `net`, keeping every other
    /// namespace it was already in.
    pub(crate) fn entering_net(&self, net: Arc<NetNs>) -> Self {
        Self {
            net,
            uts: Arc::clone(&self.uts),
            container: Arc::clone(&self.container),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::{Container, Kernel, LaunchContext, RootBootstrap, RunId};
    use crate::namespace::process::alloc_ns_id;
    use crate::network::model::{HostWireInterface, HostWireSnapshot, LinuxNetworkLink};
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

    /// Booting a second container must not rename or replace the network view
    /// of a task that was already published in the shared carrier graph.
    ///
    /// The production regression this catches is cloning both task nsproxies
    /// from the carrier-global root cells: beta's launch publication then
    /// changes alpha's already-live `uname`, `/sys`, rtnetlink and `/proc/net`
    /// source objects in place.
    #[test]
    fn containers_do_not_share_root_uts_or_net() {
        let alpha_container = Arc::new(
            Container::new(LaunchContext::unmanaged(RunId::new("namespace-alpha")))
                .with_hostname("alpha-host")
                .with_network_model(with_uplink("alpha0")),
        );
        let alpha_bootstrap = RootBootstrap::for_reference_model(
            7_810,
            carrick_hal::ThreadId::synthetic_for_tests(7_810),
            "namespace-alpha-init".to_owned(),
        )
        .expect("alpha bootstrap")
        .with_container(alpha_container);
        let (kernel, alpha) = Kernel::bootstrap_root(alpha_bootstrap).expect("alpha root");

        let beta_container = Arc::new(
            Container::new(LaunchContext::unmanaged(RunId::new("namespace-beta")))
                .with_hostname("beta-host")
                .with_network_model(with_uplink("beta0")),
        );
        let beta = kernel
            .prepare_container_root(
                carrick_hal::ThreadId::synthetic_for_tests(7_820),
                None,
                "namespace-beta-init".to_owned(),
                beta_container,
                None,
            )
            .expect("prepare beta root")
            .commit()
            .expect("publish beta root");

        assert_eq!(alpha.task().uts_ns().nodename(), "alpha-host");
        assert_eq!(beta.task().uts_ns().nodename(), "beta-host");
        let link_names = |context: &crate::kernel::KernelContext| {
            context
                .task()
                .net_ns()
                .view()
                .links
                .iter()
                .map(|link| link.name.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(link_names(&alpha), ["lo", "alpha0"]);
        assert_eq!(link_names(&beta), ["lo", "beta0"]);
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
