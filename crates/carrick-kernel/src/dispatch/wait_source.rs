//! Where a guest fd's readiness comes from while it is parked in a wait.
//!
//! One [`WaitRegistration`] per guest fd fuses the host target and the exact
//! [`FileSlotAuthority`] that used to live in two independently-built lists
//! joined by a single `logical_interest` scalar. Nothing correlated entry `i`
//! of one list with entry `j` of the other, so the post-enrollment readiness
//! probe — the only thing that closes the window between a syscall's own
//! readiness check and the wait service's enrollment — ran with a fabricated
//! interest, or not at all. Three lost-wake hangs in one day came from that
//! scalar reading `0`.
//!
//! The invariants are types, not comments:
//!
//! * a [`WaitInterest`] cannot be empty, so "a description-backed registration
//!   with no events to probe" is unrepresentable;
//! * [`WaitSource::Host`] carries no interest, so "a host registration for an
//!   fd whose readiness the description decides" is unrepresentable;
//! * [`HostProxyCoverage`] exists only inside [`WaitSource::Dual`], so
//!   "complete host coverage with no host descriptor" is unrepresentable;
//! * a [`WatchedSlot`] carries no interest, so "probe a watched slot" is
//!   unrepresentable.

use carrick_abi::{LinuxEpollEvents, LinuxPollEvents};

use crate::dispatch::abi_args::{Fd, HostFd};
use crate::kernel::objects::FileSlotAuthority;

/// The poll interest a description-backed source is probed with. NEVER empty:
/// an empty interest is the state that produced three lost-wake hangs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WaitInterest(LinuxPollEvents);

impl WaitInterest {
    /// `None` for an empty set. There is no other constructor.
    pub(crate) fn new(events: LinuxPollEvents) -> Option<Self> {
        if events.is_empty() {
            None
        } else {
            Some(Self(events))
        }
    }

    pub(crate) const fn events(self) -> LinuxPollEvents {
        self.0
    }

    /// The epoll spelling `OpenDescription::readiness` takes.
    pub(crate) const fn epoll(self) -> LinuxEpollEvents {
        self.0.to_epoll()
    }
}

/// A host descriptor the reactor parks on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HostWaitTarget {
    fd: HostFd,
    events: LinuxPollEvents,
}

impl HostWaitTarget {
    pub(crate) const fn new(fd: HostFd, events: LinuxPollEvents) -> Self {
        Self { fd, events }
    }

    pub(crate) const fn fd(self) -> HostFd {
        self.fd
    }

    pub(crate) const fn events(self) -> LinuxPollEvents {
        self.events
    }
}

/// Whether a [`WaitSource::Dual`] host descriptor is a COMPLETE latched mirror
/// of the description's readiness, or only observes host-crossing producers.
///
/// `LatchedLevelTriggered` is the ONLY exemption from the post-enrollment
/// probe, and every construction site owes a test that proves the latch: the
/// producer fires in the gap and the host descriptor ALONE reports the waiter
/// ready. Absent that proof a site is `HostPeersOnly` and takes the probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostProxyCoverage {
    /// An in-memory pipe or eventfd readiness pipe, or an epoll instance's
    /// `EVFILT_USER` wake: level-triggered, so a gap edge leaves the host
    /// descriptor readable and the reactor reports it.
    LatchedLevelTriggered,
    /// An in-zone listener's Darwin listen socket: a connection paired in-zone
    /// never touches it, so the description must still be probed.
    HostPeersOnly,
}

/// Where one guest fd's readiness comes from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WaitSource {
    /// The host descriptor both wakes the reactor and decides guest-visible
    /// readiness; its revents are the answer verbatim.
    Host { host: HostWaitTarget },
    /// No host object: the description's wait queue is the only wake source.
    Description { interest: WaitInterest },
    /// Both, with typed coverage.
    Dual {
        host: HostWaitTarget,
        interest: WaitInterest,
        coverage: HostProxyCoverage,
    },
}

impl WaitSource {
    /// `Some` exactly when the wait service must enroll on the description's
    /// wait queue; `None` for a pure host source.
    pub(crate) const fn description_interest(&self) -> Option<WaitInterest> {
        match self {
            Self::Host { .. } => None,
            Self::Description { interest } | Self::Dual { interest, .. } => Some(*interest),
        }
    }

    /// `true` when the post-enrollment probe is required.
    pub(crate) const fn probe_after_enrol(&self) -> bool {
        match self {
            Self::Host { .. } => false,
            Self::Description { .. } => true,
            Self::Dual { coverage, .. } => matches!(coverage, HostProxyCoverage::HostPeersOnly),
        }
    }

    pub(crate) const fn host(&self) -> Option<HostWaitTarget> {
        match self {
            Self::Host { host } | Self::Dual { host, .. } => Some(*host),
            Self::Description { .. } => None,
        }
    }
}

/// One guest fd's participation in a wait: the fd the caller named, the exact
/// slot captured at admission, the events the guest requested, and the source
/// that decides readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitRegistration {
    guest_fd: Fd,
    slot: FileSlotAuthority,
    requested: LinuxPollEvents,
    source: WaitSource,
}

impl WaitRegistration {
    pub(crate) const fn new(
        guest_fd: Fd,
        slot: FileSlotAuthority,
        requested: LinuxPollEvents,
        source: WaitSource,
    ) -> Self {
        Self {
            guest_fd,
            slot,
            requested,
            source,
        }
    }

    #[allow(dead_code)]
    pub(crate) const fn guest_fd(&self) -> Fd {
        self.guest_fd
    }

    pub(crate) const fn slot(&self) -> FileSlotAuthority {
        self.slot
    }

    #[allow(dead_code)]
    pub(crate) const fn requested(&self) -> LinuxPollEvents {
        self.requested
    }

    pub(crate) const fn source(&self) -> WaitSource {
        self.source
    }
}

/// An advisory slot: re-dispatch when the slot is replaced, never probed.
///
/// `epoll_pwait`'s interest targets exist to force a re-dispatch when a
/// registered fd's slot is replaced. They carry no requested events anywhere
/// in the code — the mask lives in the epoll registration — so there is no
/// interest to probe with, and this type has nowhere to put one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WatchedSlot(FileSlotAuthority);

impl WatchedSlot {
    pub(crate) const fn new(slot: FileSlotAuthority) -> Self {
        Self(slot)
    }

    pub(crate) const fn slot(self) -> FileSlotAuthority {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_target() -> HostWaitTarget {
        HostWaitTarget::new(HostFd(9), LinuxPollEvents::IN)
    }

    fn interest() -> WaitInterest {
        WaitInterest::new(LinuxPollEvents::IN).expect("POLLIN is not empty")
    }

    /// The one constructor refuses the state that lost three wakes.
    #[test]
    fn wait_interest_rejects_empty_events() {
        assert_eq!(WaitInterest::new(LinuxPollEvents::empty()), None);
        assert_eq!(
            WaitInterest::new(LinuxPollEvents::IN).map(WaitInterest::events),
            Some(LinuxPollEvents::IN)
        );
        assert_eq!(
            WaitInterest::new(LinuxPollEvents::OUT)
                .map(WaitInterest::epoll)
                .expect("POLLOUT"),
            LinuxEpollEvents::OUT
        );
    }

    /// A host source has no interest FIELD, so the wait service cannot enroll
    /// or probe on it even by mistake.
    #[test]
    fn host_source_has_no_description_interest() {
        let source = WaitSource::Host {
            host: host_target(),
        };
        assert_eq!(source.description_interest(), None);
        assert!(!source.probe_after_enrol());
        assert_eq!(source.host(), Some(host_target()));
    }

    /// A description source has no host FIELD, so it contributes no reactor
    /// entry — the `-1` sentinel has nowhere to live — and it is always probed.
    #[test]
    fn description_source_has_no_host_target_and_is_always_probed() {
        let source = WaitSource::Description {
            interest: interest(),
        };
        assert_eq!(source.host(), None);
        assert_eq!(source.description_interest(), Some(interest()));
        assert!(source.probe_after_enrol());
    }

    /// `Dual` is the only variant with both halves, and the only one that can
    /// name coverage.
    #[test]
    fn dual_source_requires_both_a_host_target_and_an_interest() {
        for coverage in [
            HostProxyCoverage::LatchedLevelTriggered,
            HostProxyCoverage::HostPeersOnly,
        ] {
            let source = WaitSource::Dual {
                host: host_target(),
                interest: interest(),
                coverage,
            };
            assert_eq!(source.host(), Some(host_target()));
            assert_eq!(source.description_interest(), Some(interest()));
        }
    }

    /// Latched coverage is the ONLY probe exemption for a description-bearing
    /// source, and it exists only where a host descriptor does.
    #[test]
    fn latched_coverage_is_unrepresentable_without_a_host_target() {
        let latched = WaitSource::Dual {
            host: host_target(),
            interest: interest(),
            coverage: HostProxyCoverage::LatchedLevelTriggered,
        };
        let peers_only = WaitSource::Dual {
            host: host_target(),
            interest: interest(),
            coverage: HostProxyCoverage::HostPeersOnly,
        };
        assert!(
            !latched.probe_after_enrol(),
            "a latched level-triggered host descriptor already reports a gap edge"
        );
        assert!(
            peers_only.probe_after_enrol(),
            "a host descriptor that only sees host peers cannot cover an in-zone producer"
        );
        // Every source that names coverage has a host target: there is no
        // `Description { coverage }` to construct.
        assert!(latched.host().is_some());
        assert!(peers_only.host().is_some());
    }
}
