use carrick_abi::{LinuxErrno, LinuxPollEvents};
use serde::Serialize;

use crate::dispatch::abi_args::{Fd, HostFd};
use crate::dispatch::fd_table::HostFdRef;
use crate::dispatch::fifo_beacon::ParkedOpenerToken;
use crate::dispatch::wait_source::{
    HostWaitTarget, WaitInterest, WaitRegistration, WaitSource, WatchedSlot,
};
use crate::dispatch::{DispatchOutcome, SyscallDispatcher};
use crate::io_wait::WaitFd;
use crate::kernel::objects::FileSlotAuthority;
use crate::linux_abi::LINUX_EBADF;

#[derive(Debug, Clone)]
pub(crate) enum WaitFdGuard {
    HostFd(#[allow(dead_code)] HostFdRef),
    ParkedOpener(#[allow(dead_code)] ParkedOpenerToken),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InternalWaitKind {
    CarrierControl,
    /// A blocking FIFO `open` parked on the peer-presence pipe owned by
    /// `fifo_beacon`. The guest has no fd for the FIFO yet, so there is no
    /// exact file description to pin; the parked-opener guard owns the host
    /// state for the wait's lifetime.
    FifoOpen,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InternalWaitAuthority {
    kind: InternalWaitKind,
    generation: u64,
}

/// A guest slot a park pins STRICTLY but whose readiness source the park does
/// not yet name.
///
/// It is the exact pre-migration policy, and nothing more: subscribe the slot,
/// enroll on its description's wait queue, never probe. It carries no interest
/// at all, so it cannot resurrect the scalar this migration deletes — an
/// unclassified slot is a slot whose source is UNKNOWN, not a slot with an
/// empty interest.
///
/// Tasks 4-7 replace every construction with a classified [`WaitRegistration`]
/// (`net.rs`'s `wait_source_for`); the last one to go is
/// `dispatch/net/netlink.rs`'s `WaitFds::raw_one(-1, 0)`, which Task 6 repairs
/// red-first. Task 9's grep deletes this type with the adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UnclassifiedSlot(FileSlotAuthority);

impl UnclassifiedSlot {
    pub(crate) const fn slot(self) -> FileSlotAuthority {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WaitFdAuthority {
    Empty,
    Missing,
    Logical {
        /// One per guest fd whose readiness source the wait names. The host
        /// target and the exact slot live in ONE value, so the wait service
        /// probes each description with that fd's own interest instead of a
        /// scalar folded across the whole wait.
        registrations: Vec<WaitRegistration>,
        /// Strictly pinned slots still awaiting classification (see
        /// [`UnclassifiedSlot`]).
        unclassified: Vec<UnclassifiedSlot>,
        /// Advisory: re-dispatch when the slot is replaced, never probed.
        watched: Vec<WatchedSlot>,
    },
    Internal(InternalWaitAuthority),
}

impl WaitFdAuthority {
    /// A park that pins ONE guest slot and whose readiness source is the wait's
    /// own reactor entry. [`WaitFds::with_authority`] is where the two halves
    /// meet, so the classification happens there; Task 6 replaces these call
    /// sites with `assemble_wait`.
    pub(crate) fn logical(slot: FileSlotAuthority) -> Self {
        Self::Logical {
            registrations: Vec::new(),
            unclassified: vec![UnclassifiedSlot(slot)],
            watched: Vec::new(),
        }
    }

    pub(crate) fn internal(kind: InternalWaitKind) -> Self {
        static NEXT_INTERNAL_WAIT: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(1);
        Self::Internal(InternalWaitAuthority {
            kind,
            generation: NEXT_INTERNAL_WAIT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        })
    }

    /// Every slot the wait is STRICTLY authorised against: a close or reuse of
    /// any of them invalidates the wait. Watched slots are advisory and are
    /// deliberately absent.
    pub(crate) fn strict_slots(&self) -> Vec<FileSlotAuthority> {
        match self {
            Self::Logical {
                registrations,
                unclassified,
                ..
            } => registrations
                .iter()
                .map(WaitRegistration::slot)
                .chain(unclassified.iter().map(|slot| slot.slot()))
                .collect(),
            Self::Empty | Self::Missing | Self::Internal(_) => Vec::new(),
        }
    }

    pub(crate) fn has_strict_slots(&self) -> bool {
        match self {
            Self::Logical {
                registrations,
                unclassified,
                ..
            } => !registrations.is_empty() || !unclassified.is_empty(),
            Self::Empty | Self::Missing | Self::Internal(_) => false,
        }
    }

    /// The union of the interests the wait service will actually probe with.
    /// Empty when every source is a host descriptor or is unclassified.
    #[cfg(test)]
    pub(crate) fn probed_interest_for_test(&self) -> LinuxPollEvents {
        match self {
            Self::Logical { registrations, .. } => registrations
                .iter()
                .filter(|registration| registration.source().probe_after_enrol())
                .filter_map(|registration| registration.source().description_interest())
                .fold(LinuxPollEvents::empty(), |acc, interest| {
                    acc | interest.events()
                }),
            Self::Empty | Self::Missing | Self::Internal(_) => LinuxPollEvents::empty(),
        }
    }
}

/// Classify the slots an ADAPTER captured against the reactor entries the same
/// park built, which is the correlation the two-list shape never had.
///
/// * a `-1` sentinel entry with non-empty events means the park has no host
///   object for those slots: they are [`WaitSource::Description`] and take the
///   post-enrollment probe with exactly those events;
/// * otherwise, when the entries are all host descriptors and line up one-to-one
///   with the slots, each slot is the [`WaitSource::Host`] at its index;
/// * anything else stays an [`UnclassifiedSlot`] — no host target is invented
///   and no interest is fabricated.
///
/// Tasks 4-7 delete this together with the adapters that call it.
fn classify_adapter_slots(
    fds: &[WaitFd],
    slots: Vec<FileSlotAuthority>,
) -> (Vec<WaitRegistration>, Vec<UnclassifiedSlot>) {
    let sentinel = fds
        .iter()
        .filter(|entry| entry.fd() < 0)
        .fold(LinuxPollEvents::empty(), |acc, entry| {
            acc | LinuxPollEvents::from_bits_retain(entry.events())
        });
    if let Some(interest) = WaitInterest::new(sentinel) {
        let registrations = slots
            .into_iter()
            .map(|slot| {
                WaitRegistration::new(
                    Fd(slot.number().raw()),
                    slot,
                    interest.events(),
                    WaitSource::Description { interest },
                )
            })
            .collect();
        return (registrations, Vec::new());
    }
    let all_host = fds.iter().all(|entry| entry.fd() >= 0);
    if all_host && fds.len() == slots.len() {
        let registrations = slots
            .into_iter()
            .zip(fds.iter())
            .map(|(slot, entry)| {
                let events = LinuxPollEvents::from_bits_retain(entry.events());
                WaitRegistration::new(
                    Fd(slot.number().raw()),
                    slot,
                    events,
                    WaitSource::Host {
                        host: HostWaitTarget::new(HostFd(entry.fd()), events),
                    },
                )
            })
            .collect();
        return (registrations, Vec::new());
    }
    (
        Vec::new(),
        slots.into_iter().map(UnclassifiedSlot).collect(),
    )
}

#[derive(Debug, Clone)]
pub struct WaitFds {
    pub(in crate::dispatch) fds: Vec<WaitFd>,
    #[allow(dead_code)]
    pub(in crate::dispatch) guards: Vec<WaitFdGuard>,
    pub(in crate::dispatch) authority: WaitFdAuthority,
}

impl Default for WaitFds {
    fn default() -> Self {
        Self {
            fds: Vec::new(),
            guards: Vec::new(),
            authority: WaitFdAuthority::Empty,
        }
    }
}

impl WaitFds {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn raw(fds: Vec<(i32, i16)>) -> Self {
        let authority = if fds.is_empty() {
            WaitFdAuthority::Empty
        } else {
            WaitFdAuthority::Missing
        };
        Self {
            fds: fds
                .into_iter()
                .map(|(fd, events)| WaitFd::raw(fd, events))
                .collect(),
            guards: Vec::new(),
            authority,
        }
    }

    pub fn raw_one(fd: i32, events: i16) -> Self {
        Self::raw(vec![(fd, events)])
    }

    /// Build the reactor lowering and the authority from ONE list: a `Host` or
    /// `Dual` source contributes its host descriptor, a `Description` source
    /// contributes none. There is no `-1` sentinel to write.
    // Tasks 4-6 route every park through this; until then the adapters below
    // still build the authority from separately captured slots.
    #[allow(dead_code)]
    pub(crate) fn from_registrations(
        registrations: Vec<WaitRegistration>,
        watched: Vec<WatchedSlot>,
    ) -> Result<Self, LinuxErrno> {
        if registrations.is_empty() {
            return Err(LINUX_EBADF);
        }
        let fds = registrations
            .iter()
            .filter_map(|registration| registration.source().host())
            .map(|host| WaitFd::raw(host.fd().get(), host.events().bits()))
            .collect();
        Ok(Self {
            fds,
            guards: Vec::new(),
            authority: WaitFdAuthority::Logical {
                registrations,
                unclassified: Vec::new(),
                watched,
            },
        })
    }

    pub(in crate::dispatch) fn authorized_raw_one(
        fd: i32,
        events: i16,
        authority: WaitFdAuthority,
    ) -> Self {
        Self::raw_one(fd, events).with_authority(authority)
    }

    pub(in crate::dispatch) fn anchored_one(
        fd: i32,
        events: i16,
        owner: Option<HostFdRef>,
    ) -> Self {
        match owner {
            Some(owner) => Self {
                fds: vec![WaitFd::anchored(fd, events)],
                guards: vec![WaitFdGuard::HostFd(owner)],
                authority: WaitFdAuthority::Missing,
            },
            None => Self::raw_one(fd, events),
        }
    }

    pub(in crate::dispatch) fn anchored_parked_opener(
        fd: i32,
        events: i16,
        token: ParkedOpenerToken,
    ) -> Self {
        Self {
            fds: vec![WaitFd::anchored(fd, events)],
            guards: vec![WaitFdGuard::ParkedOpener(token)],
            authority: WaitFdAuthority::internal(InternalWaitKind::FifoOpen),
        }
    }

    pub fn first(&self) -> Option<(i32, i16)> {
        self.fds.first().map(|fd| (fd.fd(), fd.events()))
    }

    /// Task 6 removes this with the last `raw_*` park: it pins slots captured
    /// separately from the reactor list and classifies them against it.
    #[cfg(test)]
    pub(crate) fn with_slot_authorities(mut self, slots: Vec<FileSlotAuthority>) -> Self {
        if self.fds.is_empty() && slots.is_empty() {
            self.authority = WaitFdAuthority::Empty;
        } else {
            let (registrations, unclassified) = classify_adapter_slots(&self.fds, slots);
            self.authority = WaitFdAuthority::Logical {
                registrations,
                unclassified,
                watched: Vec::new(),
            };
        }
        self
    }

    /// Attach an authority. A `Logical` authority built without the reactor
    /// list (`WaitFdAuthority::logical`) is classified here, where both halves
    /// are finally in scope; Task 6 removes that path.
    pub(crate) fn with_authority(mut self, authority: WaitFdAuthority) -> Self {
        self.authority = match authority {
            WaitFdAuthority::Logical {
                mut registrations,
                unclassified,
                watched,
            } if !unclassified.is_empty() => {
                let (classified, still_unclassified) = classify_adapter_slots(
                    &self.fds,
                    unclassified.iter().map(|slot| slot.slot()).collect(),
                );
                registrations.extend(classified);
                WaitFdAuthority::Logical {
                    registrations,
                    unclassified: still_unclassified,
                    watched,
                }
            }
            authority => authority,
        };
        self
    }

    pub(crate) fn authority(&self) -> &WaitFdAuthority {
        &self.authority
    }

    #[cfg(test)]
    pub(crate) fn logical_authorities_for_test(&self) -> Vec<FileSlotAuthority> {
        self.authority.strict_slots()
    }

    #[cfg(test)]
    pub(crate) fn watched_authorities_for_test(&self) -> Vec<FileSlotAuthority> {
        match &self.authority {
            WaitFdAuthority::Logical { watched, .. } => {
                watched.iter().map(|slot| slot.slot()).collect()
            }
            _ => Vec::new(),
        }
    }

    /// Task 6 replaces this with `assemble_wait`: it captures the guest slots a
    /// park named and classifies them against the park's own reactor entries.
    pub(in crate::dispatch) fn with_guest_slots(
        mut self,
        files: &crate::kernel::objects::FileTable,
        guest_fds: impl IntoIterator<Item = i32>,
    ) -> Result<Self, LinuxErrno> {
        let slots = capture_slots(files, guest_fds)?;
        if slots.is_empty() && !self.fds.is_empty() {
            return Err(LINUX_EBADF);
        }
        if slots.is_empty() {
            self.authority = WaitFdAuthority::Empty;
        } else {
            let (registrations, unclassified) = classify_adapter_slots(&self.fds, slots);
            self.authority = WaitFdAuthority::Logical {
                registrations,
                unclassified,
                watched: Vec::new(),
            };
        }
        Ok(self)
    }

    /// Task 6/7 replace this with `assemble_wait`: the strict slots are
    /// classified against the park's reactor entries, the watched slots stay
    /// advisory and probe-exempt by type.
    pub(crate) fn with_redispatch_and_watched_slots(
        mut self,
        files: &crate::kernel::objects::FileTable,
        strict_fds: impl IntoIterator<Item = i32>,
        watched_fds: impl IntoIterator<Item = i32>,
    ) -> Result<Self, LinuxErrno> {
        let strict = capture_slots(files, strict_fds)?;
        let watched: Vec<WatchedSlot> = watched_fds
            .into_iter()
            .filter_map(|fd| crate::kernel::FileSlotNumber::for_open_fd(fd).ok())
            .filter_map(|number| files.capture_slot_or_stdio_authority(number))
            .map(WatchedSlot::new)
            .collect();
        if strict.is_empty() {
            return Err(LINUX_EBADF);
        }
        let (registrations, unclassified) = classify_adapter_slots(&self.fds, strict);
        self.authority = WaitFdAuthority::Logical {
            registrations,
            unclassified,
            watched,
        };
        Ok(self)
    }
}

fn capture_slots(
    files: &crate::kernel::objects::FileTable,
    guest_fds: impl IntoIterator<Item = i32>,
) -> Result<Vec<FileSlotAuthority>, LinuxErrno> {
    guest_fds
        .into_iter()
        .filter(|fd| *fd >= 0)
        .map(|fd| {
            let number = crate::kernel::FileSlotNumber::for_open_fd(fd).map_err(|_| LINUX_EBADF)?;
            files
                .capture_slot_or_stdio_authority(number)
                .ok_or(LINUX_EBADF)
        })
        .collect()
}

#[cfg(test)]
mod wait_fds_tests {
    use std::sync::Arc;

    use super::*;

    fn install_slot(
        files: &crate::kernel::objects::FileTable,
        ids: &crate::kernel::ObjectIdRegistry,
        fd: i32,
    ) -> FileSlotAuthority {
        let number = crate::kernel::FileSlotNumber::for_open_fd(fd).expect("open fd");
        files.install(
            number,
            Arc::new(crate::kernel::objects::FileDescription::regular(
                ids.file_description_id().expect("file description ID"),
            )),
            false,
        );
        files
            .capture_slot_authority(number)
            .expect("installed file slot authority")
    }

    /// A park with no host object for its slots makes them `Description`
    /// sources carrying exactly the events the park asked for, and those are
    /// the ones the wait service probes. A host-fd park makes them `Host`
    /// sources, which are never probed.
    #[test]
    fn adapter_classification_follows_the_parks_own_reactor_entries() {
        let ids = crate::kernel::ObjectIdRegistry::new();
        let files =
            crate::kernel::objects::FileTable::new(ids.file_table_id().expect("file table ID"));
        install_slot(&files, &ids, 20);
        let logical = WaitFds::raw_one(-1, libc::POLLIN)
            .with_redispatch_and_watched_slots(&files, [20], [20])
            .expect("logical wait");
        assert_eq!(
            logical.authority().probed_interest_for_test(),
            LinuxPollEvents::IN
        );
        let host = WaitFds::raw_one(7, libc::POLLIN)
            .with_guest_slots(&files, [20])
            .expect("host wait");
        assert_eq!(
            host.authority().probed_interest_for_test(),
            LinuxPollEvents::empty(),
            "a host descriptor decides its own readiness and is never probed"
        );
        let mixed = WaitFds::raw(vec![(7, libc::POLLIN), (-1, libc::POLLOUT)])
            .with_redispatch_and_watched_slots(&files, [20], [20])
            .expect("mixed wait");
        assert_eq!(
            mixed.authority().probed_interest_for_test(),
            LinuxPollEvents::OUT
        );
    }

    /// The one park that still names no source at all — `netlink.rs`'s
    /// `raw_one(-1, 0)` — keeps its slot STRICT and probe-free, exactly as
    /// before. Task 6 repairs it.
    #[test]
    fn a_park_with_no_host_object_and_no_events_leaves_its_slot_unclassified() {
        let ids = crate::kernel::ObjectIdRegistry::new();
        let files =
            crate::kernel::objects::FileTable::new(ids.file_table_id().expect("file table ID"));
        let slot = install_slot(&files, &ids, 21);
        let fds = WaitFds::raw_one(-1, 0)
            .with_guest_slots(&files, [21])
            .expect("netlink-shaped wait");
        assert_eq!(fds.authority().strict_slots(), [slot]);
        assert_eq!(
            fds.authority().probed_interest_for_test(),
            LinuxPollEvents::empty()
        );
        assert!(matches!(
            fds.authority(),
            WaitFdAuthority::Logical { registrations, unclassified, .. }
                if registrations.is_empty() && unclassified.len() == 1
        ));
    }

    /// `from_registrations` lowers `Host`/`Dual` sources to reactor entries and
    /// `Description` sources to none: the `-1` sentinel has nowhere to live.
    #[test]
    fn from_registrations_lowers_only_host_backed_sources_to_the_reactor() {
        let ids = crate::kernel::ObjectIdRegistry::new();
        let files =
            crate::kernel::objects::FileTable::new(ids.file_table_id().expect("file table ID"));
        let described = install_slot(&files, &ids, 22);
        let hosted = install_slot(&files, &ids, 23);
        let interest = WaitInterest::new(LinuxPollEvents::IN).expect("POLLIN");
        let fds = WaitFds::from_registrations(
            vec![
                WaitRegistration::new(
                    Fd(22),
                    described,
                    LinuxPollEvents::IN,
                    WaitSource::Description { interest },
                ),
                WaitRegistration::new(
                    Fd(23),
                    hosted,
                    LinuxPollEvents::OUT,
                    WaitSource::Host {
                        host: HostWaitTarget::new(HostFd(9), LinuxPollEvents::OUT),
                    },
                ),
            ],
            Vec::new(),
        )
        .expect("typed wait");
        assert_eq!(fds.first(), Some((9, libc::POLLOUT)));
        assert_eq!(fds.len(), 1);
        assert_eq!(fds.authority().strict_slots(), [described, hosted]);
        assert_eq!(
            fds.authority().probed_interest_for_test(),
            LinuxPollEvents::IN
        );
    }

    #[test]
    fn redispatch_authority_omits_missing_watched_slots_but_requires_strict_slots() {
        let ids = crate::kernel::ObjectIdRegistry::new();
        let files =
            crate::kernel::objects::FileTable::new(ids.file_table_id().expect("file table ID"));
        let strict = install_slot(&files, &ids, 11);
        let live_watched = install_slot(&files, &ids, 13);

        let fds = WaitFds::raw_one(-1, 0)
            .with_redispatch_and_watched_slots(&files, [11], [12, 13])
            .expect("missing watched slot must be advisory");
        assert_eq!(fds.logical_authorities_for_test(), [strict]);
        assert_eq!(fds.watched_authorities_for_test(), [live_watched]);

        assert_eq!(
            WaitFds::raw_one(-1, 0).with_redispatch_and_watched_slots(&files, [10], [13]),
            Err(LINUX_EBADF),
            "missing strict epfd must remain fail-closed"
        );
    }
}

impl PartialEq for WaitFds {
    fn eq(&self, other: &Self) -> bool {
        self.fds == other.fds
    }
}

impl Eq for WaitFds {}

impl Serialize for WaitFds {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let fds: Vec<(i32, i16)> = self.fds.iter().map(|fd| (fd.fd(), fd.events())).collect();
        fds.serialize(serializer)
    }
}

impl std::ops::Deref for WaitFds {
    type Target = [WaitFd];

    fn deref(&self) -> &Self::Target {
        &self.fds
    }
}

impl SyscallDispatcher {
    #[allow(dead_code)]
    pub(in crate::dispatch) fn complete_wait_fd_authority(
        &self,
        outcome: DispatchOutcome,
        files: &crate::kernel::objects::FileTable,
        guest_fds: impl IntoIterator<Item = i32>,
    ) -> DispatchOutcome {
        let guest_fds = guest_fds.into_iter().collect::<Vec<_>>();
        let authorize = |fds: WaitFds| fds.with_guest_slots(files, guest_fds.iter().copied());
        match outcome {
            DispatchOutcome::WaitOnFds {
                fds,
                timeout,
                sig_mask,
                completion,
            } => match authorize(fds) {
                Ok(fds) => DispatchOutcome::WaitOnFds {
                    fds,
                    timeout,
                    sig_mask,
                    completion,
                },
                Err(errno) => DispatchOutcome::errno(errno),
            },
            outcome => outcome,
        }
    }
}
