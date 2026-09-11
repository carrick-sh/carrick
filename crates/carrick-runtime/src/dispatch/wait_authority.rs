use carrick_abi::LinuxErrno;
use serde::Serialize;

use crate::dispatch::fd_table::HostFdRef;
use crate::dispatch::fifo_beacon::ParkedOpenerToken;
use crate::dispatch::{DispatchOutcome, SyscallDispatcher};
use crate::io_wait::WaitFd;
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WaitFdAuthority {
    Empty,
    Missing,
    Logical {
        strict: Vec<crate::kernel::objects::FileSlotAuthority>,
        watched: Vec<crate::kernel::objects::FileSlotAuthority>,
    },
    Internal(InternalWaitAuthority),
}

impl WaitFdAuthority {
    pub(crate) fn logical(authority: crate::kernel::objects::FileSlotAuthority) -> Self {
        Self::Logical {
            strict: vec![authority],
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

    #[cfg(test)]
    pub(crate) fn with_slot_authorities(
        mut self,
        slot_authorities: Vec<crate::kernel::objects::FileSlotAuthority>,
    ) -> Self {
        if self.fds.is_empty() && slot_authorities.is_empty() {
            self.authority = WaitFdAuthority::Empty;
        } else {
            self.authority = WaitFdAuthority::Logical {
                strict: slot_authorities,
                watched: Vec::new(),
            };
        }
        self
    }

    pub(crate) fn with_authority(mut self, authority: WaitFdAuthority) -> Self {
        self.authority = authority;
        self
    }

    pub(crate) fn authority(&self) -> &WaitFdAuthority {
        &self.authority
    }

    #[cfg(test)]
    pub(crate) fn logical_authorities_for_test(
        &self,
    ) -> &[crate::kernel::objects::FileSlotAuthority] {
        match &self.authority {
            WaitFdAuthority::Logical { strict, .. } => strict,
            _ => &[],
        }
    }

    #[cfg(test)]
    pub(crate) fn watched_authorities_for_test(
        &self,
    ) -> &[crate::kernel::objects::FileSlotAuthority] {
        match &self.authority {
            WaitFdAuthority::Logical { watched, .. } => watched,
            _ => &[],
        }
    }

    pub(in crate::dispatch) fn with_guest_slots(
        mut self,
        files: &crate::kernel::objects::FileTable,
        guest_fds: impl IntoIterator<Item = i32>,
    ) -> Result<Self, LinuxErrno> {
        let slot_authorities = guest_fds
            .into_iter()
            .filter(|fd| *fd >= 0)
            .map(|fd| {
                let number =
                    crate::kernel::FileSlotNumber::for_open_fd(fd).map_err(|_| LINUX_EBADF)?;
                files
                    .capture_slot_or_stdio_authority(number)
                    .ok_or(LINUX_EBADF)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if slot_authorities.is_empty() && !self.fds.is_empty() {
            return Err(LINUX_EBADF);
        }
        if slot_authorities.is_empty() {
            self.authority = WaitFdAuthority::Empty;
        } else {
            self.authority = WaitFdAuthority::Logical {
                strict: slot_authorities,
                watched: Vec::new(),
            };
        }
        Ok(self)
    }

    pub(crate) fn with_redispatch_and_watched_slots(
        mut self,
        files: &crate::kernel::objects::FileTable,
        strict_fds: impl IntoIterator<Item = i32>,
        watched_fds: impl IntoIterator<Item = i32>,
    ) -> Result<Self, LinuxErrno> {
        let capture = |fds: Vec<i32>| {
            fds.into_iter()
                .filter(|fd| *fd >= 0)
                .map(|fd| {
                    let number =
                        crate::kernel::FileSlotNumber::for_open_fd(fd).map_err(|_| LINUX_EBADF)?;
                    files
                        .capture_slot_or_stdio_authority(number)
                        .ok_or(LINUX_EBADF)
                })
                .collect::<Result<Vec<_>, _>>()
        };
        let strict = capture(strict_fds.into_iter().collect())?;
        let watched = watched_fds
            .into_iter()
            .filter_map(|fd| crate::kernel::FileSlotNumber::for_open_fd(fd).ok())
            .filter_map(|number| files.capture_slot_or_stdio_authority(number))
            .collect();
        if strict.is_empty() {
            return Err(LINUX_EBADF);
        }
        self.authority = WaitFdAuthority::Logical { strict, watched };
        Ok(self)
    }
}

#[cfg(test)]
mod wait_fds_tests {
    use std::sync::Arc;

    use super::*;

    fn install_slot(
        files: &crate::kernel::objects::FileTable,
        ids: &crate::kernel::ObjectIdRegistry,
        fd: i32,
    ) -> crate::kernel::objects::FileSlotAuthority {
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
