use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use super::epoll::EpollState;
use super::types::{DescriptionBackingSnapshot, VfsObjectId};

/// Actual authority-owned payload for an open file description.
///
/// This deliberately begins with two fully functional backings rather than a
/// metadata shell. Further host-backed and readiness/transfer variants are
/// added here as their operation families move behind the same closed API.
#[derive(Debug)]
pub(super) enum AuthorityBacking {
    Synthetic { contents: Vec<u8> },
    Vfs { object: VfsObjectId },
    Host { fd: OwnedFd, writable: bool },
    Epoll(EpollState),
    EventCounter { counter: u64, semaphore: bool },
}

impl AuthorityBacking {
    pub(super) fn snapshot(&self) -> DescriptionBackingSnapshot {
        match self {
            Self::Synthetic { contents } => DescriptionBackingSnapshot::Synthetic {
                length: u64::try_from(contents.len()).unwrap_or(u64::MAX),
            },
            Self::Vfs { object } => DescriptionBackingSnapshot::VfsFile { object: *object },
            Self::Host { writable, .. } => DescriptionBackingSnapshot::HostFile {
                writable: *writable,
            },
            Self::Epoll(state) => DescriptionBackingSnapshot::Epoll {
                interests: u32::try_from(state.len()).unwrap_or(u32::MAX),
            },
            Self::EventCounter { counter, semaphore } => DescriptionBackingSnapshot::EventCounter {
                counter: *counter,
                semaphore: *semaphore,
            },
        }
    }

    pub(super) const fn vfs_object(&self) -> Option<VfsObjectId> {
        match self {
            Self::Synthetic { .. }
            | Self::Host { .. }
            | Self::Epoll(_)
            | Self::EventCounter { .. } => None,
            Self::Vfs { object } => Some(*object),
        }
    }

    pub(super) fn host_fd(&self) -> Option<RawFd> {
        match self {
            Self::Host { fd, .. } => Some(fd.as_raw_fd()),
            Self::Synthetic { .. }
            | Self::Vfs { .. }
            | Self::Epoll(_)
            | Self::EventCounter { .. } => None,
        }
    }
}
