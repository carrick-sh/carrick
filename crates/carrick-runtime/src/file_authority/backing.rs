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
    Synthetic {
        contents: Vec<u8>,
    },
    Vfs {
        object: VfsObjectId,
    },
    Host {
        fd: OwnedFd,
        writable: bool,
    },
    HostStream {
        fd: OwnedFd,
        kind: super::HostStreamKind,
    },
    IoUring {
        data_fd: OwnedFd,
        lock_fd: OwnedFd,
        entries: u32,
        data_length: u64,
    },
    Epoll(EpollState),
    EventCounter {
        counter: u64,
        semaphore: bool,
    },
    PipeEnd {
        pipe: super::PipeId,
        end: super::PipeEnd,
    },
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
            Self::HostStream { kind, .. } => DescriptionBackingSnapshot::HostStream { kind: *kind },
            Self::IoUring {
                entries,
                data_length,
                ..
            } => DescriptionBackingSnapshot::IoUring {
                entries: *entries,
                data_length: *data_length,
            },
            Self::Epoll(state) => DescriptionBackingSnapshot::Epoll {
                interests: u32::try_from(state.len()).unwrap_or(u32::MAX),
            },
            Self::EventCounter { counter, semaphore } => DescriptionBackingSnapshot::EventCounter {
                counter: *counter,
                semaphore: *semaphore,
            },
            Self::PipeEnd { pipe, end } => DescriptionBackingSnapshot::PipeEnd {
                pipe: *pipe,
                end: *end,
            },
        }
    }

    pub(super) const fn vfs_object(&self) -> Option<VfsObjectId> {
        match self {
            Self::Synthetic { .. }
            | Self::Host { .. }
            | Self::IoUring { .. }
            | Self::HostStream { .. }
            | Self::Epoll(_)
            | Self::EventCounter { .. }
            | Self::PipeEnd { .. } => None,
            Self::Vfs { object } => Some(*object),
        }
    }

    pub(super) fn host_fd(&self, purpose: super::CapabilityLeasePurpose) -> Option<RawFd> {
        match (self, purpose) {
            (Self::Host { fd, .. }, super::CapabilityLeasePurpose::MappingSource) => {
                Some(fd.as_raw_fd())
            }
            (Self::HostStream { fd, .. }, super::CapabilityLeasePurpose::PollSource) => {
                Some(fd.as_raw_fd())
            }
            (Self::IoUring { data_fd, .. }, super::CapabilityLeasePurpose::IoUringData) => {
                Some(data_fd.as_raw_fd())
            }
            (Self::IoUring { lock_fd, .. }, super::CapabilityLeasePurpose::IoUringLock) => {
                Some(lock_fd.as_raw_fd())
            }
            _ => None,
        }
    }
}
