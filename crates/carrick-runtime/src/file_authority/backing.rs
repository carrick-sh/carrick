use std::any::Any;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use super::epoll::EpollState;
use super::types::{DescriptionBackingSnapshot, VfsObjectId};

/// One authority-owned open-file-description payload.
///
/// Open by construction: a new backing kind is a new type implementing this
/// trait, not a new arm in every match over a closed enum.
pub(super) trait AuthorityBackingKind: std::fmt::Debug + Send + Sync {
    fn snapshot(&self) -> DescriptionBackingSnapshot;

    /// The host descriptor this backing's readiness and I/O ride on, if any,
    /// matching the requested capability lease purpose.
    fn host_fd(&self, _purpose: super::CapabilityLeasePurpose) -> Option<RawFd> {
        None
    }

    fn as_any(&self) -> &dyn Any;

    fn as_any_mut(&mut self) -> &mut dyn Any;
}

#[derive(Debug)]
pub(super) struct AuthorityBacking(Box<dyn AuthorityBackingKind>);

impl AuthorityBacking {
    pub(super) fn new<T>(kind: T) -> Self
    where
        T: AuthorityBackingKind + 'static,
    {
        Self(Box::new(kind))
    }

    pub(super) fn snapshot(&self) -> DescriptionBackingSnapshot {
        self.0.snapshot()
    }

    pub(super) fn vfs_object(&self) -> Option<VfsObjectId> {
        self.downcast_ref::<VfsBacking>().map(|vfs| vfs.object)
    }

    pub(super) fn host_fd(&self, purpose: super::CapabilityLeasePurpose) -> Option<RawFd> {
        self.0.host_fd(purpose)
    }

    pub(super) fn downcast_ref<T>(&self) -> Option<&T>
    where
        T: AuthorityBackingKind + 'static,
    {
        self.0.as_any().downcast_ref()
    }

    pub(super) fn downcast_mut<T>(&mut self) -> Option<&mut T>
    where
        T: AuthorityBackingKind + 'static,
    {
        self.0.as_any_mut().downcast_mut()
    }
}

#[derive(Debug)]
pub(super) struct SyntheticBacking {
    pub(super) contents: Vec<u8>,
}

impl AuthorityBackingKind for SyntheticBacking {
    fn snapshot(&self) -> DescriptionBackingSnapshot {
        DescriptionBackingSnapshot::Synthetic {
            length: u64::try_from(self.contents.len()).unwrap_or(u64::MAX),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[derive(Debug)]
pub(super) struct VfsBacking {
    pub(super) object: VfsObjectId,
}

impl AuthorityBackingKind for VfsBacking {
    fn snapshot(&self) -> DescriptionBackingSnapshot {
        DescriptionBackingSnapshot::VfsFile {
            object: self.object,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[derive(Debug)]
pub(super) struct HostBacking {
    pub(super) fd: OwnedFd,
    pub(super) writable: bool,
}

impl AuthorityBackingKind for HostBacking {
    fn snapshot(&self) -> DescriptionBackingSnapshot {
        DescriptionBackingSnapshot::HostFile {
            writable: self.writable,
        }
    }

    fn host_fd(&self, purpose: super::CapabilityLeasePurpose) -> Option<RawFd> {
        match purpose {
            super::CapabilityLeasePurpose::MappingSource => Some(self.fd.as_raw_fd()),
            _ => None,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[derive(Debug)]
pub(super) struct HostStreamBacking {
    pub(super) fd: OwnedFd,
    pub(super) kind: super::HostStreamKind,
}

impl AuthorityBackingKind for HostStreamBacking {
    fn snapshot(&self) -> DescriptionBackingSnapshot {
        DescriptionBackingSnapshot::HostStream { kind: self.kind }
    }

    fn host_fd(&self, purpose: super::CapabilityLeasePurpose) -> Option<RawFd> {
        match purpose {
            super::CapabilityLeasePurpose::PollSource => Some(self.fd.as_raw_fd()),
            _ => None,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[derive(Debug)]
pub(super) struct IoUringBacking {
    pub(super) data_fd: OwnedFd,
    pub(super) lock_fd: OwnedFd,
    pub(super) entries: u32,
    pub(super) data_length: u64,
}

impl AuthorityBackingKind for IoUringBacking {
    fn snapshot(&self) -> DescriptionBackingSnapshot {
        DescriptionBackingSnapshot::IoUring {
            entries: self.entries,
            data_length: self.data_length,
        }
    }

    fn host_fd(&self, purpose: super::CapabilityLeasePurpose) -> Option<RawFd> {
        match purpose {
            super::CapabilityLeasePurpose::IoUringData => Some(self.data_fd.as_raw_fd()),
            super::CapabilityLeasePurpose::IoUringLock => Some(self.lock_fd.as_raw_fd()),
            _ => None,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[derive(Debug)]
pub(super) struct EpollBacking {
    pub(super) state: EpollState,
}

impl AuthorityBackingKind for EpollBacking {
    fn snapshot(&self) -> DescriptionBackingSnapshot {
        DescriptionBackingSnapshot::Epoll {
            interests: u32::try_from(self.state.len()).unwrap_or(u32::MAX),
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[derive(Debug)]
pub(super) struct EventCounterBacking {
    pub(super) counter: u64,
    pub(super) semaphore: bool,
}

impl AuthorityBackingKind for EventCounterBacking {
    fn snapshot(&self) -> DescriptionBackingSnapshot {
        DescriptionBackingSnapshot::EventCounter {
            counter: self.counter,
            semaphore: self.semaphore,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[derive(Debug)]
pub(super) struct SignalFdBacking {
    pub(super) mask: carrick_abi::SigSet,
}

impl AuthorityBackingKind for SignalFdBacking {
    fn snapshot(&self) -> DescriptionBackingSnapshot {
        DescriptionBackingSnapshot::SignalFd { mask: self.mask }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[derive(Debug)]
pub(super) struct TimerBacking {
    pub(super) interval_ns: u64,
    pub(super) initial_ns: u64,
    pub(super) pending: u64,
}

impl AuthorityBackingKind for TimerBacking {
    fn snapshot(&self) -> DescriptionBackingSnapshot {
        DescriptionBackingSnapshot::Timer {
            interval_ns: self.interval_ns,
            initial_ns: self.initial_ns,
            pending: self.pending,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[derive(Debug)]
pub(super) struct PipeEndBacking {
    pub(super) pipe: super::PipeId,
    pub(super) end: super::PipeEnd,
}

impl AuthorityBackingKind for PipeEndBacking {
    fn snapshot(&self) -> DescriptionBackingSnapshot {
        DescriptionBackingSnapshot::PipeEnd {
            pipe: self.pipe,
            end: self.end,
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
