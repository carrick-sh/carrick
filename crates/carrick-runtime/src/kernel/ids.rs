use std::num::{NonZeroI32, NonZeroU64};
use std::sync::atomic::{AtomicU64, Ordering};

use carrick_hal::{FrameId, KernelTransactionId, MappingId};

macro_rules! linux_i32_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[repr(transparent)]
        pub struct $name(NonZeroI32);

        impl $name {
            pub fn from_abi_positive(raw: i32) -> Result<Self, InvalidLinuxId> {
                let value = NonZeroI32::new(raw).ok_or(InvalidLinuxId::Zero)?;
                if raw < 0 {
                    return Err(InvalidLinuxId::Negative(raw));
                }
                Ok(Self(value))
            }

            pub const fn raw(self) -> i32 {
                self.0.get()
            }
        }
    };
}

macro_rules! serial_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        #[repr(transparent)]
        pub struct $name(NonZeroU64);

        impl $name {
            pub(crate) const fn from_registry_allocation(raw: NonZeroU64) -> Self {
                Self(raw)
            }

            pub const fn raw(self) -> u64 {
                self.0.get()
            }
        }
    };
}

linux_i32_id!(TaskId);
linux_i32_id!(LinuxTid);
linux_i32_id!(ProcessGroupId);
linux_i32_id!(SessionId);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct FileSlotNumber(i32);

impl FileSlotNumber {
    pub fn for_open_fd(raw: i32) -> Result<Self, InvalidFileSlot> {
        if raw < 0 {
            return Err(InvalidFileSlot(raw));
        }
        Ok(Self(raw))
    }

    pub const fn raw(self) -> i32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct LinuxSignal(NonZeroI32);

impl LinuxSignal {
    pub fn for_signal_number(raw: i32) -> Result<Self, InvalidLinuxSignal> {
        let value = NonZeroI32::new(raw).ok_or(InvalidLinuxSignal::OutOfRange(raw))?;
        if !(1..=64).contains(&raw) {
            return Err(InvalidLinuxSignal::OutOfRange(raw));
        }
        Ok(Self(value))
    }

    pub const fn raw(self) -> i32 {
        self.0.get()
    }
}

serial_id!(TaskSerial);
serial_id!(ThreadSerial);
serial_id!(MmId);
serial_id!(FileTableId);
serial_id!(FileDescriptionId);
serial_id!(FsContextId);
serial_id!(CredentialsId);
serial_id!(SighandId);

impl TaskId {
    pub(crate) const fn from_registry_allocation(raw: NonZeroI32) -> Self {
        Self(raw)
    }

    pub fn for_root_bootstrap(raw: i32) -> Result<Self, InvalidLinuxId> {
        Self::from_abi_positive(raw)
    }
}

impl LinuxTid {
    pub(crate) const fn from_registry_allocation(raw: NonZeroI32) -> Self {
        Self(raw)
    }

    /// The initial thread of a thread group has the same numeric identity as
    /// its task/TGID, but remains a distinct semantic domain.
    pub const fn for_task_leader(task: TaskId) -> Self {
        Self(task.0)
    }
}

impl ProcessGroupId {
    pub fn from_leader(leader: TaskId) -> Self {
        Self(leader.0)
    }
}

impl SessionId {
    pub fn from_leader(leader: TaskId) -> Self {
        Self(leader.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidLinuxId {
    #[error("Linux identity zero is reserved")]
    Zero,
    #[error("Linux identity {0} is negative")]
    Negative(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum InvalidLinuxSignal {
    #[error("Linux signal number {0} is outside 1..=64")]
    OutOfRange(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("file slot {0} is negative")]
pub struct InvalidFileSlot(i32);

/// Monotonic source for object identities that are never reused by one kernel.
#[derive(Debug)]
pub struct ObjectIdRegistry {
    next: AtomicU64,
}

impl Default for ObjectIdRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ObjectIdRegistry {
    pub const fn new() -> Self {
        Self {
            next: AtomicU64::new(1),
        }
    }

    fn allocate(&self) -> Result<NonZeroU64, ObjectIdError> {
        let raw = self
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| ObjectIdError::Exhausted)?;
        NonZeroU64::new(raw).ok_or(ObjectIdError::Exhausted)
    }

    pub fn task_serial(&self) -> Result<TaskSerial, ObjectIdError> {
        self.allocate().map(TaskSerial::from_registry_allocation)
    }

    pub fn thread_serial(&self) -> Result<ThreadSerial, ObjectIdError> {
        self.allocate().map(ThreadSerial::from_registry_allocation)
    }

    pub fn mm_id(&self) -> Result<MmId, ObjectIdError> {
        self.allocate().map(MmId::from_registry_allocation)
    }

    pub fn file_table_id(&self) -> Result<FileTableId, ObjectIdError> {
        self.allocate().map(FileTableId::from_registry_allocation)
    }

    pub fn file_description_id(&self) -> Result<FileDescriptionId, ObjectIdError> {
        self.allocate()
            .map(FileDescriptionId::from_registry_allocation)
    }

    pub fn fs_context_id(&self) -> Result<FsContextId, ObjectIdError> {
        self.allocate().map(FsContextId::from_registry_allocation)
    }

    pub fn credentials_id(&self) -> Result<CredentialsId, ObjectIdError> {
        self.allocate().map(CredentialsId::from_registry_allocation)
    }

    pub fn sighand_id(&self) -> Result<SighandId, ObjectIdError> {
        self.allocate().map(SighandId::from_registry_allocation)
    }

    pub fn frame_id(&self) -> Result<FrameId, ObjectIdError> {
        self.allocate().map(FrameId::from_kernel_allocation)
    }

    pub fn mapping_id(&self) -> Result<MappingId, ObjectIdError> {
        self.allocate().map(MappingId::from_kernel_allocation)
    }

    pub fn transaction_id(&self) -> Result<KernelTransactionId, ObjectIdError> {
        self.allocate()
            .map(KernelTransactionId::from_kernel_allocation)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ObjectIdError {
    #[error("kernel object identity space exhausted")]
    Exhausted,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_ids_reject_zero_and_negative_values() {
        assert_eq!(TaskId::from_abi_positive(0), Err(InvalidLinuxId::Zero));
        assert_eq!(
            LinuxTid::from_abi_positive(-2),
            Err(InvalidLinuxId::Negative(-2))
        );
        assert_eq!(
            LinuxSignal::for_signal_number(65),
            Err(InvalidLinuxSignal::OutOfRange(65))
        );
        assert_eq!(FileSlotNumber::for_open_fd(-1), Err(InvalidFileSlot(-1)));
    }

    #[test]
    fn group_and_session_ids_preserve_the_leader_domain() {
        let leader = TaskId::for_root_bootstrap(42).expect("positive leader");

        assert_eq!(LinuxTid::for_task_leader(leader).raw(), 42);
        assert_eq!(ProcessGroupId::from_leader(leader).raw(), 42);
        assert_eq!(SessionId::from_leader(leader).raw(), 42);
    }

    #[test]
    fn object_ids_are_nonzero_and_never_reused() {
        let ids = ObjectIdRegistry::new();
        let task = ids.task_serial().expect("task serial");
        let thread = ids.thread_serial().expect("thread serial");
        let mm = ids.mm_id().expect("mm ID");

        assert_eq!(task.raw(), 1);
        assert_eq!(thread.raw(), 2);
        assert_eq!(mm.raw(), 3);
    }
}
