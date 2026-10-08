use carrick_sched_core::process::identity_allocator::{
    SerialAllocator, TransferredSerialAllocator,
};
pub use carrick_sched_core::process::{
    ChildExitSignal, InvalidLinuxId, InvalidLinuxSignal, LinuxSignal, ProcessGroupId, SessionId,
    TaskId, TaskSerial,
};
use std::num::{NonZeroI32, NonZeroU64};

use carrick_hal::{FrameId, KernelTransactionId, MappingId};

/// File descriptions may be created deep in dispatch helpers after the exact
/// KernelContext has selected a table. A process-global monotonic source keeps
/// their stable identities collision-free across every Kernel generation and
/// independently copied table without recapturing registry state.
static NEXT_FILE_DESCRIPTION_ID: SerialAllocator = SerialAllocator::new();

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
            pub const fn from_registry_allocation(raw: NonZeroU64) -> Self {
                Self(raw)
            }

            pub const fn raw(self) -> u64 {
                self.0.get()
            }

            #[allow(dead_code)]
            pub const fn from_raw_u64(raw: u64) -> Option<Self> {
                match NonZeroU64::new(raw) {
                    Some(nz) => Some(Self(nz)),
                    None => None,
                }
            }
        }
    };
}

linux_i32_id!(LinuxTid);

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

serial_id!(ThreadSerial);
serial_id!(MmId);
serial_id!(FileTableId);
serial_id!(FileDescriptionId);
serial_id!(FsContextId);
serial_id!(CredentialsId);
serial_id!(SighandId);

impl MmId {
    pub const fn nonzero(self) -> NonZeroU64 {
        self.0
    }
}

impl LinuxTid {
    pub(crate) const fn from_registry_allocation(raw: NonZeroI32) -> Self {
        Self(raw)
    }

    /// The initial thread of a thread group has the same numeric identity as
    /// its task/TGID, but remains a distinct semantic domain.
    pub const fn for_task_leader(task: TaskId) -> Self {
        Self(task.nonzero())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("file slot {0} is negative")]
pub struct InvalidFileSlot(i32);

/// The carrier-wide source of [`MmId`]s ([`ObjectIdRegistry::mm_id`]).
static CARRIER_MM_IDS: ObjectIdRegistry = ObjectIdRegistry::new();

/// Monotonic source for object identities that are never reused by one kernel.
#[derive(Debug)]
pub struct ObjectIdRegistry {
    allocator: SerialAllocator,
    host_mm: parking_lot::RwLock<HostMmIdentityAuthority>,
}

#[derive(Debug)]
enum HostMmIdentityAuthority {
    Available,
    Transferred,
}

impl Default for ObjectIdRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ObjectIdRegistry {
    pub const fn new() -> Self {
        Self {
            allocator: SerialAllocator::new(),
            host_mm: parking_lot::RwLock::new(HostMmIdentityAuthority::Available),
        }
    }

    /// Revoke this kernel's MM admission and move only its local serial cursor.
    /// The carrier MM source and file-description source are separate owners.
    pub(in crate::kernel) fn transfer_local_serials(&self) -> Option<TransferredSerialAllocator> {
        let mut authority = self.host_mm.write();
        *authority = HostMmIdentityAuthority::Transferred;
        self.allocator.transfer()
    }

    pub(in crate::kernel) fn local_transfer_available(&self) -> bool {
        !self.allocator.is_transferred()
    }

    pub fn transferred_refusals(&self) -> Option<u64> {
        self.allocator.refused_attempts()
    }

    #[cfg(test)]
    pub(in crate::kernel) fn exhaust_for_test(&self) {
        self.allocator.advance_to(NonZeroU64::MAX);
    }

    fn allocate(&self) -> Result<NonZeroU64, ObjectIdError> {
        self.allocator.allocate().ok_or_else(|| {
            if self.allocator.is_transferred() {
                ObjectIdError::AuthorityTransferred
            } else {
                ObjectIdError::Exhausted
            }
        })
    }

    pub fn task_serial(&self) -> Result<TaskSerial, ObjectIdError> {
        self.allocate().map(TaskSerial::from_registry_allocation)
    }

    pub fn thread_serial(&self) -> Result<ThreadSerial, ObjectIdError> {
        self.allocate().map(ThreadSerial::from_registry_allocation)
    }

    /// MM identities are unique across every kernel in the carrier process,
    /// not only within this one: the EL1 zone's occupancy words and
    /// published address spaces key on them, and one carrier runs several
    /// containers (kernels) whose vCPUs share that table. A per-kernel
    /// counter gave two containers' first MMs the same key, so a pause of
    /// one counted the other's vCPUs (the concurrent container gate).
    pub fn mm_id(&self) -> Result<MmId, ObjectIdError> {
        let authority = self.host_mm.read();
        if matches!(*authority, HostMmIdentityAuthority::Transferred) {
            // The moved serial source also owns the refusal receipt. Its
            // terminal state cannot allocate or be reopened by imports.
            let _ = self.allocator.allocate();
            return Err(ObjectIdError::AuthorityTransferred);
        }
        CARRIER_MM_IDS
            .allocate()
            .map(MmId::from_registry_allocation)
    }

    pub fn file_table_id(&self) -> Result<FileTableId, ObjectIdError> {
        self.allocate().map(FileTableId::from_registry_allocation)
    }

    pub fn file_description_id(&self) -> Result<FileDescriptionId, ObjectIdError> {
        allocate_file_description_id()
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
    #[error("kernel identity authority was transferred to the native owner")]
    AuthorityTransferred,
}

#[allow(dead_code)]
pub(crate) fn restore_file_description_id(raw: u64) -> Result<FileDescriptionId, ObjectIdError> {
    let value = NonZeroU64::new(raw).ok_or(ObjectIdError::Exhausted)?;
    NEXT_FILE_DESCRIPTION_ID
        .advance_past(value)
        .ok_or(ObjectIdError::Exhausted)?;
    Ok(FileDescriptionId::from_registry_allocation(value))
}

pub(crate) fn allocate_file_description_id() -> Result<FileDescriptionId, ObjectIdError> {
    NEXT_FILE_DESCRIPTION_ID
        .allocate()
        .map(FileDescriptionId::from_registry_allocation)
        .ok_or(ObjectIdError::Exhausted)
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
    fn restored_file_description_ids_advance_the_process_wide_allocator() {
        let before = allocate_file_description_id().expect("description ID");
        let restored_raw = before.raw().max(1_u64 << 62);
        let restored = restore_file_description_id(restored_raw).expect("restored ID");
        let after = allocate_file_description_id().expect("post-restore ID");

        assert_eq!(restored.raw(), restored_raw);
        assert!(after.raw() > restored.raw());
        assert_eq!(
            restore_file_description_id(0),
            Err(ObjectIdError::Exhausted)
        );
    }

    #[test]
    fn object_ids_are_nonzero_and_never_reused() {
        let ids = ObjectIdRegistry::new();
        let task = ids.task_serial().expect("task serial");
        let thread = ids.thread_serial().expect("thread serial");
        let mm = ids.mm_id().expect("mm ID");
        let other_kernel_mm = ObjectIdRegistry::new().mm_id().expect("mm ID");

        assert_eq!(task.raw(), 1);
        assert_eq!(thread.raw(), 2);
        // MM ids come from one carrier-wide source: another kernel's never
        // equals this one's.
        assert_ne!(mm, other_kernel_mm);
    }
    #[test]
    fn transferred_object_owner_refuses_mm_without_freezing_carrier() {
        let source = ObjectIdRegistry::new();
        let _initial_mm = source.mm_id().expect("initial owned MM");
        let first = source.task_serial().expect("source task serial");
        let native = source
            .transfer_local_serials()
            .expect("one transfer")
            .into_allocator();
        assert_eq!(
            native.allocate().expect("native cursor").get(),
            first.raw() + 1
        );
        assert_eq!(
            source.task_serial(),
            Err(ObjectIdError::AuthorityTransferred)
        );
        assert_eq!(source.mm_id(), Err(ObjectIdError::AuthorityTransferred));
        assert_eq!(source.mm_id(), Err(ObjectIdError::AuthorityTransferred));
        assert!(source.transfer_local_serials().is_none());
        assert_eq!(source.transferred_refusals(), Some(4));
        let other = ObjectIdRegistry::new();
        assert!(other.mm_id().is_ok());
        assert!(other.file_description_id().is_ok());
        assert_eq!(other.transferred_refusals(), Some(0));
    }
}
