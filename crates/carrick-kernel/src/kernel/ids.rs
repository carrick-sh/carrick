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

use carrick_sched_core::serial_id;

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
    Local,
    Zone(std::sync::Arc<dyn carrick_hal::birth_serial::BirthSerialSource>),
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
            host_mm: parking_lot::RwLock::new(HostMmIdentityAuthority::Local),
        }
    }

    /// Revoke this kernel's MM admission and move only its local serial cursor.
    /// The carrier MM source and file-description source are separate owners.
    #[cfg(test)]
    pub(in crate::kernel) fn transfer_local_serials(&self) -> Option<TransferredSerialAllocator> {
        self.transfer_serials_and_births()
            .map(|(serials, _)| serials)
    }

    pub(in crate::kernel) fn transfer_serials_and_births(
        &self,
    ) -> Option<(
        TransferredSerialAllocator,
        Option<std::sync::Arc<dyn carrick_hal::birth_serial::BirthSerialSource>>,
    )> {
        let mut authority = self.host_mm.write();
        let source = match &*authority {
            HostMmIdentityAuthority::Zone(source) => Some(source.clone()),
            _ => None,
        };
        let serials = self.allocator.transfer()?;
        *authority = HostMmIdentityAuthority::Transferred;
        Some((serials, source))
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

    /// Install the actual carrier source before this registry issues births.
    pub fn with_birth_source(
        source: std::sync::Arc<dyn carrick_hal::birth_serial::BirthSerialSource>,
    ) -> Self {
        let registry = Self::new();
        *registry.host_mm.write() = HostMmIdentityAuthority::Zone(source);
        registry
    }

    /// Exclusive initial handoff. Caller must exclude native entry until this
    /// commits. The write authority spans all earlier host-issued births,
    /// including retired/reserved/unpublished identities, not a member scan.
    pub fn bind_initial_birth_source(
        &self,
        source: std::sync::Arc<dyn carrick_hal::birth_serial::BirthSerialSource>,
    ) -> Result<(), ObjectIdError> {
        let mut births = self.host_mm.write();
        match &*births {
            HostMmIdentityAuthority::Zone(old) => {
                if old.identity() != source.identity() {
                    return Err(ObjectIdError::ForeignBirthSource);
                }
                return Ok(());
            }
            HostMmIdentityAuthority::Transferred => {
                return Err(ObjectIdError::AuthorityTransferred);
            }
            HostMmIdentityAuthority::Local => {}
        }
        let high_water = self.allocate()?;
        source
            .adopt_initial(source.identity(), high_water)
            .map_err(|_| ObjectIdError::ForeignBirthSource)?;
        *births = HostMmIdentityAuthority::Zone(source);
        Ok(())
    }

    /// A later root cannot silently join an active native carrier without its
    /// actual engine source, or bind an independent local registry after entry.
    pub fn authenticate_birth_source(
        &self,
        source: Option<&std::sync::Arc<dyn carrick_hal::birth_serial::BirthSerialSource>>,
    ) -> Result<(), ObjectIdError> {
        match (&*self.host_mm.read(), source) {
            (HostMmIdentityAuthority::Local, None) => Ok(()),
            (HostMmIdentityAuthority::Zone(old), Some(source))
                if old.identity() == source.identity() =>
            {
                Ok(())
            }
            (HostMmIdentityAuthority::Transferred, _) => Err(ObjectIdError::AuthorityTransferred),
            _ => Err(ObjectIdError::ForeignBirthSource),
        }
    }

    fn allocate_birth(&self) -> Result<NonZeroU64, ObjectIdError> {
        match &*self.host_mm.read() {
            HostMmIdentityAuthority::Local => self.allocate(),
            HostMmIdentityAuthority::Zone(source) => {
                source
                    .allocate(source.identity())
                    .map_err(|error| match error {
                        carrick_hal::birth_serial::BirthSourceError::Exhausted => {
                            ObjectIdError::Exhausted
                        }
                        carrick_hal::birth_serial::BirthSourceError::StaleOwner => {
                            ObjectIdError::ForeignBirthSource
                        }
                    })
            }
            HostMmIdentityAuthority::Transferred => {
                let _ = self.allocator.allocate();
                Err(ObjectIdError::AuthorityTransferred)
            }
        }
    }

    pub fn task_serial(&self) -> Result<TaskSerial, ObjectIdError> {
        self.allocate_birth()
            .map(TaskSerial::from_registry_allocation)
    }

    pub fn thread_serial(&self) -> Result<ThreadSerial, ObjectIdError> {
        self.allocate_birth()
            .map(ThreadSerial::from_registry_allocation)
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
    #[error("birth source belongs to another or retired carrier VM")]
    ForeignBirthSource,
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

    fn birth_zone() -> std::sync::Arc<
        carrick_hal::birth_serial::test_support::OwnedBirthZone<carrick_sched_core::ThreadCtx>,
    > {
        let layout = std::alloc::Layout::new::<carrick_sched_core::ZoneTables>();
        // SAFETY: correctly aligned complete allocation; zero is the valid zone ABI.
        let zone = unsafe {
            let ptr = std::alloc::alloc_zeroed(layout).cast::<carrick_sched_core::ZoneTables>();
            if ptr.is_null() {
                std::alloc::handle_alloc_error(layout);
            }
            std::sync::Arc::from(Box::from_raw(ptr))
        };
        std::sync::Arc::new(carrick_hal::birth_serial::test_support::OwnedBirthZone::new(zone))
    }

    #[test]
    fn carrier_births_cover_reserved_unpublished_replenished_and_two_roots() {
        use carrick_hal::birth_serial::BirthSerialSource;
        let source = birth_zone();
        let make_root = || {
            let bootstrap = crate::kernel::RootBootstrap::for_reference_model(
                41,
                carrick_hal::ThreadId::from_guest_supplied_tid(41),
                "shared-birth-root".into(),
            )
            .unwrap()
            .with_birth_source(source.clone());
            crate::kernel::Kernel::bootstrap_root(bootstrap).unwrap()
        };
        let (kernel, first) = make_root();
        let reserved = kernel.object_ids().thread_serial().unwrap();
        let unpublished_native = source.zone.serial_issuer().allocate().unwrap();
        let after_native = kernel.object_ids().thread_serial().unwrap();
        assert!(reserved.raw() < unpublished_native.get());
        assert!(after_native.raw() > unpublished_native.get());
        // Later host/pool supply and another root both use the same word.
        let (other_kernel, other) = make_root();
        assert_ne!(first.task().key().serial, other.task().key().serial);
        assert_ne!(first.thread().key().serial, other.thread().key().serial);
        for _ in 0..16 {
            let pool = other_kernel.object_ids().thread_serial().unwrap();
            let native = source.zone.serial_issuer().allocate().unwrap();
            assert!(native.get() > pool.raw());
        }
        let before = source.allocate(source.identity()).unwrap();
        assert!(kernel.object_ids().thread_serial().unwrap().raw() > before.get());
    }

    #[test]
    fn initial_birth_handoff_captures_burned_values_and_refuses_live_join() {
        let source = birth_zone();
        let ids = ObjectIdRegistry::new();
        let burned = ids.thread_serial().unwrap();
        let reserved = ids.thread_serial().unwrap();
        // Neither identity is in a visible-member inventory.
        ids.bind_initial_birth_source(source.clone()).unwrap();
        let native = source.zone.serial_issuer().allocate().unwrap();
        assert!(native.get() > reserved.raw());
        assert!(native.get() > burned.raw());
        assert!(ids.thread_serial().unwrap().raw() > native.get());
        let late = ObjectIdRegistry::new();
        let _escaped = late.thread_serial().unwrap();
        assert_eq!(
            late.bind_initial_birth_source(source.clone()),
            Err(ObjectIdError::ForeignBirthSource)
        );
    }

    #[test]
    fn carrier_birth_owner_rejects_another_generation_one_and_retired_owner() {
        use carrick_hal::birth_serial::{BirthSerialSource, BirthSourceError};
        let first = birth_zone();
        let second = birth_zone();
        // Both fixture backend carrier numbers AND generations are one. Only
        // their retained custody objects differ, as in independently created VMs.
        assert_ne!(first.identity(), second.identity());
        assert_eq!(
            first.allocate(second.identity()),
            Err(BirthSourceError::StaleOwner)
        );
        let ids = ObjectIdRegistry::with_birth_source(first.clone());
        assert_eq!(
            ids.bind_initial_birth_source(second),
            Err(ObjectIdError::ForeignBirthSource)
        );
        first.retire();
        assert_eq!(ids.thread_serial(), Err(ObjectIdError::ForeignBirthSource));
    }

    #[test]
    fn shared_birth_transfer_revokes_only_old_handle_and_partial_exhaustion_burns() {
        let source = birth_zone();
        let old = ObjectIdRegistry::with_birth_source(source.clone());
        let peer = ObjectIdRegistry::with_birth_source(source.clone());
        let before = old.thread_serial().unwrap();
        let (_objects, exported) = old.transfer_serials_and_births().unwrap();
        let exported = ObjectIdRegistry::with_birth_source(exported.unwrap());
        assert_eq!(
            old.thread_serial(),
            Err(ObjectIdError::AuthorityTransferred)
        );
        assert!(peer.thread_serial().unwrap().raw() > before.raw());
        let next = exported.thread_serial().unwrap();
        assert!(peer.thread_serial().unwrap().raw() > next.raw());
        source
            .zone
            .serial_issuer()
            .advance_past(NonZeroU64::new(u64::MAX - 1).unwrap());
        assert_eq!(peer.task_serial().unwrap().raw(), u64::MAX);
        assert_eq!(exported.thread_serial(), Err(ObjectIdError::Exhausted));
        assert_eq!(peer.task_serial(), Err(ObjectIdError::Exhausted));
        // No reset from old-handle transfer or a low admission observation.
        source.zone.serial_issuer().advance_past(NonZeroU64::MIN);
        assert_eq!(peer.thread_serial(), Err(ObjectIdError::Exhausted));
    }

    #[test]
    fn linux_ids_reject_zero_and_negative_values() {
        assert_eq!(
            carrick_personality_linux::identity::task_id_from_linux_pid(0),
            Err(InvalidLinuxId::Zero)
        );
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
        let leader = carrick_personality_linux::identity::task_id_from_linux_pid(42)
            .expect("positive leader");

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
