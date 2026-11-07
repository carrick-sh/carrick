//! Carrier-scoped storage venue for the shared file ABI. This grants table
//! access, not file service or permission to open backing storage.

use crate::{
    DELEGATED_FILE_MAX_SIZE, DelegatedFile, DelegatedOpenFile, EL1_CACHE_OFFSET, EL1_CACHE_SIZE,
    EL1_FD_MAP_OFFSET, EL1_FD_MAP_SIZE, EL1_NAME_CACHE_OFFSET, EL1_NAME_CACHE_SIZE,
    EL1_OBJECT_TABLE_OFFSET, EL1_OBJECT_TABLE_SIZE, EL1_OPEN_FILE_TABLE_OFFSET,
    EL1_OPEN_FILE_TABLE_SIZE, EL1_REGION_SIZE, FD_MAP_CAPACITY, FdMapSlot, InotifyNameCache,
    MAX_DELEGATED_FILES, MAX_ZONE_OPEN_FILES,
};
use carrick_guest_arch::{FrameGpa, GuestLen, KernelVa};
use core::sync::atomic::{AtomicU64, Ordering};
use core::{
    marker::PhantomData,
    mem::{align_of, size_of},
    num::NonZeroU64,
    ptr::NonNull,
};

/// Publication occupies unused space after the bounded open records.
pub const EL1_FILE_REGION_HEADER_OFFSET: u64 =
    EL1_OPEN_FILE_TABLE_OFFSET + EL1_OPEN_FILE_TABLE_SIZE - 64;

#[repr(C, align(64))]
struct FileRegionHeader {
    live_identity: AtomicU64,
    guest: KernelVa,
    physical: FrameGpa,
    bytes: GuestLen,
}

const _: () = {
    assert!(size_of::<FileRegionHeader>() == 64);
    assert!(
        crate::EL1_IPC_TABLE_MAP_OFFSET + size_of::<crate::ipc_tables::IpcTableMap>() as u64
            <= EL1_REGION_SIZE
    );
    assert!(
        crate::EL1_IPC_TABLE_MAP_OFFSET
            .is_multiple_of(align_of::<crate::ipc_tables::IpcTableMap>() as u64)
    );
    assert!(size_of::<[DelegatedFile; MAX_DELEGATED_FILES]>() as u64 <= EL1_OBJECT_TABLE_SIZE);
    assert!(size_of::<[FdMapSlot; FD_MAP_CAPACITY]>() as u64 <= EL1_FD_MAP_SIZE);
    assert!(
        EL1_OPEN_FILE_TABLE_OFFSET + size_of::<[DelegatedOpenFile; MAX_ZONE_OPEN_FILES]>() as u64
            <= EL1_FILE_REGION_HEADER_OFFSET
    );
    assert!(
        crate::OPEN_REFERENCE_PENDING_OFFSET + size_of::<crate::OpenReferencePending>() as u64
            <= EL1_FILE_REGION_HEADER_OFFSET
    );
    assert!(size_of::<InotifyNameCache>() as u64 <= EL1_NAME_CACHE_SIZE);
    assert!(EL1_OBJECT_TABLE_OFFSET.is_multiple_of(align_of::<DelegatedFile>() as u64));
    assert!(EL1_FD_MAP_OFFSET.is_multiple_of(align_of::<FdMapSlot>() as u64));
    assert!(EL1_OPEN_FILE_TABLE_OFFSET.is_multiple_of(align_of::<DelegatedOpenFile>() as u64));
    assert!(EL1_NAME_CACHE_OFFSET.is_multiple_of(align_of::<InotifyNameCache>() as u64));
    assert!(EL1_FILE_REGION_HEADER_OFFSET.is_multiple_of(align_of::<FileRegionHeader>() as u64));
    assert!(EL1_CACHE_OFFSET + EL1_CACHE_SIZE <= EL1_NAME_CACHE_OFFSET);
    assert!(EL1_NAME_CACHE_OFFSET + EL1_NAME_CACHE_SIZE <= EL1_REGION_SIZE);
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileRegionError {
    /// No carrier has ever published this binding.
    Unpublished,
    Layout,
    Foreign,
    Retired,
    /// Host table access cannot acquire stopped-carrier custody.
    Running,
    /// Stopped CPL0 still owns an unfinished descriptor transaction.
    MutationActive,
}

impl FileRegionError {
    /// Exact CPL0 fatal-doorbell domain for venue refusal, separate from a
    /// general boot refusal. Guest-observed retirement is a fixture witness.
    pub const fn fatal_payload(self) -> u64 {
        match self {
            Self::Unpublished => 0xf205,
            Self::Layout => 0xf201,
            Self::Foreign => 0xf202,
            Self::Retired => 0xf203,
            Self::Running => 0xf204,
            Self::MutationActive => 0xf206,
        }
    }
}

/// Region identity issued by the carrier owner. Task/MM IDs cannot be passed
/// to region authentication without an explicit authority-boundary conversion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct FileRegionId(u64);

impl FileRegionId {
    pub const fn from_carrier(identity: NonZeroU64) -> Self {
        Self(identity.get())
    }
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Guest supervisor VA and physical extent are intentionally distinct. The
/// identity is issued by the carrier owner, never by a guest-created handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct FileRegionBinding {
    identity: FileRegionId,
    guest: KernelVa,
    physical: FrameGpa,
    bytes: GuestLen,
}

impl FileRegionBinding {
    /// Recover the mapping owner's publication at this image's supervisor layout.
    /// This supplies geometry, not host mapping custody.
    ///
    /// # Safety
    /// The current carrier retains an initialized, supervisor-only region at
    /// `layout.region` for the call. Its header is immutable after publication;
    /// retirement may only clear the atomic identity. Host callers may use this
    /// only in fixtures that retain storage at the supplied supervisor VA.
    pub unsafe fn in_guest_layout(
        layout: carrick_guest_arch::KernelLayout,
    ) -> Result<Self, FileRegionError> {
        let base = layout.region.raw();
        if base == 0 || !base.is_multiple_of(4096) || base.checked_add(EL1_REGION_SIZE).is_none() {
            return Err(FileRegionError::Layout);
        }
        // SAFETY: the caller retains the initialized header in this extent.
        let header =
            unsafe { &*((base + EL1_FILE_REGION_HEADER_OFFSET) as *const FileRegionHeader) };
        let identity = NonZeroU64::new(header.live_identity.load(Ordering::Acquire))
            .ok_or(FileRegionError::Retired)?;
        if header.guest != layout.region {
            return Err(FileRegionError::Foreign);
        }
        Self::new(
            FileRegionId::from_carrier(identity),
            header.guest,
            header.physical,
            header.bytes,
        )
    }

    pub const UNPUBLISHED: Self = Self {
        identity: FileRegionId(0),
        guest: KernelVa::new(0),
        physical: FrameGpa::new(0),
        bytes: GuestLen::new(0),
    };

    pub fn new(
        identity: FileRegionId,
        guest: KernelVa,
        physical: FrameGpa,
        bytes: GuestLen,
    ) -> Result<Self, FileRegionError> {
        if identity.raw() == 0 {
            return Err(FileRegionError::Unpublished);
        }
        if bytes.raw() != EL1_REGION_SIZE
            || guest.raw() == 0
            || !guest.raw().is_multiple_of(4096)
            || !physical.raw().is_multiple_of(4096)
            || guest.raw().checked_add(bytes.raw()).is_none()
            || physical.raw().checked_add(bytes.raw()).is_none()
        {
            return Err(FileRegionError::Layout);
        }
        Ok(Self {
            identity,
            guest,
            physical,
            bytes,
        })
    }

    pub const fn guest(self) -> KernelVa {
        self.guest
    }
    pub const fn physical(self) -> FrameGpa {
        self.physical
    }
    pub const fn bytes(self) -> GuestLen {
        self.bytes
    }
    pub const fn identity(self) -> FileRegionId {
        self.identity
    }
}

/// Retained carrier ownership for descriptor publications that outlive a
/// host boundary. Implementations authenticate their registration and retain
/// its mapping while invoking the visitor. No borrowed map may escape.
pub trait IpcTableMapBacking: Send + Sync {
    /// Visit exactly once while the registration is live; refuse without a
    /// visit after retirement. The map borrow cannot escape its custody.
    ///
    /// ```compile_fail
    /// use carrick_el1_abi::{IpcTableMapBacking, ipc_tables::IpcTableMap};
    /// fn escape(backing: &dyn IpcTableMapBacking) -> &'static IpcTableMap {
    ///     let mut escaped = None;
    ///     backing.with_table_map(&mut |map| escaped = Some(map)).unwrap();
    ///     escaped.unwrap()
    /// }
    /// ```
    fn with_table_map(
        &self,
        visitor: &mut dyn FnMut(&crate::ipc_tables::IpcTableMap),
    ) -> Result<(), FileRegionError>;
}

/// Non-cloning host registration. Its constructor requires retained mapping
/// custody; a bare process-global region pointer cannot create this authority.
#[derive(Debug)]
pub struct FileRegionRegistration {
    mapped: NonNull<u8>,
    binding: FileRegionBinding,
}

impl FileRegionRegistration {
    /// Initialize unpublished storage and publish it once, before guest entry.
    ///
    /// # Safety
    /// `mapped` covers the entire exclusively owned, writable binding extent.
    /// It must remain mapped until this registration is dropped. No other
    /// registration, guest or table reference may access it during initialization.
    pub unsafe fn initialize(
        mapped: NonNull<u8>,
        binding: FileRegionBinding,
    ) -> Result<Self, FileRegionError> {
        check_mapping(mapped, binding)?;
        // SAFETY: caller grants exclusive initialized extent custody; every
        // allocation and its alignment is checked by the shared layout.
        unsafe {
            mapped
                .as_ptr()
                .add(crate::EL1_METADATA_MAILBOX_OFFSET as usize)
                .cast::<crate::MetadataGrantMailbox>()
                .write(crate::MetadataGrantMailbox::new());
            for slot in 0..(crate::EL1_STACK_SLOTS as usize) {
                mapped
                    .as_ptr()
                    .add(crate::EL1_CURRENT_TASKS_OFFSET as usize)
                    .cast::<crate::CurrentTask>()
                    .add(slot)
                    .write(crate::CurrentTask::new());
            }
            for index in 0..MAX_DELEGATED_FILES {
                mapped
                    .as_ptr()
                    .add(EL1_OBJECT_TABLE_OFFSET as usize)
                    .cast::<DelegatedFile>()
                    .add(index)
                    .write(DelegatedFile::new());
            }
            for index in 0..MAX_ZONE_OPEN_FILES {
                mapped
                    .as_ptr()
                    .add(EL1_OPEN_FILE_TABLE_OFFSET as usize)
                    .cast::<DelegatedOpenFile>()
                    .add(index)
                    .write(DelegatedOpenFile::new());
            }
            for index in 0..FD_MAP_CAPACITY {
                mapped
                    .as_ptr()
                    .add(EL1_FD_MAP_OFFSET as usize)
                    .cast::<FdMapSlot>()
                    .add(index)
                    .write(FdMapSlot::new());
            }
            mapped
                .as_ptr()
                .add(EL1_NAME_CACHE_OFFSET as usize)
                .cast::<InotifyNameCache>()
                .write(InotifyNameCache::new());
            // The map and zone tables contain only atomics and claim-protected
            // context; all-zero is their empty, unpublished state. Initialize
            // in place without a large by-value temporary on a supervisor stack.
            mapped
                .as_ptr()
                .add(crate::EL1_IPC_TABLE_MAP_OFFSET as usize)
                .cast::<crate::ipc_tables::IpcTableMap>()
                .write_bytes(0, 1);
            mapped
                .as_ptr()
                .add(crate::EL1_ZONE_OFFSET as usize)
                .cast::<crate::ZoneTables>()
                .write_bytes(0, 1);
            mapped
                .as_ptr()
                .add(EL1_FILE_REGION_HEADER_OFFSET as usize)
                .cast::<FileRegionHeader>()
                .write(FileRegionHeader {
                    live_identity: AtomicU64::new(0),
                    guest: binding.guest,
                    physical: binding.physical,
                    bytes: binding.bytes,
                });
            // Publish initialized records and the complete address-domain
            // binding together, before any CPU receives this publication.
            (*mapped
                .as_ptr()
                .add(EL1_FILE_REGION_HEADER_OFFSET as usize)
                .cast::<FileRegionHeader>())
            .live_identity
            .store(binding.identity.raw(), Ordering::Release);
        }
        Ok(Self { mapped, binding })
    }

    pub const fn binding(&self) -> FileRegionBinding {
        self.binding
    }

    /// Authenticate that this registration remains live and return the base of
    /// its retained `EL1_REGION_SIZE` mapping.
    pub fn retained_base(&self) -> Result<NonNull<u8>, FileRegionError> {
        self.tables(self.binding)?;
        Ok(self.mapped)
    }

    /// Borrow the initialized mailbox from this exact carrier registration.
    /// Retirement refuses new borrows; no process-global aperture is read.
    pub fn metadata_mailbox(&self) -> Result<&crate::MetadataGrantMailbox, FileRegionError> {
        self.tables(self.binding)?;
        // SAFETY: initialization writes this atomic record before publication;
        // the registration borrow retains its complete aligned extent.
        Ok(unsafe {
            &*self
                .mapped
                .as_ptr()
                .add(crate::EL1_METADATA_MAILBOX_OFFSET as usize)
                .cast::<crate::MetadataGrantMailbox>()
        })
    }

    /// Borrow the initialized zone tables from this exact carrier registration.
    /// Retirement refuses new borrows; no process-global aperture is read.
    pub fn zone_tables(&self) -> Result<&crate::ZoneTables, FileRegionError> {
        const {
            assert!(core::mem::align_of::<crate::ZoneTables>() <= 4096);
        }
        self.tables(self.binding)?;
        // SAFETY: initialization zeroes this atomic/claim-protected table
        // before publication; 4 KiB mapping alignment plus checked offset
        // guarantee alignment, and the borrow retains the mapping.
        Ok(unsafe {
            &*self
                .mapped
                .as_ptr()
                .add(crate::EL1_ZONE_OFFSET as usize)
                .cast::<crate::ZoneTables>()
        })
    }

    /// Borrow a slot's `CurrentTask` record from this exact carrier registration.
    pub fn current_task(
        &self,
        slot: carrick_guest_arch::SlotId,
    ) -> Result<&crate::CurrentTask, FileRegionError> {
        const {
            assert!(core::mem::align_of::<crate::CurrentTask>() <= 4096);
        }
        let index = usize::from(slot.raw());
        if index >= crate::EL1_STACK_SLOTS as usize {
            return Err(FileRegionError::Layout);
        }
        self.tables(self.binding)?;
        // SAFETY: initialization writes all `EL1_STACK_SLOTS` task records
        // before publication; `index` is in bounds and aligned.
        Ok(unsafe {
            &*self
                .mapped
                .as_ptr()
                .add(crate::EL1_CURRENT_TASKS_OFFSET as usize)
                .cast::<crate::CurrentTask>()
                .add(index)
        })
    }

    /// Publish pending host work on `slot` in this exact carrier registration.
    pub fn mark_pending_host_work(
        &self,
        slot: carrick_guest_arch::SlotId,
    ) -> Result<(), FileRegionError> {
        let current_task = self.current_task(slot)?;
        current_task.linux.mark_pending_host_work();
        crate::record_direct_slot_host_work_publication();
        Ok(())
    }

    pub fn tables(&self, expected: FileRegionBinding) -> Result<FileTables<'_>, FileRegionError> {
        if expected.identity.raw() == 0 {
            return Err(FileRegionError::Unpublished);
        }
        if expected != self.binding {
            return Err(FileRegionError::Foreign);
        }
        // SAFETY: registration retains initialized mapping custody; the borrow
        // prevents retirement while host references exist.
        unsafe { FileTables::attach(self.mapped, expected) }
    }

    /// The carrier must have stopped every guest consumer before retirement.
    /// Host table borrows cannot survive this exclusive borrow.
    pub fn retire(&mut self) {
        // SAFETY: initialized publication is retained through registration drop.
        unsafe {
            &*self
                .mapped
                .as_ptr()
                .add(EL1_FILE_REGION_HEADER_OFFSET as usize)
                .cast::<FileRegionHeader>()
        }
        .live_identity
        .store(0, Ordering::Release);
    }
}

impl Drop for FileRegionRegistration {
    fn drop(&mut self) {
        self.retire();
    }
}

fn check_mapping(mapped: NonNull<u8>, binding: FileRegionBinding) -> Result<(), FileRegionError> {
    FileRegionBinding::new(
        binding.identity,
        binding.guest,
        binding.physical,
        binding.bytes,
    )?;
    if !(mapped.as_ptr() as usize).is_multiple_of(4096)
        || (mapped.as_ptr() as usize)
            .checked_add(EL1_REGION_SIZE as usize)
            .is_none()
    {
        return Err(FileRegionError::Layout);
    }
    Ok(())
}

/// The x86 CPL0 personality uses this checked venue for its file records,
/// stdio and cache. ARM dispatch/delegation still use their existing raw bases.
pub struct FileTables<'a> {
    mapped: NonNull<u8>,
    _retained: PhantomData<&'a FileRegionRegistration>,
}

impl<'a> FileTables<'a> {
    unsafe fn attach(
        mapped: NonNull<u8>,
        expected: FileRegionBinding,
    ) -> Result<Self, FileRegionError> {
        check_mapping(mapped, expected)?;
        // SAFETY: caller retains the full mapping and initialized header; the
        // size/alignment checks above precede the first memory access.
        let header = unsafe {
            &*mapped
                .as_ptr()
                .add(EL1_FILE_REGION_HEADER_OFFSET as usize)
                .cast::<FileRegionHeader>()
        };
        let live = header.live_identity.load(Ordering::Acquire);
        if live == 0 {
            return Err(FileRegionError::Retired);
        }
        if live != expected.identity.raw()
            || header.guest != expected.guest
            || header.physical != expected.physical
            || header.bytes != expected.bytes
        {
            return Err(FileRegionError::Foreign);
        }
        Ok(Self {
            mapped,
            _retained: PhantomData,
        })
    }

    /// Attach through the current CPU's owner-published guest region binding.
    ///
    /// # Safety
    /// The current carrier maps `expected.guest()` supervisor-only to its live,
    /// initialized physical extent for `'a`. Guest consumers must stop before
    /// the host retires the registration. This converts a guest VA only in the
    /// guest; host code must use `FileRegionRegistration::tables`.
    pub unsafe fn in_guest(expected: FileRegionBinding) -> Result<Self, FileRegionError> {
        if expected.identity.raw() == 0 {
            return Err(FileRegionError::Unpublished);
        }
        let mapped =
            NonNull::new(expected.guest.raw() as *mut u8).ok_or(FileRegionError::Layout)?;
        // SAFETY: guest mapping custody is the caller's explicit obligation.
        unsafe { Self::attach(mapped, expected) }
    }

    /// Descriptor namespace map in this authenticated carrier's region.
    /// The borrow retains registration custody; no process-global aperture
    /// or ISA-specific virtual address participates in host resolution.
    pub fn ipc_table_map(&self) -> &crate::ipc_tables::IpcTableMap {
        self.retained_ipc_table_map()
    }

    /// Consume the view while retaining the original registration lifetime.
    /// A guest venue can keep this map after the temporary file view is gone;
    /// its mapping custody is still bounded by the registration borrow (or
    /// the explicit unsafe guest-attachment contract).
    pub fn into_ipc_table_map(self) -> &'a crate::ipc_tables::IpcTableMap {
        self.retained_ipc_table_map()
    }

    fn retained_ipc_table_map(&self) -> &'a crate::ipc_tables::IpcTableMap {
        // SAFETY: registration initializes this reservation before publishing
        // its identity. Attachment authenticates that identity and retains
        // mapping custody for 'a; the ABI checks extent and alignment.
        unsafe {
            &*self
                .mapped
                .as_ptr()
                .add(crate::EL1_IPC_TABLE_MAP_OFFSET as usize)
                .cast::<crate::ipc_tables::IpcTableMap>()
        }
    }

    pub fn objects(&self) -> &[DelegatedFile; MAX_DELEGATED_FILES] {
        // SAFETY: attached initialized venue; fixed ABI extent/alignment.
        unsafe {
            &*self
                .mapped
                .as_ptr()
                .add(EL1_OBJECT_TABLE_OFFSET as usize)
                .cast()
        }
    }
    pub fn opens(&self) -> &[DelegatedOpenFile; MAX_ZONE_OPEN_FILES] {
        // SAFETY: attached initialized venue; fixed ABI extent/alignment.
        unsafe {
            &*self
                .mapped
                .as_ptr()
                .add(EL1_OPEN_FILE_TABLE_OFFSET as usize)
                .cast()
        }
    }
    pub fn fd_map(&self) -> &[FdMapSlot; FD_MAP_CAPACITY] {
        // SAFETY: attached initialized venue; fixed ABI extent/alignment.
        unsafe { &*self.mapped.as_ptr().add(EL1_FD_MAP_OFFSET as usize).cast() }
    }
    pub fn names(&self) -> &InotifyNameCache {
        // SAFETY: attached initialized venue; fixed ABI extent/alignment.
        unsafe {
            &*self
                .mapped
                .as_ptr()
                .add(EL1_NAME_CACHE_OFFSET as usize)
                .cast()
        }
    }
    pub fn cache(&self, inode_handle: u32) -> Option<NonNull<u8>> {
        let index = inode_handle.checked_sub(1)? as usize;
        if index >= MAX_DELEGATED_FILES {
            return None;
        }
        let offset = EL1_CACHE_OFFSET as usize + index * DELEGATED_FILE_MAX_SIZE as usize;
        // SAFETY: index bound and shared ABI cache extent keep the address in
        // retained storage. Byte access still requires the inode's authority.
        Some(unsafe { NonNull::new_unchecked(self.mapped.as_ptr().add(offset)) })
    }
}

#[cfg(test)]
mod registration_mailbox_tests {
    extern crate std;
    use super::*;

    #[test]
    fn registered_metadata_mailbox_is_carrier_local_and_refuses_retirement() {
        let layout = std::alloc::Layout::from_size_align(EL1_REGION_SIZE as usize, 4096)
            .expect("region layout");
        let allocate = || {
            // SAFETY: exact page-aligned region allocation, retained below.
            NonNull::new(unsafe { std::alloc::alloc_zeroed(layout) }).expect("region allocation")
        };
        let first = allocate();
        let second = allocate();
        let binding = |identity| {
            FileRegionBinding::new(
                FileRegionId::from_carrier(NonZeroU64::new(identity).expect("identity")),
                KernelVa::new(crate::EL1_REGION_BASE),
                FrameGpa::new(crate::EL1_REGION_BASE),
                GuestLen::new(EL1_REGION_SIZE),
            )
            .expect("binding")
        };
        {
            // SAFETY: exclusive initialized extents outlive both registrations.
            let mut a = unsafe { FileRegionRegistration::initialize(first, binding(1)) }
                .expect("first registration");
            // SAFETY: disjoint exclusive extent, retained until registration drop.
            let b = unsafe { FileRegionRegistration::initialize(second, binding(2)) }
                .expect("second registration");
            let mailbox = a.metadata_mailbox().expect("live first carrier");
            assert!(mailbox.try_publish_request(crate::MetadataGrantRequest {
                op: crate::METADATA_GRANT_OP_ALLOC,
                arg1: 4096,
                arg2: 0,
                arg3: 0,
                cookie: 7,
            }));
            assert!(
                b.metadata_mailbox()
                    .expect("live second carrier")
                    .claim_request()
                    .is_none()
            );
            assert_eq!(mailbox.claim_request().expect("first request").cookie, 7);
            a.retire();
            assert!(matches!(
                a.metadata_mailbox(),
                Err(FileRegionError::Retired)
            ));
            assert!(b.metadata_mailbox().is_ok());
        }
        // SAFETY: registrations and every borrowed view are now gone.
        unsafe {
            std::alloc::dealloc(first.as_ptr(), layout);
            std::alloc::dealloc(second.as_ptr(), layout);
        }
    }

    #[test]
    fn registered_zone_and_slot_doorbell_are_carrier_local_and_refuse_retirement() {
        let layout =
            std::alloc::Layout::from_size_align(EL1_REGION_SIZE as usize, 4096).expect("layout");
        let allocate =
            || NonNull::new(unsafe { std::alloc::alloc_zeroed(layout) }).expect("allocated region");
        let first = allocate();
        let second = allocate();
        let binding = |identity| {
            FileRegionBinding::new(
                FileRegionId::from_carrier(NonZeroU64::new(identity).expect("identity")),
                KernelVa::new(crate::EL1_REGION_BASE),
                FrameGpa::new(crate::EL1_REGION_BASE),
                GuestLen::new(EL1_REGION_SIZE),
            )
            .expect("binding")
        };
        let slot = carrick_guest_arch::SlotId::from_index(3).expect("valid slot");
        {
            // SAFETY: exclusive extents outlive both registrations and have no guest CPUs.
            let mut a = unsafe { FileRegionRegistration::initialize(first, binding(11)) }
                .expect("first registration");
            // SAFETY: disjoint exclusive extent retained until registration drop.
            let b = unsafe { FileRegionRegistration::initialize(second, binding(22)) }
                .expect("second registration");

            assert_eq!(a.retained_base().expect("live first base"), first);
            assert_eq!(b.retained_base().expect("live second base"), second);

            let first_zone = a.zone_tables().expect("live first zone");
            let second_zone = b.zone_tables().expect("live second zone");
            first_zone.spaces.set_idle_ttbr(0x1111_0000);
            assert_eq!(second_zone.spaces.idle_ttbr(), 0);

            a.mark_pending_host_work(slot)
                .expect("first slot doorbell publication");
            assert!(
                a.current_task(slot)
                    .expect("first slot task")
                    .linux
                    .has_pending_host_work()
            );
            assert!(
                !b.current_task(slot)
                    .expect("second slot task")
                    .linux
                    .has_pending_host_work()
            );

            a.retire();
            assert!(matches!(a.retained_base(), Err(FileRegionError::Retired)));
            assert!(matches!(a.zone_tables(), Err(FileRegionError::Retired)));
            assert!(matches!(
                a.current_task(slot),
                Err(FileRegionError::Retired)
            ));
            assert!(matches!(
                a.mark_pending_host_work(slot),
                Err(FileRegionError::Retired)
            ));
            assert_eq!(
                b.zone_tables()
                    .expect("second remains live")
                    .spaces
                    .idle_ttbr(),
                0
            );
        }
        // SAFETY: registrations and every borrowed view are now gone.
        unsafe {
            std::alloc::dealloc(first.as_ptr(), layout);
            std::alloc::dealloc(second.as_ptr(), layout);
        }
    }
}
