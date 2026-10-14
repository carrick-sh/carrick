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

/// Non-cloning host registration. Its constructor requires retained mapping
/// custody; a bare process-global region pointer cannot create this authority.
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
    #[cfg(target_os = "none")]
    pub unsafe fn in_guest(expected: FileRegionBinding) -> Result<Self, FileRegionError> {
        if expected.identity.raw() == 0 {
            return Err(FileRegionError::Unpublished);
        }
        let mapped =
            NonNull::new(expected.guest.raw() as *mut u8).ok_or(FileRegionError::Layout)?;
        // SAFETY: guest mapping custody is the caller's explicit obligation.
        unsafe { Self::attach(mapped, expected) }
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
