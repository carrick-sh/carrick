//! Exact identity and pinned host resolution of guest-owned metadata storage.

use core::ptr::NonNull;

/// One complete grant, not a suballocation or a guest-user mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct MetadataExtent {
    base: u64,
    len: u64,
    token: u64,
}

impl MetadataExtent {
    pub fn new(base: u64, len: u64, token: u64) -> Option<Self> {
        (base != 0 && len != 0 && token != 0 && base.checked_add(len).is_some()).then_some(Self {
            base,
            len,
            token,
        })
    }
    pub const fn base(self) -> u64 {
        self.base
    }
    pub const fn len(self) -> u64 {
        self.len
    }
    pub const fn is_empty(self) -> bool {
        false
    }
    pub const fn token(self) -> u64 {
        self.token
    }
    pub fn contains(self, base: u64, len: u64) -> bool {
        base >= self.base
            && base
                .checked_add(len)
                .is_some_and(|end| end <= self.base + self.len)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetadataResolutionError {
    InvalidExtent,
    StaleOwner,
    Busy,
}

/// Owns the host backing until dropped; obtaining a pin does not transfer the
/// guest allocator's allocation or grant-return authority.
///
/// # Safety
/// `host_base` must cover the exact receipt throughout this value's lifetime.
/// Returning/unmapping the extent must be excluded while a pin exists. Raw
/// access still requires the metadata consumer's own synchronization.
pub unsafe trait PinnedMetadataExtent {
    fn extent(&self) -> MetadataExtent;
    fn host_base(&self) -> NonNull<u8>;
}

/// The resolver is bound to one carrier and VM generation. It must authenticate
/// the complete grant identity before pinning. User-copy pointers cannot satisfy
/// this interface: their dispatch lifetime is unrelated to extent ownership.
pub trait MetadataExtentResolver {
    type Pin: PinnedMetadataExtent;
    fn pin(&self, extent: MetadataExtent) -> Result<Self::Pin, MetadataResolutionError>;
}
