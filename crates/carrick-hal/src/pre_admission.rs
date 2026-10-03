//! Physical preparation borrows the kernel's existing publication owner.
use core::num::NonZeroU64;

/// Implemented by the kernel guard holding address-space publication exclusion.
///
/// # Safety
/// The owner must retain its publication lock for every issued permit, and
/// report unpublished only when no target root can name prepared physical data.
pub unsafe trait PreAdmissionOwner {
    fn mm(&self) -> NonZeroU64;
    fn unpublished(&self) -> bool;
}

/// A borrowed, exact-MM pre-admission physical preparation capability.
pub struct PreAdmissionPermit<'a> {
    owner: &'a dyn PreAdmissionOwner,
}
impl<'a> PreAdmissionPermit<'a> {
    pub fn new(owner: &'a dyn PreAdmissionOwner) -> Option<Self> {
        owner.unpublished().then_some(Self { owner })
    }
    pub fn mm(&self) -> NonZeroU64 {
        self.owner.mm()
    }
    pub fn unpublished(&self) -> bool {
        self.owner.unpublished()
    }
    pub fn authenticates(&self, receipt: &PreAdmissionReceipt<'_>) -> bool {
        core::ptr::addr_eq(self.owner, receipt.owner) && self.mm() == receipt.owner.mm()
    }
}

/// Normal root admission has completed under the same publication owner.
pub struct PreAdmissionReceipt<'a> {
    owner: &'a dyn PreAdmissionOwner,
}
impl<'a> PreAdmissionReceipt<'a> {
    /// # Safety
    /// The exact owner's normal root admission and descriptor/backing setup
    /// must have completed successfully before issuing this receipt.
    pub unsafe fn after_admission(owner: &'a dyn PreAdmissionOwner) -> Self {
        Self { owner }
    }
}
