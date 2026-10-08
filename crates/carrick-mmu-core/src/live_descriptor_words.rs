//! ISA-neutral access to a live stage-1 descriptor graph.

use crate::descriptor_refusal::DescriptorRefusal;

/// Hardware access to one live stage-1 table graph by table physical address.
pub trait LiveDescriptorWords {
    /// Load one descriptor; reject addresses outside the admitted table arena.
    fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal>;
    /// Replace exactly `current` by `new`; false means editor exclusion failed.
    fn compare_exchange(&self, pa: u64, current: u64, new: u64) -> Result<bool, DescriptorRefusal>;
    /// Store into a granted table page unreachable by hardware walkers.
    fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), DescriptorRefusal>;
    /// Make earlier stores visible to table walkers before linking the page.
    fn publish_barrier(&self);
    /// Invalidate this MM's translation for `[va, va + len)`.
    fn invalidate_range(&self, va: u64, len: u64);
}
