//! Native x86 preparation for the shared owner fork transaction.
//! The caller retains its exact-MM editor and supplies its reservation census,
//! zeroed child/parent table arenas, and the live descriptor word venue.

use carrick_core::mm::fork::{
    ForkError, ForkScratch, ForkTableCursor, Mapping, MappingInheritancePolicy, PreparedOwnerFork,
    copy_table,
};
use carrick_el1_abi::PortalForkRequest;
use carrick_guest_arch::RootGpa;
use carrick_mmu_core::live_descriptor_words::LiveDescriptorWords;
use carrick_mmu_core::x86::owner_mmu::X86Mmu;

/// Prepare the exact x86 table copy and parent COW journal without publishing
/// either root. The returned neutral transaction owns rollback and completion;
/// the caller supplies real owner metadata to `publish` and `commit`.
pub fn prepare_owner_fork<W: LiveDescriptorWords + ?Sized, P: MappingInheritancePolicy>(
    words: &W,
    request: PortalForkRequest,
    parent_root: RootGpa,
    mappings: &[Mapping],
    policy: &P,
) -> Result<PreparedOwnerFork<X86Mmu>, ForkError> {
    let parent_root = parent_root.address().raw();
    if !request.valid() || parent_root == 0 {
        return Err(ForkError::Invalid);
    }
    let mut scratch = ForkScratch::new(request, mappings.len())?;
    scratch.mappings.extend_from_slice(mappings);
    copy_table::<X86Mmu, _, _>(
        policy,
        words,
        request,
        &mut scratch,
        ForkTableCursor {
            table: parent_root,
            level: 0,
            base: 0,
            child_offset: 0,
        },
    )?;
    Ok(PreparedOwnerFork::new(request, parent_root, scratch))
}
