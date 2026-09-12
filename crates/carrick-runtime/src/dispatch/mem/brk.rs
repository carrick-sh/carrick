//! Program break (`brk`/`sbrk`) heap management.
//!
//! Advances or retreats the program break (`brk_current`) within the heap region.
//! Growing re-validates identity leaves as RW and publishes permissions;
//! shrinking invalidates released pages and zeroes their raw backing so subsequent
//! re-growth re-exposes clean zero-filled anonymous memory matching Linux semantics.

use super::*;
use carrick_fatal::carrick_fatal;

pub(in crate::dispatch) fn update_semantic_heap_pages(
    mem: &mut MemState,
    old_page_end: u64,
    new_page_end: u64,
) {
    mem.semantic_vmas
        .update_heap_pages(old_page_end, new_page_end);
}

impl<'a> MemView<'a> {
    define_syscall! {
        mm_mutation fn brk(this, cx, requested: u64) {
            let permit = cx.mm_mutation.host_alias_permit();
            let mut host_alias_dispatch = this.begin_host_alias_dispatch(&permit);
            let mem_authority_13 = this.mem();
            let mut mem = mem_authority_13.lock();
            let current = mem.brk_current;
            if requested == 0 {
                return Ok(DispatchOutcome::returned_u64(current)?);
            }
            if range_within(requested, 0, mem.layout.heap_base, mem.layout.heap_size) {
                let page_size = this.linux_page_size();
                let Some(old_page_end) = align_up_u64(current, page_size) else {
                    return Ok(DispatchOutcome::returned_u64(current)?);
                };
                let Some(new_page_end) = align_up_u64(requested, page_size) else {
                    return Ok(DispatchOutcome::returned_u64(current)?);
                };

                if requested > current {
                    // RLIMIT_AS / RLIMIT_DATA on the page-rounded growth; the
                    // heap is data by definition. brk(2) reports ENOMEM by
                    // returning the unchanged break.
                    if let Some((as_limit, data_limit)) = this.address_space_limits_apply(true) {
                        let page_size = this.linux_page_size();
                        let grow = align_up_u64(requested, page_size)
                            .zip(align_up_u64(current, page_size))
                            .map_or(u64::MAX, |(new_end, old_end)| new_end.saturating_sub(old_end));
                        if this
                            .check_address_space_limits_locked(&mem, as_limit, data_limit, grow, true)
                            .is_err()
                        {
                            return Ok(DispatchOutcome::returned_u64(current)?);
                        }
                    }
                }

                if new_page_end > old_page_end {
                    // Grow: revalidate old-page-end..new-page-end identity leaves as RW,
                    // then publish RW in MemoryProtections (clearing unmapped atomically), then commit.
                    let grow_start = old_page_end;
                    let Some(grow_len) = new_page_end
                        .checked_sub(old_page_end)
                        .and_then(|len| usize::try_from(len).ok())
                    else {
                        return Ok(DispatchOutcome::returned_u64(current)?);
                    };
                    let rw = crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE;
                    if cx.memory.protect_range(grow_start, grow_len, rw).is_err() {
                        carrick_fatal!(
                            "dispatch::brk",
                            "protect_range failed during brk heap expansion"
                        );
                    }
                    cx.memory.set_mapping_protection(grow_start, grow_len, false, false);
                    update_semantic_heap_pages(&mut mem, old_page_end, new_page_end);
                    mem.brk_current = requested;
                    host_alias_dispatch.mark_vma_revision(mem_authority_13.revision_publisher());
                } else if new_page_end < old_page_end {
                    // Shrink: first make removed page tail stage-1-invalid, then publish
                    // unmapped, then zero raw backing for safe reuse, then commit.
                    let shrink_start = new_page_end;
                    let Some(shrink_len) = old_page_end
                        .checked_sub(new_page_end)
                        .and_then(|len| usize::try_from(len).ok())
                    else {
                        return Ok(DispatchOutcome::returned_u64(current)?);
                    };
                    if cx.memory.protect_range(shrink_start, shrink_len, 0).is_err() {
                        carrick_fatal!(
                            "dispatch::brk",
                            "protect_range failed during brk heap contraction"
                        );
                    }
                    cx.memory.set_unmapped(shrink_start, shrink_len, true);
                    if cx.memory.zero_backing(shrink_start, shrink_len).is_err() {
                        carrick_fatal!(
                            "dispatch::brk",
                            "zero_backing failed during brk heap contraction"
                        );
                    }
                    update_semantic_heap_pages(&mut mem, old_page_end, new_page_end);
                    mem.brk_current = requested;
                    host_alias_dispatch.mark_vma_revision(mem_authority_13.revision_publisher());
                } else if requested != current {
                    // Same-page movement: only update byte-precise break.
                    mem.brk_current = requested;
                    host_alias_dispatch.mark_vma_revision(mem_authority_13.revision_publisher());
                }
            }
            Ok(DispatchOutcome::returned_u64(mem.brk_current)?)
        }
    }
}

#[cfg(test)]
mod tests;
