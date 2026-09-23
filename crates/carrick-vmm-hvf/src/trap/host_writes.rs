//! Writer-only projection of ordinary syscall destinations. Read lookups keep
//! their scalar MappingView. These admissions track bytes, not executable entry.
use super::code_content::{CodeContent, ContentWrite};
use super::*;
use carrick_guest_mem::HostWriteRange;
use std::{ops::Deref, sync::Arc};

pub(crate) enum MappingSource<'a> {
    Region(&'a HvfMappedRegion),
    Alias(&'a AliasBacking),
}

impl MappingSource<'_> {
    pub(crate) fn view(&self) -> MappingView {
        match self {
            Self::Region(row) => row.view(),
            Self::Alias(alias) => MappingView::from_alias(alias),
        }
    }

    pub(crate) fn begin_write(
        &self,
        task: &HvfTaskState,
        custody: &CarrierVmCustody,
        address: u64,
        len: usize,
        expected_host: Option<usize>,
    ) -> Result<BackingWrite, MemoryError> {
        let error = || MemoryError::OutOfBounds {
            address,
            length: len,
        };
        let view = self.view();
        let offset = address.checked_sub(view.start).ok_or_else(error)?;
        let end = address.checked_add(len as u64).ok_or_else(error)?;
        if len == 0 || end > view.end {
            return Err(error());
        }
        let pointer = (view.host_addr as usize)
            .checked_add(offset as usize)
            .ok_or_else(error)?;
        if expected_host.is_some_and(|expected| expected != pointer) {
            return Err(error());
        }
        let (physical_ipa, physical_size, physical_host, generation, direct_structural) = match self
        {
            Self::Region(row) => {
                let projection_offset = row.ipa.checked_sub(row.physical_ipa).ok_or_else(error)?;
                let host = (row.host_addr as usize)
                    .checked_sub(projection_offset as usize)
                    .ok_or_else(error)?;
                (
                    row.physical_ipa,
                    row.physical_size,
                    host,
                    row.owner_generation,
                    row.structural_owner.as_ref(),
                )
            }
            Self::Alias(alias) => (
                alias.physical_ipa,
                alias.physical_size,
                alias.physical_host_addr,
                alias.owner_generation,
                None,
            ),
        };
        let physical_offset = view
            .ipa
            .checked_sub(physical_ipa)
            .and_then(|value| value.checked_add(offset))
            .and_then(|value| usize::try_from(value).ok())
            .ok_or_else(error)?;
        if physical_offset
            .checked_add(len)
            .is_none_or(|end| end > physical_size)
            || physical_host.checked_add(physical_offset) != Some(pointer)
        {
            return Err(error());
        }
        let owner = if let Some(pin) = pin_exact_live_global_frame_owner_in(
            custody,
            physical_ipa,
            physical_size as u64,
            physical_host,
            generation,
        ) {
            Some(WriteOwner::Global(pin))
        } else {
            let structural = direct_structural.cloned().or_else(|| {
                task.mm_access
                    .structural_owners
                    .read()
                    .get(&(physical_ipa, physical_size))
                    .cloned()
            });
            if let Some(owner) = structural {
                let owner_custody = owner.custody.upgrade().ok_or_else(error)?;
                if !std::ptr::eq(Arc::as_ptr(&owner_custody), custody)
                    || owner.physical_ipa != physical_ipa
                    || owner.len() != physical_size
                    || owner.ptr() as usize != physical_host
                    || (generation != 0 && generation != owner.epoch.raw())
                {
                    return Err(error());
                }
                let pin = owner_custody
                    .pin_stage2_record(owner.record_identity())
                    .map_err(|_| error())?;
                Some(WriteOwner::Structural { owner, _pin: pin })
            } else if generation == 0
                && !is_reusable_global_frame_extent(physical_ipa, physical_size as u64)
                && !custody
                    .global_frame_host_owners
                    .lock()
                    .contains_key(&(physical_ipa, physical_size as u64))
            {
                // Legacy/VM-control mappings have no tracked backing owner.
                // An unstamped row must not downgrade an existing tracked owner
                // (including retirement-pending ownership) to this path.
                // These mappings cannot supply a tracked instruction receipt. Preserve
                // their existing dispatch-lifetime access, without claiming
                // content or executable-publication coverage for them.
                None
            } else {
                return Err(error());
            }
        };
        let content = owner
            .map(|owner| ContentWrite::new(owner, physical_offset, len).map_err(|_| error()))
            .transpose()?;
        Ok(BackingWrite {
            view,
            pointer: pointer as *mut u8,
            content,
        })
    }
}

#[derive(Debug)]
enum WriteOwner {
    Global(GlobalFrameOwnerPin),
    Structural {
        owner: Arc<StructuralBackingOwner>,
        _pin: CarrierStage2Pin,
    },
}

impl Deref for WriteOwner {
    type Target = CodeContent;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Global(pin) => &pin.owner().mapping.code_content,
            Self::Structural { owner, .. } => &owner.retained.mapping.code_content,
        }
    }
}

pub(crate) struct BackingWrite {
    pub(crate) view: MappingView,
    pub(crate) pointer: *mut u8,
    // Kept through the copy/host call. Drop ends content admission before
    // releasing the exact stage-2/backing owner inside ContentWrite.
    #[cfg_attr(not(test), allow(dead_code))]
    content: Option<ContentWrite<WriteOwner>>,
}

impl BackingWrite {
    #[cfg(test)]
    pub(crate) fn visited_pages(&self) -> usize {
        self.content.as_ref().map_or(0, ContentWrite::visited_pages)
    }
}

/// Scratch belongs to one executor, never to the shared MM. Capacity is reused
/// across host calls; finish drops admissions, not the allocation.
#[derive(Default)]
pub(crate) struct HostWrites {
    writes: Vec<BackingWrite>,
}

impl HostWrites {
    pub(crate) fn begin(
        &mut self,
        task: &HvfTaskState,
        custody: &CarrierVmCustody,
        ranges: &[HostWriteRange],
    ) -> Result<(), MemoryError> {
        debug_assert!(self.writes.is_empty(), "nested host write admission");
        let result = self.admit(task, custody, ranges);
        if result.is_err() {
            self.finish();
        }
        result
    }

    fn admit(
        &mut self,
        task: &HvfTaskState,
        custody: &CarrierVmCustody,
        ranges: &[HostWriteRange],
    ) -> Result<(), MemoryError> {
        for range in ranges {
            let address = strip_pointer_tag(range.guest.raw());
            let error = || MemoryError::OutOfBounds {
                address,
                length: range.len,
            };
            if task.protections.range_write_denied(address, range.len) {
                return Err(error());
            }
            if range.len == 0 {
                continue;
            }
            let lookup = if crate::memory::needs_stage1_translation(address, range.len as u64) {
                task.translate_va(address).unwrap_or(address)
            } else {
                address
            };
            // A zero-copy range is one contiguous mapping. Retain that owner
            // once, rather than growing a pin/vector entry for every 4 KiB.
            let write = task
                .with_mapping_for_range_in(custody, lookup, range.len, |source| {
                    if !source.view().guest_writable {
                        return Err(error());
                    }
                    source.begin_write(task, custody, lookup, range.len, Some(range.host.raw()))
                })
                .ok_or_else(error)??;
            let first_ipa = write
                .view
                .ipa
                .checked_add(lookup.checked_sub(write.view.start).ok_or_else(error)?)
                .ok_or_else(error)?;
            let mut checked = 0;
            while checked < range.len {
                let (va, len) = HvfVmState::guest_copy_chunk(address, checked, range.len)?;
                let lookup = if crate::memory::needs_stage1_translation(va, len as u64) {
                    task.translate_va(va).unwrap_or(va)
                } else {
                    va
                };
                let view = task
                    .mapping_for_range_in(custody, lookup, len)
                    .ok_or_else(error)?;
                let offset = lookup.checked_sub(view.start).ok_or_else(error)?;
                if !view.guest_writable
                    || (view.host_addr as usize).checked_add(offset as usize)
                        != range.host.raw().checked_add(checked)
                    || view.ipa.checked_add(offset) != first_ipa.checked_add(checked as u64)
                {
                    return Err(error());
                }
                checked += len;
            }
            self.writes.push(write);
        }
        Ok(())
    }

    pub(crate) fn finish(&mut self) {
        self.writes.clear();
    }

    #[cfg(test)]
    pub(crate) fn visited_pages(&self) -> usize {
        self.writes.iter().map(BackingWrite::visited_pages).sum()
    }
}
