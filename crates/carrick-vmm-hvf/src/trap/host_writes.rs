//! Host access admission for ordinary syscall sources and destinations.
//!
//! Every host-side copy or host call that touches guest memory through a raw
//! host pointer is admitted here, in either direction: the exact backing owner
//! (owner, host VA and generation) is re-validated against the selected live
//! mapping and pinned until the access ends, so retirement of that frame by a
//! sibling's `munmap`/`MAP_FIXED`/`mremap` or a COW repoint is deferred
//! (`DeferredActivePins`) instead of recycling it under the access. Writes
//! additionally admit content (executable-receipt revocation). These
//! admissions track bytes, not executable entry.
use super::code_content::{CodeContent, ContentWrite};
use super::*;
use carrick_guest_mem::{HostRead, HostReadRetention, HostWriteRange};
use std::{ops::Deref, sync::Arc};

/// Direction of one host access to guest memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HostAccess {
    Read,
    Write,
}

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

    /// Admit one access to `[address, address+len)` of this live mapping:
    /// re-validate the exact backing owner and retain it for the access.
    pub(crate) fn begin_access(
        &self,
        access: HostAccess,
        task: &HvfTaskState,
        custody: &CarrierVmCustody,
        address: u64,
        len: usize,
        expected_host: Option<usize>,
    ) -> Result<BackingAccess, MemoryError> {
        let error = || MemoryError::OutOfBounds {
            address,
            length: len,
        };
        // A physical generation authenticates backing, not guest access.
        // Admitted MMs must arrive through owner-issued UserTransfer pins.
        let _legacy = task.protections.legacy().ok_or_else(error)?;
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
            Some(BackingOwner::Global(pin))
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
                Some(BackingOwner::Structural { owner, _pin: pin })
            } else if generation == 0
                && self.untracked_backing_outlives_access(task)
                && !is_reusable_global_frame_extent(physical_ipa, physical_size as u64)
                && !custody
                    .global_frame_host_owners
                    .lock()
                    .contains_key(&(physical_ipa, physical_size as u64))
            {
                // Untracked VM-control mappings have no backing owner to pin.
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
        let admission = match access {
            HostAccess::Read => Admission::Read(owner),
            HostAccess::Write => Admission::Write(
                owner
                    .map(|owner| {
                        ContentWrite::new(owner, physical_offset, len).map_err(|_| error())
                    })
                    .transpose()?,
            ),
        };
        Ok(BackingAccess {
            view,
            pointer: pointer as *mut u8,
            admission,
        })
    }

    /// Whether an unpinned (untracked) row's host backing provably outlives
    /// any host access. In the persistent HVPatch carrier every guest frame
    /// has a global or structural owner, so only the fixed carrier control
    /// mappings (owned carrier-wide by `PersistentCarrierMappings`, dropped
    /// only after the VM) are untracked; any other unstamped row there could
    /// be torn down by a sibling's unmap and must not be accessed unpinned.
    /// The non-persistent lifecycle exists only for single-mm bring-up before
    /// the runtime enables the persistent carrier, with no sibling to unmap.
    fn untracked_backing_outlives_access(&self, task: &HvfTaskState) -> bool {
        if !task.persistent_vm_lifecycle {
            return true;
        }
        match self {
            Self::Region(row) => is_persistent_executor_carrier_mapping(row),
            Self::Alias(_) => false,
        }
    }
}

#[derive(Debug)]
enum BackingOwner {
    Global(GlobalFrameOwnerPin),
    Structural {
        owner: Arc<StructuralBackingOwner>,
        _pin: CarrierStage2Pin,
    },
}

impl Deref for BackingOwner {
    type Target = CodeContent;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Global(pin) => &pin.owner().mapping.code_content,
            Self::Structural { owner, .. } => &owner.retained.mapping.code_content,
        }
    }
}

// Retention for one access, kept through the copy/host call. A write's drop
// ends content admission before releasing the exact stage-2/backing owner
// inside ContentWrite; a read retains only the owner.
#[derive(Debug)]
enum Admission {
    Read(#[allow(dead_code)] Option<BackingOwner>),
    Write(#[cfg_attr(not(test), allow(dead_code))] Option<ContentWrite<BackingOwner>>),
}

pub(crate) struct BackingAccess {
    pub(crate) view: MappingView,
    pub(crate) pointer: *mut u8,
    admission: Admission,
}

impl BackingAccess {
    #[cfg(test)]
    pub(crate) fn visited_pages(&self) -> usize {
        match &self.admission {
            Admission::Write(content) => content.as_ref().map_or(0, ContentWrite::visited_pages),
            Admission::Read(_) => 0,
        }
    }

    /// Whether this access holds a tracked owner pin (false only for the
    /// untracked carrier control mappings).
    #[cfg(test)]
    pub(crate) fn retains_owner(&self) -> bool {
        match &self.admission {
            Admission::Read(owner) => owner.is_some(),
            Admission::Write(content) => content.is_some(),
        }
    }
}

/// A global owner retains a host read through its own immutable record
/// identity: the read's exact logical and stage-2 pins transfer to the
/// `Arc<GlobalFrameHostOwner>` the pin already holds, coerced without
/// allocation, and are released here when the `HostRead` drops.
impl HostReadRetention for GlobalFrameHostOwner {
    fn release(&self) {
        self.mapping.unpin();
        if let Some(custody) = self.custody.upgrade() {
            custody.release_stage2_pin(self.record_identity);
        }
    }
}

/// A structural owner's record identity can be rebound, so its retention keeps
/// the exact pinned record (one allocation; structural rows are image and
/// kernel-state mappings, not the anonymous hot path).
struct StructuralReadRetention {
    _owner: Arc<StructuralBackingOwner>,
    pin: parking_lot::Mutex<Option<CarrierStage2Pin>>,
}

impl HostReadRetention for StructuralReadRetention {
    fn release(&self) {
        drop(self.pin.lock().take());
    }
}

impl BackingOwner {
    fn into_read_retention(self) -> Arc<dyn HostReadRetention> {
        match self {
            Self::Global(pin) => pin.into_read_retention(),
            Self::Structural { owner, _pin } => Arc::new(StructuralReadRetention {
                _owner: owner,
                pin: parking_lot::Mutex::new(Some(_pin)),
            }),
        }
    }
}

impl HvfTaskState {
    /// Admit `len` bytes at guest `address` (one contiguous mapping) as a
    /// zero-copy host-call SOURCE, retaining the exact backing owner for the
    /// lifetime of the returned [`HostRead`].
    pub(crate) fn admit_host_read(
        &self,
        custody: &CarrierVmCustody,
        address: u64,
        len: usize,
    ) -> Option<HostRead> {
        let address = strip_pointer_tag(address);
        if len == 0
            || self
                .protections
                .legacy()
                .is_none_or(|protections| protections.range_no_access(address, len))
        {
            return None;
        }
        let access = admit_contiguous(self, custody, HostAccess::Read, address, len, None).ok()?;
        let retention = match access.admission {
            Admission::Read(owner) => owner.map(BackingOwner::into_read_retention),
            Admission::Write(_) => return None,
        };
        // SAFETY: `admit_contiguous` proved every page-bounded fragment of the
        // range is one live mapping advancing linearly from `pointer`, and the
        // retention (when the row is tracked) keeps that exact owner from
        // retirement until the HostRead drops. Untracked rows are carrier
        // control mappings that outlive every access.
        Some(unsafe {
            HostRead::retained(
                carrick_guest_mem::GuestVa(address),
                access.pointer,
                len,
                retention,
            )
        })
    }
}

/// Admit one contiguous host range for `access`. The whole range must be a
/// single live mapping, selected exactly like the per-page copy path, whose
/// IPA and host pointer advance linearly; `expected_host` (when supplied by a
/// caller that resolved the pointer earlier) must match the current owner.
fn admit_contiguous(
    task: &HvfTaskState,
    custody: &CarrierVmCustody,
    access: HostAccess,
    address: u64,
    len: usize,
    expected_host: Option<usize>,
) -> Result<BackingAccess, MemoryError> {
    let error = || MemoryError::OutOfBounds {
        address,
        length: len,
    };
    let writable = |view: &MappingView| access == HostAccess::Read || view.guest_writable;
    let lookup = if crate::memory::needs_stage1_translation(address, len as u64) {
        task.translate_va(address).unwrap_or(address)
    } else {
        address
    };
    // A zero-copy range is one contiguous mapping. Retain that owner
    // once, rather than growing a pin/vector entry for every 4 KiB.
    let admitted = task
        .with_mapping_for_range_in(custody, lookup, len, |source| {
            if !writable(&source.view()) {
                return Err(error());
            }
            source.begin_access(access, task, custody, lookup, len, expected_host)
        })
        .ok_or_else(error)??;
    let first_ipa = admitted
        .view
        .ipa
        .checked_add(lookup.checked_sub(admitted.view.start).ok_or_else(error)?)
        .ok_or_else(error)?;
    let first_host = admitted.pointer as usize;
    let mut checked = 0;
    while checked < len {
        let (va, chunk) = HvfVmState::guest_copy_chunk(address, checked, len)?;
        let lookup = if crate::memory::needs_stage1_translation(va, chunk as u64) {
            task.translate_va(va).unwrap_or(va)
        } else {
            va
        };
        let view = task
            .mapping_for_range_in(custody, lookup, chunk)
            .ok_or_else(error)?;
        let offset = lookup.checked_sub(view.start).ok_or_else(error)?;
        if !writable(&view)
            || (view.host_addr as usize).checked_add(offset as usize)
                != first_host.checked_add(checked)
            || view.ipa.checked_add(offset) != first_ipa.checked_add(checked as u64)
        {
            return Err(error());
        }
        checked += chunk;
    }
    Ok(admitted)
}

/// Scratch belongs to one executor, never to the shared MM. Capacity is reused
/// across host calls; finish drops admissions, not the allocation.
#[derive(Default)]
pub(crate) struct HostWrites {
    writes: Vec<BackingAccess>,
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
            if task
                .protections
                .legacy()
                .is_none_or(|protections| protections.range_write_denied(address, range.len))
            {
                return Err(MemoryError::OutOfBounds {
                    address,
                    length: range.len,
                });
            }
            if range.len == 0 {
                continue;
            }
            let write = admit_contiguous(
                task,
                custody,
                HostAccess::Write,
                address,
                range.len,
                Some(range.host.raw()),
            )?;
            self.writes.push(write);
        }
        Ok(())
    }

    pub(crate) fn finish(&mut self) {
        self.writes.clear();
    }

    #[cfg(test)]
    pub(crate) fn visited_pages(&self) -> usize {
        self.writes.iter().map(BackingAccess::visited_pages).sum()
    }
}
