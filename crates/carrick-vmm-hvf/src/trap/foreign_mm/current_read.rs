//! Resident, single-leaf input capability. Preparation may inspect the full
//! snapshot; reuse observes only the accessed leaf and exact backing owner.
use super::*;
use carrick_guest_mem::GuestVa;
use carrick_hal::{
    ForeignMmLiveAuthority, ForeignMmReadWindow, ForeignMmSnapshot,
    ForeignMmTransportError as Error,
};
use std::{sync::Arc, time::Instant};

struct ReadWindow {
    custody: Arc<CarrierVmCustody>,
    state: Arc<MmAccessState>,
    snapshot: CarrierForeignMmSnapshot,
    start: GuestVa,
    len: usize,
    physical: u64,
    logical_key: (u64, u64),
    owner_key: (u64, u64),
    mapping: carrick_hal::MappingId,
    frame: carrick_hal::FrameId,
    pin: GlobalFrameOwnerPin,
}

impl std::fmt::Debug for ReadWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadWindow")
            .field("start", &self.start)
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

/// Walk hardware-visible descriptors. The caller holds the MM mutation and
/// page-table read guards through validation/copy. Each descriptor is resolved
/// against this MM's live inventory and exact backing generation; neither a
/// software descriptor shadow nor a retained pointer is translation authority.
fn translation(
    state: &MmAccessState,
    custody: &CarrierVmCustody,
    root: carrick_guest_mem::Gpa,
    va: GuestVa,
    deadline: Instant,
) -> Result<u64, Error> {
    use std::sync::atomic::{AtomicU64, Ordering};
    const ADDRESS_MASK: u64 = 0x0000_ffff_ffff_f000;
    let mut table = root.raw();
    for (level, shift) in [39, 30, 21, 12].into_iter().enumerate() {
        let ipa = table
            .checked_add(((va.raw() >> shift) & 0x1ff) * 8)
            .ok_or(Error::Translation(va))?;
        let inventory = state
            .frame_inventory
            .ledger
            .try_lock_until(deadline)
            .ok_or(Error::TimedOut)?;
        let (&logical, extent) = inventory
            .extents
            .range(..=(ipa, u64::MAX))
            .next_back()
            .filter(|(key, _)| {
                ipa.checked_add(8)
                    .is_some_and(|end| key.0.checked_add(key.1).is_some_and(|limit| end <= limit))
            })
            .ok_or(Error::OwnerStale)?;
        let key = (extent.stage2_base, extent.stage2_length);
        let expected = extent.stage2_owner;
        if logical.0 < key.0
            || logical
                .0
                .checked_add(logical.1)
                .is_none_or(|end| key.0.checked_add(key.1).is_none_or(|limit| end > limit))
        {
            return Err(Error::OwnerStale);
        }
        let offset = ipa
            .checked_sub(key.0)
            .and_then(|v| usize::try_from(v).ok())
            .ok_or(Error::OwnerStale)?;
        let owners = custody
            .global_frame_host_owners
            .try_lock_until(deadline)
            .ok_or(Error::TimedOut)?;
        let structural = state
            .structural_owners
            .try_read_until(deadline)
            .ok_or(Error::TimedOut)?;
        let ptr = if let Some(owner) = owners
            .get(&key)
            .and_then(GlobalFrameOwnerEntry::live_owner)
            .filter(|owner| {
                owner.generation() != 0
                    && owner.generation() == expected.generation
                    && owner.host_addr() == expected.host_addr
                    && owner.length() == key.1
            }) {
            owner.ptr()
        } else {
            let size = usize::try_from(key.1).map_err(|_| Error::OwnerStale)?;
            structural
                .get(&(key.0, size))
                .filter(|owner| {
                    owner.epoch.raw() != 0
                        && owner.epoch.raw() == expected.generation
                        && owner.ptr() as usize == expected.host_addr
                        && owner.len() == size
                })
                .ok_or(Error::OwnerStale)?
                .ptr()
        };
        if offset.checked_add(8).is_none_or(|end| end as u64 > key.1)
            || (ptr as usize)
                .checked_add(offset)
                .is_none_or(|addr| addr % 8 != 0)
        {
            return Err(Error::OwnerStale);
        }
        // SAFETY: exact live owner and full aligned descriptor extent checked
        // above. Registry guards retain its storage across the atomic load.
        let descriptor = unsafe { (*ptr.add(offset).cast::<AtomicU64>()).load(Ordering::Acquire) };
        if descriptor & 1 == 0 {
            return Err(Error::Translation(va));
        }
        if level < 3 && descriptor & 2 != 0 {
            table = descriptor & ADDRESS_MASK;
            continue;
        }
        // L0 blocks and an L3 table-bit-clear descriptor are reserved. AP[1]
        // must grant EL0 access for either a read-only or read-write leaf.
        if level == 0 || (level == 3 && descriptor & 2 == 0) || descriptor & (1 << 6) == 0 {
            return Err(Error::Translation(va));
        }
        let mask = (1_u64 << shift) - 1;
        return Ok((descriptor & ADDRESS_MASK & !mask) | (va.raw() & mask));
    }
    Err(Error::Translation(va))
}

pub(super) fn prepare(
    lease: &CarrierForeignMmReadLease,
    authority: &dyn ForeignMmLiveAuthority,
    snapshot: &dyn ForeignMmSnapshot,
    start: GuestVa,
    len: usize,
    deadline: Instant,
) -> Result<Box<dyn ForeignMmReadWindow>, Error> {
    let end = start
        .raw()
        .checked_add(len as u64)
        .ok_or(Error::Translation(start))?;
    if len == 0 || (start.raw() & !0xfff) != ((end - 1) & !0xfff) {
        return Err(Error::AuthorityUnavailable);
    }
    let inner = lease
        .inner
        .try_lock_until(deadline)
        .ok_or(Error::TimedOut)?;
    if !inner.retained.has_same_contents(snapshot) {
        return Err(Error::LeaseStale);
    }
    let _coordinator = lease
        .state
        .mutation_coordinator
        .try_lock_until(deadline)
        .ok_or(Error::TimedOut)?;
    if !authority.snapshot(deadline)?.has_same_contents(snapshot) {
        return Err(Error::LeaseStale);
    }
    if lease
        .state
        .protections
        .legacy()
        .is_none_or(|protections| protections.range_no_access(start.raw(), len))
    {
        return Err(Error::Translation(start));
    }
    let page_tables = lease
        .state
        .page_tables
        .try_read_until(deadline)
        .ok_or(Error::TimedOut)?;
    let physical = page_tables.try_with_manager_until(
        deadline,
        Error::TimedOut,
        Error::AuthorityUnavailable,
        |_| {
            translation(
                &lease.state,
                &lease.custody,
                snapshot.binding().stage1_root(),
                start,
                deadline,
            )
        },
    )?;
    let inventory = lease
        .state
        .frame_inventory
        .ledger
        .try_lock_until(deadline)
        .ok_or(Error::TimedOut)?;
    let (&logical_key, extent) = inventory
        .extents
        .iter()
        .find(|(key, extent)| {
            key.0 <= physical
                && physical
                    .checked_add(len as u64)
                    .is_some_and(|end| key.0.checked_add(key.1).is_some_and(|limit| end <= limit))
                && snapshot.mapping_ids().contains(&extent.mapping)
        })
        .ok_or(Error::OwnerStale)?;
    let owner_key = (extent.stage2_base, extent.stage2_length);
    let expected = extent.stage2_owner;
    let mapping = extent.mapping;
    let frame = extent.frame;
    if physical < owner_key.0
        || physical.checked_add(len as u64).is_none_or(|end| {
            owner_key
                .0
                .checked_add(owner_key.1)
                .is_none_or(|limit| end > limit)
        })
    {
        return Err(Error::OwnerStale);
    }
    drop(inventory);
    let owners = lease
        .custody
        .global_frame_host_owners
        .try_lock_until(deadline)
        .ok_or(Error::TimedOut)?;
    let owner = owners
        .get(&owner_key)
        .and_then(GlobalFrameOwnerEntry::live_owner)
        .ok_or(Error::AuthorityUnavailable)?;
    if owner.generation() == 0
        || owner.generation() != expected.generation
        || owner.host_addr() != expected.host_addr
        || owner.length() != owner_key.1
    {
        return Err(Error::OwnerStale);
    }
    let pin = owner.pin().map_err(|_| Error::OwnerStale)?;
    #[cfg(any(test, feature = "foreign-cow-test-support"))]
    lease
        .state
        .copy_owner_pins
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    drop(owners);
    if !authority.matches_authenticated_snapshot(snapshot, deadline)? {
        return Err(Error::LeaseStale);
    }
    drop(page_tables);
    Ok(Box::new(ReadWindow {
        custody: Arc::clone(&lease.custody),
        state: Arc::clone(&lease.state),
        snapshot: CarrierForeignMmSnapshot::capture(snapshot),
        start,
        len,
        physical,
        logical_key,
        owner_key,
        mapping,
        frame,
        pin,
    }))
}

impl ForeignMmReadWindow for ReadWindow {
    fn authenticates(&self, snapshot: &dyn ForeignMmSnapshot, start: GuestVa, len: usize) -> bool {
        self.snapshot.has_same_contents(snapshot) && self.start == start && self.len == len
    }

    fn copy_into(
        &self,
        authority: &dyn ForeignMmLiveAuthority,
        snapshot: &dyn ForeignMmSnapshot,
        va: GuestVa,
        dst: &mut [u8],
        deadline: Instant,
    ) -> Result<(), Error> {
        // Kernel-owned windows authenticate full contents only on preparation.
        // Equal non-reusing authority revisions are necessary on each reuse.
        if self.snapshot.mm != snapshot.mm()
            || self.snapshot.binding() != snapshot.binding()
            || self.snapshot.backend_revision != snapshot.backend_revision()
            || self.snapshot.vma_revision != snapshot.vma_revision()
            || self.snapshot.frame_inventory_revision != snapshot.frame_inventory_revision()
            || va.raw() < self.start.raw()
            || va
                .raw()
                .checked_add(dst.len() as u64)
                .is_none_or(|end| end > self.start.raw() + self.len as u64)
        {
            return Err(Error::LeaseStale);
        }
        let _coordinator = self
            .state
            .mutation_coordinator
            .try_lock_until(deadline)
            .ok_or(Error::TimedOut)?;
        if !authority.matches_authenticated_snapshot(&self.snapshot, deadline)? {
            return Err(Error::LeaseStale);
        }
        if self
            .state
            .identity
            .try_read_until(deadline)
            .ok_or(Error::TimedOut)?
            .as_ref()
            != Some(&(self.snapshot.mm, self.snapshot.binding))
        {
            return Err(Error::MissingBinding);
        }
        let owner = self.pin.owner();
        {
            let inventory = self
                .state
                .frame_inventory
                .ledger
                .try_lock_until(deadline)
                .ok_or(Error::TimedOut)?;
            if !inventory.extents.get(&self.logical_key).is_some_and(|e| {
                e.mapping == self.mapping
                    && e.frame == self.frame
                    && e.stage2_base == self.owner_key.0
                    && e.stage2_length == self.owner_key.1
                    && e.stage2_owner.host_addr == owner.host_addr()
                    && e.stage2_owner.generation == owner.generation()
            }) {
                return Err(Error::OwnerStale);
            }
        }
        if !global_frame_host_owner_matches_in(
            &self.custody,
            self.owner_key.0,
            self.owner_key.1,
            owner.host_addr(),
            owner.generation(),
        ) {
            return Err(Error::OwnerStale);
        }
        if self
            .state
            .protections
            .legacy()
            .is_none_or(|protections| protections.range_no_access(va.raw(), dst.len()))
        {
            return Err(Error::Translation(va));
        }
        let physical = self
            .physical
            .checked_add(va.raw() - self.start.raw())
            .ok_or(Error::Translation(va))?;
        let offset = usize::try_from(physical - self.owner_key.0).map_err(|_| Error::OwnerStale)?;
        let page_tables = self
            .state
            .page_tables
            .try_read_until(deadline)
            .ok_or(Error::TimedOut)?;
        page_tables.try_with_manager_until(
            deadline,
            Error::TimedOut,
            Error::AuthorityUnavailable,
            |_| {
                if translation(
                    &self.state,
                    &self.custody,
                    self.snapshot.binding().stage1_root(),
                    va,
                    deadline,
                )? != physical
                {
                    return Err(Error::Translation(va));
                }
                // SAFETY: preparation checked the entire single-leaf range against
                // this exact pinned owner. Live ledger, owner, permissions and hardware
                // leaf were revalidated above. The mutation/page-table guards span the
                // copy; only bytes are copied and no guest-memory reference escapes.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        owner.ptr().add(offset),
                        dst.as_mut_ptr(),
                        dst.len(),
                    );
                }
                Ok(())
            },
        )?;
        drop(page_tables);
        if !authority.matches_authenticated_snapshot(&self.snapshot, deadline)? {
            return Err(Error::LeaseStale);
        }
        Ok(())
    }
}
