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

fn translation(tables: &crate::page_table::PageTableManager, va: GuestVa) -> Result<u64, Error> {
    let leaf = carrick_mem::page_table::terminal_descriptor(tables.debug_walk(va.raw()));
    // AP[1] grants EL0 access for both RW (01) and read-only (11) leaves.
    if leaf & 1 == 0 || leaf & (1 << 6) == 0 {
        return Err(Error::Translation(va));
    }
    tables
        .translate_retained_output(va.raw())
        .ok_or(Error::Translation(va))
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
    if lease.state.protections.range_no_access(start.raw(), len) {
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
        |tables| translation(tables, start),
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
        if self.state.protections.range_no_access(va.raw(), dst.len()) {
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
            |tables| {
                if translation(tables, va)? != physical {
                    return Err(Error::Translation(va));
                }
                // SAFETY: preparation checked the entire single-leaf range against
                // this exact pinned owner. Live ledger, owner, permissions and leaf
                // were revalidated above. The page-table read lock spans the copy;
                // only bytes are copied, and no guest-memory reference escapes.
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
