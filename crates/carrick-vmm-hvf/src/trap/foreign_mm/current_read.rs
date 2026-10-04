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

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
mod owner_tests {
    use super::*;
    use carrick_aarch64::user_transfer::{TransferCustody, TransferPin};
    use carrick_el1::personality::mm_portal::{MmPortal, test_support as owner};
    use carrick_el1_abi::{AddressSpaces, SlotId, ZONE_SLOTS};
    use std::num::{NonZeroU16, NonZeroU64};
    use std::time::Duration;

    #[derive(Debug)]
    struct Live(CarrierForeignMmSnapshot);
    impl ForeignMmLiveAuthority for Live {
        fn snapshot(&self, _: Instant) -> Result<Box<dyn ForeignMmSnapshot>, Error> {
            Ok(Box::new(self.0.clone()))
        }
    }

    /// Physical fixture only: admission/permissions remain the existing EL1
    /// reservation and descriptor owners. No replacement observer policy.
    fn install(
        custody: &Arc<CarrierVmCustody>,
        handle: carrick_el1_abi::El1MmHandle,
        tables: &owner::Tables,
        ipa: u64,
        fill: u8,
    ) -> Result<(Arc<MmAccessState>, CarrierForeignMmSnapshot), String> {
        let ordinal = handle.mm().raw();
        let mut inventory = HvpatchFrameInventory::default();
        let mut mappings = Vec::new();
        for (base, len, data) in [
            (tables.base, tables.words.len() * 8, true),
            (ipa, 0x4000, false),
        ] {
            let mapping = crate::host_mapping::OwnedHostMapping::map_shared_anon(
                len,
                crate::host_mapping::HostMappingKind::PerMmKernelState,
            )
            .map_err(|error| format!("physical fixture allocation: {error:?}"))?;
            let generation = next_global_frame_owner_generation();
            let host_addr = mapping.as_ptr() as usize;
            // SAFETY: this fixture owns the entire new allocation. Descriptor
            // words originate in the existing production-owner test fixture.
            unsafe {
                if data {
                    std::ptr::copy_nonoverlapping(
                        tables.words.as_ptr().cast::<u8>(),
                        mapping.as_ptr(),
                        len,
                    );
                } else {
                    mapping.as_ptr().write_bytes(fill, len);
                }
            }
            let physical = GlobalFrameHostOwner::new(
                GlobalFrameStage2Lease::fixed(base, len as u64),
                mapping,
                3,
                generation,
                base,
                len as u64,
            );
            custody.global_frame_host_owners.lock().insert(
                (base, len as u64),
                GlobalFrameOwnerEntry::Live(Arc::new(physical)),
            );
            let id = NonZeroU64::new(ordinal * 10 + u64::from(data))
                .ok_or("physical fixture mapping identity is zero")?;
            let mapping = carrick_hal::MappingId::from_kernel_allocation(id);
            mappings.push(mapping);
            inventory.extents.insert(
                (base, len as u64),
                InventoryExtent {
                    frame: carrick_hal::FrameId::from_kernel_allocation(id),
                    mapping,
                    backing: InventoryBackingIdentity::Private(id.get()),
                    stage2_base: base,
                    stage2_length: len as u64,
                    stage2_owner: InventoryStage2OwnerIdentity {
                        host_addr,
                        generation,
                    },
                },
            );
        }
        let binding = CarrierForeignMmBinding {
            asid: carrick_hal::ForeignAsid::from_kernel_allocation(
                NonZeroU16::new(
                    u16::try_from(ordinal).map_err(|error| format!("fixture ASID: {error}"))?,
                )
                .ok_or("physical fixture ASID is zero")?,
            ),
            stage1_root: carrick_guest_mem::Gpa(tables.base),
        };
        let snapshot = CarrierForeignMmSnapshot {
            mm: carrick_hal::ForeignMmId::from_kernel_allocation(
                NonZeroU64::new(ordinal).ok_or("physical fixture MM identity is zero")?,
            ),
            binding,
            backend_revision: carrick_hal::ForeignBackendRevision::from_authority_raw(1),
            vma_revision: carrick_hal::ForeignVmaRevision::from_authority_raw(1),
            frame_inventory_revision:
                carrick_hal::ForeignFrameInventoryRevision::from_authority_raw(1),
            mapping_ids: mappings,
            executable_ranges: Vec::new(),
            readable_ranges: vec![
                carrick_hal::ForeignReadableRange::from_kernel_projection(
                    GuestVa(owner::VA),
                    GuestVa(owner::VA + 4096),
                )
                .ok_or("physical fixture readable range is invalid")?,
            ],
        };
        // An admitted handle carries no host page-table manager or mirror.
        let state = MmAccessState::new_unbound(
            carrick_aarch64::Stage1Authority::new_with_manager(None),
            carrick_guest_mem::UserMemoryAuthority::from_owner(handle),
            Arc::new(parking_lot::Mutex::new(inventory)),
            Arc::new(parking_lot::Mutex::new(CowArmedRanges::default())),
            Arc::new(parking_lot::Mutex::new(Vec::new())),
            crate::hvf_aarch64_engine::HostCowStats::default(),
        );
        state.install_identity(snapshot.mm, binding);
        Ok((state, snapshot))
    }

    fn check_fixture_custody(
        custody: &Arc<CarrierVmCustody>,
        tables: &owner::Tables,
        ipa: u64,
    ) -> Result<(), String> {
        let transfer = crate::trap::UserTransferCustody::new(custody.clone());
        for (base, len) in [(tables.base, tables.words.len() * 8), (ipa, 0x4000)] {
            let physical = custody
                .global_frame_host_owners
                .lock()
                .get(&(base, len as u64))
                .and_then(|entry| entry.live_owner().cloned())
                .ok_or("fixture physical owner is missing")?;
            if !physical
                .custody
                .upgrade()
                .is_some_and(|registered| Arc::ptr_eq(&registered, custody))
            {
                return Err("fixture physical owner belongs to another carrier custody".into());
            }
            let record = custody
                .stage2_record_covering(base, len)
                .ok_or("fixture carrier has no covering stage-2 record")?;
            if record != physical.record_identity {
                return Err("fixture stage-2 record differs from physical owner".into());
            }
            let retained = transfer
                .retain(
                    carrick_el1_abi::PortalSelectedData {
                        ipa: base,
                        executable: false,
                        root_generation: NonZeroU64::MIN,
                        offset: 0,
                    },
                    4,
                    carrick_el1_abi::PortalTransferIntent::CarrickInternalRead,
                )
                .map_err(|error| format!("fixture UserTransfer physical retention: {error:?}"))?
                .ok_or("fixture UserTransfer cannot retain physical backing")?;
            if retained.identity().record.get() != record.record_id.0
                || retained.identity().vm_generation.get() != record.vm_generation.0
                || transfer.carrier() != custody.transfer_carrier
            {
                return Err("fixture UserTransfer retained another carrier record".into());
            }
        }
        Ok(())
    }

    struct ResidentFixture {
        _region: owner::Region,
        tables: owner::Tables,
        custody: Arc<CarrierVmCustody>,
        lease: CarrierForeignMmReadLease,
        snapshot: CarrierForeignMmSnapshot,
    }

    fn resident_fixture() -> Result<ResidentFixture, String> {
        let region = owner::Region::new();
        let mm = owner::admit_notified(&region, 77, owner::ROOT, 1, 0);
        let nodes = owner::nodes(&region);
        let custody = Arc::new(CarrierVmCustody::new_live_fixture());
        let portal = MmPortal::new(
            custody.transfer_carrier,
            region.table(),
            &region.zone().spaces,
            &nodes,
        )
        .with_zone(region.zone())
        .map_err(|error| format!("fixture portal zone: {error:?}"))?;
        let handle = portal
            .admitted_handle(mm, 0)
            .map_err(|error| format!("fixture admitted handle: {error:?}"))?;
        let tables = owner::Tables::new(owner::ROOT, owner::IPA, 1);
        let (state, snapshot) = install(&custody, handle, &tables, owner::IPA, b'A')?;
        let backing = state
            .retain_physical_backing_in(
                &custody,
                &snapshot,
                Instant::now() + Duration::from_secs(1),
            )
            .map_err(|error| format!("fixture read lease backing: {error:?}"))?;
        let lease = CarrierForeignMmReadLease {
            custody: custody.clone(),
            state,
            inner: parking_lot::Mutex::new(CarrierLeaseState {
                retained: snapshot.clone(),
                backing,
            }),
        };
        Ok(ResidentFixture {
            _region: region,
            tables,
            custody,
            lease,
            snapshot,
        })
    }

    #[test]
    fn n1_review_owner_window_refusal_cannot_select_legacy_fallback() {
        let _guard = crate::trap::foreign_mm_tests::FOREIGN_MM_TEST_LOCK.lock();
        let fixture = resident_fixture().unwrap();
        for len in [4, 4097] {
            let refusal = prepare(
                &fixture.lease,
                &Live(fixture.snapshot.clone()),
                &fixture.snapshot,
                GuestVa(owner::VA),
                len,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap_err();
            assert_eq!(refusal, Error::Translation(GuestVa(owner::VA)));
        }
    }

    #[test]
    fn n1_review_observer_fixture_uses_exact_carrier_custody() {
        let _guard = crate::trap::foreign_mm_tests::FOREIGN_MM_TEST_LOCK.lock();
        let fixture = resident_fixture().unwrap();
        check_fixture_custody(&fixture.custody, &fixture.tables, owner::IPA).unwrap();
    }

    #[test]
    fn n1_stopped_observer_and_native_lease_use_exact_owner() {
        let _guard = crate::trap::foreign_mm_tests::FOREIGN_MM_TEST_LOCK.lock();
        let region = owner::Region::new();
        let spaces: &AddressSpaces = &region.zone().spaces;
        let a = owner::admit_notified(&region, 77, owner::ROOT, 1, 0);
        let b = owner::admit_notified(&region, 78, owner::ROOT + 0x100000, 1, 0);
        let nodes = owner::nodes(&region);
        let custody = Arc::new(CarrierVmCustody::new_live_fixture());
        let portal = MmPortal::new(custody.transfer_carrier, region.table(), spaces, &nodes)
            .with_zone(region.zone())
            .unwrap();
        // Occupy every production EL1 service slot. This is not a substitute
        // for the reserved runtime's default executor-pool exhaustion binding.
        for index in 0..ZONE_SLOTS {
            let slot = SlotId::from_index(index).unwrap();
            region.zone().publish_slot(slot, a.raw(), None, 0);
            region.zone().drive(slot, u64::try_from(index).unwrap() + 1);
        }
        let mut identity = carrick_el1_abi::ThreadIdentity {
            tid: 1000,
            serial: 1,
            mm: a.raw(),
            generation: 1,
            ..Default::default()
        };
        let stopped = region.zone().alloc_record(identity).unwrap();
        region
            .zone()
            .publish_park(stopped, region.zone().next_seq(stopped));
        identity.tid += 1;
        identity.mm = b.raw();
        let live = region.zone().alloc_host_runnable(identity).unwrap();
        let mut failures = Vec::new();
        for (mm, root, ipa, expected) in [
            (a, owner::ROOT, owner::IPA, b'A'),
            (b, owner::ROOT + 0x100000, owner::IPA + 0x100000, b'B'),
        ] {
            let tables = owner::Tables::new(root, ipa, 1);
            let handle = portal.admitted_handle(mm, 0).unwrap();
            let selected = owner::selected(owner::select(
                &portal,
                &portal
                    .begin(
                        handle,
                        carrick_el1::personality::mm_portal::GuestVa::new(owner::VA),
                        4,
                        carrick_el1_abi::PortalTransferIntent::UserRead,
                        0,
                    )
                    .unwrap(),
                &tables,
            ));
            assert_eq!(selected.ipa, ipa, "production owner selected another MM");
            let (state, snapshot) = install(&custody, handle, &tables, ipa, expected).unwrap();
            let deadline = Instant::now() + Duration::from_secs(1);
            let backing = state
                .retain_physical_backing_in(&custody, &snapshot, deadline)
                .unwrap();
            let lease = CarrierForeignMmReadLease {
                custody: custody.clone(),
                state,
                inner: parking_lot::Mutex::new(CarrierLeaseState {
                    retained: snapshot.clone(),
                    backing,
                }),
            };
            let mut bytes = [0; 4];
            match prepare(
                &lease,
                &Live(snapshot.clone()),
                &snapshot,
                GuestVa(owner::VA),
                4,
                deadline,
            ) {
                Ok(window) => {
                    window
                        .copy_into(
                            &Live(snapshot.clone()),
                            &snapshot,
                            GuestVa(owner::VA),
                            &mut bytes,
                            deadline,
                        )
                        .unwrap();
                    assert_eq!(bytes, [expected; 4]);
                }
                Err(error) => {
                    failures.push(format!("mm={} checked owner read: {error:?}", mm.raw()))
                }
            }
        }
        assert!(matches!(
            region.zone().record(stopped).claim(),
            carrick_el1_abi::Claim::Parked { .. }
        ));
        assert!(region.zone().record(live).needs_host());
        assert!(
            failures.is_empty(),
            "missing production observer owner binding: {failures:?}"
        );
    }
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
    let legacy = lease
        .state
        .protections
        .legacy()
        .ok_or(Error::AuthorityUnavailable)?;
    if legacy.range_no_access(start.raw(), len) {
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
        let legacy = self
            .state
            .protections
            .legacy()
            .ok_or(Error::AuthorityUnavailable)?;
        if legacy.range_no_access(va.raw(), dst.len()) {
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
