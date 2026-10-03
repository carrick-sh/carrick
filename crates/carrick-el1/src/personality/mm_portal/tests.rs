use super::*;
use carrick_el1_abi::MetadataResolutionError;
use core::cell::UnsafeCell;

#[derive(Default)]
struct PhysicalStats {
    zero_reuses: AtomicU64,
    callbacks: AtomicU64,
    pin_acquires: AtomicU64,
    pin_releases: AtomicU64,
    lock_crossings: AtomicU64,
}
struct Observer {
    table: NonNull<SharedReservations>,
    stats: Arc<PhysicalStats>,
}
impl Observer {
    fn callback(&self) {
        self.stats.callbacks.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the test portal owns this stable allocation; callbacks occur
        // only while it is alive, never during destruction of the backend.
        if unsafe { self.table.as_ref() }.el1_slot_holding(0).is_some() {
            self.stats.lock_crossings.fetch_add(1, Ordering::Relaxed);
        }
    }
}
// SAFETY: every observer access occurs on the single portal execution lane.
unsafe impl Send for Observer {}
// SAFETY: no test invokes callbacks concurrently; counters are atomic.
unsafe impl Sync for Observer {}
struct Bytes(UnsafeCell<Box<[u128]>>);
// SAFETY: the test portal serializes every access; pins retain stable storage.
unsafe impl Send for Bytes {}
// SAFETY: no test invokes raw access concurrently with a byte callback.
unsafe impl Sync for Bytes {}
struct Pin {
    extent: MetadataExtent,
    bytes: Arc<Bytes>,
    observer: Arc<Observer>,
}
impl Drop for Pin {
    fn drop(&mut self) {
        self.observer
            .stats
            .pin_releases
            .fetch_add(1, Ordering::Relaxed);
    }
}
// SAFETY: the exact extent stays allocated through the retained Arc.
unsafe impl PinnedMetadataExtent for Pin {
    fn extent(&self) -> MetadataExtent {
        self.extent
    }
    fn host_base(&self) -> NonNull<u8> {
        self.observer.callback();
        // SAFETY: allocation never resizes and the portal excludes writers.
        unsafe { NonNull::new((*self.bytes.0.get()).as_mut_ptr().cast()).unwrap() }
    }
}
struct Physical {
    returned_bases: BTreeSet<u64>,
    next: u64,
    generation: u64,
    grants: BTreeMap<u64, Pin>,
    observer: Arc<Observer>,
}
impl MetadataExtentResolver for Physical {
    type Pin = Pin;
    fn pin(&self, extent: MetadataExtent) -> Result<Pin, MetadataResolutionError> {
        self.observer.callback();
        let p = self
            .grants
            .get(&extent.base())
            .ok_or(MetadataResolutionError::StaleOwner)?;
        if p.extent != extent {
            return Err(MetadataResolutionError::StaleOwner);
        }
        self.observer
            .stats
            .pin_acquires
            .fetch_add(1, Ordering::Relaxed);
        Ok(Pin {
            extent,
            bytes: p.bytes.clone(),
            observer: self.observer.clone(),
        })
    }
}
impl PhysicalExtentBackend for Physical {
    fn grant(&mut self, kind: ExtentKind, bytes: u64) -> Result<ExtentGrant, MmError> {
        self.observer.callback();
        let base = if let Some(base) = self.returned_bases.pop_first() {
            base
        } else {
            let base = self.next;
            self.next += bytes;
            base
        };
        let extent = MetadataExtent::new(base, bytes, self.generation).ok_or(MmError::Invalid)?;
        self.generation += 1;
        self.observer
            .stats
            .pin_acquires
            .fetch_add(1, Ordering::Relaxed);
        self.grants.insert(
            extent.base(),
            Pin {
                extent,
                observer: self.observer.clone(),
                bytes: Arc::new(Bytes(UnsafeCell::new(
                    vec![0; bytes as usize / 16].into_boxed_slice(),
                ))),
            },
        );
        Ok(ExtentGrant {
            carrier: NonZeroU64::new(1).unwrap(),
            extent,
            kind,
            zero_provenance: true,
        })
    }
    fn return_extent(&mut self, grant: ExtentGrant) -> Result<(), MmError> {
        self.observer.callback();
        let p = self
            .grants
            .get(&grant.extent.base())
            .ok_or(MmError::Stale)?;
        if p.extent != grant.extent {
            return Err(MmError::Stale);
        }
        if Arc::strong_count(&p.bytes) != 1 {
            return Err(MmError::Busy);
        }
        self.grants.remove(&grant.extent.base());
        self.returned_bases.insert(grant.extent.base());
        Ok(())
    }
    fn read(
        &mut self,
        extent: MetadataExtent,
        offset: u64,
        bytes: &mut [u8],
    ) -> Result<(), MmError> {
        self.observer.callback();
        let pin = self.pin(extent).map_err(|_| MmError::Stale)?;
        if !extent.contains(extent.base() + offset, bytes.len() as u64) {
            return Err(MmError::Invalid);
        }
        // SAFETY: bounded exact pin and single owner access.
        unsafe {
            core::ptr::copy_nonoverlapping(
                pin.host_base().as_ptr().add(offset as usize),
                bytes.as_mut_ptr(),
                bytes.len(),
            );
        }
        Ok(())
    }
    fn write(&mut self, extent: MetadataExtent, offset: u64, bytes: &[u8]) -> Result<(), MmError> {
        self.observer.callback();
        let pin = self.pin(extent).map_err(|_| MmError::Stale)?;
        if !extent.contains(extent.base() + offset, bytes.len() as u64) {
            return Err(MmError::Invalid);
        }
        // Observation only: count zeroing of an already dirty physical page.
        // The backend never chooses which page is retired or reused.
        if bytes.len() == PAGE_BYTES as usize && bytes.iter().all(|b| *b == 0) {
            // SAFETY: exact pinned and checked span, single owner access.
            let old = unsafe {
                core::slice::from_raw_parts(
                    pin.host_base().as_ptr().add(offset as usize),
                    bytes.len(),
                )
            };
            if old.iter().any(|b| *b != 0) {
                self.observer
                    .stats
                    .zero_reuses
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        // SAFETY: bounded exact pin and single owner access.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                pin.host_base().as_ptr().add(offset as usize),
                bytes.len(),
            );
        }
        Ok(())
    }
}
const VA: u64 = 0x100000;
fn range(va: u64, bytes: u64) -> ReservationRange {
    ReservationRange::new(va, va + bytes).unwrap()
}
fn boot(nodes: usize) -> BootMmBuilder {
    let mut boot = BootMmBuilder::new(
        Layout {
            heap: range(PAGE_BYTES, VA - PAGE_BYTES),
            arena: range(VA, 0x10000000 - VA),
            brk: PAGE_BYTES,
            address_limit: u64::MAX,
            data_limit: u64::MAX,
            external_address_bytes: 0,
            external_data_bytes: 0,
        },
        carrick_mem::memory::stage1_hvpatch_page_tables(),
        carrick_mem::memory::LINUX_PAGE_TABLES_BASE,
    );
    for n in 0..nodes {
        boot.map_lazy(
            range(0x1000000 + n as u64 * PAGE_BYTES * 2, PAGE_BYTES),
            ReservationProtection::READ_WRITE,
        );
    }
    boot
}
fn portal() -> (MmPortal<Physical>, Arc<PhysicalStats>) {
    // SAFETY: production shared region starts zeroed, exactly allocated here.
    let raw = unsafe { std::alloc::alloc_zeroed(std::alloc::Layout::new::<SharedReservations>()) };
    assert!(!raw.is_null());
    // SAFETY: exact allocation and sole ownership.
    let table = unsafe { Box::from_raw(raw.cast()) };
    let stats = Arc::new(PhysicalStats::default());
    let observer = Arc::new(Observer {
        table: NonNull::from(&*table),
        stats: stats.clone(),
    });
    (
        MmPortal::new(
            NonZeroU64::new(1).unwrap(),
            table,
            Physical {
                returned_bases: BTreeSet::new(),
                next: 0x100000000,
                generation: 1,
                grants: BTreeMap::new(),
                observer,
            },
        ),
        stats,
    )
}
fn write(p: &mut MmPortal<Physical>, h: El1MmHandle, va: u64, bytes: &[u8]) -> Result<(), MmError> {
    p.user_transfer(
        h,
        UserTransfer::CopyOut {
            address: GuestVa::new(va),
            bytes,
            intent: TransferIntent::UserWrite,
        },
    )
}
fn read(
    p: &mut MmPortal<Physical>,
    h: El1MmHandle,
    va: u64,
    bytes: &mut [u8],
) -> Result<(), MmError> {
    p.user_transfer(
        h,
        UserTransfer::CopyIn {
            address: GuestVa::new(va),
            bytes,
            intent: TransferIntent::UserRead,
        },
    )
}
#[test]
fn native_owner_matrix() {
    for pages in [16, 64, 256] {
        for nodes in [16, 512] {
            let (mut p, physical) = portal();
            let a = boot(nodes).seal(&mut p).unwrap();
            let b = boot(nodes).seal(&mut p).unwrap();
            let span = range(VA, pages * PAGE_BYTES);
            for h in [a, b] {
                p.user_transfer(
                    h,
                    UserTransfer::MapLazy {
                        range: span,
                        protection: ReservationProtection::READ_WRITE,
                    },
                )
                .unwrap();
            }
            // Real scheduler records remain parked, including the stopped target;
            // the owner entry does not consume or unpark a service slot.
            let raw = unsafe {
                std::alloc::alloc_zeroed(std::alloc::Layout::new::<carrick_sched_core::ZoneTables>())
            };
            assert!(!raw.is_null());
            let zone = unsafe { Box::from_raw(raw.cast::<carrick_sched_core::ZoneTables>()) };
            // Physical root identity is supplied at boot, never queried through
            // the admitted handle. First allocation is metadata, second tables.
            let stopped = zone
                .spaces
                .publish_closed(1, 0x100100000, 0x100100000)
                .unwrap();
            assert!(!zone.spaces.is_open(1));
            let gate = zone.spaces.gate(stopped);
            let mut waiting = Vec::new();
            for n in 0..carrick_sched_core::ZONE_SLOTS {
                let record = zone
                    .alloc_host_runnable(carrick_sched_core::ThreadIdentity {
                        tid: n as u64 + 1,
                        serial: 1,
                        mm: 1,
                        file_table: 1,
                        generation: 1,
                        affinity: 0,
                        lifecycle_page: 0,
                        control_slot: 0,
                    })
                    .unwrap();
                let seq = zone.next_seq(record);
                zone.publish_park(record, seq);
                waiting.push(record);
            }
            let initial = p.work();
            let payload = vec![0x31; pages as usize * PAGE_BYTES as usize];
            write(&mut p, a, VA, &payload).unwrap();
            write(&mut p, b, VA, &vec![0x72; payload.len()]).unwrap();
            let mut bytes = vec![0; payload.len()];
            read(&mut p, a, VA, &mut bytes).unwrap();
            assert_eq!(bytes, payload);
            let transfer = p.work();
            for record in &waiting {
                assert!(matches!(
                    zone.record(*record).claim(),
                    carrick_sched_core::Claim::Parked { .. }
                ));
            }
            assert_eq!(zone.spaces.gate(stopped), gate);
            assert!(!zone.spaces.is_open(1));
            assert_eq!(transfer.el0_entries + transfer.host_worker_parks, 0);
            assert!(
                transfer.table_visits - initial.table_visits
                    <= pages
                        * 3
                        * 4
                        * (carrick_mmu_core::aarch64::descriptor_txn::MAX_TABLE_GRANTS as u64
                            + carrick_mmu_core::aarch64::descriptor_txn::MAX_RECLAIMED_TABLES
                                as u64
                            + 4)
            );
            assert!(
                transfer.capacity_grants - initial.capacity_grants <= 2 * (pages + 4).div_ceil(256)
            );
            let mut internal = [1; 4];
            p.user_transfer(
                a,
                UserTransfer::CopyIn {
                    address: GuestVa::new(INTERNAL_VA + 4),
                    bytes: &mut internal,
                    intent: TransferIntent::CarrickInternalRead,
                },
            )
            .unwrap();
            assert_eq!(internal, [0; 4]);
            assert_eq!(
                read(&mut p, a, INTERNAL_VA + 4, &mut internal),
                Err(MmError::Fault)
            );
            for prot in [
                ReservationProtection::from_bits(1).unwrap(),
                ReservationProtection::NONE,
            ] {
                p.user_transfer(
                    a,
                    UserTransfer::Protect {
                        range: span,
                        protection: prot,
                    },
                )
                .unwrap();
                assert_eq!(write(&mut p, a, VA, &[1]).unwrap_err().errno(), 14);
                if prot == ReservationProtection::NONE {
                    assert_eq!(read(&mut p, a, VA, &mut [0]).unwrap_err().errno(), 14);
                }
            }
            p.user_transfer(
                a,
                UserTransfer::Protect {
                    range: span,
                    protection: ReservationProtection::READ_WRITE,
                },
            )
            .unwrap();
            let old = p
                .begin_copyout(a, GuestVa::new(VA), &[0xee], TransferIntent::UserWrite)
                .unwrap();
            p.user_transfer(
                a,
                UserTransfer::Unmap {
                    range: range(VA, PAGE_BYTES),
                },
            )
            .unwrap();
            p.user_transfer(
                a,
                UserTransfer::MapLazy {
                    range: range(VA, PAGE_BYTES),
                    protection: ReservationProtection::READ_WRITE,
                },
            )
            .unwrap();
            write(&mut p, a, VA, &[0x42]).unwrap();
            assert_eq!(p.complete_copyout(old), Err(MmError::Stale));
            read(&mut p, a, VA, &mut bytes[..1]).unwrap();
            assert_eq!(bytes[0], 0x42);
            p.user_transfer(
                a,
                UserTransfer::MapLazy {
                    range: range(0x900000, PAGE_BYTES),
                    protection: ReservationProtection::READ_WRITE,
                },
            )
            .unwrap();
            read(&mut p, a, 0x900000, &mut bytes[..PAGE_BYTES as usize]).unwrap();
            assert!(bytes[..PAGE_BYTES as usize].iter().all(|b| *b == 0));
            read(&mut p, a, VA + PAGE_BYTES, &mut bytes[..1]).unwrap();
            assert_eq!(bytes[0], 0x31);
            assert!(physical.zero_reuses.load(Ordering::Relaxed) >= 1);
            p.user_transfer(
                a,
                UserTransfer::Unmap {
                    range: range(0x900000, PAGE_BYTES),
                },
            )
            .unwrap();
            p.user_transfer(
                a,
                UserTransfer::Remap {
                    source: range(VA, PAGE_BYTES),
                    destination: GuestVa::new(0x800000),
                },
            )
            .unwrap();
            read(&mut p, a, 0x800000, &mut bytes[..1]).unwrap();
            assert_eq!(bytes[0], 0x42);
            let fork_before = p.work();
            let child = p.fork(a).unwrap().into_handle();
            let fork_work = p.work();
            let fork_bound = (nodes as u64 + 3) * (nodes as u64 + 3).ilog2() as u64 * 32;
            assert!(fork_work.vma_nodes - fork_before.vma_nodes <= fork_bound);
            assert_eq!(fork_work.host_semantic_callbacks, 0);
            write(&mut p, child, VA + PAGE_BYTES, &[0x99]).unwrap();
            read(&mut p, a, VA + PAGE_BYTES, &mut bytes[..1]).unwrap();
            assert_eq!(bytes[0], 0x31);
            read(&mut p, b, VA, &mut bytes[..1]).unwrap();
            assert_eq!(bytes[0], 0x72);
            let CapacityResult::Granted(grant) = p.capacity(a, Capacity::Grant).unwrap() else {
                panic!("grant");
            };
            assert_eq!(p.capacity(b, Capacity::Return(grant)), Err(MmError::Stale));
            assert_eq!(
                p.capacity(a, Capacity::Return(grant)),
                Ok(CapacityResult::Returned)
            );
            assert_eq!(p.capacity(a, Capacity::Return(grant)), Err(MmError::Stale));
            assert_eq!(p.references().1, 0);
            // Forged owner generation and incarnation cannot acquire authority.
            assert_eq!(
                write(
                    &mut p,
                    El1MmHandle {
                        incarnation: NonZeroU64::new(999).unwrap(),
                        ..a
                    },
                    VA,
                    &[0]
                ),
                Err(MmError::Stale)
            );
            for h in [a, b, child] {
                p.user_transfer(h, UserTransfer::Unmap { range: span })
                    .unwrap();
                if h != b {
                    p.user_transfer(
                        h,
                        UserTransfer::Unmap {
                            range: range(0x800000, PAGE_BYTES),
                        },
                    )
                    .unwrap();
                }
                p.capacity(h, Capacity::Settle).unwrap();
            }
            assert_eq!(
                p.references(),
                (3, 0),
                "only three explicit boot-control references remain"
            );
            let work = p.work();
            assert_eq!(work.pin_acquires, work.pin_releases);
            assert_eq!(
                work.host_semantic_callbacks
                    + work.host_protection_decisions
                    + work.host_cow_decisions
                    + work.host_projection_decisions,
                0
            );
            assert!(
                transfer.vma_nodes - initial.vma_nodes
                    <= pages * 3 * (nodes as u64 + 1).ilog2() as u64 * 4
            );
            assert_eq!(physical.lock_crossings.load(Ordering::Relaxed), 0);
            drop(p);
            assert_eq!(
                physical.pin_acquires.load(Ordering::Relaxed),
                physical.pin_releases.load(Ordering::Relaxed)
            );
            std::println!(
                "physical callbacks={} pins={}/{} zero_reuses={} lock_crossings=0",
                physical.callbacks.load(Ordering::Relaxed),
                physical.pin_acquires.load(Ordering::Relaxed),
                physical.pin_releases.load(Ordering::Relaxed),
                physical.zero_reuses.load(Ordering::Relaxed)
            );
            std::println!(
                "N0 pages={pages} nodes={nodes} transfer_table={} transfer_vma={} fork_vma={} total={work:?}",
                transfer.table_visits - initial.table_visits,
                transfer.vma_nodes - initial.vma_nodes,
                fork_work.vma_nodes - fork_before.vma_nodes
            );
        }
    }
}

#[test]
fn extent_generation_and_pin_custody() {
    let (mut p, stats) = portal();
    let h = boot(16).seal(&mut p).unwrap();
    let CapacityResult::Granted(grant) = p.capacity(h, Capacity::Grant).unwrap() else {
        panic!("grant");
    };
    let bad = ExtentGrant {
        extent: MetadataExtent::new(
            grant.extent.base(),
            grant.extent.len(),
            grant.extent.token() + 1,
        )
        .unwrap(),
        ..grant
    };
    assert_eq!(p.capacity(h, Capacity::Return(bad)), Err(MmError::Stale));
    let span = range(VA, 512 * PAGE_BYTES);
    p.user_transfer(
        h,
        UserTransfer::MapLazy {
            range: span,
            protection: ReservationProtection::READ_WRITE,
        },
    )
    .unwrap();
    write(&mut p, h, VA, &vec![7; span.len() as usize]).unwrap();
    assert_eq!(p.capacity(h, Capacity::Return(grant)), Err(MmError::Busy));
    let pending = p
        .begin_copyout(
            h,
            GuestVa::new(VA + 255 * PAGE_BYTES),
            &[9],
            TransferIntent::UserWrite,
        )
        .unwrap();
    assert!(matches!(p.fork(h), Err(MmError::Busy)));
    p.user_transfer(h, UserTransfer::Unmap { range: span })
        .unwrap();
    assert_eq!(p.capacity(h, Capacity::Return(grant)), Err(MmError::Busy));
    assert_eq!(p.complete_copyout(pending), Err(MmError::Stale));
    assert_eq!(
        p.capacity(h, Capacity::Return(grant)),
        Ok(CapacityResult::Returned)
    );
    let CapacityResult::Granted(reused) = p.capacity(h, Capacity::Grant).unwrap() else {
        panic!("grant");
    };
    assert_eq!(reused.extent.base(), grant.extent.base());
    assert_ne!(reused.extent.token(), grant.extent.token());
    assert_eq!(p.capacity(h, Capacity::Return(grant)), Err(MmError::Stale));
    p.capacity(h, Capacity::Return(reused)).unwrap();
    p.capacity(h, Capacity::Settle).unwrap();
    assert_eq!(p.references(), (1, 0));
    assert_eq!(stats.lock_crossings.load(Ordering::Relaxed), 0);
    drop(p);
    assert_eq!(
        stats.pin_acquires.load(Ordering::Relaxed),
        stats.pin_releases.load(Ordering::Relaxed)
    );
}
