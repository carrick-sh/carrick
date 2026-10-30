//! Native lifecycle composed with the shared physical stock and retirement owners.
use super::*;
use carrick_core::mm::retirement::{self, *};
use carrick_hal::fork_stock::{ForkStock, GrantExecution, LifecycleWindow, NoTableLedger};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub(super) struct PinVenue(Arc<Mutex<CarrierStage2Record>>);
impl RecordPinVenue for PinVenue {
    fn release_pin(&self, identity: CarrierStage2RecordIdentity) {
        retirement::release_record_pin(&mut self.0.lock().unwrap(), identity);
    }
}

#[derive(Debug)]
pub(super) struct PhysicalChild {
    _inherited: RecordPin<PinVenue>,
    pub supplied: Option<carrick_hal::physical_grants::NativePhysicalGrants<SupplyBacking>>,
}
impl carrick_hal::physical_grants::NativeSupplyCustody for PhysicalChild {
    type Backing = SupplyBacking;
    fn supplied(
        &mut self,
    ) -> Option<&mut carrick_hal::physical_grants::NativePhysicalGrants<SupplyBacking>> {
        self.supplied.as_mut()
    }
}
pub(super) struct SupplyBacking {
    record: Arc<Mutex<CarrierStage2Record>>,
    identity: CarrierStage2RecordIdentity,
    authority: Arc<dyn carrick_hal::FrameCowAuthority>,
    mapping: carrick_hal::MappingId,
    early_drop: Arc<core::sync::atomic::AtomicBool>,
}
impl SupplyBacking {
    pub(super) fn release_unused(
        &self,
    ) -> Result<carrick_hal::physical_grants::PhysicalGrantRelease, carrick_hal::TrapError> {
        if self.authority.live_mapping_row(self.mapping).is_some() {
            self.early_drop.store(true, Ordering::Release);
            return Err(carrick_hal::TrapError::Hypervisor(
                "live inventory at release".into(),
            ));
        }
        let mut record = self.record.lock().unwrap();
        let outcome = match prepare_record_retirement(&mut record, self.identity) {
            RecordRetirement::Unmap { .. } => {
                settle_record_retirement(&mut record, self.identity, Ok(()))
            }
            RecordRetirement::Complete(outcome) => outcome,
        };
        carrick_hal::physical_grants::PhysicalGrantRelease::from_stage2_retire_outcome(outcome)
    }
}
impl Drop for SupplyBacking {
    fn drop(&mut self) {
        assert_eq!(
            self.release_unused().unwrap(),
            carrick_hal::physical_grants::PhysicalGrantRelease::Released
        );
    }
}

pub(super) struct PhysicalStock {
    pub owner: ForkStock<carrick_hal::asid::AsidAllocator, PhysicalChild>,
    record: Arc<Mutex<CarrierStage2Record>>,
    identity: CarrierStage2RecordIdentity,
    pub inventory: Arc<dyn carrick_hal::PhysicalFrameInventory>,
    pub residency: Option<&'static carrick_el1_abi::FrameGrantResidencyTable>,
    pub pool: Option<&'static carrick_el1_abi::CowGrantPool>,
    supplied_records: Vec<Arc<Mutex<CarrierStage2Record>>>,
    early_drop: Arc<core::sync::atomic::AtomicBool>,
    pub settled: usize,
    window: Option<LifecycleWindow>,
    execution: Option<GrantExecution>,
    tables: (core::ptr::NonNull<AtomicU64>, u64, usize),
    releases: usize,
}

impl PhysicalStock {
    pub fn new(tables: &crate::mm_portal::test_support::Tables) -> Self {
        let identity = CarrierStage2RecordIdentity {
            record_id: CarrierStage2RecordId(1),
            vm_generation: CarrierVmGeneration(1),
            logical_owner: Some(CarrierLogicalOwner {
                id: 1,
                generation: 1,
            }),
        };
        let record = Arc::new(Mutex::new(CarrierStage2Record {
            snapshot: CarrierStage2RecordSnapshot {
                record_id: identity.record_id,
                vm_generation: identity.vm_generation,
                logical_owner: identity.logical_owner,
                ipa: 0x20_0000,
                len: 606208,
                host_addr: 0,
                mapped: true,
                backend_map_installed: true,
                release_ipa: false,
                perms: 3,
                pin_count: 0,
                retirement_requested: false,
                retry_eligible: false,
                retry_pending: None,
                terminalized_by_vm_destroy: false,
                superseded_by_rebind: false,
                release_in_flight: false,
                release_retry_pending: false,
            },
            unmap_in_flight: false,
        }));
        let tags = carrick_hal::asid::AsidAllocator::new();
        tags.allocate().unwrap(); // The installed parent owns the first ASID.
        let mut owner = ForkStock::new(NonZeroU64::MIN, None, tags);
        owner.provide_arm_control_capacity(0x20_0000).unwrap();
        Self {
            owner,
            record,
            identity,
            inventory: Arc::new(carrick_kernel::kernel::FrameInventoryAuthority::new())
                .physical_projection(Arc::new(carrick_kernel::kernel::ObjectIdRegistry::new())),
            residency: None,
            pool: None,
            supplied_records: Vec::new(),
            early_drop: Arc::default(),
            settled: 0,
            window: None,
            execution: None,
            tables: (
                core::ptr::NonNull::new(tables.words.as_ptr().cast_mut()).unwrap(),
                tables.base,
                tables.words.len(),
            ),
            releases: 0,
        }
    }

    pub fn loan(
        &mut self,
        req: carrick_el1_abi::ForkStockRequest,
        exchange: &mut ForkStockExchange,
        child: Vec<RootGpa>,
        parent: Vec<RootGpa>,
    ) -> ForkStockLoan {
        // One retained allocation permits the real lifecycle clear operation.
        let controls_offset = core::mem::size_of::<ThreadLifecyclePage>()
            .next_multiple_of(core::mem::align_of::<ThreadControlSlot>());
        let len = controls_offset
            + core::mem::size_of::<ThreadControlSlot>()
                * (carrick_el1_abi::THREAD_POOL_ENTRIES + 1);
        let layout = std::alloc::Layout::from_size_align(len, 16384).unwrap();
        let base = core::ptr::NonNull::new(unsafe { std::alloc::alloc_zeroed(layout) }).unwrap();
        // SAFETY: leaked test allocation has sufficient extent/alignment for both records.
        let window = unsafe { LifecycleWindow::new(base, base.as_ptr() as u64, len as u64) };
        let lifecycle = carrick_el1_abi::ForkLifecycleLoan::new(
            KernelVa::new(base.as_ptr() as u64),
            KernelVa::new(base.as_ptr() as u64 + controls_offset as u64),
        )
        .unwrap();
        let mut table_stock: Vec<_> = child.into_iter().chain(parent).collect();
        // Composed supply appends backing beyond the original fork arena.
        // Seed two distinct spares before admission: one per simultaneous
        // reply in the competing-publication witness. Never install live stock.
        if self.tables.2 > 32 * 512 {
            for page in (32..self.tables.2 / 512).rev().take(2) {
                let offset = page * 512;
                // SAFETY: the fixture retains this complete atomic table arena.
                let words =
                    unsafe { core::slice::from_raw_parts(self.tables.0.as_ptr().add(offset), 512) };
                assert!(words.iter().all(|word| word.load(Ordering::Acquire) == 0));
                table_stock.push(
                    RootGpa::page_aligned(FrameGpa::new(self.tables.1 + offset as u64 * 8))
                        .unwrap(),
                );
            }
        }
        self.owner.install(table_stock, vec![lifecycle]).unwrap();
        let aliases = window.prepare_affinity_aliases(lifecycle).unwrap();
        let execution =
            GrantExecution::new(carrick_guest_arch::CpuId::new(0), req.binding, req.context);
        self.execution = Some(execution);
        let loan = self
            .owner
            .loan(&mut NoTableLedger, execution, exchange, |life| {
                window.is_zero(life)
            })
            .unwrap();
        aliases.publish();
        self.window = Some(window);
        loan
    }

    pub fn reserve(&mut self, _loan: ForkStockLoan, settlement: &mut ForkStockSettlement) {
        let venue = PinVenue(self.record.clone());
        let identity = self.identity;
        self.owner
            .reserve_custody(
                self.execution.unwrap(),
                settlement,
                |_| true,
                |_| true,
                |_, _, _| {
                    Ok(PhysicalChild {
                        _inherited: pin_record(&mut self.record.lock().unwrap(), identity, venue)
                            .unwrap(),
                        supplied: None,
                    })
                },
            )
            .unwrap();
    }
    pub fn commit(&mut self, _loan: ForkStockLoan, settlement: &mut ForkStockSettlement) {
        self.owner
            .commit_admitted(&mut NoTableLedger, self.execution.unwrap(), settlement)
            .unwrap();
    }
    pub fn reclaim(&mut self, zone: &ZoneTables<Aarch64ParkedContext>) {
        use carrick_hal::fork_stock::{ReclaimExecution, SlotAbsence};
        // The VM-free lane applies the same maintenance-root proof without hardware.
        let idle = RootGpa::page_aligned(FrameGpa::new(zone.spaces.idle_ttbr())).unwrap();
        let execution = ReclaimExecution::maintenance_root(idle, idle).unwrap();
        let window = self.window.unwrap();
        let (words, base, len) = self.tables;
        let inventory = self.inventory.clone();
        let local_residency = carrick_el1_abi::FrameGrantResidencyTable::new();
        let residency = self.residency.unwrap_or(&local_residency);
        let returned = self
            .owner
            .reclaim(
                &mut NoTableLedger,
                execution,
                |mm| {
                    if zone.spaces.find(mm.raw()).is_some() {
                        return None;
                    }
                    SlotAbsence::scan(
                        mm,
                        (0..carrick_sched_core::ZONE_SLOTS)
                            .filter_map(SlotId::from_index)
                            .map(|slot| zone.installed_space(slot)),
                    )
                },
                |pages| {
                    for page in pages {
                        let offset = ((page.address().raw() - base) / 8) as usize;
                        assert!(offset + 512 <= len);
                        for index in offset..offset + 512 {
                            // SAFETY: the synchronous fixture retains its table arena;
                            // the shared owner admitted root retirement and slot absence.
                            unsafe {
                                words
                                    .as_ptr()
                                    .add(index)
                                    .as_ref()
                                    .unwrap()
                                    .store(0, Ordering::Release);
                            }
                        }
                    }
                    true
                },
                |life| window.clear(life),
                |absence| {
                    self.releases += 1;
                    carrick_hal::fork_stock::release_child_mm(&*inventory, residency, absence.mm())
                },
            )
            .unwrap();
        assert_eq!(
            returned, 1,
            "terminal exit must relinquish all child storage borrows"
        );
    }
    pub fn backing(
        &mut self,
        staged: &carrick_hal::physical_grants::StagedPhysicalGrants,
        len: u64,
        physical_generation: NonZeroU64,
    ) -> SupplyBacking {
        let grant = *staged.grants().last().unwrap();
        let id = CarrierStage2RecordId(self.supplied_records.len() as u64 + 2);
        let identity = CarrierStage2RecordIdentity {
            record_id: id,
            logical_owner: Some(CarrierLogicalOwner {
                id: grant.gpa.raw(),
                generation: physical_generation.get(),
            }),
            ..self.identity
        };
        let mut snapshot = self.record.lock().unwrap().snapshot;
        snapshot.record_id = id;
        snapshot.logical_owner = identity.logical_owner;
        snapshot.ipa = grant.gpa.raw();
        snapshot.len = len as usize;
        snapshot.pin_count = 0;
        let record = Arc::new(Mutex::new(CarrierStage2Record {
            snapshot,
            unmap_in_flight: false,
        }));
        self.supplied_records.push(record.clone());
        SupplyBacking {
            record,
            identity,
            authority: staged.authority().clone(),
            mapping: carrick_hal::MappingId::from_kernel_allocation(grant.identity.mapping_id),
            early_drop: self.early_drop.clone(),
        }
    }
    pub fn track_backing_tables(
        &mut self,
        owner: carrick_el1_abi::El1MmHandle,
        root: RootGpa,
        txn: &mut carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn,
    ) {
        // Reserve an actual unused table from the spares seeded before loan.
        // Existing tables are linked, so settlement returns this whole grant.
        let reservation = self
            .owner
            .reserve_native_descriptor_tables(&mut NoTableLedger, owner, root, 1)
            .unwrap();
        txn.tables = reservation.descriptor_tables();
        self.owner
            .track_native_descriptor_tables(&mut NoTableLedger, reservation, *txn)
            .unwrap();
    }
    pub fn settle_backing_reply(
        &mut self,
        owner: carrick_el1_abi::El1MmHandle,
        generation: NonZeroU64,
        slot: &carrick_el1_abi::PortalGrantSlot,
    ) {
        let root = self.owner.child_root(owner.mm()).unwrap();
        let grants = self
            .owner
            .child_physical_mut(owner.mm(), root)
            .unwrap()
            .supplied
            .as_mut()
            .unwrap();
        let txn = grants.pending_backing_reply(slot, generation).unwrap();
        assert!(
            self.owner
                .settle_native_backing_reply(
                    &mut NoTableLedger,
                    owner,
                    root,
                    slot,
                    &txn,
                    SupplyBacking::release_unused,
                )
                .unwrap()
        );
    }
    pub fn retire(
        &mut self,
        zone: &ZoneTables<Aarch64ParkedContext>,
        execution: GrantExecution,
        record: &mut carrick_el1_abi::NativeChildRetire,
    ) {
        if let Some(pool) = self.pool {
            let access = crate::sched::object_wait::space_access(zone, SlotId::new(0));
            let mm = execution.context.mm.raw().get();
            let exclusion = access
                .try_exclude_editor(access.find(mm).unwrap(), mm)
                .unwrap();
            let root = execution.context.root;
            if let Some(grants) = self
                .owner
                .child_physical_mut(ReservationMm::new(mm).unwrap(), root)
                .unwrap()
                .supplied
                .as_mut()
            {
                self.settled += grants.settle(pool, exclusion.proof()).unwrap();
            }
            pool.release_mm(exclusion.proof());
        }
        self.owner.retire_child(execution, record).unwrap();
    }
    pub fn shutdown(&self) {
        self.shutdown_after_releases(1);
    }
    pub fn shutdown_without_child(&self) {
        self.shutdown_after_releases(0);
    }
    fn shutdown_after_releases(&self, expected: usize) {
        let outcome = prepare_record_retirement(&mut self.record.lock().unwrap(), self.identity);
        assert_eq!(
            outcome,
            RecordRetirement::Unmap {
                ipa: 0x20_0000,
                len: 606208
            },
            "child retained a structural pin after exit; no subsequent loan may be required"
        );
        assert_eq!(
            settle_record_retirement(&mut self.record.lock().unwrap(), self.identity, Ok(())),
            CarrierStage2RetireOutcome::RetiredUnmapped
        );
        assert!(
            !self.early_drop.load(Ordering::Acquire),
            "physical backing dropped before exact-MM inventory retirement"
        );
        for record in &self.supplied_records {
            assert!(
                !record.lock().unwrap().snapshot.mapped,
                "supplied backing must reach neutral terminal retirement"
            );
        }
        assert_eq!(self.releases, expected);
        assert_eq!(self.owner.live_children(), 0);
        assert!(!self.owner.has_quarantine());
    }
}

#[test]
fn native_child_exit_reclaims_stock_before_carrier_structural_shutdown() {
    super::arm_child_wait_wake_with_stock(false, false, true);
}

#[test]
fn native_backing_release_already_retired_owner_is_clean_absence_without_quarantine() {
    use carrick_mmu_core::aarch64::descriptor_txn::{
        DescriptorOp, DescriptorTxn, DescriptorTxnId, PageSpan, TableGrants,
    };

    for scenario in [
        "vm_destroy_terminalized",
        "vm_generation_advanced",
        "owner_generation_advanced",
        "record_removed",
    ] {
        let tables = crate::mm_portal::test_support::Tables::new(0x10000, 0x10000, 64);
        let mut stock = PhysicalStock::new(&tables);
        let child_mm = ReservationMm::new(41).unwrap();
        let parent_ctx_root = RootGpa::page_aligned(FrameGpa::new(0x10000)).unwrap();
        let child_root = RootGpa::page_aligned(FrameGpa::new(0x11000)).unwrap();
        let parent_table = RootGpa::page_aligned(FrameGpa::new(0x12000)).unwrap();
        let spare_table = RootGpa::page_aligned(FrameGpa::new(0x13000)).unwrap();
        let parent_exec = GrantExecution::new(
            carrick_guest_arch::CpuId::new(0),
            carrick_el1_abi::ExecutionBinding {
                task: carrick_el1_abi::EntryTaskKey::from_raw(1),
                thread_generation: carrick_el1_abi::EntryThreadGeneration::from_raw(1),
                mm: carrick_el1_abi::EntryMmKey::from_raw(1),
                generation: carrick_el1_abi::SnapshotGeneration::from_raw(1),
            },
            carrick_guest_arch::AddressContext {
                root: parent_ctx_root,
                mm: MmGeneration::new(NonZeroU64::MIN),
                generation: carrick_guest_arch::ContextGeneration::new(NonZeroU64::MIN),
            },
        );
        let request = carrick_el1_abi::ForkStockRequest {
            binding: parent_exec.binding,
            context: parent_exec.context,
            operation: carrick_el1_abi::PortalOperation {
                carrier: NonZeroU64::MIN,
                mm: ReservationMm::new(1).unwrap(),
                incarnation: NonZeroU64::MIN,
                sequence: NonZeroU64::MIN,
            },
            parent_generation: carrick_el1_abi::ReservationGeneration::INITIAL,
            child_mm,
            child_bytes: 4096,
            parent_bytes: 4096,
        };
        let mut exchange = ForkStockExchange::new(request).unwrap();
        let loan = stock.loan(
            request,
            &mut exchange,
            vec![child_root],
            vec![parent_table, spare_table],
        );
        let handle = unsafe {
            carrick_el1_abi::El1MmHandle::from_admitted_owner(
                NonZeroU64::MIN,
                child_mm,
                NonZeroU64::MIN,
            )
        };
        let completion = carrick_el1_abi::PortalForkCompletion {
            request: loan.request,
            child: handle,
            parent_generation: carrick_el1_abi::ReservationGeneration::INITIAL,
            child_tables_used: 4096,
            parent_tables_used: 4096,
        };
        let mut reserve = carrick_el1_abi::ForkStockSettlement::reserve(
            loan,
            completion,
            KernelVa::new(0x1000),
            0,
        )
        .unwrap();
        stock.reserve(loan, &mut reserve);
        let mut commit =
            carrick_el1_abi::ForkStockSettlement::commit_reserved(loan, completion).unwrap();
        stock.commit(loan, &mut commit);

        let physical_owner = carrick_hal::GuestFrameOwner {
            native_mm: MmGeneration::new(NonZeroU64::new(child_mm.raw()).unwrap()),
            root_generation: carrick_guest_arch::ContextGeneration::new(NonZeroU64::MIN),
        };
        let rollback = Arc::new(carrick_hal::physical_grants::PhysicalGrantRollback::default());
        let staged = carrick_hal::physical_grants::StagedPhysicalGrants::stage(
            rollback.clone(),
            stock.inventory.clone(),
            [FrameGpa::new(0xa0020000)],
            0,
            16384,
            physical_owner,
        )
        .unwrap();
        let row = staged.grants()[0];
        let retained = stock.backing(&staged, 16384, NonZeroU64::new(7).unwrap());
        let backing_record = retained.record.clone();
        match scenario {
            "vm_destroy_terminalized" => {
                backing_record
                    .lock()
                    .unwrap()
                    .snapshot
                    .terminalized_by_vm_destroy = true;
                backing_record.lock().unwrap().snapshot.mapped = false;
            }
            "vm_generation_advanced" => {
                backing_record.lock().unwrap().snapshot.vm_generation = CarrierVmGeneration(2);
                backing_record.lock().unwrap().snapshot.mapped = false;
            }
            "owner_generation_advanced" => {
                backing_record.lock().unwrap().snapshot.logical_owner = Some(CarrierLogicalOwner {
                    id: row.gpa.raw(),
                    generation: 8,
                });
                backing_record.lock().unwrap().snapshot.mapped = false;
            }
            "record_removed" => {
                backing_record.lock().unwrap().snapshot.record_id = CarrierStage2RecordId(99);
                backing_record.lock().unwrap().snapshot.mapped = false;
            }
            _ => unreachable!(),
        }
        let window = carrick_el1_abi::PortalGrantWindow {
            operation: carrick_el1_abi::PortalOperation {
                carrier: NonZeroU64::MIN,
                mm: child_mm,
                incarnation: NonZeroU64::MIN,
                sequence: NonZeroU64::MIN,
            },
            mapping_incarnation: carrick_el1_abi::ReservationIncarnation::new(1).unwrap(),
            range: carrick_el1_abi::ReservationRange::new(super::VA, super::VA + 4096).unwrap(),
            protection: carrick_el1_abi::ReservationProtection::READ_WRITE,
            fault_page: super::VA,
            host_backing: None,
            fork_sequence: None,
        };
        let mut txn = DescriptorTxn {
            id: DescriptorTxnId {
                mm_key: NonZeroU64::new(child_mm.raw()).unwrap(),
                generation: window.operation.sequence,
            },
            root: carrick_mmu_core::aarch64::SubstrateGpa(child_root.address().raw()),
            op: DescriptorOp::Prepare {
                publication: carrick_mmu_core::aarch64::GuestLeafPublication {
                    va: window.range.start(),
                    ipa: row.gpa.raw(),
                    len: 4096,
                    writable: true,
                    executable: false,
                },
                resident: PageSpan::new(window.fault_page, 4096),
                backing: row.identity,
            },
            tables: TableGrants::NONE,
        };
        let table_stock_before = stock.owner.table_stock().len();
        stock.track_backing_tables(handle, child_root, &mut txn);
        let reply = carrick_el1_abi::PortalGrantSlot::new();
        {
            let grants = stock
                .owner
                .child_physical_mut(child_mm, child_root)
                .unwrap()
                .supplied
                .get_or_insert_with(|| {
                    carrick_hal::physical_grants::NativePhysicalGrants::new(physical_owner)
                });
            grants
                .stage_backing_reply(
                    &reply,
                    window,
                    txn,
                    staged.with_backing(retained),
                    SupplyBacking::release_unused,
                )
                .unwrap();
            assert!(grants.offer_backing_reply(&reply, &txn));
        }
        let settled = stock
            .owner
            .settle_native_backing_reply(
                &mut NoTableLedger,
                handle,
                child_root,
                &reply,
                &txn,
                SupplyBacking::release_unused,
            )
            .unwrap_or_else(|err| {
                panic!("scenario {scenario} must settle as clean absence without carrier error: {err:?}")
            });
        assert!(settled);
        assert_eq!(stock.owner.table_stock().len(), table_stock_before);
        assert!(
            stock
                .owner
                .pending_native_descriptor_transaction(
                    handle,
                    child_root,
                    window.operation.sequence
                )
                .is_none()
        );
        assert!(
            !stock.owner.is_quarantined(child_mm),
            "scenario {scenario} must not quarantine the child MM"
        );
        assert_eq!(
            rollback.retained_count(),
            0,
            "scenario {scenario} must not retain already-retired backing until MM exit"
        );
        assert!(!rollback.failed());
    }
}

#[test]
fn concurrent_drain_portal_does_not_hide_retiring_child_space() {
    use crate::retired_spaces::{RetiredSpace, RetiredSpaces};
    use std::sync::mpsc;
    use std::time::Duration;

    let region = crate::mm_portal::test_support::Region::new();
    let zone = region.zone();
    let roots = region.table();
    let child_mm = ReservationMm::new(7).unwrap();
    let child_space = zone
        .spaces
        .publish_closed(child_mm.raw(), 0x7000, 0x7000)
        .unwrap();
    roots
        .publish(
            child_space.index(),
            child_mm,
            carrick_el1_abi::Layout {
                heap: carrick_el1_abi::ReservationRange::new(4096, super::VA).unwrap(),
                arena: carrick_el1_abi::ReservationRange::new(super::VA, super::VA + 0x1000_0000)
                    .unwrap(),
                policy: carrick_el1_abi::ReservationPolicyPayload::new([
                    4096,
                    u64::MAX,
                    u64::MAX,
                    0,
                    0,
                ]),
            },
        )
        .unwrap();

    let carrier_a = NonZeroU64::new(1).unwrap();
    let carrier_b = NonZeroU64::new(2).unwrap();
    let queue = RetiredSpaces::new();

    let (b_pushed_tx, b_pushed_rx) = mpsc::channel();
    let (a_in_drain_tx, a_in_drain_rx) = mpsc::channel();
    let (b_done_tx, b_done_rx) = mpsc::channel();

    let queue_ref = &queue;
    let (a_result, b_result, b_retired_on_return) = std::thread::scope(|s| {
        let thread_a = s.spawn(move || {
            b_pushed_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("bounded wait for thread B push timed out");
            let mut signalled = false;
            queue_ref.drain(
                |space| {
                    if !signalled {
                        signalled = true;
                        a_in_drain_tx.send(()).unwrap();
                        let _ = b_done_rx.recv_timeout(Duration::from_millis(200));
                    }
                    space.carrier == carrier_a
                },
                |_| Ok(()),
            )
        });

        let thread_b = s.spawn(move || {
            queue_ref.push(RetiredSpace {
                carrier: carrier_b,
                zone: core::ptr::from_ref(zone).addr(),
                roots: core::ptr::from_ref(roots).addr(),
                mm: child_mm,
            });
            b_pushed_tx.send(()).unwrap();
            a_in_drain_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("bounded wait for thread A drain entry timed out");

            let owner: crate::aarch64_process::Portal<'_> =
                carrick_core::mm::transaction::MmPortal::for_zone(carrier_b, roots, zone);
            let result = queue_ref.drain_portal(&owner, zone, carrick_sched_core::ZONE_SLOTS, 0);
            let retired =
                zone.spaces.find(child_mm.raw()).is_none() && owner.root_any(child_mm, 0).is_err();
            let _ = b_done_tx.send(());
            (result, retired)
        });

        let a_result = thread_a.join().unwrap();
        let (b_result, b_retired_on_return) = thread_b.join().unwrap();
        (a_result, b_result, b_retired_on_return)
    });

    assert_eq!(a_result, Ok(()));
    assert_eq!(b_result, Ok(()));
    assert!(
        b_retired_on_return,
        "thread B's drain_portal returned while its queued child space remained unretired"
    );
    assert!(queue.is_empty());
}

fn test_reservation_layout() -> carrick_el1_abi::Layout {
    carrick_el1_abi::Layout {
        heap: carrick_el1_abi::ReservationRange::new(4096, super::VA).unwrap(),
        arena: carrick_el1_abi::ReservationRange::new(super::VA, super::VA + 0x1000_0000).unwrap(),
        policy: carrick_el1_abi::ReservationPolicyPayload::new([4096, u64::MAX, u64::MAX, 0, 0]),
    }
}

#[test]
fn contended_root_keeps_closed_space_queued_until_next_drain() {
    use crate::retired_spaces::{RetiredSpace, RetiredSpaces};
    use carrick_core::mm::transaction::{MmError, MmPortal};
    use carrick_el1::memory::reservations::{NoRootWait, RootReleaseVenue};

    let region = crate::mm_portal::test_support::Region::new();
    let zone = region.zone();
    let roots = region.table();
    let carrier = NonZeroU64::new(1).unwrap();

    let child_mm = ReservationMm::new(7).unwrap();
    let child_space = zone
        .spaces
        .publish_closed(child_mm.raw(), 0x7000, 0x7000)
        .unwrap();
    zone.spaces.open(child_space);
    roots
        .publish(child_space.index(), child_mm, test_reservation_layout())
        .unwrap();

    let later_mm = ReservationMm::new(8).unwrap();
    let later_space = zone
        .spaces
        .publish_closed(later_mm.raw(), 0x8000, 0x8000)
        .unwrap();
    roots
        .publish(later_space.index(), later_mm, test_reservation_layout())
        .unwrap();

    let access = crate::sched::object_wait::space_access(zone, SlotId::new(0));
    let held_root = RootReleaseVenue::new(roots, access.venue().unwrap())
        .unwrap()
        .lock(child_space.index(), child_mm, &NoRootWait)
        .unwrap();

    let queue = RetiredSpaces::new();
    for mm in [child_mm, later_mm] {
        queue.push(RetiredSpace {
            carrier,
            zone: core::ptr::from_ref(zone).addr(),
            roots: core::ptr::from_ref(roots).addr(),
            mm,
        });
    }

    let owner: crate::aarch64_process::Portal<'_> = MmPortal::for_zone(carrier, roots, zone);
    let first = queue.drain_portal(&owner, zone, carrick_sched_core::ZONE_SLOTS, 0);
    assert_eq!((first, queue.len()), (Err(NativeProcessError::Busy), 2));
    assert!(!zone.spaces.is_open(child_mm.raw()));
    assert!(zone.spaces.find(child_mm.raw()).is_some());
    assert!(zone.spaces.find(later_mm.raw()).is_some());

    drop(held_root);

    let second = queue.drain_portal(&owner, zone, carrick_sched_core::ZONE_SLOTS, 0);
    assert_eq!(second, Ok(()));
    assert!(queue.is_empty());
    assert!(zone.spaces.find(child_mm.raw()).is_none());
    assert!(zone.spaces.find(later_mm.raw()).is_none());
    assert!(matches!(owner.root_any(child_mm, 0), Err(MmError::Stale)));
    assert!(matches!(owner.root_any(later_mm, 0), Err(MmError::Stale)));
}

#[test]
fn non_busy_root_any_error_maps_to_stale_and_drops_entry() {
    use crate::retired_spaces::{RetiredSpace, RetiredSpaces, retire_closed_space};
    use carrick_core::mm::transaction::MmPortal;

    let region = crate::mm_portal::test_support::Region::new();
    let zone = region.zone();
    let roots = region.table();
    let carrier = NonZeroU64::new(1).unwrap();

    // Space exists in `zone.spaces`, so `spaces.find` and `spaces.close` pass,
    // but no reservation root was published in `roots`: `root_any` returns
    // `MmError::Stale`, which must keep mapping to `NativeProcessError::Stale`.
    let unrooted_mm = ReservationMm::new(9).unwrap();
    zone.spaces
        .publish_closed(unrooted_mm.raw(), 0x9000, 0x9000)
        .unwrap();

    let valid_mm = ReservationMm::new(10).unwrap();
    let valid_space = zone
        .spaces
        .publish_closed(valid_mm.raw(), 0xa000, 0xa000)
        .unwrap();
    roots
        .publish(valid_space.index(), valid_mm, test_reservation_layout())
        .unwrap();

    let owner: crate::aarch64_process::Portal<'_> = MmPortal::for_zone(carrier, roots, zone);
    assert_eq!(
        retire_closed_space(&owner, unrooted_mm, 0),
        Err(NativeProcessError::Stale)
    );

    let queue = RetiredSpaces::new();
    for mm in [unrooted_mm, valid_mm] {
        queue.push(RetiredSpace {
            carrier,
            zone: core::ptr::from_ref(zone).addr(),
            roots: core::ptr::from_ref(roots).addr(),
            mm,
        });
    }

    let result = queue.drain_portal(&owner, zone, carrick_sched_core::ZONE_SLOTS, 0);
    assert_eq!(result, Err(NativeProcessError::Stale));
    assert!(queue.is_empty());
    assert!(zone.spaces.find(valid_mm.raw()).is_none());
}

#[test]
fn region_teardown_drains_and_clears_shared_retired_spaces_before_address_reuse() {
    use crate::aarch64_process::{
        Portal, drain_and_clear_retired_scope, push_retired_space_for_test,
    };
    use crate::mm_portal::test_support::Region;
    use crate::retired_spaces::RetiredSpace;
    use carrick_core::mm::transaction::MmPortal;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    // 1. A ready entry left in `RETIRED_SPACES` retires cleanly when `Region` drops.
    {
        let region = Region::new();
        let zone = region.zone();
        let roots = region.table();
        let mm = ReservationMm::new(2).unwrap();
        let space = zone
            .spaces
            .publish_closed(mm.raw(), 0x2000, 0x2000)
            .unwrap();
        roots
            .publish(space.index(), mm, test_reservation_layout())
            .unwrap();
        push_retired_space_for_test(RetiredSpace {
            carrier: NonZeroU64::MIN,
            zone: core::ptr::from_ref(zone).addr(),
            roots: core::ptr::from_ref(roots).addr(),
            mm,
        });
    }

    // 2. If a test panics while an unretireable entry (`mm = 1` still installed
    //    on slot 0) is queued for `(NonZeroU64::MIN, zone, roots)`, `Region::drop`
    //    purges that scope before freeing memory so a subsequent `Region` cannot
    //    inherit the stale entry even at the same heap addresses.
    let panic_unwind = catch_unwind(AssertUnwindSafe(|| {
        let region = Region::new();
        let zone = region.zone();
        let roots = region.table();
        let mm = ReservationMm::new(1).unwrap();
        let space = zone
            .spaces
            .publish_closed(mm.raw(), 0x1000, 0x1000)
            .unwrap();
        zone.spaces.open(space);
        zone.install_space(SlotId::new(0), mm.raw()).unwrap();
        roots
            .publish(space.index(), mm, test_reservation_layout())
            .unwrap();
        push_retired_space_for_test(RetiredSpace {
            carrier: NonZeroU64::MIN,
            zone: core::ptr::from_ref(zone).addr(),
            roots: core::ptr::from_ref(roots).addr(),
            mm,
        });
        panic!("simulated mid-test failure with queued space");
    }));
    assert!(panic_unwind.is_err());

    {
        let next = Region::new();
        let zone = next.zone();
        let roots = next.table();
        let mm = ReservationMm::new(1).unwrap();
        let space = zone
            .spaces
            .publish_closed(mm.raw(), 0x1000, 0x1000)
            .unwrap();
        roots
            .publish(space.index(), mm, test_reservation_layout())
            .unwrap();
        assert_eq!(drain_and_clear_retired_scope(zone, roots), 0);
        // `next`'s own `mm = 1` was not retired by a leftover entry from the prior `Region`.
        assert!(zone.spaces.find(mm.raw()).is_some());
        let owner: Portal<'_> = MmPortal::for_zone(NonZeroU64::MIN, roots, zone);
        assert!(owner.root_any(mm, 0).is_ok());
    }

    // 3. A normal (non-panicking) teardown with an unretireable entry fails the
    //    fixture assertion at drop while still purging the shared queue.
    let leaked_entry = catch_unwind(AssertUnwindSafe(|| {
        let region = Region::new();
        let zone = region.zone();
        let roots = region.table();
        let mm = ReservationMm::new(1).unwrap();
        let space = zone
            .spaces
            .publish_closed(mm.raw(), 0x1000, 0x1000)
            .unwrap();
        zone.spaces.open(space);
        zone.install_space(SlotId::new(0), mm.raw()).unwrap();
        roots
            .publish(space.index(), mm, test_reservation_layout())
            .unwrap();
        push_retired_space_for_test(RetiredSpace {
            carrier: NonZeroU64::MIN,
            zone: core::ptr::from_ref(zone).addr(),
            roots: core::ptr::from_ref(roots).addr(),
            mm,
        });
    }));
    assert!(leaked_entry.is_err());
}
