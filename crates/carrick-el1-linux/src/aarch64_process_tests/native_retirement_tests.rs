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
pub(super) struct SupplyBacking {
    record: Arc<Mutex<CarrierStage2Record>>,
    identity: CarrierStage2RecordIdentity,
    authority: Arc<dyn carrick_hal::FrameCowAuthority>,
    mapping: carrick_hal::MappingId,
    early_drop: Arc<core::sync::atomic::AtomicBool>,
}
impl Drop for SupplyBacking {
    fn drop(&mut self) {
        if self.authority.live_mapping_row(self.mapping).is_some() {
            self.early_drop.store(true, Ordering::Release);
        }
        let mut record = self.record.lock().unwrap();
        assert!(matches!(
            prepare_record_retirement(&mut record, self.identity),
            RecordRetirement::Unmap { .. }
        ));
        assert_eq!(
            settle_record_retirement(&mut record, self.identity, Ok(())),
            CarrierStage2RetireOutcome::RetiredUnmapped
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
        self.owner
            .install(child.into_iter().chain(parent).collect(), vec![lifecycle])
            .unwrap();
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
