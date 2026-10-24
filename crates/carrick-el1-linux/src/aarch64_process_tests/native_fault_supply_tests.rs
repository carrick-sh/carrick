//! Actual native birth, empty physical supply and ring COW completion.
use super::*;
use carrick_el1::fault::{CowResolution, CowResolver, OwnerFaultSupply, OwnerFaultSupplyOutcome};
use carrick_el1_abi::Lifecycle;
use carrick_mmu_core::aarch64::descriptor_txn::LiveDescriptorWords;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

struct FaultMemory {
    pages: RefCell<BTreeMap<u64, Vec<u8>>>,
    copies: Cell<usize>,
}
struct SelectionWords<'a>(&'a dyn LiveDescriptorWords);
impl carrick_el1::fault::PreparedPageResolver for SelectionWords<'_> {
    fn select_backing_window(
        &mut self,
        root: u64,
        window: carrick_el1_abi::PortalGrantWindow,
    ) -> Result<
        carrick_el1_abi::PortalGrantWindow,
        carrick_mmu_core::descriptor_refusal::DescriptorRefusal,
    > {
        carrick_core::mm::frames::select_backing_window::<Aarch64Mmu, _>(self.0, root, window)
    }
    fn commit_prepared(
        &mut self,
        _: u64,
        _: u64,
        _: u64,
        _: carrick_mmu_core::aarch64::LeafAccess,
    ) -> Result<
        carrick_mmu_core::aarch64::GuestPreparedCommit,
        carrick_mmu_core::aarch64::GuestPreparedCommitError,
    > {
        panic!("this fixture faults only on absent leaves or private COW leaves")
    }
}
fn leaf(words: &impl LiveDescriptorWords, root: u64, va: u64) -> u64 {
    let mut table = root & AARCH64_ROOT_ADDRESS_MASK;
    for (level, index) in carrick_mmu_core::aarch64::indices(va)
        .into_iter()
        .enumerate()
    {
        let descriptor = words.load(table + index as u64 * 8).unwrap();
        if level == 3 {
            return descriptor;
        }
        assert_eq!(descriptor & 3, 3);
        table = descriptor & AARCH64_ROOT_ADDRESS_MASK;
    }
    unreachable!()
}
struct UntouchedMapping<'a>(&'a dyn LiveDescriptorWords);
impl carrick_el1::memory::AnonymousBackingProbe for UntouchedMapping<'_> {
    fn backing(
        &mut self,
        root: carrick_guest_arch::AddressSpaceRegister,
        va: UserVa,
        len: carrick_guest_arch::GuestLen,
    ) -> carrick_el1::memory::Stage1Backing {
        carrick_el1::memory::classify_stage1_range(
            &|address| self.0.load(address).ok(),
            root.raw() & AARCH64_ROOT_ADDRESS_MASK,
            va.raw(),
            len.raw(),
        )
    }
    fn stock_span(&mut self, _: ReservationMm, _: UserVa) -> Option<carrick_guest_arch::UserRange> {
        None
    }
}
impl carrick_el1::memory::AnonymousPermissionEditor for UntouchedMapping<'_> {
    fn protect_and_invalidate(
        &mut self,
        _: carrick_guest_arch::AddressSpaceRegister,
        _: carrick_mmu_core::aarch64::GuestPermissionEdit,
    ) -> Result<(), carrick_mmu_core::aarch64::GuestPermissionEditError> {
        panic!("new mapping has no resident permission work")
    }
}
impl carrick_el1::memory::AnonymousRetirementEditor for UntouchedMapping<'_> {
    fn retire_and_invalidate(
        &mut self,
        root: carrick_guest_arch::AddressSpaceRegister,
        address: UserVa,
        len: carrick_guest_arch::GuestLen,
    ) -> Result<(), carrick_mmu_core::aarch64::GuestRetirementError> {
        use carrick_mmu_core::aarch64::descriptor_txn::{
            DescriptorOp, DescriptorOutcome, InlineJournal, PageSpan, TableGrants,
            execute_descriptor_op,
        };
        assert!(matches!(
            execute_descriptor_op(
                self.0,
                carrick_mmu_core::aarch64::SubstrateGpa(root.raw() & AARCH64_ROOT_ADDRESS_MASK),
                DescriptorOp::Retire(PageSpan::new(address.raw(), len.raw())),
                &TableGrants::NONE,
                &mut InlineJournal::new(),
            ),
            DescriptorOutcome::Applied(_)
        ));
        Ok(())
    }
}

struct FaultResolver<'a> {
    tables: &'a crate::mm_portal::test_support::Tables,
    memory: &'a FaultMemory,
    pool: &'a carrick_el1_abi::CowGrantPool,
    residency: &'a carrick_el1_abi::FrameGrantResidencyTable,
}
impl CowResolver for FaultResolver<'_> {
    fn resolve_cow(&mut self, root: u64, mm: u64, address: u64) -> bool {
        self.resolve_cow_outcome(root, mm, address) == CowResolution::Resolved
    }
    fn resolve_cow_outcome(&mut self, root: u64, mm: u64, address: u64) -> CowResolution {
        let maintenance = CallerInvalidatesAsid;
        let words = self.tables.live(&maintenance);
        let root = carrick_mmu_core::aarch64::SubstrateGpa(root & AARCH64_ROOT_ADDRESS_MASK);
        let outcome = carrick_el1::cow::resolve_guest_cow(
            &carrick_el1::cow::GuestCowVenue {
                words: &words,
                root,
                pool: self.pool,
                residency: self.residency,
                copy_window: carrick_core::mm::cow::CowCopyWindow::target(&words, root),
                publish_executable: None,
            },
            mm,
            address,
            |source, destination| {
                let from = leaf(&words, root.raw(), source);
                let to = leaf(&words, root.raw(), destination);
                assert_eq!(from & 1, 1);
                assert_eq!(to & 1, 1);
                assert_eq!(from & (3 << 6), 2 << 6);
                assert_eq!(to & (3 << 6), 0);
                let bytes = self.memory.pages.borrow()[&(from & AARCH64_ROOT_ADDRESS_MASK)].clone();
                self.memory
                    .pages
                    .borrow_mut()
                    .insert(to & AARCH64_ROOT_ADDRESS_MASK, bytes);
                self.memory.copies.set(self.memory.copies.get() + 1);
            },
            || {},
        );
        carrick_el1::fault::handle_cow_outcome(outcome, &mut None)
    }
    fn editor_busy(&mut self) {}
}

#[test]
fn native_child_empty_supply_resumes_cow_without_changing_parent() {
    composed_native_supply(false, None, false);
}
#[test]
fn native_backing_reply_observes_a_competing_valid_publication() {
    composed_native_supply(true, None, false);
}
#[test]
fn native_child_backing_selection_excludes_inherited_live_neighbor() {
    composed_native_supply(false, Some(1), false);
}
#[test]
fn native_child_backing_selection_excludes_inherited_live_suffix() {
    composed_native_supply(false, Some(0), false);
}
#[test]
fn native_child_fixed_over_cow_preserves_parent_bytes_and_retires() {
    composed_native_supply(false, None, true);
}
fn composed_native_supply(
    competing_publication: bool,
    absent_page: Option<usize>,
    replace_cow: bool,
) {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    if let Some(absent_page) = absent_page {
        // Parent's two-page reservation has only one page resident.
        // Actual native fork must carry that descriptor into the child even
        // though the child's lazy-grant residency table has no corresponding row.
        fixture.tables.words[1536 + absent_page].store(0, Ordering::Relaxed);
    }
    fixture.zone.spaces.set_idle_ttbr(0x30000);
    let window = carrick_el1_abi::EL1_COW_COPY_BASE;
    let indices = carrick_mmu_core::aarch64::indices(window);
    let set = |address: u64, value| {
        fixture.tables.words[((address - 0x10000) / 8) as usize].store(value, Ordering::Relaxed)
    };
    set(0x11000 + indices[1] as u64 * 8, 0x14000 | 3);
    set(0x14000 + indices[2] as u64 * 8, 0x15000 | 3);
    for page in 0..2 {
        let alias = window + page * 4096;
        set(
            0x15000 + carrick_mmu_core::aarch64::indices(alias)[3] as u64 * 8,
            alias,
        );
    }
    let words = Box::leak(Box::new(fixture.tables.live(&fixture.maintenance)));
    let pages: Vec<_> = (0..16).map(|index| 0x20000 + index * 4096).collect();
    let pool: &'static carrick_el1_abi::CowGrantPool =
        Box::leak(Box::new(carrick_el1_abi::CowGrantPool::new()));
    let residency: &'static carrick_el1_abi::FrameGrantResidencyTable =
        Box::leak(carrick_el1::cow::test_support::residency_table());
    let mut crossing = TestStockCrossing::new(&pages);
    let mut stock = super::native_retirement_tests::PhysicalStock::new(&fixture.tables);
    stock.pool = Some(pool);
    stock.residency = Some(residency);
    crossing.physical = Some(std::sync::Mutex::new(stock));
    *crossing.zone.lock().unwrap() = Some(fixture.zone);
    let crossing = Box::leak(Box::new(crossing));
    let mut service = Aarch64NativeProcessService::with_crossing(
        &fixture.task,
        fixture.slot,
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        &*crossing,
    )
    .with_words(words)
    .with_fault_residency(residency);
    let mut frame = carrick_el1_abi::TrapFrame::default();
    let mut cpu = crate::sched::FakeCpu::default();
    frame.x[8] = 220;
    frame.x[0] = 17;
    arm_call_with_cpu(fixture, fixture.control, &mut service, &mut frame, &mut cpu).unwrap();
    assert!((frame.x[0] as i64) > 0);
    fixture.zone.publish_slot(fixture.slot, 0, None, 0);
    fixture.task.mm.key.store(0, Ordering::Release);
    let counters = carrick_el1_abi::Counters::new();
    let mut handoff = None;
    let mut zone = crate::dispatch::Zone {
        tables: fixture.zone,
        cpu: &mut cpu,
        user: &crate::sched::HardwareUserWord,
    };
    assert_eq!(
        crate::dispatch::native_scheduler(
            &mut zone,
            &fixture.task,
            &counters,
            fixture.slot,
            &mut handoff
        )
        .idle_entry(&mut frame, 0),
        carrick_el1_abi::Action::Served
    );
    let child = fixture.zone.slot(fixture.slot).current().unwrap();
    let identity = fixture.zone.record(child).identity();
    let owner = registry()
        .for_record(fixture.zone, fixture.zone.record_ref(child))
        .unwrap();
    assert!(matches!(
        resume_selected(
            &owner,
            registry(),
            BornInZoneSource {
                zone: fixture.zone,
                slot: fixture.slot
            },
            &fixture.task,
            child,
            &mut service
        ),
        super::super::native_process_runtime::NativeResume::NoPending
    ));
    let memory = FaultMemory {
        pages: RefCell::new(
            (0..2)
                .map(|i| (IPA + i * 4096, vec![17 + i as u8; 4096]))
                .collect(),
        ),
        copies: Cell::new(0),
    };
    assert_eq!(pool.ready(identity.mm).count(), 0);
    let mut resolver = FaultResolver {
        tables: &fixture.tables,
        memory: &memory,
        pool,
        residency,
    };
    let portal = fixture.region.portal_slots();
    assert!(portal.bind_carrier(NonZeroU64::MIN));
    // The same immutable birth handle used by the hardware fault entry.
    let control = unsafe { &*(identity.control_slot as *const ThreadControlSlot) };
    let handle = control
        .service
        .bound_mm(
            fixture.zone.record_ref(child),
            carrick_el1_abi::EntryThreadGeneration::from_raw(identity.serial),
        )
        .unwrap();
    let supply = OwnerFaultSupply::new(portal).with_handle(handle);
    let mailbox = carrick_el1_abi::FrameGrantMailbox::new();
    if let Some(absent_page) = absent_page {
        let fault_page = VA + absent_page as u64 * 4096;
        let neighbor = VA + (1 - absent_page) as u64 * 4096;
        frame.esr = 0x92000046;
        frame.far = fault_page;
        let access = crate::sched::object_wait::space_access(fixture.zone, fixture.slot);
        let root = access
            .grant(access.find(identity.mm).unwrap(), identity.mm)
            .unwrap()
            .ttbr0;
        assert_ne!(leaf(words, root, neighbor), 0);
        assert_eq!(leaf(words, root, fault_page), 0);
        assert!(residency.lookup(identity.mm, neighbor).is_none());
        assert_eq!(
            carrick_el1::fault::dispatch_fault_with_prepared(
                &mut frame,
                &counters,
                core::slice::from_ref(&fixture.task),
                access,
                crate::cow_resolver::native_fault_supply(
                    true,
                    carrick_el1::fault::GrantMailboxes::own(&mailbox),
                    &supply
                ),
                Some(carrick_el1::fault::PreparedFaultPath {
                    residency,
                    resolver: &mut SelectionWords(words),
                    roots: Some(fixture.region.table()),
                    file_slots: Some(portal),
                }),
                &mut resolver,
            ),
            carrick_el1_abi::Action::Forward
        );
        assert_eq!(supply.outcome(), OwnerFaultSupplyOutcome::Selected);
        let (_, window) = portal
            .grant(0)
            .unwrap()
            .pending_fault_selection(identity.mm, frame.far)
            .unwrap();
        assert_eq!(
            window.range.start(),
            fault_page,
            "physical supply must exclude the inherited live neighbor"
        );
        assert_eq!(window.range.len(), 4096);
        // Trimming a file-backed window advances its retained source by the
        // same prefix. No adapter may restart at the original file offset.
        let mut file_window = window;
        file_window.range = carrick_el1_abi::ReservationRange::new(VA, VA + 8192).unwrap();
        file_window.host_backing = Some(carrick_el1_abi::HostBackingIdentity::new(
            NonZeroU64::MIN,
            NonZeroU64::MIN,
            0x2000,
        ));
        let selected = carrick_core::mm::frames::select_backing_window::<Aarch64Mmu, _>(
            words,
            root,
            file_window,
        )
        .unwrap();
        assert_eq!(selected.range, window.range);
        assert_eq!(
            selected.host_backing.unwrap().offset(),
            0x2000 + fault_page - VA
        );
        assert!(
            portal
                .grant(0)
                .unwrap()
                .cancel_fault_selection(window, window.operation.sequence.get())
        );
        // A translation fault observed before a competing publication must
        // retry the now-live instruction, not allocate backing or signal it.
        frame.esr = 0x92000006;
        frame.far = neighbor;
        let retry = OwnerFaultSupply::new(portal).with_handle(handle);
        assert_eq!(
            carrick_el1::fault::dispatch_fault_with_prepared(
                &mut frame,
                &counters,
                core::slice::from_ref(&fixture.task),
                access,
                crate::cow_resolver::native_fault_supply(
                    true,
                    carrick_el1::fault::GrantMailboxes::own(&mailbox),
                    &retry
                ),
                Some(carrick_el1::fault::PreparedFaultPath {
                    residency,
                    resolver: &mut SelectionWords(words),
                    roots: Some(fixture.region.table()),
                    file_slots: Some(portal),
                }),
                &mut resolver,
            ),
            carrick_el1_abi::Action::Served
        );
        assert!(!portal.grant(0).unwrap().has_outstanding_for(identity.mm));
        return;
    }
    frame.esr = 0x9200004f;
    frame.far = VA + 13;
    frame.elr = 0x401234;
    frame.x[3] = 0x7abc;
    for cause in [
        carrick_el1_abi::PortalWaitCause::Editor,
        carrick_el1_abi::PortalWaitCause::Reservations,
        carrick_el1_abi::PortalWaitCause::Gate,
    ] {
        for release_before_enroll in [true, false] {
            let access = crate::sched::object_wait::space_access(fixture.zone, fixture.slot);
            let index = access.find(identity.mm).unwrap();
            let child_root = access.grant(index, identity.mm).unwrap().ttbr0;
            let mut held_editor = (cause == carrick_el1_abi::PortalWaitCause::Editor).then(|| {
                access
                    .try_begin_edit(index, identity.mm, NonZeroU64::new(99).unwrap())
                    .unwrap()
            });
            let mut held_root =
                (cause == carrick_el1_abi::PortalWaitCause::Reservations).then(|| {
                    fixture
                        .region
                        .table()
                        .lock_in(access, index.index(), handle.mm(), 7)
                        .unwrap()
                });
            if cause == carrick_el1_abi::PortalWaitCause::Gate {
                access.raise(index);
            }
            let busy = OwnerFaultSupply::new(portal).with_handle(handle);
            assert_eq!(
                carrick_el1::fault::dispatch_fault_with_prepared(
                    &mut frame,
                    &counters,
                    core::slice::from_ref(&fixture.task),
                    access,
                    crate::cow_resolver::native_fault_supply(
                        true,
                        carrick_el1::fault::GrantMailboxes::own(&mailbox),
                        &busy
                    ),
                    Some(carrick_el1::fault::PreparedFaultPath {
                        residency,
                        resolver: &mut carrick_el1::fault::NoopPreparedResolver,
                        roots: Some(fixture.region.table()),
                        file_slots: Some(portal)
                    }),
                    &mut resolver,
                ),
                carrick_el1_abi::Action::Forward
            );
            let OwnerFaultSupplyOutcome::Wait(wait) = busy.outcome() else {
                panic!("known contention lost its producer: {:?}", busy.outcome());
            };
            assert_eq!(wait.cause(), cause);
            assert_eq!(wait.handle(), handle);
            let mut release = || {
                drop(held_editor.take());
                drop(held_root.take());
                if cause == carrick_el1_abi::PortalWaitCause::Gate {
                    access.lower(index);
                }
            };
            if release_before_enroll {
                release();
            }
            let page = unsafe { &*(identity.lifecycle_page as *const ThreadLifecyclePage) };
            let mut saved = Aarch64ParkedContext::ZERO;
            crate::sched::ThreadCpu::save(&mut cpu, &frame, &mut saved);
            let result = with_process_entry(
                BornInZoneSource {
                    zone: fixture.zone,
                    slot: fixture.slot,
                },
                &fixture.task,
                &saved.native,
                child_root,
                page,
                control,
                &mut service,
                |entry| {
                    let result = entry
                        .begin_owner_service_wait(
                            ServiceOperation::Fault(carrick_guest_arch::FaultInfo {
                                address: UserVa::new(frame.far),
                                access: carrick_guest_arch::Access::Write,
                                present: true,
                            }),
                            wait,
                        )
                        .unwrap();
                    assert_eq!(
                        entry.take_handoff_receipt().is_some(),
                        !release_before_enroll
                    );
                    result
                },
            )
            .unwrap();
            assert_eq!(
                fixture.task.service_notice.take().unwrap(),
                None,
                "ring contention must not request physical service"
            );
            if release_before_enroll {
                assert!(
                    matches!(result, NativeResume::NoPending),
                    "publication in the enrollment gap retries once without parking"
                );
            } else {
                assert!(matches!(result, NativeResume::Left(None)));
                assert_eq!(page.claimed_count(), 1);
                crate::dispatch::native_service_idle(fixture.zone, fixture.slot, &mut cpu);
                release();
                let mut handoff = None;
                let mut zone = crate::dispatch::Zone {
                    tables: fixture.zone,
                    cpu: &mut cpu,
                    user: &crate::sched::HardwareUserWord,
                };
                assert_eq!(
                    crate::dispatch::native_scheduler(
                        &mut zone,
                        &fixture.task,
                        &counters,
                        fixture.slot,
                        &mut handoff
                    )
                    .idle_entry(&mut frame, 0),
                    carrick_el1_abi::Action::Served
                );
                assert_eq!(fixture.zone.slot(fixture.slot).current(), Some(child));
                assert!(matches!(
                    resume_selected(
                        &owner,
                        registry(),
                        BornInZoneSource {
                            zone: fixture.zone,
                            slot: fixture.slot
                        },
                        &fixture.task,
                        child,
                        &mut service
                    ),
                    NativeResume::NoPending
                ));
                frame.esr = 0x9200004f;
                frame.far = VA + 13;
            }
            assert_eq!(page.claimed_count(), 0);
            assert_eq!(memory.copies.get(), 0);
        }
    }
    let action = carrick_el1::fault::dispatch_fault_with_prepared(
        &mut frame,
        &counters,
        core::slice::from_ref(&fixture.task),
        crate::sched::object_wait::space_access(fixture.zone, fixture.slot),
        crate::cow_resolver::native_fault_supply(
            true,
            carrick_el1::fault::GrantMailboxes::own(&mailbox),
            &supply,
        ),
        Some(carrick_el1::fault::PreparedFaultPath {
            residency,
            resolver: &mut carrick_el1::fault::NoopPreparedResolver,
            roots: Some(fixture.region.table()),
            file_slots: Some(portal),
        }),
        &mut resolver,
    );
    assert_eq!(action, carrick_el1_abi::Action::Forward);
    assert_eq!(
        supply.outcome(),
        OwnerFaultSupplyOutcome::CowSelected,
        "native empty-pool COW must select the exact MM supply portal"
    );
    let (_, selected) = portal
        .grant(0)
        .unwrap()
        .pending_cow_fault_selection(identity.mm, frame.far)
        .unwrap();
    assert_eq!(selected.operation.mm.raw(), identity.mm);
    assert_eq!(selected.fault_page, VA);
    assert_eq!(
        memory.copies.get(),
        0,
        "selection cannot copy before physical supply"
    );
    use super::super::native_process_runtime::NativeResume;
    use carrick_core_abi::service::{ServiceCell, ServiceOperation};
    use carrick_sched_core::object_wait::ObjectWaitKey;
    let source = BornInZoneSource {
        zone: fixture.zone,
        slot: fixture.slot,
    };
    // SAFETY: the native child retains its initialized lifecycle/control allocation.
    let page = unsafe { &*(identity.lifecycle_page as *const ThreadLifecyclePage) };
    let control = unsafe { &*(identity.control_slot as *const ThreadControlSlot) };
    let mut saved = Aarch64ParkedContext::ZERO;
    crate::sched::ThreadCpu::save(&mut cpu, &frame, &mut saved);
    let child_root = fixture
        .zone
        .spaces
        .grant(fixture.zone.spaces.find(identity.mm).unwrap(), identity.mm)
        .unwrap()
        .ttbr0;
    let fault = carrick_guest_arch::FaultInfo {
        address: UserVa::new(frame.far),
        access: carrick_guest_arch::Access::Write,
        present: true,
    };
    assert!(matches!(
        with_process_entry(
            source,
            &fixture.task,
            &saved.native,
            child_root,
            page,
            control,
            &mut service,
            |entry| {
                let result = entry
                    .begin_service(
                        ServiceOperation::Fault(fault),
                        Some(selected.operation.sequence),
                    )
                    .unwrap();
                assert!(entry.take_handoff_receipt().is_some());
                result
            }
        )
        .unwrap(),
        NativeResume::Left(None)
    ));
    let selector = fixture.task.service_notice.take().unwrap().unwrap();
    let key = ObjectWaitKey::native_service(selector.record).unwrap();
    let mut ticket = {
        let queue = fixture
            .zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin)
            .unwrap();
        let member = queue.native_service_member(selector.record).unwrap();
        unsafe { ServiceCell::claim_notice(&control.service, selector, NonZeroU64::MIN, member) }
            .ok()
            .unwrap()
    };
    let captured = ticket
        .take_fault_selection(portal.grant(0).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        captured,
        carrick_core_abi::service::ServiceFaultSupply::Cow(selected)
    );
    assert!(!portal.grant(0).unwrap().has_outstanding_for(identity.mm));
    assert!(
        ticket
            .take_fault_selection(portal.grant(0).unwrap())
            .is_err(),
        "one selection transfer per ticket"
    );
    assert_eq!(
        ticket.request().identity.birth.mm.mm().raw(),
        selected.operation.mm.raw()
    );
    assert_eq!(
        ticket.request().identity.birth.mm.incarnation(),
        selected.operation.incarnation
    );
    assert_eq!(page.claimed_count(), 1);
    // The physical supplier uses the same inventory publication as CPL0 boot.
    // It receives only an exact-MM grant window, never a VMA/table owner.
    let physical = crossing
        .physical
        .as_ref()
        .unwrap()
        .lock()
        .unwrap()
        .inventory
        .clone();
    let physical_owner = carrick_hal::GuestFrameOwner {
        native_mm: MmGeneration::new(NonZeroU64::new(identity.mm).unwrap()),
        root_generation: ContextGeneration::new(selected.operation.incarnation),
    };
    let access = crate::sched::object_wait::space_access(fixture.zone, fixture.slot);
    let exclusion = access
        .try_exclude_editor(access.find(identity.mm).unwrap(), identity.mm)
        .unwrap();
    let mut physical_grants =
        carrick_hal::physical_grants::NativePhysicalGrants::new(physical_owner);
    // Carrier allocation generations already advanced before the first child
    // fault. They must not become the fresh inventory mapping's generation.
    for (gpa, physical_generation) in [(0xa0000000, 5), (0xa0004000, 6)] {
        let physical_generation = NonZeroU64::new(physical_generation).unwrap();
        let staged = carrick_hal::physical_grants::StagedPhysicalGrants::stage_with_permissions(
            std::sync::Arc::default(),
            physical.clone(),
            [FrameGpa::new(gpa)],
            0,
            16384,
            physical_owner,
            carrick_hal::physical_grants::COW_GRANT_PERMISSIONS,
        )
        .unwrap();
        let retained = crossing.physical.as_ref().unwrap().lock().unwrap().backing(
            &staged,
            16384,
            physical_generation,
        );
        physical_grants
            .publish_cow(staged, retained, pool, exclusion.proof())
            .unwrap();
    }
    assert_eq!(pool.ready(identity.mm).count(), 2, "bounded first refill");
    for grant in pool.ready(identity.mm) {
        let row = physical
            .bind(physical_owner)
            .live_mapping_row(carrick_hal::MappingId::from_kernel_allocation(
                grant.backing.mapping_id,
            ))
            .unwrap();
        assert!(
            row.permissions.exec,
            "COW backing must permit later execution"
        );
        assert_eq!(row.generation.raw(), 1, "fresh inventory publication");
    }
    let child_physical_root =
        RootGpa::page_aligned(FrameGpa::new(child_root & AARCH64_ROOT_ADDRESS_MASK)).unwrap();
    crossing
        .physical
        .as_ref()
        .unwrap()
        .lock()
        .unwrap()
        .owner
        .child_physical_mut(handle.mm(), child_physical_root)
        .unwrap()
        .supplied = Some(physical_grants);

    drop(exclusion);
    {
        let queue = fixture
            .zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin)
            .unwrap();
        assert!(ticket.complete(true).is_ok());
        queue
            .notify_object(fixture.slot, &mut Default::default())
            .unwrap();
    }
    let mut handoff = None;
    let mut zone = crate::dispatch::Zone {
        tables: fixture.zone,
        cpu: &mut cpu,
        user: &crate::sched::HardwareUserWord,
    };
    assert_eq!(
        crate::dispatch::native_scheduler(
            &mut zone,
            &fixture.task,
            &counters,
            fixture.slot,
            &mut handoff
        )
        .idle_entry(&mut frame, 0),
        carrick_el1_abi::Action::Served
    );
    assert_eq!(fixture.zone.slot(fixture.slot).current(), Some(child));
    assert!(matches!(
        resume_selected(
            &owner,
            registry(),
            source,
            &fixture.task,
            child,
            &mut service
        ),
        NativeResume::NoPending
    ));
    assert_eq!(page.claimed_count(), 0);
    assert_eq!(frame.elr, 0x401234, "resume exact fault PC");
    assert_eq!(frame.x[3], 0x7abc, "resume exact fault registers");
    // ESR/FAR describe the next hardware retry of that unchanged instruction.
    frame.esr = 0x9200004f;
    frame.far = VA + 13;
    assert_eq!(
        carrick_el1::fault::dispatch_fault_with_prepared(
            &mut frame,
            &counters,
            core::slice::from_ref(&fixture.task),
            crate::sched::object_wait::space_access(fixture.zone, fixture.slot),
            crate::cow_resolver::native_fault_supply(
                true,
                carrick_el1::fault::GrantMailboxes::own(&mailbox),
                &supply
            ),
            Some(carrick_el1::fault::PreparedFaultPath {
                residency,
                resolver: &mut carrick_el1::fault::NoopPreparedResolver,
                roots: Some(fixture.region.table()),
                file_slots: Some(portal)
            }),
            &mut resolver,
        ),
        carrick_el1_abi::Action::Served
    );
    let destination = leaf(words, child_root, VA) & AARCH64_ROOT_ADDRESS_MASK;
    assert_ne!(destination, IPA);
    memory.pages.borrow_mut().get_mut(&destination).unwrap()[13] = 99;
    assert_eq!(
        memory.pages.borrow()[&IPA][13],
        17,
        "parent bytes unchanged"
    );
    assert_eq!(memory.pages.borrow()[&destination][13], 99);
    assert!(
        memory.copies.get() > 0 && memory.copies.get() <= 4,
        "at most one compound copied"
    );
    assert_eq!(leaf(words, 0x10000, VA) & AARCH64_ROOT_ADDRESS_MASK, IPA);
    assert_eq!(pool.ready(identity.mm).count(), 1);

    // Dispatch the child's first syscall through the real ARM native adapter.
    frame.x[8] = 172;
    let cache = carrick_el1_abi::InotifyNameCache::new();
    let route = super::super::dispatch::dispatch_arm_syscall_with_native_process(
        &mut frame,
        &counters,
        core::slice::from_ref(&fixture.task),
        &[],
        &[],
        &[],
        &[],
        &cache,
        Some(crate::dispatch::Zone {
            tables: fixture.zone,
            cpu: &mut cpu,
            user: &crate::sched::HardwareUserWord,
        }),
        None,
        Some(fixture),
        page,
        control,
        &ThreadCtx::ZERO,
        child_root,
        &mut service,
        |_| core::ptr::null_mut(),
    )
    .unwrap();
    assert!(matches!(
        route,
        carrick_personality_linux::dispatch::CompletionRoute::Served
            | carrick_personality_linux::dispatch::CompletionRoute::WithWork
    ));
    assert_eq!(frame.x[0], identity.tid);
    assert_eq!(counters.served[172].load(Ordering::Acquire), 1);
    // Exercise request-owned backing through native park/resume. The fixed
    // variant replaces the second page of the completed COW span while its
    // USED receipt is still pending; the first page and parent remain live.
    frame.esr = 0x15 << 26;
    frame.x[8] = 222;
    let map_base = if replace_cow { VA + 4096 } else { VA + 0x10000 };
    frame.x[..6].copy_from_slice(&[map_base, 8192, 3, 0x32, u64::MAX, 0]);
    assert_eq!(
        carrick_el1::memory::serve_delegated_anonymous(
            &mut frame,
            &counters,
            &fixture.task,
            access,
            fixture.region.table(),
            &mut UntouchedMapping(words),
        ),
        carrick_el1::memory::DelegatedAnonymous::Served
    );
    let fresh = frame.x[0];
    if replace_cow {
        // serve_delegated_anonymous updates the installed global residency
        // table on target_os=none; this fixture owns that table explicitly.
        residency.retire_overlapping(identity.mm, fresh, 8192);
    }
    assert!(fresh == map_base, "native mmap: {fresh:#x}");
    frame.esr = 0x92000046;
    frame.far = fresh + 7;
    frame.elr = 0x401300;
    let backing_supply = OwnerFaultSupply::new(portal).with_handle(handle);
    assert_eq!(
        carrick_el1::fault::dispatch_fault_with_prepared(
            &mut frame,
            &counters,
            core::slice::from_ref(&fixture.task),
            access,
            crate::cow_resolver::native_fault_supply(
                true,
                carrick_el1::fault::GrantMailboxes::own(&mailbox),
                &backing_supply
            ),
            Some(carrick_el1::fault::PreparedFaultPath {
                residency,
                resolver: &mut SelectionWords(words),
                roots: Some(fixture.region.table()),
                file_slots: Some(portal)
            }),
            &mut resolver,
        ),
        carrick_el1_abi::Action::Forward
    );
    assert_eq!(backing_supply.outcome(), OwnerFaultSupplyOutcome::Selected);
    let (_, window) = portal
        .grant(0)
        .unwrap()
        .pending_fault_selection(identity.mm, frame.far)
        .unwrap();
    let mut saved = Aarch64ParkedContext::ZERO;
    crate::sched::ThreadCpu::save(&mut cpu, &frame, &mut saved);
    assert!(matches!(
        with_process_entry(
            source,
            &fixture.task,
            &saved.native,
            child_root,
            page,
            control,
            &mut service,
            |entry| {
                let result = entry
                    .begin_service(
                        ServiceOperation::Fault(carrick_guest_arch::FaultInfo {
                            address: UserVa::new(frame.far),
                            access: carrick_guest_arch::Access::Write,
                            present: false,
                        }),
                        Some(window.operation.sequence),
                    )
                    .unwrap();
                assert!(entry.take_handoff_receipt().is_some());
                result
            }
        )
        .unwrap(),
        NativeResume::Left(None)
    ));
    let notice = fixture.task.service_notice.take().unwrap().unwrap();
    let mut ticket = {
        let queue = fixture
            .zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin)
            .unwrap();
        let member = queue.native_service_member(notice.record).unwrap();
        unsafe { ServiceCell::claim_notice(&control.service, notice, NonZeroU64::MIN, member) }
            .unwrap()
    };
    assert_eq!(
        ticket
            .take_fault_selection(portal.grant(0).unwrap())
            .unwrap(),
        Some(carrick_core_abi::service::ServiceFaultSupply::Backing(
            window
        ))
    );
    let reply = ticket.reply_address().unwrap();
    let staged = carrick_hal::physical_grants::StagedPhysicalGrants::stage(
        std::sync::Arc::default(),
        physical.clone(),
        [FrameGpa::new(0xa0020000)],
        0,
        16384,
        physical_owner,
    )
    .unwrap();
    let rows = {
        let mut stock = crossing.physical.as_ref().unwrap().lock().unwrap();
        let retained = stock.backing(&staged, 16384, NonZeroU64::new(7).unwrap());
        stock
            .owner
            .child_physical_mut(handle.mm(), child_physical_root)
            .unwrap()
            .supplied
            .as_mut()
            .unwrap()
            .retain_backing(staged, retained)
            .unwrap()
    };
    use carrick_mmu_core::aarch64::descriptor_txn::{
        DescriptorOp, DescriptorTxn, DescriptorTxnId, PageSpan, TableGrants,
    };
    let txn = DescriptorTxn {
        id: DescriptorTxnId {
            mm_key: NonZeroU64::new(identity.mm).unwrap(),
            generation: window.operation.sequence,
        },
        root: carrick_mmu_core::aarch64::SubstrateGpa(child_physical_root.address().raw()),
        op: DescriptorOp::Prepare {
            publication: carrick_mmu_core::aarch64::GuestLeafPublication {
                va: window.range.start(),
                ipa: rows[0].gpa.raw(),
                len: 4096,
                writable: true,
                executable: false,
            },
            resident: PageSpan::new(window.fault_page, 4096),
            backing: rows[0].identity,
        },
        tables: TableGrants::new(&[]).unwrap(),
    };
    assert_eq!(window.range.start(), fresh);
    assert!(window.range.len() >= 8192);
    // SAFETY: the native pending request owns this aligned reply through ACK.
    assert!(
        unsafe { &*(reply.raw() as *const carrick_el1_abi::PortalGrantSlot) }.submit(window, &txn)
    );
    if competing_publication {
        let competing = carrick_el1_abi::PortalGrantSlot::new();
        assert!(competing.submit(window, &txn));
        let mm = crate::aarch64_process::Portal::for_zone(
            NonZeroU64::MIN,
            fixture.region.table(),
            fixture.zone,
        );
        let target = carrick_core::mm::frames::grant_target(&mm, window, 0).unwrap();
        let receipt = carrick_core::mm::frames::apply_grant::<Aarch64Mmu, _>(
            &competing,
            words,
            residency,
            target,
            || {},
        )
        .unwrap();
        assert!(matches!(
            receipt.outcome,
            carrick_mmu_core::aarch64::descriptor_txn::DescriptorOutcome::Applied(_)
        ));
        assert!(competing.take_receipt(window, &txn).is_some());
    }
    {
        let queue = fixture
            .zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin)
            .unwrap();
        assert!(ticket.complete(true).is_ok());
        queue
            .notify_object(fixture.slot, &mut Default::default())
            .unwrap();
    }
    let mut handoff = None;
    let mut zone = crate::dispatch::Zone {
        tables: fixture.zone,
        cpu: &mut cpu,
        user: &crate::sched::HardwareUserWord,
    };
    assert_eq!(
        crate::dispatch::native_scheduler(
            &mut zone,
            &fixture.task,
            &counters,
            fixture.slot,
            &mut handoff
        )
        .idle_entry(&mut frame, 0),
        carrick_el1_abi::Action::Served
    );
    assert!(matches!(
        resume_selected(
            &owner,
            registry(),
            source,
            &fixture.task,
            child,
            &mut service
        ),
        NativeResume::NoPending
    ));
    assert_eq!(frame.elr, 0x401300);
    assert!(
        !registry().signal_checkpoint_needed(fixture.zone, fixture.zone.record_ref(child)),
        "a competing valid publication cannot manufacture SIGSEGV"
    );
    assert_eq!(
        leaf(words, child_root, fresh) & AARCH64_ROOT_ADDRESS_MASK,
        rows[0].gpa.raw()
    );
    assert_eq!(
        leaf(words, child_root, fresh + 4096),
        0,
        "unreadable suffix must remain absent"
    );
    if replace_cow {
        assert_eq!(fresh % 16384, 4096, "exercise a sub-compound boundary");
        assert_eq!(
            leaf(words, 0x10000, fresh) & AARCH64_ROOT_ADDRESS_MASK,
            IPA + 4096
        );
        assert_eq!(memory.pages.borrow()[&(IPA + 4096)][13], 18);
        // The fixture's physical memory model gives fresh anonymous backing
        // zero bytes, just as the real physical allocator does.
        let replacement = rows[0].gpa.raw();
        memory.pages.borrow_mut().insert(replacement, vec![0; 4096]);
        let child_output = leaf(words, child_root, fresh) & AARCH64_ROOT_ADDRESS_MASK;
        assert!(
            memory.pages.borrow()[&child_output]
                .iter()
                .all(|byte| *byte == 0)
        );
        memory.pages.borrow_mut().get_mut(&child_output).unwrap()[13] = 77;
        assert_eq!(memory.pages.borrow()[&child_output][13], 77);
        assert_eq!(memory.pages.borrow()[&(IPA + 4096)][13], 18);
        assert_eq!(memory.pages.borrow()[&destination][13], 99);
        assert_eq!(memory.pages.borrow()[&IPA][13], 17);
    } else {
        assert_eq!(
            leaf(words, 0x10000, fresh),
            0,
            "parent acquires no child backing"
        );
    }
    assert_eq!(page.claimed_count(), 0);
    let exclusion = access
        .try_exclude_editor(access.find(identity.mm).unwrap(), identity.mm)
        .unwrap();
    let mut stock = crossing.physical.as_ref().unwrap().lock().unwrap();
    let physical_grants = stock
        .owner
        .child_physical_mut(handle.mm(), child_physical_root)
        .unwrap()
        .supplied
        .as_mut()
        .unwrap();
    assert!(
        physical_grants
            .settle(pool, exclusion.proof(), |_| None)
            .is_err()
    );
    assert!(
        pool.has_completions_for(identity.mm),
        "failed authentication retains USED"
    );
    drop(stock);
    drop(exclusion);
    // Leave USED for the actual terminal adapter: it must settle while the
    // child root exists, then return stock without any later fork loan.
    let context =
        unsafe { observed_entry_address(source, &fixture.task, child_root, child) }.unwrap();
    *crossing.child.lock().unwrap() = Some((
        crate::common_entry::execution_binding(&fixture.task),
        context,
    ));
    let mut saved = Aarch64ParkedContext::ZERO;
    crate::sched::ThreadCpu::save(&mut cpu, &frame, &mut saved);
    with_process_entry(
        source,
        &fixture.task,
        &saved.native,
        child_root,
        page,
        control,
        &mut service,
        |entry| {
            assert!(matches!(
                entry.exit_group(0),
                LifecycleOutcome::Transferred { .. }
            ));
            assert_eq!(entry.take_run_failure(), None);
        },
    )
    .unwrap();
    assert!(fixture.zone.spaces.find(identity.mm).is_none());
    assert_eq!(crossing.loans_requested.load(Ordering::Acquire), 1);
    assert_eq!(pool.ready(identity.mm).count(), 0);
    assert!(!pool.has_completions_for(identity.mm));
    let stock = crossing.physical.as_ref().unwrap().lock().unwrap();
    assert_eq!(stock.settled, 1, "terminal USED settlement is once-only");
    assert_eq!(memory.pages.borrow()[&IPA][13], 17);
    assert_eq!(
        leaf(words, 0x10000, VA) & AARCH64_ROOT_ADDRESS_MASK,
        IPA,
        "child table clear cannot alter the parent's translation"
    );
    stock.shutdown();
}
