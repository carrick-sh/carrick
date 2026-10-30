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
struct FixtureMapping<'a> {
    words: &'a dyn LiveDescriptorWords,
    residency: &'a carrick_el1_abi::FrameGrantResidencyTable,
}
impl carrick_el1::memory::AnonymousBackingProbe for FixtureMapping<'_> {
    fn backing(
        &mut self,
        root: carrick_guest_arch::AddressSpaceRegister,
        va: UserVa,
        len: carrick_guest_arch::GuestLen,
    ) -> carrick_el1::memory::Stage1Backing {
        carrick_el1::memory::classify_stage1_range(
            &|address| self.words.load(address).ok(),
            root.raw() & AARCH64_ROOT_ADDRESS_MASK,
            va.raw(),
            len.raw(),
        )
    }
    fn stock_span(&mut self, _: ReservationMm, _: UserVa) -> Option<carrick_guest_arch::UserRange> {
        None
    }
}
impl carrick_el1::memory::AnonymousPermissionEditor for FixtureMapping<'_> {
    fn protect_and_invalidate(
        &mut self,
        root: carrick_guest_arch::AddressSpaceRegister,
        edit: carrick_mmu_core::aarch64::GuestPermissionEdit,
    ) -> Result<(), carrick_mmu_core::aarch64::GuestPermissionEditError> {
        use carrick_mmu_core::aarch64::descriptor_txn::{
            DescriptorOp, DescriptorOutcome, InlineJournal, TableGrants, execute_descriptor_op,
        };
        assert!(matches!(
            execute_descriptor_op(
                self.words,
                carrick_mmu_core::aarch64::SubstrateGpa(root.raw() & AARCH64_ROOT_ADDRESS_MASK),
                DescriptorOp::Protect(edit),
                &TableGrants::NONE,
                &mut InlineJournal::new(),
            ),
            DescriptorOutcome::Applied(_)
        ));
        Ok(())
    }
}
impl carrick_el1::memory::AnonymousRetirementEditor for FixtureMapping<'_> {
    fn retire_and_invalidate(
        &mut self,
        mm: ReservationMm,
        root: carrick_guest_arch::AddressSpaceRegister,
        address: UserVa,
        len: carrick_guest_arch::GuestLen,
    ) -> Result<(), carrick_mmu_core::aarch64::GuestRetirementError> {
        use carrick_mmu_core::aarch64::descriptor_txn::{
            DescriptorOp, DescriptorOutcome, InlineJournal, PageSpan, TableGrants,
            execute_descriptor_op,
        };
        let Some(residency) =
            self.residency
                .begin_retire_overlapping(mm.raw(), address.raw(), len.raw())
        else {
            return Err(carrick_mmu_core::aarch64::GuestRetirementError::ResidencyBusy);
        };
        assert!(matches!(
            execute_descriptor_op(
                self.words,
                carrick_mmu_core::aarch64::SubstrateGpa(root.raw() & AARCH64_ROOT_ADDRESS_MASK),
                DescriptorOp::Retire(PageSpan::new(address.raw(), len.raw())),
                &TableGrants::NONE,
                &mut InlineJournal::new(),
            ),
            DescriptorOutcome::Applied(_)
        ));
        assert!(residency.commit());
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
    composed_native_supply(false, None, false, SupplyEnd::Resume);
}

#[test]
fn native_fault_reply_stale_owner_window_retries_instruction() {
    use carrick_mmu_core::aarch64::descriptor_txn::{
        DescriptorOp, DescriptorTxn, DescriptorTxnId, PageSpan, TableGrants,
    };

    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    let mut service = fixture.process_service();
    let slot = carrick_el1_abi::PortalGrantSlot::new();
    let window = carrick_el1_abi::PortalGrantWindow {
        operation: carrick_el1_abi::PortalOperation {
            carrier: NonZeroU64::new(2).unwrap(),
            mm: ReservationMm::new(1).unwrap(),
            incarnation: NonZeroU64::MIN,
            sequence: NonZeroU64::MIN,
        },
        mapping_incarnation: carrick_el1_abi::ReservationIncarnation::new(1).unwrap(),
        range: carrick_el1_abi::ReservationRange::new(VA, VA + 4096).unwrap(),
        protection: carrick_el1_abi::ReservationProtection::READ_WRITE,
        fault_page: VA,
        host_backing: None,
        fork_sequence: None,
    };
    let txn = DescriptorTxn {
        id: DescriptorTxnId {
            mm_key: NonZeroU64::MIN,
            generation: NonZeroU64::MIN,
        },
        root: carrick_mmu_core::aarch64::SubstrateGpa(0x10000),
        op: DescriptorOp::Retire(PageSpan::new(VA, 4096)),
        tables: TableGrants::NONE,
    };
    assert!(slot.submit(window, &txn));

    // A supplied reply authenticates its old operation, not the current
    // instruction. A replaced owner must retry the fault under the current
    // mapping instead of turning the stale reply into SIGSEGV.
    assert_eq!(
        NativeProcessService::apply_fault_reply(
            &mut service,
            &slot,
            crate::native_process_runtime::FaultReplyDisposition::Apply
        ),
        Ok(())
    );
}

#[test]
fn native_backing_reply_observes_a_competing_valid_publication() {
    composed_native_supply(true, None, false, SupplyEnd::Resume);
}
#[test]
fn native_child_backing_selection_excludes_inherited_live_neighbor() {
    composed_native_supply(false, Some(1), false, SupplyEnd::Resume);
}
#[test]
fn native_child_backing_selection_excludes_inherited_live_suffix() {
    composed_native_supply(false, Some(0), false, SupplyEnd::Resume);
}
#[test]
fn native_child_fixed_over_cow_preserves_parent_bytes_and_retires() {
    composed_native_supply(false, None, true, SupplyEnd::Resume);
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum SupplyEnd {
    Resume,
    Cancel,
    FailTables,
    EarlyApplyError,
}

#[test]
fn native_backing_cancel_after_delivery_restores_private_supply() {
    composed_native_supply(false, None, false, SupplyEnd::Cancel);
}

#[test]
fn native_backing_early_apply_error_settles_the_reply_before_returning() {
    composed_native_supply(false, None, false, SupplyEnd::EarlyApplyError);
}

#[test]
fn native_backing_table_failure_retains_applied_receipt_without_ack() {
    composed_native_supply(false, None, false, SupplyEnd::FailTables);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PreparedScenario {
    None,
    UntouchedGrant,
    ProtNoneAcrossFork,
    ResidentTranslationRetry,
    CompetingValidPreparedReply,
}

fn composed_native_supply(
    competing_publication: bool,
    absent_page: Option<usize>,
    replace_cow: bool,
    end: SupplyEnd,
) {
    composed_native_supply_with_prepared(
        competing_publication,
        absent_page,
        replace_cow,
        end,
        PreparedScenario::None,
    );
}

#[test]
fn native_child_first_touch_of_inherited_prepared_leaf_makes_progress() {
    composed_native_supply_with_prepared(
        false,
        None,
        false,
        SupplyEnd::Resume,
        PreparedScenario::UntouchedGrant,
    );
}

#[test]
fn native_child_prot_none_across_fork_preserves_parent_bytes() {
    composed_native_supply_with_prepared(
        false,
        None,
        false,
        SupplyEnd::Resume,
        PreparedScenario::ProtNoneAcrossFork,
    );
}

#[test]
fn native_child_translation_retry_requires_an_already_valid_leaf() {
    composed_native_supply_with_prepared(
        false,
        None,
        false,
        SupplyEnd::Resume,
        PreparedScenario::ResidentTranslationRetry,
    );
}

#[test]
fn native_prepared_reply_retries_after_competing_valid_publication() {
    composed_native_supply_with_prepared(
        false,
        None,
        false,
        SupplyEnd::Resume,
        PreparedScenario::CompetingValidPreparedReply,
    );
}

fn composed_native_supply_with_prepared(
    competing_publication: bool,
    absent_page: Option<usize>,
    replace_cow: bool,
    end: SupplyEnd,
    prepared: PreparedScenario,
) {
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    // Keep descriptor grants disjoint from the original 32-page fork arena.
    // No live-word venue or raw table pointer has been formed yet.
    let mut table_words = core::mem::take(&mut fixture.tables.words).into_vec();
    table_words.extend((0..32 * 512).map(|_| core::sync::atomic::AtomicU64::new(0)));
    fixture.tables.words = table_words.into_boxed_slice();
    match prepared {
        PreparedScenario::None | PreparedScenario::ResidentTranslationRetry => {}
        PreparedScenario::UntouchedGrant | PreparedScenario::CompetingValidPreparedReply => {
            // Untouched private anonymous stock has an output but is invalid.
            // Keep the non-identity IPA and Linux RW intent from the parent leaf.
            let descriptor = fixture.tables.words[1536].load(Ordering::Relaxed);
            fixture.tables.words[1536]
                .store((descriptor & !1) | (1 << 56) | (1 << 57), Ordering::Relaxed);
            assert!(
                carrick_mmu_core::aarch64::terminal_descriptor_is_prepared_private(
                    fixture.tables.words[1536].load(Ordering::Relaxed)
                )
            );
        }
        PreparedScenario::ProtNoneAcrossFork => {
            crate::mm_portal::test_support::change_policy(
                fixture.region,
                crate::sched::object_wait::space_access(fixture.zone, fixture.slot),
                ReservationMm::new(1).unwrap(),
                &fixture.tables,
                Some(carrick_el1_abi::ReservationProtection::NONE),
            );
            assert!(
                carrick_mmu_core::aarch64::terminal_descriptor_is_prepared_private(
                    fixture.tables.words[1536].load(Ordering::Relaxed)
                )
            );
        }
    }
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
    let mailbox = carrick_el1_abi::FrameGrantMailbox::new();
    let supply = OwnerFaultSupply::new(portal).with_handle(handle);
    let publish_inherited = |window: carrick_el1_abi::PortalGrantWindow, root: u64| {
        let reply = Box::new(carrick_el1_abi::PortalGrantSlot::new());
        let root = carrick_guest_arch::RootGpa::page_aligned(carrick_guest_arch::FrameGpa::new(
            root & AARCH64_ROOT_ADDRESS_MASK,
        ))
        .unwrap();
        let mut stock = crossing.physical.as_ref().unwrap().lock().unwrap();
        let txn = stock
            .owner
            .stage_native_prepared_reply(
                &mut carrick_hal::fork_stock::NoTableLedger,
                handle,
                root,
                &reply,
                window,
            )
            .unwrap()
            .expect("actual native fork must retain the inherited physical frame");
        assert!(matches!(
            txn.op,
            carrick_mmu_core::aarch64::descriptor_txn::DescriptorOp::Publish { .. }
        ));
        assert!(
            txn.tables.as_slice().is_empty(),
            "existing backing links no tables"
        );
        assert!(
            stock
                .owner
                .child_physical_mut(handle.mm(), root)
                .unwrap()
                .supplied
                .as_mut()
                .unwrap()
                .offer_backing_reply(&reply, &txn)
        );
        reply
    };
    match prepared {
        PreparedScenario::None => {}
        PreparedScenario::UntouchedGrant
        | PreparedScenario::ResidentTranslationRetry
        | PreparedScenario::CompetingValidPreparedReply => {
            frame.esr = 0x92000006;
            frame.far = VA;
            let access = crate::sched::object_wait::space_access(fixture.zone, fixture.slot);
            assert!(residency.lookup(identity.mm, VA).is_none());
            if prepared == PreparedScenario::UntouchedGrant {
                let index = access.find(identity.mm).unwrap();
                let held = access
                    .try_begin_edit(index, identity.mm, NonZeroU64::new(2).unwrap())
                    .unwrap();
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
                            resolver: &mut SelectionWords(words),
                            roots: Some(fixture.region.table()),
                            file_slots: Some(portal),
                        }),
                        &mut resolver,
                    ),
                    carrick_el1_abi::Action::Forward
                );
                let OwnerFaultSupplyOutcome::Wait(wait) = busy.outcome() else {
                    panic!("Busy must retain an owner wait");
                };
                assert_eq!(wait.handle(), handle);
                assert_eq!(wait.cause(), carrick_el1_abi::PortalWaitCause::Editor);
                drop(held);
            }
            let action = carrick_el1::fault::dispatch_fault_with_prepared(
                &mut frame,
                &counters,
                core::slice::from_ref(&fixture.task),
                access,
                crate::cow_resolver::native_fault_supply(
                    true,
                    carrick_el1::fault::GrantMailboxes::own(&mailbox),
                    &supply,
                ),
                Some(carrick_el1::fault::PreparedFaultPath {
                    residency,
                    resolver: &mut SelectionWords(words),
                    roots: Some(fixture.region.table()),
                    file_slots: Some(portal),
                }),
                &mut resolver,
            );
            let root = access
                .grant(access.find(identity.mm).unwrap(), identity.mm)
                .unwrap()
                .ttbr0;
            assert!(
                action == carrick_el1_abi::Action::Forward
                    && supply.outcome() == OwnerFaultSupplyOutcome::Selected
                    || leaf(words, root, VA) & 1 != 0,
                "first-touch must publish a usable translation or request backing, not retry the same invalid leaf: action={action:?} supply={:?} leaf={:#x}",
                supply.outcome(),
                leaf(words, root, VA),
            );
            if prepared == PreparedScenario::ResidentTranslationRetry {
                assert_eq!(action, carrick_el1_abi::Action::Served);
                assert_eq!(supply.outcome(), OwnerFaultSupplyOutcome::Unavailable);
                return;
            }
            let (_, selected) = portal
                .grant(0)
                .unwrap()
                .pending_prepared_fault_selection(identity.mm, VA)
                .unwrap();
            let before = leaf(words, root, VA);
            let reply = publish_inherited(selected, root);
            let mut competing = None;
            if prepared == PreparedScenario::CompetingValidPreparedReply {
                use carrick_mmu_core::aarch64::descriptor_txn::{
                    AliasAccess, BackingIdentity, DescriptorOp, DescriptorOutcome, InlineJournal,
                    PageSpan, TableGrants, execute_descriptor_op,
                };
                // A second publisher installs an already-retained neighboring
                // frame through the shipping descriptor executor while this
                // reply still retains the original expected output.
                let _editor = access
                    .try_begin_edit(
                        access.find(identity.mm).unwrap(),
                        identity.mm,
                        NonZeroU64::new(2).unwrap(),
                    )
                    .unwrap();
                assert!(matches!(
                    execute_descriptor_op(
                        words,
                        carrick_mmu_core::aarch64::SubstrateGpa(root & AARCH64_ROOT_ADDRESS_MASK),
                        DescriptorOp::MapAlias {
                            access: AliasAccess::User {
                                writable: false,
                                executable: false
                            },
                            span: PageSpan::new(VA, 4096),
                            target_ipa: carrick_mmu_core::aarch64::SubstrateGpa(IPA + 4096),
                            backing: BackingIdentity {
                                frame_id: NonZeroU64::MIN,
                                mapping_id: NonZeroU64::MIN,
                                owner_generation: NonZeroU64::MIN,
                                inventory_revision: NonZeroU64::MIN,
                            },
                        },
                        &TableGrants::NONE,
                        &mut InlineJournal::new(),
                    ),
                    DescriptorOutcome::Applied(_)
                ));
                competing = Some(leaf(words, root, VA));
            }
            NativeProcessService::apply_fault_reply(
                &mut service,
                &reply,
                crate::native_process_runtime::FaultReplyDisposition::Apply,
            )
            .unwrap();
            if let Some(competing) = competing {
                assert_eq!(
                    leaf(words, root, VA),
                    competing,
                    "late reply must preserve the competing translation"
                );
                assert_eq!(memory.pages.borrow()[&IPA], vec![17; 4096]);
                return;
            }
            assert_eq!(
                leaf(words, root, VA),
                before | 1,
                "only VALID changes; AP and COW custody survive"
            );
            assert_eq!(
                memory.pages.borrow()[&(leaf(words, root, VA) & AARCH64_ROOT_ADDRESS_MASK)],
                vec![17; 4096]
            );
            assert_eq!(memory.pages.borrow()[&IPA], vec![17; 4096]);
            assert_eq!(
                memory.copies.get(),
                0,
                "publication allocates and copies no backing"
            );
            return;
        }
        PreparedScenario::ProtNoneAcrossFork => {
            let access = crate::sched::object_wait::space_access(fixture.zone, fixture.slot);
            frame.x[8] = 226;
            frame.x[..3].copy_from_slice(&[VA, 4096, 1]);
            assert_eq!(
                carrick_el1::memory::serve_delegated_anonymous(
                    &mut frame,
                    &counters,
                    &fixture.task,
                    access,
                    fixture.region.table(),
                    &mut FixtureMapping { words, residency },
                    None,
                ),
                carrick_el1::memory::DelegatedAnonymous::Served,
            );
            assert_eq!(frame.x[0], 0);
            let root = access
                .grant(access.find(identity.mm).unwrap(), identity.mm)
                .unwrap()
                .ttbr0;
            if leaf(words, root, VA) & 1 == 0 {
                frame.esr = 0x92000006;
                frame.far = VA;
                let action = carrick_el1::fault::dispatch_fault_with_prepared(
                    &mut frame,
                    &counters,
                    core::slice::from_ref(&fixture.task),
                    access,
                    crate::cow_resolver::native_fault_supply(
                        true,
                        carrick_el1::fault::GrantMailboxes::own(&mailbox),
                        &supply,
                    ),
                    Some(carrick_el1::fault::PreparedFaultPath {
                        residency,
                        resolver: &mut SelectionWords(words),
                        roots: Some(fixture.region.table()),
                        file_slots: Some(portal),
                    }),
                    &mut resolver,
                );
                if action == carrick_el1_abi::Action::Forward
                    && supply.outcome() == OwnerFaultSupplyOutcome::Selected
                {
                    if let Some((_, window)) = portal
                        .grant(0)
                        .unwrap()
                        .pending_prepared_fault_selection(identity.mm, VA)
                    {
                        let before = leaf(words, root, VA);
                        let reply = publish_inherited(window, root);
                        NativeProcessService::apply_fault_reply(
                            &mut service,
                            &reply,
                            crate::native_process_runtime::FaultReplyDisposition::Apply,
                        )
                        .unwrap();
                        assert_eq!(leaf(words, root, VA), before | 1);
                    } else {
                        let (_, window) = portal
                            .grant(0)
                            .unwrap()
                            .pending_fault_selection(identity.mm, VA)
                            .unwrap();
                        memory.pages.borrow_mut().insert(0xa0020000, vec![0; 4096]);
                        let id = NonZeroU64::MIN;
                        let txn = carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn {
                            id: carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxnId {
                                mm_key: NonZeroU64::new(identity.mm).unwrap(),
                                generation: window.operation.sequence,
                            },
                            root: carrick_mmu_core::aarch64::SubstrateGpa(
                                root & AARCH64_ROOT_ADDRESS_MASK,
                            ),
                            op: carrick_mmu_core::aarch64::descriptor_txn::DescriptorOp::Prepare {
                                publication: carrick_mmu_core::aarch64::GuestLeafPublication {
                                    va: window.range.start(),
                                    ipa: 0xa0020000,
                                    len: 4096,
                                    writable: false,
                                    executable: false,
                                },
                                resident: carrick_mmu_core::aarch64::descriptor_txn::PageSpan::new(
                                    VA, 4096,
                                ),
                                backing:
                                    carrick_mmu_core::aarch64::descriptor_txn::BackingIdentity {
                                        frame_id: id,
                                        mapping_id: id,
                                        owner_generation: id,
                                        inventory_revision: id,
                                    },
                            },
                            tables: carrick_mmu_core::aarch64::descriptor_txn::TableGrants::NONE,
                        };
                        let slot = portal.grant(0).unwrap();
                        assert!(slot.submit(window, &txn));
                        let mm_owner = crate::mm_portal::MmPortal::<
                            crate::mm_portal::test_support::NoPin,
                        >::for_zone(
                            NonZeroU64::MIN, fixture.region.table(), fixture.zone
                        );
                        let receipt = carrick_core::mm::frames::serve_grant(
                            &mm_owner,
                            slot,
                            words,
                            residency,
                            u32::from(fixture.slot.raw()),
                            || {},
                        )
                        .unwrap()
                        .unwrap();
                        assert!(matches!(
                            receipt.outcome,
                            carrick_mmu_core::aarch64::descriptor_txn::DescriptorOutcome::Applied(
                                _
                            )
                        ));
                        assert!(slot.take_receipt(window, &txn).is_some());
                    }
                }
            }
            let child_leaf = leaf(words, root, VA);
            assert_ne!(
                child_leaf & 1,
                0,
                "child page must be readable after mprotect(PROT_READ): leaf={child_leaf:#x}"
            );
            let child_ipa = child_leaf & AARCH64_ROOT_ADDRESS_MASK;
            assert_eq!(
                memory.pages.borrow()[&child_ipa],
                vec![17; 4096],
                "PROT_NONE across fork must preserve parent's written bytes, not replace with zeros (child_ipa={child_ipa:#x})"
            );
            return;
        }
    }
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
                    &supply,
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
                    &retry,
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
                        &busy,
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
            .publish_cow(staged.with_backing(retained), pool, exclusion.proof())
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
                &supply,
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
    let replacement_len = if replace_cow { 65536 } else { 8192 };
    let backing_len = if replace_cow { replacement_len } else { 16384 };
    frame.x[..6].copy_from_slice(&[map_base, replacement_len, 3, 0x32, u64::MAX, 0]);
    let transfer_pin = replace_cow.then(|| {
        let page = residency
            .lookup(identity.mm, map_base)
            .expect("completed COW span retains residency");
        residency
            .pin_transfer(page)
            .expect("fixture owns the live residency generation")
    });
    let first = carrick_el1::memory::serve_delegated_anonymous(
        &mut frame,
        &counters,
        &fixture.task,
        access,
        fixture.region.table(),
        &mut FixtureMapping { words, residency },
        None,
    );
    if let Some(pin) = transfer_pin {
        assert_eq!(
            first,
            carrick_el1::memory::DelegatedAnonymous::Forward,
            "a transfer pin must refuse before stage-1 replacement"
        );
        assert!(
            residency.lookup(identity.mm, map_base).is_some(),
            "refusal preserves the original residency"
        );
        drop(pin);
        frame.x[..6].copy_from_slice(&[map_base, replacement_len, 3, 0x32, u64::MAX, 0]);
        assert_eq!(
            carrick_el1::memory::serve_delegated_anonymous(
                &mut frame,
                &counters,
                &fixture.task,
                access,
                fixture.region.table(),
                &mut FixtureMapping { words, residency },
                None,
            ),
            carrick_el1::memory::DelegatedAnonymous::Served
        );
    } else {
        assert_eq!(first, carrick_el1::memory::DelegatedAnonymous::Served);
    }
    let fresh = frame.x[0];
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
                &backing_supply,
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
        backing_len,
        physical_owner,
    )
    .unwrap();
    let rows = staged.grants().to_vec();
    use carrick_mmu_core::aarch64::descriptor_txn::{
        DescriptorOp, DescriptorTxn, DescriptorTxnId, PageSpan, TableGrants,
    };
    let mut txn = DescriptorTxn {
        id: DescriptorTxnId {
            mm_key: NonZeroU64::new(identity.mm).unwrap(),
            generation: window.operation.sequence,
        },
        root: carrick_mmu_core::aarch64::SubstrateGpa(child_physical_root.address().raw()),
        op: DescriptorOp::Prepare {
            publication: carrick_mmu_core::aarch64::GuestLeafPublication {
                va: window.range.start(),
                ipa: rows[0].gpa.raw(),
                len: if replace_cow {
                    window.range.len()
                } else {
                    4096
                },
                writable: true,
                executable: false,
            },
            resident: PageSpan::new(window.fault_page, 4096),
            backing: rows[0].identity,
        },
        tables: TableGrants::new(&[]).unwrap(),
    };
    assert_eq!(window.range.start(), fresh);
    assert_eq!(window.range.len(), replacement_len);
    // SAFETY: the retained native ticket owns this exact reply through ACK.
    let reply_slot = unsafe { &*(reply.raw() as *const carrick_el1_abi::PortalGrantSlot) };
    {
        let mut stock = crossing.physical.as_ref().unwrap().lock().unwrap();
        let retained = stock.backing(&staged, backing_len, NonZeroU64::new(7).unwrap());
        stock.track_backing_tables(handle, child_physical_root, &mut txn);
        let grants = stock
            .owner
            .child_physical_mut(handle.mm(), child_physical_root)
            .unwrap()
            .supplied
            .as_mut()
            .unwrap();
        grants
            .stage_backing_reply(
                reply_slot,
                window,
                txn,
                staged.with_backing(retained),
                super::native_retirement_tests::SupplyBacking::release_unused,
            )
            .unwrap();
        assert!(grants.offer_backing_reply(reply_slot, &txn));
    }
    // Guest-originated stale candidates must leave the real pending supply
    // untouched. The same two native MMs remain live for the real completion.
    {
        let mut stock = crossing.physical.as_ref().unwrap().lock().unwrap();
        let stale_owner = unsafe {
            carrick_el1_abi::El1MmHandle::from_admitted_owner(
                handle.carrier(),
                handle.mm(),
                NonZeroU64::new(handle.incarnation().get() + 1).unwrap(),
            )
        };
        let unrelated_reply = carrick_el1_abi::PortalGrantSlot::new();
        let mut stale_txn = txn;
        stale_txn.id.generation = NonZeroU64::new(txn.id.generation.get() + 1).unwrap();
        for (candidate_owner, candidate_root, candidate_reply, candidate_txn) in [
            (stale_owner, child_physical_root, reply_slot, txn),
            (
                handle,
                RootGpa::page_aligned(FrameGpa::new(0xffff0000)).unwrap(),
                reply_slot,
                txn,
            ),
            (handle, child_physical_root, &unrelated_reply, txn),
            (handle, child_physical_root, reply_slot, stale_txn),
        ] {
            let result = stock.owner.settle_native_backing_reply(
                &mut carrick_hal::fork_stock::NoTableLedger,
                candidate_owner,
                candidate_root,
                candidate_reply,
                &candidate_txn,
                |_| panic!("a stale request must not release physical custody"),
            );
            assert!(
                !result.unwrap(),
                "guest mismatch must be refused without settling the real supply"
            );
            assert!(!stock.owner.is_quarantined(handle.mm()));
            assert_eq!(
                stock.owner.pending_native_descriptor_transaction(
                    handle,
                    child_physical_root,
                    txn.id.generation
                ),
                Some(txn)
            );
        }
    }
    if competing_publication {
        let competing = carrick_el1_abi::PortalGrantSlot::new();
        // A competing producer owns different bytes and an independent
        // request. Reusing the refused reply's bytes would hide early release.
        let mut competing_window = window;
        competing_window.operation.sequence =
            NonZeroU64::new(window.operation.sequence.get() + 1).unwrap();
        let competitor = carrick_hal::physical_grants::StagedPhysicalGrants::stage(
            std::sync::Arc::default(),
            physical.clone(),
            [FrameGpa::new(0xb0020000)],
            0,
            backing_len,
            physical_owner,
        )
        .unwrap();
        let data = competitor.grants()[0];
        let mut competing_txn = txn;
        competing_txn.id.generation = competing_window.operation.sequence;
        if let DescriptorOp::Prepare {
            publication,
            backing,
            ..
        } = &mut competing_txn.op
        {
            publication.ipa = data.gpa.raw();
            *backing = data.identity;
        }
        {
            let mut stock = crossing.physical.as_ref().unwrap().lock().unwrap();
            let retained = stock.backing(&competitor, backing_len, NonZeroU64::new(8).unwrap());
            stock.track_backing_tables(handle, child_physical_root, &mut competing_txn);
            let grants = stock
                .owner
                .child_physical_mut(handle.mm(), child_physical_root)
                .unwrap()
                .supplied
                .as_mut()
                .unwrap();
            grants
                .stage_backing_reply(
                    &competing,
                    competing_window,
                    competing_txn,
                    competitor.with_backing(retained),
                    super::native_retirement_tests::SupplyBacking::release_unused,
                )
                .unwrap();
            assert!(grants.offer_backing_reply(&competing, &competing_txn));
        }
        let mm = crate::aarch64_process::Portal::for_zone(
            NonZeroU64::MIN,
            fixture.region.table(),
            fixture.zone,
        );
        let target = carrick_core::mm::frames::grant_target(&mm, competing_window, 0).unwrap();
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
        crossing
            .physical
            .as_ref()
            .unwrap()
            .lock()
            .unwrap()
            .settle_backing_reply(handle, competing_window.operation.sequence, &competing);
    }
    if end == SupplyEnd::FailTables {
        // Apply through the real ring owner, then inject loss of the pending
        // table journal between physical application and combined settlement.
        let portal = crate::aarch64_process::Portal::for_zone(
            NonZeroU64::MIN,
            fixture.region.table(),
            fixture.zone,
        );
        let target = carrick_core::mm::frames::grant_target(&portal, window, 0).unwrap();
        let receipt = carrick_core::mm::frames::apply_grant::<Aarch64Mmu, _>(
            reply_slot,
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
        let mut stock = crossing.physical.as_ref().unwrap().lock().unwrap();
        stock
            .owner
            .cancel_submitted_native_descriptor_tables(
                &mut carrick_hal::fork_stock::NoTableLedger,
                handle,
                child_physical_root,
                txn.id.generation,
            )
            .unwrap();
        assert!(
            stock
                .owner
                .settle_native_backing_reply(
                    &mut carrick_hal::fork_stock::NoTableLedger,
                    handle,
                    child_physical_root,
                    reply_slot,
                    &txn,
                    super::native_retirement_tests::SupplyBacking::release_unused
                )
                .is_err()
        );
        assert!(stock.owner.is_quarantined(handle.mm()));
        assert!(
            stock
                .owner
                .child_physical_mut(handle.mm(), child_physical_root)
                .unwrap()
                .supplied
                .as_mut()
                .unwrap()
                .failed()
        );
        assert_eq!(reply_slot.inspect_receipt(window, &txn), Some(receipt));
        assert_eq!(
            leaf(words, child_root, fresh) & AARCH64_ROOT_ADDRESS_MASK,
            rows[0].gpa.raw()
        );
        assert_eq!(
            control.service.consume(ticket.request().identity),
            Err(carrick_core_abi::service::ServiceError::Busy)
        );
        // The leaked carrier fixture retains the failed journal and both live
        // MMs; no retirement/ACK is manufactured to make this failure pass.
        return;
    }
    if end == SupplyEnd::EarlyApplyError {
        // The native target is valid, but the host-portable adapter has no
        // live words. This error used to bypass the settlement crossing.
        service.words = None;
        assert_eq!(
            NativeProcessService::apply_fault_reply(
                &mut service,
                reply_slot,
                crate::native_process_runtime::FaultReplyDisposition::Apply,
            ),
            Err(carrick_core::mm::transaction::MmError::Core)
        );
        assert!(
            reply_slot.window().is_none(),
            "early apply error stranded the supplied lane"
        );
    }
    let delivered_request = ticket.request();
    {
        let queue = fixture
            .zone
            .object_wait(key, &carrick_sched_core::ShortLockSpin)
            .unwrap();
        assert!(ticket.complete(true).is_ok());
        if end == SupplyEnd::Cancel {
            assert!(control.service.cancel(delivered_request.identity).unwrap());
        }
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
        if matches!(end, SupplyEnd::Cancel | SupplyEnd::EarlyApplyError) {
            0
        } else if competing_publication {
            0xb0020000
        } else {
            rows[0].gpa.raw()
        }
    );
    if !replace_cow {
        assert_eq!(
            leaf(words, child_root, fresh + 4096),
            0,
            "unreadable suffix must remain absent"
        );
    }
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
        for offset in (0..replacement_len).step_by(4096) {
            memory
                .pages
                .borrow_mut()
                .insert(replacement + offset, vec![0; 4096]);
        }

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
    // Another live MM cannot settle this child's physical receipts.
    let parent_mm = fixture.leader.mm;
    assert_ne!(parent_mm, identity.mm);
    let exclusion = access
        .try_exclude_editor(access.find(parent_mm).unwrap(), parent_mm)
        .unwrap();
    let mut stock = crossing.physical.as_ref().unwrap().lock().unwrap();
    let physical_grants = stock
        .owner
        .child_physical_mut(handle.mm(), child_physical_root)
        .unwrap()
        .supplied
        .as_mut()
        .unwrap();
    assert!(physical_grants.settle(pool, exclusion.proof()).is_err());
    assert!(
        pool.has_completions_for(identity.mm),
        "failed authentication retains USED"
    );
    drop(stock);
    drop(exclusion);
    // Leave USED for the actual terminal adapter: it must authenticate the
    // retained publication even after MAP_FIXED, then return stock without
    // any later fork loan.
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

/// Two live threads of one MM: while sibling B holds the reservation root or
/// MM editor preparing a first-touch grant for a shared block, thread A's
/// write into that block must wait on the shared owner publication and retry
/// rather than erasing `Busy` to `None` and forwarding an empty mailbox to
/// host first-touch (`backend-refused` -> `SIGSEGV`, #1008).
#[test]
fn arm_two_live_threads_wait_for_sibling_first_touch_publication() {
    use crate::native_process_runtime::NativeResume;
    use carrick_core_abi::service::ServiceOperation;
    use carrick_el1::fault::{GrantMailboxes, NoopCowResolver, PreparedFaultPath};
    let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
    fixture.zone.spaces.set_idle_ttbr(0x30000);
    let sibling_slot = SlotId::new(1);
    fixture.zone.drive(sibling_slot, 1);
    fixture.zone.publish_slot(sibling_slot, 1, Some(1), 2);
    fixture.zone.enter_guest(sibling_slot);
    fixture.zone.install_space(sibling_slot, 1).unwrap();
    let (_, sibling) =
        imported_thread_on_slot(fixture, sibling_slot, |identity| identity.affinity = 2);
    let mut service = fixture.process_service();
    let portal = fixture.region.portal_slots();
    assert!(portal.bind_carrier(NonZeroU64::MIN));

    assert_eq!(fixture.page.live(), 2);
    assert!(fixture.zone.live(sibling).is_some());
    assert!(
        !fixture
            .zone
            .slot(fixture.slot)
            .current()
            .is_some_and(|record| fixture.zone.record(record).is_native_owned())
    );
    let mut cpu = crate::sched::FakeCpu::default();
    let handle = crate::cow_resolver::admitted_fault_mm_handle(
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        fixture.slot,
        &fixture.task,
    )
    .expect("admitted reservation root must supply the exact MM handle before native entry");

    let access = crate::sched::object_wait::space_access(fixture.zone, fixture.slot);
    let sibling_access = crate::sched::object_wait::space_access(fixture.zone, sibling_slot);
    let index = access.find(handle.mm().raw()).unwrap();
    let residency = carrick_el1::cow::test_support::residency_table();
    let words = fixture.tables.live(&fixture.maintenance);
    let counters = carrick_el1_abi::Counters::new();

    // 1. Host-cloned (`!native`) mailbox venue (exact #1008 capture shape):
    // Sibling B holds the reservation root lock on slot 1 while inspecting/planning
    // a grant for the shared block. Thread A faults on slot 0.
    let mailbox_a = carrick_el1_abi::FrameGrantMailbox::new();
    for release_before_enroll in [false, true] {
        let mut frame = carrick_el1_abi::TrapFrame {
            esr: 0x92000046,
            far: VA + 8,
            elr: 0x401234,
            ..Default::default()
        };
        frame.x[3] = 0x7abc;

        if release_before_enroll {
            let held_root = fixture
                .region
                .table()
                .lock_in(
                    sibling_access,
                    index.index(),
                    handle.mm(),
                    u32::from(sibling_slot.raw()),
                )
                .unwrap();
            let supply = OwnerFaultSupply::new(portal).with_handle(handle);
            assert_eq!(
                carrick_el1::fault::dispatch_fault_with_prepared(
                    &mut frame,
                    &counters,
                    core::slice::from_ref(&fixture.task),
                    access,
                    crate::cow_resolver::native_fault_supply(
                        false,
                        GrantMailboxes::own(&mailbox_a),
                        &supply,
                    ),
                    Some(PreparedFaultPath {
                        residency: &residency,
                        resolver: &mut SelectionWords(&words),
                        roots: Some(fixture.region.table()),
                        file_slots: Some(portal),
                    }),
                    &mut NoopCowResolver,
                ),
                carrick_el1_abi::Action::Forward
            );
            assert!(
                mailbox_a.claim_request().is_none(),
                "contended root cannot publish an unauthenticated request"
            );
            let OwnerFaultSupplyOutcome::Wait(wait) = supply.outcome() else {
                panic!(
                    "host-born mailbox fault erased Busy instead of waiting on sibling root owner: {:?}",
                    supply.outcome()
                );
            };
            assert_eq!(wait.cause(), carrick_el1_abi::PortalWaitCause::Reservations);
            assert_eq!(wait.handle(), handle);
            drop(held_root);
            assert_eq!(
                crate::cow_resolver::park_fault_owner_wait(
                    fixture.zone,
                    &fixture.task,
                    &counters,
                    fixture.slot,
                    &mut cpu,
                    &crate::sched::HardwareUserWord,
                    &mut frame,
                    wait,
                ),
                None,
                "release before enrollment must retry immediately without parking"
            );
        } else {
            let (locked_tx, locked_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let (released_tx, released_rx) = std::sync::mpsc::channel();
            struct ReleaseSiblingOnDrop(Option<std::sync::mpsc::Sender<()>>);
            impl Drop for ReleaseSiblingOnDrop {
                fn drop(&mut self) {
                    if let Some(tx) = self.0.take() {
                        let _ = tx.send(());
                    }
                }
            }
            let table = fixture.region.table();
            let zone = fixture.zone;
            std::thread::scope(|scope| {
                let mut release_guard = ReleaseSiblingOnDrop(Some(release_tx));
                let sibling_thread = scope.spawn(move || {
                    let lock_result = table
                        .lock_in(
                            crate::sched::object_wait::space_access(zone, sibling_slot),
                            index.index(),
                            handle.mm(),
                            u32::from(sibling_slot.raw()),
                        )
                        .map_err(|err| format!("{err:?}"));
                    let held_root = match lock_result {
                        Ok(guard) => {
                            let _ = locked_tx.send(Ok(()));
                            guard
                        }
                        Err(err) => {
                            let _ = locked_tx.send(Err(err));
                            return;
                        }
                    };
                    let wait_res = release_rx.recv_timeout(std::time::Duration::from_secs(5));
                    drop(held_root);
                    let _ = released_tx.send(wait_res);
                });
                locked_rx
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .expect("timed out waiting for sibling thread to lock reservation root")
                    .expect("sibling thread failed to lock reservation root");
                let supply = OwnerFaultSupply::new(portal).with_handle(handle);
                assert_eq!(
                    carrick_el1::fault::dispatch_fault_with_prepared(
                        &mut frame,
                        &counters,
                        core::slice::from_ref(&fixture.task),
                        access,
                        crate::cow_resolver::native_fault_supply(
                            false,
                            GrantMailboxes::own(&mailbox_a),
                            &supply,
                        ),
                        Some(PreparedFaultPath {
                            residency: &residency,
                            resolver: &mut SelectionWords(&words),
                            roots: Some(fixture.region.table()),
                            file_slots: Some(portal),
                        }),
                        &mut NoopCowResolver,
                    ),
                    carrick_el1_abi::Action::Forward
                );
                assert!(
                    mailbox_a.claim_request().is_none(),
                    "contended root cannot publish an unauthenticated request"
                );
                let OwnerFaultSupplyOutcome::Wait(wait) = supply.outcome() else {
                    panic!(
                        "host-born mailbox fault erased Busy instead of waiting on sibling root owner: {:?}",
                        supply.outcome()
                    );
                };
                assert_eq!(wait.cause(), carrick_el1_abi::PortalWaitCause::Reservations);
                assert_eq!(wait.handle(), handle);
                fixture.task.linux.mark_pending_host_work();
                assert_eq!(
                    crate::cow_resolver::park_fault_owner_wait(
                        fixture.zone,
                        &fixture.task,
                        &counters,
                        fixture.slot,
                        &mut cpu,
                        &crate::sched::HardwareUserWord,
                        &mut frame,
                        wait,
                    ),
                    Some(carrick_el1_abi::Action::Idle)
                );
                assert!(fixture.task.linux.take_host_work_doorbell().is_some());
                assert_eq!(fixture.zone.slot(fixture.slot).current(), None);
                assert_eq!(fixture.zone.slot(fixture.slot).queued(), 0);
                release_guard
                    .0
                    .take()
                    .unwrap()
                    .send(())
                    .expect("sibling thread exited before release signal");
                released_rx
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .expect("timed out waiting for sibling thread to release reservation root")
                    .expect("sibling thread timed out waiting for fault waiter to park");
                sibling_thread.join().unwrap();
            });
            assert_eq!(
                fixture.zone.slot(fixture.slot).queued(),
                1,
                "sibling root release must wake the parked fault waiter onto its slot"
            );
            assert_eq!(fixture.task.service_notice.take().unwrap(), None);
            let mut handoff = None;
            let mut prod_cpu = ProductionResumeCpu {
                inner: cpu,
                zone: fixture.zone,
                task: &fixture.task,
                service: &mut service,
            };
            let mut zone = crate::dispatch::Zone {
                tables: fixture.zone,
                cpu: &mut prod_cpu,
                user: &crate::sched::HardwareUserWord,
            };
            assert_eq!(
                crate::dispatch::native_scheduler(
                    &mut zone,
                    &fixture.task,
                    &counters,
                    fixture.slot,
                    &mut handoff,
                )
                .idle_entry(&mut frame, 0),
                carrick_el1_abi::Action::Served
            );
            cpu = prod_cpu.inner;
            assert_eq!(cpu.wfis, 0);
            let record = fixture.zone.slot(fixture.slot).current().unwrap();
            assert!(
                registry()
                    .for_record(fixture.zone, fixture.zone.record_ref(record))
                    .is_none(),
                "host-born fault wait resumes before any NativeProcessRuntime registration"
            );
            assert!(
                !fixture.zone.record(record).has_object_operation(),
                "production resume custody must consume the metadata operation token"
            );
            assert_eq!(frame.elr, 0x401234, "resume exact fault PC");
            assert_eq!(frame.x[3], 0x7abc, "resume exact fault registers");
            assert_eq!(
                fixture.zone.release_current(
                    fixture.slot,
                    record,
                    &carrick_sched_core::ShortLockSpin,
                ),
                carrick_sched_core::CurrentRelease::Released
            );
        }
    }

    // Retry after sibling B releases the reservation root lock: thread A's
    // mailbox now receives the authenticated FrameGrantRequest for the block.
    let retry_supply = OwnerFaultSupply::new(portal).with_handle(handle);
    let mut retry_frame = carrick_el1_abi::TrapFrame {
        esr: 0x92000046,
        far: VA + 8,
        elr: 0x401234,
        ..Default::default()
    };
    assert_eq!(
        carrick_el1::fault::dispatch_fault_with_prepared(
            &mut retry_frame,
            &counters,
            core::slice::from_ref(&fixture.task),
            access,
            crate::cow_resolver::native_fault_supply(
                false,
                GrantMailboxes::own(&mailbox_a),
                &retry_supply,
            ),
            Some(PreparedFaultPath {
                residency: &residency,
                resolver: &mut SelectionWords(&words),
                roots: Some(fixture.region.table()),
                file_slots: Some(portal),
            }),
            &mut NoopCowResolver,
        ),
        carrick_el1_abi::Action::Forward
    );
    assert_eq!(retry_supply.outcome(), OwnerFaultSupplyOutcome::Unavailable);
    let request = mailbox_a
        .claim_request()
        .expect("uncontended retry must publish an authenticated frame grant request");
    assert_eq!(request.mm_key, handle.mm().raw());
    assert_eq!(request.fault_va, VA + 8);
    assert!(mailbox_a.complete_resolved_owner_fault(request));

    // 2. Native owner venue (`native = true`): sibling B holds the MM editor
    // while preparing publication; thread A waits on `PortalWaitCause::Editor`.
    let editor = access
        .try_begin_edit(index, handle.mm().raw(), NonZeroU64::new(2).unwrap())
        .unwrap();
    let supply = OwnerFaultSupply::new(portal).with_handle(handle);
    let mut frame = carrick_el1_abi::TrapFrame {
        esr: 0x92000046,
        far: VA + 8,
        ..Default::default()
    };
    assert_eq!(
        carrick_el1::fault::dispatch_fault_with_prepared(
            &mut frame,
            &counters,
            core::slice::from_ref(&fixture.task),
            access,
            crate::cow_resolver::native_fault_supply(
                true,
                GrantMailboxes::own(&mailbox_a),
                &supply,
            ),
            Some(PreparedFaultPath {
                residency: &residency,
                resolver: &mut SelectionWords(&words),
                roots: Some(fixture.region.table()),
                file_slots: Some(portal),
            }),
            &mut NoopCowResolver,
        ),
        carrick_el1_abi::Action::Forward
    );
    let OwnerFaultSupplyOutcome::Wait(wait) = supply.outcome() else {
        panic!(
            "valid shared-MM write lost sibling publication: {:?}",
            supply.outcome()
        );
    };
    assert_eq!(wait.cause(), carrick_el1_abi::PortalWaitCause::Editor);
    assert_eq!(wait.handle(), handle);
    let mut saved = Aarch64ParkedContext::ZERO;
    crate::sched::ThreadCpu::save(&mut cpu, &frame, &mut saved);
    let result = with_process_entry(
        BornInZoneSource {
            zone: fixture.zone,
            slot: fixture.slot,
        },
        &fixture.task,
        &saved.native,
        fixture_ttbr0(fixture),
        fixture.page,
        fixture.control,
        &mut service,
        |entry| {
            entry
                .begin_owner_service_wait(
                    ServiceOperation::Fault(carrick_guest_arch::FaultInfo {
                        address: UserVa::new(frame.far),
                        access: carrick_guest_arch::Access::Write,
                        present: false,
                    }),
                    wait,
                )
                .unwrap()
        },
    )
    .unwrap();
    assert!(matches!(result, NativeResume::Left(None)));
    assert_eq!(fixture.task.service_notice.take().unwrap(), None);
    crate::dispatch::native_service_idle(fixture.zone, fixture.slot, &mut cpu);
    drop(editor);
    let mut handoff = None;
    let mut prod_cpu = ProductionResumeCpu {
        inner: cpu,
        zone: fixture.zone,
        task: &fixture.task,
        service: &mut service,
    };
    let mut zone = crate::dispatch::Zone {
        tables: fixture.zone,
        cpu: &mut prod_cpu,
        user: &crate::sched::HardwareUserWord,
    };
    assert_eq!(
        crate::dispatch::native_scheduler(
            &mut zone,
            &fixture.task,
            &counters,
            fixture.slot,
            &mut handoff,
        )
        .idle_entry(&mut frame, 0),
        carrick_el1_abi::Action::Served
    );
    let record = fixture.zone.slot(fixture.slot).current().unwrap();
    assert!(
        registry()
            .for_record(fixture.zone, fixture.zone.record_ref(record))
            .is_some()
    );
    assert!(
        !fixture.zone.record(record).has_object_operation(),
        "production resume custody must consume the native fault wait metadata token"
    );
    assert!(
        !registry().signal_checkpoint_needed(fixture.zone, fixture.zone.record_ref(record)),
        "sibling contention wait must never manufacture SIGSEGV"
    );
    assert_eq!(fixture.page.claimed_count(), 0);
}

struct ProductionResumeCpu<'a, X: ForkStockCrossing> {
    inner: crate::sched::FakeCpu,
    zone: &'static ZoneTables<Aarch64ParkedContext>,
    task: &'static CurrentTask,
    service: &'a mut Aarch64NativeProcessService<'static, X>,
}

impl<X: ForkStockCrossing> crate::sched::ThreadCpu for ProductionResumeCpu<'_, X> {
    fn save(&mut self, frame: &carrick_el1_abi::TrapFrame, ctx: &mut Aarch64ParkedContext) {
        self.inner.save(frame, ctx);
    }

    fn load(&mut self, frame: &mut carrick_el1_abi::TrapFrame, ctx: &Aarch64ParkedContext) {
        self.inner.load(frame, ctx);
    }

    fn resume_lifecycle(
        &mut self,
        _: &ZoneTables<Aarch64ParkedContext>,
        _: &CurrentTask,
        slot: SlotId,
        record: carrick_el1_abi::RecordId,
    ) -> crate::sched::ResumeAction {
        crate::aarch64_process::resume_production_with_service(
            self.zone,
            self.task,
            slot,
            record,
            self.service,
        )
    }

    fn set_translation(&mut self, a: u64, b: u64) {
        self.inner.set_translation(a, b);
    }

    fn invalidate_asid(&mut self, root: u64) {
        self.inner.invalidate_asid(root);
    }

    fn now(&self) -> u64 {
        self.inner.now()
    }

    fn freq(&self) -> u64 {
        self.inner.freq()
    }

    fn set_timer(&mut self, deadline: Option<u64>) {
        self.inner.set_timer(deadline);
    }

    fn send_sgi(&mut self, route: u64) {
        self.inner.send_sgi(route);
    }

    fn ack_irq(&mut self) -> u32 {
        self.inner.ack_irq()
    }

    fn end_irq(&mut self, intid: u32) {
        self.inner.end_irq(intid);
    }

    fn wait_for_interrupt(&mut self) {
        self.inner.wait_for_interrupt();
    }

    fn spin(&mut self) {
        self.inner.spin();
    }

    fn own_sgi_target(&self) -> u64 {
        self.inner.own_sgi_target()
    }
}

#[test]
fn arm_host_born_fault_waiter_cancels_cleanly_on_exit_group_kill_and_sibling_exec() {
    use crate::native_process_runtime::NativeResume;
    use carrick_core_abi::service::{
        EXEC_PAYLOAD_HEADER_BYTES, ExecAdoptionReceipt, ExecCall, ExecSuccessorBacking,
        ExecSuccessorEntry, ExecSuccessorManifest, ServiceCell, encode_exec_payload_header,
    };
    use carrick_el1::fault::{GrantMailboxes, NoopCowResolver, PreparedFaultPath};
    use carrick_sched_core::object_wait::ObjectWaitKey;
    use core::num::NonZeroU16;

    #[derive(Clone, Copy, Debug)]
    enum CancelTrigger {
        ExitGroup,
        Kill,
        SiblingExec,
    }

    #[derive(Clone, Copy, Debug)]
    enum CancelMode {
        WhileParked,
        QueuedProductionResume,
        QueuedHostCancelSweep,
    }

    for (trigger_idx, trigger) in [
        CancelTrigger::ExitGroup,
        CancelTrigger::Kill,
        CancelTrigger::SiblingExec,
    ]
    .into_iter()
    .enumerate()
    {
        for (mode_idx, mode) in [
            CancelMode::WhileParked,
            CancelMode::QueuedProductionResume,
            CancelMode::QueuedHostCancelSweep,
        ]
        .into_iter()
        .enumerate()
        {
            let fixture = Box::leak(Box::new(Fixture::new(0x10000, asid(1))));
            fixture.zone.spaces.set_idle_ttbr(0x30000);
            let mut service = fixture.process_service();
            fixture
                .enter(
                    fixture.control,
                    fixture_ttbr0(fixture),
                    &mut service,
                    |_| (),
                )
                .unwrap();
            let portal = fixture.region.portal_slots();
            assert!(portal.bind_carrier(NonZeroU64::MIN));

            let mm_key = fixture.task.mm.key.load(Ordering::Acquire);
            let waiter_slot = SlotId::new(1);
            fixture.zone.drive(waiter_slot, 1);
            fixture.zone.publish_slot(waiter_slot, 1, Some(1), 2);
            fixture.zone.enter_guest(waiter_slot);
            fixture.zone.install_space(waiter_slot, mm_key).unwrap();
            let waiter_control = host_born_sibling(fixture, 42);
            let birth = waiter_control.host_birth_identity().unwrap();
            run_as(fixture, 42, 12, 102, waiter_control);

            let handle = crate::cow_resolver::admitted_fault_mm_handle(
                fixture.zone,
                fixture.region.table(),
                NonZeroU64::MIN,
                waiter_slot,
                &fixture.task,
            )
            .expect("host-born sibling must obtain admitted MM handle");
            let leader_access = crate::sched::object_wait::space_access(fixture.zone, fixture.slot);
            let waiter_access = crate::sched::object_wait::space_access(fixture.zone, waiter_slot);
            let index = waiter_access.find(handle.mm().raw()).unwrap();
            let residency = carrick_el1::cow::test_support::residency_table();
            let words = fixture.tables.live(&fixture.maintenance);
            let counters = carrick_el1_abi::Counters::new();

            let held_root = fixture
                .region
                .table()
                .lock_in(
                    leader_access,
                    index.index(),
                    handle.mm(),
                    u32::from(fixture.slot.raw()),
                )
                .unwrap();

            let mailbox = carrick_el1_abi::FrameGrantMailbox::new();
            let supply = OwnerFaultSupply::new(portal).with_handle(handle);
            let mut waiter_frame = carrick_el1_abi::TrapFrame {
                esr: 0x92000046,
                far: VA + 8,
                elr: 0x401234,
                ..Default::default()
            };
            waiter_frame.x[3] = 0x7abc;
            assert_eq!(
                carrick_el1::fault::dispatch_fault_with_prepared(
                    &mut waiter_frame,
                    &counters,
                    core::slice::from_ref(&fixture.task),
                    waiter_access,
                    crate::cow_resolver::native_fault_supply(
                        false,
                        GrantMailboxes::own(&mailbox),
                        &supply,
                    ),
                    Some(PreparedFaultPath {
                        residency: &residency,
                        resolver: &mut SelectionWords(&words),
                        roots: Some(fixture.region.table()),
                        file_slots: Some(portal),
                    }),
                    &mut NoopCowResolver,
                ),
                carrick_el1_abi::Action::Forward
            );
            let OwnerFaultSupplyOutcome::Wait(wait) = supply.outcome() else {
                panic!(
                    "expected reservation wait for {trigger:?}/{mode:?}: {:?}",
                    supply.outcome()
                );
            };
            let mut waiter_cpu = crate::sched::FakeCpu::default();
            fixture.task.linux.mark_pending_host_work();
            assert_eq!(
                crate::cow_resolver::park_fault_owner_wait(
                    fixture.zone,
                    &fixture.task,
                    &counters,
                    waiter_slot,
                    &mut waiter_cpu,
                    &crate::sched::HardwareUserWord,
                    &mut waiter_frame,
                    wait,
                ),
                Some(carrick_el1_abi::Action::Idle)
            );
            assert!(fixture.task.linux.take_host_work_doorbell().is_some());
            let waiter_record_id = fixture
                .zone
                .slot(waiter_slot)
                .host_record()
                .expect("park_fault_owner_wait must allocate and park the slot's home record");
            let waiter_record = fixture.zone.record_ref(waiter_record_id);
            waiter_control.bind_zone_record(waiter_record);
            assert!(fixture.zone.record(waiter_record.id).has_object_operation());
            assert!(
                !fixture
                    .zone
                    .record(waiter_record.id)
                    .has_adapter_operation(),
                "fault owner wait uses a metadata receipt, not an adapter IPC operation"
            );
            let census = fixture
                .zone
                .record(waiter_record.id)
                .object_wait_census()
                .expect("parked fault waiter must be enrolled in object wait queue");
            assert_ne!(census.queue, 0);
            assert_eq!(census.operation, u64::MAX);

            // Switch to the leader on slot 0 and drive the production exit_group,
            // fatal signal (SIGKILL), or sibling execve closing path.
            run_as_leader(fixture);
            let mut exec_successor_mm = None;
            match trigger {
                CancelTrigger::ExitGroup => {
                    let mut exit_frame = carrick_el1_abi::TrapFrame::default();
                    exit_frame.x[0] = 7;
                    exit_frame.x[8] = 94;
                    assert_eq!(
                        arm_call(fixture, fixture.control, &mut service, &mut exit_frame).unwrap(),
                        carrick_personality_linux::dispatch::CompletionRoute::Suspended
                    );
                }
                CancelTrigger::Kill => {
                    let saved = Aarch64ParkedContext::ZERO;
                    with_process_entry(
                        BornInZoneSource {
                            zone: fixture.zone,
                            slot: fixture.slot,
                        },
                        &fixture.task,
                        &saved.native,
                        fixture_ttbr0(fixture),
                        fixture.page,
                        fixture.control,
                        &mut service,
                        |entry| {
                            assert!(matches!(
                                entry
                                    .exit_with_signal(
                                        carrick_signal_core::policy::Signal::from_number(9)
                                            .unwrap(),
                                    )
                                    .unwrap(),
                                LifecycleOutcome::Transferred { .. }
                            ));
                        },
                    )
                    .unwrap();
                }
                CancelTrigger::SiblingExec => {
                    let path = b"/bin/sh";
                    let mut payload = vec![0; EXEC_PAYLOAD_HEADER_BYTES];
                    payload.extend_from_slice(path);
                    payload.push(0);
                    encode_exec_payload_header(
                        &mut payload,
                        ExecCall::Execve,
                        path.len() + 1,
                        0,
                        0,
                    )
                    .unwrap();
                    let saved = Aarch64ParkedContext::ZERO;
                    let result = with_process_entry(
                        BornInZoneSource {
                            zone: fixture.zone,
                            slot: fixture.slot,
                        },
                        &fixture.task,
                        &saved.native,
                        fixture_ttbr0(fixture),
                        fixture.page,
                        fixture.control,
                        &mut service,
                        |entry| {
                            let res = entry.begin_exec_service(payload.into_boxed_slice());
                            assert!(entry.take_handoff_receipt().is_some());
                            res
                        },
                    )
                    .unwrap();
                    assert!(matches!(result, Ok(NativeResume::Left(None))));
                    let mut leader_cpu = crate::sched::FakeCpu::default();
                    let selector = fixture.task.service_notice.take().unwrap().unwrap();
                    crate::dispatch::native_service_idle(
                        fixture.zone,
                        fixture.slot,
                        &mut leader_cpu,
                    );
                    let key = ObjectWaitKey::native_service(selector.record).unwrap();
                    let queue = fixture
                        .zone
                        .object_wait(key, &carrick_sched_core::ShortLockSpin)
                        .unwrap();
                    let member = fixture.zone.record(selector.record.id).identity();
                    let ticket = unsafe {
                        ServiceCell::claim_notice(
                            &fixture.control.service,
                            selector,
                            NonZeroU64::MIN,
                            member,
                        )
                    }
                    .unwrap();
                    let request = ticket.request();
                    let manifest_address = ticket.reply_address().unwrap();
                    let manifest =
                        unsafe { &mut *(manifest_address.raw() as *mut ExecSuccessorManifest) };
                    let (successor_mm, _) = manifest.proposal(request.identity).unwrap();
                    let receipt_raw = 200 + (trigger_idx * 10 + mode_idx) as u64;
                    let receipt =
                        ExecAdoptionReceipt::checked(NonZeroU64::new(receipt_raw).unwrap())
                            .unwrap();
                    let successor_asid = carrick_guest_arch::Asid::from_registry_allocation(
                        NonZeroU16::new(u16::try_from(receipt_raw + 12).unwrap()).unwrap(),
                    );
                    let successor_root = RootGpa::page_aligned(FrameGpa::new(0x90_0000)).unwrap();
                    *manifest = manifest
                        .seal(
                            request.identity,
                            receipt,
                            ExecSuccessorBacking {
                                root: successor_root,
                                asid: successor_asid,
                                asid_generation: NonZeroU64::new(receipt_raw + 14).unwrap(),
                            },
                            ExecSuccessorEntry {
                                entry: UserVa::new(0x40_0000),
                                stack_pointer: UserVa::new(0x7fff_f000),
                            },
                        )
                        .unwrap();
                    let successor_index = fixture.zone.spaces.find(successor_mm.raw()).unwrap();
                    let ttbr =
                        (u64::from(successor_asid.raw()) << 48) | successor_root.address().raw();
                    assert!(fixture.zone.spaces.bind_initial_root(
                        successor_index,
                        successor_mm.raw(),
                        ttbr,
                        ttbr,
                    ));
                    assert!(
                        ticket
                            .publish_exec_prepared(receipt, (), |_, ()| {})
                            .is_ok()
                    );
                    let mut effects = carrick_sched_core::WakeEffects::default();
                    queue.notify_object(fixture.slot, &mut effects).unwrap();
                    drop(queue);
                    NativeProcessService::wake_effects(&mut service, effects);
                    exec_successor_mm = Some(successor_mm);

                    let _ = fixture.task.linux.take_host_work_doorbell();
                    let mut leader_frame = carrick_el1_abi::TrapFrame::default();
                    let mut handoff = None;
                    let mut prod_cpu = ProductionResumeCpu {
                        inner: leader_cpu,
                        zone: fixture.zone,
                        task: &fixture.task,
                        service: &mut service,
                    };
                    let mut zone = crate::dispatch::Zone {
                        tables: fixture.zone,
                        cpu: &mut prod_cpu,
                        user: &crate::sched::HardwareUserWord,
                    };
                    assert_eq!(
                        crate::dispatch::native_scheduler(
                            &mut zone,
                            &fixture.task,
                            &counters,
                            fixture.slot,
                            &mut handoff,
                        )
                        .idle_entry(&mut leader_frame, 0),
                        carrick_el1_abi::Action::Idle,
                        "exec closing must suspend the leader while the fault waiter sibling is live"
                    );
                }
            }

            assert!(
                fixture.page.host_birth_requested(birth),
                "{trigger:?}/{mode:?} must request cancellation of the host-born fault waiter"
            );

            run_as(fixture, 42, 12, 102, waiter_control);
            let live_before_resume = fixture.page.live();
            let mut resume_frame = carrick_el1_abi::TrapFrame::default();
            let mut handoff = None;
            let mut waiter_service = Aarch64NativeProcessService::with_crossing(
                &fixture.task,
                waiter_slot,
                fixture.zone,
                fixture.region.table(),
                NonZeroU64::MIN,
                TestStockCrossing::new(&[]),
            );
            let mut prod_cpu = ProductionResumeCpu {
                inner: waiter_cpu,
                zone: fixture.zone,
                task: &fixture.task,
                service: &mut waiter_service,
            };
            let mut zone = crate::dispatch::Zone {
                tables: fixture.zone,
                cpu: &mut prod_cpu,
                user: &crate::sched::HardwareUserWord,
            };
            match mode {
                CancelMode::WhileParked => {
                    fixture.zone.unhome(waiter_slot, waiter_record.id, 2);
                    assert_eq!(
                        fixture.zone.claim_for_host(
                            waiter_record,
                            None,
                            carrick_el1_abi::Handback::Cancelled,
                            &carrick_sched_core::ShortLockSpin,
                        ),
                        carrick_sched_core::HostClaim::Claimed
                    );
                    fixture.zone.free_record(waiter_record.id);
                    drop(held_root);
                    assert_eq!(
                        crate::dispatch::native_scheduler(
                            &mut zone,
                            &fixture.task,
                            &counters,
                            waiter_slot,
                            &mut handoff,
                        )
                        .run_ready(&mut resume_frame),
                        None,
                        "{trigger:?}/{mode:?} must never reload a host-claimed fault waiter"
                    );
                }
                CancelMode::QueuedProductionResume => {
                    drop(held_root);
                    assert_eq!(
                        fixture.zone.slot(waiter_slot).queued(),
                        1,
                        "owner publication wakes waiter onto slot before {trigger:?} retirement"
                    );
                    let _ = fixture.task.linux.take_host_work_doorbell();
                    assert_eq!(
                        crate::dispatch::native_scheduler(
                            &mut zone,
                            &fixture.task,
                            &counters,
                            waiter_slot,
                            &mut handoff,
                        )
                        .idle_entry(&mut resume_frame, 0),
                        carrick_el1_abi::Action::Idle,
                        "{trigger:?}/{mode:?} must retire the fault waiter via production resume custody"
                    );
                    assert!(
                        fixture.task.linux.take_host_work_doorbell().is_some(),
                        "{trigger:?}/{mode:?} production resume retirement must ring host-work doorbell"
                    );
                }
                CancelMode::QueuedHostCancelSweep => {
                    drop(held_root);
                    assert_eq!(
                        fixture.zone.slot(waiter_slot).queued(),
                        1,
                        "owner publication wakes waiter onto slot before host cancel claim"
                    );
                    assert_eq!(
                        fixture.zone.claim_for_host(
                            waiter_record,
                            None,
                            carrick_el1_abi::Handback::Cancelled,
                            &carrick_sched_core::ShortLockSpin,
                        ),
                        carrick_sched_core::HostClaim::Claimed
                    );
                    assert!(fixture.zone.record(waiter_record.id).is_cancelled());
                    assert_eq!(fixture.zone.runnable_head(waiter_slot), None);
                    fixture.zone.free_record(waiter_record.id);
                    assert_eq!(
                        crate::dispatch::native_scheduler(
                            &mut zone,
                            &fixture.task,
                            &counters,
                            waiter_slot,
                            &mut handoff,
                        )
                        .run_ready(&mut resume_frame),
                        None,
                        "{trigger:?}/{mode:?} must never reload a swept cancelled fault waiter"
                    );
                }
            }
            assert_eq!(
                resume_frame.elr, 0,
                "{trigger:?}/{mode:?} must never restore the cancelled fault waiter's trap frame"
            );
            assert!(
                !fixture.zone.record(waiter_record.id).has_object_operation(),
                "{trigger:?}/{mode:?} must not leave a metadata operation token on the record"
            );
            assert!(
                fixture
                    .zone
                    .record(waiter_record.id)
                    .object_wait_census()
                    .is_none(),
                "{trigger:?}/{mode:?} must leave an empty object-wait census"
            );
            assert!(
                fixture.zone.live(waiter_record).is_none(),
                "{trigger:?}/{mode:?} must release the fault waiter's zone record"
            );
            assert_eq!(fixture.zone.slot(waiter_slot).current(), None);
            assert_eq!(fixture.zone.slot(waiter_slot).queued(), 0);
            fixture.zone.release_space(waiter_slot);

            assert!(live_before_resume >= 1, "the waiter retains a live unit");
            assert_eq!(
                fixture.page.live(),
                if matches!(mode, CancelMode::QueuedProductionResume) {
                    live_before_resume - 1
                } else {
                    live_before_resume
                },
                "only production resume consumes the waiter's unit in the zone"
            );
            carrick_core::terminal::reserve_host_thread_exit_membership(
                fixture.page,
                waiter_control,
            )
            .unwrap()
            .commit_zone_retirement(&carrick_core::lifecycle::RegistryWriteHeld::for_test())
            .publish();
            assert_eq!(
                fixture.page.live(),
                live_before_resume - 1,
                "native resume and host retirement together consume exactly one unit"
            );
            fixture
                .page
                .publish_exact_host_retirement(waiter_control, birth.retirement());
            run_as_leader(fixture);
            match trigger {
                CancelTrigger::ExitGroup | CancelTrigger::Kill => {
                    assert!(matches!(
                        wake_closing_root(fixture, &mut service),
                        crate::sched::ResumeAction::Left
                    ));
                    assert_eq!(service.crossing.root_exits.load(Ordering::Acquire), 1);
                }
                CancelTrigger::SiblingExec => {
                    let (mm, address) = fixture.page.exit_wait().unwrap();
                    let guard = fixture
                        .zone
                        .lock(
                            ZoneTables::<Aarch64ParkedContext>::bucket_of_with_context(
                                mm.raw(),
                                address,
                            ),
                            &carrick_sched_core::ShortLockSpin,
                        )
                        .unwrap();
                    assert_eq!(
                        fixture.zone.wake_host(
                            &guard,
                            mm.raw(),
                            address,
                            u32::MAX,
                            u32::MAX,
                            true,
                            &mut |_| panic!("exec leader must be placed in guest"),
                            &mut |_| {},
                        ),
                        1
                    );
                    drop(guard);
                    let _ = fixture.task.linux.take_host_work_doorbell();
                    let mut exec_frame = carrick_el1_abi::TrapFrame::default();
                    let mut handoff = None;
                    let mut prod_cpu = ProductionResumeCpu {
                        inner: crate::sched::FakeCpu::default(),
                        zone: fixture.zone,
                        task: &fixture.task,
                        service: &mut service,
                    };
                    let mut zone = crate::dispatch::Zone {
                        tables: fixture.zone,
                        cpu: &mut prod_cpu,
                        user: &crate::sched::HardwareUserWord,
                    };
                    assert_eq!(
                        crate::dispatch::native_scheduler(
                            &mut zone,
                            &fixture.task,
                            &counters,
                            fixture.slot,
                            &mut handoff,
                        )
                        .idle_entry(&mut exec_frame, 0),
                        carrick_el1_abi::Action::Idle
                    );
                    assert!(
                        service.crossing.exec_adopted.load(Ordering::Acquire),
                        "exec leader must adopt successor after cancelled fault waiter retires"
                    );
                    assert!(
                        fixture
                            .zone
                            .spaces
                            .is_open(exec_successor_mm.unwrap().raw()),
                        "exec leader must open successor address space after cancelled fault waiter retires"
                    );
                }
            }
        }
    }
}

#[test]
fn arm_clone_tid_output_waits_for_sibling_in_flight_grant_publication() {
    use crate::mm_portal::{GuestVa, MmError, SelectionVenues, TransferIntent, TransferStep};
    use carrick_el1::fault::{NoopCowResolver, NoopPreparedResolver};
    use carrick_mmu_core::aarch64::descriptor_txn::DescriptorRefusal;
    use core::sync::atomic::AtomicI32;

    let fixture = Box::leak(Box::new(Fixture::with_page(
        0x10000,
        asid(1),
        5,
        Box::leak(Box::new(ThreadLifecyclePage::with_hatches(
            carrick_el1_abi::LifecycleHatches::ON,
        ))),
    )));
    // `VA + 4096` is reserved in the VMA tree (`VA..VA + 8192`), but its
    // Stage-1 leaf is not yet resident while sibling B's grant is in flight.
    fixture.tables.words[1536 + 1].store(0, Ordering::Relaxed);
    fixture.zone.spaces.set_idle_ttbr(0x30000);
    assert!(fixture.control.publish_visible_tid(41));
    let child_control = Box::leak(Box::new(ThreadControlSlot::new()));
    let stocked_entry = fixture
        .page
        .stock(
            0,
            carrick_el1_abi::EntryIdentity {
                tid: 43,
                visible_tid: 43,
                thread_serial: 103,
                birth: carrick_core_abi::entry::BirthSerial::of_task(
                    carrick_sched_core::process::TaskSerial::from_raw_u64(11).unwrap(),
                ),
                uid_credit: 1,
            },
        )
        .unwrap();
    fixture
        .page
        .bind_control_address(stocked_entry, child_control as *const _ as u64)
        .unwrap();
    let mut service = fixture.process_service();
    fixture
        .enter(
            fixture.control,
            fixture_ttbr0(fixture),
            &mut service,
            |_| (),
        )
        .unwrap();
    let portal_slots = fixture.region.portal_slots();
    assert!(portal_slots.bind_carrier(NonZeroU64::MIN));

    let mm_key = fixture.task.mm.key.load(Ordering::Acquire);
    let sibling_slot = SlotId::new(1);
    fixture.zone.drive(sibling_slot, 1);
    fixture.zone.publish_slot(sibling_slot, 1, Some(1), 2);
    fixture.zone.enter_guest(sibling_slot);
    fixture.zone.install_space(sibling_slot, mm_key).unwrap();
    let _sibling_control = host_born_sibling(fixture, 42);
    run_as_leader(fixture);

    let handle = crate::cow_resolver::admitted_fault_mm_handle(
        fixture.zone,
        fixture.region.table(),
        NonZeroU64::MIN,
        fixture.slot,
        &fixture.task,
    )
    .expect("leader must obtain admitted MM handle");
    let mm_portal = crate::aarch64_process::Portal::for_zone(
        NonZeroU64::MIN,
        fixture.region.table(),
        fixture.zone,
    );

    let tid_words = [AtomicI32::new(11), AtomicI32::new(22)];
    let parent_tid_host_addr = tid_words[0].as_ptr() as u64;
    let child_tid_host_addr = tid_words[1].as_ptr() as u64;
    let non_resident_tid_va = VA + 4096;
    let child_stack = VA + 0x1000;
    // CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
    // CLONE_SYSVSEM | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID | CLONE_CHILD_SETTID
    let clone_flags: u64 = 0x0135_0f00;
    let mut clone_frame = carrick_el1_abi::TrapFrame {
        elr: 0x402000,
        ..Default::default()
    };
    clone_frame.x[0] = clone_flags;
    clone_frame.x[1] = child_stack;
    clone_frame.x[2] = parent_tid_host_addr;
    clone_frame.x[3] = 0;
    clone_frame.x[4] = child_tid_host_addr;
    clone_frame.x[8] = 220; // SYS_clone

    // 1. Before the 2 MiB stack block page `VA + 4096` is resident in Stage-1,
    // EL1 `serve_clone` faults in `TidOutput::capture` and forwards `clone` to
    // the host.
    crate::file::SIMULATE_COPY_FAULT.with(|fault| fault.store(true, Ordering::Relaxed));
    let forwarded = arm_call(fixture, fixture.control, &mut service, &mut clone_frame);
    crate::file::SIMULATE_COPY_FAULT.with(|fault| fault.store(false, Ordering::Relaxed));
    assert_eq!(
        forwarded.unwrap(),
        carrick_personality_linux::dispatch::CompletionRoute::Forward,
        "non-resident clone TID output in a valid VMA must forward to the host owner path"
    );

    // 2. On the host, `CloneTidOutputTransaction::capture` reads the TID output
    // address through `MmPortal::select`. When sibling B acquires the
    // reservation root lock while thread A's transfer is between `authorize`
    // and `Supply` planning (the exact window at `MmPortal::select` line 648),
    // `select` must return `Err(MmError::Wait(PortalOwnerWait { cause: Reservations, .. }))`
    // rather than `Err(MmError::Busy)` or `EFAULT`.
    let sibling_access = crate::sched::object_wait::space_access(fixture.zone, sibling_slot);
    let index = sibling_access.find(handle.mm().raw()).unwrap();
    let residency = Box::leak(crate::mm_portal::test_support::residency());
    let words = fixture.tables.live(&fixture.maintenance);
    let transfer = mm_portal
        .begin(
            handle,
            GuestVa::new(non_resident_tid_va),
            core::mem::size_of::<i32>() as u64,
            TransferIntent::UserRead,
            0,
        )
        .unwrap();

    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (locked_tx, locked_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (released_tx, released_rx) = std::sync::mpsc::channel();
    struct ReleaseSiblingOnDrop(Option<std::sync::mpsc::Sender<()>>);
    impl Drop for ReleaseSiblingOnDrop {
        fn drop(&mut self) {
            if let Some(tx) = self.0.take() {
                let _ = tx.send(());
            }
        }
    }
    struct LockRootOnTranslate<'a, W> {
        inner: &'a W,
        ready_tx: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>>,
        locked_rx: std::sync::Mutex<Option<std::sync::mpsc::Receiver<Result<(), String>>>>,
    }
    impl<W: LiveDescriptorWords> LiveDescriptorWords for LockRootOnTranslate<'_, W> {
        fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
            let value = self.inner.load(pa)?;
            if value == 0
                && let Some(tx) = self.ready_tx.lock().unwrap().take()
            {
                let _ = tx.send(());
                if let Some(rx) = self.locked_rx.lock().unwrap().take() {
                    rx.recv_timeout(std::time::Duration::from_secs(5))
                        .expect("timed out waiting for sibling to lock root during clone transfer")
                        .expect("sibling failed to lock root during clone transfer");
                }
            }
            Ok(value)
        }
        fn compare_exchange(
            &self,
            pa: u64,
            current: u64,
            new: u64,
        ) -> Result<bool, DescriptorRefusal> {
            self.inner.compare_exchange(pa, current, new)
        }
        fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), DescriptorRefusal> {
            self.inner.store_unlinked(pa, value)
        }
        fn publish_barrier(&self) {
            self.inner.publish_barrier();
        }
        fn invalidate_range(&self, va: u64, len: u64) {
            self.inner.invalidate_range(va, len);
        }
    }

    let table = fixture.region.table();
    let zone = fixture.zone;
    let counters = carrick_el1_abi::Counters::new();
    let mut cpu = crate::sched::FakeCpu::default();
    std::thread::scope(|scope| {
        let mut release_guard = ReleaseSiblingOnDrop(Some(release_tx));
        let sibling_thread = scope.spawn(move || {
            if ready_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .is_err()
            {
                return;
            }
            let lock_result = table
                .lock_in(
                    crate::sched::object_wait::space_access(zone, sibling_slot),
                    index.index(),
                    handle.mm(),
                    u32::from(sibling_slot.raw()),
                )
                .map_err(|err| format!("{err:?}"));
            let held_root = match lock_result {
                Ok(guard) => {
                    let _ = locked_tx.send(Ok(()));
                    guard
                }
                Err(err) => {
                    let _ = locked_tx.send(Err(err));
                    return;
                }
            };
            let wait_res = release_rx.recv_timeout(std::time::Duration::from_secs(5));
            drop(held_root);
            let _ = released_tx.send(wait_res);
        });

        let hook_words = LockRootOnTranslate {
            inner: &words,
            ready_tx: std::sync::Mutex::new(Some(ready_tx)),
            locked_rx: std::sync::Mutex::new(Some(locked_rx)),
        };
        let step = mm_portal.select(
            &transfer,
            &hook_words,
            SelectionVenues {
                prepared: &mut NoopPreparedResolver,
                cow: &mut NoopCowResolver,
                residency,
                slot: u32::from(fixture.slot.raw()),
            },
        );
        let Err(MmError::Wait(wait)) = step else {
            panic!(
                "clone TID transfer must wait on sibling's in-flight grant reservation root instead of returning Busy/EFAULT: {step:?}"
            );
        };
        assert_eq!(wait.cause(), carrick_el1_abi::PortalWaitCause::Reservations);
        assert_eq!(wait.handle(), handle);

        fixture.task.linux.mark_pending_host_work();
        assert_eq!(
            crate::cow_resolver::park_fault_owner_wait(
                fixture.zone,
                &fixture.task,
                &counters,
                fixture.slot,
                &mut cpu,
                &crate::sched::HardwareUserWord,
                &mut clone_frame,
                wait,
            ),
            Some(carrick_el1_abi::Action::Idle)
        );
        assert!(fixture.task.linux.take_host_work_doorbell().is_some());
        assert_eq!(fixture.zone.slot(fixture.slot).current(), None);
        assert_eq!(fixture.zone.slot(fixture.slot).queued(), 0);

        // Sibling B finishes publishing the 2 MiB stack grant leaf and releases
        // the reservation root lock.
        fixture.tables.words[1536 + 1].store(
            (IPA + 4096) | crate::mm_portal::test_support::RW,
            Ordering::Release,
        );
        release_guard
            .0
            .take()
            .unwrap()
            .send(())
            .expect("sibling thread exited before release signal");
        released_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("timed out waiting for sibling thread to release reservation root")
            .expect("sibling thread timed out waiting for clone waiter to park");
        sibling_thread.join().unwrap();
    });

    assert_eq!(
        fixture.zone.slot(fixture.slot).queued(),
        1,
        "sibling grant publication must wake the parked clone thread onto its slot"
    );
    let mut handoff = None;
    let mut prod_cpu = ProductionResumeCpu {
        inner: cpu,
        zone: fixture.zone,
        task: &fixture.task,
        service: &mut service,
    };
    let mut zone_view = crate::dispatch::Zone {
        tables: fixture.zone,
        cpu: &mut prod_cpu,
        user: &crate::sched::HardwareUserWord,
    };
    assert_eq!(
        crate::dispatch::native_scheduler(
            &mut zone_view,
            &fixture.task,
            &counters,
            fixture.slot,
            &mut handoff,
        )
        .idle_entry(&mut clone_frame, 0),
        carrick_el1_abi::Action::Served
    );
    let record = fixture.zone.slot(fixture.slot).current().unwrap();
    assert!(!fixture.zone.record(record).has_object_operation());
    assert_eq!(
        fixture
            .zone
            .release_current(fixture.slot, record, &carrick_sched_core::ShortLockSpin,),
        carrick_sched_core::CurrentRelease::Released
    );
    fixture.zone.release_space(sibling_slot);

    // 3. Redispatching `clone` after sibling B's grant publication now selects
    // the resident page on the host portal AND completes in EL1, writing the
    // new child's visible TID to both `parent_tid_addr` and `child_tid_addr`.
    assert!(matches!(
        mm_portal.select(
            &transfer,
            &words,
            SelectionVenues {
                prepared: &mut NoopPreparedResolver,
                cow: &mut NoopCowResolver,
                residency,
                slot: u32::from(fixture.slot.raw()),
            },
        ),
        Ok(TransferStep::Selected(_))
    ));
    assert_eq!(
        arm_call(fixture, fixture.control, &mut service, &mut clone_frame).unwrap(),
        carrick_personality_linux::dispatch::CompletionRoute::WithWork,
        "redispatched clone must succeed once sibling grant publication is resident"
    );
    let child_visible_tid = i32::try_from(clone_frame.x[0] as i64)
        .expect("clone return value must be a positive visible TID");
    assert!(
        child_visible_tid > 0,
        "clone must not fail with EFAULT (-14): got {child_visible_tid}"
    );
    assert_eq!(tid_words[0].load(Ordering::Acquire), child_visible_tid);
    assert_eq!(tid_words[1].load(Ordering::Acquire), child_visible_tid);
}

/// #898: interleave reservation admission and first touch, as the signed
/// fixture does. Count published physical-supply selections, not mmap calls
/// or synthetic reservation-tree visits. Every selection is settled through
/// the production grant authenticator and descriptor executor before continuing.
#[test]
#[ignore = "tracks the open #898 service budget; un-ignored by the layer that completes the native supply path"]
fn anonymous_reservation_first_touch_service_budget() {
    let observations = [64, 256, 1024].map(|count| (count, reservation_supply_requests(count)));
    for &(count, requests) in &observations {
        eprintln!("anonymous-reservations count={count} backing_requests={requests}");
    }
    for pair in observations.windows(2) {
        let added = pair[1].0 - pair[0].0;
        let requests = pair[1].1.saturating_sub(pair[0].1);
        // Each supply requires at least one host exit. This is a necessary
        // lower-layer consequence of the signed <0.125 host-exit slope,
        // not a replacement for that full exit-population assertion.
        assert!(
            requests * 8 < added,
            "physical supply grows per reservation: {:?}; delta={requests}/{added}, required <1/8",
            observations,
        );
    }
}

// This venue also supports the existing prepared-stock adoption mechanism,
// so a repaired supplier can spend earlier stock without changing the witness.
struct ReservationSupplyMemory<'a> {
    tables: &'a crate::mm_portal::test_support::Tables,
    residency: &'a carrick_el1_abi::FrameGrantResidencyTable,
}
impl carrick_el1::memory::AnonymousBackingProbe for ReservationSupplyMemory<'_> {
    fn backing(
        &mut self,
        root: carrick_guest_arch::AddressSpaceRegister,
        va: UserVa,
        len: carrick_guest_arch::GuestLen,
    ) -> carrick_el1::memory::Stage1Backing {
        let maintenance = CallerInvalidatesAsid;
        FixtureMapping {
            words: &self.tables.live(&maintenance),
            residency: self.residency,
        }
        .backing(root, va, len)
    }
    fn stock_span(
        &mut self,
        mm: ReservationMm,
        va: UserVa,
    ) -> Option<carrick_guest_arch::UserRange> {
        let page = self.residency.lookup(mm.raw(), va.raw())?;
        carrick_guest_arch::UserRange::checked(
            UserVa::new(page.identity.semantic_base),
            carrick_guest_arch::GuestLen::new(page.identity.len),
        )
    }
}
impl carrick_el1::memory::AnonymousPermissionEditor for ReservationSupplyMemory<'_> {
    fn protect_and_invalidate(
        &mut self,
        root: carrick_guest_arch::AddressSpaceRegister,
        edit: carrick_mmu_core::aarch64::GuestPermissionEdit,
    ) -> Result<(), carrick_mmu_core::aarch64::GuestPermissionEditError> {
        assert_eq!(root.raw() & AARCH64_ROOT_ADDRESS_MASK, self.tables.base);
        // SAFETY: retained aligned atomic table arena, under the production
        // anonymous owner's exclusive editor. No hardware TLB exists here.
        unsafe {
            carrick_mmu_core::aarch64::protect_existing_el1_private_pages(
                self.tables.words.as_ptr().cast_mut(),
                self.tables.base,
                self.tables.words.len() * 8,
                None,
                edit,
            )
        }
        .map(|_| ())
    }
}
impl carrick_el1::memory::AnonymousRetirementEditor for ReservationSupplyMemory<'_> {
    fn retire_and_invalidate(
        &mut self,
        mm: ReservationMm,
        root: carrick_guest_arch::AddressSpaceRegister,
        va: UserVa,
        len: carrick_guest_arch::GuestLen,
    ) -> Result<(), carrick_mmu_core::aarch64::GuestRetirementError> {
        let maintenance = CallerInvalidatesAsid;
        FixtureMapping {
            words: &self.tables.live(&maintenance),
            residency: self.residency,
        }
        .retire_and_invalidate(mm, root, va, len)
    }
}
impl carrick_el1::fault::PreparedPageResolver for ReservationSupplyMemory<'_> {
    fn select_backing_window(
        &mut self,
        root: u64,
        window: carrick_el1_abi::PortalGrantWindow,
    ) -> Result<
        carrick_el1_abi::PortalGrantWindow,
        carrick_mmu_core::descriptor_refusal::DescriptorRefusal,
    > {
        let maintenance = CallerInvalidatesAsid;
        SelectionWords(&self.tables.live(&maintenance)).select_backing_window(root, window)
    }
    fn commit_prepared(
        &mut self,
        root: u64,
        va: u64,
        ipa: u64,
        access: carrick_mmu_core::aarch64::LeafAccess,
    ) -> Result<
        carrick_mmu_core::aarch64::GuestPreparedCommit,
        carrick_mmu_core::aarch64::GuestPreparedCommitError,
    > {
        assert_eq!(root & AARCH64_ROOT_ADDRESS_MASK, self.tables.base);
        // SAFETY: retained aligned atomic table arena, under the production
        // fault owner's exclusive editor. No hardware TLB exists here.
        unsafe {
            carrick_mmu_core::aarch64::commit_existing_el1_prepared_page(
                self.tables.words.as_ptr().cast_mut(),
                self.tables.base,
                self.tables.words.len() * 8,
                None,
                va,
                ipa,
                access,
            )
        }
    }
}

fn reservation_supply_requests(count: usize) -> usize {
    use crate::mm_portal::test_support::{IPA, ROOT, Region, Tables, admit, nodes, residency};
    use carrick_el1::fault::{NoopCowResolver, PreparedFaultPath};
    use carrick_el1_abi::{CurrentTask, FrameGrantMailbox, TrapFrame};
    use carrick_mmu_core::aarch64::descriptor_txn::{
        BackingIdentity, DescriptorOp, DescriptorOutcome, DescriptorTxn, DescriptorTxnId, PageSpan,
        TableGrants,
    };
    use carrick_mmu_core::aarch64::{GuestLeafPublication, SubstrateGpa};
    let region = Region::new();
    let spaces = carrick_sched_core::AddressSpaces::new();
    let mm = admit(&region, &spaces, 77, ROOT, 1, 0);
    let access =
        carrick_sched_core::spaces::notification::SpaceAccess::<Aarch64ParkedContext>::source_free_with_context(&spaces);
    let task = CurrentTask::new();
    task.execution.task.store(1, Ordering::Release);
    task.mm.thread_generation.store(1, Ordering::Release);
    task.mm.key.store(mm.raw(), Ordering::Release);
    let view = nodes(&region);
    let owner = crate::mm_portal::MmPortal::new(NonZeroU64::MIN, region.table(), &spaces, &view);
    let slots = region.portal_slots();
    assert!(slots.bind_carrier(NonZeroU64::MIN));
    let tables = Tables::new(ROOT, IPA, 0);
    // Supply table storage ahead of time so this witness isolates backing
    // demand. 1024 mappings of 1/2/3/4 pages occupy five L3 tables.
    for index in 0..6 {
        tables.words[1024 + index].store((ROOT + (3 + index as u64) * 4096) | 3, Ordering::Release);
    }
    let maintenance = CallerInvalidatesAsid;
    let words = tables.live(&maintenance);
    let residency = residency();
    let counters = carrick_el1_abi::Counters::default();
    let mailbox = FrameGrantMailbox::new();
    let mut requests = 0;
    let mut mappings = Vec::new();
    for index in 0..count {
        let len = ((index % 4) + 1) as u64 * 4096;
        let mut frame = TrapFrame::default();
        frame.x[8] = 222;
        frame.x[..6].copy_from_slice(&[0, len, 3, 0x22, u64::MAX, 0]);
        assert_eq!(
            carrick_el1::memory::serve_delegated_anonymous(
                &mut frame,
                &counters,
                &task,
                access,
                region.table(),
                &mut ReservationSupplyMemory {
                    tables: &tables,
                    residency: &residency
                },
                None,
            ),
            carrick_el1::memory::DelegatedAnonymous::Served,
            "mmap index={index} counters={counters:?}",
        );
        let va = frame.x[0];
        assert_eq!(va % 4096, 0);
        assert!(va < crate::mm_portal::test_support::VA + 6 * 512 * 4096);
        frame.esr = 0x92000046; // EL0 write translation fault.
        frame.far = va;
        let supply = OwnerFaultSupply::new(slots);
        let action = carrick_el1::fault::dispatch_fault_with_prepared(
            &mut frame,
            &counters,
            core::slice::from_ref(&task),
            access,
            crate::cow_resolver::native_fault_supply(
                true,
                carrick_el1::fault::GrantMailboxes::own(&mailbox),
                &supply,
            ),
            Some(PreparedFaultPath {
                residency: &residency,
                resolver: &mut ReservationSupplyMemory {
                    tables: &tables,
                    residency: &residency,
                },
                roots: Some(region.table()),
                file_slots: Some(slots),
            }),
            &mut NoopCowResolver,
        );
        if action == carrick_el1_abi::Action::Forward {
            assert_eq!(supply.outcome(), OwnerFaultSupplyOutcome::Selected);
            let slot = slots.grant(0).unwrap();
            let (_, window) = slot.pending_fault_selection(mm.raw(), va).unwrap();
            requests += 1;
            let id = NonZeroU64::new(index as u64 + 1).unwrap();
            let txn = DescriptorTxn {
                id: DescriptorTxnId {
                    mm_key: NonZeroU64::new(mm.raw()).unwrap(),
                    generation: window.operation.sequence,
                },
                root: SubstrateGpa(ROOT),
                op: DescriptorOp::Prepare {
                    publication: GuestLeafPublication {
                        va: window.range.start(),
                        ipa: IPA + index as u64 * 0x200000,
                        len: window.range.len(),
                        writable: true,
                        executable: false,
                    },
                    resident: PageSpan::new(va, 4096),
                    backing: BackingIdentity {
                        frame_id: id,
                        mapping_id: id,
                        owner_generation: id,
                        inventory_revision: id,
                    },
                },
                tables: TableGrants::NONE,
            };
            assert!(slot.submit(window, &txn));
            let receipt =
                carrick_core::mm::frames::serve_grant(&owner, slot, &words, &residency, 0, || {})
                    .unwrap()
                    .unwrap();
            assert!(
                matches!(receipt.outcome, DescriptorOutcome::Applied(_)),
                "{receipt:?}"
            );
            assert!(slot.take_receipt(window, &txn).is_some());
        } else {
            assert_eq!(action, carrick_el1_abi::Action::Served);
        }
        assert!(residency.is_guest_committed(mm.raw(), va));
        let descriptor = leaf(&words, ROOT, va);
        assert_ne!(descriptor & 1, 0);
        mappings.push((va, descriptor));
    }
    // Later grants cannot replace or alias an earlier reservation's private
    // frame. Real bytes/VM execution remain the signed fixture's obligation.
    let mut physical = std::collections::BTreeSet::new();
    for (va, descriptor) in mappings {
        assert_eq!(leaf(&words, ROOT, va), descriptor);
        assert!(physical.insert(descriptor & AARCH64_ROOT_ADDRESS_MASK));
    }
    requests
}
