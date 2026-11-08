//! VM-free x86 CPL0 native-fork COW witness for #1733.
//!
//! Exercises the real `NativeProcessRuntime` (`admit_fresh_root::<X86Mmu>`,
//! `fork`, `exit_group`, `wait4`), `MmPortal<..., X86Mmu, ParkedContextWords>`,
//! shared `dispatch_x86_fault_with_prepared` with production `OwnerFaultSupply`
//! but test-owned prepared/COW resolvers and backing, `CowGrantPool` settlement, and
//! `RetiredSpaces::drain_portal`. The red result is the parent's first write
//! to an inherited `PREPARED|COW` sibling page after the child writes, exits,
//! and is reaped by `wait4`. This is a fixture diagnostic until a CPL0
//! production fault reaches the same page. Subsequent checks cover COW
//! replenishment across 72 16-KiB compounds once that fault is fixed.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use carrick_core::mm::cow::{
    CowClassifyOutcome, CowCopyWindow, CowRepointOp, CowRepointOutcome, GuestCowRun, GuestCowVenue,
    OwnerCowMmu, resolve_guest_cow,
};
use carrick_core::mm::fork::{ForkCensus, ForkScratch, census_table};
use carrick_core::mm::frames::serve_grant;
use carrick_core::mm::transaction::{MmError, MmPortal, OwnerVenue};
use carrick_core_abi::{BirthSerial, Decision, Placement, SnapshotGeneration};
use carrick_el1::fault::{
    CowResolution, CowResolver, FaultSupply, OwnerFaultSupply, OwnerFaultSupplyOutcome,
    PreparedFaultPath, PreparedPageResolver, dispatch_x86_fault_with_prepared, handle_cow_outcome,
};
use carrick_el1::memory::reservations::{
    Layout, NoRootWait, X86Cpl0ReservationGeometry, X86Cpl0Reservations, X86Cpl0RootReleaseVenue,
};
use carrick_el1_abi::{
    Action, BornInZoneSource, Counters, CowDecline, CowGrantPool, CurrentTask,
    EL1_FRAME_GRANT_TARGET_SIZE, El1TaskId, EntryMmKey, EntryTaskKey, EntryThreadGeneration,
    ExecutionBinding, FrameGrantResidencyIdentity, FrameGrantResidencyTable, MmPortalSlots,
    PortalForkRequest, PortalForkTableArena, PortalGrantWindow, PortalOperation, ReservationMm,
    ReservationProtection, ReservationRange, ThreadControlSlot, ThreadIdentity,
    ThreadLifecyclePage,
};
use carrick_el1_linux::mm_portal::test_support::{NoPin, Region};
use carrick_el1_linux::mm_portal::{LinuxForkPolicy, NativeForkPortal, UnpublishedEl1Child};
use carrick_el1_linux::native_process_runtime::{
    NativeForkPreparation, NativeLifecycleResources, NativeProcessError, NativeProcessRegistry,
    NativeProcessRuntime, NativeProcessService, NativeResume,
};
use carrick_el1_linux::retired_spaces::{RetiredSpace, RetiredSpaces};
use carrick_guest_arch::{
    Access as GuestAccess, AddressContext, ContextGeneration, CpuId, EditIntent, EditOperation,
    EditOwner, FaultInfo, FrameGpa, GuestLen, MmGeneration, RootGpa, UserRange, UserVa,
};
use carrick_mmu_core::aarch64::{
    GuestPreparedCommit, GuestPreparedCommitError, LeafAccess, SubstrateGpa,
};
use carrick_mmu_core::descriptor_refusal::DescriptorRefusal;
use carrick_mmu_core::x86::descriptor_txn::{
    ADDRESS, Access as X86Access, BackingIdentity, CowClass, DescriptorOp, DescriptorOutcome,
    DescriptorTxn, DescriptorTxnId, HUGE, InlineJournal, LiveDescriptorWords, MAY_WRITE, NX,
    PREPARED, PRESENT, PRIVATE, PageSpan, USER, WRITE, classify_guest_cow_write,
    execute_descriptor_txn, plan_descriptor_txn, translate_leaf,
};
use carrick_mmu_core::x86::owner_mmu::X86Mmu;
use carrick_personality_linux::lifecycle::{
    LifecycleOutcome, LinuxWaitOptions, LinuxWaitStatus, ProcessForkChildTid, ProcessNative,
    ProcessWaitPid,
};
use carrick_personality_linux::mm::{LinuxReservationPolicy, MmErrorLinux};
use carrick_sched_core::process::TaskSerial;
use carrick_sched_core::{
    AffinitySource, ParkedContextWords, RecordId, RecordRef, SlotId, WakeEffects, ZoneTables,
};
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Arc;

const CARRIER_ID: u64 = 1;
const PARENT_ROOT_PA: u64 = 0x0100_0000;
const CHILD_ROOT_BASE_PA: u64 = 0x0200_0000;
const CHILD_ARENA_BYTES: u64 = 0x0010_0000;
const PARENT_SPLIT_BASE_PA: u64 = 0x0300_0000;
const PARENT_SPLIT_BYTES: u64 = 0x0010_0000;
const DATA_FRAME_BASE_PA: u64 = 0x1000_0000;
const STATUS_VA: u64 = 0x7000_0000;

struct TestX86Venue;
impl OwnerVenue<ParkedContextWords> for TestX86Venue {
    fn space_access(
        zone: &ZoneTables<ParkedContextWords>,
        slot: SlotId,
    ) -> carrick_sched_core::spaces::notification::SpaceAccess<'_, ParkedContextWords> {
        carrick_core::wait::space_access(zone, slot, |_, _, effects| {
            let (_, effects) = effects.deliver_handbacks(&mut |_| {});
            let _ = effects;
        })
    }
    fn deliver_completion(
        _: &ZoneTables<ParkedContextWords>,
        _: SlotId,
        effects: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_, ParkedContextWords>,
    ) {
        let (_, _) = effects.deliver_handbacks(&mut |_| {});
    }
    fn encode_error(error: MmError) -> u32 {
        error.errno()
    }
    fn cancelled_copy_code() -> u32 {
        carrick_personality_linux::mm::cancelled_copy_errno()
    }
}

type TestPortal = MmPortal<
    'static,
    NoPin,
    LinuxReservationPolicy,
    X86Cpl0ReservationGeometry,
    TestX86Venue,
    X86Mmu,
    ParkedContextWords,
>;

struct SparseX86Tables {
    words: RefCell<BTreeMap<u64, Box<AtomicU64>>>,
    next_boot_table: AtomicU64,
}
impl SparseX86Tables {
    fn new(boot_table_base: u64) -> Self {
        Self {
            words: RefCell::new(BTreeMap::new()),
            next_boot_table: AtomicU64::new(boot_table_base),
        }
    }

    fn valid_pa(pa: u64) -> bool {
        pa.is_multiple_of(8) && (0x0010_0000..0x0800_0000).contains(&pa)
    }

    fn with_word<R>(
        &self,
        pa: u64,
        f: impl FnOnce(&AtomicU64) -> R,
    ) -> Result<R, DescriptorRefusal> {
        if !Self::valid_pa(pa) {
            return Err(DescriptorRefusal::TableOutsidePrimary);
        }
        let mut map = self.words.borrow_mut();
        let atom = map.entry(pa).or_insert_with(|| Box::new(AtomicU64::new(0)));
        Ok(f(atom))
    }

    fn alloc_boot_table(&self) -> u64 {
        self.next_boot_table.fetch_add(4096, Ordering::Relaxed)
    }

    fn ensure_pt_chain(&self, root_pa: u64, va: u64, need_pt: bool) -> u64 {
        let pml4_idx = (va >> 39) & 0x1ff;
        let pdpt_idx = (va >> 30) & 0x1ff;
        let pd_idx = (va >> 21) & 0x1ff;

        let pml4e_pa = root_pa + pml4_idx * 8;
        let mut pml4e = self.load(pml4e_pa).unwrap();
        if pml4e & PRESENT == 0 {
            let pdpt = self.alloc_boot_table();
            pml4e = pdpt | PRESENT | WRITE | USER;
            self.store_unlinked(pml4e_pa, pml4e).unwrap();
        }
        let pdpt_pa = pml4e & ADDRESS;

        let pdpte_pa = pdpt_pa + pdpt_idx * 8;
        let mut pdpte = self.load(pdpte_pa).unwrap();
        if pdpte & PRESENT == 0 {
            let pd = self.alloc_boot_table();
            pdpte = pd | PRESENT | WRITE | USER;
            self.store_unlinked(pdpte_pa, pdpte).unwrap();
        }
        let pd_pa = pdpte & ADDRESS;

        let pde_pa = pd_pa + pd_idx * 8;
        if !need_pt {
            return pde_pa;
        }
        let mut pde = self.load(pde_pa).unwrap();
        if pde & PRESENT == 0 {
            let pt = self.alloc_boot_table();
            pde = pt | PRESENT | WRITE | USER;
            self.store_unlinked(pde_pa, pde).unwrap();
        }
        pde & ADDRESS
    }

    fn read_pte(&self, root_pa: u64, va: u64) -> Option<u64> {
        let pml4e = self.load(root_pa + ((va >> 39) & 0x1ff) * 8).ok()?;
        if pml4e & PRESENT == 0 {
            return None;
        }
        let pdpte = self
            .load((pml4e & ADDRESS) + ((va >> 30) & 0x1ff) * 8)
            .ok()?;
        if pdpte & PRESENT == 0 {
            return None;
        }
        let pde = self
            .load((pdpte & ADDRESS) + ((va >> 21) & 0x1ff) * 8)
            .ok()?;
        if pde & PRESENT == 0 {
            return None;
        }
        if pde & HUGE != 0 {
            return Some(pde);
        }
        self.load((pde & ADDRESS) + ((va >> 12) & 0x1ff) * 8).ok()
    }
}

impl LiveDescriptorWords for SparseX86Tables {
    fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
        self.with_word(pa, |w| w.load(Ordering::Acquire))
    }
    fn compare_exchange(
        &self,
        pa: u64,
        before: u64,
        after: u64,
    ) -> Result<bool, DescriptorRefusal> {
        self.with_word(pa, |w| {
            w.compare_exchange(before, after, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        })
    }
    fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), DescriptorRefusal> {
        self.with_word(pa, |w| w.store(value, Ordering::Release))
    }
    fn publish_barrier(&self) {}
    fn invalidate_range(&self, _: u64, _: u64) {}
}

struct PhysicalPages {
    pages: RefCell<BTreeMap<u64, Box<[u8; 4096]>>>,
    next_pa: AtomicU64,
    next_id: AtomicU64,
}
impl PhysicalPages {
    fn new() -> Self {
        Self {
            pages: RefCell::new(BTreeMap::new()),
            next_pa: AtomicU64::new(DATA_FRAME_BASE_PA),
            next_id: AtomicU64::new(100),
        }
    }

    fn alloc_extent(&self, bytes: u64) -> (u64, BackingIdentity) {
        assert!(bytes.is_multiple_of(4096));
        let align = bytes.clamp(0x4000, 0x20_0000);
        let mut cur = self.next_pa.load(Ordering::Relaxed);
        let aligned = cur.next_multiple_of(align);
        cur = aligned + bytes;
        self.next_pa.store(cur, Ordering::Relaxed);
        let mut map = self.pages.borrow_mut();
        for offset in (0..bytes).step_by(4096) {
            map.insert(aligned + offset, Box::new([0u8; 4096]));
        }
        let id = NonZeroU64::new(self.next_id.fetch_add(1, Ordering::Relaxed)).unwrap();
        (
            aligned,
            BackingIdentity {
                frame_id: id,
                mapping_id: id,
                owner_generation: NonZeroU64::MIN,
                inventory_revision: id,
            },
        )
    }

    fn read_u64(&self, frame_pa: u64, page_offset: usize) -> u64 {
        let pages = self.pages.borrow();
        let page = pages
            .get(&(frame_pa & !4095))
            .unwrap_or_else(|| panic!("missing physical frame at {:#x}", frame_pa));
        u64::from_le_bytes(page[page_offset..page_offset + 8].try_into().unwrap())
    }

    fn write_u64(&self, frame_pa: u64, page_offset: usize, value: u64) {
        let mut pages = self.pages.borrow_mut();
        let page = pages
            .get_mut(&(frame_pa & !4095))
            .unwrap_or_else(|| panic!("missing physical frame at {:#x}", frame_pa));
        page[page_offset..page_offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn copy_frame(&self, src_pa: u64, dst_pa: u64) {
        let mut pages = self.pages.borrow_mut();
        let bytes = *pages
            .get(&(src_pa & !4095))
            .unwrap_or_else(|| panic!("missing COW source frame {:#x}", src_pa))
            .as_ref();
        pages.insert(dst_pa & !4095, Box::new(bytes));
    }
}

struct TestX86CowOwner;
impl OwnerCowMmu for TestX86CowOwner {
    const CARRIER_MAINT_ROOT_BASE: u64 = 0;
    const DEFAULT_COW_COPY_BASE: u64 = 0;

    fn classify_cow_write<W: LiveDescriptorWords + ?Sized>(
        words: &W,
        root: u64,
        far: u64,
        publish_executable: bool,
    ) -> CowClassifyOutcome {
        let Some(root) = RootGpa::page_aligned(FrameGpa::new(root)) else {
            return CowClassifyOutcome::Declined(CowDecline::Unreachable);
        };
        match classify_guest_cow_write(words, root, UserVa::new(far), publish_executable) {
            Ok(run) => CowClassifyOutcome::Armed(GuestCowRun {
                va: run.va,
                len: run.len,
                old_ipa: run.old_ipa.raw(),
                compound_offset: run.compound_offset,
                executable: run.executable,
            }),
            Err(CowClass::AlreadyWritable) => CowClassifyOutcome::AlreadyWritable,
            Err(reason) => CowClassifyOutcome::Declined(match reason {
                CowClass::Unmapped => CowDecline::Unmapped,
                CowClass::NotCowArmed => CowDecline::NotCowArmed,
                CowClass::AncestorNotWritable => CowDecline::NotEl1Private,
                CowClass::NoWriteIntent => CowDecline::NoWriteIntent,
                CowClass::ExecutableDenied => CowDecline::Executable,
                CowClass::Unreachable | CowClass::AlreadyWritable => CowDecline::Unreachable,
            }),
        }
    }

    fn plan_cow_repoint<W: LiveDescriptorWords + ?Sized>(
        words: &W,
        root: u64,
        op: CowRepointOp,
    ) -> bool {
        let root = RootGpa::page_aligned(FrameGpa::new(root)).unwrap();
        let txn = DescriptorTxn {
            id: DescriptorTxnId {
                mm_key: NonZeroU64::new(op.mm_key).unwrap(),
                generation: NonZeroU64::new(op.grant_epoch).unwrap(),
            },
            root,
            op: DescriptorOp::CowRepoint {
                span: PageSpan::new(op.va, op.len),
                old: FrameGpa::new(op.old_ipa),
                new: FrameGpa::new(op.new_ipa),
                backing: op.backing,
            },
            tables: &[],
        };
        plan_descriptor_txn(words, &txn, root).is_ok()
    }

    fn with_copy_aliases<W: LiveDescriptorWords + ?Sized, F: FnMut(u64, u64)>(
        _: &W,
        _: u64,
        _: u64,
        source_ipa: u64,
        destination_ipa: u64,
        effect: &mut F,
    ) -> Result<(), CowRepointOutcome> {
        effect(source_ipa, destination_ipa);
        Ok(())
    }

    fn execute_cow_repoint<W: LiveDescriptorWords + ?Sized>(
        words: &W,
        root: u64,
        op: CowRepointOp,
    ) -> CowRepointOutcome {
        let root = RootGpa::page_aligned(FrameGpa::new(root)).unwrap();
        let txn = DescriptorTxn {
            id: DescriptorTxnId {
                mm_key: NonZeroU64::new(op.mm_key).unwrap(),
                generation: NonZeroU64::new(op.grant_epoch).unwrap(),
            },
            root,
            op: DescriptorOp::CowRepoint {
                span: PageSpan::new(op.va, op.len),
                old: FrameGpa::new(op.old_ipa),
                new: FrameGpa::new(op.new_ipa),
                backing: op.backing,
            },
            tables: &[],
        };
        match execute_descriptor_txn(words, &txn, root, &mut InlineJournal::new()).outcome {
            DescriptorOutcome::Applied { .. } => CowRepointOutcome::Applied {
                flush_required: true,
            },
            DescriptorOutcome::Refused(_) => CowRepointOutcome::Refused,
            DescriptorOutcome::RolledBack(_) => CowRepointOutcome::RolledBack,
            DescriptorOutcome::Indeterminate(_) => CowRepointOutcome::Indeterminate,
        }
    }
}

struct TestX86CowResolver<'a> {
    words: &'a SparseX86Tables,
    ram: &'a PhysicalPages,
    pool: &'a CowGrantPool,
    residency: &'a FrameGrantResidencyTable,
}
impl CowResolver for TestX86CowResolver<'_> {
    fn resolve_cow(&mut self, root: u64, mm_key: u64, far: u64) -> bool {
        self.resolve_cow_outcome(root, mm_key, far) == CowResolution::Resolved
    }
    fn resolve_cow_outcome(&mut self, root: u64, mm_key: u64, far: u64) -> CowResolution {
        let venue = GuestCowVenue::<TestX86CowOwner, _> {
            words: self.words,
            root: SubstrateGpa(root),
            pool: self.pool,
            residency: self.residency,
            copy_window: CowCopyWindow::target(self.words, SubstrateGpa(root)),
            publish_executable: None,
        };
        let outcome = resolve_guest_cow::<TestX86CowOwner, _, _, _>(
            &venue,
            mm_key,
            far,
            |src_pa, dst_pa| self.ram.copy_frame(src_pa, dst_pa),
            || {},
        );
        let mut completion = None;
        handle_cow_outcome(outcome, &mut completion)
    }
    fn editor_busy(&mut self) {}
}

struct TestX86PreparedResolver<'a> {
    mm_key: NonZeroU64,
    words: &'a SparseX86Tables,
    seq: AtomicU64,
}
impl<'a> TestX86PreparedResolver<'a> {
    fn new(mm_key: NonZeroU64, words: &'a SparseX86Tables) -> Self {
        Self {
            mm_key,
            words,
            seq: AtomicU64::new(1),
        }
    }
}
impl PreparedPageResolver for TestX86PreparedResolver<'_> {
    fn select_backing_window(
        &mut self,
        root: u64,
        window: PortalGrantWindow,
    ) -> Result<PortalGrantWindow, DescriptorRefusal> {
        carrick_core::mm::frames::select_backing_window::<X86Mmu, _>(self.words, root, window)
    }
    fn commit_prepared(
        &mut self,
        root_pa: u64,
        va: u64,
        expected_pa: u64,
        access: LeafAccess,
    ) -> Result<GuestPreparedCommit, GuestPreparedCommitError> {
        let root = RootGpa::page_aligned(FrameGpa::new(root_pa))
            .ok_or(GuestPreparedCommitError::BadAddress)?;
        let range = UserRange::checked(UserVa::new(va), GuestLen::new(4096))
            .ok_or(GuestPreparedCommitError::BadAddress)?;
        let expected = FrameGpa::new(expected_pa);
        let (fault_access, native_access) = match access {
            LeafAccess::Read => (GuestAccess::Read, X86Access::Read),
            LeafAccess::Write => (GuestAccess::Write, X86Access::Write),
            LeafAccess::Execute => (GuestAccess::Execute, X86Access::Execute),
        };
        let sequence = NonZeroU64::new(self.seq.fetch_add(1, Ordering::Relaxed)).unwrap();
        // SAFETY: dispatch_x86_fault_with_prepared holds this MM's exact space editor.
        let owner = unsafe { EditOwner::issue(root, self.mm_key, sequence) };
        let intent = EditIntent::checked(
            owner,
            range,
            EditOperation::Publish {
                expected,
                access: fault_access,
            },
            &[],
        )
        .ok_or(GuestPreparedCommitError::BadAddress)?;
        let txn = DescriptorTxn::from_intent(&intent)
            .map_err(|_| GuestPreparedCommitError::BadAddress)?;
        let receipt = execute_descriptor_txn(self.words, &txn, root, &mut InlineJournal::new());
        match receipt.outcome {
            DescriptorOutcome::Applied { .. } => Ok(GuestPreparedCommit::Committed),
            DescriptorOutcome::Refused(DescriptorRefusal::NotPrepared) => {
                if translate_leaf(self.words, root, UserVa::new(va), native_access, true)
                    .is_ok_and(|leaf| leaf.output == expected)
                {
                    Ok(GuestPreparedCommit::AlreadyResident)
                } else {
                    Err(GuestPreparedCommitError::NotPrepared)
                }
            }
            DescriptorOutcome::Refused(DescriptorRefusal::WrongBacking) => {
                Err(GuestPreparedCommitError::WrongBacking)
            }
            DescriptorOutcome::Refused(DescriptorRefusal::PermissionDenied) => {
                Err(GuestPreparedCommitError::PermissionDenied)
            }
            DescriptorOutcome::Refused(DescriptorRefusal::MissingTable) => {
                Err(GuestPreparedCommitError::MissingTable)
            }
            _ => Err(GuestPreparedCommitError::BadAddress),
        }
    }
    fn inherited_prepared_supply(&self) -> bool {
        true
    }
}

struct PreparedX86Child {
    child: UnpublishedEl1Child<X86Mmu>,
    address: AddressContext<RootGpa>,
    page: &'static ThreadLifecyclePage,
    controls: &'static [ThreadControlSlot; carrick_el1_abi::THREAD_POOL_ENTRIES + 1],
}

struct BornX86Child {
    prepared: PreparedX86Child,
}

struct X86TestService<'a> {
    portal: &'a TestPortal,
    zone: &'static ZoneTables<ParkedContextWords>,
    words: &'a SparseX86Tables,
    ram: &'a PhysicalPages,
    residency: &'static FrameGrantResidencyTable,
    cow_pool: &'a CowGrantPool,
    retired: &'a RetiredSpaces,
    slot: SlotId,
    next_fork_idx: &'a AtomicU64,
    last_wait_status: &'a RefCell<Option<LinuxWaitStatus>>,
}

impl X86TestService<'_> {
    fn worker(&self) -> u32 {
        u32::from(self.slot.raw())
    }

    fn drain_retired(&self) {
        let _ = self
            .retired
            .drain_portal(self.portal, self.zone, 2, self.worker());
    }
}

impl NativeProcessService<'static, ParkedContextWords> for X86TestService<'_> {
    type Mm = AddressContext<RootGpa>;
    type PreparedMm = PreparedX86Child;
    type Born = Box<BornX86Child>;

    fn service_mm_handle(
        &self,
        mm: &Self::Mm,
    ) -> Result<carrick_core_abi::El1MmHandle, NativeProcessError> {
        self.portal
            .admitted_handle(
                ReservationMm::new(mm.mm.raw().get()).ok_or(NativeProcessError::Stale)?,
                self.worker(),
            )
            .map_err(|_| NativeProcessError::Fault)
    }

    fn prepare_mm(
        &mut self,
        parent: &Self::Mm,
        context_words: &ParkedContextWords,
        child_mm: MmGeneration,
    ) -> Result<Self::PreparedMm, NativeProcessError> {
        if !context_words.authenticates(*parent) {
            return Err(NativeProcessError::Stale);
        }
        self.drain_retired();
        let mm = ReservationMm::new(parent.mm.raw().get()).ok_or(NativeProcessError::Stale)?;
        let capacity = self
            .portal
            .fork_mapping_count(mm, self.worker())
            .map_err(|_| NativeProcessError::Fault)?;
        let mut mappings = Vec::with_capacity(capacity);
        let (operation, generation, count, layout) = {
            let index = self
                .portal
                .spaces
                .find(mm.raw())
                .ok_or(NativeProcessError::Stale)?;
            let access = self
                .portal
                .space_access(self.worker())
                .map_err(|_| NativeProcessError::Fault)?;
            let _editor = access
                .try_begin_edit(
                    index,
                    mm.raw(),
                    NonZeroU64::new(u64::from(self.worker()) + 1).unwrap(),
                )
                .ok_or(NativeProcessError::Busy)?;
            let mut root = self
                .portal
                .root(mm, self.worker())
                .map_err(|_| NativeProcessError::Fault)?;
            if !root.fork_ready() {
                return Err(NativeProcessError::Busy);
            }
            root.observe_mappings(&mut |m| mappings.push(m))
                .map_err(|_| NativeProcessError::Fault)?;
            let operation = PortalOperation {
                carrier: self.portal.carrier,
                mm,
                incarnation: NonZeroU64::new(root.incarnation().raw()).unwrap(),
                sequence: root
                    .next_transfer_sequence()
                    .map_err(|_| NativeProcessError::Fault)?,
            };
            let mut count = ForkCensus {
                child: 0,
                parent: 0,
                live: 0,
                custody: 0,
            };
            census_table::<X86Mmu, _, _>(
                &LinuxForkPolicy,
                self.words,
                &mappings,
                parent.root.address().raw(),
                0,
                0,
                &mut count,
            )
            .map_err(|_| NativeProcessError::Fault)?;
            (operation, root.generation(), count, root.layout())
        };

        let fork_idx = self.next_fork_idx.fetch_add(1, Ordering::Relaxed);
        let child_base = CHILD_ROOT_BASE_PA + fork_idx * CHILD_ARENA_BYTES;
        let parent_split_base = PARENT_SPLIT_BASE_PA + fork_idx * PARENT_SPLIT_BYTES;
        let child_mm_id = ReservationMm::new(child_mm.raw().get()).unwrap();
        let request = PortalForkRequest {
            operation,
            parent_generation: generation,
            child_mm: child_mm_id,
            child_tables: PortalForkTableArena::new(
                child_base,
                ((count.child as u64) * 8).max(4096).next_multiple_of(4096),
            )
            .unwrap(),
            parent_tables: PortalForkTableArena::new(
                parent_split_base,
                ((count.parent as u64) * 8).max(4096).next_multiple_of(4096),
            )
            .unwrap(),
            kernel_control_ipa: 0x00a0_0000,
        };

        let page = Box::leak(Box::new(ThreadLifecyclePage::new()));
        let controls = Box::leak(Box::new(core::array::from_fn(|_| ThreadControlSlot::new())));
        let root = RootGpa::page_aligned(FrameGpa::new(child_base)).unwrap();
        let index = self
            .portal
            .spaces
            .publish_closed(child_mm.raw().get(), child_base, 0)
            .ok_or(NativeProcessError::Exhausted)?;
        self.portal
            .roots
            .publish(index.index(), child_mm_id, layout)
            .map_err(|_| {
                self.portal.spaces.free(index);
                NativeProcessError::Fault
            })?;
        let scratch = ForkScratch::bounded(
            request,
            mappings.len(),
            count.child,
            count.parent,
            count.live,
            count.custody,
        )
        .map_err(|_| {
            self.portal.spaces.free(index);
            NativeProcessError::Exhausted
        })?;
        let plan = self
            .portal
            .prepare_fork(request, scratch, self.words, self.worker())
            .map_err(|_| {
                self.portal.spaces.free(index);
                NativeProcessError::Fault
            })?;
        let mut published_bases = std::collections::BTreeSet::new();
        for custody in plan.custody() {
            if let carrick_el1_abi::PortalForkCustody::Frame {
                va,
                ipa,
                len,
                shared: false,
                ..
            } = *custody
            {
                let parent_row = self.residency.lookup(mm.raw(), va);
                let mut identity =
                    parent_row
                        .map(|p| p.identity)
                        .unwrap_or(FrameGrantResidencyIdentity {
                            mm_key: mm.raw(),
                            semantic_base: va,
                            physical_ipa: ipa,
                            len,
                            frame_id: 1,
                            mapping_id: 1,
                            owner_generation: 1,
                            inventory_revision: 1,
                        });
                identity.mm_key = child_mm_id.raw();
                if published_bases.insert(identity.semantic_base) {
                    assert!(self.residency.publish(identity).is_some());
                }
                for off in (0..len).step_by(4096) {
                    let page_va = va + off;
                    let resident = self
                        .words
                        .read_pte(parent.root.address().raw(), page_va)
                        .is_some_and(|pte| pte & PRESENT != 0);
                    if resident {
                        let child_page = self
                            .residency
                            .lookup(child_mm_id.raw(), page_va)
                            .expect("child residency page");
                        assert!(self.residency.record_commit(child_page));
                    }
                }
            }
        }
        let child = self
            .portal
            .publish_fork(plan, self.words, self.worker())
            .map_err(|_| {
                let _ = self
                    .residency
                    .retire_overlapping(child_mm_id.raw(), 0, u64::MAX);
                self.portal.spaces.free(index);
                NativeProcessError::Fault
            })?;
        let address = AddressContext {
            mm: child_mm,
            root,
            generation: ContextGeneration::new(child.completion().child.incarnation()),
        };
        Ok(PreparedX86Child {
            child,
            address,
            page,
            controls,
        })
    }

    fn prepared_mm(&self, p: &Self::PreparedMm) -> Self::Mm {
        p.address
    }

    fn prepared_context(&self, p: &Self::PreparedMm) -> Self::Mm {
        p.address
    }

    fn fork_child_context(
        &self,
        parent: ParkedContextWords,
        prepared: &Self::PreparedMm,
    ) -> ParkedContextWords {
        parent.fork_child(prepared.address)
    }

    fn child_lifecycle(&self, p: &Self::PreparedMm) -> NativeLifecycleResources<'static> {
        NativeLifecycleResources {
            page: p.page,
            controls: p.controls,
        }
    }

    fn commit_mm(
        &mut self,
        p: Self::PreparedMm,
    ) -> Result<Self::Born, (NativeProcessError, Self::PreparedMm)> {
        self.commit_child(p, NonZeroU64::MIN, NonZeroU64::MIN)
    }

    fn commit_child(
        &mut self,
        mut p: Self::PreparedMm,
        _: NonZeroU64,
        _: NonZeroU64,
    ) -> Result<Self::Born, (NativeProcessError, Self::PreparedMm)> {
        match p.child.commit(self.portal, self.worker()) {
            Ok(_) => Ok(Box::new(BornX86Child { prepared: p })),
            Err(_) => Err((NativeProcessError::Fault, p)),
        }
    }

    fn abort_mm(
        &mut self,
        mut p: Self::PreparedMm,
    ) -> Result<(), (NativeProcessError, Self::PreparedMm)> {
        match p.child.abort(self.portal, self.words, self.worker()) {
            Ok(()) => {
                if let Some(index) = self.portal.spaces.find(p.address.mm.raw().get()) {
                    self.portal.spaces.free(index);
                }
                Ok(())
            }
            Err(_) => Err((NativeProcessError::Fault, p)),
        }
    }

    fn settle_mm(&mut self, born: Self::Born) -> Result<(), (NativeProcessError, Self::Born)> {
        let Some(index) = self
            .portal
            .spaces
            .find(born.prepared.address.mm.raw().get())
        else {
            return Err((NativeProcessError::Stale, born));
        };
        let Ok(access) = self.portal.space_access(self.worker()) else {
            return Err((NativeProcessError::Fault, born));
        };
        access.open(index);
        Ok(())
    }

    fn copy_status(
        &mut self,
        mm: &Self::Mm,
        address: UserVa,
        status: LinuxWaitStatus,
    ) -> Result<(), NativeProcessError> {
        *self.last_wait_status.borrow_mut() = Some(status);
        if address.raw() != 0 {
            let leaf = translate_leaf(self.words, mm.root, address, X86Access::Write, true)
                .map_err(|_| NativeProcessError::Fault)?;
            self.ram.write_u64(
                leaf.output.raw(),
                (address.raw() & 4095) as usize,
                status.raw() as u32 as u64,
            );
        }
        Ok(())
    }

    fn copy_signal_bytes(
        &mut self,
        _: &Self::Mm,
        _: UserVa,
        _: &[u8],
    ) -> Result<(), NativeProcessError> {
        Ok(())
    }

    fn copy_owned_bytes(
        &mut self,
        _: &Self::Mm,
        _: UserVa,
        _: &[u8],
    ) -> Result<(), NativeProcessError> {
        Ok(())
    }

    fn copy_siginfo(
        &mut self,
        _: &Self::Mm,
        _: UserVa,
        _: &carrick_abi::LinuxSiginfo,
    ) -> Result<(), NativeProcessError> {
        Ok(())
    }

    fn quarantine_prepared(&mut self, _: Self::PreparedMm) {
        panic!("unexpected prepared quarantine")
    }

    fn quarantine_fork(
        &mut self,
        _: NativeForkPreparation<'static, Self::Mm, Self::PreparedMm, ParkedContextWords>,
    ) {
        panic!("unexpected fork quarantine")
    }

    fn quarantine_born(&mut self, _: Self::Born) {
        panic!("unexpected born quarantine")
    }

    fn retire_mm(&mut self, mm: Self::Mm) {
        let index = self.portal.spaces.find(mm.mm.raw().get()).unwrap();
        self.portal.spaces.close(index);
        self.zone.release_space(self.slot);
        if let Some(excluded) = self.zone.spaces.unpublished(mm.mm.raw().get()) {
            self.cow_pool.release_mm(&excluded);
        }
        assert!(
            self.residency
                .retire_overlapping(mm.mm.raw().get(), 0, u64::MAX)
        );
        self.retired.push(RetiredSpace {
            carrier: self.portal.carrier,
            zone: core::ptr::from_ref(self.zone).addr(),
            roots: core::ptr::from_ref(self.portal.roots).addr(),
            mm: ReservationMm::new(mm.mm.raw().get()).unwrap(),
        });
        self.drain_retired();
    }

    fn wake_effects(&mut self, effects: WakeEffects) {
        let _ = effects;
    }

    fn request_ingress_producer_boundary(&mut self) {}
}

fn default_context_words(address: AddressContext<RootGpa>) -> ParkedContextWords {
    let mut frame = [0u64; 20];
    frame[15] = 0x40_0000;
    frame[16] = 0x23;
    frame[17] = 0x202;
    frame[18] = 0x80_0000;
    frame[19] = 0x1b;
    ParkedContextWords::from_parts(
        frame,
        address,
        0x9000,
        0,
        [0; carrick_sched_core::X86_XSAVE_BYTES],
    )
}

struct X86NativeHarness {
    zone: &'static ZoneTables<ParkedContextWords>,
    roots: &'static X86Cpl0Reservations,
    portal_slots: &'static MmPortalSlots,
    portal: &'static TestPortal,
    words: SparseX86Tables,
    ram: PhysicalPages,
    residency: &'static FrameGrantResidencyTable,
    cow_pool: CowGrantPool,
    counters: Counters,
    retired: RetiredSpaces,
    registry: &'static NativeProcessRegistry<'static, AddressContext<RootGpa>, ParkedContextWords>,
    runtime: Arc<NativeProcessRuntime<'static, AddressContext<RootGpa>, ParkedContextWords>>,
    parent_task: &'static CurrentTask,
    parent_address: AddressContext<RootGpa>,
    parent_record: RecordId,
    slot: SlotId,
    next_fork_idx: AtomicU64,
    last_wait_status: RefCell<Option<LinuxWaitStatus>>,
}

impl X86NativeHarness {
    fn new() -> Self {
        let region = Box::leak(Box::new(Region::new()));
        let (roots, zone) = unsafe {
            (
                &*region
                    .ptr
                    .as_ptr()
                    .add(carrick_core_abi::X86_CPL0_RESERVATIONS_OFFSET as usize)
                    .cast::<X86Cpl0Reservations>(),
                &*region
                    .ptr
                    .as_ptr()
                    .add(carrick_core_abi::X86_CPL0_ZONE_OFFSET as usize)
                    .cast::<ZoneTables<ParkedContextWords>>(),
            )
        };
        let portal_slots = unsafe {
            let ptr = std::alloc::alloc_zeroed(std::alloc::Layout::new::<MmPortalSlots>())
                .cast::<MmPortalSlots>();
            assert!(!ptr.is_null());
            let slots = Box::leak(Box::from_raw(ptr));
            assert!(slots.bind_carrier(NonZeroU64::new(CARRIER_ID).unwrap()));
            slots
        };
        let residency = Box::leak(carrick_el1::cow::test_support::residency_table());

        let parent_mm_raw = 10u64;
        let parent_mm = ReservationMm::new(parent_mm_raw).unwrap();
        let parent_root = RootGpa::page_aligned(FrameGpa::new(PARENT_ROOT_PA)).unwrap();
        let slot = SlotId::new(0);

        zone.spaces.set_idle_ttbr(0x00f0_0000);
        let space_idx = zone
            .spaces
            .publish_closed(parent_mm_raw, PARENT_ROOT_PA, 0)
            .unwrap();
        roots
            .publish(
                space_idx.index(),
                parent_mm,
                Layout {
                    heap: ReservationRange::new(0x0040_0000, 0x1000_0000).unwrap(),
                    arena: ReservationRange::new(0x5000_0000, 0x7800_0000).unwrap(),
                    brk: 0x0040_0000,
                    address_limit: u64::MAX,
                    data_limit: u64::MAX,
                    external_address_bytes: 0,
                    external_data_bytes: 0,
                },
            )
            .unwrap();
        let access = TestX86Venue::space_access(zone, slot);
        {
            let venue = X86Cpl0RootReleaseVenue::new(roots, access.venue().unwrap()).unwrap();
            let mut owner = venue
                .lock(space_idx.index(), parent_mm, &NoRootWait)
                .unwrap();
            owner
                .import(
                    ReservationRange::new(STATUS_VA, STATUS_VA + 4096).unwrap(),
                    ReservationProtection::READ_WRITE,
                    true,
                )
                .unwrap();
            owner.finish_import().unwrap();
        }
        access.open(space_idx);

        let portal: &'static TestPortal = Box::leak(Box::new(
            MmPortal::<
                'static,
                NoPin,
                LinuxReservationPolicy,
                X86Cpl0ReservationGeometry,
                TestX86Venue,
                carrick_mmu_core::owner_mmu::Aarch64Mmu,
                ParkedContextWords,
            >::for_zone(NonZeroU64::new(CARRIER_ID).unwrap(), roots, zone)
            .with_mmu(X86Mmu),
        ));

        let words = SparseX86Tables::new(PARENT_ROOT_PA + 4096);
        let ram = PhysicalPages::new();
        // Back STATUS_VA as a writable private page in parent so wait4 copy_status succeeds.
        let (status_pa, _) = ram.alloc_extent(4096);
        let pt_pa = words.ensure_pt_chain(PARENT_ROOT_PA, STATUS_VA, true);
        words
            .store_unlinked(
                pt_pa + ((STATUS_VA >> 12) & 0x1ff) * 8,
                status_pa | PRESENT | WRITE | USER | MAY_WRITE | PRIVATE | NX,
            )
            .unwrap();

        let page = Box::leak(Box::new(ThreadLifecyclePage::new()));
        let control = Box::leak(Box::new(ThreadControlSlot::new()));
        let parent_task = Box::leak(Box::new(CurrentTask::new()));
        let binding = ExecutionBinding {
            task: EntryTaskKey::from_raw(1),
            mm: EntryMmKey::from_raw(parent_mm_raw),
            generation: SnapshotGeneration::from_raw(1),
            thread_generation: EntryThreadGeneration::from_raw(1),
        };
        parent_task.set(El1TaskId::from_linux_tid(1), binding.generation, 1);
        parent_task.mm.key.store(parent_mm_raw, Ordering::Release);
        parent_task
            .mm
            .thread_generation
            .store(binding.thread_generation.raw(), Ordering::Release);
        parent_task.publish_visible_pid(1);
        parent_task.publish_lifecycle(page as *const _ as u64, control as *const _ as u64);
        control.publish_host_birth_identity(
            carrick_core::terminal::ThreadBirthIdentity::from_parts(
                binding.task,
                BirthSerial::of_task(TaskSerial::from_raw_u64(1).unwrap()),
                binding.thread_generation,
            )
            .unwrap(),
        );

        let parent_address = AddressContext {
            root: parent_root,
            mm: MmGeneration::new(NonZeroU64::new(parent_mm_raw).unwrap()),
            generation: ContextGeneration::new(NonZeroU64::MIN),
        };
        zone.mm_issuer().observe_existing(parent_address.mm);
        zone.drive(slot, 1);
        zone.publish_slot(slot, parent_mm_raw, Some(0), 1);
        zone.enter_guest(slot);
        zone.install_space(slot, parent_mm_raw).unwrap();
        let parent_record = zone
            .current_or_new(
                slot,
                ThreadIdentity {
                    tid: 1,
                    serial: 1,
                    mm: parent_mm_raw,
                    file_table: 1,
                    generation: 1,
                    affinity_source: AffinitySource::UNBOUND,
                    affinity: 1,
                    lifecycle_page: page as *const _ as u64,
                    control_slot: control as *const _ as u64,
                },
            )
            .unwrap();

        let source = BornInZoneSource { zone, slot };
        let runtime = Arc::new(
            NativeProcessRuntime::admit_fresh_root::<X86Mmu>(
                source,
                parent_task,
                page,
                control,
                parent_address,
                parent_address,
                default_context_words(parent_address),
            )
            .unwrap(),
        );
        let registry = Box::leak(Box::new(NativeProcessRegistry::new()));
        registry
            .register_root(runtime.clone(), source, parent_task, parent_address)
            .unwrap();
        let _ = registry
            .for_entry(source, parent_task, parent_address)
            .unwrap();

        Self {
            zone,
            roots,
            portal_slots,
            portal,
            words,
            ram,
            residency,
            cow_pool: CowGrantPool::new(),
            counters: Counters::default(),
            retired: RetiredSpaces::new(),
            registry,
            runtime,
            parent_task,
            parent_address,
            parent_record,
            slot,
            next_fork_idx: AtomicU64::new(0),
            last_wait_status: RefCell::new(None),
        }
    }

    fn service(&self, slot: SlotId) -> X86TestService<'_> {
        X86TestService {
            portal: self.portal,
            zone: self.zone,
            words: &self.words,
            ram: &self.ram,
            residency: self.residency,
            cow_pool: &self.cow_pool,
            retired: &self.retired,
            slot,
            next_fork_idx: &self.next_fork_idx,
            last_wait_status: &self.last_wait_status,
        }
    }

    fn reserve_parent_private(&self, start: u64, len: u64) {
        let mm = ReservationMm::new(self.parent_address.mm.raw().get()).unwrap();
        let mut root = self.portal.root(mm, 0).unwrap();
        match root
            .mmap(
                Placement::NoReplace(start),
                len,
                ReservationProtection::READ_WRITE,
            )
            .unwrap()
        {
            Decision::Complete(va) => assert_eq!(va, start),
            Decision::Work(req) => {
                let completion = unsafe {
                    carrick_el1_abi::ReservationCompletion::after_descriptor_and_backing_commit(
                        req,
                        carrick_el1_abi::ReservationBackingReceipt {
                            receipt: req.sequence.raw(),
                            granted_bytes: 0,
                            returned_bytes: 0,
                        },
                    )
                }
                .unwrap();
                assert_eq!(root.complete(completion).unwrap(), start);
            }
        }
    }

    fn install_parent_grant_4k(
        &self,
        start: u64,
        len: u64,
        touch_offsets: &[u64],
    ) -> (u64, BackingIdentity) {
        self.reserve_parent_private(start, len);
        let (base_pa, backing) = self.ram.alloc_extent(len);
        let mm_key = self.parent_address.mm.raw().get();
        assert!(
            self.residency
                .publish(FrameGrantResidencyIdentity {
                    mm_key,
                    semantic_base: start,
                    physical_ipa: base_pa,
                    len,
                    mapping_id: backing.mapping_id.get(),
                    frame_id: backing.frame_id.get(),
                    owner_generation: backing.owner_generation.get(),
                    inventory_revision: backing.inventory_revision.get(),
                })
                .is_some()
        );
        for offset in (0..len).step_by(4096) {
            let va = start + offset;
            let pa = base_pa + offset;
            let pt_pa = self.words.ensure_pt_chain(PARENT_ROOT_PA, va, true);
            let touched = touch_offsets.contains(&offset);
            let flags = if touched {
                PRESENT | WRITE | USER | MAY_WRITE | PRIVATE | NX
            } else {
                PREPARED | WRITE | USER | MAY_WRITE | PRIVATE | NX
            };
            self.words
                .store_unlinked(pt_pa + ((va >> 12) & 0x1ff) * 8, pa | flags)
                .unwrap();
            if touched {
                let page = self.residency.lookup(mm_key, va).unwrap();
                assert!(self.residency.record_commit(page));
            }
        }
        (base_pa, backing)
    }

    fn replenish_cow_grants(&self, mm_key: u64, count: usize) {
        let index = self.zone.spaces.find(mm_key).unwrap();
        let access = TestX86Venue::space_access(self.zone, self.slot);
        let excluded = access
            .try_exclude_editor(index, mm_key)
            .expect("editor uncontended");
        let grants: Vec<_> = self
            .cow_pool
            .completions(excluded.proof())
            .map(|c| c.grant)
            .collect();
        for grant in grants {
            assert!(self.cow_pool.finish(excluded.proof(), &grant));
        }
        drop(excluded);

        for _ in 0..count {
            let (pa, backing) = self.ram.alloc_extent(0x4000);
            let aarch_backing = carrick_mmu_core::aarch64::descriptor_txn::BackingIdentity {
                frame_id: backing.frame_id,
                mapping_id: backing.mapping_id,
                owner_generation: backing.owner_generation,
                inventory_revision: backing.inventory_revision,
            };
            assert!(
                self.cow_pool.publish(mm_key, pa, aarch_backing).is_some(),
                "CowGrantPool::publish failed for mm {mm_key}"
            );
        }
    }

    fn fault_x86(
        &self,
        slot: SlotId,
        task: &CurrentTask,
        address: AddressContext<RootGpa>,
        va: u64,
        present: bool,
        access: GuestAccess,
    ) -> (Action, OwnerFaultSupplyOutcome) {
        let mm = ReservationMm::new(address.mm.raw().get()).unwrap();
        let handle = self
            .portal
            .admitted_handle(mm, u32::from(slot.raw()))
            .unwrap();
        let supply = OwnerFaultSupply::new(self.portal_slots).with_handle(handle);
        let mut prepared_resolver = TestX86PreparedResolver::new(address.mm.raw(), &self.words);
        let mut cow_resolver = TestX86CowResolver {
            words: &self.words,
            ram: &self.ram,
            pool: &self.cow_pool,
            residency: self.residency,
        };
        let spaces = TestX86Venue::space_access(self.zone, slot);
        let action = dispatch_x86_fault_with_prepared(
            CpuId::new(u32::from(slot.raw())),
            FaultInfo {
                address: UserVa::new(va),
                access,
                present,
            },
            &self.counters,
            task,
            spaces,
            FaultSupply::Owner(&supply),
            Some(PreparedFaultPath {
                residency: self.residency,
                resolver: &mut prepared_resolver,
                roots: Some(self.roots),
                file_slots: Some(self.portal_slots),
            }),
            &mut cow_resolver,
        );
        (action, supply.outcome())
    }

    fn resolve_user_write(
        &self,
        slot: SlotId,
        task: &CurrentTask,
        address: AddressContext<RootGpa>,
        va: u64,
        value: u64,
    ) {
        for _step in 0..4 {
            if let Ok(leaf) = translate_leaf(
                &self.words,
                address.root,
                UserVa::new(va),
                X86Access::Write,
                true,
            ) {
                self.ram
                    .write_u64(leaf.output.raw(), (va & 4095) as usize, value);
                return;
            }
            let pte = self
                .words
                .read_pte(address.root.address().raw(), va)
                .unwrap_or(0);
            let present = pte & PRESENT != 0;
            let (action, outcome) =
                self.fault_x86(slot, task, address, va, present, GuestAccess::Write);
            match (action, outcome) {
                (Action::Served, _) => continue,
                (Action::Forward, OwnerFaultSupplyOutcome::CowSelected) => {
                    let grant_slot = self.portal_slots.grant(slot.raw() as usize).unwrap();
                    let (_, window) = grant_slot
                        .pending_cow_fault_selection(address.mm.raw().get(), va)
                        .expect("pending COW fault selection");
                    assert!(grant_slot.take_cow_fault_selection(window));
                    self.replenish_cow_grants(address.mm.raw().get(), 16);
                }
                (Action::Forward, OwnerFaultSupplyOutcome::Selected) => {
                    let grant_slot = self.portal_slots.grant(slot.raw() as usize).unwrap();
                    let (_, window) = grant_slot
                        .pending_fault_selection(address.mm.raw().get(), va)
                        .expect("pending lazy fault selection");
                    let len = window.range.len();
                    let (pa, backing) = self.ram.alloc_extent(len);
                    let aarch_backing =
                        carrick_mmu_core::aarch64::descriptor_txn::BackingIdentity {
                            frame_id: backing.frame_id,
                            mapping_id: backing.mapping_id,
                            owner_generation: backing.owner_generation,
                            inventory_revision: backing.inventory_revision,
                        };
                    // Ensure PT pages exist for the newly granted window.
                    for off in (0..len).step_by(4096) {
                        self.words.ensure_pt_chain(
                            address.root.address().raw(),
                            window.range.start() + off,
                            true,
                        );
                    }
                    let op = carrick_mmu_core::aarch64::descriptor_txn::DescriptorOp::Prepare {
                        publication: carrick_mmu_core::aarch64::GuestLeafPublication {
                            va: window.range.start(),
                            ipa: pa,
                            len,
                            writable: window.protection.permits(ReservationProtection::WRITE),
                            executable: window.protection.permits(ReservationProtection::EXECUTE),
                        },
                        resident: PageSpan::new(window.fault_page, 4096),
                        backing: aarch_backing,
                    };
                    let txn = carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxn {
                        id: carrick_mmu_core::aarch64::descriptor_txn::DescriptorTxnId {
                            mm_key: address.mm.raw(),
                            generation: NonZeroU64::new(window.operation.sequence.get()).unwrap(),
                        },
                        root: SubstrateGpa(address.root.address().raw()),
                        op,
                        tables: carrick_mmu_core::aarch64::descriptor_txn::TableGrants::NONE,
                    };
                    assert!(grant_slot.submit(window, &txn));
                    let receipt = serve_grant(
                        self.portal,
                        grant_slot,
                        &self.words,
                        self.residency,
                        u32::from(slot.raw()),
                        || {},
                    )
                    .unwrap()
                    .expect("grant receipt");
                    assert!(matches!(
                        receipt.outcome,
                        carrick_mmu_core::aarch64::descriptor_txn::DescriptorOutcome::Applied(_)
                    ));
                    assert!(grant_slot.take_receipt(window, &txn).is_some());
                }
                other => panic!(
                    "x86 write fault at {va:#x} (present={present}, pte={pte:#x}) failed: {other:?}"
                ),
            }
        }
        panic!("x86 write fault at {va:#x} did not converge to writable leaf");
    }

    fn read_user_u64(&self, address: AddressContext<RootGpa>, va: u64) -> u64 {
        let leaf = translate_leaf(
            &self.words,
            address.root,
            UserVa::new(va),
            X86Access::Read,
            true,
        )
        .unwrap_or_else(|e| panic!("unreadable user VA {va:#x} in mm {:?}: {e:?}", address.mm));
        self.ram.read_u64(leaf.output.raw(), (va & 4095) as usize)
    }

    fn fork_from_parent(
        &self,
    ) -> (
        u32,
        RecordRef,
        AddressContext<RootGpa>,
        &'static CurrentTask,
        ParkedContextWords,
    ) {
        let mut service = self.service(self.slot);
        let source = BornInZoneSource {
            zone: self.zone,
            slot: self.slot,
        };
        let mut entry = self
            .runtime
            .enter_registered(
                self.registry,
                source,
                self.parent_task,
                self.parent_address,
                &default_context_words(self.parent_address),
                &mut service,
            )
            .unwrap();
        let outcome = entry.fork(ProcessForkChildTid::NONE);
        let child_pid = match outcome {
            LifecycleOutcome::Returned { result, .. } => {
                assert!(result.raw() > 0, "fork returned error: {}", result.raw());
                result.raw() as u32
            }
            _ => panic!("unexpected fork outcome"),
        };
        drop(entry);

        // Preempt parent onto `self.slot`'s queue and switch in the queued born child.
        assert!(
            self.zone
                .requeue_preempted(self.slot, self.parent_record)
                .is_queued()
        );
        self.zone.release_space(self.slot);
        self.zone.publish_slot(self.slot, 0, Some(0), 1);

        let selected = self
            .zone
            .switch_in_full(self.slot)
            .expect("queued born child record");
        assert_ne!(selected.record, self.parent_record);
        let child_ref = self.zone.record_ref(selected.record);
        // SAFETY: `switch_in_full` transferred exclusive record ownership onto `self.slot`.
        let state =
            unsafe { self.runtime.record_binding(child_ref) }.expect("born child record binding");
        let identity = self.zone.record(selected.record).identity();
        let child_address = state.address;
        self.zone
            .install_space(self.slot, child_address.mm.raw().get())
            .unwrap();

        let child_task = Box::leak(Box::new(CurrentTask::new()));
        child_task.set(
            El1TaskId::from_linux_tid(identity.tid as i32),
            SnapshotGeneration::from_raw(identity.generation),
            identity.file_table,
        );
        child_task
            .mm
            .key
            .store(child_address.mm.raw().get(), Ordering::Release);
        child_task
            .mm
            .thread_generation
            .store(identity.serial, Ordering::Release);
        child_task.publish_visible_pid(state.visible_pid);
        child_task.publish_lifecycle(identity.lifecycle_page, identity.control_slot);

        let mut words = state.words;
        {
            let mut adopt_entry = self
                .runtime
                .enter(source, child_task, words, &mut service)
                .unwrap();
            let resumed = adopt_entry.resume_checkpoint(|_| Ok(None)).unwrap();
            assert!(matches!(resumed, NativeResume::NoPending));
            if let Some(res) = selected.result {
                words.set_syscall_return(res);
            }
        }

        (child_pid, child_ref, child_address, child_task, words)
    }

    fn exit_child(&self, child_task: &'static CurrentTask, child_words: ParkedContextWords) {
        let mut service = self.service(self.slot);
        let source = BornInZoneSource {
            zone: self.zone,
            slot: self.slot,
        };
        let mut entry = self
            .runtime
            .enter(source, child_task, child_words, &mut service)
            .unwrap();
        let outcome = entry.exit_group(0);
        assert!(matches!(
            outcome,
            LifecycleOutcome::Transferred { .. } | LifecycleOutcome::HostCustody
        ));
        drop(entry);

        // Switch the host-registered parent record back onto `self.slot`.
        self.zone.release_space(self.slot);
        let selected = self
            .zone
            .switch_in_full(self.slot)
            .expect("queued parent record after child exit");
        assert_eq!(selected.record, self.parent_record);
        let parent_mm_raw = self.parent_address.mm.raw().get();
        self.zone.publish_slot(self.slot, parent_mm_raw, Some(0), 1);
        self.zone.install_space(self.slot, parent_mm_raw).unwrap();
    }

    fn wait4_in_parent(&self) -> (i64, LinuxWaitStatus) {
        // The production guest-copy path resolves a COW write fault on the
        // inherited status page before depositing wait4's status word. This
        // fixture's copy_status uses a direct translated store, so fault it
        // through the production supply path before that store.
        self.resolve_user_write(
            self.slot,
            self.parent_task,
            self.parent_address,
            STATUS_VA,
            0,
        );
        *self.last_wait_status.borrow_mut() = None;
        let mut service = self.service(self.slot);
        let source = BornInZoneSource {
            zone: self.zone,
            slot: self.slot,
        };
        let mut entry = self
            .runtime
            .enter_registered(
                self.registry,
                source,
                self.parent_task,
                self.parent_address,
                &default_context_words(self.parent_address),
                &mut service,
            )
            .unwrap();
        let outcome = entry.wait4(
            ProcessWaitPid::from_syscall_argument((-1i64) as u64),
            UserVa::new(STATUS_VA),
            LinuxWaitOptions::empty(),
            UserVa::new(0),
        );
        let reaped = match outcome {
            LifecycleOutcome::Returned { result, .. } => result.raw(),
            _ => panic!("expected synchronous zombie reap in wait4"),
        };
        let status = self
            .last_wait_status
            .borrow_mut()
            .take()
            .expect("copied LinuxWaitStatus");
        (reaped, status)
    }
}

#[test]
#[ignore = "#1733: red witness"]
fn serial_host_x86_native_fork_post_fork_first_touch_and_cow_refill_across_child_exit_wait4() {
    let h = X86NativeHarness::new();

    // Region A (2 MiB multi-page grant): parent touches page 0 before fork,
    // leaving sibling page +0x1000 PREPARED (untouched by parent before fork).
    let grant_a = 0x6000_0000u64;
    let (grant_a_pa, _) = h.install_parent_grant_4k(grant_a, EL1_FRAME_GRANT_TARGET_SIZE, &[0]);
    h.ram.write_u64(grant_a_pa, 0, 0xcafe_0000_0000_0001);

    // Region B: unbacked private anonymous reservation untouched by parent before fork.
    let unbacked_b = 0x6040_0000u64;
    h.reserve_parent_private(unbacked_b, 8192);

    // Region C: 72 x 16-KiB compounds (> COW_GRANT_PROBES = 64) touched by parent before fork.
    let cow_c = 0x6080_0000u64;
    let compounds = 72u64;
    let cow_c_len = compounds * 0x4000;
    let touches: Vec<u64> = (0..compounds).map(|c| c * 0x4000).collect();
    let (cow_c_pa, _) = h.install_parent_grant_4k(cow_c, cow_c_len, &touches);
    for c in 0..compounds {
        h.ram
            .write_u64(cow_c_pa + c * 0x4000, 0, 0xbeef_0000_0000_0000 + c);
    }

    let (child_pid, _child_ref, child_addr, child_task, child_words) = h.fork_from_parent();
    assert_eq!(child_pid, 2);

    // Child first-touches unbacked_b, COW-writes grant_a page 0 and cow_c compound 0, then exits.
    h.resolve_user_write(
        h.slot,
        child_task,
        child_addr,
        unbacked_b,
        0xdead_c0de_dead_c0de,
    );
    h.resolve_user_write(
        h.slot,
        child_task,
        child_addr,
        grant_a,
        0xdead_cafe_0000_0001,
    );
    h.resolve_user_write(h.slot, child_task, child_addr, cow_c, 0xdead_beef_0000_0000);
    h.exit_child(child_task, child_words);

    let (reaped_pid, status) = h.wait4_in_parent();
    assert_eq!(reaped_pid, i64::from(child_pid));
    assert_eq!(status.raw(), 0);

    // Variant (b.1): Parent first-touches unbacked_b only AFTER fork + child write/exit/wait4.
    h.resolve_user_write(
        h.slot,
        h.parent_task,
        h.parent_address,
        unbacked_b,
        0xface_b00c_0000_0001,
    );
    assert_eq!(
        h.read_user_u64(h.parent_address, unbacked_b),
        0xface_b00c_0000_0001
    );

    // Variant (b.2): Parent write first-touches inherited PREPARED sibling page `grant_a + 0x1000`
    // only AFTER fork + child exit/wait4.
    assert!(
        h.residency
            .lookup(h.parent_address.mm.raw().get(), grant_a + 0x1000)
            .is_some(),
        "parent prepared sibling lost residency after child exit"
    );
    h.resolve_user_write(
        h.slot,
        h.parent_task,
        h.parent_address,
        grant_a + 0x1000,
        0xcafe_0000_0000_0002,
    );
    assert_eq!(
        h.read_user_u64(h.parent_address, grant_a),
        0xcafe_0000_0000_0001
    );
    assert_eq!(
        h.read_user_u64(h.parent_address, grant_a + 0x1000),
        0xcafe_0000_0000_0002
    );

    // Variant (c): Parent writes again across all 72 (> 64) 16-KiB COW compounds after child exit,
    // settling USED completions and replenishing CowGrantPool past COW_GRANT_PROBES = 64.
    for c in 0..compounds {
        let va = cow_c + c * 0x4000;
        assert_eq!(
            h.read_user_u64(h.parent_address, va),
            0xbeef_0000_0000_0000 + c
        );
        h.resolve_user_write(
            h.slot,
            h.parent_task,
            h.parent_address,
            va,
            0xabcd_0000_0000_0000 + c,
        );
        assert_eq!(
            h.read_user_u64(h.parent_address, va),
            0xabcd_0000_0000_0000 + c
        );
    }
}
