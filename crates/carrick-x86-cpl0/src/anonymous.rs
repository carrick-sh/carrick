// CPL0 binding of the shared Linux anonymous reservation owner.
// Serves anonymous mmap, munmap, mprotect, and brk in CPL0 through the shared
// serve_delegated_anonymous and an x86 AnonymousDescriptorEditor.
use carrick_el1::memory::{
    AnonymousBackingProbe, AnonymousPermissionEditor, AnonymousRetirementEditor,
    DelegatedAnonymous, Stage1Backing, classify_x86_stage1_range, serve_delegated_anonymous,
};
use carrick_el1::memory::reservations::{X86Cpl0Zone, shared_x86_cpl0_guest};
use carrick_el1_abi::{Counters, CurrentTask, ReservationMm, TrapFrame};
use carrick_guest_arch::RootGpa;
use carrick_mmu_core::aarch64::{GuestPermissionEdit, GuestPermissionEditError, GuestRetirementError};
use carrick_mmu_core::descriptor_refusal::DescriptorRefusal;
use carrick_mmu_core::x86::descriptor_txn::{
    DescriptorOp, DescriptorOutcome, DescriptorTxn, DescriptorTxnId, InlineJournal,
    LiveDescriptorWords, PageSpan, Permissions, execute_descriptor_txn,
};
use carrick_personality_linux::dispatch::FamilyCompletion;
use carrick_personality_linux::entry::{CanonicalCall, SyscallResult};
use carrick_personality_linux::pending_anonymous::{
    DelegatedStep, PendingAnonymousVenue, PermissionStep, RetirementStep,
};
use carrick_sched_core::SlotId;
use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

static TABLE_START: AtomicU64 = AtomicU64::new(0);
static TABLE_END: AtomicU64 = AtomicU64::new(0);

pub(super) fn admit_tables(start: u64, end: u64) {
    TABLE_START.store(start, Ordering::Relaxed);
    TABLE_END.store(end, Ordering::Release);
}

pub(super) struct X86AnonymousVenue<'a> {
    frame: TrapFrame,
    task: &'a CurrentTask,
    counters: &'a Counters,
}

impl<'a> X86AnonymousVenue<'a> {
    pub(super) fn new(
        call: &CanonicalCall,
        task: &'a CurrentTask,
        slot: u32,
        return_pc: u64,
        counters: &'a Counters,
    ) -> Self {
        let mut frame = TrapFrame {
            slot: u64::from(slot),
            elr: return_pc,
            ..Default::default()
        };
        frame.x[..6].copy_from_slice(&call.args);
        frame.x[8] = call.canonical.raw();
        Self {
            frame,
            task,
            counters,
        }
    }
}

struct X86DescriptorWords {
    table_start: u64,
    table_end: u64,
}

impl X86DescriptorWords {
    fn word(&self, pa: u64) -> Result<&core::sync::atomic::AtomicU64, DescriptorRefusal> {
        let in_grants = pa >= self.table_start
            && pa.checked_add(8).is_some_and(|end| end <= self.table_end);
        let in_root = (0x60_0000..0x7c_0000).contains(&pa);
        if pa & 7 != 0 || !(in_grants || in_root) {
            return Err(DescriptorRefusal::TableOutsidePrimary);
        }
        let mapped = carrick_el1::isa::x86::user_tables::table_alias(
            carrick_guest_arch::FrameGpa::new(pa & !4095),
        )
        .ok_or(DescriptorRefusal::TableOutsidePrimary)?
        .raw()
            + (pa & 4095);
        // SAFETY: Cpl0Carrier retains this supervisor mapping for the VM
        // lifetime; the MM owner holds the stopped sibling and exact grant.
        Ok(unsafe { &*(mapped as *const core::sync::atomic::AtomicU64) })
    }
}

impl LiveDescriptorWords for X86DescriptorWords {
    fn load(&self, pa: u64) -> Result<u64, DescriptorRefusal> {
        Ok(self.word(pa)?.load(Ordering::Acquire))
    }

    fn compare_exchange(
        &self,
        pa: u64,
        before: u64,
        after: u64,
    ) -> Result<bool, DescriptorRefusal> {
        Ok(self
            .word(pa)?
            .compare_exchange(before, after, Ordering::AcqRel, Ordering::Acquire)
            .is_ok())
    }

    fn store_unlinked(&self, pa: u64, value: u64) -> Result<(), DescriptorRefusal> {
        self.word(pa)?
            .compare_exchange(0, value, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| DescriptorRefusal::Contended)
    }

    fn publish_barrier(&self) {
        core::sync::atomic::fence(Ordering::SeqCst);
    }

    fn invalidate_range(&self, va: u64, len: u64) {
        #[cfg(all(target_os = "none", target_arch = "x86_64"))]
        {
            use carrick_guest_arch::MmuBackend;
            if let (Ok(root), Some(range)) = (
                carrick_el1::isa::x86::hardware_live_root(),
                carrick_guest_arch::UserRange::checked(
                    carrick_guest_arch::UserVa::new(va),
                    carrick_guest_arch::GuestLen::new(len),
                ),
            ) {
                let mut backend = carrick_el1::isa::x86::X86Backend;
                let context = carrick_guest_arch::AddressContext {
                    root,
                    mm: carrick_guest_arch::MmGeneration::new(NonZeroU64::MIN),
                    generation: carrick_guest_arch::ContextGeneration::new(NonZeroU64::MIN),
                };
                if let Ok(ticket) = backend.request_invalidation(context, range) {
                    let _ = backend.ack_drain(ticket);
                }
            }
        }
        #[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
        {
            let _ = (va, len);
        }
    }
}

struct X86AnonymousDescriptorEditor {
    mm_key: u64,
    words: X86DescriptorWords,
}

impl X86AnonymousDescriptorEditor {
    fn new(mm_key: u64, table_start: u64, table_end: u64) -> Self {
        Self {
            mm_key,
            words: X86DescriptorWords {
                table_start,
                table_end,
            },
        }
    }
}

impl AnonymousBackingProbe for X86AnonymousDescriptorEditor {
    fn backing(&mut self, ttbr0: u64, va: u64, len: u64) -> Stage1Backing {
        let read = |pa: u64| self.words.load(pa).ok();
        classify_x86_stage1_range(&read, ttbr0, va, len)
    }

    fn stock_span(&mut self, mm_key: u64, va: u64) -> Option<(u64, u64)> {
        #[cfg(target_os = "none")]
        {
            let page = carrick_el1_abi::frame_grant_residency_guest().lookup(mm_key, va)?;
            Some((
                page.identity.semantic_base,
                page.identity.semantic_base + page.identity.len,
            ))
        }
        #[cfg(not(target_os = "none"))]
        {
            let _ = (mm_key, va);
            None
        }
    }
}

impl AnonymousPermissionEditor for X86AnonymousDescriptorEditor {
    fn protect_and_invalidate(
        &mut self,
        ttbr0: u64,
        edit: GuestPermissionEdit,
    ) -> Result<(), GuestPermissionEditError> {
        let root = RootGpa::page_aligned(carrick_guest_arch::FrameGpa::new(ttbr0))
            .ok_or(GuestPermissionEditError::BadRange)?;
        let span = PageSpan::new(edit.va, edit.len);
        let permissions = Permissions {
            writable: edit.writable,
            executable: edit.executable,
            user: true,
        };
        let op = DescriptorOp::Protect { span, permissions };
        let txn = DescriptorTxn {
            id: DescriptorTxnId {
                mm_key: NonZeroU64::new(self.mm_key)
                    .ok_or(GuestPermissionEditError::BadRange)?,
                generation: NonZeroU64::MIN,
            },
            root,
            op,
            tables: &[],
        };
        let mut journal = InlineJournal::new();
        let receipt = execute_descriptor_txn(&self.words, &txn, root, &mut journal);
        match receipt.outcome {
            DescriptorOutcome::Applied { .. } => Ok(()),
            DescriptorOutcome::Indeterminate(_) => Err(GuestPermissionEditError::RollbackFailed),
            DescriptorOutcome::Refused(refusal) | DescriptorOutcome::RolledBack(refusal) => {
                Err(match refusal {
                    DescriptorRefusal::BadRange => GuestPermissionEditError::BadRange,
                    DescriptorRefusal::TableOutsidePrimary => {
                        GuestPermissionEditError::TableOutsidePrimary
                    }
                    DescriptorRefusal::MissingTable => GuestPermissionEditError::MissingTable,
                    DescriptorRefusal::PermissionWidening | DescriptorRefusal::CowArmed => {
                        GuestPermissionEditError::PermissionWidening
                    }
                    _ => GuestPermissionEditError::NotPrivateAnonymous,
                })
            }
        }
    }
}

impl AnonymousRetirementEditor for X86AnonymousDescriptorEditor {
    fn retire_and_invalidate(
        &mut self,
        ttbr0: u64,
        address: u64,
        len: u64,
    ) -> Result<(), GuestRetirementError> {
        let root = RootGpa::page_aligned(carrick_guest_arch::FrameGpa::new(ttbr0))
            .ok_or(GuestRetirementError::BadRange)?;
        let span = PageSpan::new(address, len);
        let op = DescriptorOp::Retire(span);
        let txn = DescriptorTxn {
            id: DescriptorTxnId {
                mm_key: NonZeroU64::new(self.mm_key)
                    .ok_or(GuestRetirementError::BadRange)?,
                generation: NonZeroU64::MIN,
            },
            root,
            op,
            tables: &[],
        };
        let mut journal = InlineJournal::new();
        let receipt = execute_descriptor_txn(&self.words, &txn, root, &mut journal);
        match receipt.outcome {
            DescriptorOutcome::Applied { .. } => Ok(()),
            DescriptorOutcome::Indeterminate(_) => Err(GuestRetirementError::RollbackFailed),
            DescriptorOutcome::Refused(refusal) | DescriptorOutcome::RolledBack(refusal) => {
                Err(match refusal {
                    DescriptorRefusal::BadRange => GuestRetirementError::BadRange,
                    DescriptorRefusal::TableOutsidePrimary => {
                        GuestRetirementError::TableOutsidePrimary
                    }
                    DescriptorRefusal::MissingTable => GuestRetirementError::MissingTable,
                    _ => GuestRetirementError::NotPrivateAnonymous,
                })
            }
        }
    }
}

impl PendingAnonymousVenue for X86AnonymousVenue<'_> {
    fn original_argument0(&self) -> u64 {
        self.frame.x[0]
    }
    fn task_state(&self) -> Option<&carrick_personality_linux::abi::entry::LinuxTaskState> {
        Some(&self.task.linux)
    }
    fn delegated(&mut self) -> DelegatedStep {
        let table_end = TABLE_END.load(Ordering::Acquire);
        let table_start = TABLE_START.load(Ordering::Relaxed);
        if table_start == 0 || table_end <= table_start {
            return DelegatedStep::Forward;
        }
        let zone_address = carrick_el1::isa::x86_kernel_layout().zone.raw();
        // SAFETY: the carrier retains and maps the aligned zone with the
        // reservation store throughout this initial MM's execution.
        let zone = unsafe { &*(zone_address as *const X86Cpl0Zone) };
        let Some(mm) = ReservationMm::new(self.task.mm.key.load(Ordering::Acquire)) else {
            return DelegatedStep::Forward;
        };
        let Some(index) = zone.spaces.find(mm.raw()) else {
            return DelegatedStep::Forward;
        };
        let table = shared_x86_cpl0_guest();
        if !table.admitted(index.index(), mm) {
            return DelegatedStep::NotDelegated;
        }
        let Some(slot) = SlotId::from_index(self.frame.slot as usize) else {
            return DelegatedStep::Forward;
        };
        let access = carrick_core::wait::space_access(zone, slot, initial_release);
        let Some(grant) = access.grant(index, mm.raw()) else {
            return DelegatedStep::Forward;
        };
        let Some(root) = RootGpa::page_aligned(carrick_guest_arch::FrameGpa::new(grant.ttbr0)) else {
            return DelegatedStep::Forward;
        };
        if !carrick_el1::isa::x86::hardware_live_root()
            .is_ok_and(|live| live.address() == root.address())
        {
            return DelegatedStep::Forward;
        }
        let mut editor = X86AnonymousDescriptorEditor::new(mm.raw(), table_start, table_end);
        match serve_delegated_anonymous(
            &mut self.frame,
            self.counters,
            self.task,
            access,
            table,
            &mut editor,
        ) {
            DelegatedAnonymous::PreparedConflict => DelegatedStep::PreparedConflict,
            DelegatedAnonymous::NotDelegated => DelegatedStep::NotDelegated,
            DelegatedAnonymous::Served => {
                DelegatedStep::Served(SyscallResult::new(self.frame.x[0] as i64))
            }
            DelegatedAnonymous::Forward => DelegatedStep::Forward,
        }
    }
    fn park_prepared(&mut self) -> Option<FamilyCompletion> {
        None
    }
    fn permission(&mut self) -> PermissionStep {
        PermissionStep::Forward
    }
    fn retirement(&mut self) -> RetirementStep {
        RetirementStep::Forward
    }
    fn install_result(&mut self, result: SyscallResult) {
        self.frame.x[0] = result.raw() as u64;
    }
}

fn initial_release(
    _: &X86Cpl0Zone,
    _: carrick_sched_core::Waker,
    owned: carrick_sched_core::object_wait::OwnedObjectWakeEffects<'_, carrick_sched_core::ParkedContextWords>,
) {
    let mut handed = false;
    let (_, effects) = owned.deliver_handbacks(&mut |_| handed = true);
    if handed || effects != carrick_sched_core::WakeEffects::default() {
        fatal_reservation();
    }
}

fn fatal_reservation() -> ! {
    super::initial_boot::fatal_boot()
}
