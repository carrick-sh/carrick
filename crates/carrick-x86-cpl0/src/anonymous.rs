// CPL0 binding of the shared Linux anonymous reservation owner. Fresh
// descriptor holes complete in the guest root; backed edits still forward
// until the x86 descriptor/backing service is bound.
use super::InitialWords;
use carrick_el1::memory::{
    RangeBacking, ReservationDisposition, X86AnonymousDecode, classify_anonymous_range,
    decide_anonymous_syscall,
};
use carrick_el1::memory::reservations::{X86Cpl0Zone, shared_x86_cpl0_guest};
use carrick_el1_abi::{
    CurrentTask, ReservationBackingReceipt, ReservationCompletion, ReservationMm, TrapFrame,
};
use carrick_guest_arch::RootGpa;
use carrick_mmu_core::x86::descriptor_txn::LiveDescriptorWords;
use carrick_personality_linux::dispatch::FamilyCompletion;
use carrick_personality_linux::entry::{CanonicalCall, SyscallResult};
use carrick_personality_linux::pending_anonymous::{
    DelegatedStep, PendingAnonymousVenue, PermissionStep, RetirementStep,
};
use carrick_sched_core::SlotId;
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
}
impl<'a> X86AnonymousVenue<'a> {
    pub(super) fn new(call: &CanonicalCall, task: &'a CurrentTask, slot: u32, return_pc: u64) -> Self {
        let mut frame = TrapFrame {
            slot: u64::from(slot),
            elr: return_pc,
            ..Default::default()
        };
        frame.x[..6].copy_from_slice(&call.args);
        frame.x[8] = call.canonical.raw();
        Self { frame, task }
    }
}

/// Test whether this span has no descriptor authority at any level. An absent
/// ancestor skips its whole subtree, so large untouched reservations do not
/// cost one four-level walk per page.
fn empty_stage1(root: RootGpa, start: u64, end: u64, table_start: u64, table_end: u64) -> Option<bool> {
    if start >= end || end > 0x8000_0000_0000 {
        return None;
    }
    let words = InitialWords::production(table_start, table_end);
    let read = |pa| words.load(pa).ok();
    Some(
        classify_anonymous_range::<X86AnonymousDecode>(
            &read, root.address().raw(), start, end - start,
        ).summary == RangeBacking::Empty,
    )
}

impl PendingAnonymousVenue for X86AnonymousVenue<'_> {
    fn original_argument0(&self) -> u64 { self.frame.x[0] }
    fn task_state(&self) -> Option<&carrick_personality_linux::abi::entry::LinuxTaskState> {
        Some(&self.task.linux)
    }
    fn delegated(&mut self) -> DelegatedStep {
        let table_end = TABLE_END.load(Ordering::Acquire);
        let table_start = TABLE_START.load(Ordering::Relaxed);
        if table_start == 0 || table_end <= table_start { return DelegatedStep::Forward; }
        let zone_address = carrick_el1::isa::x86_kernel_layout().zone.raw();
        // SAFETY: the carrier retains and maps the aligned zone with the
        // reservation store throughout this initial MM's execution.
        let zone = unsafe { &*(zone_address as *const X86Cpl0Zone) };
        let Some(mm) = ReservationMm::new(self.task.mm.key.load(Ordering::Acquire)) else {
            return DelegatedStep::Forward;
        };
        let Some(index) = zone.spaces.find(mm.raw()) else { return DelegatedStep::Forward; };
        let table = shared_x86_cpl0_guest();
        if !table.admitted(index.index(), mm) { return DelegatedStep::NotDelegated; }
        let Some(slot) = SlotId::from_index(self.frame.slot as usize) else {
            return DelegatedStep::Forward;
        };
        let access = carrick_core::wait::space_access(zone, slot, initial_release);
        let Some(grant) = access.grant(index, mm.raw()) else { return DelegatedStep::Forward; };
        let Some(root) = RootGpa::page_aligned(carrick_guest_arch::FrameGpa::new(grant.ttbr0)) else {
            return DelegatedStep::Forward;
        };
        if !carrick_el1::isa::x86::hardware_live_root()
            .is_ok_and(|live| live.address() == root.address()) {
            return DelegatedStep::Forward;
        }
        let Ok(mut model) = table.lock_in(access, index.index(), mm, self.frame.slot as u32) else {
            return DelegatedStep::Forward;
        };
        match decide_anonymous_syscall(&self.frame, self.task, &mut model) {
            ReservationDisposition::Return(value) => {
                DelegatedStep::Served(SyscallResult::new(value))
            }
            ReservationDisposition::Work(mut pending) => {
                let request = pending.request();
                if empty_stage1(root, request.range.start(), request.range.end(), table_start, table_end)
                    != Some(true)
                {
                    if pending.cancel(&mut model).is_err() { fatal_reservation(); }
                    return DelegatedStep::Forward;
                }
                // SAFETY: the exact MM root and editor are held. This range
                // has no descriptor at any level, so no stage-1, backing or
                // inventory change is owed before the reservation commit.
                let completion = unsafe {
                    ReservationCompletion::after_descriptor_and_backing_commit(
                        request,
                        ReservationBackingReceipt {
                            receipt: request.sequence.raw(),
                            granted_bytes: 0,
                            returned_bytes: 0,
                        },
                    )
                };
                if completion.is_some_and(|completion| {
                    pending.complete(&mut self.frame, self.task, &mut model, completion).is_ok()
                }) {
                    DelegatedStep::Served(SyscallResult::new(self.frame.x[0] as i64))
                } else {
                    if pending.cancel(&mut model).is_err() { fatal_reservation(); }
                    DelegatedStep::Forward
                }
            }
            ReservationDisposition::Forward | ReservationDisposition::Unavailable(_) => {
                DelegatedStep::Forward
            }
        }
    }
    fn park_prepared(&mut self) -> Option<FamilyCompletion> { None }
    fn permission(&mut self) -> PermissionStep { PermissionStep::Forward }
    fn retirement(&mut self) -> RetirementStep { RetirementStep::Forward }
    fn install_result(&mut self, result: SyscallResult) {
        self.frame.x[0] = result.raw() as u64;
    }
}

pub(super) fn initial_release(
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
